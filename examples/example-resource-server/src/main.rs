//! A resource server: every request to the API needs an access token of the identity provider.
//! The SSF receiver adds the push endpoint and rejects the access tokens of sessions the identity
//! provider revoked. The identity provider is both the issuer of the access tokens and the SSF
//! transmitter: any transmitter that supports CAEP session-revoked events does; the defaults fit
//! the Keycloak of `examples/keycloak`.
//!
//! ```sh
//! cargo run -p example-resource-server                     # PUSH stream of example-resource-server
//! cargo run -p example-resource-server -- --profile poll   # POLL stream of example-poll-receiver
//! ```
//!
//! `SSF_TRANSMITTER_ISSUER`, `SSF_TOKEN_URI`, `SSF_CLIENT_ID`, `SSF_CLIENT_SECRET` and
//! `SSF_PUSH_URL` override the defaults of `config.toml`. The application contains no SSF code
//! apart from that configuration and the auditing handler that logs the events; `auth.rs`
//! validates the access tokens, which Spring Security does for the Java example.

mod auth;
mod handler;

use std::sync::Arc;
use std::time::SystemTime;

use axum::Router;
use axum::extract::Extension;
use axum::middleware::from_fn_with_state;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use easyssf_receiver::config::SsfReceiverConfig;
use easyssf_receiver::revocation::SsfTokenClaims;
use easyssf_receiver::{BoxError, SsfReceiver};
use easyssf_receiver_axum::{SsfRevocationLayer, push_router_for};
use http::request::Parts;
use metrics_exporter_prometheus::PrometheusBuilder;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::{AccessToken, AccessTokens};
use crate::handler::AuditingSsfEventHandler;

const CONFIG: &str = include_str!("../config.toml");
const CONFIG_POLL: &str = include_str!("../config-poll.toml");

#[derive(Debug, Deserialize)]
struct ServerConfig {
    port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { port: 8081 }
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    example_support::init_tracing("info,easyssf=debug,example_resource_server=debug");
    let args: Vec<String> = std::env::args().collect();
    let sources = match example_support::argument(&args, "profile").as_deref() {
        None => vec![CONFIG],
        Some("poll") => vec![CONFIG, CONFIG_POLL],
        Some(other) => return Err(format!("Unknown profile '{other}', there is 'poll'").into()),
    };
    let settings = example_support::load(&sources)?;
    let server: ServerConfig = example_support::section(&settings, "server")?;
    let config: SsfReceiverConfig = example_support::section(&settings, "easyssf.receiver")?;
    // the transmitter is the identity provider: its access tokens are the ones the API accepts
    let issuer = config
        .transmitter
        .issuer()
        .ok_or("easyssf.receiver.transmitter-issuer is required")?
        .to_owned();

    // the receiver records easyssf.receiver.* with the `metrics` facade, the Prometheus exporter
    // renders them for GET /metrics (the Actuator endpoint of the Java example)
    let metrics = PrometheusBuilder::new().install_recorder()?;

    // the receiver: the push endpoint, the stream at the transmitter, the revocation store and
    // the handler that revokes the access tokens, plus the application's own handler
    let receiver = Arc::new(SsfReceiver::builder(config).handler(AuditingSsfEventHandler).build()?);
    receiver.start();

    // validates the access tokens of the identity provider and leaves their claims on the request
    let access_tokens = Arc::new(AccessTokens::new(&issuer));
    // rejects the access tokens of revoked sessions and users: reads the claims the
    // authentication left on the request and looks them up in the revocation store
    let revocation = SsfRevocationLayer::new(receiver.token_revocation_store(), |parts: &Parts| {
        parts.extensions.get::<SsfTokenClaims>().cloned()
    });
    let api = Router::new()
        .route("/api/me", get(me))
        .route(
            "/metrics",
            get(move || {
                let metrics = metrics.clone();
                async move { metrics.render() }
            }),
        )
        // layers run from the outside in: authentication first, then the revocation check
        .layer(revocation)
        .layer(from_fn_with_state(access_tokens, auth::require_access_token));
    let health_receiver = receiver.clone();
    let app = Router::new()
        .merge(api)
        .route(
            "/health",
            get(move || {
                let receiver = health_receiver.clone();
                async move { health(&receiver).await }
            }),
        )
        // the push endpoint the transmitter delivers to, at easyssf.receiver.push.endpoint-path
        .merge(push_router_for(&receiver));

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", server.port))
        .await
        .map_err(|error| {
            format!(
                "Could not listen on port {} ({error}); SERVER_PORT chooses another one",
                server.port
            )
        })?;
    tracing::info!(
        "The example resource server listens on http://localhost:{}",
        server.port
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    receiver.shutdown().await;
    Ok(())
}

/// The user of the access token, as `GET /api/me` of the Java example shows it.
async fn me(Extension(token): Extension<AccessToken>) -> Json<Value> {
    tracing::info!(
        user = token.string("preferred_username").unwrap_or(""),
        session = token.string("sid").unwrap_or(""),
        issued_at = time(token.time("iat")).unwrap_or_default(),
        "GET /api/me"
    );
    Json(json!({
        "username": token.string("preferred_username"),
        "subject": token.string("sub"),
        "sessionId": token.string("sid"),
        "tokenIssuedAt": time(token.time("iat")),
        "tokenExpiresAt": time(token.time("exp")),
    }))
}

/// The health of the receiver: its transmitter, stream and, in the `poll` profile, the poller.
async fn health(receiver: &SsfReceiver) -> Response {
    let health = receiver.health().await;
    let status = if health.status == easyssf_receiver::receiver::SsfHealthStatus::Unhealthy {
        http::StatusCode::SERVICE_UNAVAILABLE
    } else {
        http::StatusCode::OK
    };
    let transmitters: Vec<Value> = health
        .transmitters
        .iter()
        .map(|transmitter| {
            json!({
                "name": transmitter.name,
                "status": transmitter.status.as_str(),
                "issuer": transmitter.issuer,
                "delivery": transmitter.delivery,
                "streamId": transmitter.stream_id,
                "lastSuccessfulPollAt": time(transmitter.last_successful_poll_at),
                "pollError": transmitter.poll_error,
                "pendingAcks": transmitter.pending_acks,
            })
        })
        .collect();
    (
        status,
        Json(json!({ "status": health.status.as_str(), "description": health.description, "transmitters": transmitters })),
    )
        .into_response()
}

fn time(time: Option<SystemTime>) -> Option<String> {
    time.map(|time| humantime::format_rfc3339_seconds(time).to_string())
}
