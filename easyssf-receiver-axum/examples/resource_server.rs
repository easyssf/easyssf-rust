//! A resource server that receives pushed SETs and rejects the access tokens of revoked sessions.
//!
//! The receiver is assembled from configuration, as an application would do it; the
//! `TestTransmitter` stands in for the identity provider and answers the metadata and JWK Set
//! requests in-process. Validating the access token is left out: `x-sid` stands in for it.
//!
//! ```sh
//! cargo run -p easyssf-receiver-axum --example resource_server
//! curl -i localhost:8081/api/orders -H 'x-sid: session-1'
//! curl -i localhost:8081/healthz
//! ```

use std::time::SystemTime;

use axum::Router;
use axum::body::Body;
use axum::response::IntoResponse;
use axum::routing::get;
use easyssf_receiver::event::{SsfEventContext, for_event};
use easyssf_receiver::revocation::SsfTokenClaims;
use easyssf_receiver::{BoxError, SsfReceiver, config::SsfReceiverConfig};
use easyssf_receiver_axum::{SsfRevocationLayer, push_router_for};
use easyssf_test::TestTransmitter;
use http::Request;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let transmitter = TestTransmitter::new();
    let config: SsfReceiverConfig = toml::from_str(&format!(
        r#"
        transmitter-issuer = "{}"
        expected-audience = "https://my-app.example"
        [push]
        expected-auth-header = "Bearer s3cr3t"
        "#,
        transmitter.issuer()
    ))?;
    let receiver = SsfReceiver::builder(config)
        .http_client(transmitter.clone()) // a reqwest client by default
        .handler(for_event("CaepSessionRevoked", |context: SsfEventContext| async move {
            let subject = context.subject();
            // end what you hold for subject.session_id() or subject.subject()
            println!(
                "session revoked: user {:?}, session {:?}",
                subject.subject(),
                subject.session_id()
            );
            Ok(())
        }))
        .build()?;
    receiver.start();

    // stands in for the layer that validates the access token and leaves its claims on the request
    let issuer = transmitter.issuer().to_owned();
    let fake_authentication =
        axum::middleware::from_fn(move |mut request: Request<Body>, next: axum::middleware::Next| {
            let issuer = issuer.clone();
            async move {
                if let Some(sid) = request
                    .headers()
                    .get("x-sid")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_owned)
                {
                    request.extensions_mut().insert(SsfTokenClaims {
                        issuer: Some(issuer),
                        subject: Some("alice".to_owned()),
                        session_id: Some(sid),
                        issued_at: Some(SystemTime::now()),
                    });
                }
                next.run(request).await
            }
        });
    let health_receiver = std::sync::Arc::new(receiver);
    let health = health_receiver.clone();
    let app = Router::new()
        .route("/api/orders", get(|| async { "orders" }))
        .layer(SsfRevocationLayer::new(
            health_receiver.token_revocation_store(),
            |parts| parts.extensions.get::<SsfTokenClaims>().cloned(),
        ))
        .layer(fake_authentication)
        .route(
            "/healthz",
            get(move || {
                let health = health.clone();
                async move {
                    let health = health.health().await;
                    (
                        [(http::header::CONTENT_TYPE, "application/json")],
                        serde_json::json!({ "status": health.status.as_str(), "description": health.description })
                            .to_string(),
                    )
                        .into_response()
                }
            }),
        )
        .merge(push_router_for(&health_receiver)); // POST /ssf/push

    let set = transmitter.sign_set(&{
        let mut claims = transmitter.set_claims(
            "CaepSessionRevoked",
            Some(easyssf_test::subjects::complex(
                Some(easyssf_test::subjects::iss_sub(transmitter.issuer(), "alice")),
                Some(easyssf_test::subjects::opaque("session-1")),
            )),
        );
        claims.insert("aud".to_owned(), "https://my-app.example".into());
        claims
    });
    println!(
        "Revoke session-1 with:\ncurl -i -X POST localhost:8081/ssf/push -H 'Authorization: Bearer s3cr3t' -d '{set}'"
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8081").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
