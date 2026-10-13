//! A web application that logs users in with Keycloak. The SSF receiver adds the push endpoint and
//! ends the local session of a user when Keycloak reports that their session was revoked or their
//! credentials changed. Keycloak is both the identity provider and the SSF transmitter.
//!
//! ```sh
//! cargo run -p example-oidc-client
//! ```
//!
//! The application contains no SSF code apart from the configuration in `config.toml` and the
//! two layers of `easyssf-receiver-axum`; `oidc.rs` is the login, which Spring Security does for
//! the Java example, `home.rs` the page.

mod home;
mod oidc;

use std::sync::Arc;

use axum::Router;
use axum::extract::{Form, Query, State};
use axum::response::{Html, IntoResponse, Json, Redirect, Response};
use axum::routing::{get, post};
use easyssf_receiver::config::SsfReceiverConfig;
use easyssf_receiver::{BoxError, SsfReceiver};
use easyssf_receiver_axum::push_router_for;
use easyssf_receiver_axum::sessions::{SsfSessionLogin, SsfSessionRevocationLayer, record_login};
use http::StatusCode;
use http::header::CACHE_CONTROL;
use serde::Deserialize;
use serde_json::json;
use tower_sessions::cookie::SameSite;
use tower_sessions::{MemoryStore, Session, SessionManagerLayer};
use url::Url;

use crate::oidc::{CallbackParams, LoggedInUser, Oidc, OidcConfig};

const CONFIG: &str = include_str!("../config.toml");

/// Keys of the session.
const USER_KEY: &str = "oidc.user";
const CSRF_KEY: &str = "csrf";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct ServerConfig {
    port: u16,
    base_url: Url,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 8082,
            base_url: Url::parse("http://localhost:8082").expect("URL"),
        }
    }
}

/// What the handlers share.
struct App {
    oidc: Oidc,
    base_url: Url,
    account_console: String,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    example_support::init_tracing("info,easyssf=debug,example_oidc_client=debug");
    let settings = example_support::load(&[CONFIG])?;
    let server: ServerConfig = example_support::section(&settings, "server")?;
    let keycloak: OidcConfig = example_support::section(&settings, "keycloak")?;
    let config: SsfReceiverConfig = example_support::section(&settings, "easyssf.receiver")?;

    // the receiver: the push endpoint, the stream at Keycloak, the revocation store and the
    // handler that records which sessions and users the events revoked
    let receiver = Arc::new(SsfReceiver::builder(config).build()?);
    receiver.start();

    let app = Arc::new(App {
        account_console: format!("{}/account", keycloak.issuer.trim_end_matches('/')),
        oidc: Oidc::new(keycloak, server.base_url.join("/login/oauth2/code/keycloak")?),
        base_url: server.base_url,
    });
    let router = Router::new()
        .route("/", get(home))
        .route("/login", get(login))
        .route("/login/oauth2/code/keycloak", get(callback))
        .route("/auth/check", get(check))
        .route("/logout", post(logout))
        .with_state(app)
        // flushes a session whose user or Keycloak session an event revoked after the login;
        // inside the session layer, so that the session is loaded before the check
        .layer(SsfSessionRevocationLayer::new(receiver.token_revocation_store()))
        .layer(
            SessionManagerLayer::new(MemoryStore::default())
                .with_secure(false)
                // the cookie has to come along when Keycloak redirects back after the login
                .with_same_site(SameSite::Lax),
        )
        // the push endpoint Keycloak delivers to, at easyssf.receiver.push.endpoint-path
        .merge(push_router_for(&receiver));

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", server.port))
        .await
        .map_err(|error| {
            format!(
                "Could not listen on port {} ({error}); SERVER_PORT chooses another one",
                server.port
            )
        })?;
    tracing::info!("The example OIDC client listens on http://localhost:{}", server.port);
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    receiver.shutdown().await;
    Ok(())
}

/// The page, for a logged-in user; the login otherwise.
async fn home(State(app): State<Arc<App>>, session: Session) -> Response {
    let Some(user) = user(&session).await else {
        return Redirect::to("/login").into_response();
    };
    let csrf_token = match session.get::<String>(CSRF_KEY).await {
        Ok(Some(token)) => token,
        _ => {
            let token = openidconnect::CsrfToken::new_random().secret().clone();
            if let Err(error) = session.insert(CSRF_KEY, &token).await {
                tracing::error!(%error, "Could not store the CSRF token in the session");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            token
        }
    };
    let local_session = session.id().map(|id| id.to_string()).unwrap_or_default();
    Html(home::page(&user, &local_session, &app.account_console, &csrf_token)).into_response()
}

/// Starts the login: remembers state, nonce and PKCE verifier in the session and sends the browser
/// to Keycloak.
async fn login(State(app): State<Arc<App>>, session: Session) -> Response {
    match app.oidc.start_login(&session).await {
        Ok(authorization_url) => Redirect::to(authorization_url.as_str()).into_response(),
        Err(error) => {
            tracing::warn!(%error, "Could not start the login with Keycloak");
            login_failed(&error.to_string())
        }
    }
}

/// The redirect URI: exchanges the code, validates the ID token and records the login for the
/// revocation check.
async fn callback(State(app): State<Arc<App>>, session: Session, Query(params): Query<CallbackParams>) -> Response {
    let user = match app.oidc.finish_login(&session, params).await {
        Ok(user) => user,
        Err(error) => {
            // the default login page only says that the login failed, the reason is in the log
            tracing::warn!("Login with Keycloak failed: {error}");
            return login_failed(&error.to_string());
        }
    };
    // a fresh session id for the logged-in session
    if let Err(error) = session.cycle_id().await {
        tracing::error!(%error, "Could not renew the session");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    // what the revocation check compares the events with: issuer, subject, Keycloak session, time
    let login = SsfSessionLogin::new(&user.issuer, Some(&user.subject), user.sid.as_deref());
    if let Err(error) = record_login(&session, &login).await {
        tracing::error!(%error, "Could not record the login in the session");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    if let Err(error) = session.insert(USER_KEY, &user).await {
        tracing::error!(%error, "Could not store the user in the session");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    tracing::info!(
        user = user.username.as_deref().unwrap_or(""),
        subject = user.subject,
        sid = user.sid.as_deref().unwrap_or(""),
        "Logged in"
    );
    Redirect::to("/").into_response()
}

/// Lets the page find out whether its local session still exists. The check does not call
/// Keycloak: the receiver ends the local session when Keycloak reports the end of the Keycloak
/// session, so the request either arrives in the session (200) or without one (401).
async fn check(session: Session) -> Response {
    let no_store = [(CACHE_CONTROL, "no-store")];
    match user(&session).await {
        Some(user) => (
            StatusCode::OK,
            no_store,
            Json(json!({
                "user": user.username,
                "sid": user.sid,
                "localSession": session.id().map(|id| id.to_string()),
                "checkedAt": humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string(),
            })),
        )
            .into_response(),
        None => (StatusCode::UNAUTHORIZED, no_store).into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct LogoutForm {
    #[serde(rename = "_csrf")]
    csrf: String,
}

/// Logging out of the application also logs the user out of Keycloak (RP-initiated logout).
async fn logout(State(app): State<Arc<App>>, session: Session, Form(form): Form<LogoutForm>) -> Response {
    match session.get::<String>(CSRF_KEY).await {
        Ok(Some(token)) if token == form.csrf => {}
        _ => return StatusCode::FORBIDDEN.into_response(),
    }
    let user = user(&session).await;
    if let Err(error) = session.flush().await {
        tracing::error!(%error, "Could not end the session");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let Some(user) = user else {
        return Redirect::to("/").into_response();
    };
    tracing::info!(
        user = user.username.as_deref().unwrap_or(""),
        "Logged out, ending the Keycloak session as well"
    );
    match app.oidc.logout_url(&user, &app.base_url).await {
        Ok(Some(url)) => Redirect::to(url.as_str()).into_response(),
        Ok(None) => Redirect::to("/").into_response(),
        Err(error) => {
            tracing::warn!(%error, "Could not log out of Keycloak");
            Redirect::to("/").into_response()
        }
    }
}

async fn user(session: &Session) -> Option<LoggedInUser> {
    match session.get::<LoggedInUser>(USER_KEY).await {
        Ok(user) => user,
        Err(error) => {
            tracing::warn!(%error, "Could not read the user from the session");
            None
        }
    }
}

fn login_failed(reason: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Html(format!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Login failed</title></head>\
             <body><h1>Login failed</h1><p>{}</p><p><a href=\"/login\">Try again</a></p></body></html>",
            home::escape(reason)
        )),
    )
        .into_response()
}
