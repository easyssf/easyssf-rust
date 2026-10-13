//! Ends tower-sessions sessions a security event revoked (feature `tower-sessions`); the
//! counterpart of the cookie hook of the .NET port and of the OIDC client integration of the
//! Spring Boot starter.
//!
//! The `SessionStore` of tower-sessions finds sessions by id only, not by user, so the receiver
//! cannot end the sessions of a user when the event arrives. Instead, at login the application
//! [records](record_login) who logged in and when, and [`SsfSessionRevocationLayer`] checks the
//! revocation store on every request: a session whose user or session id was revoked after the
//! login is flushed, and the request continues anonymous. The revocation TTL has to cover the
//! longest session lifetime, or a revoked session is accepted again once the revocation is
//! forgotten. This covers axum-login too, which sits on tower-sessions.
//!
//! Add the layer *inside* the `SessionManagerLayer`, so that the session is loaded before the
//! check: in axum, `.layer(SsfSessionRevocationLayer::new(store)).layer(session_manager_layer)`.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime};

use axum::response::{IntoResponse, Response};
use easyssf_receiver::revocation::{SsfTokenClaims, SsfTokenRevocationStore};
use http::{Request, StatusCode};
use serde::{Deserialize, Serialize};
use tower::{Layer, Service};
use tower_sessions::Session;

/// The key under which the login is kept in the session.
pub const SESSION_KEY: &str = "easyssf.login";

/// Who logged in, as the revocation check reads it: the `iss`, `sub` and `sid` of the ID token,
/// and the time of the login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsfSessionLogin {
    /// The `iss` of the ID token.
    pub issuer: String,
    /// The `sub` of the ID token.
    pub subject: Option<String>,
    /// The `sid` of the ID token.
    pub session_id: Option<String>,
    /// When the user logged in, seconds since the epoch.
    pub logged_in_at: u64,
}

impl SsfSessionLogin {
    /// A login now.
    pub fn new(issuer: impl Into<String>, subject: Option<&str>, session_id: Option<&str>) -> Self {
        Self {
            issuer: issuer.into(),
            subject: subject.map(str::to_owned),
            session_id: session_id.map(str::to_owned),
            logged_in_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// The login as the claims the revocation store checks.
    pub fn claims(&self) -> SsfTokenClaims {
        SsfTokenClaims {
            issuer: Some(self.issuer.clone()),
            subject: self.subject.clone(),
            session_id: self.session_id.clone(),
            issued_at: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(self.logged_in_at)),
        }
    }
}

/// Records the login in the session, for [`SsfSessionRevocationLayer`] to check.
pub async fn record_login(session: &Session, login: &SsfSessionLogin) -> Result<(), tower_sessions::session::Error> {
    session.insert(SESSION_KEY, login).await
}

/// The login recorded in the session, if any.
pub async fn login(session: &Session) -> Result<Option<SsfSessionLogin>, tower_sessions::session::Error> {
    session.get(SESSION_KEY).await
}

/// Flushes a session whose login a security event revoked, see the [module](self) documentation.
#[derive(Clone)]
pub struct SsfSessionRevocationLayer {
    store: Arc<dyn SsfTokenRevocationStore>,
}

impl SsfSessionRevocationLayer {
    /// A layer that checks the logins against `store`.
    pub fn new(store: impl SsfTokenRevocationStore) -> Self {
        Self { store: Arc::new(store) }
    }
}

impl<S> Layer<S> for SsfSessionRevocationLayer {
    type Service = SsfSessionRevocationService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SsfSessionRevocationService {
            inner,
            store: self.store.clone(),
        }
    }
}

/// The service of [`SsfSessionRevocationLayer`].
#[derive(Clone)]
pub struct SsfSessionRevocationService<S> {
    inner: S,
    store: Arc<dyn SsfTokenRevocationStore>,
}

impl<S, B> Service<Request<B>> for SsfSessionRevocationService<S>
where
    S: Service<Request<B>, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
    B: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let session = request.extensions().get::<Session>().cloned();
        let store = self.store.clone();
        Box::pin(async move {
            if let Some(session) = session {
                match login(&session).await {
                    Ok(Some(login)) => match store.is_revoked(&login.claims()).await {
                        Ok(false) => {}
                        Ok(true) => {
                            tracing::info!(
                                subject = login.subject.as_deref().unwrap_or(""),
                                "Ending the revoked session"
                            );
                            if let Err(error) = session.flush().await {
                                tracing::error!(%error, "Could not end the revoked session, rejecting the request");
                                return Ok(StatusCode::SERVICE_UNAVAILABLE.into_response());
                            }
                        }
                        // fail closed
                        Err(error) => {
                            tracing::error!(%error, "The revocation store failed, rejecting the request");
                            return Ok(StatusCode::SERVICE_UNAVAILABLE.into_response());
                        }
                    },
                    Ok(None) => {}
                    Err(error) => tracing::warn!(%error, "Could not read the login from the session"),
                }
            }
            inner.call(request).await
        })
    }
}
