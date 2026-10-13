//! Ends actix-session sessions a security event revoked (feature `actix-session`); the
//! counterpart of the cookie hook of the .NET port and of the OIDC client integration of the
//! Spring Boot starter.
//!
//! At login the application [records](record_login) who logged in and when, and
//! [`SsfSessionRevocation`] checks the revocation store on every request: a session whose user
//! or session id was revoked after the login is purged, and the request continues anonymous. The
//! revocation TTL has to cover the longest session lifetime.
//!
//! Wrap it *inside* the `SessionMiddleware`, so that the session is loaded before the check:
//! `App::new().wrap(SsfSessionRevocation::new(store)).wrap(session_middleware)`.

use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use actix_session::{Session, SessionExt};
use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::{Error, HttpResponse};
use easyssf_receiver::revocation::{SsfTokenClaims, SsfTokenRevocationStore};
use serde::{Deserialize, Serialize};

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

/// Records the login in the session, for [`SsfSessionRevocation`] to check.
pub fn record_login(session: &Session, login: &SsfSessionLogin) -> Result<(), actix_session::SessionInsertError> {
    session.insert(SESSION_KEY, login)
}

/// The login recorded in the session, if any.
pub fn login(session: &Session) -> Result<Option<SsfSessionLogin>, actix_session::SessionGetError> {
    session.get(SESSION_KEY)
}

/// Purges a session whose login a security event revoked, see the [module](self) documentation.
#[derive(Clone)]
pub struct SsfSessionRevocation {
    store: Arc<dyn SsfTokenRevocationStore>,
}

impl SsfSessionRevocation {
    /// A middleware that checks the logins against `store`.
    pub fn new(store: impl SsfTokenRevocationStore) -> Self {
        Self { store: Arc::new(store) }
    }
}

impl<S, B> Transform<S, ServiceRequest> for SsfSessionRevocation
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = SsfSessionRevocationMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SsfSessionRevocationMiddleware {
            service: Rc::new(service),
            store: self.store.clone(),
        }))
    }
}

/// The service of [`SsfSessionRevocation`].
pub struct SsfSessionRevocationMiddleware<S> {
    service: Rc<S>,
    store: Arc<dyn SsfTokenRevocationStore>,
}

impl<S, B> Service<ServiceRequest> for SsfSessionRevocationMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, request: ServiceRequest) -> Self::Future {
        let service = self.service.clone();
        let store = self.store.clone();
        let session = request.get_session();
        Box::pin(async move {
            match login(&session) {
                Ok(Some(login)) => match store.is_revoked(&login.claims()).await {
                    Ok(false) => {}
                    Ok(true) => {
                        tracing::info!(
                            subject = login.subject.as_deref().unwrap_or(""),
                            "Ending the revoked session"
                        );
                        session.purge();
                    }
                    // fail closed
                    Err(error) => {
                        tracing::error!(%error, "The revocation store failed, rejecting the request");
                        return Ok(request
                            .into_response(HttpResponse::ServiceUnavailable().finish())
                            .map_into_right_body());
                    }
                },
                Ok(None) => {}
                Err(error) => tracing::warn!(%error, "Could not read the login from the session"),
            }
            service
                .call(request)
                .await
                .map(|response| response.map_into_left_body())
        })
    }
}
