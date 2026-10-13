//! The easyssf receiver for actix-web: the push endpoint, the token revocation middleware for
//! resource servers, and (feature `actix-session`) the middleware that ends sessions a security
//! event revoked.
//!
//! actix-web builds the `App` once per worker thread. Build the receiver once, outside the
//! `HttpServer::new` closure, and share it as `web::Data`; built inside, every worker would
//! register the stream and poll on its own.
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use actix_web::{App, HttpMessage, HttpServer, web};
//! # use easyssf_receiver::{SsfReceiver, revocation::SsfTokenClaims};
//! # use easyssf_receiver_actix_web::{SsfRevocation, configure_push_for};
//! # async fn serve(receiver: SsfReceiver) -> std::io::Result<()> {
//! let receiver = Arc::new(receiver);            // once, outside the closure
//! receiver.start();
//! HttpServer::new(move || {
//!     App::new()
//!         .configure(configure_push_for(&receiver)) // POST /ssf/push, or easyssf.receiver.push.endpoint-path
//!         .service(
//!             web::scope("/api")
//!                 // inside the middleware that validates the access token and leaves its claims in the extensions
//!                 .wrap(SsfRevocation::new(receiver.token_revocation_store(), |request| {
//!                     request.extensions().get::<SsfTokenClaims>().cloned()
//!                 }))
//!                 .route("/orders", web::get().to(|| async { "orders" })),
//!         )
//! })
//! .bind(("127.0.0.1", 8080))?
//! .run()
//! .await
//! # }
//! ```

use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;

use actix_web::body::EitherBody;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready};
use actix_web::http::StatusCode;
use actix_web::http::header::{CONTENT_LANGUAGE, CONTENT_TYPE, WWW_AUTHENTICATE};
use actix_web::{Error, HttpRequest, HttpResponse, web};
use easyssf_receiver::SsfReceiver;
use easyssf_receiver::push::{SsfPushHandler, SsfPushResponse};
use easyssf_receiver::revocation::{SsfTokenClaims, SsfTokenRevocationStore};

#[cfg(feature = "actix-session")]
pub mod sessions;

/// Where [`configure_push`] mounts the endpoint.
pub const DEFAULT_PUSH_PATH: &str = "/ssf/push";

/// Configures `POST /ssf/push` for `App::configure`. Not behind the authentication of the
/// application: the transmitter authenticates with its `Authorization` header and the SET with
/// its signature.
pub fn configure_push(handler: SsfPushHandler) -> impl Fn(&mut web::ServiceConfig) + Clone {
    configure_push_at(DEFAULT_PUSH_PATH.to_owned(), handler)
}

/// Configures the push endpoint at `path` for `App::configure`.
pub fn configure_push_at(path: String, handler: SsfPushHandler) -> impl Fn(&mut web::ServiceConfig) + Clone {
    move |cfg: &mut web::ServiceConfig| {
        cfg.service(
            web::resource(path.clone())
                .app_data(web::Data::new(handler.clone()))
                .app_data(web::PayloadConfig::new(SsfPushHandler::MAX_SET_SIZE + 1))
                .route(web::post().to(push)),
        );
    }
}

/// Configures the push endpoint of a configured receiver, at
/// `easyssf.receiver.push.endpoint-path`, for `App::configure`.
pub fn configure_push_for(receiver: &SsfReceiver) -> impl Fn(&mut web::ServiceConfig) + Clone {
    tracing::info!(path = receiver.push_endpoint_path(), "Receiving SSF security events");
    configure_push_at(receiver.push_endpoint_path().to_owned(), receiver.push_handler())
}

async fn push(handler: web::Data<SsfPushHandler>, request: HttpRequest, body: web::Bytes) -> HttpResponse {
    let authorization = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let handler = handler.get_ref().clone();
    // the handlers run to completion even when the transmitter disconnects, which drops this
    // future at whatever await it reached; a panic becomes a 500 with the claim left to the lease
    let processing = tokio::spawn(async move { handler.handle(authorization.as_deref(), &body).await });
    match processing.await {
        Ok(response) => into_response(response),
        Err(error) => {
            tracing::error!(%error, "Processing the pushed SET panicked");
            HttpResponse::InternalServerError().finish()
        }
    }
}

/// Turns the response of the push handler into an HTTP response, with the headers of RFC 8935.
pub fn into_response(response: SsfPushResponse) -> HttpResponse {
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    match response.body {
        // RFC 8935, section 2.3
        Some(body) => HttpResponse::build(status)
            .insert_header((CONTENT_TYPE, SsfPushResponse::CONTENT_TYPE))
            .insert_header((CONTENT_LANGUAGE, SsfPushResponse::CONTENT_LANGUAGE))
            .body(body),
        None => HttpResponse::build(status).finish(),
    }
}

/// Reads the claims of the access token from a request.
pub type ClaimsReader = Arc<dyn Fn(&HttpRequest) -> Option<SsfTokenClaims> + Send + Sync>;

/// Rejects requests whose access token or session an SSF event revoked.
///
/// It does not validate tokens: the reader returns what the authentication middleware of the
/// application left on the request (actix-web-httpauth, an extractor of your own on
/// jsonwebtoken, ...), so the middleware works with any of them. A request without claims
/// passes; whether anonymous requests are allowed is for the application to decide. Wrap it
/// inside the authentication middleware.
#[derive(Clone)]
pub struct SsfRevocation {
    store: Arc<dyn SsfTokenRevocationStore>,
    claims: ClaimsReader,
}

impl SsfRevocation {
    /// A middleware that looks the claims `claims` returns up in `store`.
    pub fn new(
        store: impl SsfTokenRevocationStore,
        claims: impl Fn(&HttpRequest) -> Option<SsfTokenClaims> + Send + Sync + 'static,
    ) -> Self {
        Self {
            store: Arc::new(store),
            claims: Arc::new(claims),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for SsfRevocation
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = SsfRevocationMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SsfRevocationMiddleware {
            service: Rc::new(service),
            store: self.store.clone(),
            claims: self.claims.clone(),
        }))
    }
}

/// The service of [`SsfRevocation`].
pub struct SsfRevocationMiddleware<S> {
    service: Rc<S>,
    store: Arc<dyn SsfTokenRevocationStore>,
    claims: ClaimsReader,
}

impl<S, B> Service<ServiceRequest> for SsfRevocationMiddleware<S>
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
        let claims = (self.claims)(request.request());
        Box::pin(async move {
            if let Some(claims) = claims {
                match store.is_revoked(&claims).await {
                    Ok(false) => {}
                    Ok(true) => {
                        tracing::debug!(
                            subject = claims.subject.as_deref().unwrap_or(""),
                            "Rejecting a revoked access token"
                        );
                        let challenge = r#"Bearer error="invalid_token", error_description="The token was revoked""#;
                        let response = HttpResponse::Unauthorized()
                            .insert_header((WWW_AUTHENTICATE, challenge))
                            .finish();
                        return Ok(request.into_response(response).map_into_right_body());
                    }
                    // fail closed: a store that cannot answer must not let a revoked token through
                    Err(error) => {
                        tracing::error!(%error, "The revocation store failed, rejecting the request");
                        return Ok(request
                            .into_response(HttpResponse::ServiceUnavailable().finish())
                            .map_into_right_body());
                    }
                }
            }
            service
                .call(request)
                .await
                .map(|response| response.map_into_left_body())
        })
    }
}
