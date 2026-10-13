//! The easyssf receiver for axum, and through tower for tonic, Loco, Leptos and everything else
//! that runs on it: the push endpoint, the token revocation layer for resource servers, and
//! (feature `tower-sessions`) the layer that ends sessions a security event revoked.
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use easyssf_receiver::{SsfReceiver, config::SsfReceiverConfig, revocation::SsfTokenClaims};
//! # use easyssf_receiver_axum::{SsfRevocationLayer, push_router_for};
//! # fn app(receiver: &SsfReceiver) -> axum::Router {
//! axum::Router::new()
//!     .route("/api/orders", axum::routing::get(|| async { "orders" }))
//!     // after the layer that validates the access token and leaves its claims in the extensions
//!     .layer(SsfRevocationLayer::new(receiver.token_revocation_store(), |parts| {
//!         parts.extensions.get::<SsfTokenClaims>().cloned()
//!     }))
//!     .merge(push_router_for(receiver)) // POST /ssf/push, or easyssf.receiver.push.endpoint-path
//! # }
//! ```
//!
//! The push route runs the processing of a SET in a spawned task: axum drops the handler future
//! when the transmitter disconnects, and the handlers of the application must run to completion
//! regardless.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, post};
use easyssf_receiver::SsfReceiver;
use easyssf_receiver::push::{SsfPushHandler, SsfPushResponse};
use easyssf_receiver::revocation::{SsfTokenClaims, SsfTokenRevocationStore};
use http::header::{AUTHORIZATION, CONTENT_LANGUAGE, CONTENT_TYPE, WWW_AUTHENTICATE};
use http::request::Parts;
use http::{HeaderMap, Request, StatusCode};
use tower::{Layer, Service};

#[cfg(feature = "tower-sessions")]
pub mod sessions;

/// Where [`push_router`] mounts the endpoint.
pub const DEFAULT_PUSH_PATH: &str = "/ssf/push";

/// A router with `POST /ssf/push`. Not behind the authentication of the application: the
/// transmitter authenticates with its `Authorization` header and the SET with its signature.
pub fn push_router(handler: SsfPushHandler) -> Router {
    push_router_at(DEFAULT_PUSH_PATH, handler)
}

/// A router with the push endpoint at `path`.
pub fn push_router_at(path: &str, handler: SsfPushHandler) -> Router {
    Router::new().route(path, push_route(handler))
}

/// A router with the push endpoint of a configured receiver, at
/// `easyssf.receiver.push.endpoint-path`.
pub fn push_router_for(receiver: &SsfReceiver) -> Router {
    tracing::info!(path = receiver.push_endpoint_path(), "Receiving SSF security events");
    push_router_at(receiver.push_endpoint_path(), receiver.push_handler())
}

/// The push endpoint as a method router, to mount at a path of your own.
pub fn push_route<S: Clone + Send + Sync + 'static>(handler: SsfPushHandler) -> MethodRouter<S> {
    post(push)
        .layer(DefaultBodyLimit::max(SsfPushHandler::MAX_SET_SIZE + 1))
        .with_state(handler)
}

async fn push(State(handler): State<SsfPushHandler>, headers: HeaderMap, body: Bytes) -> Response {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    // the handlers run to completion even when the transmitter disconnects, which drops this
    // future at whatever await it reached; a panic becomes a 500 with the claim left to the lease
    let processing = tokio::spawn(async move { handler.handle(authorization.as_deref(), &body).await });
    match processing.await {
        Ok(response) => into_response(response),
        Err(error) => {
            tracing::error!(%error, "Processing the pushed SET panicked");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Turns the response of the push handler into an HTTP response, with the headers of RFC 8935.
pub fn into_response(response: SsfPushResponse) -> Response {
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    match response.body {
        // RFC 8935, section 2.3
        Some(body) => (
            status,
            [
                (CONTENT_TYPE, SsfPushResponse::CONTENT_TYPE),
                (CONTENT_LANGUAGE, SsfPushResponse::CONTENT_LANGUAGE),
            ],
            body,
        )
            .into_response(),
        None => status.into_response(),
    }
}

/// Rejects requests whose access token or session an SSF event revoked.
///
/// It does not validate tokens: `claims` reads what the authentication layer of the application
/// left on the request, so the layer works with any of them (jwt-authorizer, an extractor of your
/// own on jsonwebtoken, ...). A request without claims passes; whether anonymous requests are
/// allowed is for the application to decide. A plain tower layer over [`http::Request`], so it
/// wraps gRPC services of tonic as well.
#[derive(Clone)]
pub struct SsfRevocationLayer<F> {
    store: Arc<dyn SsfTokenRevocationStore>,
    claims: F,
}

impl<F> SsfRevocationLayer<F>
where
    F: Fn(&Parts) -> Option<SsfTokenClaims> + Clone,
{
    /// A layer that looks the claims `claims` returns up in `store`.
    pub fn new(store: impl SsfTokenRevocationStore, claims: F) -> Self {
        Self {
            store: Arc::new(store),
            claims,
        }
    }
}

impl<S, F: Clone> Layer<S> for SsfRevocationLayer<F> {
    type Service = SsfRevocationService<S, F>;

    fn layer(&self, inner: S) -> Self::Service {
        SsfRevocationService {
            inner,
            store: self.store.clone(),
            claims: self.claims.clone(),
        }
    }
}

/// The service of [`SsfRevocationLayer`].
#[derive(Clone)]
pub struct SsfRevocationService<S, F> {
    inner: S,
    store: Arc<dyn SsfTokenRevocationStore>,
    claims: F,
}

impl<S, F, B> Service<Request<B>> for SsfRevocationService<S, F>
where
    S: Service<Request<B>, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
    F: Fn(&Parts) -> Option<SsfTokenClaims> + Clone,
    B: Send + 'static,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        // the clone that was polled ready is the one to call
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let (parts, body) = request.into_parts();
        let claims = (self.claims)(&parts);
        let store = self.store.clone();
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
                        return Ok(
                            (StatusCode::UNAUTHORIZED, [(WWW_AUTHENTICATE, challenge)], Body::empty()).into_response(),
                        );
                    }
                    // fail closed: a store that cannot answer must not let a revoked token through
                    Err(error) => {
                        tracing::error!(%error, "The revocation store failed, rejecting the request");
                        return Ok(StatusCode::SERVICE_UNAVAILABLE.into_response());
                    }
                }
            }
            inner.call(Request::from_parts(parts, body)).await
        })
    }
}
