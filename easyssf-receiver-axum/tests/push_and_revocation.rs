//! The push endpoint and the revocation layer, end to end through an axum router.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use axum::Router;
use axum::body::Body;
use axum::routing::get;
use easyssf_receiver::BoxError;
use easyssf_receiver::event::{SsfEventContext, for_event};
use easyssf_receiver::push::SsfPushHandler;
use easyssf_receiver::revocation::{InMemorySsfTokenRevocationStore, SsfTokenClaims, SsfTokenRevocationEventHandler};
use easyssf_receiver::set::{InMemorySsfJtiDedupStore, JwtSsfSetVerifier, SsfSetProcessor, SsfSetVerifierOptions};
use easyssf_receiver_axum::{SsfRevocationLayer, push_router};
use easyssf_test::subjects::{complex, iss_sub, opaque};
use easyssf_test::{TestSigningKey, TestTransmitter};
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const AUDIENCE: &str = "https://my-app.example";
const PUSH_SECRET: &str = "Bearer s3cr3t";

struct Receiver {
    transmitter: TestTransmitter,
    app: Router,
    handled: Arc<AtomicUsize>,
}

fn receiver() -> Receiver {
    let transmitter = TestTransmitter::new();
    let options = SsfSetVerifierOptions {
        expected_audiences: vec![AUDIENCE.to_owned()],
        ..Default::default()
    };
    let verifier = JwtSsfSetVerifier::new(transmitter.issuer(), Arc::new(transmitter.jwk_set()), options);

    let revocations = Arc::new(InMemorySsfTokenRevocationStore::default());
    let handled = Arc::new(AtomicUsize::new(0));
    let counter = handled.clone();
    let processor = SsfSetProcessor::new(verifier, InMemorySsfJtiDedupStore::default())
        .handler(SsfTokenRevocationEventHandler::new(revocations.clone()))
        .handler(for_event("CaepSessionRevoked", move |context: SsfEventContext| {
            let counter = counter.clone();
            async move {
                if context.subject().subject() == Some("fails") {
                    return Err(BoxError::from("handler failed"));
                }
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }));
    let push_handler = SsfPushHandler::new(Arc::new(processor), Some(PUSH_SECRET));

    // stands in for the JWT layer of the application: claims arrive in a header
    let fake_authentication =
        axum::middleware::from_fn(|mut request: Request<Body>, next: axum::middleware::Next| async move {
            if let Some(sid) = request
                .headers()
                .get("x-sid")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
            {
                request.extensions_mut().insert(SsfTokenClaims {
                    issuer: Some("https://transmitter.example/realms/test".to_owned()),
                    subject: Some("alice".to_owned()),
                    session_id: Some(sid),
                    issued_at: Some(SystemTime::now()),
                });
            }
            next.run(request).await
        });
    let app = Router::new()
        .route("/api", get(|| async { "ok" }))
        .layer(SsfRevocationLayer::new(revocations, |parts| {
            parts.extensions.get::<SsfTokenClaims>().cloned()
        }))
        .layer(fake_authentication)
        .merge(push_router(push_handler));
    Receiver {
        transmitter,
        app,
        handled,
    }
}

impl Receiver {
    fn session_revoked(&self, sub: &str, session: &str) -> serde_json::Map<String, Value> {
        let subject = complex(Some(iss_sub(self.transmitter.issuer(), sub)), Some(opaque(session)));
        let mut claims = self.transmitter.set_claims("CaepSessionRevoked", Some(subject));
        claims.insert("aud".to_owned(), json!(AUDIENCE));
        claims
    }

    async fn push(&self, authorization: Option<&str>, encoded_set: String) -> (StatusCode, Value) {
        let mut request = Request::post("/ssf/push").header("content-type", "application/secevent+jwt");
        if let Some(authorization) = authorization {
            request = request.header("authorization", authorization);
        }
        let response = self
            .app
            .clone()
            .oneshot(request.body(Body::from(encoded_set)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    async fn api(&self, sid: &str) -> StatusCode {
        let request = Request::get("/api").header("x-sid", sid).body(Body::empty()).unwrap();
        self.app.clone().oneshot(request).await.unwrap().status()
    }
}

#[tokio::test]
async fn rejects_push_without_the_expected_authorization_header() {
    let receiver = receiver();
    let set = receiver
        .transmitter
        .sign_set(&receiver.session_revoked("alice", "session-1"));
    assert_eq!(receiver.push(None, set.clone()).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        receiver.push(Some("Bearer wrong"), set).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(receiver.handled.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rejects_set_signed_with_unknown_key() {
    let receiver = receiver();
    let other = TestSigningKey::generate(2048, "other-key");
    let set = TestTransmitter::sign(
        &other,
        Some("secevent+jwt"),
        &receiver.session_revoked("alice", "session-1"),
    );
    let (status, body) = receiver.push(Some(PUSH_SECRET), set).await;
    assert_eq!(
        (status, body["err"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_key"))
    );
}

#[tokio::test]
async fn rejects_set_signed_with_another_key_under_a_known_key_id() {
    let receiver = receiver();
    let forged = TestSigningKey::generate(2048, "test-key");
    let set = TestTransmitter::sign(
        &forged,
        Some("secevent+jwt"),
        &receiver.session_revoked("alice", "session-1"),
    );
    let (status, body) = receiver.push(Some(PUSH_SECRET), set).await;
    assert_eq!(
        (status, body["err"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_key"))
    );
    assert_eq!(receiver.handled.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn rejects_set_for_another_audience_issuer_or_type() {
    let receiver = receiver();
    let mut claims = receiver.session_revoked("alice", "session-1");
    claims.insert("aud".to_owned(), json!("https://other.example"));
    let (status, body) = receiver
        .push(Some(PUSH_SECRET), receiver.transmitter.sign_set(&claims))
        .await;
    assert_eq!(
        (status, body["err"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_audience"))
    );

    let mut claims = receiver.session_revoked("alice", "session-1");
    claims.insert("iss".to_owned(), json!("https://evil.example"));
    let (status, body) = receiver
        .push(Some(PUSH_SECRET), receiver.transmitter.sign_set(&claims))
        .await;
    assert_eq!(
        (status, body["err"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_issuer"))
    );

    let claims = receiver.session_revoked("alice", "session-1");
    let plain_jwt = TestTransmitter::sign(receiver.transmitter.key(), Some("JWT"), &claims);
    let (status, body) = receiver.push(Some(PUSH_SECRET), plain_jwt).await;
    assert_eq!(
        (status, body["err"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_request"))
    );

    let mut claims = receiver.session_revoked("alice", "session-1");
    claims.remove("jti");
    let (status, body) = receiver
        .push(Some(PUSH_SECRET), receiver.transmitter.sign_set(&claims))
        .await;
    assert_eq!(
        (status, body["err"].as_str()),
        (StatusCode::BAD_REQUEST, Some("invalid_request"))
    );
}

#[tokio::test]
async fn accepts_set_hands_it_to_handlers_once_and_revokes_the_session() {
    let receiver = receiver();
    assert_eq!(receiver.api("session-1").await, StatusCode::OK);

    let set = receiver
        .transmitter
        .sign_set(&receiver.session_revoked("alice", "session-1"));
    assert_eq!(
        receiver.push(Some(PUSH_SECRET), set.clone()).await.0,
        StatusCode::ACCEPTED
    );
    assert_eq!(receiver.handled.load(Ordering::SeqCst), 1);

    // a redelivery is acknowledged and not handled again
    assert_eq!(receiver.push(Some(PUSH_SECRET), set).await.0, StatusCode::ACCEPTED);
    assert_eq!(receiver.handled.load(Ordering::SeqCst), 1);

    assert_eq!(receiver.api("session-1").await, StatusCode::UNAUTHORIZED);
    assert_eq!(receiver.api("session-2").await, StatusCode::OK);
}

#[tokio::test]
async fn failed_handler_leaves_the_set_for_redelivery() {
    let receiver = receiver();
    let set = receiver
        .transmitter
        .sign_set(&receiver.session_revoked("fails", "session-9"));
    assert_eq!(
        receiver.push(Some(PUSH_SECRET), set.clone()).await.0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    // not recorded as processed: the redelivery runs the handlers again
    assert_eq!(
        receiver.push(Some(PUSH_SECRET), set).await.0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    // the other handler ran all the same
    assert_eq!(receiver.api("session-9").await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rejects_body_larger_than_a_set() {
    let receiver = receiver();
    let (status, _) = receiver
        .push(Some(PUSH_SECRET), "a".repeat(SsfPushHandler::MAX_SET_SIZE + 1))
        .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn error_document_carries_the_headers_of_rfc_8935() {
    let receiver = receiver();
    let request = Request::post("/ssf/push")
        .header("authorization", PUSH_SECRET)
        .body(Body::from("garbage"))
        .unwrap();
    let response = receiver.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(response.headers()["content-language"], "en");
}
