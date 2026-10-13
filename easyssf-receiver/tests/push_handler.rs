//! `SsfPushHandlerTests` of the Java library.

mod common;

use std::sync::Arc;

use common::{Recorder, processor, verifier};
use easyssf_receiver::BoxError;
use easyssf_receiver::event::SsfEventContext;
use easyssf_receiver::push::SsfPushHandler;
use easyssf_receiver::set::{InMemorySsfJtiDedupStore, SsfSetProcessor};
use easyssf_test::TestTransmitter;
use easyssf_test::subjects::iss_sub;
use serde_json::Value;

const SECRET: &str = "Bearer s3cr3t";

fn set(transmitter: &TestTransmitter) -> String {
    transmitter.set("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")))
}

fn handler(transmitter: &TestTransmitter, recorder: &Recorder) -> SsfPushHandler {
    SsfPushHandler::new(
        Arc::new(processor(transmitter).handler(recorder.handler())),
        Some(SECRET),
    )
}

fn error_code(body: &Option<String>) -> String {
    let body: Value = serde_json::from_str(body.as_deref().expect("an error document")).unwrap();
    body["err"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn accepts_and_handles_set() {
    let transmitter = TestTransmitter::new();
    let recorder = Recorder::default();
    let response = handler(&transmitter, &recorder)
        .handle(Some(SECRET), set(&transmitter).as_bytes())
        .await;
    assert_eq!(response.status, 202);
    assert!(response.is_accepted());
    assert!(response.body.is_none());
    assert_eq!(recorder.count(), 1);
}

#[tokio::test]
async fn accepts_duplicate_without_handling_it_again() {
    let transmitter = TestTransmitter::new();
    let recorder = Recorder::default();
    let handler = handler(&transmitter, &recorder);
    let set = set(&transmitter);
    handler.handle(Some(SECRET), set.as_bytes()).await;
    assert_eq!(handler.handle(Some(SECRET), set.as_bytes()).await.status, 202);
    assert_eq!(recorder.count(), 1);
}

#[tokio::test]
async fn rejects_transmitter_that_does_not_authenticate() {
    let transmitter = TestTransmitter::new();
    let recorder = Recorder::default();
    let handler = handler(&transmitter, &recorder);
    let set = set(&transmitter);
    for authorization in [None, Some("Bearer wrong"), Some("bearer s3cr3t"), Some("")] {
        let response = handler.handle(authorization, set.as_bytes()).await;
        assert_eq!(response.status, 401, "{authorization:?}");
        assert_eq!(error_code(&response.body), "authentication_failed");
    }
    assert_eq!(recorder.count(), 0);
    // without an expected header anything goes
    let open = SsfPushHandler::new(Arc::new(processor(&transmitter).handler(recorder.handler())), None);
    assert_eq!(open.handle(None, set.as_bytes()).await.status, 202);
}

#[tokio::test]
async fn rejects_invalid_set_with_error_document() {
    let transmitter = TestTransmitter::new();
    let recorder = Recorder::default();
    let handler = handler(&transmitter, &recorder);
    let mut claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    claims.insert("aud".to_owned(), Value::String("https://other.example".to_owned()));
    let response = handler
        .handle(Some(SECRET), transmitter.sign_set(&claims).as_bytes())
        .await;
    assert_eq!(response.status, 400);
    assert_eq!(error_code(&response.body), "invalid_audience");
    let body: Value = serde_json::from_str(response.body.as_deref().unwrap()).unwrap();
    assert!(body["description"].as_str().unwrap().contains("not addressed"));
    let response = handler.handle(Some(SECRET), b"garbage").await;
    assert_eq!(error_code(&response.body), "invalid_request");
    let response = handler.handle(Some(SECRET), &[0xff, 0xfe]).await;
    assert_eq!(
        (response.status, error_code(&response.body)),
        (400, "invalid_request".to_owned())
    );
    assert_eq!(recorder.count(), 0);
}

#[tokio::test]
async fn rejects_oversized_set() {
    let transmitter = TestTransmitter::new();
    let recorder = Recorder::default();
    let handler = handler(&transmitter, &recorder);
    let response = handler
        .handle(Some(SECRET), &vec![b'a'; SsfPushHandler::MAX_SET_SIZE + 1])
        .await;
    assert_eq!(response.status, 413);
    assert_eq!(error_code(&response.body), "invalid_request");
}

#[tokio::test]
async fn asks_for_redelivery_when_handler_fails() {
    let transmitter = TestTransmitter::new();
    let processor =
        Arc::new(processor(&transmitter).handler(|_: SsfEventContext| async { Err(BoxError::from("nope")) }));
    let handler = SsfPushHandler::new(processor, Some(SECRET));
    let response = handler.handle(Some(SECRET), set(&transmitter).as_bytes()).await;
    assert_eq!(response.status, 500);
    assert!(response.body.is_none());
}

#[tokio::test]
async fn asks_for_redelivery_while_transmitter_keys_are_unavailable() {
    let transmitter = TestTransmitter::new();
    transmitter.remove_document("/realms/test/jwks");
    let recorder = Recorder::default();
    let handler = handler(&transmitter, &recorder);
    let set = set(&transmitter);
    assert_eq!(handler.handle(Some(SECRET), set.as_bytes()).await.status, 503);
    transmitter.publish_jwks(&[transmitter.key()]);
    assert_eq!(handler.handle(Some(SECRET), set.as_bytes()).await.status, 202);
}

#[tokio::test]
async fn authenticates_every_transmitter_with_its_own_header() {
    let transmitter = TestTransmitter::new();
    let recorder = Recorder::default();
    let processor = Arc::new(
        SsfSetProcessor::new(verifier(&transmitter), InMemorySsfJtiDedupStore::new(10)).handler(recorder.handler()),
    );
    let issuer = transmitter.issuer().to_owned();
    let handler = SsfPushHandler::by_issuer(
        processor,
        Arc::new(move |iss| {
            if iss == issuer {
                Some("Bearer mine".to_owned())
            } else {
                None
            }
        }),
    );
    let set = set(&transmitter);
    assert_eq!(handler.handle(Some(SECRET), set.as_bytes()).await.status, 401);
    assert_eq!(handler.handle(Some("Bearer mine"), set.as_bytes()).await.status, 202);
    // a SET of an unknown issuer needs no header to be rejected as invalid_issuer
    let mut claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    claims.insert("iss".to_owned(), Value::String("https://unknown.example".to_owned()));
    let response = handler.handle(None, transmitter.sign_set(&claims).as_bytes()).await;
    assert_eq!(
        (response.status, error_code(&response.body)),
        (400, "invalid_issuer".to_owned())
    );
}
