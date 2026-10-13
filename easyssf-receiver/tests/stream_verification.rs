//! `SsfStreamVerificationTests` of the Java library.

mod common;

use std::sync::{Arc, Mutex};

use common::{Recorder, processor};
use easyssf_core::{SsfDeliveryMethod, SsfEventToken, event_types};
use easyssf_receiver::event::SsfEventContext;
use easyssf_receiver::set::{SsfErrorCode, SsfSetProcessingError, SsfSetProcessorOptions, SsfSetVerificationError};
use easyssf_receiver::stream::SsfStreamVerification;
use easyssf_test::TestTransmitter;
use easyssf_test::subjects::{iss_sub, opaque};
use serde_json::{Map, Value, json};

fn verification_event(stream_id: Option<&str>, state: Option<&str>) -> SsfEventContext {
    let mut event = Map::new();
    if let Some(state) = state {
        event.insert("state".to_owned(), Value::String(state.to_owned()));
    }
    let mut claims = json!({ "jti": "1", "iss": "https://t.example", "iat": 1, "events": { event_types::SSF_STREAM_VERIFICATION: event } });
    if let Some(stream_id) = stream_id {
        claims["sub_id"] = Value::Object(opaque(stream_id));
    }
    SsfEventContext::new(
        SsfEventToken::from_claims(claims.as_object().unwrap().clone()).unwrap(),
        SsfDeliveryMethod::Push,
    )
}

fn for_stream(stream_id: &'static str) -> SsfStreamVerification {
    SsfStreamVerification::new().with_stream_id(move || Some(stream_id.to_owned()))
}

fn code(error: SsfSetVerificationError) -> SsfErrorCode {
    error.code().expect("a rejection")
}

#[test]
fn accepts_verification_event_that_echoes_the_requested_state() {
    let verification = for_stream("s-1");
    let state = verification.new_state();
    assert!(verification.is_pending());
    verification
        .validate(&verification_event(Some("s-1"), Some(&state)))
        .unwrap();
    assert!(!verification.is_pending());
}

#[test]
fn rejects_verification_event_with_another_state_than_the_requested_one() {
    let verification = for_stream("s-1");
    let _state = verification.new_state();
    let error = verification
        .validate(&verification_event(Some("s-1"), Some("other")))
        .unwrap_err();
    assert_eq!(code(error), SsfErrorCode::InvalidState);
    assert!(verification.is_pending(), "the request stays pending");
}

#[test]
fn accepts_verification_event_initiated_by_the_transmitter() {
    let verification = for_stream("s-1");
    verification.validate(&verification_event(Some("s-1"), None)).unwrap();
    let _state = verification.new_state();
    verification.validate(&verification_event(Some("s-1"), None)).unwrap();
}

#[test]
fn accepts_state_when_no_verification_was_requested_unless_strict() {
    let verification = for_stream("s-1");
    verification
        .validate(&verification_event(Some("s-1"), Some("transmitter-state")))
        .unwrap();
    let strict = for_stream("s-1").with_reject_unrequested_state(true);
    assert_eq!(
        code(
            strict
                .validate(&verification_event(Some("s-1"), Some("transmitter-state")))
                .unwrap_err()
        ),
        SsfErrorCode::InvalidState
    );
}

#[test]
fn rejects_verification_event_about_another_stream() {
    let verification = for_stream("s-1");
    assert_eq!(
        code(
            verification
                .validate(&verification_event(Some("s-2"), None))
                .unwrap_err()
        ),
        SsfErrorCode::InvalidRequest
    );
    // an iss_sub subject is not a stream either
    let claims = json!({ "jti": "1", "iss": "i", "iat": 1, "sub_id": iss_sub("i", "s-1"), "events": { event_types::SSF_STREAM_VERIFICATION: {} } });
    let context = SsfEventContext::new(
        SsfEventToken::from_claims(claims.as_object().unwrap().clone()).unwrap(),
        SsfDeliveryMethod::Push,
    );
    assert_eq!(
        code(verification.validate(&context).unwrap_err()),
        SsfErrorCode::InvalidRequest
    );
}

#[test]
fn rejects_verification_event_without_subject_id() {
    let verification = for_stream("s-1");
    assert_eq!(
        code(verification.validate(&verification_event(None, None)).unwrap_err()),
        SsfErrorCode::InvalidRequest
    );
}

#[test]
fn does_not_check_the_stream_while_it_is_unknown() {
    let verification = SsfStreamVerification::new();
    verification
        .validate(&verification_event(Some("whatever"), None))
        .unwrap();
    verification.validate(&verification_event(None, None)).unwrap();
}

#[test]
fn ignores_other_events() {
    let verification = for_stream("s-1");
    let _state = verification.new_state();
    let claims = json!({ "jti": "1", "iss": "i", "iat": 1, "sub_id": iss_sub("i", "alice"), "events": { event_types::CAEP_SESSION_REVOKED: { "state": "x" } } });
    let context = SsfEventContext::new(
        SsfEventToken::from_claims(claims.as_object().unwrap().clone()).unwrap(),
        SsfDeliveryMethod::Push,
    );
    verification.validate(&context).unwrap();
    assert!(verification.is_pending());
}

#[tokio::test]
async fn processor_rejects_invalid_verification_event_without_handling_or_remembering_it() {
    let transmitter = TestTransmitter::new();
    let verification = Arc::new(for_stream("s-1"));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorder = Recorder(seen);
    let lookup = verification.clone();
    let processor = processor(&transmitter)
        .options(SsfSetProcessorOptions {
            stream_verifications: Some(Arc::new(move |_| Some(lookup.clone()))),
            ..SsfSetProcessorOptions::default()
        })
        .handler(recorder.handler());
    let mut payload = Map::new();
    payload.insert("state".to_owned(), Value::String("unexpected".to_owned()));
    let _pending = verification.new_state();
    let claims = transmitter.set_claims_with_payload("SsfStreamVerification", Some(opaque("s-1")), payload);
    let set = transmitter.sign_set(&claims);
    let error = processor.process(&set, SsfDeliveryMethod::Push).await.unwrap_err();
    assert!(matches!(
        error,
        SsfSetProcessingError::Verification(SsfSetVerificationError::Rejected {
            code: SsfErrorCode::InvalidState,
            ..
        })
    ));
    assert_eq!(recorder.count(), 0);
    // a valid one is handled, and the SET was not remembered as processed by the rejection
    let claims = transmitter.set_claims_with_payload("SsfStreamVerification", Some(opaque("s-1")), Map::new());
    processor
        .process(&transmitter.sign_set(&claims), SsfDeliveryMethod::Push)
        .await
        .unwrap();
    assert_eq!(recorder.count(), 1);
}
