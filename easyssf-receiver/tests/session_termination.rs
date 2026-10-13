//! `SsfSessionTerminationEventHandlerTests` and `SsfSubjectClaimsMatcherTests` of the Java library.

mod common;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use common::processor;
use easyssf_core::{SsfDeliveryMethod, SsfSubject};
use easyssf_receiver::BoxError;
use easyssf_receiver::session::subject_claims_matcher::{DEFAULT_SCIM_ATTRIBUTE_CLAIMS, matches, matches_with};
use easyssf_receiver::session::{SsfSessionTerminationEventHandler, SsfSessionTerminator};
use easyssf_test::TestTransmitter;
use easyssf_test::subjects::{self, aliases, complex, complex_members, email, iss_sub, opaque, phone_number, scim};
use serde_json::{Map, Value, json};

const IDP: &str = "https://idp.example";

/// Sessions by (claims) that a terminator ends when the subject matches.
#[derive(Default)]
struct Sessions {
    logged_in: Mutex<Vec<Map<String, Value>>>,
    terminated: Mutex<Vec<SsfSubject>>,
}

#[async_trait]
impl SsfSessionTerminator for Sessions {
    async fn terminate_sessions(&self, subject: &SsfSubject) -> Result<usize, BoxError> {
        self.terminated.lock().unwrap().push(subject.clone());
        let mut sessions = self.logged_in.lock().unwrap();
        let before = sessions.len();
        sessions.retain(|claims| !matches(subject, claims, None));
        Ok(before - sessions.len())
    }
}

fn claims(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn subject(identifier: Map<String, Value>) -> SsfSubject {
    SsfSubject::from(Some(&identifier))
}

async fn login_and_handle(
    transmitter: &TestTransmitter,
    sessions: &Arc<Sessions>,
    event_type: &str,
    subject: Map<String, Value>,
) -> usize {
    sessions.terminated.lock().unwrap().clear();
    *sessions.logged_in.lock().unwrap() = vec![
        claims(json!({ "iss": IDP, "sub": "alice", "sid": "s1" })),
        claims(json!({ "iss": IDP, "sub": "alice", "sid": "s2" })),
        claims(json!({ "iss": IDP, "sub": "bob", "sid": "s3" })),
    ];
    let processor = processor(transmitter).handler(SsfSessionTerminationEventHandler::new(sessions.clone()));
    processor
        .process(&transmitter.set(event_type, Some(subject)), SsfDeliveryMethod::Push)
        .await
        .unwrap();
    3 - sessions.logged_in.lock().unwrap().len()
}

#[tokio::test]
async fn session_event_terminates_the_session_named() {
    let transmitter = TestTransmitter::new();
    let sessions = Arc::new(Sessions::default());
    let terminated = login_and_handle(
        &transmitter,
        &sessions,
        "CaepSessionRevoked",
        complex(Some(iss_sub(IDP, "alice")), Some(opaque("s1"))),
    )
    .await;
    assert_eq!(terminated, 1);
    assert_eq!(sessions.terminated.lock().unwrap()[0].session_id(), Some("s1"));
    // naming only the user ends all sessions of the user
    let terminated = login_and_handle(&transmitter, &sessions, "CaepSessionRevoked", iss_sub(IDP, "alice")).await;
    assert_eq!(terminated, 2);
}

#[tokio::test]
async fn user_event_terminates_all_sessions_of_the_user() {
    let transmitter = TestTransmitter::new();
    let sessions = Arc::new(Sessions::default());
    let terminated = login_and_handle(
        &transmitter,
        &sessions,
        "CaepCredentialChange",
        complex(Some(iss_sub(IDP, "alice")), Some(opaque("s1"))),
    )
    .await;
    assert_eq!(
        terminated, 2,
        "the session of the event is ignored, the user is widened"
    );
    assert_eq!(sessions.terminated.lock().unwrap()[0].session_id(), None);
}

#[tokio::test]
async fn scim_deactivate_and_delete_terminate_the_sessions_of_the_resource() {
    let transmitter = TestTransmitter::new();
    let sessions = Arc::new(Sessions::default());
    let handler = SsfSessionTerminationEventHandler::with_event_types(
        sessions.clone(),
        &["CaepSessionRevoked".to_owned()],
        &["ScimProvDeactivate".to_owned(), "ScimProvDelete".to_owned()],
    );
    *sessions.logged_in.lock().unwrap() = vec![claims(json!({ "iss": IDP, "sub": "ext-alice", "sid": "s1" }))];
    let processor = processor(&transmitter).handler(handler);
    let set = transmitter.set(
        "ScimProvDeactivate",
        Some(subjects::scim_with_external_id("/Users/42", Some("ext-alice"))),
    );
    processor.process(&set, SsfDeliveryMethod::Push).await.unwrap();
    assert!(sessions.logged_in.lock().unwrap().is_empty());
}

#[tokio::test]
async fn event_without_subject_terminates_nothing() {
    let transmitter = TestTransmitter::new();
    let sessions = Arc::new(Sessions::default());
    *sessions.logged_in.lock().unwrap() = vec![claims(json!({ "iss": IDP, "sub": "alice", "sid": "s1" }))];
    let processor = processor(&transmitter).handler(SsfSessionTerminationEventHandler::new(sessions.clone()));
    // a subject without a format resolves to nothing
    let set = transmitter.set("CaepSessionRevoked", Some(claims(json!({ "sub": "alice" }))));
    processor.process(&set, SsfDeliveryMethod::Push).await.unwrap();
    assert!(sessions.terminated.lock().unwrap().is_empty());
    assert_eq!(sessions.logged_in.lock().unwrap().len(), 1);
}

// SsfSubjectClaimsMatcherTests

#[test]
fn session_subject_matches_that_session_only() {
    let subject = subject(complex(Some(iss_sub(IDP, "alice")), Some(opaque("s1"))));
    assert!(matches(
        &subject,
        &claims(json!({ "iss": IDP, "sub": "alice", "sid": "s1" })),
        None
    ));
    assert!(!matches(
        &subject,
        &claims(json!({ "iss": IDP, "sub": "alice", "sid": "s2" })),
        None
    ));
    assert!(!matches(&subject, &claims(json!({ "iss": IDP, "sub": "alice" })), None));
    // the user is not compared when a session is named
    assert!(matches(
        &subject,
        &claims(json!({ "iss": IDP, "sub": "bob", "sid": "s1" })),
        None
    ));
}

#[test]
fn session_subject_matches_only_at_the_issuer_of_its_user() {
    let subject = subject(complex(Some(iss_sub(IDP, "alice")), Some(opaque("s1"))));
    assert!(!matches(
        &subject,
        &claims(json!({ "iss": "https://other.example", "sid": "s1" })),
        None
    ));
    assert!(!matches(&subject, &claims(json!({ "sid": "s1" })), None));
    // a session without an issuer matches any
    let no_issuer = self::subject(complex(None, Some(opaque("s1"))));
    assert!(matches(&no_issuer, &claims(json!({ "sid": "s1" })), None));
    // or the issuer of an iss_sub session identifier
    let session_with_issuer = self::subject(complex(None, Some(iss_sub(IDP, "s1"))));
    assert!(matches(
        &session_with_issuer,
        &claims(json!({ "iss": IDP, "sid": "s1" })),
        None
    ));
    assert!(!matches(
        &session_with_issuer,
        &claims(json!({ "iss": "https://other.example", "sid": "s1" })),
        None
    ));
}

#[test]
fn user_subject_matches_subject_of_that_issuer() {
    let subject = subject(iss_sub(IDP, "alice"));
    assert!(matches(
        &subject,
        &claims(json!({ "iss": IDP, "sub": "alice", "sid": "s1" })),
        None
    ));
    assert!(matches(
        &subject,
        &claims(json!({ "iss": IDP, "sub": "alice", "sid": "s2" })),
        None
    ));
    assert!(!matches(&subject, &claims(json!({ "iss": IDP, "sub": "bob" })), None));
}

#[test]
fn email_subject_matches_ignoring_case() {
    let subject = subject(email("Alice@Example.com"));
    assert!(matches(
        &subject,
        &claims(json!({ "email": "alice@example.com" })),
        None
    ));
    assert!(!matches(&subject, &claims(json!({ "email": "bob@example.com" })), None));
    assert!(!matches(&subject, &claims(json!({ "sub": "Alice@Example.com" })), None));
}

#[test]
fn opaque_subject_matches_session_or_user() {
    let subject = subject(opaque("xyz"));
    assert!(matches(&subject, &claims(json!({ "sid": "xyz" })), None));
    assert!(matches(&subject, &claims(json!({ "sub": "xyz" })), None));
    assert!(!matches(&subject, &claims(json!({ "sub": "abc", "sid": "def" })), None));
}

#[test]
fn name_is_used_when_claims_have_no_subject() {
    let subject = subject(iss_sub(IDP, "alice"));
    assert!(matches(&subject, &claims(json!({ "iss": IDP })), Some("alice")));
    assert!(!matches(&subject, &claims(json!({ "iss": IDP })), Some("bob")));
    assert!(
        !matches(&subject, &claims(json!({ "iss": IDP, "sub": "bob" })), Some("alice")),
        "a sub claim wins over the name"
    );
}

#[test]
fn iss_sub_requires_the_issuer_of_the_claims() {
    let subject = subject(iss_sub(IDP, "alice"));
    assert!(!matches(&subject, &claims(json!({ "sub": "alice" })), None));
    assert!(!matches(
        &subject,
        &claims(json!({ "iss": "https://other.example", "sub": "alice" })),
        None
    ));
}

#[test]
fn phone_number_and_other_formats_match_the_claim_of_the_same_name() {
    assert!(matches(
        &subject(phone_number("+15555550123")),
        &claims(json!({ "phone_number": "+15555550123" })),
        None
    ));
    assert!(!matches(
        &subject(phone_number("+15555550123")),
        &claims(json!({ "phone_number": "+15555550124" })),
        None
    ));
    let custom = subject(claims(json!({ "format": "employee_id", "employee_id": "E-1" })));
    assert!(
        !matches(&custom, &claims(json!({ "employee_id": "E-1" })), None),
        "an unknown format has no value"
    );
    assert!(matches(
        &subject(subjects::did("did:example:1")),
        &claims(json!({ "did": "did:example:1" })),
        None
    ));
}

#[test]
fn aliases_match_if_any_identifier_does() {
    let subject = subject(aliases(vec![iss_sub(IDP, "alice"), email("alice@example.com")]));
    assert!(matches(
        &subject,
        &claims(json!({ "email": "ALICE@example.com" })),
        None
    ));
    assert!(matches(&subject, &claims(json!({ "iss": IDP, "sub": "alice" })), None));
    assert!(!matches(&subject, &claims(json!({ "iss": IDP, "sub": "bob" })), None));
}

#[test]
fn scim_resource_matches_by_external_id_or_id_against_the_subject() {
    let subject = subject(subjects::scim_with_external_id("/Users/42", Some("ext-alice")));
    assert!(matches(&subject, &claims(json!({ "sub": "ext-alice" })), None));
    assert!(matches(&subject, &claims(json!({ "sub": "42" })), None));
    assert!(!matches(&subject, &claims(json!({ "sub": "bob" })), None));
    assert!(matches(&subject, &claims(json!({})), Some("42")));
}

#[test]
fn scim_resource_matches_by_user_name_against_the_preferred_username() {
    let subject = subject(claims(
        json!({ "format": "scim", "uri": "/Users/42", "userName": "alice" }),
    ));
    assert!(matches(
        &subject,
        &claims(json!({ "preferred_username": "alice" })),
        None
    ));
    assert!(!matches(
        &subject,
        &claims(json!({ "preferred_username": "bob" })),
        None
    ));
}

#[test]
fn scim_attribute_claims_are_configurable() {
    let subject = subject(claims(
        json!({ "format": "scim", "uri": "/Users/42", "userName": "alice", "externalId": "ext" }),
    ));
    let pairs = vec![("userName".to_owned(), "sub".to_owned())];
    assert!(matches_with(&subject, &claims(json!({ "sub": "alice" })), None, &pairs));
    assert!(!matches_with(&subject, &claims(json!({ "sub": "ext" })), None, &pairs));
    assert_eq!(DEFAULT_SCIM_ATTRIBUTE_CLAIMS.len(), 3);
}

#[test]
fn multi_valued_scim_attributes_match_by_any_value() {
    let subject = subject(claims(json!({
        "format": "scim", "uri": "/Users/42",
        "emails": [{ "value": "Alice@Example.com", "primary": true }, "alias@example.com", 3]
    })));
    let pairs = vec![("emails".to_owned(), "email".to_owned())];
    assert!(matches_with(
        &subject,
        &claims(json!({ "email": "alice@example.com" })),
        None,
        &pairs
    ));
    assert!(matches_with(
        &subject,
        &claims(json!({ "email": "alias@example.com" })),
        None,
        &pairs
    ));
    assert!(!matches_with(
        &subject,
        &claims(json!({ "email": "bob@example.com" })),
        None,
        &pairs
    ));
}

#[test]
fn complex_subject_with_other_members_only_does_not_match() {
    let subject = subject(complex_members(vec![
        ("device", opaque("d1")),
        ("tenant", opaque("t1")),
    ]));
    assert!(!matches(
        &subject,
        &claims(json!({ "iss": IDP, "sub": "alice", "sid": "d1" })),
        None
    ));
    assert!(!matches(&SsfSubject::empty(), &claims(json!({ "sub": "alice" })), None));
    assert!(!matches(
        &self::subject(scim("/Users/42")),
        &claims(json!({ "sub": "43" })),
        None
    ));
}
