//! `SsfTokenRevocationTests` of the Java library.

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use common::{TestClock, processor};
use easyssf_core::SsfDeliveryMethod;
use easyssf_receiver::revocation::{
    InMemorySsfTokenRevocationStore, SsfTokenClaims, SsfTokenRevocationEventHandler, SsfTokenRevocationStore,
};
use easyssf_test::TestTransmitter;
use easyssf_test::subjects::{complex, email, iss_sub, opaque};
use serde_json::{Map, Value, json};

const IDP: &str = "https://idp.example";

fn claims(issuer: &str, subject: Option<&str>, session: Option<&str>, issued_at: Option<SystemTime>) -> SsfTokenClaims {
    SsfTokenClaims {
        issuer: Some(issuer.to_owned()),
        subject: subject.map(str::to_owned),
        session_id: session.map(str::to_owned),
        issued_at,
    }
}

async fn revoke(
    transmitter: &TestTransmitter,
    store: Arc<InMemorySsfTokenRevocationStore>,
    event_type: &str,
    subject: Map<String, Value>,
) {
    let processor = processor(transmitter).handler(SsfTokenRevocationEventHandler::new(store));
    processor
        .process(&transmitter.set(event_type, Some(subject)), SsfDeliveryMethod::Push)
        .await
        .unwrap();
}

#[tokio::test]
async fn session_event_revokes_tokens_of_that_session_only() {
    let transmitter = TestTransmitter::new();
    let store = Arc::new(InMemorySsfTokenRevocationStore::default());
    revoke(
        &transmitter,
        store.clone(),
        "CaepSessionRevoked",
        complex(Some(iss_sub(IDP, "alice")), Some(opaque("s1"))),
    )
    .await;
    assert!(
        store
            .is_revoked(&claims(IDP, Some("alice"), Some("s1"), None))
            .await
            .unwrap()
    );
    assert!(
        !store
            .is_revoked(&claims(IDP, Some("alice"), Some("s2"), None))
            .await
            .unwrap()
    );
    assert!(!store.is_revoked(&claims(IDP, Some("alice"), None, None)).await.unwrap());
    assert!(store.is_session_revoked(IDP, "s1").await.unwrap());
}

#[tokio::test]
async fn user_event_revokes_tokens_issued_up_to_the_event() {
    let transmitter = TestTransmitter::new();
    let store = Arc::new(InMemorySsfTokenRevocationStore::default());
    let now = SystemTime::now();
    revoke(&transmitter, store.clone(), "CaepSessionRevoked", iss_sub(IDP, "alice")).await;
    assert!(
        store
            .is_revoked(&claims(IDP, Some("alice"), None, Some(now - Duration::from_secs(5))))
            .await
            .unwrap()
    );
    assert!(
        store
            .is_revoked(&claims(IDP, Some("alice"), Some("any"), None))
            .await
            .unwrap(),
        "without iat: revoked"
    );
    assert!(
        !store
            .is_revoked(&claims(IDP, Some("alice"), None, Some(now + Duration::from_secs(60))))
            .await
            .unwrap()
    );
    assert!(
        !store
            .is_revoked(&claims(IDP, Some("bob"), None, Some(now - Duration::from_secs(5))))
            .await
            .unwrap()
    );
    assert!(store.subject_revoked_at(IDP, "alice").await.unwrap().is_some());
}

#[tokio::test]
async fn opaque_subject_revokes_matching_session_and_subject() {
    let transmitter = TestTransmitter::new();
    let store = Arc::new(InMemorySsfTokenRevocationStore::default());
    revoke(&transmitter, store.clone(), "CaepSessionRevoked", opaque("xyz")).await;
    let issuer = transmitter.issuer();
    assert!(
        store
            .is_revoked(&claims(issuer, None, Some("xyz"), None))
            .await
            .unwrap()
    );
    assert!(
        store
            .is_revoked(&claims(
                issuer,
                Some("xyz"),
                None,
                Some(SystemTime::now() - Duration::from_secs(1))
            ))
            .await
            .unwrap()
    );
    assert!(
        !store
            .is_revoked(&claims(issuer, Some("other"), Some("other"), None))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn revocations_are_scoped_to_the_issuer() {
    let transmitter = TestTransmitter::new();
    let store = Arc::new(InMemorySsfTokenRevocationStore::default());
    revoke(
        &transmitter,
        store.clone(),
        "CaepSessionRevoked",
        complex(Some(iss_sub(IDP, "alice")), Some(opaque("s1"))),
    )
    .await;
    assert!(
        !store
            .is_revoked(&claims("https://other-idp.example", Some("alice"), Some("s1"), None))
            .await
            .unwrap()
    );
    assert!(
        !store
            .is_revoked(&SsfTokenClaims {
                issuer: None,
                subject: Some("alice".into()),
                session_id: Some("s1".into()),
                issued_at: None
            })
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn session_is_revoked_at_the_issuer_of_its_user() {
    let transmitter = TestTransmitter::new();
    let store = Arc::new(InMemorySsfTokenRevocationStore::default());
    revoke(
        &transmitter,
        store.clone(),
        "CaepSessionRevoked",
        complex(Some(iss_sub(IDP, "alice")), Some(opaque("s1"))),
    )
    .await;
    assert!(store.is_session_revoked(IDP, "s1").await.unwrap());
    assert!(!store.is_session_revoked(transmitter.issuer(), "s1").await.unwrap());
    // a session without a user is revoked at the transmitter
    revoke(
        &transmitter,
        store.clone(),
        "CaepSessionRevoked",
        complex(None, Some(opaque("s2"))),
    )
    .await;
    assert!(store.is_session_revoked(transmitter.issuer(), "s2").await.unwrap());
}

#[tokio::test]
async fn identifier_of_another_issuer_is_revoked_at_that_issuer() {
    let transmitter = TestTransmitter::new();
    let store = Arc::new(InMemorySsfTokenRevocationStore::default());
    revoke(
        &transmitter,
        store.clone(),
        "CaepSessionRevoked",
        iss_sub("https://third.example", "carol"),
    )
    .await;
    assert!(
        store
            .subject_revoked_at("https://third.example", "carol")
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .subject_revoked_at(transmitter.issuer(), "carol")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn ignores_other_events_and_subjects_without_session_or_subject() {
    let transmitter = TestTransmitter::new();
    let store = Arc::new(InMemorySsfTokenRevocationStore::default());
    revoke(
        &transmitter,
        store.clone(),
        "CaepCredentialChange",
        complex(Some(iss_sub(IDP, "alice")), Some(opaque("s1"))),
    )
    .await;
    assert!(!store.is_session_revoked(IDP, "s1").await.unwrap());
    revoke(
        &transmitter,
        store.clone(),
        "CaepSessionRevoked",
        email("alice@example.com"),
    )
    .await;
    assert!(
        !store
            .is_revoked(&claims(IDP, Some("alice@example.com"), None, None))
            .await
            .unwrap()
    );
    // user event types revoke the user even if the event names a session
    let handler =
        SsfTokenRevocationEventHandler::with_event_types(store.clone(), &[], &["CaepCredentialChange".to_owned()]);
    let processor = processor(&transmitter).handler(handler);
    let set = transmitter.set(
        "CaepCredentialChange",
        Some(complex(Some(iss_sub(IDP, "alice")), Some(opaque("s1")))),
    );
    processor.process(&set, SsfDeliveryMethod::Push).await.unwrap();
    assert!(!store.is_session_revoked(IDP, "s1").await.unwrap());
    assert!(store.subject_revoked_at(IDP, "alice").await.unwrap().is_some());
}

#[tokio::test]
async fn revocations_expire() {
    let clock = TestClock::new();
    let store = InMemorySsfTokenRevocationStore::new(Duration::from_secs(60)).with_clock(clock.clock());
    store.revoke_session(IDP, "s1").await.unwrap();
    store.revoke_subject(IDP, "alice", clock.now()).await.unwrap();
    clock.advance(Duration::from_secs(59));
    assert!(store.is_session_revoked(IDP, "s1").await.unwrap());
    assert!(store.subject_revoked_at(IDP, "alice").await.unwrap().is_some());
    clock.advance(Duration::from_secs(2));
    assert!(!store.is_session_revoked(IDP, "s1").await.unwrap());
    assert!(store.subject_revoked_at(IDP, "alice").await.unwrap().is_none());
}

#[tokio::test]
async fn event_delivered_late_does_not_shorten_more_recent_revocation() {
    let clock = TestClock::new();
    let store = InMemorySsfTokenRevocationStore::new(Duration::from_secs(3600)).with_clock(clock.clock());
    let now = clock.now();
    store.revoke_subject(IDP, "alice", now).await.unwrap();
    store
        .revoke_subject(IDP, "alice", now - Duration::from_secs(600))
        .await
        .unwrap();
    assert_eq!(store.subject_revoked_at(IDP, "alice").await.unwrap(), Some(now));
    assert!(
        store
            .is_revoked(&claims(IDP, Some("alice"), None, Some(now - Duration::from_secs(300))))
            .await
            .unwrap()
    );
    let _ = json!({});
}
