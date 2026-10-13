//! `SsfSetProcessorTests` of the Java library.

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use common::{Recorder, TestClock, processor, verifier};
use easyssf_core::{SsfDeliveryMethod, SsfEventToken};
use easyssf_receiver::BoxError;
use easyssf_receiver::event::SsfEventContext;
use easyssf_receiver::set::{
    InMemorySsfJtiDedupStore, SsfErrorCode, SsfJtiClaim, SsfJtiDedupStore, SsfSetProcessingError,
    SsfSetProcessingOutcome, SsfSetProcessor, SsfSetProcessorOptions, SsfSetVerificationError, SsfSetVerifier,
};
use easyssf_test::TestTransmitter;
use easyssf_test::subjects::{complex, iss_sub, opaque};
use tokio::sync::Notify;

fn set(transmitter: &TestTransmitter) -> String {
    transmitter.set("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")))
}

#[tokio::test]
async fn hands_verified_set_to_all_handlers() {
    let transmitter = TestTransmitter::new();
    let first = Recorder::default();
    let second = Recorder::default();
    let processor = processor(&transmitter)
        .handler(first.handler())
        .handler(second.handler());
    let outcome = processor
        .process(&set(&transmitter), SsfDeliveryMethod::Poll)
        .await
        .unwrap();
    assert_eq!(outcome, SsfSetProcessingOutcome::Handled);
    assert_eq!(first.count(), 1);
    assert_eq!(second.count(), 1);
    let context = &first.0.lock().unwrap()[0];
    assert_eq!(context.delivery_method(), SsfDeliveryMethod::Poll);
    assert_eq!(context.subject().subject(), Some("alice"));
}

#[tokio::test]
async fn skips_set_that_was_processed_before() {
    let transmitter = TestTransmitter::new();
    let recorder = Recorder::default();
    let processor = processor(&transmitter).handler(recorder.handler());
    let set = set(&transmitter);
    assert_eq!(
        processor.process(&set, SsfDeliveryMethod::Push).await.unwrap(),
        SsfSetProcessingOutcome::Handled
    );
    assert_eq!(
        processor.process(&set, SsfDeliveryMethod::Push).await.unwrap(),
        SsfSetProcessingOutcome::Duplicate
    );
    assert_eq!(recorder.count(), 1);
}

#[tokio::test]
async fn processes_duplicates_without_dedup_store() {
    let transmitter = TestTransmitter::new();
    let recorder = Recorder::default();
    let processor = SsfSetProcessor::without_dedup(verifier(&transmitter)).handler(recorder.handler());
    let set = set(&transmitter);
    processor.process(&set, SsfDeliveryMethod::Push).await.unwrap();
    assert_eq!(
        processor.process(&set, SsfDeliveryMethod::Push).await.unwrap(),
        SsfSetProcessingOutcome::Handled
    );
    assert_eq!(recorder.count(), 2);
}

#[tokio::test]
async fn failing_handler_does_not_keep_others_from_handling_and_allows_redelivery() {
    let transmitter = TestTransmitter::new();
    let after = Recorder::default();
    let processor = processor(&transmitter)
        .handler(|_: SsfEventContext| async { Err(BoxError::from("boom")) })
        .handler(after.handler());
    let set = set(&transmitter);
    let error = processor.process(&set, SsfDeliveryMethod::Push).await.unwrap_err();
    assert!(
        matches!(error, SsfSetProcessingError::Handling { failed: 1, .. }),
        "{error}"
    );
    assert!(error.to_string().contains("boom"));
    assert_eq!(after.count(), 1, "the handler after the failing one ran");
    // the redelivery runs the handlers again
    assert!(processor.process(&set, SsfDeliveryMethod::Push).await.is_err());
    assert_eq!(after.count(), 2);
}

/// A store whose claims say the SET is in progress elsewhere.
struct InProgressStore;

#[async_trait]
impl SsfJtiDedupStore for InProgressStore {
    async fn claim(&self, _: &SsfEventToken) -> Result<SsfJtiClaim, BoxError> {
        Ok(SsfJtiClaim::InProgress)
    }

    async fn processed(&self, _: &SsfEventToken, _: SsfJtiClaim) -> Result<(), BoxError> {
        panic!("not called")
    }

    async fn forget(&self, _: &SsfEventToken, _: SsfJtiClaim) -> Result<(), BoxError> {
        panic!("not called")
    }
}

#[tokio::test]
async fn set_being_handled_elsewhere_is_left_for_a_redelivery() {
    let transmitter = TestTransmitter::new();
    let recorder = Recorder::default();
    let processor = SsfSetProcessor::new(verifier(&transmitter), InProgressStore).handler(recorder.handler());
    let error = processor
        .process(&set(&transmitter), SsfDeliveryMethod::Push)
        .await
        .unwrap_err();
    assert!(matches!(error, SsfSetProcessingError::InProgress));
    assert_eq!(recorder.count(), 0);
}

#[tokio::test]
async fn handled_set_is_marked_processed_and_failed_one_forgotten() {
    let transmitter = TestTransmitter::new();
    let store = Arc::new(InMemorySsfJtiDedupStore::new(10));
    let fail = Arc::new(AtomicUsize::new(1));
    let failing = fail.clone();
    let processor = SsfSetProcessor::new(verifier(&transmitter), store.clone()).handler(move |_: SsfEventContext| {
        let failing = failing.clone();
        async move {
            if failing.load(Ordering::SeqCst) > 0 {
                return Err(BoxError::from("fail once"));
            }
            Ok(())
        }
    });
    let set = set(&transmitter);
    let token = verifier(&transmitter).verify(&set).await.unwrap();
    assert!(processor.process(&set, SsfDeliveryMethod::Push).await.is_err());
    let probe = store.claim(&token).await.unwrap();
    assert!(probe.is_granted(), "forgotten after the failure");
    store.forget(&token, probe).await.unwrap();
    fail.store(0, Ordering::SeqCst);
    assert_eq!(
        processor.process(&set, SsfDeliveryMethod::Push).await.unwrap(),
        SsfSetProcessingOutcome::Handled
    );
    assert_eq!(store.claim(&token).await.unwrap(), SsfJtiClaim::Processed);
}

/// A handler that waits until it is released.
struct Gate {
    release: Arc<Notify>,
    entered: Arc<Notify>,
}

#[tokio::test]
async fn renewed_claim_keeps_the_set_while_a_handler_outlives_the_lease() {
    let transmitter = TestTransmitter::new();
    let clock = TestClock::new();
    let store = Arc::new(
        InMemorySsfJtiDedupStore::new(10)
            .with_lease(Duration::from_millis(300))
            .with_clock(clock.clock()),
    );
    let gate = Gate {
        release: Arc::new(Notify::new()),
        entered: Arc::new(Notify::new()),
    };
    let (release, entered) = (gate.release.clone(), gate.entered.clone());
    let processor = Arc::new(
        SsfSetProcessor::new(verifier(&transmitter), store.clone())
            .options(SsfSetProcessorOptions {
                claim_renewal: Some(Duration::from_millis(50)),
                ..SsfSetProcessorOptions::default()
            })
            .handler(move |_: SsfEventContext| {
                let (release, entered) = (release.clone(), entered.clone());
                async move {
                    entered.notify_one();
                    release.notified().await;
                    Ok(())
                }
            }),
    );
    let set = set(&transmitter);
    let token = verifier(&transmitter).verify(&set).await.unwrap();
    let running = {
        let processor = processor.clone();
        let set = set.clone();
        tokio::spawn(async move { processor.process(&set, SsfDeliveryMethod::Push).await })
    };
    gate.entered.notified().await;
    // the lease passes while the handler runs, but renewals keep the claim fresh
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(120)).await;
        clock.advance(Duration::from_millis(120));
    }
    assert_eq!(
        store.claim(&token).await.unwrap(),
        SsfJtiClaim::InProgress,
        "not abandoned"
    );
    gate.release.notify_one();
    assert_eq!(running.await.unwrap().unwrap(), SsfSetProcessingOutcome::Handled);
    assert_eq!(store.claim(&token).await.unwrap(), SsfJtiClaim::Processed);
}

#[tokio::test]
async fn without_renewal_a_handler_that_outlives_the_lease_loses_the_set() {
    let transmitter = TestTransmitter::new();
    let clock = TestClock::new();
    let store = Arc::new(
        InMemorySsfJtiDedupStore::new(10)
            .with_lease(Duration::from_millis(100))
            .with_clock(clock.clock()),
    );
    let gate = Gate {
        release: Arc::new(Notify::new()),
        entered: Arc::new(Notify::new()),
    };
    let (release, entered) = (gate.release.clone(), gate.entered.clone());
    let processor = Arc::new(SsfSetProcessor::new(verifier(&transmitter), store.clone()).handler(
        move |_: SsfEventContext| {
            let (release, entered) = (release.clone(), entered.clone());
            async move {
                entered.notify_one();
                release.notified().await;
                Ok(())
            }
        },
    ));
    let set = set(&transmitter);
    let token = verifier(&transmitter).verify(&set).await.unwrap();
    let running = {
        let processor = processor.clone();
        let set = set.clone();
        tokio::spawn(async move { processor.process(&set, SsfDeliveryMethod::Push).await })
    };
    gate.entered.notified().await;
    clock.advance(Duration::from_millis(200));
    // another instance takes the SET over
    let taken = store.claim(&token).await.unwrap();
    assert!(taken.is_granted());
    gate.release.notify_one();
    assert_eq!(running.await.unwrap().unwrap(), SsfSetProcessingOutcome::Handled);
    // the first instance's success did not change the claim of the second
    assert_eq!(store.claim(&token).await.unwrap(), SsfJtiClaim::InProgress);
    store.processed(&token, taken).await.unwrap();
    assert_eq!(store.claim(&token).await.unwrap(), SsfJtiClaim::Processed);
}

#[tokio::test]
async fn dedup_store_evicts_oldest_entry_when_full() {
    let transmitter = TestTransmitter::new();
    let recorder = Recorder::default();
    let processor =
        SsfSetProcessor::new(verifier(&transmitter), InMemorySsfJtiDedupStore::new(2)).handler(recorder.handler());
    let first = set(&transmitter);
    processor.process(&first, SsfDeliveryMethod::Push).await.unwrap();
    processor
        .process(&set(&transmitter), SsfDeliveryMethod::Push)
        .await
        .unwrap();
    processor
        .process(&set(&transmitter), SsfDeliveryMethod::Push)
        .await
        .unwrap();
    assert_eq!(
        processor.process(&first, SsfDeliveryMethod::Push).await.unwrap(),
        SsfSetProcessingOutcome::Handled
    );
    assert_eq!(recorder.count(), 4);
}

#[tokio::test]
async fn rejects_set_with_critical_subject_member_the_receiver_does_not_understand() {
    let transmitter = TestTransmitter::new();
    let recorder = Recorder::default();
    let processor = processor(&transmitter)
        .options(SsfSetProcessorOptions {
            understood_subject_members: BTreeSet::from(["user".to_owned(), "session".to_owned()]),
            critical_subject_members: Some(Arc::new(|_| vec!["tenant".to_owned(), "device".to_owned()])),
            ..SsfSetProcessorOptions::default()
        })
        .handler(recorder.handler());
    let with_tenant = easyssf_test::subjects::complex_members(vec![
        ("user", iss_sub(transmitter.issuer(), "alice")),
        ("tenant", opaque("t-1")),
    ]);
    let set = transmitter.set("CaepSessionRevoked", Some(with_tenant));
    let error = processor.process(&set, SsfDeliveryMethod::Push).await.unwrap_err();
    assert!(matches!(
        error,
        SsfSetProcessingError::Verification(SsfSetVerificationError::Rejected {
            code: SsfErrorCode::InvalidRequest,
            ..
        })
    ));
    assert!(error.to_string().contains("tenant"), "{error}");
    assert_eq!(recorder.count(), 0);
    // a critical member that is absent, or one that is understood, is fine
    let with_session = transmitter.set(
        "CaepSessionRevoked",
        Some(complex(
            Some(iss_sub(transmitter.issuer(), "alice")),
            Some(opaque("s1")),
        )),
    );
    processor.process(&with_session, SsfDeliveryMethod::Push).await.unwrap();
    assert_eq!(recorder.count(), 1);
}
