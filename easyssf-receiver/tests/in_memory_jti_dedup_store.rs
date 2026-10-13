//! `InMemorySsfJtiDedupStoreTests` of the Java library.

mod common;

use std::time::Duration;

use common::TestClock;
use easyssf_core::SsfEventToken;
use easyssf_receiver::set::{InMemorySsfJtiDedupStore, SsfJtiClaim, SsfJtiDedupStore};
use serde_json::json;

fn token(jti: &str) -> SsfEventToken {
    let claims = json!({ "jti": jti, "iss": "https://t.example", "iat": 1, "events": { "e": {} } });
    SsfEventToken::from_claims(claims.as_object().unwrap().clone()).unwrap()
}

#[tokio::test]
async fn claim_in_progress_processed_forget() {
    let store = InMemorySsfJtiDedupStore::new(10);
    let set = token("1");
    let claim = store.claim(&set).await.unwrap();
    assert!(claim.is_granted());
    assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::InProgress);
    store.processed(&set, claim).await.unwrap();
    assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::Processed);
    // forgetting a processed SET does nothing: only an in-progress claim is forgotten
    store.forget(&set, claim).await.unwrap();
    assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::Processed);

    let other = token("2");
    let claim = store.claim(&other).await.unwrap();
    store.forget(&other, claim).await.unwrap();
    assert!(store.claim(&other).await.unwrap().is_granted());
    assert_eq!(store.len(), 2);
}

#[tokio::test]
async fn abandoned_claim_is_taken_over_after_the_lease() {
    let clock = TestClock::new();
    let store = InMemorySsfJtiDedupStore::new(10)
        .with_lease(Duration::from_secs(60))
        .with_clock(clock.clock());
    let set = token("1");
    let first = store.claim(&set).await.unwrap();
    clock.advance(Duration::from_secs(59));
    assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::InProgress);
    clock.advance(Duration::from_secs(2));
    let second = store.claim(&set).await.unwrap();
    assert!(second.is_granted());
    assert_ne!(second.token(), first.token());
}

#[tokio::test]
async fn late_holder_can_neither_complete_nor_forget_the_claim_taken_over_from_it() {
    let clock = TestClock::new();
    let store = InMemorySsfJtiDedupStore::new(10)
        .with_lease(Duration::from_secs(60))
        .with_clock(clock.clock());
    let set = token("1");
    let first = store.claim(&set).await.unwrap();
    clock.advance(Duration::from_secs(61));
    let second = store.claim(&set).await.unwrap();
    store.processed(&set, first).await.unwrap();
    assert_eq!(
        store.claim(&set).await.unwrap(),
        SsfJtiClaim::InProgress,
        "still held by the second"
    );
    store.forget(&set, first).await.unwrap();
    assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::InProgress);
    assert_eq!(store.renew(&set, first).await.unwrap(), None);
    store.processed(&set, second).await.unwrap();
    assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::Processed);
}

#[tokio::test]
async fn renewed_claim_outlives_the_lease() {
    let clock = TestClock::new();
    let store = InMemorySsfJtiDedupStore::new(10)
        .with_lease(Duration::from_secs(60))
        .with_clock(clock.clock());
    let set = token("1");
    let claim = store.claim(&set).await.unwrap();
    clock.advance(Duration::from_secs(40));
    let renewed = store.renew(&set, claim).await.unwrap().unwrap();
    clock.advance(Duration::from_secs(40));
    assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::InProgress);
    store.processed(&set, renewed).await.unwrap();
    assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::Processed);
}

#[tokio::test]
async fn success_of_an_evicted_claim_is_recorded() {
    let store = InMemorySsfJtiDedupStore::new(2);
    let first = token("1");
    let claim = store.claim(&first).await.unwrap();
    store.claim(&token("2")).await.unwrap();
    store.claim(&token("3")).await.unwrap();
    assert_eq!(store.len(), 2);
    assert!(store.claim(&first).await.unwrap().is_granted(), "evicted: claimed anew");
    let claim2 = store.claim(&token("4")).await.unwrap();
    store.claim(&token("5")).await.unwrap();
    store.processed(&token("4"), claim2).await.unwrap();
    assert_eq!(store.claim(&token("4")).await.unwrap(), SsfJtiClaim::Processed);
    // the original claim of the first SET was evicted and re-claimed: the old token does not hold
    store.processed(&first, claim).await.unwrap();
    assert_eq!(store.len(), 2);
}

#[tokio::test]
async fn capacity_evicts_the_oldest_entry() {
    let store = InMemorySsfJtiDedupStore::new(3);
    for jti in ["1", "2", "3"] {
        let set = token(jti);
        let claim = store.claim(&set).await.unwrap();
        store.processed(&set, claim).await.unwrap();
    }
    assert_eq!(store.claim(&token("1")).await.unwrap(), SsfJtiClaim::Processed);
    let set = token("4");
    let claim = store.claim(&set).await.unwrap();
    store.processed(&set, claim).await.unwrap();
    assert_eq!(store.len(), 3);
    assert!(
        store.claim(&token("1")).await.unwrap().is_granted(),
        "the oldest was evicted"
    );
}
