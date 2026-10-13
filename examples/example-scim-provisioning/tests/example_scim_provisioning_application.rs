//! Runs the application against the in-process transmitter, without the demo, and plays the
//! life of a user.

mod common;

use std::time::Duration;

use easyssf_core::event_types;
use easyssf_test::{TestTransmitter, eventually, subjects};
use example_scim_provisioning::ApplicationOptions;
use serde_json::{Map, Value, json};

const ALICE: &str = "/Users/2b2f880af6674ac284bae9381673d462";

const TIMEOUT: Duration = Duration::from_secs(10);

const OPTIONS: ApplicationOptions = ApplicationOptions {
    demo: false,
    autoplay: false,
};

#[tokio::test(flavor = "multi_thread")]
async fn mirrors_the_life_of_a_user() {
    let transmitter = TestTransmitter::new();
    let started = common::start(&transmitter, OPTIONS).await;
    let directory = started.application.directory.clone();
    wait_for_the_stream(&transmitter).await;

    transmit(
        &transmitter,
        event_types::SCIM_PROV_CREATE_FULL,
        json!({"version": "1", "data": {
            "userName": "alice",
            "name": {"givenName": "Alice", "familyName": "Adams"},
            "emails": [{"value": "alice@example.com"}]
        }}),
    );
    eventually(TIMEOUT, "alice is created", || {
        directory.find("2b2f880af6674ac284bae9381673d462").is_some()
    })
    .await;
    let alice = directory.find("2b2f880af6674ac284bae9381673d462").unwrap();
    assert_eq!(alice.user_name.as_deref(), Some("alice"));
    assert_eq!(alice.display_name.as_deref(), Some("Alice Adams"));
    assert_eq!(alice.emails, vec!["alice@example.com"]);
    assert_eq!(alice.external_id.as_deref(), Some("alice"));
    assert!(alice.active);
    assert_eq!(alice.version.as_deref(), Some("1"));
    let users = reqwest::get(format!("{}/users", started.base_url)).await.unwrap();
    assert_eq!(users.status(), 200);
    let body = users.text().await.unwrap();
    assert!(body.contains("\"userName\":\"alice\""), "{body}");
    assert!(body.contains("\"displayName\":\"Alice Adams\""), "{body}");

    transmit(
        &transmitter,
        event_types::SCIM_PROV_PATCH_FULL,
        json!({"version": "2", "data": {"Operations": [
            {"op": "replace", "path": "displayName", "value": "Alice Baker"},
            {"op": "replace", "value": {"active": false}}
        ]}}),
    );
    eventually(TIMEOUT, "alice is patched", || {
        directory
            .find("2b2f880af6674ac284bae9381673d462")
            .is_some_and(|alice| alice.version.as_deref() == Some("2"))
    })
    .await;
    let alice = directory.find("2b2f880af6674ac284bae9381673d462").unwrap();
    assert_eq!(alice.display_name.as_deref(), Some("Alice Baker"));
    assert!(!alice.active);

    transmit(&transmitter, event_types::SCIM_PROV_ACTIVATE, json!({}));
    eventually(TIMEOUT, "alice is activated", || {
        directory
            .find("2b2f880af6674ac284bae9381673d462")
            .is_some_and(|alice| alice.active)
    })
    .await;

    // a notice carries no data and changes nothing
    transmit(
        &transmitter,
        event_types::SCIM_PROV_PUT_NOTICE,
        json!({"attributes": ["userName"]}),
    );
    transmit(&transmitter, event_types::SCIM_PROV_DELETE, json!({}));
    eventually(TIMEOUT, "alice is deleted", || {
        directory.find("2b2f880af6674ac284bae9381673d462").is_none()
    })
    .await;
    let user = reqwest::get(format!("{}/users/2b2f880af6674ac284bae9381673d462", started.base_url))
        .await
        .unwrap();
    assert_eq!(user.status(), 404);
    started.application.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn ignores_groups() {
    let transmitter = TestTransmitter::new();
    let started = common::start(&transmitter, OPTIONS).await;
    let directory = started.application.directory.clone();
    wait_for_the_stream(&transmitter).await;

    transmit_for(
        &transmitter,
        event_types::SCIM_PROV_CREATE_FULL,
        "/Groups/176f397ec4c44b94b2cfcb759780b8c2",
        Some("crmUsers"),
        json!({"data": {"displayName": "crmUsers"}}),
    );
    transmit_for(
        &transmitter,
        event_types::SCIM_PROV_CREATE_FULL,
        "/Users/44f6142df96bd6ab61e7521d9",
        None,
        json!({"data": {"userName": "jdoe"}}),
    );
    eventually(TIMEOUT, "jdoe is created", || {
        directory.find("44f6142df96bd6ab61e7521d9").is_some()
    })
    .await;
    assert!(directory.find("176f397ec4c44b94b2cfcb759780b8c2").is_none());
    started.application.shutdown().await;
}

async fn wait_for_the_stream(transmitter: &TestTransmitter) {
    eventually(TIMEOUT, "the receiver registers its stream", || {
        !transmitter.streams().is_empty()
    })
    .await;
}

fn transmit(transmitter: &TestTransmitter, event_type: &str, payload: Value) {
    transmit_for(transmitter, event_type, ALICE, Some("alice"), payload);
}

fn transmit_for(transmitter: &TestTransmitter, event_type: &str, uri: &str, external_id: Option<&str>, payload: Value) {
    let audience = transmitter.streams()[0].get("aud").cloned().unwrap_or(Value::Null);
    let payload: Map<String, Value> = payload.as_object().cloned().unwrap_or_default();
    let mut claims = transmitter.set_claims_with_payload(
        event_type,
        Some(subjects::scim_with_external_id(uri, external_id)),
        payload,
    );
    claims.insert("aud".to_owned(), audience);
    transmitter.queue_set(&transmitter.sign_set(&claims));
}
