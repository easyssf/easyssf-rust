//! The demo: the service provider API transmits SCIM Events that the receiver of the same
//! application mirrors, the walk-through of `example-scim-provisioning.http`.

mod common;

use std::time::Duration;

use easyssf_test::{TestTransmitter, eventually};
use example_scim_provisioning::ApplicationOptions;
use serde_json::{Value, json};

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread")]
async fn requests_to_the_demo_provider_are_mirrored_by_the_receiver() {
    let transmitter = TestTransmitter::new();
    let started = common::start(
        &transmitter,
        ApplicationOptions {
            demo: true,
            autoplay: false,
        },
    )
    .await;
    let directory = started.application.directory.clone();
    let base_url = &started.base_url;
    eventually(TIMEOUT, "the receiver registers its stream", || {
        !transmitter.streams().is_empty()
    })
    .await;
    let rest = reqwest::Client::new();

    let created = rest
        .post(format!("{base_url}/demo/scim/Users"))
        .json(
            &json!({"userName": "carol", "externalId": "carol", "name": {"givenName": "Carol", "familyName": "Clark"}}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let location = created.headers()["location"].to_str().unwrap().to_owned();
    let body: Value = created.json().await.unwrap();
    let claims = &body["claims"];
    assert_eq!(claims["sub_id"]["format"], "scim");
    assert_eq!(claims["sub_id"]["externalId"], "carol");
    let uri = claims["sub_id"]["uri"].as_str().unwrap().to_owned();
    let id = uri.strip_prefix("/Users/").unwrap().to_owned();
    let events: Vec<&String> = claims["events"].as_object().unwrap().keys().collect();
    assert_eq!(
        events,
        [
            "urn:ietf:params:scim:event:feed:add",
            "urn:ietf:params:scim:event:prov:create:full"
        ]
    );
    assert_eq!(location, format!("/demo/scim{uri}"));

    eventually(TIMEOUT, "carol is mirrored", || directory.find(&id).is_some()).await;
    let carol = directory.find(&id).unwrap();
    assert_eq!(carol.display_name.as_deref(), Some("Carol Clark"));
    assert_eq!(carol.external_id.as_deref(), Some("carol"));

    rest.patch(format!("{base_url}/demo/scim/Users/{id}?mode=notice"))
        .json(&json!({"Operations": [{"op": "replace", "path": "phoneNumbers", "value": []}]}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    rest.post(format!("{base_url}/demo/scim/Users/{id}/deactivate"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    eventually(TIMEOUT, "carol is deactivated", || {
        directory.find(&id).is_some_and(|carol| !carol.active)
    })
    .await;
    assert_eq!(directory.find(&id).unwrap().version.as_deref(), Some("1"));

    rest.delete(format!("{base_url}/demo/scim/Users/{id}"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    eventually(TIMEOUT, "carol is deleted", || directory.find(&id).is_none()).await;

    let events: Vec<Value> = rest
        .get(format!("{base_url}/demo/scim/events"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(events.len(), 4);
    assert!(
        events
            .iter()
            .all(|set| set["set"].as_str().is_some_and(|jwt| jwt.contains('.')))
    );
    let gone = rest.get(format!("{base_url}/users/{id}")).send().await.unwrap();
    assert_eq!(gone.status(), 404);
    started.application.shutdown().await;
}
