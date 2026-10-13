//! The demo SCIM service provider.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use easyssf_core::event_types;
use easyssf_test::TestTransmitter;
use easyssf_test::subjects;
use http::StatusCode;
use http::header::LOCATION;
use serde::Deserialize;
use serde_json::{Map, Value, json};

/// Plays the SCIM service provider: every operation on a user becomes a SCIM Event (RFC 9967)
/// that the demo transmitter delivers to the receiver of this very application. The operations
/// are driven by the [`router`] (`/demo/scim`) and, with `demo.autoplay`, by [`play`](Self::play),
/// which tells the life of two users once the receiver has registered its stream, one SET every
/// few seconds.
///
/// The SETs transmitted are kept, decoded, for `GET /demo/scim/events`: that is what a SCIM Event
/// looks like on the wire.
pub struct DemoScimProvider {
    transmitter: TestTransmitter,
    versions: Mutex<HashMap<String, u32>>,
    external_ids: Mutex<HashMap<String, String>>,
    transmitted: Mutex<Vec<Value>>,
}

/// Alice in the scripted demo.
pub const ALICE: &str = "/Users/2b2f880af6674ac284bae9381673d462";

/// Bob in the scripted demo.
pub const BOB: &str = "/Users/c3a6e1f0b2d94f0e9a7c5d8b6e4f2a10";

const PAUSE: Duration = Duration::from_secs(4);

/// The receiver has not registered its stream yet.
#[derive(Debug)]
pub struct NotReady;

impl std::fmt::Display for NotReady {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("The receiver has not registered its stream yet, try again in a moment")
    }
}

impl std::error::Error for NotReady {}

impl DemoScimProvider {
    /// A service provider that transmits through `transmitter`.
    pub fn new(transmitter: TestTransmitter) -> Self {
        Self {
            transmitter,
            versions: Mutex::new(HashMap::new()),
            external_ids: Mutex::new(HashMap::new()),
            transmitted: Mutex::new(Vec::new()),
        }
    }

    /// The life of two users: created, modified, replaced, deactivated, deleted. The resources
    /// and the patch are written as JSON here so that the SCIM payloads are easy to read; an
    /// application would build them from its own objects.
    pub async fn play(self: Arc<Self>) {
        while self.transmitter.streams().is_empty() {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        tracing::info!("The receiver registered its stream, the demo SCIM service provider starts");
        narrate(
            "Alice is created at the service provider and joins the feed: feed:add and prov:create:full in one SET, \
             with her representation as data",
        );
        let _ = self.create(
            ALICE,
            Some("alice"),
            object(json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "alice",
                "displayName": "Alice Adams",
                "emails": [{"type": "work", "value": "alice@example.com", "primary": true}],
                "active": true
            })),
        );
        tokio::time::sleep(PAUSE).await;
        narrate("Bob is created as well");
        let _ = self.create(
            BOB,
            Some("bob"),
            object(json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "bob",
                "displayName": "Bob Brown",
                "emails": [{"type": "work", "value": "bob@example.com", "primary": true}],
                "active": true
            })),
        );
        tokio::time::sleep(PAUSE).await;
        // alice marries: a SCIM PATCH with two operations
        narrate(
            "Alice marries: a SCIM PATCH changes her display name and adds an email, prov:patch:full carries the \
             PatchOp as data",
        );
        let _ = self.patch(
            ALICE,
            object(json!({
                "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                "Operations": [
                    {"op": "replace", "path": "displayName", "value": "Alice Baker"},
                    {"op": "add", "path": "emails", "value": [
                        {"type": "work", "value": "alice@example.com"},
                        {"type": "home", "value": "alice.baker@home.example"}
                    ]}
                ]
            })),
        );
        tokio::time::sleep(PAUSE).await;
        // bob is replaced wholesale: a SCIM PUT
        narrate("Bob is replaced wholesale with a SCIM PUT: prov:put:full carries the new representation");
        let _ = self.replace(
            BOB,
            object(json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": "robert",
                "displayName": "Robert Brown",
                "emails": [{"type": "work", "value": "robert@example.com", "primary": true}],
                "active": true
            })),
        );
        tokio::time::sleep(PAUSE).await;
        // a notice event: only the attributes that changed, no data
        narrate(
            "Alice's phone number changes, reported as a notice: prov:patch:notice names the attribute but carries \
             no data, the receiver would have to GET the resource",
        );
        let _ = self.patch_notice(ALICE, vec!["phoneNumbers".to_owned()]);
        tokio::time::sleep(PAUSE).await;
        narrate("Alice leaves the company and is deactivated: prov:deactivate, an event without payload");
        let _ = self.deactivate(ALICE);
        tokio::time::sleep(PAUSE).await;
        narrate("Bob is deleted: prov:delete, which also removes him from the feed");
        let _ = self.delete(BOB);
        tracing::info!(
            "The demo SCIM service provider is done, GET http://localhost:8083/users shows the result once the \
             receiver has polled, GET /demo/scim/events the SETs"
        );
    }

    /// Creates the user: `feed:add` and `prov:create:full` in one SET, as RFC 9967 allows for
    /// events about the same resource.
    ///
    /// Returns the SET transmitted, decoded.
    pub fn create(&self, uri: &str, external_id: Option<&str>, user: Map<String, Value>) -> Result<Value, NotReady> {
        if let Some(external_id) = external_id {
            self.external_ids
                .lock()
                .unwrap()
                .insert(uri.to_owned(), external_id.to_owned());
        }
        let mut events = Map::new();
        events.insert(event_types::SCIM_FEED_ADD.to_owned(), json!({}));
        events.insert(
            event_types::SCIM_PROV_CREATE_FULL.to_owned(),
            json!({"version": self.next_version(uri), "data": user}),
        );
        self.transmit(uri, events)
    }

    /// Replaces the user with SCIM PUT: `prov:put:full` with the new representation.
    pub fn replace(&self, uri: &str, user: Map<String, Value>) -> Result<Value, NotReady> {
        self.transmit(
            uri,
            single(
                event_types::SCIM_PROV_PUT_FULL,
                json!({"version": self.next_version(uri), "data": user}),
            ),
        )
    }

    /// Modifies the user with SCIM PATCH: `prov:patch:full` with the `PatchOp`.
    pub fn patch(&self, uri: &str, patch_op: Map<String, Value>) -> Result<Value, NotReady> {
        self.transmit(
            uri,
            single(
                event_types::SCIM_PROV_PATCH_FULL,
                json!({"version": self.next_version(uri), "data": patch_op}),
            ),
        )
    }

    /// Reports a modification without its data: `prov:patch:notice` naming the attributes that
    /// changed.
    pub fn patch_notice(&self, uri: &str, attributes: Vec<String>) -> Result<Value, NotReady> {
        self.transmit(
            uri,
            single(
                event_types::SCIM_PROV_PATCH_NOTICE,
                json!({"version": self.next_version(uri), "attributes": attributes}),
            ),
        )
    }

    /// Activates the user: `prov:activate`.
    pub fn activate(&self, uri: &str) -> Result<Value, NotReady> {
        self.transmit(uri, single(event_types::SCIM_PROV_ACTIVATE, json!({})))
    }

    /// Deactivates the user: `prov:deactivate`.
    pub fn deactivate(&self, uri: &str) -> Result<Value, NotReady> {
        self.transmit(uri, single(event_types::SCIM_PROV_DEACTIVATE, json!({})))
    }

    /// Deletes the user: `prov:delete`, which has no payload attributes and removes the resource
    /// from the feed as well.
    pub fn delete(&self, uri: &str) -> Result<Value, NotReady> {
        let set = self.transmit(uri, single(event_types::SCIM_PROV_DELETE, json!({})))?;
        self.versions.lock().unwrap().remove(uri);
        self.external_ids.lock().unwrap().remove(uri);
        Ok(set)
    }

    /// The SETs transmitted so far, oldest first: the compact JWT as `set` and its decoded
    /// `claims`.
    pub fn transmitted(&self) -> Vec<Value> {
        self.transmitted.lock().unwrap().clone()
    }

    fn transmit(&self, uri: &str, events: Map<String, Value>) -> Result<Value, NotReady> {
        let streams = self.transmitter.streams();
        let Some(stream) = streams.first() else {
            return Err(NotReady);
        };
        // the receiver expects the audience the transmitter assigned to the stream
        let audience = stream.get("aud").cloned().unwrap_or(Value::Null);
        let event_type = events.keys().next().cloned().unwrap_or_default();
        let external_id = self.external_ids.lock().unwrap().get(uri).cloned();
        let subject = subjects::scim_with_external_id(uri, external_id.as_deref());
        let mut claims = self
            .transmitter
            .set_claims_with_payload(&event_type, Some(subject), Map::new());
        claims.insert("aud".to_owned(), audience);
        claims.insert(
            "txn".to_owned(),
            Value::String(uuid::Uuid::new_v4().simple().to_string()),
        );
        claims.insert("events".to_owned(), Value::Object(events.clone()));
        let set = self.transmitter.sign_set(&claims);
        self.transmitter.queue_set(&set);
        let transmitted = json!({"set": set, "claims": claims});
        self.transmitted.lock().unwrap().push(transmitted.clone());
        // the decoded SET in the log: this is what a SCIM Event looks like
        let aliases: Vec<String> = events.keys().map(|uri| event_types::alias_of(uri)).collect();
        let jti = claims.get("jti").and_then(Value::as_str).unwrap_or_default();
        let pretty = serde_json::to_string_pretty(&claims).unwrap_or_default();
        tracing::info!("Transmitted SET {jti} with {aliases:?} for {uri}:\n{pretty}");
        Ok(transmitted)
    }

    fn next_version(&self, uri: &str) -> String {
        let mut versions = self.versions.lock().unwrap();
        let version = versions.entry(uri.to_owned()).or_insert(0);
        *version += 1;
        version.to_string()
    }
}

/// The URI of a new user.
pub fn new_user_uri() -> String {
    format!("/Users/{}", uuid::Uuid::new_v4().simple())
}

fn single(event_type: &str, payload: Value) -> Map<String, Value> {
    let mut events = Map::new();
    events.insert(event_type.to_owned(), payload);
    events
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// A headline in the log for the step that follows, to scroll along in a demo.
fn narrate(what_happens: &str) {
    // the line break leaves an empty line in the log before the headline
    tracing::info!("\n### {what_happens}");
}

/// The API of the demo SCIM service provider under `/demo/scim`, a tiny stand-in for the `/Users`
/// endpoint of a SCIM server: each request changes a user and transmits the SCIM Event about it,
/// which the receiver of this application mirrors into `/users` on its next poll. Every response
/// is the SET transmitted, so that the event is visible next to its cause. See
/// `example-scim-provisioning.http`.
pub fn router(provider: Arc<DemoScimProvider>) -> Router {
    Router::new()
        .route("/demo/scim/Users", post(create))
        .route(
            "/demo/scim/Users/{id}",
            axum::routing::put(replace).patch(patch).delete(delete),
        )
        .route("/demo/scim/Users/{id}/activate", post(activate))
        .route("/demo/scim/Users/{id}/deactivate", post(deactivate))
        .route("/demo/scim/events", get(events))
        .with_state(provider)
}

type Provider = State<Arc<DemoScimProvider>>;

/// Creates a user from its SCIM representation: `feed:add` and `prov:create:full`. The
/// `externalId` of the representation, if any, goes into the subject of the events.
async fn create(State(provider): Provider, Json(user): Json<Map<String, Value>>) -> Response {
    let uri = new_user_uri();
    let external_id = user.get("externalId").and_then(Value::as_str).map(str::to_owned);
    narrate(&format!(
        "POST /demo/scim/Users: {} is created and joins the feed",
        user.get("userName").and_then(Value::as_str).unwrap_or(&uri)
    ));
    match provider.create(&uri, external_id.as_deref(), user) {
        Ok(set) => (StatusCode::CREATED, [(LOCATION, format!("/demo/scim{uri}"))], Json(set)).into_response(),
        Err(error) => not_ready(error),
    }
}

/// Replaces a user: `prov:put:full`.
async fn replace(State(provider): Provider, Path(id): Path<String>, Json(user): Json<Map<String, Value>>) -> Response {
    narrate(&format!("PUT /demo/scim/Users/{id}: the user is replaced"));
    respond(provider.replace(&format!("/Users/{id}"), user))
}

#[derive(Debug, Deserialize)]
struct PatchMode {
    mode: Option<String>,
}

/// Modifies a user with a SCIM `PatchOp`: `prov:patch:full`, or with `?mode=notice` a
/// `prov:patch:notice` that only names the paths of the operations.
async fn patch(
    State(provider): Provider,
    Path(id): Path<String>,
    Query(query): Query<PatchMode>,
    Json(patch_op): Json<Map<String, Value>>,
) -> Response {
    let uri = format!("/Users/{id}");
    if query.mode.as_deref() == Some("notice") {
        narrate(&format!(
            "PATCH /demo/scim/Users/{id}?mode=notice: the user is modified, reported without data"
        ));
        return respond(provider.patch_notice(&uri, paths(&patch_op)));
    }
    narrate(&format!("PATCH /demo/scim/Users/{id}: the user is modified"));
    respond(provider.patch(&uri, patch_op))
}

async fn activate(State(provider): Provider, Path(id): Path<String>) -> Response {
    narrate(&format!("POST /demo/scim/Users/{id}/activate: the user is activated"));
    respond(provider.activate(&format!("/Users/{id}")))
}

async fn deactivate(State(provider): Provider, Path(id): Path<String>) -> Response {
    narrate(&format!(
        "POST /demo/scim/Users/{id}/deactivate: the user is deactivated"
    ));
    respond(provider.deactivate(&format!("/Users/{id}")))
}

/// Deletes a user: `prov:delete`.
async fn delete(State(provider): Provider, Path(id): Path<String>) -> Response {
    narrate(&format!("DELETE /demo/scim/Users/{id}: the user is deleted"));
    respond(provider.delete(&format!("/Users/{id}")))
}

/// The SETs transmitted so far, oldest first, each as the compact JWT and its decoded claims.
async fn events(State(provider): Provider) -> Json<Vec<Value>> {
    Json(provider.transmitted())
}

fn respond(result: Result<Value, NotReady>) -> Response {
    match result {
        Ok(set) => Json(set).into_response(),
        Err(error) => not_ready(error),
    }
}

fn not_ready(error: NotReady) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error": error.to_string()})),
    )
        .into_response()
}

fn paths(patch_op: &Map<String, Value>) -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(Value::Array(operations)) = patch_op.get("Operations") {
        for operation in operations.iter().filter_map(Value::as_object) {
            if let Some(path) = operation.get("path").and_then(Value::as_str) {
                paths.push(path.to_owned());
            } else if let Some(Value::Object(attributes)) = operation.get("value") {
                paths.extend(attributes.keys().cloned());
            }
        }
    }
    paths
}
