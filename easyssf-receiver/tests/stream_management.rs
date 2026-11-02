//! `SsfStreamManagementTests` of the Java library.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use easyssf_core::stream::{SsfStreamConfiguration, SsfStreamStatus};
use easyssf_receiver::BoxError;
use easyssf_receiver::http::{SsfHttpClient, SsfHttpRequest, SsfHttpResponse};
use easyssf_receiver::stream::{
    SsfReceiverStream, SsfStreamClient, SsfStreamError, SsfStreamRegistrar, SsfStreamRegistrarState,
};
use easyssf_receiver::transmitter::{
    ClientCredentialsSsfTransmitterTokenProvider, SsfClientCredentialsOptions, SsfTransmitterTokenProvider,
};
use easyssf_test::subjects::email;
use easyssf_test::{TestTransmitter, during, eventually};
use serde_json::{Map, Value, json};
use url::Url;

fn token_provider(transmitter: &TestTransmitter) -> impl SsfTransmitterTokenProvider {
    ClientCredentialsSsfTransmitterTokenProvider::new(
        transmitter.clone(),
        Url::parse(&transmitter.token_uri()).unwrap(),
        TestTransmitter::CLIENT_ID,
        TestTransmitter::CLIENT_SECRET,
        SsfClientCredentialsOptions::default(),
    )
}

fn client(transmitter: &TestTransmitter) -> Arc<SsfStreamClient> {
    Arc::new(SsfStreamClient::new(
        transmitter.clone(),
        token_provider(transmitter),
        common::metadata_resolver(transmitter),
    ))
}

fn push_stream(events: &[&str]) -> SsfStreamConfiguration {
    SsfStreamConfiguration::push(
        &Url::parse("https://app.example/ssf/push").unwrap(),
        Some("Bearer s3cr3t"),
        &events.iter().map(|e| (*e).to_owned()).collect::<Vec<_>>(),
        Some("test stream"),
    )
}

#[tokio::test]
async fn manages_stream() {
    let transmitter = TestTransmitter::new();
    let client = client(&transmitter);
    assert!(client.streams().await.unwrap().is_empty());
    let created = client
        .create_stream(&push_stream(&["CaepSessionRevoked"]))
        .await
        .unwrap();
    let stream_id = created.stream_id().unwrap().to_owned();
    assert_eq!(created.issuer(), Some(transmitter.issuer()));
    assert_eq!(
        created.audience(),
        [format!("{}/{stream_id}", TestTransmitter::CLIENT_ID)]
    );
    assert_eq!(
        created.events_delivered(),
        [easyssf_core::event_types::CAEP_SESSION_REVOKED]
    );
    assert!(
        created.claims()["delivery"].get("authorization_header").is_none(),
        "the transmitter does not echo the header"
    );

    assert_eq!(client.streams().await.unwrap().len(), 1);
    assert_eq!(
        client.stream(&stream_id).await.unwrap().stream_id(),
        Some(stream_id.as_str())
    );

    let mut changes = Map::new();
    changes.insert("description".to_owned(), Value::String("changed".to_owned()));
    assert_eq!(
        client.update_stream(&stream_id, &changes).await.unwrap().description(),
        Some("changed")
    );
    let replaced = client
        .replace_stream(&stream_id, &push_stream(&["CaepCredentialChange"]))
        .await
        .unwrap();
    assert_eq!(
        replaced.events_requested(),
        [easyssf_core::event_types::CAEP_CREDENTIAL_CHANGE]
    );

    assert_eq!(
        client.status(&stream_id).await.unwrap().status,
        SsfStreamStatus::ENABLED
    );
    let paused = client
        .update_status(&stream_id, SsfStreamStatus::PAUSED, Some("maintenance"))
        .await
        .unwrap();
    assert_eq!(paused.status, SsfStreamStatus::PAUSED);

    client
        .add_subject(&stream_id, &email("alice@example.com"), true)
        .await
        .unwrap();
    assert_eq!(transmitter.added_subjects()[0]["email"], "alice@example.com");
    client
        .remove_subject(&stream_id, &email("alice@example.com"))
        .await
        .unwrap();
    assert_eq!(transmitter.removed_subjects().len(), 1);
    client.request_verification(&stream_id, Some("state-1")).await.unwrap();
    assert_eq!(transmitter.verification_requests(), ["state-1"]);

    client.delete_stream(&stream_id).await.unwrap();
    assert!(client.streams().await.unwrap().is_empty());
}

#[tokio::test]
async fn reports_status_of_failed_calls() {
    let transmitter = TestTransmitter::new();
    let client = client(&transmitter);
    let error = client.stream("missing").await.unwrap_err();
    assert_eq!(error.status(), 404);
    assert!(error.to_string().contains("404"), "{error}");
    transmitter.set_available(false);
    let error = client.streams().await.unwrap_err();
    assert_eq!(
        error.status(),
        503,
        "the cached token was used, the transmitter answered: {error}"
    );
    let fresh = self::client(&transmitter);
    let error = fresh.streams().await.unwrap_err();
    assert_eq!(
        error.status(),
        0,
        "the token request failed, the transmitter was not called: {error}"
    );
}

#[tokio::test]
async fn refuses_stream_created_with_another_issuer() {
    let transmitter = TestTransmitter::new();
    transmitter.set_stream_issuer(Some("https://other.example"));
    let error = client(&transmitter)
        .create_stream(&push_stream(&["CaepSessionRevoked"]))
        .await
        .unwrap_err();
    assert!(matches!(error, SsfStreamError::IssuerMismatch { .. }), "{error}");
    assert!(error.to_string().contains("https://other.example"));
}

#[tokio::test]
async fn registrar_deletes_stream_created_with_another_issuer_and_gives_up() {
    let transmitter = TestTransmitter::new();
    transmitter.set_stream_issuer(Some("https://other.example"));
    let stream = Arc::new(SsfReceiverStream::new());
    let registrar = SsfStreamRegistrar::for_managed_stream(
        client(&transmitter),
        stream.clone(),
        push_stream(&["CaepSessionRevoked"]),
    );
    registrar.start();
    eventually(Duration::from_secs(5), "the registrar gave up", || {
        registrar.state() == SsfStreamRegistrarState::Failed
    })
    .await;
    assert!(registrar.last_error().unwrap().contains("https://other.example"));
    assert!(transmitter.streams().is_empty(), "the stream was deleted");
    assert!(stream.configuration().is_none());
    registrar.stop().await;
}

#[tokio::test]
async fn obtains_new_access_token_when_the_transmitter_rejects_the_current_one() {
    let transmitter = TestTransmitter::new();
    let client = client(&transmitter);
    client.streams().await.unwrap();
    transmitter.expire_access_tokens();
    client.streams().await.unwrap();
    assert_eq!(transmitter.token_requests(), 2);
}

#[tokio::test]
async fn registrar_creates_stream() {
    let transmitter = TestTransmitter::new();
    let stream = Arc::new(SsfReceiverStream::new());
    let registrar = SsfStreamRegistrar::for_managed_stream(
        client(&transmitter),
        stream.clone(),
        push_stream(&["CaepSessionRevoked"]),
    );
    assert_eq!(registrar.state(), SsfStreamRegistrarState::NotStarted);
    let registered = registrar.register().await.unwrap();
    assert_eq!(registrar.state(), SsfStreamRegistrarState::Registered);
    assert_eq!(stream.stream_id(), registered.stream_id().map(str::to_owned));
    assert_eq!(stream.audience().len(), 1);
    assert_eq!(transmitter.streams().len(), 1);
}

#[tokio::test]
async fn registrar_tells_its_listeners_once_the_stream_is_registered() {
    let transmitter = TestTransmitter::new();
    let stream = Arc::new(SsfReceiverStream::new());
    let registrar = SsfStreamRegistrar::for_managed_stream(
        client(&transmitter),
        stream.clone(),
        push_stream(&["CaepSessionRevoked"]),
    );
    let told = Arc::new(Mutex::new(Vec::new()));
    let listener = told.clone();
    registrar.add_listener(move |stream| listener.lock().unwrap().push(stream.stream_id().unwrap().to_owned()));
    registrar.start();
    assert!(registrar.is_running());
    eventually(Duration::from_secs(5), "the listener was told", || {
        !told.lock().unwrap().is_empty()
    })
    .await;
    assert_eq!(told.lock().unwrap()[0], stream.stream_id().unwrap());
    registrar.stop().await;
    assert!(!registrar.is_running());
}

#[tokio::test]
async fn registrar_reuses_existing_stream() {
    let transmitter = TestTransmitter::new();
    let existing = transmitter.add_stream(push_stream(&["CaepSessionRevoked"]).claims());
    let stream = Arc::new(SsfReceiverStream::new());
    let registrar = SsfStreamRegistrar::for_managed_stream(
        client(&transmitter),
        stream.clone(),
        push_stream(&["CaepSessionRevoked"]),
    );
    let registered = registrar.register().await.unwrap();
    assert_eq!(registered.stream_id(), existing["stream_id"].as_str());
    assert_eq!(transmitter.streams().len(), 1);
}

#[tokio::test]
async fn registrar_updates_requested_events_of_existing_stream() {
    let transmitter = TestTransmitter::new();
    let existing = transmitter.add_stream(push_stream(&["CaepSessionRevoked"]).claims());
    let stream = Arc::new(SsfReceiverStream::new());
    let desired = push_stream(&["CaepSessionRevoked", "CaepCredentialChange"]);
    let registrar = SsfStreamRegistrar::for_managed_stream(client(&transmitter), stream.clone(), desired);
    let registered = registrar.register().await.unwrap();
    assert_eq!(registered.stream_id(), existing["stream_id"].as_str());
    assert_eq!(registered.events_requested().len(), 2);
    assert_eq!(transmitter.streams().len(), 1);
}

#[tokio::test]
async fn registrar_changes_delivery_of_the_only_stream_the_transmitter_allows() {
    let transmitter = TestTransmitter::new();
    let poll = SsfStreamConfiguration::poll(&["CaepSessionRevoked".to_owned()], None);
    let existing = transmitter.add_stream(poll.claims());
    let stream = Arc::new(SsfReceiverStream::new());
    let registrar = SsfStreamRegistrar::for_managed_stream(
        client(&transmitter),
        stream.clone(),
        push_stream(&["CaepSessionRevoked"]),
    );
    let registered = registrar.register().await.unwrap();
    assert_eq!(registered.stream_id(), existing["stream_id"].as_str());
    assert_eq!(registered.delivery_method(), Some("urn:ietf:rfc:8935"));
    assert_eq!(
        registered.delivery_endpoint_url().unwrap().as_str(),
        "https://app.example/ssf/push"
    );
}

#[tokio::test]
async fn registrar_looks_up_stream_created_at_the_transmitter() {
    let transmitter = TestTransmitter::new();
    let existing =
        transmitter.add_stream(SsfStreamConfiguration::poll(&["CaepSessionRevoked".to_owned()], None).claims());
    let stream_id = existing["stream_id"].as_str().unwrap();
    let stream = Arc::new(SsfReceiverStream::new());
    let registrar = SsfStreamRegistrar::for_existing_stream(client(&transmitter), stream.clone(), stream_id);
    registrar.register().await.unwrap();
    assert_eq!(stream.stream_id().as_deref(), Some(stream_id));
    assert_eq!(
        stream
            .configuration()
            .unwrap()
            .delivery_endpoint_url()
            .unwrap()
            .as_str(),
        transmitter.poll_uri()
    );
    let missing =
        SsfStreamRegistrar::for_existing_stream(client(&transmitter), Arc::new(SsfReceiverStream::new()), "missing");
    assert_eq!(missing.register().await.unwrap_err().status(), 404);
}

#[tokio::test]
async fn registrar_retries_in_the_background_until_the_transmitter_answers() {
    let transmitter = TestTransmitter::new();
    transmitter.set_available(false);
    let stream = Arc::new(SsfReceiverStream::new());
    let registrar = SsfStreamRegistrar::for_managed_stream(
        client(&transmitter),
        stream.clone(),
        push_stream(&["CaepSessionRevoked"]),
    )
    .with_initial_retry_delay(Duration::from_millis(20));
    registrar.start();
    eventually(Duration::from_secs(5), "a failed attempt", || {
        registrar.last_error().is_some()
    })
    .await;
    assert_eq!(registrar.state(), SsfStreamRegistrarState::Registering);
    transmitter.set_available(true);
    eventually(Duration::from_secs(5), "the registration", || {
        registrar.state() == SsfStreamRegistrarState::Registered
    })
    .await;
    assert!(registrar.last_error().is_none());
    assert!(stream.stream_id().is_some());
    registrar.stop().await;
}

#[tokio::test]
async fn registrar_deletes_managed_stream_on_shutdown_if_asked() {
    let transmitter = TestTransmitter::new();
    let stream = Arc::new(SsfReceiverStream::new());
    let registrar = SsfStreamRegistrar::for_managed_stream(
        client(&transmitter),
        stream.clone(),
        push_stream(&["CaepSessionRevoked"]),
    )
    .with_delete_on_shutdown(true);
    registrar.start();
    eventually(Duration::from_secs(5), "the registration", || {
        registrar.state() == SsfStreamRegistrarState::Registered
    })
    .await;
    assert_eq!(transmitter.streams().len(), 1);
    registrar.stop().await;
    assert!(transmitter.streams().is_empty());
    // not asked: the stream stays
    let keep = SsfStreamRegistrar::for_managed_stream(
        client(&transmitter),
        Arc::new(SsfReceiverStream::new()),
        push_stream(&["CaepSessionRevoked"]),
    );
    keep.register().await.unwrap();
    keep.stop().await;
    assert_eq!(transmitter.streams().len(), 1);
    let _ = json!({});
}

#[tokio::test]
async fn refuses_existing_streams_with_another_issuer() {
    let transmitter = TestTransmitter::new();
    transmitter.set_stream_issuer(Some("https://other.example"));
    let existing =
        transmitter.add_stream(SsfStreamConfiguration::poll(&["CaepSessionRevoked".to_owned()], None).claims());
    let stream_id = existing["stream_id"].as_str().unwrap();
    let client = client(&transmitter);
    let mismatch = |result: Result<SsfStreamConfiguration, SsfStreamError>| {
        matches!(result, Err(SsfStreamError::IssuerMismatch { .. }))
    };
    assert!(mismatch(client.stream(stream_id).await));
    assert!(matches!(
        client.streams().await,
        Err(SsfStreamError::IssuerMismatch { .. })
    ));
    let mut changes = Map::new();
    changes.insert("description".to_owned(), json!("x"));
    assert!(mismatch(client.update_stream(stream_id, &changes).await));
    assert!(mismatch(
        client
            .replace_stream(
                stream_id,
                &SsfStreamConfiguration::poll(&["CaepSessionRevoked".to_owned()], None)
            )
            .await
    ));
}

#[tokio::test]
async fn registrar_gives_up_on_existing_stream_with_another_issuer_without_deleting_it() {
    let transmitter = TestTransmitter::new();
    transmitter.set_stream_issuer(Some("https://other.example"));
    let existing =
        transmitter.add_stream(SsfStreamConfiguration::poll(&["CaepSessionRevoked".to_owned()], None).claims());
    let stream = Arc::new(SsfReceiverStream::new());
    let registrar = SsfStreamRegistrar::for_existing_stream(
        client(&transmitter),
        stream.clone(),
        existing["stream_id"].as_str().unwrap(),
    )
    .with_initial_retry_delay(Duration::from_millis(50));
    registrar.start();
    eventually(Duration::from_secs(5), "the registrar gave up", || {
        registrar.state() == SsfStreamRegistrarState::Failed
    })
    .await;
    registrar.stop().await;
    assert!(registrar.last_error().unwrap().contains("https://other.example"));
    assert!(stream.stream_id().is_none());
    // the stream is not this registrar's to delete
    assert_eq!(transmitter.streams().len(), 1);

    // nor is one the receiver manages that it found at the transmitter
    let managed = SsfStreamRegistrar::for_managed_stream(
        client(&transmitter),
        Arc::new(SsfReceiverStream::new()),
        SsfStreamConfiguration::poll(&["CaepSessionRevoked".to_owned()], None),
    )
    .with_delete_on_shutdown(true);
    assert!(matches!(
        managed.register().await,
        Err(SsfStreamError::IssuerMismatch { .. })
    ));
    managed.stop().await;
    assert_eq!(transmitter.streams().len(), 1);
}

/// Hands the requests to the transmitter of the tests and records them; holds a list of the
/// streams (`GET .../streams`) until [opened](Self::open), as a transmitter that is slow to answer.
#[derive(Clone)]
struct Gated {
    transmitter: TestTransmitter,
    requests: Arc<Mutex<Vec<String>>>,
    held: Arc<AtomicUsize>,
    open: tokio::sync::watch::Sender<bool>,
}

impl Gated {
    fn new(transmitter: &TestTransmitter, open: bool) -> Self {
        Self {
            transmitter: transmitter.clone(),
            requests: Arc::default(),
            held: Arc::default(),
            open: tokio::sync::watch::Sender::new(open),
        }
    }

    fn open(&self) {
        self.open.send_replace(true);
    }

    fn requests(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    fn client(&self) -> Arc<SsfStreamClient> {
        Arc::new(SsfStreamClient::new(
            self.clone(),
            token_provider(&self.transmitter),
            common::metadata_resolver(&self.transmitter),
        ))
    }
}

#[async_trait]
impl SsfHttpClient for Gated {
    async fn execute(&self, request: SsfHttpRequest) -> Result<SsfHttpResponse, BoxError> {
        self.requests
            .lock()
            .unwrap()
            .push(format!("{} {}", request.method, request.url.path()));
        if request.method == "GET" && request.url.path().ends_with("/streams") {
            self.held.fetch_add(1, Ordering::SeqCst);
            let _ = self.open.subscribe().wait_for(|open| *open).await;
        }
        self.transmitter.execute(request).await
    }
}

fn poll_stream() -> SsfStreamConfiguration {
    SsfStreamConfiguration::poll(&["CaepSessionRevoked".to_owned()], None)
}

#[tokio::test]
async fn registrar_start_is_idempotent_and_stop_ends_the_registration() {
    let transmitter = TestTransmitter::new();
    transmitter.set_available(false);
    let stream = Arc::new(SsfReceiverStream::new());
    let registrar = SsfStreamRegistrar::for_managed_stream(client(&transmitter), stream.clone(), poll_stream())
        .with_initial_retry_delay(Duration::from_millis(20));
    registrar.start();
    registrar.start();
    assert!(registrar.is_running());
    // the metadata cannot be fetched, every attempt asks for it again
    eventually(Duration::from_secs(5), "three attempts", || transmitter.requests() >= 3).await;

    registrar.stop().await;
    registrar.stop().await;
    assert!(!registrar.is_running());
    let requests = transmitter.requests();
    during(Duration::from_millis(200), "no more attempts", || {
        transmitter.requests() == requests
    })
    .await;
    assert!(stream.stream_id().is_none());
}

#[tokio::test]
async fn registration_that_completes_after_stop_publishes_nothing() {
    let transmitter = TestTransmitter::new();
    let http = Gated::new(&transmitter, false);
    let stream = Arc::new(SsfReceiverStream::new());
    let registered = Arc::new(AtomicUsize::new(0));
    let registrar = SsfStreamRegistrar::for_managed_stream(http.client(), stream.clone(), poll_stream())
        .with_delete_on_shutdown(true);
    let counter = registered.clone();
    registrar.add_listener(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
    });
    registrar.start();
    eventually(Duration::from_secs(5), "the list of streams requested", || {
        http.held.load(Ordering::SeqCst) == 1
    })
    .await;

    // stop() lets the call complete, which creates the stream
    let stopping = tokio::spawn({
        let registrar = registrar.clone();
        async move { registrar.stop_with_timeout(Duration::MAX).await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!stopping.is_finished());
    http.open();
    tokio::time::timeout(Duration::from_secs(5), stopping)
        .await
        .unwrap()
        .unwrap();

    // the stream created on the way is deleted, as it would have been on shutdown
    assert!(http.requests.lock().unwrap().iter().any(|r| r.starts_with("POST")));
    assert!(transmitter.streams().is_empty());
    assert_eq!(registered.load(Ordering::SeqCst), 0);
    assert!(stream.stream_id().is_none());
    assert_ne!(registrar.state(), SsfStreamRegistrarState::Registered);
}

#[tokio::test]
async fn stop_with_timeout_abandons_a_call_that_takes_longer() {
    let transmitter = TestTransmitter::new();
    let http = Gated::new(&transmitter, false);
    let stream = Arc::new(SsfReceiverStream::new());
    let registrar = SsfStreamRegistrar::for_managed_stream(http.client(), stream.clone(), poll_stream())
        .with_delete_on_shutdown(true);
    registrar.start();
    eventually(Duration::from_secs(5), "the list of streams requested", || {
        http.held.load(Ordering::SeqCst) == 1
    })
    .await;

    tokio::time::timeout(
        Duration::from_secs(5),
        registrar.stop_with_timeout(Duration::from_millis(100)),
    )
    .await
    .unwrap();
    assert!(!registrar.is_running());

    // the call was dropped, nothing follows it
    http.open();
    during(Duration::from_millis(200), "no stream created", || {
        transmitter.streams().is_empty()
    })
    .await;
    assert!(stream.stream_id().is_none());
}

#[tokio::test]
async fn start_during_stop_waits_for_it() {
    let transmitter = TestTransmitter::new();
    let http = Gated::new(&transmitter, false);
    let stream = Arc::new(SsfReceiverStream::new());
    let registrar = SsfStreamRegistrar::for_managed_stream(http.client(), stream.clone(), poll_stream())
        .with_delete_on_shutdown(true);
    registrar.start();
    eventually(Duration::from_secs(5), "the list of streams requested", || {
        http.held.load(Ordering::SeqCst) == 1
    })
    .await;
    let stopping = tokio::spawn({
        let registrar = registrar.clone();
        async move { registrar.stop_with_timeout(Duration::MAX).await }
    });
    eventually(Duration::from_secs(5), "stop() took the registration", || {
        !registrar.is_running()
    })
    .await;

    registrar.start();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        http.held.load(Ordering::SeqCst),
        1,
        "the new registration waits for stop()"
    );
    http.open();
    tokio::time::timeout(Duration::from_secs(5), stopping)
        .await
        .unwrap()
        .unwrap();
    eventually(Duration::from_secs(5), "the new registration", || {
        registrar.state() == SsfStreamRegistrarState::Registered
    })
    .await;

    // the stream of the stopped registration is gone, the new one is the receiver's
    let streams = transmitter.streams();
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0]["stream_id"].as_str(), stream.stream_id().as_deref());
    registrar.stop().await;
    assert!(transmitter.streams().is_empty());
}

#[tokio::test]
async fn stop_deletes_only_a_stream_published_since_the_last_stop() {
    let transmitter = TestTransmitter::new();
    let http = Gated::new(&transmitter, true);
    let stream = Arc::new(SsfReceiverStream::new());
    let registrar = SsfStreamRegistrar::for_managed_stream(http.client(), stream.clone(), poll_stream())
        .with_delete_on_shutdown(true);

    // never started: nothing to delete
    registrar.stop().await;
    assert_eq!(http.requests(), 0);

    registrar.register().await.unwrap();
    registrar.stop().await;
    assert!(transmitter.streams().is_empty());
    let requests = http.requests();

    // the receiver keeps the stream id, a second stop() does not delete it again
    assert!(stream.stream_id().is_some());
    registrar.stop().await;
    assert_eq!(http.requests(), requests);
}
