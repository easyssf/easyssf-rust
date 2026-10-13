//! `SsfTransmittersTests` and `SsfTransmitterTests` of the Java library.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{Recorder, metadata_resolver, verifier};
use easyssf_core::stream::SsfStreamConfiguration;
use easyssf_receiver::poll::{SsfPoller, SsfPollerOptions};
use easyssf_receiver::push::SsfPushHandler;
use easyssf_receiver::set::{
    InMemorySsfJtiDedupStore, IssuerRoutingSsfSetVerifier, SsfErrorCode, SsfSetProcessor, SsfSetVerifier,
};
use easyssf_receiver::stream::{SsfReceiverStream, SsfStreamClient, SsfStreamRegistrar};
use easyssf_receiver::transmitter::{FixedSsfTransmitterTokenProvider, SsfTransmitter, SsfTransmitters};
use easyssf_test::subjects::iss_sub;
use easyssf_test::{MetadataLocation, TestTransmitter, eventually};
use serde_json::json;

fn transmitter(name: &str, transmitter: &TestTransmitter, header: Option<&str>) -> SsfTransmitter {
    let mut builder = SsfTransmitter::builder(name, transmitter.issuer());
    builder.metadata_resolver = Some(metadata_resolver(transmitter));
    builder.verifier = Some(Arc::new(verifier(transmitter)));
    builder.push_authorization_header = header.map(str::to_owned);
    builder.build()
}

fn two() -> (TestTransmitter, TestTransmitter, SsfTransmitters) {
    let first = TestTransmitter::with_metadata(MetadataLocation::Ssf, Some("first.example"));
    let second = TestTransmitter::with_metadata(MetadataLocation::Ssf, Some("second.example"));
    let transmitters = SsfTransmitters::new(vec![
        transmitter("default", &first, Some("Bearer first")),
        transmitter("second", &second, None),
    ])
    .unwrap();
    (first, second, transmitters)
}

#[tokio::test]
async fn verifies_sets_of_every_transmitter_by_issuer() {
    let (first, second, transmitters) = two();
    let verifier = transmitters.verifier();
    let token = verifier
        .verify(&first.set("CaepSessionRevoked", Some(iss_sub(first.issuer(), "alice"))))
        .await
        .unwrap();
    assert_eq!(token.issuer(), first.issuer());
    let token = verifier
        .verify(&second.set("CaepSessionRevoked", Some(iss_sub(second.issuer(), "bob"))))
        .await
        .unwrap();
    assert_eq!(token.issuer(), second.issuer());
}

#[tokio::test]
async fn rejects_sets_of_unknown_issuers_and_garbage() {
    let (first, _, transmitters) = two();
    let verifier = transmitters.verifier();
    let mut claims = first.set_claims("CaepSessionRevoked", Some(iss_sub(first.issuer(), "alice")));
    claims.insert("iss".to_owned(), json!("https://unknown.example"));
    assert_eq!(
        verifier.verify(&first.sign_set(&claims)).await.unwrap_err().code(),
        Some(SsfErrorCode::InvalidIssuer)
    );
    assert_eq!(
        verifier.verify("garbage").await.unwrap_err().code(),
        Some(SsfErrorCode::InvalidRequest)
    );
    assert_eq!(verifier.verifiers().len(), 2);
    let direct = IssuerRoutingSsfSetVerifier::new(verifier.verifiers().clone());
    assert!(
        direct
            .verify(&first.set("CaepSessionRevoked", Some(iss_sub(first.issuer(), "alice"))))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn push_authenticates_every_transmitter_with_its_own_header() {
    let (first, second, transmitters) = two();
    let transmitters = Arc::new(transmitters);
    let recorder = Recorder::default();
    let processor = Arc::new(
        SsfSetProcessor::new(transmitters.verifier(), InMemorySsfJtiDedupStore::new(10)).handler(recorder.handler()),
    );
    let lookup = transmitters.clone();
    let handler = SsfPushHandler::by_issuer(
        processor,
        Arc::new(move |issuer| lookup.push_authorization_header(issuer)),
    );
    let set = first.set("CaepSessionRevoked", Some(iss_sub(first.issuer(), "alice")));
    assert_eq!(handler.handle(None, set.as_bytes()).await.status, 401);
    assert_eq!(handler.handle(Some("Bearer first"), set.as_bytes()).await.status, 202);
    let set = second.set("CaepSessionRevoked", Some(iss_sub(second.issuer(), "bob")));
    assert_eq!(
        handler.handle(None, set.as_bytes()).await.status,
        202,
        "the second expects no header"
    );
    assert_eq!(recorder.count(), 2);
}

#[test]
fn looks_up_transmitters_by_name_and_issuer() {
    let (first, second, transmitters) = two();
    assert_eq!(transmitters.get("second").unwrap().issuer(), second.issuer());
    assert_eq!(transmitters.by_issuer(first.issuer()).unwrap().name(), "default");
    assert!(transmitters.get("third").is_none());
    assert_eq!(transmitters.name_of(second.issuer()), "second");
    assert_eq!(
        transmitters.name_of("https://unknown.example"),
        "https://unknown.example"
    );
    assert_eq!(
        transmitters.push_authorization_header(first.issuer()).as_deref(),
        Some("Bearer first")
    );
    assert_eq!(transmitters.push_authorization_header(second.issuer()), None);
    assert!(transmitters.stream_verification(first.issuer()).is_some());
    assert!(transmitters.stream_verification("https://unknown.example").is_none());
    assert!(
        transmitters.critical_subject_members(first.issuer()).is_empty(),
        "metadata not resolved yet"
    );
    assert_eq!(transmitters.all().len(), 2);
}

#[test]
fn primary_is_the_only_or_the_default_transmitter() {
    let (_, _, transmitters) = two();
    assert_eq!(transmitters.primary().unwrap().name(), "default");
    let only = TestTransmitter::new();
    let transmitters = SsfTransmitters::new(vec![transmitter("okta", &only, None)]).unwrap();
    assert_eq!(transmitters.primary().unwrap().name(), "okta");
    let a = TestTransmitter::with_metadata(MetadataLocation::Ssf, Some("a.example"));
    let b = TestTransmitter::with_metadata(MetadataLocation::Ssf, Some("b.example"));
    let transmitters = SsfTransmitters::new(vec![transmitter("a", &a, None), transmitter("b", &b, None)]).unwrap();
    assert!(transmitters.primary().is_none());
}

#[test]
fn rejects_duplicate_names_and_issuers() {
    let a = TestTransmitter::with_metadata(MetadataLocation::Ssf, Some("a.example"));
    let b = TestTransmitter::with_metadata(MetadataLocation::Ssf, Some("b.example"));
    let error = SsfTransmitters::new(vec![transmitter("same", &a, None), transmitter("same", &b, None)]).unwrap_err();
    assert!(error.contains("Two transmitters are named 'same'"), "{error}");
    let error = SsfTransmitters::new(vec![transmitter("x", &a, None), transmitter("y", &a, None)]).unwrap_err();
    assert!(error.contains("same issuer"), "{error}");
    assert!(SsfTransmitters::new(vec![]).is_err());
}

#[tokio::test]
async fn poller_fetches_as_soon_as_the_stream_is_registered() {
    let transmitter = TestTransmitter::new();
    let resolver = metadata_resolver(&transmitter);
    let token_provider = FixedSsfTransmitterTokenProvider(TestTransmitter::ACCESS_TOKEN.to_owned());
    let client = Arc::new(SsfStreamClient::new(
        transmitter.clone(),
        token_provider.clone(),
        resolver.clone(),
    ));
    let stream = Arc::new(SsfReceiverStream::new());
    let registrar = SsfStreamRegistrar::for_managed_stream(
        client,
        stream.clone(),
        SsfStreamConfiguration::poll(&["CaepSessionRevoked".to_owned()], None),
    );
    let endpoint_stream = stream.clone();
    let poller = SsfPoller::new(
        transmitter.clone(),
        token_provider,
        Arc::new(move || endpoint_stream.configuration().and_then(|c| c.delivery_endpoint_url())),
        Arc::new(SsfSetProcessor::new(
            verifier(&transmitter),
            InMemorySsfJtiDedupStore::new(10),
        )),
        SsfPollerOptions {
            interval: Duration::from_secs(60),
            endpoint_retry: Duration::from_secs(60),
            ..SsfPollerOptions::default()
        },
    );
    let mut builder = SsfTransmitter::builder("default", transmitter.issuer());
    builder.metadata_resolver = Some(resolver);
    builder.verifier = Some(Arc::new(verifier(&transmitter)));
    builder.receiver_stream = stream;
    builder.stream_registrar = Some(registrar);
    builder.poller = Some(poller);
    let built = builder.build();
    built.start();
    // the poller looked once without an endpoint and would wait a minute; the registration wakes it
    eventually(Duration::from_secs(5), "a poll right after the registration", || {
        transmitter.poll_requests() >= 1
    })
    .await;
    built.stop().await;
    assert!(built.poller().is_some());
    assert!(built.stream_registrar().is_some());
    assert_eq!(built.to_string(), format!("default ({})", transmitter.issuer()));
}
