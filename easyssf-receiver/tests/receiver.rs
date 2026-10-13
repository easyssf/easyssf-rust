//! The configured receiver: `SsfReceiverOptionsValidator`, `SsfTransmitterFactory` and the
//! hosting integration tests of the .NET port.

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use common::Recorder;
use easyssf_receiver::SsfReceiver;
use easyssf_receiver::config::{SsfDeliveryMethodConfig, SsfReceiverConfig, SsfStreamManagement};
use easyssf_receiver::event::for_event;
use easyssf_receiver::receiver::SsfHealthStatus;
use easyssf_receiver::revocation::{SsfTokenClaims, SsfTokenRevocationStore};
use easyssf_test::subjects::{complex, iss_sub, opaque};
use easyssf_test::{MetadataLocation, TestTransmitter, eventually};
use serde_json::json;

fn push_config(transmitter: &TestTransmitter) -> SsfReceiverConfig {
    toml::from_str(&format!(
        r#"
        transmitter-issuer = "{}"
        expected-audience = "{}"
        [push]
        expected-auth-header = "Bearer s3cr3t"
        "#,
        transmitter.issuer(),
        TestTransmitter::AUDIENCE
    ))
    .unwrap()
}

#[test]
fn config_parses_toml_with_defaults_and_kebab_case_keys() {
    let config: SsfReceiverConfig = toml::from_str(
        r#"
        transmitter-issuer = "https://idp.example/realms/demo"
        delivery-method = "poll"
        event-aliases = { AcmeLoginCfg = "https://events.acme.example/login" }
        [oauth2]
        token-uri = "https://idp.example/token"
        client-id = "app"
        client-secret = "secret"
        scopes = ["ssf.read"]
        client-authentication-method = "post"
        [stream]
        management = "receiver"
        events-requested = ["CaepSessionRevoked"]
        [poll]
        interval = "10s"
        long-polling = true
        [poll.rate-limit]
        fallback-backoff = "2m"
        [set-validation]
        accepted-algorithms = ["RS256", "PS256"]
        subject-compatibility = "legacy"
        [dedup]
        lease = "90s"
        [revocation]
        ttl = "48h"
        [transmitters.okta]
        transmitter-issuer = "https://okta.example"
        expected-audience = "app"
        "#,
    )
    .unwrap();
    assert_eq!(config.transmitter.delivery_method, SsfDeliveryMethodConfig::Poll);
    assert_eq!(config.transmitter.oauth2.scopes, ["ssf.read"]);
    assert_eq!(config.transmitter.stream.management, SsfStreamManagement::Receiver);
    assert_eq!(config.transmitter.poll.interval, Duration::from_secs(10));
    assert!(config.transmitter.poll.long_polling);
    assert_eq!(
        config.transmitter.poll.long_polling_hold,
        Duration::from_secs(30),
        "default"
    );
    assert_eq!(
        config.transmitter.poll.rate_limit.fallback_backoff,
        Some(Duration::from_secs(120))
    );
    assert_eq!(
        config.transmitter.set_validation.effective_accepted_algorithms(),
        ["RS256", "PS256"]
    );
    assert_eq!(config.dedup.lease, Duration::from_secs(90));
    assert_eq!(config.revocation.ttl, Duration::from_secs(48 * 3600));
    assert_eq!(config.transmitter.push.endpoint_path, "/ssf/push");
    assert_eq!(
        config.transmitters["okta"].transmitter_issuer.as_deref(),
        Some("https://okta.example")
    );
    assert_eq!(config.configured_transmitters().unwrap().len(), 2);
    config.validate().unwrap();
    assert_eq!(
        easyssf_core::event_types::resolve("AcmeLoginCfg"),
        "https://events.acme.example/login"
    );
}

#[test]
fn validation_reports_every_failure() {
    let config: SsfReceiverConfig = toml::from_str(
        r#"
        transmitter-issuer = "http://idp.example"
        [push]
        endpoint-path = "ssf"
        [dedup]
        capacity = 0
        [transmitters.default]
        transmitter-issuer = "https://x.example"
        "#,
    )
    .unwrap();
    let error = config.validate().unwrap_err();
    let text = error.to_string();
    assert!(text.contains("transmitters.default"), "{text}");
    let config: SsfReceiverConfig = toml::from_str(
        r#"
        transmitter-issuer = "http://idp.example"
        [push]
        endpoint-path = "ssf"
        [dedup]
        capacity = 0
        [oauth2]
        token-uri = "https://idp.example/token"
        [set-validation]
        accepted-algorithms = ["HS256"]
        "#,
    )
    .unwrap();
    let failures = config.validate().unwrap_err();
    let failures = failures.failures();
    assert!(
        failures
            .iter()
            .any(|f| f.contains("transmitter-issuer") && f.contains("https")),
        "{failures:?}"
    );
    assert!(failures.iter().any(|f| f.contains("expected-audience")), "{failures:?}");
    assert!(failures.iter().any(|f| f.contains("oauth2.client-id")), "{failures:?}");
    assert!(
        failures.iter().any(|f| f.contains("accepted-algorithms")),
        "{failures:?}"
    );
    assert!(
        failures.iter().any(|f| f.contains("push.endpoint-path")),
        "{failures:?}"
    );
    assert!(failures.iter().any(|f| f.contains("dedup")), "{failures:?}");
    // nothing configured
    assert!(
        SsfReceiverConfig::default()
            .validate()
            .unwrap_err()
            .to_string()
            .contains("transmitter-issuer")
    );
    // disabled: anything goes
    let disabled = SsfReceiverConfig {
        enabled: false,
        ..SsfReceiverConfig::default()
    };
    disabled.validate().unwrap();
    // poll without an endpoint
    let mut poll = SsfReceiverConfig::for_transmitter("https://idp.example");
    poll.transmitter.delivery_method = SsfDeliveryMethodConfig::Poll;
    poll.transmitter.expected_audience = Some("a".into());
    assert!(poll.validate().unwrap_err().to_string().contains("poll.endpoint-url"));
    // a managed push stream needs the delivery endpoint
    let mut managed = SsfReceiverConfig::for_transmitter("https://idp.example");
    managed.transmitter.stream.management = SsfStreamManagement::Receiver;
    assert!(
        managed
            .validate()
            .unwrap_err()
            .to_string()
            .contains("push.delivery-endpoint-url")
    );
}

#[tokio::test]
async fn builds_a_push_receiver_and_handles_sets_end_to_end() {
    let transmitter = TestTransmitter::new();
    let recorder = Recorder::default();
    let receiver = SsfReceiver::builder(push_config(&transmitter))
        .http_client(transmitter.clone())
        .handler(for_event("CaepSessionRevoked", recorder.handler()))
        .build()
        .unwrap();
    receiver.start();
    assert_eq!(receiver.push_endpoint_path(), "/ssf/push");
    assert_eq!(receiver.transmitters().all().len(), 1);
    let push = receiver.push_handler();
    let set = transmitter.set(
        "CaepSessionRevoked",
        Some(complex(
            Some(iss_sub(transmitter.issuer(), "alice")),
            Some(opaque("s1")),
        )),
    );
    assert_eq!(push.handle(None, set.as_bytes()).await.status, 401);
    assert_eq!(push.handle(Some("Bearer s3cr3t"), set.as_bytes()).await.status, 202);
    assert_eq!(recorder.count(), 1);
    // the built-in revocation handler filled the store
    let claims = SsfTokenClaims {
        issuer: Some(transmitter.issuer().to_owned()),
        subject: Some("alice".to_owned()),
        session_id: Some("s1".to_owned()),
        issued_at: Some(SystemTime::now()),
    };
    assert!(receiver.token_revocation_store().is_revoked(&claims).await.unwrap());
    // a duplicate is accepted but not handled again
    assert_eq!(push.handle(Some("Bearer s3cr3t"), set.as_bytes()).await.status, 202);
    assert_eq!(recorder.count(), 1);
    let health = receiver.health().await;
    assert_eq!(health.status, SsfHealthStatus::Healthy, "{health:?}");
    assert_eq!(health.transmitters[0].delivery, "push");
    assert!(health.transmitters[0].metadata_resolved);
    receiver.shutdown().await;
}

#[tokio::test]
async fn health_is_degraded_until_the_transmitter_was_reached() {
    let transmitter = TestTransmitter::with_metadata(MetadataLocation::None, None);
    let receiver = SsfReceiver::builder(push_config(&transmitter))
        .http_client(transmitter.clone())
        .build()
        .unwrap();
    let health = receiver.health().await;
    assert_eq!(health.status, SsfHealthStatus::Degraded);
    assert!(!health.transmitters[0].metadata_resolved);
    assert_eq!(health.transmitters[0].name, "default");
    // a SET cannot be verified without the keys: 503, the transmitter delivers it again
    let set = transmitter.set("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    assert_eq!(
        receiver
            .push_handler()
            .handle(Some("Bearer s3cr3t"), set.as_bytes())
            .await
            .status,
        503
    );
}

#[tokio::test]
async fn polling_receiver_registers_its_stream_and_polls() {
    let transmitter = TestTransmitter::new();
    let config: SsfReceiverConfig = toml::from_str(&format!(
        r#"
        transmitter-issuer = "{}"
        delivery-method = "poll"
        [oauth2]
        token-uri = "{}"
        client-id = "{}"
        client-secret = "{}"
        [stream]
        management = "receiver"
        [poll]
        interval = "100ms"
        initial-delay = "0s"
        "#,
        transmitter.issuer(),
        transmitter.token_uri(),
        TestTransmitter::CLIENT_ID,
        TestTransmitter::CLIENT_SECRET
    ))
    .unwrap();
    let recorder = Recorder::default();
    let receiver = SsfReceiver::builder(config)
        .http_client(transmitter.clone())
        .handler(recorder.handler())
        .build()
        .unwrap();
    receiver.start();
    eventually(Duration::from_secs(5), "the stream", || {
        !transmitter.streams().is_empty()
    })
    .await;
    let stream = &transmitter.streams()[0];
    assert_eq!(stream["delivery"]["method"], "urn:ietf:rfc:8936");
    // the audience of the stream is the audience the verifier expects
    let audience = stream["aud"][0].as_str().unwrap().to_owned();
    let mut claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    claims.insert("aud".to_owned(), json!(audience));
    transmitter.queue_set(&transmitter.sign_set(&claims));
    eventually(Duration::from_secs(5), "the SET", || recorder.count() == 1).await;
    eventually(Duration::from_secs(5), "the acknowledgement", || {
        transmitter.acknowledged_sets().len() == 1
    })
    .await;
    // a SET for another audience is reported
    transmitter.queue_set(&transmitter.set("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "bob"))));
    eventually(Duration::from_secs(5), "the error report", || {
        transmitter.reported_errors().len() == 1
    })
    .await;
    assert_eq!(transmitter.reported_errors()[0].1["err"], "invalid_audience");
    let health = receiver.health().await;
    assert_eq!(health.status, SsfHealthStatus::Healthy, "{health:?}");
    assert_eq!(health.transmitters[0].delivery, "poll");
    assert!(health.transmitters[0].stream_id.is_some());
    assert!(health.transmitters[0].last_successful_poll_at.is_some());
    receiver.shutdown().await;
    assert!(!receiver.transmitters().all()[0].poller().unwrap().is_running());
}

#[tokio::test]
async fn sets_are_left_for_redelivery_until_the_stream_tells_the_audience() {
    let transmitter = TestTransmitter::new();
    transmitter.set_available(false);
    let config: SsfReceiverConfig = toml::from_str(&format!(
        r#"
        transmitter-issuer = "{}"
        transmitter-access-token = "{}"
        [stream]
        management = "receiver"
        [push]
        delivery-endpoint-url = "https://app.example/ssf/push"
        "#,
        transmitter.issuer(),
        TestTransmitter::ACCESS_TOKEN
    ))
    .unwrap();
    let receiver = SsfReceiver::builder(config)
        .http_client(transmitter.clone())
        .build()
        .unwrap();
    let push = receiver.push_handler();
    let set = transmitter.set("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    assert_eq!(
        push.handle(None, set.as_bytes()).await.status,
        503,
        "the stream is not registered yet"
    );
    transmitter.set_available(true);
    receiver.start();
    eventually(Duration::from_secs(5), "the stream", || {
        !transmitter.streams().is_empty()
    })
    .await;
    assert_eq!(
        push.handle(None, set.as_bytes()).await.status,
        400,
        "wrong audience now that the stream tells it"
    );
    let audience = transmitter.streams()[0]["aud"][0].as_str().unwrap().to_owned();
    let mut claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    claims.insert("aud".to_owned(), json!(audience));
    assert_eq!(
        push.handle(None, transmitter.sign_set(&claims).as_bytes()).await.status,
        202
    );
    receiver.shutdown().await;
}

#[tokio::test]
async fn several_transmitters_each_authenticate_with_their_own_header() {
    let first = TestTransmitter::with_metadata(MetadataLocation::Ssf, Some("first.example"));
    let second = TestTransmitter::with_metadata(MetadataLocation::Ssf, Some("second.example"));
    /// Routes requests to the transmitter whose host they name.
    struct Router(TestTransmitter, TestTransmitter);
    #[async_trait::async_trait]
    impl easyssf_receiver::http::SsfHttpClient for Router {
        async fn execute(
            &self,
            request: easyssf_receiver::http::SsfHttpRequest,
        ) -> Result<easyssf_receiver::http::SsfHttpResponse, easyssf_receiver::BoxError> {
            if request.url.host_str() == Some("first.example") {
                self.0.execute(request).await
            } else {
                self.1.execute(request).await
            }
        }
    }
    let config: SsfReceiverConfig = toml::from_str(&format!(
        r#"
        transmitter-issuer = "{}"
        expected-audience = "{aud}"
        [push]
        expected-auth-header = "Bearer first"
        [transmitters.second]
        transmitter-issuer = "{}"
        expected-audience = "{aud}"
        [transmitters.second.push]
        expected-auth-header = "Bearer second"
        "#,
        first.issuer(),
        second.issuer(),
        aud = TestTransmitter::AUDIENCE
    ))
    .unwrap();
    let recorder = Recorder::default();
    let receiver = SsfReceiver::builder(config)
        .http_client(Router(first.clone(), second.clone()))
        .handler(recorder.handler())
        .build()
        .unwrap();
    let push = receiver.push_handler();
    let set = second.set("CaepSessionRevoked", Some(iss_sub(second.issuer(), "bob")));
    assert_eq!(push.handle(Some("Bearer first"), set.as_bytes()).await.status, 401);
    assert_eq!(push.handle(Some("Bearer second"), set.as_bytes()).await.status, 202);
    let set = first.set("CaepSessionRevoked", Some(iss_sub(first.issuer(), "alice")));
    assert_eq!(push.handle(Some("Bearer first"), set.as_bytes()).await.status, 202);
    assert_eq!(recorder.count(), 2);
    assert_eq!(receiver.transmitters().name_of(second.issuer()), "second");
    let health = receiver.health().await;
    assert_eq!(health.transmitters.len(), 2);
}

#[tokio::test]
async fn customizer_replaces_parts_before_the_transmitter_is_built() {
    let transmitter = TestTransmitter::new();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let names = seen.clone();
    let receiver = SsfReceiver::builder(push_config(&transmitter))
        .http_client(transmitter.clone())
        .customize_transmitter(move |builder| {
            names.lock().unwrap().push(builder.name.clone());
            builder.push_authorization_header = Some("Bearer custom".to_owned());
        })
        .build()
        .unwrap();
    assert_eq!(*seen.lock().unwrap(), ["default"]);
    let set = transmitter.set("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    assert_eq!(
        receiver
            .push_handler()
            .handle(Some("Bearer custom"), set.as_bytes())
            .await
            .status,
        202
    );
}

#[tokio::test]
async fn disabled_receiver_starts_nothing() {
    let config = SsfReceiverConfig {
        enabled: false,
        ..SsfReceiverConfig::default()
    };
    let error = SsfReceiver::builder(config)
        .http_client(TestTransmitter::new())
        .build()
        .unwrap_err();
    // a disabled receiver has no transmitters, which the assembly refuses
    assert!(error.to_string().contains("transmitters"), "{error}");
}
