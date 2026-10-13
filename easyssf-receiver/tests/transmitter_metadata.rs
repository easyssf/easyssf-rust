//! `SsfTransmitterMetadataResolverTests`, `ClientCredentialsSsfTransmitterTokenProviderTests` and
//! the policy test of `SsfTransmitterUriPolicyTests` of the Java library.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::TestClock;
use easyssf_receiver::transmitter::{
    ClientCredentialsSsfTransmitterTokenProvider, SsfClientCredentialsOptions, SsfTransmitterMetadataResolver,
    SsfTransmitterTokenProvider, SsfTransmitterUriPolicy,
};
use easyssf_test::{MetadataLocation, TestTransmitter};
use url::Url;

#[tokio::test]
async fn resolves_metadata_from_ssf_location() {
    let transmitter = TestTransmitter::new();
    let resolver = common::metadata_resolver(&transmitter);
    assert!(resolver.resolved_metadata().is_none());
    let metadata = resolver.resolve().await.unwrap();
    assert_eq!(metadata.issuer(), transmitter.issuer());
    assert_eq!(metadata.jwks_uri().unwrap().as_str(), transmitter.jwks_uri());
    assert_eq!(
        metadata.configuration_endpoint().unwrap().as_str(),
        format!("{}/streams", transmitter.issuer())
    );
    assert_eq!(transmitter.requests(), 1);
    // cached
    resolver.resolve().await.unwrap();
    assert_eq!(transmitter.requests(), 1);
    assert!(resolver.resolved_metadata().is_some());
}

#[tokio::test]
async fn falls_back_to_location_appended_to_issuer() {
    let transmitter = TestTransmitter::with_metadata(MetadataLocation::OidcStyle, None);
    let resolver = common::metadata_resolver(&transmitter);
    let metadata = resolver.resolve().await.unwrap();
    assert_eq!(metadata.issuer(), transmitter.issuer());
    assert_eq!(transmitter.requests(), 2, "the SSF location first, then the fallback");
}

#[tokio::test]
async fn unresolvable_metadata_is_reported_as_unavailable_and_retried() {
    let transmitter = TestTransmitter::with_metadata(MetadataLocation::None, None);
    let resolver = common::metadata_resolver(&transmitter);
    let error = resolver.resolve().await.unwrap_err();
    assert!(
        error.to_string().contains("Could not resolve SSF transmitter metadata"),
        "{error}"
    );
    assert!(resolver.resolved_metadata().is_none());
    transmitter.publish_metadata(MetadataLocation::Ssf);
    assert!(resolver.resolve().await.is_ok());
}

#[tokio::test]
async fn rejects_metadata_of_another_issuer() {
    let transmitter = TestTransmitter::new();
    transmitter.publish_document(
        "/.well-known/ssf-configuration/realms/test",
        r#"{"issuer":"https://evil.example","jwks_uri":"https://evil.example/jwks"}"#,
    );
    let resolver = common::metadata_resolver(&transmitter);
    let error = resolver.resolve().await.unwrap_err();
    assert!(error.to_string().contains("does not match"), "{error}");
}

#[tokio::test]
async fn explicit_metadata_url_is_the_only_location() {
    let transmitter = TestTransmitter::with_metadata(MetadataLocation::None, None);
    transmitter.publish_document(
        "/custom/metadata",
        &format!(
            r#"{{"issuer":"{}","jwks_uri":"{}"}}"#,
            transmitter.issuer(),
            transmitter.jwks_uri()
        ),
    );
    let resolver = SsfTransmitterMetadataResolver::new(
        transmitter.issuer(),
        Some(Url::parse("https://transmitter.example/custom/metadata").unwrap()),
        transmitter.clone(),
        SsfTransmitterUriPolicy::DEFAULT,
    )
    .unwrap();
    assert_eq!(resolver.metadata_uris().len(), 1);
    assert!(resolver.resolve().await.is_ok());
}

#[test]
fn resolver_applies_the_policy_to_the_issuer_and_the_metadata_url() {
    let transmitter = TestTransmitter::new();
    assert!(
        SsfTransmitterMetadataResolver::new(
            "http://idp.example/realms/x",
            None,
            transmitter.clone(),
            SsfTransmitterUriPolicy::DEFAULT
        )
        .is_err()
    );
    assert!(
        SsfTransmitterMetadataResolver::new(
            "http://idp.example/realms/x",
            None,
            transmitter.clone(),
            SsfTransmitterUriPolicy::INSECURE
        )
        .is_ok()
    );
    assert!(
        SsfTransmitterMetadataResolver::new(
            "https://idp.example/realms/x",
            Some(Url::parse("http://idp.example/meta").unwrap()),
            transmitter.clone(),
            SsfTransmitterUriPolicy::DEFAULT
        )
        .is_err()
    );
}

#[tokio::test]
async fn insecure_endpoints_in_the_metadata_are_rejected_unless_allowed() {
    let transmitter = TestTransmitter::new();
    transmitter.publish_document(
        "/.well-known/ssf-configuration/realms/test",
        &format!(
            r#"{{"issuer":"{}","jwks_uri":"http://keys.example/jwks"}}"#,
            transmitter.issuer()
        ),
    );
    let resolver = common::metadata_resolver(&transmitter);
    assert!(resolver.resolve().await.is_err());
    let insecure = SsfTransmitterMetadataResolver::new(
        transmitter.issuer(),
        None,
        transmitter.clone(),
        SsfTransmitterUriPolicy::INSECURE,
    )
    .unwrap();
    assert!(insecure.resolve().await.is_ok());
}

fn token_provider(
    transmitter: &TestTransmitter,
    options: SsfClientCredentialsOptions,
) -> ClientCredentialsSsfTransmitterTokenProvider {
    ClientCredentialsSsfTransmitterTokenProvider::new(
        transmitter.clone(),
        Url::parse(&transmitter.token_uri()).unwrap(),
        TestTransmitter::CLIENT_ID,
        TestTransmitter::CLIENT_SECRET,
        options,
    )
}

#[tokio::test]
async fn token_provider_caches_access_token() {
    let transmitter = TestTransmitter::new();
    let provider = token_provider(&transmitter, SsfClientCredentialsOptions::default());
    assert_eq!(
        provider.access_token().await.unwrap().as_deref(),
        Some(TestTransmitter::ACCESS_TOKEN)
    );
    assert_eq!(
        provider.access_token().await.unwrap().as_deref(),
        Some(TestTransmitter::ACCESS_TOKEN)
    );
    assert_eq!(transmitter.token_requests(), 1);
    provider.invalidate().await;
    provider.access_token().await.unwrap();
    assert_eq!(transmitter.token_requests(), 2);
}

#[tokio::test]
async fn token_provider_authenticates_with_request_body() {
    let transmitter = TestTransmitter::new();
    let provider = token_provider(
        &transmitter,
        SsfClientCredentialsOptions {
            authenticate_with_request_body: true,
            ..SsfClientCredentialsOptions::default()
        },
    );
    assert!(provider.access_token().await.unwrap().is_some());
    assert_eq!(transmitter.token_requests(), 1);
}

#[tokio::test]
async fn token_provider_reports_rejected_credentials() {
    let transmitter = TestTransmitter::new();
    let provider = ClientCredentialsSsfTransmitterTokenProvider::new(
        transmitter.clone(),
        Url::parse(&transmitter.token_uri()).unwrap(),
        "wrong",
        "wrong",
        SsfClientCredentialsOptions::default(),
    );
    let error = provider.access_token().await.unwrap_err();
    assert!(
        error.to_string().contains("Could not obtain an access token"),
        "{error}"
    );
    transmitter.set_available(false);
    let provider = token_provider(&transmitter, SsfClientCredentialsOptions::default());
    assert!(provider.access_token().await.is_err());
}

#[tokio::test]
async fn sends_the_grant_with_scopes_and_additional_parameters() {
    let transmitter = TestTransmitter::new();
    let provider = token_provider(
        &transmitter,
        SsfClientCredentialsOptions {
            scopes: vec!["ssf.read".to_owned(), "ssf.manage".to_owned()],
            additional_parameters: vec![
                ("audience".to_owned(), "ssf api".to_owned()),
                ("grant_type".to_owned(), "ignored".to_owned()),
            ],
            authenticate_with_request_body: true,
            ..SsfClientCredentialsOptions::default()
        },
    );
    // the transmitter checks the form for grant_type, client_id and client_secret
    assert!(provider.access_token().await.unwrap().is_some());
}

#[tokio::test]
async fn renews_the_token_ahead_of_its_expiry_by_the_safety_window() {
    let transmitter = TestTransmitter::new();
    let clock = TestClock::new();
    // the transmitter issues tokens for 300 s; the safety window is 30 s
    let provider = token_provider(
        &transmitter,
        SsfClientCredentialsOptions {
            clock: clock.clock(),
            ..SsfClientCredentialsOptions::default()
        },
    );
    provider.access_token().await.unwrap();
    clock.advance(Duration::from_secs(269));
    provider.access_token().await.unwrap();
    assert_eq!(transmitter.token_requests(), 1);
    clock.advance(Duration::from_secs(2));
    provider.access_token().await.unwrap();
    assert_eq!(transmitter.token_requests(), 2);
}

#[tokio::test]
async fn safety_window_is_configurable_but_at_most_a_quarter_of_the_lifetime() {
    let transmitter = TestTransmitter::new();
    let clock = TestClock::new();
    let provider = token_provider(
        &transmitter,
        SsfClientCredentialsOptions {
            clock: clock.clock(),
            expiry_safety_window: Duration::from_secs(200),
            ..SsfClientCredentialsOptions::default()
        },
    );
    provider.access_token().await.unwrap();
    // 300 s lifetime, window capped at 75 s: renewed after 225 s
    clock.advance(Duration::from_secs(224));
    provider.access_token().await.unwrap();
    assert_eq!(transmitter.token_requests(), 1);
    clock.advance(Duration::from_secs(2));
    provider.access_token().await.unwrap();
    assert_eq!(transmitter.token_requests(), 2);
    let _ = Arc::new(());
}
