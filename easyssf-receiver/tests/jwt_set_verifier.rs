//! `NimbusSsfSetVerifierTests` of the Java library.

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use common::{TestClock, options, verifier, verifier_with};
use easyssf_core::SubjectCompatibilityMode;
use easyssf_receiver::set::{
    HttpSsfJwkSetSource, JwtSsfSetVerifier, SsfErrorCode, SsfSetVerificationError, SsfSetVerifier,
};
use easyssf_test::subjects::{email, iss_sub};
use easyssf_test::{TestSigningKey, TestTransmitter};
use jsonwebtoken::Algorithm;
use serde_json::json;
use url::Url;

fn code(error: SsfSetVerificationError) -> SsfErrorCode {
    match error {
        SsfSetVerificationError::Rejected { code, .. } => code,
        other => panic!("not a rejection: {other}"),
    }
}

#[tokio::test]
async fn verifies_set() {
    let transmitter = TestTransmitter::new();
    let set = transmitter.set("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    let token = verifier(&transmitter).verify(&set).await.unwrap();
    assert_eq!(token.issuer(), transmitter.issuer());
    assert_eq!(token.audience(), [TestTransmitter::AUDIENCE]);
    assert!(
        token
            .events()
            .contains_key(easyssf_core::event_types::CAEP_SESSION_REVOKED)
    );
    assert_eq!(token.subject_id().unwrap()["sub"], "alice");
}

#[tokio::test]
async fn rejects_malformed_set() {
    let transmitter = TestTransmitter::new();
    let verifier = verifier(&transmitter);
    for malformed in ["", "   ", "not.a.jwt", "a.b", "a.b.c.d", "eyJ.eyJ.sig"] {
        assert_eq!(
            code(verifier.verify(malformed).await.unwrap_err()),
            SsfErrorCode::InvalidRequest,
            "{malformed:?}"
        );
    }
}

#[tokio::test]
async fn rejects_set_signed_with_unknown_key() {
    let transmitter = TestTransmitter::new();
    let other = TestSigningKey::generate(2048, "other-key");
    let claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    let set = TestTransmitter::sign(&other, Some(TestTransmitter::SECEVENT_JWT_TYPE), &claims);
    assert_eq!(
        code(verifier(&transmitter).verify(&set).await.unwrap_err()),
        SsfErrorCode::InvalidKey
    );
    // the same kid as the transmitter's key, another key: the signature does not verify
    let forged = TestSigningKey::generate(2048, "test-key");
    let set = TestTransmitter::sign(&forged, Some(TestTransmitter::SECEVENT_JWT_TYPE), &claims);
    assert_eq!(
        code(verifier(&transmitter).verify(&set).await.unwrap_err()),
        SsfErrorCode::InvalidKey
    );
}

#[tokio::test]
async fn rejects_unsigned_set() {
    let transmitter = TestTransmitter::new();
    let claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    let set = TestTransmitter::unsigned(&claims);
    assert_eq!(
        code(verifier(&transmitter).verify(&set).await.unwrap_err()),
        SsfErrorCode::InvalidRequest
    );
}

#[tokio::test]
async fn rejects_algorithm_that_is_not_accepted() {
    let transmitter = TestTransmitter::new();
    let claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    let set = TestTransmitter::sign_with(
        transmitter.key(),
        Algorithm::RS512,
        Some(TestTransmitter::SECEVENT_JWT_TYPE),
        &claims,
    );
    assert_eq!(
        code(verifier(&transmitter).verify(&set).await.unwrap_err()),
        SsfErrorCode::InvalidKey
    );
    let mut accepting = options();
    accepting.accepted_algorithms = vec![Algorithm::RS256, Algorithm::RS512];
    assert!(verifier_with(&transmitter, accepting).verify(&set).await.is_ok());
    let ps = TestTransmitter::sign_with(
        transmitter.key(),
        Algorithm::PS256,
        Some(TestTransmitter::SECEVENT_JWT_TYPE),
        &claims,
    );
    let mut ps_only = options();
    ps_only.accepted_algorithms = vec![Algorithm::PS256];
    assert!(verifier_with(&transmitter, ps_only).verify(&ps).await.is_ok());
}

#[tokio::test]
async fn rejects_signing_key_below_minimum_size() {
    let transmitter = TestTransmitter::new();
    let weak = TestSigningKey::generate(1024, "weak");
    transmitter.publish_jwks(&[transmitter.key(), &weak]);
    let claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    let set = TestTransmitter::sign(&weak, Some(TestTransmitter::SECEVENT_JWT_TYPE), &claims);
    assert_eq!(
        code(verifier(&transmitter).verify(&set).await.unwrap_err()),
        SsfErrorCode::InvalidKey
    );
    let mut any_size = options();
    any_size.min_rsa_key_size = 0;
    assert!(verifier_with(&transmitter, any_size).verify(&set).await.is_ok());
}

#[tokio::test]
async fn rejects_set_that_is_not_typed_as_security_event() {
    let transmitter = TestTransmitter::new();
    let claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    let untyped = TestTransmitter::sign(transmitter.key(), None, &claims);
    assert_eq!(
        code(verifier(&transmitter).verify(&untyped).await.unwrap_err()),
        SsfErrorCode::InvalidRequest
    );
    let mut lenient = options();
    lenient.require_type_header = false;
    assert!(verifier_with(&transmitter, lenient).verify(&untyped).await.is_ok());
    // the type is compared ignoring case
    let upper = TestTransmitter::sign(transmitter.key(), Some("SECEVENT+JWT"), &claims);
    assert!(verifier(&transmitter).verify(&upper).await.is_ok());
}

#[tokio::test]
async fn rejects_access_token_presented_as_set() {
    let transmitter = TestTransmitter::new();
    let access_token = transmitter.access_token("alice", "session-1", SystemTime::now());
    assert_eq!(
        code(verifier(&transmitter).verify(&access_token).await.unwrap_err()),
        SsfErrorCode::InvalidRequest
    );
}

#[tokio::test]
async fn rejects_set_of_another_issuer() {
    let transmitter = TestTransmitter::new();
    let mut claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    claims.insert("iss".to_owned(), json!("https://evil.example"));
    let set = transmitter.sign_set(&claims);
    assert_eq!(
        code(verifier(&transmitter).verify(&set).await.unwrap_err()),
        SsfErrorCode::InvalidIssuer
    );
}

#[tokio::test]
async fn rejects_set_for_another_audience() {
    let transmitter = TestTransmitter::new();
    let mut claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    claims.insert("aud".to_owned(), json!(["https://other.example"]));
    let set = transmitter.sign_set(&claims);
    assert_eq!(
        code(verifier(&transmitter).verify(&set).await.unwrap_err()),
        SsfErrorCode::InvalidAudience
    );
    // one of several audiences is enough
    claims.insert(
        "aud".to_owned(),
        json!(["https://other.example", TestTransmitter::AUDIENCE]),
    );
    assert!(
        verifier(&transmitter)
            .verify(&transmitter.sign_set(&claims))
            .await
            .is_ok()
    );
    // a provider decides per SET
    let mut provided = options();
    provided.expected_audiences = Vec::new();
    provided.expected_audiences_provider = Some(Arc::new(|| Ok(vec!["https://other.example".to_owned()])));
    claims.insert("aud".to_owned(), json!(TestTransmitter::AUDIENCE));
    assert_eq!(
        code(
            verifier_with(&transmitter, provided)
                .verify(&transmitter.sign_set(&claims))
                .await
                .unwrap_err()
        ),
        SsfErrorCode::InvalidAudience
    );
}

#[tokio::test]
async fn accepts_any_audience_when_none_is_expected() {
    let transmitter = TestTransmitter::new();
    let mut claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    claims.insert("aud".to_owned(), json!("https://other.example"));
    let mut any = options();
    any.expected_audiences = Vec::new();
    assert!(
        verifier_with(&transmitter, any.clone())
            .verify(&transmitter.sign_set(&claims))
            .await
            .is_ok()
    );
    claims.remove("aud");
    assert!(
        verifier_with(&transmitter, any)
            .verify(&transmitter.sign_set(&claims))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn rejects_set_without_required_claims() {
    let transmitter = TestTransmitter::new();
    let verifier = verifier(&transmitter);
    for claim in ["jti", "iat", "events"] {
        let mut claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
        claims.remove(claim);
        assert_eq!(
            code(verifier.verify(&transmitter.sign_set(&claims)).await.unwrap_err()),
            SsfErrorCode::InvalidRequest,
            "{claim}"
        );
    }
    let mut claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    claims.insert("events".to_owned(), json!({}));
    assert_eq!(
        code(verifier.verify(&transmitter.sign_set(&claims)).await.unwrap_err()),
        SsfErrorCode::InvalidRequest
    );
    claims.insert("events".to_owned(), json!({ "e": {} }));
    claims.insert("aud".to_owned(), json!(42));
    assert_eq!(
        code(verifier.verify(&transmitter.sign_set(&claims)).await.unwrap_err()),
        SsfErrorCode::InvalidRequest
    );
}

#[tokio::test]
async fn rejects_set_without_top_level_subject_unless_allowed() {
    let transmitter = TestTransmitter::new();
    let mut payload = serde_json::Map::new();
    payload.insert(
        "subject".to_owned(),
        serde_json::Value::Object(email("alice@example.com")),
    );
    let claims = transmitter.set_claims_with_payload("CaepSessionRevoked", None, payload);
    let set = transmitter.sign_set(&claims);
    assert_eq!(
        code(verifier(&transmitter).verify(&set).await.unwrap_err()),
        SsfErrorCode::InvalidRequest
    );
    let mut legacy = options();
    legacy.subject_compatibility = SubjectCompatibilityMode::Legacy;
    let token = verifier_with(&transmitter, legacy).verify(&set).await.unwrap();
    assert!(token.subject_id().is_none());
}

#[tokio::test]
async fn rejects_set_issued_in_the_future() {
    let transmitter = TestTransmitter::new();
    let mut claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    claims.insert("iat".to_owned(), json!(now + 120));
    let set = transmitter.sign_set(&claims);
    assert_eq!(
        code(verifier(&transmitter).verify(&set).await.unwrap_err()),
        SsfErrorCode::InvalidRequest
    );
    // within the clock skew
    claims.insert("iat".to_owned(), json!(now + 30));
    assert!(
        verifier(&transmitter)
            .verify(&transmitter.sign_set(&claims))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn unreachable_jwk_set_is_reported_as_unavailable() {
    let transmitter = TestTransmitter::new();
    transmitter.remove_document("/realms/test/jwks");
    let set = transmitter.set("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    let verifier = verifier(&transmitter);
    assert!(matches!(
        verifier.verify(&set).await.unwrap_err(),
        SsfSetVerificationError::TransmitterUnavailable(_)
    ));
    // not cached: the next SET fetches again
    transmitter.publish_jwks(&[transmitter.key()]);
    assert!(verifier.verify(&set).await.is_ok());
}

#[tokio::test]
async fn fetches_the_jwk_set_again_for_an_unknown_key_but_rate_limited() {
    let transmitter = TestTransmitter::new();
    let clock = TestClock::new();
    let keys = HttpSsfJwkSetSource::new(transmitter.clone(), Url::parse(&transmitter.jwks_uri()).unwrap())
        .with_refresh_rate_limit(Duration::from_secs(30))
        .with_clock(clock.clock());
    let verifier = JwtSsfSetVerifier::new(transmitter.issuer(), keys, options());
    let set = transmitter.set("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    verifier.verify(&set).await.unwrap();
    let fetches = transmitter.requests();

    // the transmitter rotates its key: the first SET with the new kid triggers a fetch
    let rotated = TestSigningKey::generate(2048, "rotated");
    transmitter.publish_jwks(&[&rotated]);
    let claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    let signed_with_rotated = TestTransmitter::sign(&rotated, Some(TestTransmitter::SECEVENT_JWT_TYPE), &claims);
    assert_eq!(
        code(verifier.verify(&signed_with_rotated).await.unwrap_err()),
        SsfErrorCode::InvalidKey
    );
    assert_eq!(
        transmitter.requests(),
        fetches,
        "within the rate limit no fetch happens"
    );
    clock.advance(Duration::from_secs(31));
    verifier.verify(&signed_with_rotated).await.unwrap();
    assert_eq!(transmitter.requests(), fetches + 1);
    // and the old key is gone
    assert_eq!(code(verifier.verify(&set).await.unwrap_err()), SsfErrorCode::InvalidKey);
}

#[tokio::test]
async fn jwk_set_location_is_resolved_from_the_metadata_on_first_use() {
    let transmitter = TestTransmitter::new();
    let resolver = common::metadata_resolver(&transmitter);
    let keys = HttpSsfJwkSetSource::resolved(
        transmitter.clone(),
        Arc::new(move || {
            let resolver = resolver.clone();
            Box::pin(async move {
                let metadata = resolver.resolve().await?;
                Ok(metadata.jwks_uri().cloned().expect("jwks_uri"))
            })
        }),
    );
    let verifier = JwtSsfSetVerifier::new(transmitter.issuer(), keys, options());
    assert_eq!(transmitter.requests(), 0, "nothing is fetched before the first SET");
    let set = transmitter.set("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    verifier.verify(&set).await.unwrap();
    assert_eq!(transmitter.requests(), 2, "metadata and JWK Set");
    verifier.verify(&set).await.unwrap();
    assert_eq!(transmitter.requests(), 2, "both are cached");
}
