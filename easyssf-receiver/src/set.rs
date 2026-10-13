//! SET verification (RFC 8417), de-duplication and the processor.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use easyssf_core::{SsfDeliveryMethod, SsfEventToken, SsfSubject, SubjectCompatibilityMode, event_types};
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};
use url::Url;

use crate::event::{BoxedSsfEventHandler, SsfEventContext, SsfEventHandler};
use crate::http::{SsfHttpClient, SsfHttpRequest};
use crate::metrics::{NoopSsfReceiverMetrics, SsfReceiverMetrics, SsfSetOutcome};
use crate::stream::SsfStreamVerification;
use crate::transmitter::SsfTransmitterUnavailable;
use crate::{BoxError, Clock, system_clock, unix_seconds};

/// The media type a SET must be explicitly typed with (RFC 8417, section 2.3).
pub const SECEVENT_JWT_TYPE: &str = "secevent+jwt";

/// The error codes of RFC 8935, section 2.4, and `invalid_state` of SSF 1.0, section 8.1.4.1.
/// Decided by this crate, not by the JWT library.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsfErrorCode {
    /// `invalid_request`: the SET is malformed or lacks a claim.
    InvalidRequest,
    /// `invalid_key`: the SET is signed with a key the receiver does not accept.
    InvalidKey,
    /// `invalid_issuer`: the SET was issued by another transmitter.
    InvalidIssuer,
    /// `invalid_audience`: the SET is not addressed to this receiver.
    InvalidAudience,
    /// `invalid_state`: the state of a verification event is not the expected one.
    InvalidState,
}

impl SsfErrorCode {
    /// The code as it goes on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidKey => "invalid_key",
            Self::InvalidIssuer => "invalid_issuer",
            Self::InvalidAudience => "invalid_audience",
            Self::InvalidState => "invalid_state",
        }
    }
}

impl std::fmt::Display for SsfErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a SET was not verified.
#[derive(Debug, thiserror::Error)]
pub enum SsfSetVerificationError {
    /// The SET is invalid; the transmitter must not deliver it again. Carries the error code
    /// reported to the transmitter (RFC 8935, section 2.4).
    #[error("{description} ({code})")]
    Rejected {
        /// The RFC 8935 error code.
        code: SsfErrorCode,
        /// For the error document and the log.
        description: String,
    },
    /// The transmitter's metadata or keys could not be obtained: temporary, the SET should be
    /// delivered again.
    #[error(transparent)]
    TransmitterUnavailable(#[from] SsfTransmitterUnavailable),
}

impl SsfSetVerificationError {
    /// A rejection with an error code.
    pub fn rejected(code: SsfErrorCode, description: impl Into<String>) -> Self {
        Self::Rejected {
            code,
            description: description.into(),
        }
    }

    /// The error code of a rejection, `None` if the transmitter was unavailable.
    pub fn code(&self) -> Option<SsfErrorCode> {
        match self {
            Self::Rejected { code, .. } => Some(*code),
            Self::TransmitterUnavailable(_) => None,
        }
    }
}

fn rejected(code: SsfErrorCode, description: impl Into<String>) -> SsfSetVerificationError {
    SsfSetVerificationError::rejected(code, description)
}

/// Verifies an encoded Security Event Token (RFC 8417).
#[async_trait]
pub trait SsfSetVerifier: Send + Sync + 'static {
    /// Verifies the signature and claims of the given SET, in JWS compact serialization.
    async fn verify(&self, encoded_set: &str) -> Result<SsfEventToken, SsfSetVerificationError>;
}

#[async_trait]
impl<T: SsfSetVerifier> SsfSetVerifier for Arc<T> {
    async fn verify(&self, encoded_set: &str) -> Result<SsfEventToken, SsfSetVerificationError> {
        (**self).verify(encoded_set).await
    }
}

#[async_trait]
impl SsfSetVerifier for Arc<dyn SsfSetVerifier> {
    async fn verify(&self, encoded_set: &str) -> Result<SsfEventToken, SsfSetVerificationError> {
        (**self).verify(encoded_set).await
    }
}

/// Reads the `iss` claim of a SET before it is verified, to decide how to verify it. Nothing read
/// this way is trusted. `None` if the SET cannot be parsed or has no issuer.
pub fn unverified_issuer(encoded_set: &str) -> Option<String> {
    unverified_payload(encoded_set)?.get("iss")?.as_str().map(str::to_owned)
}

/// The claims of a SET without any verification: `None` if it is not a JWS in compact
/// serialization whose payload is a JSON object. Nothing read this way is trusted.
pub fn unverified_payload(encoded_set: &str) -> Option<Map<String, Value>> {
    let mut parts = encoded_set.trim().split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let _signature = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        Value::Object(claims) => Some(claims),
        _ => None,
    }
}

/// Where the verifier gets the transmitter's keys.
#[async_trait]
pub trait SsfJwkSetSource: Send + Sync + 'static {
    /// The JWK Set; `refresh` asks for a fetch because a SET named a key that is not in it.
    async fn jwk_set(&self, refresh: bool) -> Result<Arc<JwkSet>, SsfTransmitterUnavailable>;
}

#[async_trait]
impl SsfJwkSetSource for Arc<JwkSet> {
    async fn jwk_set(&self, _refresh: bool) -> Result<Arc<JwkSet>, SsfTransmitterUnavailable> {
        Ok(self.clone())
    }
}

#[async_trait]
impl SsfJwkSetSource for Arc<dyn SsfJwkSetSource> {
    async fn jwk_set(&self, refresh: bool) -> Result<Arc<JwkSet>, SsfTransmitterUnavailable> {
        (**self).jwk_set(refresh).await
    }
}

/// Resolves the location of a JWK Set on first use, for example from the transmitter metadata.
pub type JwkSetUriResolver =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<Url, SsfTransmitterUnavailable>> + Send>> + Send + Sync>;

enum JwkSetUri {
    Fixed(Url),
    Resolved(JwkSetUriResolver),
}

struct JwkSetSnapshot {
    url: Url,
    keys: Arc<JwkSet>,
    fetched_at: SystemTime,
}

/// [`SsfJwkSetSource`] that fetches the JWK Set over HTTP and caches it. The location is resolved
/// on first use, so a transmitter that is not reachable does not prevent the receiver from
/// starting. The JWK Set is fetched again after the [cache lifetime](Self::with_cache_lifetime),
/// and when a SET is signed with a key that is not in it, at most once per
/// [refresh rate limit](Self::with_refresh_rate_limit), so that bogus SETs cannot make the
/// receiver flood the transmitter.
pub struct HttpSsfJwkSetSource {
    http: Arc<dyn SsfHttpClient>,
    uri: JwkSetUri,
    cache_lifetime: Duration,
    refresh_rate_limit: Duration,
    clock: Clock,
    cache: Mutex<Option<Arc<JwkSetSnapshot>>>,
    fetching: tokio::sync::Mutex<()>,
}

impl HttpSsfJwkSetSource {
    /// Fetches the JWK Set at a known location.
    pub fn new(http: impl SsfHttpClient, url: Url) -> Self {
        Self::create(Arc::new(http), JwkSetUri::Fixed(url))
    }

    /// Fetches the JWK Set at a location resolved on first use.
    pub fn resolved(http: impl SsfHttpClient, resolver: JwkSetUriResolver) -> Self {
        Self::create(Arc::new(http), JwkSetUri::Resolved(resolver))
    }

    fn create(http: Arc<dyn SsfHttpClient>, uri: JwkSetUri) -> Self {
        Self {
            http,
            uri,
            cache_lifetime: Duration::from_secs(300),
            refresh_rate_limit: Duration::from_secs(30),
            clock: system_clock(),
            cache: Mutex::new(None),
            fetching: tokio::sync::Mutex::new(()),
        }
    }

    /// How long a fetched JWK Set is used before it is fetched again; five minutes by default.
    pub fn with_cache_lifetime(mut self, lifetime: Duration) -> Self {
        self.cache_lifetime = lifetime;
        self
    }

    /// How soon after a fetch the JWK Set may be fetched again because a SET names a key that is
    /// not in it; 30 seconds by default.
    pub fn with_refresh_rate_limit(mut self, rate_limit: Duration) -> Self {
        self.refresh_rate_limit = rate_limit;
        self
    }

    /// The clock the cache ages by.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    fn needs_fetch(&self, snapshot: &JwkSetSnapshot, now: SystemTime, refresh: bool) -> bool {
        let age = now.duration_since(snapshot.fetched_at).unwrap_or_default();
        age >= self.cache_lifetime || (refresh && age >= self.refresh_rate_limit)
    }

    async fn fetch(&self, url: &Url) -> Result<JwkSet, SsfTransmitterUnavailable> {
        let request =
            SsfHttpRequest::get(url.clone()).with_header("Accept", "application/jwk-set+json, application/json");
        let response = self.http.execute(request).await.map_err(|e| {
            SsfTransmitterUnavailable::caused(format!("Could not retrieve the keys to verify the SET from {url}"), e)
        })?;
        if !response.is_successful() {
            return Err(SsfTransmitterUnavailable::new(format!(
                "The JWK Set endpoint {url} answered with status {}",
                response.status
            )));
        }
        serde_json::from_str(&response.body).map_err(|e| {
            SsfTransmitterUnavailable::caused(format!("The JWK Set endpoint {url} did not answer with a JWK Set"), e)
        })
    }
}

#[async_trait]
impl SsfJwkSetSource for HttpSsfJwkSetSource {
    async fn jwk_set(&self, refresh: bool) -> Result<Arc<JwkSet>, SsfTransmitterUnavailable> {
        let now = (self.clock)();
        if let Some(snapshot) = self.cache.lock().unwrap().clone()
            && !self.needs_fetch(&snapshot, now, refresh)
        {
            return Ok(snapshot.keys.clone());
        }
        let _fetching = self.fetching.lock().await;
        let cached = self.cache.lock().unwrap().clone();
        if let Some(snapshot) = &cached
            && !self.needs_fetch(snapshot, now, refresh)
        {
            return Ok(snapshot.keys.clone());
        }
        let url = match (&cached, &self.uri) {
            (Some(snapshot), _) => snapshot.url.clone(),
            (None, JwkSetUri::Fixed(url)) => url.clone(),
            (None, JwkSetUri::Resolved(resolver)) => resolver().await?,
        };
        let keys = Arc::new(self.fetch(&url).await?);
        let snapshot = Arc::new(JwkSetSnapshot {
            url,
            keys: keys.clone(),
            fetched_at: (self.clock)(),
        });
        *self.cache.lock().unwrap() = Some(snapshot);
        Ok(keys)
    }
}

/// The asymmetric signature algorithms SETs may be signed with: the RSA, RSA-PSS and ECDSA
/// algorithms of RFC 7518, section 3, and EdDSA (RFC 8037).
pub const SUPPORTED_ALGORITHMS: [Algorithm; 9] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// The algorithm with the given JWS name, if it is one of the [`SUPPORTED_ALGORITHMS`].
pub fn supported_algorithm(name: &str) -> Option<Algorithm> {
    let algorithm = Algorithm::from_str(name.trim()).ok()?;
    SUPPORTED_ALGORITHMS.contains(&algorithm).then_some(algorithm)
}

/// Supplies the audiences a SET must be addressed to, consulted for every SET: for example the
/// audience of a stream once it is registered.
pub type ExpectedAudiencesProvider = Arc<dyn Fn() -> Result<Vec<String>, SsfSetVerificationError> + Send + Sync>;

/// How a [`JwtSsfSetVerifier`] verifies SETs; the Java setters. Read for every SET.
#[derive(Clone)]
pub struct SsfSetVerifierOptions {
    /// The audiences a SET must be addressed to; it has to be addressed to at least one of them.
    /// Any audience is accepted while this is empty and no provider is set.
    pub expected_audiences: Vec<String>,
    /// Supplies the audiences instead of [`expected_audiences`](Self::expected_audiences), for
    /// example the audience of a stream once it is registered. Any audience is accepted while the
    /// provider returns none.
    pub expected_audiences_provider: Option<ExpectedAudiencesProvider>,
    /// The JWS algorithms SETs may be signed with, `RS256` by default; only the
    /// [`SUPPORTED_ALGORITHMS`] are allowed.
    pub accepted_algorithms: Vec<Algorithm>,
    /// The minimum size of RSA signing keys in bits, `0` to accept any. 2048 by default.
    pub min_rsa_key_size: usize,
    /// Whether a SET must have a `typ` header of `secevent+jwt` (RFC 8417, section 2.3). `true`
    /// by default.
    pub require_type_header: bool,
    /// How strictly the subject of a SET is validated: [`SubjectCompatibilityMode::Strict`]
    /// requires the top-level `sub_id` claim of SSF 1.0, [`SubjectCompatibilityMode::Legacy`]
    /// accepts SETs of transmitters following earlier drafts, which put the subject into the
    /// event payload.
    pub subject_compatibility: SubjectCompatibilityMode,
    /// How far in the future a SET may be issued according to the local clock. One minute by
    /// default.
    pub clock_skew: Duration,
    /// The clock `iat` is checked against.
    pub clock: Clock,
}

impl Default for SsfSetVerifierOptions {
    fn default() -> Self {
        Self {
            expected_audiences: Vec::new(),
            expected_audiences_provider: None,
            accepted_algorithms: vec![Algorithm::RS256],
            min_rsa_key_size: 2048,
            require_type_header: true,
            subject_compatibility: SubjectCompatibilityMode::Strict,
            clock_skew: Duration::from_secs(60),
            clock: system_clock(),
        }
    }
}

impl std::fmt::Debug for SsfSetVerifierOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsfSetVerifierOptions")
            .field("expected_audiences", &self.expected_audiences)
            .field(
                "expected_audiences_provider",
                &self.expected_audiences_provider.is_some(),
            )
            .field("accepted_algorithms", &self.accepted_algorithms)
            .field("min_rsa_key_size", &self.min_rsa_key_size)
            .field("require_type_header", &self.require_type_header)
            .field("subject_compatibility", &self.subject_compatibility)
            .field("clock_skew", &self.clock_skew)
            .finish()
    }
}

/// [`SsfSetVerifier`] that verifies SET signatures against the transmitter's JWK Set and validates
/// the claims required by RFC 8417 and the SSF profile (`NimbusSsfSetVerifier` in Java,
/// `JwtSsfSetVerifier` in .NET).
///
/// [`jsonwebtoken`] checks the signature only. Every claim rule is applied here, so that the
/// error codes of RFC 8935 stay ours: a SET has no `exp` (RFC 8417, section 2.2), and the
/// defaults of [`Validation`] would reject every SET.
pub struct JwtSsfSetVerifier {
    issuer: String,
    keys: Arc<dyn SsfJwkSetSource>,
    options: SsfSetVerifierOptions,
}

impl JwtSsfSetVerifier {
    /// A verifier for the SETs of one transmitter.
    ///
    /// # Panics
    ///
    /// If `options.accepted_algorithms` is empty or names an algorithm that is not asymmetric.
    pub fn new(issuer: impl Into<String>, keys: impl SsfJwkSetSource, options: SsfSetVerifierOptions) -> Self {
        assert!(
            !options.accepted_algorithms.is_empty(),
            "accepted_algorithms must not be empty"
        );
        for algorithm in &options.accepted_algorithms {
            assert!(
                SUPPORTED_ALGORITHMS.contains(algorithm),
                "Not an asymmetric signature algorithm: {algorithm:?}"
            );
        }
        Self {
            issuer: issuer.into(),
            keys: Arc::new(keys),
            options,
        }
    }

    /// The issuer every SET must be issued by.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// How SETs are verified.
    pub fn options(&self) -> &SsfSetVerifierOptions {
        &self.options
    }

    fn expected_audiences(&self) -> Result<Vec<String>, SsfSetVerificationError> {
        match &self.options.expected_audiences_provider {
            Some(provider) => provider(),
            None => Ok(self.options.expected_audiences.clone()),
        }
    }

    async fn select_key(&self, kid: Option<&str>, algorithm: Algorithm) -> Result<Jwk, SsfSetVerificationError> {
        let keys = self.keys.jwk_set(false).await?;
        if let Some(key) = self.matching(&keys, kid, algorithm) {
            return Ok(key);
        }
        if kid.is_some() {
            // the transmitter may have rotated its keys since the JWK Set was fetched
            let keys = self.keys.jwk_set(true).await?;
            if let Some(key) = self.matching(&keys, kid, algorithm) {
                return Ok(key);
            }
        }
        Err(rejected(
            SsfErrorCode::InvalidKey,
            "The SET is signed with an unknown key",
        ))
    }

    fn matching(&self, keys: &JwkSet, kid: Option<&str>, algorithm: Algorithm) -> Option<Jwk> {
        let candidates: Vec<&Jwk> = keys
            .keys
            .iter()
            .filter(|key| kid.is_none() || key.common.key_id.as_deref() == kid)
            .filter(|key| !matches!(key.common.public_key_use, Some(PublicKeyUse::Encryption)))
            .filter(|key| {
                key.common
                    .key_algorithm
                    .is_none_or(|alg| key_algorithm_matches(alg, algorithm))
            })
            .filter(|key| key_type_matches(key, algorithm))
            .filter(|key| {
                self.options.min_rsa_key_size == 0
                    || rsa_key_bits(key).is_none_or(|bits| bits >= self.options.min_rsa_key_size)
            })
            .collect();
        // without a kid only an unambiguous JWK Set is usable
        match (kid, candidates.as_slice()) {
            (Some(_), [first, ..]) => Some((*first).clone()),
            (None, [only]) => Some((*only).clone()),
            _ => None,
        }
    }

    fn validate_claims(&self, claims: Map<String, Value>) -> Result<SsfEventToken, SsfSetVerificationError> {
        use SsfErrorCode::*;
        if claims.get("iss").and_then(Value::as_str) != Some(self.issuer.as_str()) {
            return Err(rejected(
                InvalidIssuer,
                "The SET was not issued by the expected transmitter",
            ));
        }
        let expected = self.expected_audiences()?;
        let audiences = easyssf_core::event::audiences(claims.get("aud"));
        if let Some(aud) = claims.get("aud")
            && !aud.is_string()
            && !(aud.is_array() && aud.as_array().unwrap().iter().all(Value::is_string))
        {
            return Err(rejected(InvalidRequest, "The aud claim of the SET is malformed"));
        }
        if !expected.is_empty() && !audiences.iter().any(|aud| expected.contains(aud)) {
            return Err(rejected(InvalidAudience, "The SET is not addressed to this receiver"));
        }
        if claims
            .get("jti")
            .and_then(Value::as_str)
            .is_none_or(|jti| jti.trim().is_empty())
        {
            return Err(rejected(InvalidRequest, "The SET has no jti claim"));
        }
        let Some(issued_at) = claims
            .get("iat")
            .and_then(|iat| iat.as_i64().or_else(|| iat.as_f64().map(|f| f as i64)))
        else {
            return Err(rejected(InvalidRequest, "The SET has no iat claim"));
        };
        let now = unix_seconds((self.options.clock)());
        if issued_at > now + self.options.clock_skew.as_secs() as i64 {
            return Err(rejected(InvalidRequest, "The SET was issued in the future"));
        }
        if claims
            .get("events")
            .and_then(Value::as_object)
            .is_none_or(Map::is_empty)
        {
            return Err(rejected(InvalidRequest, "The SET has no events claim"));
        }
        if self.options.subject_compatibility == SubjectCompatibilityMode::Strict
            && claims
                .get("sub_id")
                .and_then(Value::as_object)
                .is_none_or(Map::is_empty)
        {
            return Err(rejected(
                InvalidRequest,
                "The SET has no top-level sub_id claim, which SSF 1.0 requires (the subject compatibility mode \
                 Legacy accepts SETs of transmitters that put the subject into the event)",
            ));
        }
        SsfEventToken::from_claims(claims)
            .ok_or_else(|| rejected(InvalidRequest, "The SET lacks jti, iss, iat or events"))
    }
}

fn key_algorithm_matches(key_algorithm: KeyAlgorithm, algorithm: Algorithm) -> bool {
    key_algorithm.to_string() == format!("{algorithm:?}")
}

fn key_type_matches(key: &Jwk, algorithm: Algorithm) -> bool {
    matches!(
        (&key.algorithm, algorithm),
        (
            AlgorithmParameters::RSA(_),
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512
        ) | (
            AlgorithmParameters::RSA(_),
            Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512
        ) | (
            AlgorithmParameters::EllipticCurve(_),
            Algorithm::ES256 | Algorithm::ES384
        ) | (AlgorithmParameters::OctetKeyPair(_), Algorithm::EdDSA)
    )
}

/// The size of an RSA key in bits, `None` for other key types.
pub fn rsa_key_bits(key: &Jwk) -> Option<usize> {
    let AlgorithmParameters::RSA(rsa) = &key.algorithm else {
        return None;
    };
    let modulus = URL_SAFE_NO_PAD.decode(&rsa.n).ok()?;
    let leading_zeros = modulus.iter().take_while(|byte| **byte == 0).count();
    let bytes = &modulus[leading_zeros..];
    let first = bytes.first()?;
    Some((bytes.len() - 1) * 8 + (8 - first.leading_zeros() as usize))
}

#[async_trait]
impl SsfSetVerifier for JwtSsfSetVerifier {
    async fn verify(&self, encoded_set: &str) -> Result<SsfEventToken, SsfSetVerificationError> {
        use SsfErrorCode::*;
        let encoded_set = encoded_set.trim();
        if encoded_set.is_empty() {
            return Err(rejected(InvalidRequest, "The SET is empty"));
        }
        let parts: Vec<&str> = encoded_set.split('.').collect();
        if parts.len() != 3 || parts[0].is_empty() || parts[1].is_empty() {
            return Err(rejected(
                InvalidRequest,
                "The SET is not a JWS in compact serialization",
            ));
        }
        if parts[2].is_empty() {
            return Err(rejected(InvalidRequest, "The SET is not a signed JWT"));
        }
        let header = jsonwebtoken::decode_header(encoded_set)
            .map_err(|e| rejected(InvalidRequest, format!("The SET is not a signed JWT: {e}")))?;
        let options = &self.options;
        // RFC 8417, section 2.3
        if options.require_type_header
            && !header
                .typ
                .as_deref()
                .is_some_and(|t| t.eq_ignore_ascii_case(SECEVENT_JWT_TYPE))
        {
            return Err(rejected(
                InvalidRequest,
                format!("The SET must be typed with a typ header of {SECEVENT_JWT_TYPE}"),
            ));
        }
        if !options.accepted_algorithms.contains(&header.alg) || !SUPPORTED_ALGORITHMS.contains(&header.alg) {
            return Err(rejected(
                InvalidKey,
                format!(
                    "The SET is signed with the algorithm {:?}, which is not accepted",
                    header.alg
                ),
            ));
        }
        let jwk = self.select_key(header.kid.as_deref(), header.alg).await?;
        let key =
            DecodingKey::from_jwk(&jwk).map_err(|e| rejected(InvalidKey, format!("The key cannot be used: {e}")))?;

        // jsonwebtoken checks the signature only; every claim rule is ours, so that the error
        // code is ours too. A SET has no `exp` (RFC 8417, section 2.2): the defaults of
        // `Validation` would reject every SET.
        let mut validation = Validation::new(header.alg);
        validation.algorithms = vec![header.alg];
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        let claims = jsonwebtoken::decode::<Map<String, Value>>(encoded_set, &key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    rejected(InvalidKey, "The signature of the SET is invalid")
                }
                _ => rejected(InvalidRequest, format!("The SET was rejected: {e}")),
            })?
            .claims;
        self.validate_claims(claims)
    }
}

/// Verifies SETs of several transmitters: the `iss` claim of a SET selects the [`SsfSetVerifier`]
/// of that transmitter, which then verifies the SET, including its issuer. A SET of an unknown
/// issuer is rejected.
pub struct IssuerRoutingSsfSetVerifier {
    verifiers: HashMap<String, Arc<dyn SsfSetVerifier>>,
}

impl IssuerRoutingSsfSetVerifier {
    /// The verifier of each transmitter by its issuer.
    ///
    /// # Panics
    ///
    /// If `verifiers` is empty.
    pub fn new(verifiers: HashMap<String, Arc<dyn SsfSetVerifier>>) -> Self {
        assert!(!verifiers.is_empty(), "verifiers must not be empty");
        Self { verifiers }
    }

    /// The verifiers by issuer.
    pub fn verifiers(&self) -> &HashMap<String, Arc<dyn SsfSetVerifier>> {
        &self.verifiers
    }
}

#[async_trait]
impl SsfSetVerifier for IssuerRoutingSsfSetVerifier {
    async fn verify(&self, encoded_set: &str) -> Result<SsfEventToken, SsfSetVerificationError> {
        let Some(issuer) = unverified_issuer(encoded_set) else {
            return Err(rejected(
                SsfErrorCode::InvalidRequest,
                "The SET cannot be parsed or has no issuer",
            ));
        };
        let Some(verifier) = self.verifiers.get(&issuer) else {
            return Err(rejected(
                SsfErrorCode::InvalidIssuer,
                format!("The SET was issued by '{issuer}', which is not a transmitter of this receiver"),
            ));
        };
        verifier.verify(encoded_set).await
    }
}

/// What a store knows about a SET when it is claimed, and, for a granted claim, the token that
/// fences it against a later take-over of the same SET.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsfJtiClaim {
    /// Not seen before, or abandoned by a crashed instance: the caller handles the SET. The
    /// token is a value the store chooses, for example the time of the claim.
    Granted(i64),
    /// Another instance is handling the SET right now: neither handle nor acknowledge it.
    InProgress,
    /// The SET was handled before: acknowledge it, do not handle it again.
    Processed,
}

impl SsfJtiClaim {
    /// Whether the claim was granted: the caller handles the SET.
    pub fn is_granted(self) -> bool {
        matches!(self, Self::Granted(_))
    }

    /// The token of a granted claim, `0` otherwise.
    pub fn token(self) -> i64 {
        match self {
            Self::Granted(token) => token,
            _ => 0,
        }
    }
}

/// Remembers which SETs were processed, so that a redelivery of a handled SET is skipped and a
/// SET another instance is handling is left alone. It does not make handling exactly once: an
/// instance that dies after a handler ran and before [`processed`](Self::processed) hands the SET
/// to the next instance after the lease, which is why handlers are idempotent. Implement it to
/// back it with a shared or durable store.
///
/// A SET is [claimed](Self::claim) before its handlers run and marked
/// [processed](Self::processed) once they succeeded. In between it is *in progress*: another
/// instance of the application that receives the same SET then neither handles nor acknowledges
/// it, and leaves it to the transmitter's redelivery. An instance that crashes mid-processing
/// leaves the claim behind, so a claim older than the store's lease counts as abandoned and the
/// next instance takes the SET over.
///
/// A granted claim carries a token that fences it: [`processed`](Self::processed),
/// [`forget`](Self::forget) and [`renew`](Self::renew) only act on the claim with that token. An
/// instance whose handlers outlived the lease therefore neither completes nor deletes the claim
/// of the instance that took the SET over; the SET belongs to the new holder. An instance whose
/// handlers may run longer than the lease renews its claim meanwhile.
#[async_trait]
pub trait SsfJtiDedupStore: Send + Sync + 'static {
    /// Atomically records that the caller is about to handle the SET, unless it was handled
    /// before or is being handled by another instance.
    async fn claim(&self, token: &SsfEventToken) -> Result<SsfJtiClaim, BoxError>;

    /// Records that the handlers of a claimed SET succeeded. Does nothing if the claim was taken
    /// over meanwhile, because the handlers outlived the lease.
    async fn processed(&self, token: &SsfEventToken, claim: SsfJtiClaim) -> Result<(), BoxError>;

    /// Forgets the given SET again, because handling it failed and it is expected to be
    /// delivered once more. Does nothing if the claim was taken over meanwhile.
    async fn forget(&self, token: &SsfEventToken, claim: SsfJtiClaim) -> Result<(), BoxError>;

    /// Extends the claim of a SET whose handlers are still running: its age starts over, so it
    /// does not count as abandoned after the lease. Returns the claim to use from now on, as a
    /// store may give a renewed claim a new token; `None` if the claim was taken over, the SET
    /// then belongs to the instance that took it over. A store that does not renew returns the
    /// claim as it is, which leaves the lease as the bound for the handlers.
    async fn renew(&self, token: &SsfEventToken, claim: SsfJtiClaim) -> Result<Option<SsfJtiClaim>, BoxError> {
        let _ = token;
        Ok(Some(claim))
    }
}

#[async_trait]
impl<T: SsfJtiDedupStore> SsfJtiDedupStore for Arc<T> {
    async fn claim(&self, token: &SsfEventToken) -> Result<SsfJtiClaim, BoxError> {
        (**self).claim(token).await
    }

    async fn processed(&self, token: &SsfEventToken, claim: SsfJtiClaim) -> Result<(), BoxError> {
        (**self).processed(token, claim).await
    }

    async fn forget(&self, token: &SsfEventToken, claim: SsfJtiClaim) -> Result<(), BoxError> {
        (**self).forget(token, claim).await
    }

    async fn renew(&self, token: &SsfEventToken, claim: SsfJtiClaim) -> Result<Option<SsfJtiClaim>, BoxError> {
        (**self).renew(token, claim).await
    }
}

#[async_trait]
impl SsfJtiDedupStore for Arc<dyn SsfJtiDedupStore> {
    async fn claim(&self, token: &SsfEventToken) -> Result<SsfJtiClaim, BoxError> {
        (**self).claim(token).await
    }

    async fn processed(&self, token: &SsfEventToken, claim: SsfJtiClaim) -> Result<(), BoxError> {
        (**self).processed(token, claim).await
    }

    async fn forget(&self, token: &SsfEventToken, claim: SsfJtiClaim) -> Result<(), BoxError> {
        (**self).forget(token, claim).await
    }

    async fn renew(&self, token: &SsfEventToken, claim: SsfJtiClaim) -> Result<Option<SsfJtiClaim>, BoxError> {
        (**self).renew(token, claim).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KnownState {
    InProgress,
    Processed,
}

#[derive(Debug, Clone, Copy)]
struct Known {
    state: KnownState,
    since: SystemTime,
    token: i64,
    sequence: u64,
}

struct InMemoryEntries {
    entries: HashMap<String, Known>,
    order: VecDeque<(String, u64)>,
    next_sequence: u64,
    next_token: i64,
}

/// [`SsfJtiDedupStore`] that remembers a bounded number of SETs in memory, evicting the oldest
/// first. Its content is lost on restart and not shared between instances, so the in-progress
/// state only matters when the same SET arrives twice while a handler of this instance still
/// runs.
pub struct InMemorySsfJtiDedupStore {
    capacity: usize,
    lease: Duration,
    clock: Clock,
    inner: Mutex<InMemoryEntries>,
}

impl InMemorySsfJtiDedupStore {
    /// The lease by default: 60 seconds.
    pub const DEFAULT_LEASE: Duration = Duration::from_secs(60);

    /// A store that remembers `capacity` SETs, at least one.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            lease: Self::DEFAULT_LEASE,
            clock: system_clock(),
            inner: Mutex::new(InMemoryEntries {
                entries: HashMap::new(),
                order: VecDeque::new(),
                next_sequence: 0,
                next_token: 0,
            }),
        }
    }

    /// Sets how long a claim holds before the SET counts as abandoned by a crashed or stuck
    /// handler and is handled again; 60 seconds by default, longer than the longest handler.
    pub fn with_lease(mut self, lease: Duration) -> Self {
        assert!(!lease.is_zero(), "lease must be positive");
        self.lease = lease;
        self
    }

    /// The clock the lease is measured by.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// The number of SETs remembered.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }

    /// Whether no SET is remembered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn put(&self, inner: &mut InMemoryEntries, key: String, state: KnownState, token: i64) {
        let sequence = inner.next_sequence;
        inner.next_sequence += 1;
        inner.entries.insert(
            key.clone(),
            Known {
                state,
                since: (self.clock)(),
                token,
                sequence,
            },
        );
        inner.order.push_back((key, sequence));
        while inner.entries.len() > self.capacity {
            let Some((oldest, oldest_sequence)) = inner.order.pop_front() else {
                break;
            };
            if inner
                .entries
                .get(&oldest)
                .is_some_and(|known| known.sequence == oldest_sequence)
            {
                inner.entries.remove(&oldest);
            }
        }
        // drop stale order entries now and then so the deque does not grow without bound
        if inner.order.len() > self.capacity * 2 + 16 {
            let entries = &inner.entries;
            inner
                .order
                .retain(|(key, sequence)| entries.get(key).is_some_and(|known| known.sequence == *sequence));
        }
    }

    fn grant(&self, inner: &mut InMemoryEntries, key: String) -> SsfJtiClaim {
        inner.next_token += 1;
        let token = inner.next_token;
        self.put(inner, key, KnownState::InProgress, token);
        SsfJtiClaim::Granted(token)
    }
}

impl Default for InMemorySsfJtiDedupStore {
    fn default() -> Self {
        Self::new(10_000)
    }
}

fn holds(known: &Known, claim: SsfJtiClaim) -> bool {
    known.state == KnownState::InProgress && known.token == claim.token()
}

#[async_trait]
impl SsfJtiDedupStore for InMemorySsfJtiDedupStore {
    async fn claim(&self, token: &SsfEventToken) -> Result<SsfJtiClaim, BoxError> {
        let key = token.idempotency_key();
        let now = (self.clock)();
        let mut inner = self.inner.lock().unwrap();
        let Some(known) = inner.entries.get(&key).copied() else {
            return Ok(self.grant(&mut inner, key));
        };
        if known.state == KnownState::Processed {
            return Ok(SsfJtiClaim::Processed);
        }
        if known.since + self.lease <= now {
            // abandoned: taken over, with a token of its own
            return Ok(self.grant(&mut inner, key));
        }
        Ok(SsfJtiClaim::InProgress)
    }

    async fn processed(&self, token: &SsfEventToken, claim: SsfJtiClaim) -> Result<(), BoxError> {
        let key = token.idempotency_key();
        let mut inner = self.inner.lock().unwrap();
        // the claim may have been evicted meanwhile: record the success anyway
        if inner.entries.get(&key).is_none_or(|known| holds(known, claim)) {
            self.put(&mut inner, key, KnownState::Processed, claim.token());
        }
        Ok(())
    }

    async fn forget(&self, token: &SsfEventToken, claim: SsfJtiClaim) -> Result<(), BoxError> {
        let key = token.idempotency_key();
        let mut inner = self.inner.lock().unwrap();
        if inner.entries.get(&key).is_some_and(|known| holds(known, claim)) {
            inner.entries.remove(&key);
        }
        Ok(())
    }

    async fn renew(&self, token: &SsfEventToken, claim: SsfJtiClaim) -> Result<Option<SsfJtiClaim>, BoxError> {
        let key = token.idempotency_key();
        let mut inner = self.inner.lock().unwrap();
        if inner.entries.get(&key).is_some_and(|known| !holds(known, claim)) {
            return Ok(None);
        }
        // an evicted claim is restored, as processed() records it as well
        self.put(&mut inner, key, KnownState::InProgress, claim.token());
        Ok(Some(claim))
    }
}

/// What happened to a valid SET.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsfSetProcessingOutcome {
    /// The SET was handled by all handlers.
    Handled,
    /// The SET was processed before and has been skipped.
    Duplicate,
}

/// Why a SET was not processed.
#[derive(Debug, thiserror::Error)]
pub enum SsfSetProcessingError {
    /// The SET is invalid or could not be verified.
    #[error(transparent)]
    Verification(#[from] SsfSetVerificationError),
    /// Another instance is handling the SET; leave it for redelivery.
    #[error("the SET is being handled by another instance")]
    InProgress,
    /// A handler failed; the SET must be delivered again.
    #[error("{failed} handler(s) failed for the SET, the first with: {first}")]
    Handling {
        /// How many handlers returned an error.
        failed: usize,
        /// The error of the first handler that failed.
        first: BoxError,
    },
    /// The dedup store failed.
    #[error("the dedup store failed: {0}")]
    Store(#[source] BoxError),
}

/// Looks up the stream verification of a transmitter by its issuer.
pub type StreamVerifications = Arc<dyn Fn(&str) -> Option<Arc<SsfStreamVerification>> + Send + Sync>;

/// Looks up the `critical_subject_members` a transmitter declares in its metadata, by its issuer;
/// empty for an unknown issuer.
pub type CriticalSubjectMembers = Arc<dyn Fn(&str) -> Vec<String> + Send + Sync>;

/// How an [`SsfSetProcessor`] processes SETs beyond verifying, de-duplicating and handling them.
#[derive(Clone)]
pub struct SsfSetProcessorOptions {
    /// Records what the processor does. Records nothing by default.
    pub metrics: Arc<dyn SsfReceiverMetrics>,
    /// The stream verification of a transmitter by its issuer: validates stream verification
    /// events before the handlers see them. Verification events are accepted unchecked while this
    /// is `None`.
    pub stream_verifications: Option<StreamVerifications>,
    /// The members of a complex subject the application interprets. A SET whose subject has a
    /// member the transmitter declared critical (`critical_subject_members` of its metadata) that
    /// is not among them is rejected as `invalid_request`, as the SSF specification requires
    /// critical members to be interpreted by the receiver. By default the members
    /// [`SsfSubject`] gives access to, [`SsfSubject::MEMBERS`].
    pub understood_subject_members: BTreeSet<String>,
    /// The `critical_subject_members` a transmitter declares in its metadata, by its issuer.
    /// Nothing is critical while this is `None`.
    pub critical_subject_members: Option<CriticalSubjectMembers>,
    /// Renews the claim of a SET at this interval while its handlers run
    /// ([`SsfJtiDedupStore::renew`]), so that a handler that runs longer than the lease of the
    /// dedup store does not lose the SET to another instance; a third of the lease is a good
    /// interval. `None`, the default, turns renewal off: the lease then bounds the handlers. A
    /// renewal that finds the claim taken over stops, and the result of the handlers is not
    /// recorded, as without renewal after the lease.
    pub claim_renewal: Option<Duration>,
}

impl Default for SsfSetProcessorOptions {
    fn default() -> Self {
        Self {
            metrics: Arc::new(NoopSsfReceiverMetrics),
            stream_verifications: None,
            understood_subject_members: SsfSubject::MEMBERS.iter().map(|m| (*m).to_owned()).collect(),
            critical_subject_members: None,
            claim_renewal: None,
        }
    }
}

/// Processes a received SET independent of how it was delivered: verifies it, skips it if it was
/// processed before and hands it to the [handlers](SsfEventHandler).
///
/// With an [`SsfJtiDedupStore`] the SET is claimed while the handlers run. A
/// [claim renewal](SsfSetProcessorOptions::claim_renewal) keeps the claim alive while a handler
/// runs longer than the store's lease; without it the lease bounds the handlers.
pub struct SsfSetProcessor {
    verifier: Arc<dyn SsfSetVerifier>,
    dedup: Option<Arc<dyn SsfJtiDedupStore>>,
    handlers: Vec<BoxedSsfEventHandler>,
    options: SsfSetProcessorOptions,
}

impl SsfSetProcessor {
    /// A processor without handlers; add them with [`handler`](Self::handler).
    pub fn new(verifier: impl SsfSetVerifier, dedup: impl SsfJtiDedupStore) -> Self {
        Self {
            verifier: Arc::new(verifier),
            dedup: Some(Arc::new(dedup)),
            handlers: Vec::new(),
            options: SsfSetProcessorOptions::default(),
        }
    }

    /// A processor that processes duplicates: no dedup store.
    pub fn without_dedup(verifier: impl SsfSetVerifier) -> Self {
        Self {
            verifier: Arc::new(verifier),
            dedup: None,
            handlers: Vec::new(),
            options: SsfSetProcessorOptions::default(),
        }
    }

    /// Adds a handler; every handler is called, in order, for every verified SET.
    pub fn handler(mut self, handler: impl SsfEventHandler) -> Self {
        self.handlers.push(Arc::new(handler));
        self
    }

    /// Adds a handler held type-erased.
    pub fn boxed_handler(mut self, handler: BoxedSsfEventHandler) -> Self {
        self.handlers.push(handler);
        self
    }

    /// Sets the options.
    pub fn options(mut self, options: SsfSetProcessorOptions) -> Self {
        self.options = options;
        self
    }

    /// The number of handlers.
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }

    /// Verifies and handles the given SET, in JWS compact serialization.
    pub async fn process(
        &self,
        encoded_set: &str,
        delivery: SsfDeliveryMethod,
    ) -> Result<SsfSetProcessingOutcome, SsfSetProcessingError> {
        let metrics = &self.options.metrics;
        let unverified_issuer = unverified_issuer(encoded_set);
        let token = match self.verify(encoded_set).await {
            Ok(token) => token,
            Err(error) => {
                let outcome = match &error {
                    SsfSetVerificationError::Rejected { .. } => SsfSetOutcome::Invalid,
                    SsfSetVerificationError::TransmitterUnavailable(_) => SsfSetOutcome::Unavailable,
                };
                metrics.set_received(unverified_issuer.as_deref(), delivery, outcome);
                return Err(error.into());
            }
        };
        let issuer = token.issuer().to_owned();
        let context = SsfEventContext::new(token.clone(), delivery);
        let mut claim = None;
        if let Some(dedup) = &self.dedup {
            match dedup.claim(&token).await.map_err(SsfSetProcessingError::Store)? {
                SsfJtiClaim::Processed => {
                    tracing::debug!(jti = token.jti(), "Skipping SET, it was processed before");
                    metrics.set_received(Some(&issuer), delivery, SsfSetOutcome::Duplicate);
                    return Ok(SsfSetProcessingOutcome::Duplicate);
                }
                SsfJtiClaim::InProgress => {
                    tracing::debug!(
                        jti = token.jti(),
                        "Leaving SET for a redelivery, another instance is handling it"
                    );
                    metrics.set_received(Some(&issuer), delivery, SsfSetOutcome::InProgress);
                    return Err(SsfSetProcessingError::InProgress);
                }
                granted => claim = Some(granted),
            }
        }
        tracing::debug!(
            jti = token.jti(),
            delivery = %delivery,
            events = ?context.event_types().iter().map(|e| event_types::alias_of(e)).collect::<Vec<_>>(),
            "Received SET"
        );
        if context.has_event(event_types::SSF_STREAM_VERIFICATION) {
            tracing::info!(transmitter = issuer, "Received stream verification event");
        }
        let renewal = match (claim, &self.dedup, self.options.claim_renewal) {
            (Some(claim), Some(dedup), Some(interval)) => {
                Some(ClaimRenewal::start(dedup.clone(), token.clone(), claim, interval))
            }
            _ => None,
        };
        let mut failed = 0;
        let mut first: Option<BoxError> = None;
        // every handler runs, also after one failed: a failing handler must not keep the others
        // from reacting to the event
        for handler in &self.handlers {
            if let Err(error) = handler.handle_dyn(context.clone()).await {
                tracing::error!(jti = token.jti(), handler = handler.name(), %error, "An event handler failed");
                failed += 1;
                first.get_or_insert(error);
            }
        }
        if let Some(renewal) = renewal {
            // the claim as last renewed; a taken-over one no longer belongs to this instance, so
            // the outcome of the handlers is not recorded
            claim = renewal.stop().await;
        }
        if let Some(first) = first {
            if let (Some(dedup), Some(claim)) = (&self.dedup, claim) {
                dedup
                    .forget(&token, claim)
                    .await
                    .map_err(SsfSetProcessingError::Store)?;
            }
            metrics.set_received(Some(&issuer), delivery, SsfSetOutcome::Failed);
            return Err(SsfSetProcessingError::Handling { failed, first });
        }
        if let (Some(dedup), Some(claim)) = (&self.dedup, claim) {
            dedup
                .processed(&token, claim)
                .await
                .map_err(SsfSetProcessingError::Store)?;
        }
        metrics.set_received(Some(&issuer), delivery, SsfSetOutcome::Handled);
        for event_type in context.event_types() {
            metrics.event_handled(Some(&issuer), &event_type, delivery);
        }
        Ok(SsfSetProcessingOutcome::Handled)
    }

    async fn verify(&self, encoded_set: &str) -> Result<SsfEventToken, SsfSetVerificationError> {
        let token = self.verifier.verify(encoded_set).await?;
        let context = SsfEventContext::new(token.clone(), SsfDeliveryMethod::Push);
        if let Some(verifications) = &self.options.stream_verifications
            && let Some(verification) = verifications(token.issuer())
        {
            verification.validate(&context)?;
        }
        self.check_critical_subject_members(&context)?;
        Ok(token)
    }

    fn check_critical_subject_members(&self, context: &SsfEventContext) -> Result<(), SsfSetVerificationError> {
        let Some(critical) = &self.options.critical_subject_members else {
            return Ok(());
        };
        let critical = critical(context.event_token().issuer());
        if critical.is_empty() {
            return Ok(());
        }
        let present = context.subject().member_names();
        let not_understood: Vec<&String> = critical
            .iter()
            .filter(|member| present.contains(*member) && !self.options.understood_subject_members.contains(*member))
            .collect();
        if not_understood.is_empty() {
            return Ok(());
        }
        Err(rejected(
            SsfErrorCode::InvalidRequest,
            format!(
                "The subject has the members {not_understood:?} which the transmitter declared critical and this receiver does not understand"
            ),
        ))
    }
}

struct RenewalState {
    claim: Option<SsfJtiClaim>,
    stopped: bool,
}

/// The claim of a SET in progress, renewed at an interval until the handlers are done. A renewal
/// and the end of the handlers exclude each other, so the claim the outcome is recorded with is
/// the one the store holds.
struct ClaimRenewal {
    state: Arc<tokio::sync::Mutex<RenewalState>>,
    task: tokio::task::JoinHandle<()>,
}

impl ClaimRenewal {
    fn start(dedup: Arc<dyn SsfJtiDedupStore>, token: SsfEventToken, claim: SsfJtiClaim, interval: Duration) -> Self {
        let state = Arc::new(tokio::sync::Mutex::new(RenewalState {
            claim: Some(claim),
            stopped: false,
        }));
        let renewing = state.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let mut state = renewing.lock().await;
                if state.stopped {
                    return;
                }
                let Some(claim) = state.claim else {
                    return;
                };
                match dedup.renew(&token, claim).await {
                    Ok(Some(renewed)) => state.claim = Some(renewed),
                    Ok(None) => {
                        tracing::warn!(
                            jti = token.jti(),
                            "SET was taken over by another instance while its handlers were still running; the lease of the dedup store is shorter than they take"
                        );
                        state.claim = None;
                        state.stopped = true;
                        return;
                    }
                    // tried again at the next interval
                    Err(error) => tracing::warn!(jti = token.jti(), %error, "Could not renew the claim of the SET"),
                }
            }
        });
        Self { state, task }
    }

    /// The claim as last renewed, once no renewal runs any more; `None` if it was taken over.
    async fn stop(self) -> Option<SsfJtiClaim> {
        let claim = {
            let mut state = self.state.lock().await;
            state.stopped = true;
            state.claim
        };
        self.task.abort();
        claim
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unverified_claims_are_read_without_verification() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"iss":"https://t.example","jti":"1"}"#);
        let set = format!("eyJhbGciOiJSUzI1NiJ9.{payload}.sig");
        assert_eq!(unverified_issuer(&set).as_deref(), Some("https://t.example"));
        assert_eq!(unverified_issuer("garbage"), None);
        assert_eq!(unverified_issuer(""), None);
        assert_eq!(unverified_issuer("a.b.c.d"), None);
        let array = URL_SAFE_NO_PAD.encode(b"[1]");
        assert!(unverified_payload(&format!("h.{array}.s")).is_none());
    }

    #[test]
    fn supported_algorithms_are_asymmetric() {
        assert_eq!(supported_algorithm("RS256"), Some(Algorithm::RS256));
        assert_eq!(supported_algorithm(" ES384 "), Some(Algorithm::ES384));
        assert_eq!(supported_algorithm("HS256"), None);
        assert_eq!(supported_algorithm("none"), None);
    }

    #[test]
    fn rsa_key_bits_counts_the_modulus() {
        let n = URL_SAFE_NO_PAD.encode([0x80u8; 256]);
        let jwk: Jwk = serde_json::from_value(serde_json::json!({ "kty": "RSA", "n": n, "e": "AQAB" })).unwrap();
        assert_eq!(rsa_key_bits(&jwk), Some(2048));
        let short = URL_SAFE_NO_PAD.encode([0x01u8; 128]);
        let jwk: Jwk = serde_json::from_value(serde_json::json!({ "kty": "RSA", "n": short, "e": "AQAB" })).unwrap();
        assert_eq!(rsa_key_bits(&jwk), Some(1017));
        let ec: Jwk =
            serde_json::from_value(serde_json::json!({ "kty": "EC", "crv": "P-256", "x": "AA", "y": "AA" })).unwrap();
        assert_eq!(rsa_key_bits(&ec), None);
    }
}
