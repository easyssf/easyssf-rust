//! `TestTransmitter`: a minimal SSF transmitter / identity provider for the tests of a receiver.
//! It publishes transmitter metadata and a JWK Set, signs SETs and access tokens, issues access
//! tokens for the client credentials grant and offers stream management and a poll endpoint that
//! behave like the ones of Keycloak. Everything is served in-process through the receiver's
//! [`SsfHttpClient`] trait: give the receiver under test the transmitter as its HTTP client, no
//! socket is involved.
//!
//! ```
//! # use easyssf_test::{TestTransmitter, subjects::{complex, iss_sub, opaque}};
//! let transmitter = TestTransmitter::new();
//! let mut claims = transmitter.set_claims("CaepSessionRevoked", Some(complex(Some(iss_sub(transmitter.issuer(), "alice")), Some(opaque("session-1")))));
//! claims.insert("aud".to_owned(), "https://my-app.example".into());
//! let encoded_set = transmitter.sign_set(&claims);
//! // POST encoded_set to /ssf/push, or transmitter.queue_set(&encoded_set) for a polling receiver
//! ```

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use easyssf_receiver::BoxError;
use easyssf_receiver::http::{SsfHttpClient, SsfHttpRequest, SsfHttpResponse};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde_json::{Map, Value, json};
use tokio::sync::Notify;

pub use easyssf_core::event::subjects;

/// An RSA key pair a [`TestTransmitter`] signs with, together with its `kid`. Keys of any size
/// can be generated, so that tests can sign with keys a receiver has to reject.
#[derive(Clone)]
pub struct TestSigningKey {
    kid: String,
    bits: usize,
    encoding_key: EncodingKey,
    jwk: Value,
}

impl TestSigningKey {
    /// Generates a key pair; `TestSigningKey::generate(1024, "weak")` is one a receiver refuses.
    pub fn generate(bits: usize, kid: &str) -> Self {
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), bits).expect("RSA key");
        let pem = key.to_pkcs1_pem(Default::default()).expect("PEM");
        let jwk = json!({
            "kty": "RSA", "use": "sig", "kid": kid,
            "n": URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(key.e().to_bytes_be()),
        });
        Self {
            kid: kid.to_owned(),
            bits,
            encoding_key: EncodingKey::from_rsa_pem(pem.as_bytes()).expect("key"),
            jwk,
        }
    }

    /// The `kid` of the key, in the JWK Set and in the header of every token signed with it.
    pub fn key_id(&self) -> &str {
        &self.kid
    }

    /// The size of the key in bits.
    pub fn key_size(&self) -> usize {
        self.bits
    }

    /// The public key as a JWK (RFC 7517): `kty`, `use`, `kid`, `n` and `e`.
    pub fn public_jwk(&self) -> Value {
        self.jwk.clone()
    }

    /// The same key under another `kid`, for a SET that names a key the receiver does not know.
    pub fn with_key_id(&self, kid: &str) -> Self {
        let mut jwk = self.jwk.clone();
        jwk["kid"] = Value::String(kid.to_owned());
        Self {
            kid: kid.to_owned(),
            bits: self.bits,
            encoding_key: self.encoding_key.clone(),
            jwk,
        }
    }
}

/// Where the transmitter publishes its metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataLocation {
    /// SSF 1.0, section 7.2: `/.well-known/ssf-configuration` followed by the path of the
    /// issuer.
    Ssf,
    /// `/.well-known/ssf-configuration` under the path of the issuer, as OpenID Connect Discovery
    /// places its document and some transmitters do.
    OidcStyle,
    /// No metadata is published.
    None,
}

const REALM: &str = "/realms/test";

struct Inner {
    issuer: String,
    key: TestSigningKey,
    documents: Mutex<HashMap<String, String>>,
    streams: Mutex<Vec<Map<String, Value>>>,
    queued_sets: Mutex<Vec<(String, String)>>,
    set_queued: Notify,
    acknowledged_sets: Mutex<Vec<String>>,
    reported_errors: Mutex<Vec<(String, Value)>>,
    verification_requests: Mutex<Vec<String>>,
    added_subjects: Mutex<Vec<Map<String, Value>>>,
    removed_subjects: Mutex<Vec<Map<String, Value>>>,
    requests: AtomicUsize,
    token_requests: AtomicUsize,
    poll_requests: AtomicUsize,
    last_poll_request: Mutex<Map<String, Value>>,
    long_poll_hold: Mutex<Duration>,
    available: AtomicBool,
    valid_access_token: Mutex<String>,
    stream_issuer: Mutex<Option<String>>,
    last_user_agent: Mutex<Option<String>>,
}

/// A minimal SSF transmitter for tests, see the [crate documentation](crate). Cheap to clone;
/// clones share the state. Use it as the [`SsfHttpClient`] of the receiver under test.
#[derive(Clone)]
pub struct TestTransmitter {
    inner: Arc<Inner>,
}

impl Default for TestTransmitter {
    fn default() -> Self {
        Self::new()
    }
}

/// The 2048 bit key every default transmitter of the process signs with: generating one takes a
/// while, and the tests do not depend on the keys of two transmitters differing.
fn shared_key() -> &'static TestSigningKey {
    static KEY: OnceLock<TestSigningKey> = OnceLock::new();
    KEY.get_or_init(|| TestSigningKey::generate(2048, "test-key"))
}

impl TestTransmitter {
    /// The audience of the SETs the transmitter signs by default.
    pub const AUDIENCE: &'static str = "https://receiver.example";
    /// The client id the token endpoint accepts.
    pub const CLIENT_ID: &'static str = "receiver";
    /// The client secret the token endpoint accepts.
    pub const CLIENT_SECRET: &'static str = "receiver-secret";
    /// The access token the token endpoint issues until [`expire_access_tokens`](Self::expire_access_tokens).
    pub const ACCESS_TOKEN: &'static str = "transmitter-access-token";
    /// The `typ` header of a SET (RFC 8417, section 2.3).
    pub const SECEVENT_JWT_TYPE: &'static str = "secevent+jwt";
    /// The `typ` header of a plain JWT such as an access token.
    pub const JWT_TYPE: &'static str = "JWT";

    /// A transmitter at `https://transmitter.example/realms/test` with its metadata at the SSF
    /// location.
    pub fn new() -> Self {
        Self::with_metadata(MetadataLocation::Ssf, None)
    }

    /// A transmitter that publishes its metadata at the given location, or not at all. `host` is
    /// the host of the issuer, `transmitter.example` if `None`; give every transmitter of a test
    /// its own, as a receiver tells transmitters apart by issuer.
    pub fn with_metadata(location: MetadataLocation, host: Option<&str>) -> Self {
        let transmitter = Self {
            inner: Arc::new(Inner {
                issuer: format!("https://{}{REALM}", host.unwrap_or("transmitter.example")),
                key: shared_key().clone(),
                documents: Mutex::new(HashMap::new()),
                streams: Mutex::new(Vec::new()),
                queued_sets: Mutex::new(Vec::new()),
                set_queued: Notify::new(),
                acknowledged_sets: Mutex::new(Vec::new()),
                reported_errors: Mutex::new(Vec::new()),
                verification_requests: Mutex::new(Vec::new()),
                added_subjects: Mutex::new(Vec::new()),
                removed_subjects: Mutex::new(Vec::new()),
                requests: AtomicUsize::new(0),
                token_requests: AtomicUsize::new(0),
                poll_requests: AtomicUsize::new(0),
                last_poll_request: Mutex::new(Map::new()),
                long_poll_hold: Mutex::new(Duration::ZERO),
                available: AtomicBool::new(true),
                valid_access_token: Mutex::new(Self::ACCESS_TOKEN.to_owned()),
                stream_issuer: Mutex::new(None),
                last_user_agent: Mutex::new(None),
            }),
        };
        transmitter.publish_jwks(&[&transmitter.inner.key]);
        transmitter.publish_metadata(location);
        transmitter
    }

    /// The issuer of the transmitter: the `iss` of every SET and the base of its endpoints.
    pub fn issuer(&self) -> &str {
        &self.inner.issuer
    }

    /// The key the transmitter signs with.
    pub fn key(&self) -> &TestSigningKey {
        &self.inner.key
    }

    /// The JWK Set a receiver verifies the SETs with, as published.
    pub fn jwk_set(&self) -> JwkSet {
        let document = self
            .inner
            .documents
            .lock()
            .unwrap()
            .get(&format!("{REALM}/jwks"))
            .cloned()
            .unwrap_or_default();
        serde_json::from_str(&document).expect("the published JWK Set")
    }

    /// Where the JWK Set is published.
    pub fn jwks_uri(&self) -> String {
        format!("{}/jwks", self.inner.issuer)
    }

    /// The token endpoint.
    pub fn token_uri(&self) -> String {
        format!("{}/token", self.inner.issuer)
    }

    /// The poll endpoint.
    pub fn poll_uri(&self) -> String {
        format!("{}/poll", self.inner.issuer)
    }

    /// Makes the token, stream management and poll endpoints answer with 503. Published documents
    /// (the JWK Set, the metadata) are served regardless.
    pub fn set_available(&self, available: bool) {
        self.inner.available.store(available, Ordering::SeqCst);
    }

    /// Makes the transmitter create streams with the given issuer instead of its own.
    pub fn set_stream_issuer(&self, issuer: Option<&str>) {
        *self.inner.stream_issuer.lock().unwrap() = issuer.map(str::to_owned);
    }

    /// How long a poll request without `returnImmediately: true` is held while no SET is queued.
    /// Zero by default: the transmitter then answers at once, as if it did not support long
    /// polling.
    pub fn set_long_poll_hold(&self, hold: Duration) {
        *self.inner.long_poll_hold.lock().unwrap() = hold;
    }

    /// Makes the access tokens issued so far invalid: requests with them are answered with 401
    /// and the token endpoint issues another token.
    pub fn expire_access_tokens(&self) {
        *self.inner.valid_access_token.lock().unwrap() = format!("{}-{}", Self::ACCESS_TOKEN, uuid::Uuid::new_v4());
    }

    /// The number of HTTP requests received so far.
    pub fn requests(&self) -> usize {
        self.inner.requests.load(Ordering::SeqCst)
    }

    /// The number of token requests answered with a token.
    pub fn token_requests(&self) -> usize {
        self.inner.token_requests.load(Ordering::SeqCst)
    }

    /// The number of poll requests received.
    pub fn poll_requests(&self) -> usize {
        self.inner.poll_requests.load(Ordering::SeqCst)
    }

    /// The body of the last poll request, empty if none was received.
    pub fn last_poll_request(&self) -> Map<String, Value> {
        self.inner.last_poll_request.lock().unwrap().clone()
    }

    /// The `User-Agent` header of the most recent request.
    pub fn last_user_agent(&self) -> Option<String> {
        self.inner.last_user_agent.lock().unwrap().clone()
    }

    /// The streams registered at the transmitter, a snapshot.
    pub fn streams(&self) -> Vec<Map<String, Value>> {
        self.inner.streams.lock().unwrap().clone()
    }

    /// The `jti`s of the SETs a polling receiver acknowledged, a snapshot.
    pub fn acknowledged_sets(&self) -> Vec<String> {
        self.inner.acknowledged_sets.lock().unwrap().clone()
    }

    /// The errors a polling receiver reported, by `jti`, a snapshot.
    pub fn reported_errors(&self) -> Vec<(String, Value)> {
        self.inner.reported_errors.lock().unwrap().clone()
    }

    /// The `state`s of the verification requests received, a snapshot.
    pub fn verification_requests(&self) -> Vec<String> {
        self.inner.verification_requests.lock().unwrap().clone()
    }

    /// The subjects added to streams, a snapshot.
    pub fn added_subjects(&self) -> Vec<Map<String, Value>> {
        self.inner.added_subjects.lock().unwrap().clone()
    }

    /// The subjects removed from streams, a snapshot.
    pub fn removed_subjects(&self) -> Vec<Map<String, Value>> {
        self.inner.removed_subjects.lock().unwrap().clone()
    }

    /// The number of SETs queued and not yet acknowledged.
    pub fn queued_set_count(&self) -> usize {
        self.inner.queued_sets.lock().unwrap().len()
    }

    /// Makes the given SET available at the poll endpoint, under its `jti`.
    pub fn queue_set(&self, set: &str) {
        let jti = Self::claims_of(set)["jti"].as_str().expect("a jti").to_owned();
        self.queue_set_with_jti(&jti, set);
    }

    /// Makes the given SET available at the poll endpoint.
    pub fn queue_set_with_jti(&self, jti: &str, set: &str) {
        let mut queued = self.inner.queued_sets.lock().unwrap();
        match queued.iter_mut().find(|(queued_jti, _)| queued_jti == jti) {
            Some(entry) => entry.1 = set.to_owned(),
            None => queued.push((jti.to_owned(), set.to_owned())),
        }
        // wakes up held poll requests
        self.inner.set_queued.notify_waiters();
    }

    /// Forgets streams, queued SETs and what the receiver reported.
    pub fn reset(&self) {
        self.inner.streams.lock().unwrap().clear();
        self.inner.queued_sets.lock().unwrap().clear();
        self.inner.acknowledged_sets.lock().unwrap().clear();
        self.inner.reported_errors.lock().unwrap().clear();
        self.inner.verification_requests.lock().unwrap().clear();
        self.inner.added_subjects.lock().unwrap().clear();
        self.inner.removed_subjects.lock().unwrap().clear();
        self.inner.poll_requests.store(0, Ordering::SeqCst);
        *self.inner.last_poll_request.lock().unwrap() = Map::new();
        *self.inner.long_poll_hold.lock().unwrap() = Duration::ZERO;
        self.inner.available.store(true, Ordering::SeqCst);
        *self.inner.valid_access_token.lock().unwrap() = Self::ACCESS_TOKEN.to_owned();
        *self.inner.stream_issuer.lock().unwrap() = None;
        self.inner.set_queued.notify_waiters();
    }

    /// Publishes a document at a path of the transmitter's host, for example a JWK Set.
    pub fn publish_document(&self, path: &str, json: &str) {
        self.inner
            .documents
            .lock()
            .unwrap()
            .insert(path.to_owned(), json.to_owned());
    }

    /// Removes a published document, so that requests for it are answered with 404.
    pub fn remove_document(&self, path: &str) {
        self.inner.documents.lock().unwrap().remove(path);
    }

    /// Publishes the public keys as the JWK Set of the transmitter.
    pub fn publish_jwks(&self, keys: &[&TestSigningKey]) {
        let jwks: Vec<Value> = keys.iter().map(|key| key.public_jwk()).collect();
        self.publish_document(&format!("{REALM}/jwks"), &json!({ "keys": jwks }).to_string());
    }

    /// Publishes the metadata at the given location.
    pub fn publish_metadata(&self, location: MetadataLocation) {
        let issuer = &self.inner.issuer;
        let metadata = json!({
            "issuer": issuer,
            "jwks_uri": self.jwks_uri(),
            "configuration_endpoint": format!("{issuer}/streams"),
            "status_endpoint": format!("{issuer}/streams/status"),
            "verification_endpoint": format!("{issuer}/verify"),
            "add_subject_endpoint": format!("{issuer}/subjects/add"),
            "remove_subject_endpoint": format!("{issuer}/subjects/remove"),
        })
        .to_string();
        match location {
            MetadataLocation::Ssf => {
                self.publish_document(&format!("/.well-known/ssf-configuration{REALM}"), &metadata)
            }
            MetadataLocation::OidcStyle => {
                self.publish_document(&format!("{REALM}/.well-known/ssf-configuration"), &metadata)
            }
            MetadataLocation::None => {}
        }
    }

    /// Registers a stream the way the transmitter does for a create request: assigns the
    /// identifier, the audience and, for POLL delivery, the poll endpoint.
    pub fn add_stream(&self, request: &Map<String, Value>) -> Map<String, Value> {
        let mut stream = request.clone();
        if !stream.get("stream_id").is_some_and(Value::is_string) {
            stream.insert("stream_id".to_owned(), Value::String(uuid::Uuid::new_v4().to_string()));
        }
        let stream_id = stream["stream_id"].as_str().unwrap().to_owned();
        let issuer = self
            .inner
            .stream_issuer
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| self.inner.issuer.clone());
        stream.insert("iss".to_owned(), Value::String(issuer));
        stream.insert("aud".to_owned(), json!([format!("{}/{stream_id}", Self::CLIENT_ID)]));
        let delivered = stream.get("events_requested").cloned().unwrap_or_else(|| json!([]));
        stream.insert("events_delivered".to_owned(), delivered);
        let mut delivery = stream
            .get("delivery")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        delivery.remove("authorization_header");
        if delivery.get("method").and_then(Value::as_str) == Some("urn:ietf:rfc:8936") {
            delivery.insert("endpoint_url".to_owned(), Value::String(self.poll_uri()));
        }
        stream.insert("delivery".to_owned(), Value::Object(delivery));
        self.inner.streams.lock().unwrap().push(stream.clone());
        stream
    }

    /// Claims of a valid SET with a single event whose payload has an `event_timestamp`.
    /// `event_type` is an alias such as `CaepSessionRevoked` or an event type URI, `subject_id`
    /// the `sub_id` claim, left out if `None`.
    pub fn set_claims(&self, event_type: &str, subject_id: Option<Map<String, Value>>) -> Map<String, Value> {
        let mut payload = Map::new();
        payload.insert("event_timestamp".to_owned(), json!(now_seconds()));
        self.set_claims_with_payload(event_type, subject_id, payload)
    }

    /// Claims of a valid SET with a single event and the given payload.
    pub fn set_claims_with_payload(
        &self,
        event_type: &str,
        subject_id: Option<Map<String, Value>>,
        payload: Map<String, Value>,
    ) -> Map<String, Value> {
        let mut events = Map::new();
        events.insert(easyssf_core::event_types::resolve(event_type), Value::Object(payload));
        let mut claims = Map::new();
        claims.insert("iss".to_owned(), Value::String(self.inner.issuer.clone()));
        claims.insert("jti".to_owned(), Value::String(uuid::Uuid::new_v4().to_string()));
        claims.insert("iat".to_owned(), json!(now_seconds()));
        claims.insert("aud".to_owned(), Value::String(Self::AUDIENCE.to_owned()));
        claims.insert("events".to_owned(), Value::Object(events));
        if let Some(subject_id) = subject_id {
            claims.insert("sub_id".to_owned(), Value::Object(subject_id));
        }
        claims
    }

    /// A valid, signed SET with a single event.
    pub fn set(&self, event_type: &str, subject_id: Option<Map<String, Value>>) -> String {
        self.sign_set(&self.set_claims(event_type, subject_id))
    }

    /// Signs the claims as a SET: typed `secevent+jwt`, with the transmitter's key.
    pub fn sign_set(&self, claims: &Map<String, Value>) -> String {
        Self::sign(&self.inner.key, Some(Self::SECEVENT_JWT_TYPE), claims)
    }

    /// An access token of the identity provider, as an OAuth client would present it.
    pub fn access_token(&self, subject: &str, session_id: &str, issued_at: SystemTime) -> String {
        let claims = json!({
            "iss": self.inner.issuer,
            "sub": subject,
            "sid": session_id,
            "iat": issued_at.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            "exp": now_seconds() + 300,
        });
        Self::sign(&self.inner.key, Some(Self::JWT_TYPE), claims.as_object().unwrap())
    }

    /// Signs the claims with `RS256`; `typ` is the `typ` header, left out if `None`.
    pub fn sign(key: &TestSigningKey, typ: Option<&str>, claims: &Map<String, Value>) -> String {
        Self::sign_with(key, Algorithm::RS256, typ, claims)
    }

    /// Signs the claims as a JWS in compact serialization with an RSA algorithm of RFC 7518:
    /// `RS256`, `RS384`, `RS512`, `PS256`, `PS384` or `PS512`. No minimum key size: tests need to
    /// sign with keys the receiver has to reject.
    pub fn sign_with(
        key: &TestSigningKey,
        algorithm: Algorithm,
        typ: Option<&str>,
        claims: &Map<String, Value>,
    ) -> String {
        let mut header = Header::new(algorithm);
        header.typ = typ.map(str::to_owned);
        header.kid = Some(key.kid.clone());
        jsonwebtoken::encode(&header, claims, &key.encoding_key).expect("signed JWT")
    }

    /// The claims as an unsecured JWT (RFC 7519, section 6): `alg` of `none`, no signature.
    pub fn unsigned(claims: &Map<String, Value>) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
        let payload = URL_SAFE_NO_PAD.encode(Value::Object(claims.clone()).to_string());
        format!("{header}.{payload}.")
    }

    /// The claims of a JWS in compact serialization, without any verification.
    ///
    /// # Panics
    ///
    /// If `jws` is not a JWS whose payload is a JSON object.
    pub fn claims_of(jws: &str) -> Map<String, Value> {
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3, "Not a JWS in compact serialization");
        let payload = URL_SAFE_NO_PAD.decode(parts[1]).expect("base64url payload");
        match serde_json::from_slice(&payload).expect("JSON payload") {
            Value::Object(claims) => claims,
            _ => panic!("The payload is not a JSON object"),
        }
    }

    async fn handle(&self, request: SsfHttpRequest) -> SsfHttpResponse {
        let inner = &self.inner;
        inner.requests.fetch_add(1, Ordering::SeqCst);
        *inner.last_user_agent.lock().unwrap() = request.header("User-Agent").map(str::to_owned);
        let path = request.url.path().to_owned();
        if let Some(document) = inner.documents.lock().unwrap().get(&path).cloned() {
            return respond(200, Some(document));
        }
        let Some(endpoint) = path.strip_prefix(&format!("{REALM}/")).map(str::to_owned) else {
            return respond(404, None);
        };
        if !inner.available.load(Ordering::SeqCst) {
            return respond(503, None);
        }
        let body = request.body.clone().unwrap_or_default();
        if endpoint == "token" {
            return self.handle_token(&request, &body);
        }
        let valid = inner.valid_access_token.lock().unwrap().clone();
        if request.header("Authorization") != Some(format!("Bearer {valid}").as_str()) {
            return respond(401, None);
        }
        let request_body: Map<String, Value> = if body.trim().is_empty() {
            Map::new()
        } else {
            match serde_json::from_str::<Value>(&body) {
                Ok(Value::Object(object)) => object,
                _ => Map::new(),
            }
        };
        let stream_id = request
            .url
            .query_pairs()
            .find(|(name, _)| name == "stream_id")
            .map(|(_, value)| value.into_owned())
            .or_else(|| request_body.get("stream_id").and_then(Value::as_str).map(str::to_owned));
        match endpoint.as_str() {
            "streams" => self.handle_streams(&request.method, stream_id.as_deref(), &request_body),
            "streams/status" => {
                let found = stream_id.as_deref().is_some_and(|id| self.find_stream(id).is_some());
                respond(
                    if found { 200 } else { 404 },
                    Some(
                        json!({
                            "stream_id": stream_id.unwrap_or_else(|| "null".to_owned()),
                            "status": request_body.get("status").and_then(Value::as_str).unwrap_or("enabled"),
                        })
                        .to_string(),
                    ),
                )
            }
            "verify" => {
                let state = match request_body.get("state") {
                    Some(Value::String(state)) => state.clone(),
                    Some(other) => other.to_string(),
                    None => "null".to_owned(),
                };
                inner.verification_requests.lock().unwrap().push(state);
                respond(204, None)
            }
            "poll" => respond(200, Some(Value::Object(self.poll(&request_body).await).to_string())),
            "subjects/add" => {
                inner.added_subjects.lock().unwrap().push(subject(&request_body));
                respond(200, None)
            }
            "subjects/remove" => {
                inner.removed_subjects.lock().unwrap().push(subject(&request_body));
                respond(204, None)
            }
            _ => respond(404, None),
        }
    }

    fn handle_token(&self, request: &SsfHttpRequest, form: &str) -> SsfHttpResponse {
        let credentials =
            base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", Self::CLIENT_ID, Self::CLIENT_SECRET));
        let basic = request.header("Authorization") == Some(format!("Basic {credentials}").as_str());
        let authenticated = basic
            || (form.contains(&format!("client_id={}", Self::CLIENT_ID))
                && form.contains(&format!("client_secret={}", Self::CLIENT_SECRET)));
        if !authenticated || !form.contains("grant_type=client_credentials") {
            return respond(401, Some(json!({ "error": "invalid_client" }).to_string()));
        }
        self.inner.token_requests.fetch_add(1, Ordering::SeqCst);
        let token = self.inner.valid_access_token.lock().unwrap().clone();
        respond(
            200,
            Some(json!({ "access_token": token, "token_type": "Bearer", "expires_in": 300 }).to_string()),
        )
    }

    fn handle_streams(&self, method: &str, stream_id: Option<&str>, request: &Map<String, Value>) -> SsfHttpResponse {
        let stream = stream_id.and_then(|id| self.find_stream(id));
        match method {
            "GET" => match stream_id {
                None => respond(
                    200,
                    Some(Value::Array(self.streams().into_iter().map(Value::Object).collect()).to_string()),
                ),
                Some(_) => match stream {
                    Some(stream) => respond(200, Some(Value::Object(stream).to_string())),
                    None => respond(404, None),
                },
            },
            "POST" => {
                if !self.inner.streams.lock().unwrap().is_empty() {
                    return respond(
                        409,
                        Some(json!({ "error": "stream_error", "error_description": "Only one stream per receiver is allowed" }).to_string()),
                    );
                }
                respond(201, Some(Value::Object(self.add_stream(request)).to_string()))
            }
            "PATCH" | "PUT" => {
                let Some(mut updated) = stream else {
                    return respond(404, None);
                };
                for (name, value) in request {
                    updated.insert(name.clone(), value.clone());
                }
                self.inner
                    .streams
                    .lock()
                    .unwrap()
                    .retain(|s| s.get("stream_id") != updated.get("stream_id"));
                respond(200, Some(Value::Object(self.add_stream(&updated)).to_string()))
            }
            "DELETE" => match stream {
                Some(stream) => {
                    self.inner
                        .streams
                        .lock()
                        .unwrap()
                        .retain(|s| s.get("stream_id") != stream.get("stream_id"));
                    respond(204, None)
                }
                None => respond(404, None),
            },
            _ => respond(405, None),
        }
    }

    async fn poll(&self, request: &Map<String, Value>) -> Map<String, Value> {
        let inner = &self.inner;
        inner.poll_requests.fetch_add(1, Ordering::SeqCst);
        *inner.last_poll_request.lock().unwrap() = request.clone();
        let max_events = request.get("maxEvents").and_then(Value::as_u64).unwrap_or(10) as usize;
        let return_immediately = request
            .get("returnImmediately")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let hold = *inner.long_poll_hold.lock().unwrap();
        {
            let mut queued = inner.queued_sets.lock().unwrap();
            if let Some(Value::Array(acks)) = request.get("ack") {
                for jti in acks.iter().filter_map(Value::as_str) {
                    if queued.iter().any(|(queued_jti, _)| queued_jti == jti) {
                        queued.retain(|(queued_jti, _)| queued_jti != jti);
                        inner.acknowledged_sets.lock().unwrap().push(jti.to_owned());
                    }
                }
            }
            if let Some(Value::Object(errors)) = request.get("setErrs") {
                for (jti, error) in errors {
                    queued.retain(|(queued_jti, _)| queued_jti != jti);
                    inner.reported_errors.lock().unwrap().push((jti.clone(), error.clone()));
                }
            }
        }
        // a long poll (returnImmediately false or absent, RFC 8936 section 2.5) is held until a
        // SET is queued or the hold time elapses
        if !return_immediately && max_events > 0 && !hold.is_zero() {
            let deadline = tokio::time::Instant::now() + hold;
            loop {
                let notified = inner.set_queued.notified();
                tokio::pin!(notified);
                if !inner.queued_sets.lock().unwrap().is_empty() {
                    break;
                }
                tokio::select! {
                    _ = &mut notified => {}
                    _ = tokio::time::sleep_until(deadline) => break,
                }
            }
        }
        let queued = inner.queued_sets.lock().unwrap();
        let mut sets = Map::new();
        for (jti, set) in queued.iter().take(max_events) {
            sets.insert(jti.clone(), Value::String(set.clone()));
        }
        let more = queued.len() > sets.len();
        let mut response = Map::new();
        response.insert("sets".to_owned(), Value::Object(sets));
        response.insert("moreAvailable".to_owned(), Value::Bool(more));
        response
    }

    fn find_stream(&self, stream_id: &str) -> Option<Map<String, Value>> {
        self.inner
            .streams
            .lock()
            .unwrap()
            .iter()
            .find(|stream| stream.get("stream_id").and_then(Value::as_str) == Some(stream_id))
            .cloned()
    }
}

#[async_trait]
impl SsfHttpClient for TestTransmitter {
    async fn execute(&self, request: SsfHttpRequest) -> Result<SsfHttpResponse, BoxError> {
        Ok(self.handle(request).await)
    }
}

fn subject(request: &Map<String, Value>) -> Map<String, Value> {
    request
        .get("subject")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn respond(status: u16, json: Option<String>) -> SsfHttpResponse {
    let mut response = SsfHttpResponse::new(status, json.unwrap_or_default());
    response = response.with_header("Content-Type", "application/json");
    response
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Waits until `condition` holds, polling it every 10 milliseconds for at most `timeout`; the
/// `Eventually` of the Java and .NET tests. Panics with `what` if it does not hold in time.
pub async fn eventually(timeout: Duration, what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !condition() {
        assert!(tokio::time::Instant::now() < deadline, "Timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Checks that `condition` keeps holding for `duration`, polling it every 10 milliseconds.
pub async fn during(duration: Duration, what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + duration;
    while tokio::time::Instant::now() < deadline {
        assert!(condition(), "Stopped holding: {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
