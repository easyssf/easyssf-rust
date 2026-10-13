//! The transmitter as the receiver sees it: its issuer and endpoints, its metadata, the access
//! token to call it with, and everything the receiver holds for it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use base64::Engine;
use easyssf_core::metadata::SsfTransmitterMetadata;
use serde_json::{Map, Value};
use url::Url;

use crate::http::{SsfHttpClient, SsfHttpRequest};
use crate::poll::SsfPoller;
use crate::set::{IssuerRoutingSsfSetVerifier, SsfSetVerifier};
use crate::stream::{SsfReceiverStream, SsfStreamClient, SsfStreamRegistrar, SsfStreamVerification};
use crate::{BoxError, Clock, system_clock};

/// The transmitter's metadata or keys cannot be obtained. Unlike an invalid SET this is a
/// temporary condition, the SET should be delivered again later.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct SsfTransmitterUnavailable {
    message: String,
    #[source]
    source: Option<BoxError>,
}

impl SsfTransmitterUnavailable {
    /// An unavailability with a message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// An unavailability with a message and its cause.
    pub fn caused(message: impl Into<String>, source: impl Into<BoxError>) -> Self {
        Self {
            message: message.into(),
            source: Some(source.into()),
        }
    }

    /// What is unavailable.
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// What the issuer of a transmitter and the endpoints it publishes must look like. SSF requires
/// `https` and an issuer without query or fragment. Loopback addresses (`localhost`, `127.0.0.1`,
/// `::1`) may use `http`, so that a transmitter on the developer's machine works;
/// [`INSECURE`](Self::INSECURE) extends that to every host, for test setups only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SsfTransmitterUriPolicy {
    /// Whether `http` is accepted for hosts other than loopback.
    pub allow_insecure_http: bool,
}

impl SsfTransmitterUriPolicy {
    /// `https`, or `http` on loopback addresses only.
    pub const DEFAULT: Self = Self {
        allow_insecure_http: false,
    };

    /// `http` on any host as well. For development and test setups only: the metadata of the
    /// transmitter decides where keys come from, and without TLS anyone on the path can change
    /// it.
    pub const INSECURE: Self = Self {
        allow_insecure_http: true,
    };

    /// Whether the URL uses plain `http`.
    pub fn is_insecure(url: &Url) -> bool {
        url.scheme().eq_ignore_ascii_case("http")
    }

    /// Whether the host of the URL is a loopback address.
    pub fn is_loopback(url: &Url) -> bool {
        let Some(host) = url.host_str() else {
            return false;
        };
        let host = host.to_ascii_lowercase();
        host == "localhost"
            || host.ends_with(".localhost")
            || host.starts_with("127.")
            || host == "[::1]"
            || host == "::1"
            || host == "[0:0:0:0:0:0:0:1]"
    }

    /// Checks the issuer of a transmitter and returns it as a URL.
    pub fn check_issuer(&self, issuer: &str) -> Result<Url, String> {
        let url = parse(issuer, "Transmitter issuer")?;
        if url.query().is_some() || url.fragment().is_some() {
            return Err(format!(
                "Transmitter issuer must not have a query or fragment: {issuer}"
            ));
        }
        self.check_scheme(&url, "Transmitter issuer")?;
        Ok(url)
    }

    /// Checks an endpoint of the transmitter: its metadata, JWK Set, stream management or poll
    /// endpoint. `description` says what the endpoint is, for the message.
    pub fn check_endpoint(&self, url: &Url, description: &str) -> Result<(), String> {
        parse(url.as_str(), description)?;
        if url.fragment().is_some() {
            return Err(format!("{description} must not have a fragment: {url}"));
        }
        self.check_scheme(url, description)
    }

    fn check_scheme(&self, url: &Url, description: &str) -> Result<(), String> {
        let scheme = url.scheme().to_ascii_lowercase();
        if scheme == "https" || (scheme == "http" && (self.allow_insecure_http || Self::is_loopback(url))) {
            return Ok(());
        }
        Err(format!("{description} must use https: {url}"))
    }
}

impl Default for SsfTransmitterUriPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

fn parse(value: &str, description: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|e| format!("{description} is not a valid URI: {value} ({e})"))?;
    if url.host_str().is_none_or(str::is_empty) {
        return Err(format!("{description} must be an absolute URI with a host: {value}"));
    }
    Ok(url)
}

const WELL_KNOWN_PATH: &str = "/.well-known/ssf-configuration";

/// Resolves the [`SsfTransmitterMetadata`] of the transmitter. The metadata is fetched on first
/// use and cached once it was retrieved successfully, so a receiver can start even when the
/// transmitter is not reachable.
pub struct SsfTransmitterMetadataResolver {
    issuer: String,
    metadata_uris: Vec<Url>,
    http: Arc<dyn SsfHttpClient>,
    uri_policy: SsfTransmitterUriPolicy,
    warned_insecure: AtomicBool,
    metadata: Mutex<Option<Arc<SsfTransmitterMetadata>>>,
    resolving: tokio::sync::Mutex<()>,
}

impl SsfTransmitterMetadataResolver {
    /// A resolver for the metadata of the transmitter with the given issuer, at `metadata_uri`
    /// or, if `None`, at the locations derived from the issuer.
    ///
    /// # Errors
    ///
    /// If the issuer or the metadata URI is not acceptable to the policy.
    pub fn new(
        issuer: impl Into<String>,
        metadata_uri: Option<Url>,
        http: impl SsfHttpClient,
        uri_policy: SsfTransmitterUriPolicy,
    ) -> Result<Self, String> {
        let issuer = issuer.into();
        uri_policy.check_issuer(&issuer)?;
        if let Some(metadata_uri) = &metadata_uri {
            uri_policy.check_endpoint(metadata_uri, "Transmitter metadata URL")?;
        }
        let metadata_uris = match metadata_uri {
            Some(uri) => vec![uri],
            None => Self::derive_metadata_uris(&issuer)?,
        };
        Ok(Self {
            issuer,
            metadata_uris,
            http: Arc::new(http),
            uri_policy,
            warned_insecure: AtomicBool::new(false),
            metadata: Mutex::new(None),
            resolving: tokio::sync::Mutex::new(()),
        })
    }

    /// Derives the metadata locations for an issuer. SSF 1.0 (section 7.2) inserts
    /// `/.well-known/ssf-configuration` between the host and the path of the issuer.
    /// Transmitters that grew out of OpenID providers tend to append it to the issuer instead, so
    /// that location is used as a fallback.
    pub fn derive_metadata_uris(issuer: &str) -> Result<Vec<Url>, String> {
        let url = parse(issuer, "Transmitter issuer")?;
        let base = format!("{}://{}", url.scheme(), url.authority());
        let path = url.path().trim_end_matches('/');
        let mut uris = Vec::new();
        for candidate in [
            format!("{base}{WELL_KNOWN_PATH}{path}"),
            format!("{base}{path}{WELL_KNOWN_PATH}"),
        ] {
            let uri =
                Url::parse(&candidate).map_err(|e| format!("Cannot derive the metadata location of {issuer}: {e}"))?;
            if !uris.contains(&uri) {
                uris.push(uri);
            }
        }
        Ok(uris)
    }

    /// The issuer of the transmitter.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The locations the metadata is looked up at, in order.
    pub fn metadata_uris(&self) -> &[Url] {
        &self.metadata_uris
    }

    /// The metadata if it was retrieved already, without retrieving it.
    pub fn resolved_metadata(&self) -> Option<Arc<SsfTransmitterMetadata>> {
        self.metadata.lock().unwrap().clone()
    }

    /// The metadata, fetched on first use.
    pub async fn resolve(&self) -> Result<Arc<SsfTransmitterMetadata>, SsfTransmitterUnavailable> {
        if let Some(metadata) = self.resolved_metadata() {
            return Ok(metadata);
        }
        let _resolving = self.resolving.lock().await;
        if let Some(metadata) = self.resolved_metadata() {
            return Ok(metadata);
        }
        let mut failures = Vec::new();
        for uri in &self.metadata_uris {
            match self.fetch(uri).await {
                Ok(metadata) => {
                    tracing::info!(transmitter = self.issuer, %uri, "Resolved SSF transmitter metadata");
                    let metadata = Arc::new(metadata);
                    *self.metadata.lock().unwrap() = Some(metadata.clone());
                    return Ok(metadata);
                }
                Err(failure) => {
                    tracing::debug!(%uri, %failure, "Could not resolve SSF transmitter metadata");
                    failures.push(format!("{uri}: {failure}"));
                }
            }
        }
        Err(SsfTransmitterUnavailable::new(format!(
            "Could not resolve SSF transmitter metadata from {}",
            failures.join("; ")
        )))
    }

    async fn fetch(&self, uri: &Url) -> Result<SsfTransmitterMetadata, String> {
        let response = self
            .http
            .execute(SsfHttpRequest::get(uri.clone()))
            .await
            .map_err(|e| e.to_string())?;
        if !response.is_successful() {
            return Err(format!("The transmitter answered with status {}", response.status));
        }
        let claims: Map<String, Value> =
            serde_json::from_str(&response.body).map_err(|e| format!("The metadata is not JSON: {e}"))?;
        let metadata_issuer = claims.get("issuer").and_then(Value::as_str);
        if metadata_issuer != Some(self.issuer.as_str()) {
            return Err(format!(
                "SSF transmitter metadata issuer '{}' does not match the configured transmitter issuer '{}'",
                metadata_issuer.unwrap_or(""),
                self.issuer
            ));
        }
        let jwks_uri = match claims.get("jwks_uri").and_then(Value::as_str) {
            Some(value) => Some(Url::parse(value).map_err(|e| format!("jwks_uri is not a valid URL: {e}"))?),
            None => None,
        };
        let metadata = SsfTransmitterMetadata::new(self.issuer.clone(), jwks_uri, claims);
        self.check_endpoints(&metadata)?;
        Ok(metadata)
    }

    /// The metadata controls where keys and stream operations come from, so its endpoints are
    /// held to the same standard as the issuer.
    fn check_endpoints(&self, metadata: &SsfTransmitterMetadata) -> Result<(), String> {
        let mut insecure = Vec::new();
        let endpoints = [
            (metadata.jwks_uri().cloned(), "jwks_uri"),
            (metadata.configuration_endpoint(), "configuration_endpoint"),
            (metadata.status_endpoint(), "status_endpoint"),
            (metadata.add_subject_endpoint(), "add_subject_endpoint"),
            (metadata.remove_subject_endpoint(), "remove_subject_endpoint"),
            (metadata.verification_endpoint(), "verification_endpoint"),
        ];
        for (endpoint, name) in endpoints {
            let Some(endpoint) = endpoint else { continue };
            self.uri_policy
                .check_endpoint(&endpoint, &format!("SSF transmitter metadata {name}"))?;
            if SsfTransmitterUriPolicy::is_insecure(&endpoint) && !SsfTransmitterUriPolicy::is_loopback(&endpoint) {
                insecure.push(format!("{name} {endpoint}"));
            }
        }
        if !insecure.is_empty()
            && self.uri_policy.allow_insecure_http
            && !self.warned_insecure.swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                transmitter = self.issuer,
                endpoints = ?insecure,
                "The SSF transmitter publishes endpoints without TLS, accepted because insecure http is allowed. For development only"
            );
        }
        Ok(())
    }
}

/// Provides the access token the receiver authenticates with when it calls the stream management
/// and poll endpoints of the transmitter. Implement it to obtain the token in another way than
/// the built-in ones.
#[async_trait]
pub trait SsfTransmitterTokenProvider: Send + Sync + 'static {
    /// The access token to send as bearer token, or `None` to call the transmitter without
    /// authentication.
    async fn access_token(&self) -> Result<Option<String>, SsfTransmitterUnavailable>;

    /// Called when the transmitter rejected the access token (HTTP 401), so that the next call
    /// of [`access_token`](Self::access_token) returns a new one. Does nothing by default.
    async fn invalidate(&self) {}
}

#[async_trait]
impl<T: SsfTransmitterTokenProvider> SsfTransmitterTokenProvider for Arc<T> {
    async fn access_token(&self) -> Result<Option<String>, SsfTransmitterUnavailable> {
        (**self).access_token().await
    }

    async fn invalidate(&self) {
        (**self).invalidate().await
    }
}

#[async_trait]
impl SsfTransmitterTokenProvider for Arc<dyn SsfTransmitterTokenProvider> {
    async fn access_token(&self) -> Result<Option<String>, SsfTransmitterUnavailable> {
        (**self).access_token().await
    }

    async fn invalidate(&self) {
        (**self).invalidate().await
    }
}

/// Calls the transmitter without authentication.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSsfTransmitterTokenProvider;

#[async_trait]
impl SsfTransmitterTokenProvider for NoSsfTransmitterTokenProvider {
    async fn access_token(&self) -> Result<Option<String>, SsfTransmitterUnavailable> {
        Ok(None)
    }
}

/// Always sends the same token, for transmitters that hand out long-lived tokens.
#[derive(Debug, Clone)]
pub struct FixedSsfTransmitterTokenProvider(pub String);

#[async_trait]
impl SsfTransmitterTokenProvider for FixedSsfTransmitterTokenProvider {
    async fn access_token(&self) -> Result<Option<String>, SsfTransmitterUnavailable> {
        Ok(Some(self.0.clone()))
    }
}

/// How a [`ClientCredentialsSsfTransmitterTokenProvider`] obtains tokens.
#[derive(Clone)]
pub struct SsfClientCredentialsOptions {
    /// The scopes to request, none by default.
    pub scopes: Vec<String>,
    /// Whether the client credentials are sent in the request body (`client_secret_post`) instead
    /// of with HTTP basic authentication (`client_secret_basic`).
    pub authenticate_with_request_body: bool,
    /// How long before its expiry a token is renewed, 30 seconds by default; never more than a
    /// quarter of the token's lifetime.
    pub expiry_safety_window: Duration,
    /// Form parameters to send with the token request in addition to the grant, for extensions
    /// of the token endpoint.
    pub additional_parameters: Vec<(String, String)>,
    /// The clock the expiry is measured by.
    pub clock: Clock,
}

impl Default for SsfClientCredentialsOptions {
    fn default() -> Self {
        Self {
            scopes: Vec::new(),
            authenticate_with_request_body: false,
            expiry_safety_window: Duration::from_secs(30),
            additional_parameters: Vec::new(),
            clock: system_clock(),
        }
    }
}

struct CachedToken {
    access_token: String,
    expires_at: SystemTime,
}

/// [`SsfTransmitterTokenProvider`] that obtains access tokens with the OAuth2 client credentials
/// grant and caches them until shortly before they expire.
pub struct ClientCredentialsSsfTransmitterTokenProvider {
    http: Arc<dyn SsfHttpClient>,
    token_uri: Url,
    client_id: String,
    client_secret: String,
    options: SsfClientCredentialsOptions,
    cached: tokio::sync::Mutex<Option<CachedToken>>,
}

impl ClientCredentialsSsfTransmitterTokenProvider {
    /// A provider that requests tokens at `token_uri` for the client.
    pub fn new(
        http: impl SsfHttpClient,
        token_uri: Url,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        options: SsfClientCredentialsOptions,
    ) -> Self {
        Self {
            http: Arc::new(http),
            token_uri,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            options,
            cached: tokio::sync::Mutex::new(None),
        }
    }

    fn token_request(&self) -> SsfHttpRequest {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "client_credentials");
        if !self.options.scopes.is_empty() {
            form.append_pair("scope", &self.options.scopes.join(" "));
        }
        for (name, value) in &self.options.additional_parameters {
            if name != "grant_type" && name != "scope" {
                form.append_pair(name, value);
            }
        }
        let mut request = SsfHttpRequest::of("POST", self.token_uri.clone()).with_header("Accept", "application/json");
        if self.options.authenticate_with_request_body {
            form.append_pair("client_id", &self.client_id);
            form.append_pair("client_secret", &self.client_secret);
        } else {
            let credentials =
                base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", self.client_id, self.client_secret));
            request = request.with_header("Authorization", &format!("Basic {credentials}"));
        }
        request.with_body("application/x-www-form-urlencoded", form.finish())
    }

    async fn request_token(&self) -> Result<CachedToken, SsfTransmitterUnavailable> {
        let request = self.token_request();
        let unavailable = |e: BoxError| {
            SsfTransmitterUnavailable::caused(
                format!(
                    "Could not obtain an access token for the SSF transmitter from {}",
                    self.token_uri
                ),
                e,
            )
        };
        let response = self.http.execute(request).await.map_err(unavailable)?;
        if !response.is_successful() {
            return Err(unavailable(
                format!("The token endpoint answered with status {}", response.status).into(),
            ));
        }
        let body: Map<String, Value> = serde_json::from_str(&response.body).map_err(|e| unavailable(e.into()))?;
        let Some(token) = body
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|t| !t.trim().is_empty())
        else {
            return Err(SsfTransmitterUnavailable::new(format!(
                "The token response of {} has no access_token",
                self.token_uri
            )));
        };
        let expires_in = body.get("expires_in").and_then(Value::as_u64).unwrap_or(60);
        // renew ahead of the expiry, but still use a short-lived token for most of its lifetime
        let safety_window = Duration::from_secs(self.options.expiry_safety_window.as_secs().min(expires_in / 4));
        let expires_at = (self.options.clock)() + Duration::from_secs(expires_in) - safety_window;
        Ok(CachedToken {
            access_token: token.to_owned(),
            expires_at,
        })
    }
}

#[async_trait]
impl SsfTransmitterTokenProvider for ClientCredentialsSsfTransmitterTokenProvider {
    async fn access_token(&self) -> Result<Option<String>, SsfTransmitterUnavailable> {
        let mut cached = self.cached.lock().await;
        let now = (self.options.clock)();
        if let Some(token) = &*cached
            && now < token.expires_at
        {
            return Ok(Some(token.access_token.clone()));
        }
        let token = self.request_token().await?;
        let access_token = token.access_token.clone();
        *cached = Some(token);
        Ok(Some(access_token))
    }

    async fn invalidate(&self) {
        *self.cached.lock().await = None;
    }
}

/// Everything the receiver holds for one transmitter: how its SETs are verified, how it is
/// called, the stream of the receiver at it, and the background work for it. Build it with
/// [`SsfTransmitter::builder`].
pub struct SsfTransmitter {
    name: String,
    issuer: String,
    metadata_resolver: Arc<SsfTransmitterMetadataResolver>,
    verifier: Arc<dyn SsfSetVerifier>,
    token_provider: Option<Arc<dyn SsfTransmitterTokenProvider>>,
    stream_client: Option<Arc<SsfStreamClient>>,
    receiver_stream: Arc<SsfReceiverStream>,
    stream_verification: Arc<SsfStreamVerification>,
    stream_registrar: Option<Arc<SsfStreamRegistrar>>,
    poller: Option<SsfPoller>,
    auto_start_polling: bool,
    push_authorization_header: Option<String>,
}

impl SsfTransmitter {
    /// The name of the transmitter an application configures without naming it.
    pub const DEFAULT_NAME: &'static str = "default";

    /// A builder for the transmitter with the given name ([`DEFAULT_NAME`](Self::DEFAULT_NAME)
    /// for an unnamed one) and issuer.
    pub fn builder(name: impl Into<String>, issuer: impl Into<String>) -> SsfTransmitterBuilder {
        SsfTransmitterBuilder {
            name: name.into(),
            issuer: issuer.into(),
            metadata_resolver: None,
            verifier: None,
            token_provider: None,
            stream_client: None,
            receiver_stream: Arc::new(SsfReceiverStream::default()),
            stream_verification: None,
            stream_registrar: None,
            poller: None,
            auto_start_polling: true,
            push_authorization_header: None,
        }
    }

    /// The name of the transmitter.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The issuer of the transmitter.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Resolves the metadata of the transmitter.
    pub fn metadata_resolver(&self) -> &Arc<SsfTransmitterMetadataResolver> {
        &self.metadata_resolver
    }

    /// Verifies the SETs of the transmitter.
    pub fn verifier(&self) -> &Arc<dyn SsfSetVerifier> {
        &self.verifier
    }

    /// The token provider, `None` if the transmitter is not called.
    pub fn token_provider(&self) -> Option<&Arc<dyn SsfTransmitterTokenProvider>> {
        self.token_provider.as_ref()
    }

    /// The stream client, `None` if the transmitter is not called.
    pub fn stream_client(&self) -> Option<&Arc<SsfStreamClient>> {
        self.stream_client.as_ref()
    }

    /// The stream of the receiver at the transmitter, once it is known.
    pub fn receiver_stream(&self) -> &Arc<SsfReceiverStream> {
        &self.receiver_stream
    }

    /// Validates verification events of the transmitter.
    pub fn stream_verification(&self) -> &Arc<SsfStreamVerification> {
        &self.stream_verification
    }

    /// The registrar, `None` if the stream is neither looked up nor managed.
    pub fn stream_registrar(&self) -> Option<&Arc<SsfStreamRegistrar>> {
        self.stream_registrar.as_ref()
    }

    /// The poller, `None` with PUSH delivery.
    pub fn poller(&self) -> Option<&SsfPoller> {
        self.poller.as_ref()
    }

    /// The `Authorization` header the transmitter has to send to the push endpoint, `None` if
    /// none is expected.
    pub fn push_authorization_header(&self) -> Option<&str> {
        self.push_authorization_header.as_deref()
    }

    /// Starts the background work: looking up or registering the stream, and polling. Needs a
    /// tokio runtime.
    pub fn start(&self) {
        if let Some(registrar) = &self.stream_registrar {
            registrar.start();
        }
        if let Some(poller) = &self.poller
            && self.auto_start_polling
        {
            poller.start();
        }
    }

    /// Stops the background work and sends the acknowledgements the poller owes.
    pub async fn stop(&self) {
        if let Some(poller) = &self.poller {
            poller.stop().await;
        }
        if let Some(registrar) = &self.stream_registrar {
            registrar.stop().await;
        }
    }
}

impl std::fmt::Debug for SsfTransmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.issuer)
    }
}

impl std::fmt::Debug for IssuerRoutingSsfSetVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuerRoutingSsfSetVerifier")
            .field("issuers", &self.verifiers().keys().collect::<Vec<_>>())
            .finish()
    }
}

impl std::fmt::Display for SsfTransmitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.issuer)
    }
}

/// Assembles an [`SsfTransmitter`]: set the parts and call [`build`](Self::build). The metadata
/// resolver and the verifier are required; the rest depends on whether the receiver calls the
/// transmitter and how SETs are delivered.
pub struct SsfTransmitterBuilder {
    /// The name of the transmitter.
    pub name: String,
    /// The issuer of the transmitter.
    pub issuer: String,
    /// Resolves the metadata of the transmitter. Required.
    pub metadata_resolver: Option<Arc<SsfTransmitterMetadataResolver>>,
    /// Verifies the SETs of the transmitter. Required.
    pub verifier: Option<Arc<dyn SsfSetVerifier>>,
    /// Authenticates the receiver at the transmitter, `None` if the transmitter is not called.
    pub token_provider: Option<Arc<dyn SsfTransmitterTokenProvider>>,
    /// Calls the stream management API, `None` if the transmitter is not called.
    pub stream_client: Option<Arc<SsfStreamClient>>,
    /// Holds the stream once it is known. A fresh one by default.
    pub receiver_stream: Arc<SsfReceiverStream>,
    /// Validates verification events; one that checks the identifier of the receiver stream if
    /// `None`.
    pub stream_verification: Option<Arc<SsfStreamVerification>>,
    /// Looks up or registers the stream, `None` if the stream is neither looked up nor managed.
    pub stream_registrar: Option<Arc<SsfStreamRegistrar>>,
    /// Polls the transmitter, `None` with PUSH delivery.
    pub poller: Option<SsfPoller>,
    /// Whether [`SsfTransmitter::start`] starts the poller. `true` by default.
    pub auto_start_polling: bool,
    /// The `Authorization` header the transmitter has to send to the push endpoint, `None` or
    /// blank if none is expected.
    pub push_authorization_header: Option<String>,
}

impl SsfTransmitterBuilder {
    /// Builds the transmitter.
    ///
    /// # Panics
    ///
    /// If the metadata resolver or the verifier is missing.
    pub fn build(self) -> SsfTransmitter {
        let metadata_resolver = self.metadata_resolver.expect("metadata_resolver must be set");
        let verifier = self.verifier.expect("verifier must be set");
        let receiver_stream = self.receiver_stream;
        let stream_verification = self.stream_verification.unwrap_or_else(|| {
            let stream = receiver_stream.clone();
            Arc::new(SsfStreamVerification::new().with_stream_id(move || stream.stream_id()))
        });
        if let (Some(registrar), Some(poller)) = (&self.stream_registrar, &self.poller) {
            // the first poll right after the stream is registered, not an interval later
            let poller = poller.clone();
            registrar.add_listener(move |_| poller.wake_up());
        }
        SsfTransmitter {
            name: self.name,
            issuer: self.issuer,
            metadata_resolver,
            verifier,
            token_provider: self.token_provider,
            stream_client: self.stream_client,
            receiver_stream,
            stream_verification,
            stream_registrar: self.stream_registrar,
            poller: self.poller,
            auto_start_polling: self.auto_start_polling,
            push_authorization_header: self.push_authorization_header.filter(|h| !h.trim().is_empty()),
        }
    }
}

/// The transmitters of a receiver, by name and by issuer. Most applications have one, the
/// [default](SsfTransmitter::DEFAULT_NAME) one.
#[derive(Debug)]
pub struct SsfTransmitters {
    by_name: Vec<Arc<SsfTransmitter>>,
    verifier: Arc<IssuerRoutingSsfSetVerifier>,
}

impl SsfTransmitters {
    /// The transmitters, at least one.
    ///
    /// # Errors
    ///
    /// If two transmitters share a name or an issuer, or there is none.
    pub fn new(transmitters: Vec<SsfTransmitter>) -> Result<Self, String> {
        if transmitters.is_empty() {
            return Err("transmitters must not be empty".to_owned());
        }
        let mut by_name: Vec<Arc<SsfTransmitter>> = Vec::new();
        let mut verifiers: HashMap<String, Arc<dyn SsfSetVerifier>> = HashMap::new();
        for transmitter in transmitters {
            if by_name.iter().any(|t| t.name == transmitter.name) {
                return Err(format!("Two transmitters are named '{}'", transmitter.name));
            }
            if let Some(same) = by_name.iter().find(|t| t.issuer == transmitter.issuer) {
                return Err(format!(
                    "The transmitters '{}' and '{}' have the same issuer {}",
                    transmitter.name, same.name, transmitter.issuer
                ));
            }
            verifiers.insert(transmitter.issuer.clone(), transmitter.verifier.clone());
            by_name.push(Arc::new(transmitter));
        }
        Ok(Self {
            by_name,
            verifier: Arc::new(IssuerRoutingSsfSetVerifier::new(verifiers)),
        })
    }

    /// All transmitters, in the order given.
    pub fn all(&self) -> &[Arc<SsfTransmitter>] {
        &self.by_name
    }

    /// The transmitter with the given name.
    pub fn get(&self, name: &str) -> Option<&Arc<SsfTransmitter>> {
        self.by_name.iter().find(|t| t.name == name)
    }

    /// The transmitter with the given issuer.
    pub fn by_issuer(&self, issuer: &str) -> Option<&Arc<SsfTransmitter>> {
        self.by_name.iter().find(|t| t.issuer == issuer)
    }

    /// The transmitter if there is exactly one, else the default one if there is one.
    pub fn primary(&self) -> Option<&Arc<SsfTransmitter>> {
        if self.by_name.len() == 1 {
            return self.by_name.first();
        }
        self.get(SsfTransmitter::DEFAULT_NAME)
    }

    /// The short name of a transmitter, for labels such as metric tags, where its issuer would
    /// be long: the name of the transmitter with the given issuer, or the issuer itself if no
    /// transmitter has it.
    pub fn name_of(&self, issuer: &str) -> String {
        self.by_issuer(issuer)
            .map(|t| t.name.clone())
            .unwrap_or_else(|| issuer.to_owned())
    }

    /// A verifier that verifies the SETs of every transmitter, by issuer.
    pub fn verifier(&self) -> Arc<IssuerRoutingSsfSetVerifier> {
        self.verifier.clone()
    }

    /// The stream verification of the transmitter with the given issuer, `None` for an unknown
    /// issuer.
    pub fn stream_verification(&self, issuer: &str) -> Option<Arc<SsfStreamVerification>> {
        self.by_issuer(issuer).map(|t| t.stream_verification.clone())
    }

    /// The `critical_subject_members` the transmitter with the given issuer declares in its
    /// metadata, empty if none or the issuer is unknown. The metadata is the resolved one: a SET
    /// of the transmitter was verified with its keys before.
    pub fn critical_subject_members(&self, issuer: &str) -> Vec<String> {
        self.by_issuer(issuer)
            .and_then(|t| t.metadata_resolver.resolved_metadata())
            .map(|metadata| metadata.critical_subject_members())
            .unwrap_or_default()
    }

    /// The `Authorization` header the transmitter with the given issuer has to send to the push
    /// endpoint, `None` if none is expected or the issuer is unknown.
    pub fn push_authorization_header(&self, issuer: &str) -> Option<String> {
        self.by_issuer(issuer).and_then(|t| t.push_authorization_header.clone())
    }

    /// Starts the background work of every transmitter.
    pub fn start(&self) {
        for transmitter in &self.by_name {
            transmitter.start();
        }
    }

    /// Stops the background work of every transmitter.
    pub async fn stop(&self) {
        for transmitter in &self.by_name {
            transmitter.stop().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inserts_well_known_path_between_host_and_issuer_path() {
        let uris = SsfTransmitterMetadataResolver::derive_metadata_uris("https://idp.example/realms/demo/").unwrap();
        assert_eq!(
            uris.iter().map(Url::as_str).collect::<Vec<_>>(),
            [
                "https://idp.example/.well-known/ssf-configuration/realms/demo",
                "https://idp.example/realms/demo/.well-known/ssf-configuration"
            ]
        );
    }

    #[test]
    fn issuer_without_path_has_single_location() {
        let uris = SsfTransmitterMetadataResolver::derive_metadata_uris("https://idp.example").unwrap();
        assert_eq!(
            uris.iter().map(Url::as_str).collect::<Vec<_>>(),
            ["https://idp.example/.well-known/ssf-configuration"]
        );
    }

    #[test]
    fn rejects_relative_issuer() {
        assert!(SsfTransmitterMetadataResolver::derive_metadata_uris("/realms/demo").is_err());
        assert!(SsfTransmitterMetadataResolver::derive_metadata_uris("idp.example").is_err());
    }

    #[test]
    fn accepts_https_issuer_with_path() {
        let url = SsfTransmitterUriPolicy::DEFAULT
            .check_issuer("https://idp.example/realms/demo")
            .unwrap();
        assert_eq!(url.path(), "/realms/demo");
    }

    #[test]
    fn rejects_http_issuer_except_on_loopback() {
        let policy = SsfTransmitterUriPolicy::DEFAULT;
        assert!(
            policy
                .check_issuer("http://idp.example/realms/demo")
                .unwrap_err()
                .contains("must use https")
        );
        for issuer in [
            "http://localhost:8080/realms/demo",
            "http://127.0.0.1:8080/x",
            "http://[::1]:8080/x",
            "http://app.localhost/x",
        ] {
            assert!(policy.check_issuer(issuer).is_ok(), "{issuer}");
        }
    }

    #[test]
    fn insecure_policy_accepts_http_anywhere() {
        assert!(
            SsfTransmitterUriPolicy::INSECURE
                .check_issuer("http://idp.example/realms/demo")
                .is_ok()
        );
        assert!(
            SsfTransmitterUriPolicy::INSECURE
                .check_issuer("ftp://idp.example/realms/demo")
                .is_err()
        );
    }

    #[test]
    fn rejects_issuer_with_query_fragment_or_without_host() {
        let policy = SsfTransmitterUriPolicy::DEFAULT;
        assert!(
            policy
                .check_issuer("https://idp.example/x?y=1")
                .unwrap_err()
                .contains("query or fragment")
        );
        assert!(
            policy
                .check_issuer("https://idp.example/x#frag")
                .unwrap_err()
                .contains("query or fragment")
        );
        assert!(policy.check_issuer("https://").is_err());
        assert!(policy.check_issuer("mailto:alice@example.com").is_err());
        assert!(policy.check_issuer("not a uri").is_err());
    }

    #[test]
    fn endpoints_follow_the_same_rules_but_may_have_a_query() {
        let policy = SsfTransmitterUriPolicy::DEFAULT;
        assert!(
            policy
                .check_endpoint(&Url::parse("https://idp.example/jwks?x=1").unwrap(), "The JWK Set URL")
                .is_ok()
        );
        assert!(
            policy
                .check_endpoint(&Url::parse("https://idp.example/jwks#f").unwrap(), "The JWK Set URL")
                .unwrap_err()
                .contains("fragment")
        );
        assert!(
            policy
                .check_endpoint(&Url::parse("http://idp.example/jwks").unwrap(), "The JWK Set URL")
                .unwrap_err()
                .contains("must use https")
        );
        assert!(
            policy
                .check_endpoint(&Url::parse("http://localhost/jwks").unwrap(), "The JWK Set URL")
                .is_ok()
        );
    }
}
