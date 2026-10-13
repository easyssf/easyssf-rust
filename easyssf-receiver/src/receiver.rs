//! The configured receiver: the counterpart of `AddSsfReceiver()` and of the Spring Boot
//! auto-configuration. Builds every part from an [`SsfReceiverConfig`], runs the stream
//! registration and polling in the background, and reports its health.
//!
//! ```no_run
//! # use easyssf_receiver::{BoxError, SsfReceiver, config::SsfReceiverConfig, event::for_event};
//! # async fn run() -> Result<(), BoxError> {
//! // easyssf.receiver.* from any serde source, with the keys of the Spring starter
//! let config: SsfReceiverConfig = toml::from_str(r#"
//!     transmitter-issuer = "https://idp.example/realms/demo"
//!     expected-audience = "https://my-app.example"
//! "#)?;
//!
//! let receiver = SsfReceiver::builder(config)
//!     .handler(for_event("CaepCredentialChange", |context| async move { Ok(()) }))
//!     .build()?;                                   // validates, as SsfReceiverOptionsValidator does
//! receiver.start();                                // registers the stream, starts polling
//! let push_handler = receiver.push_handler();      // for the push route of the web framework
//! // ... serve ...
//! receiver.shutdown().await;                       // sends the acknowledgements it owes
//! # Ok(()) }
//! ```

#[cfg(feature = "metrics")]
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use async_trait::async_trait;
use easyssf_core::SsfEventToken;
use easyssf_core::stream::SsfStreamConfiguration;
use url::Url;

use crate::config::{
    CONFIGURATION_SECTION, SsfClientAuthenticationMethod, SsfDeliveryMethodConfig, SsfReceiverConfig,
    SsfReceiverConfigError, SsfStreamManagement, SsfTransmitterConfig,
};
use crate::event::{BoxedSsfEventHandler, SsfEventHandler};
use crate::http::SsfHttpClient;
use crate::metrics::{NoopSsfReceiverMetrics, SsfReceiverMetrics};
use crate::poll::{PollEndpoint, SsfPollAckStore, SsfPoller, SsfPollerOptions};
use crate::push::SsfPushHandler;
use crate::revocation::{InMemorySsfTokenRevocationStore, SsfTokenRevocationEventHandler, SsfTokenRevocationStore};
use crate::session::{SsfSessionTerminationEventHandler, SsfSessionTerminator};
use crate::set::{
    HttpSsfJwkSetSource, InMemorySsfJtiDedupStore, JwkSetUriResolver, JwtSsfSetVerifier, SsfErrorCode,
    SsfJtiDedupStore, SsfSetProcessor, SsfSetProcessorOptions, SsfSetVerificationError, SsfSetVerifier,
    SsfSetVerifierOptions, supported_algorithm,
};
use crate::stream::{
    SsfReceiverStream, SsfStreamClient, SsfStreamRegistrar, SsfStreamRegistrarState, SsfStreamVerification,
};
use crate::transmitter::{
    ClientCredentialsSsfTransmitterTokenProvider, FixedSsfTransmitterTokenProvider, NoSsfTransmitterTokenProvider,
    SsfClientCredentialsOptions, SsfTransmitter, SsfTransmitterBuilder, SsfTransmitterMetadataResolver,
    SsfTransmitterTokenProvider, SsfTransmitterUnavailable, SsfTransmitters,
};

/// Customizes a transmitter before it is built: replaces a part the builder built from the
/// configuration, or adds one. Called for every transmitter, the default one included;
/// [`SsfTransmitterBuilder::name`] tells which.
pub type SsfTransmitterCustomizer = Box<dyn Fn(&mut SsfTransmitterBuilder) + Send + Sync>;

type TransmittersSlot = Arc<OnceLock<Arc<SsfTransmitters>>>;

/// Assembles an [`SsfReceiver`] from its configuration and the parts of the application.
pub struct SsfReceiverBuilder {
    config: SsfReceiverConfig,
    handlers: Vec<BoxedSsfEventHandler>,
    http_client: Option<Arc<dyn SsfHttpClient>>,
    jti_dedup_store: Option<Arc<dyn SsfJtiDedupStore>>,
    token_revocation_store: Option<Arc<dyn SsfTokenRevocationStore>>,
    poll_ack_store: Option<Arc<dyn SsfPollAckStore>>,
    session_terminator: Option<Arc<dyn SsfSessionTerminator>>,
    metrics: Option<Arc<dyn SsfReceiverMetrics>>,
    customizers: Vec<SsfTransmitterCustomizer>,
}

impl SsfReceiverBuilder {
    /// Adds an event handler, invoked for every SET.
    pub fn handler(mut self, handler: impl SsfEventHandler) -> Self {
        self.handlers.push(Arc::new(handler));
        self
    }

    /// Adds a handler held type-erased.
    pub fn boxed_handler(mut self, handler: BoxedSsfEventHandler) -> Self {
        self.handlers.push(handler);
        self
    }

    /// The HTTP client that calls the transmitters: metadata, JWK Sets, tokens, stream
    /// management and polling. A reqwest client built from `easyssf.receiver.http` by default
    /// (feature `reqwest`).
    pub fn http_client(mut self, client: impl SsfHttpClient) -> Self {
        self.http_client = Some(Arc::new(client));
        self
    }

    /// Replaces the in-memory de-duplication store, for example with the store of
    /// `easyssf-receiver-sqlx`.
    pub fn jti_dedup_store(mut self, store: impl SsfJtiDedupStore) -> Self {
        self.jti_dedup_store = Some(Arc::new(store));
        self
    }

    /// Replaces the in-memory revocation store.
    pub fn token_revocation_store(mut self, store: impl SsfTokenRevocationStore) -> Self {
        self.token_revocation_store = Some(Arc::new(store));
        self
    }

    /// Replaces the in-memory store of the acknowledgements a poller owes.
    pub fn poll_ack_store(mut self, store: impl SsfPollAckStore) -> Self {
        self.poll_ack_store = Some(Arc::new(store));
        self
    }

    /// Ends the server-side sessions of the application when a session event arrives.
    pub fn session_terminator(mut self, terminator: impl SsfSessionTerminator) -> Self {
        self.session_terminator = Some(Arc::new(terminator));
        self
    }

    /// Records what the receiver does; the `metrics` facade with feature `metrics`, nothing
    /// otherwise.
    pub fn metrics(mut self, metrics: impl SsfReceiverMetrics) -> Self {
        self.metrics = Some(Arc::new(metrics));
        self
    }

    /// Adds a customizer that is called for every transmitter before it is built.
    pub fn customize_transmitter(
        mut self,
        customize: impl Fn(&mut SsfTransmitterBuilder) + Send + Sync + 'static,
    ) -> Self {
        self.customizers.push(Box::new(customize));
        self
    }

    /// Builds the receiver: validates the configuration, registers the event aliases and builds
    /// every part. Nothing is started and no transmitter is called.
    ///
    /// # Errors
    ///
    /// If the configuration is not usable, or no HTTP client is available.
    pub fn build(self) -> Result<SsfReceiver, SsfReceiverConfigError> {
        let config = self.config;
        config.validate()?;
        let http = match self.http_client {
            Some(client) => client,
            None => default_http_client(&config)?,
        };
        let metrics = self.metrics.unwrap_or_else(|| default_metrics(&config));
        let revocation_store = self
            .token_revocation_store
            .unwrap_or_else(|| Arc::new(InMemorySsfTokenRevocationStore::new(config.revocation.ttl)));
        let dedup_store: Option<Arc<dyn SsfJtiDedupStore>> = if config.dedup.enabled {
            Some(self.jti_dedup_store.unwrap_or_else(|| {
                Arc::new(InMemorySsfJtiDedupStore::new(config.dedup.capacity).with_lease(config.dedup.lease))
            }))
        } else {
            None
        };
        let slot: TransmittersSlot = Arc::new(OnceLock::new());

        // the issuer of a SET selects the transmitter that verifies it; the transmitters are
        // looked up when the first SET arrives, as their pollers need the processor
        let verifier = TransmittersVerifier { slot: slot.clone() };
        let mut processor = match &dedup_store {
            Some(store) => SsfSetProcessor::new(verifier, store.clone()),
            None => SsfSetProcessor::without_dedup(verifier),
        };
        let verifications_slot = slot.clone();
        let critical_slot = slot.clone();
        processor = processor.options(SsfSetProcessorOptions {
            metrics: metrics.clone(),
            stream_verifications: Some(Arc::new(move |issuer| {
                verifications_slot
                    .get()
                    .and_then(|transmitters| transmitters.stream_verification(issuer))
            })),
            understood_subject_members: config.effective_understood_subject_members().into_iter().collect(),
            critical_subject_members: Some(Arc::new(move |issuer| {
                critical_slot
                    .get()
                    .map(|transmitters| transmitters.critical_subject_members(issuer))
                    .unwrap_or_default()
            })),
            // a handler may run longer than the lease: the claim is renewed meanwhile
            claim_renewal: config.dedup.enabled.then(|| config.dedup.lease / 3),
        });
        if config.revocation.enabled {
            processor = processor.handler(SsfTokenRevocationEventHandler::with_event_types(
                revocation_store.clone(),
                &config.revocation.effective_session_event_types(),
                &config.revocation.user_event_types,
            ));
        }
        if config.session_termination.enabled
            && let Some(terminator) = self.session_terminator
        {
            processor = processor.handler(SsfSessionTerminationEventHandler::with_event_types(
                terminator,
                &config.session_termination.effective_session_event_types(),
                &config.session_termination.effective_user_event_types(),
            ));
        }
        for handler in self.handlers {
            processor = processor.boxed_handler(handler);
        }
        let processor = Arc::new(processor);

        let mut transmitters = Vec::new();
        for (name, transmitter_config) in config.configured_transmitters()? {
            let mut builder = transmitter_builder(
                &name,
                transmitter_config,
                http.clone(),
                processor.clone(),
                metrics.clone(),
                self.poll_ack_store.clone(),
            )?;
            for customizer in &self.customizers {
                customizer(&mut builder);
            }
            transmitters.push(builder.build());
        }
        let transmitters = Arc::new(
            SsfTransmitters::new(transmitters)
                .map_err(|e| SsfReceiverConfigError::new(format!("{CONFIGURATION_SECTION}.transmitters: {e}")))?,
        );
        let _ = slot.set(transmitters.clone());

        // with one transmitter the header is checked before the SET is even parsed
        let push_handler = if transmitters.all().len() == 1 {
            SsfPushHandler::new(processor.clone(), transmitters.all()[0].push_authorization_header())
        } else {
            let headers = transmitters.clone();
            SsfPushHandler::by_issuer(
                processor.clone(),
                Arc::new(move |issuer| headers.push_authorization_header(issuer)),
            )
        }
        .with_metrics(metrics.clone());

        Ok(SsfReceiver {
            config,
            transmitters,
            processor,
            push_handler,
            revocation_store,
            dedup_store,
            metrics,
        })
    }
}

#[cfg(feature = "reqwest")]
fn default_http_client(config: &SsfReceiverConfig) -> Result<Arc<dyn SsfHttpClient>, SsfReceiverConfigError> {
    let mut client = crate::http::ReqwestSsfHttpClient::with_timeout(config.http.timeout);
    if let Some(user_agent) = config.http.user_agent.as_deref().filter(|ua| !ua.trim().is_empty()) {
        client = client.with_user_agent(user_agent);
    }
    Ok(Arc::new(client))
}

#[cfg(not(feature = "reqwest"))]
fn default_http_client(_config: &SsfReceiverConfig) -> Result<Arc<dyn SsfHttpClient>, SsfReceiverConfigError> {
    Err(SsfReceiverConfigError::new(
        "No HTTP client: enable the `reqwest` feature of easyssf-receiver or give the builder an SsfHttpClient",
    ))
}

#[cfg(feature = "metrics")]
fn default_metrics(config: &SsfReceiverConfig) -> Arc<dyn SsfReceiverMetrics> {
    if !config.metrics.enabled {
        return Arc::new(NoopSsfReceiverMetrics);
    }
    let names: HashMap<String, String> = config
        .configured_transmitters()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(name, transmitter)| transmitter.issuer().map(|issuer| (issuer.to_owned(), name)))
        .collect();
    Arc::new(
        crate::metrics::MetricsSsfReceiverMetrics::new()
            .with_transmitter_labels(move |issuer| names.get(issuer).cloned().unwrap_or_else(|| issuer.to_owned())),
    )
}

#[cfg(not(feature = "metrics"))]
fn default_metrics(_config: &SsfReceiverConfig) -> Arc<dyn SsfReceiverMetrics> {
    Arc::new(NoopSsfReceiverMetrics)
}

/// Verifies a SET with the transmitter that issued it, looked up on first use.
struct TransmittersVerifier {
    slot: TransmittersSlot,
}

#[async_trait]
impl SsfSetVerifier for TransmittersVerifier {
    async fn verify(&self, encoded_set: &str) -> Result<SsfEventToken, SsfSetVerificationError> {
        let Some(transmitters) = self.slot.get() else {
            return Err(SsfTransmitterUnavailable::new("The receiver is not built yet").into());
        };
        transmitters.verifier().verify(encoded_set).await
    }
}

fn describe(name: &str, issuer: &str) -> String {
    if name == SsfTransmitter::DEFAULT_NAME {
        issuer.to_owned()
    } else {
        format!("'{name}' ({issuer})")
    }
}

/// A builder with every part of the transmitter built from its configuration, as
/// `SsfTransmitterFactory` builds them in .NET. An application that assembles a receiver by hand
/// can use it for the parts it does not want to build itself.
pub fn transmitter_builder(
    name: &str,
    config: &SsfTransmitterConfig,
    http: Arc<dyn SsfHttpClient>,
    processor: Arc<SsfSetProcessor>,
    metrics: Arc<dyn SsfReceiverMetrics>,
    ack_store: Option<Arc<dyn SsfPollAckStore>>,
) -> Result<SsfTransmitterBuilder, SsfReceiverConfigError> {
    let prefix = SsfTransmitterConfig::prefix(name);
    let failures = config.validate(name);
    if !failures.is_empty() {
        return Err(SsfReceiverConfigError::new(failures.join("; ")));
    }
    let issuer = config.issuer().expect("validated").to_owned();
    let policy = config.uri_policy();
    let receiver_stream = Arc::new(SsfReceiverStream::new());
    let metadata_resolver = Arc::new(
        SsfTransmitterMetadataResolver::new(
            issuer.clone(),
            config.transmitter_metadata_url.clone(),
            http.clone(),
            policy,
        )
        .map_err(|e| SsfReceiverConfigError::new(format!("{prefix}transmitter-issuer: {e}")))?,
    );
    tracing::info!(
        transmitter = describe(name, &issuer),
        metadata_uris = ?metadata_resolver.metadata_uris().iter().map(Url::as_str).collect::<Vec<_>>(),
        "SSF transmitter: metadata is resolved from"
    );
    if config.allow_insecure_http {
        tracing::warn!(
            transmitter = describe(name, &issuer),
            "{prefix}allow-insecure-http is on, the SSF transmitter is used without TLS. For development only"
        );
    }
    let token_provider: Arc<dyn SsfTransmitterTokenProvider> = token_provider(config, http.clone());
    let stream_client = Arc::new(SsfStreamClient::new(
        http.clone(),
        token_provider.clone(),
        metadata_resolver.clone(),
    ));
    let verifier = verifier(name, config, http.clone(), &metadata_resolver, &receiver_stream);
    let stream_verification = {
        let stream = receiver_stream.clone();
        Arc::new(SsfStreamVerification::new().with_stream_id(move || stream.stream_id()))
    };
    let stream_registrar = if config.registers_stream() {
        Some(if config.stream.management == SsfStreamManagement::Receiver {
            SsfStreamRegistrar::for_managed_stream(
                stream_client.clone(),
                receiver_stream.clone(),
                desired_stream(config),
            )
            .with_delete_on_shutdown(config.stream.delete_on_shutdown)
        } else {
            SsfStreamRegistrar::for_existing_stream(
                stream_client.clone(),
                receiver_stream.clone(),
                config.stream.id.as_deref().unwrap_or("").trim(),
            )
        })
    } else {
        None
    };
    let poller = if config.delivery_method == SsfDeliveryMethodConfig::Poll {
        let poll = &config.poll;
        let mut options = SsfPollerOptions {
            transmitter: Some(issuer.clone()),
            metrics,
            interval: poll.interval,
            initial_delay: poll.initial_delay,
            max_events: poll.max_events,
            long_polling_hold: poll.long_polling.then_some(poll.long_polling_hold),
            rate_limit_fallback: poll.rate_limit.fallback_backoff,
            max_pause: poll.rate_limit.max_backoff,
            ..SsfPollerOptions::default()
        };
        if let Some(ack_store) = ack_store {
            options.ack_store = ack_store;
        }
        let endpoint: PollEndpoint = match &poll.endpoint_url {
            Some(configured) => {
                let configured = configured.clone();
                Arc::new(move || Some(configured.clone()))
            }
            None => {
                let stream = receiver_stream.clone();
                Arc::new(move || {
                    stream
                        .configuration()
                        .filter(|c| c.delivery_method() == Some(easyssf_core::SsfDeliveryMethod::Poll.uri()))
                        .and_then(|c| c.delivery_endpoint_url())
                })
            }
        };
        Some(SsfPoller::new(
            http,
            token_provider.clone(),
            endpoint,
            processor,
            options,
        ))
    } else {
        None
    };
    let mut builder = SsfTransmitter::builder(name, issuer);
    builder.metadata_resolver = Some(metadata_resolver);
    builder.verifier = Some(verifier);
    builder.token_provider = Some(token_provider);
    builder.stream_client = Some(stream_client);
    builder.receiver_stream = receiver_stream;
    builder.stream_verification = Some(stream_verification);
    builder.stream_registrar = stream_registrar;
    builder.poller = poller;
    builder.auto_start_polling = config.poll.auto_startup;
    builder.push_authorization_header = config.push.expected_auth_header.clone();
    Ok(builder)
}

fn token_provider(config: &SsfTransmitterConfig, http: Arc<dyn SsfHttpClient>) -> Arc<dyn SsfTransmitterTokenProvider> {
    if let Some(token) = config
        .transmitter_access_token
        .as_deref()
        .filter(|t| !t.trim().is_empty())
    {
        return Arc::new(FixedSsfTransmitterTokenProvider(token.to_owned()));
    }
    let Some(token_uri) = &config.oauth2.token_uri else {
        return Arc::new(NoSsfTransmitterTokenProvider);
    };
    let oauth2 = &config.oauth2;
    Arc::new(ClientCredentialsSsfTransmitterTokenProvider::new(
        http,
        token_uri.clone(),
        oauth2.client_id.clone().unwrap_or_default(),
        oauth2.client_secret.clone().unwrap_or_default(),
        SsfClientCredentialsOptions {
            scopes: oauth2.scopes.clone(),
            authenticate_with_request_body: oauth2.client_authentication_method == SsfClientAuthenticationMethod::Post,
            expiry_safety_window: oauth2.expiry_safety_window,
            additional_parameters: oauth2
                .additional_parameters
                .iter()
                .map(|(n, v)| (n.clone(), v.clone()))
                .collect(),
            ..SsfClientCredentialsOptions::default()
        },
    ))
}

/// The verifier of the transmitter. The audience is the configured one; without one, the
/// audience of the stream once it is registered, and SETs are left unverified (transmitter
/// unavailable) until it is; without a registered stream, any, which the validation allows only
/// with `set-validation.allow-any-audience`.
fn verifier(
    name: &str,
    config: &SsfTransmitterConfig,
    http: Arc<dyn SsfHttpClient>,
    metadata_resolver: &Arc<SsfTransmitterMetadataResolver>,
    receiver_stream: &Arc<SsfReceiverStream>,
) -> Arc<dyn SsfSetVerifier> {
    let prefix = SsfTransmitterConfig::prefix(name);
    let issuer = config.issuer().expect("validated").to_owned();
    let validation = &config.set_validation;
    let mut options = SsfSetVerifierOptions {
        accepted_algorithms: validation
            .effective_accepted_algorithms()
            .iter()
            .filter_map(|a| supported_algorithm(a))
            .collect(),
        min_rsa_key_size: validation.min_rsa_key_size,
        require_type_header: validation.require_type_header,
        subject_compatibility: validation.subject_compatibility_mode(),
        clock_skew: validation.clock_skew,
        ..SsfSetVerifierOptions::default()
    };
    if let Some(audience) = config.expected_audience.as_deref().filter(|a| !a.trim().is_empty()) {
        options.expected_audiences = vec![audience.trim().to_owned()];
    } else if config.registers_stream() {
        // the transmitter tells the audience of the stream; until the stream is known a SET
        // cannot be checked, so it is left to the redelivery instead of being accepted blindly
        let any_audience = validation.allow_any_audience;
        let transmitter = describe(name, &issuer);
        let stream = receiver_stream.clone();
        let prefix = prefix.clone();
        options.expected_audiences_provider = Some(Arc::new(move || {
            if stream.configuration().is_none() {
                return Err(SsfTransmitterUnavailable::new(format!(
                    "The stream at {transmitter} is not registered yet, so the audience of SETs cannot be checked"
                ))
                .into());
            }
            let audience = stream.audience();
            if audience.is_empty() && !any_audience {
                return Err(SsfSetVerificationError::rejected(
                    SsfErrorCode::InvalidAudience,
                    format!(
                        "The stream at {transmitter} has no audience (aud), set {prefix}expected-audience or {prefix}set-validation.allow-any-audience"
                    ),
                ));
            }
            Ok(audience)
        }));
    } else {
        // allowed by the validation only with set-validation.allow-any-audience
        tracing::warn!(
            transmitter = describe(name, &issuer),
            "{prefix}expected-audience is not set, SETs that the transmitter issued for other receivers are accepted as well"
        );
    }
    let keys = match &config.transmitter_jwks_url {
        Some(url) => HttpSsfJwkSetSource::new(http, url.clone()),
        None => {
            let resolver = metadata_resolver.clone();
            let prefix = prefix.clone();
            let resolve: JwkSetUriResolver = Arc::new(move || {
                let resolver = resolver.clone();
                let prefix = prefix.clone();
                Box::pin(async move {
                    let metadata = resolver.resolve().await?;
                    metadata.jwks_uri().cloned().ok_or_else(|| {
                        SsfTransmitterUnavailable::new(format!(
                            "The SSF transmitter metadata has no jwks_uri, configure {prefix}transmitter-jwks-url"
                        ))
                    })
                })
            });
            HttpSsfJwkSetSource::resolved(http, resolve)
        }
    };
    Arc::new(JwtSsfSetVerifier::new(issuer, keys, options))
}

fn desired_stream(config: &SsfTransmitterConfig) -> SsfStreamConfiguration {
    let stream = &config.stream;
    let events = stream.effective_events_requested();
    if config.delivery_method == SsfDeliveryMethodConfig::Poll {
        return SsfStreamConfiguration::poll(&events, stream.description.as_deref());
    }
    let endpoint = config.push.delivery_endpoint_url.as_ref().expect("validated");
    SsfStreamConfiguration::push(
        endpoint,
        config
            .push
            .expected_auth_header
            .as_deref()
            .filter(|h| !h.trim().is_empty()),
        &events,
        stream.description.as_deref(),
    )
}

/// The receiver assembled from its configuration: the transmitters with their background work,
/// the processor with the handlers, the push handler for the web framework, and the stores.
pub struct SsfReceiver {
    config: SsfReceiverConfig,
    transmitters: Arc<SsfTransmitters>,
    processor: Arc<SsfSetProcessor>,
    push_handler: SsfPushHandler,
    revocation_store: Arc<dyn SsfTokenRevocationStore>,
    dedup_store: Option<Arc<dyn SsfJtiDedupStore>>,
    metrics: Arc<dyn SsfReceiverMetrics>,
}

impl std::fmt::Debug for SsfReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SsfReceiver")
            .field("transmitters", &self.transmitters.all())
            .finish()
    }
}

impl SsfReceiver {
    /// A builder for a receiver with the given configuration.
    pub fn builder(config: SsfReceiverConfig) -> SsfReceiverBuilder {
        SsfReceiverBuilder {
            config,
            handlers: Vec::new(),
            http_client: None,
            jti_dedup_store: None,
            token_revocation_store: None,
            poll_ack_store: None,
            session_terminator: None,
            metrics: None,
            customizers: Vec::new(),
        }
    }

    /// The configuration the receiver was built from.
    pub fn config(&self) -> &SsfReceiverConfig {
        &self.config
    }

    /// The transmitters.
    pub fn transmitters(&self) -> &Arc<SsfTransmitters> {
        &self.transmitters
    }

    /// The processor with every handler.
    pub fn processor(&self) -> &Arc<SsfSetProcessor> {
        &self.processor
    }

    /// The push handler, for the push route of the web framework.
    pub fn push_handler(&self) -> SsfPushHandler {
        self.push_handler.clone()
    }

    /// The path of the push endpoint, `easyssf.receiver.push.endpoint-path`.
    pub fn push_endpoint_path(&self) -> &str {
        &self.config.transmitter.push.endpoint_path
    }

    /// The revocation store the web framework consults.
    pub fn token_revocation_store(&self) -> Arc<dyn SsfTokenRevocationStore> {
        self.revocation_store.clone()
    }

    /// The de-duplication store, `None` if de-duplication is off.
    pub fn jti_dedup_store(&self) -> Option<Arc<dyn SsfJtiDedupStore>> {
        self.dedup_store.clone()
    }

    /// What the receiver records with.
    pub fn metrics(&self) -> Arc<dyn SsfReceiverMetrics> {
        self.metrics.clone()
    }

    /// Starts the background work: looking up or registering the streams and polling the
    /// transmitters. Needs a tokio runtime. Does nothing if the receiver is disabled.
    pub fn start(&self) {
        if !self.config.enabled {
            tracing::info!("The SSF receiver is disabled ({CONFIGURATION_SECTION}.enabled = false)");
            return;
        }
        self.transmitters.start();
        tracing::info!(
            count = self.transmitters.all().len(),
            transmitters = ?self.transmitters.all().iter().map(ToString::to_string).collect::<Vec<_>>(),
            "SSF receiver started"
        );
    }

    /// Stops the background work and sends the acknowledgements the pollers owe.
    pub async fn shutdown(&self) {
        self.transmitters.stop().await;
    }

    /// The health of the receiver as of now, from what it already knows; no transmitter is
    /// called.
    pub async fn health(&self) -> SsfReceiverHealth {
        if !self.config.enabled {
            return SsfReceiverHealth {
                status: SsfHealthStatus::Healthy,
                description: "The SSF receiver is disabled".to_owned(),
                transmitters: Vec::new(),
            };
        }
        let mut transmitters = Vec::new();
        let mut status = SsfHealthStatus::Healthy;
        for transmitter in self.transmitters.all() {
            let health = SsfTransmitterHealth::of(transmitter).await;
            status = status.worse(health.status);
            transmitters.push(health);
        }
        SsfReceiverHealth {
            status,
            description: match status {
                SsfHealthStatus::Healthy => "In contact with the SSF transmitter(s)",
                SsfHealthStatus::Unhealthy => "An SSF transmitter cannot be polled or its stream cannot be used",
                SsfHealthStatus::Degraded => "No contact with an SSF transmitter yet",
            }
            .to_owned(),
            transmitters,
        }
    }
}

/// Whether the receiver is in contact with its transmitters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsfHealthStatus {
    /// Every transmitter was reached, that is its metadata was retrieved (PUSH) or the last poll
    /// succeeded (POLL), and its stream, if it is looked up or managed, is registered.
    Healthy,
    /// No contact with a transmitter yet. The application starts without it.
    Degraded,
    /// A last poll failed, or a stream cannot be used.
    Unhealthy,
}

impl SsfHealthStatus {
    fn worse(self, other: Self) -> Self {
        if self == Self::Unhealthy || other == Self::Unhealthy {
            return Self::Unhealthy;
        }
        if self == Self::Degraded || other == Self::Degraded {
            return Self::Degraded;
        }
        Self::Healthy
    }

    /// The lowercase name: `healthy`, `degraded`, `unhealthy`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
        }
    }
}

/// The health of the receiver, see [`SsfReceiver::health`].
#[derive(Debug, Clone)]
pub struct SsfReceiverHealth {
    /// The worst status of the transmitters.
    pub status: SsfHealthStatus,
    /// What the status means.
    pub description: String,
    /// The health of every transmitter.
    pub transmitters: Vec<SsfTransmitterHealth>,
}

/// The health of one transmitter.
#[derive(Debug, Clone)]
pub struct SsfTransmitterHealth {
    /// The status of the transmitter.
    pub status: SsfHealthStatus,
    /// The name of the transmitter.
    pub name: String,
    /// The issuer of the transmitter.
    pub issuer: String,
    /// `push` or `poll`.
    pub delivery: &'static str,
    /// Whether the metadata was retrieved.
    pub metadata_resolved: bool,
    /// The JWK Set location from the metadata.
    pub jwks_uri: Option<String>,
    /// The identifier of the stream, once known.
    pub stream_id: Option<String>,
    /// The state of the stream registration, `None` if the stream is neither looked up nor
    /// managed.
    pub stream_registration: Option<SsfStreamRegistrarState>,
    /// Why the stream registration failed.
    pub stream_registration_error: Option<String>,
    /// When the transmitter was last polled.
    pub last_poll_at: Option<SystemTime>,
    /// When the transmitter was last polled successfully.
    pub last_successful_poll_at: Option<SystemTime>,
    /// Why the last poll failed.
    pub poll_error: Option<String>,
    /// The acknowledgements and error reports waiting for the next poll request.
    pub pending_acks: usize,
    /// Until when the transmitter asked not to be polled.
    pub paused_until: Option<SystemTime>,
}

impl SsfTransmitterHealth {
    async fn of(transmitter: &SsfTransmitter) -> Self {
        let mut status = SsfHealthStatus::Degraded;
        let metadata = transmitter.metadata_resolver().resolved_metadata();
        if metadata.is_some() {
            status = SsfHealthStatus::Healthy;
        }
        let registrar = transmitter.stream_registrar();
        if let Some(registrar) = registrar {
            match registrar.state() {
                SsfStreamRegistrarState::Failed => status = SsfHealthStatus::Unhealthy,
                SsfStreamRegistrarState::Registered => {}
                _ => status = SsfHealthStatus::Degraded,
            }
        }
        let poller = transmitter.poller();
        let mut pending_acks = 0;
        if let Some(poller) = poller {
            pending_acks = poller.pending_ack_count().await;
            if poller.last_poll_error().is_some() {
                status = SsfHealthStatus::Unhealthy;
            } else if poller.last_successful_poll_at().is_none() && status != SsfHealthStatus::Unhealthy {
                status = SsfHealthStatus::Degraded;
            }
        }
        Self {
            status,
            name: transmitter.name().to_owned(),
            issuer: transmitter.issuer().to_owned(),
            delivery: if poller.is_some() { "poll" } else { "push" },
            metadata_resolved: metadata.is_some(),
            jwks_uri: metadata.as_ref().and_then(|m| m.jwks_uri().map(ToString::to_string)),
            stream_id: transmitter.receiver_stream().stream_id(),
            stream_registration: registrar.map(|r| r.state()),
            stream_registration_error: registrar.and_then(|r| r.last_error()),
            last_poll_at: poller.and_then(SsfPoller::last_poll_at),
            last_successful_poll_at: poller.and_then(SsfPoller::last_successful_poll_at),
            poll_error: poller.and_then(SsfPoller::last_poll_error),
            pending_acks,
            paused_until: poller.and_then(SsfPoller::paused_until),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_needs_a_usable_configuration() {
        let error = SsfReceiver::builder(SsfReceiverConfig::default()).build().unwrap_err();
        assert!(error.to_string().contains("transmitter-issuer"), "{error}");
    }
}
