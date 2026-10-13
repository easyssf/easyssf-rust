//! The configuration of a receiver, deserialized with serde from TOML, YAML, JSON or the
//! environment through the configuration crate of your choice (figment, config-rs, ...). The keys
//! are those of the Spring Boot starter and of the .NET options, in kebab-case, under
//! `easyssf.receiver`:
//!
//! ```toml
//! [easyssf.receiver]
//! transmitter-issuer = "https://idp.example/realms/demo"   # required
//! expected-audience = "https://my-app.example"             # or let the receiver register the stream
//! [easyssf.receiver.push]
//! expected-auth-header = "Bearer s3cr3t"                   # recommended
//! ```
//!
//! The settings of a transmitter ([`SsfTransmitterConfig`]) at `easyssf.receiver` configure the
//! default transmitter; `easyssf.receiver.transmitters.<name>` adds further ones, each complete
//! on its own. Everything else is shared by all transmitters. Durations are strings such as
//! `"30s"`, `"5m"` or `"24h"`.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use easyssf_core::{SsfDeliveryMethod, SsfSubject, SubjectCompatibilityMode, event_types};
use serde::Deserialize;
use url::Url;

use crate::set::supported_algorithm;
use crate::transmitter::{SsfTransmitter, SsfTransmitterUriPolicy};

/// The configuration section the receiver reads, for messages: `easyssf.receiver`.
pub const CONFIGURATION_SECTION: &str = "easyssf.receiver";

/// The configuration is not usable; every failure is listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfReceiverConfigError {
    failures: Vec<String>,
}

impl SsfReceiverConfigError {
    /// An error with one failure.
    pub fn new(failure: impl Into<String>) -> Self {
        Self {
            failures: vec![failure.into()],
        }
    }

    /// What is wrong, one line each, with the key of the setting first.
    pub fn failures(&self) -> &[String] {
        &self.failures
    }
}

impl fmt::Display for SsfReceiverConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "The SSF receiver configuration is not usable: {}",
            self.failures.join("; ")
        )
    }
}

impl std::error::Error for SsfReceiverConfigError {}

/// Configuration of the receiver, bound from `easyssf.receiver`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SsfReceiverConfig {
    /// Whether the SSF receiver is enabled.
    pub enabled: bool,
    /// The settings of the default transmitter.
    #[serde(flatten)]
    pub transmitter: SsfTransmitterConfig,
    /// Aliases for event type URIs, e.g. `AcmeLogin = "https://events.acme.example/login"`, usable
    /// wherever an event type is named. They add to the built-in aliases and cannot redefine one.
    pub event_aliases: BTreeMap<String, String>,
    /// The members of a complex subject the application interprets. A SET with a member a
    /// transmitter declared critical (`critical_subject_members`) that is not listed here is
    /// rejected. Empty, the default, means the members [`SsfSubject`] gives access to (`user`,
    /// `session`, `device`, `application`, `tenant`, `org_unit`, `group`).
    pub understood_subject_members: Vec<String>,
    /// Further transmitters by name, each with the settings of a transmitter. The settings at
    /// `easyssf.receiver` configure the transmitter named `default`.
    pub transmitters: BTreeMap<String, SsfTransmitterConfig>,
    /// Outbound HTTP calls to the transmitter.
    pub http: SsfHttpConfig,
    /// Metrics.
    pub metrics: SsfMetricsConfig,
    /// De-duplication of SETs by `jti`.
    pub dedup: SsfDedupConfig,
    /// Revocation of access tokens and sessions by security events.
    pub revocation: SsfRevocationConfig,
    /// Termination of server-side sessions by security events.
    pub session_termination: SsfSessionTerminationConfig,
    /// The database stores of `easyssf-receiver-sqlx`, when the application added them.
    pub data: SsfDataConfig,
}

impl Default for SsfReceiverConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            transmitter: SsfTransmitterConfig::default(),
            event_aliases: BTreeMap::new(),
            understood_subject_members: Vec::new(),
            transmitters: BTreeMap::new(),
            http: SsfHttpConfig::default(),
            metrics: SsfMetricsConfig::default(),
            dedup: SsfDedupConfig::default(),
            revocation: SsfRevocationConfig::default(),
            session_termination: SsfSessionTerminationConfig::default(),
            data: SsfDataConfig::default(),
        }
    }
}

impl SsfReceiverConfig {
    /// A configuration for one transmitter with push delivery, the common case.
    pub fn for_transmitter(issuer: &str) -> Self {
        Self {
            transmitter: SsfTransmitterConfig {
                transmitter_issuer: Some(issuer.to_owned()),
                ..SsfTransmitterConfig::default()
            },
            ..Self::default()
        }
    }

    /// Whether the default transmitter is configured: an issuer is set at `easyssf.receiver`.
    pub fn has_default_transmitter(&self) -> bool {
        self.transmitter
            .transmitter_issuer
            .as_deref()
            .is_some_and(|issuer| !issuer.trim().is_empty())
    }

    /// The members the application interprets: the configured ones, or [`SsfSubject::MEMBERS`]
    /// if none are configured.
    pub fn effective_understood_subject_members(&self) -> Vec<String> {
        if self.understood_subject_members.is_empty() {
            SsfSubject::MEMBERS.iter().map(|m| (*m).to_owned()).collect()
        } else {
            self.understood_subject_members.clone()
        }
    }

    /// The transmitters that are configured, by name: the default one if its issuer is set, and
    /// the named ones.
    ///
    /// # Errors
    ///
    /// If a named transmitter is called `default` while the default transmitter is configured as
    /// well, or has no name.
    pub fn configured_transmitters(&self) -> Result<Vec<(String, &SsfTransmitterConfig)>, SsfReceiverConfigError> {
        let mut configured = Vec::new();
        if self.has_default_transmitter() {
            configured.push((SsfTransmitter::DEFAULT_NAME.to_owned(), &self.transmitter));
        }
        for (name, transmitter) in &self.transmitters {
            if name.trim().is_empty() {
                return Err(SsfReceiverConfigError::new(format!(
                    "{CONFIGURATION_SECTION}.transmitters: A transmitter under {CONFIGURATION_SECTION}.transmitters needs a name"
                )));
            }
            if name == SsfTransmitter::DEFAULT_NAME && self.has_default_transmitter() {
                return Err(SsfReceiverConfigError::new(format!(
                    "{CONFIGURATION_SECTION}.transmitters.{name}: The transmitter named '{}' is the one configured at \
                     {CONFIGURATION_SECTION}, it cannot be configured under {CONFIGURATION_SECTION}.transmitters as well",
                    SsfTransmitter::DEFAULT_NAME
                )));
            }
            configured.push((name.clone(), transmitter));
        }
        Ok(configured)
    }

    /// Registers the configured event type aliases, so that they resolve wherever an event type
    /// is named. Returns the aliases that could not be registered, with the reason.
    pub fn register_event_aliases(&self) -> Vec<String> {
        self.event_aliases
            .iter()
            .filter_map(|(alias, uri)| {
                event_types::register_alias(alias, uri)
                    .err()
                    .map(|e| format!("{CONFIGURATION_SECTION}.event-aliases.{alias}: {e}"))
            })
            .collect()
    }

    /// Checks the configuration the way the receiver does when it is built, and registers the
    /// event aliases.
    ///
    /// # Errors
    ///
    /// With every failure, if the configuration is not usable.
    pub fn validate(&self) -> Result<(), SsfReceiverConfigError> {
        if !self.enabled {
            return Ok(());
        }
        let mut failures = self.register_event_aliases();
        match self.configured_transmitters() {
            Err(error) => failures.extend(error.failures.clone()),
            Ok(transmitters) => {
                if transmitters.is_empty() {
                    failures.push(format!(
                        "{CONFIGURATION_SECTION}.transmitter-issuer: The issuer of the SSF transmitter must be configured, or \
                         transmitters under {CONFIGURATION_SECTION}.transmitters. Set {CONFIGURATION_SECTION}.enabled = false \
                         to switch the receiver off"
                    ));
                }
                let mut by_issuer: BTreeMap<&str, &str> = BTreeMap::new();
                for (name, transmitter) in &transmitters {
                    failures.extend(transmitter.validate(name));
                    if let Some(issuer) = transmitter.transmitter_issuer.as_deref()
                        && let Some(other) = by_issuer.insert(issuer, name)
                    {
                        failures.push(format!(
                            "{CONFIGURATION_SECTION}.transmitters: The transmitters '{name}' and '{other}' have the same issuer {issuer}"
                        ));
                    }
                }
            }
        }
        let path = &self.transmitter.push.endpoint_path;
        if path.trim().is_empty() || !path.starts_with('/') {
            failures.push(format!(
                "{CONFIGURATION_SECTION}.push.endpoint-path: The path of the push endpoint must start with '/' (value: '{path}')"
            ));
        }
        if self.dedup.capacity == 0 || self.dedup.lease.is_zero() {
            failures.push(format!(
                "{CONFIGURATION_SECTION}.dedup: capacity and lease must be positive"
            ));
        }
        if self.http.timeout.is_zero() {
            failures.push(format!("{CONFIGURATION_SECTION}.http.timeout: must be positive"));
        }
        if self.revocation.ttl.is_zero() {
            failures.push(format!("{CONFIGURATION_SECTION}.revocation.ttl: must be positive"));
        }
        if self.dedup.retention.is_zero() {
            failures.push(format!("{CONFIGURATION_SECTION}.dedup.retention: must be positive"));
        }
        if !self
            .data
            .table_prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        {
            failures.push(format!(
                "{CONFIGURATION_SECTION}.data.table-prefix: may only consist of letters, digits, '_' and '.' (value: '{}')",
                self.data.table_prefix
            ));
        }
        if self.data.ack_retention.is_zero() || self.data.ack_delete_batch_size == 0 {
            failures.push(format!(
                "{CONFIGURATION_SECTION}.data: ack-retention and ack-delete-batch-size must be positive"
            ));
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(SsfReceiverConfigError { failures })
        }
    }
}

/// The settings of one SSF transmitter, at `easyssf.receiver` for the default transmitter and
/// at `easyssf.receiver.transmitters.<name>` for every other one.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SsfTransmitterConfig {
    /// Issuer of the SSF transmitter. Every inbound SET must carry this value as its `iss` claim.
    pub transmitter_issuer: Option<String>,
    /// Location of the transmitter's SSF configuration metadata. Derived from the transmitter
    /// issuer when not set.
    pub transmitter_metadata_url: Option<Url>,
    /// Location of the JWK Set used to verify SET signatures. Discovered from the transmitter
    /// metadata (`jwks_uri`) when not set.
    pub transmitter_jwks_url: Option<Url>,
    /// Whether the transmitter issuer and the endpoints it publishes may use plain `http` on hosts
    /// other than loopback addresses. For test setups only, SSF requires `https`.
    pub allow_insecure_http: bool,
    /// Audience this receiver is known as at the transmitter. When set, every inbound SET must
    /// contain it in its `aud` claim.
    pub expected_audience: Option<String>,
    /// How the transmitter delivers SETs: `push` to the endpoint of this application or `poll`
    /// from an endpoint of the transmitter.
    pub delivery_method: SsfDeliveryMethodConfig,
    /// Access token to authenticate with at the stream management and poll endpoints of the
    /// transmitter, for transmitters that hand out long-lived tokens.
    pub transmitter_access_token: Option<String>,
    /// OAuth2 client credentials to authenticate with at the transmitter.
    pub oauth2: SsfOAuth2Config,
    /// The event stream of this receiver at the transmitter.
    pub stream: SsfStreamConfig,
    /// POLL delivery (RFC 8936).
    pub poll: SsfPollConfig,
    /// How SETs are validated.
    pub set_validation: SsfSetValidationConfig,
    /// PUSH delivery (RFC 8935) from this transmitter.
    pub push: SsfPushConfig,
}

impl Default for SsfTransmitterConfig {
    fn default() -> Self {
        Self {
            transmitter_issuer: None,
            transmitter_metadata_url: None,
            transmitter_jwks_url: None,
            allow_insecure_http: false,
            expected_audience: None,
            delivery_method: SsfDeliveryMethodConfig::Push,
            transmitter_access_token: None,
            oauth2: SsfOAuth2Config::default(),
            stream: SsfStreamConfig::default(),
            poll: SsfPollConfig::default(),
            set_validation: SsfSetValidationConfig::default(),
            push: SsfPushConfig::default(),
        }
    }
}

impl SsfTransmitterConfig {
    /// The configuration prefix of the transmitter with the given name, for messages.
    pub fn prefix(name: &str) -> String {
        if name == SsfTransmitter::DEFAULT_NAME {
            format!("{CONFIGURATION_SECTION}.")
        } else {
            format!("{CONFIGURATION_SECTION}.transmitters.{name}.")
        }
    }

    /// The issuer, trimmed.
    pub fn issuer(&self) -> Option<&str> {
        self.transmitter_issuer
            .as_deref()
            .map(str::trim)
            .filter(|issuer| !issuer.is_empty())
    }

    /// The URI policy: insecure if `allow-insecure-http` is set.
    pub fn uri_policy(&self) -> SsfTransmitterUriPolicy {
        if self.allow_insecure_http {
            SsfTransmitterUriPolicy::INSECURE
        } else {
            SsfTransmitterUriPolicy::DEFAULT
        }
    }

    /// Whether the stream of the transmitter is looked up or managed on startup.
    pub fn registers_stream(&self) -> bool {
        self.stream.management == SsfStreamManagement::Receiver
            || self.stream.id.as_deref().is_some_and(|id| !id.trim().is_empty())
    }

    /// The delivery method.
    pub fn delivery(&self) -> SsfDeliveryMethod {
        match self.delivery_method {
            SsfDeliveryMethodConfig::Push => SsfDeliveryMethod::Push,
            SsfDeliveryMethodConfig::Poll => SsfDeliveryMethod::Poll,
        }
    }

    /// Checks the settings of the transmitter named `name` the way the receiver does when it
    /// builds the parts. Returns what is wrong, empty if the settings are usable.
    pub fn validate(&self, name: &str) -> Vec<String> {
        let prefix = Self::prefix(name);
        let mut failures = Vec::new();
        let Some(issuer) = self.issuer() else {
            failures.push(format!(
                "{prefix}transmitter-issuer: The issuer of the SSF transmitter must be configured"
            ));
            return failures;
        };
        let policy = self.uri_policy();
        if let Err(e) = policy.check_issuer(issuer) {
            failures.push(format!("{prefix}transmitter-issuer: {e}"));
        }
        if let Some(url) = &self.transmitter_metadata_url
            && let Err(e) = policy.check_endpoint(url, "Transmitter metadata URL")
        {
            failures.push(format!("{prefix}transmitter-metadata-url: {e}"));
        }
        if let Some(url) = &self.transmitter_jwks_url
            && let Err(e) = policy.check_endpoint(url, "The JWK Set URL")
        {
            failures.push(format!("{prefix}transmitter-jwks-url: {e}"));
        }
        for algorithm in self.set_validation.effective_accepted_algorithms() {
            if supported_algorithm(&algorithm).is_none() {
                failures.push(format!(
                    "{prefix}set-validation.accepted-algorithms: Not an asymmetric signature algorithm: {algorithm}"
                ));
            }
        }
        if self.expected_audience.as_deref().is_none_or(|a| a.trim().is_empty())
            && !self.registers_stream()
            && !self.set_validation.allow_any_audience
        {
            failures.push(format!(
                "{prefix}expected-audience: The audience of the SETs must be known: set {prefix}expected-audience, or let the \
                 receiver look the stream up ({prefix}stream.management = \"receiver\" or {prefix}stream.id), or set \
                 {prefix}set-validation.allow-any-audience = true to accept SETs the transmitter issued for other receivers as well"
            ));
        }
        if self
            .transmitter_access_token
            .as_deref()
            .is_none_or(|t| t.trim().is_empty())
            && self.oauth2.token_uri.is_some()
            && (self.oauth2.client_id.as_deref().is_none_or(|c| c.trim().is_empty())
                || self.oauth2.client_secret.as_deref().is_none_or(|c| c.trim().is_empty()))
        {
            failures.push(format!(
                "{prefix}oauth2.client-id: {prefix}oauth2.client-id and {prefix}oauth2.client-secret are required to obtain \
                 access tokens from {prefix}oauth2.token-uri"
            ));
        }
        if self.stream.management == SsfStreamManagement::Receiver
            && self.delivery_method == SsfDeliveryMethodConfig::Push
            && self.push.delivery_endpoint_url.is_none()
        {
            failures.push(format!(
                "{prefix}push.delivery-endpoint-url: A stream managed by the receiver needs the URL under which the transmitter \
                 reaches the push endpoint of this application"
            ));
        }
        if self.delivery_method == SsfDeliveryMethodConfig::Poll {
            if self.poll.endpoint_url.is_none() && !self.registers_stream() {
                failures.push(format!(
                    "{prefix}poll.endpoint-url: POLL delivery needs the poll endpoint of the stream: set {prefix}poll.endpoint-url, \
                     {prefix}stream.id or {prefix}stream.management = \"receiver\""
                ));
            }
            let poll = &self.poll;
            if poll.interval.is_zero()
                || poll.max_events == 0
                || poll.rate_limit.max_backoff.is_zero()
                || (poll.long_polling && poll.long_polling_hold.is_zero())
            {
                failures.push(format!(
                    "{prefix}poll: interval, long-polling-hold and rate-limit.max-backoff must be positive, max-events at least 1"
                ));
            }
        }
        failures
    }
}

/// How the transmitter delivers SETs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SsfDeliveryMethodConfig {
    /// To the endpoint of this application (RFC 8935).
    #[default]
    Push,
    /// From an endpoint of the transmitter (RFC 8936).
    Poll,
}

/// OAuth2 client credentials to authenticate with at the transmitter.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SsfOAuth2Config {
    /// Token endpoint to obtain access tokens from with the client credentials grant.
    pub token_uri: Option<Url>,
    /// Client id of this receiver.
    pub client_id: Option<String>,
    /// Client secret of this receiver.
    pub client_secret: Option<String>,
    /// Scopes to request.
    pub scopes: Vec<String>,
    /// How the client authenticates at the token endpoint: `basic` (`client_secret_basic`) or
    /// `post` (`client_secret_post`).
    pub client_authentication_method: SsfClientAuthenticationMethod,
    /// How long before its expiry an access token is renewed; never more than a quarter of the
    /// token's lifetime.
    #[serde(with = "humantime_serde")]
    pub expiry_safety_window: Duration,
    /// Form parameters to send with the token request in addition to the grant.
    pub additional_parameters: BTreeMap<String, String>,
}

impl Default for SsfOAuth2Config {
    fn default() -> Self {
        Self {
            token_uri: None,
            client_id: None,
            client_secret: None,
            scopes: Vec::new(),
            client_authentication_method: SsfClientAuthenticationMethod::Basic,
            expiry_safety_window: Duration::from_secs(30),
            additional_parameters: BTreeMap::new(),
        }
    }
}

/// How the receiver authenticates at the token endpoint (RFC 6749, section 2.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SsfClientAuthenticationMethod {
    /// `client_secret_basic`: HTTP basic authentication.
    #[default]
    Basic,
    /// `client_secret_post`: the credentials in the request body.
    Post,
}

/// The event stream of this receiver at the transmitter.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "kebab-case", default)]
pub struct SsfStreamConfig {
    /// Who manages the stream: with `transmitter` the stream is created at the transmitter, with
    /// `receiver` this application looks its stream up on startup and creates or updates it if
    /// necessary.
    pub management: SsfStreamManagement,
    /// Identifier of a stream that was created at the transmitter. When set, the stream is looked
    /// up on startup to learn its audience and poll endpoint.
    pub id: Option<String>,
    /// Event types (alias or URI) requested for a stream managed by the receiver. Empty, the
    /// default, requests `CaepSessionRevoked` and `CaepCredentialChange`.
    pub events_requested: Vec<String>,
    /// Description of a stream managed by the receiver.
    pub description: Option<String>,
    /// Whether a stream managed by the receiver is deleted at the transmitter when the receiver
    /// stops.
    pub delete_on_shutdown: bool,
}

impl SsfStreamConfig {
    /// The event types requested when `events-requested` is left empty.
    pub const DEFAULT_EVENTS_REQUESTED: [&'static str; 2] = ["CaepSessionRevoked", "CaepCredentialChange"];

    /// The event types a stream managed by the receiver requests: the configured ones, or the
    /// defaults if none are configured.
    pub fn effective_events_requested(&self) -> Vec<String> {
        if self.events_requested.is_empty() {
            Self::DEFAULT_EVENTS_REQUESTED.iter().map(|e| (*e).to_owned()).collect()
        } else {
            self.events_requested.clone()
        }
    }
}

/// Who manages the stream of the receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SsfStreamManagement {
    /// The stream is created at the transmitter, by an administrator or the transmitter itself.
    #[default]
    Transmitter,
    /// The receiver looks its stream up on startup and creates or updates it if necessary.
    Receiver,
}

/// POLL delivery (RFC 8936).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SsfPollConfig {
    /// Poll endpoint of the transmitter. Taken from the stream configuration when not set.
    pub endpoint_url: Option<Url>,
    /// Whether the transmitter is polled periodically. Otherwise the application polls by calling
    /// `SsfPoller::poll_now()`.
    pub auto_startup: bool,
    /// Time between two polls.
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// Time to wait before the first poll.
    #[serde(with = "humantime_serde")]
    pub initial_delay: Duration,
    /// Maximum number of SETs to fetch with one request.
    pub max_events: usize,
    /// Whether to long poll: the transmitter holds a request until SETs are available, and the
    /// next request goes out as soon as a response was handled. Otherwise the transmitter is
    /// asked to answer at once and polled every `interval`.
    pub long_polling: bool,
    /// How long the transmitter holds a long poll request, part of the agreement with it. The
    /// request waits that long plus a margin for the response.
    #[serde(with = "humantime_serde")]
    pub long_polling_hold: Duration,
    /// How the poller reacts when the transmitter rate-limits the poll endpoint.
    pub rate_limit: SsfRateLimitConfig,
}

impl Default for SsfPollConfig {
    fn default() -> Self {
        Self {
            endpoint_url: None,
            auto_startup: true,
            interval: Duration::from_secs(30),
            initial_delay: Duration::from_secs(1),
            max_events: 100,
            long_polling: false,
            long_polling_hold: Duration::from_secs(30),
            rate_limit: SsfRateLimitConfig::default(),
        }
    }
}

/// How the poller reacts when the transmitter rate-limits the poll endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SsfRateLimitConfig {
    /// Pause after a `429 Too Many Requests` without a `Retry-After` header. Not set: poll again
    /// at the regular interval.
    #[serde(with = "humantime_serde")]
    pub fallback_backoff: Option<Duration>,
    /// Longest pause a `Retry-After` header or the fallback can cause.
    #[serde(with = "humantime_serde")]
    pub max_backoff: Duration,
}

impl Default for SsfRateLimitConfig {
    fn default() -> Self {
        Self {
            fallback_backoff: None,
            max_backoff: Duration::from_secs(300),
        }
    }
}

/// How SETs are validated.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SsfSetValidationConfig {
    /// JWS algorithms accepted for SET signatures. Empty, the default, accepts `RS256`, as
    /// required by the CAEP interoperability profile.
    pub accepted_algorithms: Vec<String>,
    /// Minimum RSA key size in bits for SET signing keys. `0` disables the check.
    pub min_rsa_key_size: usize,
    /// Whether the SET must be explicitly typed with a `typ` header of `secevent+jwt`.
    pub require_type_header: bool,
    /// How strictly the subject of a SET is validated: `strict` requires the top-level `sub_id`
    /// claim of SSF 1.0, `legacy` accepts SETs of transmitters following earlier drafts, which
    /// put the subject into the event payload.
    pub subject_compatibility: SsfSubjectCompatibility,
    /// Tolerated clock skew when checking that a SET was not issued in the future.
    #[serde(with = "humantime_serde")]
    pub clock_skew: Duration,
    /// Accepts SETs whatever audience they carry when neither `expected-audience` is set nor a
    /// stream is registered or looked up that tells the audience. Off by default: a receiver
    /// without a known audience fails to start, because it would accept SETs the transmitter
    /// issued for other receivers. Only for a transmitter that sends no `aud`.
    pub allow_any_audience: bool,
}

impl Default for SsfSetValidationConfig {
    fn default() -> Self {
        Self {
            accepted_algorithms: Vec::new(),
            min_rsa_key_size: 2048,
            require_type_header: true,
            subject_compatibility: SsfSubjectCompatibility::Strict,
            clock_skew: Duration::from_secs(60),
            allow_any_audience: false,
        }
    }
}

impl SsfSetValidationConfig {
    /// The algorithms accepted when `accepted-algorithms` is left empty.
    pub const DEFAULT_ACCEPTED_ALGORITHMS: [&'static str; 1] = ["RS256"];

    /// The algorithms accepted: the configured ones, or the default if none are configured.
    pub fn effective_accepted_algorithms(&self) -> Vec<String> {
        if self.accepted_algorithms.is_empty() {
            Self::DEFAULT_ACCEPTED_ALGORITHMS
                .iter()
                .map(|a| (*a).to_owned())
                .collect()
        } else {
            self.accepted_algorithms.iter().map(|a| a.trim().to_owned()).collect()
        }
    }

    /// The subject compatibility mode.
    pub fn subject_compatibility_mode(&self) -> SubjectCompatibilityMode {
        match self.subject_compatibility {
            SsfSubjectCompatibility::Strict => SubjectCompatibilityMode::Strict,
            SsfSubjectCompatibility::Legacy => SubjectCompatibilityMode::Legacy,
        }
    }
}

/// Which convention for the subject of a SET the transmitter follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SsfSubjectCompatibility {
    /// SSF 1.0: the top-level `sub_id` claim is required.
    #[default]
    Strict,
    /// Earlier drafts: the subject may sit in the event payload.
    Legacy,
}

/// PUSH delivery (RFC 8935).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SsfPushConfig {
    /// Exact value the transmitter must send in the `Authorization` header, for example
    /// `Bearer s3cr3t`. No header check is performed when not set.
    pub expected_auth_header: Option<String>,
    /// URL under which the transmitter reaches the push endpoint. Required for a stream managed by
    /// the receiver.
    pub delivery_endpoint_url: Option<Url>,
    /// Path of the push endpoint of this application, `/ssf/push` by default. Shared by all
    /// transmitters, read from `easyssf.receiver.push` only.
    pub endpoint_path: String,
}

impl Default for SsfPushConfig {
    fn default() -> Self {
        Self {
            expected_auth_header: None,
            delivery_endpoint_url: None,
            endpoint_path: "/ssf/push".to_owned(),
        }
    }
}

/// Outbound HTTP calls to the transmitter.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SsfHttpConfig {
    /// Timeout for calls to the transmitter, 5 seconds by default. A long poll waits for its hold
    /// time plus a margin regardless.
    #[serde(with = "humantime_serde")]
    pub timeout: Duration,
    /// `User-Agent` header for calls to the transmitter. None is sent when not set.
    pub user_agent: Option<String>,
}

impl Default for SsfHttpConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            user_agent: None,
        }
    }
}

/// Metrics of the receiver.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SsfMetricsConfig {
    /// Whether received SETs and polls are recorded with the `metrics` facade (feature
    /// `metrics`).
    pub enabled: bool,
}

impl Default for SsfMetricsConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// De-duplication of SETs by `jti`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SsfDedupConfig {
    /// Whether SETs that were already processed are skipped.
    pub enabled: bool,
    /// Number of SET identifiers the in-memory store remembers.
    pub capacity: usize,
    /// How long a durable store remembers a processed SET. Has to cover the time the transmitter
    /// keeps trying to deliver a SET.
    #[serde(with = "humantime_serde")]
    pub retention: Duration,
    /// How long a SET counts as being handled by the instance that claimed it without renewing
    /// the claim, which it does every third of this time while its handlers run. Another instance
    /// that receives the SET in that time leaves it for a redelivery; after it, the claim counts
    /// as abandoned by a crashed instance and the SET is handled again.
    #[serde(with = "humantime_serde")]
    pub lease: Duration,
}

impl Default for SsfDedupConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            capacity: 10_000,
            retention: Duration::from_secs(7 * 24 * 60 * 60),
            lease: Duration::from_secs(60),
        }
    }
}

/// Revocation of access tokens and sessions by security events: the `SsfTokenRevocationStore`
/// and the handler that fills it. The web framework crates consult the store.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SsfRevocationConfig {
    /// Whether revocations are recorded and tokens of revoked sessions and subjects rejected.
    pub enabled: bool,
    /// Event types (alias or URI) that revoke the session they name, or all tokens of the user
    /// issued up to the event if they name none. Empty, the default, means `CaepSessionRevoked`.
    pub session_event_types: Vec<String>,
    /// Event types (alias or URI) that revoke all tokens of the user they name, issued up to the
    /// event, whether or not the event names a session; for example `CaepCredentialChange` for
    /// an application whose sessions are cookies. None by default.
    pub user_event_types: Vec<String>,
    /// How long a revocation is remembered. Must be at least the maximum lifetime of the access
    /// tokens and sessions it guards, or a revoked token becomes usable again when the revocation
    /// is forgotten. 24 hours by default.
    #[serde(with = "humantime_serde")]
    pub ttl: Duration,
}

impl Default for SsfRevocationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            session_event_types: Vec::new(),
            user_event_types: Vec::new(),
            ttl: Duration::from_secs(24 * 60 * 60),
        }
    }
}

impl SsfRevocationConfig {
    /// The session event types: the configured ones, or `CaepSessionRevoked`.
    pub fn effective_session_event_types(&self) -> Vec<String> {
        if self.session_event_types.is_empty() {
            vec!["CaepSessionRevoked".to_owned()]
        } else {
            self.session_event_types.clone()
        }
    }
}

/// Termination of server-side sessions by security events, through the `SsfSessionTerminator`
/// the application gives the receiver. Without one, nothing is terminated.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SsfSessionTerminationConfig {
    /// Whether local sessions are terminated when a matching event is received and a session
    /// terminator is given.
    pub enabled: bool,
    /// Event types (alias or URI) that terminate the sessions identified by the event's subject
    /// (session id and / or user). Empty, the default, means `CaepSessionRevoked`.
    pub session_event_types: Vec<String>,
    /// Event types (alias or URI) that terminate all sessions of the user identified by the
    /// event's subject. Empty, the default, means `CaepCredentialChange`.
    pub user_event_types: Vec<String>,
    /// Attributes of the `scim` subject of a SCIM Event (RFC 9967) and the claim of the logged-in
    /// user each is compared with, e.g. `externalId = "sub"`. Empty, the default, means
    /// `externalId` and `id` with `sub`, `userName` with `preferred_username`.
    pub scim_attribute_claims: BTreeMap<String, String>,
}

impl Default for SsfSessionTerminationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            session_event_types: Vec::new(),
            user_event_types: Vec::new(),
            scim_attribute_claims: BTreeMap::new(),
        }
    }
}

impl SsfSessionTerminationConfig {
    /// The session event types: the configured ones, or `CaepSessionRevoked`.
    pub fn effective_session_event_types(&self) -> Vec<String> {
        if self.session_event_types.is_empty() {
            vec!["CaepSessionRevoked".to_owned()]
        } else {
            self.session_event_types.clone()
        }
    }

    /// The user event types: the configured ones, or `CaepCredentialChange`.
    pub fn effective_user_event_types(&self) -> Vec<String> {
        if self.user_event_types.is_empty() {
            vec!["CaepCredentialChange".to_owned()]
        } else {
            self.user_event_types.clone()
        }
    }

    /// The attribute-claim pairs a `scim` subject is matched by: the configured ones, or the
    /// defaults of `subject_claims_matcher` if none are configured.
    pub fn effective_scim_attribute_claims(&self) -> Vec<(String, String)> {
        if self.scim_attribute_claims.is_empty() {
            crate::session::subject_claims_matcher::DEFAULT_SCIM_ATTRIBUTE_CLAIMS
                .iter()
                .map(|(a, c)| ((*a).to_owned(), (*c).to_owned()))
                .collect()
        } else {
            self.scim_attribute_claims
                .iter()
                .map(|(a, c)| (a.clone(), c.clone()))
                .collect()
        }
    }
}

/// The database stores of `easyssf-receiver-sqlx`, which keep processed SETs, revocations and
/// the acknowledgements a poller owes in the database of the application, shared by all its
/// instances.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case", default)]
pub struct SsfDataConfig {
    /// Whether the database stores are used. `false` keeps the state of the receiver in memory
    /// although the stores were added, for example in a test environment.
    pub enabled: bool,
    /// When to create the tables if they do not exist: for embedded databases (SQLite) only, which
    /// is the default, always, or never.
    pub initialize_schema: SsfSchemaInitialization,
    /// Prefix of the names of the tables, `EASYSSF_` by default. Letters, digits, `_` and `.`
    /// (for a schema) only.
    pub table_prefix: String,
    /// How often expired rows are purged. The stores also purge when they are written to; zero
    /// turns the periodic cleanup off. 15 minutes by default.
    #[serde(with = "humantime_serde")]
    pub cleanup_interval: Duration,
    /// How long the store keeps an acknowledgement a polling receiver owes its transmitter if no
    /// poll request manages to deliver it. 7 days by default.
    #[serde(with = "humantime_serde")]
    pub ack_retention: Duration,
    /// How many acknowledgements one DELETE of the store removes at once; databases limit the
    /// parameters of a statement. 100 by default.
    pub ack_delete_batch_size: usize,
}

impl Default for SsfDataConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            initialize_schema: SsfSchemaInitialization::Embedded,
            table_prefix: "EASYSSF_".to_owned(),
            cleanup_interval: Duration::from_secs(15 * 60),
            ack_retention: Duration::from_secs(7 * 24 * 60 * 60),
            ack_delete_batch_size: 100,
        }
    }
}

/// When the database stores create their tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum SsfSchemaInitialization {
    /// Only in an embedded database (SQLite), which has no migration tool of its own.
    #[default]
    Embedded,
    /// Whenever a table is missing, and add the columns of this release to a table of an older
    /// one.
    Always,
    /// Never: the application creates the tables, with the SQL that ships with the stores. A
    /// missing or outdated table fails the start with the statements to run.
    Never,
}
