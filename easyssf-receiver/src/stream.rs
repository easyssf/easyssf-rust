//! Stream management (SSF 1.0, section 8.1): the client, the stream of the receiver, its
//! registration and the verification events.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use easyssf_core::metadata::SsfTransmitterMetadata;
use easyssf_core::stream::{SsfStreamConfiguration, SsfStreamStatus};
use easyssf_core::{SsfDeliveryMethod, event_types};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::BoxError;
use crate::event::SsfEventContext;
use crate::http::{SsfHttpClient, SsfHttpRequest, SsfHttpResponse};
use crate::set::{SsfErrorCode, SsfSetVerificationError};
use crate::transmitter::{SsfTransmitterMetadataResolver, SsfTransmitterTokenProvider};

/// A call to the stream management API of the transmitter failed.
#[derive(Debug, thiserror::Error)]
pub enum SsfStreamError {
    /// The transmitter could not be called or answered with an error status.
    #[error("{message}")]
    Call {
        /// What failed.
        message: String,
        /// The HTTP status the transmitter answered with, `0` if it did not answer.
        status: u16,
        /// The cause, if any.
        #[source]
        source: Option<BoxError>,
    },
    /// The transmitter created a stream whose issuer is not the issuer the transmitter metadata
    /// was obtained from (SSF 1.0, section 8.1.1.1). Such a stream must not be used.
    #[error("The transmitter created stream {} with the issuer '{}' instead of '{expected_issuer}'", stream.stream_id().unwrap_or(""), stream.issuer().unwrap_or(""))]
    IssuerMismatch {
        /// The issuer of the transmitter.
        expected_issuer: String,
        /// The stream the transmitter created, for example to delete it.
        stream: SsfStreamConfiguration,
    },
}

impl SsfStreamError {
    fn call(message: impl Into<String>, status: u16, source: Option<BoxError>) -> Self {
        Self::Call {
            message: message.into(),
            status,
            source,
        }
    }

    /// The HTTP status the transmitter answered with, `0` if it did not answer.
    pub fn status(&self) -> u16 {
        match self {
            Self::Call { status, .. } => *status,
            Self::IssuerMismatch { .. } => 0,
        }
    }
}

/// Client for the stream management API of the transmitter (SSF 1.0, section 8.1). The
/// endpoints are discovered from the transmitter metadata.
pub struct SsfStreamClient {
    http: Arc<dyn SsfHttpClient>,
    token_provider: Arc<dyn SsfTransmitterTokenProvider>,
    metadata_resolver: Arc<SsfTransmitterMetadataResolver>,
}

impl SsfStreamClient {
    /// A client that calls the transmitter with `http`, authenticates with the tokens of
    /// `token_provider` and finds the endpoints with `metadata_resolver`.
    pub fn new(
        http: impl SsfHttpClient,
        token_provider: impl SsfTransmitterTokenProvider,
        metadata_resolver: Arc<SsfTransmitterMetadataResolver>,
    ) -> Self {
        Self {
            http: Arc::new(http),
            token_provider: Arc::new(token_provider),
            metadata_resolver,
        }
    }

    /// The streams of this receiver.
    pub async fn streams(&self) -> Result<Vec<SsfStreamConfiguration>, SsfStreamError> {
        let body = self.exchange("GET", self.configuration_endpoint().await?, None).await?;
        if body.trim().is_empty() {
            return Ok(Vec::new());
        }
        let parsed: Value = serde_json::from_str(&body).map_err(|e| {
            SsfStreamError::call("The transmitter returned an invalid list of streams", 0, Some(e.into()))
        })?;
        Ok(match parsed {
            Value::Array(streams) => streams
                .into_iter()
                .filter_map(|stream| match stream {
                    Value::Object(claims) => Some(SsfStreamConfiguration::new(claims)),
                    _ => None,
                })
                .collect(),
            Value::Object(claims) => vec![SsfStreamConfiguration::new(claims)],
            _ => {
                return Err(SsfStreamError::call(
                    "The transmitter returned an invalid list of streams",
                    0,
                    None,
                ));
            }
        })
    }

    /// The stream with the given identifier.
    pub async fn stream(&self, stream_id: &str) -> Result<SsfStreamConfiguration, SsfStreamError> {
        let body = self
            .exchange(
                "GET",
                with_stream_id_query(self.configuration_endpoint().await?, stream_id),
                None,
            )
            .await?;
        Ok(SsfStreamConfiguration::new(parse(&body)?))
    }

    /// Creates a stream, see [`SsfStreamConfiguration::push`] and [`SsfStreamConfiguration::poll`].
    ///
    /// # Errors
    ///
    /// [`SsfStreamError::IssuerMismatch`] if the transmitter created the stream with another
    /// issuer than its own; the stream must not be used then.
    pub async fn create_stream(
        &self,
        stream: &SsfStreamConfiguration,
    ) -> Result<SsfStreamConfiguration, SsfStreamError> {
        let body = self
            .exchange("POST", self.configuration_endpoint().await?, Some(stream.claims()))
            .await?;
        let created = SsfStreamConfiguration::new(parse(&body)?);
        let issuer = self.metadata().await?.issuer().to_owned();
        if created.issuer() != Some(issuer.as_str()) {
            return Err(SsfStreamError::IssuerMismatch {
                expected_issuer: issuer,
                stream: created,
            });
        }
        Ok(created)
    }

    /// Updates the given members of a stream, the others are left as they are.
    pub async fn update_stream(
        &self,
        stream_id: &str,
        changes: &Map<String, Value>,
    ) -> Result<SsfStreamConfiguration, SsfStreamError> {
        let body = self
            .exchange(
                "PATCH",
                self.configuration_endpoint().await?,
                Some(&with_stream_id(changes, stream_id)),
            )
            .await?;
        Ok(SsfStreamConfiguration::new(parse(&body)?))
    }

    /// Replaces the configuration of a stream.
    pub async fn replace_stream(
        &self,
        stream_id: &str,
        stream: &SsfStreamConfiguration,
    ) -> Result<SsfStreamConfiguration, SsfStreamError> {
        let body = self
            .exchange(
                "PUT",
                self.configuration_endpoint().await?,
                Some(&with_stream_id(stream.claims(), stream_id)),
            )
            .await?;
        Ok(SsfStreamConfiguration::new(parse(&body)?))
    }

    /// Deletes a stream.
    pub async fn delete_stream(&self, stream_id: &str) -> Result<(), SsfStreamError> {
        self.exchange(
            "DELETE",
            with_stream_id_query(self.configuration_endpoint().await?, stream_id),
            None,
        )
        .await?;
        Ok(())
    }

    /// The status of a stream.
    pub async fn status(&self, stream_id: &str) -> Result<SsfStreamStatus, SsfStreamError> {
        let body = self
            .exchange(
                "GET",
                with_stream_id_query(self.status_endpoint().await?, stream_id),
                None,
            )
            .await?;
        Ok(to_status(&parse(&body)?))
    }

    /// Enables, pauses or disables a stream: `status` is one of [`SsfStreamStatus::ENABLED`],
    /// [`SsfStreamStatus::PAUSED`] and [`SsfStreamStatus::DISABLED`].
    pub async fn update_status(
        &self,
        stream_id: &str,
        status: &str,
        reason: Option<&str>,
    ) -> Result<SsfStreamStatus, SsfStreamError> {
        let mut body = Map::new();
        body.insert("status".to_owned(), Value::String(status.to_owned()));
        if let Some(reason) = reason {
            body.insert("reason".to_owned(), Value::String(reason.to_owned()));
        }
        let response = self
            .exchange(
                "POST",
                self.status_endpoint().await?,
                Some(&with_stream_id(&body, stream_id)),
            )
            .await?;
        Ok(to_status(&parse(&response)?))
    }

    /// Asks the transmitter to send events about the given subject (a subject identifier, see
    /// [`easyssf_core::event::subjects`]); `verified` tells whether the receiver has verified the
    /// subject.
    pub async fn add_subject(
        &self,
        stream_id: &str,
        subject: &Map<String, Value>,
        verified: bool,
    ) -> Result<(), SsfStreamError> {
        let mut body = Map::new();
        body.insert("subject".to_owned(), Value::Object(subject.clone()));
        body.insert("verified".to_owned(), Value::Bool(verified));
        let endpoint = self
            .endpoint(|m| m.add_subject_endpoint(), "add_subject_endpoint")
            .await?;
        self.exchange("POST", endpoint, Some(&with_stream_id(&body, stream_id)))
            .await?;
        Ok(())
    }

    /// Asks the transmitter to no longer send events about the given subject.
    pub async fn remove_subject(&self, stream_id: &str, subject: &Map<String, Value>) -> Result<(), SsfStreamError> {
        let mut body = Map::new();
        body.insert("subject".to_owned(), Value::Object(subject.clone()));
        let endpoint = self
            .endpoint(|m| m.remove_subject_endpoint(), "remove_subject_endpoint")
            .await?;
        self.exchange("POST", endpoint, Some(&with_stream_id(&body, stream_id)))
            .await?;
        Ok(())
    }

    /// Asks the transmitter to send a verification event on the stream; `state` is echoed in the
    /// verification event.
    pub async fn request_verification(&self, stream_id: &str, state: Option<&str>) -> Result<(), SsfStreamError> {
        let mut body = Map::new();
        if let Some(state) = state {
            body.insert("state".to_owned(), Value::String(state.to_owned()));
        }
        let endpoint = self
            .endpoint(|m| m.verification_endpoint(), "verification_endpoint")
            .await?;
        self.exchange("POST", endpoint, Some(&with_stream_id(&body, stream_id)))
            .await?;
        Ok(())
    }

    async fn metadata(&self) -> Result<Arc<SsfTransmitterMetadata>, SsfStreamError> {
        self.metadata_resolver
            .resolve()
            .await
            .map_err(|e| SsfStreamError::call(e.message().to_owned(), 0, Some(e.into())))
    }

    async fn configuration_endpoint(&self) -> Result<Url, SsfStreamError> {
        self.endpoint(|m| m.configuration_endpoint(), "configuration_endpoint")
            .await
    }

    async fn status_endpoint(&self) -> Result<Url, SsfStreamError> {
        self.endpoint(|m| m.status_endpoint(), "status_endpoint").await
    }

    async fn endpoint(
        &self,
        endpoint: impl Fn(&SsfTransmitterMetadata) -> Option<Url>,
        name: &str,
    ) -> Result<Url, SsfStreamError> {
        let metadata = self.metadata().await?;
        endpoint(&metadata)
            .ok_or_else(|| SsfStreamError::call(format!("The SSF transmitter metadata has no {name}"), 0, None))
    }

    async fn exchange(
        &self,
        method: &str,
        url: Url,
        body: Option<&Map<String, Value>>,
    ) -> Result<String, SsfStreamError> {
        let failed = |e: BoxError| SsfStreamError::call(format!("{method} {url} failed: {e}"), 0, Some(e));
        let mut response = self.send(method, &url, body).await.map_err(failed)?;
        if response.status == 401 {
            // the access token expired or was revoked: try once more with a new one
            self.token_provider.invalidate().await;
            response = self.send(method, &url, body).await.map_err(failed)?;
        }
        if !response.is_successful() {
            return Err(SsfStreamError::call(
                format!(
                    "{method} {url} failed with status {}: {}",
                    response.status, response.body
                ),
                response.status,
                None,
            ));
        }
        Ok(response.body)
    }

    async fn send(
        &self,
        method: &str,
        url: &Url,
        body: Option<&Map<String, Value>>,
    ) -> Result<SsfHttpResponse, BoxError> {
        let token = self.token_provider.access_token().await?;
        let mut request = SsfHttpRequest::of(method, url.clone())
            .with_header("Accept", "application/json")
            .with_bearer_token(token.as_deref());
        if let Some(body) = body {
            request = request.with_json_body(Value::Object(body.clone()).to_string());
        }
        self.http.execute(request).await
    }
}

fn parse(body: &str) -> Result<Map<String, Value>, SsfStreamError> {
    match serde_json::from_str::<Value>(body) {
        Ok(Value::Object(claims)) => Ok(claims),
        Ok(_) => Err(SsfStreamError::call(
            "The transmitter returned an invalid response",
            0,
            None,
        )),
        Err(e) => Err(SsfStreamError::call(
            "The transmitter returned an invalid response",
            0,
            Some(e.into()),
        )),
    }
}

fn to_status(claims: &Map<String, Value>) -> SsfStreamStatus {
    SsfStreamStatus {
        stream_id: claims.get("stream_id").and_then(Value::as_str).unwrap_or("").to_owned(),
        status: claims.get("status").and_then(Value::as_str).unwrap_or("").to_owned(),
        reason: claims.get("reason").and_then(Value::as_str).map(str::to_owned),
    }
}

fn with_stream_id_query(mut endpoint: Url, stream_id: &str) -> Url {
    endpoint.query_pairs_mut().append_pair("stream_id", stream_id);
    endpoint
}

fn with_stream_id(body: &Map<String, Value>, stream_id: &str) -> Map<String, Value> {
    let mut with_id = Map::new();
    with_id.insert("stream_id".to_owned(), Value::String(stream_id.to_owned()));
    for (name, value) in body {
        with_id.insert(name.clone(), value.clone());
    }
    with_id
}

/// Holds the configuration of the stream this receiver gets its events from, once it is known:
/// after the [`SsfStreamRegistrar`] has registered or looked up the stream at the transmitter.
#[derive(Debug, Default)]
pub struct SsfReceiverStream {
    configuration: RwLock<Option<Arc<SsfStreamConfiguration>>>,
}

impl SsfReceiverStream {
    /// A stream that is not known yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The configuration of the stream, `None` as long as it is not known.
    pub fn configuration(&self) -> Option<Arc<SsfStreamConfiguration>> {
        self.configuration.read().unwrap().clone()
    }

    /// Sets the configuration once the stream is known.
    pub fn set_configuration(&self, configuration: SsfStreamConfiguration) {
        *self.configuration.write().unwrap() = Some(Arc::new(configuration));
    }

    /// The identifier of the stream, `None` as long as it is not known.
    pub fn stream_id(&self) -> Option<String> {
        self.configuration().and_then(|c| c.stream_id().map(str::to_owned))
    }

    /// The audiences of the SETs of the stream, empty as long as they are not known.
    pub fn audience(&self) -> Vec<String> {
        self.configuration().map(|c| c.audience()).unwrap_or_default()
    }
}

/// Validates stream verification events (SSF 1.0, section 8.1.4.1) and keeps track of the
/// verifications this receiver requested.
///
/// A verification event has to be about the stream of the receiver: its `sub_id` is an `opaque`
/// identifier with the identifier of the stream. If it echoes a `state`, that has to be a state
/// the receiver sent with a verification request that was not answered yet. An event without
/// `state` was initiated by the transmitter and is accepted.
pub struct SsfStreamVerification {
    pending_states: Mutex<HashSet<String>>,
    stream_id: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    reject_unrequested_state: bool,
}

impl Default for SsfStreamVerification {
    fn default() -> Self {
        Self::new()
    }
}

impl SsfStreamVerification {
    /// A verification that does not know the stream yet, see
    /// [`with_stream_id`](Self::with_stream_id).
    pub fn new() -> Self {
        Self {
            pending_states: Mutex::new(HashSet::new()),
            stream_id: Arc::new(|| None),
            reject_unrequested_state: false,
        }
    }

    /// Sets what tells the identifier of the stream of this receiver, `None` as long as it is not
    /// known. The subject of verification events is not checked while it is unknown.
    pub fn with_stream_id(mut self, stream_id: impl Fn() -> Option<String> + Send + Sync + 'static) -> Self {
        self.stream_id = Arc::new(stream_id);
        self
    }

    /// Whether a verification event with a `state` is rejected when the receiver is not waiting
    /// for the answer to a verification request. By default such an event is accepted, since some
    /// transmitters add a state to the verification events they initiate themselves.
    pub fn with_reject_unrequested_state(mut self, reject: bool) -> Self {
        self.reject_unrequested_state = reject;
        self
    }

    /// Creates a state for a verification request and remembers it until the verification event
    /// that echoes it arrived.
    pub fn new_state(&self) -> String {
        let state = uuid::Uuid::new_v4().to_string();
        self.pending_states.lock().unwrap().insert(state.clone());
        state
    }

    /// Asks the transmitter to send a verification event on the stream; returns the state the
    /// verification event has to echo.
    pub async fn request_verification(
        &self,
        client: &SsfStreamClient,
        stream_id: &str,
    ) -> Result<String, SsfStreamError> {
        let state = self.new_state();
        if let Err(error) = client.request_verification(stream_id, Some(&state)).await {
            self.pending_states.lock().unwrap().remove(&state);
            return Err(error);
        }
        Ok(state)
    }

    /// Whether a verification request was sent that has not been answered yet.
    pub fn is_pending(&self) -> bool {
        !self.pending_states.lock().unwrap().is_empty()
    }

    /// Validates the verification event of a SET, if it has one.
    ///
    /// # Errors
    ///
    /// If the event is about another stream (`invalid_request`) or echoes a state that is not
    /// expected (`invalid_state`).
    pub fn validate(&self, context: &SsfEventContext) -> Result<(), SsfSetVerificationError> {
        if !context.has_event(event_types::SSF_STREAM_VERIFICATION) {
            return Ok(());
        }
        if let Some(expected_stream_id) = (self.stream_id)() {
            // SSF 1.0 8.1.4.1: the sub_id of a verification event is opaque and names the stream
            let subject_id = context.event_token().subject_id();
            let about_stream = subject_id.is_some_and(|subject_id| {
                subject_id.get("format").and_then(Value::as_str) == Some("opaque")
                    && subject_id.get("id").and_then(Value::as_str) == Some(expected_stream_id.as_str())
            });
            if !about_stream {
                return Err(SsfSetVerificationError::rejected(
                    SsfErrorCode::InvalidRequest,
                    "The verification event is not about the stream of this receiver",
                ));
            }
        }
        let state = context
            .event_for(event_types::SSF_STREAM_VERIFICATION)
            .and_then(|event| event.get("state"))
            .filter(|state| !state.is_null())
            .map(|state| match state {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            });
        let Some(state) = state else {
            return Ok(());
        };
        let mut pending = self.pending_states.lock().unwrap();
        if pending.remove(&state) {
            return Ok(());
        }
        if !pending.is_empty() || self.reject_unrequested_state {
            return Err(SsfSetVerificationError::rejected(
                SsfErrorCode::InvalidState,
                "The state of the verification event is not the one this receiver sent",
            ));
        }
        tracing::debug!("Accepting a verification event with a state although no verification was requested");
        Ok(())
    }
}

/// Where the registration of an [`SsfStreamRegistrar`] stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsfStreamRegistrarState {
    /// [`SsfStreamRegistrar::start`] was not called yet.
    NotStarted,
    /// The stream is being looked up or registered, with retries while the transmitter cannot be
    /// reached.
    Registering,
    /// The stream is known and matches what the receiver wants.
    Registered,
    /// The stream cannot be used, see [`SsfStreamRegistrar::last_error`]. Not retried.
    Failed,
}

impl SsfStreamRegistrarState {
    /// The lowercase name: `not_started`, `registering`, `registered`, `failed`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Registering => "registering",
            Self::Registered => "registered",
            Self::Failed => "failed",
        }
    }
}

/// Told when the stream was looked up or registered.
pub type SsfStreamRegistrarListener = Arc<dyn Fn(&SsfStreamConfiguration) + Send + Sync>;

enum RegistrarMode {
    Existing(String),
    Managed(SsfStreamConfiguration),
}

struct RegistrarTask {
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

/// Makes the stream of this receiver known after [`start`](Self::start), without holding the
/// startup of the application up: the transmitter is called in the background and retried until
/// it answers.
///
/// Either looks up a stream that was created at the transmitter by its identifier, or manages
/// the stream itself: it reuses the stream the receiver already has at the transmitter, brings
/// it in line with the desired configuration, or creates it.
///
/// [Listeners](Self::add_listener) learn when the stream is registered; `SsfTransmitter` uses
/// that to have the poller fetch right away instead of an interval later.
pub struct SsfStreamRegistrar {
    client: Arc<SsfStreamClient>,
    receiver_stream: Arc<SsfReceiverStream>,
    mode: RegistrarMode,
    delete_on_shutdown: bool,
    initial_retry_delay: Duration,
    state: Mutex<SsfStreamRegistrarState>,
    last_error: Mutex<Option<String>>,
    listeners: Mutex<Vec<SsfStreamRegistrarListener>>,
    task: Mutex<Option<RegistrarTask>>,
}

impl SsfStreamRegistrar {
    const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

    /// Looks up the stream with the given identifier.
    pub fn for_existing_stream(
        client: Arc<SsfStreamClient>,
        receiver_stream: Arc<SsfReceiverStream>,
        stream_id: &str,
    ) -> Arc<Self> {
        Self::create(client, receiver_stream, RegistrarMode::Existing(stream_id.to_owned()))
    }

    /// Discovers, updates or creates the stream of the receiver, see
    /// [`SsfStreamConfiguration::push`] and [`SsfStreamConfiguration::poll`].
    pub fn for_managed_stream(
        client: Arc<SsfStreamClient>,
        receiver_stream: Arc<SsfReceiverStream>,
        desired_stream: SsfStreamConfiguration,
    ) -> Arc<Self> {
        Self::create(client, receiver_stream, RegistrarMode::Managed(desired_stream))
    }

    fn create(client: Arc<SsfStreamClient>, receiver_stream: Arc<SsfReceiverStream>, mode: RegistrarMode) -> Arc<Self> {
        Arc::new(Self {
            client,
            receiver_stream,
            mode,
            delete_on_shutdown: false,
            initial_retry_delay: Duration::from_secs(1),
            state: Mutex::new(SsfStreamRegistrarState::NotStarted),
            last_error: Mutex::new(None),
            listeners: Mutex::new(Vec::new()),
            task: Mutex::new(None),
        })
    }

    /// Whether a stream this receiver manages is deleted at the transmitter when the receiver
    /// stops.
    pub fn with_delete_on_shutdown(self: Arc<Self>, delete: bool) -> Arc<Self> {
        let mut registrar = Arc::try_unwrap(self).unwrap_or_else(|_| panic!("the registrar is shared already"));
        registrar.delete_on_shutdown = delete;
        Arc::new(registrar)
    }

    /// The delay before the first retry, doubled up to 30 seconds; one second by default.
    pub fn with_initial_retry_delay(self: Arc<Self>, delay: Duration) -> Arc<Self> {
        assert!(!delay.is_zero(), "initial_retry_delay must be positive");
        let mut registrar = Arc::try_unwrap(self).unwrap_or_else(|_| panic!("the registrar is shared already"));
        registrar.initial_retry_delay = delay;
        Arc::new(registrar)
    }

    /// Adds a listener that is told whenever [`register`](Self::register) succeeded, on the task
    /// that registered the stream.
    pub fn add_listener(&self, listener: impl Fn(&SsfStreamConfiguration) + Send + Sync + 'static) {
        self.listeners.lock().unwrap().push(Arc::new(listener));
    }

    /// Starts looking up or registering the stream in the background. Needs a tokio runtime.
    /// Calling it again while running has no effect.
    pub fn start(self: &Arc<Self>) {
        let mut task = self.task.lock().unwrap();
        if task.is_some() {
            return;
        }
        *self.state.lock().unwrap() = SsfStreamRegistrarState::Registering;
        let cancel = CancellationToken::new();
        let registrar = self.clone();
        let token = cancel.clone();
        let handle = tokio::spawn(async move {
            tokio::select! {
                _ = registrar.register_with_retries() => {}
                _ = token.cancelled() => {}
            }
        });
        *task = Some(RegistrarTask { cancel, handle });
    }

    /// Where the registration stands.
    pub fn state(&self) -> SsfStreamRegistrarState {
        *self.state.lock().unwrap()
    }

    /// Why the last attempt to look up or register the stream failed, `None` if it succeeded or
    /// none was made yet.
    pub fn last_error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }

    /// Whether the background registration runs.
    pub fn is_running(&self) -> bool {
        self.task.lock().unwrap().is_some()
    }

    /// Stops the background registration and deletes the stream if asked to, see
    /// [`with_delete_on_shutdown`](Self::with_delete_on_shutdown).
    pub async fn stop(&self) {
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            task.cancel.cancel();
            let _ = task.handle.await;
        }
        if self.delete_on_shutdown
            && matches!(self.mode, RegistrarMode::Managed(_))
            && let Some(stream_id) = self.receiver_stream.stream_id()
        {
            match self.client.delete_stream(&stream_id).await {
                Ok(()) => tracing::info!(stream = stream_id, "Deleted SSF stream"),
                Err(error) => tracing::warn!(stream = stream_id, %error, "Could not delete SSF stream"),
            }
        }
    }

    async fn register_with_retries(&self) {
        let mut delay = self.initial_retry_delay;
        loop {
            match self.register().await {
                Ok(_) => return,
                Err(SsfStreamError::IssuerMismatch { stream, .. }) => {
                    // trying again would only create another stream that must not be used
                    let error = SsfStreamError::IssuerMismatch {
                        expected_issuer: String::new(),
                        stream: stream.clone(),
                    };
                    tracing::error!(%error, "Not using the SSF stream");
                    *self.last_error.lock().unwrap() = Some(error.to_string());
                    *self.state.lock().unwrap() = SsfStreamRegistrarState::Failed;
                    if let Some(stream_id) = stream.stream_id()
                        && let Err(error) = self.client.delete_stream(stream_id).await
                    {
                        tracing::warn!(stream = stream_id, %error, "Could not delete SSF stream");
                    }
                    return;
                }
                Err(error) => {
                    *self.last_error.lock().unwrap() = Some(error.to_string());
                    tracing::warn!(retry_in = ?delay, %error, "Could not set up the SSF stream, trying again");
                }
            }
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Self::MAX_RETRY_DELAY);
        }
    }

    /// Looks up or registers the stream once.
    pub async fn register(&self) -> Result<SsfStreamConfiguration, SsfStreamError> {
        let (stream, action) = match &self.mode {
            RegistrarMode::Existing(stream_id) => (self.client.stream(stream_id).await?, "Using"),
            RegistrarMode::Managed(desired) => {
                let streams = self.client.streams().await?;
                let existing = streams.iter().find(|stream| has_desired_delivery(stream, desired));
                match existing {
                    Some(existing) if has_desired_events(existing, desired) => (existing.clone(), "Using existing"),
                    Some(existing) => (
                        self.client
                            .update_stream(existing.stream_id().unwrap_or(""), &changes(desired))
                            .await?,
                        "Updated",
                    ),
                    None => match self.client.create_stream(desired).await {
                        Ok(created) => (created, "Created"),
                        // the transmitter allows a single stream per receiver and it is configured
                        // differently
                        Err(error) if error.status() == 409 && streams.len() == 1 => (
                            self.client
                                .update_stream(streams[0].stream_id().unwrap_or(""), &changes(desired))
                                .await?,
                            "Updated",
                        ),
                        Err(error) => return Err(error),
                    },
                }
            }
        };
        self.receiver_stream.set_configuration(stream.clone());
        tracing::info!(
            stream = stream.stream_id().unwrap_or(""),
            delivery = stream.delivery_method().unwrap_or(""),
            endpoint = stream.delivery_endpoint_url().map(|u| u.to_string()).unwrap_or_default(),
            events = ?stream.events_delivered().iter().map(|e| event_types::alias_of(e)).collect::<Vec<_>>(),
            audience = ?stream.audience(),
            "{action} SSF stream"
        );
        *self.last_error.lock().unwrap() = None;
        *self.state.lock().unwrap() = SsfStreamRegistrarState::Registered;
        let listeners = self.listeners.lock().unwrap().clone();
        for listener in listeners {
            listener(&stream);
        }
        Ok(stream)
    }
}

fn has_desired_events(stream: &SsfStreamConfiguration, desired: &SsfStreamConfiguration) -> bool {
    let resolved = |events: Vec<String>| events.iter().map(|e| event_types::resolve(e)).collect::<HashSet<_>>();
    resolved(stream.events_requested()) == resolved(desired.events_requested())
}

fn has_desired_delivery(stream: &SsfStreamConfiguration, desired: &SsfStreamConfiguration) -> bool {
    if stream.delivery_method() != desired.delivery_method() {
        return false;
    }
    stream.delivery_method() == Some(SsfDeliveryMethod::Poll.uri())
        || stream.delivery_endpoint_url() == desired.delivery_endpoint_url()
}

fn changes(desired: &SsfStreamConfiguration) -> Map<String, Value> {
    let mut changes = Map::new();
    changes.insert(
        "delivery".to_owned(),
        desired.claims().get("delivery").cloned().unwrap_or(Value::Null),
    );
    changes.insert(
        "events_requested".to_owned(),
        Value::Array(desired.events_requested().into_iter().map(Value::String).collect()),
    );
    if let Some(description) = desired.description() {
        changes.insert("description".to_owned(), Value::String(description.to_owned()));
    }
    changes
}
