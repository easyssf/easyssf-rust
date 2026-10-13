//! Poll delivery (RFC 8936): the poller and the acknowledgements it owes the transmitter.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use easyssf_core::SsfDeliveryMethod;
use serde_json::{Map, Value, json};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::http::{SsfHttpClient, SsfHttpRequest, SsfHttpResponse};
use crate::metrics::{NoopSsfReceiverMetrics, SsfReceiverMetrics};
use crate::set::{SsfSetProcessingError, SsfSetProcessor, SsfSetVerificationError};
use crate::transmitter::SsfTransmitterTokenProvider;
use crate::{BoxError, Clock, system_clock};

/// What the poller owes the transmitter for a SET it fetched (RFC 8936, section 2.2): an
/// acknowledgement that the SET was received and handled, or an error that it was rejected, which
/// goes into the `setErrs` member of the next poll request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfPendingAck {
    /// The identifier of the SET.
    pub jti: String,
    /// The error code of a rejected SET (`invalid_request`, ...), `None` for an acknowledgement.
    pub error_code: Option<String>,
    /// A description of the error.
    pub error_description: Option<String>,
}

impl SsfPendingAck {
    /// The acknowledgement of a handled SET.
    pub fn ack(jti: impl Into<String>) -> Self {
        Self {
            jti: jti.into(),
            error_code: None,
            error_description: None,
        }
    }

    /// The report of a rejected SET.
    pub fn error(jti: impl Into<String>, error_code: impl Into<String>, error_description: Option<&str>) -> Self {
        Self {
            jti: jti.into(),
            error_code: Some(error_code.into()),
            error_description: error_description.map(str::to_owned),
        }
    }

    /// Whether this reports an error rather than acknowledging the SET.
    pub fn is_error(&self) -> bool {
        self.error_code.is_some()
    }
}

/// Keeps the acknowledgements and error reports the poller owes a transmitter until a poll
/// request has carried them (RFC 8936, section 2.4: they ride on the next request). The
/// [`InMemorySsfPollAckStore`] loses them when the application stops, so a SET handled but not
/// yet acknowledged is delivered again after a restart and skipped as a duplicate. A durable
/// implementation, such as the store of `easyssf-receiver-sqlx`, acknowledges it with the first
/// poll after the restart instead.
///
/// Entries are kept per transmitter, identified by its issuer, because a `jti` is only unique
/// per issuer and a store may serve several transmitters.
#[async_trait]
pub trait SsfPollAckStore: Send + Sync + 'static {
    /// Records an acknowledgement or error report. Recording the same `jti` again does nothing.
    async fn record(&self, issuer: &str, ack: SsfPendingAck) -> Result<(), BoxError>;

    /// The acknowledgements and error reports waiting for the transmitter, oldest first, at most
    /// `limit`.
    async fn pending(&self, issuer: &str, limit: usize) -> Result<Vec<SsfPendingAck>, BoxError>;

    /// Removes entries the transmitter has received.
    async fn remove(&self, issuer: &str, jtis: &[String]) -> Result<(), BoxError>;

    /// The number of entries waiting for the transmitter.
    async fn size(&self, issuer: &str) -> Result<usize, BoxError>;
}

#[async_trait]
impl<T: SsfPollAckStore> SsfPollAckStore for Arc<T> {
    async fn record(&self, issuer: &str, ack: SsfPendingAck) -> Result<(), BoxError> {
        (**self).record(issuer, ack).await
    }

    async fn pending(&self, issuer: &str, limit: usize) -> Result<Vec<SsfPendingAck>, BoxError> {
        (**self).pending(issuer, limit).await
    }

    async fn remove(&self, issuer: &str, jtis: &[String]) -> Result<(), BoxError> {
        (**self).remove(issuer, jtis).await
    }

    async fn size(&self, issuer: &str) -> Result<usize, BoxError> {
        (**self).size(issuer).await
    }
}

/// [`SsfPollAckStore`] that keeps the pending acknowledgements in memory, in the order they were
/// recorded. Lost when the application stops, the default of the poller.
#[derive(Debug, Default)]
pub struct InMemorySsfPollAckStore {
    pending: Mutex<HashMap<String, Vec<SsfPendingAck>>>,
}

#[async_trait]
impl SsfPollAckStore for InMemorySsfPollAckStore {
    async fn record(&self, issuer: &str, ack: SsfPendingAck) -> Result<(), BoxError> {
        let mut pending = self.pending.lock().unwrap();
        let acks = pending.entry(issuer.to_owned()).or_default();
        if !acks.iter().any(|existing| existing.jti == ack.jti) {
            acks.push(ack);
        }
        Ok(())
    }

    async fn pending(&self, issuer: &str, limit: usize) -> Result<Vec<SsfPendingAck>, BoxError> {
        let pending = self.pending.lock().unwrap();
        Ok(pending
            .get(issuer)
            .map(|acks| acks.iter().take(limit).cloned().collect())
            .unwrap_or_default())
    }

    async fn remove(&self, issuer: &str, jtis: &[String]) -> Result<(), BoxError> {
        let mut pending = self.pending.lock().unwrap();
        if let Some(acks) = pending.get_mut(issuer) {
            acks.retain(|ack| !jtis.contains(&ack.jti));
        }
        Ok(())
    }

    async fn size(&self, issuer: &str) -> Result<usize, BoxError> {
        Ok(self.pending.lock().unwrap().get(issuer).map(Vec::len).unwrap_or(0))
    }
}

/// Supplies the poll endpoint, `None` as long as it is not known.
pub type PollEndpoint = Arc<dyn Fn() -> Option<Url> + Send + Sync>;

/// How an [`SsfPoller`] polls. Read when the poller works, so configure the options before
/// [`SsfPoller::start`].
#[derive(Clone)]
pub struct SsfPollerOptions {
    /// Keeps the acknowledgements until a poll request carried them; an
    /// [`InMemorySsfPollAckStore`] by default.
    pub ack_store: Arc<dyn SsfPollAckStore>,
    /// The most acknowledgements and error reports one request carries, the rest goes with the
    /// next one; 1000 by default.
    pub max_ack_batch: usize,
    /// Records the polls. Records nothing by default.
    pub metrics: Arc<dyn SsfReceiverMetrics>,
    /// The time between two polls, 30 seconds by default. With long polling, the pause after a
    /// failed request or after a transmitter answered an empty long poll at once.
    pub interval: Duration,
    /// How long [`SsfPoller::start`] waits before the first poll, nothing by default.
    pub initial_delay: Duration,
    /// How soon the poller looks again while the poll endpoint of the stream is not known yet,
    /// one second by default; never longer than the interval.
    pub endpoint_retry: Duration,
    /// Switches to long polling (RFC 8936, section 2.5) when set: the first request of a poll
    /// asks the transmitter to hold it until SETs are available (`returnImmediately: false`), and
    /// a running poller sends the next request as soon as a response was handled. The value is
    /// how long the transmitter holds a request, part of the agreement with it (section 2.2);
    /// the request waits that long plus a margin for the response. `None`, the default, is short
    /// polling.
    pub long_polling_hold: Option<Duration>,
    /// Whether [`SsfPoller::stop`] sends the pending acknowledgements with a last request, so
    /// that the transmitter does not deliver the SETs again after a restart; `true` by default.
    pub flush_on_stop: bool,
    /// The maximum number of SETs fetched with one request, 100 by default.
    pub max_events: usize,
    /// The issuer of the transmitter that is polled, for the metrics and as the key of its
    /// acknowledgements in the [`ack_store`](Self::ack_store); the poll endpoint if `None`.
    pub transmitter: Option<String>,
    /// How long to pause polling after a `429 Too Many Requests` without a `Retry-After` header;
    /// `None`, the default, to poll again at the regular interval.
    pub rate_limit_fallback: Option<Duration>,
    /// The longest pause a `Retry-After` header or the rate limit fallback can cause, 5 minutes
    /// by default.
    pub max_pause: Duration,
    /// The clock the pauses the transmitter asks for are measured by.
    pub clock: Clock,
}

impl Default for SsfPollerOptions {
    fn default() -> Self {
        Self {
            ack_store: Arc::new(InMemorySsfPollAckStore::default()),
            max_ack_batch: 1000,
            metrics: Arc::new(NoopSsfReceiverMetrics),
            interval: Duration::from_secs(30),
            initial_delay: Duration::ZERO,
            endpoint_retry: Duration::from_secs(1),
            long_polling_hold: None,
            flush_on_stop: true,
            max_events: 100,
            transmitter: None,
            rate_limit_fallback: None,
            max_pause: Duration::from_secs(300),
            clock: system_clock(),
        }
    }
}

/// A poll request failed.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct SsfPollError {
    message: String,
    #[source]
    source: Option<BoxError>,
}

impl SsfPollError {
    fn new(message: impl Into<String>, source: Option<BoxError>) -> Self {
        Self {
            message: message.into(),
            source,
        }
    }
}

struct PollerTask {
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

struct PollerState {
    paused_until: Option<SystemTime>,
    last_poll_at: Option<SystemTime>,
    last_successful_poll_at: Option<SystemTime>,
    last_poll_error: Option<String>,
}

struct Inner {
    http: Arc<dyn SsfHttpClient>,
    token_provider: Arc<dyn SsfTransmitterTokenProvider>,
    endpoint: PollEndpoint,
    processor: Arc<SsfSetProcessor>,
    options: SsfPollerOptions,
    state: Mutex<PollerState>,
    polling: tokio::sync::Mutex<()>,
    task: Mutex<Option<PollerTask>>,
    wake_requested: AtomicBool,
    woken: Notify,
}

#[derive(Clone, Copy)]
struct PollResult {
    fetched: usize,
    skipped: bool,
    endpoint_unknown: bool,
}

/// Fetches SETs from the poll endpoint of the transmitter (RFC 8936).
///
/// A SET is acknowledged once it was handled. An invalid SET is reported as an error to the
/// transmitter. A SET that could not be handled is neither acknowledged nor reported, the
/// transmitter delivers it again with a later poll. Acknowledgements and error reports ride on
/// the next poll request (section 2.4) and wait in the [`SsfPollAckStore`] until that request
/// succeeded.
///
/// By default the poller polls at a fixed [interval](SsfPollerOptions::interval) and asks the
/// transmitter to answer right away (`returnImmediately: true`, short polling). With
/// [long polling](SsfPollerOptions::long_polling_hold) it keeps one request outstanding instead.
/// A backlog is fetched with immediate requests in both modes.
///
/// Until the poll endpoint of the stream is known, typically because the `SsfStreamRegistrar` is
/// still registering the stream when the poller starts, the poller looks again every
/// [endpoint retry](SsfPollerOptions::endpoint_retry) rather than waiting the interval.
/// [`wake_up`](Self::wake_up) ends the pause between two polls altogether; `SsfTransmitter`
/// calls it when the stream is registered, so that the first poll follows the registration at
/// once.
///
/// The poller is cheap to clone; clones share the state.
#[derive(Clone)]
pub struct SsfPoller {
    inner: Arc<Inner>,
}

impl SsfPoller {
    const MAX_REQUESTS_PER_POLL: usize = 100;
    /// How much longer than the hold time of the transmitter a long poll waits for the response.
    const LONG_POLL_MARGIN: Duration = Duration::from_secs(10);
    /// A long poll that comes back empty faster than this was not held: the transmitter does not
    /// support long polling, and the poller waits the interval before the next request.
    const MIN_HOLD: Duration = Duration::from_secs(1);

    /// A poller that fetches from `endpoint` (which supplies `None` as long as the endpoint is not
    /// known), authenticates with `token_provider` and processes the SETs with `processor`.
    ///
    /// # Panics
    ///
    /// If an option is out of range: interval, max events, max ack batch, max pause and a long
    /// polling hold must be positive.
    pub fn new(
        http: impl SsfHttpClient,
        token_provider: impl SsfTransmitterTokenProvider,
        endpoint: PollEndpoint,
        processor: Arc<SsfSetProcessor>,
        options: SsfPollerOptions,
    ) -> Self {
        assert!(!options.interval.is_zero(), "interval must be positive");
        assert!(options.max_events > 0, "max_events must be positive");
        assert!(options.max_ack_batch > 0, "max_ack_batch must be positive");
        assert!(!options.max_pause.is_zero(), "max_pause must be positive");
        assert!(!options.endpoint_retry.is_zero(), "endpoint_retry must be positive");
        assert!(
            options.long_polling_hold.is_none_or(|h| !h.is_zero()),
            "long_polling_hold must be positive"
        );
        Self {
            inner: Arc::new(Inner {
                http: Arc::new(http),
                token_provider: Arc::new(token_provider),
                endpoint,
                processor,
                options,
                state: Mutex::new(PollerState {
                    paused_until: None,
                    last_poll_at: None,
                    last_successful_poll_at: None,
                    last_poll_error: None,
                }),
                polling: tokio::sync::Mutex::new(()),
                task: Mutex::new(None),
                wake_requested: AtomicBool::new(false),
                woken: Notify::new(),
            }),
        }
    }

    /// Whether the poller long polls.
    pub fn is_long_polling(&self) -> bool {
        self.inner.options.long_polling_hold.is_some()
    }

    /// Starts polling the transmitter on a task of its own: periodically, or with one request
    /// always outstanding when long polling. Without it, SETs are only fetched by calling
    /// [`poll_now`](Self::poll_now). Needs a tokio runtime. Calling it again while running has no
    /// effect.
    pub fn start(&self) {
        let mut task = self.inner.task.lock().unwrap();
        if task.is_some() {
            return;
        }
        let cancel = CancellationToken::new();
        let poller = self.clone();
        let token = cancel.clone();
        let handle = tokio::spawn(async move { poller.run(token).await });
        *task = Some(PollerTask { cancel, handle });
    }

    /// Stops polling: ends the polling task, cancelling an outstanding long poll, and sends the
    /// pending acknowledgements with a last request unless
    /// [`flush_on_stop`](SsfPollerOptions::flush_on_stop) says otherwise.
    pub async fn stop(&self) {
        let task = self.inner.task.lock().unwrap().take();
        let Some(task) = task else {
            return;
        };
        task.cancel.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), task.handle).await;
        if self.inner.options.flush_on_stop {
            self.flush_acks().await;
        }
    }

    /// Whether the polling task runs.
    pub fn is_running(&self) -> bool {
        self.inner.task.lock().unwrap().is_some()
    }

    /// Ends the pause between two polls, so that the next poll runs now, on the poller's task and
    /// with its error handling. Does nothing while the poller is not running;
    /// [`poll_now`](Self::poll_now) polls on the caller's task regardless.
    pub fn wake_up(&self) {
        if self.is_running() {
            self.inner.wake_requested.store(true, Ordering::SeqCst);
            self.inner.woken.notify_waiters();
        }
    }

    /// When the transmitter was last polled, `None` if it was not polled yet.
    pub fn last_poll_at(&self) -> Option<SystemTime> {
        self.inner.state.lock().unwrap().last_poll_at
    }

    /// When the transmitter was last polled successfully, `None` if never.
    pub fn last_successful_poll_at(&self) -> Option<SystemTime> {
        self.inner.state.lock().unwrap().last_successful_poll_at
    }

    /// Why the last poll failed, `None` if it succeeded or none was made yet.
    pub fn last_poll_error(&self) -> Option<String> {
        self.inner.state.lock().unwrap().last_poll_error.clone()
    }

    /// Until when the transmitter asked not to be polled, `None` if it did not.
    pub fn paused_until(&self) -> Option<SystemTime> {
        let state = self.inner.state.lock().unwrap();
        state.paused_until.filter(|until| *until > (self.inner.options.clock)())
    }

    /// The number of acknowledgements and error reports waiting for the next poll request.
    pub async fn pending_ack_count(&self) -> usize {
        match self.ack_key() {
            Some(key) => self.inner.options.ack_store.size(&key).await.unwrap_or(0),
            None => 0,
        }
    }

    /// Fetches and processes the SETs that are available at the transmitter and acknowledges
    /// them, with the request answered immediately whether or not long polling is on. One poll
    /// runs at a time: a call while another is in progress returns right away.
    ///
    /// Returns the number of SETs fetched, `0` as well if the poll endpoint is not known yet,
    /// the transmitter asked to slow down or a poll is in progress.
    pub async fn poll_now(&self) -> Result<usize, SsfPollError> {
        let Ok(_polling) = self.inner.polling.try_lock() else {
            tracing::debug!("Not polling, a poll is in progress");
            return Ok(0);
        };
        self.poll(false).await.map(|result| result.fetched)
    }

    async fn run(self, cancel: CancellationToken) {
        let options = &self.inner.options;
        if !options.initial_delay.is_zero() {
            tokio::select! {
                _ = tokio::time::sleep(options.initial_delay) => {}
                _ = cancel.cancelled() => return,
            }
        }
        loop {
            if cancel.is_cancelled() {
                return;
            }
            // a wake-up during a poll is not kept: a registration that completes meanwhile is
            // picked up by the endpoint retry
            self.inner.wake_requested.store(false, Ordering::SeqCst);
            let started = tokio::time::Instant::now();
            let outcome = tokio::select! {
                outcome = self.poll_locked() => outcome,
                _ = cancel.cancelled() => return,
            };
            let mut pause = options.interval;
            match outcome {
                Ok(result) if result.endpoint_unknown => {
                    // the stream is still being registered: look again soon
                    pause = options.endpoint_retry.min(options.interval);
                }
                Ok(result) if result.skipped => pause = self.pause_while_skipped(),
                Ok(result) if self.is_long_polling() => {
                    let held = result.fetched > 0 || started.elapsed() >= Self::MIN_HOLD;
                    pause = if held { Duration::ZERO } else { options.interval };
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(%error, "Could not poll the SSF transmitter");
                }
            }
            if !pause.is_zero() {
                tokio::select! {
                    _ = self.pause(pause) => {}
                    _ = cancel.cancelled() => return,
                }
            }
        }
    }

    /// Waits the pause, unless [`wake_up`](Self::wake_up) ends it earlier.
    async fn pause(&self, pause: Duration) {
        let deadline = tokio::time::Instant::now() + pause;
        loop {
            let notified = self.inner.woken.notified();
            tokio::pin!(notified);
            if self.inner.wake_requested.load(Ordering::SeqCst) {
                return;
            }
            tokio::select! {
                _ = &mut notified => {}
                _ = tokio::time::sleep_until(deadline) => return,
            }
        }
    }

    async fn poll_locked(&self) -> Result<PollResult, SsfPollError> {
        let Ok(_polling) = self.inner.polling.try_lock() else {
            return Ok(PollResult {
                fetched: 0,
                skipped: true,
                endpoint_unknown: false,
            });
        };
        self.poll(self.is_long_polling()).await
    }

    fn pause_while_skipped(&self) -> Duration {
        let options = &self.inner.options;
        let until_resume = self
            .paused_until()
            .and_then(|until| until.duration_since((options.clock)()).ok())
            .unwrap_or(Duration::ZERO);
        if until_resume > options.interval {
            until_resume
        } else {
            options.interval
        }
    }

    async fn poll(&self, hold: bool) -> Result<PollResult, SsfPollError> {
        let options = &self.inner.options;
        let Some(endpoint) = (self.inner.endpoint)() else {
            tracing::debug!("Not polling, the poll endpoint of the SSF stream is not known yet");
            return Ok(PollResult {
                fetched: 0,
                skipped: true,
                endpoint_unknown: true,
            });
        };
        if let Some(until) = self.paused_until() {
            tracing::debug!(until = ?until, "Not polling, the SSF transmitter asked to wait");
            return Ok(PollResult {
                fetched: 0,
                skipped: true,
                endpoint_unknown: false,
            });
        }
        self.inner.state.lock().unwrap().last_poll_at = Some((options.clock)());
        let key = self.ack_key_for(&endpoint);
        let result = self.poll_requests(&endpoint, &key, hold).await;
        let mut state = self.inner.state.lock().unwrap();
        match &result {
            Ok(_) => {
                state.last_successful_poll_at = Some((options.clock)());
                state.last_poll_error = None;
            }
            Err(error) => state.last_poll_error = Some(error.to_string()),
        }
        result
    }

    async fn poll_requests(&self, endpoint: &Url, key: &str, hold: bool) -> Result<PollResult, SsfPollError> {
        let options = &self.inner.options;
        let mut fetched = 0;
        let mut more_available = true;
        let mut request = 0;
        while more_available && request < Self::MAX_REQUESTS_PER_POLL {
            // only the first request of a poll is held, a backlog is fetched right away
            let response = self
                .request(endpoint, key, options.max_events, !(hold && request == 0))
                .await?;
            let sets = sets(&response);
            for (jti, set) in &sets {
                self.process(key, jti, set).await;
            }
            fetched += sets.len();
            more_available = response.get("moreAvailable") == Some(&Value::Bool(true)) && !sets.is_empty();
            request += 1;
        }
        if !hold && options.ack_store.size(key).await.unwrap_or(0) > 0 {
            // acknowledge right away instead of with the next poll; a long poll sends its next
            // request at once anyway
            let response = self.request(endpoint, key, 0, true).await?;
            let sets = sets(&response);
            for (jti, set) in &sets {
                self.process(key, jti, set).await;
            }
            fetched += sets.len();
        }
        Ok(PollResult {
            fetched,
            skipped: false,
            endpoint_unknown: false,
        })
    }

    async fn process(&self, key: &str, jti: &str, encoded_set: &Value) {
        let encoded_set = match encoded_set {
            Value::String(set) => set.clone(),
            other => other.to_string(),
        };
        let ack = match self
            .inner
            .processor
            .process(&encoded_set, SsfDeliveryMethod::Poll)
            .await
        {
            Ok(_) => Some(SsfPendingAck::ack(jti)),
            Err(SsfSetProcessingError::Verification(SsfSetVerificationError::Rejected { code, description })) => {
                tracing::warn!(jti, code = code.as_str(), description, "Rejecting polled SET");
                Some(SsfPendingAck::error(jti, code.as_str(), Some(&description)))
            }
            Err(SsfSetProcessingError::InProgress) => {
                // another instance is on it, the transmitter delivers the SET again
                tracing::debug!(jti, "Not acknowledging polled SET, another instance is handling it");
                None
            }
            Err(error) => {
                // not acknowledged, the transmitter delivers the SET again
                tracing::warn!(jti, %error, "Could not process polled SET");
                None
            }
        };
        if let Some(ack) = ack {
            if let Err(error) = self.inner.options.ack_store.record(key, ack).await {
                tracing::warn!(jti, %error, "Could not record the acknowledgement of the polled SET");
            }
            self.report_pending(key).await;
        }
    }

    async fn report_pending(&self, key: &str) {
        let options = &self.inner.options;
        if let Ok(size) = options.ack_store.size(key).await {
            options
                .metrics
                .pending_acks_changed(options.transmitter.as_deref(), size);
        }
    }

    async fn request(
        &self,
        endpoint: &Url,
        key: &str,
        max_events: usize,
        return_immediately: bool,
    ) -> Result<Map<String, Value>, SsfPollError> {
        let options = &self.inner.options;
        let pending = options
            .ack_store
            .pending(key, options.max_ack_batch)
            .await
            .map_err(|e| SsfPollError::new(format!("Could not read the pending acknowledgements: {e}"), Some(e)))?;
        let mut acks = Vec::new();
        let mut errors = Map::new();
        for ack in &pending {
            match &ack.error_code {
                Some(code) => {
                    let mut error = Map::new();
                    error.insert("err".to_owned(), Value::String(code.clone()));
                    if let Some(description) = &ack.error_description {
                        error.insert("description".to_owned(), Value::String(description.clone()));
                    }
                    errors.insert(ack.jti.clone(), Value::Object(error));
                }
                None => acks.push(Value::String(ack.jti.clone())),
            }
        }
        let mut body = Map::new();
        body.insert("maxEvents".to_owned(), json!(max_events));
        body.insert("returnImmediately".to_owned(), Value::Bool(return_immediately));
        if !acks.is_empty() {
            body.insert("ack".to_owned(), Value::Array(acks));
        }
        if !errors.is_empty() {
            body.insert("setErrs".to_owned(), Value::Object(errors));
        }
        let started = tokio::time::Instant::now();
        let transmitter = options.transmitter.as_deref();
        let failed = |e: BoxError| SsfPollError::new(format!("Poll request to {endpoint} failed: {e}"), Some(e));
        let mut response = match self.send(endpoint, &body, return_immediately).await {
            Ok(response) => response,
            Err(e) => {
                options.metrics.poll_completed(transmitter, started.elapsed(), false);
                return Err(failed(e));
            }
        };
        if response.status == 401 {
            // the access token expired or was revoked: try once more with a new one
            self.inner.token_provider.invalidate().await;
            response = match self.send(endpoint, &body, return_immediately).await {
                Ok(response) => response,
                Err(e) => {
                    options.metrics.poll_completed(transmitter, started.elapsed(), false);
                    return Err(failed(e));
                }
            };
        }
        if !response.is_successful() {
            options.metrics.poll_completed(transmitter, started.elapsed(), false);
            self.pause_if_asked(&response);
            return Err(SsfPollError::new(
                format!("Poll request to {endpoint} failed with status {}", response.status),
                None,
            ));
        }
        let parsed: Map<String, Value> = if response.body.trim().is_empty() {
            Map::new()
        } else {
            match serde_json::from_str::<Value>(&response.body) {
                Ok(Value::Object(parsed)) => parsed,
                Ok(_) => Map::new(),
                Err(e) => {
                    options.metrics.poll_completed(transmitter, started.elapsed(), false);
                    return Err(SsfPollError::new(
                        format!("Poll request to {endpoint} failed: the response is not JSON"),
                        Some(e.into()),
                    ));
                }
            }
        };
        if !pending.is_empty() {
            let jtis: Vec<String> = pending.iter().map(|ack| ack.jti.clone()).collect();
            if let Err(error) = options.ack_store.remove(key, &jtis).await {
                tracing::warn!(%error, "Could not remove the delivered acknowledgements");
            }
            self.report_pending(key).await;
        }
        options.metrics.poll_completed(transmitter, started.elapsed(), true);
        Ok(parsed)
    }

    async fn send(
        &self,
        endpoint: &Url,
        body: &Map<String, Value>,
        return_immediately: bool,
    ) -> Result<SsfHttpResponse, BoxError> {
        let token = self.inner.token_provider.access_token().await?;
        let mut request = SsfHttpRequest::of("POST", endpoint.clone())
            .with_header("Accept", "application/json")
            .with_bearer_token(token.as_deref())
            .with_json_body(Value::Object(body.clone()).to_string());
        if let (false, Some(hold)) = (return_immediately, self.inner.options.long_polling_hold) {
            request = request.with_timeout(hold + Self::LONG_POLL_MARGIN);
        }
        self.inner.http.execute(request).await
    }

    /// Sends the pending acknowledgements with a request that asks for no SETs, best effort.
    async fn flush_acks(&self) {
        let Some(endpoint) = (self.inner.endpoint)() else {
            return;
        };
        let key = self.ack_key_for(&endpoint);
        if self.inner.options.ack_store.size(&key).await.unwrap_or(0) == 0 {
            return;
        }
        let Ok(_polling) = self.inner.polling.try_lock() else {
            return;
        };
        match self.request(&endpoint, &key, 0, true).await {
            Ok(_) => tracing::debug!("Acknowledged the pending SETs before stopping"),
            Err(error) => {
                tracing::debug!(%error, "Could not acknowledge the pending SETs before stopping, they are sent with the next poll")
            }
        }
    }

    fn ack_key(&self) -> Option<String> {
        if let Some(transmitter) = &self.inner.options.transmitter {
            return Some(transmitter.clone());
        }
        (self.inner.endpoint)().map(|endpoint| endpoint.to_string())
    }

    fn ack_key_for(&self, endpoint: &Url) -> String {
        self.inner
            .options
            .transmitter
            .clone()
            .unwrap_or_else(|| endpoint.to_string())
    }

    fn pause_if_asked(&self, response: &SsfHttpResponse) {
        let options = &self.inner.options;
        let status = response.status;
        let retry_after = response
            .header("Retry-After")
            .and_then(|value| value.trim().parse::<u64>().ok());
        let mut pause = None;
        if (status == 429 || status == 503) && retry_after.is_some() {
            pause = retry_after.map(Duration::from_secs);
        }
        if pause.is_none() && status == 429 {
            pause = options.rate_limit_fallback;
        }
        if let Some(pause) = pause {
            let pause = pause.min(options.max_pause);
            self.inner.state.lock().unwrap().paused_until = Some((options.clock)() + pause);
        }
    }
}

fn sets(response: &Map<String, Value>) -> Vec<(String, Value)> {
    match response.get("sets") {
        Some(Value::Object(sets)) => sets.iter().map(|(jti, set)| (jti.clone(), set.clone())).collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn keeps_acknowledgements_and_errors_in_order_per_issuer() {
        let store = InMemorySsfPollAckStore::default();
        store.record("a", SsfPendingAck::ack("1")).await.unwrap();
        store
            .record("a", SsfPendingAck::error("2", "invalid_request", Some("bad")))
            .await
            .unwrap();
        store.record("b", SsfPendingAck::ack("3")).await.unwrap();
        let pending = store.pending("a", 10).await.unwrap();
        assert_eq!(pending.iter().map(|a| a.jti.as_str()).collect::<Vec<_>>(), ["1", "2"]);
        assert!(pending[1].is_error());
        assert_eq!(store.pending("a", 1).await.unwrap().len(), 1);
        assert_eq!(store.size("b").await.unwrap(), 1);
        assert_eq!(store.size("c").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn recording_the_same_set_again_changes_nothing() {
        let store = InMemorySsfPollAckStore::default();
        store.record("a", SsfPendingAck::ack("1")).await.unwrap();
        store
            .record("a", SsfPendingAck::error("1", "invalid_request", None))
            .await
            .unwrap();
        assert_eq!(store.size("a").await.unwrap(), 1);
        assert!(!store.pending("a", 10).await.unwrap()[0].is_error());
    }

    #[tokio::test]
    async fn removes_what_the_transmitter_received() {
        let store = InMemorySsfPollAckStore::default();
        store.record("a", SsfPendingAck::ack("1")).await.unwrap();
        store.record("a", SsfPendingAck::ack("2")).await.unwrap();
        store.remove("a", &["1".to_owned(), "x".to_owned()]).await.unwrap();
        assert_eq!(store.pending("a", 10).await.unwrap()[0].jti, "2");
        store.remove("unknown", &["1".to_owned()]).await.unwrap();
    }

    #[test]
    fn pending_ack_tells_errors_from_acknowledgements() {
        assert!(!SsfPendingAck::ack("1").is_error());
        let error = SsfPendingAck::error("1", "invalid_key", None);
        assert!(error.is_error());
        assert_eq!(error.error_description, None);
    }
}
