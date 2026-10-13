//! Records what the receiver does. The default records nothing; [`MetricsSsfReceiverMetrics`]
//! (feature `metrics`) records to the [`metrics`] facade under the names of the Java library.

use std::sync::Arc;
use std::time::Duration;

use easyssf_core::SsfDeliveryMethod;

/// What happened to a received SET.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsfSetOutcome {
    /// The SET was verified and handled.
    Handled,
    /// The SET was processed before and has been skipped.
    Duplicate,
    /// The SET is being handled by another instance and has been left for a redelivery.
    InProgress,
    /// The SET was rejected because it is invalid.
    Invalid,
    /// The SET was rejected because the transmitter did not authenticate.
    Unauthenticated,
    /// The SET could not be verified because the keys of the transmitter could not be obtained.
    Unavailable,
    /// An event handler failed.
    Failed,
}

impl SsfSetOutcome {
    /// The outcome as a metric tag: `handled`, `duplicate`, `in_progress`, `invalid`,
    /// `unauthenticated`, `unavailable`, `failed`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Handled => "handled",
            Self::Duplicate => "duplicate",
            Self::InProgress => "in_progress",
            Self::Invalid => "invalid",
            Self::Unauthenticated => "unauthenticated",
            Self::Unavailable => "unavailable",
            Self::Failed => "failed",
        }
    }
}

/// Records what the receiver does. Every method does nothing by default, implement the ones you
/// record. `transmitter` is the issuer of the transmitter, `None` if the SET did not tell.
pub trait SsfReceiverMetrics: Send + Sync + 'static {
    /// A SET was received.
    fn set_received(&self, transmitter: Option<&str>, delivery_method: SsfDeliveryMethod, outcome: SsfSetOutcome) {
        let _ = (transmitter, delivery_method, outcome);
    }

    /// An event of a SET was handled. `event_type` is the event type URI.
    fn event_handled(&self, transmitter: Option<&str>, event_type: &str, delivery_method: SsfDeliveryMethod) {
        let _ = (transmitter, event_type, delivery_method);
    }

    /// The transmitter was polled for SETs; `success` tells whether it answered the request.
    fn poll_completed(&self, transmitter: Option<&str>, duration: Duration, success: bool) {
        let _ = (transmitter, duration, success);
    }

    /// The number of acknowledgements and error reports a poller owes its transmitter changed,
    /// for a gauge.
    fn pending_acks_changed(&self, transmitter: Option<&str>, pending_acks: usize) {
        let _ = (transmitter, pending_acks);
    }
}

/// Records nothing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSsfReceiverMetrics;

impl SsfReceiverMetrics for NoopSsfReceiverMetrics {}

impl<T: SsfReceiverMetrics> SsfReceiverMetrics for Arc<T> {
    fn set_received(&self, transmitter: Option<&str>, delivery_method: SsfDeliveryMethod, outcome: SsfSetOutcome) {
        (**self).set_received(transmitter, delivery_method, outcome)
    }

    fn event_handled(&self, transmitter: Option<&str>, event_type: &str, delivery_method: SsfDeliveryMethod) {
        (**self).event_handled(transmitter, event_type, delivery_method)
    }

    fn poll_completed(&self, transmitter: Option<&str>, duration: Duration, success: bool) {
        (**self).poll_completed(transmitter, duration, success)
    }

    fn pending_acks_changed(&self, transmitter: Option<&str>, pending_acks: usize) {
        (**self).pending_acks_changed(transmitter, pending_acks)
    }
}

/// [`SsfReceiverMetrics`] that records to the [`metrics`] facade (feature `metrics`), under the
/// names of the Java library:
///
/// - `easyssf.receiver.sets`: a counter of received SETs, tagged with `transmitter`, `delivery`
///   (`push`, `poll`) and `outcome` (`handled`, `duplicate`, `in_progress`, `invalid`,
///   `unauthenticated`, `unavailable`, `failed`)
/// - `easyssf.receiver.events`: a counter of handled events, tagged with `transmitter`, `delivery`
///   and `event` (for example `CaepSessionRevoked`)
/// - `easyssf.receiver.poll`: a histogram of the duration of poll requests in seconds, tagged with
///   `transmitter` and `outcome` (`success`, `failure`)
/// - `easyssf.receiver.poll.pending-acks`: a gauge of the acknowledgements and error reports a
///   poller owes its transmitter, tagged with `transmitter`
#[cfg(feature = "metrics")]
pub struct MetricsSsfReceiverMetrics {
    transmitter_labels: Arc<dyn Fn(&str) -> String + Send + Sync>,
}

#[cfg(feature = "metrics")]
impl MetricsSsfReceiverMetrics {
    /// Records with the issuer as the `transmitter` tag.
    pub fn new() -> Self {
        Self {
            transmitter_labels: Arc::new(|issuer| issuer.to_owned()),
        }
    }

    /// Sets the value of the `transmitter` tag for the issuer of a transmitter, for example its
    /// name, as issuers are long. See `SsfTransmitters::name_of`.
    pub fn with_transmitter_labels(mut self, labels: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
        self.transmitter_labels = Arc::new(labels);
        self
    }

    fn transmitter(&self, issuer: Option<&str>) -> String {
        issuer
            .map(|issuer| (self.transmitter_labels)(issuer))
            .unwrap_or_else(|| "unknown".to_owned())
    }
}

#[cfg(feature = "metrics")]
impl Default for MetricsSsfReceiverMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "metrics")]
impl SsfReceiverMetrics for MetricsSsfReceiverMetrics {
    fn set_received(&self, transmitter: Option<&str>, delivery_method: SsfDeliveryMethod, outcome: SsfSetOutcome) {
        metrics::counter!(
            "easyssf.receiver.sets",
            "transmitter" => self.transmitter(transmitter),
            "delivery" => delivery_method.as_str(),
            "outcome" => outcome.as_str()
        )
        .increment(1);
    }

    fn event_handled(&self, transmitter: Option<&str>, event_type: &str, delivery_method: SsfDeliveryMethod) {
        metrics::counter!(
            "easyssf.receiver.events",
            "transmitter" => self.transmitter(transmitter),
            "delivery" => delivery_method.as_str(),
            "event" => easyssf_core::event_types::alias_of(event_type)
        )
        .increment(1);
    }

    fn poll_completed(&self, transmitter: Option<&str>, duration: Duration, success: bool) {
        metrics::histogram!(
            "easyssf.receiver.poll",
            "transmitter" => self.transmitter(transmitter),
            "outcome" => if success { "success" } else { "failure" }
        )
        .record(duration.as_secs_f64());
    }

    fn pending_acks_changed(&self, transmitter: Option<&str>, pending_acks: usize) {
        metrics::gauge!("easyssf.receiver.poll.pending-acks", "transmitter" => self.transmitter(transmitter))
            .set(pending_acks as f64);
    }
}
