//! Event handlers and the context they receive.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;

use easyssf_core::{SsfDeliveryMethod, SsfEventToken, SsfSubject, event_types};
use serde_json::{Map, Value};

use crate::BoxError;

/// A verified [`SsfEventToken`] together with convenient, alias-aware access to its events and
/// subjects. Passed to every [`SsfEventHandler`]. Cheap to clone and `'static`, so a handler can
/// move it into a task.
#[derive(Debug, Clone)]
pub struct SsfEventContext {
    token: SsfEventToken,
    subject: Arc<SsfSubject>,
    delivery: SsfDeliveryMethod,
}

impl SsfEventContext {
    /// The context of a verified SET.
    pub fn new(token: SsfEventToken, delivery: SsfDeliveryMethod) -> Self {
        let subject = Arc::new(SsfSubject::from(token.subject_id()));
        Self {
            token,
            subject,
            delivery,
        }
    }

    /// The verified SET.
    pub fn event_token(&self) -> &SsfEventToken {
        &self.token
    }

    /// How the SET arrived.
    pub fn delivery_method(&self) -> SsfDeliveryMethod {
        self.delivery
    }

    /// The key for making the side effects of a handler idempotent, the issuer and `jti` of the
    /// SET: a SET is handled at least once, not exactly once (see [`SsfEventHandler`]).
    pub fn idempotency_key(&self) -> String {
        self.token.idempotency_key()
    }

    /// The event type URIs contained in the SET.
    pub fn event_types(&self) -> BTreeSet<String> {
        self.token.events().keys().cloned().collect()
    }

    /// Whether the SET contains an event of the given type, named by alias (such as
    /// `CaepSessionRevoked`) or URI.
    pub fn has_event(&self, alias_or_uri: &str) -> bool {
        self.token.events().contains_key(&event_types::resolve(alias_or_uri))
    }

    /// The payload of the event of the given type (alias or URI), `None` if the SET has no such
    /// event or its payload is not a JSON object.
    pub fn event_for(&self, alias_or_uri: &str) -> Option<&Map<String, Value>> {
        self.token
            .events()
            .get(&event_types::resolve(alias_or_uri))
            .and_then(Value::as_object)
    }

    /// The subject of the SET, taken from its top-level `sub_id` claim; empty if the SET has
    /// none.
    pub fn subject(&self) -> &SsfSubject {
        &self.subject
    }

    /// The subject of the event of the given type: the top-level `sub_id` claim of the SET or,
    /// for transmitters following earlier SSF drafts, the `subject` member of the event payload.
    /// SETs without the top-level claim reach a handler only in the `Legacy` subject
    /// compatibility mode of the verifier.
    pub fn subject_for(&self, alias_or_uri: &str) -> SsfSubject {
        if !self.subject.is_empty() {
            return (*self.subject).clone();
        }
        match self
            .event_for(alias_or_uri)
            .and_then(|event| event.get("subject"))
            .and_then(Value::as_object)
        {
            Some(legacy_subject) => SsfSubject::from(Some(legacy_subject)),
            None => SsfSubject::empty(),
        }
    }

    /// The time the event of the given type occurred: its `event_timestamp` or, if absent, the
    /// time the SET was issued.
    pub fn event_timestamp(&self, alias_or_uri: &str) -> SystemTime {
        self.event_for(alias_or_uri)
            .and_then(|event| easyssf_core::event::event_timestamp(event.get("event_timestamp")))
            .unwrap_or_else(|| self.token.issued_at())
    }
}

/// Reacts to verified security events. Every handler given to the
/// [`SsfSetProcessor`](crate::set::SsfSetProcessor) is invoked for every SET.
///
/// A SET is handled at least once, not exactly once, so handlers must be idempotent. A SET is
/// delivered again if any handler failed, and all handlers run again, possibly on another
/// instance of the application; with a shared dedup store a SET is claimed while its handlers
/// run and another instance leaves it alone meanwhile, but an instance that dies after a
/// handler's side effects and before the success is recorded hands the SET to the next instance
/// after a lease. Side effects outside the receiver's stores should be keyed by
/// [`SsfEventContext::idempotency_key`].
///
/// Implemented for `async` closures and functions that take the context by value:
///
/// ```
/// # use easyssf_receiver::event::{SsfEventContext, SsfEventHandler};
/// fn assert_handler(_: impl SsfEventHandler) {}
/// assert_handler(|context: SsfEventContext| async move {
///     if context.has_event("CaepSessionRevoked") {
///         let _session = context.subject().session_id();
///     }
///     Ok(())
/// });
/// ```
pub trait SsfEventHandler: Send + Sync + 'static {
    /// Handles a SET. An error leaves the SET unacknowledged, the transmitter delivers it again.
    fn handle(&self, context: SsfEventContext) -> impl Future<Output = Result<(), BoxError>> + Send;
}

impl<F, Fut> SsfEventHandler for F
where
    F: Fn(SsfEventContext) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<(), BoxError>> + Send,
{
    fn handle(&self, context: SsfEventContext) -> impl Future<Output = Result<(), BoxError>> + Send {
        self(context)
    }
}

/// Calls `handler` only for SETs with an event of the given type (alias or URI).
pub fn for_event<H: SsfEventHandler>(alias_or_uri: &str, handler: H) -> impl SsfEventHandler {
    ForEvent {
        event_type: event_types::resolve(alias_or_uri),
        handler,
    }
}

struct ForEvent<H> {
    event_type: String,
    handler: H,
}

impl<H: SsfEventHandler> SsfEventHandler for ForEvent<H> {
    async fn handle(&self, context: SsfEventContext) -> Result<(), BoxError> {
        if context.has_event(&self.event_type) {
            self.handler.handle(context).await?;
        }
        Ok(())
    }
}

/// The object-safe form the processor stores; `async fn` in traits is not dyn compatible.
/// Implemented for every [`SsfEventHandler`].
pub trait DynSsfEventHandler: Send + Sync + 'static {
    /// Handles a SET, see [`SsfEventHandler::handle`].
    fn handle_dyn(&self, context: SsfEventContext) -> Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send + '_>>;

    /// The name of the handler, for the log.
    fn name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }
}

impl<H: SsfEventHandler> DynSsfEventHandler for H {
    fn handle_dyn(&self, context: SsfEventContext) -> Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send + '_>> {
        Box::pin(SsfEventHandler::handle(self, context))
    }
}

/// A handler held type-erased.
pub type BoxedSsfEventHandler = Arc<dyn DynSsfEventHandler>;

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use easyssf_core::event::subjects;
    use serde_json::json;

    use super::*;

    fn context(claims: Value) -> SsfEventContext {
        SsfEventContext::new(
            SsfEventToken::from_claims(claims.as_object().unwrap().clone()).unwrap(),
            SsfDeliveryMethod::Push,
        )
    }

    #[test]
    fn finds_events_by_alias_and_uri() {
        let context = context(json!({
            "jti": "1", "iss": "i", "iat": 1, "sub_id": subjects::opaque("x"),
            "events": { event_types::CAEP_SESSION_REVOKED: { "event_timestamp": 5 }, "https://events.acme.example/login": [] }
        }));
        assert!(context.has_event("CaepSessionRevoked"));
        assert!(context.has_event(event_types::CAEP_SESSION_REVOKED));
        assert!(!context.has_event("CaepCredentialChange"));
        assert_eq!(context.event_for("CaepSessionRevoked").unwrap()["event_timestamp"], 5);
        assert_eq!(context.event_types().len(), 2);
    }

    #[test]
    fn vendor_event_types_are_addressed_by_uri() {
        let context = context(json!({
            "jti": "1", "iss": "i", "iat": 1, "sub_id": subjects::opaque("x"),
            "events": { "https://events.acme.example/login": { "ip": "1.2.3.4" } }
        }));
        assert!(context.has_event("https://events.acme.example/login"));
        assert_eq!(
            context.event_for("https://events.acme.example/login").unwrap()["ip"],
            "1.2.3.4"
        );
        // a payload that is not an object has no map
        let context2 = context_with_array();
        assert!(context2.has_event("https://events.acme.example/list"));
        assert!(context2.event_for("https://events.acme.example/list").is_none());
    }

    fn context_with_array() -> SsfEventContext {
        context(json!({ "jti": "1", "iss": "i", "iat": 1, "events": { "https://events.acme.example/list": [1] } }))
    }

    #[test]
    fn idempotency_key_is_issuer_and_jti() {
        let context = context(json!({ "jti": "abc", "iss": "https://t.example", "iat": 1, "events": { "e": {} } }));
        assert_eq!(context.idempotency_key(), "https://t.example::abc");
    }

    #[test]
    fn subject_is_taken_from_sub_id() {
        let context = context(json!({
            "jti": "1", "iss": "i", "iat": 1,
            "sub_id": subjects::complex(Some(subjects::iss_sub("https://idp.example", "alice")), Some(subjects::opaque("s1"))),
            "events": { event_types::CAEP_SESSION_REVOKED: { "subject": subjects::email("ignored@example.com") } }
        }));
        assert_eq!(context.subject().subject(), Some("alice"));
        assert_eq!(context.subject_for("CaepSessionRevoked").session_id(), Some("s1"));
    }

    #[test]
    fn subject_falls_back_to_event_subject_of_early_drafts() {
        let context = context(json!({
            "jti": "1", "iss": "i", "iat": 1,
            "events": { event_types::CAEP_SESSION_REVOKED: { "subject": subjects::email("alice@example.com") } }
        }));
        assert!(context.subject().is_empty());
        assert_eq!(
            context.subject_for("CaepSessionRevoked").email(),
            Some("alice@example.com")
        );
        assert!(context.subject_for("CaepCredentialChange").is_empty());
    }

    #[test]
    fn event_timestamp_in_seconds_or_milliseconds_else_issued_at() {
        let context = context(json!({
            "jti": "1", "iss": "i", "iat": 1700000000,
            "events": {
                "https://e.example/seconds": { "event_timestamp": 1600000000 },
                "https://e.example/millis": { "event_timestamp": 1600000000500_i64 },
                "https://e.example/none": {}
            }
        }));
        assert_eq!(
            context.event_timestamp("https://e.example/seconds"),
            UNIX_EPOCH + Duration::from_secs(1600000000)
        );
        assert_eq!(
            context.event_timestamp("https://e.example/millis"),
            UNIX_EPOCH + Duration::from_secs(1600000000)
        );
        assert_eq!(
            context.event_timestamp("https://e.example/none"),
            UNIX_EPOCH + Duration::from_secs(1700000000)
        );
        assert_eq!(
            context.event_timestamp("https://e.example/absent"),
            UNIX_EPOCH + Duration::from_secs(1700000000)
        );
    }
}
