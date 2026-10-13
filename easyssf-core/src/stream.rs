//! Event streams (SSF 1.0, section 8.1): their configuration and status.

use serde_json::{Map, Value};
use url::Url;

use crate::SsfDeliveryMethod;
use crate::event_types;
use crate::support::{object_member, string_member, strings, strings_member};

/// The configuration of an event stream (SSF 1.0, section 8.1.1), as sent to and returned by the
/// transmitter.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SsfStreamConfiguration {
    claims: Map<String, Value>,
}

impl SsfStreamConfiguration {
    /// A stream configuration with the given members.
    pub fn new(claims: Map<String, Value>) -> Self {
        Self { claims }
    }

    /// A stream the transmitter pushes events to.
    ///
    /// `endpoint_url` is the push endpoint of the receiver as the transmitter reaches it,
    /// `authorization_header` the `Authorization` header the transmitter has to send,
    /// `events_requested` the requested event types (alias or URI).
    pub fn push(
        endpoint_url: &Url,
        authorization_header: Option<&str>,
        events_requested: &[String],
        description: Option<&str>,
    ) -> Self {
        let mut delivery = Map::new();
        delivery.insert(
            "method".to_owned(),
            Value::String(SsfDeliveryMethod::Push.uri().to_owned()),
        );
        delivery.insert("endpoint_url".to_owned(), Value::String(endpoint_url.to_string()));
        if let Some(header) = authorization_header {
            delivery.insert("authorization_header".to_owned(), Value::String(header.to_owned()));
        }
        Self::create(delivery, events_requested, description)
    }

    /// A stream the receiver polls events from.
    pub fn poll(events_requested: &[String], description: Option<&str>) -> Self {
        let mut delivery = Map::new();
        delivery.insert(
            "method".to_owned(),
            Value::String(SsfDeliveryMethod::Poll.uri().to_owned()),
        );
        Self::create(delivery, events_requested, description)
    }

    fn create(delivery: Map<String, Value>, events_requested: &[String], description: Option<&str>) -> Self {
        let mut claims = Map::new();
        claims.insert("delivery".to_owned(), Value::Object(delivery));
        claims.insert(
            "events_requested".to_owned(),
            Value::Array(
                events_requested
                    .iter()
                    .map(|e| Value::String(event_types::resolve(e)))
                    .collect(),
            ),
        );
        if let Some(description) = description {
            claims.insert("description".to_owned(), Value::String(description.to_owned()));
        }
        Self { claims }
    }

    /// The members of the stream configuration.
    pub fn claims(&self) -> &Map<String, Value> {
        &self.claims
    }

    /// The `stream_id`.
    pub fn stream_id(&self) -> Option<&str> {
        self.claims.get("stream_id").and_then(Value::as_str)
    }

    /// The `iss`, the issuer of the SETs of this stream.
    pub fn issuer(&self) -> Option<&str> {
        self.claims.get("iss").and_then(Value::as_str)
    }

    /// The audiences of the SETs of this stream, empty if unknown.
    pub fn audience(&self) -> Vec<String> {
        match self.claims.get("aud") {
            Some(Value::String(value)) => vec![value.clone()],
            other => strings(other),
        }
    }

    /// The `events_supported` of the transmitter.
    pub fn events_supported(&self) -> Vec<String> {
        strings_member(&self.claims, "events_supported")
    }

    /// The `events_requested` by the receiver.
    pub fn events_requested(&self) -> Vec<String> {
        strings_member(&self.claims, "events_requested")
    }

    /// The `events_delivered` on this stream.
    pub fn events_delivered(&self) -> Vec<String> {
        strings_member(&self.claims, "events_delivered")
    }

    /// The `description`.
    pub fn description(&self) -> Option<&str> {
        self.claims.get("description").and_then(Value::as_str)
    }

    /// The identifier of the delivery method, see [`SsfDeliveryMethod::uri`].
    pub fn delivery_method(&self) -> Option<&str> {
        self.delivery()
            .and_then(|delivery| delivery.get("method"))
            .and_then(Value::as_str)
    }

    /// The push endpoint of the receiver or the poll endpoint of the transmitter.
    pub fn delivery_endpoint_url(&self) -> Option<Url> {
        let delivery = self.delivery()?;
        string_member(delivery, "endpoint_url").and_then(|value| Url::parse(value).ok())
    }

    fn delivery(&self) -> Option<&Map<String, Value>> {
        object_member(&self.claims, "delivery")
    }
}

/// The status of an event stream (SSF 1.0, section 8.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfStreamStatus {
    /// The identifier of the stream.
    pub stream_id: String,
    /// `enabled`, `paused` or `disabled`.
    pub status: String,
    /// Why the stream has that status.
    pub reason: Option<String>,
}

impl SsfStreamStatus {
    /// The stream delivers events.
    pub const ENABLED: &'static str = "enabled";
    /// The stream holds events back and delivers them when enabled again.
    pub const PAUSED: &'static str = "paused";
    /// The stream delivers no events and drops them.
    pub const DISABLED: &'static str = "disabled";
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn push_stream_names_the_endpoint_header_and_events() {
        let stream = SsfStreamConfiguration::push(
            &Url::parse("https://app.example/ssf/push").unwrap(),
            Some("Bearer s3cr3t"),
            &[
                "CaepSessionRevoked".to_owned(),
                event_types::CAEP_CREDENTIAL_CHANGE.to_owned(),
            ],
            Some("my stream"),
        );
        assert_eq!(stream.delivery_method(), Some("urn:ietf:rfc:8935"));
        assert_eq!(
            stream.delivery_endpoint_url().unwrap().as_str(),
            "https://app.example/ssf/push"
        );
        assert_eq!(stream.claims()["delivery"]["authorization_header"], "Bearer s3cr3t");
        assert_eq!(
            stream.events_requested(),
            [event_types::CAEP_SESSION_REVOKED, event_types::CAEP_CREDENTIAL_CHANGE]
        );
        assert_eq!(stream.description(), Some("my stream"));
        assert_eq!(stream.stream_id(), None);
    }

    #[test]
    fn poll_stream_has_no_endpoint_until_the_transmitter_assigns_one() {
        let stream = SsfStreamConfiguration::poll(&["CaepSessionRevoked".to_owned()], None);
        assert_eq!(stream.delivery_method(), Some("urn:ietf:rfc:8936"));
        assert!(stream.delivery_endpoint_url().is_none());
        assert_eq!(stream.description(), None);
    }

    #[test]
    fn stream_configuration_reads_what_the_transmitter_returns() {
        let claims = json!({
            "stream_id": "s-1", "iss": "https://t.example", "aud": "receiver/s-1",
            "events_supported": ["a", "b"], "events_requested": ["a"], "events_delivered": ["a"],
            "delivery": { "method": "urn:ietf:rfc:8936", "endpoint_url": "https://t.example/poll" }
        });
        let stream = SsfStreamConfiguration::new(claims.as_object().unwrap().clone());
        assert_eq!(stream.stream_id(), Some("s-1"));
        assert_eq!(stream.issuer(), Some("https://t.example"));
        assert_eq!(stream.audience(), ["receiver/s-1"]);
        assert_eq!(stream.events_supported(), ["a", "b"]);
        assert_eq!(stream.events_delivered(), ["a"]);
        assert_eq!(
            stream.delivery_endpoint_url().unwrap().as_str(),
            "https://t.example/poll"
        );
        let list_aud = SsfStreamConfiguration::new(json!({ "aud": ["x", "y"] }).as_object().unwrap().clone());
        assert_eq!(list_aud.audience(), ["x", "y"]);
        assert!(SsfStreamConfiguration::default().audience().is_empty());
    }
}
