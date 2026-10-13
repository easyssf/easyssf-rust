//! The vocabulary of the OpenID Shared Signals Framework (SSF 1.0), shared by receivers and
//! (later) transmitters: Security Event Tokens, subjects, event types, the typed CAEP, RISC and
//! SCIM events, stream configuration and transmitter metadata.
//!
//! Raw claims stay [`serde_json::Value`]s, typed accessors sit on top, as `JsonElement` does in
//! the .NET port. Values are immutable once built and cheap to clone where a receiver passes them
//! around ([`SsfEventToken`] holds an `Arc`).
//!
//! A port of `easyssf-core` of the Java library; the Java code and the specifications are the
//! reference for protocol behaviour.

pub mod caep;
pub mod event;
pub mod event_types;
pub mod metadata;
pub mod risc;
pub mod scim;
pub mod stream;
pub(crate) mod support;

pub use event::{SsfEventToken, SsfSubject, SsfSubjectIdentifier, SubjectCompatibilityMode};

/// How SETs get from the transmitter to the receiver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsfDeliveryMethod {
    /// The transmitter sends SETs to an endpoint of the receiver (RFC 8935).
    Push,
    /// The receiver fetches SETs from an endpoint of the transmitter (RFC 8936).
    Poll,
}

impl SsfDeliveryMethod {
    /// The identifier of the delivery method in a stream configuration.
    pub fn uri(self) -> &'static str {
        match self {
            Self::Push => "urn:ietf:rfc:8935",
            Self::Poll => "urn:ietf:rfc:8936",
        }
    }

    /// The delivery method with the given identifier, `None` for any other string.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            "urn:ietf:rfc:8935" => Some(Self::Push),
            "urn:ietf:rfc:8936" => Some(Self::Poll),
            _ => None,
        }
    }

    /// The lowercase name, for logs and metric tags: `push` or `poll`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::Poll => "poll",
        }
    }
}

impl std::fmt::Display for SsfDeliveryMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
