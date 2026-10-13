//! The transmitter configuration metadata (SSF 1.0, section 7.1).

use serde_json::{Map, Value};
use url::Url;

use crate::SsfDeliveryMethod;
use crate::support::{string_member, strings_member};

/// The transmitter configuration metadata published at `.well-known/ssf-configuration` (SSF 1.0,
/// section 7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfTransmitterMetadata {
    issuer: String,
    jwks_uri: Option<Url>,
    claims: Map<String, Value>,
}

impl SsfTransmitterMetadata {
    /// The `spec_version` of the final SSF 1.0 specification.
    pub const SPEC_VERSION_1_0: &'static str = "1_0";

    /// Metadata of a transmitter: its issuer, the location of its JWK Set if any, and all members
    /// of the metadata document.
    pub fn new(issuer: impl Into<String>, jwks_uri: Option<Url>, claims: Map<String, Value>) -> Self {
        Self {
            issuer: issuer.into(),
            jwks_uri,
            claims,
        }
    }

    /// The transmitter issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Location of the transmitter's JWK Set, `None` if the metadata has none.
    pub fn jwks_uri(&self) -> Option<&Url> {
        self.jwks_uri.as_ref()
    }

    /// All members of the metadata document.
    pub fn claims(&self) -> &Map<String, Value> {
        &self.claims
    }

    /// The version of the specification the transmitter implements (`spec_version`), `None` if
    /// the transmitter does not say.
    pub fn spec_version(&self) -> Option<&str> {
        string_member(&self.claims, "spec_version")
    }

    /// The delivery method URIs the transmitter supports (`delivery_methods_supported`), empty if
    /// the transmitter does not say.
    pub fn delivery_methods_supported(&self) -> Vec<String> {
        strings_member(&self.claims, "delivery_methods_supported")
    }

    /// Whether the transmitter supports the delivery method; `true` as well if it does not say
    /// which methods it supports.
    pub fn supports_delivery_method(&self, method: SsfDeliveryMethod) -> bool {
        let supported = self.delivery_methods_supported();
        supported.is_empty() || supported.iter().any(|uri| uri == method.uri())
    }

    /// The members of a complex subject the transmitter requires to be understood
    /// (`critical_subject_members`), empty if none.
    pub fn critical_subject_members(&self) -> Vec<String> {
        strings_member(&self.claims, "critical_subject_members")
    }

    /// The authorization schemes of the management endpoints (`authorization_schemes`), each with
    /// a `spec_urn`, empty if the transmitter does not say.
    pub fn authorization_schemes(&self) -> Vec<Map<String, Value>> {
        match self.claims.get("authorization_schemes") {
            Some(Value::Array(schemes)) => schemes.iter().filter_map(Value::as_object).cloned().collect(),
            _ => Vec::new(),
        }
    }

    /// Which subjects a stream receives events for by default (`default_subjects`): `ALL` or
    /// `NONE`, `None` if the transmitter does not say.
    pub fn default_subjects(&self) -> Option<&str> {
        string_member(&self.claims, "default_subjects")
    }

    /// Endpoint to create, read, update and delete streams.
    pub fn configuration_endpoint(&self) -> Option<Url> {
        self.url("configuration_endpoint")
    }

    /// Endpoint to read and update the status of a stream.
    pub fn status_endpoint(&self) -> Option<Url> {
        self.url("status_endpoint")
    }

    /// Endpoint to add subjects to a stream.
    pub fn add_subject_endpoint(&self) -> Option<Url> {
        self.url("add_subject_endpoint")
    }

    /// Endpoint to remove subjects from a stream.
    pub fn remove_subject_endpoint(&self) -> Option<Url> {
        self.url("remove_subject_endpoint")
    }

    /// Endpoint to request a verification event.
    pub fn verification_endpoint(&self) -> Option<Url> {
        self.url("verification_endpoint")
    }

    fn url(&self, name: &str) -> Option<Url> {
        string_member(&self.claims, name).and_then(|value| Url::parse(value).ok())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn exposes_the_members_of_the_final_specification() {
        let claims = json!({
            "issuer": "https://t.example",
            "jwks_uri": "https://t.example/jwks",
            "spec_version": "1_0",
            "delivery_methods_supported": ["urn:ietf:rfc:8935"],
            "critical_subject_members": ["tenant"],
            "authorization_schemes": [{ "spec_urn": "urn:ietf:rfc:6749" }],
            "default_subjects": "ALL",
            "configuration_endpoint": "https://t.example/streams",
            "status_endpoint": "https://t.example/status",
            "add_subject_endpoint": "https://t.example/add",
            "remove_subject_endpoint": "https://t.example/remove",
            "verification_endpoint": "https://t.example/verify"
        });
        let metadata = SsfTransmitterMetadata::new(
            "https://t.example",
            Some(Url::parse("https://t.example/jwks").unwrap()),
            claims.as_object().unwrap().clone(),
        );
        assert_eq!(metadata.issuer(), "https://t.example");
        assert_eq!(metadata.jwks_uri().unwrap().as_str(), "https://t.example/jwks");
        assert_eq!(metadata.spec_version(), Some(SsfTransmitterMetadata::SPEC_VERSION_1_0));
        assert_eq!(metadata.delivery_methods_supported(), ["urn:ietf:rfc:8935"]);
        assert!(metadata.supports_delivery_method(SsfDeliveryMethod::Push));
        assert!(!metadata.supports_delivery_method(SsfDeliveryMethod::Poll));
        assert_eq!(metadata.critical_subject_members(), ["tenant"]);
        assert_eq!(metadata.authorization_schemes()[0]["spec_urn"], "urn:ietf:rfc:6749");
        assert_eq!(metadata.default_subjects(), Some("ALL"));
        assert_eq!(
            metadata.configuration_endpoint().unwrap().as_str(),
            "https://t.example/streams"
        );
        assert_eq!(metadata.status_endpoint().unwrap().as_str(), "https://t.example/status");
        assert_eq!(
            metadata.add_subject_endpoint().unwrap().as_str(),
            "https://t.example/add"
        );
        assert_eq!(
            metadata.remove_subject_endpoint().unwrap().as_str(),
            "https://t.example/remove"
        );
        assert_eq!(
            metadata.verification_endpoint().unwrap().as_str(),
            "https://t.example/verify"
        );
    }

    #[test]
    fn absent_members_are_empty_and_every_delivery_method_is_assumed_to_be_supported() {
        let metadata = SsfTransmitterMetadata::new("https://t.example", None, Map::new());
        assert!(metadata.jwks_uri().is_none());
        assert_eq!(metadata.spec_version(), None);
        assert!(metadata.delivery_methods_supported().is_empty());
        assert!(metadata.supports_delivery_method(SsfDeliveryMethod::Poll));
        assert!(metadata.critical_subject_members().is_empty());
        assert!(metadata.authorization_schemes().is_empty());
        assert_eq!(metadata.default_subjects(), None);
        assert!(metadata.configuration_endpoint().is_none());
        assert!(metadata.verification_endpoint().is_none());
    }

    #[test]
    fn claims_are_copied() {
        let mut claims = Map::new();
        claims.insert("x".to_owned(), json!(1));
        let metadata = SsfTransmitterMetadata::new("i", None, claims.clone());
        claims.insert("y".to_owned(), json!(2));
        assert_eq!(metadata.claims().len(), 1);
    }
}
