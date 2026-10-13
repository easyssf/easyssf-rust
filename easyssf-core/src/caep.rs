//! CAEP 1.0 events: the kinds of section 3 and typed access to their claims.

use std::collections::BTreeMap;
use std::time::SystemTime;

use serde_json::{Map, Value};

use crate::event::{SsfEventToken, event_timestamp};
use crate::event_types;
use crate::support::text_member;

/// The events of CAEP 1.0, section 3, and [`Other`](Self::Other) for an event type in the CAEP
/// namespace this version does not know. New variants are added as CAEP defines events, so do not
/// match over this enum exhaustively; implement `SsfCaepEventHandler` of the receiver instead.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsfCaepEventKind {
    /// The session was revoked (section 3.1).
    SessionRevoked,
    /// Claims of the token the subject identifies changed (section 3.2).
    TokenClaimsChange,
    /// A credential was created, revoked, updated or deleted (section 3.3).
    CredentialChange,
    /// The assurance level of the subject changed (section 3.4).
    AssuranceLevelChange,
    /// The compliance status of the device changed (section 3.5).
    DeviceComplianceChange,
    /// A session was established (section 3.6).
    SessionEstablished,
    /// A session was presented to the transmitter (section 3.7).
    SessionPresented,
    /// The risk level of the subject changed (section 3.8).
    RiskLevelChange,
    /// An event type in the CAEP namespace this version does not know, for example one of a later
    /// CAEP version. The common claims of CAEP section 2 are still available.
    Other,
}

impl SsfCaepEventKind {
    /// The known kinds and their event type URIs.
    pub const KNOWN: [(SsfCaepEventKind, &'static str); 8] = [
        (Self::SessionRevoked, event_types::CAEP_SESSION_REVOKED),
        (Self::TokenClaimsChange, event_types::CAEP_TOKEN_CLAIMS_CHANGE),
        (Self::CredentialChange, event_types::CAEP_CREDENTIAL_CHANGE),
        (Self::AssuranceLevelChange, event_types::CAEP_ASSURANCE_LEVEL_CHANGE),
        (Self::DeviceComplianceChange, event_types::CAEP_DEVICE_COMPLIANCE_CHANGE),
        (Self::SessionEstablished, event_types::CAEP_SESSION_ESTABLISHED),
        (Self::SessionPresented, event_types::CAEP_SESSION_PRESENTED),
        (Self::RiskLevelChange, event_types::CAEP_RISK_LEVEL_CHANGE),
    ];

    /// The event type URI, `None` for [`Other`](Self::Other).
    pub fn event_type(self) -> Option<&'static str> {
        Self::KNOWN.iter().find(|(kind, _)| *kind == self).map(|(_, uri)| *uri)
    }

    /// The kind of CAEP event of an event type URI or alias: [`Other`](Self::Other) for an
    /// unknown event type in the CAEP namespace, `None` if the event type is not a CAEP event.
    pub fn of(event_type: &str) -> Option<Self> {
        if !event_types::is_caep_event(event_type) {
            return None;
        }
        let uri = event_types::resolve(event_type);
        Some(
            Self::KNOWN
                .iter()
                .find(|(_, known)| *known == uri)
                .map(|(kind, _)| *kind)
                .unwrap_or(Self::Other),
        )
    }
}

/// A CAEP 1.0 event of a SET, with typed access to the claims every CAEP event may carry
/// (section 2: [`event_timestamp`](Self::event_timestamp),
/// [`initiating_entity`](Self::initiating_entity), [`reason_admin`](Self::reason_admin),
/// [`reason_user`](Self::reason_user)) and to the event-specific claims of section 3. An accessor
/// returns `None` (or an empty collection) when the claim is absent, whether because the
/// transmitter left it out or because the [`kind`](Self::kind) does not define it. The
/// [`payload`](Self::payload) is the event as received, for anything else.
///
/// The subject of the event is the `sub_id` of the SET, `SsfEventContext::subject()` in a
/// handler: CAEP does not prescribe a subject format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfCaepEvent {
    event_type: String,
    kind: SsfCaepEventKind,
    payload: Map<String, Value>,
}

impl SsfCaepEvent {
    /// The event of an event type URI or alias, `None` if the event type is not a CAEP event.
    pub fn of(event_type: &str, payload: Option<&Map<String, Value>>) -> Option<Self> {
        let kind = SsfCaepEventKind::of(event_type)?;
        Some(Self {
            event_type: event_types::resolve(event_type),
            kind,
            payload: payload.cloned().unwrap_or_default(),
        })
    }

    /// The CAEP events of a SET, in the order of its `events` claim. CAEP allows one event per
    /// SET; a SET with several is read like one of each.
    pub fn in_token(event_token: &SsfEventToken) -> Vec<Self> {
        event_token
            .events()
            .iter()
            .filter_map(|(event_type, payload)| {
                let kind = SsfCaepEventKind::of(event_type)?;
                Some(Self {
                    event_type: event_type.clone(),
                    kind,
                    payload: payload.as_object().cloned().unwrap_or_default(),
                })
            })
            .collect()
    }

    /// The event type URI.
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    /// The kind of event.
    pub fn kind(&self) -> SsfCaepEventKind {
        self.kind
    }

    /// The event payload as received.
    pub fn payload(&self) -> &Map<String, Value> {
        &self.payload
    }

    // CAEP section 2: claims every event may carry

    /// The `event_timestamp`, the time the event occurred. CAEP defines seconds since the epoch;
    /// a value that is clearly milliseconds is accepted too.
    pub fn event_timestamp(&self) -> Option<SystemTime> {
        event_timestamp(self.payload.get("event_timestamp"))
    }

    /// The `initiating_entity`, who invoked the event: `admin`, `user`, `policy` or `system`.
    pub fn initiating_entity(&self) -> Option<String> {
        self.string("initiating_entity")
    }

    /// The `reason_admin`, the reason for administrators, by BCP 47 language tag (`en`, `de-CH`,
    /// ...); empty if absent. A transmitter that sends a plain string instead of the localizable
    /// object of CAEP gets the key `""`.
    pub fn reason_admin(&self) -> BTreeMap<String, String> {
        self.localized("reason_admin")
    }

    /// The `reason_user`, the reason for display to the end user, by BCP 47 language tag; empty
    /// if absent, a plain string under the key `""`.
    pub fn reason_user(&self) -> BTreeMap<String, String> {
        self.localized("reason_user")
    }

    // CAEP section 3: event-specific claims

    /// The `claims` of a [`TokenClaimsChange`](SsfCaepEventKind::TokenClaimsChange), each with
    /// its new value.
    pub fn claims(&self) -> Option<&Map<String, Value>> {
        self.payload.get("claims").and_then(Value::as_object)
    }

    /// The `credential_type` of a [`CredentialChange`](SsfCaepEventKind::CredentialChange):
    /// `password`, `pin`, `x509`, `fido2-platform`, `fido2-roaming`, `fido-u2f`,
    /// `verifiable-credential`, `phone-voice`, `phone-sms`, `app` or a value agreed with the
    /// transmitter.
    pub fn credential_type(&self) -> Option<String> {
        self.string("credential_type")
    }

    /// The `change_type` of a [`CredentialChange`](SsfCaepEventKind::CredentialChange): `create`,
    /// `revoke`, `update` or `delete`.
    pub fn change_type(&self) -> Option<String> {
        self.string("change_type")
    }

    /// The `friendly_name` of the credential of a
    /// [`CredentialChange`](SsfCaepEventKind::CredentialChange).
    pub fn friendly_name(&self) -> Option<String> {
        self.string("friendly_name")
    }

    /// The `x509_issuer` of an X.509 credential.
    pub fn x509_issuer(&self) -> Option<String> {
        self.string("x509_issuer")
    }

    /// The `x509_serial` of an X.509 credential.
    pub fn x509_serial(&self) -> Option<String> {
        self.string("x509_serial")
    }

    /// The `fido2_aaguid`, the FIDO2 Authenticator Attestation GUID of the credential.
    pub fn fido2_aaguid(&self) -> Option<String> {
        self.string("fido2_aaguid")
    }

    /// The `namespace` of the levels of an
    /// [`AssuranceLevelChange`](SsfCaepEventKind::AssuranceLevelChange): `RFC8176`, `RFC6711`,
    /// `ISO-IEC-29115`, `NIST-IAL`, `NIST-AAL`, `NIST-FAL` or a value agreed with the transmitter.
    pub fn namespace(&self) -> Option<String> {
        self.string("namespace")
    }

    /// The `current_level`: the assurance level of an
    /// [`AssuranceLevelChange`](SsfCaepEventKind::AssuranceLevelChange) in its
    /// [`namespace`](Self::namespace), or the risk level of a
    /// [`RiskLevelChange`](SsfCaepEventKind::RiskLevelChange) (`LOW`, `MEDIUM`, `HIGH`).
    pub fn current_level(&self) -> Option<String> {
        self.string("current_level")
    }

    /// The `previous_level` of an assurance or risk level change, `None` if the transmitter does
    /// not know the previous level.
    pub fn previous_level(&self) -> Option<String> {
        self.string("previous_level")
    }

    /// The `change_direction` of an
    /// [`AssuranceLevelChange`](SsfCaepEventKind::AssuranceLevelChange): `increase` or `decrease`.
    pub fn change_direction(&self) -> Option<String> {
        self.string("change_direction")
    }

    /// The `current_status` of a
    /// [`DeviceComplianceChange`](SsfCaepEventKind::DeviceComplianceChange): `compliant` or
    /// `not-compliant`.
    pub fn current_status(&self) -> Option<String> {
        self.string("current_status")
    }

    /// The `previous_status` of a
    /// [`DeviceComplianceChange`](SsfCaepEventKind::DeviceComplianceChange).
    pub fn previous_status(&self) -> Option<String> {
        self.string("previous_status")
    }

    /// The `fp_ua`, the fingerprint of the user agent of a
    /// [`SessionEstablished`](SsfCaepEventKind::SessionEstablished) or
    /// [`SessionPresented`](SsfCaepEventKind::SessionPresented).
    pub fn fp_ua(&self) -> Option<String> {
        self.string("fp_ua")
    }

    /// The `acr`, the authentication context class reference of a
    /// [`SessionEstablished`](SsfCaepEventKind::SessionEstablished), as in an ID Token.
    pub fn acr(&self) -> Option<String> {
        self.string("acr")
    }

    /// The `amr`, the authentication methods references of a
    /// [`SessionEstablished`](SsfCaepEventKind::SessionEstablished), as in an ID Token; empty if
    /// absent.
    pub fn amr(&self) -> Vec<String> {
        crate::support::strings_member(&self.payload, "amr")
    }

    /// The `ext_id`, the external session identifier of a
    /// [`SessionEstablished`](SsfCaepEventKind::SessionEstablished) or
    /// [`SessionPresented`](SsfCaepEventKind::SessionPresented) that correlates it with a broader
    /// session, for example a SAML one.
    pub fn ext_id(&self) -> Option<String> {
        self.string("ext_id")
    }

    /// The `principal` of a [`RiskLevelChange`](SsfCaepEventKind::RiskLevelChange), the entity
    /// whose risk changed: `USER`, `DEVICE`, `SESSION`, `TENANT`, `ORG_UNIT`, `GROUP` or another
    /// entity of SSF.
    pub fn principal(&self) -> Option<String> {
        self.string("principal")
    }

    /// The `risk_reason` of a [`RiskLevelChange`](SsfCaepEventKind::RiskLevelChange).
    pub fn risk_reason(&self) -> Option<String> {
        self.string("risk_reason")
    }

    fn string(&self, name: &str) -> Option<String> {
        text_member(&self.payload, name)
    }

    fn localized(&self, name: &str) -> BTreeMap<String, String> {
        match self.payload.get(name) {
            Some(Value::Object(by_language)) => by_language
                .iter()
                .filter(|(_, text)| !text.is_null())
                .map(|(language, text)| {
                    let text = match text {
                        Value::String(text) => text.clone(),
                        other => other.to_string(),
                    };
                    (language.clone(), text)
                })
                .collect(),
            None | Some(Value::Null) => BTreeMap::new(),
            Some(Value::String(text)) => BTreeMap::from([(String::new(), text.clone())]),
            Some(other) => BTreeMap::from([(String::new(), other.to_string())]),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use serde_json::json;

    use super::*;

    fn token(events: Value) -> SsfEventToken {
        let claims = json!({ "jti": "1", "iss": "https://t.example", "iat": 1700000000, "events": events });
        SsfEventToken::from_claims(claims.as_object().unwrap().clone()).unwrap()
    }

    #[test]
    fn every_caep_event_type_has_a_kind_and_an_alias() {
        for (kind, uri) in SsfCaepEventKind::KNOWN {
            assert_eq!(SsfCaepEventKind::of(uri), Some(kind));
            assert_eq!(kind.event_type(), Some(uri));
            assert_ne!(event_types::alias_of(uri), uri, "{uri} has no alias");
            assert_eq!(SsfCaepEventKind::of(&event_types::alias_of(uri)), Some(kind));
        }
        assert_eq!(SsfCaepEventKind::Other.event_type(), None);
    }

    #[test]
    fn unknown_event_type_in_the_caep_namespace_is_other_and_anything_else_is_not_caep() {
        assert_eq!(
            SsfCaepEventKind::of("https://schemas.openid.net/secevent/caep/event-type/future"),
            Some(SsfCaepEventKind::Other)
        );
        assert_eq!(SsfCaepEventKind::of("RiscAccountDisabled"), None);
        assert_eq!(SsfCaepEventKind::of("https://events.acme.example/login"), None);
    }

    #[test]
    fn common_claims_of_section2_are_typed_for_every_kind() {
        let payload = json!({
            "event_timestamp": 1700000000,
            "initiating_entity": "admin",
            "reason_admin": { "en": "Landspeed violation", "de": "Zu schnell" },
            "reason_user": { "en": "You moved too fast" }
        });
        for (kind, uri) in SsfCaepEventKind::KNOWN {
            let event = SsfCaepEvent::of(uri, payload.as_object()).unwrap();
            assert_eq!(event.kind(), kind);
            assert_eq!(
                event.event_timestamp(),
                Some(UNIX_EPOCH + Duration::from_secs(1700000000))
            );
            assert_eq!(event.initiating_entity().as_deref(), Some("admin"));
            assert_eq!(event.reason_admin()["de"], "Zu schnell");
            assert_eq!(event.reason_user()["en"], "You moved too fast");
        }
    }

    #[test]
    fn absent_common_claims_are_none_or_empty_and_milliseconds_are_tolerated() {
        let event = SsfCaepEvent::of("CaepSessionRevoked", None).unwrap();
        assert_eq!(event.event_timestamp(), None);
        assert_eq!(event.initiating_entity(), None);
        assert!(event.reason_admin().is_empty());
        assert!(event.amr().is_empty());
        assert!(event.claims().is_none());
        let millis = json!({ "event_timestamp": 1700000000123_i64 });
        let event = SsfCaepEvent::of("CaepSessionRevoked", millis.as_object()).unwrap();
        assert_eq!(
            event.event_timestamp(),
            Some(UNIX_EPOCH + Duration::from_secs(1700000000))
        );
    }

    #[test]
    fn plain_string_reason_is_kept_under_the_empty_language_tag() {
        let payload = json!({ "reason_admin": "Policy", "reason_user": 42 });
        let event = SsfCaepEvent::of("CaepSessionRevoked", payload.as_object()).unwrap();
        assert_eq!(event.reason_admin()[""], "Policy");
        assert_eq!(event.reason_user()[""], "42");
    }

    #[test]
    fn token_claims_change_carries_the_new_claims() {
        let payload = json!({ "claims": { "role": "ro", "level": 2 } });
        let event = SsfCaepEvent::of("CaepTokenClaimsChange", payload.as_object()).unwrap();
        assert_eq!(event.claims().unwrap()["role"], "ro");
        assert_eq!(event.claims().unwrap()["level"], 2);
    }

    #[test]
    fn credential_change_names_the_credential() {
        let payload = json!({
            "credential_type": "fido2-roaming", "change_type": "create", "friendly_name": "Yubikey",
            "x509_issuer": "CN=CA", "x509_serial": "1234", "fido2_aaguid": "aaguid"
        });
        let event = SsfCaepEvent::of("CaepCredentialChange", payload.as_object()).unwrap();
        assert_eq!(event.credential_type().as_deref(), Some("fido2-roaming"));
        assert_eq!(event.change_type().as_deref(), Some("create"));
        assert_eq!(event.friendly_name().as_deref(), Some("Yubikey"));
        assert_eq!(event.x509_issuer().as_deref(), Some("CN=CA"));
        assert_eq!(event.x509_serial().as_deref(), Some("1234"));
        assert_eq!(event.fido2_aaguid().as_deref(), Some("aaguid"));
    }

    #[test]
    fn assurance_level_change_has_namespace_levels_and_direction() {
        let payload = json!({ "namespace": "NIST-AAL", "current_level": "nist-aal1", "previous_level": "nist-aal2", "change_direction": "decrease" });
        let event = SsfCaepEvent::of("CaepAssuranceLevelChange", payload.as_object()).unwrap();
        assert_eq!(event.namespace().as_deref(), Some("NIST-AAL"));
        assert_eq!(event.current_level().as_deref(), Some("nist-aal1"));
        assert_eq!(event.previous_level().as_deref(), Some("nist-aal2"));
        assert_eq!(event.change_direction().as_deref(), Some("decrease"));
    }

    #[test]
    fn device_compliance_change_has_both_statuses() {
        let payload = json!({ "current_status": "not-compliant", "previous_status": "compliant" });
        let event = SsfCaepEvent::of("CaepDeviceComplianceChange", payload.as_object()).unwrap();
        assert_eq!(event.current_status().as_deref(), Some("not-compliant"));
        assert_eq!(event.previous_status().as_deref(), Some("compliant"));
    }

    #[test]
    fn session_events_describe_the_session() {
        let payload = json!({ "fp_ua": "abc", "acr": "urn:acr", "amr": ["pwd", "otp", 3], "ext_id": "saml-1" });
        let event = SsfCaepEvent::of("CaepSessionEstablished", payload.as_object()).unwrap();
        assert_eq!(event.fp_ua().as_deref(), Some("abc"));
        assert_eq!(event.acr().as_deref(), Some("urn:acr"));
        assert_eq!(event.amr(), ["pwd", "otp"]);
        assert_eq!(event.ext_id().as_deref(), Some("saml-1"));
        let presented = SsfCaepEvent::of("CaepSessionPresented", payload.as_object()).unwrap();
        assert_eq!(presented.kind(), SsfCaepEventKind::SessionPresented);
    }

    #[test]
    fn risk_level_change_names_the_principal_and_the_levels() {
        let payload = json!({ "principal": "USER", "current_level": "HIGH", "previous_level": "LOW", "risk_reason": "Credential stuffing" });
        let event = SsfCaepEvent::of("CaepRiskLevelChange", payload.as_object()).unwrap();
        assert_eq!(event.principal().as_deref(), Some("USER"));
        assert_eq!(event.current_level().as_deref(), Some("HIGH"));
        assert_eq!(event.previous_level().as_deref(), Some("LOW"));
        assert_eq!(event.risk_reason().as_deref(), Some("Credential stuffing"));
    }

    #[test]
    fn finds_all_caep_events_of_a_set_in_order_and_ignores_others() {
        let set = token(json!({
            "https://schemas.openid.net/secevent/caep/event-type/session-revoked": { "event_timestamp": 1 },
            "https://schemas.openid.net/secevent/risc/event-type/account-disabled": {},
            "https://schemas.openid.net/secevent/caep/event-type/future": "not an object",
            "https://schemas.openid.net/secevent/caep/event-type/credential-change": { "change_type": "revoke" }
        }));
        let events = SsfCaepEvent::in_token(&set);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].kind(), SsfCaepEventKind::SessionRevoked);
        assert_eq!(events[1].kind(), SsfCaepEventKind::Other);
        assert!(events[1].payload().is_empty());
        assert_eq!(events[2].change_type().as_deref(), Some("revoke"));
        assert!(SsfCaepEvent::in_token(&token(json!({ "RiscAccountDisabled": {} }))).is_empty());
    }

    #[test]
    fn of_resolves_aliases_and_rejects_other_event_types() {
        let event = SsfCaepEvent::of("CaepSessionRevoked", None).unwrap();
        assert_eq!(event.event_type(), event_types::CAEP_SESSION_REVOKED);
        assert!(SsfCaepEvent::of("RiscAccountDisabled", None).is_none());
        assert!(SsfCaepEvent::of("https://events.acme.example/login", None).is_none());
    }
}
