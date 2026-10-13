//! RISC 1.0 events: the kinds of section 2 and typed access to their few attributes.

use std::time::SystemTime;

use serde_json::{Map, Value};

use crate::event::{SsfEventToken, event_timestamp};
use crate::event_types;
use crate::support::text_member;

/// The events of RISC 1.0, section 2, and [`Other`](Self::Other) for an event type in the RISC
/// namespace this version does not know. New variants are added as RISC defines events, so do not
/// match over this enum exhaustively; implement `SsfRiscEventHandler` of the receiver instead.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsfRiscEventKind {
    /// The account has to change its credential, for example after a leak elsewhere (section
    /// 2.1).
    AccountCredentialChangeRequired,
    /// The account was permanently deleted (section 2.2).
    AccountPurged,
    /// The account was disabled, see [`SsfRiscEvent::reason`] (section 2.3).
    AccountDisabled,
    /// The account was enabled again (section 2.4).
    AccountEnabled,
    /// The identifier of the subject, an email address or phone number, changed to
    /// [`SsfRiscEvent::new_value`] (section 2.5).
    IdentifierChanged,
    /// The identifier was given to someone else (section 2.6).
    IdentifierRecycled,
    /// A credential of the subject was found compromised, see [`SsfRiscEvent::credential_type`]
    /// (section 2.7).
    CredentialCompromise,
    /// The account takes part in the RISC exchange (section 2.8.1).
    OptIn,
    /// The user asked to leave the RISC exchange (section 2.8.2).
    OptOutInitiated,
    /// The user withdrew the request to leave (section 2.8.3).
    OptOutCancelled,
    /// The account left the RISC exchange (section 2.8.4).
    OptOutEffective,
    /// The account went through a recovery flow (section 2.9).
    RecoveryActivated,
    /// The recovery information of the account changed (section 2.10).
    RecoveryInformationChanged,
    /// All sessions of the account were revoked (section 2.11). Deprecated by RISC in favour of
    /// CAEP's `session-revoked`, still sent by some transmitters.
    SessionsRevoked,
    /// An event type in the RISC namespace this version does not know.
    Other,
}

impl SsfRiscEventKind {
    /// The known kinds and their event type URIs.
    pub const KNOWN: [(SsfRiscEventKind, &'static str); 14] = [
        (
            Self::AccountCredentialChangeRequired,
            event_types::RISC_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED,
        ),
        (Self::AccountPurged, event_types::RISC_ACCOUNT_PURGED),
        (Self::AccountDisabled, event_types::RISC_ACCOUNT_DISABLED),
        (Self::AccountEnabled, event_types::RISC_ACCOUNT_ENABLED),
        (Self::IdentifierChanged, event_types::RISC_IDENTIFIER_CHANGED),
        (Self::IdentifierRecycled, event_types::RISC_IDENTIFIER_RECYCLED),
        (Self::CredentialCompromise, event_types::RISC_CREDENTIAL_COMPROMISE),
        (Self::OptIn, event_types::RISC_OPT_IN),
        (Self::OptOutInitiated, event_types::RISC_OPT_OUT_INITIATED),
        (Self::OptOutCancelled, event_types::RISC_OPT_OUT_CANCELLED),
        (Self::OptOutEffective, event_types::RISC_OPT_OUT_EFFECTIVE),
        (Self::RecoveryActivated, event_types::RISC_RECOVERY_ACTIVATED),
        (
            Self::RecoveryInformationChanged,
            event_types::RISC_RECOVERY_INFORMATION_CHANGED,
        ),
        (Self::SessionsRevoked, event_types::RISC_SESSIONS_REVOKED),
    ];

    /// The event type URI, `None` for [`Other`](Self::Other).
    pub fn event_type(self) -> Option<&'static str> {
        Self::KNOWN.iter().find(|(kind, _)| *kind == self).map(|(_, uri)| *uri)
    }

    /// Whether this is one of the opt-in and opt-out events of section 2.8, which report the
    /// participation of the account in the exchange rather than a risk.
    pub fn is_opt_out_state(self) -> bool {
        matches!(
            self,
            Self::OptIn | Self::OptOutInitiated | Self::OptOutCancelled | Self::OptOutEffective
        )
    }

    /// The kind of RISC event of an event type URI or alias: [`Other`](Self::Other) for an
    /// unknown event type in the RISC namespace, `None` if the event type is not a RISC event.
    pub fn of(event_type: &str) -> Option<Self> {
        if !event_types::is_risc_event(event_type) {
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

/// A RISC 1.0 event of a SET, with typed access to the few attributes RISC defines: the
/// [`reason`](Self::reason) of an account-disabled, the [`new_value`](Self::new_value) of an
/// identifier-changed, and the [`credential_type`](Self::credential_type),
/// [`event_timestamp`](Self::event_timestamp) and reasons of a credential-compromise. Most RISC
/// events have no attributes; the [`payload`](Self::payload) is the event as received for
/// anything else.
///
/// The subject of the event is the `sub_id` of the SET, `SsfEventContext::subject()` in a
/// handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfRiscEvent {
    event_type: String,
    kind: SsfRiscEventKind,
    payload: Map<String, Value>,
}

impl SsfRiscEvent {
    /// The event of an event type URI or alias, `None` if the event type is not a RISC event.
    pub fn of(event_type: &str, payload: Option<&Map<String, Value>>) -> Option<Self> {
        let kind = SsfRiscEventKind::of(event_type)?;
        Some(Self {
            event_type: event_types::resolve(event_type),
            kind,
            payload: payload.cloned().unwrap_or_default(),
        })
    }

    /// The RISC events of a SET, in the order of its `events` claim.
    pub fn in_token(event_token: &SsfEventToken) -> Vec<Self> {
        event_token
            .events()
            .iter()
            .filter_map(|(event_type, payload)| {
                let kind = SsfRiscEventKind::of(event_type)?;
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
    pub fn kind(&self) -> SsfRiscEventKind {
        self.kind
    }

    /// The event payload as received.
    pub fn payload(&self) -> &Map<String, Value> {
        &self.payload
    }

    /// The `reason` of an [`AccountDisabled`](SsfRiscEventKind::AccountDisabled): `hijacking` or
    /// `bulk-account`.
    pub fn reason(&self) -> Option<String> {
        self.string("reason")
    }

    /// The `new-value` of an [`IdentifierChanged`](SsfRiscEventKind::IdentifierChanged), the new
    /// identifier.
    pub fn new_value(&self) -> Option<String> {
        self.string("new-value")
    }

    /// The `credential_type` of a [`CredentialCompromise`](SsfRiscEventKind::CredentialCompromise),
    /// one of the values of CAEP's credential-change (`password`, `pin`, `x509`, ...).
    pub fn credential_type(&self) -> Option<String> {
        self.string("credential_type")
    }

    /// The `event_timestamp` of a [`CredentialCompromise`](SsfRiscEventKind::CredentialCompromise),
    /// when the transmitter discovered the compromise. RISC defines seconds since the epoch; a
    /// value that is clearly milliseconds is accepted too.
    pub fn event_timestamp(&self) -> Option<SystemTime> {
        event_timestamp(self.payload.get("event_timestamp"))
    }

    /// The `reason_admin` of a [`CredentialCompromise`](SsfRiscEventKind::CredentialCompromise),
    /// the reason for administrators. RISC leaves the type open; a localizable object as CAEP
    /// defines it is returned as its JSON text.
    pub fn reason_admin(&self) -> Option<String> {
        self.string("reason_admin")
    }

    /// The `reason_user` of a [`CredentialCompromise`](SsfRiscEventKind::CredentialCompromise),
    /// the reason for the end user.
    pub fn reason_user(&self) -> Option<String> {
        self.string("reason_user")
    }

    fn string(&self, name: &str) -> Option<String> {
        text_member(&self.payload, name)
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
    fn every_risc_event_type_has_a_kind_and_an_alias() {
        for (kind, uri) in SsfRiscEventKind::KNOWN {
            assert_eq!(SsfRiscEventKind::of(uri), Some(kind));
            assert_eq!(kind.event_type(), Some(uri));
            assert_ne!(event_types::alias_of(uri), uri, "{uri} has no alias");
        }
    }

    #[test]
    fn unknown_event_type_in_the_risc_namespace_is_other_and_anything_else_is_not_risc() {
        assert_eq!(
            SsfRiscEventKind::of("https://schemas.openid.net/secevent/risc/event-type/future"),
            Some(SsfRiscEventKind::Other)
        );
        assert_eq!(SsfRiscEventKind::of("CaepSessionRevoked"), None);
    }

    #[test]
    fn opt_in_and_opt_out_events_report_the_participation() {
        assert!(SsfRiscEventKind::OptIn.is_opt_out_state());
        assert!(SsfRiscEventKind::OptOutInitiated.is_opt_out_state());
        assert!(SsfRiscEventKind::OptOutCancelled.is_opt_out_state());
        assert!(SsfRiscEventKind::OptOutEffective.is_opt_out_state());
        assert!(!SsfRiscEventKind::AccountDisabled.is_opt_out_state());
    }

    #[test]
    fn account_disabled_may_carry_a_reason() {
        let event = SsfRiscEvent::of("RiscAccountDisabled", json!({ "reason": "hijacking" }).as_object()).unwrap();
        assert_eq!(event.reason().as_deref(), Some("hijacking"));
        assert_eq!(SsfRiscEvent::of("RiscAccountDisabled", None).unwrap().reason(), None);
    }

    #[test]
    fn identifier_changed_may_carry_the_new_value() {
        let event = SsfRiscEvent::of(
            "RiscIdentifierChanged",
            json!({ "new-value": "new@example.com" }).as_object(),
        )
        .unwrap();
        assert_eq!(event.new_value().as_deref(), Some("new@example.com"));
    }

    #[test]
    fn credential_compromise_names_the_credential_and_when_it_was_found() {
        let payload = json!({ "credential_type": "password", "event_timestamp": 1700000000, "reason_admin": { "en": "leak" }, "reason_user": "Change it" });
        let event = SsfRiscEvent::of("RiscCredentialCompromise", payload.as_object()).unwrap();
        assert_eq!(event.credential_type().as_deref(), Some("password"));
        assert_eq!(
            event.event_timestamp(),
            Some(UNIX_EPOCH + Duration::from_secs(1700000000))
        );
        assert_eq!(event.reason_admin().as_deref(), Some(r#"{"en":"leak"}"#));
        assert_eq!(event.reason_user().as_deref(), Some("Change it"));
    }

    #[test]
    fn events_without_attributes_have_an_empty_payload() {
        let event = SsfRiscEvent::of("RiscAccountPurged", None).unwrap();
        assert!(event.payload().is_empty());
        assert_eq!(event.reason(), None);
        assert_eq!(event.event_timestamp(), None);
    }

    #[test]
    fn finds_all_risc_events_of_a_set_in_order_and_ignores_others() {
        let set = token(json!({
            "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {},
            "https://schemas.openid.net/secevent/risc/event-type/account-disabled": { "reason": "hijacking" },
            "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked": {}
        }));
        let events = SsfRiscEvent::in_token(&set);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind(), SsfRiscEventKind::AccountDisabled);
        assert_eq!(events[1].kind(), SsfRiscEventKind::SessionsRevoked);
    }

    #[test]
    fn of_resolves_aliases_and_rejects_other_event_types() {
        let event = SsfRiscEvent::of("RiscAccountEnabled", None).unwrap();
        assert_eq!(event.event_type(), event_types::RISC_ACCOUNT_ENABLED);
        assert!(SsfRiscEvent::of("CaepSessionRevoked", None).is_none());
    }
}
