//! Event type URIs defined by OpenID SSF, CAEP and RISC, and by SCIM Events (RFC 9967), together
//! with short aliases (for example `CaepSessionRevoked`) that can be used wherever an event type
//! is expected.
//!
//! Event types are identified by their URIs; the aliases are a convenience of easyssf, the family
//! and the event name in PascalCase. Both forms are accepted wherever an event type is named;
//! [`resolve`] goes from one to the other. Vendor specific event types get aliases of their own
//! with [`register_alias`].

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{OnceLock, RwLock};

const SSF: &str = "https://schemas.openid.net/secevent/ssf/event-type/";
const CAEP: &str = "https://schemas.openid.net/secevent/caep/event-type/";
const RISC: &str = "https://schemas.openid.net/secevent/risc/event-type/";
const SCIM: &str = "urn:ietf:params:scim:event:";

/// SSF 1.0, section 8.1.4.1: the stream verification event.
pub const SSF_STREAM_VERIFICATION: &str = "https://schemas.openid.net/secevent/ssf/event-type/verification";
/// SSF 1.0, section 8.1.4.2: the stream was updated.
pub const SSF_STREAM_UPDATED: &str = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated";
/// CAEP 1.0, section 3.1.
pub const CAEP_SESSION_REVOKED: &str = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
/// CAEP 1.0, section 3.2.
pub const CAEP_TOKEN_CLAIMS_CHANGE: &str = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change";
/// CAEP 1.0, section 3.3.
pub const CAEP_CREDENTIAL_CHANGE: &str = "https://schemas.openid.net/secevent/caep/event-type/credential-change";
/// CAEP 1.0, section 3.4.
pub const CAEP_ASSURANCE_LEVEL_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change";
/// CAEP 1.0, section 3.5.
pub const CAEP_DEVICE_COMPLIANCE_CHANGE: &str =
    "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change";
/// CAEP 1.0, section 3.6.
pub const CAEP_SESSION_ESTABLISHED: &str = "https://schemas.openid.net/secevent/caep/event-type/session-established";
/// CAEP 1.0, section 3.7.
pub const CAEP_SESSION_PRESENTED: &str = "https://schemas.openid.net/secevent/caep/event-type/session-presented";
/// CAEP 1.0, section 3.8.
pub const CAEP_RISK_LEVEL_CHANGE: &str = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change";
/// RISC 1.0, section 2.1.
pub const RISC_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED: &str =
    "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required";
/// RISC 1.0, section 2.2.
pub const RISC_ACCOUNT_PURGED: &str = "https://schemas.openid.net/secevent/risc/event-type/account-purged";
/// RISC 1.0, section 2.3.
pub const RISC_ACCOUNT_DISABLED: &str = "https://schemas.openid.net/secevent/risc/event-type/account-disabled";
/// RISC 1.0, section 2.4.
pub const RISC_ACCOUNT_ENABLED: &str = "https://schemas.openid.net/secevent/risc/event-type/account-enabled";
/// RISC 1.0, section 2.5.
pub const RISC_IDENTIFIER_CHANGED: &str = "https://schemas.openid.net/secevent/risc/event-type/identifier-changed";
/// RISC 1.0, section 2.6.
pub const RISC_IDENTIFIER_RECYCLED: &str = "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled";
/// RISC 1.0, section 2.7.
pub const RISC_CREDENTIAL_COMPROMISE: &str =
    "https://schemas.openid.net/secevent/risc/event-type/credential-compromise";
/// RISC 1.0, section 2.8.1.
pub const RISC_OPT_IN: &str = "https://schemas.openid.net/secevent/risc/event-type/opt-in";
/// RISC 1.0, section 2.8.2.
pub const RISC_OPT_OUT_INITIATED: &str = "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated";
/// RISC 1.0, section 2.8.3.
pub const RISC_OPT_OUT_CANCELLED: &str = "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled";
/// RISC 1.0, section 2.8.4.
pub const RISC_OPT_OUT_EFFECTIVE: &str = "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective";
/// RISC 1.0, section 2.9.
pub const RISC_RECOVERY_ACTIVATED: &str = "https://schemas.openid.net/secevent/risc/event-type/recovery-activated";
/// RISC 1.0, section 2.10.
pub const RISC_RECOVERY_INFORMATION_CHANGED: &str =
    "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed";
/// RISC 1.0, section 2.11: all sessions of the account were revoked. Deprecated by RISC in favour
/// of [`CAEP_SESSION_REVOKED`], but still emitted by some transmitters.
pub const RISC_SESSIONS_REVOKED: &str = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked";
/// SCIM Events (RFC 9967, section 2.3.1): the resource was added to the event feed.
pub const SCIM_FEED_ADD: &str = "urn:ietf:params:scim:event:feed:add";
/// SCIM Events (RFC 9967, section 2.3.2): the resource was removed from the event feed.
pub const SCIM_FEED_REMOVE: &str = "urn:ietf:params:scim:event:feed:remove";
/// SCIM Events (RFC 9967, section 2.4.1): a resource was created, the payload lists the
/// `attributes` set.
pub const SCIM_PROV_CREATE_NOTICE: &str = "urn:ietf:params:scim:event:prov:create:notice";
/// SCIM Events (RFC 9967, section 2.4.1): a resource was created, the payload carries its
/// representation as `data`.
pub const SCIM_PROV_CREATE_FULL: &str = "urn:ietf:params:scim:event:prov:create:full";
/// SCIM Events (RFC 9967, section 2.4.2): a resource was modified with SCIM PATCH, the payload
/// lists the `attributes` modified.
pub const SCIM_PROV_PATCH_NOTICE: &str = "urn:ietf:params:scim:event:prov:patch:notice";
/// SCIM Events (RFC 9967, section 2.4.2): a resource was modified with SCIM PATCH, the payload
/// carries the patch operations as `data`.
pub const SCIM_PROV_PATCH_FULL: &str = "urn:ietf:params:scim:event:prov:patch:full";
/// SCIM Events (RFC 9967, section 2.4.3): a resource was replaced with SCIM PUT, the payload lists
/// the `attributes` modified.
pub const SCIM_PROV_PUT_NOTICE: &str = "urn:ietf:params:scim:event:prov:put:notice";
/// SCIM Events (RFC 9967, section 2.4.3): a resource was replaced with SCIM PUT, the payload
/// carries the new representation as `data`.
pub const SCIM_PROV_PUT_FULL: &str = "urn:ietf:params:scim:event:prov:put:full";
/// SCIM Events (RFC 9967, section 2.4.4): the resource was deleted.
pub const SCIM_PROV_DELETE: &str = "urn:ietf:params:scim:event:prov:delete";
/// SCIM Events (RFC 9967, section 2.4.5): the resource was activated.
pub const SCIM_PROV_ACTIVATE: &str = "urn:ietf:params:scim:event:prov:activate";
/// SCIM Events (RFC 9967, section 2.4.6): the resource was deactivated, typically its user may no
/// longer have an active session.
pub const SCIM_PROV_DEACTIVATE: &str = "urn:ietf:params:scim:event:prov:deactivate";
/// SCIM Events (RFC 9967, section 2.5.1.3): an asynchronous SCIM request completed.
pub const SCIM_MISC_ASYNC_RESPONSE: &str = "urn:ietf:params:scim:event:misc:asyncresp";

const BUILT_IN: &[(&str, &str)] = &[
    ("SsfStreamVerification", SSF_STREAM_VERIFICATION),
    ("SsfStreamUpdated", SSF_STREAM_UPDATED),
    ("CaepSessionRevoked", CAEP_SESSION_REVOKED),
    ("CaepTokenClaimsChange", CAEP_TOKEN_CLAIMS_CHANGE),
    ("CaepCredentialChange", CAEP_CREDENTIAL_CHANGE),
    ("CaepAssuranceLevelChange", CAEP_ASSURANCE_LEVEL_CHANGE),
    ("CaepDeviceComplianceChange", CAEP_DEVICE_COMPLIANCE_CHANGE),
    ("CaepSessionEstablished", CAEP_SESSION_ESTABLISHED),
    ("CaepSessionPresented", CAEP_SESSION_PRESENTED),
    ("CaepRiskLevelChange", CAEP_RISK_LEVEL_CHANGE),
    (
        "RiscAccountCredentialChangeRequired",
        RISC_ACCOUNT_CREDENTIAL_CHANGE_REQUIRED,
    ),
    ("RiscAccountPurged", RISC_ACCOUNT_PURGED),
    ("RiscAccountDisabled", RISC_ACCOUNT_DISABLED),
    ("RiscAccountEnabled", RISC_ACCOUNT_ENABLED),
    ("RiscIdentifierChanged", RISC_IDENTIFIER_CHANGED),
    ("RiscIdentifierRecycled", RISC_IDENTIFIER_RECYCLED),
    ("RiscCredentialCompromise", RISC_CREDENTIAL_COMPROMISE),
    ("RiscOptIn", RISC_OPT_IN),
    ("RiscOptOutInitiated", RISC_OPT_OUT_INITIATED),
    ("RiscOptOutCancelled", RISC_OPT_OUT_CANCELLED),
    ("RiscOptOutEffective", RISC_OPT_OUT_EFFECTIVE),
    ("RiscRecoveryActivated", RISC_RECOVERY_ACTIVATED),
    ("RiscRecoveryInformationChanged", RISC_RECOVERY_INFORMATION_CHANGED),
    ("RiscSessionsRevoked", RISC_SESSIONS_REVOKED),
    ("ScimFeedAdd", SCIM_FEED_ADD),
    ("ScimFeedRemove", SCIM_FEED_REMOVE),
    ("ScimProvCreateNotice", SCIM_PROV_CREATE_NOTICE),
    ("ScimProvCreateFull", SCIM_PROV_CREATE_FULL),
    ("ScimProvPatchNotice", SCIM_PROV_PATCH_NOTICE),
    ("ScimProvPatchFull", SCIM_PROV_PATCH_FULL),
    ("ScimProvPutNotice", SCIM_PROV_PUT_NOTICE),
    ("ScimProvPutFull", SCIM_PROV_PUT_FULL),
    ("ScimProvDelete", SCIM_PROV_DELETE),
    ("ScimProvActivate", SCIM_PROV_ACTIVATE),
    ("ScimProvDeactivate", SCIM_PROV_DEACTIVATE),
    ("ScimMiscAsyncResponse", SCIM_MISC_ASYNC_RESPONSE),
];

struct Registry {
    uri_by_alias: HashMap<String, String>,
    alias_by_uri: HashMap<String, String>,
}

fn registry() -> &'static RwLock<Registry> {
    static REGISTRY: OnceLock<RwLock<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut registry = Registry {
            uri_by_alias: HashMap::new(),
            alias_by_uri: HashMap::new(),
        };
        for (alias, uri) in BUILT_IN {
            registry.uri_by_alias.insert((*alias).to_owned(), (*uri).to_owned());
            registry.alias_by_uri.insert((*uri).to_owned(), (*alias).to_owned());
        }
        RwLock::new(registry)
    })
}

/// Why an alias could not be registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfEventTypeError(String);

impl fmt::Display for SsfEventTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SsfEventTypeError {}

/// Registers an alias for an event type URI, for example of a vendor specific event type, so
/// that it can be used wherever an event type is named: in handlers, in the events requested of
/// a stream, in configuration. Aliases are a convenience of easyssf, the URIs stay the canonical
/// names.
///
/// Aliases do not conflict: an alias cannot be redefined to another URI, neither a built-in one
/// nor one registered before. A URI may have several aliases; the first one registered is the
/// one [`alias_of`] returns. Registering a mapping that exists already does nothing.
///
/// # Errors
///
/// If the alias is not a name without `:` or `/`, the URI is not an absolute URI, or the alias
/// is already mapped to another URI.
pub fn register_alias(alias: &str, uri: &str) -> Result<(), SsfEventTypeError> {
    if alias.trim().is_empty() || alias.contains(':') || alias.contains('/') || alias != alias.trim() {
        return Err(SsfEventTypeError(format!(
            "An event type alias must be a name without ':' or '/' and surrounding whitespace: '{alias}'"
        )));
    }
    if uri.trim().is_empty() || !uri.contains(':') || uri != uri.trim() {
        return Err(SsfEventTypeError(format!(
            "An event type must be an absolute URI: '{uri}'"
        )));
    }
    let mut registry = registry().write().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(existing) = registry.uri_by_alias.get(alias)
        && existing != uri
    {
        return Err(SsfEventTypeError(format!(
            "The event type alias '{alias}' is already mapped to {existing}, not to {uri}"
        )));
    }
    registry.uri_by_alias.insert(alias.to_owned(), uri.to_owned());
    registry
        .alias_by_uri
        .entry(uri.to_owned())
        .or_insert_with(|| alias.to_owned());
    Ok(())
}

/// The known aliases and their event type URIs, built-in and registered, sorted by alias.
pub fn aliases() -> BTreeMap<String, String> {
    let registry = registry().read().unwrap_or_else(|poisoned| poisoned.into_inner());
    registry
        .uri_by_alias
        .iter()
        .map(|(alias, uri)| (alias.clone(), uri.clone()))
        .collect()
}

/// Whether the name is a known alias.
pub fn is_alias(name: &str) -> bool {
    registry()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .uri_by_alias
        .contains_key(name)
}

/// Whether the event type is in the CAEP namespace
/// (`https://schemas.openid.net/secevent/caep/event-type/`), one of the events of CAEP 1.0 or a
/// later one.
pub fn is_caep_event(alias_or_uri: &str) -> bool {
    resolve(alias_or_uri).starts_with(CAEP)
}

/// Whether the event type is in the RISC namespace
/// (`https://schemas.openid.net/secevent/risc/event-type/`), one of the events of RISC 1.0 or a
/// later one.
pub fn is_risc_event(alias_or_uri: &str) -> bool {
    resolve(alias_or_uri).starts_with(RISC)
}

/// Whether the event type is in the SSF namespace, a stream management event.
pub fn is_ssf_event(alias_or_uri: &str) -> bool {
    resolve(alias_or_uri).starts_with(SSF)
}

/// Whether the event type is one of SCIM Events (RFC 9967).
pub fn is_scim_event(alias_or_uri: &str) -> bool {
    resolve(alias_or_uri).starts_with(SCIM)
}

/// Resolves an alias to its event type URI. Anything that is not a known alias is returned
/// unchanged, so full URIs (including vendor specific ones) pass through.
pub fn resolve(alias_or_uri: &str) -> String {
    let registry = registry().read().unwrap_or_else(|poisoned| poisoned.into_inner());
    registry
        .uri_by_alias
        .get(alias_or_uri)
        .cloned()
        .unwrap_or_else(|| alias_or_uri.to_owned())
}

/// Returns the alias of the given event type URI, or the URI itself if it has none.
pub fn alias_of(event_type_uri: &str) -> String {
    let registry = registry().read().unwrap_or_else(|poisoned| poisoned.into_inner());
    registry
        .alias_by_uri
        .get(event_type_uri)
        .cloned()
        .unwrap_or_else(|| event_type_uri.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_built_in_aliases_and_passes_uris_through() {
        assert_eq!(resolve("CaepSessionRevoked"), CAEP_SESSION_REVOKED);
        assert_eq!(resolve(CAEP_SESSION_REVOKED), CAEP_SESSION_REVOKED);
        assert_eq!(
            resolve("https://events.acme.example/login"),
            "https://events.acme.example/login"
        );
        assert_eq!(alias_of(RISC_ACCOUNT_DISABLED), "RiscAccountDisabled");
        assert_eq!(
            alias_of("https://events.acme.example/unaliased"),
            "https://events.acme.example/unaliased"
        );
        assert!(is_alias("CaepCredentialChange"));
        assert!(!is_alias("Nope"));
        assert!(is_caep_event("CaepSessionRevoked"));
        assert!(is_caep_event(
            "https://schemas.openid.net/secevent/caep/event-type/future"
        ));
        assert!(!is_caep_event("RiscAccountDisabled"));
        assert!(is_risc_event(RISC_SESSIONS_REVOKED));
        assert!(is_ssf_event("SsfStreamVerification"));
    }

    #[test]
    fn scim_event_types_are_urns_with_aliases() {
        assert_eq!(
            resolve("ScimProvCreateFull"),
            "urn:ietf:params:scim:event:prov:create:full"
        );
        assert_eq!(alias_of(SCIM_PROV_DEACTIVATE), "ScimProvDeactivate");
        assert!(is_scim_event("ScimFeedAdd"));
        assert_eq!(aliases().keys().filter(|alias| alias.starts_with("Scim")).count(), 12);
    }

    #[test]
    fn registered_alias_resolves_like_a_built_in_one() {
        register_alias("AcmeLoginTest", "https://events.acme.example/login").unwrap();
        assert_eq!(resolve("AcmeLoginTest"), "https://events.acme.example/login");
        assert_eq!(alias_of("https://events.acme.example/login"), "AcmeLoginTest");
        assert!(aliases().contains_key("AcmeLoginTest"));
        // registering the same mapping again does nothing
        register_alias("AcmeLoginTest", "https://events.acme.example/login").unwrap();
    }

    #[test]
    fn alias_cannot_be_mapped_to_another_uri() {
        let error = register_alias("CaepSessionRevoked", "https://events.acme.example/other").unwrap_err();
        assert!(error.to_string().contains("already mapped"));
        register_alias("AcmeOnce", "https://events.acme.example/once").unwrap();
        assert!(register_alias("AcmeOnce", "https://events.acme.example/twice").is_err());
    }

    #[test]
    fn uri_may_have_several_aliases_and_keeps_the_first_for_display() {
        register_alias("AcmeFirst", "https://events.acme.example/several").unwrap();
        register_alias("AcmeSecond", "https://events.acme.example/several").unwrap();
        assert_eq!(resolve("AcmeSecond"), "https://events.acme.example/several");
        assert_eq!(alias_of("https://events.acme.example/several"), "AcmeFirst");
    }

    #[test]
    fn rejects_malformed_aliases_and_uris() {
        assert!(register_alias("", "https://x.example/e").is_err());
        assert!(register_alias("has:colon", "https://x.example/e").is_err());
        assert!(register_alias("has/slash", "https://x.example/e").is_err());
        assert!(register_alias(" padded", "https://x.example/e").is_err());
        assert!(register_alias("Ok", "not-a-uri").is_err());
        assert!(register_alias("Ok", "").is_err());
    }
}
