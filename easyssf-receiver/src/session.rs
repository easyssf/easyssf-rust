//! Session termination: ending the local sessions of the subject of an event, and matching the
//! subject of an event with the claims of a logged-in user.

use std::sync::Arc;

use async_trait::async_trait;
use easyssf_core::event_types;
use easyssf_core::scim::SsfScimSubject;
use easyssf_core::{SsfSubject, SsfSubjectIdentifier};
use serde_json::{Map, Value};

use crate::BoxError;
use crate::event::{SsfEventContext, SsfEventHandler};

/// Terminates the local sessions of a subject. Implement it for the session store of the
/// application; [`subject_claims_matcher::matches`] tells which sessions belong to the subject.
#[async_trait]
pub trait SsfSessionTerminator: Send + Sync + 'static {
    /// Terminates the sessions that belong to the given subject: the session with the subject's
    /// session identifier if it has one, otherwise all sessions of its user. Returns the number
    /// of terminated sessions.
    async fn terminate_sessions(&self, subject: &SsfSubject) -> Result<usize, BoxError>;
}

#[async_trait]
impl<T: SsfSessionTerminator> SsfSessionTerminator for Arc<T> {
    async fn terminate_sessions(&self, subject: &SsfSubject) -> Result<usize, BoxError> {
        (**self).terminate_sessions(subject).await
    }
}

#[async_trait]
impl SsfSessionTerminator for Arc<dyn SsfSessionTerminator> {
    async fn terminate_sessions(&self, subject: &SsfSubject) -> Result<usize, BoxError> {
        (**self).terminate_sessions(subject).await
    }
}

/// Terminates local sessions in reaction to security events.
///
/// Session events (by default CAEP `session-revoked`) terminate the session named by the event,
/// or all sessions of its user if it names no session. User events (by default CAEP
/// `credential-change`) always terminate all sessions of the user.
pub struct SsfSessionTerminationEventHandler {
    terminator: Arc<dyn SsfSessionTerminator>,
    session_event_types: Vec<String>,
    user_event_types: Vec<String>,
}

impl SsfSessionTerminationEventHandler {
    /// The event types that terminate the sessions of their subject by default:
    /// `CaepSessionRevoked`.
    pub const DEFAULT_SESSION_EVENT_TYPES: [&'static str; 1] = ["CaepSessionRevoked"];
    /// The event types that terminate all sessions of their subject's user by default:
    /// `CaepCredentialChange`.
    pub const DEFAULT_USER_EVENT_TYPES: [&'static str; 1] = ["CaepCredentialChange"];

    /// A handler with the default event types.
    pub fn new(terminator: impl SsfSessionTerminator) -> Self {
        Self::with_event_types(
            terminator,
            &Self::DEFAULT_SESSION_EVENT_TYPES.map(str::to_owned),
            &Self::DEFAULT_USER_EVENT_TYPES.map(str::to_owned),
        )
    }

    /// A handler for the given event types (alias or URI).
    pub fn with_event_types(
        terminator: impl SsfSessionTerminator,
        session_event_types: &[String],
        user_event_types: &[String],
    ) -> Self {
        Self {
            terminator: Arc::new(terminator),
            session_event_types: session_event_types.iter().map(|e| event_types::resolve(e)).collect(),
            user_event_types: user_event_types.iter().map(|e| event_types::resolve(e)).collect(),
        }
    }

    async fn terminate(
        &self,
        context: &SsfEventContext,
        event_type: &str,
        subject: SsfSubject,
    ) -> Result<(), BoxError> {
        let alias = event_types::alias_of(event_type);
        if subject.is_empty() {
            tracing::warn!(
                event = alias,
                jti = context.event_token().jti(),
                "event has no subject that identifies a session or user, no sessions were terminated"
            );
            return Ok(());
        }
        let terminated = self.terminator.terminate_sessions(&subject).await?;
        tracing::info!(
            event = alias,
            terminated,
            subject = describe(&subject),
            "terminated session(s)"
        );
        Ok(())
    }
}

fn describe(subject: &SsfSubject) -> String {
    if let Some(session_id) = subject.session_id() {
        return format!("session {session_id}");
    }
    if let Some(user) = subject.user_identifier() {
        return format!("user {}", user.value().unwrap_or(user.format()));
    }
    format!("session or subject {}", subject.opaque_id().unwrap_or(""))
}

impl SsfEventHandler for SsfSessionTerminationEventHandler {
    async fn handle(&self, context: SsfEventContext) -> Result<(), BoxError> {
        for event_type in &self.session_event_types {
            if context.has_event(event_type) {
                self.terminate(&context, event_type, context.subject_for(event_type))
                    .await?;
            }
        }
        for event_type in &self.user_event_types {
            if context.has_event(event_type) {
                self.terminate(&context, event_type, context.subject_for(event_type).without_session())
                    .await?;
            }
        }
        Ok(())
    }
}

/// Decides whether the subject of a security event refers to a user or session that is described
/// by claims, typically the claims of the ID token the user logged in with: `sid` for a session,
/// `iss` and `sub`, `email` or `phone_number` for a user.
///
/// An `iss_sub` identifier names the user at an issuer, so both have to match: claims without an
/// `iss` never match such a subject. A session is matched by its `sid` and, if the event names
/// the issuer of the session or of its user, by that issuer as well.
///
/// A `scim` identifier (RFC 9967) names a resource of a SCIM service provider, whose identifiers
/// an OpenID Provider may or may not share. Which attributes of the resource are compared with
/// which claims is configurable; by default ([`subject_claims_matcher::DEFAULT_SCIM_ATTRIBUTE_CLAIMS`]) the resource
/// matches a user whose `sub` is its `externalId` or its `id`, or whose `preferred_username` is
/// its `userName`. A SCIM attribute that is multi-valued, such as `emails`, matches if any of its
/// values (the `value` of each entry) does. Values compared with the `email` claim match ignoring
/// case, all others exactly.
pub mod subject_claims_matcher {
    use super::*;

    /// The attributes of a `scim` subject and the claims they are compared with by default:
    /// `externalId` and `id` with `sub`, `userName` with `preferred_username`.
    pub const DEFAULT_SCIM_ATTRIBUTE_CLAIMS: [(&str, &str); 3] =
        [("externalId", "sub"), ("id", "sub"), ("userName", "preferred_username")];

    /// Whether the subject of an event refers to the user or session with the given claims.
    /// `name` is the name of the user, compared with the subject of the event if the claims have
    /// no `sub`. Matches `scim` subjects with the [`DEFAULT_SCIM_ATTRIBUTE_CLAIMS`].
    pub fn matches(subject: &SsfSubject, claims: &Map<String, Value>, name: Option<&str>) -> bool {
        let defaults: Vec<(String, String)> = DEFAULT_SCIM_ATTRIBUTE_CLAIMS
            .iter()
            .map(|(a, c)| ((*a).to_owned(), (*c).to_owned()))
            .collect();
        matches_with(subject, claims, name, &defaults)
    }

    /// Like [`matches()`], with the attributes of a `scim` subject (RFC 9967) and the claim each is
    /// compared with, for example `externalId` with `sub`; the subject matches if any pair does.
    pub fn matches_with(
        subject: &SsfSubject,
        claims: &Map<String, Value>,
        name: Option<&str>,
        scim_attribute_claims: &[(String, String)],
    ) -> bool {
        let session_id = string(claims, "sid");
        let user_subject = string(claims, "sub").or_else(|| name.map(str::to_owned));
        if let Some(session) = subject.session() {
            if session.value().is_none() || session.value() != session_id.as_deref() {
                return false;
            }
            // the session belongs to the issuer the event names, in the session identifier or
            // the user it belongs to; session identifiers are not unique across issuers
            let issuer = session
                .issuer()
                .or_else(|| subject.user().and_then(|user| user.issuer()));
            return issuer.is_none_or(|issuer| Some(issuer) == string(claims, "iss").as_deref());
        }
        if let Some(user) = subject.user_identifier() {
            return matches_user(user, claims, user_subject.as_deref(), scim_attribute_claims);
        }
        if let Some(opaque_id) = subject.opaque_id() {
            // an opaque identifier does not tell whether it names a session or a user
            return Some(opaque_id) == session_id.as_deref() || Some(opaque_id) == user_subject.as_deref();
        }
        false
    }

    fn matches_user(
        user: &SsfSubjectIdentifier,
        claims: &Map<String, Value>,
        user_subject: Option<&str>,
        scim_attribute_claims: &[(String, String)],
    ) -> bool {
        let value = user.value();
        match user.format() {
            SsfSubjectIdentifier::ISS_SUB => {
                value.is_some()
                    && value == user_subject
                    && user.issuer().is_some()
                    && user.issuer() == string(claims, "iss").as_deref()
            }
            SsfSubjectIdentifier::EMAIL => value
                .is_some_and(|value| string(claims, "email").is_some_and(|email| value.eq_ignore_ascii_case(&email))),
            SsfSubjectIdentifier::OPAQUE => value.is_some() && value == user_subject,
            SsfSubjectIdentifier::ALIASES => user
                .aliases()
                .iter()
                .any(|alias| matches_user(alias, claims, user_subject, scim_attribute_claims)),
            SsfSubjectIdentifier::SCIM => SsfScimSubject::from_identifier(Some(user))
                .is_some_and(|resource| matches_scim_resource(&resource, claims, user_subject, scim_attribute_claims)),
            // phone_number, account, did, uri and unknown formats: a claim of the same name
            format => value.is_some() && value == string(claims, format).as_deref(),
        }
    }

    fn matches_scim_resource(
        resource: &SsfScimSubject,
        claims: &Map<String, Value>,
        user_subject: Option<&str>,
        scim_attribute_claims: &[(String, String)],
    ) -> bool {
        for (attribute, claim_name) in scim_attribute_claims {
            let claim_value = if claim_name == "sub" {
                user_subject.map(str::to_owned)
            } else {
                string(claims, claim_name)
            };
            let Some(claim_value) = claim_value else {
                continue;
            };
            for value in scim_attribute_values(resource, attribute) {
                let matched = if claim_name == "email" {
                    value.eq_ignore_ascii_case(&claim_value)
                } else {
                    value == claim_value
                };
                if matched {
                    return true;
                }
            }
        }
        false
    }

    /// The values of an attribute of a SCIM resource: the string of a single-valued attribute,
    /// the `id` resolved from the uri if the resource has no `id` attribute, or the strings and
    /// the `value` members of a multi-valued attribute such as `emails`.
    fn scim_attribute_values(resource: &SsfScimSubject, attribute: &str) -> Vec<String> {
        if attribute == "id" {
            return resource.id().into_iter().collect();
        }
        match resource.claims().get(attribute) {
            Some(Value::String(value)) if !value.trim().is_empty() => vec![value.clone()],
            Some(Value::Array(values)) => values
                .iter()
                .filter_map(|element| match element {
                    Value::String(value) if !value.trim().is_empty() => Some(value.clone()),
                    Value::Object(complex) => complex
                        .get("value")
                        .and_then(Value::as_str)
                        .filter(|v| !v.trim().is_empty())
                        .map(str::to_owned),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    fn string(claims: &Map<String, Value>, name: &str) -> Option<String> {
        match claims.get(name) {
            None | Some(Value::Null) => None,
            Some(Value::String(value)) => Some(value.clone()),
            Some(other) => Some(other.to_string()),
        }
    }
}
