//! Security Event Tokens (RFC 8417) and their subjects (RFC 9493).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::SystemTime;

use serde_json::{Map, Value};

use crate::support::{string_member, system_time};

/// A verified Security Event Token (SET, RFC 8417) with the SSF profile claims. Cheap to clone:
/// the claims are shared.
#[derive(Debug, Clone)]
pub struct SsfEventToken(Arc<Inner>);

#[derive(Debug)]
struct Inner {
    jti: String,
    iss: String,
    iat: i64,
    aud: Vec<String>,
    events: Map<String, Value>,
    subject_id: Option<Map<String, Value>>,
    txn: Option<String>,
    claims: Map<String, Value>,
}

impl SsfEventToken {
    /// Lenient: `None` if the claims lack a non-empty `jti`, a string `iss`, a numeric `iat` or
    /// a non-empty `events` object (RFC 8417, section 2.2).
    pub fn from_claims(claims: Map<String, Value>) -> Option<Self> {
        let jti = string_member(&claims, "jti")?.to_owned();
        let iss = claims.get("iss")?.as_str()?.to_owned();
        let iat = issued_at(claims.get("iat")?)?;
        let events = claims.get("events")?.as_object()?.clone();
        if events.is_empty() {
            return None;
        }
        let aud = audiences(claims.get("aud"));
        let subject_id = claims
            .get("sub_id")
            .and_then(Value::as_object)
            .filter(|s| !s.is_empty())
            .cloned();
        let txn = claims.get("txn").and_then(Value::as_str).map(str::to_owned);
        Some(Self(Arc::new(Inner {
            jti,
            iss,
            iat,
            aud,
            events,
            subject_id,
            txn,
            claims,
        })))
    }

    /// The `jti` claim, the identifier of the SET, unique per issuer.
    pub fn jti(&self) -> &str {
        &self.0.jti
    }

    /// The `iss` claim, the issuer of the SET (the transmitter).
    pub fn issuer(&self) -> &str {
        &self.0.iss
    }

    /// The `iat` claim, seconds since the epoch.
    pub fn issued_at_seconds(&self) -> i64 {
        self.0.iat
    }

    /// The `iat` claim as a point in time.
    pub fn issued_at(&self) -> SystemTime {
        system_time(self.0.iat)
    }

    /// The `aud` claim, a single value as a list of one, empty if the claim was absent.
    pub fn audience(&self) -> &[String] {
        &self.0.aud
    }

    /// The `events` claim: event payloads keyed by event type URI.
    pub fn events(&self) -> &Map<String, Value> {
        &self.0.events
    }

    /// The top-level `sub_id` claim SSF 1.0 requires, `None` if absent or empty.
    pub fn subject_id(&self) -> Option<&Map<String, Value>> {
        self.0.subject_id.as_ref()
    }

    /// The `txn` claim, the transaction identifier that groups SETs (RFC 8417, section 2.2),
    /// `None` if absent.
    pub fn txn(&self) -> Option<&str> {
        self.0.txn.as_deref()
    }

    /// All claims of the SET as received.
    pub fn claims(&self) -> &Map<String, Value> {
        &self.0.claims
    }

    /// The key that identifies this SET across deliveries: the issuer and the `jti`, which is
    /// only unique per issuer (RFC 8417, section 2.2). A handler that has side effects outside the
    /// receiver's stores uses it to make them idempotent, because a SET may be handled more than
    /// once: after a handler failed, or on another instance after the one that handled it died
    /// before recording the success.
    pub fn idempotency_key(&self) -> String {
        format!("{}::{}", self.0.iss, self.0.jti)
    }
}

fn issued_at(value: &Value) -> Option<i64> {
    if let Some(seconds) = value.as_i64() {
        return Some(seconds);
    }
    value.as_f64().filter(|f| f.is_finite()).map(|f| f as i64)
}

/// The `aud` claim as a list: a string as a list of one, an array of its strings.
pub fn audiences(aud: Option<&Value>) -> Vec<String> {
    match aud {
        Some(Value::String(one)) => vec![one.clone()],
        Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
        _ => Vec::new(),
    }
}

/// Which convention for the subject of a SET a peer follows. SSF 1.0 requires a top-level
/// `sub_id` claim in every SET, including those of the CAEP and RISC event types defined before
/// it; earlier drafts put the subject into the event payload instead. A receiver validates by it,
/// a transmitter would emit by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SubjectCompatibilityMode {
    /// SSF 1.0: a SET without a top-level `sub_id` is rejected as `invalid_request`. The default.
    #[default]
    Strict,
    /// The top-level `sub_id` is optional, for transmitters that follow earlier drafts;
    /// `SsfEventContext::subject_for` then reads the `subject` member of the event payload.
    Legacy,
}

/// Reads an `event_timestamp` claim of an event payload. CAEP 1.0 (section 2) and RISC 1.0
/// (section 2.7) define it as a JSON number of seconds since the epoch; a value that is clearly
/// milliseconds is read as such, as some transmitters send milliseconds.
///
/// Returns `None` if the value is not a number.
pub fn event_timestamp(value: Option<&Value>) -> Option<SystemTime> {
    let number = value?
        .as_i64()
        .or_else(|| value?.as_f64().filter(|f| f.is_finite()).map(|f| f as i64))?;
    // CAEP defines seconds since epoch, some transmitters send milliseconds
    if number > 100_000_000_000 {
        Some(system_time(number / 1000))
    } else {
        Some(system_time(number))
    }
}

/// A subject identifier (RFC 9493): a `format` and the members that format defines. Any format is
/// represented, the ones of RFC 9493 and the `scim` format of SCIM Events (RFC 9967) are known by
/// name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfSubjectIdentifier {
    format: String,
    claims: Map<String, Value>,
}

impl SsfSubjectIdentifier {
    /// The `account` format: an `acct:` URI (RFC 7565).
    pub const ACCOUNT: &'static str = "account";
    /// The `email` format.
    pub const EMAIL: &'static str = "email";
    /// The `iss_sub` format: an issuer and the subject at that issuer.
    pub const ISS_SUB: &'static str = "iss_sub";
    /// The `opaque` format: an identifier that does not tell what it names.
    pub const OPAQUE: &'static str = "opaque";
    /// The `phone_number` format, E.164.
    pub const PHONE_NUMBER: &'static str = "phone_number";
    /// The `did` format: a decentralized identifier.
    pub const DID: &'static str = "did";
    /// The `uri` format.
    pub const URI: &'static str = "uri";
    /// The `aliases` format: several identifiers that name the same subject.
    pub const ALIASES: &'static str = "aliases";
    /// The format of SCIM Events (RFC 9967, section 2.1): a SCIM resource named by its relative
    /// `uri`, with its `externalId` and `id` if known. See [`crate::scim::SsfScimSubject`].
    pub const SCIM: &'static str = "scim";

    /// Lenient: `None` if the identifier has no non-empty string `format`.
    pub fn from(identifier: &Map<String, Value>) -> Option<Self> {
        let format = string_member(identifier, "format")?.to_owned();
        Some(Self {
            format,
            claims: identifier.clone(),
        })
    }

    /// The format, never empty.
    pub fn format(&self) -> &str {
        &self.format
    }

    /// The members of the identifier as received, including `format`.
    pub fn claims(&self) -> &Map<String, Value> {
        &self.claims
    }

    /// Whether the identifier has the given format.
    pub fn is(&self, format: &str) -> bool {
        self.format == format
    }

    /// Whether the format is `iss_sub`.
    pub fn is_iss_sub(&self) -> bool {
        self.is(Self::ISS_SUB)
    }

    /// Whether the format is `email`.
    pub fn is_email(&self) -> bool {
        self.is(Self::EMAIL)
    }

    /// Whether the format is `opaque`.
    pub fn is_opaque(&self) -> bool {
        self.is(Self::OPAQUE)
    }

    /// Whether the format is `scim`.
    pub fn is_scim(&self) -> bool {
        self.is(Self::SCIM)
    }

    /// A member of the identifier, `None` if absent or not a non-empty string.
    pub fn claim(&self, name: &str) -> Option<&str> {
        string_member(&self.claims, name)
    }

    /// The issuer of an `iss_sub` identifier, `None` for other formats.
    pub fn issuer(&self) -> Option<&str> {
        if self.is_iss_sub() { self.claim("iss") } else { None }
    }

    /// The member that identifies the subject within its format: `sub` of `iss_sub`, `email`,
    /// `id` of `opaque`, `uri` of `account`, `uri` and `scim`, `phone_number`, `url` of `did`.
    /// `None` for `aliases` and unknown formats.
    pub fn value(&self) -> Option<&str> {
        match self.format.as_str() {
            Self::ISS_SUB => self.claim("sub"),
            Self::EMAIL => self.claim("email"),
            Self::OPAQUE => self.claim("id"),
            Self::ACCOUNT | Self::URI | Self::SCIM => self.claim("uri"),
            Self::PHONE_NUMBER => self.claim("phone_number"),
            Self::DID => self.claim("url"),
            _ => None,
        }
    }

    /// The identifiers of an `aliases` identifier, empty for other formats.
    pub fn aliases(&self) -> Vec<SsfSubjectIdentifier> {
        if !self.is(Self::ALIASES) {
            return Vec::new();
        }
        match self.claims.get("identifiers") {
            Some(Value::Array(identifiers)) => identifiers
                .iter()
                .filter_map(Value::as_object)
                .filter_map(SsfSubjectIdentifier::from)
                .collect(),
            _ => Vec::new(),
        }
    }
}

/// The subject of a SET (its `sub_id` claim): a simple subject identifier (RFC 9493), or a complex
/// subject whose members (`user`, `session`, `device`, `tenant`, ...) are identifiers.
///
/// [`user_identifier`](Self::user_identifier) and [`session`](Self::session) are the two members
/// the receiver acts on, and [`issuer`](Self::issuer), [`subject`](Self::subject),
/// [`session_id`](Self::session_id), [`email`](Self::email) and [`opaque_id`](Self::opaque_id)
/// are shortcuts to their most common values. Everything else is available through
/// [`member`](Self::member) and [`raw`](Self::raw).
///
/// Keycloak reports the revocation of all sessions of a user with a `session` member whose
/// identifier is [`ALL_SESSIONS`](Self::ALL_SESSIONS). Such a subject is resolved like one that
/// names only the user: it has no session.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SsfSubject {
    raw: Map<String, Value>,
    identifier: Option<SsfSubjectIdentifier>,
    members: Vec<(String, SsfSubjectIdentifier)>,
}

impl SsfSubject {
    /// Session identifier Keycloak uses to refer to all sessions of a user.
    pub const ALL_SESSIONS: &'static str = "ALL";
    /// The `user` member of a complex subject.
    pub const USER: &'static str = "user";
    /// The `session` member of a complex subject.
    pub const SESSION: &'static str = "session";
    /// The `device` member of a complex subject.
    pub const DEVICE: &'static str = "device";
    /// The `application` member of a complex subject.
    pub const APPLICATION: &'static str = "application";
    /// The `tenant` member of a complex subject.
    pub const TENANT: &'static str = "tenant";
    /// The `org_unit` member of a complex subject.
    pub const ORG_UNIT: &'static str = "org_unit";
    /// The `group` member of a complex subject.
    pub const GROUP: &'static str = "group";

    /// The members of a complex subject this type gives access to, in the order of the SSF
    /// specification: `user`, `session`, `device`, `application`, `tenant`, `org_unit`, `group`.
    pub const MEMBERS: [&'static str; 7] = [
        Self::USER,
        Self::SESSION,
        Self::DEVICE,
        Self::APPLICATION,
        Self::TENANT,
        Self::ORG_UNIT,
        Self::GROUP,
    ];

    /// The subject of a SET that carried none.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Resolves the given `sub_id` claim; lenient, empty for `None` or an empty object.
    pub fn from(subject_id: Option<&Map<String, Value>>) -> Self {
        let Some(subject_id) = subject_id.filter(|subject_id| !subject_id.is_empty()) else {
            return Self::empty();
        };
        let format = subject_id.get("format").and_then(Value::as_str);
        // Early SSF drafts used complex subjects without a format member
        let complex = format == Some("complex") || (format.is_none() && has_members(subject_id));
        if !complex {
            return Self {
                raw: subject_id.clone(),
                identifier: SsfSubjectIdentifier::from(subject_id),
                members: Vec::new(),
            };
        }
        let mut members: Vec<(String, SsfSubjectIdentifier)> = subject_id
            .iter()
            .filter_map(|(name, value)| {
                let member = value.as_object()?;
                SsfSubjectIdentifier::from(member).map(|identifier| (name.clone(), identifier))
            })
            .collect();
        let all_sessions = members.iter().any(|(name, session)| {
            name == Self::SESSION && session.is_opaque() && session.value() == Some(Self::ALL_SESSIONS)
        }) && members.iter().any(|(name, _)| name == Self::USER);
        if all_sessions {
            members.retain(|(name, _)| name != Self::SESSION);
        }
        Self {
            raw: subject_id.clone(),
            identifier: None,
            members,
        }
    }

    /// The subject identifier as received, empty if the SET carried none.
    pub fn raw(&self) -> &Map<String, Value> {
        &self.raw
    }

    /// The identifier of a simple subject, `None` for a complex subject or none.
    pub fn identifier(&self) -> Option<&SsfSubjectIdentifier> {
        self.identifier.as_ref()
    }

    /// The members of a complex subject by name, in the order received; empty for a simple
    /// subject.
    pub fn members(&self) -> impl Iterator<Item = (&str, &SsfSubjectIdentifier)> {
        self.members
            .iter()
            .map(|(name, identifier)| (name.as_str(), identifier))
    }

    /// The names of the members of a complex subject, whether or not [`member`](Self::member) can
    /// read them; empty for a simple subject.
    pub fn member_names(&self) -> BTreeSet<String> {
        if self.identifier.is_some() {
            return BTreeSet::new();
        }
        self.raw
            .iter()
            .filter(|(name, value)| name.as_str() != "format" && value.is_object())
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Whether this is a complex subject.
    pub fn is_complex(&self) -> bool {
        !self.members.is_empty()
    }

    /// The member of a complex subject with the given name, `None` if absent.
    pub fn member(&self, name: &str) -> Option<&SsfSubjectIdentifier> {
        self.members
            .iter()
            .find(|(member, _)| member == name)
            .map(|(_, identifier)| identifier)
    }

    /// The `user` member of a complex subject.
    pub fn user(&self) -> Option<&SsfSubjectIdentifier> {
        self.member(Self::USER)
    }

    /// The `session` member of a complex subject.
    pub fn session(&self) -> Option<&SsfSubjectIdentifier> {
        self.member(Self::SESSION)
    }

    /// The `device` member of a complex subject.
    pub fn device(&self) -> Option<&SsfSubjectIdentifier> {
        self.member(Self::DEVICE)
    }

    /// The `application` member of a complex subject.
    pub fn application(&self) -> Option<&SsfSubjectIdentifier> {
        self.member(Self::APPLICATION)
    }

    /// The `tenant` member of a complex subject.
    pub fn tenant(&self) -> Option<&SsfSubjectIdentifier> {
        self.member(Self::TENANT)
    }

    /// The `org_unit` member of a complex subject.
    pub fn org_unit(&self) -> Option<&SsfSubjectIdentifier> {
        self.member(Self::ORG_UNIT)
    }

    /// The `group` member of a complex subject.
    pub fn group(&self) -> Option<&SsfSubjectIdentifier> {
        self.member(Self::GROUP)
    }

    /// The identifier that names the user: the `user` member of a complex subject, or the
    /// identifier of a simple subject unless it is `opaque`, which may as well name a session
    /// (see [`opaque_id`](Self::opaque_id)). `None` if the subject does not name a user.
    pub fn user_identifier(&self) -> Option<&SsfSubjectIdentifier> {
        match &self.identifier {
            Some(identifier) => (!identifier.is_opaque()).then_some(identifier),
            None => self.user(),
        }
    }

    /// The issuer of the user, from an `iss_sub` identifier.
    pub fn issuer(&self) -> Option<&str> {
        self.user_identifier().and_then(SsfSubjectIdentifier::issuer)
    }

    /// The identifier of the user at the issuer: `sub` of an `iss_sub` identifier, or the `id` of
    /// an `opaque` user of a complex subject.
    pub fn subject(&self) -> Option<&str> {
        let user = self.user_identifier()?;
        if user.is_iss_sub() || user.is_opaque() {
            user.value()
        } else {
            None
        }
    }

    /// The identifier of the session.
    pub fn session_id(&self) -> Option<&str> {
        self.session().and_then(SsfSubjectIdentifier::value)
    }

    /// The email address of the user, from an `email` identifier.
    pub fn email(&self) -> Option<&str> {
        let user = self.user_identifier()?;
        if user.is_email() { user.value() } else { None }
    }

    /// The identifier of a simple `opaque` subject, which does not tell whether it names a user
    /// or a session.
    pub fn opaque_id(&self) -> Option<&str> {
        match &self.identifier {
            Some(identifier) if identifier.is_opaque() => identifier.value(),
            _ => None,
        }
    }

    /// Whether the SET carried no subject identifier that could be resolved.
    pub fn is_empty(&self) -> bool {
        self.identifier.is_none() && self.members.is_empty()
    }

    /// Whether this subject identifies a user (as opposed to only a session).
    pub fn has_user(&self) -> bool {
        self.user_identifier().is_some()
    }

    /// This subject without its session, i.e. widened to the user.
    pub fn without_session(&self) -> Self {
        if self.session().is_none() {
            return self.clone();
        }
        Self {
            raw: self.raw.clone(),
            identifier: self.identifier.clone(),
            members: self
                .members
                .iter()
                .filter(|(name, _)| name != Self::SESSION)
                .cloned()
                .collect(),
        }
    }
}

fn has_members(subject_id: &Map<String, Value>) -> bool {
    subject_id.values().any(Value::is_object)
}

/// Creates subject identifiers (RFC 9493) as they appear in the `sub_id` claim of a SET and in
/// requests to add or remove subjects of a stream; the `SsfSubjectIdentifiers` of the Java
/// library.
pub mod subjects {
    use serde_json::{Map, Value, json};

    /// A subject identified by its issuer and its identifier at that issuer.
    pub fn iss_sub(issuer: &str, subject: &str) -> Map<String, Value> {
        object(json!({ "format": "iss_sub", "iss": issuer, "sub": subject }))
    }

    /// A subject identified by an email address.
    pub fn email(email: &str) -> Map<String, Value> {
        object(json!({ "format": "email", "email": email }))
    }

    /// A subject identified by an opaque identifier.
    pub fn opaque(id: &str) -> Map<String, Value> {
        object(json!({ "format": "opaque", "id": id }))
    }

    /// A subject identified by an `acct:` URI (RFC 7565).
    pub fn account(uri: &str) -> Map<String, Value> {
        object(json!({ "format": "account", "uri": uri }))
    }

    /// A subject identified by a telephone number in E.164 format.
    pub fn phone_number(phone_number: &str) -> Map<String, Value> {
        object(json!({ "format": "phone_number", "phone_number": phone_number }))
    }

    /// A subject identified by a decentralized identifier.
    pub fn did(url: &str) -> Map<String, Value> {
        object(json!({ "format": "did", "url": url }))
    }

    /// A subject identified by a URI.
    pub fn uri(uri: &str) -> Map<String, Value> {
        object(json!({ "format": "uri", "uri": uri }))
    }

    /// A SCIM resource (RFC 9967), the subject of SCIM Events.
    /// `uri` is the relative path of the resource, for example `/Users/2b2f880a`.
    pub fn scim(uri: &str) -> Map<String, Value> {
        object(json!({ "format": "scim", "uri": uri }))
    }

    /// A SCIM resource (RFC 9967) with its `externalId`.
    pub fn scim_with_external_id(uri: &str, external_id: Option<&str>) -> Map<String, Value> {
        let mut identifier = scim(uri);
        if let Some(external_id) = external_id {
            identifier.insert("externalId".to_owned(), Value::String(external_id.to_owned()));
        }
        identifier
    }

    /// A subject with several identifiers that all name it.
    pub fn aliases(identifiers: Vec<Map<String, Value>>) -> Map<String, Value> {
        let mut identifier = Map::new();
        identifier.insert("format".to_owned(), Value::String("aliases".to_owned()));
        identifier.insert(
            "identifiers".to_owned(),
            Value::Array(identifiers.into_iter().map(Value::Object).collect()),
        );
        identifier
    }

    /// A complex subject with the given members (`user`, `session`, `device`, `tenant`, ...),
    /// each a subject identifier.
    pub fn complex_members(members: Vec<(&str, Map<String, Value>)>) -> Map<String, Value> {
        let mut identifier = Map::new();
        identifier.insert("format".to_owned(), Value::String("complex".to_owned()));
        for (name, member) in members {
            identifier.insert(name.to_owned(), Value::Object(member));
        }
        identifier
    }

    /// A subject made up of a user and a session, either may be `None`.
    pub fn complex(user: Option<Map<String, Value>>, session: Option<Map<String, Value>>) -> Map<String, Value> {
        let mut members = Vec::new();
        if let Some(user) = user {
            members.push(("user", user));
        }
        if let Some(session) = session {
            members.push(("session", session));
        }
        complex_members(members)
    }

    fn object(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(object) => object,
            _ => unreachable!("built from a JSON object"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use serde_json::json;

    use super::subjects::*;
    use super::*;

    fn subject(value: Value) -> SsfSubject {
        SsfSubject::from(value.as_object())
    }

    #[test]
    fn absent_subject_is_empty() {
        assert!(SsfSubject::from(None).is_empty());
        assert!(subject(json!({})).is_empty());
        assert!(!SsfSubject::from(None).has_user());
        assert_eq!(SsfSubject::from(None).session_id(), None);
    }

    #[test]
    fn resolves_iss_sub() {
        let subject = SsfSubject::from(Some(&iss_sub("https://idp.example", "alice")));
        assert_eq!(subject.issuer(), Some("https://idp.example"));
        assert_eq!(subject.subject(), Some("alice"));
        assert!(subject.has_user());
        assert!(!subject.is_complex());
        assert_eq!(subject.session_id(), None);
        assert_eq!(subject.identifier().unwrap().format(), "iss_sub");
        assert!(subject.member_names().is_empty());
    }

    #[test]
    fn resolves_email() {
        let subject = SsfSubject::from(Some(&email("alice@example.com")));
        assert_eq!(subject.email(), Some("alice@example.com"));
        assert_eq!(subject.subject(), None);
        assert!(subject.has_user());
    }

    #[test]
    fn simple_opaque_subject_is_neither_user_nor_session() {
        let subject = SsfSubject::from(Some(&opaque("abc")));
        assert_eq!(subject.opaque_id(), Some("abc"));
        assert!(!subject.has_user());
        assert_eq!(subject.subject(), None);
        assert_eq!(subject.session_id(), None);
        assert!(!subject.is_empty());
    }

    #[test]
    fn resolves_complex_subject_with_user_and_session() {
        let subject = SsfSubject::from(Some(&complex(
            Some(iss_sub("https://idp.example", "alice")),
            Some(opaque("session-1")),
        )));
        assert!(subject.is_complex());
        assert_eq!(subject.issuer(), Some("https://idp.example"));
        assert_eq!(subject.subject(), Some("alice"));
        assert_eq!(subject.session_id(), Some("session-1"));
        assert_eq!(subject.session().unwrap().format(), "opaque");
        assert_eq!(
            subject.member_names().into_iter().collect::<Vec<_>>(),
            vec!["session", "user"]
        );
    }

    #[test]
    fn keycloak_all_sessions_marker_names_only_the_user() {
        let subject = SsfSubject::from(Some(&complex(
            Some(iss_sub("https://idp.example", "alice")),
            Some(opaque("ALL")),
        )));
        assert_eq!(subject.subject(), Some("alice"));
        assert_eq!(subject.session_id(), None);
        assert!(subject.session().is_none());
        // the raw claim keeps the member
        assert!(subject.member_names().contains("session"));
        // without a user the marker is an ordinary session identifier
        let only_session = SsfSubject::from(Some(&complex(None, Some(opaque("ALL")))));
        assert_eq!(only_session.session_id(), Some("ALL"));
    }

    #[test]
    fn resolves_complex_subject_with_opaque_user() {
        let subject = SsfSubject::from(Some(&complex(Some(opaque("user-1")), Some(opaque("session-1")))));
        assert_eq!(subject.subject(), Some("user-1"));
        assert_eq!(subject.issuer(), None);
        assert_eq!(subject.opaque_id(), None);
        assert!(subject.has_user());
    }

    #[test]
    fn resolves_complex_subject_without_format_of_early_drafts() {
        let subject = subject(json!({
            "user": { "format": "iss_sub", "iss": "https://idp.example", "sub": "alice" },
            "session": { "format": "opaque", "id": "s1" }
        }));
        assert!(subject.is_complex());
        assert_eq!(subject.subject(), Some("alice"));
        assert_eq!(subject.session_id(), Some("s1"));
    }

    #[test]
    fn other_formats_of_rfc9493_name_the_user() {
        for (identifier, value) in [
            (account("acct:alice@example.com"), "acct:alice@example.com"),
            (phone_number("+12025550123"), "+12025550123"),
            (did("did:example:123"), "did:example:123"),
            (uri("https://example.com/alice"), "https://example.com/alice"),
        ] {
            let subject = SsfSubject::from(Some(&identifier));
            assert!(subject.has_user());
            assert_eq!(subject.user_identifier().unwrap().value(), Some(value));
            assert_eq!(subject.subject(), None);
        }
    }

    #[test]
    fn scim_resource_of_rfc9967_names_the_user_by_its_uri() {
        let subject = SsfSubject::from(Some(&scim_with_external_id("/Users/2b2f880a", Some("ext-1"))));
        let user = subject.user_identifier().unwrap();
        assert!(user.is_scim());
        assert_eq!(user.value(), Some("/Users/2b2f880a"));
        assert_eq!(user.claim("externalId"), Some("ext-1"));
        assert_eq!(subject.subject(), None);
    }

    #[test]
    fn aliases_carry_every_identifier() {
        let subject = SsfSubject::from(Some(&aliases(vec![
            iss_sub("https://idp.example", "alice"),
            email("alice@example.com"),
        ])));
        let user = subject.user_identifier().unwrap();
        assert_eq!(user.value(), None);
        let aliases = user.aliases();
        assert_eq!(aliases.len(), 2);
        assert_eq!(aliases[0].value(), Some("alice"));
        assert_eq!(aliases[1].value(), Some("alice@example.com"));
        assert!(
            SsfSubjectIdentifier::from(&iss_sub("i", "s"))
                .unwrap()
                .aliases()
                .is_empty()
        );
    }

    #[test]
    fn unknown_format_is_kept_without_value() {
        let subject = subject(json!({ "format": "custom", "thing": "x" }));
        let user = subject.user_identifier().unwrap();
        assert_eq!(user.format(), "custom");
        assert_eq!(user.value(), None);
        assert_eq!(user.claim("thing"), Some("x"));
    }

    #[test]
    fn identifier_without_format_is_empty() {
        assert!(subject(json!({ "sub": "alice" })).is_empty());
        assert!(SsfSubjectIdentifier::from(&Map::new()).is_none());
        assert!(SsfSubjectIdentifier::from(json!({ "format": " " }).as_object().unwrap()).is_none());
    }

    #[test]
    fn complex_subject_exposes_all_members() {
        let subject = SsfSubject::from(Some(&complex_members(vec![
            ("user", iss_sub("https://idp.example", "alice")),
            ("device", opaque("dev-1")),
            ("tenant", opaque("t-1")),
            ("application", opaque("app-1")),
            ("org_unit", opaque("ou-1")),
            ("group", opaque("g-1")),
        ])));
        assert_eq!(subject.device().unwrap().value(), Some("dev-1"));
        assert_eq!(subject.tenant().unwrap().value(), Some("t-1"));
        assert_eq!(subject.application().unwrap().value(), Some("app-1"));
        assert_eq!(subject.org_unit().unwrap().value(), Some("ou-1"));
        assert_eq!(subject.group().unwrap().value(), Some("g-1"));
        assert_eq!(subject.member("device"), subject.device());
        assert_eq!(subject.members().count(), 6);
        assert_eq!(SsfSubject::MEMBERS.len(), 7);
    }

    #[test]
    fn without_session_widens_to_user() {
        let subject = SsfSubject::from(Some(&complex(
            Some(iss_sub("https://idp.example", "alice")),
            Some(opaque("session-1")),
        )));
        let widened = subject.without_session();
        assert_eq!(widened.subject(), Some("alice"));
        assert_eq!(widened.session_id(), None);
        assert_eq!(widened.raw(), subject.raw());
        let simple = SsfSubject::from(Some(&email("a@b")));
        assert_eq!(simple.without_session(), simple);
    }

    #[test]
    fn event_token_reads_the_profile_claims() {
        let claims = json!({
            "jti": "1", "iss": "https://t.example", "iat": 1700000000, "aud": ["a", "b"],
            "txn": "tx-1", "sub_id": { "format": "opaque", "id": "x" },
            "events": { "https://e.example/one": {} }
        });
        let token = SsfEventToken::from_claims(claims.as_object().unwrap().clone()).unwrap();
        assert_eq!(token.jti(), "1");
        assert_eq!(token.issuer(), "https://t.example");
        assert_eq!(token.issued_at(), UNIX_EPOCH + Duration::from_secs(1700000000));
        assert_eq!(token.audience(), ["a", "b"]);
        assert_eq!(token.txn(), Some("tx-1"));
        assert_eq!(token.subject_id().unwrap()["id"], "x");
        assert_eq!(token.idempotency_key(), "https://t.example::1");
        assert_eq!(token.claims().len(), 7);

        let single_aud = json!({ "jti": "1", "iss": "i", "iat": 1, "aud": "one", "events": { "e": {} } });
        let token = SsfEventToken::from_claims(single_aud.as_object().unwrap().clone()).unwrap();
        assert_eq!(token.audience(), ["one"]);
        assert_eq!(token.txn(), None);
        assert!(token.subject_id().is_none());

        for broken in [
            json!({ "iss": "i", "iat": 1, "events": { "e": {} } }),
            json!({ "jti": "", "iss": "i", "iat": 1, "events": { "e": {} } }),
            json!({ "jti": "1", "iat": 1, "events": { "e": {} } }),
            json!({ "jti": "1", "iss": "i", "events": { "e": {} } }),
            json!({ "jti": "1", "iss": "i", "iat": "now", "events": { "e": {} } }),
            json!({ "jti": "1", "iss": "i", "iat": 1, "events": {} }),
            json!({ "jti": "1", "iss": "i", "iat": 1 }),
        ] {
            assert!(
                SsfEventToken::from_claims(broken.as_object().unwrap().clone()).is_none(),
                "{broken}"
            );
        }
    }

    #[test]
    fn event_timestamp_in_seconds_or_milliseconds() {
        assert_eq!(
            event_timestamp(Some(&json!(1700000000))),
            Some(UNIX_EPOCH + Duration::from_secs(1700000000))
        );
        assert_eq!(
            event_timestamp(Some(&json!(1700000000123_i64))),
            Some(UNIX_EPOCH + Duration::from_secs(1700000000))
        );
        assert_eq!(event_timestamp(Some(&json!("2024-01-01"))), None);
        assert_eq!(event_timestamp(None), None);
    }
}
