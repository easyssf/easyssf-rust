//! Token revocation: what `session-revoked` events revoke, for resource servers to check.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use easyssf_core::event_types;

use crate::event::{SsfEventContext, SsfEventHandler};
use crate::{BoxError, Clock, system_clock};

/// The claims of an access token or session the revocation check reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SsfTokenClaims {
    /// The `iss` claim; a token without one is not revoked.
    pub issuer: Option<String>,
    /// The `sub` claim.
    pub subject: Option<String>,
    /// The `sid` claim.
    pub session_id: Option<String>,
    /// The `iat` claim, or the time a session was established.
    pub issued_at: Option<SystemTime>,
}

/// Remembers which sessions and subjects were revoked, so that their access tokens can be
/// rejected. Implement it on top of a shared store to share revocations between the instances
/// of a resource server, since a SET is pushed to only one of them.
///
/// Sessions and subjects are scoped to the issuer of their tokens: a subject `alice` of one
/// issuer is not the subject `alice` of another. Events name that issuer in an `iss_sub`
/// identifier; for identifiers without one, the transmitter that sent the event is taken to be
/// the issuer.
///
/// Revocations only need to be kept for as long as an access token issued before the revocation
/// can still be valid, i.e. for the maximum access token lifetime.
#[async_trait]
pub trait SsfTokenRevocationStore: Send + Sync + 'static {
    /// Revokes all access tokens bound to the given session (the `sid` claim).
    async fn revoke_session(&self, issuer: &str, session_id: &str) -> Result<(), BoxError>;

    /// Revokes all access tokens of the given subject (the `sub` claim) that were issued at or
    /// before `revoked_at`.
    async fn revoke_subject(&self, issuer: &str, subject: &str, revoked_at: SystemTime) -> Result<(), BoxError>;

    /// Whether the session was revoked.
    async fn is_session_revoked(&self, issuer: &str, session_id: &str) -> Result<bool, BoxError>;

    /// The time up to which the tokens of the given subject are revoked: the time of the most
    /// recent revocation, or `None` if the subject is not revoked.
    async fn subject_revoked_at(&self, issuer: &str, subject: &str) -> Result<Option<SystemTime>, BoxError>;

    /// Whether an access token was revoked: it is bound to a revoked session, or it belongs to a
    /// revoked subject and was issued at or before the revocation. A token without an issuer is
    /// not revoked.
    async fn is_revoked(&self, claims: &SsfTokenClaims) -> Result<bool, BoxError> {
        let Some(issuer) = &claims.issuer else {
            return Ok(false);
        };
        if let Some(session_id) = &claims.session_id
            && self.is_session_revoked(issuer, session_id).await?
        {
            return Ok(true);
        }
        let Some(subject) = &claims.subject else {
            return Ok(false);
        };
        let revoked_at = self.subject_revoked_at(issuer, subject).await?;
        Ok(revoked_at.is_some_and(|at| claims.issued_at.is_none_or(|iat| iat <= at)))
    }
}

#[async_trait]
impl<T: SsfTokenRevocationStore> SsfTokenRevocationStore for Arc<T> {
    async fn revoke_session(&self, issuer: &str, session_id: &str) -> Result<(), BoxError> {
        (**self).revoke_session(issuer, session_id).await
    }

    async fn revoke_subject(&self, issuer: &str, subject: &str, revoked_at: SystemTime) -> Result<(), BoxError> {
        (**self).revoke_subject(issuer, subject, revoked_at).await
    }

    async fn is_session_revoked(&self, issuer: &str, session_id: &str) -> Result<bool, BoxError> {
        (**self).is_session_revoked(issuer, session_id).await
    }

    async fn subject_revoked_at(&self, issuer: &str, subject: &str) -> Result<Option<SystemTime>, BoxError> {
        (**self).subject_revoked_at(issuer, subject).await
    }

    async fn is_revoked(&self, claims: &SsfTokenClaims) -> Result<bool, BoxError> {
        (**self).is_revoked(claims).await
    }
}

#[async_trait]
impl SsfTokenRevocationStore for Arc<dyn SsfTokenRevocationStore> {
    async fn revoke_session(&self, issuer: &str, session_id: &str) -> Result<(), BoxError> {
        (**self).revoke_session(issuer, session_id).await
    }

    async fn revoke_subject(&self, issuer: &str, subject: &str, revoked_at: SystemTime) -> Result<(), BoxError> {
        (**self).revoke_subject(issuer, subject, revoked_at).await
    }

    async fn is_session_revoked(&self, issuer: &str, session_id: &str) -> Result<bool, BoxError> {
        (**self).is_session_revoked(issuer, session_id).await
    }

    async fn subject_revoked_at(&self, issuer: &str, subject: &str) -> Result<Option<SystemTime>, BoxError> {
        (**self).subject_revoked_at(issuer, subject).await
    }

    async fn is_revoked(&self, claims: &SsfTokenClaims) -> Result<bool, BoxError> {
        (**self).is_revoked(claims).await
    }
}

#[derive(Debug, Clone, Copy)]
struct SubjectRevocation {
    revoked_at: SystemTime,
    expires_at: SystemTime,
}

/// [`SsfTokenRevocationStore`] that keeps revocations in memory for a fixed time. Its content is
/// lost on restart and not shared between instances.
pub struct InMemorySsfTokenRevocationStore {
    sessions: Mutex<HashMap<(String, String), SystemTime>>,
    subjects: Mutex<HashMap<(String, String), SubjectRevocation>>,
    ttl: Duration,
    clock: Clock,
}

impl InMemorySsfTokenRevocationStore {
    /// The time to live by default: 24 hours.
    pub const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

    /// A store that remembers a revocation for `ttl`, at least the maximum access token lifetime.
    ///
    /// # Panics
    ///
    /// If `ttl` is zero.
    pub fn new(ttl: Duration) -> Self {
        assert!(!ttl.is_zero(), "ttl must be positive");
        Self {
            sessions: Mutex::new(HashMap::new()),
            subjects: Mutex::new(HashMap::new()),
            ttl,
            clock: system_clock(),
        }
    }

    /// The clock the time to live is measured by.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    fn remove_expired(&self, now: SystemTime) {
        self.sessions.lock().unwrap().retain(|_, expires_at| *expires_at > now);
        self.subjects
            .lock()
            .unwrap()
            .retain(|_, revocation| revocation.expires_at > now);
    }
}

impl Default for InMemorySsfTokenRevocationStore {
    fn default() -> Self {
        Self::new(Self::DEFAULT_TTL)
    }
}

#[async_trait]
impl SsfTokenRevocationStore for InMemorySsfTokenRevocationStore {
    async fn revoke_session(&self, issuer: &str, session_id: &str) -> Result<(), BoxError> {
        let now = (self.clock)();
        self.remove_expired(now);
        self.sessions
            .lock()
            .unwrap()
            .insert((issuer.to_owned(), session_id.to_owned()), now + self.ttl);
        Ok(())
    }

    async fn revoke_subject(&self, issuer: &str, subject: &str, revoked_at: SystemTime) -> Result<(), BoxError> {
        let now = (self.clock)();
        self.remove_expired(now);
        let mut subjects = self.subjects.lock().unwrap();
        let entry = subjects.entry((issuer.to_owned(), subject.to_owned()));
        // an event delivered late must not shorten a more recent revocation
        entry
            .and_modify(|existing| {
                existing.revoked_at = existing.revoked_at.max(revoked_at);
                existing.expires_at = now + self.ttl;
            })
            .or_insert(SubjectRevocation {
                revoked_at,
                expires_at: now + self.ttl,
            });
        Ok(())
    }

    async fn is_session_revoked(&self, issuer: &str, session_id: &str) -> Result<bool, BoxError> {
        let now = (self.clock)();
        Ok(self
            .sessions
            .lock()
            .unwrap()
            .get(&(issuer.to_owned(), session_id.to_owned()))
            .is_some_and(|expires_at| *expires_at > now))
    }

    async fn subject_revoked_at(&self, issuer: &str, subject: &str) -> Result<Option<SystemTime>, BoxError> {
        let now = (self.clock)();
        Ok(self
            .subjects
            .lock()
            .unwrap()
            .get(&(issuer.to_owned(), subject.to_owned()))
            .filter(|revocation| revocation.expires_at > now)
            .map(|revocation| revocation.revoked_at))
    }
}

/// Records the session or subject of revocation events (by default CAEP `session-revoked`) in the
/// [`SsfTokenRevocationStore`].
///
/// A session event that names a session revokes the tokens of that session; one that only names
/// a user revokes all tokens of that user issued up to the time of the event. A user event (none
/// by default, `CaepCredentialChange` for an application whose sessions are cookies) always
/// revokes all tokens of the user.
pub struct SsfTokenRevocationEventHandler {
    store: Arc<dyn SsfTokenRevocationStore>,
    session_event_types: Vec<String>,
    user_event_types: Vec<String>,
}

impl SsfTokenRevocationEventHandler {
    /// The event types that revoke sessions by default: `CaepSessionRevoked`.
    pub const DEFAULT_SESSION_EVENT_TYPES: [&'static str; 1] = ["CaepSessionRevoked"];

    /// A handler that records what `CaepSessionRevoked` events revoke in `store`.
    pub fn new(store: impl SsfTokenRevocationStore) -> Self {
        Self::with_event_types(store, &Self::DEFAULT_SESSION_EVENT_TYPES.map(str::to_owned), &[])
    }

    /// A handler for the given event types (alias or URI): `session_event_types` revoke the
    /// session they name, or all tokens of the user if they name none; `user_event_types` revoke
    /// all tokens of the user they name, whether or not the event names a session.
    pub fn with_event_types(
        store: impl SsfTokenRevocationStore,
        session_event_types: &[String],
        user_event_types: &[String],
    ) -> Self {
        Self {
            store: Arc::new(store),
            session_event_types: session_event_types.iter().map(|e| event_types::resolve(e)).collect(),
            user_event_types: user_event_types.iter().map(|e| event_types::resolve(e)).collect(),
        }
    }

    async fn revoke(&self, context: &SsfEventContext, event_type: &str, user_event: bool) -> Result<(), BoxError> {
        let subject = context.subject_for(event_type);
        let subject = if user_event { subject.without_session() } else { subject };
        let revoked_at = context.event_timestamp(event_type);
        let alias = event_types::alias_of(event_type);
        let transmitter = context.event_token().issuer();
        if let Some(session_id) = subject.session_id() {
            let session = subject.session().expect("a session id comes from a session");
            let issuer = session
                .issuer()
                .or_else(|| subject.user().and_then(|user| user.issuer()))
                .unwrap_or(transmitter);
            self.store.revoke_session(issuer, session_id).await?;
            tracing::info!(
                event = alias,
                session = session_id,
                issuer,
                "revoked access tokens of session"
            );
        } else if let Some(sub) = subject.subject() {
            let issuer = subject
                .user_identifier()
                .and_then(|user| user.issuer())
                .unwrap_or(transmitter);
            self.store.revoke_subject(issuer, sub, revoked_at).await?;
            tracing::info!(event = alias, subject = sub, issuer, "revoked access tokens of subject");
        } else if let Some(opaque_id) = subject.opaque_id() {
            // an opaque identifier does not tell whether it names a session or a user
            self.store.revoke_session(transmitter, opaque_id).await?;
            self.store.revoke_subject(transmitter, opaque_id, revoked_at).await?;
            tracing::info!(
                event = alias,
                id = opaque_id,
                issuer = transmitter,
                "revoked access tokens of session or subject"
            );
        } else {
            tracing::warn!(
                event = alias,
                jti = context.event_token().jti(),
                "event has no subject that identifies a session or user by sid or sub, no tokens were revoked"
            );
        }
        Ok(())
    }
}

impl SsfEventHandler for SsfTokenRevocationEventHandler {
    async fn handle(&self, context: SsfEventContext) -> Result<(), BoxError> {
        for event_type in &self.session_event_types {
            if context.has_event(event_type) {
                self.revoke(&context, event_type, false).await?;
            }
        }
        for event_type in &self.user_event_types {
            if context.has_event(event_type) {
                self.revoke(&context, event_type, true).await?;
            }
        }
        Ok(())
    }
}
