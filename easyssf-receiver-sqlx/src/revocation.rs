//! The revocation store on a database table.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use easyssf_receiver::revocation::{SsfTokenClaims, SsfTokenRevocationStore};
use easyssf_receiver::{BoxError, Clock, system_clock};

use crate::cleanup::SsfExpiringStore;
use crate::ops::{SsfSqlError, SsfSqlOperations, SsfSqlValue};
use crate::schema::SsfSqlSchema;

fn millis(time: SystemTime) -> i64 {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(since) => since.as_millis() as i64,
        Err(before) => -(before.duration().as_millis() as i64),
    }
}

fn from_millis(millis: i64) -> SystemTime {
    if millis >= 0 {
        SystemTime::UNIX_EPOCH + Duration::from_millis(millis as u64)
    } else {
        SystemTime::UNIX_EPOCH - Duration::from_millis(millis.unsigned_abs())
    }
}

/// [`SsfTokenRevocationStore`] that keeps revocations in a database table, so that all instances
/// of a resource server reject the access tokens of a revoked session or subject, whichever
/// instance received the event. Sessions and subjects are keyed by the issuer of their tokens.
///
/// Checking an access token takes one query on the primary key of the table. Revocations are
/// removed after the time to live: the store deletes them when it is written to, and
/// [`purge_expired`](SsfExpiringStore::purge_expired) does so on demand.
pub struct SqlSsfTokenRevocationStore {
    db: Arc<dyn SsfSqlOperations>,
    table_prefix: String,
    table: String,
    ttl: Duration,
    clock: Clock,
}

impl SqlSsfTokenRevocationStore {
    const SESSION: &'static str = "SESSION";
    const SUBJECT: &'static str = "SUBJECT";

    /// A store on the table with the given prefix that remembers a revocation for `ttl`, at
    /// least the maximum access token lifetime.
    ///
    /// # Panics
    ///
    /// If `ttl` is zero.
    pub fn new(db: impl SsfSqlOperations, table_prefix: &str, ttl: Duration) -> Self {
        assert!(!ttl.is_zero(), "ttl must be positive");
        Self {
            db: Arc::new(db),
            table_prefix: table_prefix.to_owned(),
            table: SsfSqlSchema::revocation_table(table_prefix),
            ttl,
            clock: system_clock(),
        }
    }

    /// The name of the table.
    pub fn table(&self) -> &str {
        &self.table
    }

    /// The clock of the store.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Makes sure the table exists, see [`SsfSqlSchema::prepare_table`].
    pub async fn prepare_table(&self, create: bool, hint: Option<&str>) -> Result<(), SsfSqlError> {
        SsfSqlSchema::prepare_table(
            &*self.db,
            &self.table,
            &SsfSqlSchema::create_revocation_table(&self.table_prefix),
            &[],
            create,
            hint,
        )
        .await
    }

    async fn revoke(&self, kind: &str, issuer: &str, id: &str, revoked_at: SystemTime) -> Result<(), BoxError> {
        if issuer.trim().is_empty() || id.trim().is_empty() {
            return Err("issuer and id must not be empty".into());
        }
        let now = (self.clock)();
        self.purge_expired().await?;
        let expires_at = millis(now + self.ttl);
        if self.update(kind, issuer, id, millis(revoked_at), expires_at).await? {
            return Ok(());
        }
        let insert = format!(
            "INSERT INTO {} (KIND, ISSUER, ID, REVOKED_AT, EXPIRES_AT) VALUES (?, ?, ?, ?, ?)",
            self.table
        );
        match self
            .db
            .update(
                &insert,
                &[
                    kind.into(),
                    issuer.into(),
                    id.into(),
                    millis(revoked_at).into(),
                    expires_at.into(),
                ],
            )
            .await
        {
            Ok(_) => Ok(()),
            // revoked by another instance at the same time
            Err(error) if error.is_duplicate_key() => {
                self.update(kind, issuer, id, millis(revoked_at), expires_at).await?;
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn update(
        &self,
        kind: &str,
        issuer: &str,
        id: &str,
        revoked_at: i64,
        expires_at: i64,
    ) -> Result<bool, SsfSqlError> {
        let update = format!(
            "UPDATE {} SET REVOKED_AT = ?, EXPIRES_AT = ? WHERE KIND = ? AND ISSUER = ? AND ID = ? AND REVOKED_AT <= ?",
            self.table
        );
        let mut updated = self
            .db
            .update(
                &update,
                &[
                    revoked_at.into(),
                    expires_at.into(),
                    kind.into(),
                    issuer.into(),
                    id.into(),
                    revoked_at.into(),
                ],
            )
            .await?;
        if updated == 0 {
            // an event delivered late must not shorten a more recent revocation
            let extend = format!(
                "UPDATE {} SET EXPIRES_AT = ? WHERE KIND = ? AND ISSUER = ? AND ID = ?",
                self.table
            );
            updated = self
                .db
                .update(&extend, &[expires_at.into(), kind.into(), issuer.into(), id.into()])
                .await?;
        }
        Ok(updated > 0)
    }
}

#[async_trait]
impl SsfTokenRevocationStore for SqlSsfTokenRevocationStore {
    async fn revoke_session(&self, issuer: &str, session_id: &str) -> Result<(), BoxError> {
        self.revoke(Self::SESSION, issuer, session_id, (self.clock)()).await
    }

    async fn revoke_subject(&self, issuer: &str, subject: &str, revoked_at: SystemTime) -> Result<(), BoxError> {
        self.revoke(Self::SUBJECT, issuer, subject, revoked_at).await
    }

    async fn is_session_revoked(&self, issuer: &str, session_id: &str) -> Result<bool, BoxError> {
        self.is_revoked(&SsfTokenClaims {
            issuer: Some(issuer.to_owned()),
            subject: None,
            session_id: Some(session_id.to_owned()),
            issued_at: None,
        })
        .await
    }

    async fn subject_revoked_at(&self, issuer: &str, subject: &str) -> Result<Option<SystemTime>, BoxError> {
        let query = format!(
            "SELECT REVOKED_AT FROM {} WHERE KIND = ? AND ISSUER = ? AND ID = ? AND EXPIRES_AT > ?",
            self.table
        );
        let rows = self
            .db
            .query(
                &query,
                Some(1),
                &[
                    Self::SUBJECT.into(),
                    issuer.into(),
                    subject.into(),
                    millis((self.clock)()).into(),
                ],
            )
            .await?;
        Ok(rows.first().and_then(|row| row.i64(0)).map(from_millis))
    }

    async fn is_revoked(&self, claims: &SsfTokenClaims) -> Result<bool, BoxError> {
        let Some(issuer) = &claims.issuer else {
            return Ok(false);
        };
        if claims.session_id.is_none() && claims.subject.is_none() {
            return Ok(false);
        }
        let mut conditions = Vec::new();
        let mut args: Vec<SsfSqlValue> = vec![millis((self.clock)()).into(), issuer.as_str().into()];
        if let Some(session_id) = &claims.session_id {
            conditions.push("(KIND = ? AND ID = ?)");
            args.push(Self::SESSION.into());
            args.push(session_id.as_str().into());
        }
        if let Some(subject) = &claims.subject {
            conditions.push("(KIND = ? AND ID = ?)");
            args.push(Self::SUBJECT.into());
            args.push(subject.as_str().into());
        }
        let query = format!(
            "SELECT KIND, REVOKED_AT FROM {} WHERE EXPIRES_AT > ? AND ISSUER = ? AND ({})",
            self.table,
            conditions.join(" OR ")
        );
        let rows = self.db.query(&query, None, &args).await?;
        let issued_at = claims.issued_at.map(millis);
        Ok(rows.iter().any(|row| {
            row.string(0).as_deref() == Some(Self::SESSION)
                || issued_at.is_none_or(|iat| row.i64(1).is_some_and(|revoked_at| iat <= revoked_at))
        }))
    }
}

#[async_trait]
impl SsfExpiringStore for SqlSsfTokenRevocationStore {
    async fn purge_expired(&self) -> Result<u64, SsfSqlError> {
        let delete = format!("DELETE FROM {} WHERE EXPIRES_AT <= ?", self.table);
        self.db.update(&delete, &[millis((self.clock)()).into()]).await
    }

    fn name(&self) -> &'static str {
        "SqlSsfTokenRevocationStore"
    }
}
