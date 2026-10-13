//! The dedup store on a database table.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use easyssf_core::SsfEventToken;
use easyssf_receiver::set::{SsfJtiClaim, SsfJtiDedupStore};
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

/// [`SsfJtiDedupStore`] that remembers processed SETs in a database table shared by the
/// instances of an application: a SET delivered to several of them or again after a restart is
/// handled by one and skipped by the others, and a SET one instance is handling is left alone by
/// the rest. Processing stays at least once, see [`SsfJtiDedupStore`].
///
/// A claim inserts the row with the state `IN_PROGRESS`: the primary key of the table makes that
/// atomic, and a second instance that meets the row leaves the SET alone. The handlers' success
/// turns the state into `PROCESSED`. `STATE_CHANGED_AT` is the time of the last state change, so
/// an `IN_PROGRESS` row older than the [lease](Self::with_lease) (60 seconds by default) counts
/// as abandoned by a crashed instance and the next claim takes it over. That `STATE_CHANGED_AT`
/// is also the token of the claim: the success or failure of the handlers only changes the row
/// while it still carries the token they were granted, so an instance that outlived the lease
/// leaves the claim of the taker-over alone. A renewal moves `STATE_CHANGED_AT` forward the same
/// way a take-over does, fenced by the current token, and the new value is the token of the
/// renewed claim.
///
/// SETs are forgotten after the [retention](Self::with_retention): the store deletes them when it
/// is written to, at most once a minute, and [`purge_expired`](SsfExpiringStore::purge_expired)
/// does so on demand. The table is checked or created with [`prepare_table`](Self::prepare_table);
/// the constructor does not touch the database.
pub struct SqlSsfJtiDedupStore {
    db: Arc<dyn SsfSqlOperations>,
    table_prefix: String,
    table: String,
    insert: String,
    select: String,
    move_claim: String,
    mark_processed: String,
    delete: String,
    delete_expired: String,
    retention: Duration,
    lease: Duration,
    clock: Clock,
    next_cleanup: Mutex<Option<SystemTime>>,
}

impl SqlSsfJtiDedupStore {
    const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
    const IN_PROGRESS: &'static str = "IN_PROGRESS";
    const PROCESSED: &'static str = "PROCESSED";

    /// A store on the table with the given prefix, see [`SsfSqlSchema::DEFAULT_TABLE_PREFIX`].
    pub fn new(db: impl SsfSqlOperations, table_prefix: &str) -> Self {
        let table = SsfSqlSchema::processed_set_table(table_prefix);
        Self {
            db: Arc::new(db),
            table_prefix: table_prefix.to_owned(),
            insert: format!("INSERT INTO {table} (ISSUER, JTI, STATE, STATE_CHANGED_AT) VALUES (?, ?, ?, ?)"),
            select: format!("SELECT STATE, STATE_CHANGED_AT FROM {table} WHERE ISSUER = ? AND JTI = ?"),
            // a take-over and a renewal both move the claim's token forward, fenced by the current one
            move_claim: format!(
                "UPDATE {table} SET STATE_CHANGED_AT = ? WHERE ISSUER = ? AND JTI = ? AND STATE = '{}' AND STATE_CHANGED_AT = ?",
                Self::IN_PROGRESS
            ),
            // processed and forget are fenced by the claim's token, the STATE_CHANGED_AT of the claim
            mark_processed: format!(
                "UPDATE {table} SET STATE = '{}', STATE_CHANGED_AT = ? WHERE ISSUER = ? AND JTI = ? AND STATE = '{}' AND STATE_CHANGED_AT = ?",
                Self::PROCESSED,
                Self::IN_PROGRESS
            ),
            delete: format!(
                "DELETE FROM {table} WHERE ISSUER = ? AND JTI = ? AND STATE = '{}' AND STATE_CHANGED_AT = ?",
                Self::IN_PROGRESS
            ),
            delete_expired: format!("DELETE FROM {table} WHERE STATE_CHANGED_AT < ?"),
            table,
            retention: Duration::from_secs(7 * 24 * 60 * 60),
            lease: Duration::from_secs(60),
            clock: system_clock(),
            next_cleanup: Mutex::new(None),
        }
    }

    /// The name of the table.
    pub fn table(&self) -> &str {
        &self.table
    }

    /// How long a processed SET is remembered, 7 days by default. Has to cover the time the
    /// transmitter keeps trying to deliver a SET.
    pub fn with_retention(mut self, retention: Duration) -> Self {
        assert!(!retention.is_zero(), "retention must be positive");
        self.retention = retention;
        self
    }

    /// How long a claim holds before the SET counts as abandoned by a crashed instance and is
    /// handled again; 60 seconds by default, longer than the longest handler.
    pub fn with_lease(mut self, lease: Duration) -> Self {
        assert!(!lease.is_zero(), "lease must be positive");
        self.lease = lease;
        self
    }

    /// The clock of the store.
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Makes sure the table exists and has the columns of this release, see
    /// [`SsfSqlSchema::prepare_table`]. `create` says whether to create a missing table and to
    /// add missing columns; `hint` is what else the application could do, for the message.
    pub async fn prepare_table(&self, create: bool, hint: Option<&str>) -> Result<(), SsfSqlError> {
        SsfSqlSchema::prepare_table(
            &*self.db,
            &self.table,
            &SsfSqlSchema::create_processed_set_table(&self.table_prefix),
            &SsfSqlSchema::processed_set_upgrades(&self.table_prefix),
            create,
            hint,
        )
        .await
    }

    async fn select(&self, token: &SsfEventToken) -> Result<Option<(String, i64)>, SsfSqlError> {
        let rows = self
            .db
            .query(&self.select, Some(1), &[token.issuer().into(), token.jti().into()])
            .await?;
        Ok(rows.first().and_then(|row| Some((row.string(0)?, row.i64(1)?))))
    }

    async fn remove_expired(&self, now: SystemTime) -> Result<(), SsfSqlError> {
        let due = self.next_cleanup.lock().unwrap().is_none_or(|next| now > next);
        if due {
            self.purge_expired().await?;
        }
        Ok(())
    }
}

#[async_trait]
impl SsfJtiDedupStore for SqlSsfJtiDedupStore {
    async fn claim(&self, token: &SsfEventToken) -> Result<SsfJtiClaim, BoxError> {
        let now = (self.clock)();
        self.remove_expired(now).await?;
        let claim_token = millis(now);
        let args = [
            token.issuer().into(),
            token.jti().into(),
            Self::IN_PROGRESS.into(),
            claim_token.into(),
        ];
        match self.db.update(&self.insert, &args).await {
            Ok(_) => Ok(SsfJtiClaim::Granted(claim_token)),
            Err(error) if error.is_duplicate_key() => {
                let Some((state, since)) = self.select(token).await? else {
                    // deleted in between: the redelivery will be claimed
                    return Ok(SsfJtiClaim::InProgress);
                };
                if state == Self::PROCESSED {
                    return Ok(SsfJtiClaim::Processed);
                }
                if since + self.lease.as_millis() as i64 <= claim_token {
                    // abandoned: take it over, unless another instance did just now. The new
                    // STATE_CHANGED_AT is the token of the new claim; the old holder's token no
                    // longer matches, so it can neither complete nor forget this claim.
                    let taken = self
                        .db
                        .update(
                            &self.move_claim,
                            &[
                                claim_token.into(),
                                token.issuer().into(),
                                token.jti().into(),
                                since.into(),
                            ],
                        )
                        .await?;
                    return Ok(if taken == 1 {
                        SsfJtiClaim::Granted(claim_token)
                    } else {
                        SsfJtiClaim::InProgress
                    });
                }
                Ok(SsfJtiClaim::InProgress)
            }
            Err(error) => Err(error.into()),
        }
    }

    async fn processed(&self, token: &SsfEventToken, claim: SsfJtiClaim) -> Result<(), BoxError> {
        let now = millis((self.clock)());
        let updated = self
            .db
            .update(
                &self.mark_processed,
                &[
                    now.into(),
                    token.issuer().into(),
                    token.jti().into(),
                    claim.token().into(),
                ],
            )
            .await?;
        if updated == 0 && self.select(token).await?.is_none() {
            // the claim was purged in between: record the success anyway. A duplicate means
            // another instance claimed the SET since, which then owns it.
            let args = [
                token.issuer().into(),
                token.jti().into(),
                Self::PROCESSED.into(),
                now.into(),
            ];
            match self.db.update(&self.insert, &args).await {
                Ok(_) => {}
                Err(error) if error.is_duplicate_key() => {}
                Err(error) => return Err(error.into()),
            }
        }
        // otherwise the claim was taken over after the lease: the SET belongs to the new holder
        Ok(())
    }

    async fn forget(&self, token: &SsfEventToken, claim: SsfJtiClaim) -> Result<(), BoxError> {
        self.db
            .update(
                &self.delete,
                &[token.issuer().into(), token.jti().into(), claim.token().into()],
            )
            .await?;
        Ok(())
    }

    async fn renew(&self, token: &SsfEventToken, claim: SsfJtiClaim) -> Result<Option<SsfJtiClaim>, BoxError> {
        // the new STATE_CHANGED_AT is the token of the renewed claim: later than the old one even
        // within the same millisecond, so that the row is seen as changed
        let renewed_token = millis((self.clock)()).max(claim.token() + 1);
        let renewed = self
            .db
            .update(
                &self.move_claim,
                &[
                    renewed_token.into(),
                    token.issuer().into(),
                    token.jti().into(),
                    claim.token().into(),
                ],
            )
            .await?;
        Ok((renewed == 1).then_some(SsfJtiClaim::Granted(renewed_token)))
    }
}

#[async_trait]
impl SsfExpiringStore for SqlSsfJtiDedupStore {
    async fn purge_expired(&self) -> Result<u64, SsfSqlError> {
        let now = (self.clock)();
        *self.next_cleanup.lock().unwrap() = Some(now + Self::CLEANUP_INTERVAL);
        let cutoff = millis(now) - self.retention.as_millis() as i64;
        self.db.update(&self.delete_expired, &[SsfSqlValue::I64(cutoff)]).await
    }

    fn name(&self) -> &'static str {
        "SqlSsfJtiDedupStore"
    }
}
