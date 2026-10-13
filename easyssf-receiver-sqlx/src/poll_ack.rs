//! The poll acknowledgement store on a database table.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use easyssf_receiver::poll::{SsfPendingAck, SsfPollAckStore};
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

/// [`SsfPollAckStore`] that keeps the acknowledgements a poller owes its transmitter in a
/// database table, so that they survive a restart: a SET handled right before the application
/// stopped is acknowledged with the first poll after it started again, instead of being
/// delivered once more.
///
/// Entries a transmitter never accepts are forgotten after the [retention](Self::with_retention)
/// (7 days by default): the store deletes them when it is written to, at most once a minute, and
/// [`purge_expired`](SsfExpiringStore::purge_expired) does so on demand.
pub struct SqlSsfPollAckStore {
    db: Arc<dyn SsfSqlOperations>,
    table_prefix: String,
    table: String,
    insert: String,
    select: String,
    delete_prefix: String,
    count: String,
    delete_expired: String,
    retention: Duration,
    delete_batch_size: usize,
    clock: Clock,
    next_cleanup: Mutex<Option<SystemTime>>,
}

impl SqlSsfPollAckStore {
    const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
    const MAX_DESCRIPTION_LENGTH: usize = 1024;

    /// How many entries one DELETE removes by default; databases limit the number of parameters
    /// of a statement.
    pub const DEFAULT_DELETE_BATCH_SIZE: usize = 100;

    /// A store on the table with the given prefix.
    pub fn new(db: impl SsfSqlOperations, table_prefix: &str) -> Self {
        let table = SsfSqlSchema::poll_ack_table(table_prefix);
        Self {
            db: Arc::new(db),
            table_prefix: table_prefix.to_owned(),
            insert: format!(
                "INSERT INTO {table} (ISSUER, JTI, ERROR_CODE, ERROR_DESCRIPTION, RECORDED_AT) VALUES (?, ?, ?, ?, ?)"
            ),
            // the limit is applied by reading no further, the SQL for it differs between databases
            select: format!(
                "SELECT JTI, ERROR_CODE, ERROR_DESCRIPTION FROM {table} WHERE ISSUER = ? ORDER BY RECORDED_AT, JTI"
            ),
            delete_prefix: format!("DELETE FROM {table} WHERE ISSUER = ? AND JTI IN ("),
            count: format!("SELECT COUNT(*) FROM {table} WHERE ISSUER = ?"),
            delete_expired: format!("DELETE FROM {table} WHERE RECORDED_AT < ?"),
            table,
            retention: Duration::from_secs(7 * 24 * 60 * 60),
            delete_batch_size: Self::DEFAULT_DELETE_BATCH_SIZE,
            clock: system_clock(),
            next_cleanup: Mutex::new(None),
        }
    }

    /// The name of the table.
    pub fn table(&self) -> &str {
        &self.table
    }

    /// How long an entry the transmitter does not accept is kept.
    pub fn with_retention(mut self, retention: Duration) -> Self {
        assert!(!retention.is_zero(), "retention must be positive");
        self.retention = retention;
        self
    }

    /// How many entries one DELETE statement removes (`JTI IN (...)`), 100 by default.
    pub fn with_delete_batch_size(mut self, size: usize) -> Self {
        assert!(size > 0, "delete_batch_size must be positive");
        self.delete_batch_size = size;
        self
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
            &SsfSqlSchema::create_poll_ack_table(&self.table_prefix),
            &[],
            create,
            hint,
        )
        .await
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
impl SsfPollAckStore for SqlSsfPollAckStore {
    async fn record(&self, issuer: &str, ack: SsfPendingAck) -> Result<(), BoxError> {
        let now = (self.clock)();
        self.remove_expired(now).await?;
        let description = ack
            .error_description
            .as_deref()
            .map(|d| d.chars().take(Self::MAX_DESCRIPTION_LENGTH).collect::<String>());
        let args = [
            issuer.into(),
            ack.jti.as_str().into(),
            ack.error_code.as_deref().into(),
            description.into(),
            millis(now).into(),
        ];
        match self.db.update(&self.insert, &args).await {
            Ok(_) => Ok(()),
            // recorded already, for example a SET delivered twice before it was acknowledged
            Err(error) if error.is_duplicate_key() => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn pending(&self, issuer: &str, limit: usize) -> Result<Vec<SsfPendingAck>, BoxError> {
        let rows = self.db.query(&self.select, Some(limit), &[issuer.into()]).await?;
        Ok(rows
            .iter()
            .filter_map(|row| {
                Some(SsfPendingAck {
                    jti: row.string(0)?,
                    error_code: row.string(1),
                    error_description: row.string(2),
                })
            })
            .collect())
    }

    async fn remove(&self, issuer: &str, jtis: &[String]) -> Result<(), BoxError> {
        for chunk in jtis.chunks(self.delete_batch_size) {
            let mut args: Vec<SsfSqlValue> = Vec::with_capacity(chunk.len() + 1);
            args.push(issuer.into());
            args.extend(chunk.iter().map(|jti| SsfSqlValue::from(jti.as_str())));
            let sql = format!("{}{})", self.delete_prefix, vec!["?"; chunk.len()].join(", "));
            self.db.update(&sql, &args).await?;
        }
        Ok(())
    }

    async fn size(&self, issuer: &str) -> Result<usize, BoxError> {
        let rows = self.db.query(&self.count, Some(1), &[issuer.into()]).await?;
        Ok(rows.first().and_then(|row| row.i64(0)).unwrap_or(0).max(0) as usize)
    }
}

#[async_trait]
impl SsfExpiringStore for SqlSsfPollAckStore {
    async fn purge_expired(&self) -> Result<u64, SsfSqlError> {
        let now = (self.clock)();
        *self.next_cleanup.lock().unwrap() = Some(now + Self::CLEANUP_INTERVAL);
        let cutoff = millis(now) - self.retention.as_millis() as i64;
        self.db.update(&self.delete_expired, &[SsfSqlValue::I64(cutoff)]).await
    }

    fn name(&self) -> &'static str {
        "SqlSsfPollAckStore"
    }
}
