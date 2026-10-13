//! The stores built from the configuration of the receiver.

use std::sync::Arc;

use easyssf_receiver::config::{CONFIGURATION_SECTION, SsfReceiverConfig, SsfSchemaInitialization};
use easyssf_receiver::receiver::SsfReceiverBuilder;

use crate::cleanup::{SqlSsfStoreCleanup, SsfExpiringStore};
use crate::dedup::SqlSsfJtiDedupStore;
use crate::ops::{SsfSqlError, SsfSqlOperations};
use crate::poll_ack::SqlSsfPollAckStore;
use crate::revocation::SqlSsfTokenRevocationStore;

/// The database stores of the receiver, built from `easyssf.receiver.data`, `dedup` and
/// `revocation` of its configuration: the counterpart of `AddDatabaseStores()` in .NET and of
/// the JDBC auto-configuration of the Spring Boot starter.
pub struct SsfSqlStores {
    db: Arc<dyn SsfSqlOperations>,
    enabled: bool,
    initialize_schema: SsfSchemaInitialization,
    cleanup_interval: std::time::Duration,
    dedup_store: Arc<SqlSsfJtiDedupStore>,
    revocation_store: Arc<SqlSsfTokenRevocationStore>,
    ack_store: Arc<SqlSsfPollAckStore>,
}

impl SsfSqlStores {
    const HINT: &'static str = "set easyssf.receiver.data.initialize-schema = \"always\" to have it created on startup, or set easyssf.receiver.data.enabled = false to keep the state of the receiver in memory";

    /// The stores on `db` with the settings of the configuration.
    pub fn from_config(db: impl SsfSqlOperations, config: &SsfReceiverConfig) -> Self {
        let db: Arc<dyn SsfSqlOperations> = Arc::new(db);
        let data = &config.data;
        Self {
            dedup_store: Arc::new(
                SqlSsfJtiDedupStore::new(db.clone(), &data.table_prefix)
                    .with_retention(config.dedup.retention)
                    .with_lease(config.dedup.lease),
            ),
            revocation_store: Arc::new(SqlSsfTokenRevocationStore::new(
                db.clone(),
                &data.table_prefix,
                config.revocation.ttl,
            )),
            ack_store: Arc::new(
                SqlSsfPollAckStore::new(db.clone(), &data.table_prefix)
                    .with_retention(data.ack_retention)
                    .with_delete_batch_size(data.ack_delete_batch_size),
            ),
            db,
            enabled: data.enabled,
            initialize_schema: data.initialize_schema,
            cleanup_interval: data.cleanup_interval,
        }
    }

    /// What the stores run their statements with.
    pub fn db(&self) -> &Arc<dyn SsfSqlOperations> {
        &self.db
    }

    /// Whether the stores are used, `easyssf.receiver.data.enabled`.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// The dedup store.
    pub fn dedup_store(&self) -> &Arc<SqlSsfJtiDedupStore> {
        &self.dedup_store
    }

    /// The revocation store.
    pub fn revocation_store(&self) -> &Arc<SqlSsfTokenRevocationStore> {
        &self.revocation_store
    }

    /// The poll acknowledgement store.
    pub fn ack_store(&self) -> &Arc<SqlSsfPollAckStore> {
        &self.ack_store
    }

    /// Whether the tables are to be created, by `easyssf.receiver.data.initialize-schema`.
    pub fn creates_tables(&self) -> bool {
        match self.initialize_schema {
            SsfSchemaInitialization::Always => true,
            SsfSchemaInitialization::Never => false,
            SsfSchemaInitialization::Embedded => self.db.is_embedded_database(),
        }
    }

    /// Checks or creates the three tables, per `easyssf.receiver.data.initialize-schema`. Does
    /// nothing if the stores are disabled.
    ///
    /// # Errors
    ///
    /// If a table is missing or outdated and is not to be changed, with the statements to run:
    /// better at startup than on the first event.
    pub async fn prepare_tables(&self) -> Result<(), SsfSqlError> {
        if !self.enabled {
            return Ok(());
        }
        let create = self.creates_tables();
        self.dedup_store.prepare_table(create, Some(Self::HINT)).await?;
        self.revocation_store.prepare_table(create, Some(Self::HINT)).await?;
        self.ack_store.prepare_table(create, Some(Self::HINT)).await?;
        tracing::info!(
            section = CONFIGURATION_SECTION,
            "The SSF receiver keeps its state in the database"
        );
        Ok(())
    }

    /// A cleanup of the expired rows of the three stores every
    /// `easyssf.receiver.data.cleanup-interval`; start it with [`SqlSsfStoreCleanup::start`].
    pub fn cleanup(&self) -> Arc<SqlSsfStoreCleanup> {
        let stores: Vec<Arc<dyn SsfExpiringStore>> = if self.enabled {
            vec![
                self.dedup_store.clone(),
                self.revocation_store.clone(),
                self.ack_store.clone(),
            ]
        } else {
            Vec::new()
        };
        SqlSsfStoreCleanup::new(stores, self.cleanup_interval)
    }

    /// Gives the receiver the three stores instead of its in-memory ones, unless the stores are
    /// disabled.
    pub fn apply(&self, builder: SsfReceiverBuilder) -> SsfReceiverBuilder {
        if !self.enabled {
            return builder;
        }
        builder
            .jti_dedup_store(self.dedup_store.clone())
            .token_revocation_store(self.revocation_store.clone())
            .poll_ack_store(self.ack_store.clone())
    }
}
