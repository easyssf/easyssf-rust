//! The database stores of the easyssf receiver on sqlx: processed SETs, revocations and the
//! acknowledgements a poller owes, in the three tables the Java and .NET libraries use
//! (`EASYSSF_PROCESSED_SET`, `EASYSSF_REVOCATION`, `EASYSSF_POLL_ACK`), so that applications of
//! any of the three can share one database.
//!
//! The stores are plain SQL over [`SsfSqlOperations`]: `?` placeholders in the order of the
//! arguments, `VARCHAR` and `BIGINT`, timestamps as milliseconds since the epoch, no vendor
//! syntax; a result limit is applied by reading no further, never with `LIMIT`. The
//! [`sqlx`](SqlxSsfSqlOperations) implementations (features `sqlite`, `postgres`, `mysql`)
//! rewrite the placeholders for PostgreSQL, which sqlx does not do; an application on another
//! data access layer implements the trait itself.
//!
//! ```no_run
//! # use easyssf_receiver::{SsfReceiver, config::SsfReceiverConfig};
//! # use easyssf_receiver_sqlx::{SqlxSsfSqlOperations, SsfSqlStores};
//! # async fn run(config: SsfReceiverConfig, pool: sqlx::SqlitePool) -> Result<(), easyssf_receiver::BoxError> {
//! let stores = SsfSqlStores::from_config(SqlxSsfSqlOperations::sqlite(pool), &config);
//! stores.prepare_tables().await?;          // checks or creates the tables, per easyssf.receiver.data
//! let cleanup = stores.cleanup();          // purges expired rows every data.cleanup-interval
//! cleanup.start();
//! let receiver = stores.apply(SsfReceiver::builder(config)).build()?;
//! # Ok(()) }
//! ```

mod cleanup;
mod dedup;
mod ops;
mod poll_ack;
mod revocation;
mod schema;
mod sqlx_ops;
mod stores;

pub use cleanup::{SqlSsfStoreCleanup, SsfExpiringStore};
pub use dedup::SqlSsfJtiDedupStore;
pub use ops::{SsfSqlError, SsfSqlOperations, SsfSqlRow, SsfSqlValue};
pub use poll_ack::SqlSsfPollAckStore;
pub use revocation::SqlSsfTokenRevocationStore;
pub use schema::{SsfSqlMigration, SsfSqlSchema, SsfSqlSchemaUpgrade};
pub use sqlx_ops::{SqlxSsfSqlOperations, placeholders};
pub use stores::SsfSqlStores;
