//! Runs the SQL of the stores.

use std::sync::Arc;

use async_trait::async_trait;

/// A value bound to a `?` placeholder, or read from a column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsfSqlValue {
    /// SQL NULL.
    Null,
    /// A `VARCHAR`.
    Str(String),
    /// A `BIGINT`.
    I64(i64),
}

impl From<&str> for SsfSqlValue {
    fn from(value: &str) -> Self {
        Self::Str(value.to_owned())
    }
}

impl From<String> for SsfSqlValue {
    fn from(value: String) -> Self {
        Self::Str(value)
    }
}

impl From<i64> for SsfSqlValue {
    fn from(value: i64) -> Self {
        Self::I64(value)
    }
}

impl From<Option<&str>> for SsfSqlValue {
    fn from(value: Option<&str>) -> Self {
        value.map_or(Self::Null, Self::from)
    }
}

impl From<Option<String>> for SsfSqlValue {
    fn from(value: Option<String>) -> Self {
        value.map_or(Self::Null, Self::Str)
    }
}

/// A row of a query result.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SsfSqlRow {
    /// The columns, in the order of the query.
    pub columns: Vec<SsfSqlValue>,
}

impl SsfSqlRow {
    /// A row with the given columns.
    pub fn new(columns: Vec<SsfSqlValue>) -> Self {
        Self { columns }
    }

    /// The string of a column, `None` if NULL. A number is rendered as text.
    pub fn string(&self, index: usize) -> Option<String> {
        match self.columns.get(index) {
            Some(SsfSqlValue::Str(value)) => Some(value.clone()),
            Some(SsfSqlValue::I64(value)) => Some(value.to_string()),
            _ => None,
        }
    }

    /// The integer of a column, `None` if NULL. A numeric string is parsed, as some drivers
    /// return `BIGINT` that way.
    pub fn i64(&self, index: usize) -> Option<i64> {
        match self.columns.get(index) {
            Some(SsfSqlValue::I64(value)) => Some(*value),
            Some(SsfSqlValue::Str(value)) => value.trim().parse().ok(),
            _ => None,
        }
    }
}

/// A statement of a store failed.
#[derive(Debug, thiserror::Error)]
pub enum SsfSqlError {
    /// An insert violated a unique constraint: the row exists already.
    #[error("Duplicate key: {sql}")]
    DuplicateKey {
        /// The statement.
        sql: String,
    },
    /// The statement failed otherwise.
    #[error("Could not run {sql}: {message}")]
    Failed {
        /// The statement.
        sql: String,
        /// What the database said.
        message: String,
        /// The SQLSTATE of the failure, `None` if the driver gave none.
        sqlstate: Option<String>,
    },
}

impl SsfSqlError {
    /// A failure of a statement.
    pub fn failed(sql: &str, message: impl Into<String>, sqlstate: Option<String>) -> Self {
        Self::Failed {
            sql: sql.to_owned(),
            message: message.into(),
            sqlstate,
        }
    }

    /// Whether the failure reports a unique constraint violation.
    pub fn is_duplicate_key(&self) -> bool {
        matches!(self, Self::DuplicateKey { .. })
    }

    /// The SQLSTATE, `None` for a duplicate key or if the driver gave none.
    pub fn sqlstate(&self) -> Option<&str> {
        match self {
            Self::Failed { sqlstate, .. } => sqlstate.as_deref(),
            Self::DuplicateKey { .. } => None,
        }
    }
}

/// Runs the SQL of the stores. Implement it over whatever the application uses to access its
/// database, so that its connection pool and transactions apply; [`SqlxSsfSqlOperations`](crate::SqlxSsfSqlOperations)
/// is the implementation on sqlx.
///
/// The statements of the stores use `?` as placeholder, in the order of the arguments, and
/// standard SQL that runs unchanged on SQLite, PostgreSQL and MySQL.
#[async_trait]
pub trait SsfSqlOperations: Send + Sync + 'static {
    /// Runs an insert, update or delete and returns the number of rows affected.
    ///
    /// # Errors
    ///
    /// [`SsfSqlError::DuplicateKey`] if the statement violates a unique constraint,
    /// [`SsfSqlError::Failed`] otherwise.
    async fn update(&self, sql: &str, args: &[SsfSqlValue]) -> Result<u64, SsfSqlError>;

    /// Runs a query and returns at most `max_rows` rows (all if `None`). The limit is applied
    /// by reading no further, which every driver supports, rather than with the SQL for it,
    /// which differs between databases (`FETCH FIRST`, `LIMIT`, `TOP`).
    async fn query(
        &self,
        sql: &str,
        max_rows: Option<usize>,
        args: &[SsfSqlValue],
    ) -> Result<Vec<SsfSqlRow>, SsfSqlError>;

    /// Runs a statement that returns nothing, for example DDL.
    async fn execute(&self, sql: &str) -> Result<(), SsfSqlError>;

    /// Whether the table exists.
    async fn table_exists(&self, table: &str) -> Result<bool, SsfSqlError>;

    /// Whether the database is an embedded one (SQLite), which an application creates the
    /// tables in without a migration tool. `false` by default.
    fn is_embedded_database(&self) -> bool {
        false
    }
}

#[async_trait]
impl<T: SsfSqlOperations> SsfSqlOperations for Arc<T> {
    async fn update(&self, sql: &str, args: &[SsfSqlValue]) -> Result<u64, SsfSqlError> {
        (**self).update(sql, args).await
    }

    async fn query(
        &self,
        sql: &str,
        max_rows: Option<usize>,
        args: &[SsfSqlValue],
    ) -> Result<Vec<SsfSqlRow>, SsfSqlError> {
        (**self).query(sql, max_rows, args).await
    }

    async fn execute(&self, sql: &str) -> Result<(), SsfSqlError> {
        (**self).execute(sql).await
    }

    async fn table_exists(&self, table: &str) -> Result<bool, SsfSqlError> {
        (**self).table_exists(table).await
    }

    fn is_embedded_database(&self) -> bool {
        (**self).is_embedded_database()
    }
}

#[async_trait]
impl SsfSqlOperations for Arc<dyn SsfSqlOperations> {
    async fn update(&self, sql: &str, args: &[SsfSqlValue]) -> Result<u64, SsfSqlError> {
        (**self).update(sql, args).await
    }

    async fn query(
        &self,
        sql: &str,
        max_rows: Option<usize>,
        args: &[SsfSqlValue],
    ) -> Result<Vec<SsfSqlRow>, SsfSqlError> {
        (**self).query(sql, max_rows, args).await
    }

    async fn execute(&self, sql: &str) -> Result<(), SsfSqlError> {
        (**self).execute(sql).await
    }

    async fn table_exists(&self, table: &str) -> Result<bool, SsfSqlError> {
        (**self).table_exists(table).await
    }

    fn is_embedded_database(&self) -> bool {
        (**self).is_embedded_database()
    }
}
