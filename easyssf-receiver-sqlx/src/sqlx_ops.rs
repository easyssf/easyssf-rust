//! [`SsfSqlOperations`] on sqlx.

use std::fmt;

use crate::ops::{SsfSqlError, SsfSqlOperations, SsfSqlRow, SsfSqlValue};

/// SQLSTATE classes of a statement the database did not understand, among them a missing table:
/// standard class 42, and the classes some databases use instead.
const BAD_GRAMMAR_CLASSES: [&str; 7] = ["07", "21", "2A", "37", "42", "65", "S0"];

const MISSING_TABLE_MESSAGES: [&str; 3] = [
    "no such table",  // SQLite
    "does not exist", // PostgreSQL
    "doesn't exist",  // MySQL, MariaDB
];

/// How a database writes positional placeholders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placeholders {
    /// `?`, as SQLite and MySQL have it.
    QuestionMark,
    /// `$1`, `$2`, ..., as PostgreSQL has it.
    Dollar,
}

/// Rewrites the `?` placeholders of a statement for the database, checking that their number
/// matches the arguments. sqlx does not rewrite them itself: PostgreSQL wants `$1`.
pub fn placeholders(sql: &str, arguments: usize, style: Placeholders) -> Result<String, SsfSqlError> {
    let count = sql.matches('?').count();
    if count != arguments {
        return Err(SsfSqlError::failed(
            sql,
            format!("The statement has {count} placeholder(s) but {arguments} argument(s)"),
            None,
        ));
    }
    Ok(match style {
        Placeholders::QuestionMark => sql.to_owned(),
        Placeholders::Dollar => {
            let mut rewritten = String::with_capacity(sql.len() + count * 2);
            let mut index = 0;
            for c in sql.chars() {
                if c == '?' {
                    index += 1;
                    rewritten.push('$');
                    rewritten.push_str(&index.to_string());
                } else {
                    rewritten.push(c);
                }
            }
            rewritten
        }
    })
}

fn translate(sql: &str, error: sqlx::Error) -> SsfSqlError {
    match &error {
        sqlx::Error::Database(database) => {
            let code = database.code().map(|c| c.to_string());
            let message = database.message().to_owned();
            if database.is_unique_violation() || code.as_deref().is_some_and(|c| c.starts_with("23")) {
                return SsfSqlError::DuplicateKey { sql: sql.to_owned() };
            }
            SsfSqlError::failed(sql, message, code)
        }
        other => SsfSqlError::failed(sql, other.to_string(), None),
    }
}

fn is_missing_table(error: &SsfSqlError) -> bool {
    match error {
        SsfSqlError::Failed { message, sqlstate, .. } => match sqlstate {
            Some(sqlstate) if sqlstate.len() >= 2 => BAD_GRAMMAR_CLASSES.contains(&&sqlstate[..2]),
            _ => MISSING_TABLE_MESSAGES
                .iter()
                .any(|m| message.to_ascii_lowercase().contains(&m.to_ascii_lowercase())),
        },
        SsfSqlError::DuplicateKey { .. } => false,
    }
}

/// [`SsfSqlOperations`] on a sqlx pool: [`sqlite`](Self::sqlite), [`postgres`](Self::postgres)
/// and [`mysql`](Self::mysql) behind the features of the same names. Every statement takes a
/// connection from the pool; the statements of the stores are single statements, so no
/// transaction is started.
#[derive(Clone)]
pub struct SqlxSsfSqlOperations {
    inner: Inner,
}

#[derive(Clone)]
enum Inner {
    #[cfg(feature = "sqlite")]
    Sqlite(sqlx::SqlitePool),
    #[cfg(feature = "postgres")]
    Postgres(sqlx::PgPool),
    #[cfg(feature = "mysql")]
    MySql(sqlx::MySqlPool),
}

impl fmt::Debug for SqlxSsfSqlOperations {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match &self.inner {
            #[cfg(feature = "sqlite")]
            Inner::Sqlite(_) => "SqlxSsfSqlOperations(sqlite)",
            #[cfg(feature = "postgres")]
            Inner::Postgres(_) => "SqlxSsfSqlOperations(postgres)",
            #[cfg(feature = "mysql")]
            Inner::MySql(_) => "SqlxSsfSqlOperations(mysql)",
        })
    }
}

impl SqlxSsfSqlOperations {
    /// Runs the statements on SQLite.
    #[cfg(feature = "sqlite")]
    pub fn sqlite(pool: sqlx::SqlitePool) -> Self {
        Self {
            inner: Inner::Sqlite(pool),
        }
    }

    /// Runs the statements on PostgreSQL; the `?` placeholders become `$1`, `$2`, ...
    #[cfg(feature = "postgres")]
    pub fn postgres(pool: sqlx::PgPool) -> Self {
        Self {
            inner: Inner::Postgres(pool),
        }
    }

    /// Runs the statements on MySQL or MariaDB.
    #[cfg(feature = "mysql")]
    pub fn mysql(pool: sqlx::MySqlPool) -> Self {
        Self {
            inner: Inner::MySql(pool),
        }
    }
}

macro_rules! bind_all {
    ($query:expr, $args:expr) => {{
        let mut query = $query;
        for arg in $args {
            query = match arg {
                SsfSqlValue::Null => query.bind(None::<String>),
                SsfSqlValue::Str(value) => query.bind(value.clone()),
                SsfSqlValue::I64(value) => query.bind(*value),
            };
        }
        query
    }};
}

macro_rules! decode_row {
    ($row:expr) => {{
        use sqlx::{Column, Row};
        let row = $row;
        let mut columns = Vec::with_capacity(row.len());
        for index in 0..row.len() {
            let column = row.column(index);
            let value = if let Ok(value) = row.try_get::<Option<i64>, _>(index) {
                value.map_or(SsfSqlValue::Null, SsfSqlValue::I64)
            } else if let Ok(value) = row.try_get::<Option<String>, _>(index) {
                value.map_or(SsfSqlValue::Null, SsfSqlValue::Str)
            } else if let Ok(value) = row.try_get::<Option<i32>, _>(index) {
                value.map_or(SsfSqlValue::Null, |v| SsfSqlValue::I64(v.into()))
            } else if let Ok(value) = row.try_get::<Option<f64>, _>(index) {
                value.map_or(SsfSqlValue::Null, |v| SsfSqlValue::I64(v as i64))
            } else {
                return Err(SsfSqlError::failed(
                    "",
                    format!("Cannot read the column {}", column.name()),
                    None,
                ));
            };
            columns.push(value);
        }
        SsfSqlRow::new(columns)
    }};
}

macro_rules! run {
    ($pool:expr, $style:expr, update, $sql:expr, $args:expr) => {{
        let rewritten = placeholders($sql, $args.len(), $style)?;
        let query = bind_all!(sqlx::query(sqlx::AssertSqlSafe(rewritten)), $args);
        query
            .execute($pool)
            .await
            .map(|result| result.rows_affected())
            .map_err(|e| translate($sql, e))
    }};
    ($pool:expr, $style:expr, query, $sql:expr, $max_rows:expr, $args:expr) => {{
        use futures_util::TryStreamExt;
        let rewritten = placeholders($sql, $args.len(), $style)?;
        let query = bind_all!(sqlx::query(sqlx::AssertSqlSafe(rewritten)), $args);
        let mut stream = query.fetch($pool);
        let mut rows = Vec::new();
        while $max_rows.is_none_or(|max| rows.len() < max) {
            match stream.try_next().await.map_err(|e| translate($sql, e))? {
                Some(row) => rows.push(decode_row!(row)),
                None => break,
            }
        }
        Ok(rows)
    }};
    ($pool:expr, execute, $sql:expr) => {{
        sqlx::query(sqlx::AssertSqlSafe($sql.to_owned()))
            .execute($pool)
            .await
            .map(|_| ())
            .map_err(|e| translate($sql, e))
    }};
}

#[async_trait::async_trait]
impl SsfSqlOperations for SqlxSsfSqlOperations {
    async fn update(&self, sql: &str, args: &[SsfSqlValue]) -> Result<u64, SsfSqlError> {
        match &self.inner {
            #[cfg(feature = "sqlite")]
            Inner::Sqlite(pool) => run!(pool, Placeholders::QuestionMark, update, sql, args),
            #[cfg(feature = "postgres")]
            Inner::Postgres(pool) => run!(pool, Placeholders::Dollar, update, sql, args),
            #[cfg(feature = "mysql")]
            Inner::MySql(pool) => run!(pool, Placeholders::QuestionMark, update, sql, args),
        }
    }

    async fn query(
        &self,
        sql: &str,
        max_rows: Option<usize>,
        args: &[SsfSqlValue],
    ) -> Result<Vec<SsfSqlRow>, SsfSqlError> {
        match &self.inner {
            #[cfg(feature = "sqlite")]
            Inner::Sqlite(pool) => run!(pool, Placeholders::QuestionMark, query, sql, max_rows, args),
            #[cfg(feature = "postgres")]
            Inner::Postgres(pool) => run!(pool, Placeholders::Dollar, query, sql, max_rows, args),
            #[cfg(feature = "mysql")]
            Inner::MySql(pool) => run!(pool, Placeholders::QuestionMark, query, sql, max_rows, args),
        }
    }

    async fn execute(&self, sql: &str) -> Result<(), SsfSqlError> {
        match &self.inner {
            #[cfg(feature = "sqlite")]
            Inner::Sqlite(pool) => run!(pool, execute, sql),
            #[cfg(feature = "postgres")]
            Inner::Postgres(pool) => run!(pool, execute, sql),
            #[cfg(feature = "mysql")]
            Inner::MySql(pool) => run!(pool, execute, sql),
        }
    }

    async fn table_exists(&self, table: &str) -> Result<bool, SsfSqlError> {
        let sql = format!("SELECT COUNT(*) FROM {table} WHERE 1 = 0");
        match self.query(&sql, Some(1), &[]).await {
            Ok(_) => Ok(true),
            Err(error) if is_missing_table(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn is_embedded_database(&self) -> bool {
        match &self.inner {
            #[cfg(feature = "sqlite")]
            Inner::Sqlite(_) => true,
            #[allow(unreachable_patterns)]
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_placeholders_for_postgres_only() {
        assert_eq!(
            placeholders("SELECT ? , ?", 2, Placeholders::Dollar).unwrap(),
            "SELECT $1 , $2"
        );
        assert_eq!(
            placeholders("SELECT ? , ?", 2, Placeholders::QuestionMark).unwrap(),
            "SELECT ? , ?"
        );
        assert!(placeholders("SELECT ?", 2, Placeholders::Dollar).is_err());
        assert!(placeholders("SELECT 1", 1, Placeholders::QuestionMark).is_err());
    }
}
