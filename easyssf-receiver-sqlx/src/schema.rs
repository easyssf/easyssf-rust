//! The tables of the stores: their DDL, the upgrades of older releases, and the scripts that ship
//! for a migration tool.

use crate::ops::{SsfSqlError, SsfSqlOperations};

/// A column a current table has and the statement that adds it to a table of an older release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfSqlSchemaUpgrade {
    /// The name of the column.
    pub column: String,
    /// The `ALTER TABLE` that adds it, with a default for the rows that exist.
    pub statement: String,
}

/// A migration script: the schema changes of one release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfSqlMigration {
    /// The file name, `V<release>__<topic>.sql` as Flyway expects it.
    pub name: &'static str,
    /// The script, see [`SsfSqlSchema::statements`].
    pub sql: &'static str,
}

/// The tables of the stores. The same statements, with the default table prefix, are in
/// [`SCHEMA_SQL`](Self::SCHEMA_SQL) to create the tables with a migration tool, and the changes
/// release by release are in [`MIGRATIONS`](Self::MIGRATIONS). The tables are those of the Java
/// library easyssf, byte for byte: an application of any of the three libraries can share them.
pub struct SsfSqlSchema;

impl SsfSqlSchema {
    /// The default prefix of the table names.
    pub const DEFAULT_TABLE_PREFIX: &'static str = "EASYSSF_";

    /// The statements that create the tables of this release, with the default table prefix, as
    /// a script: `schema.sql` of the crate.
    pub const SCHEMA_SQL: &'static str = include_str!("../sql/schema.sql");

    /// The migration scripts, oldest first: a fresh installation runs all of them, or
    /// [`SCHEMA_SQL`](Self::SCHEMA_SQL); an installation of an older release runs those it has
    /// not run yet.
    pub const MIGRATIONS: [SsfSqlMigration; 3] = [
        SsfSqlMigration {
            name: "V0_1_0__processed_sets_and_revocations.sql",
            sql: include_str!("../sql/migration/V0_1_0__processed_sets_and_revocations.sql"),
        },
        SsfSqlMigration {
            name: "V0_3_0__dedup_state_and_poll_acks.sql",
            sql: include_str!("../sql/migration/V0_3_0__dedup_state_and_poll_acks.sql"),
        },
        SsfSqlMigration {
            name: "V0_4_0__state_changed_at.sql",
            sql: include_str!("../sql/migration/V0_4_0__state_changed_at.sql"),
        },
    ];

    /// Where the statements are, for messages.
    pub const SCHEMA_LOCATION: &'static str = "sql/schema.sql of easyssf-receiver-sqlx (SsfSqlSchema::SCHEMA_SQL)";

    /// Where the versioned migration scripts are, for messages.
    pub const MIGRATION_LOCATION: &'static str = "sql/migration/ of easyssf-receiver-sqlx (SsfSqlSchema::MIGRATIONS)";

    /// The table prefix, checked: letters, digits, `_` and `.` only.
    pub fn valid_prefix(table_prefix: &str) -> Result<&str, String> {
        if table_prefix
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        {
            Ok(table_prefix)
        } else {
            Err("The table prefix may only consist of letters, digits, '_' and '.'".to_owned())
        }
    }

    fn prefixed(table_prefix: &str, table: &str) -> String {
        format!(
            "{}{table}",
            Self::valid_prefix(table_prefix).unwrap_or_else(|e| panic!("{e}"))
        )
    }

    /// The name of the table of the [`SqlSsfJtiDedupStore`](crate::SqlSsfJtiDedupStore).
    ///
    /// # Panics
    ///
    /// If the prefix is not valid, see [`valid_prefix`](Self::valid_prefix).
    pub fn processed_set_table(table_prefix: &str) -> String {
        Self::prefixed(table_prefix, "PROCESSED_SET")
    }

    /// The name of the table of the [`SqlSsfTokenRevocationStore`](crate::SqlSsfTokenRevocationStore).
    pub fn revocation_table(table_prefix: &str) -> String {
        Self::prefixed(table_prefix, "REVOCATION")
    }

    /// The name of the table of the [`SqlSsfPollAckStore`](crate::SqlSsfPollAckStore).
    pub fn poll_ack_table(table_prefix: &str) -> String {
        Self::prefixed(table_prefix, "POLL_ACK")
    }

    /// The statements that create the table of the dedup store.
    pub fn create_processed_set_table(table_prefix: &str) -> Vec<String> {
        let table = Self::processed_set_table(table_prefix);
        let name = table.replace('.', "_");
        vec![
            format!(
                "CREATE TABLE {table} (\n    ISSUER VARCHAR(255) NOT NULL,\n    JTI VARCHAR(255) NOT NULL,\n    STATE VARCHAR(16) NOT NULL,\n    STATE_CHANGED_AT BIGINT NOT NULL,\n    CONSTRAINT {name}_PK PRIMARY KEY (ISSUER, JTI)\n)"
            ),
            format!("CREATE INDEX {name}_IX1 ON {table} (STATE_CHANGED_AT)"),
        ]
    }

    /// The columns later releases added to the table of the dedup store: `STATE` in 0.3.0, and
    /// `STATE_CHANGED_AT` in 0.4.0, which is `PROCESSED_AT` renamed because it records the claim
    /// as well as the completion.
    pub fn processed_set_upgrades(table_prefix: &str) -> Vec<SsfSqlSchemaUpgrade> {
        let table = Self::processed_set_table(table_prefix);
        vec![
            SsfSqlSchemaUpgrade {
                column: "STATE".to_owned(),
                statement: format!("ALTER TABLE {table} ADD STATE VARCHAR(16) DEFAULT 'PROCESSED' NOT NULL"),
            },
            SsfSqlSchemaUpgrade {
                column: "STATE_CHANGED_AT".to_owned(),
                statement: format!("ALTER TABLE {table} RENAME COLUMN PROCESSED_AT TO STATE_CHANGED_AT"),
            },
        ]
    }

    /// The statements that create the table of the revocation store.
    pub fn create_revocation_table(table_prefix: &str) -> Vec<String> {
        let table = Self::revocation_table(table_prefix);
        let name = table.replace('.', "_");
        vec![
            format!(
                "CREATE TABLE {table} (\n    KIND VARCHAR(16) NOT NULL,\n    ISSUER VARCHAR(255) NOT NULL,\n    ID VARCHAR(255) NOT NULL,\n    REVOKED_AT BIGINT NOT NULL,\n    EXPIRES_AT BIGINT NOT NULL,\n    CONSTRAINT {name}_PK PRIMARY KEY (KIND, ISSUER, ID)\n)"
            ),
            format!("CREATE INDEX {name}_IX1 ON {table} (EXPIRES_AT)"),
        ]
    }

    /// The statements that create the table of the poll acknowledgement store.
    pub fn create_poll_ack_table(table_prefix: &str) -> Vec<String> {
        let table = Self::poll_ack_table(table_prefix);
        let name = table.replace('.', "_");
        vec![
            format!(
                "CREATE TABLE {table} (\n    ISSUER VARCHAR(255) NOT NULL,\n    JTI VARCHAR(255) NOT NULL,\n    ERROR_CODE VARCHAR(64),\n    ERROR_DESCRIPTION VARCHAR(1024),\n    RECORDED_AT BIGINT NOT NULL,\n    CONSTRAINT {name}_PK PRIMARY KEY (ISSUER, JTI)\n)"
            ),
            format!("CREATE INDEX {name}_IX1 ON {table} (RECORDED_AT)"),
        ]
    }

    /// Makes sure a table exists and has the columns of this release. `create` says whether to
    /// create a missing table and to add missing columns to an existing one; `hint` is what else
    /// the application could do, appended to the message of the error.
    ///
    /// # Errors
    ///
    /// If the table does not exist or lacks a column and is not to be changed; the message
    /// carries the statements to run.
    pub async fn prepare_table(
        db: &dyn SsfSqlOperations,
        table: &str,
        create_statements: &[String],
        upgrades: &[SsfSqlSchemaUpgrade],
        create: bool,
        hint: Option<&str>,
    ) -> Result<(), SsfSqlError> {
        let or_else = hint
            .filter(|h| !h.trim().is_empty())
            .map(|h| format!(", {h}"))
            .unwrap_or_default();
        if !db.table_exists(table).await? {
            if !create {
                return Err(SsfSqlError::failed(
                    "",
                    format!(
                        "The table {table} of the easyssf receiver does not exist. Create it with the statements in {}{or_else}.",
                        Self::SCHEMA_LOCATION
                    ),
                    None,
                ));
            }
            for statement in create_statements {
                db.execute(statement).await?;
            }
            return Ok(());
        }
        let missing = Self::missing_upgrades(db, table, upgrades).await;
        if missing.is_empty() {
            return Ok(());
        }
        if !create {
            return Err(SsfSqlError::failed(
                "",
                format!("{}{or_else}.", Self::predates_message(table, &missing)),
                None,
            ));
        }
        for upgrade in missing {
            if let Err(error) = db.execute(&upgrade.statement).await {
                // another instance starting at the same time may have added the column
                if !Self::column_exists(db, table, &upgrade.column).await {
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// The upgrades whose column the existing table lacks.
    pub async fn missing_upgrades(
        db: &dyn SsfSqlOperations,
        table: &str,
        upgrades: &[SsfSqlSchemaUpgrade],
    ) -> Vec<SsfSqlSchemaUpgrade> {
        let mut missing = Vec::new();
        for upgrade in upgrades {
            if !Self::column_exists(db, table, &upgrade.column).await {
                missing.push(upgrade.clone());
            }
        }
        missing
    }

    /// The message that a table predates this release, with the statements to run.
    pub fn predates_message(table: &str, missing: &[SsfSqlSchemaUpgrade]) -> String {
        format!(
            "The table {table} of the easyssf receiver predates this release and lacks the column(s) [{}]. Run [{}] or the migration scripts in {}",
            missing.iter().map(|u| u.column.as_str()).collect::<Vec<_>>().join(", "),
            missing
                .iter()
                .map(|u| u.statement.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            Self::MIGRATION_LOCATION
        )
    }

    /// Splits a script ([`SCHEMA_SQL`](Self::SCHEMA_SQL), a migration) into its statements:
    /// comments removed, separated at `;`, whitespace normalised.
    pub fn statements(script: &str) -> Vec<String> {
        let without_comments: String = script
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .map(|line| format!("{line}\n"))
            .collect();
        without_comments
            .split(';')
            .map(|statement| statement.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|statement| !statement.is_empty())
            .collect()
    }

    async fn column_exists(db: &dyn SsfSqlOperations, table: &str, column: &str) -> bool {
        db.query(&format!("SELECT {column} FROM {table} WHERE 1 = 0"), Some(1), &[])
            .await
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_file_matches_the_statements_that_create_the_tables() {
        let mut expected = Vec::new();
        expected.extend(SsfSqlSchema::create_processed_set_table(
            SsfSqlSchema::DEFAULT_TABLE_PREFIX,
        ));
        expected.extend(SsfSqlSchema::create_revocation_table(
            SsfSqlSchema::DEFAULT_TABLE_PREFIX,
        ));
        expected.extend(SsfSqlSchema::create_poll_ack_table(SsfSqlSchema::DEFAULT_TABLE_PREFIX));
        let expected: Vec<String> = expected
            .iter()
            .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
            .collect();
        assert_eq!(SsfSqlSchema::statements(SsfSqlSchema::SCHEMA_SQL), expected);
    }

    #[test]
    fn table_prefix_is_configurable_but_restricted() {
        assert_eq!(SsfSqlSchema::processed_set_table("app.ssf_"), "app.ssf_PROCESSED_SET");
        assert_eq!(SsfSqlSchema::revocation_table(""), "REVOCATION");
        assert!(SsfSqlSchema::valid_prefix("bad prefix").is_err());
        assert!(SsfSqlSchema::valid_prefix("x;DROP").is_err());
    }

    #[test]
    fn migrations_are_listed_oldest_first() {
        assert_eq!(
            SsfSqlSchema::MIGRATIONS[0].name,
            "V0_1_0__processed_sets_and_revocations.sql"
        );
        assert!(
            SsfSqlSchema::MIGRATIONS
                .iter()
                .all(|m| !SsfSqlSchema::statements(m.sql).is_empty())
        );
    }
}
