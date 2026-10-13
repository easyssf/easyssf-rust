//! `AbstractJdbcSsfStoresTests` and `DataSourceSsfJdbcOperationsTests` of the Java library, on
//! SQLite always, and on PostgreSQL and MySQL when `EASYSSF_DATABASE_TESTS=true` and
//! `EASYSSF_POSTGRES_URL` / `EASYSSF_MYSQL_URL` name the databases (features `postgres`,
//! `mysql`).

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use easyssf_core::SsfEventToken;
use easyssf_receiver::Clock;
use easyssf_receiver::poll::{SsfPendingAck, SsfPollAckStore};
use easyssf_receiver::revocation::{SsfTokenClaims, SsfTokenRevocationStore};
use easyssf_receiver::set::{SsfJtiClaim, SsfJtiDedupStore};
#[allow(unused_imports)]
use easyssf_receiver_sqlx::SsfSqlRow;
use easyssf_receiver_sqlx::{
    SqlSsfJtiDedupStore, SqlSsfPollAckStore, SqlSsfStoreCleanup, SqlSsfTokenRevocationStore, SqlxSsfSqlOperations,
    SsfExpiringStore, SsfSqlError, SsfSqlOperations, SsfSqlSchema, SsfSqlValue,
};
use serde_json::json;

const PREFIX: &str = "EASYSSF_";

#[derive(Clone)]
struct TestClock(Arc<Mutex<SystemTime>>);

impl TestClock {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(SystemTime::now())))
    }

    fn clock(&self) -> Clock {
        let time = self.0.clone();
        Arc::new(move || *time.lock().unwrap())
    }

    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }

    fn advance(&self, duration: Duration) {
        *self.0.lock().unwrap() += duration;
    }
}

/// Serialises the tests on PostgreSQL and MySQL: cargo runs the tests in parallel, and these two
/// databases are shared by all of them, each dropping and creating the same tables. SQLite is in
/// memory and private to the test, so the default run stays parallel.
static SHARED_DATABASES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The databases of one test, holding the lock on the shared ones until the test is done with them.
struct Databases {
    databases: std::vec::IntoIter<(&'static str, Arc<dyn SsfSqlOperations>)>,
    _shared: Option<tokio::sync::MutexGuard<'static, ()>>,
}

impl Iterator for Databases {
    type Item = (&'static str, Arc<dyn SsfSqlOperations>);

    fn next(&mut self) -> Option<Self::Item> {
        self.databases.next()
    }
}

/// Every database the tests run on: SQLite in memory always, the others when opted in.
async fn databases() -> Databases {
    let mut all: Vec<(&'static str, Arc<dyn SsfSqlOperations>)> = Vec::new();
    let mut shared = None;
    let sqlite = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    all.push(("sqlite", Arc::new(SqlxSsfSqlOperations::sqlite(sqlite))));
    if std::env::var("EASYSSF_DATABASE_TESTS").ok().as_deref() == Some("true") {
        shared = Some(SHARED_DATABASES.lock().await);
        #[cfg(feature = "postgres")]
        if let Ok(url) = std::env::var("EASYSSF_POSTGRES_URL") {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(4)
                .connect(&url)
                .await
                .unwrap();
            drop_tables(&SqlxSsfSqlOperations::postgres(pool.clone())).await;
            all.push(("postgres", Arc::new(SqlxSsfSqlOperations::postgres(pool))));
        }
        #[cfg(feature = "mysql")]
        if let Ok(url) = std::env::var("EASYSSF_MYSQL_URL") {
            let pool = sqlx::mysql::MySqlPoolOptions::new()
                .max_connections(4)
                .connect(&url)
                .await
                .unwrap();
            drop_tables(&SqlxSsfSqlOperations::mysql(pool.clone())).await;
            all.push(("mysql", Arc::new(SqlxSsfSqlOperations::mysql(pool))));
        }
    }
    Databases {
        databases: all.into_iter(),
        _shared: shared,
    }
}

#[allow(dead_code)]
async fn drop_tables(db: &dyn SsfSqlOperations) {
    for table in [
        "EASYSSF_PROCESSED_SET",
        "EASYSSF_REVOCATION",
        "EASYSSF_POLL_ACK",
        "X_PROCESSED_SET",
    ] {
        let _ = db.execute(&format!("DROP TABLE {table}")).await;
    }
}

async fn create_tables(db: &dyn SsfSqlOperations) {
    for statement in SsfSqlSchema::statements(SsfSqlSchema::SCHEMA_SQL) {
        db.execute(&statement).await.unwrap();
    }
}

fn token(jti: &str) -> SsfEventToken {
    let claims = json!({ "jti": jti, "iss": "https://t.example", "iat": 1, "events": { "e": {} } });
    SsfEventToken::from_claims(claims.as_object().unwrap().clone()).unwrap()
}

fn claims(issuer: &str, subject: Option<&str>, session: Option<&str>, issued_at: Option<SystemTime>) -> SsfTokenClaims {
    SsfTokenClaims {
        issuer: Some(issuer.to_owned()),
        subject: subject.map(str::to_owned),
        session_id: session.map(str::to_owned),
        issued_at,
    }
}

#[tokio::test]
async fn migration_scripts_lead_to_the_current_schema() {
    for (name, db) in databases().await {
        for migration in SsfSqlSchema::MIGRATIONS {
            for statement in SsfSqlSchema::statements(migration.sql) {
                db.execute(&statement).await.unwrap_or_else(|e| panic!("{name}: {e}"));
            }
        }
        let upgrades = SsfSqlSchema::processed_set_upgrades(PREFIX);
        assert!(
            SsfSqlSchema::missing_upgrades(&*db, "EASYSSF_PROCESSED_SET", &upgrades)
                .await
                .is_empty(),
            "{name}"
        );
        assert!(db.table_exists("EASYSSF_REVOCATION").await.unwrap());
        assert!(db.table_exists("EASYSSF_POLL_ACK").await.unwrap());
        // the stores work on the migrated tables
        let store = SqlSsfJtiDedupStore::new(db.clone(), PREFIX);
        store.prepare_table(false, None).await.unwrap();
        assert!(store.claim(&token("1")).await.unwrap().is_granted());
    }
}

#[tokio::test]
async fn missing_columns_are_added_where_tables_may_be_created_and_reported_otherwise() {
    for (name, db) in databases().await {
        // the table of 0.1.0
        for statement in SsfSqlSchema::statements(SsfSqlSchema::MIGRATIONS[0].sql) {
            db.execute(&statement).await.unwrap();
        }
        let store = SqlSsfJtiDedupStore::new(db.clone(), PREFIX);
        let error = store
            .prepare_table(false, Some("do something"))
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("predates this release"), "{name}: {error}");
        assert!(
            error.contains("STATE") && error.contains("RENAME COLUMN") && error.contains("do something"),
            "{name}: {error}"
        );
        store.prepare_table(true, None).await.unwrap();
        assert!(
            SsfSqlSchema::missing_upgrades(
                &*db,
                "EASYSSF_PROCESSED_SET",
                &SsfSqlSchema::processed_set_upgrades(PREFIX)
            )
            .await
            .is_empty()
        );
        assert!(store.claim(&token("1")).await.unwrap().is_granted(), "{name}");
    }
}

#[tokio::test]
async fn table_of_0dot3dot0_is_upgraded_by_renaming_the_column() {
    for (name, db) in databases().await {
        for migration in &SsfSqlSchema::MIGRATIONS[..2] {
            for statement in SsfSqlSchema::statements(migration.sql) {
                db.execute(&statement).await.unwrap();
            }
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        db.update(
            "INSERT INTO EASYSSF_PROCESSED_SET (ISSUER, JTI, PROCESSED_AT, STATE) VALUES (?, ?, ?, ?)",
            &["https://t.example".into(), "old".into(), now.into(), "PROCESSED".into()],
        )
        .await
        .unwrap();
        let store = SqlSsfJtiDedupStore::new(db.clone(), PREFIX);
        store.prepare_table(true, None).await.unwrap();
        assert_eq!(
            store.claim(&token("old")).await.unwrap(),
            SsfJtiClaim::Processed,
            "{name}: the row survived the rename"
        );
    }
}

#[tokio::test]
async fn preparing_tables_is_repeatable_and_reports_missing_tables() {
    for (name, db) in databases().await {
        let store = SqlSsfTokenRevocationStore::new(db.clone(), PREFIX, Duration::from_secs(60));
        let error = store
            .prepare_table(false, Some("or else"))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("does not exist") && error.contains("or else"),
            "{name}: {error}"
        );
        store.prepare_table(true, None).await.unwrap();
        store.prepare_table(true, None).await.unwrap();
        store.prepare_table(false, None).await.unwrap();
        let acks = SqlSsfPollAckStore::new(db.clone(), PREFIX);
        acks.prepare_table(true, None).await.unwrap();
        acks.prepare_table(false, None).await.unwrap();
    }
}

#[tokio::test]
async fn table_prefix_is_configurable_but_restricted() {
    for (_, db) in databases().await {
        let store = SqlSsfJtiDedupStore::new(db.clone(), "X_");
        assert_eq!(store.table(), "X_PROCESSED_SET");
        store.prepare_table(true, None).await.unwrap();
        assert!(db.table_exists("X_PROCESSED_SET").await.unwrap());
    }
    assert!(std::panic::catch_unwind(|| SsfSqlSchema::processed_set_table("bad prefix")).is_err());
}

#[tokio::test]
async fn set_is_seen_before_once_it_was_recorded() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let store = SqlSsfJtiDedupStore::new(db.clone(), PREFIX);
        let set = token("1");
        let claim = store.claim(&set).await.unwrap();
        assert!(claim.is_granted(), "{name}");
        store.processed(&set, claim).await.unwrap();
        assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::Processed);
        // another issuer with the same jti is another SET
        let other = SsfEventToken::from_claims(
            json!({ "jti": "1", "iss": "https://other.example", "iat": 1, "events": { "e": {} } })
                .as_object()
                .unwrap()
                .clone(),
        )
        .unwrap();
        assert!(store.claim(&other).await.unwrap().is_granted());
    }
}

#[tokio::test]
async fn processed_sets_are_shared_between_instances() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let first = SqlSsfJtiDedupStore::new(db.clone(), PREFIX);
        let second = SqlSsfJtiDedupStore::new(db.clone(), PREFIX);
        let set = token("1");
        let claim = first.claim(&set).await.unwrap();
        first.processed(&set, claim).await.unwrap();
        assert_eq!(second.claim(&set).await.unwrap(), SsfJtiClaim::Processed, "{name}");
    }
}

#[tokio::test]
async fn claim_tells_whether_another_instance_is_on_the_set() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let first = SqlSsfJtiDedupStore::new(db.clone(), PREFIX);
        let second = SqlSsfJtiDedupStore::new(db.clone(), PREFIX);
        let set = token("1");
        let claim = first.claim(&set).await.unwrap();
        assert_eq!(second.claim(&set).await.unwrap(), SsfJtiClaim::InProgress, "{name}");
        first.forget(&set, claim).await.unwrap();
        assert!(second.claim(&set).await.unwrap().is_granted());
    }
}

#[tokio::test]
async fn abandoned_claim_is_taken_over_after_the_lease() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let clock = TestClock::new();
        let store = SqlSsfJtiDedupStore::new(db.clone(), PREFIX)
            .with_lease(Duration::from_secs(60))
            .with_clock(clock.clock());
        let set = token("1");
        let first = store.claim(&set).await.unwrap();
        clock.advance(Duration::from_secs(59));
        assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::InProgress, "{name}");
        clock.advance(Duration::from_secs(2));
        let second = store.claim(&set).await.unwrap();
        assert!(second.is_granted());
        assert_ne!(second.token(), first.token());
        // renewed claims outlive the lease
        clock.advance(Duration::from_secs(40));
        let renewed = store.renew(&set, second).await.unwrap().unwrap();
        clock.advance(Duration::from_secs(40));
        assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::InProgress);
        store.processed(&set, renewed).await.unwrap();
        assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::Processed);
    }
}

#[tokio::test]
async fn late_instance_can_neither_complete_nor_forget_a_claim_taken_over_from_it() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let clock = TestClock::new();
        let store = SqlSsfJtiDedupStore::new(db.clone(), PREFIX)
            .with_lease(Duration::from_secs(60))
            .with_clock(clock.clock());
        let set = token("1");
        let first = store.claim(&set).await.unwrap();
        clock.advance(Duration::from_secs(61));
        let second = store.claim(&set).await.unwrap();
        store.processed(&set, first).await.unwrap();
        assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::InProgress, "{name}");
        store.forget(&set, first).await.unwrap();
        assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::InProgress);
        assert_eq!(store.renew(&set, first).await.unwrap(), None);
        store.processed(&set, second).await.unwrap();
        assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::Processed);
    }
}

#[tokio::test]
async fn processed_after_the_purge_records_the_set_again() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let clock = TestClock::new();
        let store = SqlSsfJtiDedupStore::new(db.clone(), PREFIX)
            .with_retention(Duration::from_secs(3600))
            .with_clock(clock.clock());
        let set = token("1");
        let claim = store.claim(&set).await.unwrap();
        clock.advance(Duration::from_secs(3601));
        assert_eq!(store.purge_expired().await.unwrap(), 1, "{name}");
        store.processed(&set, claim).await.unwrap();
        assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::Processed);
    }
}

#[tokio::test]
async fn forgotten_set_is_not_seen_before() {
    for (_, db) in databases().await {
        create_tables(&*db).await;
        let store = SqlSsfJtiDedupStore::new(db.clone(), PREFIX);
        let set = token("1");
        let claim = store.claim(&set).await.unwrap();
        store.forget(&set, claim).await.unwrap();
        assert!(store.claim(&set).await.unwrap().is_granted());
    }
}

#[tokio::test]
async fn processed_sets_are_forgotten_after_the_retention_time() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let clock = TestClock::new();
        let store = SqlSsfJtiDedupStore::new(db.clone(), PREFIX)
            .with_retention(Duration::from_secs(3600))
            .with_clock(clock.clock());
        let set = token("1");
        let claim = store.claim(&set).await.unwrap();
        store.processed(&set, claim).await.unwrap();
        clock.advance(Duration::from_secs(3599));
        assert_eq!(store.claim(&set).await.unwrap(), SsfJtiClaim::Processed, "{name}");
        clock.advance(Duration::from_secs(120));
        // the next claim purges first, at most once a minute
        assert!(store.claim(&set).await.unwrap().is_granted(), "{name}");
    }
}

#[tokio::test]
async fn revoked_session_revokes_its_tokens_whenever_they_were_issued() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let store = SqlSsfTokenRevocationStore::new(db.clone(), PREFIX, Duration::from_secs(3600));
        store.revoke_session("https://idp.example", "s1").await.unwrap();
        assert!(
            store.is_session_revoked("https://idp.example", "s1").await.unwrap(),
            "{name}"
        );
        assert!(
            store
                .is_revoked(&claims(
                    "https://idp.example",
                    Some("alice"),
                    Some("s1"),
                    Some(SystemTime::now() + Duration::from_secs(600))
                ))
                .await
                .unwrap()
        );
        assert!(
            !store
                .is_revoked(&claims("https://idp.example", Some("alice"), Some("s2"), None))
                .await
                .unwrap()
        );
        assert!(
            !store
                .is_revoked(&claims("https://other.example", None, Some("s1"), None))
                .await
                .unwrap()
        );
        assert!(!store.is_revoked(&SsfTokenClaims::default()).await.unwrap());
    }
}

#[tokio::test]
async fn revoked_subject_revokes_tokens_issued_up_to_the_revocation() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let store = SqlSsfTokenRevocationStore::new(db.clone(), PREFIX, Duration::from_secs(3600));
        let revoked_at = SystemTime::now();
        store
            .revoke_subject("https://idp.example", "alice", revoked_at)
            .await
            .unwrap();
        let stored = store
            .subject_revoked_at("https://idp.example", "alice")
            .await
            .unwrap()
            .unwrap();
        assert!(
            stored.duration_since(revoked_at).unwrap_or_default() < Duration::from_millis(2),
            "{name}"
        );
        assert!(
            store
                .is_revoked(&claims(
                    "https://idp.example",
                    Some("alice"),
                    None,
                    Some(revoked_at - Duration::from_secs(1))
                ))
                .await
                .unwrap()
        );
        assert!(
            store
                .is_revoked(&claims("https://idp.example", Some("alice"), None, None))
                .await
                .unwrap()
        );
        assert!(
            !store
                .is_revoked(&claims(
                    "https://idp.example",
                    Some("alice"),
                    None,
                    Some(revoked_at + Duration::from_secs(60))
                ))
                .await
                .unwrap()
        );
        assert!(
            !store
                .is_revoked(&claims("https://idp.example", Some("bob"), Some("s9"), None))
                .await
                .unwrap()
        );
        assert!(
            store
                .subject_revoked_at("https://idp.example", "bob")
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn revocations_are_shared_between_instances() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let first = SqlSsfTokenRevocationStore::new(db.clone(), PREFIX, Duration::from_secs(3600));
        let second = SqlSsfTokenRevocationStore::new(db.clone(), PREFIX, Duration::from_secs(3600));
        first.revoke_session("https://idp.example", "s1").await.unwrap();
        assert!(
            second.is_session_revoked("https://idp.example", "s1").await.unwrap(),
            "{name}"
        );
        // revoking again, from the other instance, extends the expiry and does not fail
        second.revoke_session("https://idp.example", "s1").await.unwrap();
    }
}

#[tokio::test]
async fn event_delivered_late_does_not_shorten_more_recent_revocation() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let clock = TestClock::new();
        let store =
            SqlSsfTokenRevocationStore::new(db.clone(), PREFIX, Duration::from_secs(3600)).with_clock(clock.clock());
        let now = clock.now();
        store.revoke_subject("https://idp.example", "alice", now).await.unwrap();
        store
            .revoke_subject("https://idp.example", "alice", now - Duration::from_secs(600))
            .await
            .unwrap();
        let stored = store
            .subject_revoked_at("https://idp.example", "alice")
            .await
            .unwrap()
            .unwrap();
        assert!(
            stored.duration_since(now).unwrap_or_default() < Duration::from_millis(2),
            "{name}"
        );
        assert!(
            store
                .is_revoked(&claims(
                    "https://idp.example",
                    Some("alice"),
                    None,
                    Some(now - Duration::from_secs(300))
                ))
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn revocations_expire_and_are_removed() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let clock = TestClock::new();
        let store =
            SqlSsfTokenRevocationStore::new(db.clone(), PREFIX, Duration::from_secs(60)).with_clock(clock.clock());
        store.revoke_session("https://idp.example", "s1").await.unwrap();
        store
            .revoke_subject("https://idp.example", "alice", clock.now())
            .await
            .unwrap();
        clock.advance(Duration::from_secs(59));
        assert!(
            store.is_session_revoked("https://idp.example", "s1").await.unwrap(),
            "{name}"
        );
        clock.advance(Duration::from_secs(2));
        assert!(!store.is_session_revoked("https://idp.example", "s1").await.unwrap());
        assert!(
            store
                .subject_revoked_at("https://idp.example", "alice")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(store.purge_expired().await.unwrap(), 2);
        assert_eq!(store.purge_expired().await.unwrap(), 0);
    }
}

#[tokio::test]
async fn acknowledgements_wait_until_removed_and_are_shared_between_instances() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let first = SqlSsfPollAckStore::new(db.clone(), PREFIX);
        let second = SqlSsfPollAckStore::new(db.clone(), PREFIX);
        first
            .record("https://t.example", SsfPendingAck::ack("1"))
            .await
            .unwrap();
        first
            .record(
                "https://t.example",
                SsfPendingAck::error("2", "invalid_request", Some("bad")),
            )
            .await
            .unwrap();
        first
            .record("https://t.example", SsfPendingAck::ack("2"))
            .await
            .unwrap();
        first
            .record("https://other.example", SsfPendingAck::ack("3"))
            .await
            .unwrap();
        let pending = second.pending("https://t.example", 10).await.unwrap();
        assert_eq!(pending.len(), 2, "{name}");
        assert_eq!(pending[0], SsfPendingAck::ack("1"));
        assert_eq!(
            pending[1],
            SsfPendingAck::error("2", "invalid_request", Some("bad")),
            "recording again changes nothing"
        );
        assert_eq!(second.size("https://t.example").await.unwrap(), 2);
        assert_eq!(second.size("https://nobody.example").await.unwrap(), 0);
        second
            .remove("https://t.example", &["1".to_owned(), "missing".to_owned()])
            .await
            .unwrap();
        assert_eq!(first.pending("https://t.example", 10).await.unwrap()[0].jti, "2");
        assert_eq!(first.size("https://other.example").await.unwrap(), 1);
    }
}

#[tokio::test]
async fn many_acknowledgements_are_listed_with_a_limit_and_removed_in_chunks() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let clock = TestClock::new();
        let store = SqlSsfPollAckStore::new(db.clone(), PREFIX)
            .with_delete_batch_size(3)
            .with_clock(clock.clock());
        let jtis: Vec<String> = (0..10).map(|i| format!("jti-{i:02}")).collect();
        for jti in &jtis {
            store
                .record("https://t.example", SsfPendingAck::ack(jti))
                .await
                .unwrap();
            clock.advance(Duration::from_millis(1));
        }
        let pending = store.pending("https://t.example", 4).await.unwrap();
        assert_eq!(
            pending.iter().map(|a| a.jti.as_str()).collect::<Vec<_>>(),
            &jtis[..4],
            "{name}: oldest first"
        );
        store.remove("https://t.example", &jtis[..7]).await.unwrap();
        assert_eq!(store.size("https://t.example").await.unwrap(), 3);
        store.remove("https://t.example", &[]).await.unwrap();
    }
}

#[tokio::test]
async fn long_error_descriptions_are_cut() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let store = SqlSsfPollAckStore::new(db.clone(), PREFIX);
        let long = "x".repeat(2000);
        store
            .record(
                "https://t.example",
                SsfPendingAck::error("1", "invalid_request", Some(&long)),
            )
            .await
            .unwrap();
        let pending = store.pending("https://t.example", 1).await.unwrap();
        assert_eq!(pending[0].error_description.as_ref().unwrap().len(), 1024, "{name}");
    }
}

#[tokio::test]
async fn acknowledgements_are_forgotten_after_the_retention_time() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let clock = TestClock::new();
        let store = SqlSsfPollAckStore::new(db.clone(), PREFIX)
            .with_retention(Duration::from_secs(3600))
            .with_clock(clock.clock());
        store
            .record("https://t.example", SsfPendingAck::ack("old"))
            .await
            .unwrap();
        clock.advance(Duration::from_secs(3601));
        assert_eq!(store.purge_expired().await.unwrap(), 1, "{name}");
        assert_eq!(store.size("https://t.example").await.unwrap(), 0);
    }
}

#[tokio::test]
async fn purge_expired_deletes_only_the_expired_rows() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let clock = TestClock::new();
        let store = SqlSsfJtiDedupStore::new(db.clone(), PREFIX)
            .with_retention(Duration::from_secs(3600))
            .with_clock(clock.clock());
        let old = token("old");
        let claim = store.claim(&old).await.unwrap();
        store.processed(&old, claim).await.unwrap();
        clock.advance(Duration::from_secs(3000));
        let recent = token("recent");
        let claim = store.claim(&recent).await.unwrap();
        store.processed(&recent, claim).await.unwrap();
        clock.advance(Duration::from_secs(700));
        assert_eq!(store.purge_expired().await.unwrap(), 1, "{name}");
        assert_eq!(store.claim(&recent).await.unwrap(), SsfJtiClaim::Processed);
        assert!(store.claim(&old).await.unwrap().is_granted());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cleanup_purges_all_stores_and_runs_only_when_enabled() {
    for (name, db) in databases().await {
        create_tables(&*db).await;
        let clock = TestClock::new();
        let dedup = Arc::new(
            SqlSsfJtiDedupStore::new(db.clone(), PREFIX)
                .with_retention(Duration::from_secs(60))
                .with_clock(clock.clock()),
        );
        let revocations = Arc::new(
            SqlSsfTokenRevocationStore::new(db.clone(), PREFIX, Duration::from_secs(60)).with_clock(clock.clock()),
        );
        let acks = Arc::new(
            SqlSsfPollAckStore::new(db.clone(), PREFIX)
                .with_retention(Duration::from_secs(60))
                .with_clock(clock.clock()),
        );
        let set = token("1");
        let claim = dedup.claim(&set).await.unwrap();
        dedup.processed(&set, claim).await.unwrap();
        revocations.revoke_session("https://idp.example", "s1").await.unwrap();
        acks.record("https://t.example", SsfPendingAck::ack("1")).await.unwrap();
        let stores: Vec<Arc<dyn SsfExpiringStore>> = vec![dedup.clone(), revocations.clone(), acks.clone()];
        let cleanup = SqlSsfStoreCleanup::new(stores, Duration::from_millis(20));
        assert!(cleanup.is_enabled());
        assert_eq!(cleanup.purge_expired().await, 0, "{name}");
        clock.advance(Duration::from_secs(61));
        cleanup.start();
        assert!(cleanup.is_running());
        easyssf_test::eventually(Duration::from_secs(5), "the purge", || {
            futures_lite_block_on(acks.size("https://t.example")) == 0
        })
        .await;
        cleanup.stop().await;
        assert!(!cleanup.is_running());
        assert!(dedup.claim(&set).await.unwrap().is_granted());
        assert!(
            !revocations
                .is_session_revoked("https://idp.example", "s1")
                .await
                .unwrap()
        );
        let off = SqlSsfStoreCleanup::new(vec![dedup.clone()], Duration::ZERO);
        assert!(!off.is_enabled());
        off.start();
        assert!(!off.is_running());
    }
}

/// Runs a store call from a sync closure, for `eventually`.
fn futures_lite_block_on<F: std::future::Future<Output = Result<usize, easyssf_receiver::BoxError>> + Send>(
    future: F,
) -> usize {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future)).unwrap_or(usize::MAX)
}

#[tokio::test]
async fn reports_duplicate_keys_missing_tables_and_other_failures() {
    for (name, db) in databases().await {
        assert!(!db.table_exists("EASYSSF_PROCESSED_SET").await.unwrap(), "{name}");
        create_tables(&*db).await;
        assert!(db.table_exists("EASYSSF_PROCESSED_SET").await.unwrap());
        let insert = "INSERT INTO EASYSSF_PROCESSED_SET (ISSUER, JTI, STATE, STATE_CHANGED_AT) VALUES (?, ?, ?, ?)";
        let args: [SsfSqlValue; 4] = ["i".into(), "j".into(), "PROCESSED".into(), 1_i64.into()];
        assert_eq!(db.update(insert, &args).await.unwrap(), 1);
        let error = db.update(insert, &args).await.unwrap_err();
        assert!(error.is_duplicate_key(), "{name}: {error}");
        let error = db
            .update("INSERT INTO NOWHERE (X) VALUES (?)", &["x".into()])
            .await
            .unwrap_err();
        assert!(matches!(error, SsfSqlError::Failed { .. }), "{name}: {error}");
        assert!(db.query("SELECT * FROM NOWHERE", None, &[]).await.is_err());
        assert!(
            db.update("SELECT ?", &[])
                .await
                .unwrap_err()
                .to_string()
                .contains("placeholder")
        );
        let rows = db
            .query(
                "SELECT JTI, STATE_CHANGED_AT, NULL FROM EASYSSF_PROCESSED_SET WHERE ISSUER = ?",
                None,
                &["i".into()],
            )
            .await
            .unwrap();
        assert_eq!(rows[0].string(0).as_deref(), Some("j"));
        assert_eq!(rows[0].i64(1), Some(1));
        assert_eq!(rows[0].columns[2], SsfSqlValue::Null);
    }
}
