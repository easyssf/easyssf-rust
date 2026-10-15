# easyssf-receiver-sqlx

The database stores of the easyssf receiver on [sqlx](https://crates.io/crates/sqlx): processed
SETs, revocations and the acknowledgements a poller owes, in the three tables the Java and .NET
libraries use (`EASYSSF_PROCESSED_SET`, `EASYSSF_REVOCATION`, `EASYSSF_POLL_ACK`), so that
applications of any of the three can share one database. SQLite, PostgreSQL and MySQL behind
features; the schema and migration scripts are those of the Java library.

```toml
[dependencies]
easyssf-receiver-sqlx = { version = "0.6.0", features = ["postgres"] }
```

Part of [easyssf-rust](https://github.com/easyssf/easyssf-rust), the port of [easyssf for Java](https://github.com/easyssf/easyssf).
The [README of the repository](https://github.com/easyssf/easyssf-rust#sharing-state-between-instances) explains the stores. Apache-2.0.
