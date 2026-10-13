# easyssf-rust for coding agents

Read this first, then the [README](README.md) for what the library does. This file holds what is
not obvious from the code: what the repository is, how it relates to the Java original and the
.NET port, the conventions it follows, and the commands that matter.

## What this is

Rust building blocks for the OpenID Shared Signals Framework (SSF 1.0) with CAEP, RISC and SCIM
Events (RFC 9967): a framework independent **receiver** library, crates for axum and actix-web, and
database stores on sqlx. The code sits in the authentication path of its users, so correctness of
verification beats convenience everywhere. Receiver only, no transmitter. Apache-2.0. Status:
experimental, pre-1.0, breaking changes are acceptable when the CHANGELOG says so.

This is a port of [easyssf for Java](https://github.com/easyssf/easyssf), following the playbook of
[easyssf-dotnet](https://github.com/easyssf/easyssf-dotnet). The Java code is the reference for
protocol behaviour, names and tests; the .NET code for options, the transmitter factory, the
hosting integration and the data stores. Local checkouts are expected at `../easyssf` and
`../easyssf-dotnet`. On a protocol matter the Java code and the specification win; on a Rust
matter this file wins.

Cargo workspace, edition 2024. Crates, in dependency order:

| Crate | Holds | Depends on |
|---|---|---|
| `easyssf-core` | The vocabulary: SETs, subjects, event types, the typed CAEP, RISC and SCIM events, stream configuration, transmitter metadata, over `serde_json::Value` | `serde_json`, `url` |
| `easyssf-receiver` | The receiver without a framework: verification, de-duplication, push and poll, stream management, handlers, revocation and session termination, metrics; `config` and `receiver` (the .NET Hosting project) | core, `jsonwebtoken`, `tokio`, `tracing`; `reqwest` and `metrics` behind features |
| `easyssf-test` | `TestTransmitter`, in-process over `SsfHttpClient` | core, receiver (and receiver dev-depends on it: cargo allows the cycle) |
| `easyssf-receiver-sqlx` | The three database stores, the schema and migrations, `SsfSqlStores` | receiver, `sqlx` |
| `easyssf-receiver-axum` | Push route, `SsfRevocationLayer`, the tower-sessions layer | receiver, `axum`, `tower` |
| `easyssf-receiver-actix-web` | `configure_push`, `SsfRevocation`, the actix-session middleware | receiver, `actix-web` |

New protocol behaviour goes into `easyssf-receiver`, new vocabulary into `easyssf-core`, framework
code only into the framework crates.

## Build and test

```sh
cargo test-all                                   # everything, in-process, no network, no Docker
cargo test -p easyssf-receiver --test poller     # one test file
cargo clippy-all                                 # warnings are errors in CI
cargo fmt --all                                  # max_width = 120, see rustfmt.toml
RUSTDOCFLAGS="-D warnings" cargo doc-all
```

- **Never `--all-features`.** `easyssf-receiver` has two crypto backends, `rust-crypto` and
  `aws-lc-rs`, of which exactly one may be on: jsonwebtoken panics at runtime with both, which the
  crate turns into a compile error. The `test-all`, `clippy-all` and `doc-all` aliases in
  `.cargo/config.toml` enable every feature that can be on at once. Features unify across the
  dependency graph, so `easyssf-test` does not pin a backend either; its own default is
  `rust-crypto`, switch both crates together.

- The tests need no network and no Docker: `TestTransmitter` answers in-process and the sqlx tests
  run on SQLite in memory. `EASYSSF_DATABASE_TESTS=true` with `EASYSSF_POSTGRES_URL` and
  `EASYSSF_MYSQL_URL` runs the store tests on those databases as well (CI does, in the `database`
  job). Run them when the SQL or the schema changes, and say so.
- `TestTransmitter::new()` shares one 2048 bit key per process: generating one takes long enough
  that the tests would crawl otherwise. `TestSigningKey::generate` always makes a fresh key, for
  SETs the receiver must reject.
- `scratch/` is ignored by git: put plans, notes and throwaway scripts there, not into the tree.
- Do not commit, push, tag or publish unless asked.

## Porting

- The Java module maps to the crate, the Java package to the module: `org.easyssf.receiver.set` is
  `easyssf_receiver::set`. Vendor names of the Java code are replaced by what the type does
  (`NimbusSsfSetVerifier` is `JwtSsfSetVerifier`).
- Port a Java type with its tests, the negative tests (the SET that must be rejected) before the
  positive ones, and keep the test names as sentences in snake_case
  (`rejects_set_signed_with_unknown_key`) so that the three suites can be compared.
- `schema.sql` and `migration/*.sql` of `easyssf-receiver-sqlx` are copies of the Java files, byte
  for byte; CI compares them. Change them in the Java repository first.

## Code conventions

- **Names.** Public types keep the `Ssf` prefix of the Java code (`SsfSubject`, `SsfEventHandler`),
  without the `I` of .NET interfaces. Without the prefix `Stream` and `ReceiverStream` read as
  async stream types, and the three code bases stop being greppable side by side.
- **Raw claims are `serde_json` values**, typed accessors sit on top. `serde_json` runs with
  `preserve_order`, so collections keep the order received. `SsfEventToken` and `SsfEventContext`
  hold an `Arc` and clone cheaply; handlers take the context by value.
- **Lenient factories return `Option`**, no panics in library code for input that does not fit.
  Errors are enums with `thiserror`; enums the specification may extend (`SsfCaepEventKind`,
  `SsfErrorCode`, ...) are `#[non_exhaustive]`: do not match them exhaustively, implement the
  typed handler traits instead.
- **Traits the processor holds as `Arc<dyn ...>`** (stores, verifier, HTTP client, token provider)
  are written with `#[async_trait]`; `async fn` in a trait is not dyn compatible. Every such trait
  is also implemented for `Arc<T>` and `Arc<dyn ...>`, so a caller can keep a handle.
  `SsfEventHandler` and the typed handler traits use `impl Future` and are type-erased once.
- **Options structs with public fields and `Default`**, filled with `..Default::default()`, read
  when the work is done. `SsfReceiverConfig` derives `serde::Deserialize` with kebab-case keys and
  `humantime` durations; lists mean their default while empty (`effective_*` resolves it).
- **jsonwebtoken checks the signature only.** Its `Validation` requires `exp`, which a SET has not:
  `required_spec_claims` is cleared and `exp`, `nbf`, `aud` are off. Every claim rule and every
  error code of RFC 8935 is in `JwtSsfSetVerifier`. The JWK Set cache with its rate-limited refresh
  is `HttpSsfJwkSetSource`.
- **A dropped request must not cancel the handlers.** The push routes of the framework crates run
  `SsfPushHandler::handle` in `tokio::spawn`; a panic becomes a 500 and the lease of the dedup store
  releases the claim.
- **Background work runs on tokio tasks** with a `CancellationToken`: `start()` is synchronous and
  needs a runtime, `stop().await` cancels and joins. Tests of background behaviour use
  `easyssf_test::eventually` / `during` with short waits; stores take a `Clock` closure the tests
  move by hand.
- **Logging** is `tracing` with fields (`jti`, `transmitter`, `event` as alias). Metrics are the
  `metrics` facade under the Java names.
- **Protocol facts carry their source.** Doc comments and comments cite the specification and
  section (`SSF 1.0 8.1.4.1`, `RFC 9967, section 2.4`) and name the real-world deviation they
  tolerate. Keep that habit.
- **Strict by default, lenient by configuration.** The receiver rejects what the specification
  forbids and tolerates older drafts or known transmitter quirks only behind an explicit mode
  (`SubjectCompatibilityMode::Legacy`, `allow-insecure-http`).
- **Handlers are idempotent** and a SET that any handler fails on is delivered again. State that
  must survive a restart belongs in a store trait with an in-memory and a sqlx implementation.
- `#![forbid(unsafe_code)]` and `missing_docs` are workspace lints; every public item has a doc
  comment.

## Documentation that changes with the code

- `README.md` is the user document. A new setting, alias, subject format or handler is documented
  there in the same change.
- `CHANGELOG.md` follows Keep a Changelog; add to the `Unreleased` section in the voice of the
  existing entries.
