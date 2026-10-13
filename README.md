# easyssf-rust

Building blocks for the
[OpenID Shared Signals Framework (SSF)](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)
in Rust, for applications that receive security events: a framework independent **receiver**
library, a crate for **axum** (and through tower for tonic, Loco and Leptos), a crate for
**actix-web**, and database stores on **sqlx**. A port of [easyssf for Java](https://github.com/easyssf/easyssf),
following the layout of the Java modules and of [easyssf-dotnet](https://github.com/easyssf/easyssf-dotnet);
the three share their test suites, their database tables and their configuration keys.

**Turn a Rust application into an SSF receiver without implementing SET validation, metadata
discovery, PUSH and POLL delivery, stream management and replay protection yourself.** Reacting to
a security event is a closure:

```rust
let receiver = SsfReceiver::builder(config)
    .handler(for_event("CaepSessionRevoked", |context: SsfEventContext| async move {
        let subject = context.subject();
        // end what you hold for subject.session_id() or subject.subject()
        Ok(())
    }))
    .build()?;
receiver.start();                                // registers the stream, starts polling
let app = Router::new().merge(push_router_for(&receiver)); // POST /ssf/push
```

| | |
|---|---|
| **Status** | Experimental, pre-1.0; the version follows the Java library (`0.7.0-alpha.N`) |
| **Rust** | 1.88 or later (edition 2024); `easyssf-receiver-sqlx` needs 1.94 (sqlx 0.9) |
| **License** | Apache-2.0 |

## Crates

| Crate | Holds | Java module | .NET project |
|---|---|---|---|
| `easyssf-core` | The vocabulary: SETs, subjects, event types with aliases, the typed CAEP, RISC and SCIM events, stream configuration, transmitter metadata | `easyssf-core` | `EasySsf.Core` |
| `easyssf-receiver` | The receiver without a web framework: verification, de-duplication with a lease, push and poll, stream management, typed handlers, token revocation, session termination, metrics; the configuration types and `SsfReceiver`, which assembles a receiver from them | `easyssf-receiver`, plus the factory half of the Spring autoconfigure module | `EasySsf.Receiver`, `EasySsf.Receiver.Hosting` |
| `easyssf-receiver-axum` | `push_router_for()`, `SsfRevocationLayer` for resource servers, `SsfSessionRevocationLayer` for tower-sessions | Spring autoconfigure (web half) | `EasySsf.Receiver.AspNetCore` |
| `easyssf-receiver-actix-web` | `configure_push_for()`, `SsfRevocation` middleware, `SsfSessionRevocation` for actix-session | none | none |
| `easyssf-receiver-sqlx` | The three tables shared with Java and .NET, on SQLite, PostgreSQL and MySQL | `easyssf-receiver-jdbc` | `EasySsf.Receiver.Data` |
| `easyssf-test` | `TestTransmitter`: signs SETs, serves metadata and the JWK Set, issues access tokens, emulates stream management and polling, in-process through the receiver's HTTP client trait | `easyssf-test` | `EasySsf.Testing` |

Rocket, Poem, Salvo and warp need no crate: read the `Authorization` header and the body, call
`SsfPushHandler::handle`, answer with its status and body (see [Plain Rust](#plain-rust)).

## What it does

- **Verifies a SET** (RFC 8417): signature against the transmitter's JWK Set, `typ`, `iss`,
  `aud`, `jti`, `iat`, `events` and the top-level `sub_id` SSF 1.0 requires. Rejections carry the
  error codes of RFC 8935 (`invalid_request`, `invalid_key`, `invalid_issuer`, `invalid_audience`).
  `jsonwebtoken` checks the signature only; every claim rule is the library's, because a SET has
  no `exp` and jsonwebtoken's defaults would reject every SET.
- **Caches the JWK Set** and fetches it again when a SET names a key it does not know, rate
  limited so that bogus SETs cannot make the receiver flood the transmitter.
- Accepts only asymmetric signature algorithms (`RS256` by default) and RSA keys of at least 2048
  bits.
- Resolves **subjects** (RFC 9493): every simple format, complex subjects, aliases, the `scim`
  format, and the conventions of early SSF drafts and of Keycloak behind explicit modes.
- Knows the **event types** of SSF, CAEP, RISC and SCIM Events (RFC 9967) by URI and by alias
  (`CaepSessionRevoked`), and lets you register aliases for vendor specific types.
- **Receives pushed SETs** (RFC 8935): checks the transmitter's `Authorization` header in constant
  time, verifies, **skips SETs it has already processed** (`jti` de-duplication with a lease and
  claim renewal, so a SET another instance is handling is left alone and one abandoned by a crash
  is taken over), hands verified events to the handlers, answers `202`, `400` with an error
  document, `401`, `413`, `500` or `503`. The web framework crates run the processing in a spawned
  task, so a transmitter that disconnects does not cancel the handlers.
- **Discovers the transmitter** from its `.well-known/ssf-configuration`, at the SSF location and
  at the one OpenID providers tend to use, and holds its issuer and endpoints to `https` unless a
  loopback address or `allow-insecure-http` says otherwise.
- **Manages its stream**: looks a stream up by id, or reuses, updates or creates the stream the
  receiver wants, in the background with retries; `SsfStreamClient` for the management API.
- **Polls** (RFC 8936) with short or long polling, acknowledges handled SETs and reports invalid
  ones with the next request, keeps acknowledgements in an `SsfPollAckStore`, backs off on
  `Retry-After`, authenticates with the client credentials grant.
- **Revokes access tokens and sessions**: `session-revoked` events fill an
  `SsfTokenRevocationStore`; the axum layer and the actix middleware reject tokens with that `sid`
  or that `sub` issued up to the event, and the session layers end sessions on their next request.
  An `SsfSessionTerminator` ends server-side sessions as the event arrives.
- **Typed events** with handler traits: `SsfCaepEventHandler`, `SsfRiscEventHandler`,
  `SsfScimEventHandler`, each adapted with `caep(...)`, `risc(...)` or `scim(...)`.
- Records **metrics** with the `metrics` facade under the Java names (feature `metrics`) and
  reports its **health** (`receiver.health()`).

## Getting started

```toml
[dependencies]
easyssf-receiver = "0.7.0-alpha.1"
easyssf-receiver-axum = "0.7.0-alpha.1"
```

The configuration keys are those of the Spring Boot starter and the .NET options, in kebab-case,
deserialized with serde from TOML, YAML, JSON or the environment through the configuration crate of
your choice (figment, config-rs, ...), under `easyssf.receiver`:

```toml
[easyssf.receiver]
transmitter-issuer = "https://idp.example/realms/demo"   # required
expected-audience = "https://my-app.example"             # or let the receiver register the stream
[easyssf.receiver.push]
expected-auth-header = "Bearer ${SSF_PUSH_SECRET}"       # recommended
```

```rust
use easyssf_receiver::{SsfReceiver, config::SsfReceiverConfig, event::for_event};
use easyssf_receiver_axum::{SsfRevocationLayer, push_router_for};

let config: SsfReceiverConfig = figment.extract_inner("easyssf.receiver")?;
let receiver = SsfReceiver::builder(config)
    .handler(for_event("CaepCredentialChange", credentials_changed))
    .build()?;                                   // validates the configuration
receiver.start();                                // registers the stream, starts polling

let app = Router::new()
    .route("/api/orders", get(orders))
    // after the layer that validates the access token and leaves its claims on the request
    .layer(SsfRevocationLayer::new(receiver.token_revocation_store(), |parts| {
        parts.extensions.get::<SsfTokenClaims>().cloned()
    }))
    .merge(push_router_for(&receiver));          // POST /ssf/push
axum::serve(listener, app).with_graceful_shutdown(shutdown_signal()).await?;
receiver.shutdown().await;                       // sends the acknowledgements it owes
```

To poll instead of being pushed to, and to let the receiver register its own stream:

```toml
[easyssf.receiver]
transmitter-issuer = "https://idp.example/realms/demo"
delivery-method = "poll"
[easyssf.receiver.stream]
management = "receiver"
events-requested = ["CaepSessionRevoked", "CaepCredentialChange"]
[easyssf.receiver.poll]
long-polling = true
[easyssf.receiver.oauth2]
token-uri = "https://idp.example/realms/demo/protocol/openid-connect/token"
client-id = "my-app"
client-secret = "..."
```

The audience of the stream is learned from the registration, so `expected-audience` is not needed.
Several transmitters go under `easyssf.receiver.transmitters.<name>`, each with the same settings;
the one at `easyssf.receiver` is named `default`. A customizer replaces parts of any transmitter
before it is built: `.customize_transmitter(|builder| if builder.name == "okta" { ... })`.

Every setting, with its default, is documented on `SsfReceiverConfig` and its sub-structs
(`cargo doc`); the keys are those of the
[.NET configuration table](https://github.com/easyssf/easyssf-dotnet#configuration) in
kebab-case, with durations as strings such as `"30s"` or `"24h"`.

### actix-web

actix-web builds the `App` once per worker thread. Build the receiver once, outside the
`HttpServer::new` closure, and share it; built inside, every worker would register the stream and
poll on its own.

```rust
let receiver = Arc::new(SsfReceiver::builder(config).build()?);
receiver.start();
HttpServer::new(move || {
    App::new()
        .configure(configure_push_for(&receiver))
        .service(web::scope("/api")
            .wrap(SsfRevocation::new(receiver.token_revocation_store(), |request| {
                request.extensions().get::<SsfTokenClaims>().cloned()
            }))
            .route("/orders", web::get().to(orders)))
})
```

### Plain Rust

Every framework integrates the library the same way: `SsfPushHandler::handle(authorization_header,
body)` returns a status and an optional JSON body. Run it in a spawned task so that a transmitter
that disconnects does not cancel the handlers:

```rust
let response = tokio::spawn(async move { push_handler.handle(authorization.as_deref(), &body).await }).await?;
// send response.status and, if Some, response.body as application/json with Content-Language: en
```

Assembling the parts by hand reads like the plain Java section of the Java README, see
`examples/resource_server.rs` of the axum crate and the documentation of `SsfSetProcessor`,
`SsfPoller` and `SsfStreamRegistrar`.

### Sharing state between instances

A SET is pushed to one instance of an application. `easyssf-receiver-sqlx` keeps the processed
SETs, the revocations and the acknowledgements a poller owes in the database of the application,
in the tables of the Java library (`EASYSSF_PROCESSED_SET`, `EASYSSF_REVOCATION`,
`EASYSSF_POLL_ACK`):

```rust
let stores = SsfSqlStores::from_config(SqlxSsfSqlOperations::postgres(pool), &config);
stores.prepare_tables().await?;          // checks or creates the tables (data.initialize-schema)
stores.cleanup().start();                // purges expired rows every data.cleanup-interval
let receiver = stores.apply(SsfReceiver::builder(config)).build()?;
```

`sql/schema.sql` and `sql/migration/` ship byte for byte with the Java library and are embedded as
`SsfSqlSchema::SCHEMA_SQL` and `SsfSqlSchema::MIGRATIONS` for a migration tool. The stores use `?`
placeholders; sqlx does not rewrite them for PostgreSQL, so the `postgres` implementation does.
An application on Diesel, SeaORM or tokio-postgres implements `SsfSqlOperations` over its own data
access.

## Testing your receiver

`easyssf-test` contains `TestTransmitter`, a transmitter that signs SETs, serves its metadata and
JWK Set, hands out access tokens and emulates the stream management and poll endpoints, all
in-process through the receiver's `SsfHttpClient` trait: give it to the receiver as its HTTP
client, no socket is involved.

```rust
let transmitter = TestTransmitter::new();
let receiver = SsfReceiver::builder(config_for(transmitter.issuer()))
    .http_client(transmitter.clone())
    .build()?;
let set = transmitter.set("CaepSessionRevoked", Some(complex(Some(iss_sub(transmitter.issuer(), "alice")), Some(opaque("session-1")))));
// POST set to /ssf/push, or transmitter.queue_set(&set) for a polling receiver
```

`transmitter.set_available(false)` simulates an outage, `transmitter.acknowledged_sets()` and
`transmitter.reported_errors()` show what a polling receiver acknowledged, `transmitter.streams()`
the streams a receiver registered. `TestSigningKey::generate(1024, "weak")` makes keys a receiver
has to reject.

## Features

| Crate | Feature | Default | |
|---|---|---|---|
| `easyssf-receiver` | `rust-crypto` | yes | The pure-Rust crypto backend of jsonwebtoken. It pulls in the `rsa` crate, whose advisory RUSTSEC-2023-0071 concerns private-key operations a receiver never performs; `deny.toml` ignores it for that reason. |
| `easyssf-receiver` | `aws-lc-rs` | | The aws-lc-rs backend instead; needs a C toolchain. Exactly one backend. |
| `easyssf-receiver` | `reqwest` | yes | The HTTP client that calls the transmitter, rustls with aws-lc-rs. Without it, give the builder an `SsfHttpClient`. |
| `easyssf-receiver` | `metrics` | | `easyssf.receiver.sets`, `.events`, `.poll` and `.poll.pending-acks` with the `metrics` facade. |
| `easyssf-receiver-axum` | `tower-sessions` | | The session revocation layer. |
| `easyssf-receiver-actix-web` | `actix-session` | | The session revocation middleware. |
| `easyssf-receiver-sqlx` | `sqlite`, `postgres`, `mysql` | `sqlite` | The databases. |

## Not included (yet)

- The conformance harness (`easyssf-test-conformance` of Java): the suite in Testcontainers, its
  plans and scenarios. The receiver is tested by the ported unit and integration tests; the four
  OpenID plans are the next step.
- OpenTelemetry metrics: the `metrics` facade is in, an OTel exporter bridges onto it.
- A transmitter. `easyssf-core` is written to be shared with one.

## Examples

[`examples/`](examples) has the port of the Spring Boot examples: a resource server and an OIDC
client on axum that receive events from a Keycloak transmitter (with the Docker Compose setup for
Keycloak), and a SCIM provisioning example that mirrors `Users` from SCIM Events against the
in-process `TestTransmitter`. See [`examples/README.md`](examples/README.md).

## Build

```sh
cargo test-all                                   # every feature that can be on at once, see .cargo/config.toml
cargo clippy-all
cargo run -p easyssf-receiver-axum --example resource_server
cargo run -p example-scim-provisioning            # the SCIM example, no Keycloak needed
```

The sqlx tests run on SQLite always and on PostgreSQL and MySQL when `EASYSSF_DATABASE_TESTS=true`
and `EASYSSF_POSTGRES_URL` / `EASYSSF_MYSQL_URL` name the databases (CI does this in the `database`
job). The `schema` job compares the SQL files with the Java repository.
