# Changelog

All notable changes to this project will be documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the version follows the Java library.

The version line starts at 0.6.0, not at 0.1.0: the crates follow the release line of
[easyssf for Java](https://github.com/easyssf/easyssf), of which this library is a port, as the
[.NET](https://github.com/easyssf/easyssf-dotnet) and [Go](https://github.com/easyssf/easyssf-go)
ports do. The port was written against the Java library as it stood for its 0.6.0 release and
carries that state in full: the same protocol behaviour, the same options and defaults, the same
database tables. The same version therefore means the same feature level on every side, and a
reader can hold the changelogs side by side. Versions 0.1.0 to 0.5.0 never existed in Rust. Below
1.0 a minor version may break the API, as in the Java library; between two minor versions,
`-alpha.N` prereleases follow the Java development line (`0.7.0-alpha.N` alongside
`0.7.0-SNAPSHOT`).

## [Unreleased]

The hardening of easyssf 0.7.0 for Java. A host name like `127.attacker.example` no longer passes
for loopback, the poll endpoint is held to the same URI policy as the metadata endpoints before the
access token goes to it, and responses from the transmitter are bounded, 4 MiB by default. Every
stream configuration the transmitter returns has its issuer checked, not only a created one.
Stopping the registrar lets a call in progress complete and no longer leaves a stream behind.

### Security

- A host name that merely starts with `127.`, such as `127.attacker.example`, counted as a loopback
  address and was allowed to use plain `http` under the default URI policy.
  `SsfTransmitterUriPolicy::is_loopback` now takes only `localhost` and names under it, IPv4
  addresses in `127.0.0.0/8` and `::1` (also as the IPv4-mapped `::ffff:127.0.0.1`), the rule of
  the Java and Go libraries. Hosts are parsed as the url crate does, so the shorthand `127.1` is
  `127.0.0.1` and counts as loopback, where the Java and Go libraries refuse it.
- The poll endpoint is held to the URI policy of the transmitter's metadata endpoints before the
  access token is sent to it, whether it was configured (`poll.endpoint-url`, checked by
  `validate()`) or taken from the stream configuration the transmitter returned: `https`, or
  `http` on loopback addresses only, unless `allow-insecure-http` is set. New option:
  `SsfPollerOptions::uri_policy`, which `SsfReceiver` sets from `allow-insecure-http`.
- Response bodies `ReqwestSsfHttpClient` reads from the transmitter (metadata, JWK Set, stream
  configurations, poll responses) are bounded, 4 MiB by default; a larger response fails the call
  as if the transmitter were unavailable instead of being buffered. New API:
  `ReqwestSsfHttpClient::with_max_response_size`, `SsfHttpResponse::DEFAULT_MAX_BODY_SIZE` for
  other `SsfHttpClient` implementations, and the setting `http.max-response-size`. The body is
  decoded in the charset of its `Content-Type`, UTF-8 by default.

### Changed

- `SsfStreamClient` checks the issuer of every stream configuration the transmitter returns, not
  only of a created one: `stream`, `streams`, `update_stream` and `replace_stream` return
  `SsfStreamError::IssuerMismatch` as `create_stream` did, as the SETs of a stream with another
  issuer would not verify. `SsfStreamRegistrar` deletes a stream it created with the wrong issuer,
  as before, and leaves an existing one alone; it fails without retrying either way.
- `SsfStreamRegistrar::stop` lets a call to the transmitter in progress complete, for up to
  `DEFAULT_STOP_TIMEOUT` (5 seconds), instead of dropping it; `stop_with_timeout` sets another
  limit, `Duration::MAX` none. A call that takes longer is abandoned as before.

### Fixed

- A SET the poll response lists under a key other than its `jti` (RFC 8936, section 2.4) is
  reported to the transmitter as `invalid_request` under that key instead of being handled and
  acknowledged under a key that is not its own. New: `set::unverified_jti`.
- A registration that `SsfStreamRegistrar::stop` ends after the transmitter created its stream
  publishes nothing and deletes that stream if the registrar deletes on shutdown, where it left the
  stream behind. A `start()` while `stop()` is in progress waits for it, so two registrations never
  run at once. `stop()` deletes only a stream published since the last `stop()`, not again the one
  a previous `stop()` deleted, nor one when the registrar never ran.
- `SsfPoller::stop` logs when the polling task is still busy after five seconds.
- The `SsfStreamError::IssuerMismatch` the registrar reported named an empty expected issuer.

## [0.6.0] - 2026-10-16

The first release: the complete port, at feature parity with easyssf 0.6.0 for Java and .NET.
Six crates on Rust 1.94 or later, with exactly one crypto backend of jsonwebtoken per build,
`rust-crypto` by default or `aws-lc-rs`.

### Added

- `easyssf-core`: the vocabulary of SSF 1.0 ported from `easyssf-core` of the Java library:
  `SsfEventToken`, `SsfSubject` and `SsfSubjectIdentifier` with the `subjects` builders, the
  event type registry with aliases, `SsfCaepEvent`, `SsfRiscEvent`, `SsfScimEvent` and
  `SsfScimSubject`, `SsfStreamConfiguration`, `SsfStreamStatus`, `SsfTransmitterMetadata`.
- `easyssf-receiver`: the receiver ported from `easyssf-receiver`: `JwtSsfSetVerifier` with the
  JWK Set cache `HttpSsfJwkSetSource`, `IssuerRoutingSsfSetVerifier`, `SsfJtiDedupStore` with the
  lease and claim renewal, `SsfSetProcessor` with critical subject members and stream verification,
  `SsfPushHandler`, `SsfPoller` with short and long polling and `SsfPollAckStore`,
  `SsfStreamClient`, `SsfStreamRegistrar`, `SsfStreamVerification`, `SsfTransmitterMetadataResolver`
  with `SsfTransmitterUriPolicy`, `ClientCredentialsSsfTransmitterTokenProvider`, `SsfTransmitter`
  and `SsfTransmitters`, `SsfTokenRevocationStore` and its handler, `SsfSessionTerminator`,
  `SsfSessionTerminationEventHandler` and `subject_claims_matcher`, the typed handler traits
  `SsfCaepEventHandler`, `SsfRiscEventHandler` and `SsfScimEventHandler`, `SsfReceiverMetrics` with
  the `metrics` facade behind a feature.
- `easyssf-receiver`: `config::SsfReceiverConfig`, the options of the Spring Boot starter and the
  .NET port in kebab-case for serde, with the validation of `SsfReceiverOptionsValidator`, and
  `SsfReceiver`, which assembles the transmitters, the processor, the push handler and the stores
  from it, starts and stops the background work and reports its health.
- `easyssf-receiver-axum`: `push_router_for`, `SsfRevocationLayer` and, behind the
  `tower-sessions` feature, `SsfSessionRevocationLayer`. The push route runs the processing in a
  spawned task, so a transmitter that disconnects does not cancel the handlers.
- `easyssf-receiver-actix-web`: `configure_push_for`, the `SsfRevocation` middleware and, behind the
  `actix-session` feature, `SsfSessionRevocation`.
- `easyssf-receiver-sqlx`: `SqlSsfJtiDedupStore`, `SqlSsfTokenRevocationStore` and
  `SqlSsfPollAckStore` over `SsfSqlOperations`, with `SqlxSsfSqlOperations` for SQLite, PostgreSQL
  and MySQL, `SsfSqlSchema` with the schema and migration scripts of the Java library, the
  cleanup of expired rows and `SsfSqlStores` from the configuration.
- `easyssf-test`: `TestTransmitter` with metadata, JWK Set, token endpoint, stream management and
  poll endpoint in-process, and `eventually` / `during` for tests of background behaviour.
- `examples/`: the port of the Spring Boot examples, not published: `example-resource-server`
  (access tokens of revoked Keycloak sessions are rejected, `poll` profile, Prometheus metrics),
  `example-oidc-client` (OIDC login on tower-sessions, local sessions end on `session-revoked` and
  `credential-change`), `example-scim-provisioning` (SCIM `Users` mirrored from SCIM Events of the
  in-process `TestTransmitter`, with the demo service provider under `/demo/scim` and its tests),
  the Keycloak compose setup and `example-support` for `config.toml` with `${VAR:default}`
  placeholders and profiles.
