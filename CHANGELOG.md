# Changelog

All notable changes to this project will be documented in this file. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the version follows the Java library.

## [Unreleased]

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
