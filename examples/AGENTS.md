# examples

A resource server and an OIDC client that receive events from a Keycloak transmitter, with a
Docker Compose setup for Keycloak, and a SCIM provisioning example that runs without Keycloak
(which emits no SCIM Events) against the in-process `TestTransmitter` of `easyssf-test`, fed by its
`DemoScimProvider`. The port of `easyssf-receiver-spring-boot-examples` of the Java library;
`example-support` holds what the three share. Workspace members, `publish = false`. The README
walks through running them.

- The Keycloak examples contain no SSF code apart from `config.toml` (and a logging handler). Keep
  them that way: a feature that needs code in an example is a feature `easyssf-receiver` or
  `easyssf-receiver-axum` is missing. What Spring Security does for the Java examples (access
  token validation, OIDC login) is application code here, in `auth.rs` and `oidc.rs`. The SCIM
  example's handler is application logic (what to do with a provisioning event), that is fine.
- `config.toml` mirrors `application.yaml` of the Java example: the `easyssf.receiver` section
  deserializes into `SsfReceiverConfig`, `${VAR:default}` reads the environment, nested in a
  default too. The resource server is transmitter-agnostic like the Go one and reads
  `SSF_TRANSMITTER_ISSUER`, `SSF_TOKEN_URI`, `SSF_CLIENT_ID`, `SSF_CLIENT_SECRET` and `SSF_PUSH_URL`;
  the OIDC client keeps the variable names of the Java and .NET examples (`KEYCLOAK_ISSUER`,
  `KEYCLOAK_CLIENT_SECRET`, `SSF_PUSH_URL`); both read `SERVER_PORT`. The `poll` profile of the
  resource server is `config-poll.toml` merged over `config.toml` (`--profile poll`).
- `example-scim-provisioning` has the only tests among the examples; they start the application
  against a `TestTransmitter` on a random port and poll every 200 ms. The demo SCIM service
  provider under `/demo/scim` (and the scripted play, `--demo.autoplay=false` turns it off),
  `example-scim-provisioning.http` and the README show the same events: keep the three in step
  when the events or payloads change.
- Before `docker compose up` in `keycloak/`, check for an existing compose project of the same
  name: `docker ps -a --filter label=com.docker.compose.project=easyssf-examples`. The compose
  file sets `name: easyssf-examples` on purpose, the same as the Java examples, so that the two
  share one Keycloak; never remove the `name`, and never run `down -v` or delete volumes you did
  not create. Developer machines tend to have several unrelated projects in folders called
  `keycloak`.
- `keycloak/compose.yaml` and `keycloak/ssf-demo-realm.json` are copies of the Java files. Change
  the realm export there first, not in a running Keycloak.
- Changing the ports (8080 Keycloak, 8081 resource server, 8082 OIDC client, 8083 SCIM
  provisioning) means changing the realm export, the `config.toml` files and the README together.
