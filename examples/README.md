# Examples

Two applications that receive security events from a Keycloak SSF transmitter, and one that mirrors
the users of a SCIM service provider from its SCIM Events, with a demo transmitter of its own. They
are the Rust port of the [Spring Boot examples](https://github.com/easyssf/easyssf/tree/main/easyssf-receiver-spring-boot-examples)
of the Java library and use the same Keycloak realm.

| | Port | |
|---|---|---|
| [`keycloak/`](keycloak) | 8080 | Docker Compose setup: Keycloak 26.8 with the `ssf` feature and a pre-configured `ssf-demo` realm |
| [`example-resource-server/`](example-resource-server) | 8081 | OAuth2 resource server on axum. Rejects access tokens once their Keycloak session was revoked. Has a `poll` profile and Prometheus metrics. |
| [`example-oidc-client/`](example-oidc-client) | 8082 | Web application with OIDC login on axum and tower-sessions. Ends the local session once the Keycloak session was revoked or the user's credentials changed. |
| [`example-scim-provisioning/`](example-scim-provisioning) | 8083 | Mirrors SCIM `Users` into a local directory from SCIM Events (RFC 9967). Runs without Keycloak, see [5.](#5-scim-provisioning) |
| [`example-support/`](example-support) | | What the three share: `config.toml` with `${VAR:default}` placeholders, profiles, logging |

Neither Keycloak application contains SSF specific code apart from its `config.toml` (and an
`SsfEventHandler` in the resource server that logs the events): `SsfReceiver::builder(config)`
assembles the receiver, `push_router_for` mounts the push endpoint, `SsfRevocationLayer` and
`SsfSessionRevocationLayer` reject what the events revoked. What Spring Security does for the Java
examples is application code here: `auth.rs` of the resource server validates the access tokens
with `jsonwebtoken`, `oidc.rs` of the OIDC client logs users in with `openidconnect`. Both manage
their own stream: on startup they authenticate with the service account of their Keycloak client
and register a PUSH stream for it (`Created SSF stream …`), after a restart they find it again
(`Using existing SSF stream …`). If you delete a stream in the admin console, the application
creates a new one on its next start.

## 1. Start Keycloak

```sh
cd examples/keycloak
docker compose up
```

- Admin console: <http://localhost:8080> (`admin` / `admin`), realm `ssf-demo`
- Users: `tester` / `test` and `bob` / `bob`

The compose project is called `easyssf-examples`, like the one of the Java examples: the two share
the realm, so one of them running is enough for both.

## 2. Build

In the root of the repository:

```sh
cargo build -p example-resource-server -p example-oidc-client -p example-scim-provisioning
```

## 3. Resource server

```sh
cargo run -p example-resource-server
```

Run the requests in
[`example-resource-server.http`](example-resource-server/example-resource-server.http) with the HTTP
client of IntelliJ IDEA, or use `curl`:

```sh
KC=http://localhost:8080/realms/ssf-demo/protocol/openid-connect

# log in as tester and call the API
TOKENS=$(curl -s $KC/token -d grant_type=password -d client_id=example-cli -d username=tester -d password=test)
ACCESS_TOKEN=$(echo "$TOKENS" | jq -r .access_token)
REFRESH_TOKEN=$(echo "$TOKENS" | jq -r .refresh_token)

curl -i localhost:8081/api/me -H "Authorization: Bearer $ACCESS_TOKEN"    # 200

# end the session in Keycloak ...
curl $KC/logout -d client_id=example-cli -d refresh_token=$REFRESH_TOKEN

# ... the access token has not expired, but is rejected within a few seconds
curl -i localhost:8081/api/me -H "Authorization: Bearer $ACCESS_TOKEN"    # 401, error="invalid_token"
```

The log of the resource server shows the stream it registered on startup and the event:

```
INFO easyssf_receiver::stream: Created SSF stream stream="d0200637-…" delivery="urn:ietf:rfc:8935" endpoint="http://host.docker.internal:8081/ssf/push" events=["CaepSessionRevoked"] audience=["example-resource-server/d0200637-…"]
DEBUG easyssf_receiver::set: Received SET jti="b639c4e1-…" delivery=push events=["CaepSessionRevoked"]
INFO easyssf_receiver::revocation: revoked access tokens of session event="CaepSessionRevoked" session="hPB29fvO…" issuer="http://localhost:8080/realms/ssf-demo"
INFO example_resource_server::handler: Security event event="CaepSessionRevoked" user="33bf4f70-…" session="hPB29fvO…" payload={"event_timestamp":…}
DEBUG easyssf_receiver_axum: Rejecting a revoked access token subject="33bf4f70-…"
```

`GET /health` reports the receiver's contact with the transmitter, its stream and, in the `poll`
profile, the poller (503 when unhealthy). The application works with any SSF transmitter that sends
CAEP `session-revoked` events and is the issuer of the access tokens: `SSF_TRANSMITTER_ISSUER`,
`SSF_TOKEN_URI`, `SSF_CLIENT_ID`, `SSF_CLIENT_SECRET` and `SSF_PUSH_URL` override the defaults,
which are the clients of the `ssf-demo` realm. `SSF_PUSH_URL` is how the transmitter reaches the
application; for Keycloak in Docker it must be allowed by `ssf.validPushUrls` of the client.

### Metrics

The receiver is built with the `metrics` feature and records what it does with the `metrics`
facade (`easyssf.receiver.*`); the application installs the Prometheus exporter and renders them
at `GET /metrics`, which needs an access token like the API:

```sh
ACCESS_TOKEN=$(curl -s $KC/token -d grant_type=password -d client_id=example-cli -d username=tester -d password=test | jq -r .access_token)
curl -s localhost:8081/metrics -H "Authorization: Bearer $ACCESS_TOKEN" | grep easyssf
```

```
easyssf_receiver_sets{transmitter="default",delivery="push",outcome="handled"} 1
easyssf_receiver_events{transmitter="default",delivery="push",event="CaepSessionRevoked"} 1
```

### POLL delivery

With the profile `poll` the resource server does not register a PUSH stream for its own client.
It authenticates with the service account of the client `example-poll-receiver` instead, registers a
POLL stream for it and polls the transmitter for events every two seconds, see
[`config-poll.toml`](example-resource-server/config-poll.toml):

```sh
cargo run -p example-resource-server -- --profile poll
```

```
INFO easyssf_receiver::stream: Created SSF stream stream="ef50c4f3-…" delivery="urn:ietf:rfc:8936" endpoint="http://localhost:8080/realms/ssf-demo/ssf/transmitter/receivers/example-poll-receiver/streams/ef50c4f3-…/poll" events=["CaepSessionRevoked"]
DEBUG easyssf_receiver::set: Received SET jti="52e22461-…" delivery=poll events=["CaepSessionRevoked"]
```

The `curl` commands and the `.http` file work the same way. Keycloak keeps pushing to the PUSH
stream of `example-resource-server` in the meantime (streams survive a restart of the application),
which the application rejects in this profile.

## 4. OIDC client

```sh
cargo run -p example-oidc-client
```

1. Open <http://localhost:8082> and log in as `tester` / `test`. The page shows the Keycloak session
   (`sid`) and the local session.
2. Sign out in Keycloak, not in the application: open the
   [account console](http://localhost:8080/realms/ssf-demo/account) (linked on the page) and sign out.
3. Switch back to the tab of the application: the page notices that its local session is gone and
   redirects to the login.

The page polls `GET /auth/check` every five seconds and whenever its tab becomes visible. The endpoint
does not call Keycloak (no token introspection): the receiver records the revocation when the
`session-revoked` event arrives and `SsfSessionRevocationLayer` flushes the local session on its
next request, so the check simply answers 200 while the session exists and 401 once it is gone.

The client `example-oidc-client` has neither a back-channel nor a front-channel logout URL in
Keycloak. The application learns about the logout only through the `session-revoked` event, which
names the Keycloak session:

```
DEBUG easyssf_receiver::set: Received SET jti="c7e34991-…" delivery=push events=["CaepSessionRevoked"]
INFO easyssf_receiver::revocation: revoked access tokens of session event="CaepSessionRevoked" session="QkNy7B8G…" issuer="http://localhost:8080/realms/ssf-demo"
INFO easyssf_receiver_axum::sessions: Ending the revoked session subject="33bf4f70-…"
```

Other things to try:

- In the admin console, sign the user out of all sessions or reset the password: all local sessions
  of the user end (`session-revoked` for the user, `credential-change`).
- *Log out* in the application logs the user out of Keycloak as well (RP-initiated logout), Keycloak
  then sends a `session-revoked` event for that session to both applications.
- Which events end local sessions is configured with `easyssf.receiver.revocation.session-event-types`
  and `user-event-types`, see the [`config.toml`](example-oidc-client/config.toml) of the application.
- If the login fails, the page only says that it failed. The reason is in the log of the application
  (`Login with Keycloak failed: …`).

## 5. SCIM provisioning

[RFC 9967](https://www.rfc-editor.org/rfc/rfc9967) lets a SCIM service provider report the changes
of its resources as SETs. The example mirrors the `Users` into an in-memory directory:
`ScimProvisioningHandler` implements `SsfScimEventHandler` of the receiver and applies `create`,
`put` and `patch` events in `full` mode (the `data` is the resource, or the `PatchOp`), flips
`active` on `activate` and `deactivate`, removes the user on `delete`, and logs `notice` events,
which carry no data; `GET /users` shows the directory.

Keycloak does not emit SCIM Events, so the example brings its own transmitter: the in-process
`TestTransmitter` of `easyssf-test`, which `main` starts before the application and whose issuer it
sets as `easyssf.receiver.transmitter-issuer`. The receiver registers a POLL stream for the SCIM
event types and polls every two seconds, exactly as it would with a real transmitter. `main` also
starts the demo SCIM service provider, `DemoScimProvider`: it plays the life of two users on startup,
one SET every four seconds, and takes requests under `/demo/scim`.

```sh
cargo run -p example-scim-provisioning
```

```
INFO easyssf_receiver::stream: Created SSF stream stream="3f0d…" delivery="urn:ietf:rfc:8936" endpoint="https://transmitter.example/realms/test/poll" events=["ScimFeedAdd", …]
INFO example_scim_provisioning::demo: The receiver registered its stream, the demo SCIM service provider starts
INFO example_scim_provisioning::demo:
### Alice is created at the service provider and joins the feed: feed:add and prov:create:full in one SET, with her representation as data
INFO example_scim_provisioning::demo: Transmitted SET 2c6a… with ["ScimFeedAdd", "ScimProvCreateFull"] for /Users/2b2f880af6674ac284bae9381673d462:
{
  "iss": "https://transmitter.example/realms/test",
  "sub_id": { "format": "scim", "uri": "/Users/2b2f880af6674ac284bae9381673d462", "externalId": "alice" },
  "events": { "urn:ietf:params:scim:event:feed:add": {}, "urn:ietf:params:scim:event:prov:create:full": { … } },
  …
}
INFO example_scim_provisioning::handler: ScimFeedAdd: /Users/2b2f880af6674ac284bae9381673d462 joined the feed
INFO example_scim_provisioning::handler: ScimProvCreateFull: created User[id=2b2f880af6674ac284bae9381673d462, externalId=alice, userName=alice, displayName=Alice Adams, emails=["alice@example.com"], active=true, version=1]
INFO example_scim_provisioning::handler: ScimProvPatchFull: patched User[…, displayName=Alice Baker, emails=["alice@example.com", "alice.baker@home.example"], …, version=2]
INFO example_scim_provisioning::handler: ScimProvPatchNotice: /Users/2b2f880a… modified changed ["phoneNumbers"]; a notice event has no data, the application would GET the resource from the SCIM service provider
INFO example_scim_provisioning::handler: ScimProvDeactivate: deactivated User[…, active=false, version=2]
INFO example_scim_provisioning::handler: ScimProvDelete: deleted User[id=c3a6e1f0…, userName=robert, …]
```

```sh
curl -s localhost:8083/users | jq
```

### Walk through it yourself

The demo service provider is a tiny stand-in for the `/Users` endpoint of a SCIM server. Every
request to it transmits the SCIM Event about the change, the receiver mirrors it on its next poll,
and the response is the SET that was transmitted, so the event sits next to its cause:

| Request | Event |
|---|---|
| `POST /demo/scim/Users` with a SCIM user | `feed:add` and `prov:create:full` in one SET |
| `PUT /demo/scim/Users/{id}` with a SCIM user | `prov:put:full` |
| `PATCH /demo/scim/Users/{id}` with a `PatchOp` | `prov:patch:full`; with `?mode=notice` a `prov:patch:notice` that only names the paths |
| `POST /demo/scim/Users/{id}/activate`, `.../deactivate` | `prov:activate`, `prov:deactivate` |
| `DELETE /demo/scim/Users/{id}` | `prov:delete` |
| `GET /demo/scim/events` | the SETs transmitted so far, compact and decoded |

[`example-scim-provisioning.http`](example-scim-provisioning/example-scim-provisioning.http) runs
the life of a third user through these requests with the HTTP client of IntelliJ IDEA, checking the
directory after each step. Start the application with `-- --demo.autoplay=false` to begin with an
empty directory.

### What a SCIM Event looks like

A SCIM Event is a SET like the CAEP events of Keycloak: the same JWT claims, verified the same
way. What is specific is the subject, a `scim` identifier with the relative `uri` of the resource and
its `externalId`, and the event types under `urn:ietf:params:scim:event:`. The demo logs every SET it
transmits decoded, and `GET /demo/scim/events` lists them; these are the claims of three of them.

A user is created and joins the feed. Two events in one SET, which RFC 9967 allows when they arise
from the same change of the same resource; `full` means the payload carries the resource as `data`:

```json
{
  "iss": "https://transmitter.example/realms/test",
  "jti": "858f32d4-6aa8-4263-b89f-c460da8c56e4",
  "iat": 1791114240,
  "aud": ["receiver/f6d117de-5ec6-4f4c-bb4c-0da0f74f37a6"],
  "txn": "9c1f3a6e2d8b4f0e8a7c5d6b4e3f2a10",
  "sub_id": {
    "format": "scim",
    "uri": "/Users/2b2f880af6674ac284bae9381673d462",
    "externalId": "alice"
  },
  "events": {
    "urn:ietf:params:scim:event:feed:add": {},
    "urn:ietf:params:scim:event:prov:create:full": {
      "version": "1",
      "data": {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "alice",
        "displayName": "Alice Adams",
        "emails": [{"type": "work", "value": "alice@example.com", "primary": true}],
        "active": true
      }
    }
  }
}
```

The user is modified with SCIM PATCH. The `data` is the `PatchOp` the service provider applied, the
`version` the ETag of the resource afterwards:

```json
{
  "iss": "https://transmitter.example/realms/test",
  "jti": "165c8a92-c6ae-4390-855f-0a99d52753af",
  "iat": 1791114248,
  "aud": ["receiver/f6d117de-5ec6-4f4c-bb4c-0da0f74f37a6"],
  "txn": "4b7e9d2c1a3f4e5d8c6b7a9e0f1d2c3b",
  "sub_id": {
    "format": "scim",
    "uri": "/Users/2b2f880af6674ac284bae9381673d462",
    "externalId": "alice"
  },
  "events": {
    "urn:ietf:params:scim:event:prov:patch:full": {
      "version": "2",
      "data": {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
          {"op": "replace", "path": "displayName", "value": "Alice Baker"},
          {"op": "add", "path": "emails", "value": [
            {"type": "work", "value": "alice@example.com"},
            {"type": "home", "value": "alice.baker@home.example"}
          ]}
        ]
      }
    }
  }
}
```

The same change as a `notice`: the payload names the attributes that changed and nothing else, a
receiver that needs the values fetches the resource from the service provider with a GET of the
`uri`. Events without payload attributes, `prov:delete`, `prov:activate` and `prov:deactivate`, have
an empty object:

```json
{
  "iss": "https://transmitter.example/realms/test",
  "jti": "913ea597-421b-4cf1-8c8a-37b918e61c6c",
  "iat": 1791114256,
  "aud": ["receiver/f6d117de-5ec6-4f4c-bb4c-0da0f74f37a6"],
  "txn": "7d2a5c8e4b1f4a6d9e3c2b5a8f7e6d4c",
  "sub_id": {
    "format": "scim",
    "uri": "/Users/2b2f880af6674ac284bae9381673d462",
    "externalId": "alice"
  },
  "events": {
    "urn:ietf:params:scim:event:prov:patch:notice": {
      "version": "3",
      "attributes": ["phoneNumbers"]
    }
  }
}
```

On the wire each of these is a signed JWT with `typ: secevent+jwt` (the `set` member of
`GET /demo/scim/events`), delivered by poll here, by push with a real transmitter that can reach the
application. The receiver verifies the signature against the transmitter's keys, `iss`, `aud`,
`iat` and `jti`, requires the top-level `sub_id` (which RFC 9967 mandates), skips a `jti` it has
seen, and hands the events to the handler.

Against a real SCIM service provider: put its issuer, token and delivery method into
[`config.toml`](example-scim-provisioning/config.toml) and build the application without the demo
(`ApplicationOptions { demo: false, .. }`); the handler and the directory stay as they are. The
tests run the application against the transmitter on a random port:
`example_scim_provisioning_application.rs` plays a user through create, patch, activate and delete
without the demo, `demo_scim_provider.rs` the walk-through of the `.http` file.

```sh
cargo test -p example-scim-provisioning
```

## What triggers an event in Keycloak

| Action | Event | Subject |
|---|---|---|
| A user logs out (logout in an application, `/logout` endpoint) | `session-revoked` | user and session |
| An admin signs a user out of all sessions | `session-revoked` | user, session `ALL` |
| A credential changes (for example an admin resets the password) | `credential-change` | user |

Removing a *single* session through the admin API (`DELETE /admin/realms/{realm}/sessions/{id}`) does
not produce an event in Keycloak 26.8.

## How the realm is set up

Everything is in [`keycloak/ssf-demo-realm.json`](keycloak/ssf-demo-realm.json) and
[`keycloak/compose.yaml`](keycloak/compose.yaml), both copies of the files of the Java examples:

| | |
|---|---|
| `--features=ssf` | SSF is an experimental feature of Keycloak. |
| Realm attribute `ssf.transmitterEnabled` | Turns the realm into an SSF transmitter. |
| Clients `example-resource-server` and `example-oidc-client` | SSF receivers (`ssf.enabled`). A receiver is a client, so the resource server gets one too although it does not log users in. |
| Service account and optional client scopes `ssf.read`, `ssf.manage` | Let the application manage the stream of its client (`easyssf.receiver.stream.management = "receiver"` with `easyssf.receiver.oauth2.*`). Keycloak creates the two client scopes when the `ssf` feature is enabled. |
| Client attribute `ssf.defaultSubjects=ALL` | Deliver events of all users. By default a receiver only gets events of users that were subscribed explicitly. |
| Client attribute `ssf.validPushUrls` | The push URLs a stream of this client may use, here `http://host.docker.internal:<port>/ssf/push`, which the application registers (`easyssf.receiver.push.delivery-endpoint-url`). |
| Client attributes `ssf.stream.*` | The stream itself. Not in the realm file: the application creates it on startup, with the `Authorization` header from `easyssf.receiver.push.expected-auth-header`. Keycloak assigns the audience (`<clientId>/<streamId>`), which the application takes from the stream to validate SETs. In the admin console: *Clients* → client → *SSF*. |
| Client `example-poll-receiver` | Receiver for the `poll` profile of the resource server: a second client, because Keycloak allows one stream per client and the PUSH stream of `example-resource-server` stays. |
| Client `example-cli` | Public client to obtain access tokens with `curl`. |
| `allow-insecure-push-targets=true` | Keycloak only pushes to public `https` URLs by default. |
| `outbox-drainer-interval=2s` | Keycloak delivers events every 30 seconds by default. |
| `KC_HOSTNAME=http://localhost:8080` | Fixes the issuer, events are created outside of a request. |

Keycloak stores its database in `keycloak/data`, so streams, users and changes made in the admin
console survive `docker compose down`. The realm is only imported into an empty database: to pick up
changes to `ssf-demo-realm.json`, stop Keycloak and delete `keycloak/data`.

## Using another Keycloak

The resource server reads the issuer from `SSF_TRANSMITTER_ISSUER` (default
`http://localhost:8080/realms/ssf-demo`), the token endpoint from `SSF_TOKEN_URI` (default
`<issuer>/protocol/openid-connect/token`) and its client from `SSF_CLIENT_ID` and
`SSF_CLIENT_SECRET` (in the `poll` profile the defaults are those of `example-poll-receiver`); it
is not tied to Keycloak. The OIDC client reads the issuer from `KEYCLOAK_ISSUER` and the secret of
its client from `KEYCLOAK_CLIENT_SECRET`. Both read the URL under which the transmitter reaches
their push endpoint from `SSF_PUSH_URL` (default `http://host.docker.internal:<port>/ssf/push`) and
their port from `SERVER_PORT`. The clients need
a service account with the client scopes `ssf.read` and `ssf.manage`, and the push URL has to be
allowed in `ssf.validPushUrls` of the client. The push authorization header is set in the
`config.toml` of each application. The receiver accepts a plain `http` issuer only on `localhost`;
for another host over `http`, set `easyssf.receiver.allow-insecure-http = true`.
