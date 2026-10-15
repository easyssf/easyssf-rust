# easyssf-receiver

An [OpenID Shared Signals Framework (SSF 1.0)](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)
receiver without a web framework: SET verification against the transmitter's JWK Set, replay
protection with a leased de-duplication store, PUSH (RFC 8935) and POLL (RFC 8936) delivery, stream
management, typed CAEP, RISC and SCIM handlers, token revocation and session termination, metrics.
`SsfReceiver` assembles all of it from a configuration whose keys are those of the Spring Boot starter
and the .NET options.

```rust
let receiver = SsfReceiver::builder(config)
    .handler(for_event("CaepSessionRevoked", |context: SsfEventContext| async move {
        // end what you hold for context.subject()
        Ok(())
    }))
    .build()?;
receiver.start(); // registers the stream, starts polling
```

```toml
[dependencies]
easyssf-receiver = "0.6.0"
```

The push endpoint, the revocation layer and the session hooks for a web framework are in
`easyssf-receiver-axum` and `easyssf-receiver-actix-web`, the database stores in
`easyssf-receiver-sqlx`, a transmitter for tests in `easyssf-test`. Exactly one crypto backend is on,
`rust-crypto` (default) or `aws-lc-rs`.

Part of [easyssf-rust](https://github.com/easyssf/easyssf-rust), the port of [easyssf for Java](https://github.com/easyssf/easyssf).
The [README of the repository](https://github.com/easyssf/easyssf-rust#readme) explains the whole library. Apache-2.0.
