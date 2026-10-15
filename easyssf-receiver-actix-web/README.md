# easyssf-receiver-actix-web

The easyssf receiver for [actix-web](https://crates.io/crates/actix-web): `configure_push_for()` for
the push endpoint, the `SsfRevocation` middleware for resource servers that must reject revoked
access tokens, and, behind the `actix-session` feature, `SsfSessionRevocation`, which ends sessions a
security event revoked.

```toml
[dependencies]
easyssf-receiver = "0.7.0-alpha.1"
easyssf-receiver-actix-web = "0.7.0-alpha.1"
```

Part of [easyssf-rust](https://github.com/easyssf/easyssf-rust), the port of [easyssf for Java](https://github.com/easyssf/easyssf).
The [README of the repository](https://github.com/easyssf/easyssf-rust#actix-web) walks through a receiver on actix-web. Apache-2.0.
