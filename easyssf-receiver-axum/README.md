# easyssf-receiver-axum

The easyssf receiver for [axum](https://crates.io/crates/axum), and through tower for tonic, Loco,
Leptos and everything else that runs on it: `push_router_for()` for the push endpoint,
`SsfRevocationLayer` for resource servers that must reject revoked access tokens, and, behind the
`tower-sessions` feature, `SsfSessionRevocationLayer`, which ends sessions a security event revoked.

```toml
[dependencies]
easyssf-receiver = "0.7.0-alpha.1"
easyssf-receiver-axum = "0.7.0-alpha.1"
```

Part of [easyssf-rust](https://github.com/easyssf/easyssf-rust), the port of [easyssf for Java](https://github.com/easyssf/easyssf).
The [README of the repository](https://github.com/easyssf/easyssf-rust#getting-started) walks through a receiver on axum. Apache-2.0.
