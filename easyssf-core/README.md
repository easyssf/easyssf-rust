# easyssf-core

The vocabulary of the [OpenID Shared Signals Framework (SSF 1.0)](https://openid.net/specs/openid-sharedsignals-framework-1_0.html)
for Rust: Security Event Tokens, subjects with every RFC 9493 identifier format, the event types of
SSF, CAEP, RISC and SCIM Events (RFC 9967) with their aliases, the typed `SsfCaepEvent`, `SsfRiscEvent`
and `SsfScimEvent`, stream configuration and transmitter metadata. Raw claims stay `serde_json` values,
typed accessors sit on top.

Part of [easyssf-rust](https://github.com/easyssf/easyssf-rust), the port of [easyssf for Java](https://github.com/easyssf/easyssf).
A receiver uses it through `easyssf-receiver`; depend on this crate alone to read SETs and events
without a receiver, or to write a transmitter.

```toml
[dependencies]
easyssf-core = "0.6.0"
```

The [README of the repository](https://github.com/easyssf/easyssf-rust#readme) explains the whole library. Apache-2.0.
