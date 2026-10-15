# easyssf-test

`TestTransmitter`, an SSF transmitter for the tests of a receiver built on `easyssf-receiver`: it
publishes transmitter metadata and a JWK Set, signs SETs and access tokens, issues tokens for the
client credentials grant and emulates stream management and a poll endpoint, all in-process through
the receiver's `SsfHttpClient` trait. No socket, no network. `eventually` and `during` wait for
background behaviour.

```toml
[dev-dependencies]
easyssf-test = "0.7.0-alpha.1"
```

Part of [easyssf-rust](https://github.com/easyssf/easyssf-rust), the port of [easyssf for Java](https://github.com/easyssf/easyssf).
The [README of the repository](https://github.com/easyssf/easyssf-rust#testing-your-receiver) shows how to test a receiver with it. Apache-2.0.
