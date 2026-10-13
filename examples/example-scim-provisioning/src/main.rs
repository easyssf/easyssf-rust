//! Mirrors the users of a SCIM service provider into a local directory from the SCIM Events
//! (RFC 9967) the provider transmits over SSF, against the in-process demo transmitter.
//!
//! ```sh
//! cargo run -p example-scim-provisioning                            # plays the life of two users
//! cargo run -p example-scim-provisioning -- --demo.autoplay=false   # starts with an empty directory
//! curl -s localhost:8083/users
//! ```
//!
//! The demo SCIM service provider takes requests under `/demo/scim`, see
//! `example-scim-provisioning.http`.

use easyssf_receiver::BoxError;
use easyssf_test::TestTransmitter;
use example_scim_provisioning::{ApplicationOptions, CONFIG, build, receiver_config};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ServerConfig {
    port: u16,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self { port: 8083 }
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    example_support::init_tracing("info,easyssf=info,example_scim_provisioning=debug");
    let args: Vec<String> = std::env::args().collect();
    let autoplay = example_support::argument(&args, "demo.autoplay").is_none_or(|value| value != "false");
    let settings = example_support::load(&[CONFIG])?;
    let server: ServerConfig = example_support::section(&settings, "server")?;

    // the transmitter starts before the application: the receiver needs its issuer
    let transmitter = TestTransmitter::new();
    let config = receiver_config(&transmitter)?;
    let application = build(transmitter, config, ApplicationOptions { demo: true, autoplay })?;
    application.start();

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", server.port))
        .await
        .map_err(|error| {
            format!(
                "Could not listen on port {} ({error}); SERVER_PORT chooses another one",
                server.port
            )
        })?;
    tracing::info!(
        "The SCIM provisioning example listens on http://localhost:{}",
        server.port
    );
    axum::serve(listener, application.router.clone())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    application.shutdown().await;
    Ok(())
}
