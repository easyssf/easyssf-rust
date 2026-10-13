//! Mirrors the users of a SCIM service provider into a local [`UserDirectory`] from the SCIM Events
//! (RFC 9967) the provider transmits over SSF. The receiver polls the transmitter and hands the
//! events to [`ScimProvisioningHandler`]; the directory is published at `/users`.
//!
//! Keycloak does not emit SCIM Events, so the example brings its own transmitter: the in-process
//! [`TestTransmitter`] of `easyssf-test`, which [`DemoScimProvider`] feeds with the life of two
//! users and with the requests to `/demo/scim`. Against a real SCIM service provider, the
//! `easyssf.receiver` section of `config.toml` is all that changes; the handler and the directory
//! stay as they are.
//!
//! The crate is a library so that the tests can start the application against a transmitter of
//! their own; `main.rs` starts it on port 8083 with the demo.

pub mod demo;
pub mod directory;
pub mod handler;
pub mod user;

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use easyssf_receiver::config::SsfReceiverConfig;
use easyssf_receiver::scim::scim;
use easyssf_receiver::{BoxError, SsfReceiver};
use easyssf_test::TestTransmitter;
use http::StatusCode;

pub use crate::demo::DemoScimProvider;
pub use crate::directory::UserDirectory;
pub use crate::handler::ScimProvisioningHandler;
pub use crate::user::User;

/// `config.toml`.
pub const CONFIG: &str = include_str!("../config.toml");

/// What to start besides the receiver and the directory.
#[derive(Debug, Clone, Copy)]
pub struct ApplicationOptions {
    /// The demo SCIM service provider under `/demo/scim` (the `demo` profile of the Java example).
    pub demo: bool,
    /// Whether the demo plays the life of two users on startup (`demo.autoplay`).
    pub autoplay: bool,
}

/// The application: the receiver against the transmitter, the directory and the HTTP API.
pub struct Application {
    /// The routes: `/users`, and `/demo/scim` with the demo.
    pub router: Router,
    /// The receiver.
    pub receiver: Arc<SsfReceiver>,
    /// The directory the events are mirrored into.
    pub directory: Arc<UserDirectory>,
    /// The demo SCIM service provider, with [`ApplicationOptions::demo`].
    pub demo: Option<Arc<DemoScimProvider>>,
    autoplay: bool,
}

/// The receiver configuration of `config.toml` with the issuer of `transmitter`.
pub fn receiver_config(transmitter: &TestTransmitter) -> Result<SsfReceiverConfig, BoxError> {
    let settings = example_support::load(&[CONFIG])?;
    let mut config: SsfReceiverConfig = example_support::section(&settings, "easyssf.receiver")?;
    config.transmitter.transmitter_issuer = Some(transmitter.issuer().to_owned());
    Ok(config)
}

/// Assembles the application against `transmitter`; [`Application::start`] starts it.
pub fn build(
    transmitter: TestTransmitter,
    config: SsfReceiverConfig,
    options: ApplicationOptions,
) -> Result<Application, BoxError> {
    let directory = Arc::new(UserDirectory::default());
    let receiver = SsfReceiver::builder(config)
        // the transmitter answers in-process
        .http_client(transmitter.clone())
        // mirrors the SCIM Events into the directory
        .handler(scim(ScimProvisioningHandler::new(directory.clone())))
        .build()?;
    let mut router = Router::new()
        .route("/users", get(users))
        .route("/users/{id}", get(user))
        .with_state(directory.clone());
    let demo = options.demo.then(|| Arc::new(DemoScimProvider::new(transmitter)));
    if let Some(demo) = &demo {
        router = router.merge(demo::router(demo.clone()));
    }
    Ok(Application {
        router,
        receiver: Arc::new(receiver),
        directory,
        demo,
        autoplay: options.autoplay,
    })
}

impl Application {
    /// Starts the receiver, which registers the stream and polls, and the scripted demo if it is
    /// on. Needs a tokio runtime.
    pub fn start(&self) {
        self.receiver.start();
        if let Some(demo) = &self.demo {
            if self.autoplay {
                tokio::spawn(demo.clone().play());
            } else {
                tracing::info!("The demo SCIM service provider waits for requests to /demo/scim, demo.autoplay is off");
            }
        }
    }

    /// Stops the receiver.
    pub async fn shutdown(&self) {
        self.receiver.shutdown().await;
    }
}

/// `GET /users`: the mirrored directory.
async fn users(State(directory): State<Arc<UserDirectory>>) -> Json<Vec<User>> {
    Json(directory.all())
}

/// `GET /users/{id}`: one user, 404 if the directory has no such user.
async fn user(State(directory): State<Arc<UserDirectory>>, Path(id): Path<String>) -> Response {
    match directory.find(&id) {
        Some(user) => Json(user).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
