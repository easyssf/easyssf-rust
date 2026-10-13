//! Starts the application against a transmitter on a random port, like the Spring Boot tests do
//! with `@SpringBootTest(webEnvironment = RANDOM_PORT)` and `@DynamicPropertySource`.

use std::time::Duration;

use easyssf_test::TestTransmitter;
use example_scim_provisioning::{Application, ApplicationOptions, build, receiver_config};

pub struct Started {
    pub base_url: String,
    pub application: Application,
}

pub async fn start(transmitter: &TestTransmitter, options: ApplicationOptions) -> Started {
    let mut config = receiver_config(transmitter).expect("configuration");
    // poll every 200 ms
    config.transmitter.poll.interval = Duration::from_millis(200);
    config.transmitter.poll.initial_delay = Duration::from_millis(100);
    let application = build(transmitter.clone(), config, options).expect("application");
    application.start();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("port");
    let address = listener.local_addr().expect("address");
    tokio::spawn(axum::serve(listener, application.router.clone()).into_future());
    Started {
        base_url: format!("http://{address}"),
        application,
    }
}
