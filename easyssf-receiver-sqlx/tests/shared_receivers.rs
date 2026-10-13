//! `AbstractJdbcSharedReceiversTests` of the Java library: two instances of a receiver on one
//! database. On SQLite in memory.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use easyssf_receiver::SsfReceiver;
use easyssf_receiver::config::SsfReceiverConfig;
use easyssf_receiver::event::SsfEventContext;
use easyssf_receiver::poll::SsfPollAckStore;
use easyssf_receiver_sqlx::{SqlxSsfSqlOperations, SsfSqlStores};
use easyssf_test::subjects::iss_sub;
use easyssf_test::{TestTransmitter, during, eventually};
use serde_json::json;
use tokio::sync::Notify;

async fn stores(config: &SsfReceiverConfig) -> SsfSqlStores {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let stores = SsfSqlStores::from_config(SqlxSsfSqlOperations::sqlite(pool), config);
    stores.prepare_tables().await.unwrap();
    stores
}

fn config(transmitter: &TestTransmitter) -> SsfReceiverConfig {
    toml::from_str(&format!(
        r#"
        transmitter-issuer = "{}"
        expected-audience = "{}"
        delivery-method = "poll"
        transmitter-access-token = "{}"
        [poll]
        endpoint-url = "{}"
        interval = "50ms"
        initial-delay = "0s"
        [dedup]
        lease = "300ms"
        "#,
        transmitter.issuer(),
        TestTransmitter::AUDIENCE,
        TestTransmitter::ACCESS_TOKEN,
        transmitter.poll_uri()
    ))
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_is_handled_once_and_acknowledged_by_whichever_instance_polls_next() {
    let transmitter = TestTransmitter::new();
    let config = config(&transmitter);
    let stores = stores(&config).await;
    let handled = Arc::new(AtomicUsize::new(0));
    let mut receivers = Vec::new();
    for _ in 0..2 {
        let counter = handled.clone();
        let receiver = stores
            .apply(SsfReceiver::builder(config.clone()))
            .http_client(transmitter.clone())
            .handler(move |_: SsfEventContext| {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            })
            .build()
            .unwrap();
        receiver.start();
        receivers.push(receiver);
    }
    transmitter.queue_set(&transmitter.set("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice"))));
    eventually(Duration::from_secs(5), "the acknowledgement", || {
        transmitter.acknowledged_sets().len() == 1
    })
    .await;
    during(Duration::from_millis(300), "handled once", || {
        handled.load(Ordering::SeqCst) == 1
    })
    .await;
    // a redelivery later is handled by no instance
    transmitter.queue_set(&transmitter.set("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "bob"))));
    eventually(Duration::from_secs(5), "the second acknowledgement", || {
        transmitter.acknowledged_sets().len() == 2
    })
    .await;
    assert_eq!(handled.load(Ordering::SeqCst), 2);
    for receiver in &receivers {
        receiver.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_being_handled_by_one_instance_is_neither_handled_nor_acknowledged_by_another() {
    let transmitter = TestTransmitter::new();
    let config = config(&transmitter);
    let stores = stores(&config).await;
    let release = Arc::new(Notify::new());
    let entered = Arc::new(AtomicUsize::new(0));
    let (gate, count) = (release.clone(), entered.clone());
    let slow = stores
        .apply(SsfReceiver::builder(config.clone()))
        .http_client(transmitter.clone())
        .handler(move |_: SsfEventContext| {
            let (gate, count) = (gate.clone(), count.clone());
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                gate.notified().await;
                Ok(())
            }
        })
        .build()
        .unwrap();
    let other_handled = Arc::new(AtomicUsize::new(0));
    let counter = other_handled.clone();
    let other = stores
        .apply(SsfReceiver::builder(config.clone()))
        .http_client(transmitter.clone())
        .handler(move |_: SsfEventContext| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .build()
        .unwrap();
    slow.start();
    transmitter.queue_set(&transmitter.set("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice"))));
    eventually(Duration::from_secs(5), "the slow handler", || {
        entered.load(Ordering::SeqCst) == 1
    })
    .await;
    other.start();
    // the other instance polls the SET too, but leaves it alone while the claim is renewed
    during(Duration::from_millis(500), "left alone", || {
        other_handled.load(Ordering::SeqCst) == 0 && transmitter.acknowledged_sets().is_empty()
    })
    .await;
    release.notify_waiters();
    eventually(Duration::from_secs(5), "the acknowledgement", || {
        transmitter.acknowledged_sets().len() == 1
    })
    .await;
    assert_eq!(other_handled.load(Ordering::SeqCst), 0);
    slow.shutdown().await;
    other.shutdown().await;
    let _ = json!({});
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn error_report_of_one_instance_leaves_with_the_next_poll_of_another() {
    let transmitter = TestTransmitter::new();
    let config = config(&transmitter);
    let stores = stores(&config).await;
    let first = stores
        .apply(SsfReceiver::builder(config.clone()))
        .http_client(transmitter.clone())
        .build()
        .unwrap();
    let second = stores
        .apply(SsfReceiver::builder(config.clone()))
        .http_client(transmitter.clone())
        .build()
        .unwrap();
    let mut claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    claims.insert("aud".to_owned(), json!("https://other.example"));
    transmitter.queue_set(&transmitter.sign_set(&claims));
    // the first instance polls once by hand and records the error; the transmitter is then down
    let poller = first.transmitters().all()[0].poller().unwrap().clone();
    let first_error = {
        transmitter.set_available(true);
        poller.poll_now().await.unwrap();
        transmitter.reported_errors().len()
    };
    assert_eq!(
        first_error, 1,
        "reported with the acknowledging request of the same poll"
    );
    // a report recorded by the first instance's store reaches the transmitter with the second's poll
    stores
        .ack_store()
        .record(
            transmitter.issuer(),
            easyssf_receiver::poll::SsfPendingAck::error("stale", "invalid_request", None),
        )
        .await
        .unwrap();
    second.start();
    eventually(Duration::from_secs(5), "the stale report", || {
        transmitter.reported_errors().iter().any(|(jti, _)| jti == "stale")
    })
    .await;
    second.shutdown().await;
}
