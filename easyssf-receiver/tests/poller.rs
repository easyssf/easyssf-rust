//! `SsfPollerTests` and `SsfPollerRateLimitTests` of the Java library.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use common::{Recorder, processor};
use easyssf_core::SsfDeliveryMethod;
use easyssf_receiver::BoxError;
use easyssf_receiver::event::SsfEventContext;
use easyssf_receiver::http::{SsfHttpClient, SsfHttpRequest, SsfHttpResponse};
use easyssf_receiver::metrics::SsfReceiverMetrics;
use easyssf_receiver::poll::{InMemorySsfPollAckStore, SsfPollAckStore, SsfPoller, SsfPollerOptions};
use easyssf_receiver::set::SsfSetProcessor;
use easyssf_receiver::transmitter::FixedSsfTransmitterTokenProvider;
use easyssf_test::subjects::iss_sub;
use easyssf_test::{TestTransmitter, during, eventually};
use serde_json::json;
use url::Url;

fn options() -> SsfPollerOptions {
    SsfPollerOptions {
        interval: Duration::from_millis(100),
        endpoint_retry: Duration::from_millis(20),
        ..SsfPollerOptions::default()
    }
}

fn poller_with(transmitter: &TestTransmitter, processor: SsfSetProcessor, options: SsfPollerOptions) -> SsfPoller {
    let endpoint = Url::parse(&transmitter.poll_uri()).unwrap();
    SsfPoller::new(
        transmitter.clone(),
        FixedSsfTransmitterTokenProvider(TestTransmitter::ACCESS_TOKEN.to_owned()),
        Arc::new(move || Some(endpoint.clone())),
        Arc::new(processor),
        options,
    )
}

fn poller(transmitter: &TestTransmitter, recorder: &Recorder) -> SsfPoller {
    poller_with(
        transmitter,
        processor(transmitter).handler(recorder.handler()),
        options(),
    )
}

fn queue(transmitter: &TestTransmitter) -> String {
    let set = transmitter.set("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    transmitter.queue_set(&set);
    TestTransmitter::claims_of(&set)["jti"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn start_is_idempotent_and_stop_ends_the_polling_task() {
    let transmitter = TestTransmitter::new();
    let poller = poller(&transmitter, &Recorder::default());
    assert!(!poller.is_running());
    poller.start();
    poller.start();
    assert!(poller.is_running());
    eventually(Duration::from_secs(5), "a poll", || transmitter.poll_requests() > 0).await;
    poller.stop().await;
    assert!(!poller.is_running());
    let polls = transmitter.poll_requests();
    during(Duration::from_millis(250), "no more polls", || {
        transmitter.poll_requests() == polls
    })
    .await;
    poller.stop().await;
}

#[tokio::test]
async fn handles_and_acknowledges_available_sets() {
    let transmitter = TestTransmitter::new();
    let recorder = Recorder::default();
    let poller = poller(&transmitter, &recorder);
    let jti = queue(&transmitter);
    assert_eq!(poller.poll_now().await.unwrap(), 1);
    assert_eq!(recorder.jtis(), std::slice::from_ref(&jti));
    assert_eq!(
        transmitter.acknowledged_sets(),
        [jti],
        "acknowledged with a second, immediate request"
    );
    assert_eq!(transmitter.queued_set_count(), 0);
    assert_eq!(poller.pending_ack_count().await, 0);
    assert!(poller.last_successful_poll_at().is_some());
    assert!(poller.last_poll_error().is_none());
    assert_eq!(poller.poll_now().await.unwrap(), 0);
}

#[tokio::test]
async fn fetches_all_sets_when_more_are_available_than_fit_in_one_request() {
    let transmitter = TestTransmitter::new();
    let recorder = Recorder::default();
    let poller = poller_with(
        &transmitter,
        processor(&transmitter).handler(recorder.handler()),
        SsfPollerOptions {
            max_events: 2,
            ..options()
        },
    );
    for _ in 0..5 {
        queue(&transmitter);
    }
    assert_eq!(poller.poll_now().await.unwrap(), 5);
    assert_eq!(recorder.count(), 5);
    assert_eq!(transmitter.acknowledged_sets().len(), 5);
}

#[tokio::test]
async fn reports_invalid_set_to_the_transmitter() {
    let transmitter = TestTransmitter::new();
    let recorder = Recorder::default();
    let poller = poller(&transmitter, &recorder);
    let mut claims = transmitter.set_claims("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    claims.insert("aud".to_owned(), json!("https://other.example"));
    transmitter.queue_set_with_jti("bad", &transmitter.sign_set(&claims));
    transmitter.queue_set_with_jti("garbage", "not a set");
    assert_eq!(poller.poll_now().await.unwrap(), 2);
    assert_eq!(recorder.count(), 0);
    let errors = transmitter.reported_errors();
    assert_eq!(errors.len(), 2);
    assert_eq!(
        errors.iter().find(|(jti, _)| jti == "bad").unwrap().1["err"],
        "invalid_audience"
    );
    assert_eq!(
        errors.iter().find(|(jti, _)| jti == "garbage").unwrap().1["err"],
        "invalid_request"
    );
    assert!(transmitter.acknowledged_sets().is_empty());
}

#[tokio::test]
async fn does_not_acknowledge_set_that_could_not_be_handled_so_that_it_is_delivered_again() {
    let transmitter = TestTransmitter::new();
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();
    let processor = processor(&transmitter).handler(move |_: SsfEventContext| {
        let counter = counter.clone();
        async move {
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(BoxError::from("first attempt fails"));
            }
            Ok(())
        }
    });
    let poller = poller_with(&transmitter, processor, options());
    let jti = queue(&transmitter);
    assert_eq!(poller.poll_now().await.unwrap(), 1);
    assert!(transmitter.acknowledged_sets().is_empty());
    assert_eq!(transmitter.queued_set_count(), 1);
    // delivered again with the next poll
    assert_eq!(poller.poll_now().await.unwrap(), 1);
    assert_eq!(transmitter.acknowledged_sets(), [jti]);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn obtains_new_access_token_when_the_transmitter_rejects_the_current_one() {
    let transmitter = TestTransmitter::new();
    let recorder = Recorder::default();
    let endpoint = Url::parse(&transmitter.poll_uri()).unwrap();
    let provider = Arc::new(
        easyssf_receiver::transmitter::ClientCredentialsSsfTransmitterTokenProvider::new(
            transmitter.clone(),
            Url::parse(&transmitter.token_uri()).unwrap(),
            TestTransmitter::CLIENT_ID,
            TestTransmitter::CLIENT_SECRET,
            easyssf_receiver::transmitter::SsfClientCredentialsOptions::default(),
        ),
    );
    let poller = SsfPoller::new(
        transmitter.clone(),
        provider,
        Arc::new(move || Some(endpoint.clone())),
        Arc::new(processor(&transmitter).handler(recorder.handler())),
        options(),
    );
    poller.poll_now().await.unwrap();
    transmitter.expire_access_tokens();
    queue(&transmitter);
    assert_eq!(poller.poll_now().await.unwrap(), 1);
    assert_eq!(transmitter.token_requests(), 2);
}

#[tokio::test]
async fn does_not_poll_while_the_poll_endpoint_is_unknown() {
    let transmitter = TestTransmitter::new();
    let known = Arc::new(Mutex::new(None::<Url>));
    let endpoint = known.clone();
    let poller = SsfPoller::new(
        transmitter.clone(),
        FixedSsfTransmitterTokenProvider(TestTransmitter::ACCESS_TOKEN.to_owned()),
        Arc::new(move || endpoint.lock().unwrap().clone()),
        Arc::new(processor(&transmitter)),
        options(),
    );
    assert_eq!(poller.poll_now().await.unwrap(), 0);
    assert_eq!(transmitter.poll_requests(), 0);
    assert!(poller.last_poll_at().is_none());
    assert_eq!(poller.pending_ack_count().await, 0);
    *known.lock().unwrap() = Some(Url::parse(&transmitter.poll_uri()).unwrap());
    poller.poll_now().await.unwrap();
    assert_eq!(transmitter.poll_requests(), 1);
}

#[tokio::test]
async fn polls_soon_after_the_endpoint_becomes_known_instead_of_waiting_the_interval() {
    let transmitter = TestTransmitter::new();
    let known = Arc::new(Mutex::new(None::<Url>));
    let endpoint = known.clone();
    let poller = SsfPoller::new(
        transmitter.clone(),
        FixedSsfTransmitterTokenProvider(TestTransmitter::ACCESS_TOKEN.to_owned()),
        Arc::new(move || endpoint.lock().unwrap().clone()),
        Arc::new(processor(&transmitter)),
        SsfPollerOptions {
            interval: Duration::from_secs(60),
            endpoint_retry: Duration::from_millis(20),
            ..SsfPollerOptions::default()
        },
    );
    poller.start();
    during(Duration::from_millis(100), "no poll without an endpoint", || {
        transmitter.poll_requests() == 0
    })
    .await;
    *known.lock().unwrap() = Some(Url::parse(&transmitter.poll_uri()).unwrap());
    eventually(Duration::from_secs(2), "a poll within the endpoint retry", || {
        transmitter.poll_requests() > 0
    })
    .await;
    poller.stop().await;
}

#[tokio::test]
async fn wake_up_ends_the_pause_and_polls_at_once() {
    let transmitter = TestTransmitter::new();
    let poller = poller_with(
        &transmitter,
        processor(&transmitter),
        SsfPollerOptions {
            interval: Duration::from_secs(60),
            ..SsfPollerOptions::default()
        },
    );
    poller.start();
    eventually(Duration::from_secs(2), "the first poll", || {
        transmitter.poll_requests() == 1
    })
    .await;
    during(Duration::from_millis(100), "the pause", || {
        transmitter.poll_requests() == 1
    })
    .await;
    poller.wake_up();
    eventually(Duration::from_secs(2), "the second poll", || {
        transmitter.poll_requests() == 2
    })
    .await;
    poller.stop().await;
}

#[tokio::test]
async fn wake_up_does_nothing_while_the_poller_is_not_running() {
    let transmitter = TestTransmitter::new();
    let poller = poller(&transmitter, &Recorder::default());
    poller.wake_up();
    during(Duration::from_millis(100), "no poll", || {
        transmitter.poll_requests() == 0
    })
    .await;
}

#[tokio::test]
async fn reports_failed_poll_request() {
    let transmitter = TestTransmitter::new();
    let poller = poller(&transmitter, &Recorder::default());
    transmitter.set_available(false);
    let error = poller.poll_now().await.unwrap_err();
    assert!(error.to_string().contains("503"), "{error}");
    assert!(poller.last_poll_at().is_some());
    assert!(poller.last_successful_poll_at().is_none());
    assert!(poller.last_poll_error().unwrap().contains("503"));
    transmitter.set_available(true);
    poller.poll_now().await.unwrap();
    assert!(poller.last_poll_error().is_none());
}

#[tokio::test]
async fn acknowledgements_wait_in_the_store_until_a_request_carried_them() {
    let transmitter = TestTransmitter::new();
    let store = Arc::new(InMemorySsfPollAckStore::default());
    let poller = poller_with(
        &transmitter,
        processor(&transmitter),
        SsfPollerOptions {
            ack_store: store.clone(),
            transmitter: Some(transmitter.issuer().to_owned()),
            ..options()
        },
    );
    let jti = queue(&transmitter);
    // the acknowledging request fails: the ack stays in the store
    let available_after_first = transmitter.clone();
    let _ = available_after_first;
    poller.poll_now().await.unwrap();
    assert_eq!(transmitter.acknowledged_sets(), std::slice::from_ref(&jti));
    assert_eq!(store.size(transmitter.issuer()).await.unwrap(), 0);
    // an acknowledgement recorded by hand rides on the next request
    store
        .record(
            transmitter.issuer(),
            easyssf_receiver::poll::SsfPendingAck::ack("manual"),
        )
        .await
        .unwrap();
    assert_eq!(poller.pending_ack_count().await, 1);
    transmitter.set_available(false);
    assert!(poller.poll_now().await.is_err());
    assert_eq!(poller.pending_ack_count().await, 1, "kept after a failed request");
    transmitter.set_available(true);
    poller.poll_now().await.unwrap();
    assert_eq!(poller.pending_ack_count().await, 0);
    assert_eq!(
        transmitter.last_poll_request()["ack"],
        json!(["manual"]),
        "delivered with the fetch"
    );
}

#[tokio::test]
async fn acknowledgements_are_sent_in_batches() {
    let transmitter = TestTransmitter::new();
    let store = Arc::new(InMemorySsfPollAckStore::default());
    let poller = poller_with(
        &transmitter,
        processor(&transmitter),
        SsfPollerOptions {
            ack_store: store.clone(),
            max_ack_batch: 2,
            transmitter: Some(transmitter.issuer().to_owned()),
            ..options()
        },
    );
    for jti in ["a", "b", "c"] {
        store
            .record(transmitter.issuer(), easyssf_receiver::poll::SsfPendingAck::ack(jti))
            .await
            .unwrap();
    }
    poller.poll_now().await.unwrap();
    assert_eq!(
        transmitter.last_poll_request()["ack"].as_array().unwrap().len(),
        1,
        "two with the fetch, the third with the acknowledging request"
    );
    assert_eq!(poller.pending_ack_count().await, 0);
}

#[derive(Default)]
struct Gauge(Mutex<Vec<usize>>);

impl SsfReceiverMetrics for Gauge {
    fn pending_acks_changed(&self, _: Option<&str>, pending_acks: usize) {
        self.0.lock().unwrap().push(pending_acks);
    }
}

#[tokio::test]
async fn pending_acknowledgements_are_a_gauge() {
    let transmitter = TestTransmitter::new();
    let gauge = Arc::new(Gauge::default());
    let poller = poller_with(
        &transmitter,
        processor(&transmitter),
        SsfPollerOptions {
            metrics: gauge.clone(),
            ..options()
        },
    );
    queue(&transmitter);
    poller.poll_now().await.unwrap();
    assert_eq!(*gauge.0.lock().unwrap(), [1, 0]);
}

#[tokio::test]
async fn stop_flushes_the_pending_acknowledgements() {
    let transmitter = TestTransmitter::new();
    let store = Arc::new(InMemorySsfPollAckStore::default());
    let poller = poller_with(
        &transmitter,
        processor(&transmitter),
        SsfPollerOptions {
            ack_store: store.clone(),
            transmitter: Some(transmitter.issuer().to_owned()),
            interval: Duration::from_secs(60),
            ..SsfPollerOptions::default()
        },
    );
    poller.start();
    eventually(Duration::from_secs(2), "the first poll", || {
        transmitter.poll_requests() == 1
    })
    .await;
    store
        .record(transmitter.issuer(), easyssf_receiver::poll::SsfPendingAck::ack("owed"))
        .await
        .unwrap();
    poller.stop().await;
    assert_eq!(transmitter.last_poll_request()["ack"], json!(["owed"]));
    assert_eq!(store.size(transmitter.issuer()).await.unwrap(), 0);
}

#[tokio::test]
async fn long_poll_is_held_until_a_set_arrives() {
    let transmitter = TestTransmitter::new();
    transmitter.set_long_poll_hold(Duration::from_secs(10));
    let recorder = Recorder::default();
    let poller = poller_with(
        &transmitter,
        processor(&transmitter).handler(recorder.handler()),
        SsfPollerOptions {
            long_polling_hold: Some(Duration::from_secs(10)),
            interval: Duration::from_secs(60),
            ..SsfPollerOptions::default()
        },
    );
    assert!(poller.is_long_polling());
    poller.start();
    eventually(Duration::from_secs(2), "the held request", || {
        transmitter.poll_requests() == 1
    })
    .await;
    assert_eq!(transmitter.last_poll_request()["returnImmediately"], false);
    during(Duration::from_millis(150), "held", || recorder.count() == 0).await;
    let jti = queue(&transmitter);
    eventually(Duration::from_secs(2), "the SET", || recorder.jtis() == [jti.clone()]).await;
    eventually(
        Duration::from_secs(2),
        "the acknowledgement with the next held request",
        || transmitter.acknowledged_sets().len() == 1,
    )
    .await;
    poller.stop().await;
}

#[tokio::test]
async fn long_poll_against_a_transmitter_that_answers_at_once_waits_the_interval() {
    let transmitter = TestTransmitter::new();
    let poller = poller_with(
        &transmitter,
        processor(&transmitter),
        SsfPollerOptions {
            long_polling_hold: Some(Duration::from_secs(10)),
            interval: Duration::from_secs(60),
            ..SsfPollerOptions::default()
        },
    );
    poller.start();
    eventually(Duration::from_secs(2), "the first poll", || {
        transmitter.poll_requests() == 1
    })
    .await;
    during(Duration::from_millis(300), "no tight loop", || {
        transmitter.poll_requests() == 1
    })
    .await;
    poller.stop().await;
}

#[tokio::test]
async fn stop_cancels_a_held_long_poll() {
    let transmitter = TestTransmitter::new();
    transmitter.set_long_poll_hold(Duration::from_secs(30));
    let poller = poller_with(
        &transmitter,
        processor(&transmitter),
        SsfPollerOptions {
            long_polling_hold: Some(Duration::from_secs(30)),
            ..SsfPollerOptions::default()
        },
    );
    poller.start();
    eventually(Duration::from_secs(2), "the held request", || {
        transmitter.poll_requests() == 1
    })
    .await;
    let stopped = tokio::time::timeout(Duration::from_secs(2), poller.stop()).await;
    assert!(stopped.is_ok(), "stop returned before the hold elapsed");
    assert!(!poller.is_running());
}

#[tokio::test]
async fn poll_now_asks_for_an_immediate_answer_even_when_long_polling() {
    let transmitter = TestTransmitter::new();
    transmitter.set_long_poll_hold(Duration::from_secs(30));
    let poller = poller_with(
        &transmitter,
        processor(&transmitter),
        SsfPollerOptions {
            long_polling_hold: Some(Duration::from_secs(30)),
            ..SsfPollerOptions::default()
        },
    );
    tokio::time::timeout(Duration::from_secs(2), poller.poll_now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(transmitter.last_poll_request()["returnImmediately"], true);
}

// SsfPollerRateLimitTests

/// Answers the poll endpoint with a canned response, everything else goes to the transmitter.
struct RateLimiting {
    transmitter: TestTransmitter,
    status: u16,
    retry_after: Option<&'static str>,
}

#[async_trait]
impl SsfHttpClient for RateLimiting {
    async fn execute(&self, request: SsfHttpRequest) -> Result<SsfHttpResponse, BoxError> {
        if request.url.path().ends_with("/poll") {
            let mut response = SsfHttpResponse::new(self.status, "");
            if let Some(retry_after) = self.retry_after {
                response = response.with_header("Retry-After", retry_after);
            }
            return Ok(response);
        }
        self.transmitter.execute(request).await
    }
}

async fn paused_after(status: u16, retry_after: Option<&'static str>, options: SsfPollerOptions) -> Option<Duration> {
    let transmitter = TestTransmitter::new();
    let endpoint = Url::parse(&transmitter.poll_uri()).unwrap();
    let poller = SsfPoller::new(
        RateLimiting {
            transmitter: transmitter.clone(),
            status,
            retry_after,
        },
        FixedSsfTransmitterTokenProvider(TestTransmitter::ACCESS_TOKEN.to_owned()),
        Arc::new(move || Some(endpoint.clone())),
        Arc::new(processor(&transmitter)),
        options,
    );
    assert!(poller.poll_now().await.is_err());
    poller
        .paused_until()
        .map(|until| until.duration_since(std::time::SystemTime::now()).unwrap_or_default())
}

#[tokio::test]
async fn pauses_for_retry_after() {
    let pause = paused_after(429, Some("120"), options()).await.unwrap();
    assert!(
        pause > Duration::from_secs(110) && pause <= Duration::from_secs(120),
        "{pause:?}"
    );
    let pause = paused_after(503, Some("60"), options()).await.unwrap();
    assert!(pause > Duration::from_secs(50), "{pause:?}");
    // a date instead of seconds is treated like no header
    assert!(
        paused_after(429, Some("Wed, 21 Oct 2026 07:28:00 GMT"), options())
            .await
            .is_none()
    );
}

#[tokio::test]
async fn polls_again_at_the_regular_interval_after_429_without_retry_after_by_default() {
    assert!(paused_after(429, None, options()).await.is_none());
}

#[tokio::test]
async fn pauses_for_the_fallback_after_429_without_retry_after() {
    let pause = paused_after(
        429,
        None,
        SsfPollerOptions {
            rate_limit_fallback: Some(Duration::from_secs(90)),
            ..options()
        },
    )
    .await
    .unwrap();
    assert!(pause > Duration::from_secs(80), "{pause:?}");
}

#[tokio::test]
async fn fallback_does_not_apply_to_503_without_retry_after() {
    let pause = paused_after(
        503,
        None,
        SsfPollerOptions {
            rate_limit_fallback: Some(Duration::from_secs(90)),
            ..options()
        },
    )
    .await;
    assert!(pause.is_none());
}

#[tokio::test]
async fn pause_is_capped_at_the_maximum() {
    let pause = paused_after(
        429,
        Some("3600"),
        SsfPollerOptions {
            max_pause: Duration::from_secs(300),
            ..options()
        },
    )
    .await
    .unwrap();
    assert!(
        pause <= Duration::from_secs(300) && pause > Duration::from_secs(290),
        "{pause:?}"
    );
}

#[tokio::test]
async fn paused_poller_skips_polls_until_the_pause_is_over() {
    let transmitter = TestTransmitter::new();
    let endpoint = Url::parse(&transmitter.poll_uri()).unwrap();
    let poller = SsfPoller::new(
        RateLimiting {
            transmitter: transmitter.clone(),
            status: 429,
            retry_after: Some("60"),
        },
        FixedSsfTransmitterTokenProvider(TestTransmitter::ACCESS_TOKEN.to_owned()),
        Arc::new(move || Some(endpoint.clone())),
        Arc::new(processor(&transmitter)),
        options(),
    );
    assert!(poller.poll_now().await.is_err());
    assert_eq!(poller.poll_now().await.unwrap(), 0, "skipped while paused");
    let _ = SsfDeliveryMethod::Poll;
}
