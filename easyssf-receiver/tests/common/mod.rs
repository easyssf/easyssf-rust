//! Shared helpers of the receiver tests.
#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use easyssf_receiver::Clock;
use easyssf_receiver::event::SsfEventContext;
use easyssf_receiver::set::{
    HttpSsfJwkSetSource, InMemorySsfJtiDedupStore, JwtSsfSetVerifier, SsfSetProcessor, SsfSetVerifierOptions,
};
use easyssf_receiver::transmitter::{SsfTransmitterMetadataResolver, SsfTransmitterUriPolicy};
use easyssf_test::TestTransmitter;
use url::Url;

/// A clock the tests move by hand.
#[derive(Clone)]
pub struct TestClock(Arc<Mutex<SystemTime>>);

impl Default for TestClock {
    fn default() -> Self {
        Self::new()
    }
}

impl TestClock {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(SystemTime::now())))
    }

    pub fn clock(&self) -> Clock {
        let time = self.0.clone();
        Arc::new(move || *time.lock().unwrap())
    }

    pub fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }

    pub fn advance(&self, duration: Duration) {
        let mut time = self.0.lock().unwrap();
        *time += duration;
    }
}

pub fn options() -> SsfSetVerifierOptions {
    SsfSetVerifierOptions {
        expected_audiences: vec![TestTransmitter::AUDIENCE.to_owned()],
        ..SsfSetVerifierOptions::default()
    }
}

pub fn metadata_resolver(transmitter: &TestTransmitter) -> Arc<SsfTransmitterMetadataResolver> {
    Arc::new(
        SsfTransmitterMetadataResolver::new(
            transmitter.issuer(),
            None,
            transmitter.clone(),
            SsfTransmitterUriPolicy::DEFAULT,
        )
        .unwrap(),
    )
}

/// A verifier over the JWK Set of the transmitter, fetched from its known location.
pub fn verifier(transmitter: &TestTransmitter) -> JwtSsfSetVerifier {
    verifier_with(transmitter, options())
}

pub fn verifier_with(transmitter: &TestTransmitter, options: SsfSetVerifierOptions) -> JwtSsfSetVerifier {
    let keys = HttpSsfJwkSetSource::new(transmitter.clone(), Url::parse(&transmitter.jwks_uri()).unwrap());
    JwtSsfSetVerifier::new(transmitter.issuer(), keys, options)
}

pub fn processor(transmitter: &TestTransmitter) -> SsfSetProcessor {
    SsfSetProcessor::new(verifier(transmitter), InMemorySsfJtiDedupStore::new(100))
}

/// Records the contexts a handler saw.
#[derive(Clone, Default)]
pub struct Recorder(pub Arc<Mutex<Vec<SsfEventContext>>>);

impl Recorder {
    pub fn handler(&self) -> impl easyssf_receiver::event::SsfEventHandler {
        let seen = self.0.clone();
        move |context: SsfEventContext| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(context);
                Ok(())
            }
        }
    }

    pub fn count(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    pub fn jtis(&self) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .map(|c| c.event_token().jti().to_owned())
            .collect()
    }
}
