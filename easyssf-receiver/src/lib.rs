//! The SSF receiver without a web framework: verifies Security Event Tokens (RFC 8417) a
//! transmitter pushes (RFC 8935) or it polls (RFC 8936), de-duplicates them, manages its stream
//! at the transmitter and hands the events to handlers.
//!
//! A port of `easyssf-receiver` of the Java library, with the options, the transmitter factory
//! and the assembly of a receiver from its configuration of the .NET `EasySsf.Receiver.Hosting`
//! project in [`config`] and [`receiver`]. One module per Java package.
//!
//! Reacting to an event is a closure, see [`event::for_event`]; assembling a receiver by hand is
//! a few lines, see [`set::SsfSetProcessor`] and [`push::SsfPushHandler`]; assembling it from
//! configuration is [`receiver::SsfReceiver`].

use std::sync::Arc;
use std::time::SystemTime;

#[cfg(all(feature = "rust-crypto", feature = "aws-lc-rs"))]
compile_error!(
    "easyssf-receiver: enable exactly one crypto backend, `rust-crypto` (the default) or `aws-lc-rs`; jsonwebtoken \
     panics with both. For `aws-lc-rs`, turn the default features off on every easyssf crate (easyssf-test, \
     easyssf-receiver-sqlx, easyssf-receiver-axum, easyssf-receiver-actix-web forward the backend) and name it on \
     each. Never build this workspace with --all-features, use the `test-all` cargo alias."
);

#[cfg(not(any(feature = "rust-crypto", feature = "aws-lc-rs")))]
compile_error!("easyssf-receiver: enable a crypto backend, `rust-crypto` (the default) or `aws-lc-rs`");

pub mod caep;
pub mod config;
pub mod event;
pub mod http;
pub mod metrics;
pub mod poll;
pub mod push;
pub mod receiver;
pub mod revocation;
pub mod risc;
pub mod scim;
pub mod session;
pub mod set;
pub mod stream;
pub mod transmitter;

pub use receiver::SsfReceiver;

/// The error a handler or a store returns.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// A clock: the time now. Tests replace it.
pub type Clock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

/// The system clock.
pub fn system_clock() -> Clock {
    Arc::new(SystemTime::now)
}

pub(crate) fn unix_millis(time: SystemTime) -> i64 {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(since) => since.as_millis() as i64,
        Err(before) => -(before.duration().as_millis() as i64),
    }
}

pub(crate) fn unix_seconds(time: SystemTime) -> i64 {
    unix_millis(time).div_euclid(1000)
}

#[allow(dead_code)]
pub(crate) fn from_unix_millis(millis: i64) -> SystemTime {
    if millis >= 0 {
        SystemTime::UNIX_EPOCH + std::time::Duration::from_millis(millis as u64)
    } else {
        SystemTime::UNIX_EPOCH - std::time::Duration::from_millis(millis.unsigned_abs())
    }
}
