//! Purges the expired rows of the stores periodically.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::ops::SsfSqlError;

/// A store whose rows expire and are purged, by the store itself when it is written to and
/// periodically by [`SqlSsfStoreCleanup`].
#[async_trait]
pub trait SsfExpiringStore: Send + Sync + 'static {
    /// Deletes the rows that expired and returns how many.
    async fn purge_expired(&self) -> Result<u64, SsfSqlError>;

    /// The name of the store, for the log.
    fn name(&self) -> &'static str;
}

struct Task {
    cancel: CancellationToken,
    handle: tokio::task::JoinHandle<()>,
}

/// Purges the expired rows of the [stores](SsfExpiringStore) periodically, so that they do not
/// linger in a receiver that gets no events for a while. Either call
/// [`purge_expired`](Self::purge_expired) from the scheduler of the application, or
/// [`start`](Self::start) to run it on a task of its own.
pub struct SqlSsfStoreCleanup {
    stores: Vec<Arc<dyn SsfExpiringStore>>,
    interval: Duration,
    task: Mutex<Option<Task>>,
}

impl SqlSsfStoreCleanup {
    /// A cleanup of the stores every `interval`; the periodic cleanup is off when the interval
    /// is zero.
    pub fn new(stores: Vec<Arc<dyn SsfExpiringStore>>, interval: Duration) -> Arc<Self> {
        Arc::new(Self {
            stores,
            interval,
            task: Mutex::new(None),
        })
    }

    /// How often the stores are purged.
    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Whether the periodic cleanup runs when started: the interval is positive and there is a
    /// store to purge.
    pub fn is_enabled(&self) -> bool {
        !self.interval.is_zero() && !self.stores.is_empty()
    }

    /// Whether the periodic cleanup is running.
    pub fn is_running(&self) -> bool {
        self.task.lock().unwrap().is_some()
    }

    /// Purges the expired rows of all stores once; a store that fails is logged and skipped.
    /// Returns the number of rows deleted.
    pub async fn purge_expired(&self) -> u64 {
        let mut deleted = 0;
        for store in &self.stores {
            match store.purge_expired().await {
                Ok(count) => deleted += count,
                Err(error) => tracing::warn!(store = store.name(), %error, "Could not purge the expired rows"),
            }
        }
        if deleted > 0 {
            tracing::debug!(deleted, "Purged expired rows");
        }
        deleted
    }

    /// Starts purging periodically in the background, if [enabled](Self::is_enabled). Needs a
    /// tokio runtime.
    pub fn start(self: &Arc<Self>) {
        let mut task = self.task.lock().unwrap();
        if task.is_some() || !self.is_enabled() {
            return;
        }
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let cleanup = self.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(cleanup.interval) => { cleanup.purge_expired().await; }
                    _ = token.cancelled() => return,
                }
            }
        });
        *task = Some(Task { cancel, handle });
    }

    /// Stops the periodic cleanup.
    pub async fn stop(&self) {
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            task.cancel.cancel();
            let _ = task.handle.await;
        }
    }
}
