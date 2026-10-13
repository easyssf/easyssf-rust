//! The typed handler for SCIM Events (RFC 9967).

use std::future::Future;

use easyssf_core::scim::{SsfScimEvent, SsfScimOperation};

use crate::BoxError;
use crate::event::{SsfEventContext, SsfEventHandler};

/// A handler for SCIM Events (RFC 9967) that dispatches every SCIM Event of a SET to the method
/// of its operation: [`on_create`](Self::on_create), [`on_patch`](Self::on_patch),
/// [`on_put`](Self::on_put), [`on_delete`](Self::on_delete), [`on_activate`](Self::on_activate),
/// [`on_deactivate`](Self::on_deactivate), [`on_feed_add`](Self::on_feed_add),
/// [`on_feed_remove`](Self::on_feed_remove) and [`on_async_response`](Self::on_async_response).
/// The methods do nothing by default, implement the ones the receiver acts on. SETs without SCIM
/// Events are ignored. Turn it into an [`SsfEventHandler`] with [`scim`].
///
/// Each event comes with its [subject](SsfScimEvent::subject), the SCIM resource it is about,
/// and the [`SsfEventContext`] of the SET for its `jti`, `iss` and `txn`. Like every handler, an
/// implementation has to be idempotent: a SET is delivered again if any handler failed. The
/// `txn` claim identifies the underlying transaction across such retransmissions.
#[allow(unused_variables)]
pub trait SsfScimEventHandler: Send + Sync + 'static {
    /// Called for every SCIM Event of a SET, dispatches to the method of its operation. Implement
    /// it to treat all SCIM Events alike, or to refuse events without a SCIM subject.
    fn on_scim_event(
        &self,
        event: SsfScimEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async move {
            match event.operation() {
                SsfScimOperation::FeedAdd => self.on_feed_add(event, context).await,
                SsfScimOperation::FeedRemove => self.on_feed_remove(event, context).await,
                SsfScimOperation::Create => self.on_create(event, context).await,
                SsfScimOperation::Patch => self.on_patch(event, context).await,
                SsfScimOperation::Put => self.on_put(event, context).await,
                SsfScimOperation::Delete => self.on_delete(event, context).await,
                SsfScimOperation::Activate => self.on_activate(event, context).await,
                SsfScimOperation::Deactivate => self.on_deactivate(event, context).await,
                SsfScimOperation::AsyncResponse => self.on_async_response(event, context).await,
                _ => Ok(()),
            }
        }
    }

    /// The resource joined the event feed (`feed:add`).
    fn on_feed_add(
        &self,
        event: SsfScimEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The resource left the event feed (`feed:remove`).
    fn on_feed_remove(
        &self,
        event: SsfScimEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The resource was created (`prov:create:notice` or `prov:create:full`).
    fn on_create(
        &self,
        event: SsfScimEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The resource was modified with SCIM PATCH (`prov:patch:notice` or `prov:patch:full`).
    fn on_patch(
        &self,
        event: SsfScimEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The resource was replaced with SCIM PUT (`prov:put:notice` or `prov:put:full`).
    fn on_put(
        &self,
        event: SsfScimEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The resource was deleted (`prov:delete`).
    fn on_delete(
        &self,
        event: SsfScimEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The resource was activated (`prov:activate`).
    fn on_activate(
        &self,
        event: SsfScimEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The resource was deactivated (`prov:deactivate`).
    fn on_deactivate(
        &self,
        event: SsfScimEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// An asynchronous SCIM request completed (`misc:asyncresp`).
    fn on_async_response(
        &self,
        event: SsfScimEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }
}

/// Turns an [`SsfScimEventHandler`] into an [`SsfEventHandler`] that gets every SET.
pub fn scim<H: SsfScimEventHandler>(handler: H) -> impl SsfEventHandler {
    ScimAdapter(handler)
}

struct ScimAdapter<H>(H);

impl<H: SsfScimEventHandler> SsfEventHandler for ScimAdapter<H> {
    async fn handle(&self, context: SsfEventContext) -> Result<(), BoxError> {
        for event in SsfScimEvent::in_token(context.event_token()) {
            self.0.on_scim_event(event, context.clone()).await?;
        }
        Ok(())
    }
}
