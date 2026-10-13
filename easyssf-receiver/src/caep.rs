//! The typed handler for CAEP 1.0 events.

use std::future::Future;

use easyssf_core::caep::{SsfCaepEvent, SsfCaepEventKind};

use crate::BoxError;
use crate::event::{SsfEventContext, SsfEventHandler};

/// A handler for CAEP 1.0 events that dispatches every CAEP event of a SET to the method of its
/// kind: [`on_session_revoked`](Self::on_session_revoked),
/// [`on_token_claims_change`](Self::on_token_claims_change),
/// [`on_credential_change`](Self::on_credential_change),
/// [`on_assurance_level_change`](Self::on_assurance_level_change),
/// [`on_device_compliance_change`](Self::on_device_compliance_change),
/// [`on_session_established`](Self::on_session_established),
/// [`on_session_presented`](Self::on_session_presented),
/// [`on_risk_level_change`](Self::on_risk_level_change), and
/// [`on_other_caep_event`](Self::on_other_caep_event) for an event type in the CAEP namespace
/// this version does not know. The methods do nothing by default, implement the ones the
/// receiver acts on. SETs without CAEP events are ignored. Turn it into an [`SsfEventHandler`]
/// with [`caep`].
///
/// Each event comes with typed access to its payload and with the [`SsfEventContext`] of the
/// SET, whose [subject](SsfEventContext::subject) the event is about. The built-in reactions to
/// `session-revoked` and `credential-change`, ending sessions and rejecting tokens, are
/// `SsfSessionTerminationEventHandler` and `SsfTokenRevocationEventHandler`; this handler is for
/// what the application does on top. Like every handler, an implementation has to be idempotent.
///
/// ```
/// # use easyssf_core::caep::SsfCaepEvent;
/// # use easyssf_receiver::{BoxError, caep::{SsfCaepEventHandler, caep}, event::SsfEventContext};
/// struct StepUpHandler;
///
/// impl SsfCaepEventHandler for StepUpHandler {
///     async fn on_assurance_level_change(&self, event: SsfCaepEvent, context: SsfEventContext) -> Result<(), BoxError> {
///         if event.change_direction().as_deref() == Some("decrease") {
///             // step_up.require(context.subject().subject(), event.current_level())
///         }
///         Ok(())
///     }
/// }
/// let handler = caep(StepUpHandler);
/// ```
#[allow(unused_variables)]
pub trait SsfCaepEventHandler: Send + Sync + 'static {
    /// Called for every CAEP event of a SET, dispatches to the method of its kind. Implement it
    /// to treat all CAEP events alike.
    fn on_caep_event(
        &self,
        event: SsfCaepEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async move {
            match event.kind() {
                SsfCaepEventKind::SessionRevoked => self.on_session_revoked(event, context).await,
                SsfCaepEventKind::TokenClaimsChange => self.on_token_claims_change(event, context).await,
                SsfCaepEventKind::CredentialChange => self.on_credential_change(event, context).await,
                SsfCaepEventKind::AssuranceLevelChange => self.on_assurance_level_change(event, context).await,
                SsfCaepEventKind::DeviceComplianceChange => self.on_device_compliance_change(event, context).await,
                SsfCaepEventKind::SessionEstablished => self.on_session_established(event, context).await,
                SsfCaepEventKind::SessionPresented => self.on_session_presented(event, context).await,
                SsfCaepEventKind::RiskLevelChange => self.on_risk_level_change(event, context).await,
                _ => self.on_other_caep_event(event, context).await,
            }
        }
    }

    /// The session was revoked (`CaepSessionRevoked`).
    fn on_session_revoked(
        &self,
        event: SsfCaepEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// Claims of the token changed (`CaepTokenClaimsChange`), see [`SsfCaepEvent::claims`].
    fn on_token_claims_change(
        &self,
        event: SsfCaepEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// A credential was created, revoked, updated or deleted (`CaepCredentialChange`), see
    /// [`SsfCaepEvent::credential_type`] and [`SsfCaepEvent::change_type`].
    fn on_credential_change(
        &self,
        event: SsfCaepEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The assurance level changed (`CaepAssuranceLevelChange`), see
    /// [`SsfCaepEvent::current_level`] and [`SsfCaepEvent::change_direction`].
    fn on_assurance_level_change(
        &self,
        event: SsfCaepEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The compliance status of the device changed (`CaepDeviceComplianceChange`), see
    /// [`SsfCaepEvent::current_status`].
    fn on_device_compliance_change(
        &self,
        event: SsfCaepEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// A session was established (`CaepSessionEstablished`).
    fn on_session_established(
        &self,
        event: SsfCaepEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// A session was presented (`CaepSessionPresented`).
    fn on_session_presented(
        &self,
        event: SsfCaepEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The risk level changed (`CaepRiskLevelChange`), see [`SsfCaepEvent::current_level`] and
    /// [`SsfCaepEvent::principal`].
    fn on_risk_level_change(
        &self,
        event: SsfCaepEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// An event in the CAEP namespace this version of easyssf does not know
    /// ([`SsfCaepEventKind::Other`]): the common claims of CAEP section 2 are typed, the rest is
    /// in [`SsfCaepEvent::payload`].
    fn on_other_caep_event(
        &self,
        event: SsfCaepEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }
}

/// Turns an [`SsfCaepEventHandler`] into an [`SsfEventHandler`] that gets every SET.
pub fn caep<H: SsfCaepEventHandler>(handler: H) -> impl SsfEventHandler {
    CaepAdapter(handler)
}

struct CaepAdapter<H>(H);

impl<H: SsfCaepEventHandler> SsfEventHandler for CaepAdapter<H> {
    async fn handle(&self, context: SsfEventContext) -> Result<(), BoxError> {
        for event in SsfCaepEvent::in_token(context.event_token()) {
            self.0.on_caep_event(event, context.clone()).await?;
        }
        Ok(())
    }
}
