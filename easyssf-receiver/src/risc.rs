//! The typed handler for RISC 1.0 events.

use std::future::Future;

use easyssf_core::risc::{SsfRiscEvent, SsfRiscEventKind};

use crate::BoxError;
use crate::event::{SsfEventContext, SsfEventHandler};

/// A handler for RISC 1.0 events that dispatches every RISC event of a SET to the method of its
/// kind, and [`on_other_risc_event`](Self::on_other_risc_event) for an event type in the RISC
/// namespace this version does not know. The methods do nothing by default, implement the ones
/// the receiver acts on. SETs without RISC events are ignored. Turn it into an
/// [`SsfEventHandler`] with [`risc`].
///
/// Each event comes with the [`SsfEventContext`] of the SET, whose
/// [subject](SsfEventContext::subject) is the account the event is about. Like every handler, an
/// implementation has to be idempotent.
#[allow(unused_variables)]
pub trait SsfRiscEventHandler: Send + Sync + 'static {
    /// Called for every RISC event of a SET, dispatches to the method of its kind. Implement it
    /// to treat all RISC events alike.
    fn on_risc_event(
        &self,
        event: SsfRiscEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async move {
            match event.kind() {
                SsfRiscEventKind::AccountCredentialChangeRequired => {
                    self.on_account_credential_change_required(event, context).await
                }
                SsfRiscEventKind::AccountPurged => self.on_account_purged(event, context).await,
                SsfRiscEventKind::AccountDisabled => self.on_account_disabled(event, context).await,
                SsfRiscEventKind::AccountEnabled => self.on_account_enabled(event, context).await,
                SsfRiscEventKind::IdentifierChanged => self.on_identifier_changed(event, context).await,
                SsfRiscEventKind::IdentifierRecycled => self.on_identifier_recycled(event, context).await,
                SsfRiscEventKind::CredentialCompromise => self.on_credential_compromise(event, context).await,
                SsfRiscEventKind::OptIn => self.on_opt_in(event, context).await,
                SsfRiscEventKind::OptOutInitiated => self.on_opt_out_initiated(event, context).await,
                SsfRiscEventKind::OptOutCancelled => self.on_opt_out_cancelled(event, context).await,
                SsfRiscEventKind::OptOutEffective => self.on_opt_out_effective(event, context).await,
                SsfRiscEventKind::RecoveryActivated => self.on_recovery_activated(event, context).await,
                SsfRiscEventKind::RecoveryInformationChanged => {
                    self.on_recovery_information_changed(event, context).await
                }
                SsfRiscEventKind::SessionsRevoked => self.on_sessions_revoked(event, context).await,
                _ => self.on_other_risc_event(event, context).await,
            }
        }
    }

    /// The account has to change its credential (`RiscAccountCredentialChangeRequired`).
    fn on_account_credential_change_required(
        &self,
        event: SsfRiscEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The account was permanently deleted (`RiscAccountPurged`).
    fn on_account_purged(
        &self,
        event: SsfRiscEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The account was disabled (`RiscAccountDisabled`), see [`SsfRiscEvent::reason`].
    fn on_account_disabled(
        &self,
        event: SsfRiscEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The account was enabled again (`RiscAccountEnabled`).
    fn on_account_enabled(
        &self,
        event: SsfRiscEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The identifier of the account changed (`RiscIdentifierChanged`), see
    /// [`SsfRiscEvent::new_value`].
    fn on_identifier_changed(
        &self,
        event: SsfRiscEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The identifier was given to someone else (`RiscIdentifierRecycled`).
    fn on_identifier_recycled(
        &self,
        event: SsfRiscEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// A credential was found compromised (`RiscCredentialCompromise`), see
    /// [`SsfRiscEvent::credential_type`].
    fn on_credential_compromise(
        &self,
        event: SsfRiscEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The account takes part in the RISC exchange (`RiscOptIn`).
    fn on_opt_in(
        &self,
        event: SsfRiscEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The user asked to leave the RISC exchange (`RiscOptOutInitiated`).
    fn on_opt_out_initiated(
        &self,
        event: SsfRiscEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The user withdrew the request to leave (`RiscOptOutCancelled`).
    fn on_opt_out_cancelled(
        &self,
        event: SsfRiscEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The account left the RISC exchange (`RiscOptOutEffective`).
    fn on_opt_out_effective(
        &self,
        event: SsfRiscEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The account went through a recovery flow (`RiscRecoveryActivated`).
    fn on_recovery_activated(
        &self,
        event: SsfRiscEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// The recovery information changed (`RiscRecoveryInformationChanged`).
    fn on_recovery_information_changed(
        &self,
        event: SsfRiscEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// All sessions of the account were revoked (`RiscSessionsRevoked`, deprecated by RISC in
    /// favour of `CaepSessionRevoked`).
    fn on_sessions_revoked(
        &self,
        event: SsfRiscEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }

    /// An event in the RISC namespace this version of easyssf does not know
    /// ([`SsfRiscEventKind::Other`]); its attributes are in [`SsfRiscEvent::payload`].
    fn on_other_risc_event(
        &self,
        event: SsfRiscEvent,
        context: SsfEventContext,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        async { Ok(()) }
    }
}

/// Turns an [`SsfRiscEventHandler`] into an [`SsfEventHandler`] that gets every SET.
pub fn risc<H: SsfRiscEventHandler>(handler: H) -> impl SsfEventHandler {
    RiscAdapter(handler)
}

struct RiscAdapter<H>(H);

impl<H: SsfRiscEventHandler> SsfEventHandler for RiscAdapter<H> {
    async fn handle(&self, context: SsfEventContext) -> Result<(), BoxError> {
        for event in SsfRiscEvent::in_token(context.event_token()) {
            self.0.on_risc_event(event, context.clone()).await?;
        }
        Ok(())
    }
}
