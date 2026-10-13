//! An application specific handler.

use easyssf_core::event_types;
use easyssf_receiver::BoxError;
use easyssf_receiver::event::{SsfEventContext, SsfEventHandler};
use serde_json::Value;

/// Logs every event of every verified SET. It is invoked in addition to the handler of the
/// receiver that revokes the access tokens.
pub struct AuditingSsfEventHandler;

impl SsfEventHandler for AuditingSsfEventHandler {
    async fn handle(&self, context: SsfEventContext) -> Result<(), BoxError> {
        for event_type in context.event_types() {
            let subject = context.subject_for(&event_type);
            let payload = Value::Object(context.event_for(&event_type).cloned().unwrap_or_default());
            tracing::info!(
                event = event_types::alias_of(&event_type),
                user = subject.subject().unwrap_or(""),
                session = subject.session_id().unwrap_or(""),
                %payload,
                "Security event"
            );
        }
        Ok(())
    }
}
