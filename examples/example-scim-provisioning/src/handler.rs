//! The handler that mirrors the SCIM Events.

use std::sync::Arc;

use easyssf_core::event_types;
use easyssf_core::scim::{SsfScimEvent, SsfScimOperation, SsfScimSubject};
use easyssf_receiver::BoxError;
use easyssf_receiver::event::SsfEventContext;
use easyssf_receiver::scim::SsfScimEventHandler;
use serde_json::{Map, Value};

use crate::directory::UserDirectory;
use crate::user::User;

/// Mirrors the SCIM Events about `Users` into the [`UserDirectory`]. The receiver calls it for
/// every verified SET; [`SsfScimEventHandler`] dispatches the SCIM Events of the SET to the
/// method of their operation.
///
/// `full` events carry the resource (or the patch) as `data` and are applied directly. `notice`
/// events only name the attributes that changed: the application would fetch the resource from the
/// SCIM service provider with a GET of the subject's `uri`, which this example does not have, so
/// it logs them. Like every handler it is idempotent: applying an event twice leaves the directory
/// in the same state.
pub struct ScimProvisioningHandler {
    directory: Arc<UserDirectory>,
}

impl ScimProvisioningHandler {
    /// A handler that mirrors into `directory`.
    pub fn new(directory: Arc<UserDirectory>) -> Self {
        Self { directory }
    }

    fn set_active(&self, event: &SsfScimEvent, subject: &SsfScimSubject, active: bool) {
        let id = subject.id().unwrap_or_default();
        match self
            .directory
            .update(&id, |user| user.with_active(active).with_version(event.version()))
        {
            Some(user) => tracing::info!(
                "{}: {} {user}",
                alias(event),
                if active { "activated" } else { "deactivated" }
            ),
            None => tracing::warn!(
                "{}: {} is not in the directory",
                alias(event),
                subject.uri().unwrap_or_default()
            ),
        }
    }
}

impl SsfScimEventHandler for ScimProvisioningHandler {
    async fn on_scim_event(&self, event: SsfScimEvent, context: SsfEventContext) -> Result<(), BoxError> {
        let Some(subject) = event.subject().filter(|subject| subject.id().is_some()) else {
            tracing::warn!(
                "{} of SET {} has no SCIM subject, ignored",
                alias(&event),
                context.event_token().jti()
            );
            return Ok(());
        };
        if subject.resource_type().as_deref() != Some("Users") {
            tracing::info!(
                "{} for {}: only Users are mirrored",
                alias(&event),
                subject.uri().unwrap_or_default()
            );
            return Ok(());
        }
        match event.operation() {
            SsfScimOperation::FeedAdd => self.on_feed_add(event, context).await,
            SsfScimOperation::FeedRemove => self.on_feed_remove(event, context).await,
            SsfScimOperation::Create => self.on_create(event, context).await,
            SsfScimOperation::Patch => self.on_patch(event, context).await,
            SsfScimOperation::Put => self.on_put(event, context).await,
            SsfScimOperation::Delete => self.on_delete(event, context).await,
            SsfScimOperation::Activate => self.on_activate(event, context).await,
            SsfScimOperation::Deactivate => self.on_deactivate(event, context).await,
            _ => Ok(()),
        }
    }

    async fn on_feed_add(&self, event: SsfScimEvent, _context: SsfEventContext) -> Result<(), BoxError> {
        tracing::info!("{}: {} joined the feed", alias(&event), uri(&event));
        Ok(())
    }

    async fn on_feed_remove(&self, event: SsfScimEvent, _context: SsfEventContext) -> Result<(), BoxError> {
        tracing::info!(
            "{}: {} left the feed, the user stays in the directory",
            alias(&event),
            uri(&event)
        );
        Ok(())
    }

    async fn on_create(&self, event: SsfScimEvent, _context: SsfEventContext) -> Result<(), BoxError> {
        match (event.is_full(), event.data()) {
            (true, Some(data)) => {
                let user = user_of(&event, data);
                tracing::info!("{}: created {user}", alias(&event));
                self.directory.save(user);
            }
            _ => log_notice(&event, "created"),
        }
        Ok(())
    }

    async fn on_put(&self, event: SsfScimEvent, _context: SsfEventContext) -> Result<(), BoxError> {
        match (event.is_full(), event.data()) {
            (true, Some(data)) => {
                let user = user_of(&event, data);
                tracing::info!("{}: replaced {user}", alias(&event));
                self.directory.save(user);
            }
            _ => log_notice(&event, "replaced"),
        }
        Ok(())
    }

    async fn on_patch(&self, event: SsfScimEvent, _context: SsfEventContext) -> Result<(), BoxError> {
        let (true, Some(data)) = (event.is_full(), event.data()) else {
            log_notice(&event, "modified");
            return Ok(());
        };
        let id = subject_id(&event);
        match self
            .directory
            .update(&id, |user| apply_patch(user, data).with_version(event.version()))
        {
            Some(patched) => tracing::info!("{}: patched {patched}", alias(&event)),
            None => tracing::warn!(
                "{}: {} is not in the directory, nothing to patch",
                alias(&event),
                uri(&event)
            ),
        }
        Ok(())
    }

    async fn on_delete(&self, event: SsfScimEvent, _context: SsfEventContext) -> Result<(), BoxError> {
        match self.directory.remove(&subject_id(&event)) {
            Some(removed) => tracing::info!("{}: deleted {removed}", alias(&event)),
            None => tracing::info!("{}: deleted {}", alias(&event), uri(&event)),
        }
        Ok(())
    }

    async fn on_activate(&self, event: SsfScimEvent, _context: SsfEventContext) -> Result<(), BoxError> {
        if let Some(subject) = event.subject() {
            self.set_active(&event, subject, true);
        }
        Ok(())
    }

    async fn on_deactivate(&self, event: SsfScimEvent, _context: SsfEventContext) -> Result<(), BoxError> {
        if let Some(subject) = event.subject() {
            self.set_active(&event, subject, false);
        }
        Ok(())
    }
}

/// Applies the `Operations` of a SCIM `PatchOp` (RFC 7644, section 3.5.2) to the user, as far as
/// this application mirrors the attributes: `replace` and `add` of a top-level attribute by
/// `path`, or of several attributes with a `value` object and no path; `remove` of `emails`.
fn apply_patch(mut user: User, patch: &Map<String, Value>) -> User {
    let Some(Value::Array(operations)) = patch.get("Operations") else {
        return user;
    };
    for operation in operations.iter().filter_map(Value::as_object) {
        let op = operation
            .get("op")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let path = operation.get("path").and_then(Value::as_str);
        let value = operation.get("value");
        match op.as_str() {
            "add" | "replace" => {
                if let Some(path) = path {
                    user = user.with(path, value);
                } else if let Some(Value::Object(attributes)) = value {
                    for (attribute, value) in attributes {
                        user = user.with(attribute, Some(value));
                    }
                }
            }
            "remove" => {
                if path == Some("emails") {
                    user = user.with("emails", None);
                } else {
                    tracing::debug!("remove of {} is not mirrored", path.unwrap_or_default());
                }
            }
            other => tracing::debug!("unknown PatchOp operation {other}"),
        }
    }
    user
}

fn user_of(event: &SsfScimEvent, data: &Map<String, Value>) -> User {
    let subject = event.subject();
    User::from_scim(
        &subject_id(event),
        subject.and_then(SsfScimSubject::external_id),
        data,
        event.version(),
    )
}

fn log_notice(event: &SsfScimEvent, what: &str) {
    tracing::info!(
        "{}: {} {what} changed {:?}; a notice event has no data, the application would GET the resource from the \
         SCIM service provider",
        alias(event),
        uri(event),
        event.attributes()
    );
}

fn subject_id(event: &SsfScimEvent) -> String {
    event.subject().and_then(SsfScimSubject::id).unwrap_or_default()
}

fn uri(event: &SsfScimEvent) -> String {
    event
        .subject()
        .and_then(SsfScimSubject::uri)
        .unwrap_or_default()
        .to_owned()
}

fn alias(event: &SsfScimEvent) -> String {
    event_types::alias_of(event.event_type())
}
