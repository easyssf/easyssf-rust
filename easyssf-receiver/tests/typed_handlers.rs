//! `SsfCaepEventHandlerTests`, `SsfRiscEventHandlerTests` and `SsfScimEventHandlerTests` of the
//! Java library.

mod common;

use std::sync::{Arc, Mutex};

use common::processor;
use easyssf_core::caep::{SsfCaepEvent, SsfCaepEventKind};
use easyssf_core::risc::{SsfRiscEvent, SsfRiscEventKind};
use easyssf_core::scim::{SsfScimEvent, SsfScimOperation};
use easyssf_core::{SsfDeliveryMethod, event_types};
use easyssf_receiver::BoxError;
use easyssf_receiver::caep::{SsfCaepEventHandler, caep};
use easyssf_receiver::event::SsfEventContext;
use easyssf_receiver::risc::{SsfRiscEventHandler, risc};
use easyssf_receiver::scim::{SsfScimEventHandler, scim};
use easyssf_test::TestTransmitter;
use easyssf_test::subjects::{iss_sub, scim as scim_subject};
use serde_json::{Map, Value, json};

#[derive(Default, Clone)]
struct Calls(Arc<Mutex<Vec<String>>>);

impl Calls {
    fn record(&self, what: impl Into<String>) {
        self.0.lock().unwrap().push(what.into());
    }

    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

struct CaepRecorder(Calls);

impl SsfCaepEventHandler for CaepRecorder {
    async fn on_session_revoked(&self, event: SsfCaepEvent, context: SsfEventContext) -> Result<(), BoxError> {
        self.0.record(format!(
            "session_revoked:{}:{}",
            context.subject().subject().unwrap_or(""),
            event.initiating_entity().unwrap_or_default()
        ));
        Ok(())
    }
    async fn on_token_claims_change(&self, _: SsfCaepEvent, _: SsfEventContext) -> Result<(), BoxError> {
        self.0.record("token_claims_change");
        Ok(())
    }
    async fn on_credential_change(&self, _: SsfCaepEvent, _: SsfEventContext) -> Result<(), BoxError> {
        self.0.record("credential_change");
        Ok(())
    }
    async fn on_assurance_level_change(&self, _: SsfCaepEvent, _: SsfEventContext) -> Result<(), BoxError> {
        self.0.record("assurance_level_change");
        Ok(())
    }
    async fn on_device_compliance_change(&self, _: SsfCaepEvent, _: SsfEventContext) -> Result<(), BoxError> {
        self.0.record("device_compliance_change");
        Ok(())
    }
    async fn on_session_established(&self, _: SsfCaepEvent, _: SsfEventContext) -> Result<(), BoxError> {
        self.0.record("session_established");
        Ok(())
    }
    async fn on_session_presented(&self, _: SsfCaepEvent, _: SsfEventContext) -> Result<(), BoxError> {
        self.0.record("session_presented");
        Ok(())
    }
    async fn on_risk_level_change(&self, _: SsfCaepEvent, _: SsfEventContext) -> Result<(), BoxError> {
        self.0.record("risk_level_change");
        Ok(())
    }
    async fn on_other_caep_event(&self, event: SsfCaepEvent, _: SsfEventContext) -> Result<(), BoxError> {
        self.0.record(format!("other:{}", event.event_type()));
        Ok(())
    }
}

fn context(events: Value) -> SsfEventContext {
    let claims = json!({ "jti": "1", "iss": "https://t.example", "iat": 1, "sub_id": iss_sub("https://idp.example", "alice"), "events": events });
    SsfEventContext::new(
        easyssf_core::SsfEventToken::from_claims(claims.as_object().unwrap().clone()).unwrap(),
        SsfDeliveryMethod::Push,
    )
}

#[tokio::test]
async fn dispatches_every_kind_to_its_method() {
    use easyssf_receiver::event::SsfEventHandler;
    let calls = Calls::default();
    let handler = caep(CaepRecorder(calls.clone()));
    for (kind, uri) in SsfCaepEventKind::KNOWN {
        handler
            .handle(context(json!({ uri: { "initiating_entity": "admin" } })))
            .await
            .unwrap();
        let expected = match kind {
            SsfCaepEventKind::SessionRevoked => "session_revoked:alice:admin".to_owned(),
            other => format!("{other:?}").chars().fold(String::new(), |mut s, c| {
                if c.is_uppercase() && !s.is_empty() {
                    s.push('_');
                }
                s.push(c.to_ascii_lowercase());
                s
            }),
        };
        assert_eq!(calls.take(), [expected], "{uri}");
    }
    handler
        .handle(context(
            json!({ "https://schemas.openid.net/secevent/caep/event-type/future": {} }),
        ))
        .await
        .unwrap();
    assert_eq!(
        calls.take(),
        ["other:https://schemas.openid.net/secevent/caep/event-type/future"]
    );
}

#[tokio::test]
async fn handles_all_caep_events_of_a_set_and_ignores_other_sets() {
    use easyssf_receiver::event::SsfEventHandler;
    let calls = Calls::default();
    let handler = caep(CaepRecorder(calls.clone()));
    handler
        .handle(context(json!({
            event_types::CAEP_CREDENTIAL_CHANGE: {},
            event_types::RISC_ACCOUNT_DISABLED: {},
            event_types::CAEP_RISK_LEVEL_CHANGE: {}
        })))
        .await
        .unwrap();
    assert_eq!(calls.take(), ["credential_change", "risk_level_change"]);
    handler
        .handle(context(json!({ event_types::RISC_ACCOUNT_DISABLED: {} })))
        .await
        .unwrap();
    assert!(calls.take().is_empty());
}

#[tokio::test]
async fn caep_set_passes_strict_verification_and_reaches_the_handler() {
    let transmitter = TestTransmitter::new();
    let calls = Calls::default();
    let processor = processor(&transmitter).handler(caep(CaepRecorder(calls.clone())));
    let set = transmitter.set("CaepSessionRevoked", Some(iss_sub(transmitter.issuer(), "alice")));
    processor.process(&set, SsfDeliveryMethod::Push).await.unwrap();
    assert_eq!(calls.take(), ["session_revoked:alice:"]);
}

struct RiscRecorder(Calls);

impl SsfRiscEventHandler for RiscRecorder {
    async fn on_risc_event(&self, event: SsfRiscEvent, context: SsfEventContext) -> Result<(), BoxError> {
        self.0.record(format!("{:?}", event.kind()));
        self.dispatch(event, context).await
    }
    async fn on_account_disabled(&self, event: SsfRiscEvent, _: SsfEventContext) -> Result<(), BoxError> {
        self.0
            .record(format!("disabled:{}", event.reason().unwrap_or_default()));
        Ok(())
    }
    async fn on_account_purged(&self, _: SsfRiscEvent, _: SsfEventContext) -> Result<(), BoxError> {
        self.0.record("purged");
        Ok(())
    }
}

impl RiscRecorder {
    async fn dispatch(&self, event: SsfRiscEvent, context: SsfEventContext) -> Result<(), BoxError> {
        match event.kind() {
            SsfRiscEventKind::AccountDisabled => self.on_account_disabled(event, context).await,
            SsfRiscEventKind::AccountPurged => self.on_account_purged(event, context).await,
            _ => Ok(()),
        }
    }
}

#[tokio::test]
async fn risc_dispatches_every_kind_to_its_method() {
    use easyssf_receiver::event::SsfEventHandler;
    let calls = Calls::default();
    let handler = risc(RiscRecorder(calls.clone()));
    handler
        .handle(context(
            json!({ event_types::RISC_ACCOUNT_DISABLED: { "reason": "hijacking" } }),
        ))
        .await
        .unwrap();
    assert_eq!(calls.take(), ["AccountDisabled", "disabled:hijacking"]);
    for (kind, uri) in SsfRiscEventKind::KNOWN {
        handler.handle(context(json!({ uri: {} }))).await.unwrap();
        assert_eq!(calls.take()[0], format!("{kind:?}"));
    }
}

#[tokio::test]
async fn handles_all_risc_events_of_a_set_and_ignores_other_sets() {
    use easyssf_receiver::event::SsfEventHandler;
    let calls = Calls::default();
    let handler = risc(RiscRecorder(calls.clone()));
    handler
        .handle(context(json!({ event_types::CAEP_SESSION_REVOKED: {}, event_types::RISC_ACCOUNT_PURGED: {}, event_types::RISC_OPT_IN: {} })))
        .await
        .unwrap();
    assert_eq!(calls.take(), ["AccountPurged", "purged", "OptIn"]);
}

#[tokio::test]
async fn risc_set_passes_strict_verification_and_reaches_the_handler() {
    let transmitter = TestTransmitter::new();
    let calls = Calls::default();
    let processor = processor(&transmitter).handler(risc(RiscRecorder(calls.clone())));
    let set = transmitter.set("RiscAccountPurged", Some(iss_sub(transmitter.issuer(), "alice")));
    processor.process(&set, SsfDeliveryMethod::Push).await.unwrap();
    assert_eq!(calls.take(), ["AccountPurged", "purged"]);
}

struct ScimRecorder(Calls);

impl SsfScimEventHandler for ScimRecorder {
    async fn on_scim_event(&self, event: SsfScimEvent, context: SsfEventContext) -> Result<(), BoxError> {
        self.0.record(format!(
            "{:?}:{}",
            event.operation(),
            event.subject().and_then(|s| s.id()).unwrap_or_default()
        ));
        if event.operation() == SsfScimOperation::Create {
            self.on_create(event, context).await?;
        }
        Ok(())
    }
    async fn on_create(&self, event: SsfScimEvent, _: SsfEventContext) -> Result<(), BoxError> {
        self.0.record(format!("create:full={}", event.is_full()));
        Ok(())
    }
}

#[tokio::test]
async fn scim_dispatches_every_operation_to_its_method() {
    use easyssf_receiver::event::SsfEventHandler;
    let calls = Calls::default();
    let handler = scim(ScimRecorder(calls.clone()));
    let scim_context = |uri: &str| {
        let claims = json!({ "jti": "1", "iss": "i", "iat": 1, "sub_id": scim_subject("/Users/42"), "events": { uri: { "data": {} } } });
        SsfEventContext::new(
            easyssf_core::SsfEventToken::from_claims(claims.as_object().unwrap().clone()).unwrap(),
            SsfDeliveryMethod::Push,
        )
    };
    for (operation, uri) in SsfScimOperation::KNOWN {
        handler.handle(scim_context(uri)).await.unwrap();
        let calls = calls.take();
        assert_eq!(calls[0], format!("{operation:?}:42"), "{uri}");
        if operation == SsfScimOperation::Create {
            assert_eq!(calls[1], format!("create:full={}", uri.ends_with(":full")));
        }
    }
}

#[tokio::test]
async fn handles_all_scim_events_of_a_set_and_ignores_other_sets() {
    use easyssf_receiver::event::SsfEventHandler;
    let calls = Calls::default();
    let handler = scim(ScimRecorder(calls.clone()));
    handler.handle(context(json!({ event_types::SCIM_PROV_DELETE: {}, event_types::CAEP_SESSION_REVOKED: {}, event_types::SCIM_FEED_REMOVE: {} }))).await.unwrap();
    // the SET's subject is iss_sub, so the events have no SCIM subject
    assert_eq!(calls.take(), ["Delete:", "FeedRemove:"]);
    handler
        .handle(context(json!({ event_types::CAEP_SESSION_REVOKED: {} })))
        .await
        .unwrap();
    assert!(calls.take().is_empty());
}

#[tokio::test]
async fn scim_set_passes_strict_verification_and_reaches_the_handler() {
    let transmitter = TestTransmitter::new();
    let calls = Calls::default();
    let processor = processor(&transmitter).handler(scim(ScimRecorder(calls.clone())));
    let mut payload = Map::new();
    payload.insert("data".to_owned(), json!({ "userName": "alice" }));
    let claims = transmitter.set_claims_with_payload("ScimProvCreateFull", Some(scim_subject("/Users/42")), payload);
    processor
        .process(&transmitter.sign_set(&claims), SsfDeliveryMethod::Push)
        .await
        .unwrap();
    assert_eq!(calls.take(), ["Create:42", "create:full=true"]);
}
