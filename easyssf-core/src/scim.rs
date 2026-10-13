//! SCIM Events (RFC 9967): the operations, the `scim` subject and the typed event payload.

use serde_json::{Map, Value};

use crate::event::{SsfEventToken, SsfSubject, SsfSubjectIdentifier};
use crate::event_types;
use crate::support::{strings_member, text_member};

/// What a SCIM Event (RFC 9967) reports, independent of whether its payload carries the resource
/// (`full`) or only names the attributes that changed (`notice`).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SsfScimOperation {
    /// The resource joined the event feed (section 2.3.1), it is not necessarily new.
    FeedAdd,
    /// The resource left the event feed (section 2.3.2), it was not necessarily deleted.
    FeedRemove,
    /// The resource was created (section 2.4.1).
    Create,
    /// The resource was modified with SCIM PATCH (section 2.4.2).
    Patch,
    /// The resource was replaced with SCIM PUT (section 2.4.3).
    Put,
    /// The resource was deleted, and thereby removed from the feed (section 2.4.4).
    Delete,
    /// The resource was activated, for example its account may be logged in to (section 2.4.5).
    Activate,
    /// The resource was deactivated, typically its user may no longer have an active session
    /// (section 2.4.6).
    Deactivate,
    /// An asynchronous SCIM request completed (section 2.5.1.3).
    AsyncResponse,
}

impl SsfScimOperation {
    /// The operations and the event type URIs that report them.
    pub const KNOWN: [(SsfScimOperation, &'static str); 12] = [
        (Self::FeedAdd, event_types::SCIM_FEED_ADD),
        (Self::FeedRemove, event_types::SCIM_FEED_REMOVE),
        (Self::Create, event_types::SCIM_PROV_CREATE_NOTICE),
        (Self::Create, event_types::SCIM_PROV_CREATE_FULL),
        (Self::Patch, event_types::SCIM_PROV_PATCH_NOTICE),
        (Self::Patch, event_types::SCIM_PROV_PATCH_FULL),
        (Self::Put, event_types::SCIM_PROV_PUT_NOTICE),
        (Self::Put, event_types::SCIM_PROV_PUT_FULL),
        (Self::Delete, event_types::SCIM_PROV_DELETE),
        (Self::Activate, event_types::SCIM_PROV_ACTIVATE),
        (Self::Deactivate, event_types::SCIM_PROV_DEACTIVATE),
        (Self::AsyncResponse, event_types::SCIM_MISC_ASYNC_RESPONSE),
    ];

    /// The event type URIs that report this operation, one or, for the provisioning operations
    /// with a `notice` and a `full` variant, two.
    pub fn event_types(self) -> Vec<&'static str> {
        Self::KNOWN
            .iter()
            .filter(|(operation, _)| *operation == self)
            .map(|(_, uri)| *uri)
            .collect()
    }

    /// Whether this is one of the provisioning operations of section 2.4, which report a change
    /// of the resource at the SCIM service provider.
    pub fn is_provisioning(self) -> bool {
        !matches!(self, Self::FeedAdd | Self::FeedRemove | Self::AsyncResponse)
    }

    /// The operation an event type URI or alias reports, `None` if it is not a SCIM Event.
    pub fn of(event_type: &str) -> Option<Self> {
        let uri = event_types::resolve(event_type);
        Self::KNOWN
            .iter()
            .find(|(_, known)| *known == uri)
            .map(|(operation, _)| *operation)
    }

    /// Whether the event type is one of SCIM Events.
    pub fn is_scim_event(event_type: &str) -> bool {
        Self::of(event_type).is_some()
    }
}

/// The subject of a SCIM Event (RFC 9967, section 2.1): a SCIM resource named by a `scim` subject
/// identifier. The identifier carries the relative `uri` of the resource (its resource type
/// endpoint plus its `id`, for example `/Users/2b2f880af6674ac284bae9381673d462`), the
/// `externalId` and `id` of the resource if known, and possibly further attributes of the
/// resource that are unique at the SCIM service provider, such as `userName`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfScimSubject {
    identifier: SsfSubjectIdentifier,
}

impl SsfScimSubject {
    /// The SCIM subject of an identifier, `None` if the identifier is not of format `scim`.
    pub fn from_identifier(identifier: Option<&SsfSubjectIdentifier>) -> Option<Self> {
        let identifier = identifier?;
        identifier.is_scim().then(|| Self {
            identifier: identifier.clone(),
        })
    }

    /// The SCIM subject of a SET's subject, `None` if the subject is not a `scim` identifier (nor
    /// a complex subject whose `user` is one).
    pub fn from(subject: &SsfSubject) -> Option<Self> {
        Self::from_identifier(subject.user_identifier())
    }

    /// The `scim` subject identifier as received.
    pub fn identifier(&self) -> &SsfSubjectIdentifier {
        &self.identifier
    }

    /// The relative path of the resource at the SCIM service provider, which RFC 9967 requires;
    /// `None` if the transmitter left it out nevertheless.
    pub fn uri(&self) -> Option<&str> {
        self.identifier.claim("uri")
    }

    /// The resource type endpoint of the [`uri`](Self::uri), for example `Users` or `Groups`;
    /// `None` if the uri has no such segment.
    pub fn resource_type(&self) -> Option<String> {
        let segments = self.segments();
        (segments.len() >= 2).then(|| segments[segments.len() - 2].clone())
    }

    /// The `id` of the resource: the `id` attribute of the identifier or, if absent, the last
    /// segment of the [`uri`](Self::uri); `None` if there is neither.
    pub fn id(&self) -> Option<String> {
        if let Some(id) = self.identifier.claim("id") {
            return Some(id.to_owned());
        }
        self.segments().last().cloned()
    }

    /// The `externalId` of the resource, the identifier the receiver's domain knows it by.
    pub fn external_id(&self) -> Option<&str> {
        self.identifier.claim("externalId")
    }

    /// A further attribute of the identifier, such as `userName`; `None` if absent or not a
    /// non-empty string.
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.identifier.claim(name)
    }

    /// All members of the identifier as received, including `format`.
    pub fn claims(&self) -> &Map<String, Value> {
        self.identifier.claims()
    }

    fn segments(&self) -> Vec<String> {
        let Some(uri) = self.uri() else {
            return Vec::new();
        };
        let path = uri.split('?').next().unwrap_or("");
        path.split('/')
            .filter(|segment| !segment.is_empty())
            .map(str::to_owned)
            .collect()
    }
}

/// A SCIM Event (RFC 9967) of a SET, with typed access to the common payload attributes of
/// section 2.2: the resource as `data` in `full` mode, the modified `attributes` in `notice`
/// mode, and the ETag `version` of the resource after the event. The `txn` that groups the SETs
/// of one transaction is a claim of the [`SsfEventToken`].
///
/// A SET may carry several SCIM Events; RFC 9967 then has them arise from the same change of the
/// same resource, so they share the [`subject`](Self::subject).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsfScimEvent {
    event_type: String,
    operation: SsfScimOperation,
    subject: Option<SsfScimSubject>,
    payload: Map<String, Value>,
}

impl SsfScimEvent {
    /// The event of an event type URI or alias, `None` if the event type is not one of SCIM
    /// Events. `subject` is the SCIM subject of the SET, `None` if it has none.
    pub fn of(event_type: &str, subject: Option<SsfScimSubject>, payload: Option<&Map<String, Value>>) -> Option<Self> {
        let operation = SsfScimOperation::of(event_type)?;
        Some(Self {
            event_type: event_types::resolve(event_type),
            operation,
            subject,
            payload: payload.cloned().unwrap_or_default(),
        })
    }

    /// The SCIM Events of a SET, in the order of its `events` claim.
    pub fn in_token(event_token: &SsfEventToken) -> Vec<Self> {
        let subject = SsfScimSubject::from(&SsfSubject::from(event_token.subject_id()));
        event_token
            .events()
            .iter()
            .filter_map(|(event_type, payload)| {
                let operation = SsfScimOperation::of(event_type)?;
                Some(Self {
                    event_type: event_type.clone(),
                    operation,
                    subject: subject.clone(),
                    payload: payload.as_object().cloned().unwrap_or_default(),
                })
            })
            .collect()
    }

    /// The event type URI.
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    /// What the event reports.
    pub fn operation(&self) -> SsfScimOperation {
        self.operation
    }

    /// The SCIM resource the event is about, `None` if the `sub_id` of the SET is not a `scim`
    /// subject identifier (which RFC 9967 requires, but a handler should expect).
    pub fn subject(&self) -> Option<&SsfScimSubject> {
        self.subject.as_ref()
    }

    /// The event payload as received.
    pub fn payload(&self) -> &Map<String, Value> {
        &self.payload
    }

    /// Whether the payload carries the resource as [`data`](Self::data): the event type ends in
    /// `:full`.
    pub fn is_full(&self) -> bool {
        self.event_type.ends_with(":full")
    }

    /// Whether the payload only names the modified [`attributes`](Self::attributes): the event
    /// type ends in `:notice`. A receiver may fetch the resource from the SCIM service provider
    /// with a GET of the subject's uri.
    pub fn is_notice(&self) -> bool {
        self.event_type.ends_with(":notice")
    }

    /// The `data` of a `full` event: the representation of the created or replaced resource, or
    /// the `PatchOp` applied.
    pub fn data(&self) -> Option<&Map<String, Value>> {
        self.payload.get("data").and_then(Value::as_object)
    }

    /// The `attributes` of a `notice` event: the paths of the attributes created, modified or
    /// removed; empty if absent.
    pub fn attributes(&self) -> Vec<String> {
        strings_member(&self.payload, "attributes")
    }

    /// The ETag `version` of the resource after the event.
    pub fn version(&self) -> Option<String> {
        text_member(&self.payload, "version")
    }

    /// The HTTP `method` of the request an [`AsyncResponse`](SsfScimOperation::AsyncResponse)
    /// reports on, `None` for other events.
    pub fn method(&self) -> Option<String> {
        text_member(&self.payload, "method")
    }

    /// The HTTP `status` of the request an [`AsyncResponse`](SsfScimOperation::AsyncResponse)
    /// reports on, as a string like the SCIM bulk response has it; `None` for other events.
    pub fn status(&self) -> Option<String> {
        text_member(&self.payload, "status")
    }

    /// The SCIM error `response` of a failed request an
    /// [`AsyncResponse`](SsfScimOperation::AsyncResponse) reports on, with `scimType` and
    /// `detail`; `None` if the request succeeded or for other events.
    pub fn response(&self) -> Option<&Map<String, Value>> {
        self.payload.get("response").and_then(Value::as_object)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::event::subjects;

    fn token(sub_id: Option<Map<String, Value>>, events: Value) -> SsfEventToken {
        let mut claims = json!({ "jti": "1", "iss": "https://t.example", "iat": 1700000000, "events": events });
        if let Some(sub_id) = sub_id {
            claims["sub_id"] = Value::Object(sub_id);
        }
        SsfEventToken::from_claims(claims.as_object().unwrap().clone()).unwrap()
    }

    fn scim_subject(uri: &str) -> SsfScimSubject {
        SsfScimSubject::from(&SsfSubject::from(Some(&subjects::scim(uri)))).unwrap()
    }

    #[test]
    fn every_scim_event_type_has_an_operation_and_an_alias() {
        for (operation, uri) in SsfScimOperation::KNOWN {
            assert_eq!(SsfScimOperation::of(uri), Some(operation));
            assert!(operation.event_types().contains(&uri));
            assert_ne!(event_types::alias_of(uri), uri, "{uri} has no alias");
            assert!(SsfScimOperation::is_scim_event(&event_types::alias_of(uri)));
        }
        assert_eq!(SsfScimOperation::Create.event_types().len(), 2);
        assert_eq!(SsfScimOperation::Delete.event_types().len(), 1);
        assert_eq!(SsfScimOperation::of("CaepSessionRevoked"), None);
    }

    #[test]
    fn provisioning_operations_are_the_ones_of_section_2dot4() {
        assert!(SsfScimOperation::Create.is_provisioning());
        assert!(SsfScimOperation::Deactivate.is_provisioning());
        assert!(!SsfScimOperation::FeedAdd.is_provisioning());
        assert!(!SsfScimOperation::FeedRemove.is_provisioning());
        assert!(!SsfScimOperation::AsyncResponse.is_provisioning());
    }

    #[test]
    fn full_event_carries_the_resource_as_data() {
        let payload = json!({ "data": { "userName": "alice" }, "version": "W/\"1\"" });
        let event = SsfScimEvent::of(
            "ScimProvCreateFull",
            Some(scim_subject("/Users/1")),
            payload.as_object(),
        )
        .unwrap();
        assert!(event.is_full());
        assert!(!event.is_notice());
        assert_eq!(event.data().unwrap()["userName"], "alice");
        assert_eq!(event.version().as_deref(), Some("W/\"1\""));
        assert!(event.attributes().is_empty());
        assert_eq!(event.operation(), SsfScimOperation::Create);
        assert_eq!(event.subject().unwrap().id().as_deref(), Some("1"));
    }

    #[test]
    fn notice_event_lists_the_modified_attributes() {
        let payload = json!({ "attributes": ["emails", "name.familyName", 3] });
        let event = SsfScimEvent::of("ScimProvPatchNotice", None, payload.as_object()).unwrap();
        assert!(event.is_notice());
        assert_eq!(event.attributes(), ["emails", "name.familyName"]);
        assert!(event.data().is_none());
    }

    #[test]
    fn events_without_payload_attributes_are_neither_full_nor_notice() {
        let event = SsfScimEvent::of("ScimProvDelete", None, None).unwrap();
        assert!(!event.is_full());
        assert!(!event.is_notice());
        assert!(event.payload().is_empty());
        assert_eq!(event.version(), None);
    }

    #[test]
    fn async_response_carries_the_outcome_of_the_request() {
        let payload =
            json!({ "method": "POST", "status": "409", "response": { "scimType": "uniqueness", "detail": "exists" } });
        let event = SsfScimEvent::of("ScimMiscAsyncResponse", None, payload.as_object()).unwrap();
        assert_eq!(event.method().as_deref(), Some("POST"));
        assert_eq!(event.status().as_deref(), Some("409"));
        assert_eq!(event.response().unwrap()["scimType"], "uniqueness");
    }

    #[test]
    fn finds_all_scim_events_of_a_set_in_order_and_ignores_others() {
        let set = token(
            Some(subjects::scim("/Users/42")),
            json!({
                "urn:ietf:params:scim:event:prov:create:full": { "data": {} },
                "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {},
                "urn:ietf:params:scim:event:feed:add": {}
            }),
        );
        let events = SsfScimEvent::in_token(&set);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].operation(), SsfScimOperation::Create);
        assert_eq!(events[1].operation(), SsfScimOperation::FeedAdd);
        assert_eq!(events[1].subject().unwrap().uri(), Some("/Users/42"));
    }

    #[test]
    fn subject_is_none_unless_the_set_has_a_scim_subject() {
        let with_iss_sub = token(
            Some(subjects::iss_sub("https://idp.example", "alice")),
            json!({ "urn:ietf:params:scim:event:prov:delete": {} }),
        );
        assert!(SsfScimEvent::in_token(&with_iss_sub)[0].subject().is_none());
        let without = token(None, json!({ "urn:ietf:params:scim:event:prov:delete": {} }));
        assert!(SsfScimEvent::in_token(&without)[0].subject().is_none());
    }

    #[test]
    fn of_resolves_aliases_and_rejects_other_event_types() {
        let event = SsfScimEvent::of("ScimProvActivate", None, None).unwrap();
        assert_eq!(event.event_type(), event_types::SCIM_PROV_ACTIVATE);
        assert!(SsfScimEvent::of("CaepSessionRevoked", None, None).is_none());
    }

    #[test]
    fn resolves_resource_type_and_id_from_the_uri() {
        let subject = scim_subject("/Users/2b2f880a");
        assert_eq!(subject.resource_type().as_deref(), Some("Users"));
        assert_eq!(subject.id().as_deref(), Some("2b2f880a"));
        assert_eq!(subject.external_id(), None);
    }

    #[test]
    fn tolerates_absolute_uris_and_queries() {
        let subject = scim_subject("https://scim.example/v2/Groups/g1?attributes=members");
        assert_eq!(subject.resource_type().as_deref(), Some("Groups"));
        assert_eq!(subject.id().as_deref(), Some("g1"));
    }

    #[test]
    fn id_attribute_wins_over_the_uri() {
        let identifier = json!({ "format": "scim", "uri": "/Users/from-uri", "id": "from-id", "externalId": "ext" });
        let subject = SsfScimSubject::from(&SsfSubject::from(identifier.as_object())).unwrap();
        assert_eq!(subject.id().as_deref(), Some("from-id"));
        assert_eq!(subject.external_id(), Some("ext"));
    }

    #[test]
    fn further_attributes_are_available_by_name() {
        let identifier = json!({ "format": "scim", "uri": "/Users/1", "userName": "alice", "active": true });
        let subject = SsfScimSubject::from(&SsfSubject::from(identifier.as_object())).unwrap();
        assert_eq!(subject.attribute("userName"), Some("alice"));
        assert_eq!(subject.attribute("active"), None);
        assert_eq!(subject.claims()["active"], true);
    }

    #[test]
    fn subject_without_uri_has_no_resource() {
        let identifier = json!({ "format": "scim", "externalId": "ext" });
        let subject = SsfScimSubject::from(&SsfSubject::from(identifier.as_object())).unwrap();
        assert_eq!(subject.uri(), None);
        assert_eq!(subject.resource_type(), None);
        assert_eq!(subject.id(), None);
    }

    #[test]
    fn only_scim_identifiers_are_scim_subjects() {
        assert!(SsfScimSubject::from(&SsfSubject::from(Some(&subjects::email("a@b.example")))).is_none());
        assert!(SsfScimSubject::from(&SsfSubject::empty()).is_none());
        assert!(SsfScimSubject::from_identifier(None).is_none());
    }

    #[test]
    fn user_of_a_complex_subject_may_be_a_scim_resource() {
        let complex = subjects::complex(Some(subjects::scim("/Users/7")), Some(subjects::opaque("s1")));
        let subject = SsfScimSubject::from(&SsfSubject::from(Some(&complex))).unwrap();
        assert_eq!(subject.id().as_deref(), Some("7"));
    }
}
