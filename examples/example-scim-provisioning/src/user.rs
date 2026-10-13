//! A user of the local directory.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A user of the local directory, the mirror of a SCIM `User` resource (RFC 7643, section 4.1):
/// the attributes this application cares about, and the ETag `version` the service provider
/// reported with the last event about the resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    /// The id of the resource, the last segment of the subject's `uri`.
    pub id: String,
    /// The `externalId` of the subject.
    pub external_id: Option<String>,
    /// `userName`.
    pub user_name: Option<String>,
    /// `displayName`, or the name assembled from `name`.
    pub display_name: Option<String>,
    /// The addresses of `emails`.
    pub emails: Vec<String>,
    /// `active`.
    pub active: bool,
    /// The `version` of the last event.
    pub version: Option<String>,
}

impl User {
    /// Builds the user from the `data` of a `prov:create:full` or `prov:put:full` event, the
    /// representation of the resource.
    pub fn from_scim(id: &str, external_id: Option<&str>, data: &Map<String, Value>, version: Option<String>) -> Self {
        Self {
            id: id.to_owned(),
            external_id: external_id.map(str::to_owned),
            user_name: string(data.get("userName")),
            display_name: display_name(data),
            emails: emails(data.get("emails")),
            active: data.get("active") != Some(&Value::Bool(false)),
            version,
        }
    }

    /// Applies one attribute of a SCIM PATCH (`replace` or `add`) to the user. Attributes this
    /// application does not mirror are ignored.
    pub fn with(mut self, attribute: &str, value: Option<&Value>) -> Self {
        match attribute {
            "userName" => self.user_name = string(value),
            "displayName" => self.display_name = string(value),
            "emails" => self.emails = emails(value),
            "active" => {
                self.active = value != Some(&Value::Bool(false)) && value != Some(&Value::String("false".to_owned()));
            }
            _ => {}
        }
        self
    }

    /// The user with `active`.
    pub fn with_active(mut self, active: bool) -> Self {
        self.active = active;
        self
    }

    /// The user with `version`, if the event carried one.
    pub fn with_version(mut self, version: Option<String>) -> Self {
        if version.is_some() {
            self.version = version;
        }
        self
    }
}

impl fmt::Display for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "User[id={}, externalId={}, userName={}, displayName={}, emails={:?}, active={}, version={}]",
            self.id,
            self.external_id.as_deref().unwrap_or("null"),
            self.user_name.as_deref().unwrap_or("null"),
            self.display_name.as_deref().unwrap_or("null"),
            self.emails,
            self.active,
            self.version.as_deref().unwrap_or("null"),
        )
    }
}

fn display_name(data: &Map<String, Value>) -> Option<String> {
    if let Some(display_name) = string(data.get("displayName")) {
        return Some(display_name);
    }
    let name = data.get("name")?.as_object()?;
    if let Some(formatted) = string(name.get("formatted")) {
        return Some(formatted);
    }
    let given = string(name.get("givenName"));
    let family = string(name.get("familyName"));
    if given.is_none() && family.is_none() {
        return None;
    }
    Some(format!(
        "{}{}",
        given.map(|given| format!("{given} ")).unwrap_or_default(),
        family.unwrap_or_default()
    ))
}

/// The values of the multi-valued `emails` attribute: complex values with a `value` member, or
/// plain strings.
fn emails(value: Option<&Value>) -> Vec<String> {
    let Some(Value::Array(values)) = value else {
        return Vec::new();
    };
    values
        .iter()
        .filter_map(|email| match email {
            Value::Object(complex) => complex.get("value").and_then(Value::as_str),
            Value::String(address) => Some(address.as_str()),
            _ => None,
        })
        .map(str::to_owned)
        .collect()
}

fn string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|string| !string.trim().is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn builds_the_user_from_the_scim_representation() {
        let data = json!({
            "userName": "carol",
            "name": {"givenName": "Carol", "familyName": "Clark"},
            "emails": [{"type": "work", "value": "carol@example.com"}, "carol@home.example"],
        });
        let user = User::from_scim("1", Some("carol"), data.as_object().unwrap(), Some("1".to_owned()));
        assert_eq!(user.user_name.as_deref(), Some("carol"));
        assert_eq!(user.display_name.as_deref(), Some("Carol Clark"));
        assert_eq!(user.emails, vec!["carol@example.com", "carol@home.example"]);
        assert!(user.active);
        assert_eq!(user.version.as_deref(), Some("1"));
    }

    #[test]
    fn applies_patched_attributes() {
        let user = User::from_scim("1", None, json!({"userName": "carol"}).as_object().unwrap(), None)
            .with("displayName", Some(&json!("Carol Davis")))
            .with("active", Some(&json!("false")))
            .with("phoneNumbers", Some(&json!(["+1"])));
        assert_eq!(user.display_name.as_deref(), Some("Carol Davis"));
        assert!(!user.active);
    }
}
