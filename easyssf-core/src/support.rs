//! Small helpers over `serde_json` values shared by the value objects.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

/// A non-empty string member of an object, `None` otherwise.
pub(crate) fn string_member<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

/// Any member rendered as text: a string as it is, anything else as its JSON, `None` if absent
/// or JSON `null`.
pub(crate) fn text_member(object: &Map<String, Value>, name: &str) -> Option<String> {
    match object.get(name) {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(other) => Some(other.to_string()),
    }
}

/// The strings of an array member, non-strings skipped; empty if absent or not an array.
pub(crate) fn strings_member(object: &Map<String, Value>, name: &str) -> Vec<String> {
    strings(object.get(name))
}

/// The strings of an array value, non-strings skipped; empty for anything else.
pub(crate) fn strings(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(values)) => values.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
        _ => Vec::new(),
    }
}

/// An object member, `None` if absent or not an object.
pub(crate) fn object_member<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a Map<String, Value>> {
    object.get(name).and_then(Value::as_object)
}

/// Seconds since the epoch as a [`SystemTime`]; a time before the epoch becomes the epoch.
pub(crate) fn system_time(seconds: i64) -> SystemTime {
    if seconds < 0 {
        UNIX_EPOCH
    } else {
        UNIX_EPOCH + Duration::from_secs(seconds as u64)
    }
}
