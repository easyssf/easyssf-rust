//! What the example applications share: configuration files with `${VAR:default}` placeholders,
//! profiles that overlay them, command line arguments and logging. It plays the part that Spring
//! Boot plays for the Java examples (`application.yaml`, `application-poll.yaml`, `${ENV:default}`)
//! and the host for the .NET examples. Not published.

use std::env;

use serde::de::DeserializeOwned;
use toml::{Table, Value};

/// Replaces `${NAME}` and `${NAME:default}` with the environment variable `NAME`, or with the
/// default when the variable is not set or empty. A placeholder without a default whose variable
/// is not set stays as it is.
pub fn expand_placeholders(text: &str) -> String {
    let mut expanded = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        expanded.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            expanded.push_str("${");
            rest = after;
            continue;
        };
        let placeholder = &after[..end];
        let (name, default) = match placeholder.split_once(':') {
            Some((name, default)) => (name, Some(default)),
            None => (placeholder, None),
        };
        let value = env::var(name)
            .ok()
            .filter(|value| !value.is_empty())
            .or_else(|| default.map(str::to_owned));
        match value {
            Some(value) => expanded.push_str(&value),
            None => {
                expanded.push_str("${");
                expanded.push_str(placeholder);
                expanded.push('}');
            }
        }
        rest = &after[end + 1..];
    }
    expanded.push_str(rest);
    expanded
}

/// Merges `overlay` into `base`: tables merge recursively, every other value of the overlay
/// replaces the value of the base.
pub fn merge(base: &mut Table, overlay: Table) {
    for (key, value) in overlay {
        match (base.get_mut(&key), value) {
            (Some(Value::Table(existing)), Value::Table(table)) => merge(existing, table),
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

/// Parses the TOML sources after expanding their placeholders and merges them in order: the first
/// is the configuration, the others are profiles that override parts of it.
pub fn load(sources: &[&str]) -> Result<Table, toml::de::Error> {
    let mut settings = Table::new();
    for source in sources {
        merge(&mut settings, expand_placeholders(source).parse::<Table>()?);
    }
    Ok(settings)
}

/// The table at the dotted `path` of the settings, such as `easyssf.receiver`, as `T`; the default
/// of `T` when there is no such table.
pub fn section<T: DeserializeOwned + Default>(settings: &Table, path: &str) -> Result<T, toml::de::Error> {
    let mut table = settings;
    for segment in path.split('.') {
        match table.get(segment) {
            Some(Value::Table(next)) => table = next,
            Some(_) => return Err(serde::de::Error::custom(format!("{path} is not a table"))),
            None => return Ok(T::default()),
        }
    }
    Value::Table(table.clone()).try_into()
}

/// The value of the argument `--name=value` or `--name value`, if given.
pub fn argument(args: &[String], name: &str) -> Option<String> {
    let flag = format!("--{name}");
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix(&flag) {
            if let Some(value) = value.strip_prefix('=') {
                return Some(value.to_owned());
            }
            if value.is_empty() {
                return args.next().cloned();
            }
        }
    }
    None
}

/// Logs to stderr with the filter of `RUST_LOG`, or `default_filter` when it is not set.
pub fn init_tracing(default_filter: &str) {
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_placeholders_with_defaults() {
        let expanded =
            expand_placeholders("issuer = \"${EXAMPLE_SUPPORT_UNSET:http://localhost:8080/realms/demo}/token\"");
        assert_eq!(expanded, "issuer = \"http://localhost:8080/realms/demo/token\"");
    }

    #[test]
    fn keeps_a_placeholder_without_value() {
        assert_eq!(
            expand_placeholders("a = \"${EXAMPLE_SUPPORT_UNSET}\""),
            "a = \"${EXAMPLE_SUPPORT_UNSET}\""
        );
    }

    #[test]
    fn profiles_override_parts_of_the_configuration() {
        let settings = load(&["[a]\nx = 1\ny = 2\n[a.b]\nz = 3\n", "[a]\ny = 20\n[a.b]\nw = 4\n"]).unwrap();
        let a = settings["a"].as_table().unwrap();
        assert_eq!(a["x"].as_integer(), Some(1));
        assert_eq!(a["y"].as_integer(), Some(20));
        assert_eq!(a["b"]["z"].as_integer(), Some(3));
        assert_eq!(a["b"]["w"].as_integer(), Some(4));
    }

    #[test]
    fn reads_arguments() {
        let args: Vec<String> = ["app", "--profile=poll", "--demo.autoplay", "false"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(argument(&args, "profile").as_deref(), Some("poll"));
        assert_eq!(argument(&args, "demo.autoplay").as_deref(), Some("false"));
        assert_eq!(argument(&args, "other"), None);
    }
}
