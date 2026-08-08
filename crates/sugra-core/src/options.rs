//! Pure scanner-option resolution.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use sugra_domain::{OptionDefinition, OptionKind};
use thiserror::Error;

/// Scanner option validation failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OptionError {
    /// Caller supplied an option absent from the descriptor.
    #[error("unknown option: {0}")]
    Unknown(String),
    /// A required option has no caller value or default.
    #[error("missing required option: {0}")]
    Missing(String),
    /// A value violates the option type or bounds.
    #[error("invalid option {key}: {message}")]
    Invalid {
        /// Option key.
        key: String,
        /// Safe validation message.
        message: String,
    },
}

/// Applies defaults and parses caller values according to descriptor definitions.
///
/// # Errors
///
/// Returns an option error when a key is unknown, a required value is missing,
/// or a supplied value violates its declared type or bounds.
pub fn resolve_options(
    definitions: &[OptionDefinition],
    supplied: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, Value>, OptionError> {
    let known: BTreeSet<&str> = definitions
        .iter()
        .map(|definition| definition.key.as_str())
        .collect();
    if let Some(unknown) = supplied.keys().find(|key| !known.contains(key.as_str())) {
        return Err(OptionError::Unknown(unknown.clone()));
    }
    let mut resolved = BTreeMap::new();
    for definition in definitions {
        let raw = supplied
            .get(&definition.key)
            .or(definition.default.as_ref());
        match raw {
            Some(raw) => {
                resolved.insert(definition.key.clone(), parse_value(definition, raw)?);
            }
            None if definition.required => {
                return Err(OptionError::Missing(definition.key.clone()));
            }
            None => {}
        }
    }
    Ok(resolved)
}

fn parse_value(definition: &OptionDefinition, raw: &str) -> Result<Value, OptionError> {
    let invalid = |message: &str| OptionError::Invalid {
        key: definition.key.clone(),
        message: message.into(),
    };
    match &definition.kind {
        OptionKind::Boolean => raw
            .parse::<bool>()
            .map(Value::Bool)
            .map_err(|_| invalid("expected true or false")),
        OptionKind::Integer { min, max } => raw
            .parse::<i64>()
            .ok()
            .filter(|value| value >= min && value <= max)
            .map(Value::from)
            .ok_or_else(|| invalid("integer is outside the accepted range")),
        OptionKind::Text { max_len } => {
            if raw.len() <= *max_len && !raw.contains('\0') {
                Ok(Value::String(raw.into()))
            } else {
                Err(invalid("text exceeds its limit or contains a null byte"))
            }
        }
        OptionKind::Choice { values } => {
            if values.iter().any(|value| value == raw) {
                Ok(Value::String(raw.into()))
            } else {
                Err(invalid("value is not one of the declared choices"))
            }
        }
        OptionKind::List { max_items } => {
            let values: Vec<Value> = raw
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| Value::String(value.into()))
                .collect();
            if values.len() <= *max_items {
                Ok(Value::Array(values))
            } else {
                Err(invalid("list exceeds its item limit"))
            }
        }
        OptionKind::SecretRef => {
            let valid = !raw.is_empty()
                && raw.len() <= 128
                && raw
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
            if valid {
                Ok(Value::String(raw.into()))
            } else {
                Err(invalid(
                    "secret reference must be an environment variable name",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use sugra_domain::OptionKind;

    use super::*;

    #[test]
    fn specific_value_overrides_default_without_mutating_input() -> Result<(), OptionError> {
        let definitions = vec![OptionDefinition {
            key: "timeout".into(),
            description: "timeout".into(),
            kind: OptionKind::Integer { min: 1, max: 30 },
            default: Some("10".into()),
            required: false,
        }];
        let supplied = BTreeMap::from([("timeout".into(), "20".into())]);
        let original = supplied.clone();
        let resolved = resolve_options(&definitions, &supplied)?;
        assert_eq!(resolved.get("timeout"), Some(&Value::from(20)));
        assert_eq!(supplied, original);
        Ok(())
    }
}
