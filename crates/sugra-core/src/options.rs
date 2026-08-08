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

    fn definition(
        key: &str,
        kind: OptionKind,
        default: Option<&str>,
        required: bool,
    ) -> OptionDefinition {
        OptionDefinition {
            key: key.into(),
            description: format!("{key} option"),
            kind,
            default: default.map(Into::into),
            required,
        }
    }

    #[test]
    fn every_option_kind_resolves_to_typed_json() -> Result<(), OptionError> {
        let definitions = vec![
            definition("enabled", OptionKind::Boolean, None, true),
            definition(
                "retries",
                OptionKind::Integer { min: 0, max: 3 },
                None,
                true,
            ),
            definition("label", OptionKind::Text { max_len: 8 }, None, true),
            definition(
                "mode",
                OptionKind::Choice {
                    values: vec!["safe".into(), "strict".into()],
                },
                None,
                true,
            ),
            definition("ports", OptionKind::List { max_items: 3 }, None, true),
            definition("credential", OptionKind::SecretRef, None, true),
        ];
        let supplied = BTreeMap::from([
            ("enabled".into(), "true".into()),
            ("retries".into(), "3".into()),
            ("label".into(), "bounded".into()),
            ("mode".into(), "strict".into()),
            ("ports".into(), "80, 443,,8080".into()),
            ("credential".into(), "SUGRA_TEST_TOKEN_2".into()),
        ]);

        let resolved = resolve_options(&definitions, &supplied)?;

        assert_eq!(resolved.get("enabled"), Some(&Value::Bool(true)));
        assert_eq!(resolved.get("retries"), Some(&Value::from(3)));
        assert_eq!(resolved.get("label"), Some(&Value::from("bounded")));
        assert_eq!(resolved.get("mode"), Some(&Value::from("strict")));
        assert_eq!(
            resolved.get("ports"),
            Some(&Value::Array(vec![
                Value::from("80"),
                Value::from("443"),
                Value::from("8080"),
            ]))
        );
        assert_eq!(
            resolved.get("credential"),
            Some(&Value::from("SUGRA_TEST_TOKEN_2"))
        );
        Ok(())
    }

    #[test]
    fn defaults_are_parsed_and_absent_optional_values_are_omitted() -> Result<(), OptionError> {
        let definitions = vec![
            definition("enabled", OptionKind::Boolean, Some("false"), false),
            definition("optional", OptionKind::Text { max_len: 4 }, None, false),
            definition(
                "empty-list",
                OptionKind::List { max_items: 0 },
                Some(""),
                false,
            ),
        ];

        let resolved = resolve_options(&definitions, &BTreeMap::new())?;

        assert_eq!(resolved.get("enabled"), Some(&Value::Bool(false)));
        assert!(!resolved.contains_key("optional"));
        assert_eq!(resolved.get("empty-list"), Some(&Value::Array(Vec::new())));
        Ok(())
    }

    #[test]
    fn unknown_and_missing_options_are_distinct_errors() {
        let required = definition("required", OptionKind::Boolean, None, true);
        assert_eq!(
            resolve_options(
                std::slice::from_ref(&required),
                &BTreeMap::from([("unexpected".into(), "true".into())]),
            ),
            Err(OptionError::Unknown("unexpected".into()))
        );
        assert_eq!(
            resolve_options(&[required], &BTreeMap::new()),
            Err(OptionError::Missing("required".into()))
        );
    }

    #[test]
    fn invalid_values_report_the_declared_key_without_echoing_input() {
        let cases = [
            (
                definition("boolean", OptionKind::Boolean, None, true),
                "yes",
                "expected true or false",
            ),
            (
                definition(
                    "integer",
                    OptionKind::Integer { min: 1, max: 2 },
                    None,
                    true,
                ),
                "3",
                "integer is outside the accepted range",
            ),
            (
                definition("text", OptionKind::Text { max_len: 3 }, None, true),
                "four",
                "text exceeds its limit or contains a null byte",
            ),
            (
                definition(
                    "choice",
                    OptionKind::Choice {
                        values: vec!["one".into()],
                    },
                    None,
                    true,
                ),
                "two",
                "value is not one of the declared choices",
            ),
            (
                definition("list", OptionKind::List { max_items: 1 }, None, true),
                "one,two",
                "list exceeds its item limit",
            ),
            (
                definition("secret", OptionKind::SecretRef, None, true),
                "lowercase-secret",
                "secret reference must be an environment variable name",
            ),
        ];

        for (definition, raw, expected_message) in cases {
            let key = definition.key.clone();
            let result = resolve_options(
                std::slice::from_ref(&definition),
                &BTreeMap::from([(key.clone(), raw.into())]),
            );
            assert_eq!(
                result,
                Err(OptionError::Invalid {
                    key,
                    message: expected_message.into(),
                })
            );
            assert!(
                !result
                    .err()
                    .map(|error| error.to_string())
                    .unwrap_or_default()
                    .contains(raw)
            );
        }
    }

    #[test]
    fn text_null_bytes_and_oversized_secret_names_are_rejected() {
        let text = definition("text", OptionKind::Text { max_len: 32 }, None, true);
        assert!(
            resolve_options(
                &[text],
                &BTreeMap::from([("text".into(), "safe\0hidden".into())]),
            )
            .is_err()
        );

        let secret = definition("secret", OptionKind::SecretRef, None, true);
        assert!(
            resolve_options(
                &[secret],
                &BTreeMap::from([("secret".into(), "A".repeat(129))]),
            )
            .is_err()
        );
    }
}
