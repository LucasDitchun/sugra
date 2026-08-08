//! Immutable values and invariants shared by every Sugra component.

mod http_options;

pub use http_options::{
    PUBLISHED_SCANNER_OPTION_CONTRACT_COUNT, ScannerOptionContract,
    published_scanner_option_contracts, scanner_options,
};

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use time::OffsetDateTime;
use url::{Host, Url};
use uuid::Uuid;

/// Errors raised while constructing domain values.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DomainError {
    /// A scanner identifier is empty or contains unsupported characters.
    #[error("invalid scanner identifier: {0}")]
    InvalidScannerId(String),
    /// A target cannot be parsed as its declared kind.
    #[error("invalid {kind} target: {value}")]
    InvalidTarget {
        /// Expected target kind.
        kind: &'static str,
        /// Rejected value, safe for display.
        value: String,
    },
    /// A budget is zero or exceeds an invariant.
    #[error("invalid execution budget: {0}")]
    InvalidBudget(String),
    /// An option schema has an unsafe shape, invalid bounds, or invalid default.
    #[error("invalid option definition {key}: {reason}")]
    InvalidOptionDefinition {
        /// Stable option key.
        key: String,
        /// Safe invariant description.
        reason: &'static str,
    },
    /// Scanner metadata violates a catalog invariant.
    #[error("invalid scanner descriptor {scanner_id}: {reason}")]
    InvalidScannerDescriptor {
        /// Canonical scanner identity.
        scanner_id: String,
        /// Safe invariant description.
        reason: &'static str,
    },
    /// A scope contains no allowed targets.
    #[error("scope must contain at least one rule")]
    EmptyScope,
    /// A requested target is outside the declared scope.
    #[error("target is outside the declared scope")]
    OutOfScope,
}

/// Stable canonical identity of a scanner.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ScannerId(String);

impl ScannerId {
    /// Constructs a lowercase, dash-separated scanner identifier.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::InvalidScannerId` when the value is empty,
    /// oversized, or not canonical lowercase dash-separated text.
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 80
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !value.starts_with('-')
            && !value.ends_with('-')
            && !value.contains("--");
        if valid {
            Ok(Self(value))
        } else {
            Err(DomainError::InvalidScannerId(value))
        }
    }

    /// Returns the identifier as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for ScannerId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Published identity used by the compatibility selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum LegacyId {
    /// A catalog entry in the historical range 1 through 134.
    Catalog(u16),
    /// An additional module identified during catalog reconciliation.
    Additional(u8),
}

impl Display for LegacyId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Catalog(value) => write!(formatter, "{value}"),
            Self::Additional(value) => write!(formatter, "U{value:03}"),
        }
    }
}

/// Input shapes accepted by scanners.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetKind {
    /// A DNS domain name.
    Domain,
    /// An IPv4 or IPv6 address.
    Ip,
    /// An IPv4 or IPv6 network.
    Cidr,
    /// An HTTP or HTTPS URL.
    Url,
    /// A host and TCP/UDP port.
    HostPort,
    /// An autonomous system number.
    Asn,
    /// An email address.
    Email,
    /// A scanner-specific opaque value such as a token.
    Opaque,
}

impl TargetKind {
    /// Returns the stable CLI spelling of this target kind.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Ip => "ip",
            Self::Cidr => "cidr",
            Self::Url => "url",
            Self::HostPort => "host-port",
            Self::Asn => "asn",
            Self::Email => "email",
            Self::Opaque => "opaque",
        }
    }
}

/// Validated scan target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum Target {
    /// A normalized domain name.
    Domain(String),
    /// An IP address.
    Ip(IpAddr),
    /// An IP network.
    Cidr(IpNet),
    /// An HTTP or HTTPS URL.
    Url(Url),
    /// A host and port pair.
    HostPort {
        /// Normalized host name or address.
        host: String,
        /// Network port.
        port: u16,
    },
    /// An autonomous system number without the AS prefix.
    Asn(u32),
    /// A normalized email address.
    Email(String),
    /// A bounded scanner-specific value.
    Opaque(String),
}

impl Target {
    /// Parses and validates a target of the declared kind.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::InvalidTarget` when the input cannot be safely
    /// normalized as the requested target kind.
    pub fn parse(kind: TargetKind, input: &str) -> Result<Self, DomainError> {
        let trimmed = input.trim();
        let invalid = || DomainError::InvalidTarget {
            kind: kind.as_str(),
            value: trimmed.chars().take(160).collect(),
        };
        match kind {
            TargetKind::Domain => normalize_host(trimmed)
                .filter(|host| host.parse::<IpAddr>().is_err())
                .map(Self::Domain)
                .ok_or_else(invalid),
            TargetKind::Ip => trimmed.parse().map(Self::Ip).map_err(|_| invalid()),
            TargetKind::Cidr => trimmed.parse().map(Self::Cidr).map_err(|_| invalid()),
            TargetKind::Url => {
                let url = Url::parse(trimmed).map_err(|_| invalid())?;
                if matches!(url.scheme(), "http" | "https") && url.host().is_some() {
                    Ok(Self::Url(url))
                } else {
                    Err(invalid())
                }
            }
            TargetKind::HostPort => parse_host_port(trimmed).ok_or_else(invalid),
            TargetKind::Asn => trimmed
                .trim_start_matches(|character: char| character.eq_ignore_ascii_case(&'a'))
                .trim_start_matches(|character: char| character.eq_ignore_ascii_case(&'s'))
                .parse::<u32>()
                .ok()
                .filter(|value| *value > 0)
                .map(Self::Asn)
                .ok_or_else(invalid),
            TargetKind::Email => normalize_email(trimmed)
                .map(Self::Email)
                .ok_or_else(invalid),
            TargetKind::Opaque => {
                if trimmed.is_empty() || trimmed.len() > 4096 || trimmed.contains('\0') {
                    Err(invalid())
                } else {
                    Ok(Self::Opaque(trimmed.to_owned()))
                }
            }
        }
    }

    /// Returns the target kind.
    #[must_use]
    pub const fn kind(&self) -> TargetKind {
        match self {
            Self::Domain(_) => TargetKind::Domain,
            Self::Ip(_) => TargetKind::Ip,
            Self::Cidr(_) => TargetKind::Cidr,
            Self::Url(_) => TargetKind::Url,
            Self::HostPort { .. } => TargetKind::HostPort,
            Self::Asn(_) => TargetKind::Asn,
            Self::Email(_) => TargetKind::Email,
            Self::Opaque(_) => TargetKind::Opaque,
        }
    }

    /// Returns a canonical, safe display form.
    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Self::Domain(value) | Self::Email(value) | Self::Opaque(value) => value.clone(),
            Self::Ip(value) => value.to_string(),
            Self::Cidr(value) => value.to_string(),
            Self::Url(value) => value.as_str().to_owned(),
            Self::HostPort { host, port } => format!("{host}:{port}"),
            Self::Asn(value) => format!("AS{value}"),
        }
    }

    /// Returns the domain or host when one is available.
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        match self {
            Self::Domain(value) => Some(value),
            Self::Url(value) => value.host_str(),
            Self::HostPort { host, .. } => Some(host),
            Self::Email(value) => value.rsplit_once('@').map(|(_, domain)| domain),
            Self::Ip(_) | Self::Cidr(_) | Self::Asn(_) | Self::Opaque(_) => None,
        }
    }
}

fn normalize_host(input: &str) -> Option<String> {
    let input = input.trim_end_matches('.');
    match Host::parse(input).ok()? {
        Host::Domain(domain) if domain.len() <= 253 && domain.contains('.') => {
            Some(domain.to_ascii_lowercase())
        }
        Host::Ipv4(address) => Some(address.to_string()),
        Host::Ipv6(address) => Some(address.to_string()),
        Host::Domain(_) => None,
    }
}

fn normalize_email(input: &str) -> Option<String> {
    let (local, domain) = input.rsplit_once('@')?;
    if local.is_empty()
        || local.len() > 64
        || input.len() > 254
        || local.chars().any(char::is_whitespace)
    {
        return None;
    }
    let domain = normalize_host(domain)?;
    Some(format!("{local}@{domain}"))
}

fn parse_host_port(input: &str) -> Option<Target> {
    if let Ok(address) = input.parse::<std::net::SocketAddr>() {
        return Some(Target::HostPort {
            host: address.ip().to_string(),
            port: address.port(),
        });
    }
    let (host, port) = input.rsplit_once(':')?;
    let port = port.parse::<u16>().ok().filter(|value| *value > 0)?;
    let host = normalize_host(host)?;
    Some(Target::HostPort { host, port })
}

/// Permission class required by a scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    /// Public DNS, registry, or transparency data without target interaction.
    PassiveNetwork,
    /// A configured third-party service.
    ThirdPartyApi,
    /// Bounded GET, HEAD, OPTIONS, or TLS interaction.
    ActiveHttpSafe,
    /// Enumeration or fuzzing that can generate many requests.
    ActiveFuzz,
    /// Direct TCP, UDP, ICMP, SNMP, NTP, or similar probing.
    ActiveProtocol,
    /// A local command or operating-system integration.
    LocalExec,
    /// Input or output that requires redaction.
    SensitiveOutput,
    /// Pure analysis without external I/O.
    LocalAnalysis,
}

impl Capability {
    /// Returns whether the capability requires explicit active authorization.
    #[must_use]
    pub const fn requires_authorization(self) -> bool {
        matches!(
            self,
            Self::ActiveHttpSafe | Self::ActiveFuzz | Self::ActiveProtocol | Self::LocalExec
        )
    }
}

/// Type of a configurable scanner option.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OptionKind {
    /// Boolean option.
    Boolean,
    /// Signed integer with inclusive bounds.
    Integer {
        /// Inclusive minimum.
        min: i64,
        /// Inclusive maximum.
        max: i64,
    },
    /// Free text with a maximum byte length.
    Text {
        /// Maximum UTF-8 byte length.
        max_len: usize,
    },
    /// One value from a closed set.
    Choice {
        /// Accepted values.
        values: Vec<String>,
    },
    /// A comma-separated list with a maximum item count.
    List {
        /// Maximum comma-separated item count.
        max_items: usize,
    },
    /// Name of an environment variable containing a secret.
    SecretRef,
}

/// Definition of one scanner option.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptionDefinition {
    /// Stable option key.
    pub key: String,
    /// Help text shown by CLI and TUI.
    pub description: String,
    /// Value type and bounds.
    pub kind: OptionKind,
    /// Default textual value, parsed through the same validator as user input.
    pub default: Option<String>,
    /// Whether callers must supply a value.
    pub required: bool,
}

impl OptionDefinition {
    /// Validates the public option schema and its textual default.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidOptionDefinition`] when the key or help
    /// text is malformed, kind bounds are unsafe, or the default cannot be
    /// parsed by the declared kind.
    pub fn validate(&self) -> Result<(), DomainError> {
        let invalid = |reason| DomainError::InvalidOptionDefinition {
            key: self.key.clone(),
            reason,
        };
        let valid_key = !self.key.is_empty()
            && self.key.len() <= 64
            && self
                .key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            && !self.key.starts_with('_')
            && !self.key.ends_with('_')
            && !self.key.contains("__");
        if !valid_key {
            return Err(invalid("key must be canonical snake_case"));
        }
        let description = self.description.trim();
        if description.is_empty() || description.len() > 320 {
            return Err(invalid("description must contain 1 through 320 bytes"));
        }
        if self.required && self.default.is_some() {
            return Err(invalid("required options cannot declare a default"));
        }
        match &self.kind {
            OptionKind::Boolean => self.validate_default(|value| matches!(value, "true" | "false")),
            OptionKind::Integer { min, max } => {
                if min > max {
                    return Err(invalid("integer minimum exceeds maximum"));
                }
                self.validate_default(|value| {
                    value
                        .parse::<i64>()
                        .is_ok_and(|parsed| parsed >= *min && parsed <= *max)
                })
            }
            OptionKind::Text { max_len } => {
                if *max_len == 0 || *max_len > 65_536 {
                    return Err(invalid("text limit must be between 1 and 65536 bytes"));
                }
                self.validate_default(|value| value.len() <= *max_len && !value.contains('\0'))
            }
            OptionKind::Choice { values } => {
                let unique: BTreeSet<&str> = values.iter().map(String::as_str).collect();
                if values.is_empty()
                    || values.len() > 64
                    || unique.len() != values.len()
                    || values
                        .iter()
                        .any(|value| value.is_empty() || value.len() > 128 || value.contains('\0'))
                {
                    return Err(invalid("choices must be unique, nonempty, and bounded"));
                }
                self.validate_default(|value| values.iter().any(|choice| choice == value))
            }
            OptionKind::List { max_items } => {
                if *max_items == 0 || *max_items > 1_024 {
                    return Err(invalid("list limit must be between 1 and 1024 items"));
                }
                self.validate_default(|value| {
                    let items: Vec<_> = value.split(',').map(str::trim).collect();
                    !items.is_empty()
                        && items.len() <= *max_items
                        && items
                            .iter()
                            .all(|item| !item.is_empty() && !item.contains('\0'))
                })
            }
            OptionKind::SecretRef => self.validate_default(valid_secret_reference),
        }
        .map_err(|()| invalid("default does not satisfy the declared kind"))
    }

    fn validate_default(&self, predicate: impl FnOnce(&str) -> bool) -> Result<(), ()> {
        if self.default.as_deref().is_none_or(predicate) {
            Ok(())
        } else {
            Err(())
        }
    }
}

fn valid_secret_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        && value.as_bytes()[0].is_ascii_uppercase()
}

/// Declarative metadata for a scanner implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerDescriptor {
    /// Canonical scanner identity.
    pub id: ScannerId,
    /// Optional published identity accepted by compatibility mode.
    pub legacy_id: Option<LegacyId>,
    /// Human-readable name.
    pub name: String,
    /// Concise purpose.
    pub description: String,
    /// Capability-oriented implementation group.
    pub track: String,
    /// Supported input shapes.
    pub target_kinds: Vec<TargetKind>,
    /// Required permissions.
    pub capabilities: Vec<Capability>,
    /// Typed configuration definitions.
    pub options: Vec<OptionDefinition>,
    /// Implementation version.
    pub version: String,
}

impl ScannerDescriptor {
    /// Validates metadata required by deterministic catalog consumers.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::InvalidScannerDescriptor`] when display fields,
    /// compatibility identity, target kinds, capabilities, option keys, or
    /// implementation version violate a catalog invariant. Invalid option
    /// schemas retain their more specific
    /// [`DomainError::InvalidOptionDefinition`] error.
    pub fn validate(&self) -> Result<(), DomainError> {
        let invalid = |reason| DomainError::InvalidScannerDescriptor {
            scanner_id: self.id.to_string(),
            reason,
        };
        if self.name.trim().is_empty() || self.name.len() > 160 {
            return Err(invalid("name must contain 1 through 160 bytes"));
        }
        if self.description.trim().is_empty() || self.description.len() > 640 {
            return Err(invalid("description must contain 1 through 640 bytes"));
        }
        let valid_track = !self.track.is_empty()
            && self.track.len() <= 64
            && self
                .track
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !self.track.starts_with('-')
            && !self.track.ends_with('-')
            && !self.track.contains("--");
        if !valid_track {
            return Err(invalid(
                "track must be canonical lowercase dash-separated text",
            ));
        }
        if self.legacy_id.is_some_and(|legacy_id| match legacy_id {
            LegacyId::Catalog(value) => !(1..=134).contains(&value),
            LegacyId::Additional(value) => value == 0,
        }) {
            return Err(invalid("compatibility ID is outside its published range"));
        }
        if self.target_kinds.is_empty()
            || self
                .target_kinds
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != self.target_kinds.len()
        {
            return Err(invalid("target kinds must be nonempty and unique"));
        }
        if self.capabilities.is_empty()
            || self
                .capabilities
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != self.capabilities.len()
        {
            return Err(invalid("capabilities must be nonempty and unique"));
        }
        let unique_options: BTreeSet<&str> = self
            .options
            .iter()
            .map(|option| option.key.as_str())
            .collect();
        if unique_options.len() != self.options.len() {
            return Err(invalid("option keys must be unique"));
        }
        for option in &self.options {
            option.validate()?;
        }
        let valid_version = !self.version.is_empty()
            && self.version.len() <= 32
            && self
                .version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'));
        if !valid_version {
            return Err(invalid("version must be a bounded release identifier"));
        }
        Ok(())
    }
}

/// Bounded execution resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// Per-scanner timeout in milliseconds.
    pub timeout_ms: u64,
    /// Maximum scanners running concurrently.
    pub concurrency: usize,
    /// Maximum HTTP or protocol operations per scanner.
    pub max_requests: usize,
    /// Maximum response bytes consumed by one operation.
    pub max_response_bytes: usize,
    /// Maximum traversal or crawl depth.
    pub max_depth: usize,
}

impl Budget {
    /// Conservative default budget for interactive scans.
    pub const DEFAULT: Self = Self {
        timeout_ms: 15_000,
        concurrency: 4,
        max_requests: 64,
        max_response_bytes: 2 * 1024 * 1024,
        max_depth: 3,
    };

    /// Validates non-zero and upper-bound invariants.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::InvalidBudget` when any resource limit falls
    /// outside the supported safety bounds.
    pub fn validate(self) -> Result<Self, DomainError> {
        if self.timeout_ms == 0 || self.timeout_ms > 300_000 {
            return Err(DomainError::InvalidBudget(
                "timeout must be 1..=300000 ms".into(),
            ));
        }
        if self.concurrency == 0 || self.concurrency > 256 {
            return Err(DomainError::InvalidBudget(
                "concurrency must be 1..=256".into(),
            ));
        }
        if self.max_requests == 0 || self.max_requests > 100_000 {
            return Err(DomainError::InvalidBudget(
                "max_requests must be 1..=100000".into(),
            ));
        }
        if self.max_response_bytes == 0 || self.max_response_bytes > 64 * 1024 * 1024 {
            return Err(DomainError::InvalidBudget(
                "max_response_bytes must be 1..=67108864".into(),
            ));
        }
        if self.max_depth > 32 {
            return Err(DomainError::InvalidBudget(
                "max_depth must be 0..=32".into(),
            ));
        }
        Ok(self)
    }

    /// Returns the timeout as a standard duration.
    #[must_use]
    pub const fn timeout(self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// One rule in an operator-declared scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum ScopeRule {
    /// An exact canonical target.
    Exact(String),
    /// One exact domain or host, independent of URL path and port.
    Host(String),
    /// A domain and all of its subdomains.
    Domain(String),
    /// An IP network.
    Network(IpNet),
}

/// Explicit scope and active-authorization decision for a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeGrant {
    /// Allowed target rules.
    pub rules: Vec<ScopeRule>,
    /// Whether active capabilities were explicitly authorized.
    pub active_authorized: bool,
    /// Safe label describing who supplied the scope.
    pub issuer: String,
    /// Time the decision was recorded.
    pub issued_at: OffsetDateTime,
}

impl ScopeGrant {
    /// Constructs a scope after verifying it has at least one rule.
    ///
    /// # Errors
    ///
    /// Returns `DomainError::EmptyScope` when no allow rule is supplied.
    pub fn new(
        rules: Vec<ScopeRule>,
        active_authorized: bool,
        issuer: impl Into<String>,
        issued_at: OffsetDateTime,
    ) -> Result<Self, DomainError> {
        if rules.is_empty() {
            return Err(DomainError::EmptyScope);
        }
        Ok(Self {
            rules,
            active_authorized,
            issuer: issuer.into(),
            issued_at,
        })
    }

    /// Builds the narrowest scope that contains one target.
    #[must_use]
    pub fn exact(target: &Target, active_authorized: bool, issued_at: OffsetDateTime) -> Self {
        let rule = match target {
            Target::Domain(host) | Target::HostPort { host, .. } => ScopeRule::Host(host.clone()),
            Target::Url(url) => url.host_str().map_or_else(
                || ScopeRule::Exact(target.canonical()),
                |host| ScopeRule::Host(host.into()),
            ),
            Target::Email(value) => value.rsplit_once('@').map_or_else(
                || ScopeRule::Exact(target.canonical()),
                |(_, host)| ScopeRule::Host(host.into()),
            ),
            Target::Cidr(network) => ScopeRule::Network(*network),
            Target::Ip(_) | Target::Asn(_) | Target::Opaque(_) => {
                ScopeRule::Exact(target.canonical())
            }
        };
        Self {
            rules: vec![rule],
            active_authorized,
            issuer: "operator".into(),
            issued_at,
        }
    }

    /// Returns whether the scope contains a target.
    #[must_use]
    pub fn allows(&self, target: &Target) -> bool {
        let canonical = target.canonical();
        self.rules.iter().any(|rule| match rule {
            ScopeRule::Exact(value) => value.eq_ignore_ascii_case(&canonical),
            ScopeRule::Host(expected) => target
                .host()
                .is_some_and(|host| host.eq_ignore_ascii_case(expected)),
            ScopeRule::Domain(domain) => target.host().is_some_and(|host| {
                host.eq_ignore_ascii_case(domain)
                    || host.to_ascii_lowercase().ends_with(&format!(".{domain}"))
            }),
            ScopeRule::Network(network) => match target {
                Target::Ip(address) => network.contains(address),
                Target::Cidr(candidate) => network.contains(&candidate.network()),
                _ => false,
            },
        })
    }
}

/// Immutable request delivered to a scanner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanRequest {
    /// Scanner to execute.
    pub scanner_id: ScannerId,
    /// Validated target.
    pub target: Target,
    /// Validated option values.
    pub options: BTreeMap<String, Value>,
    /// Resource limits.
    pub budget: Budget,
    /// Explicit scope and authorization decision.
    pub scope: ScopeGrant,
}

/// Finding severity set by the scanner that owns the observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    /// Informational observation.
    Info,
    /// Low-impact weakness.
    Low,
    /// Material weakness requiring review.
    Medium,
    /// High-impact weakness.
    High,
    /// Immediate critical risk.
    Critical,
}

/// Confidence in a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    /// Direct protocol or source evidence.
    Confirmed,
    /// Heuristic evidence.
    Inferred,
    /// Insufficient evidence for a conclusion.
    Unknown,
}

/// Structured source material supporting a finding or observation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Stable evidence category.
    pub kind: String,
    /// Safe source description such as a URL origin or DNS resolver label.
    pub source: String,
    /// Structured redacted observation.
    pub observation: Value,
    /// Observation timestamp.
    pub observed_at: OffsetDateTime,
}

/// One security-relevant conclusion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable finding key within the scanner.
    pub key: String,
    /// Human-readable title.
    pub title: String,
    /// Severity assigned at the source.
    pub severity: Severity,
    /// Confidence assigned at the source.
    pub confidence: Confidence,
    /// Indices into the result evidence array.
    pub evidence: Vec<usize>,
}

/// Safe operational diagnostic that is not a finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    /// Stable diagnostic kind.
    pub kind: String,
    /// Safe message suitable for users and reports.
    pub message: String,
}

/// Terminal state of an individual scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionStatus {
    /// Scanner completed normally.
    Completed,
    /// Some boundaries failed while valid evidence remained.
    Partial,
    /// Policy or unavailable dependency prevented execution.
    Skipped,
    /// Scanner failed without a valid result.
    Failed,
    /// Operator or parent run cancelled execution.
    Cancelled,
}

/// Typed output returned by one scanner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanResult {
    /// Terminal state.
    pub status: ExecutionStatus,
    /// Security conclusions.
    pub findings: Vec<Finding>,
    /// Structured observations.
    pub evidence: Vec<Evidence>,
    /// Non-finding operational diagnostics.
    pub diagnostics: Vec<Diagnostic>,
}

impl ScanResult {
    /// Constructs a successful observation result.
    #[must_use]
    pub fn completed(evidence: Vec<Evidence>, findings: Vec<Finding>) -> Self {
        Self {
            status: ExecutionStatus::Completed,
            findings,
            evidence,
            diagnostics: Vec::new(),
        }
    }

    /// Constructs a skipped result with a safe reason.
    #[must_use]
    pub fn skipped(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: ExecutionStatus::Skipped,
            findings: Vec::new(),
            evidence: Vec::new(),
            diagnostics: vec![Diagnostic {
                kind: kind.into(),
                message: message.into(),
            }],
        }
    }
}

/// Stable unique identity of one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RunId(Uuid);

impl RunId {
    /// Generates a random version-four run identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for RunId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for RunId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, formatter)
    }
}

impl FromStr for RunId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

/// Completed record for one scanner within a run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanExecution {
    /// Executed scanner.
    pub scanner_id: ScannerId,
    /// Terminal result.
    pub result: ScanResult,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

/// Canonical persisted report for a run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunReport {
    /// Report schema version.
    pub schema_version: u32,
    /// Run identity.
    pub run_id: RunId,
    /// Product version.
    pub app_version: String,
    /// Start time.
    pub started_at: OffsetDateTime,
    /// End time.
    pub finished_at: OffsetDateTime,
    /// Results in logical plan order.
    pub executions: Vec<ScanExecution>,
}

impl RunReport {
    /// Computes an aggregate terminal state without hiding partial or failed work.
    #[must_use]
    pub fn status(&self) -> ExecutionStatus {
        let mut has_partial = false;
        let mut has_failed = false;
        let mut has_cancelled = false;
        for execution in &self.executions {
            match execution.result.status {
                ExecutionStatus::Partial | ExecutionStatus::Skipped => has_partial = true,
                ExecutionStatus::Failed => has_failed = true,
                ExecutionStatus::Cancelled => has_cancelled = true,
                ExecutionStatus::Completed => {}
            }
        }
        if has_failed {
            ExecutionStatus::Failed
        } else if has_cancelled {
            ExecutionStatus::Cancelled
        } else if has_partial {
            ExecutionStatus::Partial
        } else {
            ExecutionStatus::Completed
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;

    #[test]
    fn scanner_id_rejects_non_canonical_values() {
        assert!(ScannerId::new("dns-records").is_ok());
        assert!(ScannerId::new("DNS Records").is_err());
        assert!(ScannerId::new("dns--records").is_err());
    }

    #[test]
    fn target_parsing_is_typed_and_normalized() {
        assert_eq!(
            Target::parse(TargetKind::Domain, "Example.COM.").ok(),
            Some(Target::Domain("example.com".into()))
        );
        assert!(Target::parse(TargetKind::Url, "file:///etc/passwd").is_err());
        assert!(Target::parse(TargetKind::Email, "bad address").is_err());
    }

    #[test]
    fn option_definitions_validate_shape_bounds_and_defaults() {
        let valid = OptionDefinition {
            key: "max_pages".into(),
            description: "Maximum number of same-origin pages to inspect.".into(),
            kind: OptionKind::Integer { min: 1, max: 500 },
            default: Some("100".into()),
            required: false,
        };
        assert!(valid.validate().is_ok());

        let reversed_bounds = OptionDefinition {
            kind: OptionKind::Integer { min: 500, max: 1 },
            ..valid.clone()
        };
        assert!(reversed_bounds.validate().is_err());

        let out_of_range_default = OptionDefinition {
            default: Some("501".into()),
            ..valid
        };
        assert!(out_of_range_default.validate().is_err());
    }

    #[test]
    fn published_option_catalog_is_total_unique_and_typed() -> Result<(), Box<dyn std::error::Error>>
    {
        let contracts = published_scanner_option_contracts()?;
        assert_eq!(contracts.len(), PUBLISHED_SCANNER_OPTION_CONTRACT_COUNT);
        let unique_ids: BTreeSet<_> = contracts
            .iter()
            .map(|contract| contract.scanner_id.as_str())
            .collect();
        assert_eq!(unique_ids.len(), PUBLISHED_SCANNER_OPTION_CONTRACT_COUNT);
        assert!(
            contracts
                .iter()
                .flat_map(|contract| &contract.options)
                .all(|option| option.validate().is_ok())
        );
        assert_eq!(
            contracts
                .iter()
                .map(|contract| contract.options.len())
                .sum::<usize>(),
            90
        );

        let broken_links = contracts
            .iter()
            .find(|contract| contract.scanner_id.as_str() == "broken-links")
            .ok_or_else(|| io::Error::other("broken-links contract is missing"))?;
        assert_eq!(broken_links.options.len(), 3);
        let sample_ratio = broken_links
            .options
            .iter()
            .find(|option| option.key == "sample_ratio")
            .ok_or_else(|| io::Error::other("sample_ratio contract is missing"))?;
        assert!(matches!(sample_ratio.kind, OptionKind::Text { max_len: 8 }));
        assert_eq!(sample_ratio.default.as_deref(), Some("0.15"));

        let server_info = contracts
            .iter()
            .find(|contract| contract.scanner_id.as_str() == "server-info")
            .ok_or_else(|| io::Error::other("server-info contract is missing"))?;
        assert!(server_info.options.is_empty());
        assert!(
            scanner_options(&server_info.scanner_id)?.is_some_and(|options| options.is_empty())
        );
        let outside_cohort = ScannerId::new("dns-records")?;
        assert!(scanner_options(&outside_cohort)?.is_none());
        Ok(())
    }

    #[test]
    fn scanner_descriptors_reject_duplicate_or_invalid_options() {
        let option = OptionDefinition {
            key: "timeout".into(),
            description: "Per-request timeout in seconds.".into(),
            kind: OptionKind::Integer { min: 1, max: 300 },
            default: Some("10".into()),
            required: false,
        };
        let descriptor = ScannerDescriptor {
            id: ScannerId::new("http-headers")
                .unwrap_or_else(|error| unreachable!("valid test scanner ID: {error}")),
            legacy_id: Some(LegacyId::Catalog(99)),
            name: "HTTP Headers".into(),
            description: "Inspect HTTP response headers.".into(),
            track: "web-observation".into(),
            target_kinds: vec![TargetKind::Domain, TargetKind::Url],
            capabilities: vec![Capability::ActiveHttpSafe],
            options: vec![option.clone()],
            version: "1".into(),
        };
        assert!(descriptor.validate().is_ok());

        let duplicate = ScannerDescriptor {
            options: vec![option.clone(), option],
            ..descriptor
        };
        assert!(duplicate.validate().is_err());
    }

    #[test]
    fn domain_scope_includes_subdomains_but_not_suffix_tricks() {
        let scope = ScopeGrant::new(
            vec![ScopeRule::Domain("example.com".into())],
            false,
            "test",
            OffsetDateTime::UNIX_EPOCH,
        )
        .unwrap_or_else(|error| unreachable!("valid test scope: {error}"));
        let child = Target::parse(TargetKind::Domain, "a.example.com")
            .unwrap_or_else(|error| unreachable!("valid test domain: {error}"));
        let trick = Target::parse(TargetKind::Domain, "notexample.com")
            .unwrap_or_else(|error| unreachable!("valid test domain: {error}"));
        assert!(scope.allows(&child));
        assert!(!scope.allows(&trick));
    }

    #[test]
    fn aggregate_status_preserves_failure() {
        let report = RunReport {
            schema_version: 1,
            run_id: RunId::new(),
            app_version: "test".into(),
            started_at: OffsetDateTime::UNIX_EPOCH,
            finished_at: OffsetDateTime::UNIX_EPOCH,
            executions: vec![ScanExecution {
                scanner_id: ScannerId::new("dns-records")
                    .unwrap_or_else(|error| unreachable!("valid test ID: {error}")),
                result: ScanResult {
                    status: ExecutionStatus::Failed,
                    findings: Vec::new(),
                    evidence: Vec::new(),
                    diagnostics: Vec::new(),
                },
                duration_ms: 1,
            }],
        };
        assert_eq!(report.status(), ExecutionStatus::Failed);
    }
}
