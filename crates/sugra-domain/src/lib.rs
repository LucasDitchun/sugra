//! Immutable values and invariants shared by every Sugra component.

use std::collections::BTreeMap;
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
