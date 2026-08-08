//! Narrow I/O boundaries consumed by scanner implementations.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sugra_domain::{Budget, ScopeGrant, Target};
use thiserror::Error;
use time::OffsetDateTime;
use url::Url;

/// Categories of boundary failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PortErrorKind {
    /// Internal adapter invariant failed before exposing sensitive detail.
    Internal,
    /// An optional tool, provider, or credential is unavailable.
    Unavailable,
    /// The configured time budget expired.
    Timeout,
    /// A response could not be parsed or violated its protocol.
    InvalidResponse,
    /// A provider rejected the request because of a rate limit.
    RateLimited,
    /// Transport failed before a valid response was received.
    Transport,
    /// A redirect or resolved endpoint left the declared scope.
    OutOfScope,
    /// A response exceeded its byte budget.
    TooLarge,
}

/// Safe boundary error without request secrets or response bodies.
#[derive(Debug, Clone, PartialEq, Eq, Error, Serialize, Deserialize)]
#[error("{message}")]
pub struct PortError {
    /// Stable failure category.
    pub kind: PortErrorKind,
    /// Safe user-facing message.
    pub message: String,
    /// Retry delay advertised by a provider, when present.
    pub retry_after_ms: Option<u64>,
}

impl PortError {
    /// Constructs a boundary error with no retry hint.
    #[must_use]
    pub fn new(kind: PortErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            retry_after_ms: None,
        }
    }
}

/// Supported public DNS record types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsRecordType {
    /// IPv4 address.
    A,
    /// IPv6 address.
    Aaaa,
    /// Canonical name.
    Cname,
    /// Mail exchanger.
    Mx,
    /// Authoritative name server.
    Ns,
    /// Start of authority.
    Soa,
    /// Text record.
    Txt,
    /// Service locator.
    Srv,
    /// Certificate authority authorization.
    Caa,
    /// Domain security key.
    Dnskey,
    /// Delegation signer.
    Ds,
    /// Reverse pointer.
    Ptr,
}

impl DnsRecordType {
    /// Returns the conventional uppercase DNS spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Ns => "NS",
            Self::Soa => "SOA",
            Self::Txt => "TXT",
            Self::Srv => "SRV",
            Self::Caa => "CAA",
            Self::Dnskey => "DNSKEY",
            Self::Ds => "DS",
            Self::Ptr => "PTR",
        }
    }
}

/// A bounded DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    /// Name to resolve.
    pub name: String,
    /// Requested record types.
    pub record_types: Vec<DnsRecordType>,
    /// Shared resource limits.
    pub budget: Budget,
}

/// Normalized DNS response item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    /// Queried or returned owner name.
    pub name: String,
    /// Record type.
    pub record_type: DnsRecordType,
    /// Normalized presentation value.
    pub value: String,
    /// Time to live in seconds when exposed by the resolver.
    pub ttl: Option<u32>,
}

/// DNS resolution boundary.
#[async_trait]
pub trait DnsPort: Send + Sync {
    /// Resolves a bounded set of record types.
    async fn query(&self, query: DnsQuery) -> Result<Vec<DnsRecord>, PortError>;
}

/// HTTP verbs available to scanners.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// GET request.
    Get,
    /// HEAD request.
    Head,
    /// OPTIONS request.
    Options,
    /// POST request with an explicitly supplied bounded body.
    Post,
}

/// A bounded HTTP operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// Absolute HTTP or HTTPS URL.
    pub url: Url,
    /// Request method.
    pub method: HttpMethod,
    /// Safe headers; secret values must be injected inside the concrete boundary.
    pub headers: BTreeMap<String, String>,
    /// Optional bounded body.
    pub body: Vec<u8>,
    /// Maximum redirects to follow.
    pub max_redirects: usize,
    /// Shared resource limits.
    pub budget: Budget,
    /// Scope applied to the initial URL and every redirect.
    pub scope: ScopeGrant,
}

/// Safe metadata for one `Set-Cookie` response header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpCookie {
    /// SHA-256 fingerprint of the cookie name; the value is never retained.
    pub name_sha256: String,
    /// Declared cookie domain, when present.
    pub domain: Option<String>,
    /// Declared cookie path, when present.
    pub path: Option<String>,
    /// Whether the `Secure` attribute is present.
    pub secure: bool,
    /// Whether the `HttpOnly` attribute is present.
    pub http_only: bool,
    /// Normalized `SameSite` attribute, when present.
    pub same_site: Option<String>,
    /// Declared maximum lifetime in seconds, when present.
    pub max_age_seconds: Option<i64>,
}

/// One manually validated HTTP redirect hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRedirect {
    /// Redirect response status.
    pub status: u16,
    /// URL that returned the redirect.
    pub from: Url,
    /// Scoped destination resolved from `Location`.
    pub to: Url,
    /// Whether and why the boundary followed the destination.
    pub decision: HttpRedirectDecision,
}

/// Safety decision for one redirect destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HttpRedirectDecision {
    /// Destination was in scope and followed.
    Followed,
    /// Destination was recorded but not contacted because it was out of scope.
    OutOfScope,
    /// Destination was recorded but not contacted because the hop limit was reached.
    LimitReached,
}

/// Normalized HTTP response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    /// Final URL after allowed redirects.
    pub final_url: Url,
    /// HTTP status code.
    pub status: u16,
    /// Lowercase response headers with redacted values where required.
    pub headers: BTreeMap<String, String>,
    /// Redacted metadata for every response cookie.
    pub cookies: Vec<HttpCookie>,
    /// Redirect hops followed by the boundary.
    pub redirects: Vec<HttpRedirect>,
    /// Bounded response body.
    pub body: Vec<u8>,
    /// Observed duration in milliseconds.
    pub duration_ms: u64,
}

/// HTTP boundary.
#[async_trait]
pub trait HttpPort: Send + Sync {
    /// Performs a bounded HTTP operation.
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError>;
}

/// A bounded TCP operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpRequest {
    /// Host name or address.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Optional request bytes.
    pub payload: Vec<u8>,
    /// Whether one bounded response read is required after connecting.
    pub read_response: bool,
    /// Shared resource limits.
    pub budget: Budget,
    /// Scope applied before name resolution or connection.
    pub scope: ScopeGrant,
}

/// Bounded TCP response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpResponse {
    /// Remote endpoint label.
    pub endpoint: String,
    /// Received bytes, capped by the budget.
    pub bytes: Vec<u8>,
    /// Observed duration in milliseconds.
    pub duration_ms: u64,
}

/// TCP boundary.
#[async_trait]
pub trait TcpPort: Send + Sync {
    /// Connects, optionally writes a payload, and reads a bounded response.
    async fn execute(&self, request: TcpRequest) -> Result<TcpResponse, PortError>;
}

/// A bounded UDP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpRequest {
    /// Host name or address.
    pub host: String,
    /// UDP port.
    pub port: u16,
    /// Datagram bytes.
    pub payload: Vec<u8>,
    /// Shared resource limits.
    pub budget: Budget,
    /// Scope applied before name resolution or send.
    pub scope: ScopeGrant,
}

/// Bounded UDP response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpResponse {
    /// Remote endpoint label.
    pub endpoint: String,
    /// Received datagram bytes.
    pub bytes: Vec<u8>,
    /// Observed duration in milliseconds.
    pub duration_ms: u64,
}

/// UDP boundary.
#[async_trait]
pub trait UdpPort: Send + Sync {
    /// Sends one datagram and waits for one bounded response.
    async fn execute(&self, request: UdpRequest) -> Result<UdpResponse, PortError>;
}

/// A validated TLS handshake request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRequest {
    /// Host name or address used to establish the scoped connection.
    pub host: String,
    /// Optional DNS name used for SNI and certificate validation.
    pub server_name: Option<String>,
    /// TLS port, normally 443.
    pub port: u16,
    /// Shared resource limits.
    pub budget: Budget,
    /// Scope applied before connecting.
    pub scope: ScopeGrant,
}

/// Parsed metadata for one validated peer certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsCertificate {
    /// Lowercase SHA-256 fingerprint of the DER certificate.
    pub sha256: String,
    /// Distinguished subject name.
    pub subject: String,
    /// Distinguished issuer name.
    pub issuer: String,
    /// Printable certificate serial number.
    pub serial: String,
    /// Validity start as a Unix timestamp.
    pub not_before: i64,
    /// Validity end as a Unix timestamp.
    pub not_after: i64,
    /// Bounded DNS subject alternative names.
    pub dns_names: Vec<String>,
    /// Signature algorithm object identifier.
    pub signature_algorithm: String,
    /// Subject public-key algorithm object identifier.
    pub public_key_algorithm: String,
    /// Whether Basic Constraints identifies a certificate authority.
    pub is_ca: Option<bool>,
}

/// Negotiated TLS handshake mode without exposing library-specific types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TlsHandshakeKind {
    /// A complete handshake was performed.
    Full,
    /// A complete handshake required a `HelloRetryRequest` round trip.
    FullWithHelloRetryRequest,
    /// A previously established session was resumed.
    Resumed,
    /// The TLS backend did not expose the handshake mode.
    Unknown,
}

/// Safe metadata from a validated TLS handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsObservation {
    /// Whether the connection used a full or resumed handshake.
    pub handshake_kind: TlsHandshakeKind,
    /// Negotiated protocol version.
    pub protocol: String,
    /// Negotiated cipher suite.
    pub cipher_suite: String,
    /// Negotiated application protocol, when present.
    pub alpn: Option<String>,
    /// SHA-256 fingerprints of the peer certificate chain.
    pub certificate_sha256: Vec<String>,
    /// Parsed bounded metadata for the peer certificate chain.
    pub certificates: Vec<TlsCertificate>,
    /// Observed duration in milliseconds.
    pub duration_ms: u64,
}

/// Certificate-validating TLS boundary.
#[async_trait]
pub trait TlsPort: Send + Sync {
    /// Connects and performs one validated TLS handshake.
    async fn handshake(&self, request: TlsRequest) -> Result<TlsObservation, PortError>;
}

/// Allowlisted operating-system command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandKind {
    /// ICMP reachability through the platform ping utility.
    Ping,
    /// Route discovery through traceroute or tracert.
    Traceroute,
    /// Public registration query through whois.
    Whois,
    /// Public SSH host-key collection through ssh-keyscan.
    SshKeyscan,
}

/// Bounded allowlisted command request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRequest {
    /// Allowlisted operation.
    pub kind: CommandKind,
    /// Validated host, address, or domain argument.
    pub target: Target,
    /// Shared resource limits.
    pub budget: Budget,
    /// Scope applied before process creation.
    pub scope: ScopeGrant,
}

/// Safe bounded command output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandResponse {
    /// Process exit code when available.
    pub exit_code: Option<i32>,
    /// UTF-8-lossy stdout capped by the byte budget.
    pub stdout: String,
    /// UTF-8-lossy stderr capped by the byte budget.
    pub stderr: String,
    /// Observed duration in milliseconds.
    pub duration_ms: u64,
}

/// Allowlisted local command boundary.
#[async_trait]
pub trait CommandPort: Send + Sync {
    /// Runs one allowlisted platform command without a shell.
    async fn execute(&self, request: CommandRequest) -> Result<CommandResponse, PortError>;
}

/// One explicit, bounded local text-file read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalInputRequest {
    /// Absolute path selected by the operator.
    pub path: PathBuf,
    /// Shared byte and line limits.
    pub budget: Budget,
}

/// Normalized lines read from a local input file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalInputResponse {
    /// UTF-8 lines without line terminators.
    pub lines: Vec<String>,
}

/// Bounded local text-input boundary.
#[async_trait]
pub trait LocalInputPort: Send + Sync {
    /// Reads one explicitly selected regular file without exposing its path in errors.
    async fn read_lines(&self, request: LocalInputRequest)
    -> Result<LocalInputResponse, PortError>;
}

/// Generic request to an optional intelligence provider.
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderRequest {
    /// Stable provider key.
    pub provider: String,
    /// Operation key understood by the configured provider.
    pub operation: String,
    /// Structured non-secret query values.
    pub query: BTreeMap<String, Value>,
    /// Name of the environment variable containing a credential, when required.
    pub secret_env: Option<String>,
    /// Shared resource limits.
    pub budget: Budget,
}

/// Normalized provider response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderResponse {
    /// Stable provider key.
    pub provider: String,
    /// Structured redacted response.
    pub data: Value,
    /// Observed duration in milliseconds.
    pub duration_ms: u64,
}

/// Optional intelligence-provider boundary.
#[async_trait]
pub trait ProviderPort: Send + Sync {
    /// Queries a configured provider.
    async fn query(&self, request: ProviderRequest) -> Result<ProviderResponse, PortError>;
}

/// Injectable clock for deterministic evidence and reports.
pub trait Clock: Send + Sync {
    /// Returns the current UTC time.
    fn now(&self) -> OffsetDateTime;
}

/// Shared boundary implementations injected into built-in scanners.
#[derive(Clone)]
pub struct ServiceBundle {
    /// DNS resolver boundary.
    pub dns: Arc<dyn DnsPort>,
    /// HTTP client boundary.
    pub http: Arc<dyn HttpPort>,
    /// TCP client boundary.
    pub tcp: Arc<dyn TcpPort>,
    /// UDP client boundary.
    pub udp: Arc<dyn UdpPort>,
    /// TLS handshake boundary.
    pub tls: Arc<dyn TlsPort>,
    /// Allowlisted local command boundary.
    pub command: Arc<dyn CommandPort>,
    /// Intelligence-provider boundary.
    pub provider: Arc<dyn ProviderPort>,
    /// Explicit bounded local text-input boundary.
    pub local_input: Arc<dyn LocalInputPort>,
    /// Clock boundary.
    pub clock: Arc<dyn Clock>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_errors_have_a_safe_message_and_no_implicit_retry() {
        let error = PortError::new(
            PortErrorKind::RateLimited,
            "provider rate limited the request",
        );
        assert_eq!(error.kind, PortErrorKind::RateLimited);
        assert_eq!(error.message, "provider rate limited the request");
        assert_eq!(error.retry_after_ms, None);
        assert_eq!(error.to_string(), "provider rate limited the request");
    }

    #[test]
    fn dns_record_type_spellings_are_complete_and_stable() {
        let cases = [
            (DnsRecordType::A, "A"),
            (DnsRecordType::Aaaa, "AAAA"),
            (DnsRecordType::Cname, "CNAME"),
            (DnsRecordType::Mx, "MX"),
            (DnsRecordType::Ns, "NS"),
            (DnsRecordType::Soa, "SOA"),
            (DnsRecordType::Txt, "TXT"),
            (DnsRecordType::Srv, "SRV"),
            (DnsRecordType::Caa, "CAA"),
            (DnsRecordType::Dnskey, "DNSKEY"),
            (DnsRecordType::Ds, "DS"),
            (DnsRecordType::Ptr, "PTR"),
        ];
        for (record_type, spelling) in cases {
            assert_eq!(record_type.as_str(), spelling);
        }
    }
}
