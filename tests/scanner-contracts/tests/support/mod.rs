use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use serde_json::json;
use sugra_core::{
    Clock, CommandPort, CommandRequest, CommandResponse, DnsPort, DnsQuery, DnsRecord,
    DnsRecordType, HttpPort, HttpRequest, HttpResponse, PortError, PortErrorKind, ProviderPort,
    ProviderRequest, ProviderResponse, ScanContext, ServiceBundle, TcpPort, TcpRequest,
    TcpResponse, TlsCertificate, TlsHandshakeKind, TlsObservation, TlsPort, TlsRequest, UdpPort,
    UdpRequest, UdpResponse, resolve_options,
};
use sugra_domain::{Budget, RunId, ScanRequest, ScannerDescriptor, ScopeGrant, Target, TargetKind};
use sugra_scanner_contracts::Boundary;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

pub const SECRET_MARKER: &str = "contract-fixture-secret-7f31";

#[derive(Debug, Clone, Copy)]
enum Mode {
    Successful,
    Failing,
}

#[derive(Debug, Default)]
struct Calls {
    dns: AtomicUsize,
    http: AtomicUsize,
    tcp: AtomicUsize,
    udp: AtomicUsize,
    tls: AtomicUsize,
    command: AtomicUsize,
    provider: AtomicUsize,
}

impl Calls {
    fn increment(&self, boundary: Boundary) {
        if let Some(counter) = self.counter(boundary) {
            counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn counter(&self, boundary: Boundary) -> Option<&AtomicUsize> {
        match boundary {
            Boundary::Dns => Some(&self.dns),
            Boundary::Http => Some(&self.http),
            Boundary::Tcp => Some(&self.tcp),
            Boundary::Udp => Some(&self.udp),
            Boundary::Tls => Some(&self.tls),
            Boundary::Command => Some(&self.command),
            Boundary::Provider => Some(&self.provider),
            Boundary::Local => None,
        }
    }

    fn reset(&self) {
        for boundary in EXTERNAL_BOUNDARIES {
            if let Some(counter) = self.counter(boundary) {
                counter.store(0, Ordering::SeqCst);
            }
        }
    }

    fn snapshot(&self) -> BTreeMap<Boundary, usize> {
        EXTERNAL_BOUNDARIES
            .into_iter()
            .filter_map(|boundary| {
                self.counter(boundary)
                    .map(|counter| (boundary, counter.load(Ordering::SeqCst)))
            })
            .collect()
    }
}

const EXTERNAL_BOUNDARIES: [Boundary; 7] = [
    Boundary::Dns,
    Boundary::Http,
    Boundary::Tcp,
    Boundary::Udp,
    Boundary::Tls,
    Boundary::Command,
    Boundary::Provider,
];

#[derive(Clone)]
pub struct Harness {
    calls: Arc<Calls>,
    mode: Mode,
}

impl Harness {
    pub fn successful() -> Self {
        Self {
            calls: Arc::default(),
            mode: Mode::Successful,
        }
    }

    pub fn failing() -> Self {
        Self {
            calls: Arc::default(),
            mode: Mode::Failing,
        }
    }

    pub fn services(&self) -> ServiceBundle {
        ServiceBundle {
            dns: Arc::new(FakeDns(self.clone())),
            http: Arc::new(FakeHttp(self.clone())),
            tcp: Arc::new(FakeTcp(self.clone())),
            udp: Arc::new(FakeUdp(self.clone())),
            tls: Arc::new(FakeTls(self.clone())),
            command: Arc::new(FakeCommand(self.clone())),
            provider: Arc::new(FakeProvider(self.clone())),
            clock: Arc::new(FixedClock),
        }
    }

    pub fn reset(&self) {
        self.calls.reset();
    }

    pub fn observed_boundaries(&self) -> BTreeMap<Boundary, usize> {
        self.calls.snapshot()
    }

    fn record(&self, boundary: Boundary) -> Result<(), PortError> {
        self.calls.increment(boundary);
        match self.mode {
            Mode::Successful => Ok(()),
            Mode::Failing => Err(PortError::new(
                PortErrorKind::Transport,
                "offline fixture boundary failure",
            )),
        }
    }
}

#[derive(Clone, Copy)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }
}

struct FakeDns(Harness);

#[async_trait]
impl DnsPort for FakeDns {
    async fn query(&self, query: DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
        self.0.record(Boundary::Dns)?;
        Ok(vec![DnsRecord {
            name: query.name,
            record_type: query
                .record_types
                .first()
                .copied()
                .unwrap_or(DnsRecordType::A),
            value: "192.0.2.1".into(),
            ttl: Some(300),
        }])
    }
}

struct FakeHttp(Harness);

#[async_trait]
impl HttpPort for FakeHttp {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
        self.0.record(Boundary::Http)?;
        Ok(HttpResponse {
            final_url: request.url,
            status: 200,
            headers: BTreeMap::from([
                ("content-type".into(), "text/html".into()),
                (
                    "content-security-policy".into(),
                    "default-src 'self'".into(),
                ),
                (
                    "strict-transport-security".into(),
                    "max-age=31536000".into(),
                ),
                ("x-content-type-options".into(), "nosniff".into()),
            ]),
            cookies: Vec::new(),
            redirects: Vec::new(),
            body: format!("<html><title>Fixture</title><!-- token={SECRET_MARKER} --></html>")
                .into_bytes(),
            duration_ms: 1,
        })
    }
}

struct FakeTcp(Harness);

#[async_trait]
impl TcpPort for FakeTcp {
    async fn execute(&self, request: TcpRequest) -> Result<TcpResponse, PortError> {
        self.0.record(Boundary::Tcp)?;
        Ok(TcpResponse {
            endpoint: format!("{}:{}", request.host, request.port),
            bytes: format!("fixture-banner {SECRET_MARKER}").into_bytes(),
            duration_ms: 1,
        })
    }
}

struct FakeUdp(Harness);

#[async_trait]
impl UdpPort for FakeUdp {
    async fn execute(&self, request: UdpRequest) -> Result<UdpResponse, PortError> {
        self.0.record(Boundary::Udp)?;
        let mut bytes = vec![0_u8; 48];
        bytes[0] = 0x24;
        bytes[1] = 2;
        Ok(UdpResponse {
            endpoint: format!("{}:{}", request.host, request.port),
            bytes,
            duration_ms: 1,
        })
    }
}

struct FakeTls(Harness);

#[async_trait]
impl TlsPort for FakeTls {
    async fn handshake(&self, _request: TlsRequest) -> Result<TlsObservation, PortError> {
        self.0.record(Boundary::Tls)?;
        Ok(TlsObservation {
            handshake_kind: TlsHandshakeKind::Full,
            protocol: "TLSv1_3".into(),
            cipher_suite: "TLS_AES_256_GCM_SHA384".into(),
            alpn: Some("h2".into()),
            certificate_sha256: vec!["00".repeat(32)],
            certificates: vec![TlsCertificate {
                sha256: "00".repeat(32),
                subject: "CN=example.com".into(),
                issuer: "CN=Fixture CA".into(),
                serial: "01".into(),
                not_before: -86_400,
                not_after: 31_536_000,
                dns_names: vec!["example.com".into()],
                signature_algorithm: "1.2.840.113549.1.1.11".into(),
                public_key_algorithm: "1.2.840.113549.1.1.1".into(),
                is_ca: Some(false),
            }],
            duration_ms: 1,
        })
    }
}

struct FakeCommand(Harness);

#[async_trait]
impl CommandPort for FakeCommand {
    async fn execute(&self, _request: CommandRequest) -> Result<CommandResponse, PortError> {
        self.0.record(Boundary::Command)?;
        Ok(CommandResponse {
            exit_code: Some(0),
            stdout: "fixture command output".into(),
            stderr: format!("token={SECRET_MARKER}"),
            duration_ms: 1,
        })
    }
}

struct FakeProvider(Harness);

#[async_trait]
impl ProviderPort for FakeProvider {
    async fn query(&self, request: ProviderRequest) -> Result<ProviderResponse, PortError> {
        self.0.record(Boundary::Provider)?;
        Ok(ProviderResponse {
            provider: request.provider,
            data: json!({"fixture": true, "api_token": SECRET_MARKER}),
            duration_ms: 1,
        })
    }
}

pub fn request_for(
    descriptor: &ScannerDescriptor,
) -> Result<ScanRequest, Box<dyn std::error::Error>> {
    let kind = descriptor
        .target_kinds
        .first()
        .copied()
        .ok_or("scanner descriptor has no target kind")?;
    let target = target_for(kind, descriptor.id.as_str())?;
    let budget = Budget {
        timeout_ms: 1_000,
        concurrency: 1,
        max_requests: 8,
        max_response_bytes: 64 * 1024,
        max_depth: 1,
    }
    .validate()?;
    Ok(ScanRequest {
        scanner_id: descriptor.id.clone(),
        options: resolve_options(&descriptor.options, &BTreeMap::new())?,
        scope: ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH),
        target,
        budget,
    })
}

pub fn context(cancelled: bool) -> ScanContext {
    let cancellation = CancellationToken::new();
    if cancelled {
        cancellation.cancel();
    }
    ScanContext {
        run_id: RunId::new(),
        cancellation,
        clock: Arc::new(FixedClock),
    }
}

fn target_for(kind: TargetKind, id: &str) -> Result<Target, Box<dyn std::error::Error>> {
    let input = match kind {
        TargetKind::Domain => "example.com",
        TargetKind::Ip => "192.0.2.10",
        TargetKind::Cidr => "192.0.2.0/30",
        TargetKind::Url => "https://example.com/",
        TargetKind::HostPort => "example.com:443",
        TargetKind::Asn => "AS64496",
        TargetKind::Email => "security@example.com",
        TargetKind::Opaque if id == "jwt-token-analyzer" => {
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiJmaXh0dXJlIn0.c2lnbmF0dXJl"
        }
        TargetKind::Opaque => "example-fixture",
    };
    Ok(Target::parse(kind, input)?)
}
