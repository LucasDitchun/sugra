//! Public offline contracts for truthful DNS recursion and HTTP protocol observations.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sugra_core::{
    DnsFlagState, DnsPort, DnsQuery, DnsRecord, DnsRecursionObservation, DnsRecursionRequest,
    PortError, PortErrorKind, QuicObservation, QuicRequest, ScanError, ScanErrorKind,
    TlsCertificate, TlsHandshakeKind, TlsObservation, TlsPort, TlsRequest,
};
use sugra_domain::{
    Budget, Confidence, ExecutionStatus, ScanResult, ScopeGrant, ScopeRule, Severity, Target,
    TargetKind,
};
use sugra_scanners::build_builtins;
use tokio_util::sync::CancellationToken;

#[allow(dead_code)]
mod support;

struct RecursionDns {
    observation: DnsRecursionObservation,
    requests: Arc<Mutex<Vec<DnsRecursionRequest>>>,
}

struct ScopeFilteringDns {
    requests: Arc<Mutex<Vec<DnsRecursionRequest>>>,
}

struct ErrorDns(PortErrorKind);

#[async_trait]
impl DnsPort for ErrorDns {
    async fn query(&self, query: DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
        Ok(nameserver_records(&query.name))
    }

    async fn probe_recursion(
        &self,
        _request: DnsRecursionRequest,
    ) -> Result<DnsRecursionObservation, PortError> {
        Err(PortError::new(
            self.0,
            format!("offline {:?} DNS recursion failure", self.0),
        ))
    }
}

struct ProtocolTls {
    tls_result: Result<TlsObservation, PortError>,
    quic_result: Result<QuicObservation, PortError>,
    tls_requests: Arc<Mutex<Vec<TlsRequest>>>,
    quic_requests: Arc<Mutex<Vec<QuicRequest>>>,
}

struct CancellingProtocolTls {
    cancellation: CancellationToken,
    quic_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl TlsPort for CancellingProtocolTls {
    async fn handshake(&self, _request: TlsRequest) -> Result<TlsObservation, PortError> {
        self.cancellation.cancel();
        Ok(tls_observation(Some("h2")))
    }

    async fn handshake_quic(&self, _request: QuicRequest) -> Result<QuicObservation, PortError> {
        self.quic_calls.fetch_add(1, Ordering::SeqCst);
        Ok(quic_observation(Some("h3"), None))
    }
}

#[async_trait]
impl TlsPort for ProtocolTls {
    async fn handshake(&self, request: TlsRequest) -> Result<TlsObservation, PortError> {
        self.tls_requests
            .lock()
            .map_err(|_| {
                PortError::new(
                    sugra_core::PortErrorKind::Internal,
                    "fixture TLS request log is unavailable",
                )
            })?
            .push(request);
        self.tls_result.clone()
    }

    async fn handshake_quic(&self, request: QuicRequest) -> Result<QuicObservation, PortError> {
        self.quic_requests
            .lock()
            .map_err(|_| {
                PortError::new(
                    sugra_core::PortErrorKind::Internal,
                    "fixture QUIC request log is unavailable",
                )
            })?
            .push(request);
        self.quic_result.clone()
    }
}

fn tls_observation(alpn: Option<&str>) -> TlsObservation {
    TlsObservation {
        handshake_kind: TlsHandshakeKind::Full,
        protocol: "TLSv1_3".into(),
        cipher_suite: "TLS_AES_256_GCM_SHA384".into(),
        alpn: alpn.map(str::to_owned),
        certificate_sha256: vec!["00".repeat(32)],
        certificates: vec![TlsCertificate {
            sha256: "00".repeat(32),
            subject: "CN=example.com".into(),
            issuer: format!("CN={}", support::SECRET_MARKER),
            serial: "01".into(),
            not_before: -86_400,
            not_after: 31_536_000,
            dns_names: vec!["example.com".into()],
            signature_algorithm: "1.2.840.113549.1.1.11".into(),
            public_key_algorithm: "1.2.840.113549.1.1.1".into(),
            is_ca: Some(false),
        }],
        duration_ms: 2,
    }
}

fn quic_observation(alpn: Option<&str>, version: Option<&str>) -> QuicObservation {
    QuicObservation {
        alpn: alpn.map(str::to_owned),
        version: version.map(str::to_owned),
        duration_ms: 3,
    }
}

async fn run_recursion(
    observation: DnsRecursionObservation,
    cancelled: bool,
) -> Result<
    (
        Result<ScanResult, ScanError>,
        Arc<Mutex<Vec<DnsRecursionRequest>>>,
    ),
    Box<dyn std::error::Error>,
> {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut services = support::Harness::successful().services();
    services.dns = Arc::new(RecursionDns {
        observation,
        requests: Arc::clone(&requests),
    });
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new("recursive-nameserver-leak-test")?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("scanner missing")?;
    let mut request = support::request_for(scanner.descriptor())?;
    authorize_nameserver(&mut request)?;
    Ok((
        scanner.scan(&request, &support::context(cancelled)).await,
        requests,
    ))
}

async fn run_protocol(
    tls_result: Result<TlsObservation, PortError>,
    quic_result: Result<QuicObservation, PortError>,
    max_requests: usize,
    cancelled: bool,
    target: Option<Target>,
) -> Result<
    (
        Result<ScanResult, ScanError>,
        Arc<Mutex<Vec<TlsRequest>>>,
        Arc<Mutex<Vec<QuicRequest>>>,
    ),
    Box<dyn std::error::Error>,
> {
    let tls_requests = Arc::new(Mutex::new(Vec::new()));
    let quic_requests = Arc::new(Mutex::new(Vec::new()));
    let mut services = support::Harness::successful().services();
    services.tls = Arc::new(ProtocolTls {
        tls_result,
        quic_result,
        tls_requests: Arc::clone(&tls_requests),
        quic_requests: Arc::clone(&quic_requests),
    });
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new("http2-http3-checker")?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("scanner missing")?;
    let mut request = support::request_for(scanner.descriptor())?;
    request.budget = Budget {
        max_requests,
        ..request.budget
    }
    .validate()?;
    if let Some(target) = target {
        request.scope = ScopeGrant::exact(&target, true, time::OffsetDateTime::UNIX_EPOCH);
        request.target = target;
    }
    Ok((
        scanner.scan(&request, &support::context(cancelled)).await,
        tls_requests,
        quic_requests,
    ))
}

fn error_matrix() -> [(PortErrorKind, ScanErrorKind); 8] {
    [
        (PortErrorKind::Internal, ScanErrorKind::Internal),
        (
            PortErrorKind::Unavailable,
            ScanErrorKind::DependencyUnavailable,
        ),
        (PortErrorKind::Timeout, ScanErrorKind::Timeout),
        (
            PortErrorKind::InvalidResponse,
            ScanErrorKind::InvalidResponse,
        ),
        (PortErrorKind::RateLimited, ScanErrorKind::Timeout),
        (PortErrorKind::Transport, ScanErrorKind::Transport),
        (PortErrorKind::OutOfScope, ScanErrorKind::PolicyDenied),
        (PortErrorKind::TooLarge, ScanErrorKind::InvalidResponse),
    ]
}

#[async_trait]
impl DnsPort for RecursionDns {
    async fn query(&self, query: DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
        Ok(nameserver_records(&query.name))
    }

    async fn probe_recursion(
        &self,
        request: DnsRecursionRequest,
    ) -> Result<DnsRecursionObservation, PortError> {
        self.requests
            .lock()
            .map_err(|_| {
                PortError::new(
                    sugra_core::PortErrorKind::Internal,
                    "fixture request log is unavailable",
                )
            })?
            .push(request);
        Ok(self.observation.clone())
    }
}

#[async_trait]
impl DnsPort for ScopeFilteringDns {
    async fn query(&self, query: DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
        Ok(["aaa.outside.example.", "ns1.example.net."]
            .into_iter()
            .map(|value| DnsRecord {
                name: query.name.clone(),
                record_type: sugra_core::DnsRecordType::Ns,
                value: value.into(),
                ttl: Some(300),
            })
            .collect())
    }

    async fn probe_recursion(
        &self,
        request: DnsRecursionRequest,
    ) -> Result<DnsRecursionObservation, PortError> {
        self.requests
            .lock()
            .map_err(|_| PortError::new(PortErrorKind::Internal, "fixture lock unavailable"))?
            .push(request);
        Ok(DnsRecursionObservation {
            recursion_desired: DnsFlagState::Set,
            recursion_available: DnsFlagState::Set,
            response_code: 3,
            authoritative: DnsFlagState::Unset,
            truncated: DnsFlagState::Unset,
            answer_count: 0,
            duration_ms: 1,
        })
    }
}

fn nameserver_records(domain: &str) -> Vec<DnsRecord> {
    vec![DnsRecord {
        name: domain.into(),
        record_type: sugra_core::DnsRecordType::Ns,
        value: "ns1.example.net.".into(),
        ttl: Some(300),
    }]
}

fn authorize_nameserver(
    request: &mut sugra_domain::ScanRequest,
) -> Result<(), sugra_domain::DomainError> {
    request.scope = ScopeGrant::new(
        vec![
            ScopeRule::Host("example.com".into()),
            ScopeRule::Host("ns1.example.net".into()),
        ],
        true,
        "offline-contract",
        time::OffsetDateTime::UNIX_EPOCH,
    )?;
    Ok(())
}

#[tokio::test]
async fn recursive_nameserver_positive_observes_selected_server_flags()
-> Result<(), Box<dyn std::error::Error>> {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut services = support::Harness::successful().services();
    services.dns = Arc::new(RecursionDns {
        observation: DnsRecursionObservation {
            recursion_desired: DnsFlagState::Set,
            recursion_available: DnsFlagState::Set,
            response_code: 3,
            authoritative: DnsFlagState::Unset,
            truncated: DnsFlagState::Unset,
            answer_count: 0,
            duration_ms: 4,
        },
        requests: Arc::clone(&requests),
    });
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new("recursive-nameserver-leak-test")?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("scanner missing")?;
    let mut request = support::request_for(scanner.descriptor())?;
    authorize_nameserver(&mut request)?;
    let result = scanner.scan(&request, &support::context(false)).await?;

    assert_eq!(result.status, ExecutionStatus::Completed);
    assert!(result.diagnostics.is_empty());
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].key, "dns-recursion-exposed");
    assert_eq!(result.findings[0].severity, Severity::Medium);
    assert_eq!(result.findings[0].confidence, Confidence::Confirmed);
    assert_eq!(result.findings[0].evidence, [0]);

    let evidence = &result.evidence[0];
    assert_eq!(
        evidence.kind,
        "recursive-nameserver-leak-test-dns-recursion-observation"
    );
    assert_eq!(evidence.source, "ns1.example.net:53");
    assert_eq!(evidence.observation["scanner_id"], scanner_id.as_str());
    assert_eq!(evidence.observation["analysis"], "dns-exposure-analysis");
    assert_eq!(
        evidence.observation["purpose"],
        "Assess whether recursive DNS behavior is exposed."
    );
    assert_eq!(
        evidence.observation["observation"],
        serde_json::json!({
            "recursion_desired": "set",
            "recursion_available": "set",
            "response_code": 3,
            "authoritative": "unset",
            "truncated": "unset",
            "answer_count": 0,
            "duration_ms": 4,
        })
    );

    let requests = requests
        .lock()
        .map_err(|_| "fixture request log is unavailable")?;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].resolver, "ns1.example.net");
    assert_eq!(requests[0].port, 53);
    assert_eq!(requests[0].query_name, "sugra-recursion-probe.invalid");
    assert_eq!(requests[0].budget, request.budget);
    assert_eq!(requests[0].scope, request.scope);
    Ok(())
}

#[tokio::test]
async fn recursive_nameserver_filters_scope_before_spending_probe_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut services = support::Harness::successful().services();
    services.dns = Arc::new(ScopeFilteringDns {
        requests: Arc::clone(&requests),
    });
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new("recursive-nameserver-leak-test")?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("scanner missing")?;
    let mut request = support::request_for(scanner.descriptor())?;
    authorize_nameserver(&mut request)?;
    request.budget.max_requests = 2;

    let result = scanner.scan(&request, &support::context(false)).await?;

    assert_eq!(result.status, ExecutionStatus::Partial);
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(result.diagnostics[0].kind, "out-of-scope");
    let requests = requests.lock().map_err(|_| "request log unavailable")?;
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].resolver, "ns1.example.net");
    Ok(())
}

#[tokio::test]
async fn http2_http3_positive_separates_tls_and_quic_observations()
-> Result<(), Box<dyn std::error::Error>> {
    let tls_requests = Arc::new(Mutex::new(Vec::new()));
    let quic_requests = Arc::new(Mutex::new(Vec::new()));
    let mut services = support::Harness::successful().services();
    services.tls = Arc::new(ProtocolTls {
        tls_result: Ok(tls_observation(Some("h2"))),
        quic_result: Ok(QuicObservation {
            alpn: Some("h3".into()),
            version: Some(support::SECRET_MARKER.into()),
            duration_ms: 3,
        }),
        tls_requests: Arc::clone(&tls_requests),
        quic_requests: Arc::clone(&quic_requests),
    });
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new("http2-http3-checker")?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("scanner missing")?;
    let request = support::request_for(scanner.descriptor())?;
    let result = scanner.scan(&request, &support::context(false)).await?;

    assert_eq!(result.status, ExecutionStatus::Completed);
    assert!(result.diagnostics.is_empty());
    assert!(result.findings.is_empty());
    assert_eq!(result.evidence.len(), 2);
    assert_eq!(result.evidence[0].kind, "http2-http3-checker-tls-handshake");
    assert_eq!(result.evidence[0].source, "example.com:443/tcp");
    assert_eq!(
        result.evidence[0].observation["observation"]["application_protocol"],
        "http2"
    );
    assert_eq!(
        result.evidence[1].kind,
        "http2-http3-checker-quic-handshake"
    );
    assert_eq!(result.evidence[1].source, "example.com:443/udp");
    assert_eq!(
        result.evidence[1].observation["observation"],
        serde_json::json!({
            "application_protocol": "http3",
            "version_available": true,
            "duration_ms": 3,
        })
    );
    for evidence in &result.evidence {
        assert_eq!(evidence.observation["scanner_id"], scanner_id.as_str());
        assert_eq!(evidence.observation["analysis"], "tls-protocol-analysis");
        assert_eq!(
            evidence.observation["purpose"],
            "Observe negotiated HTTP protocol support over TLS."
        );
    }

    let tls_requests = tls_requests
        .lock()
        .map_err(|_| "fixture TLS request log is unavailable")?;
    assert_eq!(tls_requests.len(), 1);
    assert_eq!(tls_requests[0].host, "example.com");
    assert_eq!(tls_requests[0].port, 443);
    assert_eq!(tls_requests[0].budget, request.budget);
    assert_eq!(tls_requests[0].scope, request.scope);
    let quic_requests = quic_requests
        .lock()
        .map_err(|_| "fixture QUIC request log is unavailable")?;
    assert_eq!(quic_requests.len(), 1);
    assert_eq!(quic_requests[0].host, "example.com");
    assert_eq!(quic_requests[0].port, 443);
    assert_eq!(quic_requests[0].budget, request.budget);
    assert_eq!(quic_requests[0].scope, request.scope);
    assert!(!serde_json::to_string(&result)?.contains(support::SECRET_MARKER));
    Ok(())
}

#[tokio::test]
async fn http_protocol_scan_rechecks_cancellation_before_quic()
-> Result<(), Box<dyn std::error::Error>> {
    let context = support::context(false);
    let quic_calls = Arc::new(AtomicUsize::new(0));
    let mut services = support::Harness::successful().services();
    services.tls = Arc::new(CancellingProtocolTls {
        cancellation: context.cancellation.clone(),
        quic_calls: Arc::clone(&quic_calls),
    });
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new("http2-http3-checker")?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("scanner missing")?;
    let request = support::request_for(scanner.descriptor())?;
    let result = scanner.scan(&request, &context).await?;

    assert_eq!(result.status, ExecutionStatus::Cancelled);
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(quic_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn recursive_nameserver_negative_and_edge_never_infer_from_flags_alone()
-> Result<(), Box<dyn std::error::Error>> {
    let (negative, _) = run_recursion(
        DnsRecursionObservation {
            recursion_desired: DnsFlagState::Set,
            recursion_available: DnsFlagState::Unset,
            response_code: 5,
            authoritative: DnsFlagState::Unset,
            truncated: DnsFlagState::Unset,
            answer_count: 0,
            duration_ms: 4,
        },
        false,
    )
    .await?;
    let negative = negative?;
    assert_eq!(negative.status, ExecutionStatus::Completed);
    assert!(negative.findings.is_empty());
    assert_eq!(
        negative.evidence[0].observation["observation"]["response_code"],
        5
    );

    let (edge, _) = run_recursion(
        DnsRecursionObservation {
            recursion_desired: DnsFlagState::Set,
            recursion_available: DnsFlagState::Set,
            response_code: 0,
            authoritative: DnsFlagState::Unset,
            truncated: DnsFlagState::Set,
            answer_count: 64,
            duration_ms: 4,
        },
        false,
    )
    .await?;
    let edge = edge?;
    assert_eq!(edge.status, ExecutionStatus::Completed);
    assert!(
        edge.findings.is_empty(),
        "a truncated response does not prove recursion"
    );
    assert_eq!(
        edge.evidence[0].observation["observation"]["truncated"],
        "set"
    );

    let (authoritative, _) = run_recursion(
        DnsRecursionObservation {
            recursion_desired: DnsFlagState::Set,
            recursion_available: DnsFlagState::Set,
            response_code: 0,
            authoritative: DnsFlagState::Set,
            truncated: DnsFlagState::Unset,
            answer_count: 1,
            duration_ms: 4,
        },
        false,
    )
    .await?;
    assert!(
        authoritative?.findings.is_empty(),
        "an authoritative answer does not prove recursion"
    );
    Ok(())
}

#[tokio::test]
async fn recursive_nameserver_preserves_error_matrix_cancel_budget_and_descriptor()
-> Result<(), Box<dyn std::error::Error>> {
    for (port_kind, scan_kind) in error_matrix() {
        let mut services = support::Harness::successful().services();
        services.dns = Arc::new(ErrorDns(port_kind));
        let builtins = build_builtins(&services)?;
        let scanner_id = sugra_domain::ScannerId::new("recursive-nameserver-leak-test")?;
        let scanner = builtins
            .registry
            .get(&scanner_id)
            .ok_or("scanner missing")?;
        let mut request = support::request_for(scanner.descriptor())?;
        authorize_nameserver(&mut request)?;
        let Err(error) = scanner.scan(&request, &support::context(false)).await else {
            return Err(format!("DNS {port_kind:?} became success").into());
        };
        assert_eq!(error.kind, scan_kind, "{port_kind:?}");
        assert_eq!(
            error.message,
            format!("offline {port_kind:?} DNS recursion failure")
        );
    }

    let (cancelled, requests) = run_recursion(
        DnsRecursionObservation {
            recursion_desired: DnsFlagState::Set,
            recursion_available: DnsFlagState::Set,
            response_code: 0,
            authoritative: DnsFlagState::Unset,
            truncated: DnsFlagState::Unset,
            answer_count: 1,
            duration_ms: 1,
        },
        true,
    )
    .await?;
    let Err(cancelled) = cancelled else {
        return Err("cancelled DNS scan completed".into());
    };
    assert_eq!(cancelled.kind, ScanErrorKind::Cancelled);
    assert!(
        requests
            .lock()
            .map_err(|_| "request log unavailable")?
            .is_empty()
    );

    let services = support::Harness::successful().services();
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new("recursive-nameserver-leak-test")?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("scanner missing")?;
    let descriptor = scanner.descriptor();
    assert_eq!(descriptor.target_kinds, [TargetKind::Domain]);
    assert_eq!(
        descriptor
            .options
            .iter()
            .map(|option| option.key.as_str())
            .collect::<Vec<_>>(),
        ["timeout"]
    );
    Ok(())
}

#[tokio::test]
async fn http2_http3_negative_and_tcp_h3_edge_do_not_overclaim()
-> Result<(), Box<dyn std::error::Error>> {
    let (negative, _, _) = run_protocol(
        Ok(tls_observation(Some("http/1.1"))),
        Ok(quic_observation(Some("hq-29"), Some("1"))),
        2,
        false,
        None,
    )
    .await?;
    let negative = negative?;
    assert_eq!(negative.status, ExecutionStatus::Completed);
    assert_eq!(negative.findings.len(), 2);
    assert_eq!(negative.findings[0].key, "http2-not-negotiated");
    assert_eq!(negative.findings[0].evidence, [0]);
    assert_eq!(negative.findings[1].key, "http3-not-negotiated");
    assert_eq!(negative.findings[1].evidence, [1]);
    assert!(
        negative
            .findings
            .iter()
            .all(|finding| finding.confidence == Confidence::Confirmed)
    );

    let (edge, _, _) = run_protocol(
        Ok(tls_observation(Some("h3"))),
        Err(PortError::new(
            PortErrorKind::Unavailable,
            "offline QUIC transport unavailable",
        )),
        2,
        false,
        None,
    )
    .await?;
    let edge = edge?;
    assert_eq!(edge.status, ExecutionStatus::Partial);
    assert_eq!(edge.evidence.len(), 1);
    assert_eq!(edge.findings.len(), 1);
    assert_eq!(edge.findings[0].key, "http2-not-negotiated");
    assert_eq!(edge.findings[0].evidence, [0]);
    assert_eq!(edge.diagnostics.len(), 1);
    assert_eq!(edge.diagnostics[0].kind, "quic-unavailable");
    assert_eq!(
        edge.evidence[0].observation["observation"]["application_protocol"],
        "other"
    );
    assert!(!serde_json::to_string(&edge)?.contains("http3-transport-unverified"));
    Ok(())
}

#[tokio::test]
async fn http2_http3_preserves_error_matrix_and_request_budget()
-> Result<(), Box<dyn std::error::Error>> {
    for (port_kind, scan_kind) in error_matrix() {
        let tls_error = PortError::new(
            port_kind,
            format!("offline {port_kind:?} TLS protocol failure"),
        );
        let quic_error = PortError::new(
            port_kind,
            format!("offline {port_kind:?} QUIC protocol failure"),
        );
        let (result, _, _) = run_protocol(Err(tls_error), Err(quic_error), 2, false, None).await?;
        let Err(error) = result else {
            return Err(format!("protocol {port_kind:?} became success").into());
        };
        assert_eq!(error.kind, scan_kind, "{port_kind:?}");
        assert_eq!(
            error.message,
            format!("offline {port_kind:?} TLS protocol failure")
        );
    }

    let (bounded, tls_requests, quic_requests) = run_protocol(
        Ok(tls_observation(Some("h2"))),
        Ok(quic_observation(Some("h3"), Some("1"))),
        1,
        false,
        None,
    )
    .await?;
    let bounded = bounded?;
    assert_eq!(bounded.status, ExecutionStatus::Partial);
    assert_eq!(bounded.evidence.len(), 1);
    assert!(bounded.findings.is_empty());
    assert_eq!(bounded.diagnostics[0].kind, "budget-exhausted");
    assert_eq!(
        tls_requests
            .lock()
            .map_err(|_| "TLS log unavailable")?
            .len(),
        1
    );
    assert!(
        quic_requests
            .lock()
            .map_err(|_| "QUIC log unavailable")?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn http2_http3_honors_cancel_url_target_redaction_and_descriptor()
-> Result<(), Box<dyn std::error::Error>> {
    let (cancelled, tls_requests, quic_requests) = run_protocol(
        Ok(tls_observation(Some("h2"))),
        Ok(quic_observation(Some("h3"), Some("1"))),
        2,
        true,
        None,
    )
    .await?;
    let Err(cancelled) = cancelled else {
        return Err("cancelled protocol scan completed".into());
    };
    assert_eq!(cancelled.kind, ScanErrorKind::Cancelled);
    assert!(
        tls_requests
            .lock()
            .map_err(|_| "TLS log unavailable")?
            .is_empty()
    );
    assert!(
        quic_requests
            .lock()
            .map_err(|_| "QUIC log unavailable")?
            .is_empty()
    );

    let url = Target::parse(
        TargetKind::Url,
        &format!(
            "https://example.com:8443/private?token={}",
            support::SECRET_MARKER
        ),
    )?;
    let (url_result, tls_requests, quic_requests) = run_protocol(
        Ok(tls_observation(Some("h2"))),
        Ok(quic_observation(Some("h3"), Some(support::SECRET_MARKER))),
        2,
        false,
        Some(url),
    )
    .await?;
    let url_result = url_result?;
    assert_eq!(url_result.status, ExecutionStatus::Completed);
    assert_eq!(url_result.evidence[0].source, "example.com:8443/tcp");
    assert_eq!(url_result.evidence[1].source, "example.com:8443/udp");
    assert!(!serde_json::to_string(&url_result)?.contains(support::SECRET_MARKER));
    assert_eq!(
        tls_requests.lock().map_err(|_| "TLS log unavailable")?[0].port,
        8443
    );
    assert_eq!(
        quic_requests.lock().map_err(|_| "QUIC log unavailable")?[0].port,
        8443
    );

    let services = support::Harness::successful().services();
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new("http2-http3-checker")?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("scanner missing")?;
    let descriptor = scanner.descriptor();
    assert_eq!(
        descriptor.target_kinds,
        [TargetKind::Domain, TargetKind::Url]
    );
    assert!(descriptor.options.is_empty());
    Ok(())
}
