//! Public offline semantic contracts for DNS, TLS, IPv6, and UDP scanners.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use sugra_core::{
    Clock, CommandPort, CommandRequest, CommandResponse, DnsPort, DnsQuery, DnsRecord,
    DnsRecordType, HttpPort, HttpRequest, HttpResponse, LocalInputPort, LocalInputRequest,
    LocalInputResponse, PortError, PortErrorKind, ProviderPort, ProviderRequest, ProviderResponse,
    ScanContext, ScanErrorKind, ServiceBundle, TcpPort, TcpRequest, TcpResponse, TlsHandshakeKind,
    TlsObservation, TlsPort, TlsRequest, UdpPort, UdpRequest, UdpResponse, resolve_options,
};
use sugra_domain::{Budget, RunId, ScanRequest, ScanResult, ScopeGrant, Target, TargetKind};
use sugra_scanners::build_builtins;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureCase {
    PositiveSignal,
    NegativeControl,
    EdgeCase,
    TypedFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UdpProtocol {
    DnsSampler,
    Ntp,
    SnmpGet,
    Netbios,
    SnmpBulk,
}

#[derive(Debug, Clone, Copy)]
enum Fixture {
    DnsPolicy(FixtureCase),
    TlsPinning(FixtureCase),
    Ipv6(FixtureCase),
    Udp {
        protocol: UdpProtocol,
        case: FixtureCase,
    },
}

#[derive(Clone)]
struct FakePorts {
    fixture: Fixture,
}

#[async_trait]
impl DnsPort for FakePorts {
    async fn query(&self, query: DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
        match self.fixture {
            Fixture::DnsPolicy(case) => dns_policy_response(case, &query),
            Fixture::Ipv6(case) => ipv6_dns_response(case, &query),
            Fixture::TlsPinning(_) | Fixture::Udp { .. } => Err(unexpected_boundary("DNS")),
        }
    }
}

fn dns_policy_response(case: FixtureCase, query: &DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
    if case == FixtureCase::TypedFailure {
        return Err(PortError::new(
            PortErrorKind::Transport,
            "policy fixture resolver unavailable",
        ));
    }
    let txt = |value: &str| DnsRecord {
        name: query.name.clone(),
        record_type: DnsRecordType::Txt,
        value: value.into(),
        ttl: Some(300),
    };
    let records = match case {
        FixtureCase::PositiveSignal => Vec::new(),
        FixtureCase::NegativeControl if query.name == "example.com" => {
            vec![txt("v=spf1 -all")]
        }
        FixtureCase::NegativeControl if query.name.starts_with("_dmarc.") => {
            vec![txt("v=DMARC1; p=reject")]
        }
        FixtureCase::EdgeCase if query.name == "example.com" => vec![txt("v=spf1 +all")],
        FixtureCase::EdgeCase if query.name.starts_with("_dmarc.") => {
            vec![txt("v=DMARC1; p=none")]
        }
        FixtureCase::NegativeControl | FixtureCase::EdgeCase => {
            vec![txt("v=DKIM1; p=fixture-public-key")]
        }
        FixtureCase::TypedFailure => unreachable!("typed failure returned above"),
    };
    Ok(records)
}

fn ipv6_dns_response(case: FixtureCase, query: &DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
    assert_eq!(query.record_types, vec![DnsRecordType::Aaaa]);
    match case {
        FixtureCase::PositiveSignal | FixtureCase::NegativeControl => Ok(vec![DnsRecord {
            name: query.name.clone(),
            record_type: DnsRecordType::Aaaa,
            value: "2001:db8::1".into(),
            ttl: Some(300),
        }]),
        FixtureCase::EdgeCase => Ok(Vec::new()),
        FixtureCase::TypedFailure => Err(unexpected_boundary("DNS for IPv4 literal")),
    }
}

#[async_trait]
impl HttpPort for FakePorts {
    async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse, PortError> {
        Err(unexpected_boundary("HTTP"))
    }
}

#[async_trait]
impl TcpPort for FakePorts {
    async fn execute(&self, request: TcpRequest) -> Result<TcpResponse, PortError> {
        match self.fixture {
            Fixture::Ipv6(FixtureCase::PositiveSignal) => {
                assert_eq!(request.host, "2001:db8::1");
                assert_eq!(request.port, 443);
                Ok(TcpResponse {
                    endpoint: "[2001:db8::1]:443".into(),
                    bytes: Vec::new(),
                    duration_ms: 4,
                })
            }
            Fixture::Ipv6(FixtureCase::NegativeControl) => Err(PortError::new(
                PortErrorKind::Transport,
                "IPv6 endpoint did not accept a connection",
            )),
            Fixture::Ipv6(FixtureCase::EdgeCase | FixtureCase::TypedFailure) => {
                Err(unexpected_boundary("TCP without an IPv6 candidate"))
            }
            Fixture::DnsPolicy(_) | Fixture::TlsPinning(_) | Fixture::Udp { .. } => {
                Err(unexpected_boundary("TCP"))
            }
        }
    }
}

#[async_trait]
impl UdpPort for FakePorts {
    async fn execute(&self, request: UdpRequest) -> Result<UdpResponse, PortError> {
        let Fixture::Udp { protocol, case } = self.fixture else {
            return Err(unexpected_boundary("UDP"));
        };
        let bytes = udp_response(protocol, case, &request);
        Ok(UdpResponse {
            endpoint: format!("{}:{}", request.host, request.port),
            bytes,
            duration_ms: 3,
        })
    }
}

fn udp_response(protocol: UdpProtocol, case: FixtureCase, request: &UdpRequest) -> Vec<u8> {
    match protocol {
        UdpProtocol::DnsSampler => dns_udp_response(case, request),
        UdpProtocol::Ntp => ntp_response(case, request),
        UdpProtocol::Netbios => netbios_response(case, request),
        UdpProtocol::SnmpGet | UdpProtocol::SnmpBulk => snmp_response(protocol, case, request),
    }
}

fn dns_udp_response(case: FixtureCase, request: &UdpRequest) -> Vec<u8> {
    assert_eq!(request.port, 53);
    assert_eq!(request.payload.len(), 17);
    if case == FixtureCase::TypedFailure {
        return vec![0; 11];
    }
    let mut response = vec![0_u8; 12];
    response[..2].copy_from_slice(&request.payload[..2]);
    response[2..4].copy_from_slice(&[0x81, 0x80]);
    match case {
        FixtureCase::PositiveSignal => response[6..8].copy_from_slice(&1_u16.to_be_bytes()),
        FixtureCase::NegativeControl => {}
        FixtureCase::EdgeCase => {
            response[..2].copy_from_slice(&[0, 1]);
            response[6..8].copy_from_slice(&1_u16.to_be_bytes());
        }
        FixtureCase::TypedFailure => unreachable!("typed failure returned above"),
    }
    response
}

fn ntp_response(case: FixtureCase, request: &UdpRequest) -> Vec<u8> {
    assert_eq!(request.port, 123);
    assert_eq!(request.payload.len(), 48);
    if case == FixtureCase::TypedFailure {
        return vec![0; 47];
    }
    let mut response = vec![0_u8; 48];
    response[0] = if case == FixtureCase::EdgeCase {
        0x23
    } else {
        0x24
    };
    response[1] = 2;
    if case != FixtureCase::NegativeControl {
        response[24..32].copy_from_slice(&request.payload[40..48]);
    }
    response
}

fn netbios_response(case: FixtureCase, request: &UdpRequest) -> Vec<u8> {
    assert_eq!(request.port, 137);
    assert_eq!(request.payload.len(), 50);
    if case == FixtureCase::TypedFailure {
        return vec![0; 8];
    }
    let mut response = vec![0_u8; 12];
    response[..2].copy_from_slice(&request.payload[..2]);
    response[2..4].copy_from_slice(&[0x85, 0]);
    if case == FixtureCase::PositiveSignal || case == FixtureCase::EdgeCase {
        response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    }
    if case == FixtureCase::EdgeCase {
        response[..2].copy_from_slice(&[0, 1]);
    }
    response
}

fn snmp_response(protocol: UdpProtocol, case: FixtureCase, request: &UdpRequest) -> Vec<u8> {
    assert_eq!(request.port, 161);
    assert_eq!(request.payload.len(), 43);
    assert!(request.payload.contains(&match protocol {
        UdpProtocol::SnmpGet => 0xa0,
        UdpProtocol::SnmpBulk => 0xa5,
        _ => unreachable!("SNMP response requires an SNMP fixture"),
    }));
    if case == FixtureCase::TypedFailure {
        return vec![0x30, 1, 0];
    }
    let status = match case {
        FixtureCase::PositiveSignal => 0,
        FixtureCase::NegativeControl => 2,
        FixtureCase::EdgeCase => 5,
        FixtureCase::TypedFailure => unreachable!("typed failure returned above"),
    };
    let mut pdu = ber_tlv(0x02, &[0x53, 0x55, 0x47, 0x52]);
    pdu.extend(ber_tlv(0x02, &[status]));
    pdu.extend(ber_tlv(0x02, &[0]));
    pdu.extend(ber_tlv(0x30, &[]));
    let mut message = ber_tlv(0x02, &[1]);
    message.extend(ber_tlv(0x04, b"public"));
    message.extend(ber_tlv(0xa2, &pdu));
    ber_tlv(0x30, &message)
}

fn ber_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let Ok(length) = u8::try_from(body.len()) else {
        unreachable!("fixture BER body is tiny");
    };
    let mut encoded = vec![tag, length];
    encoded.extend_from_slice(body);
    encoded
}

#[async_trait]
impl TlsPort for FakePorts {
    async fn handshake(&self, request: TlsRequest) -> Result<TlsObservation, PortError> {
        let Fixture::TlsPinning(case) = self.fixture else {
            return Err(unexpected_boundary("TLS"));
        };
        assert_eq!(request.host, "example.com");
        assert_eq!(request.port, 443);
        let certificate_sha256 = match case {
            FixtureCase::PositiveSignal => vec!["aa".repeat(32)],
            FixtureCase::NegativeControl => vec!["bb".repeat(32)],
            FixtureCase::EdgeCase => Vec::new(),
            FixtureCase::TypedFailure => vec!["malformed-fingerprint".into()],
        };
        Ok(TlsObservation {
            handshake_kind: TlsHandshakeKind::Full,
            protocol: "TLSv1_3".into(),
            cipher_suite: "TLS_AES_256_GCM_SHA384".into(),
            alpn: Some("h2".into()),
            certificate_sha256,
            certificates: Vec::new(),
            duration_ms: 5,
        })
    }
}

#[async_trait]
impl CommandPort for FakePorts {
    async fn execute(&self, _request: CommandRequest) -> Result<CommandResponse, PortError> {
        Err(unexpected_boundary("command"))
    }
}

#[async_trait]
impl ProviderPort for FakePorts {
    async fn query(&self, _request: ProviderRequest) -> Result<ProviderResponse, PortError> {
        Err(unexpected_boundary("provider"))
    }
}

#[async_trait]
impl LocalInputPort for FakePorts {
    async fn read_lines(
        &self,
        _request: LocalInputRequest,
    ) -> Result<LocalInputResponse, PortError> {
        Err(unexpected_boundary("local input"))
    }
}

impl Clock for FakePorts {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }
}

fn unexpected_boundary(boundary: &str) -> PortError {
    PortError::new(
        PortErrorKind::Internal,
        format!("unexpected {boundary} boundary call in protocol fixture"),
    )
}

fn services(fixture: Fixture) -> ServiceBundle {
    let ports = Arc::new(FakePorts { fixture });
    ServiceBundle {
        dns: ports.clone(),
        http: ports.clone(),
        tcp: ports.clone(),
        udp: ports.clone(),
        tls: ports.clone(),
        command: ports.clone(),
        provider: ports.clone(),
        local_input: ports.clone(),
        clock: ports,
    }
}

fn context() -> ScanContext {
    ScanContext {
        run_id: RunId::new(),
        cancellation: CancellationToken::new(),
        clock: Arc::new(FakePorts {
            fixture: Fixture::DnsPolicy(FixtureCase::NegativeControl),
        }),
    }
}

async fn scan(
    id: &str,
    fixture: Fixture,
    target_kind: TargetKind,
    target_value: &str,
    supplied: BTreeMap<String, String>,
) -> Result<ScanResult, sugra_core::ScanError> {
    let Ok(builtins) = build_builtins(&services(fixture)) else {
        unreachable!("built-in catalog must be valid");
    };
    let Ok(scanner_id) = sugra_domain::ScannerId::new(id) else {
        unreachable!("fixture scanner ID must be valid");
    };
    let Some(scanner) = builtins.registry.get(&scanner_id) else {
        unreachable!("fixture scanner must be registered");
    };
    let Ok(target) = Target::parse(target_kind, target_value) else {
        unreachable!("fixture target must be valid");
    };
    let Ok(options) = resolve_options(&scanner.descriptor().options, &supplied) else {
        unreachable!("fixture options must be valid");
    };
    let request = ScanRequest {
        scanner_id,
        options,
        budget: Budget {
            timeout_ms: 1_000,
            concurrency: 1,
            max_requests: 8,
            max_response_bytes: 512,
            max_depth: 1,
        },
        scope: ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH),
        target,
    };
    scanner.scan(&request, &context()).await
}

fn finding_keys(result: &ScanResult) -> Vec<&str> {
    result
        .findings
        .iter()
        .map(|finding| finding.key.as_str())
        .collect()
}

fn has_finding(result: &ScanResult, key: &str) -> bool {
    result.findings.iter().any(|finding| finding.key == key)
}

fn udp_protocol(result: &ScanResult) -> &Value {
    &result.evidence[0].observation["observation"]["protocol"]
}

#[tokio::test]
async fn spf_dkim_dmarc_validator_covers_all_fixture_classes()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan(
        "spf-dkim-dmarc-validator",
        Fixture::DnsPolicy(FixtureCase::PositiveSignal),
        TargetKind::Domain,
        "example.com",
        BTreeMap::new(),
    )
    .await?;
    let keys = finding_keys(&positive);
    assert!(keys.contains(&"spf-not-observed"));
    assert!(keys.contains(&"dkim-not-observed"));
    assert!(keys.contains(&"dmarc-not-observed"));

    let negative = scan(
        "spf-dkim-dmarc-validator",
        Fixture::DnsPolicy(FixtureCase::NegativeControl),
        TargetKind::Domain,
        "example.com",
        BTreeMap::new(),
    )
    .await?;
    assert!(!has_finding(&negative, "spf-not-observed"));
    assert!(!has_finding(&negative, "dkim-not-observed"));
    assert!(!has_finding(&negative, "dmarc-not-observed"));

    let edge = scan(
        "spf-dkim-dmarc-validator",
        Fixture::DnsPolicy(FixtureCase::EdgeCase),
        TargetKind::Domain,
        "example.com",
        BTreeMap::new(),
    )
    .await?;
    assert!(has_finding(&edge, "spf-permissive-all"));
    assert!(has_finding(&edge, "dmarc-monitoring-only"));
    assert!(!has_finding(&edge, "dkim-not-observed"));

    let failure = scan(
        "spf-dkim-dmarc-validator",
        Fixture::DnsPolicy(FixtureCase::TypedFailure),
        TargetKind::Domain,
        "example.com",
        BTreeMap::new(),
    )
    .await
    .err()
    .ok_or("DNS transport failure unexpectedly succeeded")?;
    assert_eq!(failure.kind, ScanErrorKind::Transport);
    Ok(())
}

#[tokio::test]
async fn ssl_pinning_check_covers_all_fixture_classes() -> Result<(), Box<dyn std::error::Error>> {
    let options = BTreeMap::from([("baseline_sha256".into(), "bb".repeat(32))]);
    let positive = scan(
        "ssl-pinning-check",
        Fixture::TlsPinning(FixtureCase::PositiveSignal),
        TargetKind::Domain,
        "example.com",
        options.clone(),
    )
    .await?;
    assert!(has_finding(&positive, "tls-pinning-baseline-mismatch"));

    let negative = scan(
        "ssl-pinning-check",
        Fixture::TlsPinning(FixtureCase::NegativeControl),
        TargetKind::Domain,
        "example.com",
        options.clone(),
    )
    .await?;
    assert!(negative.findings.is_empty());

    let edge = scan(
        "ssl-pinning-check",
        Fixture::TlsPinning(FixtureCase::EdgeCase),
        TargetKind::Domain,
        "example.com",
        options.clone(),
    )
    .await?;
    assert!(has_finding(&edge, "tls-pinning-material-unavailable"));

    let failure = scan(
        "ssl-pinning-check",
        Fixture::TlsPinning(FixtureCase::TypedFailure),
        TargetKind::Domain,
        "example.com",
        options,
    )
    .await
    .err()
    .ok_or("malformed TLS fingerprint unexpectedly succeeded")?;
    assert_eq!(failure.kind, ScanErrorKind::InvalidResponse);
    Ok(())
}

#[tokio::test]
async fn ipv6_reachability_test_covers_all_fixture_classes()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan(
        "ipv6-reachability-test",
        Fixture::Ipv6(FixtureCase::PositiveSignal),
        TargetKind::Domain,
        "example.com",
        BTreeMap::new(),
    )
    .await?;
    assert!(has_finding(&positive, "ipv6-service-reachable"));

    let negative = scan(
        "ipv6-reachability-test",
        Fixture::Ipv6(FixtureCase::NegativeControl),
        TargetKind::Domain,
        "example.com",
        BTreeMap::new(),
    )
    .await?;
    assert!(!has_finding(&negative, "ipv6-service-reachable"));
    assert_eq!(
        negative.evidence[0].observation["observation"]["state"],
        "unreachable"
    );

    let edge = scan(
        "ipv6-reachability-test",
        Fixture::Ipv6(FixtureCase::EdgeCase),
        TargetKind::Domain,
        "example.com",
        BTreeMap::new(),
    )
    .await?;
    assert!(edge.findings.is_empty());
    assert_eq!(
        edge.evidence[0].kind,
        "ipv6-reachability-test-ipv6-resolution"
    );
    assert_eq!(
        edge.evidence[0].observation["observation"]["ipv6_addresses"],
        0
    );

    let failure = scan(
        "ipv6-reachability-test",
        Fixture::Ipv6(FixtureCase::TypedFailure),
        TargetKind::Ip,
        "192.0.2.10",
        BTreeMap::new(),
    )
    .await
    .err()
    .ok_or("IPv4 target unexpectedly satisfied the IPv6 contract")?;
    assert_eq!(failure.kind, ScanErrorKind::InvalidInput);
    Ok(())
}

async fn scan_udp_case(
    id: &str,
    protocol: UdpProtocol,
    case: FixtureCase,
) -> Result<ScanResult, sugra_core::ScanError> {
    let supplied = if protocol == UdpProtocol::DnsSampler {
        BTreeMap::from([("ports".into(), "53".into())])
    } else {
        BTreeMap::new()
    };
    scan(
        id,
        Fixture::Udp { protocol, case },
        TargetKind::Ip,
        "192.0.2.10",
        supplied,
    )
    .await
}

#[tokio::test]
async fn ntp_info_leak_checker_covers_all_fixture_classes() -> Result<(), Box<dyn std::error::Error>>
{
    let positive = scan_udp_case(
        "ntp-info-leak-checker",
        UdpProtocol::Ntp,
        FixtureCase::PositiveSignal,
    )
    .await?;
    assert!(has_finding(&positive, "ntp-service-observed"));
    assert_eq!(udp_protocol(&positive)["mode"], 4);

    let negative = scan_udp_case(
        "ntp-info-leak-checker",
        UdpProtocol::Ntp,
        FixtureCase::NegativeControl,
    )
    .await?;
    assert!(!has_finding(&negative, "ntp-service-observed"));
    assert_eq!(udp_protocol(&negative)["transaction_matches"], false);

    let edge = scan_udp_case(
        "ntp-info-leak-checker",
        UdpProtocol::Ntp,
        FixtureCase::EdgeCase,
    )
    .await?;
    assert!(!has_finding(&edge, "ntp-service-observed"));
    assert_eq!(udp_protocol(&edge)["transaction_matches"], true);
    assert_eq!(udp_protocol(&edge)["mode"], 3);

    assert_udp_typed_failure("ntp-info-leak-checker", UdpProtocol::Ntp).await?;
    Ok(())
}

#[tokio::test]
async fn snmp_public_community_checker_covers_all_fixture_classes()
-> Result<(), Box<dyn std::error::Error>> {
    assert_snmp_contract("snmp-public-community-checker", UdpProtocol::SnmpGet).await
}

#[tokio::test]
async fn udp_service_sampler_covers_all_fixture_classes() -> Result<(), Box<dyn std::error::Error>>
{
    let positive = scan_udp_case(
        "udp-service-sampler",
        UdpProtocol::DnsSampler,
        FixtureCase::PositiveSignal,
    )
    .await?;
    assert!(has_finding(&positive, "udp-dns-service-observed"));
    assert_eq!(udp_protocol(&positive)["answers"], 1);

    let negative = scan_udp_case(
        "udp-service-sampler",
        UdpProtocol::DnsSampler,
        FixtureCase::NegativeControl,
    )
    .await?;
    assert!(!has_finding(&negative, "udp-dns-service-observed"));
    assert_eq!(udp_protocol(&negative)["transaction_matches"], true);
    assert_eq!(udp_protocol(&negative)["answers"], 0);

    let edge = scan_udp_case(
        "udp-service-sampler",
        UdpProtocol::DnsSampler,
        FixtureCase::EdgeCase,
    )
    .await?;
    assert!(!has_finding(&edge, "udp-dns-service-observed"));
    assert_eq!(udp_protocol(&edge)["transaction_matches"], false);
    assert_eq!(udp_protocol(&edge)["answers"], 1);

    assert_udp_typed_failure("udp-service-sampler", UdpProtocol::DnsSampler).await?;
    Ok(())
}

#[tokio::test]
async fn netbios_name_query_covers_all_fixture_classes() -> Result<(), Box<dyn std::error::Error>> {
    let positive = scan_udp_case(
        "netbios-name-query",
        UdpProtocol::Netbios,
        FixtureCase::PositiveSignal,
    )
    .await?;
    assert!(has_finding(&positive, "netbios-name-service-observed"));

    let negative = scan_udp_case(
        "netbios-name-query",
        UdpProtocol::Netbios,
        FixtureCase::NegativeControl,
    )
    .await?;
    assert!(!has_finding(&negative, "netbios-name-service-observed"));
    assert_eq!(udp_protocol(&negative)["answers"], 0);

    let edge = scan_udp_case(
        "netbios-name-query",
        UdpProtocol::Netbios,
        FixtureCase::EdgeCase,
    )
    .await?;
    assert!(!has_finding(&edge, "netbios-name-service-observed"));
    assert_eq!(udp_protocol(&edge)["transaction_matches"], false);
    assert_eq!(udp_protocol(&edge)["answers"], 1);

    assert_udp_typed_failure("netbios-name-query", UdpProtocol::Netbios).await?;
    Ok(())
}

#[tokio::test]
async fn snmp_bulk_walk_covers_all_fixture_classes() -> Result<(), Box<dyn std::error::Error>> {
    assert_snmp_contract("snmp-bulk-walk", UdpProtocol::SnmpBulk).await
}

async fn assert_snmp_contract(
    id: &str,
    protocol: UdpProtocol,
) -> Result<(), Box<dyn std::error::Error>> {
    let positive = scan_udp_case(id, protocol, FixtureCase::PositiveSignal).await?;
    assert!(has_finding(&positive, "snmp-public-community-accepted"));
    assert_eq!(udp_protocol(&positive)["error_status"], 0);

    let negative = scan_udp_case(id, protocol, FixtureCase::NegativeControl).await?;
    assert!(!has_finding(&negative, "snmp-public-community-accepted"));
    assert_eq!(udp_protocol(&negative)["error_status"], 2);

    let edge = scan_udp_case(id, protocol, FixtureCase::EdgeCase).await?;
    assert!(!has_finding(&edge, "snmp-public-community-accepted"));
    assert_eq!(udp_protocol(&edge)["error_status"], 5);

    assert_udp_typed_failure(id, protocol).await
}

async fn assert_udp_typed_failure(
    id: &str,
    protocol: UdpProtocol,
) -> Result<(), Box<dyn std::error::Error>> {
    let failure = scan_udp_case(id, protocol, FixtureCase::TypedFailure)
        .await
        .err()
        .ok_or("malformed UDP response unexpectedly succeeded")?;
    assert_eq!(failure.kind, ScanErrorKind::InvalidResponse);
    Ok(())
}
