//! Public offline contracts for bounded TCP, command, and local scanners.

#![allow(dead_code)] // Shared fixture support exposes cases used by sibling contract suites.

mod support;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{Value, json};
use sugra_core::{
    CommandKind, CommandPort, CommandRequest, CommandResponse, PortError, PortErrorKind,
    ScanErrorKind, ServiceBundle, TcpPort, TcpRequest, TcpResponse,
};
use sugra_domain::{Budget, ScanRequest, ScanResult, ScopeGrant, Target, TargetKind};
use sugra_scanners::build_builtins;
use time::OffsetDateTime;

const SECRET: &str = "wave3-secret-material-91c7";

#[derive(Debug, Clone)]
enum TcpReply {
    Connected(Vec<u8>),
    Error(PortErrorKind),
}

#[derive(Clone)]
struct ScriptedTcp {
    reply: TcpReply,
    requests: Arc<Mutex<Vec<TcpRequest>>>,
}

#[async_trait]
impl TcpPort for ScriptedTcp {
    async fn execute(&self, request: TcpRequest) -> Result<TcpResponse, PortError> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.clone());
        match &self.reply {
            TcpReply::Connected(bytes) => Ok(TcpResponse {
                endpoint: format!("{}:{}-{SECRET}", request.host, request.port),
                bytes: bytes.clone(),
                duration_ms: 7,
            }),
            TcpReply::Error(kind) => Err(PortError::new(*kind, "typed TCP fixture failure")),
        }
    }
}

#[derive(Debug, Clone)]
struct CommandReply(Result<CommandResponse, PortError>);

#[derive(Clone)]
struct ScriptedCommand {
    reply: CommandReply,
    requests: Arc<Mutex<Vec<CommandRequest>>>,
}

#[async_trait]
impl CommandPort for ScriptedCommand {
    async fn execute(&self, request: CommandRequest) -> Result<CommandResponse, PortError> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request);
        self.reply.0.clone()
    }
}

fn tcp_services(reply: TcpReply) -> (ServiceBundle, Arc<Mutex<Vec<TcpRequest>>>) {
    let mut services = support::Harness::successful().services();
    let requests = Arc::new(Mutex::new(Vec::new()));
    services.tcp = Arc::new(ScriptedTcp {
        reply,
        requests: requests.clone(),
    });
    (services, requests)
}

fn command_services(
    reply: Result<CommandResponse, PortError>,
) -> (ServiceBundle, Arc<Mutex<Vec<CommandRequest>>>) {
    let mut services = support::Harness::successful().services();
    let requests = Arc::new(Mutex::new(Vec::new()));
    services.command = Arc::new(ScriptedCommand {
        reply: CommandReply(reply),
        requests: requests.clone(),
    });
    (services, requests)
}

fn make_request(
    services: &ServiceBundle,
    id: &str,
    target: Target,
) -> Result<(Arc<dyn sugra_core::Scanner>, ScanRequest), Box<dyn std::error::Error>> {
    let builtins = build_builtins(services)?;
    let scanner_id = sugra_domain::ScannerId::new(id)?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("scanner missing from registry")?;
    let mut request = support::request_for(scanner.descriptor())?;
    request.scope = ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH);
    request.target = target;
    Ok((scanner, request))
}

fn has_finding(result: &ScanResult, key: &str) -> bool {
    result.findings.iter().any(|finding| finding.key == key)
}

fn observations(result: &ScanResult) -> Vec<&Value> {
    result
        .evidence
        .iter()
        .filter_map(|evidence| evidence.observation.get("observation"))
        .collect()
}

fn small_budget(max_requests: usize, max_response_bytes: usize) -> Budget {
    Budget {
        timeout_ms: 1_000,
        concurrency: 1,
        max_requests,
        max_response_bytes,
        max_depth: 1,
    }
}

async fn expected_scan_error(
    scanner: &Arc<dyn sugra_core::Scanner>,
    request: &ScanRequest,
    cancelled: bool,
    message: &'static str,
) -> Result<sugra_core::ScanError, Box<dyn std::error::Error>> {
    match scanner.scan(request, &support::context(cancelled)).await {
        Err(error) => Ok(error),
        Ok(_) => Err(message.into()),
    }
}

#[tokio::test]
async fn open_ports_requires_a_connection_signal_and_preserves_typed_failures()
-> Result<(), Box<dyn std::error::Error>> {
    let target = Target::parse(TargetKind::Ip, "192.0.2.10")?;
    let (services, requests) = tcp_services(TcpReply::Connected(Vec::new()));
    let (scanner, mut request) = make_request(&services, "open-ports", target.clone())?;
    request.options.insert("ports".into(), json!(["443"]));
    let result = scanner.scan(&request, &support::context(false)).await?;
    assert!(has_finding(&result, "tcp-port-open"));
    assert_eq!(observations(&result)[0]["state"], "open");
    assert!(!serde_json::to_string(&result)?.contains(SECRET));
    assert_eq!(
        requests.lock().map_err(|_| "request lock poisoned")?.len(),
        1
    );

    for (kind, expected) in [
        (PortErrorKind::Transport, ScanErrorKind::Transport),
        (PortErrorKind::Timeout, ScanErrorKind::Timeout),
        (PortErrorKind::OutOfScope, ScanErrorKind::PolicyDenied),
    ] {
        let (services, _) = tcp_services(TcpReply::Error(kind));
        let (scanner, mut request) = make_request(&services, "open-ports", target.clone())?;
        request.options.insert("ports".into(), json!(["443"]));
        let error = expected_scan_error(
            &scanner,
            &request,
            false,
            "a boundary failure must not become closed-port evidence",
        )
        .await?;
        assert_eq!(error.kind, expected);
    }

    let (services, _) = tcp_services(TcpReply::Connected(vec![0_u8; 65]));
    let (scanner, mut request) = make_request(&services, "open-ports", target)?;
    request.options.insert("ports".into(), json!(["443"]));
    request.budget = small_budget(1, 64);
    let error = expected_scan_error(
        &scanner,
        &request,
        false,
        "oversized TCP material must not become open-port evidence",
    )
    .await?;
    assert_eq!(error.kind, ScanErrorKind::InvalidResponse);

    Ok(())
}

#[tokio::test]
async fn ip_range_scanner_is_bounded_by_hosts_requests_and_unique_ports()
-> Result<(), Box<dyn std::error::Error>> {
    let target = Target::parse(TargetKind::Cidr, "192.0.2.0/24")?;
    let (services, requests) = tcp_services(TcpReply::Connected(Vec::new()));
    let (scanner, mut request) = make_request(&services, "ip-range-scanner", target)?;
    request.budget = small_budget(5, 1_024);
    request.options.insert("max_hosts".into(), json!(3));
    request
        .options
        .insert("ports".into(), json!(["443", "80", "443"]));
    let result = scanner.scan(&request, &support::context(false)).await?;
    assert_eq!(result.evidence.len(), 5);
    {
        let recorded = requests.lock().map_err(|_| "request lock poisoned")?;
        assert_eq!(recorded.len(), 5);
        assert!(
            recorded
                .iter()
                .all(|request| matches!(request.port, 80 | 443))
        );
        assert_eq!(
            recorded
                .iter()
                .map(|request| (&request.host, request.port))
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            recorded.len()
        );
    }

    let target = Target::parse(TargetKind::Cidr, "192.0.2.0/24")?;
    let (scanner, mut request) = make_request(&services, "ip-range-scanner", target)?;
    request.options.insert("ports".into(), json!(["0", "443"]));
    let error = expected_scan_error(
        &scanner,
        &request,
        false,
        "an invalid port list must fail before the TCP boundary",
    )
    .await?;
    assert_eq!(error.kind, ScanErrorKind::InvalidInput);
    assert_eq!(
        requests.lock().map_err(|_| "request lock poisoned")?.len(),
        5
    );
    Ok(())
}

fn dns_name(name: &str) -> Vec<u8> {
    let mut encoded = Vec::new();
    for label in name.split('.') {
        encoded.push(u8::try_from(label.len()).unwrap_or_else(|_| unreachable!("fixture label")));
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    encoded
}

fn axfr_response(rcode: u8, soa_records: usize) -> Vec<u8> {
    let mut message = vec![
        0x53,
        0x55,
        0x81,
        0x80 | (rcode & 0x0f),
        0,
        1,
        0,
        u8::try_from(soa_records).unwrap_or_else(|_| unreachable!("tiny fixture")),
        0,
        0,
        0,
        0,
    ];
    message.extend(dns_name("example.com"));
    message.extend_from_slice(&[0, 252, 0, 1]);
    for _ in 0..soa_records {
        message.extend_from_slice(&[0xc0, 0x0c, 0, 6, 0, 1, 0, 0, 1, 44, 0, 22]);
        message.extend_from_slice(&[0, 0]);
        message.extend_from_slice(&[0_u8; 20]);
    }
    let mut framed = u16::try_from(message.len())
        .unwrap_or_else(|_| unreachable!("tiny fixture"))
        .to_be_bytes()
        .to_vec();
    framed.extend(message);
    framed
}

#[tokio::test]
async fn zone_transfer_requires_a_complete_axfr_and_reports_refusal_without_a_finding()
-> Result<(), Box<dyn std::error::Error>> {
    let target = Target::parse(TargetKind::Domain, "example.com")?;
    let (services, requests) = tcp_services(TcpReply::Connected(axfr_response(0, 2)));
    let (scanner, request) = make_request(&services, "zonetransfer", target.clone())?;
    let accepted = scanner.scan(&request, &support::context(false)).await?;
    assert!(has_finding(&accepted, "dns-zone-transfer-accepted"));
    assert_eq!(observations(&accepted)[0]["transfer_accepted"], true);
    {
        let requests = requests.lock().map_err(|_| "request lock poisoned")?;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].port, 53);
        assert!(requests[0].read_response);
        assert_eq!(&requests[0].payload[2..4], &[0x53, 0x55]);
        assert_eq!(
            &requests[0].payload[requests[0].payload.len() - 4..requests[0].payload.len() - 2],
            &[0, 252]
        );
    }

    let (services, _) = tcp_services(TcpReply::Connected(axfr_response(5, 0)));
    let (scanner, request) = make_request(&services, "zonetransfer", target.clone())?;
    let refused = scanner.scan(&request, &support::context(false)).await?;
    assert!(!has_finding(&refused, "dns-zone-transfer-accepted"));
    assert_eq!(observations(&refused)[0]["transfer_accepted"], false);
    assert_eq!(observations(&refused)[0]["response_code"], 5);

    let (services, _) = tcp_services(TcpReply::Connected(axfr_response(0, 1)));
    let (scanner, request) = make_request(&services, "zonetransfer", target)?;
    let error = expected_scan_error(
        &scanner,
        &request,
        false,
        "an incomplete transfer must not be reported as accepted",
    )
    .await?;
    assert_eq!(error.kind, ScanErrorKind::InvalidResponse);

    Ok(())
}

fn command_response(exit_code: i32, stdout: &str, stderr: &str) -> CommandResponse {
    CommandResponse {
        exit_code: Some(exit_code),
        stdout: stdout.into(),
        stderr: stderr.into(),
        duration_ms: 9,
    }
}

async fn command_scan(
    id: &str,
    target: Target,
    response: CommandResponse,
) -> Result<(ScanResult, Vec<CommandRequest>), Box<dyn std::error::Error>> {
    let (services, requests) = command_services(Ok(response));
    let (scanner, request) = make_request(&services, id, target)?;
    let result = scanner.scan(&request, &support::context(false)).await?;
    let requests = requests
        .lock()
        .map_err(|_| "request lock poisoned")?
        .clone();
    Ok((result, requests))
}

#[tokio::test]
async fn icmp_matrix_distinguishes_replies_no_replies_and_malformed_success()
-> Result<(), Box<dyn std::error::Error>> {
    let target = Target::parse(TargetKind::Ip, "192.0.2.10")?;
    let (reachable, requests) = command_scan(
        "icmp-reachability-matrix",
        target.clone(),
        command_response(
            0,
            "64 bytes from 192.0.2.10: icmp_seq=1 ttl=52 time=1.2 ms\n",
            "",
        ),
    )
    .await?;
    assert!(has_finding(&reachable, "icmp-reachable"));
    assert_eq!(observations(&reachable)[0]["details"]["reachable"], true);
    assert_eq!(requests[0].kind, CommandKind::Ping);

    let (unreachable, _) = command_scan(
        "icmp-reachability-matrix",
        target.clone(),
        command_response(1, "1 packets transmitted, 0 received", ""),
    )
    .await?;
    assert!(has_finding(&unreachable, "icmp-unreachable"));
    assert_eq!(observations(&unreachable)[0]["details"]["reachable"], false);

    let (services, _) = command_services(Ok(command_response(0, "", "")));
    let (scanner, request) = make_request(&services, "icmp-reachability-matrix", target)?;
    let error = expected_scan_error(
        &scanner,
        &request,
        false,
        "exit zero without an ICMP reply is not reachability evidence",
    )
    .await?;
    assert_eq!(error.kind, ScanErrorKind::InvalidResponse);
    Ok(())
}

#[tokio::test]
async fn traceroute_requires_structured_hops_and_never_retains_raw_output()
-> Result<(), Box<dyn std::error::Error>> {
    let target = Target::parse(TargetKind::Ip, "192.0.2.10")?;
    let (complete, requests) = command_scan(
        "traceroute",
        target.clone(),
        command_response(
            0,
            "traceroute to 192.0.2.10, 30 hops max\n 1  192.0.2.1  1.0 ms\n 2  192.0.2.10  2.0 ms\n",
            SECRET,
        ),
    )
    .await?;
    assert!(has_finding(&complete, "network-path-observed"));
    assert_eq!(observations(&complete)[0]["details"]["hop_count"], 2);
    assert_eq!(requests[0].kind, CommandKind::Traceroute);
    assert!(!serde_json::to_string(&complete)?.contains(SECRET));

    let (partial, _) = command_scan(
        "traceroute",
        target.clone(),
        command_response(
            1,
            "traceroute to 192.0.2.10, 30 hops max\n 1  192.0.2.1  1.0 ms\n 2  * * *\n",
            "",
        ),
    )
    .await?;
    assert_eq!(observations(&partial)[0]["details"]["exit_success"], false);

    let (services, _) = command_services(Ok(command_response(0, "not a route", "")));
    let (scanner, request) = make_request(&services, "traceroute", target)?;
    let error = expected_scan_error(
        &scanner,
        &request,
        false,
        "unstructured output must not become route evidence",
    )
    .await?;
    assert_eq!(error.kind, ScanErrorKind::InvalidResponse);

    for output in [
        "traceroute to 192.0.2.10, 30 hops max\n1 warning",
        "traceroute to 192.0.2.10, 30 hops max\n2 permission denied",
    ] {
        let (services, _) = command_services(Ok(command_response(0, output, "")));
        let target = Target::parse(TargetKind::Ip, "192.0.2.10")?;
        let (scanner, request) = make_request(&services, "traceroute", target)?;
        let error = expected_scan_error(
            &scanner,
            &request,
            false,
            "numbered diagnostic text must not become a traceroute hop",
        )
        .await?;
        assert_eq!(error.kind, ScanErrorKind::InvalidResponse);
    }
    Ok(())
}

#[tokio::test]
async fn whois_distinguishes_registration_absence_and_redacts_contact_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let target = Target::parse(TargetKind::Domain, "example.com")?;
    let (registered, requests) = command_scan(
        "whois-lookup",
        target.clone(),
        command_response(
            0,
            &format!(
                "Domain Name: EXAMPLE.COM\nRegistrar: Fixture Registrar\nRegistrant Email: {SECRET}\nName Server: NS1.EXAMPLE.COM"
            ),
            "",
        ),
    )
    .await?;
    assert!(has_finding(&registered, "registration-record-observed"));
    assert_eq!(observations(&registered)[0]["details"]["registered"], true);
    assert_eq!(requests[0].kind, CommandKind::Whois);
    assert!(!serde_json::to_string(&registered)?.contains(SECRET));

    let (absent, _) = command_scan(
        "whois-lookup",
        target.clone(),
        command_response(0, "No match for domain EXAMPLE.COM", ""),
    )
    .await?;
    assert_eq!(observations(&absent)[0]["details"]["registered"], false);
    assert!(!has_finding(&absent, "registration-record-observed"));

    let (services, _) = command_services(Ok(command_response(
        1,
        "Domain Name: EXAMPLE.COM\nRegistrar: stale-cache",
        "whois query failed",
    )));
    let (scanner, request) = make_request(&services, "whois-lookup", target.clone())?;
    let error = expected_scan_error(
        &scanner,
        &request,
        false,
        "non-zero WHOIS exit must not turn partial fields into registration evidence",
    )
    .await?;
    assert_eq!(error.kind, ScanErrorKind::InvalidResponse);

    let oversized = "x".repeat(65);
    let (services, _) = command_services(Ok(command_response(0, &oversized, "")));
    let (scanner, mut request) = make_request(&services, "whois-lookup", target)?;
    request.budget = small_budget(1, 64);
    let error = expected_scan_error(
        &scanner,
        &request,
        false,
        "oversized command output must be rejected",
    )
    .await?;
    assert_eq!(error.kind, ScanErrorKind::InvalidResponse);
    Ok(())
}

#[tokio::test]
async fn ssh_fingerprinter_requires_decodable_keys_and_hashes_banner_material()
-> Result<(), Box<dyn std::error::Error>> {
    let target = Target::parse(TargetKind::Domain, "example.com")?;
    let (observed, requests) = command_scan(
        "ssh-banner-key-fingerprinter",
        target.clone(),
        command_response(
            0,
            "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDAxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTAx",
            &format!("# example.com:22 SSH-2.0-OpenSSH_9.3 {SECRET}"),
        ),
    )
    .await?;
    assert!(has_finding(&observed, "ssh-host-key-observed"));
    assert!(has_finding(&observed, "ssh-banner-observed"));
    assert_eq!(
        observations(&observed)[0]["details"]["host_keys"][0]["type"],
        "ssh-ed25519"
    );
    assert_eq!(requests[0].kind, CommandKind::SshKeyscan);
    assert!(!serde_json::to_string(&observed)?.contains(SECRET));

    let (absent, _) = command_scan(
        "ssh-banner-key-fingerprinter",
        target.clone(),
        command_response(1, "", "ssh-keyscan: connection refused"),
    )
    .await?;
    assert!(!has_finding(&absent, "ssh-host-key-observed"));
    assert_eq!(observations(&absent)[0]["details"]["key_count"], 0);

    let (services, _) = command_services(Ok(command_response(
        0,
        "example.com ssh-ed25519 not-base64!",
        "",
    )));
    let (scanner, request) = make_request(&services, "ssh-banner-key-fingerprinter", target)?;
    let error = expected_scan_error(
        &scanner,
        &request,
        false,
        "malformed key material must not become a fingerprint",
    )
    .await?;
    assert_eq!(error.kind, ScanErrorKind::InvalidResponse);
    Ok(())
}

fn base64url(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(TABLE[usize::from(first >> 2)]));
        output.push(char::from(
            TABLE[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        if chunk.len() > 1 {
            output.push(char::from(
                TABLE[usize::from(((second & 0x0f) << 2) | (third >> 6))],
            ));
        }
        if chunk.len() > 2 {
            output.push(char::from(TABLE[usize::from(third & 0x3f)]));
        }
    }
    output
}

fn jwt(header: &str, payload: &str, signature: &[u8]) -> String {
    format!(
        "{}.{}.{}",
        base64url(header.as_bytes()),
        base64url(payload.as_bytes()),
        base64url(signature)
    )
}

#[tokio::test]
async fn local_wordlist_is_deterministic_bounded_and_rejects_wrong_target_kinds()
-> Result<(), Box<dyn std::error::Error>> {
    let services = support::Harness::successful().services();
    let target = Target::parse(TargetKind::Domain, "api-api.example.com")?;
    let (scanner, request) = make_request(&services, "custom-wordlist-generator", target)?;
    let first = scanner.scan(&request, &support::context(false)).await?;
    let second = scanner.scan(&request, &support::context(false)).await?;
    let first_tokens = observations(&first)[0]["tokens"]
        .as_array()
        .ok_or("tokens must be an array")?;
    assert_eq!(observations(&first), observations(&second));
    assert!(first_tokens.len() <= 256);
    assert!(first_tokens.windows(2).all(|pair| {
        pair[0]
            .as_str()
            .zip(pair[1].as_str())
            .is_some_and(|(left, right)| left < right)
    }));
    assert_eq!(
        first_tokens.iter().filter(|token| **token == "api").count(),
        1
    );

    let wrong = Target::parse(TargetKind::Ip, "192.0.2.10")?;
    let mut request = request;
    request.scope = ScopeGrant::exact(&wrong, true, OffsetDateTime::UNIX_EPOCH);
    request.target = wrong;
    let error = expected_scan_error(
        &scanner,
        &request,
        false,
        "the local scanner must enforce its published target kind",
    )
    .await?;
    assert_eq!(error.kind, ScanErrorKind::InvalidInput);
    Ok(())
}

#[tokio::test]
async fn jwt_analysis_reports_structural_risk_without_retaining_claim_values()
-> Result<(), Box<dyn std::error::Error>> {
    let services = support::Harness::successful().services();
    let insecure = jwt(
        r#"{"alg":"none","typ":"JWT"}"#,
        &format!(r#"{{"sub":"{SECRET}","exp":-1}}"#),
        b"",
    );
    let target = Target::parse(TargetKind::Opaque, &insecure)?;
    let (scanner, request) = make_request(&services, "jwt-token-analyzer", target)?;
    let result = scanner.scan(&request, &support::context(false)).await?;
    assert!(has_finding(&result, "unsigned-jwt"));
    assert!(has_finding(&result, "jwt-expired"));
    let serialized = serde_json::to_string(&result)?;
    assert!(!serialized.contains(SECRET));
    assert!(!serialized.contains(&insecure));

    let secure = jwt(
        r#"{"alg":"HS256","typ":"JWT"}"#,
        r#"{"sub":"public-subject","exp":4102444800}"#,
        b"signed",
    );
    let target = Target::parse(TargetKind::Opaque, &secure)?;
    let (_, request) = make_request(&services, "jwt-token-analyzer", target)?;
    let result = scanner.scan(&request, &support::context(false)).await?;
    assert!(result.findings.is_empty());
    assert_eq!(observations(&result)[0]["signature_verified"], false);

    let malformed = Target::parse(TargetKind::Opaque, "only.two")?;
    let (_, request) = make_request(&services, "jwt-token-analyzer", malformed)?;
    let error = expected_scan_error(
        &scanner,
        &request,
        false,
        "malformed compact JWT must be rejected",
    )
    .await?;
    assert_eq!(error.kind, ScanErrorKind::InvalidInput);
    Ok(())
}

#[tokio::test]
async fn command_boundaries_preserve_typed_failures_and_pre_cancel_without_execution()
-> Result<(), Box<dyn std::error::Error>> {
    let target = Target::parse(TargetKind::Ip, "192.0.2.10")?;
    let (services, requests) = command_services(Err(PortError::new(
        PortErrorKind::Unavailable,
        "command unavailable",
    )));
    let (scanner, request) = make_request(&services, "icmp-reachability-matrix", target.clone())?;
    let error = expected_scan_error(
        &scanner,
        &request,
        false,
        "typed boundary failure must be preserved",
    )
    .await?;
    assert_eq!(error.kind, ScanErrorKind::DependencyUnavailable);
    assert_eq!(
        requests.lock().map_err(|_| "request lock poisoned")?.len(),
        1
    );

    let (services, requests) = command_services(Ok(command_response(0, "reply ttl=1", "")));
    let (scanner, request) = make_request(&services, "icmp-reachability-matrix", target)?;
    let error =
        expected_scan_error(&scanner, &request, true, "pre-cancelled request must fail").await?;
    assert_eq!(error.kind, ScanErrorKind::Cancelled);
    assert!(
        requests
            .lock()
            .map_err(|_| "request lock poisoned")?
            .is_empty()
    );
    Ok(())
}
