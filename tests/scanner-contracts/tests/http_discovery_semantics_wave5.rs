//! Public offline contracts for Wave 5 HTTP discovery and exposure scanners.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{Value, json};
use sugra_core::{
    HttpMethod, HttpPort, HttpRequest, HttpResponse, PortError, PortErrorKind, ScanErrorKind,
};
use sugra_domain::{
    Budget, Confidence, ExecutionStatus, Finding, ScanRequest, ScanResult, ScopeRule, Severity,
    TargetKind,
};
use sugra_scanners::build_builtins;

#[allow(dead_code)]
mod support;

const SECRET: &str = "wave5-discovery-secret-7f31";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const SCANNERS: [&str; 9] = [
    "attack-surface-delta",
    "bug-bounty-program-finder",
    "cloud-bucket-exposure",
    "cloud-service-enumeration",
    "directory-finder",
    "exposed-api-endpoints",
    "login-page-brute-identifier",
    "multi-language-url-tester",
    "virtual-host-fuzzer",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Case {
    Positive,
    Negative,
    Edge,
    Bounded,
}

#[derive(Clone)]
struct FixtureHttp {
    scanner_id: &'static str,
    case: Case,
    requests: Arc<Mutex<Vec<HttpRequest>>>,
}

#[async_trait]
impl HttpPort for FixtureHttp {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
        let call = {
            let mut requests = self
                .requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let call = requests.len();
            requests.push(request.clone());
            call
        };
        Ok(fixture_response(self.scanner_id, self.case, call, &request))
    }
}

struct FailingHttp(PortErrorKind);

#[async_trait]
impl HttpPort for FailingHttp {
    async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse, PortError> {
        Err(PortError::new(
            self.0,
            format!("wave5 HTTP {:?} failure", self.0),
        ))
    }
}

struct FirstPartyDisclosureHttp;

#[async_trait]
impl HttpPort for FirstPartyDisclosureHttp {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
        let root = request.url.path() == "/";
        Ok(HttpResponse {
            final_url: request.url,
            status: if root { 200 } else { 404 },
            headers: BTreeMap::from([("content-type".into(), "text/html".into())]),
            cookies: Vec::new(),
            redirects: Vec::new(),
            body: if root {
                br#"<main><a href="/responsible-disclosure">Responsible disclosure</a></main>"#
                    .to_vec()
            } else {
                Vec::new()
            },
            duration_ms: 1,
        })
    }
}

fn fixture_response(
    scanner_id: &str,
    case: Case,
    call: usize,
    request: &HttpRequest,
) -> HttpResponse {
    let mut response = HttpResponse {
        final_url: request.url.clone(),
        status: 404,
        headers: BTreeMap::from([
            ("content-type".into(), "text/html; charset=utf-8".into()),
            ("x-private-fixture".into(), SECRET.into()),
        ]),
        cookies: Vec::new(),
        redirects: Vec::new(),
        body: format!("<p>ordinary response {SECRET}</p>").into_bytes(),
        duration_ms: 5,
    };
    response
        .final_url
        .query_pairs_mut()
        .append_pair("private", SECRET);

    if case == Case::Bounded {
        response.status = 200;
        response.body = format!(
            "<html>{}</html>",
            format!(r#"<a href="/next?secret={SECRET}">next</a>"#).repeat(512)
        )
        .into_bytes();
        for index in 0..300 {
            response
                .headers
                .insert(format!("x-bound-{index:03}"), SECRET.into());
        }
        return response;
    }

    match scanner_id {
        "attack-surface-delta" => configure_attack_surface(&mut response, case),
        "bug-bounty-program-finder" => configure_bug_bounty(&mut response, case, call),
        "cloud-bucket-exposure" | "cloud-service-enumeration" => {
            configure_cloud(&mut response, case, call);
        }
        "directory-finder" => configure_directory(&mut response, case, call),
        "exposed-api-endpoints" => configure_api(&mut response, case, call),
        "login-page-brute-identifier" => configure_login(&mut response, case, call),
        "multi-language-url-tester" => configure_languages(&mut response, case, call),
        "virtual-host-fuzzer" => configure_virtual_host(&mut response, case, call),
        _ => unreachable!("missing fixture for {scanner_id}"),
    }
    response
}

fn configure_attack_surface(response: &mut HttpResponse, case: Case) {
    response.status = 200;
    response.body = match case {
        Case::Positive => format!("changed attack surface {SECRET}").into_bytes(),
        Case::Negative => Vec::new(),
        Case::Edge => b"snapshot without a valid baseline".to_vec(),
        Case::Bounded => unreachable!(),
    };
}

fn configure_bug_bounty(response: &mut HttpResponse, case: Case, call: usize) {
    match (case, call) {
        (Case::Positive, 0) => {
            response.status = 200;
            response.body = b"Policy: https://hackerone.com/example-program".to_vec();
        }
        (Case::Negative, _) => {
            response.status = 200;
            response.body = b"Contact: mailto:security@example.com".to_vec();
        }
        (Case::Edge, 0) => {
            response.status = 200;
            response.body = b"Our bug bountyevil mascot appears in this fictional story.".to_vec();
        }
        _ => {}
    }
}

fn configure_cloud(response: &mut HttpResponse, case: Case, call: usize) {
    match (case, call) {
        (Case::Positive, 0) => {
            response.status = 200;
            response.body = format!(
                r#"<a href="https://public-bucket.s3.amazonaws.com/object?token={SECRET}">asset</a>"#
            )
            .into_bytes();
        }
        (Case::Negative, 0) => {
            response.status = 200;
            response.body = b"<p>No external cloud resources are linked.</p>".to_vec();
        }
        (Case::Edge, 0) => {
            response.status = 200;
            response.body =
                b"<p>Training prose mentions amazonaws.com without a resource URL.</p>".to_vec();
        }
        _ => {}
    }
}

fn configure_directory(response: &mut HttpResponse, case: Case, call: usize) {
    match (case, call) {
        (Case::Positive, 0) => {
            response.status = 404;
            response.body = b"deterministic not-found control".to_vec();
        }
        (Case::Positive, _) => {
            response.status = 200;
            response.body = b"<h1>Administration</h1>".to_vec();
        }
        (Case::Negative, _) => {}
        (Case::Edge, _) => {
            response.status = 200;
            response.body = b"<!doctype html><div id=root>branded SPA fallback</div>".to_vec();
        }
        (Case::Bounded, _) => unreachable!(),
    }
}

fn configure_api(response: &mut HttpResponse, case: Case, call: usize) {
    if call != 0 {
        return;
    }
    match case {
        Case::Positive => {
            response.status = 200;
            response
                .headers
                .insert("content-type".into(), "application/json".into());
            response.body = br#"{"openapi":"3.1.0","paths":{"/users":{}}}"#.to_vec();
        }
        Case::Negative => {}
        Case::Edge => {
            response.status = 200;
            response
                .headers
                .insert("content-type".into(), "application/json".into());
            response.body = br#"{"error":"route not found","status":404}"#.to_vec();
        }
        Case::Bounded => unreachable!(),
    }
}

fn configure_login(response: &mut HttpResponse, case: Case, call: usize) {
    if call != 0 {
        return;
    }
    response.status = 200;
    response.body = match case {
        Case::Positive => {
            b"<form method=post><input name=user><input type=password name=password></form>"
                .to_vec()
        }
        Case::Negative => b"<form><input name=search></form>".to_vec(),
        Case::Edge => b"<password-input>custom component documentation</password-input>".to_vec(),
        Case::Bounded => unreachable!(),
    };
}

fn configure_languages(response: &mut HttpResponse, case: Case, call: usize) {
    response.status = match case {
        Case::Positive if call > 0 => 404,
        Case::Positive | Case::Negative => 200,
        Case::Edge if call.is_multiple_of(2) => 200,
        Case::Edge => 201,
        Case::Bounded => unreachable!(),
    };
    response.body = format!("locale sample {call}").into_bytes();
}

fn configure_virtual_host(response: &mut HttpResponse, case: Case, call: usize) {
    response.status = 200;
    response.body = match case {
        Case::Positive if call == 1 => b"authorized alternate host".to_vec(),
        Case::Positive | Case::Negative => b"baseline host".to_vec(),
        Case::Edge => b"scope-filtered baseline".to_vec(),
        Case::Bounded => unreachable!(),
    };
}

struct Run {
    result: ScanResult,
    requests: Vec<HttpRequest>,
}

async fn scan_case(
    scanner_id: &'static str,
    case: Case,
) -> Result<Run, Box<dyn std::error::Error>> {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut services = support::Harness::successful().services();
    services.http = Arc::new(FixtureHttp {
        scanner_id,
        case,
        requests: Arc::clone(&requests),
    });
    let builtins = build_builtins(&services)?;
    let id = sugra_domain::ScannerId::new(scanner_id)?;
    let scanner = builtins.registry.get(&id).ok_or("scanner is missing")?;
    let mut request = support::request_for(scanner.descriptor())?;
    configure_request(&mut request, scanner_id, case);
    let result = scanner.scan(&request, &support::context(false)).await?;
    let requests = requests
        .lock()
        .map_err(|_| "request log is unavailable")?
        .clone();
    Ok(Run { result, requests })
}

fn configure_request(request: &mut ScanRequest, scanner_id: &str, case: Case) {
    match scanner_id {
        "attack-surface-delta" => {
            let baseline = match case {
                Case::Positive | Case::Bounded => "0".repeat(64),
                Case::Negative => EMPTY_SHA256.into(),
                Case::Edge => "not-a-sha256".into(),
            };
            request
                .options
                .insert("baseline_sha256".into(), Value::String(baseline));
        }
        "directory-finder" => {
            request.options.insert(
                "wordlist".into(),
                json!(["admin/", "https://out-of-scope.invalid/private"]),
            );
        }
        "login-page-brute-identifier" => {
            request
                .options
                .insert("paths".into(), json!(["/custom-login"]));
            request
                .options
                .insert("follow_redirects".into(), json!(false));
        }
        "virtual-host-fuzzer" => {
            request.scope.rules = vec![ScopeRule::Domain("example.com".into())];
            request.options.insert(
                "hosts".into(),
                if case == Case::Edge {
                    json!(["out-of-scope.invalid"])
                } else {
                    json!(["alt.example.com", "out-of-scope.invalid"])
                },
            );
        }
        _ => {}
    }
}

fn expected_contract(id: &str) -> (&'static str, &'static str) {
    match id {
        "attack-surface-delta" => (
            "web-change-analysis",
            "Build a deterministic attack-surface snapshot for comparison.",
        ),
        "bug-bounty-program-finder" => (
            "web-metadata-analysis",
            "Discover published vulnerability-disclosure programs.",
        ),
        "cloud-bucket-exposure" => (
            "web-exposure-analysis",
            "Check bounded cloud-storage exposure candidates.",
        ),
        "cloud-service-enumeration" => (
            "web-exposure-analysis",
            "Discover public cloud-service indicators.",
        ),
        "directory-finder" => (
            "authorized-web-probe-analysis",
            "Probe a bounded set of common directories.",
        ),
        "exposed-api-endpoints" => (
            "web-exposure-analysis",
            "Probe a bounded set of common API endpoints.",
        ),
        "login-page-brute-identifier" => (
            "technology-detection-analysis",
            "Locate authentication surfaces without attempting credentials.",
        ),
        "multi-language-url-tester" => (
            "web-metadata-analysis",
            "Inspect alternate-language URL publication.",
        ),
        "virtual-host-fuzzer" => (
            "authorized-web-probe-analysis",
            "Probe an explicitly bounded virtual-host candidate set.",
        ),
        _ => unreachable!("missing contract for {id}"),
    }
}

fn expected_finding(id: &str, evidence: Vec<usize>) -> Finding {
    let (key, title, severity, confidence) = match id {
        "attack-surface-delta" => (
            "attack-surface-changed",
            "The current response fingerprint differs from the supplied baseline",
            Severity::Info,
            Confidence::Confirmed,
        ),
        "bug-bounty-program-finder" => (
            "disclosure-program-observed",
            "A vulnerability disclosure or bug bounty program is referenced",
            Severity::Info,
            Confidence::Confirmed,
        ),
        "cloud-bucket-exposure" => (
            "cloud-storage-reference-observed",
            "A public cloud-storage reference is present",
            Severity::Info,
            Confidence::Inferred,
        ),
        "cloud-service-enumeration" => (
            "cloud-service-signal-observed",
            "A public cloud-service signal is present",
            Severity::Info,
            Confidence::Inferred,
        ),
        "directory-finder" => (
            "directory-response-observed",
            "A candidate path differs from the deterministic not-found control",
            Severity::Info,
            Confidence::Inferred,
        ),
        "exposed-api-endpoints" => (
            "api-surface-observed",
            "A public API surface is reachable",
            Severity::Info,
            Confidence::Confirmed,
        ),
        "login-page-brute-identifier" => (
            "login-surface-observed",
            "A password-based login surface is present",
            Severity::Info,
            Confidence::Confirmed,
        ),
        "multi-language-url-tester" => (
            "locale-status-varies",
            "Locale paths returned different HTTP status classes",
            Severity::Info,
            Confidence::Confirmed,
        ),
        "virtual-host-fuzzer" => (
            "virtual-host-response-differs",
            "An authorized Host candidate returned a distinct response",
            Severity::Info,
            Confidence::Inferred,
        ),
        _ => unreachable!("missing finding for {id}"),
    };
    Finding {
        key: key.into(),
        title: title.into(),
        severity,
        confidence,
        evidence,
    }
}

fn positive_evidence(id: &str) -> Vec<usize> {
    match id {
        "directory-finder" | "virtual-host-fuzzer" => vec![0, 1],
        "multi-language-url-tester" => (0..5).collect(),
        _ => vec![0],
    }
}

fn attack_surface_supplement_findings() -> Vec<Finding> {
    [(22, 4_usize), (53, 5_usize)]
        .into_iter()
        .map(|(port, evidence)| Finding {
            key: "tcp-port-open".into(),
            title: format!("TCP port {port} accepted a connection"),
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
            evidence: vec![evidence],
        })
        .collect()
}

fn assert_envelope(run: &Run, id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (analysis, purpose) = expected_contract(id);
    assert_eq!(run.result.status, ExecutionStatus::Completed, "{id}");
    assert!(run.result.diagnostics.is_empty(), "{id}");
    if id == "attack-surface-delta" {
        assert_eq!(run.requests.len(), 1);
        assert_eq!(run.result.evidence.len(), 6);
        let observed_analyses = run
            .result
            .evidence
            .iter()
            .map(|evidence| {
                evidence.observation["analysis"]
                    .as_str()
                    .unwrap_or_default()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            observed_analyses,
            BTreeSet::from([
                "asset-source-analysis",
                "dns-topology-analysis",
                "tcp-port-analysis",
                "web-change-analysis",
            ])
        );
        for evidence in &run.result.evidence {
            assert!(evidence.kind.starts_with("attack-surface-delta-"));
            assert_eq!(evidence.observation["scanner_id"], id);
            assert_eq!(evidence.observation["purpose"], purpose);
            assert_eq!(
                object_keys(&evidence.observation),
                BTreeSet::from(["analysis", "observation", "purpose", "scanner_id"])
            );
        }
        let serialized = serde_json::to_string(&run.result)?;
        assert!(!serialized.contains(SECRET));
        return Ok(());
    }
    assert_eq!(run.result.evidence.len(), run.requests.len(), "{id}");
    for evidence in &run.result.evidence {
        assert_eq!(evidence.kind, format!("{id}-http-observation"), "{id}");
        assert!(!evidence.source.contains('?'), "{id}");
        assert_eq!(evidence.observation["scanner_id"], id, "{id}");
        assert_eq!(evidence.observation["analysis"], analysis, "{id}");
        assert_eq!(evidence.observation["purpose"], purpose, "{id}");
        assert_eq!(
            object_keys(&evidence.observation),
            BTreeSet::from(["analysis", "observation", "purpose", "scanner_id"]),
            "{id}"
        );
        assert_eq!(
            object_keys(&evidence.observation["observation"]),
            BTreeSet::from([
                "bytes",
                "cookies",
                "document",
                "duration_ms",
                "headers",
                "method",
                "probe",
                "redirects",
                "sha256",
                "status",
            ]),
            "{id}"
        );
    }
    let serialized = serde_json::to_string(&run.result)?;
    assert!(!serialized.contains(SECRET), "{id}");
    assert!(run.result.findings.iter().all(|finding| {
        finding
            .evidence
            .iter()
            .all(|index| *index < run.result.evidence.len())
    }));
    Ok(())
}

fn object_keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .into_iter()
        .flat_map(|object| object.keys().map(String::as_str))
        .collect()
}

#[tokio::test]
async fn every_discovery_scanner_proves_real_positive_negative_and_edge_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    for id in SCANNERS {
        let positive = scan_case(id, Case::Positive).await?;
        assert_envelope(&positive, id)?;
        let mut expected_positive = vec![expected_finding(id, positive_evidence(id))];
        if id == "attack-surface-delta" {
            expected_positive.extend(attack_surface_supplement_findings());
        }
        assert_eq!(
            positive.result.findings, expected_positive,
            "{id}: positive"
        );
        assert_plan(id, Case::Positive, &positive.requests);

        let negative = scan_case(id, Case::Negative).await?;
        assert_envelope(&negative, id)?;
        let expected_non_change = if id == "attack-surface-delta" {
            attack_surface_supplement_findings()
        } else {
            Vec::new()
        };
        assert_eq!(
            negative.result.findings, expected_non_change,
            "{id}: negative"
        );

        let edge = scan_case(id, Case::Edge).await?;
        assert_envelope(&edge, id)?;
        let expected_non_change = if id == "attack-surface-delta" {
            attack_surface_supplement_findings()
        } else {
            Vec::new()
        };
        assert_eq!(edge.result.findings, expected_non_change, "{id}: edge");
    }
    Ok(())
}

fn assert_plan(id: &str, case: Case, requests: &[HttpRequest]) {
    let paths = requests
        .iter()
        .map(|request| request.url.path().to_owned())
        .collect::<Vec<_>>();
    match id {
        "attack-surface-delta" => assert_eq!(paths, ["/"]),
        "bug-bounty-program-finder" => {
            assert_eq!(paths, ["/.well-known/security.txt", "/security.txt", "/"]);
        }
        "cloud-bucket-exposure" | "cloud-service-enumeration" => assert_eq!(
            paths,
            [
                "/",
                "/.well-known/assetlinks.json",
                "/.well-known/apple-app-site-association",
            ]
        ),
        "directory-finder" => assert_eq!(
            paths,
            ["/.well-known/sugra-directory-control-not-found", "/admin/"]
        ),
        "exposed-api-endpoints" => {
            assert_eq!(paths, ["/api", "/api/v1", "/swagger", "/openapi.json"]);
        }
        "login-page-brute-identifier" => {
            assert_eq!(paths, ["/custom-login"]);
            assert_eq!(requests[0].max_redirects, 0);
        }
        "multi-language-url-tester" => {
            assert_eq!(paths, ["/", "/en/", "/es/", "/fr/", "/pt/"]);
        }
        "virtual-host-fuzzer" => {
            assert_eq!(paths, ["/", "/"]);
            assert!(requests[0].headers.is_empty());
            assert_eq!(
                requests[1].headers.get("host").map(String::as_str),
                Some("alt.example.com")
            );
            assert!(requests.iter().all(|request| {
                !request
                    .headers
                    .values()
                    .any(|value| value.contains("out-of-scope.invalid"))
            }));
            assert_eq!(case, Case::Positive);
        }
        _ => unreachable!("missing plan for {id}"),
    }
    assert!(
        requests
            .iter()
            .all(|request| request.method == HttpMethod::Get)
    );
    assert!(requests.iter().all(|request| request.body.is_empty()));
}

#[test]
fn descriptors_publish_exact_target_kinds_and_typed_option_keys()
-> Result<(), Box<dyn std::error::Error>> {
    let builtins = build_builtins(&support::Harness::successful().services())?;
    for id in SCANNERS {
        let scanner_id = sugra_domain::ScannerId::new(id)?;
        let scanner = builtins
            .registry
            .get(&scanner_id)
            .ok_or("scanner is missing")?;
        let descriptor = scanner.descriptor();
        let (target_kinds, options): (&[TargetKind], &[&str]) = match id {
            "attack-surface-delta" => (
                &[TargetKind::Domain],
                &["baseline_sha256", "ports_top", "timeout"],
            ),
            "bug-bounty-program-finder" => (&[TargetKind::Domain], &["timeout", "workers"]),
            "cloud-bucket-exposure" => (&[TargetKind::Domain], &["timeout"]),
            "cloud-service-enumeration" => (&[TargetKind::Domain], &[]),
            "directory-finder" => (
                &[TargetKind::Domain, TargetKind::Url],
                &["status_keep", "timeout", "wordlist"],
            ),
            "exposed-api-endpoints" => (&[TargetKind::Domain, TargetKind::Url], &[]),
            "login-page-brute-identifier" => (
                &[TargetKind::Domain, TargetKind::Url],
                &["follow_redirects", "paths", "paths_file", "timeout"],
            ),
            "multi-language-url-tester" => (&[TargetKind::Domain, TargetKind::Url], &["timeout"]),
            "virtual-host-fuzzer" => (&[TargetKind::Domain], &["hosts"]),
            _ => unreachable!(),
        };
        assert_eq!(descriptor.target_kinds, target_kinds, "{id}");
        assert_eq!(
            descriptor
                .options
                .iter()
                .map(|option| option.key.as_str())
                .collect::<Vec<_>>(),
            options,
            "{id}"
        );
        assert!(
            descriptor
                .options
                .iter()
                .all(|option| option.validate().is_ok())
        );
    }
    Ok(())
}

#[tokio::test]
async fn every_discovery_scanner_preserves_all_http_error_kinds()
-> Result<(), Box<dyn std::error::Error>> {
    let matrix = [
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
    ];
    for id in SCANNERS {
        for (port_kind, scan_kind) in matrix {
            let mut services = support::Harness::successful().services();
            services.http = Arc::new(FailingHttp(port_kind));
            let builtins = build_builtins(&services)?;
            let scanner_id = sugra_domain::ScannerId::new(id)?;
            let scanner = builtins
                .registry
                .get(&scanner_id)
                .ok_or("scanner is missing")?;
            let mut request = support::request_for(scanner.descriptor())?;
            configure_request(&mut request, id, Case::Positive);
            let outcome = scanner.scan(&request, &support::context(false)).await;
            if id == "attack-surface-delta" {
                let result = outcome?;
                assert_eq!(
                    result.status,
                    ExecutionStatus::Partial,
                    "{id}: {port_kind:?}"
                );
                assert!(result.diagnostics.iter().any(|diagnostic| {
                    diagnostic.kind == "analysis-stage-unavailable"
                        && diagnostic.message
                            == format!("web-change-analysis stage unavailable ({scan_kind:?})")
                }));
            } else {
                let Err(error) = outcome else {
                    return Err(format!("{id}: {port_kind:?} became success").into());
                };
                assert_eq!(error.kind, scan_kind, "{id}: {port_kind:?}");
                assert_eq!(error.message, format!("wave5 HTTP {port_kind:?} failure"));
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn every_discovery_scanner_is_cancel_safe_bounded_and_redacted()
-> Result<(), Box<dyn std::error::Error>> {
    for id in SCANNERS {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mut services = support::Harness::successful().services();
        services.http = Arc::new(FixtureHttp {
            scanner_id: id,
            case: Case::Bounded,
            requests: Arc::clone(&requests),
        });
        let builtins = build_builtins(&services)?;
        let scanner_id = sugra_domain::ScannerId::new(id)?;
        let scanner = builtins
            .registry
            .get(&scanner_id)
            .ok_or("scanner is missing")?;
        let mut request = support::request_for(scanner.descriptor())?;
        let budget = Budget {
            max_requests: 2,
            max_response_bytes: 4_096,
            ..request.budget
        }
        .validate()?;
        request.budget = budget;
        configure_request(&mut request, id, Case::Bounded);

        let cancelled = scanner.scan(&request, &support::context(true)).await;
        let Err(error) = cancelled else {
            return Err(format!("{id}: cancelled scan became success").into());
        };
        assert_eq!(error.kind, ScanErrorKind::Cancelled, "{id}");
        assert!(
            requests
                .lock()
                .map_err(|_| "request log unavailable")?
                .is_empty()
        );

        let result = scanner.scan(&request, &support::context(false)).await?;
        let requests = requests.lock().map_err(|_| "request log unavailable")?;
        assert!(!requests.is_empty(), "{id}");
        assert!(requests.len() <= 2, "{id}");
        if id == "attack-surface-delta" {
            assert_eq!(result.status, ExecutionStatus::Partial);
            assert_eq!(result.evidence.len(), 2);
            assert_eq!(requests.len(), 1);
        } else {
            assert_eq!(result.evidence.len(), requests.len(), "{id}");
        }
        if id == "attack-surface-delta" {
            let stage_budget = Budget {
                max_requests: 1,
                ..budget
            };
            assert!(
                requests
                    .iter()
                    .all(|request| request.budget == stage_budget)
            );
        } else {
            assert!(requests.iter().all(|request| request.budget == budget));
        }
        let serialized = serde_json::to_string(&result)?;
        assert!(!serialized.contains(SECRET), "{id}");
        assert!(serialized.len() < 100_000, "{id}");
        let http_evidence = result
            .evidence
            .iter()
            .filter_map(|evidence| evidence.observation["observation"]["headers"].as_array());
        assert!(http_evidence.clone().all(|headers| headers.len() <= 256));
        assert!(http_evidence.count() >= requests.len(), "{id}");
    }
    Ok(())
}

#[test]
fn discovery_fixture_covers_exactly_the_assigned_ids() {
    assert_eq!(
        SCANNERS.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "attack-surface-delta",
            "bug-bounty-program-finder",
            "cloud-bucket-exposure",
            "cloud-service-enumeration",
            "directory-finder",
            "exposed-api-endpoints",
            "login-page-brute-identifier",
            "multi-language-url-tester",
            "virtual-host-fuzzer",
        ])
    );
}

#[tokio::test]
async fn bug_bounty_contract_accepts_a_structured_first_party_disclosure_page()
-> Result<(), Box<dyn std::error::Error>> {
    let mut services = support::Harness::successful().services();
    services.http = Arc::new(FirstPartyDisclosureHttp);
    let builtins = build_builtins(&services)?;
    let id = sugra_domain::ScannerId::new("bug-bounty-program-finder")?;
    let scanner = builtins.registry.get(&id).ok_or("scanner is missing")?;
    let request = support::request_for(scanner.descriptor())?;
    let result = scanner.scan(&request, &support::context(false)).await?;

    assert_eq!(result.status, ExecutionStatus::Completed);
    assert_eq!(result.findings.len(), 1);
    assert_eq!(result.findings[0].key, "disclosure-program-observed");
    assert_eq!(result.findings[0].evidence, [result.evidence.len() - 1]);
    Ok(())
}
