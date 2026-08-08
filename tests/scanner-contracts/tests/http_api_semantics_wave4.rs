//! Public offline contracts for the fourth HTTP/API semantic wave.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::Value;
use sugra_core::{
    HttpCookie, HttpMethod, HttpPort, HttpRequest, HttpResponse, PortError, PortErrorKind,
    ScanErrorKind,
};
use sugra_domain::{Budget, Confidence, ExecutionStatus, ScanResult, Severity};
use sugra_scanners::build_builtins;

#[allow(dead_code)]
mod support;

const SCANNERS: [&str; 4] = [
    "form-grabber",
    "graphql-introspection-probe",
    "http-method-enumerator",
    "websocket-endpoint-sniffer",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Positive,
    Negative,
    Edge,
    MethodPost,
    MethodPatch,
    WebsocketJsonScript,
    WebsocketLdJsonScript,
    Bounded,
}

struct FixtureHttp {
    scanner_id: String,
    scenario: Scenario,
    requests: Arc<Mutex<Vec<HttpRequest>>>,
}

#[async_trait]
impl HttpPort for FixtureHttp {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
        let call = {
            let mut requests = self.requests.lock().map_err(|_| {
                PortError::new(
                    PortErrorKind::Internal,
                    "fixture request log is unavailable",
                )
            })?;
            let call = requests.len();
            requests.push(request.clone());
            call
        };
        Ok(fixture_response(
            &self.scanner_id,
            self.scenario,
            call,
            &request,
        ))
    }
}

struct ErrorHttp(PortErrorKind);

#[async_trait]
impl HttpPort for ErrorHttp {
    async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse, PortError> {
        Err(PortError::new(
            self.0,
            format!("offline {:?} fixture failure", self.0),
        ))
    }
}

fn fixture_response(
    scanner_id: &str,
    scenario: Scenario,
    call: usize,
    request: &HttpRequest,
) -> HttpResponse {
    let mut response = HttpResponse {
        final_url: request.url.clone(),
        status: 200,
        headers: BTreeMap::from([("content-type".into(), "text/html; charset=utf-8".into())]),
        cookies: Vec::new(),
        redirects: Vec::new(),
        body: fixture_body(scanner_id, scenario, call).into_bytes(),
        duration_ms: 7,
    };

    if scanner_id == "graphql-introspection-probe" {
        response
            .headers
            .insert("content-type".into(), "application/json".into());
        if scenario == Scenario::Edge {
            response.status = 204;
        }
    }
    if scanner_id == "http-method-enumerator" {
        let allow = match scenario {
            Scenario::Positive if request.method == HttpMethod::Options => {
                Some("GET, HEAD, OPTIONS, PUT")
            }
            Scenario::MethodPost if request.method == HttpMethod::Options => {
                Some("GET, HEAD, OPTIONS, POST")
            }
            Scenario::MethodPatch if request.method == HttpMethod::Options => {
                Some("GET, HEAD, OPTIONS, PATCH")
            }
            Scenario::Negative => Some("GET, HEAD, OPTIONS"),
            Scenario::Edge => Some("GET, HEAD, OPTIONS, DISCONNECT"),
            _ => None,
        };
        if let Some(allow) = allow {
            response.headers.insert("allow".into(), allow.into());
        }
    }
    if scenario == Scenario::Bounded {
        add_bounded_metadata(&mut response);
    }
    response
}

fn fixture_body(scanner_id: &str, scenario: Scenario, call: usize) -> String {
    if scenario == Scenario::Bounded {
        if call == 0 && matches!(scanner_id, "form-grabber" | "websocket-endpoint-sniffer") {
            let mut body = String::new();
            for index in 0..20 {
                let _ = write!(
                    body,
                    r#"<a href="/child-{index}?token={}">child</a>"#,
                    support::SECRET_MARKER
                );
            }
            return body;
        }
        return format!("bounded response {}", support::SECRET_MARKER);
    }

    match (scanner_id, scenario) {
        ("form-grabber", Scenario::Positive) => format!(
            r#"<form method="post" action="/submit?token={}"><input name="email"></form>"#,
            support::SECRET_MARKER
        ),
        ("form-grabber", Scenario::Negative) => "<p>No interactive controls.</p>".into(),
        ("form-grabber", Scenario::Edge) => {
            "<formless>This custom element is not an HTML form.</formless>".into()
        }
        ("graphql-introspection-probe", Scenario::Positive) => format!(
            r#"{{"data":{{"__schema":{{"queryType":{{"name":"{}"}}}}}}}}"#,
            support::SECRET_MARKER
        ),
        ("graphql-introspection-probe", Scenario::Negative) => {
            r#"{"data":{"queryType":{"name":"Query"}}}"#.into()
        }
        ("graphql-introspection-probe", Scenario::Edge) => {
            r#"{"data":{"__schema":{"queryType":{"name":"Query"}}}}"#.into()
        }
        ("http-method-enumerator", _) => format!("method response {}", support::SECRET_MARKER),
        ("websocket-endpoint-sniffer", Scenario::Positive) => format!(
            r#"<script>const channel = new WebSocket("wss://example.com/live?token={}");</script>"#,
            support::SECRET_MARKER
        ),
        ("websocket-endpoint-sniffer", Scenario::Negative) => {
            "<script>const channel = new EventSource('/events');</script>".into()
        }
        ("websocket-endpoint-sniffer", Scenario::Edge) => {
            "<p>The WebSocket() constructor is mentioned in documentation only.</p>".into()
        }
        ("websocket-endpoint-sniffer", Scenario::WebsocketJsonScript) => r#"
            <script type="application/json">
                {"endpoint":"wss://example.com/live","decoder":"atob(payload)","client":"new WebSocket(endpoint)"}
            </script>
        "#
        .into(),
        ("websocket-endpoint-sniffer", Scenario::WebsocketLdJsonScript) => r#"
            <script type="application/ld+json">
                {"@context":"https://schema.org","endpoint":"ws://example.com/live","decoder":"eval(atob(payload))"}
            </script>
        "#
        .into(),
        _ => String::new(),
    }
}

fn add_bounded_metadata(response: &mut HttpResponse) {
    for index in 0..300 {
        response.headers.insert(
            format!("x-fixture-{index:03}"),
            format!("{}-{index}", support::SECRET_MARKER),
        );
        response.cookies.push(HttpCookie {
            name_sha256: format!("cookie-fingerprint-{index:03}"),
            domain: Some(format!("{}.invalid", support::SECRET_MARKER)),
            path: Some(format!("/private/{index}")),
            secure: true,
            http_only: true,
            same_site: Some("Lax".into()),
            max_age_seconds: Some(60),
        });
    }
}

struct Run {
    result: ScanResult,
    requests: Vec<HttpRequest>,
}

async fn scan(
    id: &str,
    scenario: Scenario,
    max_requests: usize,
) -> Result<Run, Box<dyn std::error::Error>> {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut services = support::Harness::successful().services();
    services.http = Arc::new(FixtureHttp {
        scanner_id: id.into(),
        scenario,
        requests: Arc::clone(&requests),
    });
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new(id)?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("fixture scanner is missing")?;
    let mut request = support::request_for(scanner.descriptor())?;
    request.budget = Budget {
        max_requests,
        ..request.budget
    }
    .validate()?;
    let result = scanner.scan(&request, &support::context(false)).await?;
    let requests = requests
        .lock()
        .map_err(|_| "fixture request log is unavailable")?
        .clone();
    Ok(Run { result, requests })
}

fn annotation(id: &str) -> Option<(&'static str, &'static str)> {
    match id {
        "form-grabber" => Some((
            "web-inventory-analysis",
            "Inventory public forms, methods, and actions.",
        )),
        "graphql-introspection-probe" => Some((
            "api-surface-analysis",
            "Check scoped GraphQL introspection behavior.",
        )),
        "http-method-enumerator" => {
            Some(("api-surface-analysis", "Observe allowed safe HTTP methods."))
        }
        "websocket-endpoint-sniffer" => Some((
            "api-surface-analysis",
            "Discover WebSocket endpoint indicators.",
        )),
        _ => None,
    }
}

fn assert_completed(run: &Run, id: &str, evidence_count: usize) {
    let (analysis, purpose) = annotation(id).unwrap_or(("missing", "missing"));
    assert_eq!(run.result.status, ExecutionStatus::Completed, "{id}");
    assert!(run.result.diagnostics.is_empty(), "{id}");
    assert_eq!(run.result.evidence.len(), evidence_count, "{id}");
    for evidence in &run.result.evidence {
        assert_eq!(evidence.kind, format!("{id}-http-observation"), "{id}");
        assert_eq!(evidence.observation["scanner_id"], id, "{id}");
        assert_eq!(evidence.observation["analysis"], analysis, "{id}");
        assert_eq!(evidence.observation["purpose"], purpose, "{id}");
        assert!(evidence.observation["observation"].is_object(), "{id}");
    }
}

fn assert_finding(
    result: &ScanResult,
    key: &str,
    title: &str,
    severity: Severity,
    evidence: &[usize],
) {
    assert_eq!(result.findings.len(), 1);
    let finding = &result.findings[0];
    assert_eq!(finding.key, key);
    assert_eq!(finding.title, title);
    assert_eq!(finding.severity, severity);
    assert_eq!(finding.confidence, Confidence::Confirmed);
    assert_eq!(finding.evidence, evidence);
}

fn observation(run: &Run, index: usize) -> &Value {
    &run.result.evidence[index].observation["observation"]
}

fn assert_redacted(result: &ScanResult) -> Result<(), Box<dyn std::error::Error>> {
    assert!(!serde_json::to_string(result)?.contains(support::SECRET_MARKER));
    Ok(())
}

#[tokio::test]
async fn form_grabber_proves_positive_negative_and_parser_edge_contracts()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("form-grabber", Scenario::Positive, 8).await?;
    assert_completed(&positive, "form-grabber", 1);
    assert_finding(
        &positive.result,
        "web-forms-observed",
        "One or more web forms are present",
        Severity::Info,
        &[0],
    );
    assert_eq!(observation(&positive, 0)["document"]["forms"], 1);
    assert_eq!(observation(&positive, 0)["document"]["inputs"], 1);
    assert_root_get_plan(&positive.requests);
    assert_root_evidence(&positive);
    assert_redacted(&positive.result)?;

    let negative = scan("form-grabber", Scenario::Negative, 8).await?;
    assert_completed(&negative, "form-grabber", 1);
    assert!(negative.result.findings.is_empty());
    assert_eq!(observation(&negative, 0)["document"]["forms"], 0);
    assert_root_evidence(&negative);

    let edge = scan("form-grabber", Scenario::Edge, 8).await?;
    assert_completed(&edge, "form-grabber", 1);
    assert!(edge.result.findings.is_empty());
    assert_eq!(observation(&edge, 0)["document"]["forms"], 0);
    assert_root_evidence(&edge);
    Ok(())
}

#[tokio::test]
async fn graphql_probe_proves_positive_negative_status_edge_and_exact_post()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("graphql-introspection-probe", Scenario::Positive, 8).await?;
    assert_completed(&positive, "graphql-introspection-probe", 1);
    assert_finding(
        &positive.result,
        "graphql-introspection-enabled",
        "The GraphQL endpoint returned schema introspection metadata",
        Severity::Low,
        &[0],
    );
    assert_graphql_plan(&positive.requests);
    assert_eq!(observation(&positive, 0)["status"], 200);
    assert_eq!(observation(&positive, 0)["method"], "POST");
    assert_graphql_evidence(&positive, 200);
    assert_redacted(&positive.result)?;

    let negative = scan("graphql-introspection-probe", Scenario::Negative, 8).await?;
    assert_completed(&negative, "graphql-introspection-probe", 1);
    assert!(negative.result.findings.is_empty());
    assert_eq!(observation(&negative, 0)["status"], 200);
    assert_graphql_evidence(&negative, 200);

    let edge = scan("graphql-introspection-probe", Scenario::Edge, 8).await?;
    assert_completed(&edge, "graphql-introspection-probe", 1);
    assert!(edge.result.findings.is_empty());
    assert_eq!(observation(&edge, 0)["status"], 204);
    assert_graphql_evidence(&edge, 204);
    Ok(())
}

#[tokio::test]
async fn method_enumerator_proves_positive_negative_and_exact_token_edge()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("http-method-enumerator", Scenario::Positive, 8).await?;
    assert_completed(&positive, "http-method-enumerator", 3);
    assert_finding(
        &positive.result,
        "state-changing-http-method-advertised",
        "The server advertises a state-changing or diagnostic HTTP method",
        Severity::Low,
        &[2],
    );
    assert_method_plan(&positive.requests, 3);
    assert_method_evidence(&positive);
    assert_redacted(&positive.result)?;

    let negative = scan("http-method-enumerator", Scenario::Negative, 8).await?;
    assert_completed(&negative, "http-method-enumerator", 3);
    assert!(negative.result.findings.is_empty());
    assert_method_evidence(&negative);

    let edge = scan("http-method-enumerator", Scenario::Edge, 8).await?;
    assert_completed(&edge, "http-method-enumerator", 3);
    assert!(
        edge.result.findings.is_empty(),
        "DISCONNECT is not the CONNECT method"
    );
    assert_method_evidence(&edge);
    Ok(())
}

#[tokio::test]
async fn method_enumerator_recognizes_post_as_an_exact_allow_token()
-> Result<(), Box<dyn std::error::Error>> {
    assert_sensitive_method_scenario(Scenario::MethodPost).await
}

#[tokio::test]
async fn method_enumerator_recognizes_patch_as_an_exact_allow_token()
-> Result<(), Box<dyn std::error::Error>> {
    assert_sensitive_method_scenario(Scenario::MethodPatch).await
}

async fn assert_sensitive_method_scenario(
    scenario: Scenario,
) -> Result<(), Box<dyn std::error::Error>> {
    let run = scan("http-method-enumerator", scenario, 8).await?;
    assert_completed(&run, "http-method-enumerator", 3);
    assert_finding(
        &run.result,
        "state-changing-http-method-advertised",
        "The server advertises a state-changing or diagnostic HTTP method",
        Severity::Low,
        &[2],
    );
    assert_method_evidence(&run);
    Ok(())
}

#[tokio::test]
async fn websocket_sniffer_proves_positive_negative_and_prose_edge_contracts()
-> Result<(), Box<dyn std::error::Error>> {
    let positive = scan("websocket-endpoint-sniffer", Scenario::Positive, 8).await?;
    assert_completed(&positive, "websocket-endpoint-sniffer", 1);
    assert_finding(
        &positive.result,
        "websocket-reference-observed",
        "A WebSocket endpoint reference is present",
        Severity::Info,
        &[0],
    );
    assert_eq!(
        observation(&positive, 0)["document"]["websocket_references"],
        2
    );
    assert_root_get_plan(&positive.requests);
    assert_root_evidence(&positive);
    assert_redacted(&positive.result)?;

    let negative = scan("websocket-endpoint-sniffer", Scenario::Negative, 8).await?;
    assert_completed(&negative, "websocket-endpoint-sniffer", 1);
    assert!(negative.result.findings.is_empty());
    assert_eq!(
        observation(&negative, 0)["document"]["websocket_references"],
        0
    );
    assert_root_evidence(&negative);

    let edge = scan("websocket-endpoint-sniffer", Scenario::Edge, 8).await?;
    assert_completed(&edge, "websocket-endpoint-sniffer", 1);
    assert!(
        edge.result.findings.is_empty(),
        "documentation prose is not an executable WebSocket reference"
    );
    assert_root_evidence(&edge);
    Ok(())
}

#[tokio::test]
async fn websocket_sniffer_ignores_application_json_data_scripts()
-> Result<(), Box<dyn std::error::Error>> {
    let run = scan(
        "websocket-endpoint-sniffer",
        Scenario::WebsocketJsonScript,
        8,
    )
    .await?;
    assert_completed(&run, "websocket-endpoint-sniffer", 1);
    assert!(
        run.result.findings.is_empty(),
        "application/json script data is not executable JavaScript"
    );
    assert_eq!(observation(&run, 0)["document"]["websocket_references"], 0);
    assert_root_evidence(&run);
    Ok(())
}

#[tokio::test]
async fn websocket_sniffer_ignores_application_ld_json_data_scripts()
-> Result<(), Box<dyn std::error::Error>> {
    let run = scan(
        "websocket-endpoint-sniffer",
        Scenario::WebsocketLdJsonScript,
        8,
    )
    .await?;
    assert_completed(&run, "websocket-endpoint-sniffer", 1);
    assert!(
        run.result.findings.is_empty(),
        "application/ld+json script data is not executable JavaScript"
    );
    assert_eq!(observation(&run, 0)["document"]["websocket_references"], 0);
    assert_root_evidence(&run);
    Ok(())
}

fn assert_root_evidence(run: &Run) {
    assert_eq!(run.result.evidence.len(), 1);
    let evidence = &run.result.evidence[0];
    assert_eq!(evidence.source, "https://example.com/");
    let projected = &evidence.observation["observation"];
    assert_eq!(
        projected["probe"],
        "path-0:8a5edab282632443219e051e4ade2d1d5bbc671c781051bf1437897cbdfea0f1"
    );
    assert_eq!(projected["method"], "GET");
    assert_eq!(projected["status"], 200);
    assert_eq!(projected["duration_ms"], 7);
}

fn assert_graphql_evidence(run: &Run, status: u16) {
    assert_eq!(run.result.evidence.len(), 1);
    let evidence = &run.result.evidence[0];
    assert_eq!(evidence.source, "https://example.com/graphql");
    let projected = &evidence.observation["observation"];
    assert_eq!(projected["probe"], "graphql-schema-query-0");
    assert_eq!(projected["method"], "POST");
    assert_eq!(projected["status"], status);
    assert_eq!(projected["duration_ms"], 7);
}

fn assert_method_evidence(run: &Run) {
    assert_eq!(run.result.evidence.len(), 3);
    let expected = [
        ("method-Get", "GET"),
        ("method-Head", "HEAD"),
        ("method-Options", "OPTIONS"),
    ];
    for (evidence, (probe, method)) in run.result.evidence.iter().zip(expected) {
        assert_eq!(evidence.source, "https://example.com/");
        let projected = &evidence.observation["observation"];
        assert_eq!(projected["probe"], probe);
        assert_eq!(projected["method"], method);
        assert_eq!(projected["status"], 200);
        assert_eq!(projected["duration_ms"], 7);
    }
}

fn assert_root_get_plan(requests: &[HttpRequest]) {
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.url.as_str(), "https://example.com/");
    assert_eq!(request.method, HttpMethod::Get);
    assert!(request.headers.is_empty());
    assert!(request.body.is_empty());
    assert_eq!(request.max_redirects, 3);
}

fn assert_graphql_plan(requests: &[HttpRequest]) {
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.url.as_str(), "https://example.com/graphql");
    assert_eq!(request.method, HttpMethod::Post);
    assert_eq!(
        request.headers,
        BTreeMap::from([("content-type".into(), "application/json".into())])
    );
    assert_eq!(
        request.body,
        br#"{"query":"query SugraSchemaProbe { __schema { queryType { name } } }"}"#
    );
    assert_eq!(request.max_redirects, 1);
}

fn assert_method_plan(requests: &[HttpRequest], expected: usize) {
    assert_eq!(requests.len(), expected);
    let methods = [HttpMethod::Get, HttpMethod::Head, HttpMethod::Options];
    for (request, method) in requests.iter().zip(methods) {
        assert_eq!(request.url.as_str(), "https://example.com/");
        assert_eq!(request.method, method);
        assert!(request.headers.is_empty());
        assert!(request.body.is_empty());
        assert_eq!(request.max_redirects, 3);
    }
}

#[tokio::test]
async fn every_scanner_enforces_request_and_evidence_projection_bounds()
-> Result<(), Box<dyn std::error::Error>> {
    for id in SCANNERS {
        let run = scan(id, Scenario::Bounded, 2).await?;
        let expected_requests = match id {
            "graphql-introspection-probe" => 1,
            _ => 2,
        };
        assert_completed(&run, id, expected_requests);
        assert_eq!(run.requests.len(), expected_requests, "{id}");
        assert!(
            run.requests
                .iter()
                .all(|request| request.budget.max_requests == 2)
        );
        assert!(run.result.findings.is_empty(), "{id}");
        for evidence in &run.result.evidence {
            let projected = &evidence.observation["observation"];
            assert_eq!(projected["headers"].as_array().map(Vec::len), Some(256));
            assert_eq!(projected["cookies"].as_array().map(Vec::len), Some(128));
            assert!(!evidence.source.contains('?'));
        }
        assert_redacted(&run.result)?;
    }
    Ok(())
}

#[tokio::test]
async fn every_scanner_preserves_the_complete_port_error_kind_matrix()
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
            services.http = Arc::new(ErrorHttp(port_kind));
            let builtins = build_builtins(&services)?;
            let scanner_id = sugra_domain::ScannerId::new(id)?;
            let scanner = builtins
                .registry
                .get(&scanner_id)
                .ok_or("failure scanner is missing")?;
            let request = support::request_for(scanner.descriptor())?;
            let Err(error) = scanner.scan(&request, &support::context(false)).await else {
                return Err(format!("{id} converted {port_kind:?} into success").into());
            };
            assert_eq!(error.kind, scan_kind, "{id}: {port_kind:?}");
            assert_eq!(
                error.message,
                format!("offline {port_kind:?} fixture failure"),
                "{id}: {port_kind:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn fixture_contract_covers_exactly_the_assigned_scanners() {
    assert_eq!(
        SCANNERS.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "form-grabber",
            "graphql-introspection-probe",
            "http-method-enumerator",
            "websocket-endpoint-sniffer",
        ])
    );
}
