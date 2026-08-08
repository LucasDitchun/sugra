//! Public offline contracts for the fourth HTTP exposure and change wave.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{Value, json};
use sugra_core::{
    HttpMethod, HttpPort, HttpRedirect, HttpRedirectDecision, HttpRequest, HttpResponse, PortError,
    PortErrorKind, ScanErrorKind,
};
use sugra_domain::{Budget, Confidence, ExecutionStatus, ScanRequest, ScanResult, Severity};
use sugra_scanners::build_builtins;

#[allow(dead_code)]
mod support;

const SECRET: &str = "wave4-http-secret-7f31";
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

const SCANNERS: [&str; 5] = [
    "exposed-env-files",
    "git-repo-exposure-check",
    "open-redirect-finder",
    "javascript-obfuscation-detector",
    "security-changelog-diff",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Case {
    Positive,
    Negative,
    Edge,
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
        Err(PortError::new(self.0, "typed HTTP fixture failure"))
    }
}

#[derive(Clone)]
struct GitHeadHttp {
    body: &'static str,
    requests: Arc<Mutex<Vec<HttpRequest>>>,
}

#[async_trait]
impl HttpPort for GitHeadHttp {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.clone());
        let is_head = request.url.path() == "/.git/HEAD";
        Ok(HttpResponse {
            final_url: request.url,
            status: if is_head { 206 } else { 404 },
            headers: BTreeMap::from([("content-type".into(), "text/plain".into())]),
            cookies: Vec::new(),
            redirects: Vec::new(),
            body: if is_head {
                self.body.as_bytes().to_vec()
            } else {
                Vec::new()
            },
            duration_ms: 2,
        })
    }
}

#[derive(Clone)]
struct BoundedHttp {
    requests: Arc<Mutex<Vec<HttpRequest>>>,
}

#[async_trait]
impl HttpPort for BoundedHttp {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
        self.requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(request.clone());
        let links = (0..600).fold(String::new(), |mut links, index| {
            let _ = write!(
                links,
                r#"<script src="/asset-{index}.js?token={SECRET}"></script>"#
            );
            links
        });
        let mut headers: BTreeMap<String, String> = (0..300)
            .map(|index| (format!("x-fixture-{index:03}"), SECRET.into()))
            .collect();
        headers.insert("content-type".into(), "text/html".into());
        Ok(HttpResponse {
            final_url: request.url,
            status: 200,
            headers,
            cookies: Vec::new(),
            redirects: Vec::new(),
            body: links.into_bytes(),
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
        status: 200,
        headers: BTreeMap::from([
            ("content-type".into(), "text/html; charset=utf-8".into()),
            ("x-private-fixture".into(), SECRET.into()),
        ]),
        cookies: Vec::new(),
        redirects: Vec::new(),
        body: format!("<p>ordinary public response {SECRET}</p>").into_bytes(),
        duration_ms: 7,
    };
    response
        .final_url
        .query_pairs_mut()
        .append_pair("private", SECRET);

    match scanner_id {
        "exposed-env-files" => configure_env_fixture(&mut response, case, call),
        "git-repo-exposure-check" => configure_git_fixture(&mut response, case, call),
        "open-redirect-finder" => {
            configure_open_redirect_fixture(&mut response, case, call, request);
        }
        "javascript-obfuscation-detector" => {
            configure_javascript_fixture(&mut response, case, call);
        }
        "security-changelog-diff" => configure_changelog_fixture(&mut response, case),
        _ => {}
    }
    response
}

fn configure_env_fixture(response: &mut HttpResponse, case: Case, call: usize) {
    match (case, call) {
        (Case::Positive, 0) => {
            response
                .headers
                .insert("content-type".into(), "text/plain".into());
            response.body =
                format!("DATABASE_URL=postgres://db\nSECRET_TOKEN={SECRET}").into_bytes();
        }
        (Case::Negative, call) => {
            response.status = 200;
            if call == 2 {
                response
                    .headers
                    .insert("content-type".into(), "text/plain".into());
            }
            response.body = match call {
                0 => format!(
                    "<html><script>\nwindow.__ENV__ = {{}};\nwindow.API_TOKEN = '{SECRET}';\n</script></html>"
                ),
                1 => format!(
                    "<html><pre>DATABASE_URL=postgres://example.invalid\nSECRET_TOKEN={SECRET}</pre></html>"
                ),
                _ => format!(
                    "Set SECRET_TOKEN={SECRET} before running the app.\nThe DATABASE_URL=example string is shown only as documentation."
                ),
            }
            .into_bytes();
        }
        (Case::Edge, 0) => {
            response
                .headers
                .insert("content-type".into(), "text/plain".into());
            response.body = format!("SECRET_TOKEN={SECRET}\n").into_bytes();
        }
        (Case::Positive | Case::Edge, _) => response.status = 404,
    }
}

fn configure_git_fixture(response: &mut HttpResponse, case: Case, call: usize) {
    match (case, call) {
        (Case::Positive, 0) => {
            response
                .headers
                .insert("content-type".into(), "text/plain".into());
            response.body = b"ref: refs/heads/main\n".to_vec();
        }
        (Case::Negative, call) => {
            response.status = 200;
            if call == 0 {
                response
                    .headers
                    .insert("content-type".into(), "text/plain".into());
                response.body =
                    b"This guide mentions ref: refs/heads/main when explaining Git.".to_vec();
            } else {
                response.body =
                    b"<html><p>The documentation discusses the [core] section.</p></html>".to_vec();
            }
        }
        (Case::Positive, _) => response.status = 404,
        (Case::Edge, 0) => {
            response.status = 206;
            response
                .headers
                .insert("content-type".into(), "text/plain".into());
            response.body = b"ref: refs/heads/main\n".to_vec();
        }
        (Case::Edge, _) => {
            response.status = 206;
            response
                .headers
                .insert("content-type".into(), "text/plain".into());
            response.body = b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n".to_vec();
        }
    }
}

fn configure_open_redirect_fixture(
    response: &mut HttpResponse,
    case: Case,
    call: usize,
    request: &HttpRequest,
) {
    match (case, call) {
        (Case::Positive, _) => {
            response.status = 302;
            response.redirects.push(external_redirect(request, true));
        }
        (Case::Negative, _) => {
            response.status = 302;
            response.redirects.push(external_redirect(request, false));
        }
        (Case::Edge, _) => {
            response.status = 302;
            response.headers.insert(
                "location".into(),
                format!("https://scope-check.invalid/{SECRET}?private={SECRET}#{SECRET}"),
            );
        }
    }
}

fn external_redirect(request: &HttpRequest, correlated: bool) -> HttpRedirect {
    let mut source = request.url.clone();
    if !correlated {
        source.set_query(None);
        source.set_fragment(None);
    }
    let mut destination = request
        .url
        .join("https://scope-check.invalid/landing")
        .unwrap_or_else(|_| unreachable!("static redirect URL is valid"));
    destination.set_path(&format!("/landing/{SECRET}"));
    destination.query_pairs_mut().append_pair("private", SECRET);
    destination.set_fragment(Some(SECRET));
    HttpRedirect {
        status: 302,
        from: source,
        to: destination,
        decision: HttpRedirectDecision::OutOfScope,
    }
}

fn configure_javascript_fixture(response: &mut HttpResponse, case: Case, call: usize) {
    match (case, call) {
        (Case::Positive, 0) => {
            response.body =
                format!(r#"<script src="/assets/app.js?private={SECRET}"></script>"#).into_bytes();
        }
        (Case::Positive, 1) => {
            response
                .headers
                .insert("content-type".into(), "application/javascript".into());
            response.body = format!("eval(atob('{SECRET}'));").into_bytes();
        }
        (Case::Negative, _) => {
            response.body = b"<script>const answer = 42;</script>".to_vec();
        }
        (Case::Edge, _) => {
            response.body = b"<script>eval('single marker')</script>".to_vec();
        }
        _ => {}
    }
}

fn configure_changelog_fixture(response: &mut HttpResponse, case: Case) {
    match case {
        Case::Negative => response.body.clear(),
        Case::Positive | Case::Edge => {
            response.body = format!("security snapshot {SECRET}").into_bytes();
        }
    }
}

fn configure_case(request: &mut ScanRequest, scanner_id: &str, case: Case) {
    if scanner_id == "security-changelog-diff" {
        let baseline = match case {
            Case::Positive => "0".repeat(64),
            Case::Negative => EMPTY_SHA256.into(),
            Case::Edge => "A".repeat(64),
        };
        request
            .options
            .insert("baseline_sha256".into(), Value::String(baseline));
    }
}

async fn scan_case(
    scanner_id: &'static str,
    case: Case,
) -> Result<(ScanResult, Vec<HttpRequest>), Box<dyn std::error::Error>> {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let mut services = support::Harness::successful().services();
    services.http = Arc::new(FixtureHttp {
        scanner_id,
        case,
        requests: requests.clone(),
    });
    let builtins = build_builtins(&services)?;
    let id = sugra_domain::ScannerId::new(scanner_id)?;
    let scanner = builtins.registry.get(&id).ok_or("scanner is missing")?;
    let mut request = support::request_for(scanner.descriptor())?;
    configure_case(&mut request, scanner_id, case);
    let result = scanner.scan(&request, &support::context(false)).await?;
    let recorded = requests
        .lock()
        .map_err(|_| "HTTP fixture request lock poisoned")?
        .clone();
    Ok((result, recorded))
}

async fn scan_with_http(
    scanner_id: &'static str,
    http: Arc<dyn HttpPort>,
) -> Result<ScanResult, Box<dyn std::error::Error>> {
    let mut services = support::Harness::successful().services();
    services.http = http;
    let builtins = build_builtins(&services)?;
    let id = sugra_domain::ScannerId::new(scanner_id)?;
    let scanner = builtins.registry.get(&id).ok_or("scanner is missing")?;
    let request = support::request_for(scanner.descriptor())?;
    Ok(scanner.scan(&request, &support::context(false)).await?)
}

fn expected_contract(scanner_id: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match scanner_id {
        "exposed-env-files" => Some((
            "environment-file-exposed",
            "web-exposure-analysis",
            "Check for publicly readable environment files.",
        )),
        "git-repo-exposure-check" => Some((
            "git-metadata-exposed",
            "web-exposure-analysis",
            "Check for publicly readable repository metadata.",
        )),
        "open-redirect-finder" => Some((
            "external-open-redirect",
            "authorized-web-probe-analysis",
            "Check a bounded set of redirect parameters.",
        )),
        "javascript-obfuscation-detector" => Some((
            "javascript-obfuscation-markers",
            "content-risk-analysis",
            "Detect obfuscation indicators in public scripts.",
        )),
        "security-changelog-diff" => Some((
            "security-posture-changed",
            "web-change-analysis",
            "Compare published security-change indicators.",
        )),
        _ => None,
    }
}

fn expected_finding_shape(
    scanner_id: &str,
) -> Option<(&'static str, &'static str, Severity, Confidence, Vec<usize>)> {
    match scanner_id {
        "exposed-env-files" => Some((
            "environment-file-exposed",
            "An environment-style configuration file is publicly readable",
            Severity::Critical,
            Confidence::Confirmed,
            vec![0],
        )),
        "git-repo-exposure-check" => Some((
            "git-metadata-exposed",
            "Repository metadata is publicly readable",
            Severity::High,
            Confidence::Confirmed,
            vec![0],
        )),
        "open-redirect-finder" => Some((
            "external-open-redirect",
            "The application accepted an external redirect destination",
            Severity::Medium,
            Confidence::Confirmed,
            vec![0],
        )),
        "javascript-obfuscation-detector" => Some((
            "javascript-obfuscation-markers",
            "Client code contains multiple obfuscation markers",
            Severity::Low,
            Confidence::Inferred,
            vec![1],
        )),
        "security-changelog-diff" => Some((
            "security-posture-changed",
            "The current response fingerprint differs from the supplied baseline",
            Severity::Info,
            Confidence::Confirmed,
            vec![0],
        )),
        _ => None,
    }
}

fn expected_evidence(scanner_id: &str, case: Case) -> usize {
    match (scanner_id, case) {
        ("exposed-env-files" | "open-redirect-finder", _) => 3,
        ("git-repo-exposure-check", _) | ("javascript-obfuscation-detector", Case::Positive) => 2,
        ("javascript-obfuscation-detector", Case::Negative | Case::Edge)
        | ("security-changelog-diff", _) => 1,
        _ => 0,
    }
}

fn assert_annotations_and_evidence(
    scanner_id: &str,
    case: Case,
    result: &ScanResult,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_, analysis, purpose) = expected_contract(scanner_id).ok_or("missing contract")?;
    assert_eq!(result.status, ExecutionStatus::Completed, "{scanner_id}");
    assert!(result.diagnostics.is_empty(), "{scanner_id}");
    assert_eq!(
        result.evidence.len(),
        expected_evidence(scanner_id, case),
        "{scanner_id}: {case:?}"
    );
    for evidence in &result.evidence {
        assert_eq!(evidence.kind, format!("{scanner_id}-http-observation"));
        assert_eq!(evidence.observation["scanner_id"], scanner_id);
        assert_eq!(evidence.observation["analysis"], analysis);
        assert_eq!(evidence.observation["purpose"], purpose);
        let observation = &evidence.observation["observation"];
        assert_eq!(observation["method"], "GET");
        assert!(observation["probe"].is_string());
        assert!(observation["status"].is_u64());
        assert!(
            observation["sha256"]
                .as_str()
                .is_some_and(|hash| hash.len() == 64)
        );
        assert_eq!(observation["duration_ms"], 7);
        assert!(!evidence.source.contains('?'));
        assert!(!evidence.source.contains('#'));
    }
    let serialized = serde_json::to_string(result)?;
    assert!(
        !serialized.contains(SECRET),
        "{scanner_id} leaked fixture material"
    );
    Ok(())
}

fn assert_positive_finding(scanner_id: &str, result: &ScanResult) {
    let (key, title, severity, confidence, evidence) =
        expected_finding_shape(scanner_id).unwrap_or_else(|| unreachable!("known scanner"));
    assert_eq!(result.findings.len(), 1, "{scanner_id}");
    let finding = &result.findings[0];
    assert_eq!(finding.key, key);
    assert_eq!(finding.title, title);
    assert_eq!(finding.severity, severity);
    assert_eq!(finding.confidence, confidence);
    assert_eq!(finding.evidence, evidence);
}

fn assert_correlated_open_redirect_findings(result: &ScanResult) {
    let (key, title, severity, confidence, _) = expected_finding_shape("open-redirect-finder")
        .unwrap_or_else(|| unreachable!("open redirect contract exists"));
    assert_eq!(result.findings.len(), 3);
    for (index, finding) in result.findings.iter().enumerate() {
        assert_eq!(finding.key, key);
        assert_eq!(finding.title, title);
        assert_eq!(finding.severity, severity);
        assert_eq!(finding.confidence, confidence);
        assert_eq!(finding.evidence, [index]);
    }
}

#[tokio::test]
async fn exposure_and_change_scanners_prove_positive_negative_and_edge_contracts()
-> Result<(), Box<dyn std::error::Error>> {
    for scanner_id in SCANNERS {
        let (positive, requests) = scan_case(scanner_id, Case::Positive).await?;
        if scanner_id == "open-redirect-finder" {
            assert_correlated_open_redirect_findings(&positive);
        } else {
            assert_positive_finding(scanner_id, &positive);
        }
        assert_annotations_and_evidence(scanner_id, Case::Positive, &positive)?;
        assert_eq!(
            requests.len(),
            expected_evidence(scanner_id, Case::Positive)
        );

        let (negative, requests) = scan_case(scanner_id, Case::Negative).await?;
        assert!(negative.findings.is_empty(), "{scanner_id}: negative");
        assert_annotations_and_evidence(scanner_id, Case::Negative, &negative)?;
        assert_eq!(
            requests.len(),
            expected_evidence(scanner_id, Case::Negative)
        );

        let (edge, requests) = scan_case(scanner_id, Case::Edge).await?;
        if scanner_id == "git-repo-exposure-check" {
            assert_eq!(edge.findings.len(), 2, "{scanner_id}: edge");
            assert!(edge.findings.iter().all(|finding| {
                finding.key == "git-metadata-exposed"
                    && finding.title == "Repository metadata is publicly readable"
                    && finding.severity == Severity::High
                    && finding.confidence == Confidence::Confirmed
            }));
            assert_eq!(edge.findings[0].evidence, [0]);
            assert_eq!(edge.findings[1].evidence, [1]);
        } else if scanner_id == "open-redirect-finder" {
            assert_correlated_open_redirect_findings(&edge);
        } else if matches!(scanner_id, "exposed-env-files" | "security-changelog-diff") {
            assert_positive_finding(scanner_id, &edge);
        } else {
            assert!(edge.findings.is_empty(), "{scanner_id}: edge");
        }
        assert_annotations_and_evidence(scanner_id, Case::Edge, &edge)?;
        assert_eq!(requests.len(), expected_evidence(scanner_id, Case::Edge));
    }
    Ok(())
}

#[tokio::test]
async fn git_exposure_accepts_structural_head_and_config_partial_content()
-> Result<(), Box<dyn std::error::Error>> {
    let (partial_content, requests) = scan_case("git-repo-exposure-check", Case::Edge).await?;
    assert_eq!(partial_content.findings.len(), 2);
    assert!(partial_content.findings.iter().all(|finding| {
        finding.key == "git-metadata-exposed"
            && finding.title == "Repository metadata is publicly readable"
            && finding.severity == Severity::High
            && finding.confidence == Confidence::Confirmed
    }));
    assert_eq!(partial_content.findings[0].evidence, [0]);
    assert_eq!(partial_content.findings[1].evidence, [1]);
    assert_annotations_and_evidence("git-repo-exposure-check", Case::Edge, &partial_content)?;
    assert_eq!(requests.len(), 2);
    Ok(())
}

#[tokio::test]
async fn git_exposure_rejects_prose_and_html_that_only_mention_git_markers()
-> Result<(), Box<dyn std::error::Error>> {
    let (nearby_text, requests) = scan_case("git-repo-exposure-check", Case::Negative).await?;
    assert!(nearby_text.findings.is_empty());
    assert_annotations_and_evidence("git-repo-exposure-check", Case::Negative, &nearby_text)?;
    assert_eq!(requests.len(), 2);
    Ok(())
}

#[tokio::test]
async fn git_exposure_accepts_symbolic_tag_and_remote_head_refs()
-> Result<(), Box<dyn std::error::Error>> {
    for body in [
        "ref: refs/tags/v1.2.3\n",
        "ref: refs/remotes/origin/release-2026\n",
    ] {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let result = scan_with_http(
            "git-repo-exposure-check",
            Arc::new(GitHeadHttp {
                body,
                requests: requests.clone(),
            }),
        )
        .await?;
        assert_positive_finding("git-repo-exposure-check", &result);
        assert_eq!(
            requests
                .lock()
                .map_err(|_| "Git request lock poisoned")?
                .len(),
            2
        );
    }
    Ok(())
}

#[tokio::test]
async fn git_exposure_rejects_malformed_symbolic_refnames() -> Result<(), Box<dyn std::error::Error>>
{
    for body in [
        "ref: refs/tags/../private\n",
        "ref: refs/remotes/origin//main\n",
        "ref: refs/tags/release.lock\n",
    ] {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let result = scan_with_http(
            "git-repo-exposure-check",
            Arc::new(GitHeadHttp {
                body,
                requests: requests.clone(),
            }),
        )
        .await?;
        assert!(
            result.findings.is_empty(),
            "accepted malformed refname: {body}"
        );
        assert_eq!(
            requests
                .lock()
                .map_err(|_| "Git request lock poisoned")?
                .len(),
            2
        );
    }
    Ok(())
}

#[tokio::test]
async fn environment_exposure_accepts_one_sensitive_assignment()
-> Result<(), Box<dyn std::error::Error>> {
    let (single_assignment, requests) = scan_case("exposed-env-files", Case::Edge).await?;
    assert_positive_finding("exposed-env-files", &single_assignment);
    assert_annotations_and_evidence("exposed-env-files", Case::Edge, &single_assignment)?;
    assert_eq!(requests.len(), 3);
    Ok(())
}

#[tokio::test]
async fn environment_exposure_rejects_spa_documentation_and_assignment_like_html()
-> Result<(), Box<dyn std::error::Error>> {
    let (html_fallbacks, requests) = scan_case("exposed-env-files", Case::Negative).await?;
    assert!(html_fallbacks.findings.is_empty());
    assert_annotations_and_evidence("exposed-env-files", Case::Negative, &html_fallbacks)?;
    assert_eq!(requests.len(), 3);
    Ok(())
}

#[tokio::test]
async fn open_redirect_correlates_each_injected_parameter_with_an_out_of_scope_hop()
-> Result<(), Box<dyn std::error::Error>> {
    let (positive, requests) = scan_case("open-redirect-finder", Case::Positive).await?;
    assert_correlated_open_redirect_findings(&positive);
    assert_eq!(requests.len(), 3);
    assert!(requests.iter().all(|request| {
        request.method == HttpMethod::Get
            && request.url.host_str() == Some("example.com")
            && request.max_redirects == 3
    }));
    assert_eq!(
        requests
            .iter()
            .filter_map(|request| request.url.query())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "next=https%3A%2F%2Fscope-check.invalid%2F",
            "redirect=https%3A%2F%2Fscope-check.invalid%2F",
            "url=https%3A%2F%2Fscope-check.invalid%2F",
        ])
    );
    let redirect = &positive.evidence[0].observation["observation"]["redirects"][0];
    assert_eq!(redirect["status"], 302);
    assert_eq!(redirect["decision"], "outofscope");
    assert_eq!(redirect["to"], "https://scope-check.invalid/");
    Ok(())
}

#[tokio::test]
async fn open_redirect_evidence_redacts_destination_path_query_and_fragment()
-> Result<(), Box<dyn std::error::Error>> {
    let (result, _) = scan_case("open-redirect-finder", Case::Positive).await?;
    assert_correlated_open_redirect_findings(&result);
    let redirect = &result.evidence[0].observation["observation"]["redirects"][0];
    assert_eq!(redirect["to"], "https://scope-check.invalid/");
    assert!(!serde_json::to_string(&result)?.contains(SECRET));
    Ok(())
}

#[tokio::test]
async fn open_redirect_accepts_an_external_location_without_adapter_redirects()
-> Result<(), Box<dyn std::error::Error>> {
    let (result, requests) = scan_case("open-redirect-finder", Case::Edge).await?;
    assert_correlated_open_redirect_findings(&result);
    assert_eq!(requests.len(), 3);
    assert!(
        result.evidence[0].observation["observation"]["redirects"]
            .as_array()
            .is_some_and(Vec::is_empty)
    );
    assert!(!serde_json::to_string(&result)?.contains(SECRET));
    Ok(())
}

#[tokio::test]
async fn open_redirect_rejects_an_uncorrelated_static_external_redirect()
-> Result<(), Box<dyn std::error::Error>> {
    let (result, requests) = scan_case("open-redirect-finder", Case::Negative).await?;
    assert!(result.findings.is_empty());
    assert_eq!(requests.len(), 3);
    assert!(requests.iter().all(|request| request.url.query().is_some()));
    assert!(result.evidence.iter().all(|evidence| {
        evidence.observation["observation"]["redirects"]
            .as_array()
            .is_some_and(|redirects| redirects.len() == 1)
    }));
    assert!(!serde_json::to_string(&result)?.contains(SECRET));
    Ok(())
}

#[tokio::test]
async fn uppercase_sha256_baseline_participates_in_change_comparison()
-> Result<(), Box<dyn std::error::Error>> {
    let (result, requests) = scan_case("security-changelog-diff", Case::Edge).await?;
    assert_positive_finding("security-changelog-diff", &result);
    assert_annotations_and_evidence("security-changelog-diff", Case::Edge, &result)?;
    assert_eq!(requests.len(), 1);
    Ok(())
}

#[tokio::test]
async fn all_http_port_error_kinds_preserve_the_public_scan_error_mapping()
-> Result<(), Box<dyn std::error::Error>> {
    let error_matrix = [
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

    for scanner_id in SCANNERS {
        for (port_kind, expected_kind) in error_matrix {
            let mut services = support::Harness::successful().services();
            services.http = Arc::new(FailingHttp(port_kind));
            let builtins = build_builtins(&services)?;
            let id = sugra_domain::ScannerId::new(scanner_id)?;
            let scanner = builtins.registry.get(&id).ok_or("scanner is missing")?;
            let mut request = support::request_for(scanner.descriptor())?;
            configure_case(&mut request, scanner_id, Case::Positive);
            let Err(error) = scanner.scan(&request, &support::context(false)).await else {
                return Err(format!("{scanner_id}: {port_kind:?} became success").into());
            };
            assert_eq!(error.kind, expected_kind, "{scanner_id}: {port_kind:?}");
            assert_eq!(error.message, "typed HTTP fixture failure");
        }
    }
    Ok(())
}

#[tokio::test]
async fn probe_counts_and_evidence_projection_remain_budget_bounded_and_redacted()
-> Result<(), Box<dyn std::error::Error>> {
    let budget = Budget {
        timeout_ms: 1_000,
        concurrency: 1,
        max_requests: 2,
        max_response_bytes: 64 * 1024,
        max_depth: 1,
    }
    .validate()?;

    for (scanner_id, expected_requests) in [
        ("exposed-env-files", 2),
        ("git-repo-exposure-check", 2),
        ("open-redirect-finder", 2),
        ("javascript-obfuscation-detector", 2),
        ("security-changelog-diff", 1),
    ] {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mut services = support::Harness::successful().services();
        services.http = Arc::new(BoundedHttp {
            requests: requests.clone(),
        });
        let builtins = build_builtins(&services)?;
        let id = sugra_domain::ScannerId::new(scanner_id)?;
        let scanner = builtins.registry.get(&id).ok_or("scanner is missing")?;
        let mut request = support::request_for(scanner.descriptor())?;
        request.budget = budget;
        if scanner_id == "security-changelog-diff" {
            request
                .options
                .insert("baseline_sha256".into(), json!("0".repeat(64)));
        }
        let result = scanner.scan(&request, &support::context(false)).await?;
        let recorded = requests
            .lock()
            .map_err(|_| "bounded HTTP request lock poisoned")?;
        assert_eq!(recorded.len(), expected_requests, "{scanner_id}");
        assert!(recorded.iter().all(|request| request.budget == budget));
        assert_eq!(result.evidence.len(), expected_requests, "{scanner_id}");
        assert!(result.evidence.iter().all(|evidence| {
            evidence.observation["observation"]["headers"]
                .as_array()
                .is_some_and(|headers| headers.len() == 256)
        }));
        let serialized = serde_json::to_string(&result)?;
        assert!(!serialized.contains(SECRET), "{scanner_id}");
        assert!(serialized.len() < 100_000, "{scanner_id}");
    }
    Ok(())
}
