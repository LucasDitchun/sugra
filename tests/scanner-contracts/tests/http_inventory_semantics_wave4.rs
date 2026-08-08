//! Public offline contracts for the fourth HTTP inventory and metadata wave.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use sugra_core::{HttpPort, HttpRequest, HttpResponse, PortError, PortErrorKind, ScanErrorKind};
use sugra_domain::{Confidence, ExecutionStatus, Finding, ScanResult, Severity};
use sugra_scanners::build_builtins;

#[allow(dead_code)]
mod support;

const SCANNERS: [&str; 6] = [
    "html-comments-extractor",
    "third-party-integrations",
    "sitemap",
    "social-media",
    "favicon-hashing",
    "technology-stack",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FixtureCase {
    Positive,
    Negative,
    Edge,
    SemanticTrap,
    Bounds,
}

struct FixtureHttp {
    scanner_id: &'static str,
    case: FixtureCase,
    calls: Arc<AtomicUsize>,
}

struct FailingHttp(PortErrorKind);

struct FaviconBodyHttp {
    content_type: &'static str,
    body: Vec<u8>,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl HttpPort for FixtureHttp {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert!(
            request.budget.max_requests >= 1,
            "{} received an invalid request budget",
            self.scanner_id
        );
        assert!(
            request.budget.max_response_bytes >= 1,
            "{} received an invalid response budget",
            self.scanner_id
        );
        if self.case == FixtureCase::Bounds {
            assert_eq!(request.budget.max_requests, 1, "{}", self.scanner_id);
            assert_eq!(
                request.budget.max_response_bytes, 4_096,
                "{}",
                self.scanner_id
            );
        }
        Ok(fixture_response(self.scanner_id, self.case, request))
    }
}

#[async_trait]
impl HttpPort for FailingHttp {
    async fn execute(&self, _request: HttpRequest) -> Result<HttpResponse, PortError> {
        Err(PortError::new(
            self.0,
            format!("offline HTTP {:?} fixture failure", self.0),
        ))
    }
}

#[async_trait]
impl HttpPort for FaviconBodyHttp {
    async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(request.url.path(), "/favicon.ico");
        Ok(HttpResponse {
            final_url: request.url,
            status: 200,
            headers: BTreeMap::from([("content-type".into(), self.content_type.into())]),
            cookies: Vec::new(),
            redirects: Vec::new(),
            body: self.body.clone(),
            duration_ms: 3,
        })
    }
}

fn fixture_response(id: &str, case: FixtureCase, request: HttpRequest) -> HttpResponse {
    let mut response = HttpResponse {
        final_url: request.url,
        status: 200,
        headers: BTreeMap::from([("content-type".into(), "text/html; charset=utf-8".into())]),
        cookies: Vec::new(),
        redirects: Vec::new(),
        body: Vec::new(),
        duration_ms: 3,
    };
    match id {
        "html-comments-extractor" => comments_response(&mut response, case),
        "third-party-integrations" => integrations_response(&mut response, case),
        "sitemap" => sitemap_response(&mut response, case),
        "social-media" => social_response(&mut response, case),
        "favicon-hashing" => favicon_response(&mut response, case),
        "technology-stack" => technology_response(&mut response, case),
        _ => unreachable!("fixture is missing for {id}: {case:?}"),
    }
    response
}

fn comments_response(response: &mut HttpResponse, case: FixtureCase) {
    match case {
        FixtureCase::Positive => html(
            response,
            &format!(
                "<main><!-- {} --><p>public</p></main>",
                support::SECRET_MARKER
            ),
        ),
        FixtureCase::Negative => {
            html(response, "<main><p>public</p></main>");
        }
        FixtureCase::Edge => {
            response
                .headers
                .insert("content-type".into(), "application/json".into());
            response.body = format!(
                r#"{{"documentation":"<!-- {} is not an HTML comment -->"}}"#,
                support::SECRET_MARKER
            )
            .into_bytes();
        }
        FixtureCase::SemanticTrap => html(
            response,
            r#"<script>const template = "<!-- not a document comment -->";</script>"#,
        ),
        FixtureCase::Bounds => html(
            response,
            &format!("<!-- {} -->", support::SECRET_MARKER).repeat(1_024),
        ),
    }
}

fn integrations_response(response: &mut HttpResponse, case: FixtureCase) {
    match case {
        FixtureCase::Positive => html(
            response,
            &format!(
                r#"<script src="https://cdn.example.net/app.js?token={}"></script>"#,
                support::SECRET_MARKER
            ),
        ),
        FixtureCase::Negative => {
            html(response, r#"<script src="/app.js"></script>"#);
        }
        FixtureCase::Edge => html(
            response,
            r#"<link rel="preconnect" href="https://cdn.example.net"><p>cdn.example.net</p>"#,
        ),
        FixtureCase::SemanticTrap => html(
            response,
            r#"<a href="https://cdn.example.net/docs">ordinary external link</a>"#,
        ),
        FixtureCase::Bounds => {
            let mut body = String::new();
            for index in 0..256 {
                assert!(
                    write!(
                        body,
                        r#"<script src="https://cdn-{index}.example.net/app.js?token={}"></script>"#,
                        support::SECRET_MARKER
                    )
                    .is_ok()
                );
            }
            html(response, &body);
        }
    }
}

fn sitemap_response(response: &mut HttpResponse, case: FixtureCase) {
    match case {
        FixtureCase::Positive if response.final_url.path() == "/sitemap.xml" => {
            xml(
                response,
                &format!(
                    "<urlset><url><loc>https://example.com/{}?token={}</loc></url></urlset>",
                    support::SECRET_MARKER,
                    support::SECRET_MARKER
                ),
            );
        }
        FixtureCase::Edge if response.final_url.path() == "/sitemap_index.xml" => {
            xml(
                response,
                &format!(
                    "<sitemapindex><sitemap><loc>https://example.com/{}-child.xml</loc></sitemap></sitemapindex>",
                    support::SECRET_MARKER
                ),
            );
        }
        FixtureCase::Bounds if response.final_url.path() == "/sitemap.xml" => {
            xml(
                response,
                &format!(
                    "<urlset>{}</urlset>",
                    format!(
                        "<url><loc>https://example.com/{}?token={}</loc></url>",
                        support::SECRET_MARKER,
                        support::SECRET_MARKER
                    )
                    .repeat(2_048)
                ),
            );
        }
        FixtureCase::SemanticTrap if response.final_url.path() == "/sitemap.xml" => xml(
            response,
            "<urlsetevil><url><loc>https://example.com/not-a-sitemap</loc></url></urlsetevil>",
        ),
        FixtureCase::SemanticTrap if response.final_url.path() == "/sitemap_index.xml" => xml(
            response,
            "<sitemapindexer><sitemap><loc>https://example.com/not-an-index.xml</loc></sitemap></sitemapindexer>",
        ),
        _ => {
            response.status = 404;
            response
                .headers
                .insert("content-type".into(), "application/xml".into());
            response.body = support::SECRET_MARKER.as_bytes().to_vec();
        }
    }
}

fn social_response(response: &mut HttpResponse, case: FixtureCase) {
    match case {
        FixtureCase::Positive => html(
            response,
            &format!(
                r#"<a href="https://x.com/example?token={}">social</a>"#,
                support::SECRET_MARKER
            ),
        ),
        FixtureCase::Negative => {
            html(
                response,
                "<p>Follow the project through its public channels.</p>",
            );
        }
        FixtureCase::Edge => html(
            response,
            r#"<a href="https://notx.com/profile">unrelated host</a><script>const x = "https://x.com/example";</script>"#,
        ),
        FixtureCase::SemanticTrap => html(response, "<p>No social links.</p>"),
        FixtureCase::Bounds => html(
            response,
            &format!(
                r#"<a href="https://x.com/example?token={}">social</a>"#,
                support::SECRET_MARKER
            )
            .repeat(2_048),
        ),
    }
}

fn favicon_response(response: &mut HttpResponse, case: FixtureCase) {
    match case {
        FixtureCase::Positive => {
            response
                .headers
                .insert("content-type".into(), "image/x-icon".into());
            response.body = plausible_ico();
        }
        FixtureCase::Negative => {
            response.status = 404;
            response.body = support::SECRET_MARKER.as_bytes().to_vec();
        }
        FixtureCase::Edge => {
            response
                .headers
                .insert("content-type".into(), "image/x-icon".into());
        }
        FixtureCase::SemanticTrap => {
            response.status = 404;
        }
        FixtureCase::Bounds => {
            response
                .headers
                .insert("content-type".into(), "image/x-icon".into());
            response.body = support::SECRET_MARKER.repeat(16_384).into_bytes();
        }
    }
}

fn plausible_ico() -> Vec<u8> {
    const DIRECTORY_SIZE: u32 = 6 + 16;
    const IMAGE_SIZE: u32 = 40 + 4 + 4;

    let mut body = Vec::with_capacity((DIRECTORY_SIZE + IMAGE_SIZE) as usize);
    body.extend_from_slice(&[0, 0, 1, 0, 1, 0]);
    body.extend_from_slice(&[1, 1, 0, 0, 1, 0, 32, 0]);
    body.extend_from_slice(&IMAGE_SIZE.to_le_bytes());
    body.extend_from_slice(&DIRECTORY_SIZE.to_le_bytes());
    body.extend_from_slice(&40_u32.to_le_bytes());
    body.extend_from_slice(&1_i32.to_le_bytes());
    body.extend_from_slice(&2_i32.to_le_bytes());
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&32_u16.to_le_bytes());
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&4_u32.to_le_bytes());
    body.extend_from_slice(&0_i32.to_le_bytes());
    body.extend_from_slice(&0_i32.to_le_bytes());
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&[0; 4]);
    body.extend_from_slice(&[0; 4]);
    body
}

fn technology_response(response: &mut HttpResponse, case: FixtureCase) {
    match case {
        FixtureCase::Positive => html(
            response,
            &format!(
                r#"<meta name="generator" content="WordPress 6"><p>{}</p>"#,
                support::SECRET_MARKER
            ),
        ),
        FixtureCase::Negative => html(
            response,
            r#"<meta name="generator" content="Private Site Builder">"#,
        ),
        FixtureCase::Edge => {
            response.headers.insert("server".into(), String::new());
            html(response, "<p>No technology metadata</p>");
        }
        FixtureCase::SemanticTrap => html(response, "<p>No technology metadata</p>"),
        FixtureCase::Bounds => {
            for index in 0..300 {
                response.headers.insert(
                    format!("x-fixture-{index:03}"),
                    support::SECRET_MARKER.into(),
                );
            }
            html(
                response,
                &format!(
                    r#"<meta name="generator" content="Drupal 11"><p>{}</p>"#,
                    support::SECRET_MARKER.repeat(4_096)
                ),
            );
        }
    }
}

fn html(response: &mut HttpResponse, body: &str) {
    response
        .headers
        .insert("content-type".into(), "text/html; charset=utf-8".into());
    response.body = body.as_bytes().to_vec();
}

fn xml(response: &mut HttpResponse, body: &str) {
    response
        .headers
        .insert("content-type".into(), "application/xml".into());
    response.body = body.as_bytes().to_vec();
}

async fn scan(
    scanner_id: &'static str,
    case: FixtureCase,
) -> Result<(ScanResult, usize), Box<dyn std::error::Error>> {
    scan_with_budget(scanner_id, case, 8, 64 * 1_024).await
}

async fn scan_with_budget(
    scanner_id: &'static str,
    case: FixtureCase,
    max_requests: usize,
    max_response_bytes: usize,
) -> Result<(ScanResult, usize), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut services = support::Harness::successful().services();
    services.http = Arc::new(FixtureHttp {
        scanner_id,
        case,
        calls: Arc::clone(&calls),
    });
    let builtins = build_builtins(&services)?;
    let scanner_id_value = sugra_domain::ScannerId::new(scanner_id)?;
    let scanner = builtins
        .registry
        .get(&scanner_id_value)
        .ok_or("fixture scanner is missing")?;
    let mut request = support::request_for(scanner.descriptor())?;
    request.budget.max_requests = max_requests;
    request.budget.max_response_bytes = max_response_bytes;
    let result = scanner.scan(&request, &support::context(false)).await?;
    Ok((result, calls.load(Ordering::SeqCst)))
}

async fn scan_favicon_body(
    content_type: &'static str,
    body: impl Into<Vec<u8>>,
) -> Result<(ScanResult, usize), Box<dyn std::error::Error>> {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut services = support::Harness::successful().services();
    services.http = Arc::new(FaviconBodyHttp {
        content_type,
        body: body.into(),
        calls: Arc::clone(&calls),
    });
    let builtins = build_builtins(&services)?;
    let scanner_id = sugra_domain::ScannerId::new("favicon-hashing")?;
    let scanner = builtins
        .registry
        .get(&scanner_id)
        .ok_or("favicon scanner is missing")?;
    let request = support::request_for(scanner.descriptor())?;
    let result = scanner.scan(&request, &support::context(false)).await?;
    Ok((result, calls.load(Ordering::SeqCst)))
}

async fn assert_favicon_body_rejected(
    content_type: &'static str,
    body: impl Into<Vec<u8>>,
    reason: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (result, calls) = scan_favicon_body(content_type, body).await?;
    assert_eq!(calls, 1);
    assert!(result.findings.is_empty(), "{reason}");
    assert_exact_envelope("favicon-hashing", &result, 1)
}

fn expected_contract(id: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match id {
        "html-comments-extractor" => Some((
            "html-comments-observed",
            "web-metadata-analysis",
            "Extract bounded HTML comment metadata.",
        )),
        "third-party-integrations" => Some((
            "third-party-integration-observed",
            "web-inventory-analysis",
            "Inventory third-party origins and integrations.",
        )),
        "sitemap" => Some((
            "sitemap-observed",
            "web-metadata-analysis",
            "Retrieve and summarize published sitemaps.",
        )),
        "social-media" => Some((
            "social-link-observed",
            "web-inventory-analysis",
            "Inventory public social-platform links.",
        )),
        "favicon-hashing" => Some((
            "favicon-fingerprint-observed",
            "web-metadata-analysis",
            "Fingerprint the published favicon content.",
        )),
        "technology-stack" => Some((
            "technology-signal-observed",
            "technology-detection-analysis",
            "Detect public technology-stack indicators.",
        )),
        _ => None,
    }
}

fn assert_exact_finding(result: &ScanResult, id: &str, evidence: usize) {
    let Some((key, _, _)) = expected_contract(id) else {
        unreachable!("missing expected contract for {id}");
    };
    assert_eq!(result.findings.len(), 1, "{id}");
    assert_eq!(
        result.findings[0],
        Finding {
            key: key.into(),
            title: expected_title(id).into(),
            severity: Severity::Info,
            confidence: if id == "technology-stack" {
                Confidence::Inferred
            } else {
                Confidence::Confirmed
            },
            evidence: vec![evidence],
        },
        "{id}"
    );
}

fn expected_title(id: &str) -> &'static str {
    match id {
        "html-comments-extractor" => "HTML comments are present",
        "third-party-integrations" => "Third-party integrations are present",
        "sitemap" => "A sitemap document is publicly available",
        "social-media" => "Public social-media links are present",
        "favicon-hashing" => "A favicon fingerprint was collected",
        "technology-stack" => "Public technology-identification metadata is present",
        _ => unreachable!("missing expected title for {id}"),
    }
}

fn assert_exact_envelope(
    id: &str,
    result: &ScanResult,
    expected_evidence: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some((_, analysis, purpose)) = expected_contract(id) else {
        return Err(format!("missing expected contract for {id}").into());
    };
    assert_eq!(result.status, ExecutionStatus::Completed, "{id}");
    assert!(result.diagnostics.is_empty(), "{id}");
    assert_eq!(result.evidence.len(), expected_evidence, "{id}");
    let expected_sources = expected_sources(id);
    assert!(expected_sources.len() >= expected_evidence, "{id}");
    for (evidence, expected_source) in result.evidence.iter().zip(expected_sources) {
        assert_eq!(evidence.kind, format!("{id}-http-observation"), "{id}");
        assert_eq!(evidence.source, *expected_source, "{id}");
        assert_eq!(
            object_keys(&evidence.observation),
            BTreeSet::from(["analysis", "observation", "purpose", "scanner_id"]),
            "{id}"
        );
        assert_eq!(evidence.observation["scanner_id"], id, "{id}");
        assert_eq!(evidence.observation["analysis"], analysis, "{id}");
        assert_eq!(evidence.observation["purpose"], purpose, "{id}");
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
    let serialized = serde_json::to_string(result)?;
    assert!(!serialized.contains(support::SECRET_MARKER), "{id}");
    assert!(result.findings.iter().all(|finding| {
        !finding.evidence.is_empty()
            && finding
                .evidence
                .iter()
                .all(|index| *index < result.evidence.len())
    }));
    Ok(())
}

fn expected_sources(id: &str) -> &'static [&'static str] {
    match id {
        "sitemap" => &[
            "https://example.com/sitemap.xml",
            "https://example.com/sitemap_index.xml",
        ],
        "favicon-hashing" => &["https://example.com/favicon.ico"],
        "third-party-integrations" => &["https://example.com/", "https://example.com/app.js"],
        _ => &["https://example.com/"],
    }
}

fn object_keys(value: &serde_json::Value) -> BTreeSet<&str> {
    value
        .as_object()
        .into_iter()
        .flat_map(|object| object.keys().map(String::as_str))
        .collect()
}

async fn assert_no_signal(
    id: &'static str,
    case: FixtureCase,
    expected_evidence: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let (result, calls) = scan(id, case).await?;
    assert!(result.findings.is_empty(), "{id}: {case:?}");
    assert_eq!(calls, expected_evidence, "{id}: {case:?}");
    assert_exact_envelope(id, &result, expected_evidence)
}

#[tokio::test]
async fn html_comments_extractor_is_content_aware_across_positive_negative_and_edge()
-> Result<(), Box<dyn std::error::Error>> {
    let (positive, calls) = scan("html-comments-extractor", FixtureCase::Positive).await?;
    assert_eq!(calls, 1);
    assert_exact_finding(&positive, "html-comments-extractor", 0);
    assert_eq!(
        positive.evidence[0].observation["observation"]["document"]["comments"],
        1
    );
    assert_exact_envelope("html-comments-extractor", &positive, 1)?;
    assert_no_signal("html-comments-extractor", FixtureCase::Negative, 1).await?;
    let (edge, calls) = scan("html-comments-extractor", FixtureCase::Edge).await?;
    assert_eq!(calls, 1);
    assert!(edge.findings.is_empty());
    assert_eq!(
        edge.evidence[0].observation["observation"]["document"]["comments"],
        0
    );
    assert_exact_envelope("html-comments-extractor", &edge, 1)
}

#[tokio::test]
async fn html_comments_extractor_ignores_comment_delimiters_inside_scripts()
-> Result<(), Box<dyn std::error::Error>> {
    let (result, calls) = scan("html-comments-extractor", FixtureCase::SemanticTrap).await?;
    assert_eq!(calls, 1);
    assert!(result.findings.is_empty());
    assert_eq!(
        result.evidence[0].observation["observation"]["document"]["comments"],
        0
    );
    assert_exact_envelope("html-comments-extractor", &result, 1)
}

#[tokio::test]
async fn third_party_integrations_inventory_structured_external_origins_across_pne()
-> Result<(), Box<dyn std::error::Error>> {
    let (positive, calls) = scan("third-party-integrations", FixtureCase::Positive).await?;
    assert_eq!(calls, 1);
    assert_exact_finding(&positive, "third-party-integrations", 0);
    assert_eq!(
        positive.evidence[0].observation["observation"]["document"]["external_integration_hosts"],
        serde_json::json!(["cdn.example.net"])
    );
    assert_exact_envelope("third-party-integrations", &positive, 1)?;
    assert_no_signal("third-party-integrations", FixtureCase::Negative, 2).await?;

    let (preconnect, calls) = scan("third-party-integrations", FixtureCase::Edge).await?;
    assert_eq!(calls, 1);
    assert_exact_finding(&preconnect, "third-party-integrations", 0);
    assert_eq!(
        preconnect.evidence[0].observation["observation"]["document"]["external_integration_hosts"],
        serde_json::json!(["cdn.example.net"])
    );
    assert_exact_envelope("third-party-integrations", &preconnect, 1)?;

    let (anchor, calls) = scan("third-party-integrations", FixtureCase::SemanticTrap).await?;
    assert_eq!(calls, 1);
    assert!(
        anchor.findings.is_empty(),
        "an ordinary external anchor is not an integration"
    );
    assert_eq!(
        anchor.evidence[0].observation["observation"]["document"]["external_integration_hosts"],
        serde_json::json!([])
    );
    assert_exact_envelope("third-party-integrations", &anchor, 1)
}

#[tokio::test]
async fn sitemap_accepts_url_sets_and_indexes_without_accepting_error_bodies()
-> Result<(), Box<dyn std::error::Error>> {
    let (positive, calls) = scan("sitemap", FixtureCase::Positive).await?;
    assert_eq!(calls, 2);
    assert_exact_finding(&positive, "sitemap", 0);
    assert_exact_envelope("sitemap", &positive, 2)?;
    assert_no_signal("sitemap", FixtureCase::Negative, 2).await?;

    let (edge, calls) = scan("sitemap", FixtureCase::Edge).await?;
    assert_eq!(calls, 2);
    assert_exact_finding(&edge, "sitemap", 1);
    assert_exact_envelope("sitemap", &edge, 2)
}

#[tokio::test]
async fn sitemap_rejects_near_match_urlset_and_sitemapindex_root_names()
-> Result<(), Box<dyn std::error::Error>> {
    let (result, calls) = scan("sitemap", FixtureCase::SemanticTrap).await?;
    assert_eq!(calls, 2);
    assert!(
        result.findings.is_empty(),
        "urlsetevil and sitemapindexer are not sitemap root elements"
    );
    assert_exact_envelope("sitemap", &result, 2)
}

#[tokio::test]
async fn social_media_requires_a_link_to_an_exact_supported_host_across_pne()
-> Result<(), Box<dyn std::error::Error>> {
    let (positive, calls) = scan("social-media", FixtureCase::Positive).await?;
    assert_eq!(calls, 1);
    assert_exact_finding(&positive, "social-media", 0);
    assert_eq!(
        positive.evidence[0].observation["observation"]["document"]["social_links"],
        1
    );
    assert_exact_envelope("social-media", &positive, 1)?;
    assert_no_signal("social-media", FixtureCase::Negative, 1).await?;
    assert_no_signal("social-media", FixtureCase::Edge, 1).await
}

#[tokio::test]
async fn favicon_hashing_requires_plausible_icon_content_across_pne()
-> Result<(), Box<dyn std::error::Error>> {
    let (positive, calls) = scan("favicon-hashing", FixtureCase::Positive).await?;
    assert_eq!(calls, 1);
    assert_exact_finding(&positive, "favicon-hashing", 0);
    assert_eq!(
        positive.evidence[0].source,
        "https://example.com/favicon.ico"
    );
    assert_exact_envelope("favicon-hashing", &positive, 1)?;
    assert_no_signal("favicon-hashing", FixtureCase::Negative, 1).await?;
    assert_no_signal("favicon-hashing", FixtureCase::Edge, 1).await
}

#[tokio::test]
async fn favicon_hashing_rejects_a_successful_html_document()
-> Result<(), Box<dyn std::error::Error>> {
    assert_favicon_body_rejected(
        "text/html; charset=utf-8",
        "<!doctype html><html><head><title>Not an icon</title></head><body></body></html>",
        "a successful HTML response is not favicon content",
    )
    .await
}

#[tokio::test]
async fn favicon_hashing_rejects_a_branded_spa_behind_an_icon_content_type()
-> Result<(), Box<dyn std::error::Error>> {
    assert_favicon_body_rejected(
        "image/x-icon",
        "<!doctype html><html><body><div id=\"root\" data-app=\"Example Brand\"></div></body></html>",
        "a branded SPA fallback is not favicon content",
    )
    .await
}

#[tokio::test]
async fn favicon_hashing_rejects_arbitrary_text_with_a_superficial_ico_header()
-> Result<(), Box<dyn std::error::Error>> {
    let mut body = vec![0, 0, 1, 0, 1, 0];
    body.extend_from_slice(b"branded-icon-placeholder-text");
    assert_favicon_body_rejected(
        "image/x-icon",
        body,
        "ICO magic bytes without a valid directory are arbitrary text",
    )
    .await
}

#[tokio::test]
async fn technology_stack_requires_nonempty_recognized_metadata_across_pne()
-> Result<(), Box<dyn std::error::Error>> {
    let (positive, calls) = scan("technology-stack", FixtureCase::Positive).await?;
    assert_eq!(calls, 1);
    assert_exact_finding(&positive, "technology-stack", 0);
    assert_eq!(
        positive.evidence[0].observation["observation"]["document"]["generator"],
        "wordpress"
    );
    assert_exact_envelope("technology-stack", &positive, 1)?;
    assert_no_signal("technology-stack", FixtureCase::Negative, 1).await?;
    assert_no_signal("technology-stack", FixtureCase::Edge, 1).await
}

#[tokio::test]
async fn every_scanner_preserves_the_complete_http_port_error_matrix()
-> Result<(), Box<dyn std::error::Error>> {
    for scanner_id in SCANNERS {
        for (port_kind, scan_kind) in [
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
        ] {
            let mut services = support::Harness::successful().services();
            services.http = Arc::new(FailingHttp(port_kind));
            let builtins = build_builtins(&services)?;
            let scanner_id_value = sugra_domain::ScannerId::new(scanner_id)?;
            let scanner = builtins
                .registry
                .get(&scanner_id_value)
                .ok_or("failure scanner is missing")?;
            let request = support::request_for(scanner.descriptor())?;
            let result = scanner.scan(&request, &support::context(false)).await;
            let Err(error) = result else {
                return Err(format!(
                    "{scanner_id} converted {port_kind:?} into a successful result"
                )
                .into());
            };
            assert_eq!(error.kind, scan_kind, "{scanner_id}: {port_kind:?}");
            assert_eq!(
                error.message,
                format!("offline HTTP {port_kind:?} fixture failure"),
                "{scanner_id}: {port_kind:?}"
            );
            assert!(!error.message.contains(support::SECRET_MARKER));
        }
    }
    Ok(())
}

#[tokio::test]
async fn every_scanner_honors_request_bounds_and_redacts_oversized_fixture_material()
-> Result<(), Box<dyn std::error::Error>> {
    for scanner_id in SCANNERS {
        let (result, calls) = scan_with_budget(scanner_id, FixtureCase::Bounds, 1, 4_096).await?;
        assert_eq!(calls, 1, "{scanner_id}");
        assert!(result.evidence.len() <= 1, "{scanner_id}");
        assert_exact_envelope(scanner_id, &result, 1)?;
        assert!(
            serde_json::to_vec(&result)?.len() < 32 * 1_024,
            "{scanner_id} retained an unbounded HTTP projection"
        );
        let observation = &result.evidence[0].observation["observation"];
        assert!(
            observation["headers"]
                .as_array()
                .is_some_and(|headers| headers.len() <= 256),
            "{scanner_id} retained too many header names"
        );
        if scanner_id == "third-party-integrations" {
            assert_eq!(
                observation["document"]["external_integration_hosts"]
                    .as_array()
                    .map(Vec::len),
                Some(128)
            );
        }
    }
    Ok(())
}
