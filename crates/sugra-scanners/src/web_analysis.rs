//! Structured, privacy-preserving analysis for HTTP scanner evidence.

use std::collections::{BTreeMap, BTreeSet};

use scraper::{Html, Selector};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sugra_core::{HttpCookie, HttpMethod, HttpRedirectDecision, HttpResponse};
use sugra_domain::{Confidence, Finding, Severity};
use url::Url;

const MAX_FINDING_EVIDENCE: usize = 32;

/// Safe signals derived from one bounded HTTP response body.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct WebSignals {
    pub(crate) title_sha256: Option<String>,
    pub(crate) links: usize,
    pub(crate) scripts: usize,
    pub(crate) inline_scripts: usize,
    pub(crate) external_script_hosts: Vec<String>,
    pub(crate) external_integration_hosts: Vec<String>,
    pub(crate) external_scripts_without_integrity: usize,
    pub(crate) forms: usize,
    pub(crate) inputs: usize,
    pub(crate) file_inputs: usize,
    pub(crate) password_inputs: usize,
    pub(crate) sensitive_autocomplete_inputs: usize,
    pub(crate) password_get_forms: usize,
    pub(crate) hidden_inputs: usize,
    pub(crate) comments: usize,
    pub(crate) iframes: usize,
    pub(crate) unsandboxed_iframes: usize,
    pub(crate) embedded_objects: usize,
    pub(crate) images: usize,
    pub(crate) lazy_resources: usize,
    pub(crate) tracking_pixels: usize,
    pub(crate) email_fingerprints: Vec<String>,
    pub(crate) social_links: usize,
    pub(crate) websocket_references: usize,
    pub(crate) api_references: usize,
    pub(crate) dom_sink_markers: usize,
    pub(crate) obfuscation_markers: usize,
    pub(crate) browser_feature_markers: usize,
    pub(crate) captcha_markers: usize,
    pub(crate) cms_markers: usize,
    pub(crate) privacy_markers: usize,
    pub(crate) cloud_markers: usize,
    pub(crate) generator: Option<String>,
    pub(crate) text_bytes: usize,
}

/// Bounded cross-response material used by aggregate analyzers.
#[derive(Debug, Clone)]
pub(crate) struct WebSample {
    pub(crate) label: String,
    pub(crate) status: u16,
    pub(crate) body_sha256: String,
    pub(crate) cookie_scopes: BTreeMap<String, String>,
    pub(crate) headers: BTreeSet<String>,
    pub(crate) duration_ms: u64,
    pub(crate) bytes: usize,
    pub(crate) redirect_count: usize,
    cache_reusable: bool,
    has_security_contact: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnalysisGroup {
    Api,
    Change,
    Crawler,
    Detection,
    Exposure,
    Fuzz,
    Headers,
    Inventory,
    Metadata,
    Performance,
    Privacy,
    Risk,
}

/// Extracts deterministic signals without retaining the body or direct email values.
pub(crate) fn signals(response: &HttpResponse) -> WebSignals {
    let text = String::from_utf8_lossy(&response.body);
    let lower = text.to_ascii_lowercase();
    let document = Html::parse_document(&text);
    let title_sha256 = first_text(&document, "title", 256)
        .map(|title| hex::encode(Sha256::digest(title.as_bytes())));
    let script_selector = selector("script[src]");
    let scripts = count(&document, "script");
    let inline_scripts =
        scripts.saturating_sub(count_selected(&document, script_selector.as_ref()));
    let base_host = response.final_url.host_str().unwrap_or_default();
    let (external_script_hosts, external_scripts_without_integrity) = script_selector.map_or_else(
        || (Vec::new(), 0),
        |selector| external_scripts(&document, &selector, &response.final_url, base_host),
    );
    let external_integration_hosts =
        external_integration_hosts(&document, &response.final_url, base_host);
    let password_selector = selector("input[type='password' i]");
    let password_inputs = count_selected(&document, password_selector.as_ref());
    WebSignals {
        title_sha256,
        links: count(&document, "a[href]"),
        scripts,
        inline_scripts,
        external_script_hosts,
        external_integration_hosts,
        external_scripts_without_integrity,
        forms: count(&document, "form"),
        inputs: count(&document, "input, textarea, select"),
        file_inputs: count(&document, "input[type='file' i]"),
        password_inputs,
        sensitive_autocomplete_inputs: sensitive_autocomplete(&document),
        password_get_forms: password_get_forms(&document),
        hidden_inputs: count(&document, "input[type='hidden' i]"),
        comments: html_comment_count(response, &document),
        iframes: count(&document, "iframe"),
        unsandboxed_iframes: count(&document, "iframe:not([sandbox])"),
        embedded_objects: count(&document, "object, embed, applet"),
        images: count(&document, "img"),
        lazy_resources: count(&document, "[loading='lazy' i], [data-src], [data-lazy-src]"),
        tracking_pixels: tracking_pixels(&document),
        email_fingerprints: email_fingerprints(&text),
        social_links: link_host_count(&document, &response.final_url, social_host),
        websocket_references: websocket_reference_count(response, &document, &lower),
        api_references: marker_count(
            &lower,
            &[
                "/api/",
                "/graphql",
                "openapi",
                "swagger",
                "application/json",
            ],
        ),
        dom_sink_markers: executable_marker_count(
            response,
            &document,
            &lower,
            &[
                ".innerhtml",
                "document.write",
                "eval(",
                "insertadjacenthtml",
            ],
        ),
        obfuscation_markers: executable_marker_count(
            response,
            &document,
            &lower,
            &["fromcharcode", "unescape(", "eval(", "atob(", "\\x"],
        ),
        browser_feature_markers: marker_count(
            &lower,
            &[
                "postmessage",
                "localstorage",
                "geolocation",
                "serviceworker",
                "websocket",
            ],
        ),
        captcha_markers: captcha_integrations(&document, &response.final_url),
        cms_markers: cms_markers(&document, &response.final_url),
        privacy_markers: marker_count(&lower, &["privacy", "cookie consent", "gdpr", "opt-out"]),
        cloud_markers: marker_count(
            &lower,
            &[
                "amazonaws.com",
                "storage.googleapis.com",
                "blob.core.windows.net",
            ],
        ),
        generator: recognized_generator(&document),
        text_bytes: document.root_element().text().map(str::len).sum(),
    }
}

/// Builds the redacted evidence projection consumed equally by CLI and TUI.
pub(crate) fn observation(
    label: &str,
    method: HttpMethod,
    response: &HttpResponse,
    signals: &WebSignals,
) -> Value {
    json!({
        "probe": safe_probe_label(label),
        "method": format!("{method:?}").to_ascii_uppercase(),
        "status": response.status,
        "headers": response.headers.keys().take(256).collect::<Vec<_>>(),
        "cookies": response.cookies.iter().take(128).map(safe_cookie).collect::<Vec<_>>(),
        "redirects": response.redirects.iter().map(|redirect| json!({
            "status": redirect.status,
            "from": safe_redirect_url(&redirect.from),
            "to": safe_redirect_url(&redirect.to),
            "decision": format!("{:?}", redirect.decision).to_ascii_lowercase(),
        })).collect::<Vec<_>>(),
        "bytes": response.body.len(),
        "sha256": hex::encode(Sha256::digest(&response.body)),
        "document": signals,
        "duration_ms": response.duration_ms,
    })
}

/// Captures bounded material for comparisons within one scan execution.
pub(crate) fn sample(label: String, response: &HttpResponse) -> WebSample {
    WebSample {
        label,
        status: response.status,
        body_sha256: hex::encode(Sha256::digest(&response.body)),
        cookie_scopes: response
            .cookies
            .iter()
            .take(128)
            .map(|cookie| (cookie.name_sha256.clone(), cookie_scope_sha256(cookie)))
            .collect(),
        headers: response.headers.keys().cloned().collect(),
        duration_ms: response.duration_ms,
        bytes: response.body.len(),
        redirect_count: response.redirects.len(),
        cache_reusable: response_is_reusable(response),
        has_security_contact: has_valid_security_contact(&response.body),
    }
}

/// Scanner-specific findings derived from one response.
pub(crate) fn response_findings(
    id: &str,
    response: &HttpResponse,
    signals: &WebSignals,
    evidence: usize,
) -> Vec<Finding> {
    match analysis_group(id) {
        Some(AnalysisGroup::Api) => api_findings(id, response, signals, evidence),
        Some(AnalysisGroup::Change | AnalysisGroup::Performance) | None => Vec::new(),
        Some(AnalysisGroup::Crawler) => crawler_findings(id, response, signals, evidence),
        Some(AnalysisGroup::Detection) => detection_findings(id, response, signals, evidence),
        Some(AnalysisGroup::Exposure) => exposure_findings(id, response, signals, evidence),
        Some(AnalysisGroup::Fuzz) => fuzz_findings(id, response, signals, evidence),
        Some(AnalysisGroup::Headers) => header_findings(id, response, evidence),
        Some(AnalysisGroup::Inventory) => inventory_findings(id, signals, evidence),
        Some(AnalysisGroup::Metadata) => metadata_findings(id, response, signals, evidence),
        Some(AnalysisGroup::Privacy) => privacy_findings(id, response, signals, evidence),
        Some(AnalysisGroup::Risk) => risk_findings(id, signals, evidence),
    }
}

/// Findings requiring comparison across multiple bounded responses.
pub(crate) fn aggregate_findings(
    id: &str,
    samples: &[WebSample],
    options: &BTreeMap<String, Value>,
) -> Vec<Finding> {
    match id {
        "cookie-scope-diff" => cookie_diff(samples),
        "cache-behavior-analyzer" => cache_diff(samples),
        "virtual-host-fuzzer" => virtual_host_diff(samples),
        "rate-limit-waf-bypass-test" => rate_limit_observation(samples),
        "multi-language-url-tester" => language_diff(samples),
        "carbon-footprint" | "performance-monitoring" | "quality-metrics" => {
            performance_findings(id, samples)
        }
        "attack-surface-delta" | "security-changelog-diff" => baseline_diff(id, samples, options),
        "security-txt" | "security-contact-gap-finder" => security_contact_gap(samples),
        _ => Vec::new(),
    }
}

fn analysis_group(id: &str) -> Option<AnalysisGroup> {
    match id {
        "api-schema-grabber"
        | "file-upload-surface-finder"
        | "form-grabber"
        | "graphql-introspection-probe"
        | "hidden-parameter-discovery"
        | "http-method-enumerator"
        | "websocket-endpoint-sniffer" => Some(AnalysisGroup::Api),
        "attack-surface-delta" | "security-changelog-diff" => Some(AnalysisGroup::Change),
        "broken-links" | "content-discovery" | "crawler" => Some(AnalysisGroup::Crawler),
        "cdn-detection"
        | "captcha-presence-checker"
        | "cms-detection"
        | "login-page-brute-identifier"
        | "technology-stack"
        | "firewall-detection"
        | "passive-cve-mapper" => Some(AnalysisGroup::Detection),
        "cloud-bucket-exposure"
        | "cloud-service-enumeration"
        | "exposed-api-endpoints"
        | "exposed-env-files"
        | "git-repo-exposure-check" => Some(AnalysisGroup::Exposure),
        "directory-finder"
        | "open-redirect-finder"
        | "rate-limit-waf-bypass-test"
        | "virtual-host-fuzzer" => Some(AnalysisGroup::Fuzz),
        "cache-behavior-analyzer"
        | "clickjacking-test"
        | "cors-misconfiguration-scanner"
        | "csp-deep-analyzer"
        | "http-headers"
        | "http-security" => Some(AnalysisGroup::Headers),
        "dependency-js-cdn-scanner"
        | "email-harvester"
        | "embedded-object-hunter"
        | "lazy-load-resource-finder"
        | "pixel-tracker-finder"
        | "social-media"
        | "static-asset-fingerprinter"
        | "third-party-integrations" => Some(AnalysisGroup::Inventory),
        "server-info"
        | "crawl-rules"
        | "favicon-hashing"
        | "html-comments-extractor"
        | "multi-language-url-tester"
        | "redirect-chain"
        | "sitemap"
        | "bug-bounty-program-finder"
        | "security-contact-gap-finder"
        | "security-txt" => Some(AnalysisGroup::Metadata),
        "carbon-footprint" | "performance-monitoring" | "quality-metrics" => {
            Some(AnalysisGroup::Performance)
        }
        "cookie-scope-diff"
        | "cookies"
        | "privacy-gdpr"
        | "session-cookie-lifetime-checker"
        | "session-hijacking-passive" => Some(AnalysisGroup::Privacy),
        "autocomplete-vulnerability-checker"
        | "dom-sink-scanner"
        | "html5-feature-abuse-detector"
        | "javascript-file-analyzer"
        | "javascript-obfuscation-detector"
        | "seo-abuse-detector"
        | "third-party-script-risk-profiler" => Some(AnalysisGroup::Risk),
        _ => None,
    }
}

fn finding(
    key: &str,
    title: &str,
    severity: Severity,
    confidence: Confidence,
    evidence: usize,
) -> Finding {
    Finding {
        key: key.into(),
        title: title.into(),
        severity,
        confidence,
        evidence: vec![evidence],
    }
}

fn count(document: &Html, value: &str) -> usize {
    selector(value).map_or(0, |selector| document.select(&selector).count())
}

fn count_selected(document: &Html, selector: Option<&Selector>) -> usize {
    selector.map_or(0, |selector| document.select(selector).count())
}

fn selector(value: &str) -> Option<Selector> {
    Selector::parse(value).ok()
}

fn first_text(document: &Html, value: &str, limit: usize) -> Option<String> {
    selector(value).and_then(|selector| {
        document.select(&selector).next().map(|element| {
            element
                .text()
                .collect::<String>()
                .trim()
                .chars()
                .take(limit)
                .collect()
        })
    })
}

fn marker_count(text: &str, markers: &[&str]) -> usize {
    markers
        .iter()
        .map(|marker| text.matches(marker).count())
        .sum()
}

fn cookie_scope_sha256(cookie: &HttpCookie) -> String {
    let scope = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}",
        cookie
            .domain
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        cookie.path.as_deref().unwrap_or_default(),
        cookie.secure,
        cookie.http_only,
        cookie
            .same_site
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        cookie.max_age_seconds.unwrap_or_default(),
        cookie.max_age_seconds.is_some(),
    );
    hex::encode(Sha256::digest(scope.as_bytes()))
}

fn safe_cookie(cookie: &HttpCookie) -> Value {
    json!({
        "name_sha256": cookie.name_sha256,
        "scope_sha256": cookie_scope_sha256(cookie),
        "secure": cookie.secure,
        "http_only": cookie.http_only,
        "same_site": cookie.same_site,
        "has_domain": cookie.domain.is_some(),
        "has_path": cookie.path.is_some(),
        "max_age_seconds": cookie.max_age_seconds,
    })
}

fn executable_marker_count(
    response: &HttpResponse,
    document: &Html,
    lower: &str,
    markers: &[&str],
) -> usize {
    let is_script_response = response.headers.get("content-type").is_some_and(|value| {
        let value = value.to_ascii_lowercase();
        value.contains("javascript") || value.contains("ecmascript")
    }) || response.final_url.path().rsplit_once('.').is_some_and(
        |(_, extension)| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "js" | "mjs" | "cjs"
            )
        },
    );
    if is_script_response {
        return marker_count(lower, markers);
    }
    selector("script:not([src])").map_or(0, |selector| {
        document
            .select(&selector)
            .filter(|script| is_executable_script_type(script.value().attr("type")))
            .map(|script| marker_count(&script.inner_html().to_ascii_lowercase(), markers))
            .sum()
    })
}

fn is_executable_script_type(value: Option<&str>) -> bool {
    value.is_none_or(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "" | "module"
                | "text/javascript"
                | "application/javascript"
                | "text/ecmascript"
                | "application/ecmascript"
        )
    })
}

fn html_comment_count(response: &HttpResponse, document: &Html) -> usize {
    if !is_html_response(response) {
        return 0;
    }
    let parsed = document
        .tree
        .nodes()
        .filter(|node| node.value().is_comment())
        .take(256)
        .count();
    let source = String::from_utf8_lossy(&response.body);
    parsed.min(
        source
            .matches("<!--")
            .count()
            .min(source.matches("-->").count()),
    )
}

fn websocket_reference_count(response: &HttpResponse, document: &Html, lower: &str) -> usize {
    let executable = executable_marker_count(
        response,
        document,
        lower,
        &["ws://", "wss://", "websocket("],
    );
    let structured = selector("[href], [src], [data-url], [data-endpoint]").map_or(0, |selector| {
        document
            .select(&selector)
            .filter(|element| {
                ["href", "src", "data-url", "data-endpoint"]
                    .iter()
                    .filter_map(|attribute| element.value().attr(attribute))
                    .any(|value| {
                        let value = value.trim().to_ascii_lowercase();
                        value.starts_with("ws://") || value.starts_with("wss://")
                    })
            })
            .count()
    });
    executable.saturating_add(structured)
}

fn recognized_generator(document: &Html) -> Option<String> {
    selector("meta[name='generator' i]").and_then(|selector| {
        document
            .select(&selector)
            .next()
            .and_then(|element| element.value().attr("content"))
            .and_then(recognized_cms_name)
    })
}

fn recognized_cms_name(value: &str) -> Option<String> {
    let lower = value.trim().to_ascii_lowercase();
    ["wordpress", "drupal", "joomla", "ghost"]
        .into_iter()
        .find(|candidate| lower.contains(candidate))
        .map(str::to_owned)
}

fn cms_markers(document: &Html, base: &Url) -> usize {
    let Some(selector) = selector("[href], [src], [action]") else {
        return 0;
    };
    document
        .select(&selector)
        .filter_map(|element| {
            ["href", "src", "action"]
                .into_iter()
                .find_map(|name| element.value().attr(name))
        })
        .filter_map(|value| base.join(value).ok())
        .filter(|url| {
            let path = url.path().to_ascii_lowercase();
            path.contains("/wp-content/")
                || path.contains("/wp-includes/")
                || path.contains("/sites/default/")
                || path.contains("/media/system/")
        })
        .take(32)
        .count()
}

fn captcha_integrations(document: &Html, base: &Url) -> usize {
    let class_markers = selector("[class]").map_or(0, |selector| {
        document
            .select(&selector)
            .filter(|element| {
                element
                    .value()
                    .attr("class")
                    .into_iter()
                    .flat_map(str::split_ascii_whitespace)
                    .any(|class| {
                        ["g-recaptcha", "h-captcha", "cf-turnstile"]
                            .iter()
                            .any(|marker| class.eq_ignore_ascii_case(marker))
                    })
            })
            .take(32)
            .count()
    });
    let script_markers = selector("script[src]").map_or(0, |selector| {
        document
            .select(&selector)
            .filter_map(|script| {
                script
                    .value()
                    .attr("src")
                    .and_then(|value| base.join(value).ok())
            })
            .filter(|url| {
                let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
                let path = url.path().to_ascii_lowercase();
                ((host == "google.com" || host.ends_with(".google.com"))
                    && path.contains("/recaptcha/"))
                    || ((host == "hcaptcha.com" || host.ends_with(".hcaptcha.com"))
                        && path.contains("/captcha/"))
                    || (host == "challenges.cloudflare.com" && path.contains("/turnstile/"))
            })
            .take(32)
            .count()
    });
    class_markers.saturating_add(script_markers).min(32)
}

fn safe_url(url: &Url) -> String {
    let mut safe = url.clone();
    let _ = safe.set_username("");
    let _ = safe.set_password(None);
    safe.set_query(None);
    safe.set_fragment(None);
    safe.to_string()
}

fn safe_redirect_url(url: &Url) -> String {
    let mut safe = url.clone();
    let _ = safe.set_username("");
    let _ = safe.set_password(None);
    safe.set_path("/");
    safe.set_query(None);
    safe.set_fragment(None);
    safe.to_string()
}

fn safe_probe_label(label: &str) -> String {
    let Some((kind, value)) = label.split_once(':') else {
        return label.chars().take(128).collect();
    };
    if let Ok(url) = Url::parse(value) {
        return format!(
            "{}:{}",
            kind.chars().take(64).collect::<String>(),
            safe_url(&url)
        );
    }
    format!(
        "{}:{}",
        kind.chars().take(64).collect::<String>(),
        hex::encode(Sha256::digest(value.as_bytes()))
    )
}

fn external_scripts(
    document: &Html,
    selector: &Selector,
    base: &Url,
    base_host: &str,
) -> (Vec<String>, usize) {
    let mut hosts = BTreeSet::new();
    let mut missing_integrity = 0;
    for script in document.select(selector) {
        let Some(url) = script
            .value()
            .attr("src")
            .and_then(|value| base.join(value).ok())
        else {
            continue;
        };
        let Some(host) = url.host_str() else {
            continue;
        };
        if !host.eq_ignore_ascii_case(base_host) {
            hosts.insert(host.to_ascii_lowercase());
            if script.value().attr("integrity").is_none() {
                missing_integrity += 1;
            }
        }
    }
    (hosts.into_iter().take(128).collect(), missing_integrity)
}

fn external_integration_hosts(document: &Html, base: &Url, base_host: &str) -> Vec<String> {
    let mut hosts = BTreeSet::new();
    let Some(selector) = selector(
        "script[src], iframe[src], embed[src], object[data], form[action], link[href][rel]",
    ) else {
        return Vec::new();
    };
    for element in document.select(&selector) {
        let name = element.value().name();
        if name == "link"
            && !element.value().attr("rel").is_some_and(|rel| {
                rel.split_ascii_whitespace().any(|token| {
                    matches!(
                        token.to_ascii_lowercase().as_str(),
                        "preconnect" | "dns-prefetch" | "stylesheet" | "preload" | "modulepreload"
                    )
                })
            })
        {
            continue;
        }
        let attribute = match name {
            "object" => "data",
            "form" => "action",
            "link" => "href",
            _ => "src",
        };
        let Some(host) = element
            .value()
            .attr(attribute)
            .and_then(|value| base.join(value).ok())
            .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        else {
            continue;
        };
        if !host.eq_ignore_ascii_case(base_host) {
            hosts.insert(host);
        }
        if hosts.len() == 128 {
            break;
        }
    }
    hosts.into_iter().collect()
}

fn sensitive_autocomplete(document: &Html) -> usize {
    selector("input[type='password' i]").map_or(0, |selector| {
        document
            .select(&selector)
            .filter(|input| {
                !matches!(
                    input
                        .value()
                        .attr("autocomplete")
                        .map(str::to_ascii_lowercase)
                        .as_deref(),
                    Some("off" | "new-password")
                )
            })
            .count()
    })
}

fn password_get_forms(document: &Html) -> usize {
    let (Some(form_selector), Some(password_selector)) =
        (selector("form"), selector("input[type='password' i]"))
    else {
        return 0;
    };
    document
        .select(&form_selector)
        .filter(|form| {
            !form
                .value()
                .attr("method")
                .is_some_and(|method| method.eq_ignore_ascii_case("post"))
                && form.select(&password_selector).next().is_some()
        })
        .count()
}

fn tracking_pixels(document: &Html) -> usize {
    selector("img").map_or(0, |selector| {
        document
            .select(&selector)
            .filter(|image| {
                let width = image.value().attr("width").unwrap_or_default();
                let height = image.value().attr("height").unwrap_or_default();
                matches!((width, height), ("1", "1") | ("0", "0"))
            })
            .count()
    })
}

fn email_fingerprints(text: &str) -> Vec<String> {
    text.split(|character: char| character.is_whitespace() || "<>\"'(),;".contains(character))
        .filter(|token| {
            let mut parts = token.split('@');
            let local = parts.next().unwrap_or_default();
            let domain = parts.next().unwrap_or_default();
            !local.is_empty() && domain.contains('.') && parts.next().is_none()
        })
        .map(|value| hex::encode(Sha256::digest(value.to_ascii_lowercase().as_bytes())))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(256)
        .collect()
}

fn link_host_count(document: &Html, base: &Url, predicate: fn(&str) -> bool) -> usize {
    selector("a[href]").map_or(0, |selector| {
        document
            .select(&selector)
            .filter_map(|link| {
                link.value()
                    .attr("href")
                    .and_then(|value| base.join(value).ok())
                    .and_then(|url| url.host_str().map(str::to_owned))
            })
            .filter(|host| predicate(host))
            .count()
    })
}

fn social_host(host: &str) -> bool {
    [
        "facebook.com",
        "instagram.com",
        "linkedin.com",
        "mastodon.social",
        "tiktok.com",
        "x.com",
        "youtube.com",
    ]
    .iter()
    .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

fn api_findings(
    id: &str,
    response: &HttpResponse,
    signals: &WebSignals,
    evidence: usize,
) -> Vec<Finding> {
    match id {
        "api-schema-grabber" if response.status == 200 && is_api_schema(&response.body) => one(
            "api-schema-published",
            "A machine-readable API schema is publicly available",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ),
        "file-upload-surface-finder" if signals.file_inputs > 0 => one(
            "file-upload-surface",
            "A file upload input is present",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ),
        "form-grabber" if signals.forms > 0 => one(
            "web-forms-observed",
            "One or more web forms are present",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ),
        "graphql-introspection-probe"
            if response.status == 200 && is_graphql_introspection(&response.body) =>
        {
            one(
                "graphql-introspection-enabled",
                "The GraphQL endpoint returned schema introspection metadata",
                Severity::Low,
                Confidence::Confirmed,
                evidence,
            )
        }
        "hidden-parameter-discovery" if signals.hidden_inputs > 0 => one(
            "hidden-parameters-observed",
            "Hidden form parameters are present",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ),
        "http-method-enumerator"
            if response
                .headers
                .get("allow")
                .is_some_and(|allow| advertises_sensitive_method(allow)) =>
        {
            one(
                "state-changing-http-method-advertised",
                "The server advertises a state-changing or diagnostic HTTP method",
                Severity::Low,
                Confidence::Confirmed,
                evidence,
            )
        }
        "websocket-endpoint-sniffer" if signals.websocket_references > 0 => one(
            "websocket-reference-observed",
            "A WebSocket endpoint reference is present",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ),
        _ => Vec::new(),
    }
}

fn is_graphql_introspection(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|document| document.pointer("/data/__schema/queryType").cloned())
        .is_some_and(|query_type| query_type.is_object())
}

fn advertises_sensitive_method(allow: &str) -> bool {
    allow.split(',').map(str::trim).any(|candidate| {
        ["POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"]
            .iter()
            .any(|method| candidate.eq_ignore_ascii_case(method))
    })
}

fn is_api_schema(body: &[u8]) -> bool {
    const MAX_SCHEMA_BYTES: usize = 1_048_576;
    if body.len() > MAX_SCHEMA_BYTES {
        return false;
    }
    let Ok(document) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    let Some(root) = document.as_object() else {
        return false;
    };
    let has_paths = root.get("paths").is_some_and(Value::is_object);
    let openapi = root
        .get("openapi")
        .and_then(Value::as_str)
        .is_some_and(|version| version.starts_with("3."));
    let swagger = root
        .get("swagger")
        .and_then(Value::as_str)
        .is_some_and(|version| version.starts_with("2."));
    let graphql = root
        .get("data")
        .and_then(Value::as_object)
        .and_then(|data| data.get("__schema"))
        .is_some_and(Value::is_object);
    (has_paths && (openapi || swagger)) || graphql
}

fn crawler_findings(
    id: &str,
    response: &HttpResponse,
    signals: &WebSignals,
    evidence: usize,
) -> Vec<Finding> {
    match id {
        "broken-links" if (400..=599).contains(&response.status) => one(
            "broken-link",
            "An in-scope resource returned an error status",
            Severity::Low,
            Confidence::Confirmed,
            evidence,
        ),
        "crawler" if is_crawlable_response(response) && signals.links > 0 => one(
            "crawlable-links-observed",
            "The successful HTML response contains crawl candidates",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ),
        "content-discovery" if matches!(response.status, 200..=399) => one(
            "content-resource-observed",
            "An in-scope web resource is reachable",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ),
        _ => Vec::new(),
    }
}

fn detection_findings(
    id: &str,
    response: &HttpResponse,
    signals: &WebSignals,
    evidence: usize,
) -> Vec<Finding> {
    let headers = &response.headers;
    match id {
        "cdn-detection" if has_header(headers, &["cf-ray", "x-amz-cf-id", "x-cdn"]) => one(
            "cdn-signal-observed",
            "A public CDN or reverse-proxy signal is present",
            Severity::Info,
            Confidence::Inferred,
            evidence,
        ),
        "captcha-presence-checker" if signals.captcha_markers > 0 => one(
            "captcha-control-observed",
            "A CAPTCHA integration is present",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ),
        "cms-detection" if signals.generator.is_some() || signals.cms_markers > 0 => one(
            "cms-signal-observed",
            "Public content-management-system signals are present",
            Severity::Info,
            Confidence::Inferred,
            evidence,
        ),
        "login-page-brute-identifier" if signals.password_inputs > 0 => one(
            "login-surface-observed",
            "A password-based login surface is present",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ),
        "technology-stack"
            if signals.generator.is_some()
                || headers
                    .get("server")
                    .is_some_and(|value| !value.trim().is_empty()) =>
        {
            one(
                "technology-signal-observed",
                "Public technology-identification metadata is present",
                Severity::Info,
                Confidence::Inferred,
                evidence,
            )
        }
        "firewall-detection"
            if has_header(headers, &["cf-ray", "x-sucuri-id", "x-akamai-transformed"]) =>
        {
            one(
                "web-protection-signal-observed",
                "A web protection intermediary signal is present",
                Severity::Info,
                Confidence::Inferred,
                evidence,
            )
        }
        "passive-cve-mapper"
            if headers.get("server").is_some_and(|server| {
                server.contains('/') && server.chars().any(char::is_numeric)
            }) =>
        {
            one(
                "versioned-component-observed",
                "A versioned component banner is available for CVE correlation",
                Severity::Info,
                Confidence::Inferred,
                evidence,
            )
        }
        _ => Vec::new(),
    }
}

fn exposure_findings(
    id: &str,
    response: &HttpResponse,
    signals: &WebSignals,
    evidence: usize,
) -> Vec<Finding> {
    match id {
        "exposed-env-files" if is_exposed_env_file(response) => one(
            "environment-file-exposed",
            "An environment-style configuration file is publicly readable",
            Severity::Critical,
            Confidence::Confirmed,
            evidence,
        ),
        "git-repo-exposure-check" if is_exposed_git_metadata(response) => one(
            "git-metadata-exposed",
            "Repository metadata is publicly readable",
            Severity::High,
            Confidence::Confirmed,
            evidence,
        ),
        "exposed-api-endpoints"
            if response.status == 200
                && (signals.api_references > 0
                    || response
                        .headers
                        .get("content-type")
                        .is_some_and(|value| value.contains("json"))) =>
        {
            one(
                "api-surface-observed",
                "A public API surface is reachable",
                Severity::Info,
                Confidence::Confirmed,
                evidence,
            )
        }
        "cloud-bucket-exposure" if response.status == 200 && signals.cloud_markers > 0 => one(
            "cloud-storage-reference-observed",
            "A public cloud-storage reference is present",
            Severity::Info,
            Confidence::Inferred,
            evidence,
        ),
        "cloud-service-enumeration" if response.status == 200 && signals.cloud_markers > 0 => one(
            "cloud-service-signal-observed",
            "A public cloud-service signal is present",
            Severity::Info,
            Confidence::Inferred,
            evidence,
        ),
        _ => Vec::new(),
    }
}

fn is_exposed_env_file(response: &HttpResponse) -> bool {
    const MAX_ENV_BYTES: usize = 1_048_576;
    if !matches!(response.status, 200..=299)
        || response.body.len() > MAX_ENV_BYTES
        || is_html_response(response)
        || !response
            .final_url
            .path()
            .rsplit('/')
            .next()
            .is_some_and(|name| name == ".env" || name.starts_with(".env."))
    {
        return false;
    }
    let Ok(body) = std::str::from_utf8(&response.body) else {
        return false;
    };
    let mut assignments = 0;
    let mut sensitive = false;
    for line in body.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        let key = key.trim();
        if !valid_env_key(key) || value.trim().is_empty() || value.contains(['<', '>']) {
            return false;
        }
        assignments += 1;
        sensitive |= sensitive_env_key(key);
    }
    assignments > 0 && sensitive
}

fn valid_env_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn sensitive_env_key(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    upper == "DATABASE_URL"
        || upper == "PRIVATE_KEY"
        || upper == "API_KEY"
        || upper
            .split('_')
            .any(|part| matches!(part, "SECRET" | "PASSWORD" | "PASSWD" | "TOKEN"))
        || upper.ends_with("_SECRET")
        || upper.ends_with("_API_KEY")
        || upper.ends_with("_PRIVATE_KEY")
        || upper.ends_with("_ACCESS_KEY")
}

fn is_exposed_git_metadata(response: &HttpResponse) -> bool {
    const MAX_GIT_METADATA_BYTES: usize = 1_048_576;
    if !matches!(response.status, 200..=299)
        || response.body.len() > MAX_GIT_METADATA_BYTES
        || is_html_response(response)
    {
        return false;
    }
    let Ok(body) = std::str::from_utf8(&response.body) else {
        return false;
    };
    match response.final_url.path() {
        "/.git/HEAD" => valid_git_head(body),
        "/.git/config" => valid_git_config(body),
        _ => false,
    }
}

fn valid_git_head(body: &str) -> bool {
    let value = body.trim();
    value.strip_prefix("ref: ").is_some_and(valid_git_reference)
        || matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_git_reference(reference: &str) -> bool {
    let Some(name) = reference.strip_prefix("refs/") else {
        return false;
    };
    !name.is_empty()
        && !name.starts_with('.')
        && !name.ends_with(['.', '/'])
        && name
            .as_bytes()
            .get(name.len().saturating_sub(5)..)
            .is_none_or(|suffix| suffix != b".lock")
        && !name.contains("..")
        && !name.contains("//")
        && !name.contains("@{")
        && name.split('/').all(|component| {
            !component.is_empty()
                && !component.starts_with('.')
                && !component.ends_with('.')
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn valid_git_config(body: &str) -> bool {
    let mut section = None;
    let mut core_marker = false;
    let mut entries = 0;
    for line in body.lines().map(str::trim) {
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = Some(line[1..line.len() - 1].trim().to_ascii_lowercase());
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() || value.trim().is_empty() || section.is_none() {
            return false;
        }
        entries += 1;
        if section.as_deref() == Some("core")
            && matches!(
                key.as_str(),
                "repositoryformatversion" | "filemode" | "bare" | "logallrefupdates"
            )
        {
            core_marker = true;
        }
    }
    entries > 0 && core_marker
}

fn fuzz_findings(
    id: &str,
    response: &HttpResponse,
    _signals: &WebSignals,
    evidence: usize,
) -> Vec<Finding> {
    match id {
        "directory-finder" if matches!(response.status, 200..=399) => one(
            "directory-response-observed",
            "A candidate directory returned a non-error response",
            Severity::Info,
            Confidence::Inferred,
            evidence,
        ),
        "open-redirect-finder" if accepted_external_redirect(response) => one(
            "external-open-redirect",
            "The application accepted an external redirect destination",
            Severity::Medium,
            Confidence::Confirmed,
            evidence,
        ),
        _ => Vec::new(),
    }
}

fn accepted_external_redirect(response: &HttpResponse) -> bool {
    if !redirect_probe_targets_external_host(response) {
        return false;
    }
    response.redirects.iter().any(|redirect| {
        redirect.decision == HttpRedirectDecision::OutOfScope
            && redirect.to.host_str() == Some("scope-check.invalid")
    }) || matches!(response.status, 300..=399)
        && response
            .headers
            .get("location")
            .and_then(|location| response.final_url.join(location).ok())
            .is_some_and(|location| location.host_str() == Some("scope-check.invalid"))
}

fn redirect_probe_targets_external_host(response: &HttpResponse) -> bool {
    let probe = response
        .redirects
        .first()
        .map_or(&response.final_url, |redirect| &redirect.from);
    probe.query_pairs().any(|(key, value)| {
        matches!(key.as_ref(), "next" | "url" | "redirect")
            && Url::parse(&value)
                .ok()
                .is_some_and(|url| url.host_str() == Some("scope-check.invalid"))
    })
}

fn header_findings(id: &str, response: &HttpResponse, evidence: usize) -> Vec<Finding> {
    if id == "csp-deep-analyzer" {
        return csp_findings(response, evidence);
    }
    let mut findings = Vec::new();
    if is_html_response(response) && matches!(id, "http-headers" | "http-security") {
        let mut headers = vec!["content-security-policy", "x-content-type-options"];
        if response.final_url.scheme() == "https" {
            headers.push("strict-transport-security");
        }
        for header in headers {
            if !effective_security_header(id, response, header) {
                findings.push(finding(
                    &format!("missing-{header}"),
                    &format!("Security header {header} was not observed"),
                    Severity::Low,
                    Confidence::Confirmed,
                    evidence,
                ));
            }
        }
    }
    if id == "clickjacking-test" && is_html_response(response) && !framing_is_restricted(response) {
        findings.push(finding(
            "framing-not-restricted",
            "No framing restriction was observed",
            Severity::Medium,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if id == "cors-misconfiguration-scanner"
        && response
            .headers
            .get("access-control-allow-origin")
            .is_some_and(|value| permits_untrusted_cors_origin(value))
    {
        findings.push(finding(
            "permissive-cors",
            "The response permits an untrusted cross-origin caller",
            Severity::Medium,
            Confidence::Confirmed,
            evidence,
        ));
    }
    findings
}

#[derive(Debug, Default)]
struct CspSummary {
    effective_directives: usize,
    unsafe_eval: bool,
    unsafe_inline: bool,
    wildcard_source: bool,
}

fn csp_findings(response: &HttpResponse, evidence: usize) -> Vec<Finding> {
    if !is_html_response(response) {
        return Vec::new();
    }
    let Some(policy) = response.headers.get("content-security-policy") else {
        return if response
            .headers
            .get("content-security-policy-report-only")
            .is_some_and(|policy| summarize_csp(policy).effective_directives > 0)
        {
            one(
                "csp-not-enforced",
                "A Content Security Policy is present only in report-only mode",
                Severity::Low,
                Confidence::Confirmed,
                evidence,
            )
        } else {
            one(
                "csp-not-observed",
                "No enforced Content Security Policy was observed",
                Severity::Low,
                Confidence::Confirmed,
                evidence,
            )
        };
    };
    let summary = summarize_csp(policy);
    if summary.effective_directives == 0 {
        return one(
            "csp-no-effective-directive",
            "The Content Security Policy has no effective enforcement directive",
            Severity::Low,
            Confidence::Confirmed,
            evidence,
        );
    }
    let mut findings = Vec::new();
    if summary.unsafe_inline {
        findings.extend(one(
            "csp-unsafe-inline",
            "The Content Security Policy permits inline execution",
            Severity::Medium,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if summary.unsafe_eval {
        findings.extend(one(
            "csp-unsafe-eval",
            "The Content Security Policy permits dynamic code evaluation",
            Severity::Medium,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if summary.wildcard_source {
        findings.extend(one(
            "csp-wildcard-source",
            "The Content Security Policy permits an unrestricted source wildcard",
            Severity::Medium,
            Confidence::Confirmed,
            evidence,
        ));
    }
    findings
}

fn summarize_csp(policy: &str) -> CspSummary {
    let mut summary = CspSummary::default();
    for directive in policy.split(';').take(128) {
        let mut parts = directive.split_ascii_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        if !is_csp_enforcement_directive(name) {
            continue;
        }
        let sources = parts.take(128).collect::<Vec<_>>();
        if sources.is_empty() && !csp_directive_allows_empty_value(name) {
            continue;
        }
        summary.effective_directives += 1;
        for source in sources {
            summary.unsafe_inline |= source.eq_ignore_ascii_case("'unsafe-inline'");
            summary.unsafe_eval |= source.eq_ignore_ascii_case("'unsafe-eval'");
            summary.wildcard_source |= source == "*";
        }
    }
    summary
}

fn csp_directive_allows_empty_value(name: &str) -> bool {
    [
        "sandbox",
        "upgrade-insecure-requests",
        "block-all-mixed-content",
    ]
    .iter()
    .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

fn is_csp_enforcement_directive(name: &str) -> bool {
    [
        "default-src",
        "script-src",
        "style-src",
        "img-src",
        "connect-src",
        "font-src",
        "object-src",
        "media-src",
        "frame-src",
        "child-src",
        "worker-src",
        "manifest-src",
        "base-uri",
        "form-action",
        "frame-ancestors",
        "sandbox",
        "upgrade-insecure-requests",
        "block-all-mixed-content",
        "require-trusted-types-for",
        "trusted-types",
    ]
    .iter()
    .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

fn permits_untrusted_cors_origin(value: &str) -> bool {
    let value = value.trim();
    if value == "*" {
        return true;
    }
    let (Ok(candidate), Ok(probe)) = (Url::parse(value), Url::parse("https://scope-check.invalid"))
    else {
        return false;
    };
    candidate.username().is_empty()
        && candidate.password().is_none()
        && candidate.path() == "/"
        && candidate.query().is_none()
        && candidate.fragment().is_none()
        && candidate.origin() == probe.origin()
}

fn framing_is_restricted(response: &HttpResponse) -> bool {
    let x_frame_options = response
        .headers
        .get("x-frame-options")
        .map(|value| value.trim())
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("deny") || value.eq_ignore_ascii_case("sameorigin")
        });
    if x_frame_options {
        return true;
    }

    response
        .headers
        .get("content-security-policy")
        .and_then(|value| {
            value.split(';').find_map(|directive| {
                let mut parts = directive.split_ascii_whitespace();
                parts
                    .next()
                    .is_some_and(|name| name.eq_ignore_ascii_case("frame-ancestors"))
                    .then(|| parts.collect::<Vec<_>>())
            })
        })
        .is_some_and(|sources| !sources.is_empty() && !sources.contains(&"*"))
}

fn effective_security_header(id: &str, response: &HttpResponse, header: &str) -> bool {
    let Some(value) = response.headers.get(header) else {
        return false;
    };
    if id != "http-security" {
        return true;
    }

    match header {
        "content-security-policy" => has_restrictive_csp_directive(value),
        "strict-transport-security" => value.split(';').any(|directive| {
            let Some((name, seconds)) = directive.split_once('=') else {
                return false;
            };
            name.trim().eq_ignore_ascii_case("max-age")
                && seconds
                    .trim()
                    .parse::<u64>()
                    .is_ok_and(|seconds| seconds > 0)
        }),
        "x-content-type-options" => value.trim().eq_ignore_ascii_case("nosniff"),
        _ => true,
    }
}

fn has_restrictive_csp_directive(value: &str) -> bool {
    value.split(';').any(|directive| {
        let mut parts = directive.split_ascii_whitespace();
        let Some(name) = parts.next() else {
            return false;
        };
        if [
            "sandbox",
            "upgrade-insecure-requests",
            "block-all-mixed-content",
        ]
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
        {
            return true;
        }
        let restrictive_source_directive = [
            "default-src",
            "script-src",
            "style-src",
            "img-src",
            "connect-src",
            "font-src",
            "object-src",
            "media-src",
            "frame-src",
            "child-src",
            "worker-src",
            "manifest-src",
            "base-uri",
            "form-action",
            "frame-ancestors",
            "require-trusted-types-for",
            "trusted-types",
        ]
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate));
        if !restrictive_source_directive {
            return false;
        }
        let sources = parts.collect::<Vec<_>>();
        !sources.is_empty() && !sources.contains(&"*")
    })
}

fn is_html_response(response: &HttpResponse) -> bool {
    if !(200..=399).contains(&response.status) {
        return false;
    }
    if let Some(value) = response.headers.get("content-type") {
        let media_type = value.split(';').next().unwrap_or_default().trim();
        return media_type.eq_ignore_ascii_case("text/html")
            || media_type.eq_ignore_ascii_case("application/xhtml+xml");
    }

    let prefix = String::from_utf8_lossy(&response.body);
    let prefix = prefix.trim_start_matches(char::is_whitespace);
    ["<!doctype html", "<html", "<head", "<body"]
        .iter()
        .any(|tag| html_prefix_matches(prefix, tag))
}

pub(crate) fn is_crawlable_response(response: &HttpResponse) -> bool {
    response.status == 200 && is_html_response(response)
}

fn html_prefix_matches(value: &str, tag: &str) -> bool {
    value
        .get(..tag.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(tag))
        && value
            .as_bytes()
            .get(tag.len())
            .is_some_and(|byte| byte.is_ascii_whitespace() || matches!(byte, b'>' | b'/'))
}

fn inventory_findings(id: &str, signals: &WebSignals, evidence: usize) -> Vec<Finding> {
    let (key, title, count) = match id {
        "dependency-js-cdn-scanner" => (
            "external-javascript-dependency",
            "External JavaScript dependencies are present",
            signals.external_script_hosts.len(),
        ),
        "email-harvester" => (
            "public-email-reference",
            "Public email references were observed and fingerprinted",
            signals.email_fingerprints.len(),
        ),
        "embedded-object-hunter" => (
            "embedded-object-observed",
            "Embedded object surfaces are present",
            signals.embedded_objects + signals.iframes,
        ),
        "lazy-load-resource-finder" => (
            "lazy-resource-observed",
            "Lazy-loaded resources are present",
            signals.lazy_resources,
        ),
        "pixel-tracker-finder" => (
            "tracking-pixel-observed",
            "One-pixel image resources are present",
            signals.tracking_pixels,
        ),
        "social-media" => (
            "social-link-observed",
            "Public social-media links are present",
            signals.social_links,
        ),
        "third-party-integrations" => (
            "third-party-integration-observed",
            "Third-party integrations are present",
            signals.external_integration_hosts.len(),
        ),
        "static-asset-fingerprinter" => (
            "static-assets-observed",
            "Static assets are available for local fingerprinting",
            signals.scripts + signals.images,
        ),
        _ => return Vec::new(),
    };
    if count == 0 {
        Vec::new()
    } else {
        one(key, title, Severity::Info, Confidence::Confirmed, evidence)
    }
}

fn metadata_findings(
    id: &str,
    response: &HttpResponse,
    signals: &WebSignals,
    evidence: usize,
) -> Vec<Finding> {
    let lower = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    match id {
        "server-info"
            if response
                .headers
                .get("server")
                .is_some_and(|value| !value.trim().is_empty()) =>
        {
            one(
                "server-banner-observed",
                "The response exposes a server banner",
                Severity::Info,
                Confidence::Confirmed,
                evidence,
            )
        }
        "crawl-rules" if has_valid_robots_policy(response) => one(
            "crawl-rules-observed",
            "A robots policy is published",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ),
        "favicon-hashing" if is_favicon_response(response) => one(
            "favicon-fingerprint-observed",
            "A favicon fingerprint was collected",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ),
        "html-comments-extractor" if signals.comments > 0 => one(
            "html-comments-observed",
            "HTML comments are present",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ),
        "redirect-chain" if !response.redirects.is_empty() => one(
            "redirect-chain-observed",
            "One or more redirect hops were recorded",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ),
        "sitemap" if is_sitemap_document(response) => one(
            "sitemap-observed",
            "A sitemap document is publicly available",
            Severity::Info,
            Confidence::Confirmed,
            evidence,
        ),
        "bug-bounty-program-finder"
            if response.status == 200
                && (lower.contains("bug bounty") || lower.contains("vulnerability disclosure")) =>
        {
            one(
                "disclosure-program-observed",
                "A vulnerability disclosure or bug bounty program is referenced",
                Severity::Info,
                Confidence::Confirmed,
                evidence,
            )
        }
        "security-txt" | "security-contact-gap-finder"
            if response.status == 200 && has_valid_security_contact(&response.body) =>
        {
            one(
                "security-contact-observed",
                "A security contact is published",
                Severity::Info,
                Confidence::Confirmed,
                evidence,
            )
        }
        _ => Vec::new(),
    }
}

fn is_sitemap_document(response: &HttpResponse) -> bool {
    if response.status != 200
        || response
            .headers
            .get("content-type")
            .is_some_and(|value| value.to_ascii_lowercase().contains("text/html"))
    {
        return false;
    }
    let Ok(body) = std::str::from_utf8(&response.body) else {
        return false;
    };
    let mut root = body.trim_start().to_ascii_lowercase();
    if root.starts_with("<?xml") {
        let Some((_, remainder)) = root.split_once("?>") else {
            return false;
        };
        root = remainder.trim_start().to_owned();
    }
    html_prefix_matches(&root, "<urlset") || html_prefix_matches(&root, "<sitemapindex")
}

fn is_favicon_response(response: &HttpResponse) -> bool {
    const MAX_FAVICON_BYTES: usize = 1_048_576;
    if !matches!(response.status, 200..=299)
        || response.body.is_empty()
        || response.body.len() > MAX_FAVICON_BYTES
        || is_html_response(response)
    {
        return false;
    }
    let media_type = response
        .headers
        .get("content-type")
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .map(str::to_ascii_lowercase);
    match media_type.as_deref() {
        Some("image/x-icon" | "image/vnd.microsoft.icon") => is_ico(&response.body),
        Some("image/png") => response.body.starts_with(b"\x89PNG\r\n\x1a\n"),
        Some("image/gif") => {
            response.body.starts_with(b"GIF87a") || response.body.starts_with(b"GIF89a")
        }
        Some("image/jpeg") => response.body.starts_with(&[0xff, 0xd8, 0xff]),
        Some("image/webp") => {
            response.body.starts_with(b"RIFF") && response.body.get(8..12) == Some(b"WEBP")
        }
        Some("image/svg+xml") => is_svg(&response.body),
        Some("image/avif") => response
            .body
            .get(4..12)
            .is_some_and(|brand| matches!(brand, b"ftypavif" | b"ftypavis")),
        _ => {
            is_ico(&response.body)
                || response.body.starts_with(b"\x89PNG\r\n\x1a\n")
                || is_svg(&response.body)
        }
    }
}

fn is_ico(body: &[u8]) -> bool {
    if body.len() < 6 || !body.starts_with(&[0, 0, 1, 0]) {
        return false;
    }
    let count = usize::from(u16::from_le_bytes([body[4], body[5]]));
    if count == 0 || count > 256 {
        return false;
    }
    let Some(directory_end) = count.checked_mul(16).and_then(|size| size.checked_add(6)) else {
        return false;
    };
    if directory_end > body.len() {
        return false;
    }
    body[6..directory_end].chunks_exact(16).all(|entry| {
        let size = usize::try_from(u32::from_le_bytes([
            entry[8], entry[9], entry[10], entry[11],
        ]))
        .unwrap_or(usize::MAX);
        let offset = usize::try_from(u32::from_le_bytes([
            entry[12], entry[13], entry[14], entry[15],
        ]))
        .unwrap_or(usize::MAX);
        entry[3] == 0
            && size > 0
            && offset >= directory_end
            && offset
                .checked_add(size)
                .is_some_and(|end| end <= body.len())
    })
}

fn is_svg(body: &[u8]) -> bool {
    let Ok(body) = std::str::from_utf8(body) else {
        return false;
    };
    let mut root = body.trim_start();
    if root.starts_with("<?xml") {
        let Some((_, remainder)) = root.split_once("?>") else {
            return false;
        };
        root = remainder.trim_start();
    }
    html_prefix_matches(root, "<svg")
}

fn has_valid_robots_policy(response: &HttpResponse) -> bool {
    const MAX_ROBOTS_BYTES: usize = 256 * 1024;
    if response.status != 200
        || response.final_url.path() != "/robots.txt"
        || response.body.len() > MAX_ROBOTS_BYTES
        || response
            .headers
            .get("content-type")
            .is_some_and(|value| value.to_ascii_lowercase().contains("text/html"))
    {
        return false;
    }
    let Ok(text) = std::str::from_utf8(&response.body) else {
        return false;
    };
    let mut has_agent = false;
    let mut has_directive = false;
    for line in text.lines().take(4096) {
        let line = line.split('#').next().unwrap_or_default().trim();
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("user-agent") && !value.is_empty() {
            has_agent = true;
        } else if has_agent
            && ["allow", "disallow", "crawl-delay", "sitemap"]
                .iter()
                .any(|directive| name.eq_ignore_ascii_case(directive))
            && !value.is_empty()
        {
            has_directive = true;
        }
    }
    has_agent && has_directive
}

fn has_valid_security_contact(body: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(body) else {
        return false;
    };
    text.lines().any(|line| {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with('#') || line.starts_with(char::is_whitespace) {
            return false;
        }
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        if !name.eq_ignore_ascii_case("contact") {
            return false;
        }
        let value = value.trim();
        !value.is_empty()
            && !value.bytes().any(|byte| byte.is_ascii_whitespace())
            && Url::parse(value).is_ok_and(|contact| {
                !contact.scheme().is_empty()
                    && (contact.host_str().is_some() || !contact.path().is_empty())
            })
    })
}

fn privacy_findings(
    id: &str,
    response: &HttpResponse,
    signals: &WebSignals,
    evidence: usize,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if matches!(id, "cookies" | "session-hijacking-passive") {
        if response.cookies.iter().any(|cookie| !cookie.secure) {
            findings.push(finding(
                "cookie-secure-missing",
                "A response cookie does not declare Secure",
                Severity::Medium,
                Confidence::Confirmed,
                evidence,
            ));
        }
        if response.cookies.iter().any(|cookie| !cookie.http_only) {
            findings.push(finding(
                "cookie-httponly-missing",
                "A response cookie does not declare HttpOnly",
                Severity::Medium,
                Confidence::Confirmed,
                evidence,
            ));
        }
        if response.cookies.iter().any(|cookie| {
            !cookie.same_site.as_deref().is_some_and(|value| {
                value.eq_ignore_ascii_case("strict")
                    || value.eq_ignore_ascii_case("lax")
                    || value.eq_ignore_ascii_case("none")
            })
        }) {
            findings.push(finding(
                "cookie-samesite-missing",
                "A response cookie does not declare a valid SameSite policy",
                Severity::Low,
                Confidence::Confirmed,
                evidence,
            ));
        }
    }
    if id == "session-cookie-lifetime-checker"
        && response.cookies.iter().any(|cookie| {
            cookie
                .max_age_seconds
                .is_some_and(|seconds| seconds > 86_400 * 30)
        })
    {
        findings.push(finding(
            "long-lived-cookie",
            "A response cookie declares a lifetime longer than 30 days",
            Severity::Low,
            Confidence::Inferred,
            evidence,
        ));
    }
    if id == "privacy-gdpr" && signals.privacy_markers == 0 && signals.forms > 0 {
        findings.push(finding(
            "privacy-notice-not-observed",
            "No privacy or consent marker was observed near public forms",
            Severity::Info,
            Confidence::Unknown,
            evidence,
        ));
    }
    findings
}

fn risk_findings(id: &str, signals: &WebSignals, evidence: usize) -> Vec<Finding> {
    let candidate = match id {
        "autocomplete-vulnerability-checker" if signals.sensitive_autocomplete_inputs > 0 => {
            Some((
                "sensitive-autocomplete-enabled",
                "Sensitive inputs permit browser autocomplete",
                Severity::Low,
                Confidence::Confirmed,
            ))
        }
        "dom-sink-scanner" if signals.dom_sink_markers > 0 => Some((
            "dom-sink-marker-observed",
            "Client code contains DOM execution sink markers",
            Severity::Medium,
            Confidence::Inferred,
        )),
        "html5-feature-abuse-detector" if signals.browser_feature_markers > 0 => Some((
            "browser-capability-marker-observed",
            "Client code references sensitive browser capabilities",
            Severity::Info,
            Confidence::Inferred,
        )),
        "javascript-file-analyzer" if signals.api_references > 0 => Some((
            "javascript-api-reference-observed",
            "Client code contains API endpoint references",
            Severity::Info,
            Confidence::Inferred,
        )),
        "javascript-obfuscation-detector" if signals.obfuscation_markers > 1 => Some((
            "javascript-obfuscation-markers",
            "Client code contains multiple obfuscation markers",
            Severity::Low,
            Confidence::Inferred,
        )),
        "seo-abuse-detector" if signals.hidden_inputs > 20 => Some((
            "seo-hidden-content-signal",
            "The document contains an unusually large hidden-input surface",
            Severity::Info,
            Confidence::Unknown,
        )),
        "third-party-script-risk-profiler" if signals.external_scripts_without_integrity > 0 => {
            Some((
                "external-script-without-integrity",
                "An external script does not declare subresource integrity",
                Severity::Low,
                Confidence::Confirmed,
            ))
        }
        _ => None,
    };
    candidate.map_or_else(Vec::new, |(key, title, severity, confidence)| {
        one(key, title, severity, confidence, evidence)
    })
}

fn cookie_diff(samples: &[WebSample]) -> Vec<Finding> {
    let mut first_scopes = BTreeMap::new();
    let varies = samples.iter().any(|sample| {
        sample.cookie_scopes.iter().any(|(name, scope)| {
            if let Some(first_scope) = first_scopes.get(name) {
                *first_scope != scope
            } else {
                first_scopes.insert(name, scope);
                false
            }
        })
    });
    if varies {
        aggregate_one(
            "cookie-scope-varies",
            "Observed cookie names vary across the bounded path sample",
            Severity::Info,
            Confidence::Confirmed,
            samples,
        )
    } else {
        Vec::new()
    }
}

fn response_is_reusable(response: &HttpResponse) -> bool {
    if response.status != 200 {
        return false;
    }
    let Some(value) = response.headers.get("cache-control") else {
        return false;
    };
    let directives = value.split(',').map(str::trim).collect::<Vec<_>>();
    if directives.iter().any(|directive| {
        directive.eq_ignore_ascii_case("no-store")
            || directive.eq_ignore_ascii_case("no-cache")
            || directive.eq_ignore_ascii_case("private")
    }) {
        return false;
    }
    directives.iter().any(|directive| {
        directive.split_once('=').is_some_and(|(name, seconds)| {
            matches!(
                name.trim().to_ascii_lowercase().as_str(),
                "max-age" | "s-maxage"
            ) && seconds
                .trim()
                .trim_matches('"')
                .parse::<u64>()
                .is_ok_and(|seconds| seconds > 0)
        })
    })
}

fn cache_diff(samples: &[WebSample]) -> Vec<Finding> {
    if samples.len() >= 2
        && samples.iter().all(|sample| sample.cache_reusable)
        && samples
            .windows(2)
            .all(|window| window[0].body_sha256 != window[1].body_sha256)
    {
        aggregate_one(
            "cache-response-varies",
            "Repeated bounded requests returned different content fingerprints",
            Severity::Info,
            Confidence::Unknown,
            samples,
        )
    } else {
        Vec::new()
    }
}

fn virtual_host_diff(samples: &[WebSample]) -> Vec<Finding> {
    let Some(baseline) = samples.first() else {
        return Vec::new();
    };
    if samples.iter().skip(1).any(|sample| {
        sample.body_sha256 != baseline.body_sha256 || sample.status != baseline.status
    }) {
        aggregate_one(
            "virtual-host-response-differs",
            "An authorized Host candidate returned a distinct response",
            Severity::Info,
            Confidence::Inferred,
            samples,
        )
    } else {
        Vec::new()
    }
}

fn rate_limit_observation(samples: &[WebSample]) -> Vec<Finding> {
    if samples.len() >= 3
        && samples.iter().all(|sample| sample.status != 429)
        && samples
            .iter()
            .all(|sample| !sample.headers.iter().any(|name| name.contains("ratelimit")))
    {
        aggregate_one(
            "rate-limit-not-observed",
            "No rate-limit response or header appeared in the small authorized sample",
            Severity::Info,
            Confidence::Unknown,
            samples,
        )
    } else {
        Vec::new()
    }
}

fn language_diff(samples: &[WebSample]) -> Vec<Finding> {
    let statuses: BTreeSet<_> = samples.iter().map(|sample| sample.status).collect();
    if statuses.len() > 1 {
        aggregate_one(
            "locale-status-varies",
            "Locale paths returned different HTTP status classes",
            Severity::Info,
            Confidence::Confirmed,
            samples,
        )
    } else {
        Vec::new()
    }
}

fn performance_findings(id: &str, samples: &[WebSample]) -> Vec<Finding> {
    let triggered = match id {
        "carbon-footprint" => samples.iter().map(|sample| sample.bytes).sum::<usize>() > 1_048_576,
        "performance-monitoring" => samples.iter().any(|sample| sample.duration_ms > 2_000),
        "quality-metrics" => samples
            .iter()
            .any(|sample| sample.status >= 400 || sample.bytes == 0 || sample.redirect_count > 5),
        _ => false,
    };
    if !triggered {
        return Vec::new();
    }
    let (key, title) = match id {
        "carbon-footprint" => (
            "large-transfer-sample",
            "The bounded page sample transferred more than one mebibyte",
        ),
        "performance-monitoring" => (
            "slow-response-observed",
            "A bounded response took longer than two seconds",
        ),
        _ => (
            "quality-signal-observed",
            "The bounded sample contains an HTTP quality degradation signal",
        ),
    };
    aggregate_one(key, title, Severity::Info, Confidence::Confirmed, samples)
}

fn baseline_diff(
    id: &str,
    samples: &[WebSample],
    options: &BTreeMap<String, Value>,
) -> Vec<Finding> {
    let Some(baseline) = options
        .get("baseline_sha256")
        .and_then(Value::as_str)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
    else {
        return Vec::new();
    };
    let changed = samples
        .first()
        .is_some_and(|sample| !sample.body_sha256.eq_ignore_ascii_case(baseline));
    if changed {
        aggregate_one(
            if id == "attack-surface-delta" {
                "attack-surface-changed"
            } else {
                "security-posture-changed"
            },
            "The current response fingerprint differs from the supplied baseline",
            Severity::Info,
            Confidence::Confirmed,
            samples,
        )
    } else {
        Vec::new()
    }
}

fn security_contact_gap(samples: &[WebSample]) -> Vec<Finding> {
    if !samples.is_empty()
        && !samples.iter().any(|sample| {
            sample.status == 200
                && is_canonical_security_txt_probe(&sample.label)
                && sample.has_security_contact
        })
    {
        aggregate_one(
            "security-contact-not-observed",
            "No successful well-known security contact response was observed",
            Severity::Info,
            Confidence::Unknown,
            samples,
        )
    } else {
        Vec::new()
    }
}

fn is_canonical_security_txt_probe(label: &str) -> bool {
    label
        .strip_prefix("path-")
        .and_then(|label| label.split_once(':'))
        .is_some_and(|(index, path)| {
            index.parse::<usize>().is_ok() && path == "/.well-known/security.txt"
        })
}

fn one(
    key: &str,
    title: &str,
    severity: Severity,
    confidence: Confidence,
    evidence: usize,
) -> Vec<Finding> {
    vec![finding(key, title, severity, confidence, evidence)]
}

fn aggregate_one(
    key: &str,
    title: &str,
    severity: Severity,
    confidence: Confidence,
    samples: &[WebSample],
) -> Vec<Finding> {
    if samples.is_empty() {
        Vec::new()
    } else {
        vec![Finding {
            key: key.into(),
            title: title.into(),
            severity,
            confidence,
            evidence: (0..samples.len().min(MAX_FINDING_EVIDENCE)).collect(),
        }]
    }
}

fn has_header(headers: &BTreeMap<String, String>, names: &[&str]) -> bool {
    names.iter().any(|name| headers.contains_key(*name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog_data::definitions;
    use crate::definition::Operation;
    use sugra_core::{HttpCookie, HttpRedirect};

    fn response(body: &str) -> HttpResponse {
        HttpResponse {
            final_url: Url::parse("https://example.test/page?token=secret#fragment")
                .unwrap_or_else(|error| unreachable!("valid fixture URL: {error}")),
            status: 200,
            headers: BTreeMap::new(),
            cookies: Vec::new(),
            redirects: Vec::new(),
            body: body.as_bytes().to_vec(),
            duration_ms: 25,
        }
    }

    fn finding_keys(id: &str, response: &HttpResponse) -> BTreeSet<String> {
        let response_signals = signals(response);
        response_findings(id, response, &response_signals, 7)
            .into_iter()
            .map(|finding| finding.key)
            .collect()
    }

    fn cookie(
        secure: bool,
        http_only: bool,
        same_site: Option<&str>,
        max_age_seconds: Option<i64>,
    ) -> HttpCookie {
        HttpCookie {
            name_sha256: "safe-cookie-fingerprint".into(),
            domain: None,
            path: Some("/".into()),
            secure,
            http_only,
            same_site: same_site.map(str::to_owned),
            max_age_seconds,
        }
    }

    #[test]
    fn every_http_scanner_has_an_explicit_analysis_group() {
        let definitions = definitions()
            .unwrap_or_else(|error| unreachable!("valid built-in definitions: {error}"));
        let http: Vec<_> = definitions
            .iter()
            .filter(|definition| matches!(definition.operation, Operation::Http))
            .collect();
        assert_eq!(http.len(), 67);
        for definition in http {
            assert!(
                analysis_group(definition.descriptor.id.as_str()).is_some(),
                "missing analysis group for {}",
                definition.descriptor.id
            );
        }
    }

    #[test]
    fn structured_observation_fingerprints_emails_and_redacts_urls() {
        let mut response = response(
            r#"<html><head><title>private-title@example.test</title></head><body>
            <a href="mailto:person@example.test">Contact</a>
            <script src="https://cdn.example.net/app.js"></script>
            </body></html>"#,
        );
        response.headers.insert(
            "x-debug-contact".into(),
            "header-person@example.test".into(),
        );
        response.cookies.push(HttpCookie {
            name_sha256: "cookie-name-hash".into(),
            domain: Some("private-cookie.example.test".into()),
            path: Some("/secret=value".into()),
            secure: true,
            http_only: true,
            same_site: Some("Lax".into()),
            max_age_seconds: None,
        });
        response.redirects.push(HttpRedirect {
            status: 302,
            from: Url::parse("https://example.test/start/path-secret?secret=value")
                .unwrap_or_else(|error| unreachable!("valid fixture URL: {error}")),
            to: Url::parse("https://example.test/reset/session-secret?session=value")
                .unwrap_or_else(|error| unreachable!("valid fixture URL: {error}")),
            decision: HttpRedirectDecision::Followed,
        });

        let signals = signals(&response);
        let serialized = observation(
            "discovered:https://example.test/page?email=label-person@example.test",
            HttpMethod::Get,
            &response,
            &signals,
        )
        .to_string();

        assert_eq!(signals.email_fingerprints.len(), 2);
        assert_eq!(signals.title_sha256.as_deref().map(str::len), Some(64));
        assert_eq!(signals.external_script_hosts, ["cdn.example.net"]);
        assert!(!serialized.contains("person@example.test"));
        assert!(!serialized.contains("private-title@example.test"));
        assert!(!serialized.contains("header-person@example.test"));
        assert!(!serialized.contains("label-person@example.test"));
        assert!(!serialized.contains("secret=value"));
        assert!(!serialized.contains("session=value"));
        assert!(!serialized.contains("path-secret"));
        assert!(!serialized.contains("session-secret"));
        assert!(!serialized.contains("private-cookie.example.test"));
        assert!(!serialized.contains("#fragment"));
        assert!(serialized.contains("cookie-name-hash"));
    }

    #[test]
    fn schema_and_security_findings_are_scanner_specific() {
        let schema = response(r#"{"openapi":"3.1.0","paths":{}}"#);
        let schema_signals = signals(&schema);
        assert_eq!(
            response_findings("api-schema-grabber", &schema, &schema_signals, 0)[0].key,
            "api-schema-published"
        );
        assert!(response_findings("crawler", &schema, &schema_signals, 0).is_empty());

        let plain = response("<html><body>safe</body></html>");
        let plain_signals = signals(&plain);
        let keys: BTreeSet<_> = response_findings("http-security", &plain, &plain_signals, 0)
            .into_iter()
            .map(|finding| finding.key)
            .collect();
        assert!(keys.contains("missing-content-security-policy"));
        assert!(keys.contains("missing-strict-transport-security"));
        assert!(keys.contains("missing-x-content-type-options"));
    }

    #[test]
    fn dom_sink_markers_require_executable_content() {
        let prose = response("<p>Documentation mentions .innerHTML and eval( safely.</p>");
        assert_eq!(signals(&prose).dom_sink_markers, 0);
        assert!(finding_keys("dom-sink-scanner", &prose).is_empty());

        let inline =
            response(r"<script>document.querySelector('#x').innerHTML = '<b>x</b>';</script>");
        assert_eq!(signals(&inline).dom_sink_markers, 1);
        assert_eq!(
            finding_keys("dom-sink-scanner", &inline),
            BTreeSet::from(["dom-sink-marker-observed".into()])
        );

        let mut javascript = response("target.insertAdjacentHTML('beforeend', value);");
        javascript.final_url = Url::parse("https://example.test/app.js")
            .unwrap_or_else(|error| unreachable!("valid fixture URL: {error}"));
        javascript
            .headers
            .insert("content-type".into(), "application/javascript".into());
        assert_eq!(signals(&javascript).dom_sink_markers, 1);
    }

    #[test]
    fn server_info_requires_a_non_empty_banner() {
        let mut empty = response("fixture");
        empty.headers.insert("server".into(), "  ".into());
        assert!(finding_keys("server-info", &empty).is_empty());

        empty.headers.insert("server".into(), "nginx".into());
        assert_eq!(
            finding_keys("server-info", &empty),
            BTreeSet::from(["server-banner-observed".into()])
        );
    }

    #[test]
    fn api_schema_grabber_requires_a_structured_openapi_document() {
        let positive =
            response(r#"{"openapi":"3.1.0","info":{"title":"private@example.test"},"paths":{}}"#);
        let findings = response_findings("api-schema-grabber", &positive, &signals(&positive), 7);
        assert_eq!(findings[0].key, "api-schema-published");
        assert_eq!(findings[0].evidence, [7]);
        assert!(
            !serde_json::to_string(&findings)
                .unwrap_or_else(|error| unreachable!("serializable findings: {error}"))
                .contains("private@example.test")
        );

        let negative = response(r#"{"note":"the swagger migration is not a schema"}"#);
        assert!(finding_keys("api-schema-grabber", &negative).is_empty());

        let edge = response(r#"{"swagger":"2.0","paths":{}}"#);
        assert_eq!(
            finding_keys("api-schema-grabber", &edge),
            BTreeSet::from(["api-schema-published".into()])
        );

        let malformed = response(r#"{"openapi":"3.1.0","paths": private@example.test"#);
        assert!(finding_keys("api-schema-grabber", &malformed).is_empty());
    }

    #[test]
    fn broken_links_accepts_only_valid_http_error_statuses() {
        let mut positive = response("private@example.test");
        positive.status = 404;
        let findings = response_findings("broken-links", &positive, &signals(&positive), 7);
        assert_eq!(findings[0].key, "broken-link");
        assert_eq!(findings[0].evidence, [7]);
        assert!(
            !serde_json::to_string(&findings)
                .unwrap_or_else(|error| unreachable!("serializable findings: {error}"))
                .contains("private@example.test")
        );

        let negative = response("reachable");
        assert!(finding_keys("broken-links", &negative).is_empty());

        let mut edge = response("redirected");
        edge.status = 399;
        assert!(finding_keys("broken-links", &edge).is_empty());

        let mut malformed = response("invalid status private@example.test");
        malformed.status = 700;
        assert!(finding_keys("broken-links", &malformed).is_empty());
    }

    #[test]
    fn cache_behavior_requires_reusable_success_responses_and_bounds_evidence() {
        let cacheable = |body: &str| {
            let mut response = response(body);
            response
                .headers
                .insert("cache-control".into(), "public, max-age=60".into());
            response
        };
        let first = sample("repeat-0".into(), &cacheable("one private@example.test"));
        let second = sample("repeat-1".into(), &cacheable("two private@example.test"));
        let findings = aggregate_findings(
            "cache-behavior-analyzer",
            &[first.clone(), second],
            &BTreeMap::new(),
        );
        assert_eq!(findings[0].key, "cache-response-varies");
        assert_eq!(findings[0].evidence, [0, 1]);
        assert!(
            !serde_json::to_string(&findings)
                .unwrap_or_else(|error| unreachable!("serializable findings: {error}"))
                .contains("private@example.test")
        );

        let same = sample("repeat-1".into(), &cacheable("one private@example.test"));
        assert!(
            aggregate_findings(
                "cache-behavior-analyzer",
                &[first.clone(), same],
                &BTreeMap::new(),
            )
            .is_empty()
        );

        let mut not_modified = cacheable("");
        not_modified.status = 304;
        assert!(
            aggregate_findings(
                "cache-behavior-analyzer",
                &[first.clone(), sample("repeat-1".into(), &not_modified)],
                &BTreeMap::new(),
            )
            .is_empty()
        );

        let malformed = |body: &str| {
            let mut response = response(body);
            response.headers.insert(
                "cache-control".into(),
                "public, max-age=private@example.test".into(),
            );
            sample("malformed".into(), &response)
        };
        assert!(
            aggregate_findings(
                "cache-behavior-analyzer",
                &[malformed("one"), malformed("two")],
                &BTreeMap::new(),
            )
            .is_empty()
        );

        let many = (0..256)
            .map(|index| sample(format!("repeat-{index}"), &cacheable(&index.to_string())))
            .collect::<Vec<_>>();
        let bounded = aggregate_findings("cache-behavior-analyzer", &many, &BTreeMap::new());
        assert_eq!(bounded[0].evidence.len(), MAX_FINDING_EVIDENCE);
    }

    #[test]
    fn captcha_detection_requires_structural_integration_markers() {
        let positive = response(
            r#"<script src="https://www.google.com/recaptcha/api.js?account=private@example.test"></script>"#,
        );
        let findings = response_findings(
            "captcha-presence-checker",
            &positive,
            &signals(&positive),
            7,
        );
        assert_eq!(findings[0].key, "captcha-control-observed");
        assert!(
            !serde_json::to_string(&findings)
                .unwrap_or_else(|error| unreachable!("serializable findings: {error}"))
                .contains("private@example.test")
        );

        let negative = response("<p>This site does not use recaptcha.</p>");
        assert!(finding_keys("captcha-presence-checker", &negative).is_empty());

        let edge =
            response(r#"<div class="cf-turnstile" data-sitekey="private@example.test"></div>"#);
        assert_eq!(
            finding_keys("captcha-presence-checker", &edge),
            BTreeSet::from(["captcha-control-observed".into()])
        );

        let malformed = response(r#"<div class="g-recaptcha-ish">private@example.test"#);
        assert!(finding_keys("captcha-presence-checker", &malformed).is_empty());
    }

    #[test]
    fn cms_detection_requires_recognized_structural_markers() {
        let positive = response(
            r#"<link rel="stylesheet" href="/wp-content/themes/private@example.test.css">"#,
        );
        let findings = response_findings("cms-detection", &positive, &signals(&positive), 7);
        assert_eq!(findings[0].key, "cms-signal-observed");
        assert!(
            !serde_json::to_string(&findings)
                .unwrap_or_else(|error| unreachable!("serializable findings: {error}"))
                .contains("private@example.test")
        );

        let negative = response(r#"<meta name="generator" content="Private Site Builder">"#);
        assert!(finding_keys("cms-detection", &negative).is_empty());

        let edge = response(r#"<meta name="generator" content="Joomla! 5">"#);
        assert_eq!(
            finding_keys("cms-detection", &edge),
            BTreeSet::from(["cms-signal-observed".into()])
        );

        let malformed = response("wp-content belongs to private@example.test");
        assert!(finding_keys("cms-detection", &malformed).is_empty());
    }

    #[test]
    fn crawl_rules_requires_a_valid_robots_policy_document() {
        let robots = |body: &str| {
            let mut response = response(body);
            response.final_url = Url::parse("https://example.test/robots.txt")
                .unwrap_or_else(|error| unreachable!("valid fixture URL: {error}"));
            response
        };
        let positive = robots("User-agent: *\nDisallow: /private@example.test\n");
        let findings = response_findings("crawl-rules", &positive, &signals(&positive), 7);
        assert_eq!(findings[0].key, "crawl-rules-observed");
        assert!(
            !serde_json::to_string(&findings)
                .unwrap_or_else(|error| unreachable!("serializable findings: {error}"))
                .contains("private@example.test")
        );

        let mut negative = robots("User-agent: *\nDisallow: /private\n");
        negative.status = 404;
        assert!(finding_keys("crawl-rules", &negative).is_empty());

        let edge = robots(
            "# bounded fixture\r\nUser-agent: ExampleBot\r\nAllow: /\r\nSitemap: https://example.test/map.xml\r\n",
        );
        assert_eq!(
            finding_keys("crawl-rules", &edge),
            BTreeSet::from(["crawl-rules-observed".into()])
        );

        let malformed = robots("<html><p>User-agent: private@example.test</p></html>");
        assert!(finding_keys("crawl-rules", &malformed).is_empty());
    }

    #[test]
    fn crawler_reports_only_links_from_successful_html_documents() {
        let positive =
            response(r#"<html><a href="/account?email=private@example.test">Account</a></html>"#);
        let findings = response_findings("crawler", &positive, &signals(&positive), 7);
        assert_eq!(findings[0].key, "crawlable-links-observed");
        assert_eq!(findings[0].evidence, [7]);
        assert!(
            !serde_json::to_string(&findings)
                .unwrap_or_else(|error| unreachable!("serializable findings: {error}"))
                .contains("private@example.test")
        );

        let negative = response("<html><p>No links</p></html>");
        assert!(finding_keys("crawler", &negative).is_empty());

        let mut edge = positive.clone();
        edge.status = 304;
        assert!(finding_keys("crawler", &edge).is_empty());

        let mut malformed = positive;
        malformed.status = 700;
        assert!(finding_keys("crawler", &malformed).is_empty());
    }

    #[test]
    fn csp_deep_analyzer_parses_policy_tokens_without_echoing_values() {
        let html = |policy_name: &str, policy: &str| {
            let mut response = response("<html><body>fixture</body></html>");
            response
                .headers
                .insert("content-type".into(), "text/html".into());
            response.headers.insert(policy_name.into(), policy.into());
            response
        };
        let positive = html(
            "content-security-policy",
            "default-src * 'unsafe-inline'; script-src 'unsafe-eval' https://private@example.test",
        );
        let findings = response_findings("csp-deep-analyzer", &positive, &signals(&positive), 7);
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.key.as_str())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "csp-unsafe-eval",
                "csp-unsafe-inline",
                "csp-wildcard-source",
            ])
        );
        assert!(findings.iter().all(|finding| finding.evidence == [7]));
        assert!(
            !serde_json::to_string(&findings)
                .unwrap_or_else(|error| unreachable!("serializable findings: {error}"))
                .contains("private@example.test")
        );

        let negative = html(
            "content-security-policy",
            "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        );
        assert!(finding_keys("csp-deep-analyzer", &negative).is_empty());

        let edge = html("content-security-policy-report-only", "default-src 'none'");
        assert_eq!(
            finding_keys("csp-deep-analyzer", &edge),
            BTreeSet::from(["csp-not-enforced".into()])
        );

        let malformed = html(
            "content-security-policy",
            "report-uri https://private@example.test/collector",
        );
        assert_eq!(
            finding_keys("csp-deep-analyzer", &malformed),
            BTreeSet::from(["csp-no-effective-directive".into()])
        );
    }

    #[test]
    fn http_headers_only_reports_missing_controls_for_html_media_types() {
        let mut html = response("not needed for an explicit media type");
        html.headers
            .insert("content-type".into(), "text/html; charset=utf-8".into());
        assert_eq!(
            finding_keys("http-headers", &html),
            BTreeSet::from([
                "missing-content-security-policy".into(),
                "missing-strict-transport-security".into(),
                "missing-x-content-type-options".into(),
            ])
        );

        html.headers.insert(
            "content-security-policy".into(),
            "default-src 'self'".into(),
        );
        html.headers.insert(
            "strict-transport-security".into(),
            "max-age=31536000".into(),
        );
        html.headers
            .insert("x-content-type-options".into(), "nosniff".into());
        assert!(finding_keys("http-headers", &html).is_empty());

        let mut malformed = response("plain text");
        malformed
            .headers
            .insert("content-type".into(), "application/not-text/htmlish".into());
        assert!(finding_keys("http-headers", &malformed).is_empty());

        let mut failure = response("<html>upstream diagnostic: secret-token</html>");
        failure.status = 500;
        assert!(finding_keys("http-headers", &failure).is_empty());
    }

    #[test]
    fn http_security_requires_effective_header_values() {
        let mut secure = response("<html><body>ok</body></html>");
        secure.headers.insert(
            "content-security-policy".into(),
            "default-src 'self'; object-src 'none'".into(),
        );
        secure.headers.insert(
            "strict-transport-security".into(),
            "max-age=31536000; includeSubDomains".into(),
        );
        secure
            .headers
            .insert("x-content-type-options".into(), "nosniff".into());
        assert!(finding_keys("http-security", &secure).is_empty());

        let mut malformed = secure.clone();
        malformed.headers.insert(
            "content-security-policy".into(),
            "report-uri https://collector.invalid/?token=csp-secret".into(),
        );
        malformed
            .headers
            .insert("strict-transport-security".into(), "max-age=0".into());
        malformed
            .headers
            .insert("x-content-type-options".into(), "nosniff-ish".into());
        assert_eq!(
            finding_keys("http-security", &malformed),
            BTreeSet::from([
                "missing-content-security-policy".into(),
                "missing-strict-transport-security".into(),
                "missing-x-content-type-options".into(),
            ])
        );
        let findings = response_findings("http-security", &malformed, &signals(&malformed), 7);
        assert!(
            !serde_json::to_string(&findings)
                .unwrap_or_else(|error| unreachable!("serializable findings: {error}"))
                .contains("csp-secret")
        );

        let mut http = malformed;
        http.final_url = Url::parse("http://example.test/")
            .unwrap_or_else(|error| unreachable!("valid fixture URL: {error}"));
        assert_eq!(
            finding_keys("http-security", &http),
            BTreeSet::from([
                "missing-content-security-policy".into(),
                "missing-x-content-type-options".into(),
            ])
        );
    }

    #[test]
    fn clickjacking_requires_a_valid_framing_restriction_directive() {
        let vulnerable = response("<html><body>frameable</body></html>");
        assert_eq!(
            finding_keys("clickjacking-test", &vulnerable),
            BTreeSet::from(["framing-not-restricted".into()])
        );

        let mut xfo = vulnerable.clone();
        xfo.headers
            .insert("x-frame-options".into(), " SAMEORIGIN ".into());
        assert!(finding_keys("clickjacking-test", &xfo).is_empty());

        let mut csp = vulnerable.clone();
        csp.headers.insert(
            "content-security-policy".into(),
            "default-src 'self'; frame-ancestors 'none'".into(),
        );
        assert!(finding_keys("clickjacking-test", &csp).is_empty());

        let mut nearby_substring = vulnerable.clone();
        nearby_substring.headers.insert(
            "content-security-policy".into(),
            "default-src 'self'; report-uri /frame-ancestors-report".into(),
        );
        assert_eq!(
            finding_keys("clickjacking-test", &nearby_substring),
            BTreeSet::from(["framing-not-restricted".into()])
        );

        let mut malformed = vulnerable;
        malformed.headers.insert(
            "x-frame-options".into(),
            "ALLOW-FROM https://example.test".into(),
        );
        malformed
            .headers
            .insert("content-security-policy".into(), "frame-ancestors *".into());
        assert_eq!(
            finding_keys("clickjacking-test", &malformed),
            BTreeSet::from(["framing-not-restricted".into()])
        );
    }

    #[test]
    fn cors_only_accepts_wildcard_or_the_exact_untrusted_probe_origin() {
        let mut reflected = response("public response");
        reflected.headers.insert(
            "access-control-allow-origin".into(),
            "  HTTPS://SCOPE-CHECK.INVALID:443  ".into(),
        );
        assert_eq!(
            finding_keys("cors-misconfiguration-scanner", &reflected),
            BTreeSet::from(["permissive-cors".into()])
        );

        reflected.headers.insert(
            "access-control-allow-origin".into(),
            "https://scope-check.invalid.example".into(),
        );
        assert!(finding_keys("cors-misconfiguration-scanner", &reflected).is_empty());

        reflected.headers.insert(
            "access-control-allow-origin".into(),
            "https://scope-check.invalid, https://example.test".into(),
        );
        assert!(finding_keys("cors-misconfiguration-scanner", &reflected).is_empty());

        reflected
            .headers
            .insert("access-control-allow-origin".into(), " * ".into());
        let findings = response_findings(
            "cors-misconfiguration-scanner",
            &reflected,
            &signals(&reflected),
            7,
        );
        assert_eq!(findings[0].key, "permissive-cors");
        assert_eq!(findings[0].evidence, [7]);
        assert!(
            !serde_json::to_string(&findings)
                .unwrap_or_else(|error| unreachable!("serializable findings: {error}"))
                .contains("scope-check.invalid")
        );
    }

    #[test]
    fn security_txt_recognizes_only_a_valid_contact_field() {
        let published = response(
            "# security policy\r\nContact: mailto:private-security@example.test\r\nExpires: 2030-01-01T00:00:00Z\r\n",
        );
        let findings = response_findings("security-txt", &published, &signals(&published), 7);
        assert_eq!(findings[0].key, "security-contact-observed");
        assert_eq!(findings[0].evidence, [7]);
        assert!(
            !serde_json::to_string(&findings)
                .unwrap_or_else(|error| unreachable!("serializable findings: {error}"))
                .contains("private-security@example.test")
        );

        for body in [
            "# Contact: mailto:security@example.test",
            "X-Contact: mailto:security@example.test",
            "Contact:",
            "Contact: not an absolute URI",
        ] {
            let nearby = response(body);
            assert!(
                finding_keys("security-txt", &nearby).is_empty(),
                "nearby or malformed field was accepted: {body}"
            );
        }

        let mut invalid_utf8 = response("");
        invalid_utf8.body = vec![b'C', b'o', b'n', b't', b'a', b'c', b't', b':', b' ', 0xff];
        assert!(finding_keys("security-txt", &invalid_utf8).is_empty());
    }

    #[test]
    fn security_contact_gap_requires_a_valid_contact_at_the_canonical_path() {
        let valid_body = "Contact: https://example.test/security-report\n";
        let canonical = sample(
            "path-0:/.well-known/security.txt".into(),
            &response(valid_body),
        );
        assert!(
            aggregate_findings(
                "security-contact-gap-finder",
                std::slice::from_ref(&canonical),
                &BTreeMap::new(),
            )
            .is_empty()
        );

        let nearby_label = sample(
            "path-0:/.well-known/security.txt.backup".into(),
            &response(valid_body),
        );
        assert_eq!(
            aggregate_findings(
                "security-contact-gap-finder",
                &[nearby_label],
                &BTreeMap::new(),
            )[0]
            .key,
            "security-contact-not-observed"
        );

        let malformed = sample(
            "path-0:/.well-known/security.txt".into(),
            &response("# Contact: mailto:hidden@example.test"),
        );
        let findings = aggregate_findings(
            "security-contact-gap-finder",
            &[malformed],
            &BTreeMap::new(),
        );
        assert_eq!(findings[0].key, "security-contact-not-observed");
        assert!(
            !serde_json::to_string(&findings)
                .unwrap_or_else(|error| unreachable!("serializable findings: {error}"))
                .contains("hidden@example.test")
        );

        assert!(
            aggregate_findings("security-contact-gap-finder", &[], &BTreeMap::new(),).is_empty()
        );
    }

    #[test]
    fn cookies_reports_each_missing_security_attribute_once_per_response() {
        let mut insecure = response("ok");
        insecure.cookies.push(cookie(false, false, None, None));
        assert_eq!(
            finding_keys("cookies", &insecure),
            BTreeSet::from([
                "cookie-httponly-missing".into(),
                "cookie-samesite-missing".into(),
                "cookie-secure-missing".into(),
            ])
        );

        let mut hardened = response("ok");
        hardened
            .cookies
            .push(cookie(true, true, Some("Strict"), None));
        assert!(finding_keys("cookies", &hardened).is_empty());

        let mut malformed = response("ok");
        malformed
            .cookies
            .push(cookie(true, true, Some("strict-ish"), None));
        assert_eq!(
            finding_keys("cookies", &malformed),
            BTreeSet::from(["cookie-samesite-missing".into()])
        );

        insecure.cookies.push(cookie(false, false, None, None));
        insecure.cookies[0].name_sha256 = "must-not-leak-cookie-name".into();
        let findings = response_findings("cookies", &insecure, &signals(&insecure), 7);
        assert_eq!(findings.len(), 3);
        assert!(findings.iter().all(|finding| finding.evidence == [7]));
        assert!(
            !serde_json::to_string(&findings)
                .unwrap_or_else(|error| unreachable!("serializable findings: {error}"))
                .contains("must-not-leak-cookie-name")
        );
    }

    #[test]
    fn session_cookie_lifetime_uses_an_exclusive_thirty_day_boundary() {
        const THIRTY_DAYS: i64 = 30 * 24 * 60 * 60;

        let mut long_lived = response("ok");
        long_lived
            .cookies
            .push(cookie(true, true, Some("Lax"), Some(THIRTY_DAYS + 1)));
        long_lived.cookies[0].name_sha256 = "must-not-leak-session-name".into();
        let findings = response_findings(
            "session-cookie-lifetime-checker",
            &long_lived,
            &signals(&long_lived),
            7,
        );
        assert_eq!(findings[0].key, "long-lived-cookie");
        assert_eq!(findings[0].evidence, [7]);
        assert!(
            !serde_json::to_string(&findings)
                .unwrap_or_else(|error| unreachable!("serializable findings: {error}"))
                .contains("must-not-leak-session-name")
        );

        let mut boundary = response("ok");
        boundary
            .cookies
            .push(cookie(true, true, Some("Lax"), Some(THIRTY_DAYS)));
        boundary
            .cookies
            .push(cookie(true, true, Some("Lax"), Some(0)));
        boundary.cookies.push(cookie(true, true, Some("Lax"), None));
        assert!(finding_keys("session-cookie-lifetime-checker", &boundary).is_empty());
    }

    #[test]
    fn comparisons_require_meaningful_differences() {
        let cacheable = |body: &str| {
            let mut response = response(body);
            response
                .headers
                .insert("cache-control".into(), "max-age=60".into());
            response
        };
        let first = sample("first".into(), &cacheable("one"));
        let same = sample("same".into(), &cacheable("one"));
        let different = sample("different".into(), &cacheable("two"));

        assert!(
            aggregate_findings(
                "cache-behavior-analyzer",
                &[first.clone(), same],
                &BTreeMap::new()
            )
            .is_empty()
        );
        assert_eq!(
            aggregate_findings(
                "cache-behavior-analyzer",
                &[first.clone(), different.clone()],
                &BTreeMap::new(),
            )[0]
            .key,
            "cache-response-varies"
        );

        let mut options = BTreeMap::new();
        options.insert(
            "baseline_sha256".into(),
            Value::String(first.body_sha256.to_ascii_uppercase()),
        );
        assert!(
            aggregate_findings(
                "attack-surface-delta",
                std::slice::from_ref(&first),
                &options
            )
            .is_empty()
        );
        assert_eq!(
            aggregate_findings(
                "attack-surface-delta",
                std::slice::from_ref(&different),
                &options,
            )[0]
            .key,
            "attack-surface-changed"
        );
        options.insert("baseline_sha256".into(), Value::String("invalid".into()));
        assert!(aggregate_findings("attack-surface-delta", &[different], &options).is_empty());
    }

    #[test]
    fn graphql_introspection_requires_structured_schema_metadata() {
        let positive = response(r#"{"data":{"__schema":{"queryType":{"name":"Query"}}}}"#);
        assert_eq!(
            finding_keys("graphql-introspection-probe", &positive),
            BTreeSet::from(["graphql-introspection-enabled".into()])
        );

        let prose = response(r#"{"message":"Documentation mentions __schema and queryType"}"#);
        assert!(finding_keys("graphql-introspection-probe", &prose).is_empty());

        let incomplete = response(r#"{"data":{"__schema":null},"queryType":"Query"}"#);
        assert!(finding_keys("graphql-introspection-probe", &incomplete).is_empty());
    }

    #[test]
    fn method_enumerator_tokenizes_the_allow_header() {
        let mut positive = response("");
        positive.headers.insert("allow".into(), "GET, put".into());
        assert_eq!(
            finding_keys("http-method-enumerator", &positive),
            BTreeSet::from(["state-changing-http-method-advertised".into()])
        );

        let mut deceptive = response("");
        deceptive
            .headers
            .insert("allow".into(), "GET, INPUT, HEAD".into());
        assert!(finding_keys("http-method-enumerator", &deceptive).is_empty());

        for method in ["POST", "PATCH"] {
            let mut response = response("");
            response
                .headers
                .insert("allow".into(), format!("GET, HEAD, {method}"));
            assert_eq!(
                finding_keys("http-method-enumerator", &response),
                BTreeSet::from(["state-changing-http-method-advertised".into()])
            );
        }
    }

    #[test]
    fn technology_stack_requires_non_empty_server_metadata() {
        let mut empty = response("<html><body>fixture</body></html>");
        empty.headers.insert("server".into(), "  ".into());
        assert!(finding_keys("technology-stack", &empty).is_empty());

        empty.headers.insert("server".into(), "nginx".into());
        assert_eq!(
            finding_keys("technology-stack", &empty),
            BTreeSet::from(["technology-signal-observed".into()])
        );
    }

    #[test]
    fn obfuscation_markers_require_executable_content() {
        let prose = response("<p>Documentation mentions eval( and atob( safely.</p>");
        assert_eq!(signals(&prose).obfuscation_markers, 0);
        assert!(finding_keys("javascript-obfuscation-detector", &prose).is_empty());

        let script = response("<script>eval(atob(encoded));</script>");
        assert_eq!(signals(&script).obfuscation_markers, 2);
        assert_eq!(
            finding_keys("javascript-obfuscation-detector", &script),
            BTreeSet::from(["javascript-obfuscation-markers".into()])
        );

        for script_type in ["application/json", "application/ld+json"] {
            let data = response(&format!(
                r#"<script type="{script_type}">{{"example":"eval(atob(value))"}}</script>"#
            ));
            assert_eq!(signals(&data).obfuscation_markers, 0);
            assert!(finding_keys("javascript-obfuscation-detector", &data).is_empty());
        }
    }

    #[test]
    fn websocket_references_require_structured_or_executable_context() {
        let prose =
            response("<p>The WebSocket() constructor and wss:// scheme are documented.</p>");
        assert_eq!(signals(&prose).websocket_references, 0);
        assert!(finding_keys("websocket-endpoint-sniffer", &prose).is_empty());

        let link = response(r#"<a href="wss://socket.example.test/events">Events</a>"#);
        assert_eq!(signals(&link).websocket_references, 1);
        assert_eq!(
            finding_keys("websocket-endpoint-sniffer", &link),
            BTreeSet::from(["websocket-reference-observed".into()])
        );

        let script = response(r#"<script>new WebSocket("wss://socket.example.test")</script>"#);
        assert!(signals(&script).websocket_references > 0);

        let structured_data = response(
            r#"<script type="application/json">{"endpoint":"wss://socket.example.test"}</script>"#,
        );
        assert_eq!(signals(&structured_data).websocket_references, 0);
    }

    #[test]
    fn html_comments_require_a_complete_html_comment() {
        let mut html = response("<html><!-- bounded comment --><body>ok</body></html>");
        html.headers
            .insert("content-type".into(), "text/html".into());
        assert_eq!(signals(&html).comments, 1);
        assert_eq!(
            finding_keys("html-comments-extractor", &html),
            BTreeSet::from(["html-comments-observed".into()])
        );

        let mut json = response(r#"{"documentation":"<!-- not an HTML comment -->"}"#);
        json.headers
            .insert("content-type".into(), "application/json".into());
        assert_eq!(signals(&json).comments, 0);

        let mut incomplete = response("<html><!-- incomplete<body>ok</body></html>");
        incomplete
            .headers
            .insert("content-type".into(), "text/html".into());
        assert_eq!(signals(&incomplete).comments, 0);

        let mut script =
            response(r#"<html><script>const open = "<!--"; const close = "-->";</script></html>"#);
        script
            .headers
            .insert("content-type".into(), "text/html".into());
        assert_eq!(signals(&script).comments, 0);
    }

    #[test]
    fn sitemap_requires_a_document_root() {
        let mut urlset = response(r#"<?xml version="1.0"?><urlset></urlset>"#);
        urlset.final_url = Url::parse("https://example.test/sitemap.xml")
            .unwrap_or_else(|error| unreachable!("valid fixture URL: {error}"));
        assert_eq!(
            finding_keys("sitemap", &urlset),
            BTreeSet::from(["sitemap-observed".into()])
        );

        let index = response("<sitemapindex></sitemapindex>");
        assert_eq!(
            finding_keys("sitemap", &index),
            BTreeSet::from(["sitemap-observed".into()])
        );

        let prose = response("<html><p>Example: &lt;urlset&gt;</p></html>");
        assert!(finding_keys("sitemap", &prose).is_empty());

        for malformed in [
            "<urlsetevil></urlsetevil>",
            "<sitemapindexer></sitemapindexer>",
        ] {
            assert!(finding_keys("sitemap", &response(malformed)).is_empty());
        }
    }

    #[test]
    fn exposure_detectors_require_structured_boundary_evidence() {
        let mut env = response("SECRET_TOKEN=one-secret");
        env.final_url = Url::parse("https://example.test/.env")
            .unwrap_or_else(|error| unreachable!("valid fixture URL: {error}"));
        env.headers
            .insert("content-type".into(), "text/plain".into());
        assert_eq!(
            finding_keys("exposed-env-files", &env),
            BTreeSet::from(["environment-file-exposed".into()])
        );

        env.body = b"Documentation example:\nSECRET_TOKEN=placeholder".to_vec();
        assert!(finding_keys("exposed-env-files", &env).is_empty());
        env.body = b"<html><body>SECRET_TOKEN=placeholder</body></html>".to_vec();
        env.headers
            .insert("content-type".into(), "text/html".into());
        assert!(finding_keys("exposed-env-files", &env).is_empty());

        let mut git = response("ref: refs/heads/main\n");
        git.final_url = Url::parse("https://example.test/.git/HEAD")
            .unwrap_or_else(|error| unreachable!("valid fixture URL: {error}"));
        git.status = 206;
        git.headers
            .insert("content-type".into(), "text/plain".into());
        assert_eq!(
            finding_keys("git-repo-exposure-check", &git),
            BTreeSet::from(["git-metadata-exposed".into()])
        );

        git.body = b"ref: refs/tags/v1.0.0\n".to_vec();
        assert_eq!(
            finding_keys("git-repo-exposure-check", &git),
            BTreeSet::from(["git-metadata-exposed".into()])
        );

        git.body = b"Documentation mentions ref: refs/heads/main".to_vec();
        assert!(finding_keys("git-repo-exposure-check", &git).is_empty());
        git.body = b"ref: refs/tags/../private".to_vec();
        assert!(finding_keys("git-repo-exposure-check", &git).is_empty());
    }

    #[test]
    fn open_redirect_accepts_exact_external_location_without_leaking_it() {
        let mut redirect = response("");
        redirect.final_url =
            Url::parse("https://example.test/?next=https%3A%2F%2Fscope-check.invalid%2F")
                .unwrap_or_else(|error| unreachable!("valid fixture URL: {error}"));
        redirect.status = 302;
        redirect.headers.insert(
            "location".into(),
            "https://scope-check.invalid/reset/private-token?secret=value#fragment".into(),
        );
        assert_eq!(
            finding_keys("open-redirect-finder", &redirect),
            BTreeSet::from(["external-open-redirect".into()])
        );
        let serialized = observation(
            "redirect-probe",
            HttpMethod::Get,
            &redirect,
            &signals(&redirect),
        )
        .to_string();
        assert!(!serialized.contains("private-token"));
        assert!(!serialized.contains("secret=value"));

        redirect.final_url = Url::parse("https://example.test/")
            .unwrap_or_else(|error| unreachable!("valid fixture URL: {error}"));
        assert!(finding_keys("open-redirect-finder", &redirect).is_empty());
    }

    #[test]
    fn third_party_integrations_include_structured_origins_but_not_anchors() {
        let integrations = response(
            r#"<link rel="preconnect" href="https://api.example.net"><a href="https://ordinary.example.org">link</a>"#,
        );
        let signals = signals(&integrations);
        assert_eq!(signals.external_integration_hosts, ["api.example.net"]);
        assert_eq!(
            finding_keys("third-party-integrations", &integrations),
            BTreeSet::from(["third-party-integration-observed".into()])
        );
    }

    #[test]
    fn favicon_fingerprint_requires_icon_content() {
        let mut icon = response("");
        icon.final_url = Url::parse("https://example.test/favicon.ico")
            .unwrap_or_else(|error| unreachable!("valid fixture URL: {error}"));
        icon.headers
            .insert("content-type".into(), "image/x-icon".into());
        icon.body = vec![
            0, 0, 1, 0, 1, 0, // header: one icon
            16, 16, 0, 0, 1, 0, 32, 0, 4, 0, 0, 0, 22, 0, 0, 0, // directory
            1, 2, 3, 4, // bounded image payload
        ];
        assert_eq!(
            finding_keys("favicon-hashing", &icon),
            BTreeSet::from(["favicon-fingerprint-observed".into()])
        );

        icon.headers
            .insert("content-type".into(), "text/html".into());
        icon.body = b"<html><body>branded fallback</body></html>".to_vec();
        assert!(finding_keys("favicon-hashing", &icon).is_empty());
    }

    #[test]
    fn performance_findings_use_bounded_response_metadata() {
        let mut slow = response("payload");
        slow.duration_ms = 2_001;
        let slow = sample("slow".into(), &slow);
        assert_eq!(
            aggregate_findings("performance-monitoring", &[slow], &BTreeMap::new())[0].key,
            "slow-response-observed"
        );

        let empty = sample("empty".into(), &response(""));
        assert_eq!(
            aggregate_findings("quality-metrics", &[empty], &BTreeMap::new())[0].key,
            "quality-signal-observed"
        );
    }
}
