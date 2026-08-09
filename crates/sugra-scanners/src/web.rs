//! Explicit, bounded HTTP probe plans for every web scanner.

use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest, Sha256};
use sugra_core::HttpMethod;
use sugra_domain::{Budget, ScopeGrant, Target, TargetKind};
use url::Url;

const SAMPLE_SCALE: u32 = 1_000_000;

/// One same-origin HTTP operation owned by a web scanner.
#[derive(Debug, Clone)]
pub(crate) struct WebProbe {
    pub(crate) label: String,
    pub(crate) url: Url,
    pub(crate) method: HttpMethod,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) body: Vec<u8>,
    pub(crate) max_redirects: usize,
}

impl WebProbe {
    fn get(label: impl Into<String>, url: Url) -> Self {
        Self {
            label: label.into(),
            url,
            method: HttpMethod::Get,
            headers: BTreeMap::new(),
            body: Vec::new(),
            max_redirects: 3,
        }
    }

    /// Stable identity used to deduplicate discovered resources without
    /// collapsing intentional repeated probes.
    pub(crate) fn identity(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(self.label.as_bytes());
        digest.update(self.url.as_str().as_bytes());
        digest.update(format!("{:?}", self.method).as_bytes());
        for (name, value) in &self.headers {
            digest.update(name.as_bytes());
            digest.update(value.as_bytes());
        }
        digest.update(&self.body);
        hex::encode(digest.finalize())
    }
}

/// Complete bounded probe plan for one web scanner.
#[derive(Debug, Clone)]
pub(crate) struct WebPlan {
    pub(crate) probes: Vec<WebProbe>,
    pub(crate) crawl: bool,
    pub(crate) max_pages: usize,
    pub(crate) max_depth: usize,
    pub(crate) sample_per_million: u32,
    pub(crate) delay_ms: u64,
    pub(crate) include_subdomains: bool,
}

/// Returns an explicit plan for every scanner assigned to the HTTP boundary.
pub(crate) fn plan_for(
    id: &str,
    base: &Url,
    options: &BTreeMap<String, Value>,
    budget: Budget,
    scope: &ScopeGrant,
) -> Option<WebPlan> {
    let budget_limit = budget.max_requests;
    let max_pages = integer_option(options, "max_pages", budget_limit)
        .max(1)
        .min(budget_limit);
    let include_subdomains = boolean_option(options, "include_subdomains")
        .or_else(|| boolean_option(options, "include_subs"))
        .unwrap_or(false);
    let mut plan = resource_plan(id, base, options, max_pages)
        .or_else(|| active_plan(id, base, options, max_pages))
        .or_else(|| root_plan(id, base, max_pages))?;

    if id == "crawler"
        && let Some(start) = crawl_start_url(base, options, include_subdomains, scope)
    {
        plan.probes = vec![WebProbe::get("crawl-start", start)];
    }
    if (id == "cookies" && !boolean_option(options, "follow").unwrap_or(false))
        || (id == "login-page-brute-identifier"
            && !boolean_option(options, "follow_redirects").unwrap_or(true))
    {
        for probe in &mut plan.probes {
            probe.max_redirects = 0;
        }
    }

    plan.probes.truncate(budget_limit);
    plan.max_depth = integer_option(options, "depth", budget.max_depth).min(budget.max_depth);
    plan.sample_per_million = sample_ratio(options);
    plan.delay_ms = request_delay_ms(options, budget);
    plan.include_subdomains = include_subdomains;

    if id == "virtual-host-fuzzer" {
        plan.probes = virtual_host_plan(base, options, max_pages, scope).probes;
        plan.probes.truncate(budget_limit);
    }
    Some(plan)
}

fn resource_plan(
    id: &str,
    base: &Url,
    options: &BTreeMap<String, Value>,
    max_pages: usize,
) -> Option<WebPlan> {
    let plan = match id {
        "api-schema-grabber" => schema_plan(base, options, max_pages),
        "broken-links" | "content-discovery" | "crawler" => {
            paths_plan(base, vec!["/".into()], true, max_pages)
        }
        "cookies" | "session-hijacking-passive" => paths_plan(
            base,
            option_paths(options, "paths", &["/", "/login", "/account"]),
            false,
            max_pages,
        ),
        "cookie-scope-diff" => paths_plan(
            base,
            option_paths(options, "paths", &["/", "/login", "/account"]),
            true,
            max_pages,
        ),
        "crawl-rules" => paths_plan(base, vec!["/robots.txt".into()], false, max_pages),
        "sitemap" => paths_plan(
            base,
            vec!["/sitemap.xml".into(), "/sitemap_index.xml".into()],
            false,
            max_pages,
        ),
        "security-txt" | "security-contact-gap-finder" | "bug-bounty-program-finder" => paths_plan(
            base,
            vec![
                "/.well-known/security.txt".into(),
                "/security.txt".into(),
                "/".into(),
            ],
            false,
            max_pages,
        ),
        "seo-abuse-detector" => seo_plan(base, max_pages),
        _ => return exposure_plan(id, base, options, max_pages),
    };
    Some(plan)
}

fn exposure_plan(
    id: &str,
    base: &Url,
    options: &BTreeMap<String, Value>,
    max_pages: usize,
) -> Option<WebPlan> {
    let plan = match id {
        "exposed-env-files" => paths_plan(
            base,
            vec![
                "/.env".into(),
                "/.env.production".into(),
                "/.env.local".into(),
            ],
            false,
            max_pages,
        ),
        "git-repo-exposure-check" => paths_plan(
            base,
            vec!["/.git/HEAD".into(), "/.git/config".into()],
            false,
            max_pages,
        ),
        "exposed-api-endpoints" => paths_plan(
            base,
            vec![
                "/api".into(),
                "/api/v1".into(),
                "/swagger".into(),
                "/openapi.json".into(),
            ],
            false,
            max_pages,
        ),
        "directory-finder" => directory_plan(base, options, max_pages),
        "file-upload-surface-finder" => paths_plan(
            base,
            vec!["/".into(), "/upload".into(), "/uploads".into()],
            true,
            max_pages,
        ),
        "login-page-brute-identifier" => paths_plan(
            base,
            option_paths(options, "paths", &["/login", "/signin", "/admin"]),
            false,
            max_pages,
        ),
        "cloud-bucket-exposure" | "cloud-service-enumeration" => paths_plan(
            base,
            vec![
                "/".into(),
                "/.well-known/assetlinks.json".into(),
                "/.well-known/apple-app-site-association".into(),
            ],
            false,
            max_pages,
        ),
        "favicon-hashing" => paths_plan(base, vec!["/favicon.ico".into()], false, max_pages),
        "multi-language-url-tester" => paths_plan(
            base,
            vec![
                "/".into(),
                "/en/".into(),
                "/es/".into(),
                "/fr/".into(),
                "/pt/".into(),
            ],
            false,
            max_pages,
        ),
        _ => return None,
    };
    Some(plan)
}

fn active_plan(
    id: &str,
    base: &Url,
    options: &BTreeMap<String, Value>,
    max_pages: usize,
) -> Option<WebPlan> {
    let plan = match id {
        "graphql-introspection-probe" => graphql_plan(base, max_pages),
        "http-method-enumerator" => method_plan(base, max_pages),
        "cors-misconfiguration-scanner" => cors_plan(base, max_pages),
        "open-redirect-finder" => open_redirect_plan(base, max_pages),
        "virtual-host-fuzzer" => paths_plan(base, vec!["/".into()], false, max_pages),
        "rate-limit-waf-bypass-test" => repeated_plan(
            base,
            integer_option(options, "batch_size", 4).clamp(1, 8),
            max_pages,
        ),
        "cache-behavior-analyzer" => repeated_plan(base, 2, max_pages),
        "performance-monitoring" => repeated_plan(base, 3, max_pages),
        "redirect-chain" => redirect_plan(base, max_pages),
        "hidden-parameter-discovery" => parameter_plan(base, options, max_pages),
        _ => return None,
    };
    Some(plan)
}

fn root_plan(id: &str, base: &Url, max_pages: usize) -> Option<WebPlan> {
    let owns_root_probe = matches!(
        id,
        "cdn-detection"
            | "server-info"
            | "autocomplete-vulnerability-checker"
            | "cache-behavior-analyzer"
            | "captcha-presence-checker"
            | "carbon-footprint"
            | "clickjacking-test"
            | "cms-detection"
            | "csp-deep-analyzer"
            | "dependency-js-cdn-scanner"
            | "dom-sink-scanner"
            | "email-harvester"
            | "embedded-object-hunter"
            | "form-grabber"
            | "html5-feature-abuse-detector"
            | "html-comments-extractor"
            | "javascript-file-analyzer"
            | "javascript-obfuscation-detector"
            | "lazy-load-resource-finder"
            | "performance-monitoring"
            | "pixel-tracker-finder"
            | "quality-metrics"
            | "seo-abuse-detector"
            | "session-cookie-lifetime-checker"
            | "social-media"
            | "static-asset-fingerprinter"
            | "technology-stack"
            | "third-party-integrations"
            | "third-party-script-risk-profiler"
            | "websocket-endpoint-sniffer"
            | "attack-surface-delta"
            | "firewall-detection"
            | "http-headers"
            | "http-security"
            | "passive-cve-mapper"
            | "privacy-gdpr"
            | "security-changelog-diff"
    );
    let crawl = matches!(
        id,
        "dependency-js-cdn-scanner"
            | "dom-sink-scanner"
            | "email-harvester"
            | "embedded-object-hunter"
            | "form-grabber"
            | "javascript-file-analyzer"
            | "javascript-obfuscation-detector"
            | "lazy-load-resource-finder"
            | "pixel-tracker-finder"
            | "social-media"
            | "static-asset-fingerprinter"
            | "third-party-integrations"
            | "third-party-script-risk-profiler"
            | "websocket-endpoint-sniffer"
    );
    owns_root_probe.then(|| paths_plan(base, vec!["/".into()], crawl, max_pages))
}

/// Constructs a discovered GET probe after the caller has enforced scope.
pub(crate) fn discovered(url: Url) -> WebProbe {
    WebProbe::get(format!("discovered:{}", url.as_str()), url)
}

fn paths_plan(base: &Url, paths: Vec<String>, crawl: bool, max_pages: usize) -> WebPlan {
    web_plan(
        paths
            .into_iter()
            .enumerate()
            .filter_map(|(index, path)| {
                same_origin_url(base, &path)
                    .map(|url| WebProbe::get(format!("path-{index}:{path}"), url))
            })
            .collect(),
        crawl,
        max_pages,
    )
}

fn method_plan(base: &Url, max_pages: usize) -> WebPlan {
    let methods = [HttpMethod::Get, HttpMethod::Head, HttpMethod::Options];
    web_plan(
        methods
            .into_iter()
            .map(|method| WebProbe {
                method,
                ..WebProbe::get(format!("method-{method:?}"), base.clone())
            })
            .collect(),
        false,
        max_pages,
    )
}

fn schema_plan(base: &Url, options: &BTreeMap<String, Value>, max_pages: usize) -> WebPlan {
    let mut probes = graphql_probes(base, option_paths(options, "graphql_paths", &[]));
    probes.extend(
        paths_plan(
            base,
            option_paths(
                options,
                "paths",
                &["/openapi.json", "/swagger.json", "/api-docs", "/graphql"],
            ),
            false,
            max_pages,
        )
        .probes,
    );
    web_plan(probes, false, max_pages)
}

fn graphql_plan(base: &Url, max_pages: usize) -> WebPlan {
    web_plan(
        graphql_probes(base, vec!["/graphql".into()]),
        false,
        max_pages,
    )
}

fn graphql_probes(base: &Url, paths: Vec<String>) -> Vec<WebProbe> {
    let mut headers = BTreeMap::new();
    headers.insert("content-type".into(), "application/json".into());
    paths
        .into_iter()
        .enumerate()
        .filter_map(|(index, path)| {
            same_origin_url(base, &path).map(|url| WebProbe {
                label: format!("graphql-schema-query-{index}"),
                url,
                method: HttpMethod::Post,
                headers: headers.clone(),
                body: br#"{"query":"query SugraSchemaProbe { __schema { queryType { name } } }"}"#
                    .to_vec(),
                max_redirects: 1,
            })
        })
        .collect()
}

fn cors_plan(base: &Url, max_pages: usize) -> WebPlan {
    let mut probe = WebProbe::get("cors-untrusted-origin", base.clone());
    probe
        .headers
        .insert("origin".into(), "https://scope-check.invalid".into());
    web_plan(vec![probe], false, max_pages)
}

fn open_redirect_plan(base: &Url, max_pages: usize) -> WebPlan {
    paths_plan(
        base,
        vec![
            "/?next=https%3A%2F%2Fscope-check.invalid%2F".into(),
            "/?url=https%3A%2F%2Fscope-check.invalid%2F".into(),
            "/?redirect=https%3A%2F%2Fscope-check.invalid%2F".into(),
        ],
        false,
        max_pages,
    )
}

fn virtual_host_plan(
    base: &Url,
    options: &BTreeMap<String, Value>,
    max_pages: usize,
    scope: &ScopeGrant,
) -> WebPlan {
    let mut probes = vec![WebProbe::get("baseline-host", base.clone())];
    let hosts = option_strings(options, "hosts");
    for (index, host) in hosts
        .filter_map(|(index, host)| authorized_host(&host, scope).map(|host| (index, host)))
        .take(max_pages.saturating_sub(1))
    {
        let mut probe = WebProbe::get(format!("virtual-host-{index}"), base.clone());
        probe.headers.insert("host".into(), host);
        probes.push(probe);
    }
    web_plan(probes, false, max_pages)
}

fn repeated_plan(base: &Url, repetitions: usize, max_pages: usize) -> WebPlan {
    web_plan(
        (0..repetitions.min(max_pages))
            .map(|index| WebProbe::get(format!("bounded-repeat-{index}"), base.clone()))
            .collect(),
        false,
        max_pages,
    )
}

fn directory_plan(base: &Url, options: &BTreeMap<String, Value>, max_pages: usize) -> WebPlan {
    let mut paths = vec!["/.well-known/sugra-directory-control-not-found".into()];
    paths.extend(wordlist_paths(options));
    paths_plan(base, paths, false, max_pages)
}

fn seo_plan(base: &Url, max_pages: usize) -> WebPlan {
    let mut browser = WebProbe::get("seo-browser", base.clone());
    browser.headers.insert(
        "user-agent".into(),
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36".into(),
    );
    let mut crawler = WebProbe::get("seo-crawler", base.clone());
    crawler.headers.insert(
        "user-agent".into(),
        "Mozilla/5.0 (compatible; Googlebot/2.1; +https://www.google.com/bot.html)".into(),
    );
    web_plan(vec![browser, crawler], false, max_pages)
}

fn parameter_plan(base: &Url, options: &BTreeMap<String, Value>, max_pages: usize) -> WebPlan {
    let mut names = option_strings(options, "params")
        .map(|(_, value)| value)
        .filter(|value| safe_parameter_name(value))
        .collect::<Vec<_>>();
    if names.is_empty() {
        names = vec!["debug".into(), "preview".into()];
    }
    let values = option_strings(options, "test_values")
        .map(|(_, value)| value)
        .filter(|value| safe_parameter_value(value))
        .collect::<Vec<_>>();
    let values = if values.is_empty() {
        vec!["sugra-check".into(), "1".into()]
    } else {
        values
    };
    let parameter_limit = integer_option(options, "max_params", 25)
        .max(1)
        .min(max_pages.saturating_sub(1));
    let Some(root) = same_origin_url(base, "/") else {
        return web_plan(Vec::new(), false, max_pages);
    };
    let mut probes = vec![WebProbe::get("parameter-baseline", root.clone())];
    for (parameter_index, name) in names.into_iter().take(parameter_limit).enumerate() {
        for (value_index, value) in values.iter().enumerate() {
            let mut url = root.clone();
            url.query_pairs_mut().append_pair(&name, value);
            probes.push(WebProbe::get(
                format!("parameter-{parameter_index}-{value_index}"),
                url,
            ));
        }
    }
    web_plan(probes, false, max_pages)
}

fn safe_parameter_value(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn redirect_plan(base: &Url, max_pages: usize) -> WebPlan {
    let mut probe = WebProbe::get("redirect-chain", base.clone());
    probe.max_redirects = 10;
    web_plan(vec![probe], false, max_pages)
}

fn web_plan(probes: Vec<WebProbe>, crawl: bool, max_pages: usize) -> WebPlan {
    WebPlan {
        probes,
        crawl,
        max_pages,
        max_depth: 0,
        sample_per_million: SAMPLE_SCALE,
        delay_ms: 0,
        include_subdomains: false,
    }
}

fn option_paths(options: &BTreeMap<String, Value>, key: &str, defaults: &[&str]) -> Vec<String> {
    let values = option_strings(options, key)
        .map(|(_, value)| value)
        .filter(|value| safe_relative_path(value))
        .collect::<Vec<_>>();
    if values.is_empty() {
        defaults.iter().map(|value| (*value).into()).collect()
    } else {
        values
    }
}

fn wordlist_paths(options: &BTreeMap<String, Value>) -> Vec<String> {
    let paths = option_strings(options, "wordlist")
        .map(|(_, value)| value)
        .filter(|value| !value.starts_with("//") && !value.contains("://"))
        .map(|value| {
            if value.starts_with('/') {
                value
            } else {
                format!("/{value}")
            }
        })
        .filter(|value| safe_relative_path(value))
        .collect::<Vec<_>>();
    if paths.is_empty() {
        ["/admin/", "/backup/", "/config/", "/uploads/"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    } else {
        paths
    }
}

fn option_strings<'a>(
    options: &'a BTreeMap<String, Value>,
    key: &str,
) -> impl Iterator<Item = (usize, String)> + 'a {
    options
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 2_048)
        .map(str::to_owned)
        .enumerate()
}

fn safe_relative_path(value: &str) -> bool {
    value.starts_with('/') && !value.starts_with("//") && !value.contains(['\r', '\n'])
}

fn safe_parameter_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'[' | b']')
        })
}

fn same_origin_url(base: &Url, path: &str) -> Option<Url> {
    let url = base.join(path).ok()?;
    (url.scheme() == base.scheme()
        && url.host_str() == base.host_str()
        && url.port_or_known_default() == base.port_or_known_default())
    .then_some(url)
}

fn integer_option(options: &BTreeMap<String, Value>, key: &str, fallback: usize) -> usize {
    options
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(fallback)
}

fn boolean_option(options: &BTreeMap<String, Value>, key: &str) -> Option<bool> {
    options.get(key).and_then(Value::as_bool)
}

fn crawl_start_url(
    base: &Url,
    options: &BTreeMap<String, Value>,
    include_subdomains: bool,
    scope: &ScopeGrant,
) -> Option<Url> {
    let value = options.get("start_url")?.as_str()?.trim();
    if value.is_empty() || value.len() > 2_048 {
        return None;
    }
    let candidate = Url::parse(value).ok()?;
    let safe_http = matches!(candidate.scheme(), "http" | "https")
        && candidate.username().is_empty()
        && candidate.password().is_none()
        && candidate.port_or_known_default() == base.port_or_known_default()
        && candidate.scheme() == base.scheme();
    if !safe_http || !related_host(base, &candidate, include_subdomains) {
        return None;
    }
    let target = Target::parse(TargetKind::Url, candidate.as_str()).ok()?;
    scope.allows(&target).then_some(candidate)
}

fn related_host(base: &Url, candidate: &Url, include_subdomains: bool) -> bool {
    let (Some(base_host), Some(candidate_host)) = (base.host_str(), candidate.host_str()) else {
        return false;
    };
    candidate_host.eq_ignore_ascii_case(base_host)
        || include_subdomains
            && candidate_host
                .to_ascii_lowercase()
                .ends_with(&format!(".{}", base_host.to_ascii_lowercase()))
}

fn authorized_host(value: &str, scope: &ScopeGrant) -> Option<String> {
    let candidate = value.trim();
    if candidate.is_empty()
        || candidate.len() > 512
        || candidate
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '/' | '@' | '#'))
    {
        return None;
    }
    let parsed = Url::parse(&format!("http://{candidate}/")).ok()?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    let host = parsed.host_str()?;
    let target = Target::parse(TargetKind::Domain, host).ok()?;
    scope
        .allows(&target)
        .then(|| candidate.to_ascii_lowercase())
}

fn sample_ratio(options: &BTreeMap<String, Value>) -> u32 {
    options
        .get("sample_ratio")
        .and_then(Value::as_str)
        .and_then(|value| decimal_scaled(value, u64::from(SAMPLE_SCALE)))
        .filter(|value| (1..=u64::from(SAMPLE_SCALE)).contains(value))
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(SAMPLE_SCALE)
}

fn request_delay_ms(options: &BTreeMap<String, Value>, budget: Budget) -> u64 {
    let requested = ["rate_limit", "delay"]
        .into_iter()
        .find_map(|key| options.get(key).and_then(Value::as_str))
        .and_then(|value| decimal_scaled(value, 1_000))
        .unwrap_or(0);
    let per_request_budget = budget.timeout_ms / u64::try_from(budget.max_requests).unwrap_or(1);
    requested.min(per_request_budget)
}

fn decimal_scaled(value: &str, scale: u64) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() || !matches!(scale, 1_000 | 1_000_000) {
        return None;
    }
    let mut parts = value.split('.');
    let whole = parts.next()?;
    let fraction = parts.next().unwrap_or("");
    if parts.next().is_some()
        || (!whole.is_empty() && !whole.bytes().all(|byte| byte.is_ascii_digit()))
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || (whole.is_empty() && fraction.is_empty())
    {
        return None;
    }
    let whole = if whole.is_empty() {
        0
    } else {
        whole.parse::<u64>().ok()?
    };
    let digits = scale.ilog10() as usize;
    let retained = fraction.as_bytes().get(..fraction.len().min(digits))?;
    let retained = std::str::from_utf8(retained).ok()?;
    let mut fraction_value = if retained.is_empty() {
        0
    } else {
        retained.parse::<u64>().ok()?
    };
    for _ in retained.len()..digits {
        fraction_value = fraction_value.checked_mul(10)?;
    }
    if fraction
        .as_bytes()
        .get(digits..)
        .is_some_and(|remainder| remainder.iter().any(|byte| *byte != b'0'))
    {
        fraction_value = fraction_value.checked_add(1)?;
    }
    whole.checked_mul(scale)?.checked_add(fraction_value)
}

pub(crate) fn should_sample(url: &Url, sample_per_million: u32) -> bool {
    if sample_per_million >= SAMPLE_SCALE {
        return true;
    }
    let digest = Sha256::digest(url.as_str().as_bytes());
    let bucket = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) % SAMPLE_SCALE;
    bucket < sample_per_million
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog_data::definitions;
    use crate::definition::Operation;
    use sugra_domain::{Budget, ScopeGrant, ScopeRule, Target, TargetKind};
    use time::OffsetDateTime;

    fn scope_for(base: &Url) -> Result<ScopeGrant, Box<dyn std::error::Error>> {
        let target = Target::parse(TargetKind::Url, base.as_str())?;
        Ok(ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH))
    }

    fn domain_scope(domain: &str) -> Result<ScopeGrant, Box<dyn std::error::Error>> {
        Ok(ScopeGrant::new(
            vec![ScopeRule::Domain(domain.into())],
            true,
            "tests",
            OffsetDateTime::UNIX_EPOCH,
        )?)
    }

    #[test]
    fn every_http_scanner_has_a_nonempty_explicit_plan() -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse("https://example.com/")?;
        let scope = scope_for(&base)?;
        let definitions = definitions()?;
        let http: Vec<_> = definitions
            .iter()
            .filter(|definition| definition.operation == Operation::Http)
            .collect();
        assert!(!http.is_empty());
        for definition in http {
            let plan = plan_for(
                definition.descriptor.id.as_str(),
                &base,
                &BTreeMap::new(),
                Budget::DEFAULT,
                &scope,
            )
            .ok_or_else(|| format!("missing web plan for {}", definition.descriptor.id))?;
            assert!(
                !plan.probes.is_empty(),
                "{} has an empty web plan",
                definition.descriptor.id
            );
        }
        Ok(())
    }

    #[test]
    fn path_options_cannot_escape_the_base_origin() -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse("https://example.com/root")?;
        assert!(same_origin_url(&base, "/safe").is_some());
        assert!(same_origin_url(&base, "https://outside.example/path").is_none());
        assert!(!safe_relative_path("//outside.example/path"));
        Ok(())
    }

    #[test]
    fn schema_graphql_paths_are_same_origin_and_budget_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse("https://example.com/root")?;
        let scope = scope_for(&base)?;
        let options = BTreeMap::from([(
            "graphql_paths".into(),
            serde_json::json!([
                "/graphql",
                "/api/graphql",
                "//outside.example/graphql",
                "https://outside.example/graphql"
            ]),
        )]);

        let budget = Budget {
            max_requests: 2,
            ..Budget::DEFAULT
        };
        let plan = plan_for("api-schema-grabber", &base, &options, budget, &scope)
            .ok_or("schema plan is missing")?;
        let graphql: Vec<_> = plan
            .probes
            .iter()
            .filter(|probe| probe.method == HttpMethod::Post)
            .collect();

        assert_eq!(graphql.len(), 2);
        assert_eq!(graphql[0].url.as_str(), "https://example.com/graphql");
        assert_eq!(graphql[1].url.as_str(), "https://example.com/api/graphql");
        assert!(graphql.iter().all(|probe| probe.body.len() < 256));
        Ok(())
    }

    #[test]
    fn crawler_controls_are_clamped_to_the_execution_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse("https://example.com/root")?;
        let scope = scope_for(&base)?;
        let budget = Budget {
            timeout_ms: 900,
            max_requests: 3,
            max_depth: 2,
            ..Budget::DEFAULT
        };
        let options = BTreeMap::from([
            ("depth".into(), serde_json::json!(32)),
            ("max_pages".into(), serde_json::json!(10_000)),
            ("rate_limit".into(), serde_json::json!("60")),
            ("sample_ratio".into(), serde_json::json!("0.5")),
            (
                "start_url".into(),
                serde_json::json!("https://example.com/start"),
            ),
        ]);

        let plan = plan_for("crawler", &base, &options, budget, &scope)
            .ok_or("crawler plan is missing")?;

        assert_eq!(plan.max_pages, 3);
        assert_eq!(plan.max_depth, 2);
        assert_eq!(plan.sample_per_million, 500_000);
        assert_eq!(plan.delay_ms, 300);
        assert_eq!(plan.probes[0].url.as_str(), "https://example.com/start");
        Ok(())
    }

    #[test]
    fn external_start_urls_and_unauthorized_hosts_are_ignored()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse("https://example.com/root")?;
        let scope = domain_scope("example.com")?;
        let crawler_options = BTreeMap::from([(
            "start_url".into(),
            serde_json::json!("https://outside.example/start"),
        )]);
        let crawler = plan_for("crawler", &base, &crawler_options, Budget::DEFAULT, &scope)
            .ok_or("crawler plan is missing")?;
        assert_eq!(crawler.probes[0].url.as_str(), "https://example.com/");

        let host_options = BTreeMap::from([(
            "hosts".into(),
            serde_json::json!([
                "api.example.com",
                "outside.example",
                "bad.example.com\r\nx-injected: true"
            ]),
        )]);
        let hosts = plan_for(
            "virtual-host-fuzzer",
            &base,
            &host_options,
            Budget::DEFAULT,
            &scope,
        )
        .ok_or("virtual host plan is missing")?;
        let values: Vec<_> = hosts
            .probes
            .iter()
            .filter_map(|probe| probe.headers.get("host"))
            .collect();
        assert_eq!(values, vec!["api.example.com"]);
        Ok(())
    }

    #[test]
    fn scoped_subdomain_start_requires_explicit_opt_in() -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse("https://example.com/")?;
        let scope = domain_scope("example.com")?;
        let mut options = BTreeMap::from([(
            "start_url".into(),
            serde_json::json!("https://api.example.com/start"),
        )]);

        let exact = plan_for("crawler", &base, &options, Budget::DEFAULT, &scope)
            .ok_or("crawler plan is missing")?;
        assert_eq!(exact.probes[0].url.as_str(), "https://example.com/");

        options.insert("include_subdomains".into(), serde_json::json!(true));
        let subdomain = plan_for("crawler", &base, &options, Budget::DEFAULT, &scope)
            .ok_or("crawler plan is missing")?;
        assert_eq!(
            subdomain.probes[0].url.as_str(),
            "https://api.example.com/start"
        );
        Ok(())
    }

    #[test]
    fn redirect_flags_and_batch_size_have_safe_edges() -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse("https://example.com/")?;
        let scope = scope_for(&base)?;
        let cookies = plan_for("cookies", &base, &BTreeMap::new(), Budget::DEFAULT, &scope)
            .ok_or("cookie plan is missing")?;
        assert!(cookies.probes.iter().all(|probe| probe.max_redirects == 0));

        let follow = BTreeMap::from([("follow".into(), serde_json::json!(true))]);
        let cookies = plan_for("cookies", &base, &follow, Budget::DEFAULT, &scope)
            .ok_or("cookie plan is missing")?;
        assert!(cookies.probes.iter().all(|probe| probe.max_redirects == 3));

        let no_login_redirects =
            BTreeMap::from([("follow_redirects".into(), serde_json::json!(false))]);
        let login = plan_for(
            "login-page-brute-identifier",
            &base,
            &no_login_redirects,
            Budget::DEFAULT,
            &scope,
        )
        .ok_or("login plan is missing")?;
        assert!(login.probes.iter().all(|probe| probe.max_redirects == 0));

        let budget = Budget {
            max_requests: 3,
            ..Budget::DEFAULT
        };
        for batch_size in [0, 100] {
            let options = BTreeMap::from([("batch_size".into(), serde_json::json!(batch_size))]);
            let rate = plan_for(
                "rate-limit-waf-bypass-test",
                &base,
                &options,
                budget,
                &scope,
            )
            .ok_or("rate-limit plan is missing")?;
            assert!(!rate.probes.is_empty());
            assert!(rate.probes.len() <= budget.max_requests);
        }
        Ok(())
    }

    #[test]
    fn local_file_options_are_not_interpreted_as_request_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse("https://example.com/")?;
        let scope = scope_for(&base)?;
        let directory_options = BTreeMap::from([(
            "wordlist".into(),
            serde_json::json!("/private/operator/wordlist.txt"),
        )]);
        let directory = plan_for(
            "directory-finder",
            &base,
            &directory_options,
            Budget::DEFAULT,
            &scope,
        )
        .ok_or("directory plan is missing")?;
        assert!(
            directory
                .probes
                .iter()
                .all(|probe| !probe.url.path().contains("wordlist.txt"))
        );

        let login_options = BTreeMap::from([(
            "paths_file".into(),
            serde_json::json!("/private/operator/paths.txt"),
        )]);
        let login = plan_for(
            "login-page-brute-identifier",
            &base,
            &login_options,
            Budget::DEFAULT,
            &scope,
        )
        .ok_or("login plan is missing")?;
        assert!(
            login
                .probes
                .iter()
                .all(|probe| !probe.url.path().contains("paths.txt"))
        );

        let parameter_options = BTreeMap::from([(
            "params_file".into(),
            serde_json::json!("/private/operator/params.txt"),
        )]);
        let parameters = plan_for(
            "hidden-parameter-discovery",
            &base,
            &parameter_options,
            Budget::DEFAULT,
            &scope,
        )
        .ok_or("parameter plan is missing")?;
        assert!(
            parameters
                .probes
                .iter()
                .all(|probe| !probe.url.path().contains("params.txt"))
        );
        Ok(())
    }

    #[test]
    fn injected_wordlist_lines_create_only_same_origin_paths()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse("https://example.com/")?;
        let scope = scope_for(&base)?;
        let options = BTreeMap::from([(
            "wordlist".into(),
            serde_json::json!([
                "admin",
                "/api",
                "//outside.example",
                "https://outside.example"
            ]),
        )]);

        let plan = plan_for("directory-finder", &base, &options, Budget::DEFAULT, &scope)
            .ok_or("directory plan is missing")?;
        let urls: Vec<_> = plan.probes.iter().map(|probe| probe.url.as_str()).collect();

        assert_eq!(
            urls,
            vec![
                "https://example.com/.well-known/sugra-directory-control-not-found",
                "https://example.com/admin",
                "https://example.com/api"
            ]
        );
        Ok(())
    }

    #[test]
    fn injected_parameter_lines_are_validated_encoded_and_budget_bounded()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse("https://example.com/")?;
        let scope = scope_for(&base)?;
        let options = BTreeMap::from([
            (
                "params".into(),
                serde_json::json!(["token", "user name", "bad\r\nheader", "x".repeat(129)]),
            ),
            ("max_params".into(), serde_json::json!(1)),
        ]);
        let budget = Budget {
            max_requests: 2,
            ..Budget::DEFAULT
        };

        let plan = plan_for(
            "hidden-parameter-discovery",
            &base,
            &options,
            budget,
            &scope,
        )
        .ok_or("parameter plan is missing")?;
        let urls: Vec<_> = plan.probes.iter().map(|probe| probe.url.as_str()).collect();

        assert_eq!(
            urls,
            vec![
                "https://example.com/",
                "https://example.com/?token=sugra-check"
            ]
        );
        Ok(())
    }

    #[test]
    fn sampling_is_deterministic_and_invalid_ratios_fail_closed_to_full_sampling()
    -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse("https://example.com/")?;
        let scope = scope_for(&base)?;
        let invalid = BTreeMap::from([("sample_ratio".into(), serde_json::json!("1.1"))]);
        let plan = plan_for("broken-links", &base, &invalid, Budget::DEFAULT, &scope)
            .ok_or("broken links plan is missing")?;
        assert_eq!(plan.sample_per_million, SAMPLE_SCALE);

        let url = Url::parse("https://example.com/stable")?;
        assert!(should_sample(&url, SAMPLE_SCALE));
        assert_eq!(should_sample(&url, 500_000), should_sample(&url, 500_000));
        Ok(())
    }

    #[test]
    fn active_plans_remain_small_and_explicit() -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse("https://example.com/")?;
        let scope = scope_for(&base)?;
        let graphql = plan_for(
            "graphql-introspection-probe",
            &base,
            &BTreeMap::new(),
            Budget::DEFAULT,
            &scope,
        )
        .ok_or("GraphQL plan is missing")?;
        assert_eq!(graphql.probes.len(), 1);
        assert_eq!(graphql.probes[0].method, HttpMethod::Post);
        assert!(graphql.probes[0].body.len() < 256);

        let rate = plan_for(
            "rate-limit-waf-bypass-test",
            &base,
            &BTreeMap::new(),
            Budget::DEFAULT,
            &scope,
        )
        .ok_or("rate-limit plan is missing")?;
        assert_eq!(rate.probes.len(), 4);

        let cache = plan_for(
            "cache-behavior-analyzer",
            &base,
            &BTreeMap::new(),
            Budget::DEFAULT,
            &scope,
        )
        .ok_or("cache plan is missing")?;
        assert_eq!(cache.probes.len(), 2);

        let performance = plan_for(
            "performance-monitoring",
            &base,
            &BTreeMap::new(),
            Budget::DEFAULT,
            &scope,
        )
        .ok_or("performance plan is missing")?;
        assert_eq!(performance.probes.len(), 3);

        let seo = plan_for(
            "seo-abuse-detector",
            &base,
            &BTreeMap::new(),
            Budget::DEFAULT,
            &scope,
        )
        .ok_or("SEO plan is missing")?;
        assert_eq!(seo.probes.len(), 2);
        assert!(
            seo.probes[0]
                .headers
                .get("user-agent")
                .is_some_and(|value| value.contains("Chrome/") && !value.contains("compatible;"))
        );
        assert!(
            seo.probes[1]
                .headers
                .get("user-agent")
                .is_some_and(|value| value.contains("Googlebot/"))
        );
        Ok(())
    }
}
