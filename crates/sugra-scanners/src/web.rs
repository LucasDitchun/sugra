//! Explicit, bounded HTTP probe plans for every web scanner.

use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest, Sha256};
use sugra_core::HttpMethod;
use url::Url;

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
}

/// Returns an explicit plan for every scanner assigned to the HTTP boundary.
pub(crate) fn plan_for(
    id: &str,
    base: &Url,
    options: &BTreeMap<String, Value>,
    budget_limit: usize,
) -> Option<WebPlan> {
    let max_pages = integer_option(options, "max_pages", budget_limit).min(budget_limit);
    let mut plan = resource_plan(id, base, options, max_pages)
        .or_else(|| active_plan(id, base, options, max_pages))
        .or_else(|| root_plan(id, base, max_pages))?;
    plan.probes.truncate(budget_limit);
    Some(plan)
}

fn resource_plan(
    id: &str,
    base: &Url,
    options: &BTreeMap<String, Value>,
    max_pages: usize,
) -> Option<WebPlan> {
    let plan = match id {
        "api-schema-grabber" => paths_plan(
            base,
            option_paths(
                options,
                "paths",
                &["/openapi.json", "/swagger.json", "/api-docs", "/graphql"],
            ),
            false,
            max_pages,
        ),
        "broken-links" | "content-discovery" | "crawler" => {
            paths_plan(base, vec!["/".into()], true, max_pages)
        }
        "cookies" | "cookie-scope-diff" | "session-hijacking-passive" => paths_plan(
            base,
            option_paths(options, "paths", &["/", "/login", "/account"]),
            false,
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
        "directory-finder" => paths_plan(
            base,
            option_paths(
                options,
                "wordlist",
                &["/admin/", "/backup/", "/config/", "/uploads/"],
            ),
            false,
            max_pages,
        ),
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
        "virtual-host-fuzzer" => virtual_host_plan(base, options, max_pages),
        "rate-limit-waf-bypass-test" => repeated_plan(base, 4, max_pages),
        "redirect-chain" => redirect_plan(base, max_pages),
        "hidden-parameter-discovery" => paths_plan(
            base,
            vec![
                "/".into(),
                "/?debug=sugra-check".into(),
                "/?preview=sugra-check".into(),
            ],
            false,
            max_pages,
        ),
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
            | "typosquat-domain-checker"
    );
    owns_root_probe.then(|| paths_plan(base, vec!["/".into()], false, max_pages))
}

/// Constructs a discovered GET probe after the caller has enforced scope.
pub(crate) fn discovered(url: Url) -> WebProbe {
    WebProbe::get(format!("discovered:{}", url.as_str()), url)
}

fn paths_plan(base: &Url, paths: Vec<String>, crawl: bool, max_pages: usize) -> WebPlan {
    WebPlan {
        probes: paths
            .into_iter()
            .enumerate()
            .filter_map(|(index, path)| {
                same_origin_url(base, &path)
                    .map(|url| WebProbe::get(format!("path-{index}:{path}"), url))
            })
            .collect(),
        crawl,
        max_pages,
    }
}

fn method_plan(base: &Url, max_pages: usize) -> WebPlan {
    let methods = [HttpMethod::Get, HttpMethod::Head, HttpMethod::Options];
    WebPlan {
        probes: methods
            .into_iter()
            .map(|method| WebProbe {
                method,
                ..WebProbe::get(format!("method-{method:?}"), base.clone())
            })
            .collect(),
        crawl: false,
        max_pages,
    }
}

fn graphql_plan(base: &Url, max_pages: usize) -> WebPlan {
    let Some(url) = same_origin_url(base, "/graphql") else {
        return paths_plan(base, Vec::new(), false, max_pages);
    };
    let mut headers = BTreeMap::new();
    headers.insert("content-type".into(), "application/json".into());
    WebPlan {
        probes: vec![WebProbe {
            label: "graphql-schema-query".into(),
            url,
            method: HttpMethod::Post,
            headers,
            body: br#"{"query":"query SugraSchemaProbe { __schema { queryType { name } } }"}"#
                .to_vec(),
            max_redirects: 1,
        }],
        crawl: false,
        max_pages,
    }
}

fn cors_plan(base: &Url, max_pages: usize) -> WebPlan {
    let mut probe = WebProbe::get("cors-untrusted-origin", base.clone());
    probe
        .headers
        .insert("origin".into(), "https://scope-check.invalid".into());
    WebPlan {
        probes: vec![probe],
        crawl: false,
        max_pages,
    }
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

fn virtual_host_plan(base: &Url, options: &BTreeMap<String, Value>, max_pages: usize) -> WebPlan {
    let mut probes = vec![WebProbe::get("baseline-host", base.clone())];
    let hosts = option_strings(options, "hosts");
    for (index, host) in hosts.into_iter().take(max_pages.saturating_sub(1)) {
        let mut probe = WebProbe::get(format!("virtual-host-{index}"), base.clone());
        probe.headers.insert("host".into(), host);
        probes.push(probe);
    }
    WebPlan {
        probes,
        crawl: false,
        max_pages,
    }
}

fn repeated_plan(base: &Url, repetitions: usize, max_pages: usize) -> WebPlan {
    WebPlan {
        probes: (0..repetitions.min(max_pages))
            .map(|index| WebProbe::get(format!("bounded-repeat-{index}"), base.clone()))
            .collect(),
        crawl: false,
        max_pages,
    }
}

fn redirect_plan(base: &Url, max_pages: usize) -> WebPlan {
    let mut probe = WebProbe::get("redirect-chain", base.clone());
    probe.max_redirects = 10;
    WebPlan {
        probes: vec![probe],
        crawl: false,
        max_pages,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog_data::definitions;
    use crate::definition::Operation;

    #[test]
    fn every_http_scanner_has_a_nonempty_explicit_plan() -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse("https://example.com/")?;
        let definitions = definitions()?;
        let http: Vec<_> = definitions
            .iter()
            .filter(|definition| definition.operation == Operation::Http)
            .collect();
        assert_eq!(http.len(), 68);
        for definition in http {
            let plan = plan_for(
                definition.descriptor.id.as_str(),
                &base,
                &BTreeMap::new(),
                64,
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
    fn active_plans_remain_small_and_explicit() -> Result<(), Box<dyn std::error::Error>> {
        let base = Url::parse("https://example.com/")?;
        let graphql = plan_for("graphql-introspection-probe", &base, &BTreeMap::new(), 64)
            .ok_or("GraphQL plan is missing")?;
        assert_eq!(graphql.probes.len(), 1);
        assert_eq!(graphql.probes[0].method, HttpMethod::Post);
        assert!(graphql.probes[0].body.len() < 256);

        let rate = plan_for("rate-limit-waf-bypass-test", &base, &BTreeMap::new(), 64)
            .ok_or("rate-limit plan is missing")?;
        assert_eq!(rate.probes.len(), 4);
        Ok(())
    }
}
