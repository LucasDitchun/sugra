//! Allowlisted HTTP JSON providers with credential injection at the boundary.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use serde_json::Value;
use sugra_core::{
    Clock, HttpMethod, HttpPort, HttpRequest, PortError, PortErrorKind, ProviderPort,
    ProviderRequest, ProviderResponse,
};
use sugra_domain::{ScopeGrant, Target, TargetKind};
use url::Url;

/// HTTP-backed provider boundary restricted to known public endpoints.
#[derive(Clone)]
pub struct ReqwestProvider {
    http: Arc<dyn HttpPort>,
    clock: Arc<dyn Clock>,
}

impl ReqwestProvider {
    /// Constructs a provider boundary over an existing secure HTTP client.
    #[must_use]
    pub fn new(http: Arc<dyn HttpPort>, clock: Arc<dyn Clock>) -> Self {
        Self { http, clock }
    }
}

#[async_trait]
impl ProviderPort for ReqwestProvider {
    async fn query(&self, request: ProviderRequest) -> Result<ProviderResponse, PortError> {
        let mut endpoint = endpoint_for(&request)?;
        let mut headers = BTreeMap::new();
        if request.provider == "cloudflare-doh" {
            headers.insert("accept".into(), "application/dns-json".into());
        } else if request.provider == "hibp" {
            headers.insert(
                "user-agent".into(),
                format!("Sugra/{} HIBP integration", env!("CARGO_PKG_VERSION")),
            );
        } else if request.provider == "censys" {
            let asset = if request.operation == "webproperty" {
                "webproperty"
            } else {
                "host"
            };
            headers.insert(
                "accept".into(),
                format!("application/vnd.censys.api.v3.{asset}.v1+json"),
            );
        }
        if let Some(secret_env) = &request.secret_env {
            let secret = std::env::var(secret_env).map_err(|_| {
                PortError::new(
                    PortErrorKind::Unavailable,
                    "provider credential is not configured",
                )
            })?;
            inject_secret(&request.provider, &mut endpoint, &mut headers, &secret)?;
        }
        let (method, body) = provider_transport(&request, &mut headers);
        let scope_target = Target::parse(TargetKind::Url, endpoint.as_str())
            .map_err(|_| PortError::new(PortErrorKind::Internal, "provider endpoint is invalid"))?;
        let scope = ScopeGrant::exact(&scope_target, false, self.clock.now());
        let started = Instant::now();
        let response = self
            .http
            .execute(HttpRequest {
                url: endpoint,
                method,
                headers,
                body,
                max_redirects: 2,
                budget: request.budget,
                scope,
            })
            .await?;
        if response.status == 429 {
            return Err(PortError::new(
                PortErrorKind::RateLimited,
                "provider rate limit reached",
            ));
        }
        if !(200..300).contains(&response.status) {
            return Err(PortError::new(
                PortErrorKind::InvalidResponse,
                format!("provider returned HTTP {}", response.status),
            ));
        }
        let data = serde_json::from_slice::<Value>(&response.body).map_err(|_| {
            PortError::new(
                PortErrorKind::InvalidResponse,
                "provider returned invalid JSON",
            )
        })?;
        let data = normalize_provider_data(&request, data);
        Ok(ProviderResponse {
            provider: request.provider,
            data,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}

fn endpoint_for(request: &ProviderRequest) -> Result<Url, PortError> {
    if request.provider == "ripestat" {
        return ripestat_endpoint(request);
    }
    let (base, fixed): (&str, &[(&str, &str)]) =
        match (request.provider.as_str(), request.operation.as_str()) {
            ("crtsh", "query") => ("https://crt.sh/", &[("output", "json")]),
            ("wayback", "cdx") => (
                "https://web.archive.org/cdx/search/cdx",
                &[
                    ("output", "json"),
                    ("fl", "timestamp,original,statuscode,digest"),
                ],
            ),
            ("rdap", "domain") => ("https://rdap.org/domain", &[]),
            ("rdap", "ip") => ("https://rdap.org/ip", &[]),
            ("shodan", "host") => ("https://api.shodan.io/shodan/host", &[]),
            ("shodan", "search") => ("https://api.shodan.io/shodan/host/search", &[]),
            ("virustotal", "domain") => ("https://www.virustotal.com/api/v3/domains", &[]),
            ("virustotal", "ip") => ("https://www.virustotal.com/api/v3/ip_addresses", &[]),
            ("hibp", "account") => ("https://haveibeenpwned.com/api/v3/breachedaccount", &[]),
            ("hibp", "domain") => ("https://haveibeenpwned.com/api/v3/breacheddomain", &[]),
            ("hibp", "stealer-logs-domain") => (
                "https://haveibeenpwned.com/api/v3/stealerLogsByWebsiteDomain",
                &[],
            ),
            ("hibp", "paste-account") => ("https://haveibeenpwned.com/api/v3/pasteAccount", &[]),
            ("abuseipdb", "check") => ("https://api.abuseipdb.com/api/v2/check", &[]),
            ("ipinfo", "lookup") => ("https://ipinfo.io", &[]),
            ("otx", "domain") => ("https://otx.alienvault.com/api/v1/indicators/domain", &[]),
            ("urlhaus", "host") => ("https://urlhaus-api.abuse.ch/v1/host/", &[]),
            ("ssllabs", "analyze") => ("https://api.ssllabs.com/api/v3/analyze", &[]),
            ("urlscan", "search") => ("https://urlscan.io/api/v1/search/", &[]),
            ("censys", "host") => ("https://api.platform.censys.io/v3/global/asset/host", &[]),
            ("censys", "webproperty") => (
                "https://api.platform.censys.io/v3/global/asset/webproperty",
                &[],
            ),
            ("cloudflare-radar", "domain-ranking") => (
                "https://api.cloudflare.com/client/v4/radar/ranking/domain",
                &[("format", "JSON")],
            ),
            ("cloudflare-doh", "resolve") => ("https://cloudflare-dns.com/dns-query", &[]),
            ("google-doh", "resolve") => ("https://dns.google/resolve", &[]),
            ("pagespeed", "analyze") => (
                "https://pagespeedonline.googleapis.com/pagespeedonline/v5/runPagespeed",
                &[("category", "performance")],
            ),
            _ => {
                return Err(PortError::new(
                    PortErrorKind::Unavailable,
                    "provider operation is not configured",
                ));
            }
        };
    let mut url = Url::parse(base)
        .map_err(|_| PortError::new(PortErrorKind::Internal, "provider endpoint is invalid"))?;
    let target_in_path = provider_target_in_path(&request.provider, &request.operation);
    if target_in_path {
        let target = query_string(&request.query, "target")?;
        url.path_segments_mut()
            .map_err(|()| {
                PortError::new(PortErrorKind::Internal, "provider URL cannot accept a path")
            })?
            .push(target);
        if request.provider == "otx" {
            url.path_segments_mut()
                .map_err(|()| {
                    PortError::new(PortErrorKind::Internal, "provider URL cannot accept a path")
                })?
                .push("general");
        }
    }
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in fixed {
            pairs.append_pair(key, value);
        }
        if request.provider == "urlscan" && !request.query.contains_key("size") {
            pairs.append_pair("size", "100");
        }
        for (key, value) in &request.query {
            if request.provider == "urlhaus" {
                continue;
            }
            if key == "target" && target_in_path {
                continue;
            }
            if let Some(value) = value.as_str() {
                pairs.append_pair(key, value);
            } else {
                pairs.append_pair(key, &value.to_string());
            }
        }
    }
    if url.query() == Some("") {
        url.set_query(None);
    }
    Ok(url)
}

fn provider_target_in_path(provider: &str, operation: &str) -> bool {
    matches!(
        (provider, operation),
        ("rdap" | "virustotal", "domain" | "ip")
            | ("shodan", "host")
            | (
                "hibp",
                "account" | "domain" | "stealer-logs-domain" | "paste-account"
            )
            | ("ipinfo", "lookup")
            | ("otx", "domain")
            | ("censys", "host" | "webproperty")
            | ("cloudflare-radar", "domain-ranking")
    )
}

fn provider_transport(
    request: &ProviderRequest,
    headers: &mut BTreeMap<String, String>,
) -> (HttpMethod, Vec<u8>) {
    if request.provider != "urlhaus" {
        return (HttpMethod::Get, Vec::new());
    }
    headers.insert(
        "content-type".into(),
        "application/x-www-form-urlencoded".into(),
    );
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in &request.query {
        if let Some(value) = value.as_str() {
            serializer.append_pair(key, value);
        } else {
            serializer.append_pair(key, &value.to_string());
        }
    }
    (HttpMethod::Post, serializer.finish().into_bytes())
}

fn ripestat_endpoint(request: &ProviderRequest) -> Result<Url, PortError> {
    let endpoint = match request.operation.as_str() {
        "as-overview" => "as-overview",
        "asn-neighbours" => "asn-neighbours",
        "bgp-state" => "bgp-state",
        "dns-blocklists" => "dns-blocklists",
        "dns-chain" => "dns-chain",
        "historical-whois" => "historical-whois",
        "network-info" => "network-info",
        "prefix-overview" => "prefix-overview",
        "rir" => "rir",
        "rir-geo" => "rir-geo",
        "routing-history" => "routing-history",
        "rpki-history" => "rpki-history",
        "rpki-validation" => "rpki-validation",
        "whois" => "whois",
        _ => {
            return Err(PortError::new(
                PortErrorKind::Unavailable,
                "RIPEstat operation is not configured",
            ));
        }
    };
    let mut url = Url::parse(&format!("https://stat.ripe.net/data/{endpoint}/data.json"))
        .map_err(|_| PortError::new(PortErrorKind::Internal, "provider endpoint is invalid"))?;
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in &request.query {
            if let Some(value) = value.as_str() {
                pairs.append_pair(key, value);
            } else {
                pairs.append_pair(key, &value.to_string());
            }
        }
    }
    if url.query() == Some("") {
        url.set_query(None);
    }
    Ok(url)
}

fn query_string<'a>(query: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a str, PortError> {
    query.get(key).and_then(Value::as_str).ok_or_else(|| {
        PortError::new(
            PortErrorKind::InvalidResponse,
            "provider request omitted a string target",
        )
    })
}

fn inject_secret(
    provider: &str,
    url: &mut Url,
    headers: &mut BTreeMap<String, String>,
    secret: &str,
) -> Result<(), PortError> {
    match provider {
        "shodan" | "pagespeed" => {
            url.query_pairs_mut().append_pair("key", secret);
        }
        "virustotal" => {
            headers.insert("x-apikey".into(), secret.into());
        }
        "hibp" => {
            headers.insert("hibp-api-key".into(), secret.into());
        }
        "abuseipdb" => {
            headers.insert("key".into(), secret.into());
            headers.insert("accept".into(), "application/json".into());
        }
        "ipinfo" => {
            url.query_pairs_mut().append_pair("token", secret);
        }
        "otx" => {
            headers.insert("x-otx-api-key".into(), secret.into());
        }
        "censys" | "cloudflare-radar" => {
            headers.insert("authorization".into(), format!("Bearer {secret}"));
        }
        "urlscan" => {
            headers.insert("api-key".into(), secret.into());
        }
        "urlhaus" => {
            headers.insert("auth-key".into(), secret.into());
        }
        "crtsh" | "wayback" | "rdap" | "ripestat" | "ssllabs" | "cloudflare-doh" | "google-doh" => {
            return Err(PortError::new(
                PortErrorKind::InvalidResponse,
                "provider does not accept a credential for this operation",
            ));
        }
        _ => {
            return Err(PortError::new(
                PortErrorKind::Unavailable,
                "provider is not configured",
            ));
        }
    }
    Ok(())
}

fn normalize_provider_data(request: &ProviderRequest, value: Value) -> Value {
    if request.provider != "pagespeed" {
        return value;
    }

    let lighthouse = value.get("lighthouseResult").unwrap_or(&Value::Null);
    let audits = lighthouse.get("audits").unwrap_or(&Value::Null);
    let metric = |name: &str| {
        audits
            .get(name)
            .and_then(|audit| audit.get("numericValue"))
            .and_then(Value::as_f64)
    };
    serde_json::json!({
        "performance_score": lighthouse
            .pointer("/categories/performance/score")
            .and_then(Value::as_f64),
        "loading_experience": value
            .pointer("/loadingExperience/overall_category")
            .and_then(Value::as_str),
        "metrics": {
            "cumulative_layout_shift": metric("cumulative-layout-shift"),
            "first_contentful_paint_ms": metric("first-contentful-paint"),
            "largest_contentful_paint_ms": metric("largest-contentful-paint"),
            "speed_index_ms": metric("speed-index"),
            "total_blocking_time_ms": metric("total-blocking-time"),
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use serde_json::{Value, json};
    use sugra_core::{Clock, HttpPort, HttpRequest, HttpResponse, ProviderRequest};
    use sugra_domain::Budget;
    use time::OffsetDateTime;

    use super::*;

    fn request(provider: &str, operation: &str, query: BTreeMap<String, Value>) -> ProviderRequest {
        ProviderRequest {
            provider: provider.into(),
            operation: operation.into(),
            query,
            secret_env: None,
            budget: Budget::default(),
        }
    }

    #[derive(Clone)]
    struct FakeHttp {
        response: Result<HttpResponse, PortError>,
        requests: Arc<Mutex<Vec<HttpRequest>>>,
    }

    #[async_trait]
    impl HttpPort for FakeHttp {
        async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
            self.requests
                .lock()
                .map_err(|_| PortError::new(PortErrorKind::Internal, "test request lock failed"))?
                .push(request);
            self.response.clone()
        }
    }

    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH
        }
    }

    fn response(status: u16, body: &[u8]) -> HttpResponse {
        HttpResponse {
            final_url: Url::parse("https://provider.example/result")
                .unwrap_or_else(|error| unreachable!("valid test URL: {error}")),
            status,
            headers: BTreeMap::new(),
            cookies: Vec::new(),
            redirects: Vec::new(),
            body: body.to_vec(),
            duration_ms: 7,
        }
    }

    fn provider(
        response: Result<HttpResponse, PortError>,
    ) -> (ReqwestProvider, Arc<Mutex<Vec<HttpRequest>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let http = FakeHttp {
            response,
            requests: Arc::clone(&requests),
        };
        (
            ReqwestProvider::new(Arc::new(http), Arc::new(FixedClock)),
            requests,
        )
    }

    #[test]
    fn endpoint_encodes_path_targets_without_leaking_them_into_query()
    -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = endpoint_for(&request(
            "rdap",
            "domain",
            BTreeMap::from([("target".into(), json!("example.com/path"))]),
        ))?;
        assert_eq!(endpoint.host_str(), Some("rdap.org"));
        assert_eq!(endpoint.path(), "/domain/example.com%2Fpath");
        assert!(endpoint.query().is_none());
        Ok(())
    }

    #[test]
    fn hibp_monitoring_operations_use_allowlisted_path_targets()
    -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            (
                "stealer-logs-domain",
                "example.com",
                "/api/v3/stealerLogsByWebsiteDomain/example.com",
            ),
            (
                "paste-account",
                "alice@example.com",
                "/api/v3/pasteAccount/alice@example.com",
            ),
        ];

        for (operation, target, expected_path) in cases {
            let endpoint = endpoint_for(&request(
                "hibp",
                operation,
                BTreeMap::from([("target".into(), json!(target))]),
            ))?;
            assert_eq!(endpoint.host_str(), Some("haveibeenpwned.com"));
            assert_eq!(endpoint.path(), expected_path);
            assert!(endpoint.query().is_none());
        }
        assert!(
            endpoint_for(&request(
                "hibp",
                "stealer-logs-email",
                BTreeMap::from([("target".into(), json!("alice@example.com"))]),
            ))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn doh_endpoint_preserves_bounded_query_parameters() -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = endpoint_for(&request(
            "cloudflare-doh",
            "resolve",
            BTreeMap::from([
                ("name".into(), json!("example.com")),
                ("type".into(), json!("AAAA")),
            ]),
        ))?;
        let pairs: BTreeMap<_, _> = endpoint.query_pairs().into_owned().collect();
        assert_eq!(pairs.get("name").map(String::as_str), Some("example.com"));
        assert_eq!(pairs.get("type").map(String::as_str), Some("AAAA"));
        Ok(())
    }

    #[test]
    fn pagespeed_endpoint_is_allowlisted_and_uses_a_bounded_strategy()
    -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = endpoint_for(&request(
            "pagespeed",
            "analyze",
            BTreeMap::from([
                ("url".into(), json!("https://example.com/")),
                ("strategy".into(), json!("mobile")),
            ]),
        ))?;
        assert_eq!(endpoint.host_str(), Some("pagespeedonline.googleapis.com"));
        assert_eq!(endpoint.path(), "/pagespeedonline/v5/runPagespeed");
        let pairs: BTreeMap<_, _> = endpoint.query_pairs().into_owned().collect();
        assert_eq!(
            pairs.get("url").map(String::as_str),
            Some("https://example.com/")
        );
        assert_eq!(pairs.get("strategy").map(String::as_str), Some("mobile"));
        assert_eq!(
            pairs.get("category").map(String::as_str),
            Some("performance")
        );
        Ok(())
    }

    #[test]
    fn secret_injection_uses_provider_specific_locations() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut endpoint = Url::parse("https://example.com/")?;
        let mut headers = BTreeMap::new();
        inject_secret("virustotal", &mut endpoint, &mut headers, "fixture-secret")?;
        assert_eq!(
            headers.get("x-apikey").map(String::as_str),
            Some("fixture-secret")
        );
        assert!(endpoint.query().is_none());

        let Err(error) = inject_secret("rdap", &mut endpoint, &mut headers, "not-accepted") else {
            return Err("public provider accepted an unsupported credential".into());
        };
        assert_eq!(error.kind, PortErrorKind::InvalidResponse);

        let mut pagespeed = Url::parse("https://pagespeedonline.googleapis.com/")?;
        inject_secret("pagespeed", &mut pagespeed, &mut headers, "fixture-secret")?;
        assert_eq!(pagespeed.query(), Some("key=fixture-secret"));
        Ok(())
    }

    #[test]
    fn pagespeed_response_is_reduced_to_non_sensitive_metrics() {
        let request = request("pagespeed", "analyze", BTreeMap::new());
        let normalized = normalize_provider_data(
            &request,
            json!({
                "id": "https://example.com/private?token=secret",
                "loadingExperience": {"overall_category": "FAST"},
                "lighthouseResult": {
                    "finalUrl": "https://example.com/private?token=secret",
                    "categories": {"performance": {"score": 0.91}},
                    "audits": {
                        "cumulative-layout-shift": {"numericValue": 0.03},
                        "first-contentful-paint": {"numericValue": 812.0},
                        "largest-contentful-paint": {"numericValue": 1420.0},
                        "speed-index": {"numericValue": 1100.0},
                        "total-blocking-time": {"numericValue": 25.0},
                        "screenshot-thumbnails": {"details": {"items": ["large"]}}
                    }
                }
            }),
        );

        assert_eq!(normalized["performance_score"], json!(0.91));
        assert_eq!(normalized["loading_experience"], json!("FAST"));
        assert_eq!(
            normalized["metrics"]["largest_contentful_paint_ms"],
            json!(1420.0)
        );
        assert!(normalized.get("id").is_none());
        assert!(!normalized.to_string().contains("secret"));
        assert!(!normalized.to_string().contains("screenshot"));
    }

    #[test]
    fn ripestat_endpoint_uses_an_allowlisted_operation_and_resource()
    -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = endpoint_for(&request(
            "ripestat",
            "routing-history",
            BTreeMap::from([("resource".into(), json!("AS64496"))]),
        ))?;
        assert_eq!(endpoint.path(), "/data/routing-history/data.json");
        assert_eq!(endpoint.query(), Some("resource=AS64496"));
        assert!(endpoint_for(&request("ripestat", "arbitrary", BTreeMap::new())).is_err());
        Ok(())
    }

    #[test]
    fn censys_endpoint_and_bearer_header_follow_platform_v3()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut endpoint = endpoint_for(&request(
            "censys",
            "webproperty",
            BTreeMap::from([("target".into(), json!("example.com:443"))]),
        ))?;
        assert_eq!(
            endpoint.path(),
            "/v3/global/asset/webproperty/example.com:443"
        );
        let mut headers = BTreeMap::new();
        inject_secret("censys", &mut endpoint, &mut headers, "fixture-token")?;
        assert_eq!(
            headers.get("authorization").map(String::as_str),
            Some("Bearer fixture-token")
        );
        Ok(())
    }

    #[test]
    fn shodan_search_uses_the_allowlisted_search_endpoint_and_query()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut endpoint = endpoint_for(&request(
            "shodan",
            "search",
            BTreeMap::from([
                ("query".into(), json!("hostname:example.com")),
                ("minify".into(), json!("true")),
            ]),
        ))?;
        assert_eq!(endpoint.path(), "/shodan/host/search");
        inject_secret("shodan", &mut endpoint, &mut BTreeMap::new(), "fixture")?;
        let pairs: BTreeMap<_, _> = endpoint.query_pairs().into_owned().collect();
        assert_eq!(
            pairs.get("query").map(String::as_str),
            Some("hostname:example.com")
        );
        assert_eq!(pairs.get("minify").map(String::as_str), Some("true"));
        assert_eq!(pairs.get("key").map(String::as_str), Some("fixture"));
        Ok(())
    }

    #[test]
    fn urlscan_search_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let default_endpoint = endpoint_for(&request(
            "urlscan",
            "search",
            BTreeMap::from([("q".into(), json!("domain:example.com"))]),
        ))?;
        let pairs: BTreeMap<_, _> = default_endpoint.query_pairs().into_owned().collect();
        assert_eq!(
            pairs.get("q").map(String::as_str),
            Some("domain:example.com")
        );
        assert_eq!(pairs.get("size").map(String::as_str), Some("100"));

        let planned_endpoint = endpoint_for(&request(
            "urlscan",
            "search",
            BTreeMap::from([
                ("q".into(), json!("domain:example.com")),
                ("size".into(), json!(7)),
            ]),
        ))?;
        let sizes: Vec<_> = planned_endpoint
            .query_pairs()
            .filter(|(key, _)| key == "size")
            .map(|(_, value)| value.into_owned())
            .collect();
        assert_eq!(sizes, vec!["7"]);
        Ok(())
    }

    #[test]
    fn urlhaus_host_query_uses_authenticated_form_post() -> Result<(), Box<dyn std::error::Error>> {
        let request = request(
            "urlhaus",
            "host",
            BTreeMap::from([("host".into(), json!("example.com"))]),
        );
        let endpoint = endpoint_for(&request)?;
        assert!(endpoint.query().is_none());
        let mut headers = BTreeMap::new();
        let mut credential_endpoint = endpoint.clone();
        inject_secret(
            "urlhaus",
            &mut credential_endpoint,
            &mut headers,
            "fixture-key",
        )?;
        let (method, body) = provider_transport(&request, &mut headers);
        assert_eq!(method, HttpMethod::Post);
        assert_eq!(body, b"host=example.com");
        assert_eq!(
            headers.get("auth-key").map(String::as_str),
            Some("fixture-key")
        );
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("application/x-www-form-urlencoded")
        );
        Ok(())
    }

    #[tokio::test]
    async fn query_builds_a_scoped_request_and_parses_json()
    -> Result<(), Box<dyn std::error::Error>> {
        let (provider, requests) = provider(Ok(response(200, br#"{"Status": 0}"#)));
        let provider_response = provider
            .query(request(
                "cloudflare-doh",
                "resolve",
                BTreeMap::from([
                    ("name".into(), json!("example.com")),
                    ("type".into(), json!("AAAA")),
                ]),
            ))
            .await?;

        assert_eq!(provider_response.provider, "cloudflare-doh");
        assert_eq!(provider_response.data, json!({"Status": 0}));
        let requests = requests.lock().map_err(|_| "test request lock failed")?;
        let sent = requests.first().ok_or("provider did not issue a request")?;
        assert_eq!(sent.method, HttpMethod::Get);
        assert_eq!(sent.max_redirects, 2);
        assert_eq!(
            sent.headers.get("accept").map(String::as_str),
            Some("application/dns-json")
        );
        assert_eq!(sent.url.host_str(), Some("cloudflare-dns.com"));
        let target = Target::parse(TargetKind::Url, sent.url.as_str())?;
        assert!(sent.scope.allows(&target));
        Ok(())
    }

    #[tokio::test]
    async fn hibp_query_sends_an_identifiable_user_agent() -> Result<(), Box<dyn std::error::Error>>
    {
        let (provider, requests) = provider(Ok(response(200, b"[]")));
        provider
            .query(request(
                "hibp",
                "paste-account",
                BTreeMap::from([("target".into(), json!("alice@example.com"))]),
            ))
            .await?;

        let requests = requests.lock().map_err(|_| "test request lock failed")?;
        let sent = requests.first().ok_or("provider did not issue a request")?;
        let user_agent = sent
            .headers
            .get("user-agent")
            .ok_or("HIBP request omitted user-agent")?;
        assert!(user_agent.starts_with("Sugra/"));
        assert!(user_agent.contains("HIBP"));
        Ok(())
    }

    #[tokio::test]
    async fn query_classifies_status_body_and_transport_failures() {
        let cases = [
            (
                Ok(response(429, b"{}")),
                PortErrorKind::RateLimited,
                "provider rate limit reached",
            ),
            (
                Ok(response(503, b"{}")),
                PortErrorKind::InvalidResponse,
                "provider returned HTTP 503",
            ),
            (
                Ok(response(200, b"not-json")),
                PortErrorKind::InvalidResponse,
                "provider returned invalid JSON",
            ),
            (
                Err(PortError::new(
                    PortErrorKind::Timeout,
                    "provider boundary timed out",
                )),
                PortErrorKind::Timeout,
                "provider boundary timed out",
            ),
        ];

        for (response, expected_kind, expected_message) in cases {
            let (provider, _) = provider(response);
            let result = provider
                .query(request(
                    "rdap",
                    "domain",
                    BTreeMap::from([("target".into(), json!("example.com"))]),
                ))
                .await;
            let Err(error) = result else {
                unreachable!("provider failure fixture unexpectedly succeeded");
            };
            assert_eq!(error.kind, expected_kind);
            assert_eq!(error.message, expected_message);
        }
    }

    #[tokio::test]
    async fn missing_credentials_fail_before_the_http_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let (provider, requests) = provider(Ok(response(200, b"{}")));
        let mut request = request(
            "shodan",
            "host",
            BTreeMap::from([("target".into(), json!("192.0.2.1"))]),
        );
        request.secret_env = Some("SUGRA_TEST_CREDENTIAL_THAT_MUST_NOT_EXIST_7F4A".into());

        let Err(error) = provider.query(request).await else {
            return Err("missing credential unexpectedly succeeded".into());
        };
        assert_eq!(error.kind, PortErrorKind::Unavailable);
        assert_eq!(error.message, "provider credential is not configured");
        assert!(
            requests
                .lock()
                .map_err(|_| "test request lock failed")?
                .is_empty()
        );
        Ok(())
    }

    #[tokio::test]
    async fn missing_hibp_credentials_fail_before_the_http_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let (provider, requests) = provider(Ok(response(200, b"[]")));
        let mut request = request(
            "hibp",
            "stealer-logs-domain",
            BTreeMap::from([("target".into(), json!("example.com"))]),
        );
        request.secret_env = Some("SUGRA_TEST_HIBP_CREDENTIAL_THAT_MUST_NOT_EXIST_4CF1".into());

        let Err(error) = provider.query(request).await else {
            return Err("missing HIBP credential unexpectedly succeeded".into());
        };
        assert_eq!(error.kind, PortErrorKind::Unavailable);
        assert_eq!(error.message, "provider credential is not configured");
        assert!(
            requests
                .lock()
                .map_err(|_| "test request lock failed")?
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn every_authenticated_provider_uses_its_declared_credential_location()
    -> Result<(), Box<dyn std::error::Error>> {
        let header_cases = [
            ("hibp", "hibp-api-key", "fixture"),
            ("abuseipdb", "key", "fixture"),
            ("otx", "x-otx-api-key", "fixture"),
            ("cloudflare-radar", "authorization", "Bearer fixture"),
            ("urlscan", "api-key", "fixture"),
        ];
        for (provider, header, expected) in header_cases {
            let mut url = Url::parse("https://provider.example/resource")?;
            let mut headers = BTreeMap::new();
            inject_secret(provider, &mut url, &mut headers, "fixture")?;
            assert_eq!(headers.get(header).map(String::as_str), Some(expected));
        }

        let mut shodan = Url::parse("https://provider.example/resource")?;
        inject_secret("shodan", &mut shodan, &mut BTreeMap::new(), "fixture")?;
        assert_eq!(shodan.query(), Some("key=fixture"));

        let mut ipinfo = Url::parse("https://provider.example/resource")?;
        inject_secret("ipinfo", &mut ipinfo, &mut BTreeMap::new(), "fixture")?;
        assert_eq!(ipinfo.query(), Some("token=fixture"));

        let Err(error) = inject_secret(
            "unknown-provider",
            &mut Url::parse("https://provider.example/resource")?,
            &mut BTreeMap::new(),
            "fixture",
        ) else {
            return Err("unknown provider accepted a credential".into());
        };
        assert_eq!(error.kind, PortErrorKind::Unavailable);
        Ok(())
    }
}
