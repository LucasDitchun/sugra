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
            ("virustotal", "domain") => ("https://www.virustotal.com/api/v3/domains", &[]),
            ("virustotal", "ip") => ("https://www.virustotal.com/api/v3/ip_addresses", &[]),
            ("hibp", "account") => ("https://haveibeenpwned.com/api/v3/breachedaccount", &[]),
            ("hibp", "domain") => ("https://haveibeenpwned.com/api/v3/breacheddomain", &[]),
            ("abuseipdb", "check") => ("https://api.abuseipdb.com/api/v2/check", &[]),
            ("ipinfo", "lookup") => ("https://ipinfo.io", &[]),
            ("otx", "domain") => ("https://otx.alienvault.com/api/v1/indicators/domain", &[]),
            ("urlhaus", "host") => ("https://urlhaus-api.abuse.ch/v1/host/", &[]),
            ("ssllabs", "analyze") => ("https://api.ssllabs.com/api/v3/analyze", &[]),
            ("urlscan", "search") => ("https://urlscan.io/api/v1/search/", &[("size", "100")]),
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
            | ("hibp", "account" | "domain")
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
        "shodan" => {
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::{Value, json};
    use sugra_core::ProviderRequest;
    use sugra_domain::Budget;

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
        Ok(())
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
    fn urlscan_search_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = endpoint_for(&request(
            "urlscan",
            "search",
            BTreeMap::from([("q".into(), json!("domain:example.com"))]),
        ))?;
        let pairs: BTreeMap<_, _> = endpoint.query_pairs().into_owned().collect();
        assert_eq!(
            pairs.get("q").map(String::as_str),
            Some("domain:example.com")
        );
        assert_eq!(pairs.get("size").map(String::as_str), Some("100"));
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
}
