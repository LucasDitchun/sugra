//! Capability-oriented implementations shared by the 147 compiled descriptors.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use scraper::{Html, Selector};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sugra_core::{
    Catalog, CommandKind, CommandRequest, DnsQuery, DnsRecordType, HttpMethod, HttpRequest,
    PortError, PortErrorKind, ProviderRequest, ScanContext, ScanError, ScanErrorKind, Scanner,
    ScannerRegistry, ServiceBundle, TcpRequest, TlsRequest, UdpRequest,
};
use sugra_domain::{
    Confidence, Diagnostic, Evidence, ExecutionStatus, Finding, ScanRequest, ScanResult,
    ScannerDescriptor, Severity, Target, TargetKind,
};
use url::Url;

use crate::catalog_data::definitions;
use crate::definition::{BuiltinError, Builtins, Operation, ScannerDefinition};

/// Constructs the complete validated built-in catalog and implementation registry.
///
/// # Errors
///
/// Returns a built-in construction error when compiled metadata violates a
/// domain, catalog, registry, count, or identity-set invariant.
pub fn build_builtins(services: &ServiceBundle) -> Result<Builtins, BuiltinError> {
    let definitions = definitions()?;
    let descriptors: Vec<ScannerDescriptor> = definitions
        .iter()
        .map(|definition| definition.descriptor.clone())
        .collect();
    let catalog = Catalog::new(descriptors)?.require_count(147)?;
    let scanners: Vec<Arc<dyn Scanner>> = definitions
        .into_iter()
        .map(|definition| {
            Arc::new(BuiltinScanner::new(definition, services.clone())) as Arc<dyn Scanner>
        })
        .collect();
    let registry = ScannerRegistry::new(scanners)?;
    if registry.len() != catalog.len() {
        let missing = catalog
            .iter()
            .find(|descriptor| registry.get(&descriptor.id).is_none())
            .map_or_else(
                || sugra_domain::ScannerId::new("catalog-registry-mismatch"),
                |descriptor| Ok(descriptor.id.clone()),
            )?;
        return Err(BuiltinError::SetMismatch(missing));
    }
    Ok(Builtins { catalog, registry })
}

struct BuiltinScanner {
    descriptor: ScannerDescriptor,
    operation: Operation,
    services: ServiceBundle,
}

impl BuiltinScanner {
    fn new(definition: ScannerDefinition, services: ServiceBundle) -> Self {
        Self {
            descriptor: definition.descriptor,
            operation: definition.operation,
            services,
        }
    }
}

#[async_trait]
impl Scanner for BuiltinScanner {
    fn descriptor(&self) -> &ScannerDescriptor {
        &self.descriptor
    }

    async fn scan(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        if request.scanner_id != self.descriptor.id {
            return Err(ScanError::new(
                ScanErrorKind::InvalidInput,
                "request scanner ID does not match implementation",
            ));
        }
        if context.cancellation.is_cancelled() {
            return Err(ScanError::new(ScanErrorKind::Cancelled, "scan cancelled"));
        }
        match self.operation {
            Operation::Dns => self.scan_dns(request, context).await,
            Operation::Http => self.scan_http(request, context).await,
            Operation::Tls => self.scan_tls(request, context).await,
            Operation::Registry | Operation::Intelligence => {
                self.scan_providers(request, context).await
            }
            Operation::Tcp => self.scan_tcp(request, context).await,
            Operation::Udp => self.scan_udp(request, context).await,
            Operation::Command => self.scan_command(request, context).await,
            Operation::Local => self.scan_local(request, context),
        }
    }
}

impl BuiltinScanner {
    async fn scan_dns(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let name = dns_name(&request.target)?;
        let record_types = dns_types(self.descriptor.id.as_str(), request);
        let records = self
            .services
            .dns
            .query(DnsQuery {
                name: name.clone(),
                record_types: record_types.clone(),
                budget: request.budget,
            })
            .await
            .map_err(scan_error_from_port)?;
        let evidence = vec![Evidence {
            kind: "dns-records".into(),
            source: name,
            observation: json!({
                "requested_types": record_types,
                "records": records,
            }),
            observed_at: context.clock.now(),
        }];
        let mut findings = Vec::new();
        let id = self.descriptor.id.as_str();
        let records = evidence[0]
            .observation
            .get("records")
            .and_then(Value::as_array);
        if id == "dnssec" && !record_types.is_empty() && records.is_none_or(Vec::is_empty) {
            findings.push(finding(
                "dnssec-not-observed",
                "DNSSEC material was not observed",
                Severity::Low,
                Confidence::Confirmed,
                0,
            ));
        }
        if id == "dns-caa-checker" && records.is_some_and(Vec::is_empty) {
            findings.push(finding(
                "caa-not-observed",
                "No CAA policy was observed",
                Severity::Low,
                Confidence::Confirmed,
                0,
            ));
        }
        Ok(ScanResult::completed(evidence, findings))
    }

    async fn scan_http(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let base = base_url(&request.target)?;
        let id = self.descriptor.id.as_str();
        let mut queue: VecDeque<Url> = http_paths(id)
            .into_iter()
            .filter_map(|path| base.join(path).ok())
            .collect();
        let methods = http_methods(id);
        let mut seen = BTreeSet::new();
        let mut evidence = Vec::new();
        let mut findings = Vec::new();
        let mut diagnostics = Vec::new();
        let crawl = is_crawler(id);

        while let Some(url) = queue.pop_front() {
            if evidence.len() >= request.budget.max_requests
                || !seen.insert(url.as_str().to_owned())
            {
                continue;
            }
            for method in &methods {
                if evidence.len() >= request.budget.max_requests {
                    break;
                }
                let mut headers = BTreeMap::new();
                if id == "cors-misconfiguration-scanner" {
                    headers.insert("origin".into(), "https://scope-check.invalid".into());
                }
                let response = self
                    .services
                    .http
                    .execute(HttpRequest {
                        url: url.clone(),
                        method: *method,
                        headers,
                        body: Vec::new(),
                        max_redirects: if id == "redirect-chain" { 10 } else { 3 },
                        budget: request.budget,
                        scope: request.scope.clone(),
                    })
                    .await;
                match response {
                    Ok(response) => {
                        let index = evidence.len();
                        let metrics = document_metrics(&response.body);
                        analyze_http(id, &response, &metrics, index, &mut findings);
                        if crawl && *method == HttpMethod::Get {
                            enqueue_links(
                                &response.final_url,
                                &response.body,
                                &request.scope,
                                &mut queue,
                            );
                        }
                        evidence.push(Evidence {
                            kind: "http-observation".into(),
                            source: response.final_url.as_str().into(),
                            observation: json!({
                                "method": format!("{method:?}").to_ascii_uppercase(),
                                "status": response.status,
                                "headers": response.headers,
                                "bytes": response.body.len(),
                                "sha256": hex::encode(Sha256::digest(&response.body)),
                                "document": metrics,
                                "duration_ms": response.duration_ms,
                            }),
                            observed_at: context.clock.now(),
                        });
                    }
                    Err(error) => diagnostics.push(Diagnostic {
                        kind: format!("{:?}", error.kind).to_ascii_lowercase(),
                        message: error.message,
                    }),
                }
            }
        }
        if evidence.is_empty() {
            let first = diagnostics
                .first()
                .map_or("HTTP observation failed", |diagnostic| {
                    diagnostic.message.as_str()
                });
            return Err(ScanError::new(ScanErrorKind::Transport, first));
        }
        Ok(ScanResult {
            status: if diagnostics.is_empty() {
                ExecutionStatus::Completed
            } else {
                ExecutionStatus::Partial
            },
            findings,
            evidence,
            diagnostics,
        })
    }

    async fn scan_tls(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let (host, port) = tls_endpoint(&request.target)?;
        let observation = self
            .services
            .tls
            .handshake(TlsRequest {
                host: host.clone(),
                port,
                budget: request.budget,
                scope: request.scope.clone(),
            })
            .await
            .map_err(scan_error_from_port)?;
        let mut findings = Vec::new();
        if observation.protocol.contains("TLSv1_2") {
            findings.push(finding(
                "tls-modernization",
                "TLS 1.2 was negotiated; verify TLS 1.3 availability",
                Severity::Info,
                Confidence::Confirmed,
                0,
            ));
        }
        Ok(ScanResult::completed(
            vec![Evidence {
                kind: "tls-handshake".into(),
                source: format!("{host}:{port}"),
                observation: serde_json::to_value(observation).map_err(|_| {
                    ScanError::new(
                        ScanErrorKind::Internal,
                        "TLS observation serialization failed",
                    )
                })?,
                observed_at: context.clock.now(),
            }],
            findings,
        ))
    }

    async fn scan_providers(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let calls = provider_calls(self.descriptor.id.as_str(), &request.target);
        let mut evidence = Vec::new();
        let mut diagnostics = Vec::new();
        for call in calls {
            let response = self
                .services
                .provider
                .query(ProviderRequest {
                    provider: call.provider.into(),
                    operation: call.operation.into(),
                    query: provider_query(call.provider, &request.target),
                    secret_env: call.secret_env.map(str::to_owned),
                    budget: request.budget,
                })
                .await;
            match response {
                Ok(response) => evidence.push(Evidence {
                    kind: "provider-observation".into(),
                    source: response.provider,
                    observation: redact_json(response.data),
                    observed_at: context.clock.now(),
                }),
                Err(error) => diagnostics.push(Diagnostic {
                    kind: format!("{:?}", error.kind).to_ascii_lowercase(),
                    message: error.message,
                }),
            }
        }
        if evidence.is_empty() {
            let message = diagnostics
                .first()
                .map_or("all providers are unavailable", |diagnostic| {
                    diagnostic.message.as_str()
                });
            return Err(ScanError::new(
                ScanErrorKind::DependencyUnavailable,
                message,
            ));
        }
        Ok(ScanResult {
            status: if diagnostics.is_empty() {
                ExecutionStatus::Completed
            } else {
                ExecutionStatus::Partial
            },
            findings: Vec::new(),
            evidence,
            diagnostics,
        })
    }

    async fn scan_tcp(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let targets = network_hosts(&request.target, request.budget.max_requests)?;
        let ports = tcp_ports(self.descriptor.id.as_str(), request);
        let mut evidence = Vec::new();
        let mut diagnostics = Vec::new();
        for host in targets {
            for port in &ports {
                if evidence.len() + diagnostics.len() >= request.budget.max_requests {
                    break;
                }
                let response = self
                    .services
                    .tcp
                    .execute(TcpRequest {
                        host: host.clone(),
                        port: *port,
                        payload: tcp_payload(self.descriptor.id.as_str(), *port),
                        budget: request.budget,
                        scope: request.scope.clone(),
                    })
                    .await;
                match response {
                    Ok(response) => evidence.push(Evidence {
                        kind: "tcp-observation".into(),
                        source: response.endpoint,
                        observation: json!({
                            "open": true,
                            "bytes": response.bytes.len(),
                            "sha256": hex::encode(Sha256::digest(&response.bytes)),
                            "banner": safe_text(&response.bytes, 512),
                            "duration_ms": response.duration_ms,
                        }),
                        observed_at: context.clock.now(),
                    }),
                    Err(error) => diagnostics.push(Diagnostic {
                        kind: format!("{:?}", error.kind).to_ascii_lowercase(),
                        message: format!("{host}:{port}: {}", error.message),
                    }),
                }
            }
        }
        network_result(evidence, diagnostics)
    }

    async fn scan_udp(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let targets = network_hosts(&request.target, request.budget.max_requests)?;
        let ports = udp_ports(self.descriptor.id.as_str());
        let mut evidence = Vec::new();
        let mut diagnostics = Vec::new();
        for host in targets {
            for port in &ports {
                let response = self
                    .services
                    .udp
                    .execute(UdpRequest {
                        host: host.clone(),
                        port: *port,
                        payload: udp_payload(*port),
                        budget: request.budget,
                        scope: request.scope.clone(),
                    })
                    .await;
                match response {
                    Ok(response) => evidence.push(Evidence {
                        kind: "udp-observation".into(),
                        source: response.endpoint,
                        observation: json!({
                            "responded": true,
                            "bytes": response.bytes.len(),
                            "sha256": hex::encode(Sha256::digest(&response.bytes)),
                            "duration_ms": response.duration_ms,
                        }),
                        observed_at: context.clock.now(),
                    }),
                    Err(error) => diagnostics.push(Diagnostic {
                        kind: format!("{:?}", error.kind).to_ascii_lowercase(),
                        message: format!("{host}:{port}: {}", error.message),
                    }),
                }
            }
        }
        network_result(evidence, diagnostics)
    }

    async fn scan_command(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let kind = command_kind(self.descriptor.id.as_str());
        let response = self
            .services
            .command
            .execute(CommandRequest {
                kind,
                target: request.target.clone(),
                budget: request.budget,
                scope: request.scope.clone(),
            })
            .await
            .map_err(scan_error_from_port)?;
        Ok(ScanResult::completed(
            vec![Evidence {
                kind: "platform-command".into(),
                source: format!("{kind:?}"),
                observation: json!({
                    "exit_code": response.exit_code,
                    "stdout": redact_text(&response.stdout),
                    "stderr": redact_text(&response.stderr),
                    "duration_ms": response.duration_ms,
                }),
                observed_at: context.clock.now(),
            }],
            Vec::new(),
        ))
    }

    fn scan_local(
        &self,
        request: &ScanRequest,
        context: &ScanContext,
    ) -> Result<ScanResult, ScanError> {
        let id = self.descriptor.id.as_str();
        if id == "jwt-token-analyzer" {
            return scan_jwt(request, context);
        }
        let canonical = request.target.canonical();
        let host = request.target.host().unwrap_or(&canonical);
        let tokens = wordlist(host);
        Ok(ScanResult::completed(
            vec![Evidence {
                kind: "generated-wordlist".into(),
                source: id.into(),
                observation: json!({"tokens": tokens}),
                observed_at: context.clock.now(),
            }],
            Vec::new(),
        ))
    }
}

fn dns_name(target: &Target) -> Result<String, ScanError> {
    match target {
        Target::Domain(value) => Ok(value.clone()),
        Target::Url(value) => value
            .host_str()
            .map(str::to_owned)
            .ok_or_else(|| ScanError::new(ScanErrorKind::InvalidInput, "URL has no host")),
        Target::Email(value) => value
            .rsplit_once('@')
            .map(|(_, domain)| domain.to_owned())
            .ok_or_else(|| ScanError::new(ScanErrorKind::InvalidInput, "email has no domain")),
        Target::Ip(address) => Ok(reverse_name(*address)),
        Target::HostPort { host, .. } => Ok(host.clone()),
        Target::Cidr(_) | Target::Asn(_) | Target::Opaque(_) => Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "scanner requires a DNS-capable target",
        )),
    }
}

fn reverse_name(address: std::net::IpAddr) -> String {
    match address {
        std::net::IpAddr::V4(address) => {
            let [a, b, c, d] = address.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa.")
        }
        std::net::IpAddr::V6(address) => {
            let hex = hex::encode(address.octets());
            format!(
                "{}.ip6.arpa.",
                hex.chars()
                    .rev()
                    .map(|value| value.to_string())
                    .collect::<Vec<_>>()
                    .join(".")
            )
        }
    }
}

fn dns_types(id: &str, request: &ScanRequest) -> Vec<DnsRecordType> {
    if id == "dns-records" {
        if let Some(values) = request.options.get("types").and_then(Value::as_array) {
            let parsed: Vec<DnsRecordType> = values
                .iter()
                .filter_map(Value::as_str)
                .filter_map(parse_dns_type)
                .collect();
            if !parsed.is_empty() {
                return parsed;
            }
        }
        return vec![
            DnsRecordType::A,
            DnsRecordType::Aaaa,
            DnsRecordType::Cname,
            DnsRecordType::Mx,
            DnsRecordType::Ns,
            DnsRecordType::Txt,
            DnsRecordType::Soa,
        ];
    }
    if id.contains("dnssec") {
        vec![DnsRecordType::Ds, DnsRecordType::Dnskey]
    } else if id.contains("caa") {
        vec![DnsRecordType::Caa]
    } else if id.contains("txt") || id.contains("spf") || id == "email-config" {
        vec![DnsRecordType::Txt, DnsRecordType::Mx]
    } else if id.contains("reverse") {
        vec![DnsRecordType::Ptr]
    } else if id.contains("nameserver") || id.starts_with("ns-") {
        vec![DnsRecordType::Ns, DnsRecordType::A, DnsRecordType::Aaaa]
    } else {
        vec![DnsRecordType::A, DnsRecordType::Aaaa, DnsRecordType::Cname]
    }
}

fn parse_dns_type(value: &str) -> Option<DnsRecordType> {
    match value.to_ascii_uppercase().as_str() {
        "A" => Some(DnsRecordType::A),
        "AAAA" => Some(DnsRecordType::Aaaa),
        "CNAME" => Some(DnsRecordType::Cname),
        "MX" => Some(DnsRecordType::Mx),
        "NS" => Some(DnsRecordType::Ns),
        "SOA" => Some(DnsRecordType::Soa),
        "TXT" => Some(DnsRecordType::Txt),
        "SRV" => Some(DnsRecordType::Srv),
        "CAA" => Some(DnsRecordType::Caa),
        "DNSKEY" => Some(DnsRecordType::Dnskey),
        "DS" => Some(DnsRecordType::Ds),
        "PTR" => Some(DnsRecordType::Ptr),
        _ => None,
    }
}

fn base_url(target: &Target) -> Result<Url, ScanError> {
    match target {
        Target::Url(value) => Ok(value.clone()),
        Target::Domain(value) | Target::HostPort { host: value, .. } => {
            Url::parse(&format!("https://{value}/")).map_err(|_| {
                ScanError::new(ScanErrorKind::InvalidInput, "could not build target URL")
            })
        }
        Target::Ip(value) => Url::parse(&format!("https://{value}/"))
            .map_err(|_| ScanError::new(ScanErrorKind::InvalidInput, "could not build target URL")),
        Target::Email(value) => value
            .rsplit_once('@')
            .and_then(|(_, domain)| Url::parse(&format!("https://{domain}/")).ok())
            .ok_or_else(|| ScanError::new(ScanErrorKind::InvalidInput, "email has no web domain")),
        Target::Cidr(_) | Target::Asn(_) | Target::Opaque(_) => Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "scanner requires a web-capable target",
        )),
    }
}

fn is_crawler(id: &str) -> bool {
    matches!(
        id,
        "broken-links"
            | "crawler"
            | "content-discovery"
            | "email-harvester"
            | "javascript-file-analyzer"
            | "dom-sink-scanner"
            | "dependency-js-cdn-scanner"
            | "third-party-script-risk-profiler"
            | "static-asset-fingerprinter"
    )
}

fn http_paths(id: &str) -> Vec<&'static str> {
    match id {
        "crawl-rules" => vec!["/robots.txt"],
        "sitemap-parsing" => vec!["/sitemap.xml", "/sitemap_index.xml"],
        "security-txt" | "security-contact-gap-finder" => {
            vec!["/.well-known/security.txt", "/security.txt", "/"]
        }
        "exposed-env-files" => vec!["/.env", "/.env.production", "/.env.local"],
        "git-repo-exposure-check" => vec!["/.git/HEAD", "/.git/config"],
        "api-schema-grabber" => vec!["/openapi.json", "/swagger.json", "/api-docs", "/graphql"],
        "exposed-api-endpoints" => vec!["/api", "/api/v1", "/swagger", "/openapi.json"],
        "directory-finder" => vec!["/admin/", "/backup/", "/config/", "/uploads/"],
        "graphql-introspection-probe" => vec!["/graphql"],
        "file-upload-surface-finder" => vec!["/", "/upload", "/uploads"],
        "cloud-bucket-exposure" | "cloud-service-enumeration" => {
            vec!["/", "/.well-known/assetlinks.json"]
        }
        _ => vec!["/"],
    }
}

fn http_methods(id: &str) -> Vec<HttpMethod> {
    if id == "http-method-enumerator" {
        vec![HttpMethod::Get, HttpMethod::Head, HttpMethod::Options]
    } else {
        vec![HttpMethod::Get]
    }
}

#[derive(Debug, serde::Serialize)]
struct DocumentMetrics {
    title: Option<String>,
    links: usize,
    scripts: usize,
    forms: usize,
    inputs: usize,
    comments: usize,
}

fn document_metrics(body: &[u8]) -> DocumentMetrics {
    let text = String::from_utf8_lossy(body);
    let document = Html::parse_document(&text);
    let count = |selector: &str| {
        Selector::parse(selector)
            .ok()
            .map_or(0, |selector| document.select(&selector).count())
    };
    let title = Selector::parse("title").ok().and_then(|selector| {
        document.select(&selector).next().map(|element| {
            element
                .text()
                .collect::<String>()
                .trim()
                .chars()
                .take(256)
                .collect()
        })
    });
    DocumentMetrics {
        title,
        links: count("a[href]"),
        scripts: count("script"),
        forms: count("form"),
        inputs: count("input, textarea, select"),
        comments: text.matches("<!--").count(),
    }
}

fn enqueue_links(
    base: &Url,
    body: &[u8],
    scope: &sugra_domain::ScopeGrant,
    queue: &mut VecDeque<Url>,
) {
    let document = Html::parse_document(&String::from_utf8_lossy(body));
    let Ok(selector) = Selector::parse("a[href], script[src]") else {
        return;
    };
    for element in document.select(&selector) {
        let candidate = element
            .value()
            .attr("href")
            .or_else(|| element.value().attr("src"))
            .and_then(|value| base.join(value).ok());
        if let Some(candidate) = candidate
            && Target::parse(TargetKind::Url, candidate.as_str())
                .ok()
                .is_some_and(|target| scope.allows(&target))
        {
            queue.push_back(candidate);
        }
    }
}

fn analyze_http(
    id: &str,
    response: &sugra_core::HttpResponse,
    metrics: &DocumentMetrics,
    evidence: usize,
    findings: &mut Vec<Finding>,
) {
    if id == "broken-links" && response.status >= 400 {
        findings.push(finding(
            "broken-link",
            "A linked resource returned an error status",
            Severity::Low,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if id == "exposed-env-files"
        && response.status == 200
        && contains_any(
            &response.body,
            &[b"=".as_slice(), b"SECRET", b"PASSWORD", b"TOKEN"],
        )
    {
        findings.push(finding(
            "environment-file-exposed",
            "An environment-style file is publicly readable",
            Severity::Critical,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if id == "git-repo-exposure-check"
        && response.status == 200
        && contains_any(&response.body, &[b"ref: refs/", b"[core]"])
    {
        findings.push(finding(
            "git-metadata-exposed",
            "Repository metadata is publicly readable",
            Severity::High,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if matches!(
        id,
        "http-headers" | "http-security-features" | "csp-deep-analyzer"
    ) {
        for header in [
            "content-security-policy",
            "strict-transport-security",
            "x-content-type-options",
        ] {
            if !response.headers.contains_key(header) {
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
    if id == "clickjacking-test"
        && !response.headers.contains_key("x-frame-options")
        && !response
            .headers
            .get("content-security-policy")
            .is_some_and(|value| value.to_ascii_lowercase().contains("frame-ancestors"))
    {
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
            .is_some_and(|value| value == "*" || value == "https://scope-check.invalid")
    {
        findings.push(finding(
            "permissive-cors",
            "A permissive cross-origin policy was observed",
            Severity::Medium,
            Confidence::Confirmed,
            evidence,
        ));
    }
    if id == "file-upload-surface-finder" && metrics.inputs > 0 {
        let text = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
        if text.contains("type=\"file\"") || text.contains("type='file'") {
            findings.push(finding(
                "upload-surface",
                "A file upload input was observed",
                Severity::Info,
                Confidence::Confirmed,
                evidence,
            ));
        }
    }
}

fn contains_any(body: &[u8], needles: &[&[u8]]) -> bool {
    needles.iter().any(|needle| {
        body.windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
    })
}

#[derive(Clone, Copy)]
struct ProviderCall {
    provider: &'static str,
    operation: &'static str,
    secret_env: Option<&'static str>,
}

fn provider_calls(id: &str, target: &Target) -> Vec<ProviderCall> {
    let call = |provider, operation, secret_env| ProviderCall {
        provider,
        operation,
        secret_env,
    };
    match id {
        "ct-log-query" | "subdomain-enum" | "associated-hosts" | "certificate-authority-recon" => {
            vec![call("crtsh", "query", None)]
        }
        "archive-history" => vec![call("wayback", "cdx", None)],
        "shodan" | "reverse-ip-lookup" => vec![call("shodan", "host", Some("SHODAN_API_KEY"))],
        "virustotal-scan" => vec![call(
            "virustotal",
            if matches!(target, Target::Ip(_)) {
                "ip"
            } else {
                "domain"
            },
            Some("VIRUSTOTAL_API_KEY"),
        )],
        "breached-credentials-lookup" | "data-leak" => {
            vec![call("hibp", "account", Some("HIBP_API_KEY"))]
        }
        "ssl-labs-report" => vec![call("ssllabs", "analyze", None)],
        value if value.contains("reputation") || value == "threat-feed-correlator" => vec![
            call("abuseipdb", "check", Some("ABUSEIPDB_API_KEY")),
            call("otx", "domain", Some("OTX_API_KEY")),
            call("urlhaus", "host", None),
        ],
        value
            if value.contains("location")
                || value.contains("timezone")
                || value.contains("geo-ip") =>
        {
            vec![call("ipinfo", "lookup", Some("IPINFO_API_KEY"))]
        }
        value if value.contains("malware") || value.contains("phishing") => vec![
            call("virustotal", "domain", Some("VIRUSTOTAL_API_KEY")),
            call("urlhaus", "host", None),
        ],
        _ => vec![call(
            "rdap",
            if matches!(target, Target::Ip(_)) {
                "ip"
            } else {
                "domain"
            },
            None,
        )],
    }
}

fn provider_query(provider: &str, target: &Target) -> BTreeMap<String, Value> {
    let canonical = target.canonical();
    let key = match provider {
        "crtsh" => "q",
        "wayback" => "url",
        "abuseipdb" => "ipAddress",
        "ssllabs" | "urlhaus" => "host",
        _ => "target",
    };
    BTreeMap::from([(key.into(), Value::String(canonical))])
}

fn tls_endpoint(target: &Target) -> Result<(String, u16), ScanError> {
    match target {
        Target::HostPort { host, port } => Ok((host.clone(), *port)),
        Target::Domain(host) => Ok((host.clone(), 443)),
        Target::Url(url) => Ok((
            url.host_str()
                .ok_or_else(|| ScanError::new(ScanErrorKind::InvalidInput, "URL has no host"))?
                .into(),
            url.port_or_known_default().unwrap_or(443),
        )),
        Target::Ip(address) => Ok((address.to_string(), 443)),
        _ => Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "scanner requires a TLS-capable target",
        )),
    }
}

fn network_hosts(target: &Target, limit: usize) -> Result<Vec<String>, ScanError> {
    let hosts = match target {
        Target::Domain(value) => vec![value.clone()],
        Target::Ip(value) => vec![value.to_string()],
        Target::HostPort { host, .. } => vec![host.clone()],
        Target::Url(value) => value
            .host_str()
            .map(|host| vec![host.into()])
            .unwrap_or_default(),
        Target::Cidr(network) => network
            .hosts()
            .take(limit)
            .map(|address| address.to_string())
            .collect(),
        Target::Email(value) => value
            .rsplit_once('@')
            .map(|(_, host)| vec![host.into()])
            .unwrap_or_default(),
        Target::Asn(_) | Target::Opaque(_) => Vec::new(),
    };
    if hosts.is_empty() {
        Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "scanner target has no network host",
        ))
    } else {
        Ok(hosts)
    }
}

fn tcp_ports(id: &str, request: &ScanRequest) -> Vec<u16> {
    if let Some(values) = request.options.get("ports").and_then(Value::as_array) {
        let ports: Vec<u16> = values
            .iter()
            .filter_map(Value::as_str)
            .filter_map(|value| value.parse().ok())
            .filter(|value| *value > 0)
            .collect();
        if !ports.is_empty() {
            return ports;
        }
    }
    if id.contains("ssh") {
        vec![22]
    } else if id.contains("zone") {
        vec![53]
    } else if id.contains("tls") || id.contains("certificate") {
        vec![443]
    } else {
        vec![22, 53, 80, 443, 8080, 8443]
    }
}

fn tcp_payload(id: &str, port: u16) -> Vec<u8> {
    if id.contains("zone") && port == 53 {
        Vec::new()
    } else if matches!(port, 80 | 8080) {
        b"HEAD / HTTP/1.0\r\n\r\n".to_vec()
    } else {
        Vec::new()
    }
}

fn udp_ports(id: &str) -> Vec<u16> {
    if id.contains("ntp") {
        vec![123]
    } else if id.contains("snmp") {
        vec![161]
    } else if id.contains("netbios") {
        vec![137]
    } else {
        vec![53, 123, 161]
    }
}

fn udp_payload(port: u16) -> Vec<u8> {
    match port {
        123 => {
            let mut packet = vec![0_u8; 48];
            packet[0] = 0x1b;
            packet
        }
        161 => vec![
            0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0,
            0x19, 0x02, 0x04, 0x70, 0x65, 0x65, 0x72, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30,
            0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
        ],
        137 => vec![
            0x13, 0x37, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, b'C',
            b'K', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
            b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
            b'A', b'A', b'A', 0x00, 0x00, 0x21, 0x00, 0x01,
        ],
        _ => vec![0_u8; 12],
    }
}

fn command_kind(id: &str) -> CommandKind {
    if id.contains("traceroute") {
        CommandKind::Traceroute
    } else if id.contains("whois") {
        CommandKind::Whois
    } else if id.contains("ssh") {
        CommandKind::SshKeyscan
    } else {
        CommandKind::Ping
    }
}

fn scan_jwt(request: &ScanRequest, context: &ScanContext) -> Result<ScanResult, ScanError> {
    let Target::Opaque(token) = &request.target else {
        return Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "JWT analyzer requires an opaque token",
        ));
    };
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(ScanError::new(
            ScanErrorKind::InvalidInput,
            "JWT must contain three segments",
        ));
    }
    let decode = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    };
    let header = decode(parts[0])
        .ok_or_else(|| ScanError::new(ScanErrorKind::InvalidInput, "JWT header is invalid"))?;
    let payload = decode(parts[1])
        .ok_or_else(|| ScanError::new(ScanErrorKind::InvalidInput, "JWT payload is invalid"))?;
    let mut findings = Vec::new();
    if header
        .get("alg")
        .and_then(Value::as_str)
        .is_some_and(|algorithm| algorithm.eq_ignore_ascii_case("none"))
    {
        findings.push(finding(
            "unsigned-jwt",
            "JWT declares the none algorithm",
            Severity::High,
            Confidence::Confirmed,
            0,
        ));
    }
    Ok(ScanResult::completed(
        vec![Evidence {
            kind: "jwt-structure".into(),
            source: "local-input".into(),
            observation: json!({
                "header": redact_json(header),
                "payload": redact_json(payload),
                "signature_bytes": parts[2].len(),
            }),
            observed_at: context.clock.now(),
        }],
        findings,
    ))
}

fn wordlist(value: &str) -> Vec<String> {
    let base = value
        .split(['.', '-', '_'])
        .filter(|part| part.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect::<BTreeSet<_>>();
    let mut values = BTreeSet::new();
    for token in base {
        values.insert(token.clone());
        for suffix in ["admin", "api", "dev", "prod", "staging", "www"] {
            values.insert(format!("{token}-{suffix}"));
            values.insert(format!("{suffix}-{token}"));
        }
    }
    values.into_iter().take(256).collect()
}

fn network_result(
    evidence: Vec<Evidence>,
    diagnostics: Vec<Diagnostic>,
) -> Result<ScanResult, ScanError> {
    if evidence.is_empty() {
        let message = diagnostics
            .first()
            .map_or("no network endpoint responded", |diagnostic| {
                diagnostic.message.as_str()
            });
        Err(ScanError::new(ScanErrorKind::Transport, message))
    } else {
        Ok(ScanResult {
            status: if diagnostics.is_empty() {
                ExecutionStatus::Completed
            } else {
                ExecutionStatus::Partial
            },
            findings: Vec::new(),
            evidence,
            diagnostics,
        })
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

fn scan_error_from_port(error: PortError) -> ScanError {
    let kind = match error.kind {
        PortErrorKind::Unavailable => ScanErrorKind::DependencyUnavailable,
        PortErrorKind::Timeout | PortErrorKind::RateLimited => ScanErrorKind::Timeout,
        PortErrorKind::OutOfScope => ScanErrorKind::PolicyDenied,
        PortErrorKind::InvalidResponse | PortErrorKind::TooLarge => ScanErrorKind::InvalidResponse,
        PortErrorKind::Transport => ScanErrorKind::Transport,
        PortErrorKind::Internal => ScanErrorKind::Internal,
    };
    ScanError::new(kind, error.message)
}

fn safe_text(bytes: &[u8], limit: usize) -> String {
    redact_text(&String::from_utf8_lossy(&bytes[..bytes.len().min(limit)]))
}

fn redact_text(value: &str) -> String {
    value
        .lines()
        .take(128)
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            if ["password", "secret", "token", "authorization", "api_key"]
                .iter()
                .any(|marker| lower.contains(marker))
            {
                "<redacted>".into()
            } else {
                line.chars().take(512).collect::<String>()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_json(value: Value) -> Value {
    match value {
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    let sensitive = [
                        "password",
                        "secret",
                        "token",
                        "email",
                        "authorization",
                        "key",
                    ]
                    .iter()
                    .any(|marker| key.to_ascii_lowercase().contains(marker));
                    (
                        key,
                        if sensitive {
                            Value::String("<redacted>".into())
                        } else {
                            redact_json(value)
                        },
                    )
                })
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(redact_json).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use async_trait::async_trait;
    use serde_json::json;
    use sugra_core::{
        Clock, CommandPort, CommandResponse, DnsPort, DnsQuery, DnsRecord, DnsRecordType, HttpPort,
        HttpRequest, HttpResponse, PortError, ProviderPort, ProviderRequest, ProviderResponse,
        TcpPort, TcpRequest, TcpResponse, TlsObservation, TlsPort, TlsRequest, UdpPort, UdpRequest,
        UdpResponse,
    };
    use sugra_domain::{Budget, ScanRequest, ScopeGrant, Target, TargetKind};
    use time::OffsetDateTime;
    use tokio_util::sync::CancellationToken;

    use super::*;

    #[derive(Clone, Copy)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH
        }
    }

    struct FakeDns;
    #[async_trait]
    impl DnsPort for FakeDns {
        async fn query(&self, query: DnsQuery) -> Result<Vec<DnsRecord>, PortError> {
            Ok(vec![DnsRecord {
                name: query.name,
                record_type: query
                    .record_types
                    .first()
                    .copied()
                    .unwrap_or(DnsRecordType::A),
                value: "192.0.2.1".into(),
                ttl: Some(300),
            }])
        }
    }

    struct FakeHttp;
    #[async_trait]
    impl HttpPort for FakeHttp {
        async fn execute(&self, request: HttpRequest) -> Result<HttpResponse, PortError> {
            Ok(HttpResponse {
                final_url: request.url,
                status: 200,
                headers: BTreeMap::from([
                    ("content-type".into(), "text/html".into()),
                    (
                        "content-security-policy".into(),
                        "default-src 'self'".into(),
                    ),
                    (
                        "strict-transport-security".into(),
                        "max-age=31536000".into(),
                    ),
                    ("x-content-type-options".into(), "nosniff".into()),
                ]),
                body: b"<html><title>Fixture</title><a href='/next'>Next</a></html>".to_vec(),
                duration_ms: 1,
            })
        }
    }

    struct FakeTcp;
    #[async_trait]
    impl TcpPort for FakeTcp {
        async fn execute(&self, request: TcpRequest) -> Result<TcpResponse, PortError> {
            Ok(TcpResponse {
                endpoint: format!("{}:{}", request.host, request.port),
                bytes: b"fixture-banner".to_vec(),
                duration_ms: 1,
            })
        }
    }

    struct FakeUdp;
    #[async_trait]
    impl UdpPort for FakeUdp {
        async fn execute(&self, request: UdpRequest) -> Result<UdpResponse, PortError> {
            Ok(UdpResponse {
                endpoint: format!("{}:{}", request.host, request.port),
                bytes: vec![1, 2, 3],
                duration_ms: 1,
            })
        }
    }

    struct FakeTls;
    #[async_trait]
    impl TlsPort for FakeTls {
        async fn handshake(&self, _request: TlsRequest) -> Result<TlsObservation, PortError> {
            Ok(TlsObservation {
                protocol: "TLSv1_3".into(),
                cipher_suite: "TLS_AES_256_GCM_SHA384".into(),
                alpn: Some("h2".into()),
                certificate_sha256: vec!["00".repeat(32)],
                duration_ms: 1,
            })
        }
    }

    struct FakeProvider;
    #[async_trait]
    impl ProviderPort for FakeProvider {
        async fn query(&self, request: ProviderRequest) -> Result<ProviderResponse, PortError> {
            Ok(ProviderResponse {
                provider: request.provider,
                data: json!({"fixture": true}),
                duration_ms: 1,
            })
        }
    }

    struct FakeCommand;
    #[async_trait]
    impl CommandPort for FakeCommand {
        async fn execute(&self, _request: CommandRequest) -> Result<CommandResponse, PortError> {
            Ok(CommandResponse {
                exit_code: Some(0),
                stdout: "fixture".into(),
                stderr: String::new(),
                duration_ms: 1,
            })
        }
    }

    fn services() -> ServiceBundle {
        ServiceBundle {
            dns: Arc::new(FakeDns),
            http: Arc::new(FakeHttp),
            tcp: Arc::new(FakeTcp),
            udp: Arc::new(FakeUdp),
            tls: Arc::new(FakeTls),
            command: Arc::new(FakeCommand),
            provider: Arc::new(FakeProvider),
            clock: Arc::new(FixedClock),
        }
    }

    fn target_for(kind: TargetKind, id: &str) -> Result<Target, Box<dyn std::error::Error>> {
        let target = match kind {
            TargetKind::Domain => Target::parse(kind, "example.com")?,
            TargetKind::Ip => Target::parse(kind, "192.0.2.10")?,
            TargetKind::Cidr => Target::parse(kind, "192.0.2.0/30")?,
            TargetKind::Url => Target::parse(kind, "https://example.com/")?,
            TargetKind::HostPort => Target::parse(kind, "example.com:443")?,
            TargetKind::Asn => Target::parse(kind, "AS64496")?,
            TargetKind::Email => Target::parse(kind, "security@example.com")?,
            TargetKind::Opaque if id == "jwt-token-analyzer" => Target::parse(
                kind,
                "eyJhbGciOiJub25lIn0.eyJzdWIiOiJmaXh0dXJlIn0.signature",
            )?,
            TargetKind::Opaque => Target::parse(kind, "example-fixture")?,
        };
        Ok(target)
    }

    #[tokio::test]
    async fn every_built_in_has_an_offline_functional_contract()
    -> Result<(), Box<dyn std::error::Error>> {
        let builtins = build_builtins(&services())?;
        assert_eq!(builtins.catalog.len(), 147);
        assert_eq!(builtins.registry.len(), 147);
        for descriptor in builtins.catalog.iter() {
            let scanner = builtins
                .registry
                .get(&descriptor.id)
                .ok_or_else(|| format!("missing implementation for {}", descriptor.id))?;
            let target = target_for(descriptor.target_kinds[0], descriptor.id.as_str())?;
            let request = ScanRequest {
                scanner_id: descriptor.id.clone(),
                scope: ScopeGrant::exact(&target, true, OffsetDateTime::UNIX_EPOCH),
                target,
                options: BTreeMap::new(),
                budget: Budget {
                    max_requests: 4,
                    ..Budget::default()
                },
            };
            let context = ScanContext {
                run_id: sugra_domain::RunId::new(),
                cancellation: CancellationToken::new(),
                clock: Arc::new(FixedClock),
            };
            let result = scanner
                .scan(&request, &context)
                .await
                .map_err(|error| format!("{} failed its fixture: {error}", descriptor.id))?;
            assert!(
                !result.evidence.is_empty(),
                "{} returned no fixture evidence",
                descriptor.id
            );
        }
        Ok(())
    }

    #[test]
    fn catalog_has_unique_complete_compatibility_mapping() -> Result<(), Box<dyn std::error::Error>>
    {
        let builtins = build_builtins(&services())?;
        let legacy: BTreeSet<_> = builtins
            .catalog
            .iter()
            .filter_map(|descriptor| descriptor.legacy_id)
            .collect();
        assert_eq!(legacy.len(), 147);
        Ok(())
    }
}
