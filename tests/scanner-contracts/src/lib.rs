//! Offline scanner contract fixtures.

/// Expected observable I/O boundary for a built-in scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Boundary {
    /// No external boundary is used.
    Local,
    /// DNS resolver boundary.
    Dns,
    /// HTTP client boundary.
    Http,
    /// TCP client boundary.
    Tcp,
    /// UDP client boundary.
    Udp,
    /// TLS handshake boundary.
    Tls,
    /// Allowlisted platform command boundary.
    Command,
    /// Optional provider boundary.
    Provider,
}

/// One externally observable built-in scanner contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScannerContract {
    /// Canonical scanner ID.
    pub id: &'static str,
    /// Boundary the scanner must invoke for its successful fixture.
    pub boundary: Boundary,
    /// Additional boundaries required by a composite scanner.
    pub supplements: &'static [Boundary],
}

/// Scanner-specific fixture class not yet supplied by this package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingFixture {
    /// A positive response that must trigger the scanner's defining signal.
    PositiveSignal,
    /// A nearby safe response that must not trigger that signal.
    NegativeControl,
    /// A scanner-specific malformed, truncated, or boundary-value response.
    EdgeCase,
}

/// Explicit semantic coverage gap for one scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticGap {
    /// Canonical scanner ID.
    pub id: &'static str,
    /// Missing fixture classes.
    pub missing: &'static [MissingFixture],
}

const STANDARD_SEMANTIC_GAPS: &[MissingFixture] = &[
    MissingFixture::PositiveSignal,
    MissingFixture::NegativeControl,
    MissingFixture::EdgeCase,
];

const NEGATIVE_CONTROL_GAP: &[MissingFixture] = &[MissingFixture::NegativeControl];

const CONTRACT_GROUPS: &[(Boundary, &[&str])] = &[
    (
        Boundary::Provider,
        &[
            "asn-lookup",
            "associated-hosts",
            "autonomous-neighbor-peering-map",
            "bgp-route-analysis",
            "dns-over-https",
            "domain-reputation-check",
            "ip-allocation-history-tracker",
            "ip-info",
            "network-timezone-detection",
            "ns-geo-asn-diversity-analyzer",
            "rdap-lookup",
            "reverse-ip-lookup",
            "rpki-route-validity-check",
            "server-location",
            "archive-history",
            "breached-credentials-lookup",
            "censys",
            "certificate-authority-recon",
            "ct-log-query",
            "data-leak",
            "domain-shadowing-detector",
            "global-ranking",
            "ip-reputation-trending",
            "js-malware-scanner",
            "malware-phishing",
            "pastebin-monitoring",
            "rogue-certificate-check",
            "shodan",
            "ssl-labs-report",
            "subdomain-enum",
            "threat-feed-correlator",
            "virustotal-scan",
            "dark-web-monitoring",
            "geo-ip-spoof-detection",
            "ip-reputation-check",
            "irr-routing-registry-analyzer",
            "passive-dns-history",
        ],
    ),
    (
        Boundary::Dns,
        &[
            "dns-records",
            "dns-sla-latency-monitor",
            "dnssec",
            "domain-info",
            "dual-stack-behavior-profiler",
            "geo-dns-footprint",
            "recursive-nameserver-leak-test",
            "reverse-dns-scan",
            "spf-network-extractor",
            "txt-records",
            "rogue-subdomain-resolver",
            "spf-dkim-dmarc-validator",
            "subdomain-takeover",
            "typosquat-domain-checker",
            "decoy-dns-beacon",
            "dns-caa-checker",
            "dual-stack-diff",
            "email-config",
            "ttl-analysis",
        ],
    ),
    (
        Boundary::Http,
        &[
            "cdn-detection",
            "server-info",
            "api-schema-grabber",
            "autocomplete-vulnerability-checker",
            "broken-links",
            "cache-behavior-analyzer",
            "captcha-presence-checker",
            "carbon-footprint",
            "clickjacking-test",
            "cms-detection",
            "content-discovery",
            "cookie-scope-diff",
            "cookies",
            "cors-misconfiguration-scanner",
            "crawl-rules",
            "crawler",
            "csp-deep-analyzer",
            "dependency-js-cdn-scanner",
            "directory-finder",
            "dom-sink-scanner",
            "email-harvester",
            "embedded-object-hunter",
            "favicon-hashing",
            "file-upload-surface-finder",
            "form-grabber",
            "graphql-introspection-probe",
            "hidden-parameter-discovery",
            "html-comments-extractor",
            "html5-feature-abuse-detector",
            "http-method-enumerator",
            "javascript-file-analyzer",
            "javascript-obfuscation-detector",
            "lazy-load-resource-finder",
            "login-page-brute-identifier",
            "multi-language-url-tester",
            "performance-monitoring",
            "pixel-tracker-finder",
            "quality-metrics",
            "redirect-chain",
            "seo-abuse-detector",
            "session-cookie-lifetime-checker",
            "sitemap",
            "social-media",
            "static-asset-fingerprinter",
            "technology-stack",
            "third-party-integrations",
            "third-party-script-risk-profiler",
            "virtual-host-fuzzer",
            "websocket-endpoint-sniffer",
            "attack-surface-delta",
            "bug-bounty-program-finder",
            "cloud-bucket-exposure",
            "cloud-service-enumeration",
            "exposed-api-endpoints",
            "exposed-env-files",
            "firewall-detection",
            "git-repo-exposure-check",
            "http-headers",
            "http-security",
            "open-redirect-finder",
            "passive-cve-mapper",
            "privacy-gdpr",
            "rate-limit-waf-bypass-test",
            "security-changelog-diff",
            "security-contact-gap-finder",
            "security-txt",
            "session-hijacking-passive",
        ],
    ),
    (
        Boundary::Tls,
        &[
            "http2-http3-checker",
            "network-certificate-inventory",
            "ssl-chain",
            "ssl-expiry",
            "tls-cipher-suites",
            "tls-handshake",
            "tls-session-resumption-map",
            "ssl-pinning-check",
            "tls-security-config",
        ],
    ),
    (
        Boundary::Tcp,
        &[
            "ip-range-scanner",
            "ipv6-reachability-test",
            "open-ports",
            "zonetransfer",
        ],
    ),
    (
        Boundary::Udp,
        &[
            "ntp-info-leak-checker",
            "snmp-public-community-checker",
            "udp-service-sampler",
            "netbios-name-query",
            "snmp-bulk-walk",
        ],
    ),
    (
        Boundary::Command,
        &[
            "icmp-reachability-matrix",
            "ssh-banner-key-fingerprinter",
            "traceroute",
            "whois-lookup",
        ],
    ),
    (
        Boundary::Local,
        &["custom-wordlist-generator", "jwt-token-analyzer"],
    ),
];

/// Returns the explicit contract matrix for every built-in scanner.
#[must_use]
pub fn contracts() -> Vec<ScannerContract> {
    CONTRACT_GROUPS
        .iter()
        .flat_map(|(boundary, ids)| {
            ids.iter().map(|id| ScannerContract {
                id,
                boundary: *boundary,
                supplements: supplemental_boundaries(id),
            })
        })
        .collect()
}

fn supplemental_boundaries(id: &str) -> &'static [Boundary] {
    match id {
        "cdn-detection" => &[Boundary::Dns],
        "attack-surface-delta" => &[Boundary::Provider, Boundary::Dns, Boundary::Tcp],
        "firewall-detection" => &[Boundary::Tcp],
        "performance-monitoring" | "security-contact-gap-finder" => &[Boundary::Provider],
        _ => &[],
    }
}

/// Returns semantic gaps not covered by the offline boundary harness.
///
/// These entries prevent the boundary-level checks from being mistaken for
/// scanner-specific detection parity.
#[must_use]
pub fn semantic_gaps() -> Vec<SemanticGap> {
    contracts()
        .into_iter()
        .filter_map(|contract| {
            let missing = match contract.id {
                "dnssec"
                | "dual-stack-behavior-profiler"
                | "dual-stack-diff"
                | "ttl-analysis"
                | "typosquat-domain-checker"
                | "passive-dns-history"
                | "rpki-route-validity-check"
                | "rogue-certificate-check"
                | "performance-monitoring"
                | "domain-reputation-check"
                | "ip-reputation-check" => &[],
                "email-config" => NEGATIVE_CONTROL_GAP,
                _ => STANDARD_SEMANTIC_GAPS,
            };
            (!missing.is_empty()).then_some(SemanticGap {
                id: contract.id,
                missing,
            })
        })
        .collect()
}
