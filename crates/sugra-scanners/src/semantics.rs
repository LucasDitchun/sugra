//! Explicit semantic ownership for every published scanner.

/// Boundary family selected by a scanner's semantic contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BoundaryFamily {
    Dns,
    Http,
    Tls,
    Provider,
    Tcp,
    Udp,
    Command,
    Local,
}

/// Reusable analysis strategy with scanner-specific ownership layered above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Analyzer {
    DnsRecords,
    DnsPolicy,
    DnsPerformance,
    DnsTopology,
    DnsExposure,
    WebInventory,
    WebCrawler,
    WebMetadata,
    WebHeaders,
    WebBrowserRisk,
    WebApi,
    WebContentRisk,
    WebPrivacy,
    WebPerformance,
    WebChange,
    WebExposure,
    WebDetection,
    WebFuzz,
    ProviderRegistration,
    ProviderRouting,
    ProviderGeo,
    ProviderHistory,
    ProviderAsset,
    ProviderReputation,
    ProviderLeaks,
    ProviderCertificates,
    ProviderThreat,
    ProviderPerformance,
    TlsHandshake,
    TlsChain,
    TlsExpiry,
    TlsCipher,
    TlsProtocol,
    TlsPinning,
    TcpPorts,
    TcpRange,
    TcpCertificate,
    TcpDnsTransfer,
    TcpTlsState,
    UdpNtp,
    UdpSnmp,
    UdpNetbios,
    UdpSampler,
    CommandReachability,
    CommandPath,
    CommandWhois,
    CommandSsh,
    LocalWordlist,
    LocalJwt,
}

impl Analyzer {
    pub(crate) const fn family(self) -> BoundaryFamily {
        match self {
            Self::DnsRecords
            | Self::DnsPolicy
            | Self::DnsPerformance
            | Self::DnsTopology
            | Self::DnsExposure => BoundaryFamily::Dns,
            Self::WebInventory
            | Self::WebCrawler
            | Self::WebMetadata
            | Self::WebHeaders
            | Self::WebBrowserRisk
            | Self::WebApi
            | Self::WebContentRisk
            | Self::WebPrivacy
            | Self::WebPerformance
            | Self::WebChange
            | Self::WebExposure
            | Self::WebDetection
            | Self::WebFuzz => BoundaryFamily::Http,
            Self::ProviderRegistration
            | Self::ProviderRouting
            | Self::ProviderGeo
            | Self::ProviderHistory
            | Self::ProviderAsset
            | Self::ProviderReputation
            | Self::ProviderLeaks
            | Self::ProviderCertificates
            | Self::ProviderThreat
            | Self::ProviderPerformance => BoundaryFamily::Provider,
            Self::TlsHandshake
            | Self::TlsChain
            | Self::TlsExpiry
            | Self::TlsCipher
            | Self::TlsProtocol
            | Self::TlsPinning => BoundaryFamily::Tls,
            Self::TcpPorts
            | Self::TcpRange
            | Self::TcpCertificate
            | Self::TcpDnsTransfer
            | Self::TcpTlsState => BoundaryFamily::Tcp,
            Self::UdpNtp | Self::UdpSnmp | Self::UdpNetbios | Self::UdpSampler => {
                BoundaryFamily::Udp
            }
            Self::CommandReachability
            | Self::CommandPath
            | Self::CommandWhois
            | Self::CommandSsh => BoundaryFamily::Command,
            Self::LocalWordlist | Self::LocalJwt => BoundaryFamily::Local,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::DnsRecords => "dns-record-analysis",
            Self::DnsPolicy => "dns-policy-analysis",
            Self::DnsPerformance => "dns-performance-analysis",
            Self::DnsTopology => "dns-topology-analysis",
            Self::DnsExposure => "dns-exposure-analysis",
            Self::WebInventory => "web-inventory-analysis",
            Self::WebCrawler => "bounded-crawl-analysis",
            Self::WebMetadata => "web-metadata-analysis",
            Self::WebHeaders => "http-policy-analysis",
            Self::WebBrowserRisk => "browser-surface-analysis",
            Self::WebApi => "api-surface-analysis",
            Self::WebContentRisk => "content-risk-analysis",
            Self::WebPrivacy => "privacy-analysis",
            Self::WebPerformance => "web-performance-analysis",
            Self::WebChange => "web-change-analysis",
            Self::WebExposure => "web-exposure-analysis",
            Self::WebDetection => "technology-detection-analysis",
            Self::WebFuzz => "authorized-web-probe-analysis",
            Self::ProviderRegistration => "registration-source-analysis",
            Self::ProviderRouting => "routing-source-analysis",
            Self::ProviderGeo => "geolocation-source-analysis",
            Self::ProviderHistory => "historical-source-analysis",
            Self::ProviderAsset => "asset-source-analysis",
            Self::ProviderReputation => "reputation-source-analysis",
            Self::ProviderLeaks => "leak-source-analysis",
            Self::ProviderCertificates => "certificate-source-analysis",
            Self::ProviderThreat => "threat-source-analysis",
            Self::ProviderPerformance => "external-performance-analysis",
            Self::TlsHandshake => "tls-handshake-analysis",
            Self::TlsChain => "tls-chain-analysis",
            Self::TlsExpiry => "tls-expiry-analysis",
            Self::TlsCipher => "tls-cipher-analysis",
            Self::TlsProtocol => "tls-protocol-analysis",
            Self::TlsPinning => "tls-pinning-analysis",
            Self::TcpPorts => "tcp-port-analysis",
            Self::TcpRange => "tcp-range-analysis",
            Self::TcpCertificate => "network-certificate-analysis",
            Self::TcpDnsTransfer => "dns-transfer-analysis",
            Self::TcpTlsState => "tls-session-analysis",
            Self::UdpNtp => "ntp-response-analysis",
            Self::UdpSnmp => "snmp-response-analysis",
            Self::UdpNetbios => "netbios-response-analysis",
            Self::UdpSampler => "udp-service-analysis",
            Self::CommandReachability => "reachability-analysis",
            Self::CommandPath => "network-path-analysis",
            Self::CommandWhois => "whois-analysis",
            Self::CommandSsh => "ssh-key-analysis",
            Self::LocalWordlist => "wordlist-analysis",
            Self::LocalJwt => "jwt-structure-analysis",
        }
    }
}

/// One explicit, implementation-owned semantic contract.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SemanticProfile {
    pub(crate) id: &'static str,
    pub(crate) analyzer: Analyzer,
    pub(crate) supplements: &'static [Analyzer],
    pub(crate) purpose: &'static str,
}

macro_rules! profile {
    ($id:literal, $analyzer:ident, $purpose:literal) => {
        Some(SemanticProfile {
            id: $id,
            analyzer: Analyzer::$analyzer,
            supplements: &[],
            purpose: $purpose,
        })
    };
}

macro_rules! composite_profile {
    ($id:literal, $analyzer:ident, [$($supplement:ident),+ $(,)?], $purpose:literal) => {
        Some(SemanticProfile {
            id: $id,
            analyzer: Analyzer::$analyzer,
            supplements: &[$(Analyzer::$supplement),+],
            purpose: $purpose,
        })
    };
}

/// Resolves the explicit semantic contract for one canonical scanner identity.
#[allow(clippy::too_many_lines)]
pub(crate) fn profile_for(id: &str) -> Option<SemanticProfile> {
    match id {
        "asn-lookup" => profile!(
            "asn-lookup",
            ProviderRegistration,
            "Resolve autonomous-system ownership and registration data."
        ),
        "associated-hosts" => profile!(
            "associated-hosts",
            ProviderAsset,
            "Correlate hosts associated with a domain or address."
        ),
        "autonomous-neighbor-peering-map" => profile!(
            "autonomous-neighbor-peering-map",
            ProviderRouting,
            "Map upstream, downstream, and peer autonomous systems."
        ),
        "bgp-route-analysis" => profile!(
            "bgp-route-analysis",
            ProviderRouting,
            "Inspect announced prefixes and route-origin context."
        ),
        "cdn-detection" => composite_profile!(
            "cdn-detection",
            WebDetection,
            [DnsTopology],
            "Detect delivery networks from scoped HTTP and DNS indicators."
        ),
        "dns-over-https" => profile!(
            "dns-over-https",
            DnsPerformance,
            "Compare encrypted DNS resolution observations."
        ),
        "dns-records" => profile!(
            "dns-records",
            DnsRecords,
            "Collect selected public DNS record types."
        ),
        "dns-sla-latency-monitor" => profile!(
            "dns-sla-latency-monitor",
            DnsPerformance,
            "Measure bounded DNS response availability and latency."
        ),
        "dnssec" => profile!(
            "dnssec",
            DnsPolicy,
            "Verify whether DNSSEC material is publicly observable."
        ),
        "domain-info" => profile!(
            "domain-info",
            DnsRecords,
            "Summarize addressing, mail, authority, and policy records."
        ),
        "domain-reputation-check" => profile!(
            "domain-reputation-check",
            ProviderReputation,
            "Correlate domain reputation across configured sources."
        ),
        "dual-stack-behavior-profiler" => profile!(
            "dual-stack-behavior-profiler",
            DnsTopology,
            "Compare IPv4 and IPv6 publication behavior."
        ),
        "geo-dns-footprint" => profile!(
            "geo-dns-footprint",
            DnsTopology,
            "Map DNS answers for downstream geographic enrichment."
        ),
        "http2-http3-checker" => profile!(
            "http2-http3-checker",
            TlsProtocol,
            "Observe negotiated HTTP protocol support over TLS."
        ),
        "icmp-reachability-matrix" => profile!(
            "icmp-reachability-matrix",
            CommandReachability,
            "Measure bounded host reachability."
        ),
        "ip-allocation-history-tracker" => profile!(
            "ip-allocation-history-tracker",
            ProviderHistory,
            "Inspect historical address-allocation observations."
        ),
        "ip-info" => profile!(
            "ip-info",
            ProviderGeo,
            "Summarize public network and location metadata for an address."
        ),
        "ip-range-scanner" => profile!(
            "ip-range-scanner",
            TcpRange,
            "Probe a bounded address range for selected TCP services."
        ),
        "ipv6-reachability-test" => profile!(
            "ipv6-reachability-test",
            TcpRange,
            "Validate bounded IPv6 service reachability."
        ),
        "network-certificate-inventory" => profile!(
            "network-certificate-inventory",
            TcpCertificate,
            "Inventory certificates on scoped network endpoints."
        ),
        "network-timezone-detection" => profile!(
            "network-timezone-detection",
            ProviderGeo,
            "Correlate public location and timezone metadata."
        ),
        "ns-geo-asn-diversity-analyzer" => profile!(
            "ns-geo-asn-diversity-analyzer",
            ProviderRouting,
            "Assess nameserver network and geographic diversity."
        ),
        "ntp-info-leak-checker" => profile!(
            "ntp-info-leak-checker",
            UdpNtp,
            "Inspect bounded NTP responses for unnecessary information."
        ),
        "open-ports" => profile!(
            "open-ports",
            TcpPorts,
            "Discover selected open TCP ports within explicit scope."
        ),
        "rdap-lookup" => profile!(
            "rdap-lookup",
            ProviderRegistration,
            "Retrieve structured registration data through RDAP."
        ),
        "recursive-nameserver-leak-test" => profile!(
            "recursive-nameserver-leak-test",
            DnsExposure,
            "Assess whether recursive DNS behavior is exposed."
        ),
        "reverse-dns-scan" => profile!(
            "reverse-dns-scan",
            DnsRecords,
            "Collect PTR records for scoped addresses."
        ),
        "reverse-ip-lookup" => profile!(
            "reverse-ip-lookup",
            ProviderAsset,
            "Correlate hostnames observed on an address."
        ),
        "rpki-route-validity-check" => profile!(
            "rpki-route-validity-check",
            ProviderRouting,
            "Inspect route-origin authorization state."
        ),
        "server-info" => profile!(
            "server-info",
            WebMetadata,
            "Summarize status, headers, protocol, and document metadata."
        ),
        "server-location" => profile!(
            "server-location",
            ProviderGeo,
            "Resolve public server location metadata."
        ),
        "snmp-public-community-checker" => profile!(
            "snmp-public-community-checker",
            UdpSnmp,
            "Check for responses to the public SNMP community."
        ),
        "spf-network-extractor" => profile!(
            "spf-network-extractor",
            DnsPolicy,
            "Extract network mechanisms from SPF policy."
        ),
        "ssh-banner-key-fingerprinter" => profile!(
            "ssh-banner-key-fingerprinter",
            CommandSsh,
            "Collect scoped SSH host keys and banners."
        ),
        "ssl-chain" => profile!(
            "ssl-chain",
            TlsChain,
            "Inspect the validated certificate chain."
        ),
        "ssl-expiry" => profile!(
            "ssl-expiry",
            TlsExpiry,
            "Report certificate validity windows and expiry risk."
        ),
        "tls-cipher-suites" => profile!(
            "tls-cipher-suites",
            TlsCipher,
            "Observe negotiated cipher and protocol configuration."
        ),
        "tls-handshake" => profile!(
            "tls-handshake",
            TlsHandshake,
            "Perform a certificate-validating TLS handshake."
        ),
        "tls-session-resumption-map" => profile!(
            "tls-session-resumption-map",
            TcpTlsState,
            "Compare bounded TLS session establishment behavior."
        ),
        "traceroute" => profile!(
            "traceroute",
            CommandPath,
            "Record the bounded network path to a target."
        ),
        "txt-records" => profile!("txt-records", DnsRecords, "Collect public TXT records."),
        "udp-service-sampler" => profile!(
            "udp-service-sampler",
            UdpSampler,
            "Sample selected UDP services with protocol-safe payloads."
        ),
        "whois-lookup" => profile!(
            "whois-lookup",
            CommandWhois,
            "Collect allowlisted WHOIS output."
        ),
        "zonetransfer" => profile!(
            "zonetransfer",
            TcpDnsTransfer,
            "Test authoritative DNS zone-transfer policy."
        ),
        "api-schema-grabber" => profile!(
            "api-schema-grabber",
            WebApi,
            "Discover and fingerprint published API schemas."
        ),
        "archive-history" => profile!(
            "archive-history",
            ProviderHistory,
            "Collect historical URLs and snapshots."
        ),
        "autocomplete-vulnerability-checker" => profile!(
            "autocomplete-vulnerability-checker",
            WebBrowserRisk,
            "Inspect sensitive forms for unsafe autocomplete policy."
        ),
        "broken-links" => profile!(
            "broken-links",
            WebCrawler,
            "Identify linked resources returning error responses."
        ),
        "cache-behavior-analyzer" => profile!(
            "cache-behavior-analyzer",
            WebHeaders,
            "Inspect cache policy and response consistency."
        ),
        "captcha-presence-checker" => profile!(
            "captcha-presence-checker",
            WebDetection,
            "Detect common CAPTCHA integrations."
        ),
        "carbon-footprint" => profile!(
            "carbon-footprint",
            WebPerformance,
            "Estimate transfer impact from bounded response sizes."
        ),
        "clickjacking-test" => profile!(
            "clickjacking-test",
            WebHeaders,
            "Verify browser framing restrictions."
        ),
        "cms-detection" => profile!(
            "cms-detection",
            WebDetection,
            "Detect content-management platforms from public indicators."
        ),
        "content-discovery" => profile!(
            "content-discovery",
            WebCrawler,
            "Discover in-scope linked content."
        ),
        "cookie-scope-diff" => profile!(
            "cookie-scope-diff",
            WebPrivacy,
            "Compare cookie scope attributes across observed hosts."
        ),
        "cookies" => profile!(
            "cookies",
            WebPrivacy,
            "Inspect redacted cookie security attributes."
        ),
        "cors-misconfiguration-scanner" => profile!(
            "cors-misconfiguration-scanner",
            WebHeaders,
            "Check cross-origin response policy."
        ),
        "crawl-rules" => profile!(
            "crawl-rules",
            WebMetadata,
            "Retrieve and summarize robots exclusion rules."
        ),
        "crawler" => profile!("crawler", WebCrawler, "Traverse bounded in-scope links."),
        "csp-deep-analyzer" => profile!(
            "csp-deep-analyzer",
            WebHeaders,
            "Inspect Content Security Policy directives."
        ),
        "dependency-js-cdn-scanner" => profile!(
            "dependency-js-cdn-scanner",
            WebInventory,
            "Inventory JavaScript dependencies and delivery origins."
        ),
        "directory-finder" => profile!(
            "directory-finder",
            WebFuzz,
            "Probe a bounded set of common directories."
        ),
        "dom-sink-scanner" => profile!(
            "dom-sink-scanner",
            WebContentRisk,
            "Find risky browser-side DOM sinks in public scripts."
        ),
        "email-harvester" => profile!(
            "email-harvester",
            WebInventory,
            "Extract public email addresses from in-scope documents."
        ),
        "embedded-object-hunter" => profile!(
            "embedded-object-hunter",
            WebInventory,
            "Inventory embedded object surfaces."
        ),
        "favicon-hashing" => profile!(
            "favicon-hashing",
            WebMetadata,
            "Fingerprint the published favicon content."
        ),
        "file-upload-surface-finder" => profile!(
            "file-upload-surface-finder",
            WebApi,
            "Locate public file-upload form surfaces."
        ),
        "form-grabber" => profile!(
            "form-grabber",
            WebInventory,
            "Inventory public forms, methods, and actions."
        ),
        "graphql-introspection-probe" => profile!(
            "graphql-introspection-probe",
            WebApi,
            "Check scoped GraphQL introspection behavior."
        ),
        "hidden-parameter-discovery" => profile!(
            "hidden-parameter-discovery",
            WebInventory,
            "Inventory hidden form and query parameters."
        ),
        "html5-feature-abuse-detector" => profile!(
            "html5-feature-abuse-detector",
            WebBrowserRisk,
            "Detect potentially risky browser feature usage."
        ),
        "html-comments-extractor" => profile!(
            "html-comments-extractor",
            WebMetadata,
            "Extract bounded HTML comment metadata."
        ),
        "http-method-enumerator" => profile!(
            "http-method-enumerator",
            WebApi,
            "Observe allowed safe HTTP methods."
        ),
        "javascript-file-analyzer" => profile!(
            "javascript-file-analyzer",
            WebContentRisk,
            "Inventory and inspect public JavaScript resources."
        ),
        "javascript-obfuscation-detector" => profile!(
            "javascript-obfuscation-detector",
            WebContentRisk,
            "Detect obfuscation indicators in public scripts."
        ),
        "lazy-load-resource-finder" => profile!(
            "lazy-load-resource-finder",
            WebInventory,
            "Inventory lazy-loaded resources."
        ),
        "login-page-brute-identifier" => profile!(
            "login-page-brute-identifier",
            WebDetection,
            "Locate authentication surfaces without attempting credentials."
        ),
        "multi-language-url-tester" => profile!(
            "multi-language-url-tester",
            WebMetadata,
            "Inspect alternate-language URL publication."
        ),
        "performance-monitoring" => composite_profile!(
            "performance-monitoring",
            WebPerformance,
            [ProviderPerformance],
            "Measure bounded HTTP response timing and size."
        ),
        "pixel-tracker-finder" => profile!(
            "pixel-tracker-finder",
            WebPrivacy,
            "Detect tracking pixels and beacon-like resources."
        ),
        "quality-metrics" => profile!(
            "quality-metrics",
            WebPerformance,
            "Compute deterministic document quality metrics."
        ),
        "redirect-chain" => profile!(
            "redirect-chain",
            WebMetadata,
            "Observe scoped redirect behavior."
        ),
        "seo-abuse-detector" => profile!(
            "seo-abuse-detector",
            WebContentRisk,
            "Detect suspicious public SEO manipulation indicators."
        ),
        "session-cookie-lifetime-checker" => profile!(
            "session-cookie-lifetime-checker",
            WebPrivacy,
            "Inspect redacted session-cookie lifetime attributes."
        ),
        "sitemap" => profile!(
            "sitemap",
            WebMetadata,
            "Retrieve and summarize published sitemaps."
        ),
        "social-media" => profile!(
            "social-media",
            WebInventory,
            "Inventory public social-platform links."
        ),
        "static-asset-fingerprinter" => profile!(
            "static-asset-fingerprinter",
            WebInventory,
            "Fingerprint public static assets."
        ),
        "technology-stack" => profile!(
            "technology-stack",
            WebDetection,
            "Detect public technology-stack indicators."
        ),
        "third-party-integrations" => profile!(
            "third-party-integrations",
            WebInventory,
            "Inventory third-party origins and integrations."
        ),
        "third-party-script-risk-profiler" => profile!(
            "third-party-script-risk-profiler",
            WebContentRisk,
            "Profile third-party script origins and integrity controls."
        ),
        "virtual-host-fuzzer" => profile!(
            "virtual-host-fuzzer",
            WebFuzz,
            "Probe an explicitly bounded virtual-host candidate set."
        ),
        "websocket-endpoint-sniffer" => profile!(
            "websocket-endpoint-sniffer",
            WebApi,
            "Discover WebSocket endpoint indicators."
        ),
        "attack-surface-delta" => composite_profile!(
            "attack-surface-delta",
            WebChange,
            [ProviderAsset, DnsTopology, TcpPorts],
            "Build a deterministic attack-surface snapshot for comparison."
        ),
        "breached-credentials-lookup" => profile!(
            "breached-credentials-lookup",
            ProviderLeaks,
            "Query configured breach sources without exposing credentials."
        ),
        "bug-bounty-program-finder" => profile!(
            "bug-bounty-program-finder",
            WebMetadata,
            "Discover published vulnerability-disclosure programs."
        ),
        "censys" => profile!(
            "censys",
            ProviderAsset,
            "Query configured Internet asset observations."
        ),
        "certificate-authority-recon" => profile!(
            "certificate-authority-recon",
            ProviderCertificates,
            "Correlate public certificate authority observations."
        ),
        "cloud-bucket-exposure" => profile!(
            "cloud-bucket-exposure",
            WebExposure,
            "Check bounded cloud-storage exposure candidates."
        ),
        "cloud-service-enumeration" => profile!(
            "cloud-service-enumeration",
            WebExposure,
            "Discover public cloud-service indicators."
        ),
        "ct-log-query" => profile!(
            "ct-log-query",
            ProviderCertificates,
            "Query certificate-transparency observations."
        ),
        "custom-wordlist-generator" => profile!(
            "custom-wordlist-generator",
            LocalWordlist,
            "Generate a deterministic target-derived wordlist."
        ),
        "data-leak" => profile!(
            "data-leak",
            ProviderLeaks,
            "Correlate configured public leak observations."
        ),
        "domain-shadowing-detector" => profile!(
            "domain-shadowing-detector",
            ProviderThreat,
            "Detect suspicious domain infrastructure changes."
        ),
        "exposed-api-endpoints" => profile!(
            "exposed-api-endpoints",
            WebExposure,
            "Probe a bounded set of common API endpoints."
        ),
        "exposed-env-files" => profile!(
            "exposed-env-files",
            WebExposure,
            "Check for publicly readable environment files."
        ),
        "firewall-detection" => composite_profile!(
            "firewall-detection",
            WebDetection,
            [TcpPorts],
            "Detect public web-application firewall indicators."
        ),
        "git-repo-exposure-check" => profile!(
            "git-repo-exposure-check",
            WebExposure,
            "Check for publicly readable repository metadata."
        ),
        "global-ranking" => profile!(
            "global-ranking",
            ProviderReputation,
            "Correlate configured public popularity rankings."
        ),
        "http-headers" => profile!(
            "http-headers",
            WebHeaders,
            "Inventory HTTP response headers."
        ),
        "http-security" => profile!(
            "http-security",
            WebHeaders,
            "Evaluate common HTTP security controls."
        ),
        "ip-reputation-trending" => profile!(
            "ip-reputation-trending",
            ProviderReputation,
            "Create a timestamped address-reputation observation."
        ),
        "js-malware-scanner" => profile!(
            "js-malware-scanner",
            ProviderThreat,
            "Correlate public scripts with configured threat sources."
        ),
        "jwt-token-analyzer" => profile!(
            "jwt-token-analyzer",
            LocalJwt,
            "Decode and assess JWT structure without verifying secrets."
        ),
        "malware-phishing" => profile!(
            "malware-phishing",
            ProviderThreat,
            "Correlate malware and phishing observations."
        ),
        "open-redirect-finder" => profile!(
            "open-redirect-finder",
            WebFuzz,
            "Check a bounded set of redirect parameters."
        ),
        "passive-cve-mapper" => profile!(
            "passive-cve-mapper",
            WebDetection,
            "Map detected public products to vulnerability identifiers."
        ),
        "pastebin-monitoring" => profile!(
            "pastebin-monitoring",
            ProviderLeaks,
            "Query configured public paste and leak sources."
        ),
        "privacy-gdpr" => profile!(
            "privacy-gdpr",
            WebPrivacy,
            "Inspect public privacy and consent indicators."
        ),
        "rate-limit-waf-bypass-test" => profile!(
            "rate-limit-waf-bypass-test",
            WebFuzz,
            "Perform a bounded authorized rate-limit consistency probe."
        ),
        "rogue-certificate-check" => profile!(
            "rogue-certificate-check",
            ProviderCertificates,
            "Correlate unexpected certificate observations."
        ),
        "rogue-subdomain-resolver" => profile!(
            "rogue-subdomain-resolver",
            DnsExposure,
            "Identify suspicious or dangling DNS answers."
        ),
        "security-changelog-diff" => profile!(
            "security-changelog-diff",
            WebChange,
            "Compare published security-change indicators."
        ),
        "security-contact-gap-finder" => composite_profile!(
            "security-contact-gap-finder",
            WebMetadata,
            [ProviderRegistration],
            "Assess published security contact coverage."
        ),
        "security-txt" => profile!(
            "security-txt",
            WebMetadata,
            "Validate the published security.txt resource."
        ),
        "session-hijacking-passive" => profile!(
            "session-hijacking-passive",
            WebPrivacy,
            "Inspect redacted session transport protections."
        ),
        "shodan" => profile!(
            "shodan",
            ProviderAsset,
            "Query configured host intelligence."
        ),
        "spf-dkim-dmarc-validator" => profile!(
            "spf-dkim-dmarc-validator",
            DnsPolicy,
            "Validate published sender-authentication policy."
        ),
        "ssl-labs-report" => profile!(
            "ssl-labs-report",
            ProviderCertificates,
            "Retrieve configured external TLS assessment data."
        ),
        "ssl-pinning-check" => profile!(
            "ssl-pinning-check",
            TlsPinning,
            "Record certificate identity material for pinning review."
        ),
        "subdomain-enum" => profile!(
            "subdomain-enum",
            ProviderAsset,
            "Enumerate public subdomain observations."
        ),
        "subdomain-takeover" => profile!(
            "subdomain-takeover",
            DnsExposure,
            "Detect dangling DNS indicators associated with takeover risk."
        ),
        "threat-feed-correlator" => profile!(
            "threat-feed-correlator",
            ProviderThreat,
            "Correlate target indicators across configured threat feeds."
        ),
        "typosquat-domain-checker" => profile!(
            "typosquat-domain-checker",
            DnsExposure,
            "Generate and check a bounded set of typo candidates."
        ),
        "virustotal-scan" => profile!(
            "virustotal-scan",
            ProviderThreat,
            "Query configured multi-engine reputation observations."
        ),
        "dark-web-monitoring" => profile!(
            "dark-web-monitoring",
            ProviderLeaks,
            "Query a configured lawful monitoring source."
        ),
        "decoy-dns-beacon" => profile!(
            "decoy-dns-beacon",
            DnsExposure,
            "Inspect DNS indicators associated with decoy beacons."
        ),
        "dns-caa-checker" => profile!(
            "dns-caa-checker",
            DnsPolicy,
            "Validate certificate authority authorization policy."
        ),
        "dual-stack-diff" => profile!(
            "dual-stack-diff",
            DnsTopology,
            "Compare IPv4 and IPv6 publication results."
        ),
        "email-config" => profile!(
            "email-config",
            DnsPolicy,
            "Summarize mail routing and sender-authentication records."
        ),
        "geo-ip-spoof-detection" => profile!(
            "geo-ip-spoof-detection",
            ProviderGeo,
            "Compare configured geographic address observations."
        ),
        "ip-reputation-check" => profile!(
            "ip-reputation-check",
            ProviderReputation,
            "Correlate current address reputation."
        ),
        "irr-routing-registry-analyzer" => profile!(
            "irr-routing-registry-analyzer",
            ProviderRouting,
            "Inspect Internet Routing Registry route objects."
        ),
        "netbios-name-query" => profile!(
            "netbios-name-query",
            UdpNetbios,
            "Collect scoped NetBIOS name-service responses."
        ),
        "passive-dns-history" => profile!(
            "passive-dns-history",
            ProviderHistory,
            "Query configured historical DNS observations."
        ),
        "snmp-bulk-walk" => profile!(
            "snmp-bulk-walk",
            UdpSnmp,
            "Perform a bounded authorized SNMP bulk query."
        ),
        "tls-security-config" => profile!(
            "tls-security-config",
            TlsCipher,
            "Evaluate negotiated TLS security configuration."
        ),
        "ttl-analysis" => profile!(
            "ttl-analysis",
            DnsPerformance,
            "Analyze observed DNS time-to-live values."
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn semantic_keys_are_owned_by_the_complete_catalog() -> Result<(), Box<dyn std::error::Error>> {
        let definitions = crate::catalog_data::definitions()?;
        let profiles: Vec<_> = definitions
            .iter()
            .map(|definition| profile_for(definition.descriptor.id.as_str()))
            .collect();
        assert!(profiles.iter().all(Option::is_some));
        let keys: BTreeSet<_> = profiles
            .into_iter()
            .flatten()
            .map(|profile| profile.id)
            .collect();
        assert_eq!(keys.len(), 147);
        Ok(())
    }

    #[test]
    fn composite_profiles_declare_distinct_supporting_boundaries() {
        let expected = [
            ("cdn-detection", &[BoundaryFamily::Dns][..]),
            (
                "attack-surface-delta",
                &[
                    BoundaryFamily::Provider,
                    BoundaryFamily::Dns,
                    BoundaryFamily::Tcp,
                ][..],
            ),
            ("firewall-detection", &[BoundaryFamily::Tcp][..]),
            ("performance-monitoring", &[BoundaryFamily::Provider][..]),
            (
                "security-contact-gap-finder",
                &[BoundaryFamily::Provider][..],
            ),
        ];
        for (id, families) in expected {
            let Some(profile) = profile_for(id) else {
                unreachable!("missing composite profile for {id}");
            };
            let actual: Vec<_> = profile
                .supplements
                .iter()
                .map(|analyzer| analyzer.family())
                .collect();
            assert_eq!(
                actual, families,
                "unexpected supporting boundaries for {id}"
            );
            assert!(
                actual
                    .iter()
                    .all(|family| *family != profile.analyzer.family())
            );
        }
    }
}
