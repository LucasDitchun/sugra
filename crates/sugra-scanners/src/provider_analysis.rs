//! Pure, bounded projections of third-party provider responses.

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sugra_domain::{Confidence, Severity};

const MAX_PROVIDER_RECORDS: usize = 10_000;
const MAX_PROVIDER_RECORDS_U64: u64 = 10_000;

/// Optional operator-owned reference data used by a provider analyzer.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ProviderBaseline<'a> {
    /// No comparison baseline is available.
    None,
    /// Certificate issuer names approved for the target.
    CertificateIssuers(&'a [&'a str]),
}

/// Privacy-preserving projection of one provider response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProviderAnalysis {
    /// Bounded aggregate without raw provider records.
    pub(crate) summary: ProviderSummary,
    /// Security-relevant conclusions derived from the aggregate.
    pub(crate) findings: Vec<ProviderFinding>,
}

/// Supported aggregate response shapes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum ProviderSummary {
    /// Internet Archive CDX rows reduced to temporal and uniqueness counts.
    ArchiveHistory {
        /// Valid bounded snapshot rows.
        snapshots: usize,
        /// Distinct archived URLs.
        unique_urls: usize,
        /// Distinct HTTP statuses.
        unique_statuses: usize,
        /// Distinct content digests.
        unique_digests: usize,
        /// Earliest valid four-digit snapshot year.
        earliest_year: Option<u16>,
        /// Latest valid four-digit snapshot year.
        latest_year: Option<u16>,
    },
    /// Registration data reduced to non-identifying counts.
    Registration {
        /// Distinct public object handles.
        handles: usize,
        /// Valid entity objects.
        entities: usize,
        /// Distinct registration roles.
        roles: usize,
        /// Network ranges or CIDR collections present.
        networks: usize,
        /// Distinct autonomous-system identifiers.
        autonomous_systems: usize,
        /// Public notice or remark objects.
        notices: usize,
    },
    /// Host-intelligence records reduced to aggregate asset counts.
    HostIntelligence {
        /// Valid service records.
        records: usize,
        /// Distinct hostnames.
        unique_hostnames: usize,
        /// Distinct registered domains.
        unique_domains: usize,
        /// Distinct address observations.
        unique_ips: usize,
        /// Distinct open ports.
        open_ports: usize,
    },
    /// Certificate-transparency counts.
    CertificateTransparency {
        /// Provider records with the expected shape.
        records: usize,
        /// Unique DNS names across all valid records.
        unique_names: usize,
        /// Unique certificate issuers across all valid records.
        unique_issuers: usize,
        /// Names containing a wildcard label.
        wildcard_names: usize,
    },
    /// `URLScan` result counts suitable for passive history and asset summaries.
    UrlScan {
        /// Provider records with a page object.
        records: usize,
        /// Distinct domain values across valid records.
        unique_domains: usize,
        /// Distinct IP address values across valid records.
        unique_ips: usize,
        /// Records explicitly marked malicious by the provider.
        malicious_records: usize,
    },
    /// Encrypted DNS response metadata without returned names or addresses.
    DnsOverHttps {
        /// DNS response code when published by the provider.
        status: Option<u16>,
        /// Number of bounded answer records.
        answers: usize,
        /// Whether the response was truncated.
        truncated: bool,
        /// Whether the provider marked the response data as authenticated.
        authenticated_data: bool,
    },
    /// Routing and route-origin aggregate counts.
    Routing {
        /// Prefixes returned by the provider.
        prefixes: usize,
        /// Autonomous-system origins returned by the provider.
        origins: usize,
        /// Routes with a valid status.
        valid_routes: usize,
        /// Routes with an invalid status.
        invalid_routes: usize,
        /// Routes without a recognized validity status.
        unknown_routes: usize,
    },
    /// Autonomous-system neighbours reduced to directional, de-duplicated counts.
    AutonomousNeighborPeeringMap {
        /// Valid bounded neighbour records.
        records: usize,
        /// Distinct neighbouring autonomous systems.
        unique_autonomous_systems: usize,
        /// Neighbours observed to the left of the queried ASN.
        left_neighbors: usize,
        /// Neighbours observed to the right of the queried ASN.
        right_neighbors: usize,
        /// Neighbours whose direction could not be established.
        uncertain_neighbors: usize,
    },
    /// Historical registry objects reduced to bounded change counts.
    IpAllocationHistory {
        /// Historical object versions reported by the provider.
        versions: usize,
        /// Objects in the selected version.
        objects: usize,
        /// Objects referenced by the selected object.
        referencing_objects: usize,
        /// Objects that reference the selected object.
        referenced_objects: usize,
        /// Alternative registry objects suggested by the provider.
        suggestions: usize,
        /// Distinct safe object-type labels.
        unique_object_types: usize,
    },
    /// Network identity without retaining the address, prefix, or ASN values.
    IpNetworkInfo {
        /// Whether the provider returned a containing prefix.
        prefix_present: bool,
        /// Distinct announcing autonomous systems.
        autonomous_systems: usize,
    },
    /// IP location and network attributes without retaining raw provider values.
    IpLocationInfo {
        /// Whether a city was returned.
        city_present: bool,
        /// Whether a region was returned.
        region_present: bool,
        /// Whether a country was returned.
        country_present: bool,
        /// Whether a timezone was returned.
        timezone_present: bool,
        /// Whether a valid coordinate pair was returned.
        coordinates_present: bool,
        /// Whether an autonomous-system identity was returned.
        autonomous_system_present: bool,
    },
    /// Public timezone metadata reduced to field presence.
    NetworkTimezone {
        /// Whether a timezone was returned.
        timezone_present: bool,
        /// Whether a country was returned.
        country_present: bool,
        /// Whether a valid coordinate pair was returned.
        coordinates_present: bool,
    },
    /// DNS-chain topology counts; no unsupported geo/ASN enrichment is inferred.
    NameserverDiversity {
        /// Distinct forward-chain owners.
        forward_nodes: usize,
        /// Distinct reverse-chain owners.
        reverse_nodes: usize,
        /// Distinct recursive resolver addresses.
        resolver_nameservers: usize,
        /// Distinct authoritative nameserver addresses.
        authoritative_nameservers: usize,
        /// Distinct bounded targets across forward and reverse chains.
        unique_chain_targets: usize,
        /// Nameserver addresses with at least one successful enrichment.
        enriched_nameservers: usize,
        /// Distinct countries observed across location enrichments.
        unique_countries: usize,
        /// Distinct autonomous systems observed across network enrichments.
        unique_autonomous_systems: usize,
    },
    /// Public server location metadata reduced to field presence.
    ServerLocation {
        /// Whether a city was returned.
        city_present: bool,
        /// Whether a region was returned.
        region_present: bool,
        /// Whether a country was returned.
        country_present: bool,
        /// Whether a valid coordinate pair was returned.
        coordinates_present: bool,
    },
    /// Certificate-transparency authority counts for CA reconnaissance.
    CertificateAuthorityRecon {
        /// Valid bounded certificate records.
        records: usize,
        /// Distinct certificate authorities.
        unique_authorities: usize,
        /// Distinct certificate DNS names.
        unique_names: usize,
        /// Distinct wildcard DNS names.
        wildcard_names: usize,
    },
    /// Internet Routing Registry data reduced to route-object counts.
    IrrRoutingRegistry {
        /// Non-IRR whois records returned alongside the result.
        records: usize,
        /// Valid bounded IRR records.
        irr_records: usize,
        /// Distinct registry authorities queried.
        authorities: usize,
        /// IPv4 route objects.
        route_objects: usize,
        /// IPv6 route objects.
        route6_objects: usize,
        /// Distinct route origins.
        unique_origins: usize,
        /// Distinct IRR source registries.
        unique_sources: usize,
    },
    /// `PageSpeed` metrics reduced to bounded numeric values.
    PageSpeed {
        /// Lighthouse performance score from 0 through 100.
        performance_score: Option<u8>,
        /// Largest Contentful Paint in milliseconds.
        largest_contentful_paint_ms: Option<u64>,
        /// Cumulative Layout Shift multiplied by 1,000.
        cumulative_layout_shift_milli: Option<u64>,
        /// Audits explicitly scoring below 0.5.
        failed_audits: usize,
    },
    /// Reputation-engine aggregate counts.
    Reputation {
        /// Engines or sources returning a malicious verdict.
        malicious: u64,
        /// Engines or sources returning a suspicious verdict.
        suspicious: u64,
        /// Engines or sources returning a harmless verdict.
        harmless: u64,
        /// Engines without a verdict.
        undetected: u64,
        /// Abuse confidence score from 0 through 100.
        abuse_confidence: Option<u8>,
    },
    /// HIBP stealer-log account exposure reduced to a count.
    HibpStealerLogs {
        /// Email accounts present in the bounded provider response.
        exposed_accounts: usize,
    },
    /// HIBP paste observations reduced to aggregate counts.
    HibpPastes {
        /// Paste records present in the bounded provider response.
        pastes: usize,
        /// Total email mentions reported across the bounded paste records.
        email_mentions: u64,
    },
    /// HIBP breach observations reduced to aggregate account and record counts.
    HibpBreaches {
        /// Accounts or domain aliases with at least one structurally valid breach record.
        affected_accounts: usize,
        /// Structurally valid bounded breach records.
        records: usize,
    },
    /// Cloudflare Radar rank details without retaining the queried domain.
    DomainRanking {
        /// Current ordered rank when one is available.
        rank: Option<u64>,
        /// Whether the provider supplied an unordered ranking bucket.
        bucket_present: bool,
        /// Bounded category records.
        categories: usize,
    },
    /// SSL Labs endpoint-grade counts without endpoint addresses or report details.
    ExternalTlsAssessment {
        /// Whether the provider reports a completed assessment.
        ready: bool,
        /// Structurally valid bounded endpoint grades.
        endpoints: usize,
        /// Endpoints with an A or B grade.
        strong_endpoints: usize,
        /// Endpoints with a material weak/error grade.
        weak_endpoints: usize,
    },
    /// One geolocation provider reduced to a comparison-safe country digest.
    GeolocationSource {
        /// SHA-256 of the normalized country code, when one is available.
        country_sha256: Option<String>,
        /// Whether the provider supplied a valid coordinate pair.
        coordinates_present: bool,
    },
}

/// Finding independent of result evidence indexing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ProviderFinding {
    /// Stable finding identity.
    pub(crate) key: &'static str,
    /// Safe user-facing title.
    pub(crate) title: &'static str,
    /// Finding severity.
    pub(crate) severity: Severity,
    /// Evidence confidence.
    pub(crate) confidence: Confidence,
}

/// Bounded real-provider enrichment for one authoritative nameserver address.
#[derive(Debug, Clone, Default)]
pub(crate) struct NameserverEnrichment {
    /// `RIPEstat` network-info response, when available.
    pub(crate) network_info: Option<Value>,
    /// `IPinfo` lookup response, when available.
    pub(crate) location: Option<Value>,
}

/// Analyzes a supported provider response without retaining raw records.
#[must_use]
pub(crate) fn analyze_provider_response(
    scanner_id: &str,
    provider: &str,
    response: &Value,
    baseline: ProviderBaseline<'_>,
) -> Option<ProviderAnalysis> {
    match provider {
        "wayback" if scanner_id == "archive-history" => Some(analyze_wayback(response)),
        "rdap" if matches!(scanner_id, "asn-lookup" | "rdap-lookup") => {
            Some(analyze_rdap(scanner_id, response))
        }
        "shodan" if matches!(scanner_id, "associated-hosts" | "shodan") => {
            Some(analyze_shodan_host(scanner_id, response))
        }
        "censys" if scanner_id == "censys" => Some(analyze_censys(response)),
        "crtsh" if scanner_id == "certificate-authority-recon" => {
            Some(analyze_certificate_authorities(response))
        }
        "crtsh" => Some(analyze_certificate_transparency(
            scanner_id, response, baseline,
        )),
        "urlscan" => Some(analyze_urlscan(scanner_id, response)),
        "ripestat" if scanner_id == "ip-reputation-trending" => {
            Some(analyze_blocklist_reputation(scanner_id, response))
        }
        "ripestat" if scanner_id == "geo-ip-spoof-detection" => {
            Some(analyze_geolocation_source(response, true))
        }
        "ripestat" => Some(analyze_ripestat(scanner_id, response)),
        "ipinfo" if scanner_id == "geo-ip-spoof-detection" => {
            Some(analyze_geolocation_source(response, false))
        }
        "ipinfo"
            if matches!(
                scanner_id,
                "ip-info" | "network-timezone-detection" | "server-location"
            ) =>
        {
            Some(analyze_ipinfo(scanner_id, response))
        }
        "pagespeed" => Some(analyze_pagespeed(scanner_id, response)),
        "cloudflare-doh" | "google-doh" => Some(analyze_doh(response)),
        "virustotal" | "abuseipdb" => Some(analyze_reputation(scanner_id, response)),
        "urlhaus" => Some(analyze_urlhaus(scanner_id, response)),
        "otx" => Some(analyze_otx(scanner_id, response)),
        "hibp" if scanner_id == "dark-web-monitoring" => Some(analyze_hibp_stealer_logs(response)),
        "hibp" if scanner_id == "pastebin-monitoring" => Some(analyze_hibp_pastes(response)),
        "hibp" if matches!(scanner_id, "breached-credentials-lookup" | "data-leak") => {
            Some(analyze_hibp_breaches(response))
        }
        "cloudflare-radar" if scanner_id == "global-ranking" => Some(analyze_ranking(response)),
        "ssllabs" if scanner_id == "ssl-labs-report" => Some(analyze_ssl_labs(response)),
        _ => None,
    }
}

fn analyze_geolocation_source(response: &Value, ripestat: bool) -> ProviderAnalysis {
    let country = if ripestat {
        response
            .pointer("/data/located_resources/0/location")
            .or_else(|| response.pointer("/data/country"))
            .and_then(Value::as_str)
    } else {
        response
            .pointer("/geo/country_code")
            .or_else(|| response.pointer("/geo/country"))
            .or_else(|| response.get("country"))
            .and_then(Value::as_str)
    }
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .map(str::to_ascii_uppercase);
    let country_sha256 = country
        .as_deref()
        .map(|value| hex::encode(Sha256::digest(value.as_bytes())));
    let coordinates_present = if ripestat {
        response
            .pointer("/data/located_resources/0/latitude")
            .and_then(Value::as_f64)
            .zip(
                response
                    .pointer("/data/located_resources/0/longitude")
                    .and_then(Value::as_f64),
            )
            .is_some_and(valid_coordinate_pair)
    } else {
        response
            .pointer("/geo/latitude")
            .or_else(|| response.get("latitude"))
            .and_then(Value::as_f64)
            .zip(
                response
                    .pointer("/geo/longitude")
                    .or_else(|| response.get("longitude"))
                    .and_then(Value::as_f64),
            )
            .is_some_and(valid_coordinate_pair)
    };
    ProviderAnalysis {
        summary: ProviderSummary::GeolocationSource {
            country_sha256,
            coordinates_present,
        },
        findings: Vec::new(),
    }
}

fn valid_coordinate_pair((latitude, longitude): (f64, f64)) -> bool {
    latitude.is_finite()
        && longitude.is_finite()
        && (-90.0..=90.0).contains(&latitude)
        && (-180.0..=180.0).contains(&longitude)
}

fn analyze_wayback(response: &Value) -> ProviderAnalysis {
    let mut urls = BTreeSet::new();
    let mut statuses = BTreeSet::new();
    let mut digests = BTreeSet::new();
    let mut years = BTreeSet::new();
    let mut snapshots = 0_usize;
    for row in response
        .as_array()
        .into_iter()
        .flatten()
        .take(MAX_PROVIDER_RECORDS.saturating_add(1))
    {
        let Some(columns) = row.as_array() else {
            continue;
        };
        let Some(timestamp) = columns.first().and_then(Value::as_str) else {
            continue;
        };
        let Some(year) = parse_snapshot_year(timestamp) else {
            continue;
        };
        let Some(original) = columns
            .get(1)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
        else {
            continue;
        };
        let Some(status) = columns
            .get(2)
            .and_then(Value::as_str)
            .and_then(|value| value.parse::<u16>().ok())
            .filter(|value| (100..=599).contains(value))
        else {
            continue;
        };
        let Some(digest) = columns
            .get(3)
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty())
        else {
            continue;
        };
        snapshots += 1;
        urls.insert(original.to_owned());
        statuses.insert(status);
        digests.insert(digest.to_owned());
        years.insert(year);
        if snapshots == MAX_PROVIDER_RECORDS {
            break;
        }
    }
    let findings = (snapshots > 0)
        .then_some(ProviderFinding {
            key: "archived-snapshots-observed",
            title: "The archive provider returned historical snapshots",
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
        })
        .into_iter()
        .collect();
    ProviderAnalysis {
        summary: ProviderSummary::ArchiveHistory {
            snapshots,
            unique_urls: urls.len(),
            unique_statuses: statuses.len(),
            unique_digests: digests.len(),
            earliest_year: years.first().copied(),
            latest_year: years.last().copied(),
        },
        findings,
    }
}

fn parse_snapshot_year(timestamp: &str) -> Option<u16> {
    (timestamp.len() == 14 && timestamp.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| timestamp.get(..4)?.parse::<u16>().ok())
        .flatten()
        .filter(|year| (1990..=2100).contains(year))
}

fn analyze_rdap(scanner_id: &str, response: &Value) -> ProviderAnalysis {
    let mut handles = BTreeSet::new();
    let mut roles = BTreeSet::new();
    let mut autonomous_systems = BTreeSet::new();
    if let Some(handle) = response.get("handle").and_then(Value::as_str) {
        handles.insert(handle.to_owned());
    }
    let mut entities = 0_usize;
    for entity in response
        .get("entities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PROVIDER_RECORDS)
    {
        let Some(entity) = entity.as_object() else {
            continue;
        };
        entities += 1;
        if let Some(handle) = entity.get("handle").and_then(Value::as_str) {
            handles.insert(handle.to_owned());
        }
        roles.extend(
            entity
                .get("roles")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .take(128)
                .map(str::to_ascii_lowercase),
        );
    }
    for key in ["startAutnum", "endAutnum"] {
        if let Some(value) = response.get(key).and_then(Value::as_u64) {
            autonomous_systems.insert(value);
        }
    }
    autonomous_systems.extend(
        response
            .get("arin_originas0_originautnums")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_u64)
            .take(MAX_PROVIDER_RECORDS),
    );
    let networks = usize::from(
        response
            .get("startAddress")
            .and_then(Value::as_str)
            .is_some()
            || response.get("endAddress").and_then(Value::as_str).is_some(),
    ) + response
        .get("cidr0_cidrs")
        .and_then(Value::as_array)
        .map_or(0, |values| values.len().min(MAX_PROVIDER_RECORDS));
    let notices = ["notices", "remarks"]
        .into_iter()
        .filter_map(|key| response.get(key).and_then(Value::as_array))
        .flat_map(|values| values.iter())
        .filter(|value| value.is_object())
        .take(MAX_PROVIDER_RECORDS)
        .count();
    let observed = !handles.is_empty()
        || entities > 0
        || !roles.is_empty()
        || networks > 0
        || !autonomous_systems.is_empty()
        || notices > 0;
    let findings = observed
        .then_some(ProviderFinding {
            key: if scanner_id == "asn-lookup" {
                "autonomous-system-context-observed"
            } else {
                "registration-data-observed"
            },
            title: if scanner_id == "asn-lookup" {
                "The provider returned autonomous-system registration context"
            } else {
                "The provider returned public registration context"
            },
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
        })
        .into_iter()
        .collect();
    ProviderAnalysis {
        summary: ProviderSummary::Registration {
            handles: handles.len(),
            entities,
            roles: roles.len(),
            networks: networks.min(MAX_PROVIDER_RECORDS),
            autonomous_systems: autonomous_systems.len(),
            notices,
        },
        findings,
    }
}

fn analyze_shodan_host(scanner_id: &str, response: &Value) -> ProviderAnalysis {
    let mut hostnames = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut ips = BTreeSet::new();
    let mut ports = BTreeSet::new();
    hostnames.extend(
        response
            .get("hostnames")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .take(MAX_PROVIDER_RECORDS)
            .map(str::to_ascii_lowercase),
    );
    domains.extend(
        response
            .get("domains")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .take(MAX_PROVIDER_RECORDS)
            .map(str::to_ascii_lowercase),
    );
    if let Some(ip) = response.get("ip_str").and_then(Value::as_str) {
        ips.insert(ip.to_owned());
    }
    let mut records = 0_usize;
    for service in response
        .get("data")
        .or_else(|| response.get("matches"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PROVIDER_RECORDS)
    {
        let Some(service) = service.as_object() else {
            continue;
        };
        records += 1;
        if let Some(port) = service
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
        {
            ports.insert(port);
        }
        if let Some(ip) = service.get("ip_str").and_then(Value::as_str) {
            ips.insert(ip.to_owned());
        }
        hostnames.extend(
            service
                .get("hostnames")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .take(128)
                .map(str::to_ascii_lowercase),
        );
        if let Some(ip) = service
            .get("ip_str")
            .or_else(|| service.get("ip"))
            .and_then(Value::as_str)
        {
            ips.insert(ip.to_owned());
        }
    }
    let observed = if scanner_id == "shodan" {
        records > 0 || !hostnames.is_empty() || !domains.is_empty() || !ips.is_empty()
    } else {
        !hostnames.is_empty() || !domains.is_empty() || ips.len() > 1
    };
    let findings = observed
        .then_some(ProviderFinding {
            key: if scanner_id == "shodan" {
                "host-intelligence-observed"
            } else {
                "associated-hosts-observed"
            },
            title: if scanner_id == "shodan" {
                "Shodan returned bounded host intelligence observations"
            } else {
                "The provider returned associated host observations"
            },
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
        })
        .into_iter()
        .collect();
    ProviderAnalysis {
        summary: ProviderSummary::HostIntelligence {
            records,
            unique_hostnames: hostnames.len(),
            unique_domains: domains.len(),
            unique_ips: ips.len(),
            open_ports: ports.len(),
        },
        findings,
    }
}

fn analyze_censys(response: &Value) -> ProviderAnalysis {
    let envelope = response.get("result").unwrap_or(response);
    let asset = envelope
        .get("web")
        .or_else(|| envelope.get("host"))
        .unwrap_or(envelope);
    let mut hostnames = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut ips = BTreeSet::new();
    let mut ports = BTreeSet::new();
    if let Some(hostname) = asset
        .get("hostname")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        hostnames.insert(hostname.to_ascii_lowercase());
    }
    if let Some(ip) = asset
        .get("ip")
        .or_else(|| asset.get("ip_address"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        ips.insert(ip.to_owned());
    }
    if let Some(port) = asset
        .get("port")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
    {
        ports.insert(port);
    }
    let records = asset
        .get("endpoints")
        .or_else(|| asset.get("services"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PROVIDER_RECORDS)
        .inspect(|record| {
            if let Some(port) = record
                .get("port")
                .and_then(Value::as_u64)
                .and_then(|value| u16::try_from(value).ok())
            {
                ports.insert(port);
            }
            if let Some(hostname) = record
                .get("hostname")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            {
                hostnames.insert(hostname.to_ascii_lowercase());
            }
        })
        .count();
    domains.extend(
        asset
            .get("domains")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .take(MAX_PROVIDER_RECORDS)
            .map(str::to_ascii_lowercase),
    );
    let observed = records > 0 || !hostnames.is_empty() || !ips.is_empty() || !ports.is_empty();
    ProviderAnalysis {
        summary: ProviderSummary::HostIntelligence {
            records,
            unique_hostnames: hostnames.len(),
            unique_domains: domains.len(),
            unique_ips: ips.len(),
            open_ports: ports.len(),
        },
        findings: info_finding(
            observed,
            "host-intelligence-observed",
            "Censys returned bounded Internet asset observations",
        ),
    }
}

fn analyze_hibp_stealer_logs(response: &Value) -> ProviderAnalysis {
    let exposed_accounts = response
        .as_array()
        .into_iter()
        .flatten()
        .take(MAX_PROVIDER_RECORDS)
        .filter(|account| account.as_str().is_some())
        .count();
    let findings = if exposed_accounts > 0 {
        vec![ProviderFinding {
            key: "stealer-log-accounts-present",
            title: "HIBP returned stealer-log accounts for the monitored website domain",
            severity: Severity::High,
            confidence: Confidence::Confirmed,
        }]
    } else {
        Vec::new()
    };
    ProviderAnalysis {
        summary: ProviderSummary::HibpStealerLogs { exposed_accounts },
        findings,
    }
}

fn analyze_hibp_pastes(response: &Value) -> ProviderAnalysis {
    let mut pastes = 0_usize;
    let mut email_mentions = 0_u64;
    for paste in response
        .as_array()
        .into_iter()
        .flatten()
        .take(MAX_PROVIDER_RECORDS)
    {
        let Some(paste) = paste.as_object() else {
            continue;
        };
        let structurally_valid = paste.get("Source").and_then(Value::as_str).is_some()
            && paste.get("Id").and_then(Value::as_str).is_some();
        let Some(email_count) = paste.get("EmailCount").and_then(Value::as_u64) else {
            continue;
        };
        if !structurally_valid {
            continue;
        }
        pastes += 1;
        email_mentions = email_mentions
            .saturating_add(email_count)
            .min(MAX_PROVIDER_RECORDS_U64);
    }
    let findings = if pastes > 0 {
        vec![ProviderFinding {
            key: "paste-observations-present",
            title: "HIBP returned paste observations for the monitored email account",
            severity: Severity::High,
            confidence: Confidence::Confirmed,
        }]
    } else {
        Vec::new()
    };
    ProviderAnalysis {
        summary: ProviderSummary::HibpPastes {
            pastes,
            email_mentions,
        },
        findings,
    }
}

fn analyze_hibp_breaches(response: &Value) -> ProviderAnalysis {
    let (affected_accounts, records) = if let Some(breaches) = response.as_array() {
        let records = breaches
            .iter()
            .take(MAX_PROVIDER_RECORDS)
            .filter(|breach| {
                breach
                    .get("Name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| !name.trim().is_empty())
            })
            .count();
        (usize::from(records > 0), records)
    } else if let Some(accounts) = response.as_object() {
        let mut affected_accounts = 0_usize;
        let mut records = 0_usize;
        for breaches in accounts.values().take(MAX_PROVIDER_RECORDS) {
            let valid = breaches
                .as_array()
                .into_iter()
                .flatten()
                .filter(|breach| {
                    breach.as_str().is_some_and(|name| !name.trim().is_empty())
                        || breach
                            .get("Name")
                            .and_then(Value::as_str)
                            .is_some_and(|name| !name.trim().is_empty())
                })
                .take(MAX_PROVIDER_RECORDS.saturating_sub(records))
                .count();
            affected_accounts += usize::from(valid > 0);
            records += valid;
            if records == MAX_PROVIDER_RECORDS {
                break;
            }
        }
        (affected_accounts, records)
    } else {
        (0, 0)
    };
    ProviderAnalysis {
        summary: ProviderSummary::HibpBreaches {
            affected_accounts,
            records,
        },
        findings: (records > 0)
            .then_some(ProviderFinding {
                key: "breach-observations-present",
                title: "HIBP returned bounded breach observations for the authorized target",
                severity: Severity::High,
                confidence: Confidence::Confirmed,
            })
            .into_iter()
            .collect(),
    }
}

fn analyze_ranking(response: &Value) -> ProviderAnalysis {
    let details = response
        .pointer("/result/details_0")
        .or_else(|| response.get("details_0"))
        .unwrap_or(response);
    let rank = details
        .get("rank")
        .and_then(Value::as_u64)
        .filter(|rank| *rank > 0);
    let bucket_present = details
        .get("bucket")
        .and_then(Value::as_str)
        .is_some_and(|bucket| !bucket.trim().is_empty());
    let categories = bounded_array_len(details.get("categories"));
    ProviderAnalysis {
        summary: ProviderSummary::DomainRanking {
            rank,
            bucket_present,
            categories,
        },
        findings: info_finding(
            rank.is_some() || bucket_present,
            "domain-ranking-observed",
            "Cloudflare Radar returned a public domain ranking observation",
        ),
    }
}

fn analyze_ssl_labs(response: &Value) -> ProviderAnalysis {
    let ready = response
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| status.eq_ignore_ascii_case("ready"));
    let mut endpoints = 0_usize;
    let mut strong_endpoints = 0_usize;
    let mut weak_endpoints = 0_usize;
    for grade in response
        .get("endpoints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PROVIDER_RECORDS)
        .filter_map(|endpoint| endpoint.get("grade").and_then(Value::as_str))
    {
        endpoints += 1;
        if matches!(grade, "A+" | "A" | "A-" | "B") {
            strong_endpoints += 1;
        } else if matches!(grade, "C" | "D" | "E" | "F" | "T" | "M") {
            weak_endpoints += 1;
        }
    }
    ProviderAnalysis {
        summary: ProviderSummary::ExternalTlsAssessment {
            ready,
            endpoints,
            strong_endpoints,
            weak_endpoints,
        },
        findings: (weak_endpoints > 0)
            .then_some(ProviderFinding {
                key: "external-tls-grade-risk",
                title: "The external TLS assessment reported a weak endpoint grade",
                severity: Severity::Medium,
                confidence: Confidence::Confirmed,
            })
            .into_iter()
            .collect(),
    }
}

fn analyze_doh(response: &Value) -> ProviderAnalysis {
    let status = response
        .get("Status")
        .and_then(Value::as_u64)
        .and_then(|value| u16::try_from(value).ok());
    let answers = response
        .get("Answer")
        .and_then(Value::as_array)
        .map_or(0, |answers| answers.len().min(10_000));
    ProviderAnalysis {
        summary: ProviderSummary::DnsOverHttps {
            status,
            answers,
            truncated: response.get("TC").and_then(Value::as_bool).unwrap_or(false),
            authenticated_data: response.get("AD").and_then(Value::as_bool).unwrap_or(false),
        },
        findings: Vec::new(),
    }
}

fn analyze_ripestat(scanner_id: &str, response: &Value) -> ProviderAnalysis {
    match scanner_id {
        "autonomous-neighbor-peering-map" => return analyze_autonomous_neighbors(response),
        "ip-allocation-history-tracker" => return analyze_allocation_history(response),
        "ip-info" => return analyze_network_info(response),
        "ns-geo-asn-diversity-analyzer" => {
            return analyze_nameserver_diversity(response, &[]);
        }
        "irr-routing-registry-analyzer" => return analyze_irr_registry(response),
        _ => {}
    }
    let data = response.get("data").unwrap_or(response);
    let prefixes = array_len(data, &["prefixes", "announced_space"]);
    let origins = array_len(data, &["asns", "origins"]);
    let statuses = data
        .get("routes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|route| route.get("status").and_then(Value::as_str))
        .chain(data.get("status").and_then(Value::as_str));
    let mut valid_routes = 0_usize;
    let mut invalid_routes = 0_usize;
    let mut unknown_routes = 0_usize;
    for status in statuses.take(10_000) {
        if status.eq_ignore_ascii_case("valid") {
            valid_routes += 1;
        } else if status.to_ascii_lowercase().starts_with("invalid") {
            invalid_routes += 1;
        } else {
            unknown_routes += 1;
        }
    }
    let observed = prefixes + origins + valid_routes + invalid_routes + unknown_routes > 0;
    let findings = match scanner_id {
        "rpki-route-validity-check" if invalid_routes > 0 => vec![ProviderFinding {
            key: "rpki-route-invalid",
            title: "The route origin is invalid under the observed RPKI state",
            severity: Severity::High,
            confidence: Confidence::Confirmed,
        }],
        "bgp-route-analysis" if observed => vec![ProviderFinding {
            key: "routing-observations-present",
            title: "The provider returned routing observations",
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
        }],
        "asn-lookup" if observed => vec![ProviderFinding {
            key: "autonomous-system-context-observed",
            title: "The provider returned autonomous-system routing context",
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
        }],
        _ => Vec::new(),
    };
    ProviderAnalysis {
        summary: ProviderSummary::Routing {
            prefixes,
            origins,
            valid_routes,
            invalid_routes,
            unknown_routes,
        },
        findings,
    }
}

fn analyze_autonomous_neighbors(response: &Value) -> ProviderAnalysis {
    let data = response.get("data").unwrap_or(response);
    let mut autonomous_systems = BTreeSet::new();
    let mut records = 0_usize;
    let mut left_neighbors = 0_usize;
    let mut right_neighbors = 0_usize;
    let mut uncertain_neighbors = 0_usize;
    for neighbor in data
        .get("neighbours")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PROVIDER_RECORDS)
    {
        let Some(asn) = neighbor.get("asn").and_then(json_scalar_key) else {
            continue;
        };
        let Some(position) = neighbor
            .get("position")
            .or_else(|| neighbor.get("type"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        records += 1;
        autonomous_systems.insert(asn);
        if position.eq_ignore_ascii_case("left") {
            left_neighbors += 1;
        } else if position.eq_ignore_ascii_case("right") {
            right_neighbors += 1;
        } else {
            uncertain_neighbors += 1;
        }
    }
    let findings = (records > 0)
        .then_some(ProviderFinding {
            key: "autonomous-neighbors-observed",
            title: "The routing provider returned autonomous-system neighbours",
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
        })
        .into_iter()
        .collect();
    ProviderAnalysis {
        summary: ProviderSummary::AutonomousNeighborPeeringMap {
            records,
            unique_autonomous_systems: autonomous_systems.len(),
            left_neighbors,
            right_neighbors,
            uncertain_neighbors,
        },
        findings,
    }
}

fn json_scalar_key(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if !value.trim().is_empty() => Some(value.to_ascii_uppercase()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn analyze_allocation_history(response: &Value) -> ProviderAnalysis {
    let data = response.get("data").unwrap_or(response);
    let versions = data
        .get("num_versions")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or_else(|| bounded_array_len(data.get("versions")))
        .min(MAX_PROVIDER_RECORDS);
    let objects = bounded_array_len(data.get("objects"));
    let referencing_objects = bounded_array_len(data.get("referencing"));
    let referenced_objects = bounded_array_len(data.get("referenced_by"));
    let suggestions = bounded_array_len(data.get("suggestions"));
    let mut object_types = BTreeSet::new();
    for key in ["objects", "referencing", "referenced_by", "suggestions"] {
        for object in data
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(MAX_PROVIDER_RECORDS)
        {
            if let Some(object_type) = object
                .get("type")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            {
                object_types.insert(object_type.to_ascii_lowercase());
            }
        }
    }
    let observed = versions + objects + referencing_objects + referenced_objects > 0;
    ProviderAnalysis {
        summary: ProviderSummary::IpAllocationHistory {
            versions,
            objects,
            referencing_objects,
            referenced_objects,
            suggestions,
            unique_object_types: object_types.len().min(MAX_PROVIDER_RECORDS),
        },
        findings: info_finding(
            observed,
            "allocation-history-observed",
            "The registry provider returned historical allocation objects",
        ),
    }
}

fn analyze_network_info(response: &Value) -> ProviderAnalysis {
    let data = response.get("data").unwrap_or(response);
    let prefix_present = data
        .get("prefix")
        .and_then(Value::as_str)
        .is_some_and(|prefix| !prefix.trim().is_empty());
    let autonomous_systems = distinct_array_values(data.get("asns"));
    ProviderAnalysis {
        summary: ProviderSummary::IpNetworkInfo {
            prefix_present,
            autonomous_systems,
        },
        findings: info_finding(
            prefix_present || autonomous_systems > 0,
            "network-information-observed",
            "The routing provider returned public network information",
        ),
    }
}

pub(crate) fn analyze_nameserver_diversity(
    response: &Value,
    enrichments: &[NameserverEnrichment],
) -> ProviderAnalysis {
    let data = response.get("data").unwrap_or(response);
    let forward_nodes = bounded_object_len(data.get("forward_nodes"));
    let reverse_nodes = bounded_object_len(data.get("reverse_nodes"));
    let resolver_nameservers = distinct_array_values(data.get("nameservers"));
    let authoritative_nameservers = distinct_array_values(data.get("authoritative_nameservers"));
    let mut chain_targets = BTreeSet::new();
    for key in ["forward_nodes", "reverse_nodes"] {
        for values in data
            .get(key)
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(|nodes| nodes.values())
            .filter_map(Value::as_array)
        {
            for value in values.iter().take(MAX_PROVIDER_RECORDS) {
                if let Some(value) = value.as_str().filter(|value| !value.trim().is_empty()) {
                    chain_targets.insert(value.to_ascii_lowercase());
                    if chain_targets.len() == MAX_PROVIDER_RECORDS {
                        break;
                    }
                }
            }
            if chain_targets.len() == MAX_PROVIDER_RECORDS {
                break;
            }
        }
    }
    let mut countries = BTreeSet::new();
    let mut autonomous_systems = BTreeSet::new();
    let mut enriched_nameservers = 0_usize;
    for enrichment in enrichments.iter().take(MAX_PROVIDER_RECORDS) {
        enriched_nameservers +=
            usize::from(enrichment.network_info.is_some() || enrichment.location.is_some());
        if let Some(network) = enrichment.network_info.as_ref() {
            let data = network.get("data").unwrap_or(network);
            collect_array_values(data.get("asns"), &mut autonomous_systems);
        }
        if let Some(location) = enrichment.location.as_ref() {
            let geo = location.get("geo").unwrap_or(location);
            if let Some(country) = geo
                .get("country_code")
                .or_else(|| geo.get("country"))
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            {
                countries.insert(country.to_ascii_uppercase());
            }
            if let Some(asn) = location
                .pointer("/as/asn")
                .or_else(|| location.get("asn"))
                .and_then(json_scalar_key)
            {
                autonomous_systems.insert(asn);
            }
        }
    }
    let actual_diversity = countries.len() >= 2 || autonomous_systems.len() >= 2;
    ProviderAnalysis {
        summary: ProviderSummary::NameserverDiversity {
            forward_nodes,
            reverse_nodes,
            resolver_nameservers,
            authoritative_nameservers,
            unique_chain_targets: chain_targets.len(),
            enriched_nameservers,
            unique_countries: countries.len(),
            unique_autonomous_systems: autonomous_systems.len(),
        },
        findings: info_finding(
            authoritative_nameservers >= 2 && actual_diversity,
            "nameserver-diversity-observed",
            "Authoritative nameservers span multiple countries or autonomous systems",
        ),
    }
}

/// Extracts distinct authoritative nameserver IPs for bounded real enrichment.
#[must_use]
pub(crate) fn authoritative_nameserver_addresses(response: &Value) -> Vec<String> {
    let data = response.get("data").unwrap_or(response);
    let forward_nodes = data.get("forward_nodes").and_then(Value::as_object);
    let mut addresses = BTreeSet::new();
    for value in data
        .get("authoritative_nameservers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PROVIDER_RECORDS)
        .filter_map(Value::as_str)
    {
        if let Ok(address) = value.parse::<IpAddr>() {
            addresses.insert(address.to_string());
            continue;
        }
        let normalized = value.trim_end_matches('.');
        let resolved = forward_nodes.into_iter().filter_map(|nodes| {
            nodes
                .iter()
                .find(|(name, _)| name.trim_end_matches('.').eq_ignore_ascii_case(normalized))
                .map(|(_, values)| values)
        });
        for address in resolved
            .filter_map(Value::as_array)
            .flat_map(|values| values.iter())
            .take(MAX_PROVIDER_RECORDS)
            .filter_map(Value::as_str)
            .filter_map(|address| address.parse::<IpAddr>().ok())
        {
            addresses.insert(address.to_string());
        }
    }
    addresses.into_iter().collect()
}

/// Extracts distinct address answers from a DNS chain for bounded domain enrichment.
#[must_use]
pub(crate) fn dns_chain_addresses(response: &Value) -> Vec<String> {
    let data = response.get("data").unwrap_or(response);
    data.get("forward_nodes")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|nodes| nodes.values())
        .filter_map(Value::as_array)
        .flat_map(|values| values.iter())
        .take(MAX_PROVIDER_RECORDS)
        .filter_map(Value::as_str)
        .filter_map(|value| value.parse::<IpAddr>().ok())
        .map(|address| address.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn analyze_irr_registry(response: &Value) -> ProviderAnalysis {
    let data = response.get("data").unwrap_or(response);
    let records = bounded_array_len(data.get("records"));
    let authorities = distinct_array_values(data.get("authorities"));
    let mut irr_records = 0_usize;
    let mut ipv4_route_objects = 0_usize;
    let mut ipv6_route_objects = 0_usize;
    let mut origins = BTreeSet::new();
    let mut sources = BTreeSet::new();
    for record in data
        .get("irr_records")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PROVIDER_RECORDS)
    {
        let Some(entries) = record.as_array() else {
            continue;
        };
        irr_records += 1;
        let mut has_route = false;
        let mut has_route6 = false;
        for entry in entries.iter().take(1_000) {
            let Some(key) = entry.get("key").and_then(Value::as_str) else {
                continue;
            };
            let value = entry.get("value").and_then(Value::as_str);
            if key.eq_ignore_ascii_case("route") {
                has_route = true;
            } else if key.eq_ignore_ascii_case("route6") {
                has_route6 = true;
            } else if key.eq_ignore_ascii_case("origin") {
                if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
                    origins.insert(value.to_ascii_uppercase());
                }
            } else if key.eq_ignore_ascii_case("source")
                && let Some(value) = value.filter(|value| !value.trim().is_empty())
            {
                sources.insert(value.to_ascii_uppercase());
            }
        }
        ipv4_route_objects += usize::from(has_route);
        ipv6_route_objects += usize::from(has_route6);
    }
    ProviderAnalysis {
        summary: ProviderSummary::IrrRoutingRegistry {
            records,
            irr_records,
            authorities,
            route_objects: ipv4_route_objects,
            route6_objects: ipv6_route_objects,
            unique_origins: origins.len(),
            unique_sources: sources.len(),
        },
        findings: info_finding(
            ipv4_route_objects + ipv6_route_objects > 0,
            "irr-route-objects-observed",
            "The routing registry provider returned route objects",
        ),
    }
}

fn bounded_array_len(value: Option<&Value>) -> usize {
    value
        .and_then(Value::as_array)
        .map_or(0, |values| values.len().min(MAX_PROVIDER_RECORDS))
}

fn bounded_object_len(value: Option<&Value>) -> usize {
    value
        .and_then(Value::as_object)
        .map_or(0, |values| values.len().min(MAX_PROVIDER_RECORDS))
}

fn distinct_array_values(value: Option<&Value>) -> usize {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PROVIDER_RECORDS)
        .filter_map(json_scalar_key)
        .collect::<BTreeSet<_>>()
        .len()
}

fn collect_array_values(value: Option<&Value>, destination: &mut BTreeSet<String>) {
    for value in value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PROVIDER_RECORDS)
        .filter_map(json_scalar_key)
    {
        destination.insert(value);
    }
}

fn info_finding(observed: bool, key: &'static str, title: &'static str) -> Vec<ProviderFinding> {
    observed
        .then_some(ProviderFinding {
            key,
            title,
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
        })
        .into_iter()
        .collect()
}

fn array_len(data: &Value, keys: &[&str]) -> usize {
    keys.iter()
        .filter_map(|key| data.get(key).and_then(Value::as_array))
        .map(Vec::len)
        .sum::<usize>()
        .min(10_000)
}

fn analyze_pagespeed(scanner_id: &str, response: &Value) -> ProviderAnalysis {
    let raw_score = response
        .get("performance_score")
        .and_then(Value::as_f64)
        .or_else(|| {
            response
                .pointer("/lighthouseResult/categories/performance/score")
                .and_then(Value::as_f64)
        });
    let performance_score = raw_score.and_then(percent);
    let largest_contentful_paint_ms = metric(
        response,
        "/metrics/largest_contentful_paint_ms",
        "/lighthouseResult/audits/largest-contentful-paint/numericValue",
        1.0,
    );
    let cumulative_layout_shift_milli = metric(
        response,
        "/metrics/cumulative_layout_shift",
        "/lighthouseResult/audits/cumulative-layout-shift/numericValue",
        1_000.0,
    );
    let failed_audits = response
        .pointer("/lighthouseResult/audits")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|audits| audits.values())
        .filter(|audit| {
            audit
                .get("score")
                .and_then(Value::as_f64)
                .is_some_and(|score| score < 0.5)
        })
        .take(10_000)
        .count();
    let findings = if matches!(scanner_id, "performance-monitoring" | "quality-metrics")
        && performance_score.is_some_and(|score| score < 50)
    {
        vec![ProviderFinding {
            key: "low-performance-score",
            title: "The external performance assessment reported a low score",
            severity: Severity::Medium,
            confidence: Confidence::Confirmed,
        }]
    } else {
        Vec::new()
    };
    ProviderAnalysis {
        summary: ProviderSummary::PageSpeed {
            performance_score,
            largest_contentful_paint_ms,
            cumulative_layout_shift_milli,
            failed_audits,
        },
        findings,
    }
}

fn percent(value: f64) -> Option<u8> {
    let scaled = if value <= 1.0 { value * 100.0 } else { value };
    finite_u64(scaled).and_then(|value| u8::try_from(value.min(100)).ok())
}

fn metric(response: &Value, normalized: &str, raw: &str, scale: f64) -> Option<u64> {
    response
        .pointer(normalized)
        .and_then(Value::as_f64)
        .or_else(|| response.pointer(raw).and_then(Value::as_f64))
        .and_then(|value| finite_u64(value * scale))
}

fn finite_u64(value: f64) -> Option<u64> {
    (value.is_finite() && value >= 0.0)
        .then(|| value.round().to_string().parse().ok())
        .flatten()
}

fn analyze_reputation(scanner_id: &str, response: &Value) -> ProviderAnalysis {
    let stats = response
        .pointer("/data/attributes/last_analysis_stats")
        .or_else(|| response.get("stats"))
        .unwrap_or(response);
    let malicious = count(stats, "malicious");
    let suspicious = count(stats, "suspicious");
    let harmless = count(stats, "harmless");
    let undetected = count(stats, "undetected");
    let abuse_confidence = response
        .pointer("/data/abuseConfidenceScore")
        .or_else(|| response.get("abuseConfidenceScore"))
        .and_then(Value::as_u64)
        .and_then(|score| u8::try_from(score.min(100)).ok());
    reputation_analysis(
        scanner_id,
        malicious,
        suspicious,
        harmless,
        undetected,
        abuse_confidence,
    )
}

fn analyze_urlhaus(scanner_id: &str, response: &Value) -> ProviderAnalysis {
    let malicious = response
        .get("urls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PROVIDER_RECORDS)
        .filter(|url| url.as_object().is_some())
        .count();
    let malicious = u64::try_from(malicious).unwrap_or(MAX_PROVIDER_RECORDS_U64);
    reputation_analysis(scanner_id, malicious, 0, 0, 0, None)
}

fn analyze_otx(scanner_id: &str, response: &Value) -> ProviderAnalysis {
    let suspicious = response
        .pointer("/pulse_info/count")
        .and_then(Value::as_u64)
        .unwrap_or_default()
        .min(MAX_PROVIDER_RECORDS_U64);
    reputation_analysis(scanner_id, 0, suspicious, 0, 0, None)
}

fn analyze_blocklist_reputation(scanner_id: &str, response: &Value) -> ProviderAnalysis {
    let data = response.get("data").unwrap_or(response);
    let malicious = data
        .get("blocklists")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PROVIDER_RECORDS)
        .filter(|entry| entry.get("listed").and_then(Value::as_bool) == Some(true))
        .count();
    let malicious = u64::try_from(malicious).unwrap_or(MAX_PROVIDER_RECORDS_U64);
    reputation_analysis(scanner_id, malicious, 0, 0, 0, None)
}

fn reputation_analysis(
    scanner_id: &str,
    malicious: u64,
    suspicious: u64,
    harmless: u64,
    undetected: u64,
    abuse_confidence: Option<u8>,
) -> ProviderAnalysis {
    let risky =
        malicious > 0 || suspicious > 0 || abuse_confidence.is_some_and(|score| score >= 50);
    let findings = if risky && reputation_scanner(scanner_id) {
        vec![ProviderFinding {
            key: "provider-reputation-risk",
            title: "A configured reputation source returned a material risk signal",
            severity: Severity::High,
            confidence: Confidence::Confirmed,
        }]
    } else {
        Vec::new()
    };
    ProviderAnalysis {
        summary: ProviderSummary::Reputation {
            malicious,
            suspicious,
            harmless,
            undetected,
            abuse_confidence,
        },
        findings,
    }
}

fn reputation_scanner(scanner_id: &str) -> bool {
    matches!(
        scanner_id,
        "domain-reputation-check"
            | "ip-reputation-check"
            | "ip-reputation-trending"
            | "js-malware-scanner"
            | "malware-phishing"
            | "threat-feed-correlator"
            | "virustotal-scan"
    )
}

fn count(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_default()
        .min(MAX_PROVIDER_RECORDS_U64)
}

fn analyze_urlscan(scanner_id: &str, response: &Value) -> ProviderAnalysis {
    let mut domains = BTreeSet::new();
    let mut ips = BTreeSet::new();
    let mut records = 0_usize;
    let mut malicious_records = 0_usize;
    for record in response
        .get("results")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(10_000)
    {
        let Some(page) = record.get("page").and_then(Value::as_object) else {
            continue;
        };
        records += 1;
        if let Some(domain) = page.get("domain").and_then(Value::as_str) {
            domains.insert(domain.to_ascii_lowercase());
        }
        if let Some(ip) = page.get("ip").and_then(Value::as_str) {
            ips.insert(ip.to_owned());
        }
        malicious_records += usize::from(
            record
                .pointer("/verdicts/overall/malicious")
                .and_then(Value::as_bool)
                == Some(true),
        );
    }
    let findings = match scanner_id {
        "passive-dns-history" if records > 0 => vec![ProviderFinding {
            key: "historical-dns-observations",
            title: "The provider returned historical domain or address observations",
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
        }],
        "reverse-ip-lookup" if records > 0 => vec![ProviderFinding {
            key: "reverse-ip-host-observed",
            title: "The provider returned a host observation for the address",
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
        }],
        "associated-hosts" if records > 0 => vec![ProviderFinding {
            key: "associated-hosts-observed",
            title: "The provider returned associated host observations",
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
        }],
        _ if malicious_records > 0 => vec![ProviderFinding {
            key: "malicious-urlscan-observation",
            title: "URLScan marked one or more observations as malicious",
            severity: Severity::High,
            confidence: Confidence::Confirmed,
        }],
        _ => Vec::new(),
    };
    ProviderAnalysis {
        summary: ProviderSummary::UrlScan {
            records,
            unique_domains: domains.len(),
            unique_ips: ips.len(),
            malicious_records,
        },
        findings,
    }
}

fn analyze_certificate_transparency(
    scanner_id: &str,
    response: &Value,
    baseline: ProviderBaseline<'_>,
) -> ProviderAnalysis {
    let mut names = BTreeSet::new();
    let mut issuers = BTreeSet::new();
    let mut records = 0_usize;
    for record in response.as_array().into_iter().flatten().take(10_000) {
        let Some(object) = record.as_object() else {
            continue;
        };
        let Some(issuer) = object.get("issuer_name").and_then(Value::as_str) else {
            continue;
        };
        records += 1;
        issuers.insert(issuer.to_owned());
        if let Some(values) = object.get("name_value").and_then(Value::as_str) {
            names.extend(
                values
                    .lines()
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .take(1_000)
                    .map(str::to_ascii_lowercase),
            );
        }
    }
    let unexpected = match baseline {
        ProviderBaseline::CertificateIssuers(expected) => issuers.iter().any(|issuer| {
            !expected
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(issuer))
        }),
        ProviderBaseline::None => false,
    };
    let concrete_names = names
        .iter()
        .filter(|name| is_concrete_hostname(name))
        .count();
    let findings = match scanner_id {
        "rogue-certificate-check" if unexpected => vec![ProviderFinding {
            key: "unexpected-certificate-issuer",
            title: "Certificate transparency contains an unexpected issuer",
            severity: Severity::High,
            confidence: Confidence::Confirmed,
        }],
        "ct-log-query" if records > 0 => vec![ProviderFinding {
            key: "certificate-transparency-record-observed",
            title: "Certificate transparency records were observed",
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
        }],
        "subdomain-enum" if !names.is_empty() => vec![ProviderFinding {
            key: "subdomain-observations-present",
            title: "Certificate transparency returned hostname observations",
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
        }],
        "associated-hosts" if concrete_names > 0 => vec![ProviderFinding {
            key: "associated-hosts-observed",
            title: "Certificate transparency returned associated host observations",
            severity: Severity::Info,
            confidence: Confidence::Confirmed,
        }],
        _ => Vec::new(),
    };
    ProviderAnalysis {
        summary: ProviderSummary::CertificateTransparency {
            records,
            unique_names: names.len(),
            unique_issuers: issuers.len(),
            wildcard_names: names.iter().filter(|name| name.starts_with("*.")).count(),
        },
        findings,
    }
}

fn analyze_certificate_authorities(response: &Value) -> ProviderAnalysis {
    let mut names = BTreeSet::new();
    let mut authorities = BTreeSet::new();
    let mut records = 0_usize;
    for record in response
        .as_array()
        .into_iter()
        .flatten()
        .take(MAX_PROVIDER_RECORDS)
    {
        let Some(issuer) = record
            .get("issuer_name")
            .and_then(Value::as_str)
            .filter(|issuer| !issuer.trim().is_empty())
        else {
            continue;
        };
        records += 1;
        authorities.insert(issuer.to_ascii_lowercase());
        if let Some(values) = record.get("name_value").and_then(Value::as_str) {
            names.extend(
                values
                    .lines()
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .take(1_000)
                    .map(str::to_ascii_lowercase),
            );
        }
    }
    ProviderAnalysis {
        summary: ProviderSummary::CertificateAuthorityRecon {
            records,
            unique_authorities: authorities.len(),
            unique_names: names.len().min(MAX_PROVIDER_RECORDS),
            wildcard_names: names.iter().filter(|name| name.starts_with("*.")).count(),
        },
        findings: info_finding(
            !authorities.is_empty(),
            "certificate-authority-observed",
            "Certificate transparency returned certificate authority observations",
        ),
    }
}

fn analyze_ipinfo(scanner_id: &str, response: &Value) -> ProviderAnalysis {
    let geo = response.get("geo").unwrap_or(response);
    let present = |keys: &[&str]| {
        keys.iter().any(|key| {
            geo.get(key)
                .or_else(|| response.get(key))
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty())
        })
    };
    let coordinates_present = valid_coordinates(geo) || valid_coordinates(response);
    if scanner_id == "ip-info" {
        let city_present = present(&["city"]);
        let region_present = present(&["region", "region_code"]);
        let country_present = present(&["country", "country_code"]);
        let timezone_present = present(&["timezone"]);
        let autonomous_system_present = response
            .pointer("/as/asn")
            .or_else(|| response.get("asn"))
            .and_then(json_scalar_key)
            .is_some();
        return ProviderAnalysis {
            summary: ProviderSummary::IpLocationInfo {
                city_present,
                region_present,
                country_present,
                timezone_present,
                coordinates_present,
                autonomous_system_present,
            },
            findings: info_finding(
                city_present
                    || region_present
                    || country_present
                    || timezone_present
                    || coordinates_present
                    || autonomous_system_present,
                "ip-location-observed",
                "The location provider returned public address metadata",
            ),
        };
    }
    if scanner_id == "network-timezone-detection" {
        let timezone_present = present(&["timezone"]);
        let country_present = present(&["country", "country_code"]);
        return ProviderAnalysis {
            summary: ProviderSummary::NetworkTimezone {
                timezone_present,
                country_present,
                coordinates_present,
            },
            findings: info_finding(
                timezone_present,
                "network-timezone-observed",
                "The location provider returned timezone metadata",
            ),
        };
    }
    let city_present = present(&["city"]);
    let region_present = present(&["region", "region_code"]);
    let country_present = present(&["country", "country_code"]);
    ProviderAnalysis {
        summary: ProviderSummary::ServerLocation {
            city_present,
            region_present,
            country_present,
            coordinates_present,
        },
        findings: info_finding(
            city_present || region_present || country_present || coordinates_present,
            "server-location-observed",
            "The location provider returned public server location metadata",
        ),
    }
}

fn valid_coordinates(value: &Value) -> bool {
    let numeric = value
        .get("latitude")
        .and_then(Value::as_f64)
        .zip(value.get("longitude").and_then(Value::as_f64))
        .is_some_and(|(latitude, longitude)| {
            latitude.is_finite()
                && longitude.is_finite()
                && (-90.0..=90.0).contains(&latitude)
                && (-180.0..=180.0).contains(&longitude)
        });
    numeric
        || value
            .get("loc")
            .and_then(Value::as_str)
            .and_then(|coordinates| coordinates.split_once(','))
            .and_then(|(latitude, longitude)| {
                latitude
                    .parse::<f64>()
                    .ok()
                    .zip(longitude.parse::<f64>().ok())
            })
            .is_some_and(|(latitude, longitude)| {
                latitude.is_finite()
                    && longitude.is_finite()
                    && (-90.0..=90.0).contains(&latitude)
                    && (-180.0..=180.0).contains(&longitude)
            })
}

fn is_concrete_hostname(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty()
        || name.len() > 253
        || !name.is_ascii()
        || name.contains('*')
        || name.parse::<std::net::IpAddr>().is_ok()
    {
        return false;
    }

    let mut labels = name.split('.');
    let Some(first) = labels.next() else {
        return false;
    };
    let Some(second) = labels.next() else {
        return false;
    };
    valid_hostname_label(first) && valid_hostname_label(second) && labels.all(valid_hostname_label)
}

fn valid_hostname_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sugra_domain::Severity;

    use super::*;

    #[test]
    fn rogue_certificate_check_flags_unexpected_issuers_without_retaining_entries()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!([
            {"name_value": "example.com\nwww.example.com", "issuer_name": "Unexpected CA"},
            {"name_value": "*.example.com", "issuer_name": "Expected CA"}
        ]);

        let analysis = analyze_provider_response(
            "rogue-certificate-check",
            "crtsh",
            &response,
            ProviderBaseline::CertificateIssuers(&["Expected CA"]),
        )
        .ok_or("crt.sh response must be supported")?;

        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.findings[0].key, "unexpected-certificate-issuer");
        assert_eq!(analysis.findings[0].severity, Severity::High);
        let serialized = serde_json::to_string(&analysis)?;
        assert!(!serialized.contains("www.example.com"));
        assert!(!serialized.contains("Unexpected CA"));
        Ok(())
    }

    #[test]
    fn passive_dns_history_summarizes_urlscan_results_without_retaining_hosts()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({"results": [
            {"page": {"domain": "one.example.com", "ip": "192.0.2.1"}},
            {"page": {"domain": "two.example.com", "ip": "192.0.2.1"}}
        ]});

        let analysis = analyze_provider_response(
            "passive-dns-history",
            "urlscan",
            &response,
            ProviderBaseline::None,
        )
        .ok_or("URLScan response must be supported")?;

        assert_eq!(analysis.findings[0].key, "historical-dns-observations");
        assert_eq!(
            analysis.summary,
            ProviderSummary::UrlScan {
                records: 2,
                unique_domains: 2,
                unique_ips: 1,
                malicious_records: 0,
            }
        );
        let serialized = serde_json::to_string(&analysis)?;
        assert!(!serialized.contains("one.example.com"));
        assert!(!serialized.contains("192.0.2.1"));
        Ok(())
    }

    #[test]
    fn certificate_transparency_expected_issuer_is_a_negative_control()
    -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "rogue-certificate-check",
            "crtsh",
            &json!([{"name_value": "example.com", "issuer_name": "Expected CA"}]),
            ProviderBaseline::CertificateIssuers(&["expected ca"]),
        )
        .ok_or("crt.sh response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert_eq!(
            analysis.summary,
            ProviderSummary::CertificateTransparency {
                records: 1,
                unique_names: 1,
                unique_issuers: 1,
                wildcard_names: 0,
            }
        );
        Ok(())
    }

    #[test]
    fn certificate_transparency_ignores_malformed_records() -> Result<(), Box<dyn std::error::Error>>
    {
        let analysis = analyze_provider_response(
            "ct-log-query",
            "crtsh",
            &json!([null, "raw", {"name_value": "secret.example"}]),
            ProviderBaseline::None,
        )
        .ok_or("crt.sh response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert_eq!(
            analysis.summary,
            ProviderSummary::CertificateTransparency {
                records: 0,
                unique_names: 0,
                unique_issuers: 0,
                wildcard_names: 0,
            }
        );
        assert!(!serde_json::to_string(&analysis)?.contains("secret.example"));
        Ok(())
    }

    #[test]
    fn urlscan_empty_results_are_a_negative_control() -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "passive-dns-history",
            "urlscan",
            &json!({"results": []}),
            ProviderBaseline::None,
        )
        .ok_or("URLScan response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert_eq!(
            analysis.summary,
            ProviderSummary::UrlScan {
                records: 0,
                unique_domains: 0,
                unique_ips: 0,
                malicious_records: 0,
            }
        );
        Ok(())
    }

    #[test]
    fn urlscan_malformed_results_do_not_leak_nested_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "reverse-ip-lookup",
            "urlscan",
            &json!({"results": [null, {"page": "invalid", "token": "private-value"}]}),
            ProviderBaseline::None,
        )
        .ok_or("URLScan response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert!(!serde_json::to_string(&analysis)?.contains("private-value"));
        Ok(())
    }

    #[test]
    fn rpki_route_validity_flags_invalid_origins() -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "rpki-route-validity-check",
            "ripestat",
            &json!({"data": {"status": "invalid_asn", "prefixes": ["192.0.2.0/24"]}}),
            ProviderBaseline::None,
        )
        .ok_or("RIPEstat response must be supported")?;

        assert_eq!(analysis.findings[0].key, "rpki-route-invalid");
        assert_eq!(
            analysis.summary,
            ProviderSummary::Routing {
                prefixes: 1,
                origins: 0,
                valid_routes: 0,
                invalid_routes: 1,
                unknown_routes: 0,
            }
        );
        Ok(())
    }

    #[test]
    fn rpki_valid_route_is_a_negative_control() -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "rpki-route-validity-check",
            "ripestat",
            &json!({"data": {"status": "valid", "asns": [64496]}}),
            ProviderBaseline::None,
        )
        .ok_or("RIPEstat response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert!(matches!(
            analysis.summary,
            ProviderSummary::Routing {
                valid_routes: 1,
                invalid_routes: 0,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn ripestat_malformed_routes_are_counted_without_retaining_resources()
    -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "bgp-route-analysis",
            "ripestat",
            &json!({"data": {"routes": [null, {"status": "mystery"}], "resource": "private"}}),
            ProviderBaseline::None,
        )
        .ok_or("RIPEstat response must be supported")?;

        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.findings[0].key, "routing-observations-present");
        assert!(matches!(
            analysis.summary,
            ProviderSummary::Routing {
                unknown_routes: 1,
                ..
            }
        ));
        assert!(!serde_json::to_string(&analysis)?.contains("private"));
        Ok(())
    }

    #[test]
    fn performance_monitoring_flags_a_low_pagespeed_score() -> Result<(), Box<dyn std::error::Error>>
    {
        let analysis = analyze_provider_response(
            "performance-monitoring",
            "pagespeed",
            &json!({
                "performance_score": 0.42,
                "metrics": {"largest_contentful_paint_ms": 3100.0, "cumulative_layout_shift": 0.2}
            }),
            ProviderBaseline::None,
        )
        .ok_or("PageSpeed response must be supported")?;

        assert_eq!(analysis.findings[0].key, "low-performance-score");
        assert_eq!(
            analysis.summary,
            ProviderSummary::PageSpeed {
                performance_score: Some(42),
                largest_contentful_paint_ms: Some(3100),
                cumulative_layout_shift_milli: Some(200),
                failed_audits: 0,
            }
        );
        Ok(())
    }

    #[test]
    fn healthy_pagespeed_score_is_a_negative_control() -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "quality-metrics",
            "pagespeed",
            &json!({"lighthouseResult": {"categories": {"performance": {"score": 0.95}}}}),
            ProviderBaseline::None,
        )
        .ok_or("PageSpeed response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert!(matches!(
            analysis.summary,
            ProviderSummary::PageSpeed {
                performance_score: Some(95),
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn pagespeed_malformed_metrics_are_omitted_without_retaining_urls()
    -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "performance-monitoring",
            "pagespeed",
            &json!({"performance_score": "fast", "id": "https://private.example/?token=secret"}),
            ProviderBaseline::None,
        )
        .ok_or("PageSpeed response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert!(matches!(
            analysis.summary,
            ProviderSummary::PageSpeed {
                performance_score: None,
                largest_contentful_paint_ms: None,
                cumulative_layout_shift_milli: None,
                ..
            }
        ));
        let serialized = serde_json::to_string(&analysis)?;
        assert!(!serialized.contains("private.example"));
        assert!(!serialized.contains("secret"));
        Ok(())
    }

    #[test]
    fn domain_reputation_flags_malicious_engine_results() -> Result<(), Box<dyn std::error::Error>>
    {
        let analysis = analyze_provider_response(
            "domain-reputation-check",
            "virustotal",
            &json!({"data": {"attributes": {"last_analysis_stats": {
                "malicious": 3, "suspicious": 1, "harmless": 40, "undetected": 5
            }}}}),
            ProviderBaseline::None,
        )
        .ok_or("reputation response must be supported")?;

        assert_eq!(analysis.findings[0].key, "provider-reputation-risk");
        assert!(matches!(
            analysis.summary,
            ProviderSummary::Reputation {
                malicious: 3,
                suspicious: 1,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn harmless_reputation_result_is_a_negative_control() -> Result<(), Box<dyn std::error::Error>>
    {
        let analysis = analyze_provider_response(
            "virustotal-scan",
            "virustotal",
            &json!({"data": {"attributes": {"last_analysis_stats": {
                "malicious": 0, "suspicious": 0, "harmless": 52, "undetected": 4
            }}}}),
            ProviderBaseline::None,
        )
        .ok_or("reputation response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert!(matches!(
            analysis.summary,
            ProviderSummary::Reputation { harmless: 52, .. }
        ));
        Ok(())
    }

    #[test]
    fn dark_web_monitoring_counts_stealer_log_accounts_without_retaining_emails()
    -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "dark-web-monitoring",
            "hibp",
            &json!(["alice@example.com", "bob@example.net"]),
            ProviderBaseline::None,
        )
        .ok_or("HIBP response must be supported")?;

        assert_eq!(
            analysis.summary,
            ProviderSummary::HibpStealerLogs {
                exposed_accounts: 2,
            }
        );
        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.findings[0].key, "stealer-log-accounts-present");
        let serialized = serde_json::to_string(&analysis)?;
        assert!(!serialized.contains("alice@example.com"));
        assert!(!serialized.contains("bob@example.net"));
        Ok(())
    }

    #[test]
    fn pastebin_monitoring_counts_pastes_without_retaining_ids_or_titles()
    -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "pastebin-monitoring",
            "hibp",
            &json!([
                {
                    "Source": "Pastebin",
                    "Id": "private-paste-id",
                    "Title": "private paste title",
                    "EmailCount": 139
                },
                {"Source": "Pastie", "Id": "other-private-id", "EmailCount": 30}
            ]),
            ProviderBaseline::None,
        )
        .ok_or("HIBP response must be supported")?;

        assert_eq!(
            analysis.summary,
            ProviderSummary::HibpPastes {
                pastes: 2,
                email_mentions: 169,
            }
        );
        assert_eq!(analysis.findings.len(), 1);
        assert_eq!(analysis.findings[0].key, "paste-observations-present");
        let serialized = serde_json::to_string(&analysis)?;
        assert!(!serialized.contains("private-paste-id"));
        assert!(!serialized.contains("private paste title"));
        assert!(!serialized.contains("other-private-id"));
        Ok(())
    }

    #[test]
    fn hibp_empty_results_are_negative_controls() -> Result<(), Box<dyn std::error::Error>> {
        let cases = ["dark-web-monitoring", "pastebin-monitoring"];
        for scanner_id in cases {
            let analysis =
                analyze_provider_response(scanner_id, "hibp", &json!([]), ProviderBaseline::None)
                    .ok_or("HIBP response must be supported")?;
            assert!(analysis.findings.is_empty());
        }
        Ok(())
    }

    #[test]
    fn hibp_malformed_records_are_ignored_and_counts_saturate_without_leaks()
    -> Result<(), Box<dyn std::error::Error>> {
        let stealer_logs = analyze_provider_response(
            "dark-web-monitoring",
            "hibp",
            &json!([null, 7, {"Email": "hidden@example.com"}, "valid@example.com"]),
            ProviderBaseline::None,
        )
        .ok_or("HIBP response must be supported")?;
        assert_eq!(
            stealer_logs.summary,
            ProviderSummary::HibpStealerLogs {
                exposed_accounts: 1,
            }
        );

        let pastes = analyze_provider_response(
            "pastebin-monitoring",
            "hibp",
            &json!([
                null,
                "invalid",
                {"Id": "malformed-secret-id", "Title": "secret-title", "EmailCount": 7},
                {"Source": "Pastebin", "Id": "secret-id", "EmailCount": u64::MAX},
                {"Source": "Pastie", "Id": "other-secret-id", "EmailCount": 1}
            ]),
            ProviderBaseline::None,
        )
        .ok_or("HIBP response must be supported")?;
        assert_eq!(
            pastes.summary,
            ProviderSummary::HibpPastes {
                pastes: 2,
                email_mentions: MAX_PROVIDER_RECORDS_U64,
            }
        );

        let serialized = serde_json::to_string(&(stealer_logs, pastes))?;
        assert!(!serialized.contains("hidden@example.com"));
        assert!(!serialized.contains("valid@example.com"));
        assert!(!serialized.contains("secret-id"));
        assert!(!serialized.contains("secret-title"));

        let bounded = analyze_provider_response(
            "dark-web-monitoring",
            "hibp",
            &Value::Array(vec![json!("hidden@example.com"); MAX_PROVIDER_RECORDS + 1]),
            ProviderBaseline::None,
        )
        .ok_or("HIBP response must be supported")?;
        assert_eq!(
            bounded.summary,
            ProviderSummary::HibpStealerLogs {
                exposed_accounts: MAX_PROVIDER_RECORDS,
            }
        );
        Ok(())
    }

    #[test]
    fn malformed_reputation_values_are_zeroed_without_retaining_attributes()
    -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "ip-reputation-check",
            "abuseipdb",
            &json!({"data": {"abuseConfidenceScore": "high", "ipAddress": "192.0.2.44"}}),
            ProviderBaseline::None,
        )
        .ok_or("reputation response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert_eq!(
            analysis.summary,
            ProviderSummary::Reputation {
                malicious: 0,
                suspicious: 0,
                harmless: 0,
                undetected: 0,
                abuse_confidence: None,
            }
        );
        assert!(!serde_json::to_string(&analysis)?.contains("192.0.2.44"));
        Ok(())
    }

    #[test]
    fn encrypted_dns_response_is_summarized_without_answer_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "dns-over-https",
            "cloudflare-doh",
            &json!({
                "Status": 0,
                "TC": false,
                "AD": true,
                "Answer": [
                    {"name": "private.example", "type": 1, "data": "192.0.2.9"},
                    {"name": "private.example", "type": 28, "data": "2001:db8::9"}
                ]
            }),
            ProviderBaseline::None,
        )
        .ok_or("encrypted DNS response must be supported")?;

        assert_eq!(
            analysis.summary,
            ProviderSummary::DnsOverHttps {
                status: Some(0),
                answers: 2,
                truncated: false,
                authenticated_data: true,
            }
        );
        let serialized = serde_json::to_string(&analysis)?;
        assert!(!serialized.contains("private.example"));
        assert!(!serialized.contains("192.0.2.9"));
        Ok(())
    }

    #[test]
    fn malformed_encrypted_dns_metadata_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let analysis = analyze_provider_response(
            "dns-over-https",
            "google-doh",
            &json!({"Status": "ok", "TC": "false", "AD": null, "Answer": "private"}),
            ProviderBaseline::None,
        )
        .ok_or("encrypted DNS response must be supported")?;

        assert_eq!(
            analysis.summary,
            ProviderSummary::DnsOverHttps {
                status: None,
                answers: 0,
                truncated: false,
                authenticated_data: false,
            }
        );
        assert!(!serde_json::to_string(&analysis)?.contains("private"));
        Ok(())
    }

    #[test]
    fn archive_history_is_bounded_deduplicated_and_redacted()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!([
            ["timestamp", "original", "statuscode", "digest"],
            [
                "20200102030405",
                "https://private.example/a",
                "200",
                "secret-a"
            ],
            [
                "20210102030405",
                "https://private.example/a",
                "200",
                "secret-a"
            ],
            [
                "20220102030405",
                "https://private.example/b",
                "404",
                "secret-b"
            ],
            ["invalid", "https://ignored.example", "999", "secret-c"]
        ]);
        let analysis = analyze_provider_response(
            "archive-history",
            "wayback",
            &response,
            ProviderBaseline::None,
        )
        .ok_or("Wayback response must be supported")?;
        assert_eq!(
            analysis.summary,
            ProviderSummary::ArchiveHistory {
                snapshots: 3,
                unique_urls: 2,
                unique_statuses: 2,
                unique_digests: 2,
                earliest_year: Some(2020),
                latest_year: Some(2022),
            }
        );
        assert_eq!(analysis.findings[0].key, "archived-snapshots-observed");
        let serialized = serde_json::to_string(&analysis)?;
        assert!(!serialized.contains("private.example"));
        assert!(!serialized.contains("secret-a"));

        let empty = analyze_provider_response(
            "archive-history",
            "wayback",
            &json!([]),
            ProviderBaseline::None,
        )
        .ok_or("Wayback response must be supported")?;
        assert!(empty.findings.is_empty());
        Ok(())
    }

    #[test]
    fn registration_analysis_counts_context_without_retaining_contact_data()
    -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "handle": "NET-PRIVATE",
            "startAddress": "192.0.2.0",
            "endAddress": "192.0.2.255",
            "startAutnum": 64500,
            "endAutnum": 64500,
            "entities": [
                {"handle": "CONTACT-PRIVATE", "roles": ["registrant", "registrant"], "email": "secret@example.com"},
                "malformed"
            ],
            "notices": [{"title": "private notice", "description": ["secret text"]}]
        });
        for scanner_id in ["rdap-lookup", "asn-lookup"] {
            let analysis =
                analyze_provider_response(scanner_id, "rdap", &response, ProviderBaseline::None)
                    .ok_or("RDAP response must be supported")?;
            assert!(matches!(
                analysis.summary,
                ProviderSummary::Registration {
                    handles: 2,
                    entities: 1,
                    roles: 1,
                    networks: 1,
                    autonomous_systems: 1,
                    notices: 1,
                }
            ));
            assert_eq!(analysis.findings.len(), 1);
            let serialized = serde_json::to_string(&analysis)?;
            assert!(!serialized.contains("secret@example.com"));
            assert!(!serialized.contains("CONTACT-PRIVATE"));
            assert!(!serialized.contains("private notice"));
        }
        let malformed = analyze_provider_response(
            "rdap-lookup",
            "rdap",
            &json!({"entities": "private", "vcardArray": ["secret@example.com"]}),
            ProviderBaseline::None,
        )
        .ok_or("RDAP response must be supported")?;
        assert!(malformed.findings.is_empty());
        assert!(!serde_json::to_string(&malformed)?.contains("secret"));
        Ok(())
    }

    #[test]
    fn host_intelligence_is_deduplicated_and_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let response = json!({
            "hostnames": ["PRIVATE.example", "private.example"],
            "domains": ["example", "example"],
            "ip_str": "192.0.2.10",
            "data": [
                {"port": 443, "ip_str": "192.0.2.10", "banner": "secret"},
                {"port": 443},
                {"port": 70000},
                "malformed"
            ]
        });
        let analysis = analyze_provider_response(
            "associated-hosts",
            "shodan",
            &response,
            ProviderBaseline::None,
        )
        .ok_or("Shodan response must be supported")?;
        assert_eq!(
            analysis.summary,
            ProviderSummary::HostIntelligence {
                records: 3,
                unique_hostnames: 1,
                unique_domains: 1,
                unique_ips: 1,
                open_ports: 1,
            }
        );
        assert_eq!(analysis.findings[0].key, "associated-hosts-observed");
        let serialized = serde_json::to_string(&analysis)?;
        assert!(!serialized.contains("PRIVATE.example"));
        assert!(!serialized.contains("192.0.2.10"));
        assert!(!serialized.contains("secret"));

        let target_only = analyze_provider_response(
            "associated-hosts",
            "shodan",
            &json!({"ip_str": "192.0.2.10", "data": [{"port": 443}]}),
            ProviderBaseline::None,
        )
        .ok_or("Shodan response must be supported")?;
        assert!(target_only.findings.is_empty());
        Ok(())
    }

    #[test]
    fn hostname_scanners_require_a_crt_name_not_only_an_issuer()
    -> Result<(), Box<dyn std::error::Error>> {
        let issuer_only = json!([{"issuer_name": "Private CA"}]);
        for scanner_id in ["subdomain-enum", "associated-hosts"] {
            let analysis = analyze_provider_response(
                scanner_id,
                "crtsh",
                &issuer_only,
                ProviderBaseline::None,
            )
            .ok_or("crt.sh response must be supported")?;
            assert!(analysis.findings.is_empty());
            assert!(matches!(
                analysis.summary,
                ProviderSummary::CertificateTransparency {
                    records: 1,
                    unique_names: 0,
                    ..
                }
            ));
        }
        Ok(())
    }

    #[test]
    fn associated_hosts_requires_a_concrete_crt_hostname() -> Result<(), Box<dyn std::error::Error>>
    {
        let wildcard_only = json!([{
            "issuer_name": "Private CA",
            "name_value": "*.private.example"
        }]);
        let analysis = analyze_provider_response(
            "associated-hosts",
            "crtsh",
            &wildcard_only,
            ProviderBaseline::None,
        )
        .ok_or("crt.sh response must be supported")?;

        assert!(analysis.findings.is_empty());
        assert!(matches!(
            analysis.summary,
            ProviderSummary::CertificateTransparency {
                records: 1,
                unique_names: 1,
                wildcard_names: 1,
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn existing_provider_shapes_emit_scanner_specific_observation_findings()
    -> Result<(), Box<dyn std::error::Error>> {
        let cases = [
            (
                "ct-log-query",
                "crtsh",
                json!([{"issuer_name": "Private CA", "name_value": "private.example"}]),
                "certificate-transparency-record-observed",
            ),
            (
                "subdomain-enum",
                "crtsh",
                json!([{"issuer_name": "Private CA", "name_value": "*.private.example"}]),
                "subdomain-observations-present",
            ),
            (
                "reverse-ip-lookup",
                "urlscan",
                json!({"results": [{"page": {"domain": "private.example", "ip": "192.0.2.1"}}]}),
                "reverse-ip-host-observed",
            ),
            (
                "bgp-route-analysis",
                "ripestat",
                json!({"data": {"routes": [{"status": "mystery"}]}}),
                "routing-observations-present",
            ),
        ];
        for (scanner_id, provider, response, key) in cases {
            let analysis =
                analyze_provider_response(scanner_id, provider, &response, ProviderBaseline::None)
                    .ok_or("provider response must be supported")?;
            assert_eq!(analysis.findings[0].key, key);
            let serialized = serde_json::to_string(&analysis)?;
            assert!(!serialized.contains("private.example"));
            assert!(!serialized.contains("192.0.2.1"));
            assert!(!serialized.contains("Private CA"));
        }
        Ok(())
    }
}
