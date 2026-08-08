//! Pure provider request plans derived from validated scanner options.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};

use sugra_domain::TargetKind;

/// Provider identities backed by concrete adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProviderName {
    /// Certificate Transparency search.
    CrtSh,
    /// `URLScan` search.
    UrlScan,
    /// Shodan host lookup.
    Shodan,
    /// Registration Data Access Protocol.
    Rdap,
    /// `RIPEstat` network data.
    RipeStat,
    /// Internet Archive CDX index.
    Wayback,
    /// `VirusTotal` reputation API.
    VirusTotal,
    /// `URLhaus` reputation API.
    UrlHaus,
    /// `AbuseIPDB` reputation API.
    AbuseIpDb,
    /// Google `PageSpeed` Insights.
    PageSpeed,
}

impl ProviderName {
    /// Returns the adapter provider key.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::CrtSh => "crtsh",
            Self::UrlScan => "urlscan",
            Self::Shodan => "shodan",
            Self::Rdap => "rdap",
            Self::RipeStat => "ripestat",
            Self::Wayback => "wayback",
            Self::VirusTotal => "virustotal",
            Self::UrlHaus => "urlhaus",
            Self::AbuseIpDb => "abuseipdb",
            Self::PageSpeed => "pagespeed",
        }
    }
}

/// Typed option projection consumed by provider planning.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProviderPlanOptions {
    /// Selected provider sources, in operator order.
    pub(crate) sources: Vec<String>,
    /// One explicitly selected provider.
    pub(crate) provider: Option<String>,
    /// Maximum provider records to consume.
    pub(crate) limit: Option<usize>,
    /// HTTP statuses retained by historical queries.
    pub(crate) status_filter: Vec<u16>,
    /// Whether equal content digests are collapsed.
    pub(crate) collapse_digest: bool,
    /// Whether a CT query includes wildcard names.
    pub(crate) include_wildcard: bool,
    /// Short reputation window in days.
    pub(crate) short_window: Option<u16>,
    /// Long reputation window in days.
    pub(crate) long_window: Option<u16>,
    /// Historical lookback in days.
    pub(crate) days: Option<u16>,
    /// Environment-variable references keyed by provider.
    pub(crate) secret_refs: BTreeMap<ProviderName, String>,
}

/// One allowlisted provider operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderProbe {
    /// Concrete provider adapter.
    pub(crate) provider: ProviderName,
    /// Allowlisted operation key.
    pub(crate) operation: &'static str,
    /// Optional environment variable holding a credential.
    pub(crate) secret_env: Option<String>,
}

/// Bounded temporal comparison parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderWindow {
    /// Short and long reputation windows.
    ShortAndLong {
        /// Short window in days.
        short_days: u16,
        /// Long window in days, always greater than the short window.
        long_days: u16,
    },
    /// One historical lookback window.
    LookbackDays(u16),
}

/// Complete, side-effect-free provider plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProviderPlan {
    /// Ordered, de-duplicated provider probes.
    pub(crate) probes: Vec<ProviderProbe>,
    /// Maximum records consumed per probe.
    pub(crate) limit: usize,
    /// Sorted, de-duplicated HTTP status filter.
    pub(crate) status_filter: Vec<u16>,
    /// Whether equal archive digests are collapsed.
    pub(crate) collapse_digest: bool,
    /// Whether wildcard CT names are included.
    pub(crate) include_wildcard: bool,
    /// Optional bounded temporal parameters.
    pub(crate) window: Option<ProviderWindow>,
}

/// Provider plan validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProviderPlanError {
    /// A source option names a provider outside the scanner allowlist.
    UnsupportedSource(String),
    /// A provider option names a provider outside the scanner allowlist.
    UnsupportedProvider(String),
    /// The selected provider has no safe operation for this target kind.
    UnsupportedTarget {
        /// Provider being planned.
        provider: ProviderName,
        /// Rejected target shape.
        target_kind: TargetKind,
    },
    /// An HTTP status filter is outside 100 through 599.
    InvalidStatus(u16),
    /// A credential reference is not a valid environment-variable name.
    InvalidSecretReference(ProviderName),
    /// A credential reference was supplied to a public provider operation.
    SecretNotSupported(ProviderName),
}

impl Display for ProviderPlanError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSource(source) => {
                write!(formatter, "unsupported provider source: {source}")
            }
            Self::UnsupportedProvider(provider) => {
                write!(formatter, "unsupported provider selection: {provider}")
            }
            Self::UnsupportedTarget {
                provider,
                target_kind,
            } => write!(
                formatter,
                "provider {} does not support target {}",
                provider.as_str(),
                target_kind.as_str()
            ),
            Self::InvalidStatus(status) => write!(formatter, "invalid status filter: {status}"),
            Self::InvalidSecretReference(provider) => write!(
                formatter,
                "invalid secret reference for provider {}",
                provider.as_str()
            ),
            Self::SecretNotSupported(provider) => write!(
                formatter,
                "provider {} does not accept a secret reference",
                provider.as_str()
            ),
        }
    }
}

impl Error for ProviderPlanError {}

/// Builds a bounded provider plan for scanners with provider-specific options.
///
/// Unknown scanner IDs return `None`; this module never invents a fallback
/// provider.
pub(crate) fn plan_for(
    scanner_id: &str,
    target_kind: TargetKind,
    options: &ProviderPlanOptions,
) -> Result<Option<ProviderPlan>, ProviderPlanError> {
    validate_secrets(&options.secret_refs)?;
    let providers = match scanner_id {
        "associated-hosts" => selected_sources(&options.sources, target_kind)?,
        "asn-lookup" => selected_registry_providers(options.provider.as_deref(), target_kind)?,
        "archive-history" => vec![ProviderName::Wayback],
        "ct-log-query" => vec![ProviderName::CrtSh],
        "domain-shadowing-detector" => vec![ProviderName::CrtSh, ProviderName::UrlScan],
        "ip-reputation-trending" if target_kind == TargetKind::Ip => {
            vec![ProviderName::RipeStat, ProviderName::AbuseIpDb]
        }
        "ip-reputation-trending" => vec![ProviderName::RipeStat],
        "domain-reputation-check" => vec![
            ProviderName::VirusTotal,
            ProviderName::UrlScan,
            ProviderName::UrlHaus,
        ],
        "performance-monitoring" => vec![ProviderName::PageSpeed],
        _ => return Ok(None),
    };
    let probes = providers
        .into_iter()
        .map(|provider| {
            Ok(ProviderProbe {
                provider,
                operation: operation_for(scanner_id, provider, target_kind)?,
                secret_env: options.secret_refs.get(&provider).cloned(),
            })
        })
        .collect::<Result<_, ProviderPlanError>>()?;
    let status_filter = status_filter(&options.status_filter)?;
    let window = match scanner_id {
        "ip-reputation-trending" => Some(reputation_window(options)),
        "domain-shadowing-detector" => Some(ProviderWindow::LookbackDays(
            options.days.unwrap_or(30).clamp(1, 3_650),
        )),
        _ => None,
    };
    Ok(Some(ProviderPlan {
        probes,
        limit: options.limit.unwrap_or(100).clamp(1, 1_000),
        status_filter,
        collapse_digest: options.collapse_digest,
        include_wildcard: options.include_wildcard,
        window,
    }))
}

fn selected_sources(
    values: &[String],
    target_kind: TargetKind,
) -> Result<Vec<ProviderName>, ProviderPlanError> {
    let defaults: &[&str] = match target_kind {
        TargetKind::Domain => &["crtsh", "urlscan"],
        TargetKind::Ip => &["urlscan"],
        _ => &[],
    };
    let values: Vec<&str> = if values.is_empty() {
        defaults.to_vec()
    } else {
        values.iter().map(String::as_str).collect()
    };
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter_map(|source| match source {
            "crtsh" if seen.insert(ProviderName::CrtSh) => Some(Ok(ProviderName::CrtSh)),
            "urlscan" | "passive_dns" if seen.insert(ProviderName::UrlScan) => {
                Some(Ok(ProviderName::UrlScan))
            }
            "shodan" if seen.insert(ProviderName::Shodan) => Some(Ok(ProviderName::Shodan)),
            "crtsh" | "urlscan" | "passive_dns" | "shodan" => None,
            other => Some(Err(ProviderPlanError::UnsupportedSource(other.into()))),
        })
        .collect()
}

fn selected_registry_providers(
    value: Option<&str>,
    target_kind: TargetKind,
) -> Result<Vec<ProviderName>, ProviderPlanError> {
    let default = if target_kind == TargetKind::Ip {
        "ripestat"
    } else {
        "rdap"
    };
    match value.unwrap_or(default) {
        "rdap" => Ok(vec![ProviderName::Rdap]),
        "ripestat" | "ipapi" => Ok(vec![ProviderName::RipeStat]),
        "both" => Ok(vec![ProviderName::Rdap, ProviderName::RipeStat]),
        other => Err(ProviderPlanError::UnsupportedProvider(other.into())),
    }
}

fn operation_for(
    scanner_id: &str,
    provider: ProviderName,
    target_kind: TargetKind,
) -> Result<&'static str, ProviderPlanError> {
    let operation = match (scanner_id, provider, target_kind) {
        (
            "ip-reputation-trending",
            ProviderName::RipeStat,
            TargetKind::Domain | TargetKind::Ip | TargetKind::Cidr,
        ) => "dns-blocklists",
        ("associated-hosts", ProviderName::CrtSh, TargetKind::Ip)
        | (_, ProviderName::CrtSh, TargetKind::Domain) => "query",
        (_, ProviderName::UrlScan, TargetKind::Domain | TargetKind::Ip | TargetKind::Url) => {
            "search"
        }
        (_, ProviderName::Rdap, TargetKind::Domain)
        | (_, ProviderName::VirusTotal, TargetKind::Domain | TargetKind::Url) => "domain",
        (_, ProviderName::Rdap | ProviderName::VirusTotal, TargetKind::Ip) => "ip",
        (_, ProviderName::Shodan, TargetKind::Ip)
        | (_, ProviderName::UrlHaus, TargetKind::Domain | TargetKind::Ip | TargetKind::Url) => {
            "host"
        }
        (_, ProviderName::RipeStat, TargetKind::Asn) => "as-overview",
        (_, ProviderName::RipeStat, TargetKind::Cidr) => "prefix-overview",
        (_, ProviderName::RipeStat, TargetKind::Domain | TargetKind::Ip) => "network-info",
        (_, ProviderName::Wayback, TargetKind::Domain | TargetKind::Url) => "cdx",
        (_, ProviderName::AbuseIpDb, TargetKind::Ip) => "check",
        (_, ProviderName::PageSpeed, TargetKind::Domain | TargetKind::Url) => "analyze",
        _ => {
            return Err(ProviderPlanError::UnsupportedTarget {
                provider,
                target_kind,
            });
        }
    };
    Ok(operation)
}

fn status_filter(values: &[u16]) -> Result<Vec<u16>, ProviderPlanError> {
    let mut statuses = BTreeSet::new();
    for status in values.iter().copied() {
        if !(100..=599).contains(&status) {
            return Err(ProviderPlanError::InvalidStatus(status));
        }
        statuses.insert(status);
    }
    Ok(statuses.into_iter().take(32).collect())
}

fn reputation_window(options: &ProviderPlanOptions) -> ProviderWindow {
    let short_days = options.short_window.unwrap_or(7).clamp(1, 90);
    let long_days = options
        .long_window
        .unwrap_or(30)
        .clamp(short_days.saturating_add(1), 3_650);
    ProviderWindow::ShortAndLong {
        short_days,
        long_days,
    }
}

fn validate_secrets(values: &BTreeMap<ProviderName, String>) -> Result<(), ProviderPlanError> {
    for (provider, value) in values {
        if !matches!(
            provider,
            ProviderName::UrlScan
                | ProviderName::Shodan
                | ProviderName::VirusTotal
                | ProviderName::UrlHaus
                | ProviderName::AbuseIpDb
                | ProviderName::PageSpeed
        ) {
            return Err(ProviderPlanError::SecretNotSupported(*provider));
        }
        let valid = !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
        if !valid {
            return Err(ProviderPlanError::InvalidSecretReference(*provider));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use sugra_domain::TargetKind;

    use super::*;

    #[test]
    fn associated_hosts_honors_an_allowlisted_source_selection()
    -> Result<(), Box<dyn std::error::Error>> {
        let options = ProviderPlanOptions {
            sources: vec!["urlscan".into(), "crtsh".into(), "passive_dns".into()],
            ..ProviderPlanOptions::default()
        };

        let plan = plan_for("associated-hosts", TargetKind::Domain, &options)?
            .ok_or("associated-hosts plan is missing")?;

        assert_eq!(
            plan.probes
                .iter()
                .map(|probe| probe.provider)
                .collect::<Vec<_>>(),
            vec![ProviderName::UrlScan, ProviderName::CrtSh]
        );
        Ok(())
    }

    #[test]
    fn associated_hosts_maps_legacy_sources_to_concrete_adapters()
    -> Result<(), Box<dyn std::error::Error>> {
        let options = ProviderPlanOptions {
            sources: vec!["shodan".into(), "passive_dns".into()],
            secret_refs: BTreeMap::from([(ProviderName::Shodan, "SHODAN_API_KEY".into())]),
            ..ProviderPlanOptions::default()
        };

        let plan = plan_for("associated-hosts", TargetKind::Ip, &options)?
            .ok_or("associated-hosts plan is missing")?;

        assert_eq!(
            plan.probes
                .iter()
                .map(|probe| { (probe.provider, probe.operation, probe.secret_env.as_deref(),) })
                .collect::<Vec<_>>(),
            vec![
                (ProviderName::Shodan, "host", Some("SHODAN_API_KEY")),
                (ProviderName::UrlScan, "search", None),
            ]
        );
        Ok(())
    }

    #[test]
    fn associated_hosts_uses_target_compatible_defaults() -> Result<(), Box<dyn std::error::Error>>
    {
        let domain = plan_for(
            "associated-hosts",
            TargetKind::Domain,
            &ProviderPlanOptions::default(),
        )?
        .ok_or("domain plan is missing")?;
        let ip = plan_for(
            "associated-hosts",
            TargetKind::Ip,
            &ProviderPlanOptions::default(),
        )?
        .ok_or("IP plan is missing")?;

        assert_eq!(
            domain
                .probes
                .iter()
                .map(|probe| (probe.provider, probe.operation))
                .collect::<Vec<_>>(),
            vec![
                (ProviderName::CrtSh, "query"),
                (ProviderName::UrlScan, "search"),
            ]
        );
        assert_eq!(
            ip.probes
                .iter()
                .map(|probe| (probe.provider, probe.operation))
                .collect::<Vec<_>>(),
            vec![(ProviderName::UrlScan, "search")]
        );
        Ok(())
    }

    #[test]
    fn associated_hosts_rejects_unknown_and_target_incompatible_sources() {
        let unknown = ProviderPlanOptions {
            sources: vec!["unknown".into()],
            ..ProviderPlanOptions::default()
        };
        let incompatible = ProviderPlanOptions {
            sources: vec!["shodan".into()],
            ..ProviderPlanOptions::default()
        };

        assert_eq!(
            plan_for("associated-hosts", TargetKind::Domain, &unknown),
            Err(ProviderPlanError::UnsupportedSource("unknown".into()))
        );
        assert_eq!(
            plan_for("associated-hosts", TargetKind::Domain, &incompatible),
            Err(ProviderPlanError::UnsupportedTarget {
                provider: ProviderName::Shodan,
                target_kind: TargetKind::Domain,
            })
        );
    }

    #[test]
    fn asn_lookup_selects_provider_and_operation_by_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let domain = plan_for(
            "asn-lookup",
            TargetKind::Domain,
            &ProviderPlanOptions::default(),
        )?
        .ok_or("domain plan is missing")?;
        let ip = plan_for(
            "asn-lookup",
            TargetKind::Ip,
            &ProviderPlanOptions::default(),
        )?
        .ok_or("IP plan is missing")?;
        let rdap_ip = plan_for(
            "asn-lookup",
            TargetKind::Ip,
            &ProviderPlanOptions {
                provider: Some("rdap".into()),
                ..ProviderPlanOptions::default()
            },
        )?
        .ok_or("explicit RDAP plan is missing")?;
        let both = plan_for(
            "asn-lookup",
            TargetKind::Ip,
            &ProviderPlanOptions {
                provider: Some("both".into()),
                ..ProviderPlanOptions::default()
            },
        )?
        .ok_or("combined provider plan is missing")?;

        assert_eq!(
            (domain.probes[0].provider, domain.probes[0].operation),
            (ProviderName::Rdap, "domain")
        );
        assert_eq!(
            (ip.probes[0].provider, ip.probes[0].operation),
            (ProviderName::RipeStat, "network-info")
        );
        assert_eq!(
            (rdap_ip.probes[0].provider, rdap_ip.probes[0].operation),
            (ProviderName::Rdap, "ip")
        );
        assert_eq!(
            both.probes
                .iter()
                .map(|probe| (probe.provider, probe.operation))
                .collect::<Vec<_>>(),
            vec![
                (ProviderName::Rdap, "ip"),
                (ProviderName::RipeStat, "network-info"),
            ]
        );
        Ok(())
    }

    #[test]
    fn asn_lookup_rejects_a_provider_outside_its_allowlist() {
        let options = ProviderPlanOptions {
            provider: Some("urlscan".into()),
            ..ProviderPlanOptions::default()
        };

        assert_eq!(
            plan_for("asn-lookup", TargetKind::Domain, &options),
            Err(ProviderPlanError::UnsupportedProvider("urlscan".into()))
        );
    }

    #[test]
    fn archive_options_are_normalized_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let statuses = (100..=140).rev().chain([200, 100]).collect();
        let options = ProviderPlanOptions {
            limit: Some(usize::MAX),
            status_filter: statuses,
            collapse_digest: true,
            ..ProviderPlanOptions::default()
        };

        let plan = plan_for("archive-history", TargetKind::Url, &options)?
            .ok_or("archive plan is missing")?;

        assert_eq!(plan.limit, 1_000);
        assert_eq!(plan.status_filter, (100..=131).collect::<Vec<_>>());
        assert!(plan.collapse_digest);
        assert_eq!(plan.probes[0].operation, "cdx");
        Ok(())
    }

    #[test]
    fn archive_rejects_an_invalid_status_even_beyond_the_retained_limit() {
        let mut statuses = (100..=140).collect::<Vec<_>>();
        statuses.push(600);
        let options = ProviderPlanOptions {
            status_filter: statuses,
            ..ProviderPlanOptions::default()
        };

        assert_eq!(
            plan_for("archive-history", TargetKind::Domain, &options),
            Err(ProviderPlanError::InvalidStatus(600))
        );
    }

    #[test]
    fn ct_and_shadowing_options_are_preserved_and_clamped() -> Result<(), Box<dyn std::error::Error>>
    {
        let ct = plan_for(
            "ct-log-query",
            TargetKind::Domain,
            &ProviderPlanOptions {
                include_wildcard: true,
                ..ProviderPlanOptions::default()
            },
        )?
        .ok_or("CT plan is missing")?;
        let shadowing = plan_for(
            "domain-shadowing-detector",
            TargetKind::Domain,
            &ProviderPlanOptions {
                days: Some(u16::MAX),
                ..ProviderPlanOptions::default()
            },
        )?
        .ok_or("shadowing plan is missing")?;

        assert!(ct.include_wildcard);
        assert_eq!(shadowing.window, Some(ProviderWindow::LookbackDays(3_650)));
        Ok(())
    }

    #[test]
    fn reputation_plan_clamps_windows_and_uses_target_safe_probes()
    -> Result<(), Box<dyn std::error::Error>> {
        let options = ProviderPlanOptions {
            short_window: Some(0),
            long_window: Some(1),
            ..ProviderPlanOptions::default()
        };
        let ip = plan_for("ip-reputation-trending", TargetKind::Ip, &options)?
            .ok_or("IP reputation plan is missing")?;
        let cidr = plan_for("ip-reputation-trending", TargetKind::Cidr, &options)?
            .ok_or("CIDR reputation plan is missing")?;

        assert_eq!(
            ip.window,
            Some(ProviderWindow::ShortAndLong {
                short_days: 1,
                long_days: 2,
            })
        );
        assert_eq!(
            ip.probes
                .iter()
                .map(|probe| (probe.provider, probe.operation))
                .collect::<Vec<_>>(),
            vec![
                (ProviderName::RipeStat, "dns-blocklists"),
                (ProviderName::AbuseIpDb, "check"),
            ]
        );
        assert_eq!(
            cidr.probes
                .iter()
                .map(|probe| (probe.provider, probe.operation))
                .collect::<Vec<_>>(),
            vec![(ProviderName::RipeStat, "dns-blocklists")]
        );
        Ok(())
    }

    #[test]
    fn reputation_windows_clamp_at_the_upper_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let plan = plan_for(
            "ip-reputation-trending",
            TargetKind::Ip,
            &ProviderPlanOptions {
                short_window: Some(u16::MAX),
                long_window: Some(u16::MAX),
                ..ProviderPlanOptions::default()
            },
        )?
        .ok_or("reputation plan is missing")?;

        assert_eq!(
            plan.window,
            Some(ProviderWindow::ShortAndLong {
                short_days: 90,
                long_days: 3_650,
            })
        );
        Ok(())
    }

    #[test]
    fn secret_references_are_validated_and_attached_without_secret_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let options = ProviderPlanOptions {
            secret_refs: BTreeMap::from([
                (ProviderName::VirusTotal, "VIRUSTOTAL_API_KEY".into()),
                (ProviderName::UrlHaus, "URLHAUS_AUTH_KEY".into()),
            ]),
            ..ProviderPlanOptions::default()
        };

        let plan = plan_for("domain-reputation-check", TargetKind::Domain, &options)?
            .ok_or("domain reputation plan is missing")?;

        assert_eq!(
            plan.probes
                .iter()
                .map(|probe| (probe.provider, probe.secret_env.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                (ProviderName::VirusTotal, Some("VIRUSTOTAL_API_KEY")),
                (ProviderName::UrlScan, None),
                (ProviderName::UrlHaus, Some("URLHAUS_AUTH_KEY")),
            ]
        );
        Ok(())
    }

    #[test]
    fn invalid_secret_reference_is_rejected_without_echoing_its_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let secret_value = "not-a-valid-env-reference";
        let options = ProviderPlanOptions {
            secret_refs: BTreeMap::from([(ProviderName::VirusTotal, secret_value.into())]),
            ..ProviderPlanOptions::default()
        };

        let Err(error) = plan_for("domain-reputation-check", TargetKind::Domain, &options) else {
            return Err("invalid secret reference must fail".into());
        };

        assert_eq!(
            error,
            ProviderPlanError::InvalidSecretReference(ProviderName::VirusTotal)
        );
        assert!(!error.to_string().contains(secret_value));
        Ok(())
    }

    #[test]
    fn public_providers_reject_secret_references() {
        let options = ProviderPlanOptions {
            secret_refs: BTreeMap::from([(ProviderName::Rdap, "RDAP_API_KEY".into())]),
            ..ProviderPlanOptions::default()
        };

        assert_eq!(
            plan_for("asn-lookup", TargetKind::Domain, &options),
            Err(ProviderPlanError::SecretNotSupported(ProviderName::Rdap))
        );
    }

    #[test]
    fn pagespeed_uses_only_its_real_operation_and_accepts_an_env_reference()
    -> Result<(), Box<dyn std::error::Error>> {
        let options = ProviderPlanOptions {
            secret_refs: BTreeMap::from([(ProviderName::PageSpeed, "PAGESPEED_API_KEY".into())]),
            ..ProviderPlanOptions::default()
        };

        let plan = plan_for("performance-monitoring", TargetKind::Url, &options)?
            .ok_or("PageSpeed plan is missing")?;

        assert_eq!(plan.probes[0].provider, ProviderName::PageSpeed);
        assert_eq!(plan.probes[0].operation, "analyze");
        assert_eq!(
            plan.probes[0].secret_env.as_deref(),
            Some("PAGESPEED_API_KEY")
        );
        Ok(())
    }

    #[test]
    fn unsupported_target_and_unknown_scanner_do_not_gain_fallbacks() {
        assert_eq!(
            plan_for(
                "performance-monitoring",
                TargetKind::Ip,
                &ProviderPlanOptions::default(),
            ),
            Err(ProviderPlanError::UnsupportedTarget {
                provider: ProviderName::PageSpeed,
                target_kind: TargetKind::Ip,
            })
        );
        assert_eq!(
            plan_for(
                "future-provider-scanner",
                TargetKind::Domain,
                &ProviderPlanOptions::default(),
            ),
            Ok(None)
        );
    }
}
