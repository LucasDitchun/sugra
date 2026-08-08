//! Typed option contracts for the scanner cohort audited during HTTP migration.
//!
//! Contracts are keyed only by canonical scanner identity. Boundary ownership
//! can evolve without changing the public option contract.

use serde::{Deserialize, Serialize};

use crate::{DomainError, OptionDefinition, OptionKind, ScannerId};

/// Number of scanners in the published option-contract cohort.
pub const PUBLISHED_SCANNER_OPTION_CONTRACT_COUNT: usize = 68;

/// Typed options published by one scanner assigned to the HTTP boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerOptionContract {
    /// Canonical scanner identity.
    pub scanner_id: ScannerId,
    /// Options accepted by the scanner, in stable catalog order.
    pub options: Vec<OptionDefinition>,
}

/// Returns the complete deterministic option catalog for the audited cohort.
///
/// Scanners without published options are included with an empty vector so a
/// caller can distinguish a known zero-option scanner from an unknown ID.
///
/// # Errors
///
/// Returns a domain error if an embedded scanner ID or option schema violates
/// its public invariant.
pub fn published_scanner_option_contracts() -> Result<Vec<ScannerOptionContract>, DomainError> {
    SCANNER_CONTRACTS
        .iter()
        .map(|(id, keys)| {
            let scanner_id = ScannerId::new(*id)?;
            let options = keys
                .iter()
                .map(|key| option_definition(id, key))
                .collect::<Result<Vec<_>, _>>()?;
            for option in &options {
                option.validate()?;
            }
            Ok(ScannerOptionContract {
                scanner_id,
                options,
            })
        })
        .collect()
}

/// Resolves the typed options for one scanner in the audited cohort.
///
/// Returns `Some(Vec::new())` for a known scanner with no public options and
/// `None` for a scanner outside the audited contract catalog.
///
/// # Errors
///
/// Returns a domain error if an embedded option schema is unknown.
pub fn scanner_options(
    scanner_id: &ScannerId,
) -> Result<Option<Vec<OptionDefinition>>, DomainError> {
    let Some((id, keys)) = SCANNER_CONTRACTS
        .iter()
        .find(|(id, _)| *id == scanner_id.as_str())
    else {
        return Ok(None);
    };
    keys.iter()
        .map(|key| option_definition(id, key))
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

const SCANNER_CONTRACTS: [(&str, &[&str]); PUBLISHED_SCANNER_OPTION_CONTRACT_COUNT] = [
    ("cdn-detection", &["timeout"]),
    ("server-info", &[]),
    (
        "api-schema-grabber",
        &["delay", "graphql_paths", "paths", "timeout"],
    ),
    (
        "autocomplete-vulnerability-checker",
        &["max_pages", "timeout"],
    ),
    ("broken-links", &["max_pages", "sample_ratio", "timeout"]),
    (
        "cache-behavior-analyzer",
        &["max_pages", "sample_ratio", "timeout"],
    ),
    (
        "captcha-presence-checker",
        &["max_pages", "sample_ratio", "timeout"],
    ),
    ("carbon-footprint", &[]),
    (
        "clickjacking-test",
        &["max_pages", "sample_ratio", "timeout"],
    ),
    ("cms-detection", &[]),
    ("content-discovery", &["include_subdomains", "max_pages"]),
    ("cookie-scope-diff", &["include_subdomains", "max_pages"]),
    ("cookies", &["follow", "paths", "timeout"]),
    ("cors-misconfiguration-scanner", &["timeout"]),
    ("crawl-rules", &["timeout"]),
    (
        "crawler",
        &["depth", "max_pages", "rate_limit", "start_url"],
    ),
    (
        "csp-deep-analyzer",
        &["max_pages", "sample_ratio", "timeout"],
    ),
    (
        "dependency-js-cdn-scanner",
        &["max_pages", "sample_ratio", "timeout"],
    ),
    ("directory-finder", &["status_keep", "timeout", "wordlist"]),
    (
        "dom-sink-scanner",
        &["max_pages", "sample_ratio", "timeout"],
    ),
    ("email-harvester", &[]),
    ("embedded-object-hunter", &[]),
    ("favicon-hashing", &["timeout"]),
    (
        "file-upload-surface-finder",
        &["include_subs", "max_pages", "timeout"],
    ),
    ("form-grabber", &["include_subs", "max_pages", "timeout"]),
    ("graphql-introspection-probe", &[]),
    (
        "hidden-parameter-discovery",
        &[
            "max_params",
            "params_file",
            "test_values",
            "threshold",
            "timeout",
        ],
    ),
    ("html5-feature-abuse-detector", &["timeout"]),
    ("html-comments-extractor", &[]),
    ("http-method-enumerator", &[]),
    ("javascript-file-analyzer", &["timeout"]),
    (
        "javascript-obfuscation-detector",
        &[
            "export_txt",
            "include_subdomains",
            "max_pages",
            "max_scripts",
            "timeout",
        ],
    ),
    ("lazy-load-resource-finder", &["timeout"]),
    (
        "login-page-brute-identifier",
        &["follow_redirects", "paths", "paths_file", "timeout"],
    ),
    ("multi-language-url-tester", &["timeout"]),
    (
        "performance-monitoring",
        &["key", "strategies", "timeout", "verify_ssl"],
    ),
    ("pixel-tracker-finder", &[]),
    ("quality-metrics", &[]),
    ("redirect-chain", &[]),
    ("seo-abuse-detector", &[]),
    ("session-cookie-lifetime-checker", &[]),
    ("sitemap", &[]),
    ("social-media", &[]),
    ("static-asset-fingerprinter", &[]),
    ("technology-stack", &[]),
    ("third-party-integrations", &[]),
    ("third-party-script-risk-profiler", &[]),
    ("virtual-host-fuzzer", &["hosts"]),
    ("websocket-endpoint-sniffer", &[]),
    (
        "attack-surface-delta",
        &["baseline_sha256", "ports_top", "timeout"],
    ),
    ("bug-bounty-program-finder", &["timeout", "workers"]),
    ("cloud-bucket-exposure", &["timeout"]),
    ("cloud-service-enumeration", &[]),
    ("exposed-api-endpoints", &[]),
    ("exposed-env-files", &[]),
    ("firewall-detection", &["timeout"]),
    ("git-repo-exposure-check", &["timeout"]),
    ("http-headers", &[]),
    ("http-security", &["json", "timeout"]),
    ("open-redirect-finder", &["timeout"]),
    ("passive-cve-mapper", &[]),
    ("privacy-gdpr", &[]),
    ("rate-limit-waf-bypass-test", &["batch_size", "timeout"]),
    ("security-changelog-diff", &["baseline_sha256"]),
    ("security-contact-gap-finder", &[]),
    ("security-txt", &["log", "timeout"]),
    (
        "session-hijacking-passive",
        &["paths", "session_hints", "timeout"],
    ),
    ("typosquat-domain-checker", &["max_variants"]),
];

fn option_definition(scanner_id: &str, key: &str) -> Result<OptionDefinition, DomainError> {
    bounded_option(scanner_id, key)
        .or_else(|| flag_option(key))
        .or_else(|| collection_option(key))
        .or_else(|| textual_option(scanner_id, key))
        .ok_or_else(|| DomainError::InvalidOptionDefinition {
            key: key.into(),
            reason: "published scanner option has no typed contract",
        })
}

fn bounded_option(scanner_id: &str, key: &str) -> Option<OptionDefinition> {
    match key {
        "batch_size" => Some(integer(
            key,
            "Maximum requests in one authorized rate-limit test batch.",
            1,
            8,
            4,
        )),
        "depth" => Some(integer(
            key,
            "Maximum same-origin link depth to crawl.",
            1,
            32,
            3,
        )),
        "max_pages" => Some(integer(
            key,
            "Maximum number of same-origin pages to inspect.",
            1,
            10_000,
            max_pages_default(scanner_id),
        )),
        "max_params" => Some(integer(
            key,
            "Maximum candidate parameter names to test.",
            1,
            1_024,
            25,
        )),
        "max_scripts" => Some(integer(
            key,
            "Maximum same-origin JavaScript resources to inspect.",
            1,
            2_000,
            75,
        )),
        "max_variants" => Some(integer(
            key,
            "Maximum generated typo-domain candidates to resolve.",
            1,
            128,
            32,
        )),
        "ports_top" => Some(integer(
            key,
            "Number of common ports included in the bounded surface sample.",
            1,
            14,
            12,
        )),
        "threshold" => Some(integer(
            key,
            "Minimum response-size delta in bytes considered meaningful.",
            0,
            1_048_576,
            50,
        )),
        "timeout" => Some(integer(key, "Per-request timeout in seconds.", 1, 300, 10)),
        "workers" => Some(integer(
            key,
            "Maximum concurrent workers used by the scanner.",
            1,
            256,
            4,
        )),
        _ => None,
    }
}

fn flag_option(key: &str) -> Option<OptionDefinition> {
    match key {
        "export_txt" => Some(boolean(
            key,
            "Enable the optional plain-text projection.",
            false,
        )),
        "follow" => Some(boolean(
            key,
            "Follow same-origin redirects while collecting cookies.",
            false,
        )),
        "follow_redirects" => Some(boolean(
            key,
            "Follow redirects while locating login pages.",
            true,
        )),
        "include_subdomains" | "include_subs" => boolean(
            key,
            "Include explicitly scoped subdomains in the crawl.",
            false,
        )
        .into(),
        "json" => Some(boolean(
            key,
            "Enable the scanner-specific JSON projection.",
            false,
        )),
        "log" => Some(boolean(
            key,
            "Enable the scanner-specific local log projection.",
            false,
        )),
        "verify_ssl" => Some(boolean(key, "Require TLS certificate verification.", true)),
        _ => None,
    }
}

fn collection_option(key: &str) -> Option<OptionDefinition> {
    match key {
        "graphql_paths" => Some(list(
            key,
            "Comma-separated same-origin GraphQL endpoint paths.",
            64,
            None,
        )),
        "hosts" => Some(list(
            key,
            "Comma-separated authorized virtual-host candidates.",
            128,
            None,
        )),
        "paths" => list(
            key,
            "Comma-separated same-origin paths beginning with a slash.",
            1_024,
            None,
        )
        .into(),
        "session_hints" => Some(list(
            key,
            "Comma-separated cookie-name fragments treated as session indicators.",
            64,
            None,
        )),
        "status_keep" => Some(list(
            key,
            "Comma-separated HTTP status codes retained by discovery probes.",
            32,
            Some("200,301,302,403"),
        )),
        "strategies" => Some(list(
            key,
            "Comma-separated PageSpeed strategies: mobile, desktop, or both.",
            2,
            Some("mobile,desktop"),
        )),
        "test_values" => Some(list(
            key,
            "Comma-separated bounded values used for authorized parameter probes.",
            20,
            None,
        )),
        _ => None,
    }
}

fn textual_option(scanner_id: &str, key: &str) -> Option<OptionDefinition> {
    match key {
        "baseline_sha256" => Some(text(
            key,
            "Optional lowercase SHA-256 baseline used for deterministic change comparison.",
            64,
            None,
        )),
        "delay" => Some(text(
            key,
            "Delay in seconds between schema probes, from 0 through 60.",
            8,
            Some("0"),
        )),
        "key" => Some(OptionDefinition {
            key: key.into(),
            description: "Environment variable containing the Google API key.".into(),
            kind: OptionKind::SecretRef,
            default: None,
            required: false,
        }),
        "params_file" => Some(text(
            key,
            "Path to a local newline-delimited parameter-name file.",
            4_096,
            None,
        )),
        "paths_file" => Some(text(
            key,
            "Path to a local newline-delimited same-origin path file.",
            4_096,
            None,
        )),
        "rate_limit" => Some(text(
            key,
            "Minimum delay in seconds between crawl requests, from 0.01 through 60.",
            8,
            Some("0.2"),
        )),
        "sample_ratio" => Some(text(
            key,
            "Decimal fraction of discovered pages to sample, greater than 0 and at most 1.",
            8,
            Some(sample_ratio_default(scanner_id)),
        )),
        "start_url" => Some(text(
            key,
            "Absolute HTTP or HTTPS URL used as the crawl starting point.",
            2_048,
            None,
        )),
        "wordlist" => Some(text(
            key,
            "Path to a local newline-delimited discovery wordlist.",
            4_096,
            None,
        )),
        _ => None,
    }
}

fn boolean(key: &str, description: &str, default: bool) -> OptionDefinition {
    OptionDefinition {
        key: key.into(),
        description: description.into(),
        kind: OptionKind::Boolean,
        default: Some(default.to_string()),
        required: false,
    }
}

fn integer(key: &str, description: &str, min: i64, max: i64, default: i64) -> OptionDefinition {
    OptionDefinition {
        key: key.into(),
        description: description.into(),
        kind: OptionKind::Integer { min, max },
        default: Some(default.to_string()),
        required: false,
    }
}

fn text(key: &str, description: &str, max_len: usize, default: Option<&str>) -> OptionDefinition {
    OptionDefinition {
        key: key.into(),
        description: description.into(),
        kind: OptionKind::Text { max_len },
        default: default.map(str::to_owned),
        required: false,
    }
}

fn list(key: &str, description: &str, max_items: usize, default: Option<&str>) -> OptionDefinition {
    OptionDefinition {
        key: key.into(),
        description: description.into(),
        kind: OptionKind::List { max_items },
        default: default.map(str::to_owned),
        required: false,
    }
}

fn max_pages_default(scanner_id: &str) -> i64 {
    match scanner_id {
        "autocomplete-vulnerability-checker" => 25,
        "broken-links" => 200,
        "cache-behavior-analyzer" | "clickjacking-test" => 60,
        "captcha-presence-checker" => 80,
        "dependency-js-cdn-scanner" | "file-upload-surface-finder" => 150,
        "dom-sink-scanner" => 75,
        "form-grabber" => 250,
        "javascript-obfuscation-detector" => 50,
        "crawler" => 400,
        _ => 100,
    }
}

fn sample_ratio_default(scanner_id: &str) -> &'static str {
    match scanner_id {
        "broken-links" => "0.15",
        "cache-behavior-analyzer" => "0.25",
        "csp-deep-analyzer" => "0.4",
        _ => "0.3",
    }
}
