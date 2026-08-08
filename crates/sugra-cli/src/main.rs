//! Sugra command-line entry point.

use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use sugra_adapters::{
    HickoryDns, ReqwestHttp, ReqwestProvider, RustlsTls, SystemClock, SystemCommand, TokioTcp,
    TokioUdp,
};
use sugra_core::{
    Catalog, Engine, RunStore, ServiceBundle, render_csv, render_html, render_terminal,
    resolve_options,
};
use sugra_domain::{
    Budget, Capability, LegacyId, RunReport, ScanRequest, ScannerDescriptor, ScannerId, ScopeGrant,
    Target, TargetKind,
};
use sugra_scanners::{Builtins, build_builtins};
use thiserror::Error;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Parser)]
#[command(
    name = "sugra",
    version,
    about = "Scoped security observation from a modern CLI and TUI",
    long_about = "Sugra provides 147 bounded security scanners through a searchable catalog, explicit scope policy, structured evidence, and deterministic reports."
)]
struct Cli {
    /// Increase engine parallelism while preserving per-scanner budgets.
    #[arg(long, global = true, default_value_t = 4, value_parser = parse_concurrency)]
    concurrency: usize,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Browse all scanners and compatibility identities.
    #[command(alias = "list")]
    Catalog {
        /// Emit the catalog as JSON.
        #[arg(long)]
        json: bool,
        /// Filter by implementation track.
        #[arg(long)]
        track: Option<String>,
    },
    /// Show the contract of one scanner.
    Info {
        /// Canonical ID, published numeric ID, or U-prefixed supplemental ID.
        scanner: String,
        /// Emit the descriptor as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run one scanner with an exact target scope.
    Scan(ScanArgs),
    /// Run a curated scanner group against one compatible target.
    Preset {
        /// Curated scanner group.
        #[arg(value_enum)]
        preset: Preset,
        /// Domain, IP address, network, URL, email, ASN, or scanner-specific value.
        target: String,
        /// Explicitly authorize active HTTP, fuzzing, protocol, and local-command capabilities.
        #[arg(long)]
        authorize_active: bool,
        /// Report projection written to standard output.
        #[arg(long, value_enum, default_value_t = OutputFormat::Terminal)]
        format: OutputFormat,
        /// Immutable run artifact root.
        #[arg(long, default_value = "sugra-runs")]
        output: PathBuf,
    },
    /// Render a previously persisted canonical JSON report.
    Report {
        /// Path to report.json.
        path: PathBuf,
        /// Output projection.
        #[arg(long, value_enum, default_value_t = OutputFormat::Terminal)]
        format: OutputFormat,
    },
    /// Open the full-screen terminal interface.
    Tui {
        /// Immutable run artifact root.
        #[arg(long, default_value = "sugra-runs")]
        output: PathBuf,
    },
}

#[derive(Debug, clap::Args)]
struct ScanArgs {
    /// Canonical ID, published numeric ID, or U-prefixed supplemental ID.
    scanner: String,
    /// Scanner target.
    target: String,
    /// Force a declared target interpretation instead of automatic inference.
    #[arg(long, value_enum)]
    target_kind: Option<TargetKindArg>,
    /// Scanner option in key=value form; may be repeated.
    #[arg(short = 'O', long = "option", value_name = "KEY=VALUE")]
    options: Vec<String>,
    /// Explicitly authorize active HTTP, fuzzing, protocol, and local-command capabilities.
    #[arg(long)]
    authorize_active: bool,
    /// Per-scanner timeout in milliseconds.
    #[arg(long, default_value_t = Budget::DEFAULT.timeout_ms)]
    timeout_ms: u64,
    /// Maximum boundary operations per scanner.
    #[arg(long, default_value_t = Budget::DEFAULT.max_requests)]
    max_requests: usize,
    /// Maximum bytes read from one response.
    #[arg(long, default_value_t = Budget::DEFAULT.max_response_bytes)]
    max_response_bytes: usize,
    /// Maximum crawl depth.
    #[arg(long, default_value_t = Budget::DEFAULT.max_depth)]
    max_depth: usize,
    /// Report projection written to standard output.
    #[arg(long, value_enum, default_value_t = OutputFormat::Terminal)]
    format: OutputFormat,
    /// Immutable run artifact root.
    #[arg(long, default_value = "sugra-runs")]
    output: PathBuf,
    /// Execute without persisting the canonical report.
    #[arg(long)]
    no_persist: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Terminal,
    Json,
    Csv,
    Html,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Preset {
    Network,
    Web,
    Security,
    All,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TargetKindArg {
    Domain,
    Ip,
    Cidr,
    Url,
    HostPort,
    Asn,
    Email,
    Opaque,
}

fn parse_concurrency(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|value| (1..=256).contains(value))
        .ok_or_else(|| "concurrency must be between 1 and 256".into())
}

impl From<TargetKindArg> for TargetKind {
    fn from(value: TargetKindArg) -> Self {
        match value {
            TargetKindArg::Domain => Self::Domain,
            TargetKindArg::Ip => Self::Ip,
            TargetKindArg::Cidr => Self::Cidr,
            TargetKindArg::Url => Self::Url,
            TargetKindArg::HostPort => Self::HostPort,
            TargetKindArg::Asn => Self::Asn,
            TargetKindArg::Email => Self::Email,
            TargetKindArg::Opaque => Self::Opaque,
        }
    }
}

#[derive(Debug, Error)]
enum CliError {
    #[error("scanner selector is unknown: {0}")]
    UnknownScanner(String),
    #[error("target is incompatible with scanner {scanner}: {target}")]
    InvalidTarget { scanner: String, target: String },
    #[error("invalid option assignment: {0}; expected key=value")]
    InvalidAssignment(String),
    #[error("active scanner {0} requires --authorize-active")]
    AuthorizationRequired(String),
    #[error("could not initialize {component}: {message}")]
    Initialization {
        component: &'static str,
        message: String,
    },
    #[error("no scanner in preset {preset:?} accepts target {target}")]
    EmptyPreset { preset: Preset, target: String },
    #[error(transparent)]
    Engine(#[from] sugra_core::EngineError),
    #[error(transparent)]
    Options(#[from] sugra_core::OptionError),
    #[error(transparent)]
    Domain(#[from] sugra_domain::DomainError),
    #[error(transparent)]
    Store(#[from] sugra_core::StoreError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Tui(#[from] sugra_tui::TuiError),
}

#[tokio::main]
async fn main() -> ExitCode {
    match execute(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn execute(cli: Cli) -> Result<(), CliError> {
    let Cli {
        concurrency,
        command,
    } = cli;
    let Some(command) = command else {
        if io::stdin().is_terminal() && io::stdout().is_terminal() {
            return run_tui(concurrency, PathBuf::from("sugra-runs")).await;
        }
        Cli::command().print_help()?;
        writeln!(io::stdout())?;
        return Ok(());
    };

    match command {
        Command::Catalog { json, track } => {
            let builtins = build_application()?.0;
            print_catalog(&builtins.catalog, track.as_deref(), json)
        }
        Command::Info { scanner, json } => {
            let builtins = build_application()?.0;
            let descriptor = resolve_scanner(&builtins.catalog, &scanner)?;
            print_descriptor(&descriptor, json)
        }
        Command::Scan(arguments) => run_scan(concurrency, arguments).await,
        Command::Preset {
            preset,
            target,
            authorize_active,
            format,
            output,
        } => {
            run_preset(
                concurrency,
                preset,
                &target,
                authorize_active,
                format,
                output,
            )
            .await
        }
        Command::Report { path, format } => render_saved_report(&path, format).await,
        Command::Tui { output } => run_tui(concurrency, output).await,
    }
}

fn build_application() -> Result<(Builtins, Arc<SystemClock>, ServiceBundle), CliError> {
    let clock = Arc::new(SystemClock);
    let http = Arc::new(
        ReqwestHttp::new().map_err(|error| CliError::Initialization {
            component: "HTTP client",
            message: error.to_string(),
        })?,
    );
    let dns = Arc::new(
        HickoryDns::system().map_err(|error| CliError::Initialization {
            component: "DNS resolver",
            message: error.to_string(),
        })?,
    );
    let tls = Arc::new(
        RustlsTls::native().map_err(|error| CliError::Initialization {
            component: "TLS verifier",
            message: error.to_string(),
        })?,
    );
    let provider = Arc::new(ReqwestProvider::new(http.clone(), clock.clone()));
    let services = ServiceBundle {
        dns,
        http,
        tcp: Arc::new(TokioTcp),
        udp: Arc::new(TokioUdp),
        tls,
        command: Arc::new(SystemCommand),
        provider,
        clock: clock.clone(),
    };
    let builtins = build_builtins(&services).map_err(|error| CliError::Initialization {
        component: "scanner catalog",
        message: error.to_string(),
    })?;
    Ok((builtins, clock, services))
}

fn engine_for(
    registry: sugra_core::ScannerRegistry,
    clock: Arc<SystemClock>,
    concurrency: usize,
) -> Result<Engine, CliError> {
    Ok(Engine::new(registry, clock, concurrency)?)
}

fn print_catalog(catalog: &Catalog, track: Option<&str>, json: bool) -> Result<(), CliError> {
    let entries: Vec<_> = catalog
        .iter()
        .filter(|descriptor| track.is_none_or(|value| descriptor.track == value))
        .collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }
    println!("{:<6} {:<34} {:<20} TARGETS", "ID", "SCANNER", "TRACK");
    for descriptor in entries {
        println!(
            "{:<6} {:<34} {:<20} {}",
            descriptor
                .legacy_id
                .map_or_else(|| "—".into(), |id| id.to_string()),
            descriptor.id,
            descriptor.track,
            descriptor
                .target_kinds
                .iter()
                .map(|kind| kind.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    Ok(())
}

fn print_descriptor(descriptor: &ScannerDescriptor, json: bool) -> Result<(), CliError> {
    if json {
        println!("{}", serde_json::to_string_pretty(descriptor)?);
        return Ok(());
    }
    println!("{} ({})", descriptor.name, descriptor.id);
    println!("{}", descriptor.description);
    println!("Track: {}", descriptor.track);
    println!(
        "Compatibility ID: {}",
        descriptor
            .legacy_id
            .map_or_else(|| "none".into(), |id| id.to_string())
    );
    println!(
        "Target kinds: {}",
        descriptor
            .target_kinds
            .iter()
            .map(|kind| kind.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("Capabilities: {:?}", descriptor.capabilities);
    if descriptor.options.is_empty() {
        println!("Options: none");
    } else {
        println!("Options:");
        for option in &descriptor.options {
            println!(
                "  {}{} — {}",
                option.key,
                if option.required { " (required)" } else { "" },
                option.description
            );
        }
    }
    Ok(())
}

async fn run_scan(concurrency: usize, arguments: ScanArgs) -> Result<(), CliError> {
    let (builtins, clock, _) = build_application()?;
    let descriptor = resolve_scanner(&builtins.catalog, &arguments.scanner)?;
    let target = parse_target(&descriptor, &arguments.target, arguments.target_kind)?;
    require_authorization(&descriptor, arguments.authorize_active)?;
    let supplied = parse_assignments(&arguments.options)?;
    let options = resolve_options(&descriptor.options, &supplied)?;
    let budget = Budget {
        timeout_ms: arguments.timeout_ms,
        concurrency,
        max_requests: arguments.max_requests,
        max_response_bytes: arguments.max_response_bytes,
        max_depth: arguments.max_depth,
    }
    .validate()?;
    let request = request_for(
        &descriptor,
        target,
        options,
        budget,
        arguments.authorize_active,
    );
    let engine = engine_for(builtins.registry, clock, concurrency)?;
    let report = engine
        .execute(vec![request], CancellationToken::new(), None)
        .await?;
    if !arguments.no_persist {
        RunStore::new(arguments.output)?.persist(&report).await?;
    }
    print_report(&report, arguments.format)
}

async fn run_preset(
    concurrency: usize,
    preset: Preset,
    raw_target: &str,
    authorize_active: bool,
    format: OutputFormat,
    output: PathBuf,
) -> Result<(), CliError> {
    let (builtins, clock, _) = build_application()?;
    let mut requests = Vec::new();
    for descriptor in builtins
        .catalog
        .iter()
        .filter(|descriptor| preset_matches(preset, descriptor))
    {
        let Some(target) = infer_target(descriptor, raw_target) else {
            continue;
        };
        if descriptor
            .capabilities
            .iter()
            .copied()
            .any(Capability::requires_authorization)
            && !authorize_active
        {
            continue;
        }
        let options = resolve_options(&descriptor.options, &BTreeMap::new())?;
        requests.push(request_for(
            descriptor,
            target,
            options,
            Budget {
                concurrency,
                ..Budget::default()
            },
            authorize_active,
        ));
    }
    if requests.is_empty() {
        return Err(CliError::EmptyPreset {
            preset,
            target: raw_target.into(),
        });
    }
    let engine = engine_for(builtins.registry, clock, concurrency)?;
    let report = engine
        .execute(requests, CancellationToken::new(), None)
        .await?;
    RunStore::new(output)?.persist(&report).await?;
    print_report(&report, format)
}

async fn render_saved_report(path: &Path, format: OutputFormat) -> Result<(), CliError> {
    let bytes = tokio::fs::read(path).await?;
    let report = serde_json::from_slice::<RunReport>(&bytes)?;
    print_report(&report, format)
}

async fn run_tui(concurrency: usize, output: PathBuf) -> Result<(), CliError> {
    let (builtins, clock, _) = build_application()?;
    let engine = Arc::new(engine_for(builtins.registry, clock, concurrency)?);
    sugra_tui::run(sugra_tui::TuiServices {
        catalog: builtins.catalog,
        engine,
        store: RunStore::new(output)?,
    })
    .await?;
    Ok(())
}

fn resolve_scanner(catalog: &Catalog, selector: &str) -> Result<ScannerDescriptor, CliError> {
    if let Ok(id) = ScannerId::new(selector)
        && let Some(descriptor) = catalog.get(&id)
    {
        return Ok(descriptor.clone());
    }
    let compatibility = if let Some(value) = selector
        .strip_prefix('U')
        .or_else(|| selector.strip_prefix('u'))
    {
        value.parse::<u8>().ok().map(LegacyId::Additional)
    } else {
        selector.parse::<u16>().ok().map(LegacyId::Catalog)
    };
    compatibility
        .and_then(|id| catalog.resolve_legacy(id))
        .cloned()
        .ok_or_else(|| CliError::UnknownScanner(selector.into()))
}

fn parse_target(
    descriptor: &ScannerDescriptor,
    raw: &str,
    explicit: Option<TargetKindArg>,
) -> Result<Target, CliError> {
    if let Some(explicit) = explicit {
        let kind = TargetKind::from(explicit);
        if !descriptor.target_kinds.contains(&kind) {
            return Err(CliError::InvalidTarget {
                scanner: descriptor.id.to_string(),
                target: raw.into(),
            });
        }
        return Ok(Target::parse(kind, raw)?);
    }
    infer_target(descriptor, raw).ok_or_else(|| CliError::InvalidTarget {
        scanner: descriptor.id.to_string(),
        target: raw.into(),
    })
}

fn infer_target(descriptor: &ScannerDescriptor, raw: &str) -> Option<Target> {
    descriptor
        .target_kinds
        .iter()
        .find_map(|kind| Target::parse(*kind, raw).ok())
}

fn parse_assignments(values: &[String]) -> Result<BTreeMap<String, String>, CliError> {
    let mut supplied = BTreeMap::new();
    for assignment in values {
        let (key, value) = assignment
            .split_once('=')
            .filter(|(key, _)| !key.trim().is_empty())
            .ok_or_else(|| CliError::InvalidAssignment(assignment.clone()))?;
        supplied.insert(key.trim().into(), value.into());
    }
    Ok(supplied)
}

fn require_authorization(descriptor: &ScannerDescriptor, authorized: bool) -> Result<(), CliError> {
    if !authorized
        && descriptor
            .capabilities
            .iter()
            .copied()
            .any(Capability::requires_authorization)
    {
        return Err(CliError::AuthorizationRequired(descriptor.id.to_string()));
    }
    Ok(())
}

fn request_for(
    descriptor: &ScannerDescriptor,
    target: Target,
    options: BTreeMap<String, serde_json::Value>,
    budget: Budget,
    authorized: bool,
) -> ScanRequest {
    ScanRequest {
        scanner_id: descriptor.id.clone(),
        scope: ScopeGrant::exact(&target, authorized, OffsetDateTime::now_utc()),
        target,
        options,
        budget,
    }
}

fn preset_matches(preset: Preset, descriptor: &ScannerDescriptor) -> bool {
    match preset {
        Preset::All => true,
        Preset::Network => matches!(
            descriptor.track.as_str(),
            "dns" | "registry" | "tcp-probe" | "udp-probe" | "tls" | "local-command"
        ),
        Preset::Web => descriptor.track == "web-observation",
        Preset::Security => matches!(descriptor.track.as_str(), "intelligence" | "local-analysis"),
    }
}

fn print_report(report: &RunReport, format: OutputFormat) -> Result<(), CliError> {
    match format {
        OutputFormat::Terminal => print!("{}", render_terminal(report)),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(report)?),
        OutputFormat::Csv => print!("{}", render_csv(report)),
        OutputFormat::Html => print!("{}", render_html(report)),
    }
    io::stdout().flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_catalog() -> Result<Catalog, Box<dyn std::error::Error>> {
        Catalog::new(vec![ScannerDescriptor {
            id: ScannerId::new("dns-records")?,
            legacy_id: Some(LegacyId::Catalog(3)),
            name: "DNS Records".into(),
            description: "Observe public DNS records.".into(),
            track: "dns".into(),
            target_kinds: vec![TargetKind::Domain],
            capabilities: vec![Capability::PassiveNetwork],
            options: Vec::new(),
            version: "1".into(),
        }])
        .map_err(Into::into)
    }

    #[test]
    fn cli_contract_is_parseable_without_a_subcommand() {
        let cli = Cli::try_parse_from(["sugra"]);
        assert!(cli.is_ok());
    }

    #[test]
    fn compatibility_selector_resolves_to_canonical_descriptor()
    -> Result<(), Box<dyn std::error::Error>> {
        let catalog = fixture_catalog()?;
        assert_eq!(resolve_scanner(&catalog, "3")?.id.as_str(), "dns-records");
        assert_eq!(
            resolve_scanner(&catalog, "dns-records")?.id.as_str(),
            "dns-records"
        );
        Ok(())
    }

    #[test]
    fn target_inference_is_limited_to_declared_kinds() -> Result<(), Box<dyn std::error::Error>> {
        let catalog = fixture_catalog()?;
        let descriptor = resolve_scanner(&catalog, "dns-records")?;
        assert!(matches!(
            infer_target(&descriptor, "example.com"),
            Some(Target::Domain(_))
        ));
        assert!(infer_target(&descriptor, "192.0.2.1").is_none());
        Ok(())
    }

    #[test]
    fn duplicate_option_assignment_uses_last_explicit_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let values = vec!["timeout=10".into(), "timeout=20".into()];
        let parsed = parse_assignments(&values)?;
        assert_eq!(parsed.get("timeout").map(String::as_str), Some("20"));
        Ok(())
    }
}
