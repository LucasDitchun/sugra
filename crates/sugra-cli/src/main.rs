//! Sugra command-line entry point.

use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use sugra_adapters::{
    HickoryDns, ReqwestHttp, ReqwestProvider, RustlsTls, SystemClock, SystemCommand,
    SystemLocalInput, TokioTcp, TokioUdp,
};
use sugra_core::{
    Catalog, Engine, RunStore, ServiceBundle, render_csv, render_html, render_terminal,
    resolve_options,
};
use sugra_domain::{
    Budget, Capability, LegacyId, RunReport, ScanRequest, ScannerDescriptor, ScannerId, ScopeGrant,
    ScopeRule, Target, TargetKind,
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
    #[command(visible_alias = "list")]
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
    /// List canonical reports from the immutable run store.
    History {
        /// Immutable run artifact root.
        #[arg(long, default_value = "sugra-runs")]
        output: PathBuf,
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show the effective read-only CLI configuration.
    Config {
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect local capabilities without making network requests.
    #[command(visible_alias = "doctor")]
    Diagnostics {
        /// Immutable run artifact root inspected by the command.
        #[arg(long, default_value = "sugra-runs")]
        output: PathBuf,
        /// Emit structured JSON.
        #[arg(long)]
        json: bool,
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
    /// Additional DNS host explicitly included in active scope; may be repeated.
    #[arg(
        long = "allow-host",
        value_name = "HOST",
        requires = "authorize_active"
    )]
    allow_hosts: Vec<String>,
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
    #[error("scanner selector is unknown")]
    UnknownScanner,
    #[error("target is incompatible with scanner {scanner}")]
    InvalidTarget { scanner: String },
    #[error("invalid option assignment; expected key=value")]
    InvalidAssignment,
    #[error("active scanner {0} requires --authorize-active")]
    AuthorizationRequired(String),
    #[error("could not initialize {component}: {message}")]
    Initialization {
        component: &'static str,
        message: String,
    },
    #[error("no scanner in preset {preset:?} accepts the supplied target")]
    EmptyPreset { preset: Preset },
    #[error("invalid canonical report: {0}")]
    InvalidReport(PathBuf),
    #[error("could not format a report timestamp")]
    Timestamp(#[source] time::error::Format),
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
        Command::History { output, json } => print_history(&output, json).await,
        Command::Diagnostics { output, json } => print_diagnostics(&output, json),
        Command::Config { json } => print_effective_config(concurrency, json),
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
        local_input: Arc::new(SystemLocalInput),
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

fn render_effective_config(concurrency: usize, json: bool) -> Result<String, CliError> {
    if json {
        return Ok(serde_json::to_string_pretty(&serde_json::json!({
            "schema_version": 1,
            "concurrency": concurrency,
            "run_store": "sugra-runs",
            "scan_defaults": {
                "timeout_ms": Budget::DEFAULT.timeout_ms,
                "max_requests": Budget::DEFAULT.max_requests,
                "max_response_bytes": Budget::DEFAULT.max_response_bytes,
                "max_depth": Budget::DEFAULT.max_depth,
                "persist": true
            },
            "active_authorization_required": true
        }))?);
    }

    Ok(format!(
        "Concurrency: {concurrency}\nRun store: sugra-runs\nScan timeout: {} ms\nMaximum requests: {}\nMaximum response bytes: {}\nMaximum depth: {}\nPersistence: enabled by default\nActive authorization: required\n",
        Budget::DEFAULT.timeout_ms,
        Budget::DEFAULT.max_requests,
        Budget::DEFAULT.max_response_bytes,
        Budget::DEFAULT.max_depth
    ))
}

fn print_effective_config(concurrency: usize, json: bool) -> Result<(), CliError> {
    let output = render_effective_config(concurrency, json)?;
    print!("{output}");
    if !output.ends_with('\n') {
        println!();
    }
    io::stdout().flush()?;
    Ok(())
}

#[derive(Debug, Serialize)]
struct HistoryEntry {
    run_id: String,
    status: &'static str,
    started_at: String,
    finished_at: String,
    scanners: usize,
    findings: usize,
    evidence: usize,
    diagnostics: usize,
    report_path: PathBuf,
}

async fn load_history(root: &Path) -> Result<Vec<HistoryEntry>, CliError> {
    let mut directory = match tokio::fs::read_dir(root).await {
        Ok(directory) => directory,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut entries = Vec::new();
    while let Some(entry) = directory.next_entry().await? {
        if !entry.file_type().await?.is_dir() {
            continue;
        }
        let report_path = entry.path().join("report.json");
        let bytes = match tokio::fs::read(&report_path).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let report = serde_json::from_slice::<RunReport>(&bytes)
            .map_err(|_| CliError::InvalidReport(report_path.clone()))?;
        let started_at = report
            .started_at
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(CliError::Timestamp)?;
        let finished_at = report
            .finished_at
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(CliError::Timestamp)?;
        let summary = HistoryEntry {
            run_id: report.run_id.to_string(),
            status: status_label(report.status()),
            started_at,
            finished_at,
            scanners: report.executions.len(),
            findings: report
                .executions
                .iter()
                .map(|execution| execution.result.findings.len())
                .sum(),
            evidence: report
                .executions
                .iter()
                .map(|execution| execution.result.evidence.len())
                .sum(),
            diagnostics: report
                .executions
                .iter()
                .map(|execution| execution.result.diagnostics.len())
                .sum(),
            report_path,
        };
        entries.push((report.started_at, summary));
    }
    entries.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.run_id.cmp(&right.1.run_id))
    });
    Ok(entries.into_iter().map(|(_, summary)| summary).collect())
}

async fn print_history(root: &Path, json: bool) -> Result<(), CliError> {
    let history = load_history(root).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&history)?);
    } else if history.is_empty() {
        println!("No persisted runs found in {}.", root.display());
    } else {
        println!(
            "{:<36} {:<10} {:<25} {:>8} {:>8}",
            "RUN", "STATUS", "STARTED", "SCANNERS", "FINDINGS"
        );
        for run in history {
            println!(
                "{:<36} {:<10} {:<25} {:>8} {:>8}",
                run.run_id, run.status, run.started_at, run.scanners, run.findings
            );
        }
    }
    io::stdout().flush()?;
    Ok(())
}

const fn status_label(status: sugra_domain::ExecutionStatus) -> &'static str {
    match status {
        sugra_domain::ExecutionStatus::Completed => "completed",
        sugra_domain::ExecutionStatus::Partial => "partial",
        sugra_domain::ExecutionStatus::Skipped => "skipped",
        sugra_domain::ExecutionStatus::Failed => "failed",
        sugra_domain::ExecutionStatus::Cancelled => "cancelled",
    }
}

#[derive(Debug, Serialize)]
struct DiagnosticsReport {
    schema_version: u32,
    app_version: &'static str,
    platform: PlatformDiagnostics,
    catalog: CatalogDiagnostics,
    run_store: RunStoreDiagnostics,
    optional_commands: BTreeMap<&'static str, bool>,
}

#[derive(Debug, Serialize)]
struct PlatformDiagnostics {
    os: &'static str,
    arch: &'static str,
}

#[derive(Debug, Serialize)]
struct CatalogDiagnostics {
    ready: bool,
    scanner_count: usize,
}

#[derive(Debug, Serialize)]
struct RunStoreDiagnostics {
    exists: bool,
    directory: bool,
}

fn collect_diagnostics(output: &Path) -> DiagnosticsReport {
    let (catalog_ready, scanner_count) = build_application()
        .map(|(builtins, _, _)| (true, builtins.catalog.len()))
        .unwrap_or((false, 0));
    let metadata = std::fs::metadata(output).ok();
    let commands = if cfg!(target_os = "windows") {
        [
            ("ping", "ping"),
            ("traceroute", "tracert"),
            ("whois", "whois"),
            ("ssh-keyscan", "ssh-keyscan"),
        ]
    } else {
        [
            ("ping", "ping"),
            ("traceroute", "traceroute"),
            ("whois", "whois"),
            ("ssh-keyscan", "ssh-keyscan"),
        ]
    };
    DiagnosticsReport {
        schema_version: 1,
        app_version: env!("CARGO_PKG_VERSION"),
        platform: PlatformDiagnostics {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
        },
        catalog: CatalogDiagnostics {
            ready: catalog_ready,
            scanner_count,
        },
        run_store: RunStoreDiagnostics {
            exists: metadata.is_some(),
            directory: metadata.is_some_and(|value| value.is_dir()),
        },
        optional_commands: commands
            .into_iter()
            .map(|(label, executable)| (label, executable_available(executable)))
            .collect(),
    }
}

fn executable_available(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|directory| {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return true;
        }
        cfg!(target_os = "windows") && directory.join(format!("{name}.exe")).is_file()
    })
}

fn print_diagnostics(output: &Path, json: bool) -> Result<(), CliError> {
    let diagnostics = collect_diagnostics(output);
    if json {
        println!("{}", serde_json::to_string_pretty(&diagnostics)?);
    } else {
        println!("Sugra {}", diagnostics.app_version);
        println!(
            "Platform: {}/{}",
            diagnostics.platform.os, diagnostics.platform.arch
        );
        println!(
            "Catalog: {} ({} scanners)",
            if diagnostics.catalog.ready {
                "ready"
            } else {
                "unavailable"
            },
            diagnostics.catalog.scanner_count
        );
        println!(
            "Run store: {}",
            if diagnostics.run_store.directory {
                "available"
            } else if diagnostics.run_store.exists {
                "not a directory"
            } else {
                "not created"
            }
        );
        println!("Optional local commands:");
        for (command, available) in diagnostics.optional_commands {
            println!(
                "  {command}: {}",
                if available {
                    "available"
                } else {
                    "unavailable"
                }
            );
        }
    }
    io::stdout().flush()?;
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
        &arguments.allow_hosts,
    )?;
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
            &[],
        )?);
    }
    if requests.is_empty() {
        return Err(CliError::EmptyPreset { preset });
    }
    let engine = engine_for(builtins.registry, clock, concurrency)?;
    let report = engine
        .execute(requests, CancellationToken::new(), None)
        .await?;
    RunStore::new(output)?.persist(&report).await?;
    print_report(&report, format)
}

async fn render_saved_report(path: &Path, format: OutputFormat) -> Result<(), CliError> {
    let report_path = if path.is_dir() {
        path.join("report.json")
    } else {
        path.to_owned()
    };
    let bytes = tokio::fs::read(&report_path).await?;
    let report = serde_json::from_slice::<RunReport>(&bytes)
        .map_err(|_| CliError::InvalidReport(report_path))?;
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
        .ok_or(CliError::UnknownScanner)
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
            });
        }
        return Target::parse(kind, raw).map_err(|_| CliError::InvalidTarget {
            scanner: descriptor.id.to_string(),
        });
    }
    infer_target(descriptor, raw).ok_or_else(|| CliError::InvalidTarget {
        scanner: descriptor.id.to_string(),
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
            .ok_or(CliError::InvalidAssignment)?;
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
    allow_hosts: &[String],
) -> Result<ScanRequest, CliError> {
    let mut scope = ScopeGrant::exact(&target, authorized, OffsetDateTime::now_utc());
    for raw in allow_hosts {
        let Target::Domain(host) = Target::parse(TargetKind::Domain, raw)? else {
            unreachable!("domain parser returned a non-domain target")
        };
        if !scope
            .rules
            .iter()
            .any(|rule| matches!(rule, ScopeRule::Host(value) if value == &host))
        {
            scope.rules.push(ScopeRule::Host(host));
        }
    }
    Ok(ScanRequest {
        scanner_id: descriptor.id.clone(),
        scope,
        target,
        options,
        budget,
    })
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
    fn active_scan_accepts_explicit_additional_host_scope() -> Result<(), Box<dyn std::error::Error>>
    {
        let cli = Cli::try_parse_from([
            "sugra",
            "scan",
            "recursive-nameserver-leak-test",
            "example.com",
            "--authorize-active",
            "--allow-host",
            "ns1.example.net",
        ])?;
        let Some(Command::Scan(arguments)) = cli.command else {
            return Err("scan command was not parsed".into());
        };
        assert_eq!(arguments.allow_hosts, ["ns1.example.net"]);

        let descriptor = fixture_catalog()?
            .iter()
            .next()
            .cloned()
            .ok_or("fixture descriptor is missing")?;
        let target = Target::parse(TargetKind::Domain, "example.com")?;
        let request = request_for(
            &descriptor,
            target,
            BTreeMap::new(),
            Budget::default(),
            true,
            &arguments.allow_hosts,
        )?;
        assert!(
            request
                .scope
                .allows(&Target::parse(TargetKind::Domain, "ns1.example.net")?)
        );
        Ok(())
    }

    #[test]
    fn read_only_operational_commands_have_json_interfaces()
    -> Result<(), Box<dyn std::error::Error>> {
        let history = Cli::try_parse_from(["sugra", "history", "--json"])?;
        assert!(matches!(
            history.command,
            Some(Command::History { json: true, .. })
        ));

        let config = Cli::try_parse_from(["sugra", "config", "--json"])?;
        assert!(matches!(
            config.command,
            Some(Command::Config { json: true })
        ));

        let diagnostics = Cli::try_parse_from(["sugra", "diagnostics", "--json"])?;
        assert!(matches!(
            diagnostics.command,
            Some(Command::Diagnostics { json: true, .. })
        ));
        Ok(())
    }

    #[test]
    fn config_json_exposes_stable_effective_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let output = render_effective_config(7, true)?;
        let value: serde_json::Value = serde_json::from_str(&output)?;
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["concurrency"], 7);
        assert_eq!(value["run_store"], "sugra-runs");
        assert_eq!(
            value["scan_defaults"]["timeout_ms"],
            Budget::DEFAULT.timeout_ms
        );
        assert_eq!(value["active_authorization_required"], true);
        Ok(())
    }

    #[tokio::test]
    async fn history_is_newest_first_and_summarizes_reports()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::str::FromStr;

        use sugra_domain::{ExecutionStatus, RunId, ScanExecution, ScanResult};

        let root = tempfile::tempdir()?;
        let fixtures = [
            (
                "00000000-0000-4000-8000-000000000001",
                OffsetDateTime::UNIX_EPOCH,
            ),
            (
                "00000000-0000-4000-8000-000000000002",
                OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
            ),
        ];
        for (run_id, started_at) in fixtures {
            let directory = root.path().join(run_id);
            tokio::fs::create_dir(&directory).await?;
            let report = RunReport {
                schema_version: 1,
                run_id: RunId::from_str(run_id)?,
                app_version: "test".into(),
                started_at,
                finished_at: started_at,
                executions: vec![ScanExecution {
                    scanner_id: ScannerId::new("dns-records")?,
                    result: ScanResult {
                        status: ExecutionStatus::Completed,
                        findings: Vec::new(),
                        evidence: Vec::new(),
                        diagnostics: Vec::new(),
                    },
                    duration_ms: 1,
                }],
            };
            tokio::fs::write(directory.join("report.json"), serde_json::to_vec(&report)?).await?;
        }

        let history = load_history(root.path()).await?;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].run_id, fixtures[1].0);
        assert_eq!(history[0].scanners, 1);
        assert_eq!(history[0].status, "completed");
        assert!(history[0].report_path.ends_with("report.json"));
        Ok(())
    }

    #[test]
    fn diagnostics_json_is_structured_and_redacts_environment()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let diagnostics = collect_diagnostics(root.path());
        let output = serde_json::to_string(&diagnostics)?;
        let value: serde_json::Value = serde_json::from_str(&output)?;
        assert_eq!(value["schema_version"], 1);
        assert!(value["catalog"]["scanner_count"].as_u64().is_some());
        assert!(value["run_store"]["exists"].as_bool().is_some());
        assert!(value["optional_commands"].is_object());
        assert!(!output.contains("PATH"));
        Ok(())
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

    #[test]
    fn validation_errors_do_not_echo_target_or_option_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let assignment_secret = "private-api-token";
        let Err(assignment_error) = parse_assignments(&[assignment_secret.into()]) else {
            return Err(io::Error::other("invalid assignment was accepted").into());
        };
        assert!(!assignment_error.to_string().contains(assignment_secret));

        let catalog = fixture_catalog()?;
        let descriptor = resolve_scanner(&catalog, "dns-records")?;
        let target_secret = "private target value";
        let Err(error) = parse_target(&descriptor, target_secret, None) else {
            return Err(io::Error::other("invalid target was accepted").into());
        };
        assert!(!error.to_string().contains(target_secret));
        Ok(())
    }
}
