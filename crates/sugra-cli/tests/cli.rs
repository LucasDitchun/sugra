//! End-to-end tests for the public command-line contract.

use std::process::Command;
use std::str::FromStr;

use sugra_domain::{RunId, RunReport};
use time::OffsetDateTime;

fn sugra() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sugra"))
}

fn write_report(directory: &std::path::Path) -> Result<RunReport, Box<dyn std::error::Error>> {
    let report = RunReport {
        schema_version: 1,
        run_id: RunId::from_str("00000000-0000-4000-8000-000000000001")?,
        app_version: "test".into(),
        started_at: OffsetDateTime::UNIX_EPOCH,
        finished_at: OffsetDateTime::UNIX_EPOCH,
        executions: Vec::new(),
    };
    std::fs::create_dir_all(directory)?;
    std::fs::write(directory.join("report.json"), serde_json::to_vec(&report)?)?;
    Ok(report)
}

#[test]
fn report_accepts_a_run_directory_and_emits_canonical_json()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let run_directory = root.path().join("run");
    let report = write_report(&run_directory)?;

    let output = sugra()
        .args([
            "report",
            run_directory.to_string_lossy().as_ref(),
            "--format",
            "json",
        ])
        .output()?;

    assert!(output.status.success());
    let rendered: RunReport = serde_json::from_slice(&output.stdout)?;
    assert_eq!(rendered, report);
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn list_alias_emits_the_complete_json_catalog() -> Result<(), Box<dyn std::error::Error>> {
    let output = sugra().args(["list", "--json"]).output()?;

    assert!(output.status.success());
    let catalog: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(catalog.as_array().map(Vec::len), Some(147));
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn help_discloses_public_command_aliases() -> Result<(), Box<dyn std::error::Error>> {
    let output = sugra().arg("--help").output()?;

    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    assert!(help.contains("alias: list"));
    assert!(help.contains("alias: doctor"));
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn config_json_reflects_global_cli_overrides() -> Result<(), Box<dyn std::error::Error>> {
    let output = sugra()
        .args(["--concurrency", "9", "config", "--json"])
        .output()?;

    assert!(output.status.success());
    let config: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(config["concurrency"], 9);
    assert_eq!(config["active_authorization_required"], true);
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn history_json_is_an_empty_array_for_an_uncreated_store() -> Result<(), Box<dyn std::error::Error>>
{
    let root = tempfile::tempdir()?;
    let missing = root.path().join("not-created");
    let output = sugra()
        .args([
            "history",
            "--output",
            missing.to_string_lossy().as_ref(),
            "--json",
        ])
        .output()?;

    assert!(output.status.success());
    let history: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(history, serde_json::json!([]));
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn diagnostics_json_reports_capabilities_without_environment_values()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let output = sugra()
        .args([
            "diagnostics",
            "--output",
            root.path().to_string_lossy().as_ref(),
            "--json",
        ])
        .output()?;

    assert!(output.status.success());
    let diagnostics: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(diagnostics["schema_version"], 1);
    assert_eq!(diagnostics["catalog"]["scanner_count"], 147);
    assert_eq!(diagnostics["run_store"]["directory"], true);
    assert!(!String::from_utf8(output.stdout)?.contains("PATH"));
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn runtime_validation_errors_do_not_echo_invalid_values() -> Result<(), Box<dyn std::error::Error>>
{
    let sensitive_value = "private-api-token";
    let output = sugra()
        .args(["scan", "dns-records", "example.com", "-O", sensitive_value])
        .output()?;

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("invalid option assignment"));
    assert!(!stderr.contains(sensitive_value));
    assert!(output.stdout.is_empty());
    Ok(())
}

#[test]
fn malformed_reports_do_not_echo_report_contents() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let report_path = root.path().join("report.json");
    let sensitive_value = "private-report-value";
    std::fs::write(
        &report_path,
        format!(r#"{{"schema_version":"{sensitive_value}"}}"#),
    )?;

    let output = sugra()
        .args(["report", report_path.to_string_lossy().as_ref()])
        .output()?;

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr)?;
    assert!(stderr.contains("invalid canonical report"));
    assert!(!stderr.contains(sensitive_value));
    assert!(output.stdout.is_empty());
    Ok(())
}
