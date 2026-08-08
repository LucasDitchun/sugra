//! Deterministic projections of the canonical run report.

use std::fmt::Write;

use sugra_domain::RunReport;

/// Renders a concise terminal summary without ANSI control bytes.
#[must_use]
pub fn render_terminal(report: &RunReport) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "Run {} — {:?}", report.run_id, report.status());
    for execution in &report.executions {
        let _ = writeln!(
            output,
            "{:<32} {:<10?} {:>8} ms  findings={} evidence={}",
            execution.scanner_id,
            execution.result.status,
            execution.duration_ms,
            execution.result.findings.len(),
            execution.result.evidence.len()
        );
    }
    output
}

/// Renders one row per execution as RFC 4180-style CSV.
#[must_use]
pub fn render_csv(report: &RunReport) -> String {
    let mut output =
        String::from("scanner_id,status,duration_ms,findings,evidence,diagnostics\r\n");
    for execution in &report.executions {
        let row = [
            execution.scanner_id.to_string(),
            format!("{:?}", execution.result.status).to_ascii_lowercase(),
            execution.duration_ms.to_string(),
            execution.result.findings.len().to_string(),
            execution.result.evidence.len().to_string(),
            execution.result.diagnostics.len().to_string(),
        ];
        let _ = writeln!(
            output,
            "{}",
            row.iter()
                .map(|value| csv_cell(value))
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    output.replace('\n', "\r\n").replace("\r\r\n", "\r\n")
}

/// Renders a self-contained escaped HTML report.
#[must_use]
pub fn render_html(report: &RunReport) -> String {
    let mut rows = String::new();
    for execution in &report.executions {
        let _ = write!(
            rows,
            "<tr><td>{}</td><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            escape_html(&execution.scanner_id.to_string()),
            execution.result.status,
            execution.duration_ms,
            execution.result.findings.len(),
            execution.result.evidence.len()
        );
    }
    format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Sugra run {}</title><style>body{{font:16px system-ui;background:#090b10;color:#e9eef8;max-width:1100px;margin:2rem auto;padding:0 1rem}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #30384a;padding:.6rem;text-align:left}}th{{color:#63e6ff}}</style><h1>Run {}</h1><p>Status: {:?}</p><table><thead><tr><th>Scanner</th><th>Status</th><th>Duration (ms)</th><th>Findings</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table></html>",
        report.run_id,
        report.run_id,
        report.status()
    )
}

fn csv_cell(value: &str) -> String {
    if value.contains([',', '"', '\r', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.into()
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use sugra_domain::{
        Diagnostic, ExecutionStatus, RunId, RunReport, ScanExecution, ScanResult, ScannerId,
    };
    use time::OffsetDateTime;

    use super::*;

    fn report(status: ExecutionStatus) -> Result<RunReport, Box<dyn std::error::Error>> {
        Ok(RunReport {
            schema_version: 1,
            run_id: RunId::new(),
            app_version: "test".into(),
            started_at: OffsetDateTime::UNIX_EPOCH,
            finished_at: OffsetDateTime::UNIX_EPOCH,
            executions: vec![ScanExecution {
                scanner_id: ScannerId::new("safe-id")?,
                result: ScanResult {
                    status,
                    findings: Vec::new(),
                    evidence: Vec::new(),
                    diagnostics: vec![Diagnostic {
                        kind: "test".into(),
                        message: "safe diagnostic".into(),
                    }],
                },
                duration_ms: 42,
            }],
        })
    }

    #[test]
    fn html_escapes_scanner_identity_projection() -> Result<(), Box<dyn std::error::Error>> {
        let html = render_html(&report(ExecutionStatus::Partial)?);
        assert!(!html.contains("<script>"));
        Ok(())
    }

    #[test]
    fn terminal_projection_is_plain_text_with_execution_counts()
    -> Result<(), Box<dyn std::error::Error>> {
        let report = report(ExecutionStatus::Completed)?;
        let terminal = render_terminal(&report);

        assert!(terminal.starts_with(&format!("Run {} — Completed\n", report.run_id)));
        assert!(terminal.contains("safe-id"));
        assert!(terminal.contains("42 ms"));
        assert!(terminal.contains("findings=0 evidence=0"));
        assert!(!terminal.contains('\u{1b}'));
        Ok(())
    }

    #[test]
    fn csv_projection_uses_crlf_and_stable_columns() -> Result<(), Box<dyn std::error::Error>> {
        let csv = render_csv(&report(ExecutionStatus::Skipped)?);
        assert_eq!(
            csv,
            "scanner_id,status,duration_ms,findings,evidence,diagnostics\r\nsafe-id,skipped,42,0,0,1\r\n"
        );
        assert!(!csv.replace("\r\n", "").contains('\n'));
        Ok(())
    }

    #[test]
    fn csv_cells_quote_delimiters_quotes_and_line_breaks() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("comma,value"), "\"comma,value\"");
        assert_eq!(csv_cell("quoted\"value"), "\"quoted\"\"value\"");
        assert_eq!(csv_cell("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn html_projection_is_self_contained_and_escapes_all_markup_characters()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(escape_html("<&>\"'"), "&lt;&amp;&gt;&quot;&#39;");
        let report = report(ExecutionStatus::Failed)?;
        let html = render_html(&report);
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("<meta charset=\"utf-8\">"));
        assert!(html.contains(&format!("<title>Sugra run {}</title>", report.run_id)));
        assert!(html.contains("<td>safe-id</td><td>Failed</td><td>42</td>"));
        assert!(html.ends_with("</html>"));
        Ok(())
    }
}
