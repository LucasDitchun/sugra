//! Deterministic terminal rendering, navigation, and safety regression tests.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::style::Color;
use serde_json::json;
use sugra_core::{Catalog, RunEvent};
use sugra_domain::{
    Capability, Confidence, Diagnostic, Evidence, ExecutionStatus, Finding, LegacyId,
    OptionDefinition, OptionKind, RunId, RunReport, ScanExecution, ScanResult, ScannerDescriptor,
    ScannerId, Severity, Target, TargetKind,
};
use sugra_tui::{App, Screen, UiAction, render};
use time::OffsetDateTime;

fn fixture_catalog() -> Result<Catalog, Box<dyn std::error::Error>> {
    Catalog::new(vec![
        ScannerDescriptor {
            id: ScannerId::new("dns-records")?,
            legacy_id: Some(LegacyId::Catalog(3)),
            name: "DNS Records".into(),
            description: "Collect public DNS records without active probing.".into(),
            track: "dns".into(),
            target_kinds: vec![TargetKind::Domain],
            capabilities: vec![Capability::PassiveNetwork],
            options: Vec::new(),
            version: "1".into(),
        },
        ScannerDescriptor {
            id: ScannerId::new("web-probe")?,
            legacy_id: Some(LegacyId::Catalog(8)),
            name: "Web Probe".into(),
            description: "Inspect a scoped web endpoint with safe active requests.".into(),
            track: "web".into(),
            target_kinds: vec![TargetKind::Domain, TargetKind::Url],
            capabilities: vec![Capability::ActiveHttpSafe],
            options: vec![OptionDefinition {
                key: "follow_redirects".into(),
                description: "Follow safe same-scope redirects.".into(),
                kind: OptionKind::Boolean,
                default: Some("false".into()),
                required: false,
            }],
            version: "2".into(),
        },
    ])
    .map_err(Into::into)
}

fn fixture_report() -> Result<RunReport, Box<dyn std::error::Error>> {
    Ok(RunReport {
        schema_version: 1,
        run_id: RunId::new(),
        app_version: "test".into(),
        started_at: OffsetDateTime::UNIX_EPOCH,
        finished_at: OffsetDateTime::UNIX_EPOCH,
        executions: vec![ScanExecution {
            scanner_id: ScannerId::new("web-probe")?,
            result: ScanResult {
                status: ExecutionStatus::Partial,
                findings: vec![Finding {
                    key: "missing-hsts".into(),
                    title: "Strict transport policy is absent".into(),
                    severity: Severity::Medium,
                    confidence: Confidence::Confirmed,
                    evidence: vec![0],
                }],
                evidence: vec![Evidence {
                    kind: "http-response".into(),
                    source: "https://example.com".into(),
                    observation: json!({"status": 200, "hsts": false}),
                    observed_at: OffsetDateTime::UNIX_EPOCH,
                }],
                diagnostics: vec![Diagnostic {
                    kind: "rate-limit".into(),
                    message: "One request was deferred by the bounded scheduler.".into(),
                }],
            },
            duration_ms: 42,
        }],
    })
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn type_text(app: &mut App, value: &str) {
    for character in value.chars() {
        assert_eq!(
            app.handle_key(key(KeyCode::Char(character))),
            UiAction::None
        );
    }
}

fn screen(
    app: &mut App,
    width: u16,
    height: u16,
) -> Result<(String, bool), Box<dyn std::error::Error>> {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend)?;
    terminal.draw(|frame| render(frame, app))?;
    let buffer = terminal.backend().buffer();
    let mut rows = Vec::with_capacity(usize::from(height));
    for y in 0..height {
        let row = (0..width)
            .map(|x| buffer[(x, y)].symbol())
            .collect::<String>()
            .trim_end()
            .to_string();
        rows.push(row);
    }
    while rows.last().is_some_and(String::is_empty) {
        rows.pop();
    }
    let color_used = buffer
        .content()
        .iter()
        .any(|cell| cell.fg != Color::Reset || cell.bg != Color::Reset);
    Ok((rows.join("\n"), color_used))
}

fn portable_snapshot(contents: &str) -> String {
    contents.lines().collect::<Vec<_>>().join("\n")
}

#[test]
fn snapshot_comparisons_normalize_platform_line_endings() {
    assert_eq!(portable_snapshot("first\r\nsecond\r\n"), "first\nsecond");
    assert_eq!(portable_snapshot("first\nsecond\n"), "first\nsecond");
}

#[test]
fn dashboard_snapshot_is_structured_and_actionable() -> Result<(), Box<dyn std::error::Error>> {
    let catalog = fixture_catalog()?;
    let mut app = App::with_color(&catalog, false);
    let (snapshot, _) = screen(&mut app, 96, 28)?;
    assert_eq!(
        snapshot,
        portable_snapshot(include_str!("snapshots/dashboard.txt"))
    );
    assert!(snapshot.contains("SECURITY OPERATIONS CONSOLE"));
    assert!(snapshot.contains("DASHBOARD"));
    assert!(snapshot.contains('2'));
    assert!(snapshot.contains("SCANNERS"));
    assert!(snapshot.contains('1'));
    assert!(snapshot.contains("ACTIVE"));
    assert!(snapshot.contains("QUICK ACTIONS"));
    assert!(snapshot.contains("SAFE DEFAULTS"));
    assert!(snapshot.contains("Enter catalog"));
    Ok(())
}

#[test]
fn catalog_search_filters_and_opens_selected_scanner() -> Result<(), Box<dyn std::error::Error>> {
    let catalog = fixture_catalog()?;
    let mut app = App::with_color(&catalog, false);
    assert_eq!(app.handle_key(key(KeyCode::Enter)), UiAction::None);
    assert_eq!(app.screen(), Screen::Catalog);
    assert_eq!(app.handle_key(key(KeyCode::Char('/'))), UiAction::None);
    type_text(&mut app, "web");
    assert_eq!(app.handle_key(key(KeyCode::Enter)), UiAction::None);
    let (catalog_view, _) = screen(&mut app, 100, 30)?;
    assert!(catalog_view.contains("1 MATCHES"));
    assert!(catalog_view.contains("Web Probe"));
    assert!(!catalog_view.contains("DNS Records"));
    assert_eq!(app.handle_key(key(KeyCode::Enter)), UiAction::None);
    assert_eq!(app.screen(), Screen::Configure);
    let (configure_view, _) = screen(&mut app, 100, 30)?;
    assert!(configure_view.contains("Authorization"));
    assert!(configure_view.contains("REQUIRED"));
    assert!(configure_view.contains("follow_redirects"));
    Ok(())
}

#[test]
fn active_scan_requires_consent_and_returns_validated_options_and_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let catalog = fixture_catalog()?;
    let mut app = App::with_color(&catalog, false);
    let _ = app.handle_key(key(KeyCode::Enter));
    let _ = app.handle_key(key(KeyCode::Down));
    let _ = app.handle_key(key(KeyCode::Enter));
    let _ = app.handle_key(key(KeyCode::Tab));
    type_text(&mut app, "example.com");
    assert_eq!(app.handle_key(key(KeyCode::F(5))), UiAction::None);
    let (invalid_view, _) = screen(&mut app, 100, 30)?;
    assert!(
        invalid_view.contains("Explicit active authorization is")
            && invalid_view.contains("required"),
        "{invalid_view}"
    );

    let _ = app.handle_key(key(KeyCode::Tab));
    let _ = app.handle_key(key(KeyCode::Char(' ')));
    let _ = app.handle_key(key(KeyCode::Tab));
    let _ = app.handle_key(key(KeyCode::Right));
    let action = app.handle_key(key(KeyCode::F(5)));
    let UiAction::Start(request) = action else {
        return Err("expected a validated scan request".into());
    };
    assert!(request.scope.active_authorized);
    assert_eq!(request.options.get("follow_redirects"), Some(&json!(true)));
    assert_eq!(request.budget.timeout_ms, 15_000);
    assert_eq!(request.budget.max_requests, 64);
    assert_eq!(app.screen(), Screen::LiveRun);
    Ok(())
}

#[test]
fn modified_control_keys_cannot_enter_target_text() -> Result<(), Box<dyn std::error::Error>> {
    let catalog = fixture_catalog()?;
    let mut app = App::with_color(&catalog, false);
    let _ = app.handle_key(key(KeyCode::Enter));
    let _ = app.handle_key(key(KeyCode::Down));
    let _ = app.handle_key(key(KeyCode::Enter));
    let _ = app.handle_key(key(KeyCode::Tab));
    let control_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
    assert_eq!(app.handle_key(control_c), UiAction::None);
    type_text(&mut app, "example.com");
    let _ = app.handle_key(key(KeyCode::Tab));
    let _ = app.handle_key(key(KeyCode::Char(' ')));
    let UiAction::Start(request) = app.handle_key(key(KeyCode::F(5))) else {
        return Err("expected control key to be ignored".into());
    };
    assert_eq!(request.target, Target::Domain("example.com".into()));
    Ok(())
}

#[test]
fn live_events_show_real_progress_and_cancel_only_once() -> Result<(), Box<dyn std::error::Error>> {
    let catalog = fixture_catalog()?;
    let mut app = App::with_color(&catalog, false);
    let _ = app.handle_key(key(KeyCode::Enter));
    let _ = app.handle_key(key(KeyCode::Enter));
    let _ = app.handle_key(key(KeyCode::Tab));
    type_text(&mut app, "example.com");
    let UiAction::Start(_) = app.handle_key(key(KeyCode::F(5))) else {
        return Err("expected passive scan to start".into());
    };
    let run_id = RunId::new();
    app.push_event(RunEvent::Planned {
        run_id,
        scanners: 1,
    });
    app.push_event(RunEvent::ScanFinished {
        run_id,
        scanner_id: ScannerId::new("dns-records")?,
        status: ExecutionStatus::Completed,
        duration_ms: 7,
    });
    let (live_view, _) = screen(&mut app, 100, 30)?;
    assert!(live_view.contains("1/1 complete"));
    assert!(live_view.contains("[DONE] dns-records | Completed | 7 ms"));
    assert_eq!(app.handle_key(key(KeyCode::Char('c'))), UiAction::Cancel);
    assert_eq!(app.handle_key(key(KeyCode::Char('c'))), UiAction::None);
    Ok(())
}

#[test]
fn report_sections_expose_details_and_history_reopens_report()
-> Result<(), Box<dyn std::error::Error>> {
    let catalog = fixture_catalog()?;
    let mut app = App::with_color(&catalog, false);
    app.set_report(fixture_report()?);
    let (findings, _) = screen(&mut app, 120, 32)?;
    assert!(findings.contains("Strict transport policy is absent"));
    assert!(findings.contains("Evidence links: [0]"));

    let _ = app.handle_key(key(KeyCode::Tab));
    let (evidence, _) = screen(&mut app, 120, 32)?;
    assert!(evidence.contains("REDACTED OBSERVATION"));
    assert!(evidence.contains("\"hsts\":false"));

    let _ = app.handle_key(key(KeyCode::Tab));
    let (diagnostics, _) = screen(&mut app, 120, 32)?;
    assert!(diagnostics.contains("rate-limit"));
    assert!(diagnostics.contains("bounded scheduler"));

    let _ = app.handle_key(key(KeyCode::Char('h')));
    assert_eq!(app.screen(), Screen::History);
    let (history, _) = screen(&mut app, 110, 30)?;
    assert!(history.contains("1 scan(s)"));
    let _ = app.handle_key(key(KeyCode::Enter));
    assert_eq!(app.screen(), Screen::Results);
    Ok(())
}

#[test]
fn help_overlay_restores_its_origin_screen() -> Result<(), Box<dyn std::error::Error>> {
    let catalog = fixture_catalog()?;
    let mut app = App::with_color(&catalog, false);
    let _ = app.handle_key(key(KeyCode::Enter));
    let _ = app.handle_key(key(KeyCode::Char('?')));
    let (help, _) = screen(&mut app, 100, 30)?;
    assert!(help.contains("HELP & DIAGNOSTICS"));
    assert!(help.contains("Active scans require"));
    assert!(help.contains("NO_COLOR"));
    let _ = app.handle_key(key(KeyCode::Esc));
    assert_eq!(app.screen(), Screen::Catalog);
    Ok(())
}

#[test]
fn colorless_ascii_mode_has_textual_state_and_ascii_borders()
-> Result<(), Box<dyn std::error::Error>> {
    let catalog = fixture_catalog()?;
    let mut app = App::with_color(&catalog, false);
    let _ = app.handle_key(key(KeyCode::Char('s')));
    let _ = app.handle_key(key(KeyCode::Char('3')));
    let (settings, color_used) = screen(&mut app, 100, 30)?;
    assert!(!color_used);
    assert!(settings.contains('+'));
    assert!(settings.contains("[ON]"));
    assert!(!settings.contains('╭'));
    assert!(!settings.contains('─'));
    Ok(())
}

#[test]
fn small_terminal_has_safe_fallback() -> Result<(), Box<dyn std::error::Error>> {
    let catalog = fixture_catalog()?;
    let mut app = App::with_color(&catalog, false);
    let (small, _) = screen(&mut app, 60, 18)?;
    assert_eq!(
        small,
        portable_snapshot(include_str!("snapshots/small-terminal.txt"))
    );
    assert!(small.contains("[!] TERMINAL TOO SMALL"));
    assert!(small.contains("Minimum: 72x22"));
    assert!(small.contains("Resize the terminal"));
    Ok(())
}
