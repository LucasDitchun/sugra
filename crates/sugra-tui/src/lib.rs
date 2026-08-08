//! Full-screen terminal interface and its deterministic application state.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Gauge, List, ListItem, ListState, Paragraph, Tabs, Wrap};
use sugra_core::{Catalog, Engine, RunEvent, RunStore, resolve_options};
use sugra_domain::{
    Budget, Capability, RunReport, ScanRequest, ScannerDescriptor, ScopeGrant, Target,
};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const MIN_WIDTH: u16 = 80;
const MIN_HEIGHT: u16 = 24;

/// Screen currently owned by the main viewport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Searchable scanner catalog.
    Catalog,
    /// Target, option, scope, and authorization form.
    Configure,
    /// Observable run progress.
    LiveRun,
    /// Findings, evidence, and diagnostics.
    Results,
    /// Compatibility and presentation preferences.
    Settings,
}

/// Side effect requested by a keyboard transition.
#[derive(Debug, Clone, PartialEq)]
pub enum UiAction {
    /// No controller work is required.
    None,
    /// Execute one validated request.
    Start(Box<ScanRequest>),
    /// Cancel the active run.
    Cancel,
    /// Leave the interface.
    Quit,
}

/// Interactive terminal failure.
#[derive(Debug, Error)]
pub enum TuiError {
    /// Terminal input or rendering failed.
    #[error("terminal I/O failed: {0}")]
    Io(#[from] io::Error),
    /// Engine setup or execution failed.
    #[error("execution failed: {0}")]
    Engine(#[from] sugra_core::EngineError),
    /// Report persistence failed.
    #[error("report persistence failed: {0}")]
    Store(#[from] sugra_core::StoreError),
    /// Background execution ended without a report.
    #[error("execution task ended unexpectedly: {0}")]
    Join(String),
}

/// Immutable dependencies owned by the interactive controller.
pub struct TuiServices {
    /// Validated public scanner catalog.
    pub catalog: Catalog,
    /// Bounded execution engine.
    pub engine: Arc<Engine>,
    /// Immutable per-run artifact store.
    pub store: RunStore,
}

/// UI state independent from the terminal backend.
pub struct App {
    catalog: Vec<ScannerDescriptor>,
    filtered: Vec<usize>,
    selected: usize,
    list_state: ListState,
    screen: Screen,
    help_return: Option<Screen>,
    query: String,
    input_mode: InputMode,
    target_input: String,
    target_kind_index: usize,
    authorization: Authorization,
    validation: Option<String>,
    events: Vec<String>,
    report: Option<RunReport>,
    result_tab: usize,
    settings: Preferences,
    cancellation: CancellationState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputMode {
    Navigate,
    Search,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Authorization {
    NotGranted,
    Granted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CancellationState {
    Idle,
    Requested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Preference {
    Compatibility,
    Color,
    Ascii,
    ReducedMotion,
}

#[derive(Debug, Clone)]
struct Preferences {
    enabled: std::collections::BTreeSet<Preference>,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            enabled: [Preference::Compatibility, Preference::Color]
                .into_iter()
                .collect(),
        }
    }
}

impl Preferences {
    fn toggle(&mut self, preference: Preference) {
        if !self.enabled.remove(&preference) {
            self.enabled.insert(preference);
        }
    }

    fn is_enabled(&self, preference: Preference) -> bool {
        self.enabled.contains(&preference)
    }
}

impl App {
    /// Builds deterministic catalog state.
    #[must_use]
    pub fn new(catalog: &Catalog) -> Self {
        let catalog: Vec<_> = catalog.iter().cloned().collect();
        let filtered = (0..catalog.len()).collect();
        let mut list_state = ListState::default();
        if !catalog.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            catalog,
            filtered,
            selected: 0,
            list_state,
            screen: Screen::Catalog,
            help_return: None,
            query: String::new(),
            input_mode: InputMode::Navigate,
            target_input: String::new(),
            target_kind_index: 0,
            authorization: Authorization::NotGranted,
            validation: None,
            events: Vec::new(),
            report: None,
            result_tab: 0,
            settings: Preferences::default(),
            cancellation: CancellationState::Idle,
        }
    }

    /// Returns the active screen.
    #[must_use]
    pub const fn screen(&self) -> Screen {
        self.screen
    }

    /// Applies a key press and returns a controller action.
    pub fn handle_key(&mut self, key: KeyEvent) -> UiAction {
        if key.kind != KeyEventKind::Press {
            return UiAction::None;
        }
        if self.help_return.is_some() {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('?'))
                && let Some(screen) = self.help_return.take()
            {
                self.screen = screen;
            }
            return UiAction::None;
        }
        if key.code == KeyCode::Char('?') {
            self.help_return = Some(self.screen);
            return UiAction::None;
        }
        match self.screen {
            Screen::Catalog => self.handle_catalog_key(key),
            Screen::Configure => self.handle_config_key(key),
            Screen::LiveRun => self.handle_live_key(key),
            Screen::Results => self.handle_results_key(key),
            Screen::Settings => self.handle_settings_key(key),
        }
    }

    /// Records one redacted engine lifecycle event.
    pub fn push_event(&mut self, event: RunEvent) {
        let line = match event {
            RunEvent::Planned { run_id, scanners } => {
                format!("{run_id}: planned {scanners} scanner(s)")
            }
            RunEvent::ScanStarted { scanner_id, .. } => format!("{scanner_id}: running"),
            RunEvent::ScanFinished {
                scanner_id,
                status,
                duration_ms,
                ..
            } => format!("{scanner_id}: {status:?} in {duration_ms} ms"),
            RunEvent::Completed { run_id, status } => format!("{run_id}: {status:?}"),
        };
        self.events.push(line);
        if self.events.len() > 200 {
            self.events.remove(0);
        }
    }

    /// Installs a completed report and moves to results.
    pub fn set_report(&mut self, report: RunReport) {
        self.report = Some(report);
        self.screen = Screen::Results;
        self.cancellation = CancellationState::Idle;
    }

    fn handle_catalog_key(&mut self, key: KeyEvent) -> UiAction {
        if self.input_mode == InputMode::Search {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => self.input_mode = InputMode::Navigate,
                KeyCode::Backspace => {
                    self.query.pop();
                    self.refilter();
                }
                KeyCode::Char(value)
                    if !key.modifiers.contains(KeyModifiers::CONTROL)
                        && !key.modifiers.contains(KeyModifiers::ALT) =>
                {
                    self.query.push(value);
                    self.refilter();
                }
                _ => {}
            }
            return UiAction::None;
        }
        match key.code {
            KeyCode::Char('q') => UiAction::Quit,
            KeyCode::Char('/') => {
                self.input_mode = InputMode::Search;
                UiAction::None
            }
            KeyCode::Char('s') => {
                self.screen = Screen::Settings;
                UiAction::None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_selection(1);
                UiAction::None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_selection(-1);
                UiAction::None
            }
            KeyCode::Enter if self.selected_descriptor().is_some() => {
                self.target_input.clear();
                self.target_kind_index = 0;
                self.authorization = Authorization::NotGranted;
                self.validation = None;
                self.screen = Screen::Configure;
                UiAction::None
            }
            _ => UiAction::None,
        }
    }

    fn handle_config_key(&mut self, key: KeyEvent) -> UiAction {
        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::Catalog;
                UiAction::None
            }
            KeyCode::Tab => {
                if let Some(descriptor) = self.selected_descriptor() {
                    self.target_kind_index =
                        (self.target_kind_index + 1) % descriptor.target_kinds.len();
                }
                self.validation = None;
                UiAction::None
            }
            KeyCode::Char(' ') => {
                self.authorization = match self.authorization {
                    Authorization::NotGranted => Authorization::Granted,
                    Authorization::Granted => Authorization::NotGranted,
                };
                UiAction::None
            }
            KeyCode::Backspace => {
                self.target_input.pop();
                self.validation = None;
                UiAction::None
            }
            KeyCode::Enter => self.prepare_request(),
            KeyCode::Char(value)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT) =>
            {
                self.target_input.push(value);
                self.validation = None;
                UiAction::None
            }
            _ => UiAction::None,
        }
    }

    fn handle_live_key(&mut self, key: KeyEvent) -> UiAction {
        match key.code {
            KeyCode::Char('c') if self.cancellation == CancellationState::Idle => {
                self.cancellation = CancellationState::Requested;
                UiAction::Cancel
            }
            KeyCode::Char('q') => UiAction::Quit,
            _ => UiAction::None,
        }
    }

    fn handle_results_key(&mut self, key: KeyEvent) -> UiAction {
        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::Catalog;
                UiAction::None
            }
            KeyCode::Left | KeyCode::BackTab => {
                self.result_tab = self.result_tab.saturating_sub(1);
                UiAction::None
            }
            KeyCode::Right | KeyCode::Tab => {
                self.result_tab = (self.result_tab + 1).min(2);
                UiAction::None
            }
            KeyCode::Char('q') => UiAction::Quit,
            _ => UiAction::None,
        }
    }

    fn handle_settings_key(&mut self, key: KeyEvent) -> UiAction {
        match key.code {
            KeyCode::Esc => self.screen = Screen::Catalog,
            KeyCode::Char('1') => self.settings.toggle(Preference::Compatibility),
            KeyCode::Char('2') => self.settings.toggle(Preference::Color),
            KeyCode::Char('3') => self.settings.toggle(Preference::Ascii),
            KeyCode::Char('4') => self.settings.toggle(Preference::ReducedMotion),
            _ => {}
        }
        UiAction::None
    }

    fn prepare_request(&mut self) -> UiAction {
        let Some(descriptor) = self.selected_descriptor().cloned() else {
            self.validation = Some("No scanner is selected".into());
            return UiAction::None;
        };
        let kind = descriptor.target_kinds[self.target_kind_index];
        let target = match Target::parse(kind, &self.target_input) {
            Ok(target) => target,
            Err(error) => {
                self.validation = Some(error.to_string());
                return UiAction::None;
            }
        };
        let requires_active = descriptor
            .capabilities
            .iter()
            .copied()
            .any(Capability::requires_authorization);
        if requires_active && self.authorization != Authorization::Granted {
            self.validation = Some("Explicit active authorization is required".into());
            return UiAction::None;
        }
        let options = match resolve_options(&descriptor.options, &BTreeMap::new()) {
            Ok(options) => options,
            Err(error) => {
                self.validation = Some(error.to_string());
                return UiAction::None;
            }
        };
        let request = ScanRequest {
            scanner_id: descriptor.id,
            scope: ScopeGrant::exact(
                &target,
                self.authorization == Authorization::Granted,
                OffsetDateTime::now_utc(),
            ),
            target,
            options,
            budget: Budget::default(),
        };
        self.events.clear();
        self.report = None;
        self.screen = Screen::LiveRun;
        UiAction::Start(Box::new(request))
    }

    fn selected_descriptor(&self) -> Option<&ScannerDescriptor> {
        self.filtered
            .get(self.selected)
            .and_then(|index| self.catalog.get(*index))
    }

    fn refilter(&mut self) {
        let query = self.query.to_ascii_lowercase();
        self.filtered = self
            .catalog
            .iter()
            .enumerate()
            .filter(|(_, descriptor)| {
                query.is_empty()
                    || descriptor.id.as_str().contains(&query)
                    || descriptor.name.to_ascii_lowercase().contains(&query)
                    || descriptor.track.to_ascii_lowercase().contains(&query)
            })
            .map(|(index, _)| index)
            .collect();
        self.selected = 0;
        self.list_state
            .select((!self.filtered.is_empty()).then_some(0));
    }

    fn move_selection(&mut self, delta: isize) {
        if self.filtered.is_empty() {
            return;
        }
        let len = self.filtered.len();
        self.selected = if delta < 0 {
            self.selected.checked_sub(1).unwrap_or(len - 1)
        } else {
            (self.selected + 1) % len
        };
        self.list_state.select(Some(self.selected));
    }
}

/// Runs the full-screen controller until the operator exits.
///
/// # Errors
///
/// Returns a terminal, engine, persistence, or background-task error when the
/// interactive controller cannot safely continue.
pub async fn run(services: TuiServices) -> Result<(), TuiError> {
    let mut terminal = ratatui::init();
    let result = run_loop(&mut terminal, services).await;
    ratatui::restore();
    result
}

async fn run_loop(
    terminal: &mut ratatui::DefaultTerminal,
    services: TuiServices,
) -> Result<(), TuiError> {
    let mut app = App::new(&services.catalog);
    let mut task: Option<JoinHandle<Result<RunReport, sugra_core::EngineError>>> = None;
    let mut cancellation = CancellationToken::new();
    let mut receiver: Option<broadcast::Receiver<RunEvent>> = None;

    loop {
        terminal.draw(|frame| render(frame, &mut app))?;
        if let Some(events) = receiver.as_mut() {
            loop {
                match events.try_recv() {
                    Ok(event) => app.push_event(event),
                    Err(
                        broadcast::error::TryRecvError::Empty
                        | broadcast::error::TryRecvError::Closed,
                    ) => break,
                    Err(broadcast::error::TryRecvError::Lagged(count)) => {
                        app.events
                            .push(format!("{count} progress event(s) omitted"));
                    }
                }
            }
        }
        if task.as_ref().is_some_and(JoinHandle::is_finished) {
            let finished = task.take();
            if let Some(handle) = finished {
                let report = handle
                    .await
                    .map_err(|error| TuiError::Join(error.to_string()))??;
                services.store.persist(&report).await?;
                app.set_report(report);
                receiver = None;
            }
        }
        if event::poll(Duration::from_millis(80))? {
            let Event::Key(key) = event::read()? else {
                continue;
            };
            match app.handle_key(key) {
                UiAction::None => {}
                UiAction::Quit => {
                    cancellation.cancel();
                    return Ok(());
                }
                UiAction::Cancel => cancellation.cancel(),
                UiAction::Start(request) => {
                    cancellation = CancellationToken::new();
                    let (sender, events) = broadcast::channel(128);
                    receiver = Some(events);
                    let engine = Arc::clone(&services.engine);
                    let token = cancellation.clone();
                    task = Some(tokio::spawn(async move {
                        engine.execute(vec![*request], token, Some(sender)).await
                    }));
                }
            }
        }
    }
}

/// Renders one frame; exposed for deterministic terminal-backend tests.
pub fn render(frame: &mut Frame<'_>, app: &mut App) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        let message = Paragraph::new(vec![
            Line::from(Span::styled(
                "Terminal too small",
                Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(format!("Minimum: {MIN_WIDTH}x{MIN_HEIGHT}")),
            Line::from("? help  q quit"),
        ])
        .alignment(Alignment::Center)
        .block(Block::bordered().title(" Sugra "));
        frame.render_widget(message, area);
        return;
    }

    let [header, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(3),
    ])
    .areas(area);
    render_header(frame, header, app);
    match app.screen {
        Screen::Catalog => render_catalog(frame, body, app),
        Screen::Configure => render_config(frame, body, app),
        Screen::LiveRun => render_live(frame, body, app),
        Screen::Results => render_results(frame, body, app),
        Screen::Settings => render_settings(frame, body, app),
    }
    render_footer(frame, footer, app);
    if app.help_return.is_some() {
        render_help(frame, area);
    }
}

fn render_header(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let title = match app.screen {
        Screen::Catalog => "Catalog",
        Screen::Configure => "Configure",
        Screen::LiveRun => "Live run",
        Screen::Results => "Results",
        Screen::Settings => "Settings",
    };
    let status = app
        .report
        .as_ref()
        .map_or_else(|| "ready".into(), |report| format!("{:?}", report.status()));
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " SUGRA ",
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!("  {title}")),
            Span::styled(
                format!("  {status} "),
                Style::default().fg(Color::LightCyan),
            ),
        ]))
        .block(Block::bordered()),
        area,
    );
}

fn render_catalog(frame: &mut Frame<'_>, area: Rect, app: &mut App) {
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).areas(area);
    let search = if app.input_mode == InputMode::Search {
        "Search (editing)"
    } else {
        "Search"
    };
    let items = app
        .filtered
        .iter()
        .filter_map(|index| app.catalog.get(*index))
        .map(|descriptor| {
            let active = descriptor
                .capabilities
                .iter()
                .copied()
                .any(Capability::requires_authorization);
            ListItem::new(format!(
                "{:>4}  {:<30} {:<18} {}",
                descriptor
                    .legacy_id
                    .map_or_else(|| "—".into(), |id| id.to_string()),
                descriptor.name,
                descriptor.track,
                if active { "active" } else { "passive" }
            ))
        });
    let list = List::new(items)
        .block(Block::bordered().title(format!(
            " {search}: {}  [{} matches] ",
            app.query,
            app.filtered.len()
        )))
        .highlight_symbol("› ")
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_stateful_widget(list, list_area, &mut app.list_state);

    let details = app.selected_descriptor().map_or_else(
        || vec![Line::from("No scanner matches the current filter.")],
        |descriptor| {
            vec![
                Line::from(Span::styled(
                    &descriptor.name,
                    Style::default().add_modifier(Modifier::BOLD),
                )),
                Line::from(format!("ID: {}", descriptor.id)),
                Line::from(format!("Track: {}", descriptor.track)),
                Line::from(format!(
                    "Targets: {}",
                    descriptor
                        .target_kinds
                        .iter()
                        .map(|kind| kind.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
                Line::from(format!("Capabilities: {:?}", descriptor.capabilities)),
                Line::from(""),
                Line::from(descriptor.description.as_str()),
            ]
        },
    );
    frame.render_widget(
        Paragraph::new(details)
            .wrap(Wrap { trim: true })
            .block(Block::bordered().title(" Scanner details ")),
        detail_area,
    );
}

fn render_config(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let Some(descriptor) = app.selected_descriptor() else {
        frame.render_widget(
            Paragraph::new("No scanner selected").block(Block::bordered()),
            area,
        );
        return;
    };
    let kind = descriptor.target_kinds[app.target_kind_index];
    let requires_active = descriptor
        .capabilities
        .iter()
        .copied()
        .any(Capability::requires_authorization);
    let authorization = if requires_active {
        if app.authorization == Authorization::Granted {
            "[x] granted"
        } else {
            "[ ] required"
        }
    } else {
        "not required"
    };
    let lines = vec![
        Line::from(Span::styled(
            &descriptor.name,
            Style::default()
                .fg(Color::LightCyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(format!("Target type: {}  (Tab changes)", kind.as_str())),
        Line::from(format!("Target: {}", app.target_input)),
        Line::from("Scope: derived from validated target"),
        Line::from(format!("Capabilities: {:?}", descriptor.capabilities)),
        Line::from(format!("Authorization: {authorization}  (Space toggles)")),
        Line::from(""),
        Line::from(
            app.validation
                .as_deref()
                .unwrap_or("Enter starts when the plan is valid."),
        ),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: true })
            .block(Block::bordered().title(" Module configuration ")),
        area,
    );
}

fn render_live(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let [progress, events] =
        Layout::vertical([Constraint::Length(5), Constraint::Min(1)]).areas(area);
    let latest = app
        .events
        .last()
        .map_or("Waiting for the execution plan", String::as_str);
    let gauge = Gauge::default()
        .block(Block::bordered().title(" Bounded execution "))
        .gauge_style(Style::default().fg(Color::Cyan))
        .ratio(if app.events.is_empty() { 0.05 } else { 0.55 })
        .label(latest);
    frame.render_widget(gauge, progress);
    let lines: Vec<_> = app
        .events
        .iter()
        .rev()
        .take(100)
        .rev()
        .map(|line| Line::from(line.as_str()))
        .collect();
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(" Redacted event log ")),
        events,
    );
}

fn render_results(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let [tabs_area, body] =
        Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).areas(area);
    let tabs = Tabs::new(["Findings", "Evidence", "Diagnostics"])
        .select(app.result_tab)
        .block(Block::bordered())
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, tabs_area);
    let Some(report) = &app.report else {
        frame.render_widget(
            Paragraph::new("No completed report").block(Block::bordered()),
            body,
        );
        return;
    };
    let mut lines = vec![Line::from(format!(
        "Run {} — {:?} — {} execution(s)",
        report.run_id,
        report.status(),
        report.executions.len()
    ))];
    for execution in &report.executions {
        lines.push(Line::from(format!(
            "{}  {:?}  {} ms",
            execution.scanner_id, execution.result.status, execution.duration_ms
        )));
        match app.result_tab {
            0 => {
                lines.extend(execution.result.findings.iter().map(|finding| {
                    Line::from(format!("  {:?}  {}", finding.severity, finding.title))
                }));
            }
            1 => {
                lines.extend(execution.result.evidence.iter().map(|evidence| {
                    Line::from(format!("  {}  {}", evidence.kind, evidence.source))
                }));
            }
            _ => lines.extend(execution.result.diagnostics.iter().map(|diagnostic| {
                Line::from(format!("  {}  {}", diagnostic.kind, diagnostic.message))
            })),
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(" Run report ")),
        body,
    );
}

fn render_settings(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let value = |enabled| if enabled { "on" } else { "off" };
    let lines = vec![
        Line::from("1  Compatibility selectors"),
        Line::from(format!(
            "   {}",
            value(app.settings.is_enabled(Preference::Compatibility))
        )),
        Line::from("2  Color"),
        Line::from(format!(
            "   {}",
            value(app.settings.is_enabled(Preference::Color))
        )),
        Line::from("3  ASCII borders"),
        Line::from(format!(
            "   {}",
            value(app.settings.is_enabled(Preference::Ascii))
        )),
        Line::from("4  Reduced motion"),
        Line::from(format!(
            "   {}",
            value(app.settings.is_enabled(Preference::ReducedMotion))
        )),
        Line::from(""),
        Line::from("Provider secrets: shown only as configured or missing."),
        Line::from("Output directory: controlled by the CLI and traversal-checked."),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title(" Compatibility and presentation settings ")),
        area,
    );
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let keys = match app.screen {
        Screen::Catalog => "/ search   ↑↓ select   Enter configure   s settings   ? help   q quit",
        Screen::Configure => {
            "type target   Tab target type   Space authorize   Enter run   Esc back"
        }
        Screen::LiveRun => "c cancel   ? help   q quit",
        Screen::Results => "Tab/Shift-Tab sections   Esc catalog   ? help   q quit",
        Screen::Settings => "1-4 toggle   Esc catalog   ? help",
    };
    frame.render_widget(
        Paragraph::new(keys)
            .alignment(Alignment::Center)
            .block(Block::bordered().title(" Keys ")),
        area,
    );
}

fn render_help(frame: &mut Frame<'_>, area: Rect) {
    let popup = centered_rect(68, 72, area);
    frame.render_widget(Clear, popup);
    let help = Paragraph::new(vec![
        Line::from(Span::styled(
            "Context actions",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("↑/↓ or j/k  Move selection"),
        Line::from("Enter         Configure or activate"),
        Line::from("Tab           Change field or result section"),
        Line::from("Esc           Return or close"),
        Line::from(""),
        Line::from(Span::styled(
            "Global",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from("?             Toggle this help"),
        Line::from("q             Quit outside text input"),
        Line::from(""),
        Line::from("Every active scan requires an explicit authorization decision."),
    ])
    .wrap(Wrap { trim: true })
    .block(Block::bordered().title(" Help and shortcuts "));
    frame.render_widget(help, popup);
}

fn centered_rect(width_percent: u16, height_percent: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - height_percent) / 2),
            Constraint::Percentage(height_percent),
            Constraint::Percentage((100 - height_percent) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - width_percent) / 2),
            Constraint::Percentage(width_percent),
            Constraint::Percentage((100 - width_percent) / 2),
        ])
        .split(vertical[1])[1]
}

/// Default report directory used by interactive mode.
#[must_use]
pub fn default_output_directory() -> PathBuf {
    PathBuf::from("sugra-runs")
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use sugra_domain::{LegacyId, ScannerId, TargetKind};

    use super::*;

    fn fixture_catalog() -> Result<Catalog, Box<dyn std::error::Error>> {
        Catalog::new(vec![ScannerDescriptor {
            id: ScannerId::new("dns-records")?,
            legacy_id: Some(LegacyId::Catalog(3)),
            name: "DNS Records".into(),
            description: "Collect public DNS records.".into(),
            track: "dns".into(),
            target_kinds: vec![TargetKind::Domain],
            capabilities: vec![Capability::PassiveNetwork],
            options: Vec::new(),
            version: "1".into(),
        }])
        .map_err(Into::into)
    }

    fn screen_text(
        app: &mut App,
        width: u16,
        height: u16,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend)?;
        terminal.draw(|frame| render(frame, app))?;
        let text = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>();
        Ok(text)
    }

    #[test]
    fn catalog_snapshot_contains_navigation_and_scanner() -> Result<(), Box<dyn std::error::Error>>
    {
        let catalog = fixture_catalog()?;
        let mut app = App::new(&catalog);
        let text = screen_text(&mut app, 100, 32)?;
        assert!(text.contains("SUGRA"));
        assert!(text.contains("DNS Records"));
        assert!(text.contains("Scanner details"));
        assert!(text.contains("Enter configure"));
        Ok(())
    }

    #[test]
    fn small_terminal_has_safe_fallback() -> Result<(), Box<dyn std::error::Error>> {
        let catalog = fixture_catalog()?;
        let mut app = App::new(&catalog);
        let text = screen_text(&mut app, 60, 18)?;
        assert!(text.contains("Terminal too small"));
        assert!(text.contains("q quit"));
        Ok(())
    }

    #[test]
    fn active_configuration_requires_authorization() -> Result<(), Box<dyn std::error::Error>> {
        let descriptor = ScannerDescriptor {
            id: ScannerId::new("web-probe")?,
            legacy_id: None,
            name: "Web Probe".into(),
            description: "Observe a scoped web endpoint.".into(),
            track: "web".into(),
            target_kinds: vec![TargetKind::Domain],
            capabilities: vec![Capability::ActiveHttpSafe],
            options: Vec::new(),
            version: "1".into(),
        };
        let catalog = Catalog::new(vec![descriptor])?;
        let mut app = App::new(&catalog);
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            UiAction::None
        );
        for value in "example.com".chars() {
            let _ = app.handle_key(KeyEvent::new(KeyCode::Char(value), KeyModifiers::NONE));
        }
        assert_eq!(
            app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            UiAction::None
        );
        assert!(
            app.validation
                .as_deref()
                .is_some_and(|message| message.contains("authorization"))
        );
        let _ = app.handle_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
        assert!(matches!(
            app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            UiAction::Start(_)
        ));
        Ok(())
    }

    #[test]
    fn results_distinguish_empty_success_from_failure() -> Result<(), Box<dyn std::error::Error>> {
        let catalog = fixture_catalog()?;
        let mut app = App::new(&catalog);
        app.set_report(RunReport {
            schema_version: 1,
            run_id: sugra_domain::RunId::new(),
            app_version: "test".into(),
            started_at: OffsetDateTime::UNIX_EPOCH,
            finished_at: OffsetDateTime::UNIX_EPOCH,
            executions: vec![sugra_domain::ScanExecution {
                scanner_id: ScannerId::new("dns-records")?,
                result: sugra_domain::ScanResult::completed(Vec::new(), Vec::new()),
                duration_ms: 1,
            }],
        });
        let text = screen_text(&mut app, 100, 32)?;
        assert!(text.contains("Completed"));
        assert!(!text.contains("0 execution"));
        Ok(())
    }
}
