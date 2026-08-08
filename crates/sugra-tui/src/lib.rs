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
use ratatui::symbols::border;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Clear, Gauge, List, ListItem, ListState, Paragraph, Tabs, Wrap,
};
use sugra_core::{Catalog, Engine, RunEvent, RunStore, resolve_options};
use sugra_domain::{
    Budget, Capability, Evidence, Finding, OptionKind, RunReport, ScanExecution, ScanRequest,
    ScannerDescriptor, ScopeGrant, Target,
};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

const MIN_WIDTH: u16 = 72;
const MIN_HEIGHT: u16 = 22;
const MAX_INPUT_CHARS: usize = 2_048;
const ASCII_BORDER: border::Set = border::Set {
    top_left: "+",
    top_right: "+",
    bottom_left: "+",
    bottom_right: "+",
    vertical_left: "|",
    vertical_right: "|",
    horizontal_top: "-",
    horizontal_bottom: "-",
};

/// Screen currently owned by the main viewport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// At-a-glance scanner and session summary.
    Dashboard,
    /// Searchable scanner catalog.
    Catalog,
    /// Target, option, scope, and authorization form.
    Configure,
    /// Observable run progress.
    LiveRun,
    /// Findings, evidence, and diagnostics.
    Results,
    /// Reports completed during this terminal session.
    History,
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
    option_inputs: BTreeMap<String, String>,
    config_focus: usize,
    timeout_input: String,
    max_requests_input: String,
    validation: Option<String>,
    events: Vec<String>,
    planned_scanners: usize,
    finished_scanners: usize,
    report: Option<RunReport>,
    result_tab: usize,
    result_selection: usize,
    history: Vec<RunReport>,
    history_selection: usize,
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

impl Preferences {
    fn new(color: bool) -> Self {
        let mut enabled: std::collections::BTreeSet<_> =
            [Preference::Compatibility].into_iter().collect();
        if color {
            enabled.insert(Preference::Color);
        }
        Self { enabled }
    }

    fn toggle(&mut self, preference: Preference) {
        if !self.enabled.remove(&preference) {
            self.enabled.insert(preference);
        }
    }

    fn is_enabled(&self, preference: Preference) -> bool {
        self.enabled.contains(&preference)
    }
}

#[derive(Clone, Copy)]
struct Theme {
    color: bool,
    ascii: bool,
}

impl Theme {
    fn accent(self) -> Style {
        self.style(Color::Cyan).add_modifier(Modifier::BOLD)
    }

    fn secondary(self) -> Style {
        self.style(Color::LightMagenta).add_modifier(Modifier::BOLD)
    }

    fn muted(self) -> Style {
        self.style(Color::DarkGray)
    }

    fn danger(self) -> Style {
        self.style(Color::LightRed).add_modifier(Modifier::BOLD)
    }

    const fn style(self, color: Color) -> Style {
        if self.color {
            Style::new().fg(color)
        } else {
            Style::new()
        }
    }

    fn panel<'a>(self, title: impl Into<Line<'a>>) -> Block<'a> {
        let block = Block::bordered()
            .title(title)
            .border_style(self.style(Color::DarkGray));
        if self.ascii {
            block.border_set(ASCII_BORDER)
        } else {
            block.border_type(BorderType::Rounded)
        }
    }

    const fn marker(self) -> &'static str {
        if self.ascii { "> " } else { "› " }
    }
}

impl App {
    /// Builds deterministic catalog state and honors the `NO_COLOR` convention.
    #[must_use]
    pub fn new(catalog: &Catalog) -> Self {
        Self::with_color(catalog, std::env::var_os("NO_COLOR").is_none())
    }

    /// Builds state with an explicit color policy, useful for embedded frontends and tests.
    #[must_use]
    pub fn with_color(catalog: &Catalog, color: bool) -> Self {
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
            screen: Screen::Dashboard,
            help_return: None,
            query: String::new(),
            input_mode: InputMode::Navigate,
            target_input: String::new(),
            target_kind_index: 0,
            authorization: Authorization::NotGranted,
            option_inputs: BTreeMap::new(),
            config_focus: 0,
            timeout_input: Budget::DEFAULT.timeout_ms.to_string(),
            max_requests_input: Budget::DEFAULT.max_requests.to_string(),
            validation: None,
            events: Vec::new(),
            planned_scanners: 0,
            finished_scanners: 0,
            report: None,
            result_tab: 0,
            result_selection: 0,
            history: Vec::new(),
            history_selection: 0,
            settings: Preferences::new(color),
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
            Screen::Dashboard => self.handle_dashboard_key(key),
            Screen::Catalog => self.handle_catalog_key(key),
            Screen::Configure => self.handle_config_key(key),
            Screen::LiveRun => self.handle_live_key(key),
            Screen::Results => self.handle_results_key(key),
            Screen::History => self.handle_history_key(key),
            Screen::Settings => self.handle_settings_key(key),
        }
    }

    /// Records one redacted engine lifecycle event.
    pub fn push_event(&mut self, event: RunEvent) {
        let line = match event {
            RunEvent::Planned { run_id, scanners } => {
                self.planned_scanners = scanners;
                format!("[PLAN] {run_id} | {scanners} scanner(s)")
            }
            RunEvent::ScanStarted { scanner_id, .. } => {
                format!("[START] {scanner_id} | running")
            }
            RunEvent::ScanFinished {
                scanner_id,
                status,
                duration_ms,
                ..
            } => {
                self.finished_scanners = self.finished_scanners.saturating_add(1);
                format!("[DONE] {scanner_id} | {status:?} | {duration_ms} ms")
            }
            RunEvent::Completed { run_id, status } => {
                format!("[RUN] {run_id} | {status:?}")
            }
        };
        self.events.push(line);
        if self.events.len() > 200 {
            self.events.remove(0);
        }
    }

    /// Installs a completed report, adds it to session history, and moves to results.
    pub fn set_report(&mut self, report: RunReport) {
        self.history.push(report.clone());
        self.history_selection = self.history.len().saturating_sub(1);
        self.report = Some(report);
        self.result_tab = 0;
        self.result_selection = 0;
        self.screen = Screen::Results;
        self.cancellation = CancellationState::Idle;
    }

    fn theme(&self) -> Theme {
        Theme {
            color: self.settings.is_enabled(Preference::Color),
            ascii: self.settings.is_enabled(Preference::Ascii),
        }
    }

    fn handle_dashboard_key(&mut self, key: KeyEvent) -> UiAction {
        match key.code {
            KeyCode::Enter | KeyCode::Char('c' | 'n') => self.screen = Screen::Catalog,
            KeyCode::Char('h') => self.screen = Screen::History,
            KeyCode::Char('s') => self.screen = Screen::Settings,
            KeyCode::Char('q') => return UiAction::Quit,
            _ => {}
        }
        UiAction::None
    }

    fn handle_catalog_key(&mut self, key: KeyEvent) -> UiAction {
        if self.input_mode == InputMode::Search {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => self.input_mode = InputMode::Navigate,
                KeyCode::Backspace => {
                    self.query.pop();
                    self.refilter();
                }
                KeyCode::Char(value) if safe_text_key(key) && self.query.len() < 128 => {
                    self.query.push(value);
                    self.refilter();
                }
                _ => {}
            }
            return UiAction::None;
        }
        match key.code {
            KeyCode::Char('q') => UiAction::Quit,
            KeyCode::Esc | KeyCode::Char('d') => {
                self.screen = Screen::Dashboard;
                UiAction::None
            }
            KeyCode::Char('/') => {
                self.input_mode = InputMode::Search;
                UiAction::None
            }
            KeyCode::Char('s') => {
                self.screen = Screen::Settings;
                UiAction::None
            }
            KeyCode::Char('h') => {
                self.screen = Screen::History;
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
            KeyCode::Home => {
                self.select_catalog(0);
                UiAction::None
            }
            KeyCode::End => {
                self.select_catalog(self.filtered.len().saturating_sub(1));
                UiAction::None
            }
            KeyCode::Enter if self.selected_descriptor().is_some() => {
                self.reset_configuration();
                self.screen = Screen::Configure;
                UiAction::None
            }
            _ => UiAction::None,
        }
    }

    fn handle_config_key(&mut self, key: KeyEvent) -> UiAction {
        let field_count = self.config_field_count();
        match key.code {
            KeyCode::Esc => {
                self.screen = Screen::Catalog;
                UiAction::None
            }
            KeyCode::Tab | KeyCode::Down => {
                self.config_focus = (self.config_focus + 1) % field_count;
                self.validation = None;
                UiAction::None
            }
            KeyCode::BackTab | KeyCode::Up => {
                self.config_focus = self.config_focus.checked_sub(1).unwrap_or(field_count - 1);
                self.validation = None;
                UiAction::None
            }
            KeyCode::Left => {
                self.adjust_config_choice(-1);
                UiAction::None
            }
            KeyCode::Right | KeyCode::Char(' ') if self.focus_is_choice() => {
                self.adjust_config_choice(1);
                UiAction::None
            }
            KeyCode::Enter if self.config_focus == field_count - 1 => self.prepare_request(),
            KeyCode::Enter => {
                self.config_focus = (self.config_focus + 1) % field_count;
                UiAction::None
            }
            KeyCode::F(5) => self.prepare_request(),
            KeyCode::Backspace => {
                self.edit_current_input(None);
                UiAction::None
            }
            KeyCode::Char(value) if safe_text_key(key) => {
                self.edit_current_input(Some(value));
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
            KeyCode::Esc | KeyCode::Char('d') => self.screen = Screen::Dashboard,
            KeyCode::Char('h') => self.screen = Screen::History,
            KeyCode::Left | KeyCode::BackTab => {
                self.result_tab = self.result_tab.checked_sub(1).unwrap_or(2);
                self.result_selection = 0;
            }
            KeyCode::Right | KeyCode::Tab => {
                self.result_tab = (self.result_tab + 1) % 3;
                self.result_selection = 0;
            }
            KeyCode::Char('1'..='3') => {
                if let KeyCode::Char(section) = key.code {
                    self.result_tab = usize::from(section as u8 - b'1');
                    self.result_selection = 0;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_result_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_result_selection(-1),
            KeyCode::Char('q') => return UiAction::Quit,
            _ => {}
        }
        UiAction::None
    }

    fn handle_history_key(&mut self, key: KeyEvent) -> UiAction {
        match key.code {
            KeyCode::Esc | KeyCode::Char('d') => self.screen = Screen::Dashboard,
            KeyCode::Down | KeyCode::Char('j') => self.move_history_selection(-1),
            KeyCode::Up | KeyCode::Char('k') => self.move_history_selection(1),
            KeyCode::Enter => {
                if let Some(report) = self.history.get(self.history_selection).cloned() {
                    self.report = Some(report);
                    self.result_tab = 0;
                    self.result_selection = 0;
                    self.screen = Screen::Results;
                }
            }
            KeyCode::Char('q') => return UiAction::Quit,
            _ => {}
        }
        UiAction::None
    }

    fn handle_settings_key(&mut self, key: KeyEvent) -> UiAction {
        match key.code {
            KeyCode::Esc | KeyCode::Char('d') => self.screen = Screen::Dashboard,
            KeyCode::Char('1') => self.settings.toggle(Preference::Compatibility),
            KeyCode::Char('2') if std::env::var_os("NO_COLOR").is_none() => {
                self.settings.toggle(Preference::Color);
            }
            KeyCode::Char('3') => self.settings.toggle(Preference::Ascii),
            KeyCode::Char('4') => self.settings.toggle(Preference::ReducedMotion),
            _ => {}
        }
        UiAction::None
    }

    fn reset_configuration(&mut self) {
        self.target_input.clear();
        self.target_kind_index = 0;
        self.authorization = Authorization::NotGranted;
        self.validation = None;
        self.config_focus = 0;
        self.timeout_input = Budget::DEFAULT.timeout_ms.to_string();
        self.max_requests_input = Budget::DEFAULT.max_requests.to_string();
        self.option_inputs = self
            .selected_descriptor()
            .map_or_else(BTreeMap::new, |descriptor| {
                descriptor
                    .options
                    .iter()
                    .filter_map(|option| {
                        option
                            .default
                            .as_ref()
                            .map(|value| (option.key.clone(), value.clone()))
                    })
                    .collect()
            });
    }

    fn config_field_count(&self) -> usize {
        self.selected_descriptor()
            .map_or(6, |descriptor| descriptor.options.len() + 6)
    }

    fn option_focus_index(&self) -> Option<usize> {
        let option_count = self.selected_descriptor()?.options.len();
        (self.config_focus >= 3 && self.config_focus < 3 + option_count)
            .then(|| self.config_focus - 3)
    }

    fn focus_is_choice(&self) -> bool {
        if self.config_focus <= 2 {
            return self.config_focus != 1;
        }
        self.option_focus_index()
            .and_then(|index| self.selected_descriptor()?.options.get(index))
            .is_some_and(|option| {
                matches!(option.kind, OptionKind::Boolean | OptionKind::Choice { .. })
            })
    }

    fn adjust_config_choice(&mut self, delta: isize) {
        if self.config_focus == 0 {
            if let Some(descriptor) = self.selected_descriptor() {
                self.target_kind_index =
                    wrapped_index(self.target_kind_index, descriptor.target_kinds.len(), delta);
            }
        } else if self.config_focus == 2 {
            if self.selected_requires_authorization() {
                self.authorization = match self.authorization {
                    Authorization::NotGranted => Authorization::Granted,
                    Authorization::Granted => Authorization::NotGranted,
                };
            }
        } else if let Some(index) = self.option_focus_index()
            && let Some(option) = self
                .selected_descriptor()
                .and_then(|descriptor| descriptor.options.get(index))
                .cloned()
        {
            let current = self.option_inputs.get(&option.key).map(String::as_str);
            let next = match &option.kind {
                OptionKind::Boolean => Some(
                    if current == Some("true") {
                        "false"
                    } else {
                        "true"
                    }
                    .into(),
                ),
                OptionKind::Choice { values } if !values.is_empty() => {
                    let current_index = current
                        .and_then(|value| values.iter().position(|candidate| candidate == value))
                        .unwrap_or(0);
                    Some(values[wrapped_index(current_index, values.len(), delta)].clone())
                }
                _ => None,
            };
            if let Some(next) = next {
                self.option_inputs.insert(option.key, next);
            }
        }
        self.validation = None;
    }

    fn edit_current_input(&mut self, value: Option<char>) {
        let option_key = self.option_focus_index().and_then(|index| {
            self.selected_descriptor()
                .and_then(|descriptor| descriptor.options.get(index))
                .filter(|option| {
                    !matches!(option.kind, OptionKind::Boolean | OptionKind::Choice { .. })
                })
                .map(|option| option.key.clone())
        });
        let option_count = self
            .selected_descriptor()
            .map_or(0, |descriptor| descriptor.options.len());
        let input = if self.config_focus == 1 {
            Some(&mut self.target_input)
        } else if self.config_focus == 3 + option_count {
            Some(&mut self.timeout_input)
        } else if self.config_focus == 4 + option_count {
            Some(&mut self.max_requests_input)
        } else if let Some(key) = option_key {
            Some(self.option_inputs.entry(key).or_default())
        } else {
            None
        };
        if let Some(input) = input {
            match value {
                Some(value) if input.chars().count() < MAX_INPUT_CHARS => input.push(value),
                None => {
                    input.pop();
                }
                _ => {}
            }
            self.validation = None;
        }
    }

    fn prepare_request(&mut self) -> UiAction {
        let Some(descriptor) = self.selected_descriptor().cloned() else {
            self.validation = Some("No scanner is selected".into());
            return UiAction::None;
        };
        let Some(kind) = descriptor.target_kinds.get(self.target_kind_index).copied() else {
            self.validation = Some("Scanner has no supported target type".into());
            return UiAction::None;
        };
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
        let options = match resolve_options(&descriptor.options, &self.option_inputs) {
            Ok(options) => options,
            Err(error) => {
                self.validation = Some(error.to_string());
                return UiAction::None;
            }
        };
        let budget = match self.parse_budget() {
            Ok(budget) => budget,
            Err(message) => {
                self.validation = Some(message);
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
            budget,
        };
        self.events.clear();
        self.planned_scanners = 0;
        self.finished_scanners = 0;
        self.report = None;
        self.screen = Screen::LiveRun;
        UiAction::Start(Box::new(request))
    }

    fn parse_budget(&self) -> Result<Budget, String> {
        let timeout_ms = self
            .timeout_input
            .parse::<u64>()
            .map_err(|_| "Timeout must be an integer in milliseconds".to_string())?;
        let max_requests = self
            .max_requests_input
            .parse::<usize>()
            .map_err(|_| "Request limit must be a positive integer".to_string())?;
        Budget {
            timeout_ms,
            max_requests,
            ..Budget::default()
        }
        .validate()
        .map_err(|error| error.to_string())
    }

    fn selected_requires_authorization(&self) -> bool {
        self.selected_descriptor().is_some_and(|descriptor| {
            descriptor
                .capabilities
                .iter()
                .copied()
                .any(Capability::requires_authorization)
        })
    }

    fn selected_descriptor(&self) -> Option<&ScannerDescriptor> {
        self.filtered
            .get(self.selected)
            .and_then(|index| self.catalog.get(*index))
    }

    fn refilter(&mut self) {
        let query = self.query.to_lowercase();
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
        self.select_catalog(0);
    }

    fn select_catalog(&mut self, index: usize) {
        if self.filtered.is_empty() {
            self.selected = 0;
            self.list_state.select(None);
        } else {
            self.selected = index.min(self.filtered.len() - 1);
            self.list_state.select(Some(self.selected));
        }
    }

    fn move_selection(&mut self, delta: isize) {
        if !self.filtered.is_empty() {
            self.select_catalog(wrapped_index(self.selected, self.filtered.len(), delta));
        }
    }

    fn result_item_count(&self) -> usize {
        self.report.as_ref().map_or(0, |report| {
            report
                .executions
                .iter()
                .map(|execution| match self.result_tab {
                    0 => execution.result.findings.len(),
                    1 => execution.result.evidence.len(),
                    _ => execution.result.diagnostics.len(),
                })
                .sum()
        })
    }

    fn move_result_selection(&mut self, delta: isize) {
        let count = self.result_item_count();
        if count > 0 {
            self.result_selection = wrapped_index(self.result_selection, count, delta);
        }
    }

    fn move_history_selection(&mut self, delta: isize) {
        if !self.history.is_empty() {
            self.history_selection =
                wrapped_index(self.history_selection, self.history.len(), delta);
        }
    }
}

fn safe_text_key(key: KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char(value) if !value.is_control())
        && !key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
}

fn wrapped_index(index: usize, len: usize, delta: isize) -> usize {
    if len == 0 {
        return 0;
    }
    if delta < 0 {
        index.checked_sub(1).unwrap_or(len - 1)
    } else {
        (index + 1) % len
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
                            .push(format!("[WARN] {count} progress event(s) omitted"));
                    }
                }
            }
        }
        if task.as_ref().is_some_and(JoinHandle::is_finished)
            && let Some(handle) = task.take()
        {
            let report = handle
                .await
                .map_err(|error| TuiError::Join(error.to_string()))??;
            services.store.persist(&report).await?;
            app.set_report(report);
            receiver = None;
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
    let theme = app.theme();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        render_small_terminal(frame, area, theme);
        return;
    }

    let [header, body, footer] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(1),
        Constraint::Length(3),
    ])
    .areas(area);
    render_header(frame, header, app, theme);
    match app.screen {
        Screen::Dashboard => render_dashboard(frame, body, app, theme),
        Screen::Catalog => render_catalog(frame, body, app, theme),
        Screen::Configure => render_config(frame, body, app, theme),
        Screen::LiveRun => render_live(frame, body, app, theme),
        Screen::Results => render_results(frame, body, app, theme),
        Screen::History => render_history(frame, body, app, theme),
        Screen::Settings => render_settings(frame, body, app, theme),
    }
    render_footer(frame, footer, app, theme);
    if app.help_return.is_some() {
        render_help(frame, area, app, theme);
    }
}

fn render_small_terminal(frame: &mut Frame<'_>, area: Rect, theme: Theme) {
    let message = Paragraph::new(vec![
        Line::from(Span::styled("[!] TERMINAL TOO SMALL", theme.danger())),
        Line::from(format!("Minimum: {MIN_WIDTH}x{MIN_HEIGHT}")),
        Line::from("Resize the terminal to continue safely."),
    ])
    .alignment(Alignment::Center)
    .block(theme.panel(" SUGRA "));
    frame.render_widget(message, area);
}

fn render_header(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let title = screen_title(app.screen);
    let status = app.report.as_ref().map_or_else(
        || "READY".into(),
        |report| format!("{:?}", report.status()).to_uppercase(),
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" SUGRA ", theme.accent().add_modifier(Modifier::REVERSED)),
            Span::styled(format!("  {title}"), theme.secondary()),
            Span::raw("  |  "),
            Span::styled(format!("[{status}]"), theme.accent()),
        ]))
        .block(theme.panel(" SECURITY OPERATIONS CONSOLE ")),
        area,
    );
}

const fn screen_title(screen: Screen) -> &'static str {
    match screen {
        Screen::Dashboard => "DASHBOARD",
        Screen::Catalog => "SCANNER CATALOG",
        Screen::Configure => "SCAN PLAN",
        Screen::LiveRun => "LIVE EXECUTION",
        Screen::Results => "REPORT",
        Screen::History => "SESSION HISTORY",
        Screen::Settings => "SETTINGS & DIAGNOSTICS",
    }
}

fn render_dashboard(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let [metrics, lower] =
        Layout::vertical([Constraint::Length(7), Constraint::Min(1)]).areas(area);
    let metric_areas = Layout::horizontal([
        Constraint::Ratio(1, 3),
        Constraint::Ratio(1, 3),
        Constraint::Ratio(1, 3),
    ])
    .split(metrics);
    let active = app
        .catalog
        .iter()
        .filter(|descriptor| {
            descriptor
                .capabilities
                .iter()
                .copied()
                .any(Capability::requires_authorization)
        })
        .count();
    render_metric(
        frame,
        metric_areas[0],
        "SCANNERS",
        app.catalog.len(),
        "available",
        theme,
    );
    render_metric(
        frame,
        metric_areas[1],
        "ACTIVE",
        active,
        "authorization required",
        theme,
    );
    render_metric(
        frame,
        metric_areas[2],
        "RUNS",
        app.history.len(),
        "this session",
        theme,
    );

    let [actions, posture] =
        Layout::horizontal([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)]).areas(lower);
    let action_lines = vec![
        Line::from(Span::styled(
            "[ENTER]  Open scanner catalog",
            theme.accent(),
        )),
        Line::from("[H]      Review session history"),
        Line::from("[S]      Settings and diagnostics"),
        Line::from("[?]      Help and safety guidance"),
    ];
    frame.render_widget(
        Paragraph::new(action_lines)
            .block(theme.panel(" QUICK ACTIONS "))
            .wrap(Wrap { trim: false }),
        actions,
    );
    let last_run = app.history.last().map_or_else(
        || "No scans completed in this session.".to_string(),
        |report| format!("Latest run: {} | {:?}", report.run_id, report.status()),
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled("SAFE DEFAULTS", theme.secondary())),
            Line::from("Targets are typed and scope-bound."),
            Line::from("Active capabilities require explicit consent."),
            Line::from("Event output is bounded and redacted."),
            Line::from(""),
            Line::from(last_run),
        ])
        .block(theme.panel(" OPERATIONAL POSTURE "))
        .wrap(Wrap { trim: true }),
        posture,
    );
}

fn render_metric(
    frame: &mut Frame<'_>,
    area: Rect,
    label: &str,
    value: usize,
    note: &str,
    theme: Theme,
) {
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled(value.to_string(), theme.accent())),
            Line::from(note),
        ])
        .alignment(Alignment::Center)
        .block(theme.panel(format!(" {label} "))),
        area,
    );
}

fn render_catalog(frame: &mut Frame<'_>, area: Rect, app: &mut App, theme: Theme) {
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(58), Constraint::Percentage(42)]).areas(area);
    let search_state = if app.input_mode == InputMode::Search {
        "EDITING"
    } else {
        "READY"
    };
    let compatibility = app.settings.is_enabled(Preference::Compatibility);
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
                "{:>4}  {:<25} {:<13} [{}]",
                if compatibility {
                    descriptor
                        .legacy_id
                        .map_or_else(|| "--".into(), |id| id.to_string())
                } else {
                    "--".into()
                },
                truncate(&descriptor.name, 25),
                truncate(&descriptor.track, 13),
                if active { "ACTIVE" } else { "PASSIVE" }
            ))
        });
    let list = List::new(items)
        .block(theme.panel(format!(
            " SEARCH [{search_state}]: {} | {} MATCHES ",
            app.query,
            app.filtered.len()
        )))
        .highlight_symbol(theme.marker())
        .highlight_style(theme.accent().add_modifier(Modifier::REVERSED));
    frame.render_stateful_widget(list, list_area, &mut app.list_state);

    let details = app.selected_descriptor().map_or_else(
        || vec![Line::from("[EMPTY] No scanner matches the current filter.")],
        |descriptor| {
            let mode = if descriptor
                .capabilities
                .iter()
                .copied()
                .any(Capability::requires_authorization)
            {
                "ACTIVE / CONSENT REQUIRED"
            } else {
                "PASSIVE"
            };
            vec![
                Line::from(Span::styled(&descriptor.name, theme.secondary())),
                Line::from(format!("ID       {}", descriptor.id)),
                Line::from(format!("TRACK    {}", descriptor.track)),
                Line::from(format!("MODE     {mode}")),
                Line::from(format!("VERSION  {}", descriptor.version)),
                Line::from(format!(
                    "TARGETS  {}",
                    descriptor
                        .target_kinds
                        .iter()
                        .map(|kind| kind.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )),
                Line::from(format!("OPTIONS  {}", descriptor.options.len())),
                Line::from(""),
                Line::from(descriptor.description.as_str()),
            ]
        },
    );
    frame.render_widget(
        Paragraph::new(details)
            .wrap(Wrap { trim: true })
            .block(theme.panel(" SCANNER PROFILE ")),
        detail_area,
    );
}

fn render_config(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let Some(descriptor) = app.selected_descriptor() else {
        frame.render_widget(
            Paragraph::new("[EMPTY] No scanner selected").block(theme.panel(" SCAN PLAN ")),
            area,
        );
        return;
    };
    let [form, review] =
        Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)]).areas(area);
    let lines = config_form_lines(descriptor, app, theme);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(theme.panel(format!(" {} ", descriptor.name.to_uppercase()))),
        form,
    );
    render_plan_review(frame, review, descriptor, app, theme);
}

fn config_form_lines<'a>(
    descriptor: &'a ScannerDescriptor,
    app: &'a App,
    theme: Theme,
) -> Vec<Line<'a>> {
    let mut lines = Vec::new();
    let kind = descriptor
        .target_kinds
        .get(app.target_kind_index)
        .map_or("unknown", |kind| kind.as_str());
    lines.push(form_line(0, app.config_focus, "Target type", kind, theme));
    lines.push(form_line(
        1,
        app.config_focus,
        "Target",
        &app.target_input,
        theme,
    ));
    let authorization = if app.selected_requires_authorization() {
        if app.authorization == Authorization::Granted {
            "[x] GRANTED"
        } else {
            "[ ] REQUIRED"
        }
    } else {
        "[-] NOT REQUIRED"
    };
    lines.push(form_line(
        2,
        app.config_focus,
        "Authorization",
        authorization,
        theme,
    ));
    for (index, option) in descriptor.options.iter().enumerate() {
        let raw = app
            .option_inputs
            .get(&option.key)
            .map_or("", String::as_str);
        let value = if matches!(option.kind, OptionKind::SecretRef) && !raw.is_empty() {
            "<environment reference set>"
        } else if raw.is_empty() {
            "<unset>"
        } else {
            raw
        };
        lines.push(form_line(
            3 + index,
            app.config_focus,
            &option.key,
            value,
            theme,
        ));
    }
    let option_count = descriptor.options.len();
    lines.push(form_line(
        3 + option_count,
        app.config_focus,
        "Timeout (ms)",
        &app.timeout_input,
        theme,
    ));
    lines.push(form_line(
        4 + option_count,
        app.config_focus,
        "Max requests",
        &app.max_requests_input,
        theme,
    ));
    lines.push(form_line(
        5 + option_count,
        app.config_focus,
        "Execute",
        "[ENTER] START SCAN",
        theme,
    ));
    lines
}

fn render_plan_review(
    frame: &mut Frame<'_>,
    area: Rect,
    descriptor: &ScannerDescriptor,
    app: &App,
    theme: Theme,
) {
    let validation = app
        .validation
        .as_deref()
        .unwrap_or("Plan is not executed until every field passes validation.");
    let validation_style = if app.validation.is_some() {
        theme.danger()
    } else {
        theme.muted()
    };
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled("SCOPE", theme.secondary())),
            Line::from("Exact target-derived boundary"),
            Line::from(""),
            Line::from(Span::styled("CAPABILITIES", theme.secondary())),
            Line::from(format!("{:?}", descriptor.capabilities)),
            Line::from(""),
            Line::from(Span::styled("VALIDATION", theme.secondary())),
            Line::from(Span::styled(validation, validation_style)),
            Line::from(""),
            Line::from("Tab/Shift-Tab: field"),
            Line::from("Left/Right: choices"),
            Line::from("F5: validate and run"),
        ])
        .wrap(Wrap { trim: true })
        .block(theme.panel(" PLAN REVIEW ")),
        area,
    );
}

fn form_line<'a>(
    index: usize,
    focus: usize,
    label: &str,
    value: &'a str,
    theme: Theme,
) -> Line<'a> {
    let marker = if index == focus { "[>]" } else { "[ ]" };
    Line::from(vec![
        Span::styled(
            format!("{marker} {label:<18}"),
            if index == focus {
                theme.accent()
            } else {
                Style::new()
            },
        ),
        Span::raw(value),
    ])
}

fn render_live(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let [progress, events] =
        Layout::vertical([Constraint::Length(6), Constraint::Min(1)]).areas(area);
    let percent = if app.planned_scanners == 0 {
        0
    } else {
        let value = app
            .finished_scanners
            .saturating_mul(100)
            .checked_div(app.planned_scanners)
            .unwrap_or(0)
            .min(100);
        u16::try_from(value).unwrap_or(100)
    };
    let state = if app.cancellation == CancellationState::Requested {
        "CANCEL REQUESTED"
    } else {
        "RUNNING"
    };
    let label = format!(
        "[{state}] {}/{} complete",
        app.finished_scanners, app.planned_scanners
    );
    let gauge = Gauge::default()
        .block(theme.panel(" BOUNDED EXECUTION "))
        .gauge_style(theme.accent())
        .percent(percent)
        .label(label);
    frame.render_widget(gauge, progress);
    let lines: Vec<_> = app
        .events
        .iter()
        .rev()
        .take(100)
        .rev()
        .map(|line| Line::from(line.as_str()))
        .collect();
    let lines = if lines.is_empty() {
        vec![Line::from("[WAIT] Awaiting execution plan...")]
    } else {
        lines
    };
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(theme.panel(" REDACTED EVENT STREAM ")),
        events,
    );
}

fn render_results(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let [summary, tabs_area, body] = Layout::vertical([
        Constraint::Length(4),
        Constraint::Length(3),
        Constraint::Min(1),
    ])
    .areas(area);
    let Some(report) = &app.report else {
        frame.render_widget(
            Paragraph::new("[EMPTY] No completed report").block(theme.panel(" REPORT ")),
            area,
        );
        return;
    };
    let counts = report.executions.iter().fold((0, 0, 0), |acc, execution| {
        (
            acc.0 + execution.result.findings.len(),
            acc.1 + execution.result.evidence.len(),
            acc.2 + execution.result.diagnostics.len(),
        )
    });
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!("[{:?}]", report.status()).to_uppercase(),
                theme.secondary(),
            ),
            Span::raw(format!(
                "  Run {}  |  {} execution(s)  |  {} findings  |  {} evidence  |  {} diagnostics",
                report.run_id,
                report.executions.len(),
                counts.0,
                counts.1,
                counts.2
            )),
        ]))
        .block(theme.panel(" RUN SUMMARY ")),
        summary,
    );
    let tabs = Tabs::new(["[1] Findings", "[2] Evidence", "[3] Diagnostics"])
        .select(app.result_tab)
        .block(theme.panel(" REPORT SECTIONS "))
        .highlight_style(theme.accent().add_modifier(Modifier::REVERSED))
        .divider(" | ");
    frame.render_widget(tabs, tabs_area);
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(52), Constraint::Percentage(48)]).areas(body);
    render_result_list(frame, list_area, report, app, theme);
    render_result_detail(frame, detail_area, report, app, theme);
}

fn render_result_list(
    frame: &mut Frame<'_>,
    area: Rect,
    report: &RunReport,
    app: &App,
    theme: Theme,
) {
    let mut ordinal = 0;
    let mut items = Vec::new();
    for execution in &report.executions {
        match app.result_tab {
            0 => {
                for finding in &execution.result.findings {
                    items.push(selectable_result_item(
                        ordinal,
                        app.result_selection,
                        &format!(
                            "{} | {:?} | {}",
                            execution.scanner_id, finding.severity, finding.title
                        ),
                        theme,
                    ));
                    ordinal += 1;
                }
            }
            1 => {
                for evidence in &execution.result.evidence {
                    items.push(selectable_result_item(
                        ordinal,
                        app.result_selection,
                        &format!(
                            "{} | {} | {}",
                            execution.scanner_id, evidence.kind, evidence.source
                        ),
                        theme,
                    ));
                    ordinal += 1;
                }
            }
            _ => {
                for diagnostic in &execution.result.diagnostics {
                    items.push(selectable_result_item(
                        ordinal,
                        app.result_selection,
                        &format!(
                            "{} | {} | {}",
                            execution.scanner_id, diagnostic.kind, diagnostic.message
                        ),
                        theme,
                    ));
                    ordinal += 1;
                }
            }
        }
    }
    if ordinal == 0 {
        items.push(ListItem::new("[EMPTY] No items in this section."));
    }
    let mut state = ListState::default();
    if ordinal > 0 {
        state.select(Some(app.result_selection.min(ordinal - 1)));
    }
    let list = List::new(items)
        .block(theme.panel(" ITEMS "))
        .highlight_style(theme.accent())
        .highlight_symbol(" ");
    frame.render_stateful_widget(list, area, &mut state);
}

fn selectable_result_item(
    index: usize,
    selected: usize,
    content: &str,
    theme: Theme,
) -> ListItem<'static> {
    let marker = if index == selected { "[>]" } else { "[ ]" };
    ListItem::new(Line::from(Span::styled(
        format!("  {marker} {content}"),
        if index == selected {
            theme.accent()
        } else {
            Style::new()
        },
    )))
}

fn render_result_detail(
    frame: &mut Frame<'_>,
    area: Rect,
    report: &RunReport,
    app: &App,
    theme: Theme,
) {
    let lines = match app.result_tab {
        0 => selected_finding(report, app.result_selection).map_or_else(
            || {
                vec![Line::from(
                    "Select a finding to inspect its evidence links.",
                )]
            },
            |(execution, finding)| finding_detail(execution, finding, theme),
        ),
        1 => selected_evidence(report, app.result_selection).map_or_else(
            || {
                vec![Line::from(
                    "Select evidence to inspect the redacted observation.",
                )]
            },
            |(execution, evidence)| evidence_detail(execution, evidence, theme),
        ),
        _ => selected_diagnostic(report, app.result_selection).map_or_else(
            || vec![Line::from("No operational diagnostics were emitted.")],
            |(scanner, kind, message)| {
                vec![
                    Line::from(Span::styled("DIAGNOSTIC", theme.secondary())),
                    Line::from(format!("Scanner: {scanner}")),
                    Line::from(format!("Kind: {kind}")),
                    Line::from(""),
                    Line::from(message),
                ]
            },
        ),
    };
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(theme.panel(" DETAIL ")),
        area,
    );
}

fn selected_finding(report: &RunReport, selected: usize) -> Option<(&ScanExecution, &Finding)> {
    report
        .executions
        .iter()
        .flat_map(|execution| {
            execution
                .result
                .findings
                .iter()
                .map(move |item| (execution, item))
        })
        .nth(selected)
}

fn selected_evidence(report: &RunReport, selected: usize) -> Option<(&ScanExecution, &Evidence)> {
    report
        .executions
        .iter()
        .flat_map(|execution| {
            execution
                .result
                .evidence
                .iter()
                .map(move |item| (execution, item))
        })
        .nth(selected)
}

fn selected_diagnostic(report: &RunReport, selected: usize) -> Option<(&str, &str, &str)> {
    report
        .executions
        .iter()
        .flat_map(|execution| {
            execution.result.diagnostics.iter().map(move |item| {
                (
                    execution.scanner_id.as_str(),
                    item.kind.as_str(),
                    item.message.as_str(),
                )
            })
        })
        .nth(selected)
}

fn finding_detail<'a>(
    execution: &'a ScanExecution,
    finding: &'a Finding,
    theme: Theme,
) -> Vec<Line<'a>> {
    vec![
        Line::from(Span::styled(&finding.title, theme.secondary())),
        Line::from(format!("Scanner: {}", execution.scanner_id)),
        Line::from(format!("Key: {}", finding.key)),
        Line::from(format!("Severity: {:?}", finding.severity)),
        Line::from(format!("Confidence: {:?}", finding.confidence)),
        Line::from(format!("Evidence links: {:?}", finding.evidence)),
    ]
}

fn evidence_detail<'a>(
    execution: &'a ScanExecution,
    evidence: &'a Evidence,
    theme: Theme,
) -> Vec<Line<'a>> {
    vec![
        Line::from(Span::styled("REDACTED OBSERVATION", theme.secondary())),
        Line::from(format!("Scanner: {}", execution.scanner_id)),
        Line::from(format!("Kind: {}", evidence.kind)),
        Line::from(format!("Source: {}", evidence.source)),
        Line::from(format!("Observed: {}", evidence.observed_at)),
        Line::from(""),
        Line::from(evidence.observation.to_string()),
    ]
}

fn render_history(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let [list_area, detail_area] =
        Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)]).areas(area);
    let mut items = Vec::new();
    for (index, report) in app.history.iter().enumerate().rev() {
        let selected = index == app.history_selection;
        let marker = if selected { "[>]" } else { "[ ]" };
        items.push(ListItem::new(Line::from(Span::styled(
            format!(
                "{marker} {} | {:?} | {} scan(s)",
                report.run_id,
                report.status(),
                report.executions.len()
            ),
            if selected {
                theme.accent()
            } else {
                Style::new()
            },
        ))));
    }
    if items.is_empty() {
        items.push(ListItem::new("[EMPTY] No runs completed in this session."));
    }
    let mut state = ListState::default();
    if !app.history.is_empty() {
        state.select(Some(
            app.history
                .len()
                .saturating_sub(1)
                .saturating_sub(app.history_selection),
        ));
    }
    let list = List::new(items)
        .block(theme.panel(" RECENT RUNS "))
        .highlight_style(theme.accent())
        .highlight_symbol(" ");
    frame.render_stateful_widget(list, list_area, &mut state);
    let details = app.history.get(app.history_selection).map_or_else(
        || {
            vec![Line::from(
                "Completed runs appear here after their report is safely persisted.",
            )]
        },
        |report| {
            vec![
                Line::from(Span::styled(
                    format!("{:?}", report.status()).to_uppercase(),
                    theme.secondary(),
                )),
                Line::from(format!("Run ID: {}", report.run_id)),
                Line::from(format!("Started: {}", report.started_at)),
                Line::from(format!("Finished: {}", report.finished_at)),
                Line::from(format!("Version: {}", report.app_version)),
                Line::from(format!("Executions: {}", report.executions.len())),
                Line::from(""),
                Line::from("Enter opens this report."),
            ]
        },
    );
    frame.render_widget(
        Paragraph::new(details)
            .wrap(Wrap { trim: true })
            .block(theme.panel(" RUN DETAIL ")),
        detail_area,
    );
}

fn render_settings(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let value = |enabled| if enabled { "[ON]" } else { "[OFF]" };
    let no_color = std::env::var_os("NO_COLOR").is_some();
    let [preferences, diagnostics] =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);
    let lines = vec![
        Line::from("[1] Compatibility selectors"),
        Line::from(format!(
            "    {}",
            value(app.settings.is_enabled(Preference::Compatibility))
        )),
        Line::from("[2] Cyan/violet color theme"),
        Line::from(format!(
            "    {}{}",
            value(app.settings.is_enabled(Preference::Color)),
            if no_color {
                " (locked by NO_COLOR)"
            } else {
                ""
            }
        )),
        Line::from("[3] ASCII borders and markers"),
        Line::from(format!(
            "    {}",
            value(app.settings.is_enabled(Preference::Ascii))
        )),
        Line::from("[4] Reduced motion"),
        Line::from(format!(
            "    {}",
            value(app.settings.is_enabled(Preference::ReducedMotion))
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines).block(theme.panel(" PRESENTATION ")),
        preferences,
    );
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(Span::styled("TERMINAL", theme.secondary())),
            Line::from(format!("Minimum viewport: {MIN_WIDTH}x{MIN_HEIGHT}")),
            Line::from(format!(
                "Color policy: {}",
                if no_color { "NO_COLOR" } else { "interactive" }
            )),
            Line::from(format!(
                "Glyph policy: {}",
                if theme.ascii { "ASCII" } else { "Unicode" }
            )),
            Line::from(""),
            Line::from(Span::styled("DATA SAFETY", theme.secondary())),
            Line::from("Provider secrets are represented only by environment variable names."),
            Line::from("Report paths are traversal-checked and persisted once."),
            Line::from("Event history is capped at 200 entries."),
        ])
        .wrap(Wrap { trim: true })
        .block(theme.panel(" RUNTIME DIAGNOSTICS ")),
        diagnostics,
    );
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let keys = match app.screen {
        Screen::Dashboard => "Enter catalog | H history | S settings | ? help | Q quit",
        Screen::Catalog => "/ search | Up/Down select | Enter configure | D dashboard | ? help",
        Screen::Configure => "Tab field | Left/Right choice | F5 run | Esc catalog | ? help",
        Screen::LiveRun => "C cancel | ? help | Q quit",
        Screen::Results => "Tab section | Up/Down item | H history | D dashboard | ? help",
        Screen::History => "Up/Down select | Enter open | D dashboard | ? help",
        Screen::Settings => "1-4 toggle | D dashboard | ? help",
    };
    frame.render_widget(
        Paragraph::new(keys)
            .alignment(Alignment::Center)
            .block(theme.panel(" KEY MAP ")),
        area,
    );
}

fn render_help(frame: &mut Frame<'_>, area: Rect, app: &App, theme: Theme) {
    let popup = centered_rect(72, 78, area);
    frame.render_widget(Clear, popup);
    let mode = screen_title(app.help_return.unwrap_or(app.screen));
    let help = Paragraph::new(vec![
        Line::from(Span::styled(format!("CONTEXT: {mode}"), theme.secondary())),
        Line::from("Up/Down or j/k   Move through selectable items"),
        Line::from("Enter            Open, advance, or execute"),
        Line::from("Tab/Shift-Tab    Advance or reverse sections/fields"),
        Line::from("Esc              Return or close this panel"),
        Line::from(""),
        Line::from(Span::styled("SAFETY", theme.secondary())),
        Line::from("Active scans require an explicit [x] authorization decision."),
        Line::from("Targets, typed options, and resource budgets are validated before execution."),
        Line::from("Secret values are never requested; provide an environment variable name."),
        Line::from(""),
        Line::from(Span::styled("ACCESSIBILITY", theme.secondary())),
        Line::from("Selection and state always include text markers such as [>] and [ON]."),
        Line::from("Set NO_COLOR to disable color. Enable ASCII mode for limited terminals."),
        Line::from(""),
        Line::from("Press ? or Esc to close."),
    ])
    .wrap(Wrap { trim: true })
    .block(theme.panel(" HELP & DIAGNOSTICS "));
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

fn truncate(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() && max_chars > 1 {
        format!(
            "{}…",
            truncated.chars().take(max_chars - 1).collect::<String>()
        )
    } else {
        truncated
    }
}

/// Default report directory used by interactive mode.
#[must_use]
pub fn default_output_directory() -> PathBuf {
    PathBuf::from("sugra-runs")
}
