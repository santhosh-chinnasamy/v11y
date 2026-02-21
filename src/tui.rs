use std::io::{self, stdout};

use ratatui::{
    Frame, Terminal,
    crossterm::{
        ExecutableCommand,
        event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
        terminal::{
            self, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
        },
    },
    prelude::*,
    widgets::{Block, Borders, Cell, Row, Table, TableState},
};

use crate::risk::{PackageRisk, Severity};

pub fn run(risks: Vec<PackageRisk>) -> io::Result<()> {
    enable_raw_mode()?;
    let _ = stdout().execute(EnterAlternateScreen);

    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    let mut app = App::new(risks);

    let result = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    let _ = stdout().execute(LeaveAlternateScreen);

    result
}

struct App {
    risks: Vec<PackageRisk>,
    state: TableState,
    should_quit: bool,
}

impl App {
    fn new(risks: Vec<PackageRisk>) -> Self {
        let mut state = TableState::default();
        if !risks.is_empty() {
            state.select(Some(0));
        }
        Self {
            risks,
            state,
            should_quit: false,
        }
    }

    fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.risks.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.risks.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> io::Result<()> {
    loop {
        terminal
            .draw(|f| ui(f, app))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == KeyEventKind::Press {
                handle_key_event(key, app);
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}

fn handle_key_event(key: KeyEvent, app: &mut App) {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Down | KeyCode::Char('j') => app.next(),
        KeyCode::Up | KeyCode::Char('k') => app.previous(),
        _ => {}
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let area = f.area();

    let header = Row::new(vec![
        Cell::from("Package").style(Style::default().bold()),
        Cell::from("Severity").style(Style::default().bold()),
        Cell::from("Vulns No.").style(Style::default().bold()),
        Cell::from("Direct?").style(Style::default().bold()),
        Cell::from("Fixable?").style(Style::default().bold()),
    ])
    .height(1);

    let rows: Vec<Row> = app
        .risks
        .iter()
        .map(|risk| {
            let severity_style = match risk.max_severity {
                Severity::Critical => Style::default().bold().fg(Color::Red),
                Severity::High => Style::default().bold().fg(Color::Rgb(246, 170, 40)),
                Severity::Moderate => Style::default().bold().fg(Color::Yellow),
                Severity::Low => Style::default().bold().fg(Color::Gray),
            };
            Row::new(vec![
                Cell::from(risk.name.clone()),
                Cell::from(risk.max_severity.to_string()).style(severity_style),
                Cell::from(risk.vulnerability_count.to_string()),
                Cell::from(if risk.is_direct { "Yes" } else { "No" }),
                Cell::from(if risk.has_fix { "✓" } else { "✗" }),
            ])
        })
        .collect();

    let widths = [
        Constraint::Percentage(40),
        Constraint::Percentage(15),
        Constraint::Percentage(15),
        Constraint::Percentage(15),
        Constraint::Percentage(15),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" v11y ")
                // .title(Line::from("https://github.com/santhosh-chinnasamy/v11y").right_aligned())
                .title(" Vulnerability List ")
                .title_bottom(" [q: quit | ↑/↓: navigate] ")
                .title_alignment(Alignment::Center),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .highlight_symbol(">> ");

    f.render_stateful_widget(table, area, &mut app.state);
}
