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
    widgets::{
        Block, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, TableState, Wrap,
    },
};

use crate::{
    model::ViaAdvisory,
    risk::{PackageRisk, Severity},
};

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
    is_popup_open: bool,
    popup_scroll: u16,
    popup_max_scroll: u16,
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
            is_popup_open: false,
            popup_scroll: 0,
            popup_max_scroll: 0,
        }
    }

    fn toggle_popup(&mut self) {
        self.is_popup_open = !self.is_popup_open;
        if self.is_popup_open {
            self.popup_scroll = 0;
            self.popup_max_scroll = 0;
        }
    }

    fn scroll_popup_up(&mut self) {
        self.popup_scroll = self.popup_scroll.saturating_sub(1);
    }

    fn scroll_popup_down(&mut self) {
        if self.popup_scroll < self.popup_max_scroll {
            self.popup_scroll = self.popup_scroll.saturating_add(1);
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
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Esc => {
            if app.is_popup_open {
                app.toggle_popup();
            } else {
                app.should_quit = true;
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.is_popup_open {
                app.scroll_popup_down();
            } else {
                app.next();
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.is_popup_open {
                app.scroll_popup_up();
            } else {
                app.previous();
            }
        }
        KeyCode::Enter => app.toggle_popup(),
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
            let severity_style = get_severity_style(risk.max_severity);
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
                .title(" Vulnerability List ")
                .title_bottom(" [q: quit | ↑/↓: navigate] ")
                .title_alignment(Alignment::Center),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .highlight_symbol(">> ");

    f.render_stateful_widget(table, area, &mut app.state);
    if app.is_popup_open {
        render_popup(f, app);
    }
}

fn render_popup(f: &mut Frame, app: &mut App) {
    let area = f.area();

    let selected_risk = &app.risks[app.state.selected().unwrap()];
    let title = Line::from(vec![
        Span::from(" Advisory for "),
        Span::from(selected_risk.name.clone()).bold(),
    ]);
    let vulns_count = Line::from(vec![
        Span::from(" Vulns: "),
        Span::from(selected_risk.vulnerability_count.to_string()),
        Span::from(" | Severity: "),
        Span::styled(
            selected_risk.max_severity.to_string(),
            get_severity_style(selected_risk.max_severity),
        ),
    ]);
    // format!(" Vulns: {} ", selected_risk.vulnerability_count);

    let centered_area = area.centered(Constraint::Percentage(60), Constraint::Percentage(40));
    f.render_widget(Clear, centered_area);

    let popup_block = Block::bordered()
        .title(title)
        .title(Line::from(vulns_count).right_aligned())
        .bg(Color::Black);

    let advisory_info: Vec<Line> = formatted_advisory(selected_risk.advisory.clone());

    let inner_area = popup_block.inner(centered_area);
    let total_lines = count_wrapped_lines(&advisory_info, inner_area.width);
    app.popup_max_scroll = total_lines.saturating_sub(inner_area.height as usize) as u16;

    let paragraph = Paragraph::new(advisory_info)
        .block(popup_block)
        .fg(Color::White)
        .wrap(Wrap { trim: true })
        .scroll((app.popup_scroll, 0));

    f.render_widget(paragraph, centered_area);

    if total_lines > inner_area.height as usize {
        let mut scrollbar_state =
            ScrollbarState::new(app.popup_max_scroll as usize).position(app.popup_scroll as usize);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));
        f.render_stateful_widget(scrollbar, centered_area, &mut scrollbar_state);
    }
}

fn count_wrapped_lines(lines: &[Line], width: u16) -> usize {
    let mut count = 0;
    if width == 0 {
        return lines.len();
    }
    for line in lines {
        let line_width = line.width();
        if line_width == 0 {
            count += 1; // Empty line
        } else {
            count += (line_width as f64 / width as f64).ceil() as usize;
        }
    }
    count
}

fn formatted_advisory(advisory: Option<Vec<ViaAdvisory>>) -> Vec<Line<'static>> {
    match advisory {
        Some(advisories) => {
            let mut lines = Vec::new();
            for (i, advisory) in advisories.into_iter().enumerate() {
                if i > 0 {
                    lines.push(Line::from("")); // Blank line between advisories
                }
                lines.push(Line::from(vec![
                    Span::styled(format!("{}. ", i + 1), Style::default().bold()),
                    Span::styled(advisory.title, Style::default().bold()),
                ]));
                lines.push(Line::from(Span::styled(
                    advisory.url,
                    Style::default().fg(Color::Blue),
                )));
            }
            lines
        }
        None => vec![Line::from("No advisory found")],
    }
}

fn get_severity_style(severity: Severity) -> Style {
    match severity {
        Severity::Critical => Style::default().bold().fg(Color::Red),
        Severity::High => Style::default().bold().fg(Color::Rgb(246, 170, 40)),
        Severity::Moderate => Style::default().bold().fg(Color::Yellow),
        Severity::Low => Style::default().bold().fg(Color::Gray),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_severity_style() {
        assert_eq!(
            get_severity_style(Severity::Critical),
            Style::default().bold().fg(Color::Red)
        );
        assert_eq!(
            get_severity_style(Severity::High),
            Style::default().bold().fg(Color::Rgb(246, 170, 40))
        );
        assert_eq!(
            get_severity_style(Severity::Moderate),
            Style::default().bold().fg(Color::Yellow)
        );
        assert_eq!(
            get_severity_style(Severity::Low),
            Style::default().bold().fg(Color::Gray)
        );
    }
}
