use std::io::{self, stdout};

use ratatui::{
    Frame, Terminal,
    crossterm::{
        ExecutableCommand,
        event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
        terminal::{
            EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
        },
    },
    layout::{Constraint, Direction, Layout, Rect},
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

#[derive(PartialEq)]
enum ActivePane {
    List,
    Details,
}

struct App {
    all_risks: Vec<PackageRisk>,
    filtered_risks: Vec<PackageRisk>,
    state: TableState,
    should_quit: bool,
    active_pane: ActivePane,
    popup_scroll: u16,
    popup_max_scroll: u16,
    show_low: bool,
    show_moderate: bool,
    show_high: bool,
    show_critical: bool,
}

impl App {
    fn new(risks: Vec<PackageRisk>) -> Self {
        let mut state = TableState::default();
        if !risks.is_empty() {
            state.select(Some(0));
        }
        
        let filtered_risks = risks.clone();

        Self {
            all_risks: risks,
            filtered_risks,
            state,
            should_quit: false,
            active_pane: ActivePane::List,
            popup_scroll: 0,
            popup_max_scroll: 0,
            show_low: true,
            show_moderate: true,
            show_high: true,
            show_critical: true,
        }
    }

    fn apply_filters(&mut self) {
        self.filtered_risks = self.all_risks
            .iter()
            .filter(|risk| {
                match risk.max_severity {
                    Severity::Low => self.show_low,
                    Severity::Moderate => self.show_moderate,
                    Severity::High => self.show_high,
                    Severity::Critical => self.show_critical,
                }
            })
            .cloned()
            .collect();

        if self.filtered_risks.is_empty() {
            self.state.select(None);
            self.popup_scroll = 0;
        } else {
            if let Some(selected) = self.state.selected() {
                if selected >= self.filtered_risks.len() {
                    self.state.select(Some(self.filtered_risks.len() - 1));
                }
            } else {
                self.state.select(Some(0));
            }
            self.popup_scroll = 0;
        }
    }

    fn toggle_filter(&mut self, severity: Severity) {
        match severity {
            Severity::Low => self.show_low = !self.show_low,
            Severity::Moderate => self.show_moderate = !self.show_moderate,
            Severity::High => self.show_high = !self.show_high,
            Severity::Critical => self.show_critical = !self.show_critical,
        }
        self.apply_filters();
    }

    fn toggle_pane(&mut self) {
        if self.active_pane == ActivePane::List {
            self.active_pane = ActivePane::Details;
        } else {
            self.active_pane = ActivePane::List;
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
        if self.filtered_risks.is_empty() {
            return;
        }
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.filtered_risks.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
        self.popup_scroll = 0;
    }

    fn previous(&mut self) {
        if self.filtered_risks.is_empty() {
            return;
        }
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.filtered_risks.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
        self.popup_scroll = 0;
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
        KeyCode::Tab | KeyCode::Right | KeyCode::Left => app.toggle_pane(),
        KeyCode::Char('l') => app.toggle_filter(Severity::Low),
        KeyCode::Char('m') => app.toggle_filter(Severity::Moderate),
        KeyCode::Char('h') => app.toggle_filter(Severity::High),
        KeyCode::Char('c') => app.toggle_filter(Severity::Critical),
        KeyCode::Down | KeyCode::Char('j') => {
            if app.active_pane == ActivePane::Details {
                app.scroll_popup_down();
            } else {
                app.next();
            }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.active_pane == ActivePane::Details {
                app.scroll_popup_up();
            } else {
                app.previous();
            }
        }
        _ => {}
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(f.area());

    let list_area = chunks[0];
    let details_area = chunks[1];

    let header = Row::new(vec![
        Cell::from("Package").style(Style::default().bold()),
        Cell::from("Severity").style(Style::default().bold()),
        Cell::from("Vulns No.").style(Style::default().bold()),
        Cell::from("Direct?").style(Style::default().bold()),
        Cell::from("Fixable?").style(Style::default().bold()),
    ])
    .height(1);

    let rows: Vec<Row> = app
        .filtered_risks
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

    let filter_status = format!(
        " Filters - [L]ow: {} | [M]oderate: {} | [H]igh: {} | [C]ritical: {} ",
        if app.show_low { "ON" } else { "OFF" },
        if app.show_moderate { "ON" } else { "OFF" },
        if app.show_high { "ON" } else { "OFF" },
        if app.show_critical { "ON" } else { "OFF" }
    );

    let list_border_style = if app.active_pane == ActivePane::List {
        Style::default().fg(Color::White).bold()
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(list_border_style)
                .title(" v11y ")
                .title(" Vulnerability List ")
                .title_bottom(filter_status)
                .title_bottom(" [q: quit | Tab/←/→: switch pane | ↑/↓: navigate] ")
                .title_alignment(Alignment::Center),
        )
        .row_highlight_style(Style::default().bg(Color::DarkGray))
        .highlight_symbol(">> ");

    f.render_stateful_widget(table, list_area, &mut app.state);
    
    render_details(f, app, details_area);
}

fn render_details(f: &mut Frame, app: &mut App, area: Rect) {
    let details_border_style = if app.active_pane == ActivePane::Details {
        Style::default().fg(Color::White).bold()
    } else {
        Style::default().fg(Color::DarkGray)
    };

    if app.filtered_risks.is_empty() || app.state.selected().is_none() {
        let block = Block::bordered()
            .border_style(details_border_style)
            .title(" Advisory Details ");
        let paragraph = Paragraph::new("No vulnerabilities selected.")
            .block(block)
            .alignment(Alignment::Center);
        f.render_widget(paragraph, area);
        return;
    }

    let selected_risk = &app.filtered_risks[app.state.selected().unwrap()];
    let title = Line::from(vec![
        Span::from(" Advisory for "),
        Span::from(selected_risk.name.clone()).bold(),
        Span::from(" "),
    ]);
    let vulns_count = Line::from(vec![
        Span::from(" Vulns: "),
        Span::from(selected_risk.vulnerability_count.to_string()),
        Span::from(" | Severity: "),
        Span::styled(
            selected_risk.max_severity.to_string(),
            get_severity_style(selected_risk.max_severity),
        ),
        Span::from(" "),
    ]);

    let details_block = Block::bordered()
        .border_style(details_border_style)
        .title(title)
        .title(Line::from(vulns_count).right_aligned());

    let advisory_info: Vec<Line> = formatted_advisory(selected_risk.advisory.clone());

    let inner_area = details_block.inner(area);
    let total_lines = count_wrapped_lines(&advisory_info, inner_area.width);
    app.popup_max_scroll = total_lines.saturating_sub(inner_area.height as usize) as u16;

    let paragraph = Paragraph::new(advisory_info)
        .block(details_block)
        .fg(Color::White)
        .wrap(Wrap { trim: true })
        .scroll((app.popup_scroll, 0));

    f.render_widget(paragraph, area);

    if total_lines > inner_area.height as usize {
        let mut scrollbar_state =
            ScrollbarState::new(app.popup_max_scroll as usize).position(app.popup_scroll as usize);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));
        f.render_stateful_widget(scrollbar, area, &mut scrollbar_state);
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
