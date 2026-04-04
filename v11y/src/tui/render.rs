use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    prelude::*,
    widgets::{Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, Wrap},
};
use v11y_core::{
    model::{Advisory, Severity},
    risk,
};

use super::app::{ActivePane, App};

pub fn render(f: &mut Frame, app: &mut App) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(f.area());

    let summary_area = main_chunks[0];
    let content_area = main_chunks[1];

    render_summary(f, app, summary_area);

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(content_area);

    let list_area = chunks[0];
    let details_area = chunks[1];

    render_list(f, app, list_area);
    render_details(f, app, details_area);
}

fn render_summary(f: &mut Frame, app: &mut App, area: Rect) {
    let metrics = risk::compute_metrics(&app.all_risks);

    let summary_text = Line::from(vec![
        Span::from(format!(
            " Total Packages: {} | Total Vulns: {} | Fixable: {} ",
            metrics.total_packages, metrics.total_vulns, metrics.fixable
        ))
        .bold(),
        Span::from(" | Severities - "),
        Span::styled(format!(" Critical: {} ", metrics.critical), get_severity_style(Severity::Critical)),
        Span::styled(format!(" High: {} ", metrics.high), get_severity_style(Severity::High)),
        Span::styled(format!(" Moderate: {} ", metrics.moderate), get_severity_style(Severity::Moderate)),
        Span::styled(format!(" Low: {} ", metrics.low), get_severity_style(Severity::Low)),
    ]);

    let summary_paragraph = Paragraph::new(summary_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .alignment(Alignment::Center);

    f.render_widget(summary_paragraph, area);
}

fn render_list(f: &mut Frame, app: &mut App, area: Rect) {
    let list_border_style = if app.active_pane == ActivePane::List {
        Style::default().fg(Color::White).bold()
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let filter_status = format!(
        " Filters - [L]ow: {} | [M]oderate: {} | [H]igh: {} | [C]ritical: {} ",
        if app.show_low { "ON" } else { "OFF" },
        if app.show_moderate { "ON" } else { "OFF" },
        if app.show_high { "ON" } else { "OFF" },
        if app.show_critical { "ON" } else { "OFF" }
    );

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(list_border_style)
        .title(" v11y ")
        .title(" Vulnerability List ")
        .title_bottom(filter_status)
        .title_bottom(" [q: quit | Tab/←/→: switch pane | ↑/↓: navigate] ")
        .title_alignment(Alignment::Center);

    if app.filtered_risks.is_empty() {
        let empty_msg = Paragraph::new("No vulnerabilities match current filters.")
            .block(block)
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(empty_msg, area);
        return;
    }

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
            let direct_cell = if risk.is_direct {
                Cell::from("Yes").style(Style::default().fg(Color::Yellow))
            } else {
                Cell::from("No").style(Style::default().fg(Color::DarkGray))
            };
            let fixable_cell = if risk.has_fix {
                Cell::from("✓").style(Style::default().fg(Color::Green))
            } else {
                Cell::from("✗").style(Style::default().fg(Color::Red))
            };

            Row::new(vec![
                Cell::from(risk.name.clone()),
                Cell::from(risk.max_severity.to_string()).style(severity_style),
                Cell::from(risk.vulnerability_count.to_string()),
                direct_cell,
                fixable_cell,
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
        .block(block)
        .row_highlight_style(Style::default().bg(Color::Rgb(50, 50, 50)).bold())
        .highlight_symbol(">> ");

    f.render_stateful_widget(table, area, &mut app.state);
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
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(paragraph, area);
        return;
    }

    let selected_risk = &app.filtered_risks[app.state.selected().unwrap()];
    let title = Line::from(vec![
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

    let mut advisory_info = Vec::new();

    advisory_info.push(Line::from(vec![
        Span::styled(" Vulnerable Range: ", Style::default().bold()),
        Span::from(selected_risk.range.clone()),
    ]));

    if !selected_risk.nodes.is_empty() {
        advisory_info.push(Line::from(vec![
            Span::styled(" Nodes: ", Style::default().bold()),
            Span::from(selected_risk.nodes.join(", ")),
        ]));
    }

    if !selected_risk.effects.is_empty() {
        advisory_info.push(Line::from(vec![
            Span::styled(" Effects: ", Style::default().bold()),
            Span::from(selected_risk.effects.join(", ")),
        ]));
    }

    if !selected_risk.transitive_causes.is_empty() {
        advisory_info.push(Line::from(vec![
            Span::styled(" Caused By (Transitive): ", Style::default().bold()),
            Span::from(selected_risk.transitive_causes.join(", ")),
        ]));
    }

    advisory_info.push(Line::from(""));
    advisory_info.push(Line::from(Span::styled(" Advisories:", Style::default().bold().underlined())));
    advisory_info.push(Line::from(""));

    advisory_info.extend(formatted_advisories(&selected_risk.advisories));

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

fn formatted_advisories(advisories: &[Advisory]) -> Vec<Line<'static>> {
    if advisories.is_empty() {
        return vec![Line::from("No advisory found")];
    }

    let mut lines = Vec::new();
    for (i, advisory) in advisories.iter().enumerate() {
        if i > 0 {
            lines.push(Line::from("")); // Blank line between advisories
        }
        lines.push(Line::from(vec![
            Span::styled(format!("{}. ", i + 1), Style::default().bold()),
            Span::styled(advisory.title.clone(), Style::default().bold()),
        ]));
        
        if !advisory.cwe.is_empty() {
            lines.push(Line::from(vec![
                Span::from("   CWE: "),
                Span::from(advisory.cwe.join(", ")),
            ]));
        }
        
        if let Some(score) = advisory.cvss_score {
            let mut cvss_spans = vec![
                Span::from("   CVSS: "),
                Span::from(score.to_string()),
            ];
            if let Some(ref vector) = advisory.cvss_vector {
                cvss_spans.push(Span::from(format!(" ({})", vector)));
            }
            lines.push(Line::from(cvss_spans));
        }
        
        lines.push(Line::from(vec![
            Span::from("   URL: "),
            Span::styled(
                advisory.url.clone(),
                Style::default().fg(Color::Blue),
            ),
        ]));
    }
    lines
}

fn get_severity_style(severity: Severity) -> Style {
    match severity {
        Severity::Critical => Style::default().bold().fg(Color::Red),
        Severity::High => Style::default().bold().fg(Color::Rgb(246, 170, 40)),
        Severity::Moderate => Style::default().bold().fg(Color::Yellow),
        Severity::Low => Style::default().bold().fg(Color::Gray),
    }
}
