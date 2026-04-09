use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    prelude::*,
    widgets::{
        Block, Borders, Cell, Clear, Paragraph, Row, Scrollbar, ScrollbarOrientation,
        ScrollbarState, Table, Wrap,
    },
};
use v11y_core::model::Severity;

use super::app::{ActivePane, App};

pub fn render(f: &mut Frame, app: &mut App) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(0)])
        .split(f.area());

    let summary_area = main_chunks[0];
    let content_area = main_chunks[1];

    render_summary(f, app, summary_area);

    let chunks = if app.show_details {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
            .split(content_area)
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(100)])
            .split(content_area)
    };

    let list_area = chunks[0];
    render_list(f, app, list_area);

    if app.show_details && chunks.len() > 1 {
        let details_area = chunks[1];
        render_details(f, app, details_area);
    }

    if app.show_help {
        render_help(f, f.area());
    }
}

fn render_summary(f: &mut Frame, app: &mut App, area: Rect) {
    let metrics = &app.report.metrics;

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 6),
            Constraint::Ratio(1, 6),
            Constraint::Ratio(1, 6),
            Constraint::Ratio(1, 6),
            Constraint::Ratio(1, 6),
            Constraint::Ratio(1, 6),
        ])
        .split(area);

    let packages_text = if metrics.total_dependencies > 0 {
        format!("{} of {} ", metrics.total_packages, metrics.total_dependencies)
    } else {
        metrics.total_packages.to_string()
    };

    let items = vec![
        (
            "PACKAGES",
            packages_text,
            Color::White,
        ),
        ("CRITICAL", metrics.critical.to_string(), Color::Red),
        ("HIGH", metrics.high.to_string(), Color::Rgb(246, 170, 40)),
        (
            "MODERATE",
            metrics.moderate.to_string(),
            Color::Rgb(100, 150, 240),
        ),
        ("LOW", metrics.low.to_string(), Color::Gray),
        ("FIXABLE", metrics.fixable.to_string(), Color::White),
    ];

    for (i, (title, value, color)) in items.iter().enumerate() {
        let block = Block::default()
            .borders(if i == 0 {
                Borders::TOP | Borders::BOTTOM | Borders::LEFT | Borders::RIGHT
            } else {
                Borders::TOP | Borders::BOTTOM | Borders::RIGHT
            })
            .border_style(Style::default().fg(Color::DarkGray))
            .padding(ratatui::widgets::Padding::horizontal(1));

        let text = vec![
            Line::from(Span::styled(*title, Style::default().fg(Color::DarkGray))),
            Line::from(Span::styled(
                value.clone(),
                Style::default().fg(*color).bold(),
            )),
        ];

        let paragraph = Paragraph::new(text).block(block);
        f.render_widget(paragraph, chunks[i]);
    }
}

fn render_list(f: &mut Frame, app: &mut App, area: Rect) {
    let list_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
        .split(area);

    let list_border_style = if app.active_pane == ActivePane::List {
        Style::default().fg(Color::White).bold()
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let table_block = Block::default()
        .borders(if app.active_pane == ActivePane::Details {
            Borders::LEFT | Borders::RIGHT
        } else {
            Borders::LEFT | Borders::RIGHT
        })
        .border_style(list_border_style);

    let filter_block = Block::default()
        .borders(Borders::LEFT | Borders::RIGHT | Borders::BOTTOM | Borders::TOP)
        .border_style(Style::default().fg(Color::DarkGray));

    let mut filter_spans = vec![Span::styled(" Filter  ", Style::default().fg(Color::Gray))];

    let filters = [
        ("Critical", app.show_critical),
        ("High", app.show_high),
        ("Moderate", app.show_moderate),
        ("Low", app.show_low),
    ];

    for (label, active) in filters.iter() {
        if *active {
            filter_spans.push(Span::styled(
                format!("  {}  ", label),
                Style::default().bg(Color::White).fg(Color::Black).bold(),
            ));
        } else {
            filter_spans.push(Span::styled(
                format!("  {}  ", label),
                Style::default().fg(Color::White),
            ));
        }
        filter_spans.push(Span::from(" "));
    }

    let filter_p = Paragraph::new(Line::from(filter_spans))
        .block(filter_block)
        .alignment(Alignment::Left);
    f.render_widget(filter_p, list_chunks[1]);

    if app.filtered_risks.is_empty() {
        let empty_msg = Paragraph::new("No vulnerabilities match current filters.")
            .block(table_block)
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(empty_msg, list_chunks[0]);
        return;
    }

    let header = Row::new(vec![
        Cell::from("S.No.").style(Style::default().fg(Color::Gray)),
        Cell::from("PACKAGE").style(Style::default().fg(Color::Gray)),
        Cell::from("SEVERITY").style(Style::default().fg(Color::Gray)),
        Cell::from("VULNS").style(Style::default().fg(Color::Gray)),
        Cell::from("DIRECT").style(Style::default().fg(Color::Gray)),
        Cell::from("FIX").style(Style::default().fg(Color::Gray)),
    ])
    .height(1)
    .bottom_margin(1);

    let selected_idx = app.state.selected();

    let rows: Vec<Row> = app
        .filtered_risks
        .iter()
        .enumerate()
        .map(|(i, risk)| {
            let is_selected = Some(i) == selected_idx;
            let bg_color = if is_selected {
                if app.active_pane == ActivePane::List {
                    Color::Rgb(50, 50, 50)
                } else {
                    Color::Rgb(40, 40, 40)
                }
            } else {
                Color::Reset
            };

            let sno = Cell::from((i + 1).to_string()).style(Style::default().bg(bg_color));

            let pkg_line1 = Line::from(Span::styled(
                risk.name.clone(),
                Style::default().fg(Color::White).bold(),
            ));
            let via_text = if risk.is_direct {
                "direct dep".to_string()
            } else if !risk.transitive_causes.is_empty() {
                format!("via {}", risk.transitive_causes[0])
            } else {
                "indirect".to_string()
            };
            let pkg_line2 =
                Line::from(Span::styled(via_text, Style::default().fg(Color::DarkGray)));

            let pkg_cell = Cell::from(Text::from(vec![pkg_line1, pkg_line2]))
                .style(Style::default().bg(bg_color));

            let (sev_bg, sev_fg) = get_severity_colors(risk.max_severity);
            let severity_cell = Cell::from(Line::from(vec![Span::styled(
                format!(" {} ", risk.max_severity),
                Style::default().bg(sev_bg).fg(sev_fg).bold(),
            )]))
            .style(Style::default().bg(bg_color));

            let vulns_cell = Cell::from(risk.vulnerability_count.to_string())
                .style(Style::default().bg(bg_color));

            let direct_cell = if risk.is_direct {
                Cell::from("✓").style(Style::default().fg(Color::Green).bg(bg_color))
            } else {
                Cell::from(".").style(Style::default().fg(Color::DarkGray).bg(bg_color))
            };

            let fixable_cell = if risk.has_fix {
                Cell::from("✓").style(Style::default().fg(Color::Green).bg(bg_color))
            } else {
                Cell::from(".").style(Style::default().fg(Color::DarkGray).bg(bg_color))
            };

            Row::new(vec![
                sno,
                pkg_cell,
                severity_cell,
                vulns_cell,
                direct_cell,
                fixable_cell,
            ])
            .height(2)
            .bottom_margin(1)
        })
        .collect();

    let widths = [
        Constraint::Percentage(5),
        Constraint::Percentage(40),
        Constraint::Percentage(20),
        Constraint::Percentage(15),
        Constraint::Percentage(10),
        Constraint::Percentage(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(table_block)
        .row_highlight_style(Style::default().bold())
        .highlight_symbol(">> ");

    f.render_stateful_widget(table, list_chunks[0], &mut app.state);
}

fn render_details(f: &mut Frame, app: &mut App, area: Rect) {
    let details_border_style = if app.active_pane == ActivePane::Details {
        Style::default().fg(Color::White).bold()
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let block = Block::default()
        .borders(Borders::RIGHT)
        .border_style(details_border_style)
        .padding(ratatui::widgets::Padding::horizontal(2));

    if app.filtered_risks.is_empty() || app.state.selected().is_none() {
        let paragraph = Paragraph::new("No vulnerabilities selected.")
            .block(block)
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(paragraph, area);
        return;
    }

    let selected_risk = &app.filtered_risks[app.state.selected().unwrap()];

    let inner_area = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Header
            Constraint::Length(1), // Divider
            Constraint::Min(0),    // Scrollable content
        ])
        .split(inner_area);

    let header_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(0), Constraint::Length(12)])
        .split(chunks[0]);

    let (sev_bg, sev_fg) = get_severity_colors(selected_risk.max_severity);

    f.render_widget(
        Paragraph::new(selected_risk.name.clone()).style(Style::default().bold().fg(Color::White)),
        header_layout[0],
    );
    f.render_widget(
        Paragraph::new(Span::styled(
            format!(" {} ", selected_risk.max_severity),
            Style::default().bg(sev_bg).fg(sev_fg).bold(),
        ))
        .alignment(Alignment::Right),
        header_layout[1],
    );

    f.render_widget(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::DarkGray)),
        chunks[1],
    );

    let mut content = Vec::new();
    content.push(Line::from(""));
    content.push(Line::from(Span::styled(
        "AFFECTED RANGE",
        Style::default().fg(Color::DarkGray),
    )));

    content.push(Line::from(vec![
        Span::styled("Range   ", Style::default().fg(Color::Gray)),
        Span::styled(
            selected_risk.range.clone(),
            Style::default().fg(Color::White).bold(),
        ),
    ]));

    if !selected_risk.nodes.is_empty() {
        content.push(Line::from(vec![
            Span::styled("Nodes   ", Style::default().fg(Color::Gray)),
            Span::styled(
                selected_risk.nodes.join(", "),
                Style::default().fg(Color::White).bold(),
            ),
        ]));
    }

    if !selected_risk.transitive_causes.is_empty() {
        content.push(Line::from(vec![
            Span::styled("Via     ", Style::default().fg(Color::Gray)),
            Span::styled(
                selected_risk.transitive_causes.join(", "),
                Style::default().fg(Color::White).bold(),
            ),
        ]));
    }

    content.push(Line::from(""));
    content.push(Line::from(Span::styled(
        format!("{} ADVISORY", selected_risk.advisories.len()),
        Style::default().fg(Color::DarkGray),
    )));
    content.push(Line::from(""));

    for adv in &selected_risk.advisories {
        content.push(Line::from(Span::styled(
            adv.title.clone(),
            Style::default().fg(Color::White).bold(),
        )));

        let mut meta = Vec::new();
        if !adv.cwe.is_empty() {
            meta.push(Span::styled(
                format!("CWE: {} ", adv.cwe.join(", ")),
                Style::default().fg(Color::Gray),
            ));
        }
        if let Some(score) = adv.cvss_score {
            meta.push(Span::styled(
                format!("CVSS: {} ", score),
                Style::default().fg(Color::Gray),
            ));
        }
        meta.push(Span::styled(
            adv.url.clone(),
            Style::default()
                .fg(Color::Blue)
                .add_modifier(Modifier::UNDERLINED),
        ));

        content.push(Line::from(meta));
        content.push(Line::from(""));
    }

    let total_lines = count_wrapped_lines(&content, chunks[2].width);
    app.popup_max_scroll = total_lines.saturating_sub(chunks[2].height as usize) as u16;

    let paragraph = Paragraph::new(content)
        .wrap(Wrap { trim: true })
        .scroll((app.popup_scroll, 0));

    f.render_widget(paragraph, chunks[2]);

    if total_lines > chunks[2].height as usize {
        let mut scrollbar_state =
            ScrollbarState::new(app.popup_max_scroll as usize).position(app.popup_scroll as usize);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("↑"))
            .end_symbol(Some("↓"));
        f.render_stateful_widget(scrollbar, chunks[2], &mut scrollbar_state);
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
            count += 1;
        } else {
            count += (line_width as f64 / width as f64).ceil() as usize;
        }
    }
    count
}

fn get_severity_colors(severity: Severity) -> (Color, Color) {
    match severity {
        Severity::Critical => (Color::Red, Color::White),
        Severity::High => (Color::Rgb(246, 220, 170), Color::Black),
        Severity::Moderate => (Color::Rgb(200, 220, 246), Color::Black),
        Severity::Low => (Color::DarkGray, Color::White),
    }
}

fn render_help(f: &mut Frame, area: Rect) {
    let block = Block::default()
        .title(" Help / Shortcuts ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::White))
        .padding(ratatui::widgets::Padding::uniform(2));

    let text = vec![
        Line::from(Span::styled(
            "Navigation",
            Style::default().bold().fg(Color::Yellow),
        )),
        Line::from("  Up / Down / j / k : Move selection up/down"),
        Line::from("  Enter             : Toggle Details pane (keeps focus in List)"),
        Line::from("  Right             : Open Details pane and focus it"),
        Line::from("  Left              : Focus List pane"),
        Line::from("  Tab               : Switch focus between panes"),
        Line::from("  Esc               : Close Details pane (or quit if already closed)"),
        Line::from("  q                 : Quit"),
        Line::from(""),
        Line::from(Span::styled(
            "Filters",
            Style::default().bold().fg(Color::Yellow),
        )),
        Line::from("  c                 : Toggle Critical severities"),
        Line::from("  h                 : Toggle High severities"),
        Line::from("  m                 : Toggle Moderate severities"),
        Line::from("  l                 : Toggle Low severities"),
        Line::from(""),
        Line::from(Span::styled(
            "Press any key to close this help.",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let paragraph = Paragraph::new(text).block(block);

    let popup_area = centered_rect(50, 60, area);
    f.render_widget(Clear, popup_area); // clear background
    f.render_widget(paragraph, popup_area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
