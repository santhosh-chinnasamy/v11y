use ratatui::widgets::TableState;
use v11y_core::{
    model::{PackageRisk, Severity, AuditReport},
    risk,
};

#[derive(PartialEq)]
pub enum ActivePane {
    List,
    Details,
}

pub struct App {
    pub report: AuditReport,
    pub filtered_risks: Vec<PackageRisk>,
    pub state: TableState,
    pub should_quit: bool,
    pub active_pane: ActivePane,
    pub popup_scroll: u16,
    pub popup_max_scroll: u16,
    pub show_low: bool,
    pub show_moderate: bool,
    pub show_high: bool,
    pub show_critical: bool,
}

impl App {
    pub fn new(report: AuditReport) -> Self {
        let mut state = TableState::default();
        if !report.risks.is_empty() {
            state.select(Some(0));
        }

        let filtered_risks = report.risks.clone();

        Self {
            report,
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

    pub fn apply_filters(&mut self) {
        self.filtered_risks = risk::filter_risks(
            self.report.risks.clone(),
            Severity::Low, // Base filter, toggle logic handles individual flags
            false,
            false,
        )
        .into_iter()
        .filter(|risk| match risk.max_severity {
            Severity::Low => self.show_low,
            Severity::Moderate => self.show_moderate,
            Severity::High => self.show_high,
            Severity::Critical => self.show_critical,
        })
        .collect();

        if self.filtered_risks.is_empty() {
            self.state.select(None);
            self.popup_scroll = 0;
        } else {
            if let Some(selected) = self.state.selected() {
                if selected >= self.filtered_risks.len() {
                    self.state.select(Some(self.filtered_risks.len().saturating_sub(1)));
                }
            } else {
                self.state.select(Some(0));
            }
            self.popup_scroll = 0;
        }
    }

    pub fn toggle_filter(&mut self, severity: Severity) {
        match severity {
            Severity::Low => self.show_low = !self.show_low,
            Severity::Moderate => self.show_moderate = !self.show_moderate,
            Severity::High => self.show_high = !self.show_high,
            Severity::Critical => self.show_critical = !self.show_critical,
        }
        self.apply_filters();
    }

    pub fn toggle_pane(&mut self) {
        if self.active_pane == ActivePane::List {
            self.active_pane = ActivePane::Details;
        } else {
            self.active_pane = ActivePane::List;
        }
    }

    pub fn scroll_popup_up(&mut self) {
        self.popup_scroll = self.popup_scroll.saturating_sub(1);
    }

    pub fn scroll_popup_down(&mut self) {
        if self.popup_scroll < self.popup_max_scroll {
            self.popup_scroll = self.popup_scroll.saturating_add(1);
        }
    }

    pub fn next(&mut self) {
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

    pub fn previous(&mut self) {
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
