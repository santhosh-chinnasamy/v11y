use std::io::{self, stdout};
use ratatui::{
    backend::Backend,
    crossterm::{
        event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
        ExecutableCommand,
    },
    Terminal,
};
use v11y_core::model::{AuditReport, Severity};

pub mod app;
pub mod render;

use app::{ActivePane, App};

pub fn run(report: AuditReport) -> io::Result<()> {
    enable_raw_mode()?;
    let _ = stdout().execute(EnterAlternateScreen);

    let mut terminal = Terminal::new(ratatui::backend::CrosstermBackend::new(stdout()))?;
    let mut app = App::new(report);

    let result = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    let _ = stdout().execute(LeaveAlternateScreen);

    result
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> io::Result<()> {
    loop {
        terminal
            .draw(|f| render::render(f, app))
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
    if app.show_help {
        app.show_help = false;
        return;
    }

    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Esc => {
            if app.show_details {
                app.show_details = false;
                app.active_pane = ActivePane::List;
            } else {
                app.should_quit = true;
            }
        },
        KeyCode::Char('?') => app.show_help = true,
        KeyCode::Tab => app.toggle_pane(),
        KeyCode::Right => {
            app.show_details = true;
            app.active_pane = ActivePane::Details;
        },
        KeyCode::Left => app.active_pane = ActivePane::List,
        KeyCode::Enter => {
            app.show_details = !app.show_details;
            app.active_pane = ActivePane::List;
        },
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
