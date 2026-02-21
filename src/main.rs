use clap::Parser;
use std::{cmp::Reverse, process::exit};

mod audit;
mod cli;
mod model;
mod risk;
mod terminal;
mod tui;

use crate::cli::Args;

fn main() {
    let args = Args::parse();

    let audit_result = audit::npm().unwrap_or_else(|e| {
        eprintln!("Error running npm audit: {}", e);
        exit(1);
    });

    let identified_risks = risk::build_package_risk(audit_result.clone());
    let filtered_risks = risk::filter_risks(
        identified_risks,
        args.min_severity,
        args.only_direct,
        args.only_fixable,
    );
    let sorted_risks = risk::sort_by_priority(filtered_risks);

    if args.cli {
        terminal::formatted_result(sorted_risks);
    } else {
        if let Err(e) = tui::run(sorted_risks) {
            eprintln!("TUI error: {}", e);
            exit(1);
        }
    }
}
