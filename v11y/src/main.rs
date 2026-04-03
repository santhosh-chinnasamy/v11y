use clap::Parser;
use color_eyre::Result;
use v11y_core::risk;

mod audit;
mod cli;
mod terminal;
mod tui;

use crate::cli::Args;

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();

    let audit_result = audit::npm()?;

    let identified_risks = risk::build_package_risk(audit_result);
    let filtered_risks = risk::filter_risks(
        identified_risks,
        args.min_severity.into(),
        args.only_direct,
        args.only_fixable,
    );
    let sorted_risks = risk::sort_by_priority(filtered_risks);

    if args.cli {
        terminal::formatted_result(sorted_risks);
    } else {
        tui::run(sorted_risks)?;
    }

    Ok(())
}
