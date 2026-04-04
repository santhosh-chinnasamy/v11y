use clap::Parser;
use color_eyre::Result;
use v11y_core::provider::{detect_provider, npm::NpmProvider, yarn::YarnProvider, AuditProvider};
use v11y_core::risk;

mod cli;
mod terminal;
mod tui;

use crate::cli::{Args, PackageManager};

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();

    let provider: Box<dyn AuditProvider> = match args.pm {
        Some(PackageManager::Npm) => Box::new(NpmProvider),
        Some(PackageManager::Yarn) => Box::new(YarnProvider),
        None => detect_provider(),
    };
    
    let mut report = provider.audit()?;

    report.risks = risk::filter_risks(
        report.risks,
        args.min_severity.into(),
        args.only_direct,
        args.only_fixable,
    );
    report.risks = risk::sort_by_priority(report.risks);

    if args.cli {
        terminal::formatted_result(report.risks);
    } else {
        tui::run(report)?;
    }

    Ok(())
}
