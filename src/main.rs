use clap::Parser;
use std::{cmp::Reverse, process::exit};
mod audit;
mod cli;
mod model;
mod risk;
mod terminal;

use crate::cli::Args;

fn main() {
    let args = Args::parse();
    let audit_result = audit::npm().unwrap_or_else(|e| {
        /// TODO: add a wrapper function to check if folder is a node project
        eprintln!("Error running npm audit, missing package-lock.json file");
        exit(1);
    });
    println!(
        "Total Dependencies: {} \nTotal Vulnerabilities: {}",
        &audit_result.metadata.dependencies.total, &audit_result.metadata.vulnerabilities.total
    );

    let identified_risks = risk::build_package_risk(audit_result);
    let filtered_risks = risk::filter_risks(
        identified_risks,
        args.min_severity,
        args.only_direct,
        args.only_fixable,
    );

    let sorted_risks = risk::sort_by_priority(filtered_risks);
    terminal::formatted_result(sorted_risks);
}
