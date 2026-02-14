use clap::Parser;
use std::cmp::Reverse;
mod audit;
mod cli;
mod model;
mod risk;

use crate::cli::Args;

fn main() {
    let args = Args::parse();
    println!("cli args: {:#?}", args);

    let audit_result = audit::npm().unwrap();
    println!(
        "Total Dependencies: {} \nTotal Vulnerabilities: {}",
        &audit_result.metadata.dependencies.total, &audit_result.metadata.vulnerabilities.total
    );

    let risks = risk::build_package_risk(audit_result);
    let mut filtered_risks = risk::filter_risks(
        risks,
        args.min_severity,
        args.only_direct,
        args.only_fixable,
    );
    filtered_risks.sort_by_key(|pkg| Reverse(risk::risk_score(pkg)));
    println!("length: {}, {:#?}", filtered_risks.len(), filtered_risks);
}
