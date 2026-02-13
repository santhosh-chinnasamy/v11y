use std::cmp::Reverse;

mod audit;
mod model;
mod risk;

fn main() {
    let audit_result = audit::npm().unwrap();
    println!(
        "Total Dependencies: {} \nTotal Vulnerabilities: {}",
        &audit_result.metadata.dependencies.total, &audit_result.metadata.vulnerabilities.total
    );

    let risks = risk::build_package_risk(audit_result);
    let mut filtered_risks = risk::filter_risks(risks, risk::Severity::Low, true, true);
    filtered_risks.sort_by_key(|pkg| Reverse(risk::risk_score(pkg)));
    println!("{:#?}", filtered_risks);
}
