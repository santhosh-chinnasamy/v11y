use std::cmp::Reverse;

use crate::risk::risk_score;

mod audit;
mod model;
mod risk;

fn main() {
    let audit_result = audit::npm().unwrap();
    println!("{}", "═".repeat(72));
    println!(
        "Total Dependencies: {} \nTotal Vulnerabilities: {}",
        &audit_result.metadata.dependencies.total, &audit_result.metadata.vulnerabilities.total
    );

    let mut risks = risk::build_package_risk(audit_result);
    risks.sort_by_key(|pkg| Reverse(risk_score(pkg)));

    println!("{}", "═".repeat(72));
    println!("\nSorted audit report\n");

    println!(
        "{:<30} {:<8} {:<10} {:<12} {:<6}",
        "PACKAGE", "DIRECT", "SEVERITY", "VULNS", "FIX"
    );
    println!("{}", "═".repeat(72));

    for risk in risks {
        let direct = if risk.is_direct { "●" } else { "○" };
        let fix = if risk.has_fix { "✓" } else { "✗" };

        println!(
            "{:<30} {:<8} {:<10} {:<12} {:<6}",
            risk.name,
            direct,
            format!("{:?}", risk.max_severity),
            risk.vulnerability_count,
            fix
        );
    }

    println!("{}", "-".repeat(72));
}
