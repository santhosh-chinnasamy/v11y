use comfy_table::*;

use v11y_core::model::AuditReport;

pub fn formatted_result(report: AuditReport) {
    let metrics = &report.metrics;

    println!(
        "\n📦 Dependencies - Total: {} | Dev: {} | Optional: {} | Vulnerable Packages: {} (Fixable: {})",
        metrics.total_dependencies,
        metrics.dev_dependencies,
        metrics.optional_dependencies,
        metrics.total_vulns,
        metrics.fixable
    );
    println!(
        "🚨 Vulnerabilities - Critical: {} | High: {} | Moderate: {} | Low: {}",
        metrics.critical, metrics.high, metrics.moderate, metrics.low
    );
    println!();

    let mut table = Table::new();

    table
        .set_header(vec!["PACKAGE", "DIRECT", "SEVERITY", "VULNS", "FIXABLE"])
        .load_preset(presets::UTF8_FULL);

    for pkg in report.risks {
        let direct = if pkg.is_direct { "Yes" } else { "No" };
        let fix = if pkg.has_fix { "Yes" } else { "No" };

        table.add_row(vec![
            pkg.name.clone(),
            direct.to_string(),
            pkg.max_severity.to_string(),
            pkg.vulnerability_count.to_string(),
            fix.to_string(),
        ]);
    }

    println!("{}", table);
}

#[cfg(test)]
mod tests {
    use super::*;
}
