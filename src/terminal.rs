use comfy_table::*;

use crate::risk::{PackageRisk, Severity};

pub fn formatted_result(risks: Vec<PackageRisk>) {
    let mut table = Table::new();

    table
        .set_header(vec![
            "PACKAGE",
            "DIRECT",
            "SEVERITY",
            "VULNERABILITY COUNT",
            "FIX",
        ])
        .set_content_arrangement(ContentArrangement::Dynamic);

    for pkg in risks {
        let direct = if pkg.is_direct { "●" } else { "○" };
        let fix = if pkg.has_fix { "✓" } else { "" };

        table.add_row(vec![
            pkg.name,
            direct.to_string(),
            pkg.max_severity.to_string(),
            pkg.vulnerability_count.to_string(),
            fix.to_string(),
        ]);
    }

    println!("\nAudit Report");
    println!("{}", table);
}

#[cfg(test)]
mod tests {
    use super::*;
}
