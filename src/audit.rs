use crate::model::NpmAudit;
use std::{path::Path, process::Command};

pub fn npm() -> Result<NpmAudit, String> {
    let path = Path::new("/Users/santhoshc/learn/expense-tracker");

    let output = Command::new("npm")
        .arg("audit")
        .arg("--json")
        .current_dir(path)
        .output()
        .map_err(|e| format!("Failed to execute npm audit: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_npm_json(&stdout)
}

pub fn parse_npm_json(stdout: &str) -> Result<NpmAudit, String> {
    if stdout.trim().is_empty() {
        return Err("npm audit produced empty output".to_string());
    }

    serde_json::from_str(stdout).map_err(|e| format!("Failed to parse npm audit JSON: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn parses_npm_audit_fixture() {
        let json =
            fs::read_to_string("tests/fixtures/npm-audit.json").expect("failed to read fixture");

        let audit = parse_npm_json(&json).expect("failed to parse npm audit JSON");

        assert!(!audit.vulnerabilities.is_empty());
        assert!(audit.metadata.vulnerabilities.total == 13);
    }

    #[test]
    fn empty_output_is_error() {
        let err = parse_npm_json("").unwrap_err();
        assert!(err.contains("empty"));
    }
}
