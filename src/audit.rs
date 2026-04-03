use crate::model::NpmAudit;
use color_eyre::eyre::{eyre, Result, WrapErr};
use std::process::Command;

pub fn npm() -> Result<NpmAudit> {
    let output = Command::new("npm")
        .arg("audit")
        .arg("--json")
        .output()
        .wrap_err("Failed to execute npm audit")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_npm_json(&stdout)
}

pub fn parse_npm_json(stdout: &str) -> Result<NpmAudit> {
    if stdout.trim().is_empty() {
        return Err(eyre!("npm audit produced empty output"));
    }

    serde_json::from_str(stdout).wrap_err("Failed to parse npm audit JSON")
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
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn test_invalid_json_returns_error() {
        let result = parse_npm_json("{invalid json");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("parse"));
    }

    #[test]
    fn test_parse_with_whitespace() {
        let json =
            fs::read_to_string("tests/fixtures/npm-audit.json").expect("failed to read fixture");
        let with_whitespace = format!("\n\n  {}  \n", json);

        let audit = parse_npm_json(&with_whitespace).expect("should handle whitespace");
        assert!(!audit.vulnerabilities.is_empty());
    }
}
