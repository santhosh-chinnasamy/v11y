use super::AuditProvider;
use crate::model::AuditReport;
use color_eyre::eyre::{Result, WrapErr, eyre};
use std::process::Command;

mod model;
use model::parse_yarn_audit;

pub struct YarnProvider;

impl AuditProvider for YarnProvider {
    fn name(&self) -> &'static str {
        "yarn"
    }

    fn run_audit(&self) -> Result<String> {
        let version_output = Command::new("yarn")
            .arg("--version")
            .output()
            .wrap_err("Failed to execute yarn --version")?;

        let version = String::from_utf8_lossy(&version_output.stdout);

        let output = if version.starts_with("1.") {
            Command::new("yarn")
                .arg("audit")
                .arg("--json")
                .output()
                .wrap_err("Failed to execute yarn audit")?
        } else {
            Command::new("yarn")
                .arg("npm")
                .arg("audit")
                // --all ensures all workspaces in a monorepo are audited (matching npm behavior)
                .arg("--all")
                // --recursive ensures transitive dependencies are audited (matching npm behavior)
                .arg("--recursive")
                .arg("--json")
                .output()
                .wrap_err("Failed to execute yarn npm audit")?
        };

        if !output.status.success() && output.stdout.is_empty() {
            return Err(eyre!("yarn audit failed: {}", String::from_utf8_lossy(&output.stderr)));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn parse(&self, raw_output: &str) -> Result<AuditReport> {
        if raw_output.trim().is_empty() {
            return Err(eyre!("yarn audit produced empty output"));
        }

        let mut parsed_any_json = false;

        for line in raw_output.lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
                parsed_any_json = true;
                if value.get("type").and_then(|t| t.as_str()) == Some("error") {
                    if let Some(data) = value.get("data").and_then(|d| d.as_str()) {
                        return Err(eyre!("yarn audit failed: {}", data));
                    }
                }
            }
        }

        if serde_json::from_str::<serde_json::Value>(raw_output).is_ok() {
            parsed_any_json = true;
        }

        if !parsed_any_json {
            // For Yarn v2+ which outputs plain text errors to stdout (like Usage Error)
            return Err(eyre!("yarn audit failed: {}", raw_output.trim()));
        }

        Ok(parse_yarn_audit(raw_output))
    }
}
