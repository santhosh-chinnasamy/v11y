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

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn parse(&self, raw_output: &str) -> Result<AuditReport> {
        if raw_output.trim().is_empty() {
            return Err(eyre!("yarn audit produced empty output"));
        }

        Ok(parse_yarn_audit(raw_output))
    }
}
