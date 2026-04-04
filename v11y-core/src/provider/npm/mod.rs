use std::process::Command;
use color_eyre::eyre::{eyre, Result, WrapErr};
use crate::model::PackageRisk;
use super::AuditProvider;

mod model;
use model::{NpmAudit, build_package_risk_from_npm};

pub struct NpmProvider;

impl AuditProvider for NpmProvider {
    fn name(&self) -> &'static str {
        "npm"
    }

    fn run_audit(&self) -> Result<String> {
        let output = Command::new("npm")
            .arg("audit")
            .arg("--json")
            .output()
            .wrap_err("Failed to execute npm audit")?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn parse(&self, raw_output: &str) -> Result<Vec<PackageRisk>> {
        if raw_output.trim().is_empty() {
            return Err(eyre!("npm audit produced empty output"));
        }

        let audit: NpmAudit = serde_json::from_str(raw_output)
            .wrap_err("Failed to parse npm audit JSON")?;

        Ok(build_package_risk_from_npm(audit))
    }
}
