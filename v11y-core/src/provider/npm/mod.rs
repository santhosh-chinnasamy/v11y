use super::AuditProvider;
use crate::model::AuditReport;
use color_eyre::eyre::{Result, WrapErr, eyre};
use std::process::Command;

mod model;
use model::{NpmAudit, build_report_from_npm};

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

    fn parse(&self, raw_output: &str) -> Result<AuditReport> {
        if raw_output.trim().is_empty() {
            return Err(eyre!("npm audit produced empty output"));
        }

        let audit: NpmAudit =
            serde_json::from_str(raw_output).wrap_err("Failed to parse npm audit JSON")?;

        Ok(build_report_from_npm(audit))
    }
}
