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
        let output = Command::new("yarn")
            .arg("audit")
            .arg("--json")
            .output()
            .wrap_err("Failed to execute yarn audit")?;

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }

    fn parse(&self, raw_output: &str) -> Result<AuditReport> {
        if raw_output.trim().is_empty() {
            return Err(eyre!("yarn audit produced empty output"));
        }

        Ok(parse_yarn_audit(raw_output))
    }
}
