use crate::model::AuditReport;
use color_eyre::eyre::{eyre, Result};
use std::path::Path;

pub mod npm;
pub mod yarn;

pub trait AuditProvider {
    /// Name of the provider (e.g., "npm", "yarn")
    fn name(&self) -> &'static str;

    /// Executes the underlying system command and returns raw output
    fn run_audit(&self) -> Result<String>;

    /// Parses the raw output into our unified domain model
    fn parse(&self, raw_output: &str) -> Result<AuditReport>;

    /// Convenience method to orchestrate the run -> parse flow
    fn audit(&self) -> Result<AuditReport> {
        let raw = self.run_audit()?;
        self.parse(&raw)
    }
}

pub fn detect_provider() -> Result<Box<dyn AuditProvider>> {
    if Path::new("yarn.lock").exists() {
        Ok(Box::new(yarn::YarnProvider))
    } else if Path::new("package-lock.json").exists() {
        Ok(Box::new(npm::NpmProvider))
    } else if Path::new("package.json").exists() {
        // Fallback to npm if there's a package.json but no lockfile
        Ok(Box::new(npm::NpmProvider))
    } else {
        Err(eyre!(
            "No package.json, package-lock.json, or yarn.lock found. Please run v11y in a Node.js project directory, or explicitly specify the package manager using --pm."
        ))
    }
}
