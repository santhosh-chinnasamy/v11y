use color_eyre::Result;
use crate::model::AuditReport;
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

pub fn detect_provider() -> Box<dyn AuditProvider> {
    if Path::new("yarn.lock").exists() {
        Box::new(yarn::YarnProvider)
    } else if Path::new("package-lock.json").exists() {
        Box::new(npm::NpmProvider)
    } else {
        // Fallback to npm
        Box::new(npm::NpmProvider)
    }
}
