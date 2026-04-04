use color_eyre::Result;
use crate::model::PackageRisk;

pub mod npm;

pub trait AuditProvider {
    /// Name of the provider (e.g., "npm", "yarn")
    fn name(&self) -> &'static str;

    /// Executes the underlying system command and returns raw output
    fn run_audit(&self) -> Result<String>;

    /// Parses the raw output into our unified domain model
    fn parse(&self, raw_output: &str) -> Result<Vec<PackageRisk>>;

    /// Convenience method to orchestrate the run -> parse flow
    fn audit(&self) -> Result<Vec<PackageRisk>> {
        let raw = self.run_audit()?;
        self.parse(&raw)
    }
}
