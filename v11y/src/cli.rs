use std::fmt;

use clap::{Parser, ValueEnum};
use v11y_core::model::Severity;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliSeverity {
    Low,
    Moderate,
    High,
    Critical,
}

impl fmt::Display for CliSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            CliSeverity::Low => "low",
            CliSeverity::Moderate => "moderate",
            CliSeverity::High => "high",
            CliSeverity::Critical => "critical",
        };
        write!(f, "{}", value)
    }
}

impl From<CliSeverity> for Severity {
    fn from(cli_sev: CliSeverity) -> Self {
        match cli_sev {
            CliSeverity::Low => Severity::Low,
            CliSeverity::Moderate => Severity::Moderate,
            CliSeverity::High => Severity::High,
            CliSeverity::Critical => Severity::Critical,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum PackageManager {
    Npm,
    Yarn,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(long)]
    pub only_direct: bool,

    #[arg(long, default_value_t = CliSeverity::Low)]
    pub min_severity: CliSeverity,

    #[arg(long)]
    pub only_fixable: bool,

    #[arg(long)]
    pub cli: bool,

    #[arg(long)]
    pub pm: Option<PackageManager>,
}
