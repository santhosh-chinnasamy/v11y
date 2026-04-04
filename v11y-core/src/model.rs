use serde::{Deserialize, Serialize};
use core::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageRisk {
    pub name: String,
    pub is_direct: bool,
    pub max_severity: Severity,
    pub vulnerability_count: usize,
    pub has_fix: bool,
    pub effects: Vec<String>,
    pub range: String,
    pub nodes: Vec<String>,
    pub transitive_causes: Vec<String>,
    pub advisories: Vec<Advisory>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Moderate,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Severity::Low => "low",
            Severity::Moderate => "moderate",
            Severity::High => "high",
            Severity::Critical => "critical",
        };

        write!(f, "{}", value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Advisory {
    pub title: String,
    pub url: String,
    pub severity: Severity,
    pub cwe: Vec<String>,
    pub cvss_score: Option<f64>,
    pub cvss_vector: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metrics {
    pub total_packages: usize,
    pub total_vulns: usize,
    pub fixable: usize,
    pub critical: usize,
    pub high: usize,
    pub moderate: usize,
    pub low: usize,
}
