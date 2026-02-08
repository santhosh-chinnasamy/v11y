use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct NpmAudit {
    #[serde(rename = "auditReportVersion")]
    pub audit_report_version: u8,
    pub metadata: Metadata,
    pub vulnerabilities: HashMap<String, NpmVulnerability>,
}

#[derive(Debug, Deserialize, Default)]

pub struct Metadata {
    pub dependencies: DependencyCount,
    pub vulnerabilities: VulnerabilityCount,
}

#[derive(Debug, Deserialize, Default)]
pub struct DependencyCount {
    pub dev: u32,
    pub optional: u32,
    pub peer: u32,
    #[serde(rename = "peerOptional")]
    pub peer_optional: u32,
    pub prod: u32,
    pub total: u32,
}

#[derive(Debug, Deserialize, Default)]
pub struct VulnerabilityCount {
    pub critical: u32,
    pub high: u32,
    pub moderate: u32,
    pub low: u32,
    pub info: u32,
    pub total: u32,
}

#[derive(Debug, Deserialize)]
pub struct NpmVulnerability {
    pub name: String,

    #[serde(rename = "isDirect")]
    pub is_direct: bool,

    pub severity: String,

    #[serde(rename = "fixAvailable")]
    pub fix_available: serde_json::Value, // boolean or object

    pub range: String,

    pub nodes: Vec<String>,

    pub via: Vec<ViaEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum ViaEntry {
    /// Transitive dependency
    Package(String),

    /// Full Advisory
    Advisory(ViaAdvisory),
}

#[derive(Debug, Deserialize)]
pub struct ViaAdvisory {
    pub name: String,
    pub severity: String,
    pub title: String,
    pub url: String,

    #[serde(default)]
    pub dependency: Option<String>,

    #[serde(default)]
    pub range: Option<String>,
}
