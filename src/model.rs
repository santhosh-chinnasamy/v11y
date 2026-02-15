use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Clone)]
pub struct NpmAudit {
    #[serde(rename = "auditReportVersion")]
    pub audit_report_version: u8,
    pub metadata: Metadata,
    pub vulnerabilities: HashMap<String, NpmVulnerability>,
}

#[derive(Debug, Deserialize, Default, Clone)]

pub struct Metadata {
    pub dependencies: DependencyCount,
    pub vulnerabilities: VulnerabilityCount,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct DependencyCount {
    pub dev: u32,
    pub optional: u32,
    pub peer: u32,
    #[serde(rename = "peerOptional")]
    pub peer_optional: u32,
    pub prod: u32,
    pub total: u32,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct VulnerabilityCount {
    pub critical: u32,
    pub high: u32,
    pub moderate: u32,
    pub low: u32,
    pub info: u32,
    pub total: u32,
}

#[derive(Debug, Deserialize, Clone)]
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

#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum ViaEntry {
    /// Transitive dependency
    Package(String),

    /// Full Advisory
    Advisory(ViaAdvisory),
}

#[derive(Debug, Deserialize, Clone)]
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
