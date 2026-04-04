use serde::Deserialize;
use std::collections::HashMap;
use crate::model::{PackageRisk, Severity, Advisory, AuditReport, Metrics};

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

    #[serde(default)]
    pub effects: Vec<String>,

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

    #[serde(default)]
    pub cwe: Vec<String>,

    #[serde(default)]
    pub cvss: Option<CvssInfo>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CvssInfo {
    pub score: f64,
    #[serde(rename = "vectorString", default)]
    pub vector_string: Option<String>,
}

impl Severity {
    pub(crate) fn from_npm(s: &str) -> Option<Self> {
        match s {
            "low" => Some(Severity::Low),
            "moderate" => Some(Severity::Moderate),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

pub(crate) fn build_report_from_npm(audit: NpmAudit) -> AuditReport {
    let mut risks = Vec::new();
    let mut fixable = 0;

    for (pkg_name, vulns) in &audit.vulnerabilities {
        // Count only real advisories, not dependency strings
        let advisory_count = vulns
            .via
            .iter()
            .filter(|v| matches!(v, ViaEntry::Advisory(_)))
            .count();

        let has_fix = match vulns.fix_available {
            serde_json::Value::Bool(b) => b,
            serde_json::Value::Object(_) => true,
            _ => false,
        };
        
        if has_fix {
            fixable += 1;
        }

        let max_sev = max_severity(&vulns.via).unwrap_or(Severity::Low);

        let transitive_causes: Vec<String> = vulns
            .via
            .iter()
            .filter_map(|v| match v {
                ViaEntry::Package(p) => Some(p.clone()),
                _ => None,
            })
            .collect();

        let advisories: Vec<Advisory> = vulns
            .via
            .iter()
            .filter_map(|v| match v {
                ViaEntry::Advisory(advisory) => Some(Advisory {
                    title: advisory.title.clone(),
                    url: advisory.url.clone(),
                    severity: Severity::from_npm(&advisory.severity).unwrap_or(Severity::Low),
                    cwe: advisory.cwe.clone(),
                    cvss_score: advisory.cvss.as_ref().map(|c| c.score),
                    cvss_vector: advisory.cvss.as_ref().and_then(|c| c.vector_string.clone()),
                }),
                _ => None,
            })
            .collect();

        risks.push(PackageRisk {
            name: pkg_name.clone(),
            is_direct: vulns.is_direct,
            vulnerability_count: advisory_count,
            has_fix,
            max_severity: max_sev,
            effects: vulns.effects.clone(),
            range: vulns.range.clone(),
            nodes: vulns.nodes.clone(),
            transitive_causes,
            advisories,
        });
    }

    let metrics = Metrics {
        total_packages: risks.len(),
        total_vulns: audit.metadata.vulnerabilities.total as usize,
        fixable,
        critical: audit.metadata.vulnerabilities.critical as usize,
        high: audit.metadata.vulnerabilities.high as usize,
        moderate: audit.metadata.vulnerabilities.moderate as usize,
        low: audit.metadata.vulnerabilities.low as usize,
    };

    AuditReport { risks, metrics }
}

fn max_severity(via: &[ViaEntry]) -> Option<Severity> {
    via.iter()
        .filter_map(|entry| match entry {
            ViaEntry::Advisory(advisory) => Severity::from_npm(&advisory.severity),
            _ => None,
        })
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn load_fixture() -> String {
        fs::read_to_string("tests/fixtures/npm-audit.json").expect("failed to read fixture")
    }

    #[test]
    fn parses_npm_audit_fixture() {
        let json = load_fixture();
        let audit: NpmAudit = serde_json::from_str(&json).expect("failed to parse npm audit JSON");

        assert!(!audit.vulnerabilities.is_empty());
        assert!(audit.metadata.vulnerabilities.total == 13);
    }

    #[test]
    fn builds_package_risk_from_audit_fixture() {
        let json = load_fixture();
        let audit: NpmAudit = serde_json::from_str(&json).expect("failed to parse npm audit JSON");

        let report = build_report_from_npm(audit);
        let risks = report.risks;
        let vite = risks.iter().find(|risk| risk.name == "vite").unwrap();

        assert_eq!(risks.len(), 13);
        assert_eq!(vite.name, "vite");
        // vulnerability_count is 11 in our calculation, but total in metadata is 13
        assert_eq!(vite.vulnerability_count, 11);
        assert_eq!(vite.max_severity, Severity::Moderate);
        assert!(vite.is_direct);
        assert!(!vite.advisories.is_empty());
        
        // Check metrics
        assert_eq!(report.metrics.total_vulns, 13);
        assert_eq!(report.metrics.low, 3);
        assert_eq!(report.metrics.moderate, 5);
        assert_eq!(report.metrics.high, 5);
    }

    #[test]
    fn builds_single_package_risk_per_package() {
        let mut vulnerabilities = HashMap::new();

        vulnerabilities.insert(
            "vite".to_string(),
            NpmVulnerability {
                name: "vite".into(),
                is_direct: true,
                severity: "high".into(),
                fix_available: serde_json::Value::Bool(true),
                range: ">=4.0.0".into(),
                nodes: vec![],
                effects: vec![],
                via: vec![
                    ViaEntry::Advisory(ViaAdvisory {
                        name: "vite".into(),
                        title: "test".into(),
                        severity: "moderate".into(),
                        url: "http://example.com".into(),
                        dependency: None,
                        range: None,
                        cwe: vec![],
                        cvss: None,
                    }),
                    ViaEntry::Advisory(ViaAdvisory {
                        name: "vite".into(),
                        title: "test".into(),
                        severity: "high".into(),
                        url: "http://example.com".into(),
                        dependency: None,
                        range: None,
                        cwe: vec![],
                        cvss: None,
                    }),
                ],
            },
        );

        let audit = NpmAudit {
            audit_report_version: 2,
            metadata: Default::default(),
            vulnerabilities,
        };

        let report = build_report_from_npm(audit);
        let risks = report.risks;

        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].name, "vite");
        assert_eq!(risks[0].vulnerability_count, 2);
        assert_eq!(risks[0].max_severity, Severity::High);
        assert!(risks[0].is_direct);
        assert_eq!(risks[0].advisories.len(), 2);
        assert_eq!(risks[0].advisories[0].severity, Severity::Moderate);
        assert_eq!(risks[0].advisories[1].severity, Severity::High);
    }
}
