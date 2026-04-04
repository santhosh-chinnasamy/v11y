use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use crate::model::{PackageRisk, Severity, Advisory, Metrics, AuditReport};

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum YarnAuditLine {
    #[serde(rename = "auditAdvisory")]
    AuditAdvisory { data: YarnAdvisoryData },
    #[serde(rename = "auditSummary")]
    AuditSummary { data: YarnSummaryData },
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
pub struct YarnAdvisoryData {
    pub resolution: YarnResolution,
    pub advisory: YarnAdvisory,
}

#[derive(Debug, Deserialize)]
pub struct YarnResolution {
    pub path: String,
    pub dev: bool,
    pub optional: bool,
    pub bundled: bool,
}

#[derive(Debug, Deserialize)]
pub struct YarnAdvisory {
    pub findings: Vec<YarnFinding>,
    pub title: String,
    pub severity: String,
    pub module_name: String,
    pub vulnerable_versions: String,
    pub patched_versions: String,
    pub url: String,
    #[serde(default)]
    pub cwe: Vec<String>,
    #[serde(default)]
    pub cvss: Option<YarnCvss>,
}

#[derive(Debug, Deserialize)]
pub struct YarnFinding {
    pub version: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct YarnCvss {
    pub score: f64,
    #[serde(rename = "vectorString", default)]
    pub vector_string: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct YarnSummaryData {
    pub vulnerabilities: HashMap<String, usize>,
    pub dependencies: usize,
    #[serde(rename = "devDependencies")]
    pub dev_dependencies: usize,
    #[serde(rename = "optionalDependencies")]
    pub optional_dependencies: usize,
    #[serde(rename = "totalDependencies")]
    pub total_dependencies: usize,
}

impl Severity {
    pub(crate) fn from_yarn(s: &str) -> Option<Self> {
        match s {
            "info" | "low" => Some(Severity::Low),
            "moderate" => Some(Severity::Moderate),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

pub(crate) fn parse_yarn_audit(raw_output: &str) -> AuditReport {
    let mut advisories_by_module: HashMap<String, Vec<YarnAdvisoryData>> = HashMap::new();
    let mut official_metrics: Option<Metrics> = None;

    for line in raw_output.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str(line) {
            Ok(YarnAuditLine::AuditAdvisory { data }) => {
                advisories_by_module
                    .entry(data.advisory.module_name.clone())
                    .or_default()
                    .push(data);
            }
            Ok(YarnAuditLine::AuditSummary { data }) => {
                let mut total_vulns = 0;
                let critical = *data.vulnerabilities.get("critical").unwrap_or(&0);
                let high = *data.vulnerabilities.get("high").unwrap_or(&0);
                let moderate = *data.vulnerabilities.get("moderate").unwrap_or(&0);
                let low = *data.vulnerabilities.get("low").unwrap_or(&0) + *data.vulnerabilities.get("info").unwrap_or(&0);
                
                total_vulns = critical + high + moderate + low;

                official_metrics = Some(Metrics {
                    total_packages: 0, // Will be filled later
                    total_vulns,
                    fixable: 0, // Will be filled later
                    critical,
                    high,
                    moderate,
                    low,
                });
            }
            _ => {}
        }
    }

    let mut risks = Vec::new();
    let mut fixable_count = 0;

    for (pkg_name, events) in advisories_by_module {
        let mut vulnerability_count = 0;
        let mut is_direct = false;
        let mut has_fix = true;
        let mut max_sev = Severity::Low;
        let mut nodes = HashSet::new();
        let mut range = String::new();
        let mut transitive_causes = HashSet::new();
        let mut unique_advisories = HashMap::new();

        for event in events {
            let adv = event.advisory;
            
            let sev = Severity::from_yarn(&adv.severity).unwrap_or(Severity::Low);
            if sev > max_sev {
                max_sev = sev;
            }

            if adv.patched_versions == "<0.0.0" {
                has_fix = false;
            }

            if range.is_empty() {
                range = adv.vulnerable_versions.clone();
            }

            for finding in adv.findings {
                vulnerability_count += 1;
                for path in finding.paths {
                    nodes.insert(path.clone());
                    if !path.contains('>') {
                        is_direct = true;
                    } else {
                        if let Some(first) = path.split('>').next() {
                            transitive_causes.insert(first.to_string());
                        }
                    }
                }
            }

            let unified_adv = Advisory {
                title: adv.title,
                url: adv.url.clone(),
                severity: sev,
                cwe: adv.cwe,
                cvss_score: adv.cvss.as_ref().map(|c| c.score),
                cvss_vector: adv.cvss.and_then(|c| c.vector_string),
            };

            unique_advisories.insert(adv.url, unified_adv);
        }

        if has_fix {
            fixable_count += 1;
        }

        let mut nodes: Vec<_> = nodes.into_iter().collect();
        nodes.sort();
        
        let mut transitive_causes: Vec<_> = transitive_causes.into_iter().collect();
        transitive_causes.sort();

        let mut advisories: Vec<_> = unique_advisories.into_values().collect();
        advisories.sort_by(|a, b| b.severity.cmp(&a.severity)); // Sort by highest severity

        risks.push(PackageRisk {
            name: pkg_name,
            is_direct,
            vulnerability_count,
            has_fix,
            max_severity: max_sev,
            effects: vec![], // Yarn doesn't output "effects" cleanly
            range,
            nodes,
            transitive_causes,
            advisories,
        });
    }

    let metrics = if let Some(mut m) = official_metrics {
        m.total_packages = risks.len();
        m.fixable = fixable_count;
        m
    } else {
        // Fallback calculation
        Metrics {
            total_packages: risks.len(),
            total_vulns: risks.iter().map(|r| r.vulnerability_count).sum(),
            fixable: fixable_count,
            critical: risks.iter().filter(|r| r.max_severity == Severity::Critical).count(),
            high: risks.iter().filter(|r| r.max_severity == Severity::High).count(),
            moderate: risks.iter().filter(|r| r.max_severity == Severity::Moderate).count(),
            low: risks.iter().filter(|r| r.max_severity == Severity::Low).count(),
        }
    };

    AuditReport { risks, metrics }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn load_fixture() -> String {
        fs::read_to_string("tests/fixtures/yarn-audit.json").expect("failed to read fixture")
    }

    #[test]
    fn parses_yarn_audit_fixture() {
        let json = load_fixture();
        let report = parse_yarn_audit(&json);
        let risks = report.risks;
        
        assert!(!risks.is_empty());
        let vite = risks.iter().find(|r| r.name == "vite").unwrap();
        
        assert_eq!(vite.name, "vite");
        assert_eq!(vite.max_severity, Severity::Moderate);
        assert!(vite.has_fix);
        assert!(vite.nodes.len() > 0);
        assert!(!vite.advisories.is_empty());

        // Check metrics from summary
        assert_eq!(report.metrics.total_vulns, 28);
        assert_eq!(report.metrics.low, 3);
        assert_eq!(report.metrics.moderate, 8);
        assert_eq!(report.metrics.high, 17);
    }

    #[test]
    fn detects_indirect_dependency() {
        let json = load_fixture();
        let report = parse_yarn_audit(&json);
        let risks = report.risks;
        
        let tar = risks.iter().find(|r| r.name == "tar").unwrap();
        
        assert!(!tar.is_direct);
        assert_eq!(tar.max_severity, Severity::High);
        assert!(tar.transitive_causes.contains(&"@tailwindcss/vite".to_string()));
    }
}
