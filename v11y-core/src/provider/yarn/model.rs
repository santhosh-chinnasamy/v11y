use crate::model::{Advisory, AuditReport, Metrics, PackageRisk, Severity};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum YarnAuditLine {
    Classic(YarnClassicLine),
    Berry(YarnBerryLine),
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum YarnClassicLine {
    #[serde(rename = "auditAdvisory")]
    AuditAdvisory { data: YarnAdvisoryData },
    #[serde(rename = "auditSummary")]
    AuditSummary { data: YarnSummaryData },
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
pub struct YarnBerryLine {
    pub value: String,
    pub children: YarnBerryChildren,
}

#[derive(Debug, Deserialize)]
pub struct YarnBerryChildren {
    #[serde(rename = "ID")]
    pub id: serde_json::Value,
    #[serde(rename = "Issue")]
    pub issue: String,
    #[serde(rename = "URL")]
    pub url: Option<String>,
    #[serde(rename = "Severity")]
    pub severity: String,
    #[serde(rename = "Vulnerable Versions")]
    pub vulnerable_versions: String,
    #[serde(rename = "Tree Versions")]
    pub tree_versions: Vec<String>,
    #[serde(rename = "Dependents")]
    pub dependents: Vec<String>,
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

#[derive(Debug, Deserialize)]
pub struct YarnV3Audit {
    pub advisories: HashMap<String, YarnAdvisory>,
    pub metadata: YarnV3Metadata,
}

#[derive(Debug, Deserialize)]
pub struct YarnV3Metadata {
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
    // Attempt to parse as Yarn v3 (single JSON object)
    if let Ok(v3_audit) = serde_json::from_str::<YarnV3Audit>(raw_output) {
        return build_report_from_v3(v3_audit);
    }

    let mut classic_advisories_by_module: HashMap<String, Vec<YarnAdvisoryData>> = HashMap::new();
    let mut berry_findings_by_module: HashMap<String, Vec<YarnBerryChildren>> = HashMap::new();
    let mut official_metrics: Option<Metrics> = None;

    for line in raw_output.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<YarnAuditLine>(line) {
            Ok(YarnAuditLine::Classic(YarnClassicLine::AuditAdvisory { data })) => {
                classic_advisories_by_module
                    .entry(data.advisory.module_name.clone())
                    .or_default()
                    .push(data);
            }
            Ok(YarnAuditLine::Classic(YarnClassicLine::AuditSummary { data })) => {
                let critical = *data.vulnerabilities.get("critical").unwrap_or(&0);
                let high = *data.vulnerabilities.get("high").unwrap_or(&0);
                let moderate = *data.vulnerabilities.get("moderate").unwrap_or(&0);
                let low = *data.vulnerabilities.get("low").unwrap_or(&0)
                    + *data.vulnerabilities.get("info").unwrap_or(&0);

                let total_vulns = critical + high + moderate + low;

                official_metrics = Some(Metrics {
                    total_dependencies: data.dependencies,
                    dev_dependencies: data.dev_dependencies,
                    optional_dependencies: data.optional_dependencies,
                    total_packages: 0, // Will be filled later
                    total_vulns,
                    fixable: 0, // Will be filled later
                    critical,
                    high,
                    moderate,
                    low,
                });
            }
            Ok(YarnAuditLine::Berry(berry)) => {
                berry_findings_by_module
                    .entry(berry.value.clone())
                    .or_default()
                    .push(berry.children);
            }
            _ => {}
        }
    }

    let mut risks = Vec::new();
    let mut fixable_count = 0;

    // --- PARSE YARN CLASSIC ---
    for (pkg_name, events) in classic_advisories_by_module {
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
                    } else if let Some(first) = path.split('>').next() {
                        transitive_causes.insert(first.to_string());
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
            effects: vec![],
            range,
            nodes,
            transitive_causes,
            advisories,
        });
    }

    // --- PARSE YARN BERRY ---
    for (pkg_name, findings) in berry_findings_by_module {
        let mut vulnerability_count = 0;
        let mut is_direct = false;
        let has_fix = true; // Yarn berry format doesn't provide easy patched_versions info
        let mut max_sev = Severity::Low;
        let mut nodes = HashSet::new();
        let mut range = String::new();
        let mut transitive_causes = HashSet::new();
        let mut unique_advisories = HashMap::new();

        for finding in findings {
            vulnerability_count += 1;

            let sev = Severity::from_yarn(&finding.severity).unwrap_or(Severity::Low);
            if sev > max_sev {
                max_sev = sev;
            }

            if range.is_empty() {
                range = finding.vulnerable_versions.clone();
            }

            for dep in finding.dependents {
                nodes.insert(dep.clone());
                if dep.contains("workspace:.") || dep.contains("workspace:*") {
                    is_direct = true;
                } else if let Some(cause) = dep.split('@').next() {
                    if cause != pkg_name && !cause.is_empty() {
                        transitive_causes.insert(cause.to_string());
                    }
                }
            }

            let title = finding.issue.clone();
            let unified_adv = Advisory {
                title: finding.issue,
                url: finding.url.unwrap_or_default(),
                severity: sev,
                cwe: vec![],
                cvss_score: None,
                cvss_vector: None,
            };

            unique_advisories.insert(title, unified_adv); // Use title as key
        }

        if has_fix {
            fixable_count += 1;
        }

        let mut nodes: Vec<_> = nodes.into_iter().collect();
        nodes.sort();

        let mut transitive_causes: Vec<_> = transitive_causes.into_iter().collect();
        transitive_causes.sort();

        let mut advisories: Vec<_> = unique_advisories.into_values().collect();
        advisories.sort_by(|a, b| b.severity.cmp(&a.severity));

        risks.push(PackageRisk {
            name: pkg_name,
            is_direct,
            vulnerability_count,
            has_fix,
            max_severity: max_sev,
            effects: vec![],
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
        // Fallback calculation for Berry (which has no summary block in this NDJSON structure)
        Metrics {
            total_dependencies: 0,
            dev_dependencies: 0,
            optional_dependencies: 0,
            total_packages: risks.len(),
            total_vulns: risks.iter().map(|r| r.vulnerability_count).sum(),
            fixable: fixable_count,
            critical: risks
                .iter()
                .filter(|r| r.max_severity == Severity::Critical)
                .count(),
            high: risks
                .iter()
                .filter(|r| r.max_severity == Severity::High)
                .count(),
            moderate: risks
                .iter()
                .filter(|r| r.max_severity == Severity::Moderate)
                .count(),
            low: risks
                .iter()
                .filter(|r| r.max_severity == Severity::Low)
                .count(),
        }
    };

    AuditReport { risks, metrics }
}

fn build_report_from_v3(v3_audit: YarnV3Audit) -> AuditReport {
    let mut advisories_by_module: HashMap<String, Vec<YarnAdvisory>> = HashMap::new();
    for adv in v3_audit.advisories.into_values() {
        advisories_by_module
            .entry(adv.module_name.clone())
            .or_default()
            .push(adv);
    }

    let mut risks = Vec::new();
    let mut fixable_count = 0;

    for (pkg_name, pkg_advisories) in advisories_by_module {
        let mut vulnerability_count = 0;
        let mut is_direct = false;
        let mut has_fix = true;
        let mut max_sev = Severity::Low;
        let mut nodes = HashSet::new();
        let mut range = String::new();
        let mut transitive_causes = HashSet::new();
        let mut unique_advisories = HashMap::new();

        for adv in pkg_advisories {
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
                    } else if let Some(first) = path.split('>').next() {
                        transitive_causes.insert(first.to_string());
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
        advisories.sort_by(|a, b| b.severity.cmp(&a.severity));

        risks.push(PackageRisk {
            name: pkg_name,
            is_direct,
            vulnerability_count,
            has_fix,
            max_severity: max_sev,
            effects: vec![],
            range,
            nodes,
            transitive_causes,
            advisories,
        });
    }

    let critical = *v3_audit.metadata.vulnerabilities.get("critical").unwrap_or(&0);
    let high = *v3_audit.metadata.vulnerabilities.get("high").unwrap_or(&0);
    let moderate = *v3_audit.metadata.vulnerabilities.get("moderate").unwrap_or(&0);
    let low = *v3_audit.metadata.vulnerabilities.get("low").unwrap_or(&0)
        + *v3_audit.metadata.vulnerabilities.get("info").unwrap_or(&0);

    let total_vulns = critical + high + moderate + low;

    let metrics = Metrics {
        total_dependencies: v3_audit.metadata.total_dependencies,
        dev_dependencies: v3_audit.metadata.dev_dependencies,
        optional_dependencies: v3_audit.metadata.optional_dependencies,
        total_packages: risks.len(),
        total_vulns,
        fixable: fixable_count,
        critical,
        high,
        moderate,
        low,
    };

    AuditReport { risks, metrics }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn load_fixture(name: &str) -> String {
        fs::read_to_string(format!("tests/fixtures/{}", name)).expect("failed to read fixture")
    }

    #[test]
    fn parses_yarn_audit_fixture() {
        let json = load_fixture("yarn-audit.json");
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
        assert_eq!(report.metrics.total_dependencies, 359);
        assert_eq!(report.metrics.dev_dependencies, 0);
        assert_eq!(report.metrics.optional_dependencies, 0);
        assert_eq!(report.metrics.total_vulns, 28);
        assert_eq!(report.metrics.low, 3);
        assert_eq!(report.metrics.moderate, 8);
        assert_eq!(report.metrics.high, 17);
    }

    #[test]
    fn detects_indirect_dependency() {
        let json = load_fixture("yarn-audit.json");
        let report = parse_yarn_audit(&json);
        let risks = report.risks;

        let tar = risks.iter().find(|r| r.name == "tar").unwrap();

        assert!(!tar.is_direct);
        assert_eq!(tar.max_severity, Severity::High);
        assert!(tar.transitive_causes.contains(&"@tailwindcss/vite".to_string()));
    }

    #[test]
    fn parses_yarn_berry_audit_fixture() {
        let json = load_fixture("yarn-berry-audit.json");
        let report = parse_yarn_audit(&json);
        let risks = report.risks;

        assert!(!risks.is_empty());

        let babel_traverse = risks.iter().find(|r| r.name == "@babel/traverse").unwrap();
        assert_eq!(babel_traverse.max_severity, Severity::Critical);
        assert_eq!(babel_traverse.range, "<7.23.2");
        assert_eq!(babel_traverse.advisories[0].url, "https://github.com/advisories/GHSA-67hx-6x53-jw92");

        let fontawesome = risks.iter().find(|r| r.name == "@fortawesome/react-fontawesome").unwrap();
        assert!(fontawesome.is_direct); // Dependents contains "workspace:."
    }

    #[test]
    fn parses_yarn_v3_audit_fixture() {
        let json = load_fixture("yarn-v3-audit.json");
        let report = parse_yarn_audit(&json);
        let risks = report.risks;

        assert!(!risks.is_empty());
        let request = risks.iter().find(|r| r.name == "request").unwrap();
        assert_eq!(request.max_severity, Severity::Moderate);
        assert_eq!(report.metrics.total_vulns, 1201);
        assert_eq!(report.metrics.critical, 76);
    }
}
