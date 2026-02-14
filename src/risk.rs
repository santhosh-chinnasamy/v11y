use core::fmt;

use crate::model::{NpmAudit, ViaEntry};
use clap::ValueEnum;

#[derive(Debug)]
pub struct PackageRisk {
    pub name: String,
    pub is_direct: bool,
    pub max_severity: Severity,
    pub vulnerability_count: usize,
    pub has_fix: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Severity {
    Low,
    Moderate,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Severity::Low => "low",
            Severity::Moderate => "moderate",
            Severity::High => "high",
            Severity::Critical => "critical",
        };

        write!(f, "{}", value)
    }
}

impl Severity {
    fn from_npm(s: &str) -> Option<Self> {
        match s {
            "low" => Some(Severity::Low),
            "moderate" => Some(Severity::Moderate),
            "high" => Some(Severity::High),
            "critical" => Some(Severity::Critical),
            _ => None,
        }
    }
}

pub fn build_package_risk(audit: NpmAudit) -> Vec<PackageRisk> {
    let mut result = Vec::new();

    for (pkg_name, vulns) in audit.vulnerabilities {
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
        let max_sev = max_severity(&vulns.via).unwrap_or(Severity::Low);

        result.push(PackageRisk {
            name: pkg_name,
            is_direct: vulns.is_direct,
            vulnerability_count: advisory_count,
            has_fix,
            max_severity: max_sev,
        });
    }

    result
}

fn max_severity(via: &[ViaEntry]) -> Option<Severity> {
    via.iter()
        .filter_map(|entry| match entry {
            ViaEntry::Advisory(advisory) => Severity::from_npm(&advisory.severity),
            _ => None,
        })
        .max()
}

pub fn risk_score(pkg: &PackageRisk) -> i32 {
    let mut score = match pkg.max_severity {
        Severity::Critical => 100,
        Severity::High => 60,
        Severity::Moderate => 30,
        Severity::Low => 10,
    };

    if pkg.is_direct {
        score += 20
    }

    if pkg.has_fix {
        score += 10
    } else {
        score -= 20
    }

    score
}

pub fn filter_risks(
    risks: Vec<PackageRisk>,
    min_severity: Severity,
    only_direct: bool,
    only_fixable: bool,
) -> Vec<PackageRisk> {
    risks
        .into_iter()
        .filter(|pkg| pkg.max_severity >= min_severity)
        .filter(|pkg| !only_direct || pkg.is_direct)
        .filter(|pkg| !only_fixable || pkg.has_fix)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::parse_npm_json;
    use std::{fs, slice::RSplit};

    fn sample_risks() -> Vec<PackageRisk> {
        vec![
            PackageRisk {
                name: "direct-fixable-high".into(),
                is_direct: true,
                max_severity: Severity::High,
                vulnerability_count: 2,
                has_fix: true,
            },
            PackageRisk {
                name: "direct-notfixable-high".into(),
                is_direct: true,
                max_severity: Severity::High,
                vulnerability_count: 1,
                has_fix: false,
            },
            PackageRisk {
                name: "transitive-fixable-low".into(),
                is_direct: false,
                max_severity: Severity::Low,
                vulnerability_count: 1,
                has_fix: true,
            },
        ]
    }

    #[test]
    fn severity_ordering_is_correct() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Moderate);
        assert!(Severity::Moderate > Severity::Low);
    }

    #[test]
    fn max_severity_picks_highest_from_via() {
        use crate::model::ViaAdvisory;

        let via = vec![
            ViaEntry::Package("dep-a".to_string()),
            ViaEntry::Advisory(ViaAdvisory {
                name: "pkg".into(),
                title: "test".into(),
                severity: "moderate".into(),
                url: "http://example.com".into(),
                dependency: None,
                range: None,
            }),
            ViaEntry::Advisory(ViaAdvisory {
                name: "pkg".into(),
                title: "test".into(),
                severity: "high".into(),
                url: "http://example.com".into(),
                dependency: None,
                range: None,
            }),
        ];

        assert_eq!(max_severity(&via), Some(Severity::High));
    }

    #[test]
    fn builds_single_package_risk_per_package() {
        use crate::model::{NpmVulnerability, ViaAdvisory};
        use std::collections::HashMap;

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
                via: vec![
                    ViaEntry::Advisory(ViaAdvisory {
                        name: "vite".into(),
                        title: "test".into(),
                        severity: "moderate".into(),
                        url: "http://example.com".into(),
                        dependency: None,
                        range: None,
                    }),
                    ViaEntry::Advisory(ViaAdvisory {
                        name: "vite".into(),
                        title: "test".into(),
                        severity: "high".into(),
                        url: "http://example.com".into(),
                        dependency: None,
                        range: None,
                    }),
                ],
            },
        );

        let audit = NpmAudit {
            audit_report_version: 2,
            metadata: Default::default(),
            vulnerabilities,
        };

        let risks = build_package_risk(audit);

        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].name, "vite");
        assert_eq!(risks[0].vulnerability_count, 2);
        assert_eq!(risks[0].max_severity, Severity::High);
        assert!(risks[0].is_direct);
    }

    #[test]
    fn builds_package_risk_from_actual_json() {
        let json =
            fs::read_to_string("tests/fixtures/npm-audit.json").expect("failed to read fixture");

        let audit = parse_npm_json(&json).expect("failed to parse npm audit JSON");

        let risks = build_package_risk(audit);
        let vite = risks.iter().find(|risk| risk.name == "vite").unwrap();

        assert_eq!(risks.len(), 13);
        assert_eq!(vite.name, "vite");
        assert_eq!(vite.vulnerability_count, 11);
        assert_eq!(vite.max_severity, Severity::Moderate);
        assert!(vite.is_direct);
    }

    #[test]
    fn higher_severity_and_direct_dependency_scores_higher() {
        let low_transitive = PackageRisk {
            name: "low".into(),
            is_direct: false,
            max_severity: Severity::Low,
            vulnerability_count: 1,
            has_fix: true,
        };

        let high_direct = PackageRisk {
            name: "high".into(),
            is_direct: true,
            max_severity: Severity::High,
            vulnerability_count: 1,
            has_fix: true,
        };

        assert!(risk_score(&high_direct) > risk_score(&low_transitive));
    }

    #[test]
    fn severity_display_is_correct() {
        assert_eq!(Severity::Low.to_string(), "low");
        assert_eq!(Severity::Moderate.to_string(), "moderate");
        assert_eq!(Severity::High.to_string(), "high");
        assert_eq!(Severity::Critical.to_string(), "critical");
    }

    #[test]
    fn no_filters_returns_all_packages() {
        let risks = sample_risks();

        let filtered = filter_risks(
            risks,
            Severity::Low,
            false, // only_direct
            false, // only_fixable
        );

        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn only_fixable_filters_correctly() {
        let risks = sample_risks();

        let filtered = filter_risks(
            risks,
            Severity::Low,
            false,
            true, // only_fixable
        );

        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|r| r.has_fix));
    }

    #[test]
    fn only_direct_filters_correctly() {
        let risks = sample_risks();

        let filtered = filter_risks(
            risks,
            Severity::Low,
            true, // only_direct
            false,
        );

        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|r| r.is_direct));
    }

    #[test]
    fn severity_filter_applies_independently() {
        let risks = sample_risks();

        let filtered = filter_risks(risks, Severity::High, false, false);

        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|r| r.max_severity >= Severity::High));
    }
}
