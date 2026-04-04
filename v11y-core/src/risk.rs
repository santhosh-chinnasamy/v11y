use std::cmp::Reverse;
use crate::model::{PackageRisk, Severity, Metrics};

/// Risk score calculation:
/// - Base: Critical=100, High=60, Moderate=30, Low=10
/// - +20 if direct dependency
/// - +10 if fix available
/// - -20 if no fix available
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

pub fn sort_by_priority(mut risks: Vec<PackageRisk>) -> Vec<PackageRisk> {
    risks.sort_by_key(|pkg| Reverse(risk_score(pkg)));
    risks
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

pub fn compute_metrics(risks: &[PackageRisk]) -> Metrics {
    let mut metrics = Metrics {
        total_dependencies: 0,
        dev_dependencies: 0,
        optional_dependencies: 0,
        total_packages: risks.len(),
        total_vulns: 0,
        fixable: 0,
        critical: 0,
        high: 0,
        moderate: 0,
        low: 0,
    };

    for risk in risks {
        metrics.total_vulns += risk.vulnerability_count;
        if risk.has_fix {
            metrics.fixable += 1;
        }
        match risk.max_severity {
            Severity::Critical => metrics.critical += 1,
            Severity::High => metrics.high += 1,
            Severity::Moderate => metrics.moderate += 1,
            Severity::Low => metrics.low += 1,
        }
    }

    metrics
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_risks() -> Vec<PackageRisk> {
        vec![
            PackageRisk {
                name: "direct-fixable-high".into(),
                is_direct: true,
                max_severity: Severity::High,
                vulnerability_count: 2,
                has_fix: true,
                effects: vec![],
                range: "".to_string(),
                nodes: vec![],
                transitive_causes: vec![],
                advisories: vec![],
            },
            PackageRisk {
                name: "direct-notfixable-high".into(),
                is_direct: true,
                max_severity: Severity::High,
                vulnerability_count: 1,
                has_fix: false,
                effects: vec![],
                range: "".to_string(),
                nodes: vec![],
                transitive_causes: vec![],
                advisories: vec![],
            },
            PackageRisk {
                name: "transitive-fixable-low".into(),
                is_direct: false,
                max_severity: Severity::Low,
                vulnerability_count: 1,
                has_fix: true,
                effects: vec![],
                range: "".to_string(),
                nodes: vec![],
                transitive_causes: vec![],
                advisories: vec![],
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
    fn higher_severity_and_direct_dependency_scores_higher() {
        let low_transitive = PackageRisk {
            name: "low".into(),
            is_direct: false,
            max_severity: Severity::Low,
            vulnerability_count: 1,
            has_fix: true,
            effects: vec![],
            range: "".to_string(),
            nodes: vec![],
            transitive_causes: vec![],
            advisories: vec![],
        };

        let high_direct = PackageRisk {
            name: "high".into(),
            is_direct: true,
            max_severity: Severity::High,
            vulnerability_count: 1,
            has_fix: true,
            effects: vec![],
            range: "".to_string(),
            nodes: vec![],
            transitive_causes: vec![],
            advisories: vec![],
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

    #[test]
    fn sort_by_priority_orders_highest_risk_first() {
        let risks = vec![
            PackageRisk {
                name: "low".into(),
                is_direct: false,
                max_severity: Severity::Low,
                vulnerability_count: 1,
                has_fix: true,
                effects: vec![],
                range: "".to_string(),
                nodes: vec![],
                transitive_causes: vec![],
                advisories: vec![],
            },
            PackageRisk {
                name: "critical".into(),
                is_direct: true,
                max_severity: Severity::Critical,
                vulnerability_count: 5,
                has_fix: false,
                effects: vec![],
                range: "".to_string(),
                nodes: vec![],
                transitive_causes: vec![],
                advisories: vec![],
            },
            PackageRisk {
                name: "high".into(),
                is_direct: true,
                max_severity: Severity::High,
                vulnerability_count: 2,
                has_fix: false,
                effects: vec![],
                range: "".to_string(),
                nodes: vec![],
                transitive_causes: vec![],
                advisories: vec![],
            },
        ];

        let sorted = sort_by_priority(risks);

        assert_eq!(sorted[0].name, "critical");
        assert_eq!(sorted[1].name, "high");
        assert_eq!(sorted[2].name, "low");
    }

    #[test]
    fn sort_by_priority_handles_empty_vec() {
        let risks: Vec<PackageRisk> = vec![];
        let sorted = sort_by_priority(risks);
        assert_eq!(sorted.len(), 0);
    }

    #[test]
    fn risk_score_no_fix_penalty() {
        let with_fix = PackageRisk {
            name: "pkg1".into(),
            is_direct: true,
            max_severity: Severity::High,
            vulnerability_count: 1,
            has_fix: true,
            effects: vec![],
            range: "".to_string(),
            nodes: vec![],
            transitive_causes: vec![],
            advisories: vec![],
        };

        let without_fix = PackageRisk {
            name: "pkg2".into(),
            is_direct: true,
            max_severity: Severity::High,
            vulnerability_count: 1,
            has_fix: false,
            effects: vec![],
            range: "".to_string(),
            nodes: vec![],
            transitive_causes: vec![],
            advisories: vec![],
        };

        // Score difference should be 30 (10 for has_fix vs -20 for no fix)
        assert_eq!(risk_score(&with_fix) - risk_score(&without_fix), 30);
    }

    #[test]
    fn filter_combined_all_criteria() {
        let risks = vec![
            PackageRisk {
                name: "match".into(),
                is_direct: true,
                max_severity: Severity::Critical,
                vulnerability_count: 1,
                has_fix: true,
                effects: vec![],
                range: "".to_string(),
                nodes: vec![],
                transitive_causes: vec![],
                advisories: vec![],
            },
            PackageRisk {
                name: "indirect".into(),
                is_direct: false,
                max_severity: Severity::Critical,
                vulnerability_count: 1,
                has_fix: true,
                effects: vec![],
                range: "".to_string(),
                nodes: vec![],
                transitive_causes: vec![],
                advisories: vec![],
            },
            PackageRisk {
                name: "no-fix".into(),
                is_direct: true,
                max_severity: Severity::Critical,
                vulnerability_count: 1,
                has_fix: false,
                effects: vec![],
                range: "".to_string(),
                nodes: vec![],
                transitive_causes: vec![],
                advisories: vec![],
            },
            PackageRisk {
                name: "low-severity".into(),
                is_direct: true,
                max_severity: Severity::Low,
                vulnerability_count: 1,
                has_fix: true,
                effects: vec![],
                range: "".to_string(),
                nodes: vec![],
                transitive_causes: vec![],
                advisories: vec![],
            },
        ];

        let filtered = filter_risks(risks, Severity::High, true, true);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "match");
    }

    #[test]
    fn test_compute_metrics() {
        let risks = vec![
            PackageRisk {
                name: "pkg1".to_string(),
                is_direct: true,
                max_severity: Severity::Critical,
                vulnerability_count: 5,
                has_fix: true,
                effects: vec![],
                range: "".to_string(),
                nodes: vec![],
                transitive_causes: vec![],
                advisories: vec![],
            },
            PackageRisk {
                name: "pkg2".to_string(),
                is_direct: false,
                max_severity: Severity::High,
                vulnerability_count: 2,
                has_fix: false,
                effects: vec![],
                range: "".to_string(),
                nodes: vec![],
                transitive_causes: vec![],
                advisories: vec![],
            },
            PackageRisk {
                name: "pkg3".to_string(),
                is_direct: true,
                max_severity: Severity::Low,
                vulnerability_count: 1,
                has_fix: true,
                effects: vec![],
                range: "".to_string(),
                nodes: vec![],
                transitive_causes: vec![],
                advisories: vec![],
            },
        ];

        let metrics = compute_metrics(&risks);

        assert_eq!(metrics.total_dependencies, 0);
        assert_eq!(metrics.total_packages, 3);
        assert_eq!(metrics.total_vulns, 8);
        assert_eq!(metrics.fixable, 2);
        assert_eq!(metrics.critical, 1);
        assert_eq!(metrics.high, 1);
        assert_eq!(metrics.moderate, 0);
        assert_eq!(metrics.low, 1);
    }
}
