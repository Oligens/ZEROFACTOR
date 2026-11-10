//! Minimal deterministic text report rendering. Structured export formats are planned.
use crate::model::Finding;
use crate::zfi::ZfiResult;

pub fn render_summary(target: &str, result: &ZfiResult, findings: &[Finding]) -> String {
    let mut report = String::new();
    report.push_str("# ZEROFACTOR assessment summary\n\n");
    report.push_str(&format!("Target: {target}\n"));
    report.push_str(&format!("ZFI: {:.3}\n", result.score));
    report.push_str(&format!("Assessed guarantees: {}\n", result.assessed_count));
    report.push_str(&format!("Not tested: {}\n", result.not_tested_count));
    report.push_str(&format!("Coverage: {:.1}%\n\n", result.coverage_ratio * 100.0));
    report.push_str("## Findings\n");
    for finding in findings {
        report.push_str(&format!("- [{}] {} — {} ({:?})\n",
            finding.severity, finding.id, finding.title, finding.status));
    }
    report.push_str("\nThis summary is not a certification. Review scope, coverage, evidence, and limitations.\n");
    report
}
