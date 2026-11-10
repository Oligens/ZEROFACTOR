//! Aggregation layer connecting evidence-backed findings to declared guarantees.
use crate::model::{Finding, FindingStatus};
use crate::zfi::{compute_zfi, GuaranteeAssessment, ZfiError, ZfiResult};

pub fn assess_guarantees(items: &[GuaranteeAssessment]) -> Result<ZfiResult, ZfiError> { compute_zfi(items) }

pub fn evidence_backed_findings(findings: &[Finding]) -> Vec<&Finding> {
    findings.iter().filter(|finding| matches!(finding.status,
        FindingStatus::Observed | FindingStatus::Reproduced | FindingStatus::Confirmed)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Finding, FindingStatus, Severity};
    #[test]
    fn hypotheses_are_not_evidence_backed() {
        let finding = Finding { id: "ZF-1".into(), title: "Possible mismatch".into(), category: "parser".into(),
            severity: Severity::Medium, status: FindingStatus::Hypothesis, evidence_refs: vec![],
            affected_guarantee: None, impact: "Unknown".into(), remediation: "Investigate".into() };
        assert!(evidence_backed_findings(&[finding]).is_empty());
    }
}
