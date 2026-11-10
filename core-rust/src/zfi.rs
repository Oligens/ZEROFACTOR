//! Weighted Zero Factor Index (ZFI).
//! Not-tested guarantees are excluded from the denominator and reported separately.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuaranteeOutcome { ConfirmedInvalidated, PartiallyInvalidated, Resisted, NotTested }

#[derive(Debug, Clone, PartialEq)]
pub struct GuaranteeAssessment { pub guarantee_id: String, pub weight: f64, pub outcome: GuaranteeOutcome }

#[derive(Debug, Clone, PartialEq)]
pub enum ZfiError { EmptyGuaranteeId, InvalidWeight(String), NoAssessedGuarantees }

#[derive(Debug, Clone, PartialEq)]
pub struct ZfiResult {
    /// 0.0..=1.0; higher means a larger weighted share of assessed guarantees invalidated.
    pub score: f64,
    pub assessed_weight: f64,
    pub invalidated_weight: f64,
    pub not_tested_count: usize,
    pub assessed_count: usize,
}

pub fn compute_zfi(items: &[GuaranteeAssessment]) -> Result<ZfiResult, ZfiError> {
    let (mut assessed_weight, mut invalidated_weight) = (0.0, 0.0);
    let (mut not_tested_count, mut assessed_count) = (0, 0);
    for item in items {
        if item.guarantee_id.trim().is_empty() { return Err(ZfiError::EmptyGuaranteeId); }
        if !item.weight.is_finite() || item.weight <= 0.0 { return Err(ZfiError::InvalidWeight(item.guarantee_id.clone())); }
        let fraction = match item.outcome {
            GuaranteeOutcome::ConfirmedInvalidated => 1.0,
            GuaranteeOutcome::PartiallyInvalidated => 0.5,
            GuaranteeOutcome::Resisted => 0.0,
            GuaranteeOutcome::NotTested => { not_tested_count += 1; continue; }
        };
        assessed_count += 1;
        assessed_weight += item.weight;
        invalidated_weight += item.weight * fraction;
    }
    if assessed_weight == 0.0 { return Err(ZfiError::NoAssessedGuarantees); }
    Ok(ZfiResult { score: (invalidated_weight / assessed_weight).clamp(0.0, 1.0),
        assessed_weight, invalidated_weight, not_tested_count, assessed_count })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn computes_weighted_score_and_excludes_untested() {
        let items = [
            GuaranteeAssessment { guarantee_id: "auth".into(), weight: 2.0, outcome: GuaranteeOutcome::ConfirmedInvalidated },
            GuaranteeAssessment { guarantee_id: "logging".into(), weight: 1.0, outcome: GuaranteeOutcome::Resisted },
            GuaranteeAssessment { guarantee_id: "backup".into(), weight: 5.0, outcome: GuaranteeOutcome::NotTested },
        ];
        let result = compute_zfi(&items).unwrap();
        assert!((result.score - 2.0 / 3.0).abs() < f64::EPSILON);
        assert_eq!(result.not_tested_count, 1);
        assert_eq!(result.assessed_count, 2);
    }
    #[test]
    fn rejects_zero_weight() {
        let item = GuaranteeAssessment { guarantee_id: "auth".into(), weight: 0.0, outcome: GuaranteeOutcome::Resisted };
        assert!(matches!(compute_zfi(&[item]), Err(ZfiError::InvalidWeight(_))));
    }
    #[test]
    fn refuses_score_when_nothing_was_tested() {
        let item = GuaranteeAssessment { guarantee_id: "auth".into(), weight: 1.0, outcome: GuaranteeOutcome::NotTested };
        assert_eq!(compute_zfi(&[item]), Err(ZfiError::NoAssessedGuarantees));
    }
}
