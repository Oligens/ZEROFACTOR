//! Weighted Zero Factor Index (ZFI).
//! Not-tested guarantees are excluded from the failure score denominator and reported in coverage.

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GuaranteeOutcome {
    ConfirmedInvalidated,
    PartiallyInvalidated { fraction: f64 },
    Resisted,
    NotTested,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GuaranteeAssessment { pub guarantee_id: String, pub weight: f64, pub outcome: GuaranteeOutcome }

#[derive(Debug, Clone, PartialEq)]
pub enum ZfiError {
    EmptyGuaranteeId,
    InvalidWeight(String),
    InvalidPartialFraction(String),
    NoAssessedGuarantees,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ZfiResult {
    /// 0.0..=1.0; higher means a larger weighted share of assessed guarantees invalidated.
    pub score: f64,
    pub assessed_weight: f64,
    pub invalidated_weight: f64,
    pub not_tested_weight: f64,
    /// Assessed weight divided by all declared guarantee weight.
    pub coverage_ratio: f64,
    pub not_tested_count: usize,
    pub assessed_count: usize,
}

pub fn compute_zfi(items: &[GuaranteeAssessment]) -> Result<ZfiResult, ZfiError> {
    let (mut assessed_weight, mut invalidated_weight, mut not_tested_weight) = (0.0, 0.0, 0.0);
    let (mut not_tested_count, mut assessed_count) = (0, 0);
    for item in items {
        if item.guarantee_id.trim().is_empty() { return Err(ZfiError::EmptyGuaranteeId); }
        if !item.weight.is_finite() || item.weight <= 0.0 {
            return Err(ZfiError::InvalidWeight(item.guarantee_id.clone()));
        }
        let fraction = match item.outcome {
            GuaranteeOutcome::ConfirmedInvalidated => 1.0,
            GuaranteeOutcome::PartiallyInvalidated { fraction } => {
                if !fraction.is_finite() || fraction <= 0.0 || fraction >= 1.0 {
                    return Err(ZfiError::InvalidPartialFraction(item.guarantee_id.clone()));
                }
                fraction
            }
            GuaranteeOutcome::Resisted => 0.0,
            GuaranteeOutcome::NotTested => {
                not_tested_count += 1;
                not_tested_weight += item.weight;
                continue;
            }
        };
        assessed_count += 1;
        assessed_weight += item.weight;
        invalidated_weight += item.weight * fraction;
    }
    let total_weight = assessed_weight + not_tested_weight;
    if assessed_weight == 0.0 { return Err(ZfiError::NoAssessedGuarantees); }
    Ok(ZfiResult {
        score: (invalidated_weight / assessed_weight).clamp(0.0, 1.0),
        assessed_weight,
        invalidated_weight,
        not_tested_weight,
        coverage_ratio: assessed_weight / total_weight,
        not_tested_count,
        assessed_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn computes_weighted_score_and_reports_coverage() {
        let items = [
            GuaranteeAssessment { guarantee_id: "auth".into(), weight: 2.0, outcome: GuaranteeOutcome::ConfirmedInvalidated },
            GuaranteeAssessment { guarantee_id: "logging".into(), weight: 1.0, outcome: GuaranteeOutcome::Resisted },
            GuaranteeAssessment { guarantee_id: "backup".into(), weight: 5.0, outcome: GuaranteeOutcome::NotTested },
        ];
        let result = compute_zfi(&items).unwrap();
        assert!((result.score - 2.0 / 3.0).abs() < f64::EPSILON);
        assert!((result.coverage_ratio - 3.0 / 8.0).abs() < f64::EPSILON);
        assert_eq!(result.not_tested_weight, 5.0);
        assert_eq!(result.not_tested_count, 1);
        assert_eq!(result.assessed_count, 2);
    }

    #[test]
    fn supports_a_methodologically_defined_partial_fraction() {
        let item = GuaranteeAssessment { guarantee_id: "authorization".into(), weight: 4.0,
            outcome: GuaranteeOutcome::PartiallyInvalidated { fraction: 0.25 } };
        let result = compute_zfi(&[item]).unwrap();
        assert!((result.score - 0.25).abs() < f64::EPSILON);
    }

    #[test]
    fn rejects_invalid_partial_fraction() {
        let item = GuaranteeAssessment { guarantee_id: "authorization".into(), weight: 1.0,
            outcome: GuaranteeOutcome::PartiallyInvalidated { fraction: 1.0 } };
        assert!(matches!(compute_zfi(&[item]), Err(ZfiError::InvalidPartialFraction(_))));
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
