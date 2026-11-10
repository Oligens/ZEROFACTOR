//! Typed evidence ingestion primitives for the ZEROFACTOR result engine.
//! This module does not claim that a record is trustworthy merely because it parses.
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum EvidenceResult { Pass, Fail, Inconclusive, NotRun }
#[derive(Debug, Clone, PartialEq)]
pub enum EvidenceClass { Static, Simulated, Reproduced, IndependentlyVerified }
#[derive(Debug, Clone)]
pub struct ImpactMeasurement {
    pub dimension: String,
    pub value: f64,
    pub unit: String,
    pub method: String,
    pub confidence: Option<f64>,
}
#[derive(Debug, Clone)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub assessment_id: String,
    pub test_id: String,
    pub finding_id: Option<String>,
    pub classification: EvidenceClass,
    pub result: EvidenceResult,
    pub authorization_id: String,
    pub target_fingerprint: String,
    pub expires_at: String,
    pub artifact_sha256: String,
    pub impact: Vec<ImpactMeasurement>,
}
#[derive(Debug, Clone, Default)]
pub struct FindingEvidence {
    pub evidence_ids: Vec<String>,
    pub confirmed_failures: usize,
    pub impact: Vec<ImpactMeasurement>,
}
#[derive(Debug, Clone, Default)]
pub struct EvidenceIndex {
    pub findings: BTreeMap<String, FindingEvidence>,
    pub unlinked: Vec<String>,
}
impl EvidenceRecord {
    /// Structural checks only. Authorization validity and artifact hashing must be verified
    /// by the capture/assembly boundary before this record is accepted as verified evidence.
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if self.evidence_id.len() < 8 || self.assessment_id.is_empty() || self.test_id.is_empty() { return Err("missing evidence identity"); }
        if self.authorization_id.is_empty() || self.target_fingerprint.is_empty() || self.expires_at.is_empty() { return Err("missing authorization scope"); }
        if self.artifact_sha256.len() != 64 || !self.artifact_sha256.chars().all(|c| c.is_ascii_hexdigit()) { return Err("invalid SHA-256"); }
        if self.impact.iter().any(|m| !m.value.is_finite() || m.value < 0.0 || m.dimension.is_empty() || m.unit.is_empty() || m.method.is_empty()) { return Err("invalid impact measurement"); }
        if self.impact.iter().any(|m| m.confidence.map(|v| !v.is_finite() || !(0.0..=1.0).contains(&v)).unwrap_or(false)) { return Err("invalid confidence"); }
        Ok(())
    }
}
impl EvidenceIndex {
    pub fn ingest(&mut self, record: &EvidenceRecord) -> Result<(), &'static str> {
        record.validate_shape()?;
        if let Some(id) = &record.finding_id {
            let slot = self.findings.entry(id.clone()).or_default();
            slot.evidence_ids.push(record.evidence_id.clone());
            if record.result == EvidenceResult::Fail { slot.confirmed_failures += 1; }
            slot.impact.extend(record.impact.clone());
        } else { self.unlinked.push(record.evidence_id.clone()); }
        Ok(())
    }
    pub fn impact_totals(&self) -> BTreeMap<String, f64> {
        let mut totals = BTreeMap::new();
        for finding in self.findings.values() {
            for measurement in &finding.impact {
                *totals.entry(measurement.dimension.clone()).or_insert(0.0) += measurement.value;
            }
        }
        totals
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn record() -> EvidenceRecord {
        EvidenceRecord { evidence_id:"evidence-0001".into(),assessment_id:"assessment-1".into(),test_id:"http-headers".into(),
            finding_id:Some("ZF-1".into()),classification:EvidenceClass::Reproduced,result:EvidenceResult::Fail,
            authorization_id:"written-auth-1".into(),target_fingerprint:"sha256:target".into(),expires_at:"2099-01-01T00:00:00Z".into(),
            artifact_sha256:"a".repeat(64),impact:vec![ImpactMeasurement{dimension:"availability".into(),value:2.0,unit:"requests".into(),method:"bounded-test".into(),confidence:Some(0.9)}] }
    }
    #[test] fn evidence_is_linked_to_finding_and_impact_aggregated() {
        let mut index=EvidenceIndex::default();index.ingest(&record()).unwrap();
        assert_eq!(index.findings["ZF-1"].confirmed_failures,1);
        assert_eq!(index.impact_totals()["availability"],2.0);
    }
    #[test] fn malformed_hash_is_rejected() {
        let mut r=record();r.artifact_sha256="bad".into();
        assert_eq!(r.validate_shape(),Err("invalid SHA-256"));
    }
}
