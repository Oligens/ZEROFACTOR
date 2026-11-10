//! Typed evidence ingestion, integrity verification and impact aggregation.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all="snake_case")]
pub enum EvidenceResult { Pass, Fail, Inconclusive, NotRun }
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all="snake_case")]
pub enum EvidenceClass { Static, Simulated, Reproduced, IndependentlyVerified }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceScope {
    pub authorization_id: String,
    pub target_fingerprint: String,
    pub expires_at: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceIntegrity {
    pub sha256: String,
    #[serde(default)]
    pub artifact_uri: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactMeasurement {
    pub dimension: String,
    pub value: f64,
    pub unit: String,
    pub method: String,
    #[serde(default)]
    pub confidence: Option<f64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub evidence_id: String,
    pub assessment_id: String,
    pub test_id: String,
    #[serde(default)]
    pub finding_id: Option<String>,
    pub classification: EvidenceClass,
    pub scope: EvidenceScope,
    pub observed_at: String,
    pub result: EvidenceResult,
    #[serde(default)]
    pub impact: Vec<ImpactMeasurement>,
    pub integrity: EvidenceIntegrity,
}
#[derive(Debug, Clone, Default)]
pub struct FindingEvidence {
    pub evidence_ids: Vec<String>,
    pub confirmed_failures: usize,
    pub impact: Vec<ImpactMeasurement>,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct ImpactSummaryEntry {
    pub records: usize,
    pub measured_values: Vec<ImpactMeasurement>,
}
#[derive(Debug, Clone, Default)]
pub struct EvidenceIndex {
    pub records: Vec<EvidenceRecord>,
    pub findings: BTreeMap<String, FindingEvidence>,
    pub unlinked: Vec<String>,
}
impl EvidenceRecord {
    /// Structural and local artifact checks. This does not independently establish that
    /// the authorization was genuine or that the target fingerprint was captured honestly.
    pub fn verify(&self) -> Result<(), String> {
        if self.evidence_id.len()<8 || self.assessment_id.is_empty() || self.test_id.is_empty() { return Err("missing evidence identity".into()); }
        if self.scope.authorization_id.is_empty() || self.scope.target_fingerprint.is_empty() || self.scope.expires_at.is_empty() { return Err("missing authorization scope".into()); }
        if self.observed_at.is_empty() || self.integrity.sha256.len()!=64 || !self.integrity.sha256.chars().all(|c|c.is_ascii_hexdigit()) { return Err("invalid evidence timestamp or SHA-256".into()); }
        if self.impact.iter().any(|m| !m.value.is_finite() || m.value<0.0 || m.dimension.is_empty() || m.unit.is_empty() || m.method.is_empty()) { return Err("invalid impact measurement".into()); }
        if self.impact.iter().any(|m| m.confidence.map(|v|!v.is_finite() || !(0.0..=1.0).contains(&v)).unwrap_or(false)) { return Err("invalid impact confidence".into()); }
        if let Some(uri)=&self.integrity.artifact_uri {
            let path=Path::new(uri);
            if !path.is_file() { return Err(format!("evidence artifact does not exist: {uri}")); }
            let bytes=fs::read(path).map_err(|e|format!("cannot read evidence artifact: {e}"))?;
            let digest=format!("{:x}",Sha256::digest(bytes));
            if digest!=self.integrity.sha256.to_lowercase() { return Err(format!("evidence artifact SHA-256 mismatch: {uri}")); }
        }
        Ok(())
    }
}
impl EvidenceIndex {
    pub fn ingest(&mut self, record: EvidenceRecord) -> Result<(),String> {
        record.verify()?;
        if let Some(id)=&record.finding_id {
            let slot=self.findings.entry(id.clone()).or_default();
            slot.evidence_ids.push(record.evidence_id.clone());
            if record.result==EvidenceResult::Fail { slot.confirmed_failures+=1; }
            slot.impact.extend(record.impact.clone());
        } else { self.unlinked.push(record.evidence_id.clone()); }
        self.records.push(record);
        Ok(())
    }
    /// Accept either an evidence-record array or an assessment object containing evidence_records.
    pub fn load_json(&mut self, input: &str) -> Result<usize,String> {
        let value:serde_json::Value=serde_json::from_str(input).map_err(|e|format!("invalid evidence JSON: {e}"))?;
        let records=value.as_array().cloned().or_else(||value.get("evidence_records").and_then(|v|v.as_array()).cloned())
            .ok_or_else(||"expected an array or an object with evidence_records".to_string())?;
        let count=records.len();
        for value in records {
            let record:EvidenceRecord=serde_json::from_value(value).map_err(|e|format!("invalid evidence record: {e}"))?;
            self.ingest(record)?;
        }
        Ok(count)
    }
    pub fn impact_totals(&self)->BTreeMap<String,f64> {
        let mut totals=BTreeMap::new();
        for finding in self.findings.values() { for item in &finding.impact { *totals.entry(item.dimension.clone()).or_insert(0.0)+=item.value; } }
        totals
    }
    pub fn impact_summary(&self)->BTreeMap<String,ImpactSummaryEntry> {
        let mut result=BTreeMap::new();
        for finding in self.findings.values() { for item in &finding.impact {
            let slot=result.entry(item.dimension.clone()).or_insert_with(ImpactSummaryEntry::default);
            slot.records+=1;slot.measured_values.push(item.clone());
        }}
        result
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn record()->EvidenceRecord {
        EvidenceRecord { evidence_id:"evidence-0001".into(),assessment_id:"assessment-1".into(),test_id:"http-headers".into(),
            finding_id:Some("ZF-1".into()),classification:EvidenceClass::Reproduced,
            scope:EvidenceScope{authorization_id:"written-auth-1".into(),target_fingerprint:"sha256:target".into(),expires_at:"2099-01-01T00:00:00Z".into()},
            observed_at:"2026-11-09T00:00:00Z".into(),result:EvidenceResult::Fail,
            impact:vec![ImpactMeasurement{dimension:"security_posture".into(),value:2.0,unit:"missing_headers".into(),method:"bounded-test".into(),confidence:Some(0.9)}],
            integrity:EvidenceIntegrity{sha256:"a".repeat(64),artifact_uri:None} }
    }
    #[test] fn evidence_is_linked_and_impact_aggregated() {
        let mut index=EvidenceIndex::default();index.ingest(record()).unwrap();
        assert_eq!(index.findings["ZF-1"].confirmed_failures,1);
        assert_eq!(index.impact_totals()["security_posture"],2.0);
    }
    #[test] fn malformed_hash_is_rejected() { let mut r=record();r.integrity.sha256="bad".into();assert!(r.verify().is_err()); }
    #[test] fn json_array_is_ingested() {
        let value=serde_json::to_string(&vec![record()]).unwrap();
        let mut index=EvidenceIndex::default();assert_eq!(index.load_json(&value).unwrap(),1);
        assert_eq!(index.records.len(),1);
    }
}
