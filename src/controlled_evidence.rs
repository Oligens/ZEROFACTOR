//! Import of bounded controlled-module JSON results into the typed evidence engine.
//! Fixture results are always Simulated; resulting findings require human review.
use crate::{
    evidence::{EvidenceClass, EvidenceIndex, EvidenceIntegrity, EvidenceRecord, EvidenceResult, EvidenceScope},
    model::{Finding, FindingStatus, Severity},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::{Path, PathBuf}};

const MODULES: &[&str] = &["AUTH", "INPUT", "FILE", "RATE", "RECOVERY"];

pub struct ControlledImport {
    pub records: usize,
    pub findings: Vec<Finding>,
    pub inconclusive: usize,
    pub module: String,
    pub case_id: String,
}
fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value.get(key).and_then(Value::as_str).filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("controlled result missing valid {key}"))
}
fn valid_case_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 96 &&
        value.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
}
fn result_value(value: &Value) -> Result<EvidenceResult, String> {
    match required_string(value, "result")? {
        "pass" => Ok(EvidenceResult::Pass),
        "fail" => Ok(EvidenceResult::Fail),
        "inconclusive" => Ok(EvidenceResult::Inconclusive),
        other => Err(format!("unsupported controlled evidence result: {other}")),
    }
}
fn stable_finding_id(module: &str, case_id: &str) -> String {
    let digest = Sha256::digest(format!("{module}:{case_id}").as_bytes());
    format!("ZF-{module}-{}", &format!("{digest:x}")[..12])
}

/// Import one JSON output file from the offline controlled evaluator.
/// The complete artifact is hashed and every typed evidence record references it.
pub fn ingest_controlled_result(index: &mut EvidenceIndex, artifact: &Path, assessment_id: &str) -> Result<ControlledImport, String> {
    if assessment_id.trim().is_empty() { return Err("assessment_id must not be empty".into()); }
    let bytes = fs::read(artifact).map_err(|e| format!("cannot read controlled result: {e}"))?;
    if bytes.len() > 256 * 1024 { return Err("controlled result exceeds 256 KiB".into()); }
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| format!("invalid controlled result JSON: {e}"))?;
    let module = required_string(&value, "module")?.to_string();
    if !MODULES.contains(&module.as_str()) { return Err(format!("unsupported controlled module: {module}")); }
    let case_id = required_string(&value, "case_id")?.to_string();
    if !valid_case_id(&case_id) { return Err("invalid controlled case_id".into()); }
    if required_string(&value, "evidence_kind")? != "synthetic_fixture" {
        return Err("controlled importer accepts synthetic_fixture results only".into());
    }
    let safety = value.get("safety").ok_or("controlled result missing safety metadata")?;
    for key in ["network_connections", "target_files_read", "target_files_written", "credentials_used"] {
        if safety.get(key).and_then(Value::as_u64) != Some(0) {
            return Err(format!("controlled result safety assertion failed: {key} must be zero"));
        }
    }
    let records = value.get("evidence_records").and_then(Value::as_array).ok_or("controlled result evidence_records must be an array")?;
    let checks = value.get("checks").and_then(Value::as_array).ok_or("controlled result checks must be an array")?;
    if records.is_empty() || records.len() != checks.len() || records.len() > 12 {
        return Err("controlled result must contain 1–12 matching checks and evidence records".into());
    }
    let mut findings = Vec::new();
    let mut inconclusive = 0usize;
    let mut staged_index = index.clone();
    for (position, raw) in records.iter().enumerate() {
        if required_string(raw, "module")? != module || required_string(raw, "classification")? != "synthetic_fixture" {
            return Err("evidence record module/classification does not match synthetic result envelope".into());
        }
        let evidence_id = required_string(raw, "evidence_id")?.to_string();
        let record_case = required_string(raw, "case_id")?.to_string();
        if !valid_case_id(&record_case) { return Err("invalid evidence case_id".into()); }
        let authorization_id = required_string(raw, "authorization_id")?.to_string();
        let target_fingerprint = required_string(raw, "target_fingerprint")?.to_string();
        let observed_at = required_string(raw, "observed_at")?.to_string();
        let expires_at = required_string(raw, "authorization_expires_at")?.to_string();
        let result = result_value(raw)?;
        let check = &checks[position];
        if required_string(check, "case_id")? != record_case || required_string(check, "result")? != required_string(raw, "result")? {
            return Err("check/evidence record mismatch".into());
        }
        let finding_id = if result == EvidenceResult::Fail { Some(stable_finding_id(&module, &record_case)) } else { None };
        let record = EvidenceRecord {
            evidence_id, assessment_id: assessment_id.to_string(), test_id: format!("controlled-{module}-{record_case}"),
            finding_id: finding_id.clone(), classification: EvidenceClass::Simulated,
            scope: EvidenceScope { authorization_id, target_fingerprint, expires_at },
            observed_at, result: result.clone(), impact: Vec::new(),
            integrity: EvidenceIntegrity { sha256: digest.clone(), artifact_uri: Some(artifact.to_string_lossy().into_owned()) },
        };
        record.verify()?;
        if staged_index.records.iter().any(|existing| existing.evidence_id == record.evidence_id) {
            return Err(format!("duplicate evidence_id: {}", record.evidence_id));
        }
        staged_index.ingest(record)?;
        match result {
            EvidenceResult::Fail => {
                let reason = required_string(check, "reason")?;
                findings.push(Finding {
                    id: finding_id.unwrap(), category: format!("controlled_{}", module.to_ascii_lowercase()),
                    severity: Severity::Medium, status: FindingStatus::NeedsReview,
                    title: format!("[SIMULATION] {module} policy mismatch: {record_case}"),
                    path: PathBuf::from(format!("controlled/{}/{}", module.to_ascii_lowercase(), record_case)),
                    line: None,
                    evidence: format!("Synthetic fixture only; reason={reason}; artifact_sha256={digest}"),
                    recommendation: "Review the corresponding control and reproduce only with separately approved, bounded authorization; do not treat this fixture as a live vulnerability.".into(),
                });
            }
            EvidenceResult::Inconclusive => inconclusive += 1,
            EvidenceResult::Pass | EvidenceResult::NotRun => {}
        }
    }
    *index = staged_index;
    Ok(ControlledImport { records: records.len(), findings, inconclusive, module, case_id })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, time::{SystemTime, UNIX_EPOCH}};
    fn temp_file(contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("zerofactor-controlled-{}-{}.json", std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        fs::write(&path, contents).unwrap(); path
    }
    fn envelope(result: &str) -> String {
        format!(r#"{{"schema_version":1,"module":"AUTH","case_id":"auth-case","result":"{result}",
          "evidence_kind":"synthetic_fixture",
          "safety":{{"network_connections":0,"target_files_read":0,"target_files_written":0,"credentials_used":0}},
          "checks":[{{"case_id":"private-route","result":"{result}","reason":"fixture_reason"}}],
          "evidence_records":[{{"evidence_id":"evidence-123456","module":"AUTH","case_id":"private-route",
          "classification":"synthetic_fixture","result":"{result}","reason":"fixture_reason",
          "authorization_id":"written-auth-123","target_fingerprint":"0123456789abcdef",
          "authorization_expires_at":"2099-01-01T00:00:00Z","observed_at":"2026-11-10T00:00:00Z"}}]}}"#)
    }
    #[test]
    fn imports_fixture_as_simulated_and_creates_review_finding_on_failure() {
        let path = temp_file(&envelope("fail")); let mut index = EvidenceIndex::default();
        let imported = ingest_controlled_result(&mut index, &path, "assessment-1").unwrap();
        assert_eq!(imported.records, 1); assert_eq!(imported.findings.len(), 1);
        assert_eq!(imported.findings[0].status.as_str(), "needs_review");
        assert_eq!(index.records[0].classification, EvidenceClass::Simulated);
        assert_eq!(index.records[0].result, EvidenceResult::Fail); fs::remove_file(path).unwrap();
    }
    #[test]
    fn inconclusive_result_does_not_create_a_finding() {
        let path = temp_file(&envelope("inconclusive")); let mut index = EvidenceIndex::default();
        let imported = ingest_controlled_result(&mut index, &path, "assessment-1").unwrap();
        assert_eq!(imported.inconclusive, 1); assert!(imported.findings.is_empty()); fs::remove_file(path).unwrap();
    }
    #[test]
    fn rejects_nonzero_network_assertion() {
        let raw = envelope("pass").replace(r#""network_connections":0"#, r#""network_connections":1"#);
        let path = temp_file(&raw); let mut index = EvidenceIndex::default();
        assert!(ingest_controlled_result(&mut index, &path, "assessment-1").is_err()); fs::remove_file(path).unwrap();
    }
    #[test]
    fn rejects_wrong_evidence_classification() {
        let raw = envelope("pass").replace("synthetic_fixture", "reproduced");
        let path = temp_file(&raw); let mut index = EvidenceIndex::default();
        assert!(ingest_controlled_result(&mut index, &path, "assessment-1").is_err()); fs::remove_file(path).unwrap();
    }
}
