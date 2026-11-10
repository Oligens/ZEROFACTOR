//! Typed evidence ingestion, controlled-module normalization and integrity checks.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, fs, path::{Component, Path}};

const MAX_EVIDENCE_BYTES: usize = 1_048_576;
const MAX_CONTROLLED_RECORDS: usize = 12;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceResult { Pass, Fail, Inconclusive, NotRun }

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
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

/// A failed controlled check is a review candidate, not an automatically confirmed
/// vulnerability. Its evidence class records whether it was simulated or observed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlledFinding {
    pub finding_id: String,
    pub module: String,
    pub case_id: String,
    pub title: String,
    pub reason: String,
    pub status: String,
    pub classification: EvidenceClass,
    pub evidence_id: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleSummary {
    pub module: String,
    pub assessment_id: String,
    pub authorization_id: String,
    pub result: String,
    pub evidence_kind: String,
    pub observed_at: String,
    pub cases: usize,
    pub passed: usize,
    pub failed: usize,
    pub inconclusive: usize,
    pub network_connections: usize,
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
    pub controlled_findings: Vec<ControlledFinding>,
    pub module_summaries: Vec<ModuleSummary>,
}

impl EvidenceRecord {
    /// Structural and local artifact checks. This does not independently establish that
    /// authorization was genuine or that the target fingerprint was captured honestly.
    pub fn verify(&self) -> Result<(), String> {
        if self.evidence_id.len() < 8 || self.assessment_id.is_empty() || self.test_id.is_empty() {
            return Err("missing evidence identity".into());
        }
        if self.scope.authorization_id.is_empty() || self.scope.target_fingerprint.is_empty() || self.scope.expires_at.is_empty() {
            return Err("missing authorization scope".into());
        }
        if self.observed_at.is_empty() || self.integrity.sha256.len() != 64
            || !self.integrity.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("invalid evidence timestamp or SHA-256".into());
        }
        if self.impact.iter().any(|m| !m.value.is_finite() || m.value < 0.0 || m.dimension.is_empty() || m.unit.is_empty() || m.method.is_empty()) {
            return Err("invalid impact measurement".into());
        }
        if self.impact.iter().any(|m| m.confidence.map(|v| !v.is_finite() || !(0.0..=1.0).contains(&v)).unwrap_or(false)) {
            return Err("invalid impact confidence".into());
        }
        if let Some(uri) = &self.integrity.artifact_uri {
            let path = Path::new(uri);
            if path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_))) {
                return Err("artifact_uri must be a relative path without parent traversal".into());
            }
            if !path.is_file() { return Err(format!("evidence artifact does not exist: {uri}")); }
            let bytes = fs::read(path).map_err(|e| format!("cannot read evidence artifact: {e}"))?;
            let digest = format!("{:x}", Sha256::digest(bytes));
            if digest != self.integrity.sha256.to_lowercase() {
                return Err(format!("evidence artifact SHA-256 mismatch: {uri}"));
            }
        }
        Ok(())
    }
}

impl EvidenceIndex {
    pub fn ingest(&mut self, record: EvidenceRecord) -> Result<(), String> {
        record.verify()?;
        if self.records.iter().any(|existing| existing.evidence_id == record.evidence_id) {
            return Err(format!("duplicate evidence_id: {}", record.evidence_id));
        }
        if let Some(id) = &record.finding_id {
            let slot = self.findings.entry(id.clone()).or_default();
            slot.evidence_ids.push(record.evidence_id.clone());
            if record.result == EvidenceResult::Fail { slot.confirmed_failures += 1; }
            slot.impact.extend(record.impact.clone());
        } else {
            self.unlinked.push(record.evidence_id.clone());
        }
        self.records.push(record);
        Ok(())
    }

    /// Accept typed evidence records or a versioned controlled-module result.
    /// Import is transactional: invalid envelopes never leave partial evidence behind.
    pub fn load_json(&mut self, input: &str) -> Result<usize, String> {
        if input.len() > MAX_EVIDENCE_BYTES {
            return Err(format!("evidence input exceeds {MAX_EVIDENCE_BYTES} bytes"));
        }
        let value: Value = serde_json::from_str(input).map_err(|e| format!("invalid evidence JSON: {e}"))?;
        let mut staged = self.clone();
        let count = if value.get("module").is_some() && value.get("schema_version").is_some() {
            staged.ingest_controlled_document(&value)?
        } else {
            let records = value.as_array().cloned()
                .or_else(|| value.get("evidence_records").and_then(Value::as_array).cloned())
                .ok_or_else(|| "expected an array, typed evidence_records object, or controlled-module result".to_string())?;
            let count = records.len();
            for item in records {
                let record: EvidenceRecord = serde_json::from_value(item).map_err(|e| format!("invalid evidence record: {e}"))?;
                staged.ingest(record)?;
            }
            count
        };
        *self = staged;
        Ok(count)
    }

    fn ingest_controlled_document(&mut self, doc: &Value) -> Result<usize, String> {
        if doc.get("schema_version").and_then(Value::as_u64) != Some(1) {
            return Err("unsupported controlled-module schema_version".into());
        }
        let module = required_string(doc, "module")?;
        if !["AUTH", "INPUT", "FILE", "RATE", "RECOVERY"].contains(&module.as_str()) {
            return Err(format!("unsupported controlled module: {module}"));
        }
        let evidence_kind = required_string(doc, "evidence_kind")?;
        let evidence_class = match evidence_kind.as_str() {
            "synthetic_fixture" => EvidenceClass::Simulated,
            "controlled_observation" => EvidenceClass::Reproduced,
            _ => return Err("unsupported controlled evidence_kind".into()),
        };
        let safety = doc.get("safety").ok_or("missing safety metadata")?;
        let network_connections = safety.get("network_connections").and_then(Value::as_u64)
            .ok_or("missing network_connections safety counter")? as usize;
        if safety.get("target_files_read").and_then(Value::as_u64) != Some(0)
            || safety.get("target_files_written").and_then(Value::as_u64) != Some(0)
            || safety.get("credentials_used").and_then(Value::as_u64) != Some(0) {
            return Err("controlled evidence reports forbidden target file or credential activity".into());
        }
        if evidence_kind == "synthetic_fixture" && network_connections != 0 {
            return Err("synthetic fixture evidence must report zero network connections".into());
        }
        if evidence_kind == "controlled_observation" && !(1..=MAX_CONTROLLED_RECORDS).contains(&network_connections) {
            return Err("controlled observations require 1 to 12 bounded network connections".into());
        }
        let assessment_id = required_string(doc, "assessment_id")?;
        let authorization_id = required_string(doc, "authorization_id")?;
        if authorization_id.len() < 8 { return Err("authorization_id is too short".into()); }
        let expires_at = required_string(doc, "expires_at")?;
        if !looks_like_timestamp(&expires_at) { return Err("expires_at must be timezone-aware ISO-8601".into()); }
        let observed_at = required_string(doc, "observed_at")?;
        if !looks_like_timestamp(&observed_at) { return Err("observed_at must be timezone-aware ISO-8601".into()); }
        let overall = parse_result(&required_string(doc, "result")?)?;
        let target_fingerprint = required_string(doc, "target_fingerprint")?;
        if target_fingerprint.len() != 64 || !target_fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("target_fingerprint must be a SHA-256 hex digest".into());
        }
        let checks = doc.get("checks").and_then(Value::as_array).ok_or("checks must be an array")?;
        let evidence = doc.get("evidence_records").and_then(Value::as_array).ok_or("evidence_records must be an array")?;
        if checks.is_empty() || checks.len() > MAX_CONTROLLED_RECORDS || checks.len() != evidence.len() {
            return Err("checks/evidence_records count mismatch or out of bounds".into());
        }
        if evidence_kind == "controlled_observation" && network_connections != evidence.len() {
            return Err("network connection count must equal the number of captured route observations".into());
        }
        let mut ids = BTreeSet::new();
        let mut passed = 0usize;
        let mut failed = 0usize;
        let mut inconclusive = 0usize;
        for (check, item) in checks.iter().zip(evidence.iter()) {
            let evidence_id = required_string(item, "evidence_id")?;
            if !ids.insert(evidence_id.clone()) || self.records.iter().any(|r| r.evidence_id == evidence_id) {
                return Err(format!("duplicate evidence_id: {evidence_id}"));
            }
            if required_string(item, "module")? != module
                || required_string(item, "classification")? != evidence_kind
                || required_string(item, "authorization_id")? != authorization_id
                || required_string(item, "target_fingerprint")? != target_fingerprint
                || required_string(item, "observed_at")? != observed_at {
                return Err("controlled evidence provenance does not match its result envelope".into());
            }
            let case_id = required_string(check, "case_id")?;
            if case_id.len() > 96 || !case_id.chars().all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c)) {
                return Err("case_id contains unsupported characters or is too long".into());
            }
            if required_string(item, "case_id")? != case_id { return Err("check/evidence case_id mismatch".into()); }
            let result = parse_result(&required_string(check, "result")?)?;
            if parse_result(&required_string(item, "result")?)? != result {
                return Err("check/evidence result mismatch".into());
            }
            let reason = required_string(check, "reason")?;
            if reason.len() > 160 || !reason.chars().all(|c| c.is_ascii_alphanumeric() || "._:-".contains(c)) {
                return Err("reason must be a short redacted machine identifier".into());
            }
            if required_string(item, "reason")? != reason { return Err("check/evidence reason mismatch".into()); }
            if evidence_kind == "controlled_observation" {
                let method = required_string(item, "method")?;
                if !["GET", "HEAD"].contains(&method.as_str()) {
                    return Err("controlled observation contains a non-read-only HTTP method".into());
                }
                if item.get("body").is_some() || item.get("response_body").is_some() {
                    return Err("raw response bodies are forbidden in evidence".into());
                }
            }
            match result {
                EvidenceResult::Pass => passed += 1,
                EvidenceResult::Fail => failed += 1,
                EvidenceResult::Inconclusive => inconclusive += 1,
                EvidenceResult::NotRun => return Err("not_run is not valid for an emitted evidence record".into()),
            }
            let finding_id = if result == EvidenceResult::Fail {
                Some(format!("ZF-{module}-{}", &format!("{:x}", Sha256::digest(format!("{module}:{case_id}").as_bytes()))[..12]))
            } else { None };
            let raw_digest = format!("{:x}", Sha256::digest(serde_json::to_vec(item).map_err(|e| e.to_string())?));
            let record = EvidenceRecord {
                evidence_id: evidence_id.clone(),
                assessment_id: assessment_id.clone(),
                test_id: format!("{module}:{case_id}"),
                finding_id: finding_id.clone(),
                classification: evidence_class.clone(),
                scope: EvidenceScope { authorization_id: authorization_id.clone(), target_fingerprint: target_fingerprint.clone(), expires_at: expires_at.clone() },
                observed_at: observed_at.clone(),
                result: result.clone(),
                impact: Vec::new(),
                integrity: EvidenceIntegrity { sha256: raw_digest, artifact_uri: None },
            };
            self.ingest(record)?;
            if let Some(id) = finding_id {
                self.controlled_findings.push(ControlledFinding {
                    finding_id: id,
                    module: module.clone(),
                    case_id: case_id.clone(),
                    title: format!("{module} policy mismatch in case {case_id}"),
                    reason,
                    status: "needs_review".into(),
                    classification: evidence_class.clone(),
                    evidence_id,
                    recommendation: "Review the authorization, expected policy and source implementation; reproduce only in the approved isolated lab before confirming a vulnerability.".into(),
                });
            }
        }
        let derived = if failed > 0 { "fail" } else if inconclusive > 0 { "inconclusive" } else { "pass" };
        if overall.as_str() != derived { return Err("module summary result does not match its checks".into()); }
        self.module_summaries.push(ModuleSummary {
            module,
            assessment_id,
            authorization_id,
            result: derived.into(),
            evidence_kind,
            observed_at,
            cases: checks.len(),
            passed,
            failed,
            inconclusive,
            network_connections,
        });
        Ok(checks.len())
    }

    pub fn impact_totals(&self) -> BTreeMap<String, f64> {
        let mut totals = BTreeMap::new();
        for finding in self.findings.values() {
            for item in &finding.impact { *totals.entry(item.dimension.clone()).or_insert(0.0) += item.value; }
        }
        totals
    }

    pub fn impact_summary(&self) -> BTreeMap<String, ImpactSummaryEntry> {
        let mut result = BTreeMap::new();
        for finding in self.findings.values() {
            for item in &finding.impact {
                let slot = result.entry(item.dimension.clone()).or_insert_with(ImpactSummaryEntry::default);
                slot.records += 1;
                slot.measured_values.push(item.clone());
            }
        }
        result
    }
}

impl EvidenceResult {
    fn as_str(&self) -> &'static str {
        match self { Self::Pass => "pass", Self::Fail => "fail", Self::Inconclusive => "inconclusive", Self::NotRun => "not_run" }
    }
}

fn required_string(value: &Value, key: &str) -> Result<String, String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
        .filter(|s| !s.trim().is_empty()).ok_or_else(|| format!("missing or invalid string field: {key}"))
}

fn parse_result(value: &str) -> Result<EvidenceResult, String> {
    match value {
        "pass" => Ok(EvidenceResult::Pass),
        "fail" => Ok(EvidenceResult::Fail),
        "inconclusive" => Ok(EvidenceResult::Inconclusive),
        _ => Err(format!("unsupported evidence result: {value}")),
    }
}

fn looks_like_timestamp(value: &str) -> bool {
    value.contains('T') && (value.ends_with('Z') || value.rfind(|c| c == '+' || c == '-').map(|i| i > 10).unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> EvidenceRecord {
        EvidenceRecord {
            evidence_id: "evidence-0001".into(), assessment_id: "assessment-1".into(), test_id: "http-headers".into(),
            finding_id: Some("ZF-1".into()), classification: EvidenceClass::Reproduced,
            scope: EvidenceScope { authorization_id: "written-auth-1".into(), target_fingerprint: "sha256:target".into(), expires_at: "2099-01-01T00:00:00Z".into() },
            observed_at: "2026-11-09T00:00:00Z".into(), result: EvidenceResult::Fail,
            impact: vec![ImpactMeasurement { dimension: "security_posture".into(), value: 2.0, unit: "missing_headers".into(), method: "bounded-test".into(), confidence: Some(0.9) }],
            integrity: EvidenceIntegrity { sha256: "a".repeat(64), artifact_uri: None },
        }
    }

    fn controlled_fixture(result: &str, evidence_kind: &str, network: u64) -> String {
        let method = if evidence_kind == "controlled_observation" { Some("HEAD") } else { None };
        let mut entry = serde_json::json!({
            "evidence_id":"fixture-evidence-0001","module":"AUTH","case_id":"private-profile",
            "classification":evidence_kind,"result":result,"reason":if result=="fail" {"unexpected_status"} else {"unauthenticated_access_denied"},
            "authorization_id":"written-auth-1","target_fingerprint":"a".repeat(64),"observed_at":"2026-11-10T00:00:00Z"
        });
        if let Some(m) = method { entry["method"] = Value::String(m.into()); }
        serde_json::json!({
            "schema_version":1,"module":"AUTH","case_id":"auth-fixture","assessment_id":"assessment-1",
            "authorization_id":"written-auth-1","expires_at":"2099-01-01T00:00:00Z",
            "target_fingerprint":"a".repeat(64),"observed_at":"2026-11-10T00:00:00Z",
            "result":if result=="fail" {"fail"} else {"pass"},"evidence_kind":evidence_kind,
            "checks":[{"case_id":"private-profile","result":result,"reason":if result=="fail" {"unexpected_status"} else {"unauthenticated_access_denied"}}],
            "evidence_records":[entry],
            "safety":{"network_connections":network,"target_files_read":0,"target_files_written":0,"credentials_used":0}
        }).to_string()
    }

    #[test]
    fn evidence_is_linked_and_impact_aggregated() {
        let mut index = EvidenceIndex::default();
        index.ingest(record()).unwrap();
        assert_eq!(index.findings["ZF-1"].confirmed_failures, 1);
        assert_eq!(index.impact_totals()["security_posture"], 2.0);
    }

    #[test]
    fn malformed_hash_is_rejected() {
        let mut r = record(); r.integrity.sha256 = "bad".into(); assert!(r.verify().is_err());
    }

    #[test]
    fn json_array_is_ingested() {
        let value = serde_json::to_string(&vec![record()]).unwrap();
        let mut index = EvidenceIndex::default();
        assert_eq!(index.load_json(&value).unwrap(), 1);
        assert_eq!(index.records.len(), 1);
    }

    #[test]
    fn synthetic_fixture_becomes_simulated_review_finding() {
        let mut index = EvidenceIndex::default();
        assert_eq!(index.load_json(&controlled_fixture("fail", "synthetic_fixture", 0)).unwrap(), 1);
        assert_eq!(index.records[0].classification, EvidenceClass::Simulated);
        assert_eq!(index.controlled_findings.len(), 1);
        assert_eq!(index.controlled_findings[0].status, "needs_review");
        assert_eq!(index.module_summaries[0].failed, 1);
    }

    #[test]
    fn read_only_network_observation_is_preserved_as_reproduced_evidence() {
        let mut index = EvidenceIndex::default();
        assert_eq!(index.load_json(&controlled_fixture("fail", "controlled_observation", 1)).unwrap(), 1);
        assert_eq!(index.records[0].classification, EvidenceClass::Reproduced);
        assert_eq!(index.module_summaries[0].network_connections, 1);
    }

    #[test]
    fn unsafe_controlled_artifact_is_rejected_atomically() {
        let mut index = EvidenceIndex::default();
        let error = index.load_json(&controlled_fixture("fail", "synthetic_fixture", 1)).unwrap_err();
        assert!(error.contains("zero network"));
        assert!(index.records.is_empty());
        assert!(index.module_summaries.is_empty());
    }
}
