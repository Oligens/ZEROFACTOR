use std::fmt;

/// Impact classification, not a claim that an issue is exploitable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity { Informational, Low, Medium, High, Critical }

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Informational => "informational", Self::Low => "low", Self::Medium => "medium",
            Self::High => "high", Self::Critical => "critical",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStatus { Hypothesis, Observed, Reproduced, Confirmed, NotReproducible, NotTested }

/// Keeps observations distinct from reproduced and confirmed findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub category: String,
    pub severity: Severity,
    pub status: FindingStatus,
    pub evidence_refs: Vec<String>,
    pub affected_guarantee: Option<String>,
    pub impact: String,
    pub remediation: String,
}

impl Finding {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.id.trim().is_empty() || self.title.trim().is_empty() { return Err("finding id and title are required"); }
        if self.impact.trim().is_empty() { return Err("impact description is required"); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finding_rejects_missing_identity() {
        let finding = Finding { id: String::new(), title: "Example".into(), category: "logic".into(),
            severity: Severity::Low, status: FindingStatus::Hypothesis, evidence_refs: vec![],
            affected_guarantee: None, impact: "No confirmed impact".into(), remediation: "Investigate".into() };
        assert!(finding.validate().is_err());
    }
}
