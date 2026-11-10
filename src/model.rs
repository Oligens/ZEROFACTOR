use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity { Critical, High, Medium, Low, Info }
impl Severity {
    pub fn as_str(self) -> &'static str { match self { Self::Critical => "critical", Self::High => "high", Self::Medium => "medium", Self::Low => "low", Self::Info => "info" } }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingStatus { Observed, NeedsReview }
impl FindingStatus {
    pub fn as_str(self) -> &'static str { match self { Self::Observed => "observed", Self::NeedsReview => "needs_review" } }
}
#[derive(Debug, Clone)]
pub struct Finding {
    pub id: String, pub category: String, pub severity: Severity, pub status: FindingStatus,
    pub title: String, pub path: PathBuf, pub line: Option<usize>, pub evidence: String, pub recommendation: String,
}
#[derive(Debug, Clone)]
pub struct Dependency {
    pub ecosystem: String, pub name: String, pub version_spec: String, pub manifest: PathBuf,
}
#[derive(Debug, Clone)]
pub struct Check {
    pub id: String, pub description: String, pub weight: f64, pub tested: bool,
    /// 0.0 means no confirmed failure; 1.0 means the source-level criterion is demonstrably unmet.
    /// Heuristic findings remain NeedsReview and do not automatically set this value.
    pub failure_factor: f64,
}
#[derive(Debug, Clone)]
pub struct Assessment {
    pub root: PathBuf, pub files_examined: usize, pub files_skipped: usize, pub bytes_examined: u64,
    pub findings: Vec<Finding>, pub dependencies: Vec<Dependency>, pub checks: Vec<Check>, pub warnings: Vec<String>,
}
impl Assessment {
    pub fn total_weight(&self) -> f64 { self.checks.iter().map(|c| c.weight).sum() }
    pub fn tested_weight(&self) -> f64 { self.checks.iter().filter(|c| c.tested).map(|c| c.weight).sum() }
    pub fn coverage(&self) -> f64 { let total = self.total_weight(); if total == 0.0 { 0.0 } else { self.tested_weight() / total } }
    /// Experimental source-evidence index; unavailable until at least one failure is confirmed.
    pub fn zfi(&self) -> Option<f64> {
        let tested = self.tested_weight();
        if tested == 0.0 { return None; }
        let failed: f64 = self.checks.iter().filter(|c| c.tested).map(|c| c.weight * c.failure_factor.clamp(0.0, 1.0)).sum();
        if failed == 0.0 { None } else { Some((failed / tested) * 100.0) }
    }
}
