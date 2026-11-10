//! ZEROFACTOR's bounded repository analysis and evidence engine.
pub mod evidence;
pub mod model;
pub mod report;
pub mod scanner;

pub use evidence::{EvidenceClass, EvidenceIndex, EvidenceRecord, EvidenceResult, FindingEvidence, ImpactMeasurement};
pub use model::{Assessment, Check, Component, Dependency, Finding, FindingStatus, Severity};
pub use scanner::{scan_repository, ScanOptions};
