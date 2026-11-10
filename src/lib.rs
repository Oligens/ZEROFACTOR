//! ZEROFACTOR's first operational engine: bounded, local, read-only repository analysis.

pub mod model;
pub mod report;
pub mod scanner;

pub use model::{Assessment, Check, Finding, FindingStatus, Severity};
pub use scanner::{scan_repository, ScanOptions};
