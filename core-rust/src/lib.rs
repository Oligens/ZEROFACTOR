#![forbid(unsafe_code)]

//! ZEROFACTOR's initial assessment primitives.
//! Deterministic, read-only building blocks; no exploit execution or remote probing.

pub mod attack_surface;
pub mod evidence;
pub mod model;
pub mod resilience;
pub mod reporting;
pub mod scope;
pub mod semantic_engine;
pub mod simulation;
pub mod target_intelligence;
pub mod zero_factor;
pub mod zfi;

pub use model::{Finding, FindingStatus, Severity};
