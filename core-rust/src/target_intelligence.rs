//! Target metadata supplied by an authorized assessor; no automatic discovery yet.
use crate::scope::TargetKind;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetProfile {
    pub id: String,
    pub name: String,
    pub kind: TargetKind,
    pub description: String,
    pub declared_technologies: Vec<String>,
    pub declared_environments: Vec<String>,
}

impl TargetProfile {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.id.trim().is_empty() || self.name.trim().is_empty() {
            return Err("target id and name are required");
        }
        if self.description.trim().is_empty() {
            return Err("target description is required");
        }
        Ok(())
    }
}
