//! Declared attack-surface inventory; no network scanning is performed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterfaceKind { HttpApi, NetworkService, IdentityProvider, FileImport, MessageQueue, AdminConsole, BuildPipeline, Other }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttackSurfaceEntry {
    pub id: String, pub kind: InterfaceKind, pub description: String, pub trust_boundary: String, pub owner: String,
}

impl AttackSurfaceEntry {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.id.trim().is_empty() || self.description.trim().is_empty() { return Err("surface id and description are required"); }
        if self.trust_boundary.trim().is_empty() { return Err("trust boundary must be documented"); }
        Ok(())
    }
}
