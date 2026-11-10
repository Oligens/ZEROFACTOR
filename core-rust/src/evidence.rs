//! Evidence metadata. Cryptographic sealing and immutable storage are future adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub id: String, pub source: String, pub captured_at_utc: String,
    pub content_digest: Option<String>, pub description: String, pub integrity_verified: bool,
}
impl EvidenceRecord {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.id.trim().is_empty() || self.source.trim().is_empty() { return Err("evidence id and source are required"); }
        if self.captured_at_utc.trim().is_empty() || self.description.trim().is_empty() {
            return Err("evidence timestamp and description are required");
        }
        Ok(())
    }
}
