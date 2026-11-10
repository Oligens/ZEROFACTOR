//! Resilience measurements are evidence records, not inferred security guarantees.
#[derive(Debug, Clone, PartialEq)]
pub struct ResilienceMeasurement {
    pub scenario_id: String, pub recovery_time_ms: Option<u64>,
    pub service_degradation_percent: Option<f64>, pub data_integrity_verified: Option<bool>,
}
impl ResilienceMeasurement {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.scenario_id.trim().is_empty() { return Err("scenario id is required"); }
        if let Some(value) = self.service_degradation_percent {
            if !value.is_finite() || !(0.0..=100.0).contains(&value) { return Err("service degradation must be between 0 and 100"); }
        }
        Ok(())
    }
}
