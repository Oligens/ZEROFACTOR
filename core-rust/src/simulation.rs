//! Scenario declarations and safety gates; no payload execution is implemented.
use crate::scope::{AssessmentScope, ScopeError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode { ReadOnly, IsolatedLab, Active }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scenario { pub id: String, pub description: String, pub mode: ExecutionMode, pub may_disrupt_service: bool }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimulationError { InvalidScope(ScopeError), DisruptiveScenarioRequiresLab, ActiveModeNotAuthorized }

pub fn validate_scenario(scope: &AssessmentScope, scenario: &Scenario) -> Result<(), SimulationError> {
    scope.validate().map_err(SimulationError::InvalidScope)?;
    if scenario.may_disrupt_service && scenario.mode != ExecutionMode::IsolatedLab {
        return Err(SimulationError::DisruptiveScenarioRequiresLab);
    }
    if scenario.mode == ExecutionMode::Active && !scope.active_testing_allowed {
        return Err(SimulationError::ActiveModeNotAuthorized);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::TargetKind;
    #[test]
    fn disruptive_scenario_requires_isolated_lab() {
        let scope = AssessmentScope { target_id: "repo".into(), target_kind: TargetKind::LocalRepository,
            owner_or_authorizer: "owner".into(), scope_statement: "local static review".into(),
            authorization_reference: None, active_testing_allowed: false };
        let scenario = Scenario { id: "resource-exhaustion".into(), description: "bounded lab test".into(),
            mode: ExecutionMode::ReadOnly, may_disrupt_service: true };
        assert_eq!(validate_scenario(&scope, &scenario), Err(SimulationError::DisruptiveScenarioRequiresLab));
    }
}
