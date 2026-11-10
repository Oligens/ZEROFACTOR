//! Scope and authorization primitives. Active runners must enforce these checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind { LocalRepository, LocalHost, IsolatedLab, RemoteSystem }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessmentScope {
    pub target_id: String,
    pub target_kind: TargetKind,
    pub owner_or_authorizer: String,
    pub scope_statement: String,
    pub authorization_reference: Option<String>,
    pub active_testing_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeError { MissingTarget, MissingAuthorizer, MissingScopeStatement, ActiveTestingNeedsExplicitAuthorization }

impl AssessmentScope {
    pub fn validate(&self) -> Result<(), ScopeError> {
        if self.target_id.trim().is_empty() { return Err(ScopeError::MissingTarget); }
        if self.owner_or_authorizer.trim().is_empty() { return Err(ScopeError::MissingAuthorizer); }
        if self.scope_statement.trim().is_empty() { return Err(ScopeError::MissingScopeStatement); }
        if self.active_testing_allowed && self.authorization_reference.as_deref().unwrap_or("").trim().is_empty() {
            return Err(ScopeError::ActiveTestingNeedsExplicitAuthorization);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn active_test_requires_written_authorization_reference() {
        let scope = AssessmentScope { target_id: "customer-api".into(), target_kind: TargetKind::RemoteSystem,
            owner_or_authorizer: "system owner".into(), scope_statement: "approved staging host only".into(),
            authorization_reference: None, active_testing_allowed: true };
        assert_eq!(scope.validate(), Err(ScopeError::ActiveTestingNeedsExplicitAuthorization));
    }
}
