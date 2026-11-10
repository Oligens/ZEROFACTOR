//! Safe primitives for comparing interpretations from two components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interpretation { pub component: String, pub canonical_value: String }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticMismatch {
    pub left_component: String, pub right_component: String, pub left_value: String, pub right_value: String,
}

pub fn compare_interpretations(left: &Interpretation, right: &Interpretation) -> Option<SemanticMismatch> {
    if left.canonical_value == right.canonical_value { return None; }
    Some(SemanticMismatch { left_component: left.component.clone(), right_component: right.component.clone(),
        left_value: left.canonical_value.clone(), right_value: right.canonical_value.clone() })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_different_component_interpretations() {
        let front = Interpretation { component: "gateway".into(), canonical_value: "/safe".into() };
        let back = Interpretation { component: "application".into(), canonical_value: "/admin".into() };
        assert!(compare_interpretations(&front, &back).is_some());
    }
}
