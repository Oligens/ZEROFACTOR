use crate::model::{Assessment, Dependency, Finding};
use std::fmt::Write;

pub fn markdown(a: &Assessment) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# ZEROFACTOR Repository Assessment\n");
    let _ = writeln!(out, "- **Target:** `{}`", a.root.display());
    let _ = writeln!(out, "- **Files examined:** {}", a.files_examined);
    let _ = writeln!(out, "- **Files skipped:** {}", a.files_skipped);
    let _ = writeln!(out, "- **Bytes examined:** {}", a.bytes_examined);
    let _ = writeln!(out, "- **Components discovered:** {}", a.components.len());
    let _ = writeln!(out, "- **Direct dependencies discovered:** {}", a.dependencies.len());
    let _ = writeln!(out, "- **Findings:** {}\n", a.findings.len());
    match a.zfi() {
        Some(v) => { let _ = writeln!(out, "- **Source-evidence ZFI:** {:.1}/100", v); }
        None => { let _ = writeln!(out, "- **Source-evidence ZFI:** not available (no confirmed source-level failure recorded)"); }
    }
    let _ = writeln!(out, "- **Coverage:** {:.1}%\n", a.coverage() * 100.0);
    let _ = writeln!(out, "> ZFI is an experimental evidence indicator, not a probability, certification, or proof of security. Heuristic findings require human review.\n");
    let _ = writeln!(out, "## Repository components\n| Path | Classification |\n|---|---|");
    if a.components.is_empty() { let _ = writeln!(out, "| — | No top-level component directory discovered |"); }
    for component in &a.components { let _ = writeln!(out, "| {} | {} |", component.path.display(), component.kind); }
    let _ = writeln!(out, "\n## Direct dependencies\n| Ecosystem | Package | Declared version | Manifest |\n|---|---|---|---|");
    if a.dependencies.is_empty() { let _ = writeln!(out, "| — | No supported declaration parsed | — | — |"); }
    for d in &a.dependencies { write_dependency(&mut out, d); }
    let _ = writeln!(out, "\n## Findings\n");
    if a.findings.is_empty() { let _ = writeln!(out, "No selected heuristic matched. This is not proof of absence of vulnerabilities.\n"); }
    for f in &a.findings { write_finding(&mut out, f); }
    let _ = writeln!(out, "## Coverage by check\n| Check | Tested | Weight | Failure factor |\n|---|---:|---:|---:|");
    for c in &a.checks { let _ = writeln!(out, "| {} | {} | {:.1} | {:.2} |", c.id, c.tested, c.weight, c.failure_factor); }
    if !a.warnings.is_empty() {
        let _ = writeln!(out, "\n## Limitations and warnings\n");
        for w in &a.warnings { let _ = writeln!(out, "- {w}"); }
    }
    out
}
fn write_dependency(out: &mut String, d: &Dependency) {
    let _ = writeln!(out, "| {} | {} | {} | {} |", d.ecosystem, d.name, d.version_spec, d.manifest.display());
}
fn write_finding(out: &mut String, f: &Finding) {
    let _ = writeln!(out, "### [{}] {} — {}\n", f.severity.as_str().to_uppercase(), f.title, f.status.as_str());
    let _ = writeln!(out, "- **ID:** {}", f.id);
    let _ = writeln!(out, "- **Location:** {}{}", f.path.display(), f.line.map(|n| format!(":{n}")).unwrap_or_default());
    let _ = writeln!(out, "- **Category:** {}", f.category);
    let _ = writeln!(out, "- **Evidence:** `{}`", f.evidence.replace('`', "'"));
    let _ = writeln!(out, "- **Recommendation:** {}\n", f.recommendation);
}
pub fn json(a: &Assessment) -> String {
    let findings = a.findings.iter().map(|f| format!(
        "{{\"id\":{},\"category\":{},\"severity\":{},\"status\":{},\"title\":{},\"path\":{},\"line\":{},\"evidence\":{},\"recommendation\":{}}}",
        q(&f.id), q(&f.category), q(f.severity.as_str()), q(f.status.as_str()), q(&f.title), q(&f.path.display().to_string()),
        f.line.map(|n| n.to_string()).unwrap_or_else(|| "null".into()), q(&f.evidence), q(&f.recommendation)
    )).collect::<Vec<_>>().join(",");
    let components = a.components.iter().map(|c| format!("{{\\"path\\":{},\\"kind\\":{}}}", q(&c.path.display().to_string()), q(&c.kind))).collect::<Vec<_>>().join(",");
    let dependencies = a.dependencies.iter().map(|d| format!(
        "{{\"ecosystem\":{},\"name\":{},\"version_spec\":{},\"manifest\":{}}}",
        q(&d.ecosystem), q(&d.name), q(&d.version_spec), q(&d.manifest.display().to_string())
    )).collect::<Vec<_>>().join(",");
    let checks = a.checks.iter().map(|c| format!(
        "{{\"id\":{},\"description\":{},\"weight\":{},\"tested\":{},\"failure_factor\":{}}}",
        q(&c.id), q(&c.description), c.weight, c.tested, c.failure_factor
    )).collect::<Vec<_>>().join(",");
    format!("{{\"target\":{},\"files_examined\":{},\"files_skipped\":{},\"bytes_examined\":{},\"zfi\":{},\"coverage\":{},\"components\":[{}],\"dependencies\":[{}],\"findings\":[{}],\"checks\":[{}],\"warnings\":[{}]}}",
        q(&a.root.display().to_string()), a.files_examined, a.files_skipped, a.bytes_examined,
        a.zfi().map(|v| v.to_string()).unwrap_or_else(|| "null".into()), a.coverage(), components, dependencies, findings, checks,
        a.warnings.iter().map(|w| q(w)).collect::<Vec<_>>().join(","))
}
fn q(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() { match c { '"' => out.push_str("\\\""), '\\' => out.push_str("\\\\"), '\n' => out.push_str("\\n"), '\r' => out.push_str("\\r"), '\t' => out.push_str("\\t"), c if c.is_control() => out.push(' '), c => out.push(c) } }
    out.push('"'); out
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Assessment, Check};
    use std::path::PathBuf;
    #[test] fn json_is_valid_shape_and_escapes_quotes() {
        let a = Assessment { root: PathBuf::from("/tmp/a"), files_examined: 1, files_skipped: 0, bytes_examined: 2,
            findings: vec![], components: vec![], dependencies: vec![], checks: vec![Check { id: "x".into(), description: "a \"quote\"".into(), weight: 1.0, tested: true, failure_factor: 0.0 }], warnings: vec![] };
        let j = json(&a);
        assert!(j.contains("\\\"quote\\\""));
        assert!(j.starts_with("{"));
    }
}
