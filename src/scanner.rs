use crate::model::{Assessment, Check, Dependency, Finding, FindingStatus, Severity};
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const MAX_FILE_BYTES: u64 = 1_048_576;
const MAX_FILES: usize = 20_000;

#[derive(Debug, Clone)]
pub struct ScanOptions { pub max_files: usize, pub max_file_bytes: u64 }
impl Default for ScanOptions { fn default() -> Self { Self { max_files: MAX_FILES, max_file_bytes: MAX_FILE_BYTES } } }

pub fn scan_repository(root: &Path, options: &ScanOptions) -> io::Result<Assessment> {
    let root = fs::canonicalize(root)?;
    if !root.is_dir() { return Err(io::Error::new(io::ErrorKind::InvalidInput, "scan target must be a directory")); }
    let mut a = Assessment { root: root.clone(), files_examined: 0, files_skipped: 0, bytes_examined: 0, findings: Vec::new(), dependencies: Vec::new(), checks: Vec::new(), warnings: Vec::new() };
    let mut files = Vec::new();
    collect_files(&root, &root, options, &mut files, &mut a)?;
    files.sort();
    let mut seen_deps = BTreeSet::new();
    let mut sensitive_config_seen = false;
    let mut validation_patterns_seen = false;
    let mut dependency_files_seen = false;

    for path in files {
        let metadata = match fs::symlink_metadata(&path) { Ok(m) => m, Err(_) => { a.files_skipped += 1; continue; } };
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > options.max_file_bytes { a.files_skipped += 1; continue; }
        let bytes = match fs::read(&path) { Ok(b) => b, Err(_) => { a.files_skipped += 1; continue; } };
        let text = match std::str::from_utf8(&bytes) { Ok(t) => t, Err(_) => { a.files_skipped += 1; continue; } };
        a.files_examined += 1;
        a.bytes_examined += bytes.len() as u64;
        let rel = path.strip_prefix(&root).unwrap_or(&path).to_path_buf();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

        if is_manifest(name) {
            dependency_files_seen = true;
            for (ecosystem, dep_name, version) in parse_dependencies(name, text) {
                if seen_deps.insert(format!("{ecosystem}:{dep_name}:{version}")) {
                    a.dependencies.push(Dependency { ecosystem, name: dep_name, version_spec: version, manifest: rel.clone() });
                }
            }
        }
        if is_sensitive_env_file(name) {
            sensitive_config_seen = true;
            push_finding(&mut a, Finding {
                id: "ZF-CONFIG-001".into(), category: "configuration".into(), severity: Severity::High, status: FindingStatus::Observed,
                title: "Environment file is present in the scanned repository".into(), path: rel.clone(), line: None,
                evidence: "File presence observed; Git tracking and secret validity are not inferred.".into(),
                recommendation: "Keep real environment files outside version control; commit only sanitized templates.".into(),
            });
        }
        for (idx, line) in text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if looks_like_secret_assignment(&lower) || line.contains("-----BEGIN PRIVATE KEY-----") {
                sensitive_config_seen = true;
                push_finding(&mut a, Finding {
                    id: "ZF-SECRET-001".into(), category: "secrets".into(), severity: Severity::High, status: FindingStatus::NeedsReview,
                    title: "Possible hard-coded secret or private key material".into(), path: rel.clone(), line: Some(idx + 1),
                    evidence: redact_line(line),
                    recommendation: "Verify the value without copying it into reports; rotate exposed credentials and use a secret manager.".into(),
                });
            }
            if let Some((needle, severity, title, recommendation)) = validation_pattern(&lower) {
                validation_patterns_seen = true;
                push_finding(&mut a, Finding {
                    id: "ZF-VALIDATION-001".into(), category: "input_validation".into(), severity, status: FindingStatus::NeedsReview,
                    title: title.into(), path: rel.clone(), line: Some(idx + 1),
                    evidence: format!("Potential pattern: {needle}"), recommendation: recommendation.into(),
                });
            }
        }
    }

    a.dependencies.sort_by(|x, y| (&x.ecosystem, &x.name).cmp(&(&y.ecosystem, &y.name)));
    a.checks = vec![
        Check { id: "inventory".into(), description: "Repository file inventory completed".into(), weight: 1.0, tested: true, failure_factor: 0.0 },
        Check { id: "manifests".into(), description: "Common dependency manifests and direct declarations parsed".into(), weight: 1.5, tested: true, failure_factor: 0.0 },
        Check { id: "sensitive-config".into(), description: "Sensitive configuration and possible secret patterns".into(), weight: 2.0, tested: true, failure_factor: 0.0 },
        Check { id: "validation-heuristics".into(), description: "Selected source-level validation and unsafe API heuristics".into(), weight: 2.0, tested: true, failure_factor: 0.0 },
        Check { id: "dependency-audit".into(), description: "Dependency version and advisory audit".into(), weight: 3.0, tested: false, failure_factor: 0.0 },
        Check { id: "runtime-tests".into(), description: "Runtime and integration behavior verification".into(), weight: 3.0, tested: false, failure_factor: 0.0 },
        Check { id: "sandbox".into(), description: "Isolated adversarial execution and dynamic testing".into(), weight: 4.0, tested: false, failure_factor: 0.0 },
    ];
    if !dependency_files_seen { a.warnings.push("No supported dependency manifest was discovered; dependency inventory is incomplete.".into()); }
    if !sensitive_config_seen { a.warnings.push("No selected sensitive-configuration pattern was observed; this is not proof that secrets are absent.".into()); }
    if !validation_patterns_seen { a.warnings.push("No selected validation anti-pattern was observed; this is not proof that source validation is safe.".into()); }
    a.warnings.push("Dependency inventory is static and partial; no package advisory database or transitive dependency resolution is used.".into());
    Ok(a)
}

fn parse_dependencies(filename: &str, content: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut section = String::new();
    let mut in_json_deps = false;
    let mut in_go_require = false;
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") { continue; }
        if line.starts_with('[') && line.ends_with(']') { section = line.trim_matches(['[', ']']).to_string(); }
        if filename == "requirements.txt" || filename == "Pipfile" {
            if let Some((name, version)) = parse_requirement(line) { out.push(("python".into(), name, version)); }
        } else if filename == "Cargo.toml" && matches!(section.as_str(), "dependencies" | "dev-dependencies" | "build-dependencies") {
            if let Some((name, version)) = line.split_once('=') {
                let name = name.trim().trim_matches('"').to_string();
                if valid_package_name(&name) {
                    let rhs = version.trim();
                    let version = if rhs.starts_with('"') { rhs.trim_matches(',').trim_matches('"').to_string() }
                        else if let Some(pos) = rhs.find("version") { rhs[pos..].split('"').nth(1).unwrap_or("unspecified").to_string() }
                        else { "unspecified".into() };
                    out.push(("cargo".into(), name, version));
                }
            }
        } else if filename == "package.json" {
            if ["\"dependencies\"", "\"devDependencies\"", "\"peerDependencies\"", "\"optionalDependencies\""].iter().any(|k| line.contains(k)) { in_json_deps = true; continue; }
            if in_json_deps && line.starts_with('}') { in_json_deps = false; continue; }
            if in_json_deps { if let Some((name, version)) = parse_json_pair(line) { out.push(("npm".into(), name, version)); } }
        } else if filename == "go.mod" {
            if line == "require (" { in_go_require = true; continue; }
            if in_go_require && line == ")" { in_go_require = false; continue; }
            if in_go_require || line.starts_with("require ") {
                let parts: Vec<&str> = line.trim_start_matches("require ").split_whitespace().collect();
                if parts.len() >= 2 { out.push(("go".into(), parts[0].into(), parts[1].into())); }
            }
        }
    }
    out
}
fn parse_requirement(line: &str) -> Option<(String, String)> {
    let clean = line.split('#').next()?.trim();
    if clean.is_empty() || clean.starts_with('-') { return None; }
    let end = clean.find(['=', '<', '>', '!', '~', ';', '[']).unwrap_or(clean.len());
    let name = clean[..end].trim();
    if !valid_package_name(name) { return None; }
    let version = clean[end..].trim();
    Some((name.to_string(), if version.is_empty() { "unspecified".into() } else { version.into() }))
}
fn parse_json_pair(line: &str) -> Option<(String, String)> {
    let (left, right) = line.split_once(':')?;
    let name = left.trim().trim_matches('"').to_string();
    let version = right.trim().trim_end_matches(',').trim().trim_matches('"').to_string();
    if valid_package_name(&name) { Some((name, version)) } else { None }
}
fn valid_package_name(s: &str) -> bool { !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '/')) }
fn is_manifest(n: &str) -> bool { matches!(n, "Cargo.toml" | "package.json" | "requirements.txt" | "Pipfile" | "go.mod") }
fn is_sensitive_env_file(n: &str) -> bool { n == ".env" || n.starts_with(".env.") && n != ".env.example" && n != ".env.template" }
fn looks_like_secret_assignment(l: &str) -> bool {
    let key = ["password", "passwd", "secret", "api_key", "apikey", "access_token", "private_key", "client_secret"];
    key.iter().any(|k| l.contains(k)) && (l.contains('=') || l.contains(':'))
}
fn redact_line(line: &str) -> String {
    let prefix = line.split(['=', ':']).next().unwrap_or("value").trim();
    format!("{prefix} = [REDACTED]")
}
fn validation_pattern(l: &str) -> Option<(&'static str, Severity, &'static str, &'static str)> {
    if l.contains("strcpy(") || l.contains("gets(") || l.contains("sprintf(") {
        Some(("unsafe C string API", Severity::High, "Potentially unsafe C string operation", "Review bounds, lengths, and safer APIs; validate with compiler and runtime tests."))
    } else if l.contains("shell=true") || l.contains("shell: true") {
        Some(("shell=true", Severity::High, "Subprocess may invoke a shell with constructed input", "Avoid shell execution; pass an argument vector and validate each argument."))
    } else if l.contains("dangerouslysetinnerhtml") || l.contains(".innerhtml =") {
        Some(("HTML injection sink", Severity::Medium, "Potential unsafe HTML insertion sink", "Trace data provenance and apply context-aware output encoding or safe templating."))
    } else if l.contains("eval(") || l.contains("exec(") {
        Some(("dynamic eval/exec", Severity::Medium, "Dynamic code execution primitive observed", "Constrain or remove dynamic execution; validate trust boundaries and inputs."))
    } else if l.contains("verify=false") || l.contains("verify_ssl = false") || l.contains("rejectunauthorized: false") {
        Some(("TLS verification disabled", Severity::High, "TLS certificate verification may be disabled", "Enable certificate verification and configure a trusted CA where necessary."))
    } else { None }
}
fn push_finding(a: &mut Assessment, finding: Finding) { a.findings.push(finding); }
fn should_skip_dir(n: &str) -> bool {
    matches!(n, ".git" | "node_modules" | "target" | "vendor" | ".venv" | "venv" | "__pycache__" | ".next" | "dist" | "build" | ".terraform" | ".idea")
}
fn collect_files(dir: &Path, root: &Path, options: &ScanOptions, out: &mut Vec<PathBuf>, a: &mut Assessment) -> io::Result<()> {
    if out.len() >= options.max_files { a.warnings.push(format!("File limit reached ({}); remaining files were not inspected.", options.max_files)); return Ok(()); }
    let entries = match fs::read_dir(dir) { Ok(v) => v, Err(e) => { a.warnings.push(format!("Could not read {}: {e}", dir.strip_prefix(root).unwrap_or(dir).display())); return Ok(()); } };
    for entry in entries {
        if out.len() >= options.max_files { break; }
        let entry = match entry { Ok(e) => e, Err(_) => { a.files_skipped += 1; continue; } };
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if entry.file_type().map(|t| t.is_symlink()).unwrap_or(true) { a.files_skipped += 1; continue; }
        if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            if !should_skip_dir(&name) { collect_files(&path, root, options, out, a)?; }
        } else if entry.file_type().map(|t| t.is_file()).unwrap_or(false) { out.push(path); }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn redaction_never_returns_assignment_value() { assert_eq!(redact_line("API_KEY=super-secret-value"), "API_KEY = [REDACTED]"); }
    #[test] fn tls_false_is_flagged() { assert!(validation_pattern("verify=false").is_some()); }
    #[test] fn requirements_are_extracted() { assert_eq!(parse_requirement("requests>=2.31").unwrap(), ("requests".into(), ">=2.31".into())); }
    #[test] fn cargo_dependencies_are_extracted() {
        let parsed = parse_dependencies("Cargo.toml", "[dependencies]\nserde = \"1.0\"\n");
        assert_eq!(parsed[0], ("cargo".into(), "serde".into(), "1.0".into()));
    }
    #[test] fn package_json_dependencies_are_extracted() {
        let parsed = parse_dependencies("package.json", "{\n \"dependencies\": {\n \"react\": \"^18.0.0\"\n }\n}");
        assert_eq!(parsed[0], ("npm".into(), "react".into(), "^18.0.0".into()));
    }
}
