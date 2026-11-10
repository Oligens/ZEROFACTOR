use crate::model::{Assessment, Check, Finding, FindingStatus, Severity};
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const MAX_FILE_BYTES: u64 = 1_048_576;
const MAX_FILES: usize = 20_000;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_files: usize,
    pub max_file_bytes: u64,
}
impl Default for ScanOptions {
    fn default() -> Self { Self { max_files: MAX_FILES, max_file_bytes: MAX_FILE_BYTES } }
}

pub fn scan_repository(root: &Path, options: &ScanOptions) -> io::Result<Assessment> {
    let root = fs::canonicalize(root)?;
    if !root.is_dir() { return Err(io::Error::new(io::ErrorKind::InvalidInput, "scan target must be a directory")); }

    let mut assessment = Assessment {
        root: root.clone(), files_examined: 0, files_skipped: 0, bytes_examined: 0,
        findings: Vec::new(), checks: Vec::new(), warnings: Vec::new(),
    };
    let mut files = Vec::new();
    collect_files(&root, &root, options, &mut files, &mut assessment)?;
    files.sort();

    let mut manifests = BTreeSet::new();
    let mut sensitive_config_seen = false;
    let mut validation_patterns_seen = false;
    let mut dependency_files_seen = false;

    for path in files {
        let metadata = match fs::symlink_metadata(&path) { Ok(m) => m, Err(_) => { assessment.files_skipped += 1; continue; } };
        if metadata.file_type().is_symlink() || !metadata.is_file() { assessment.files_skipped += 1; continue; }
        if metadata.len() > options.max_file_bytes { assessment.files_skipped += 1; continue; }
        let bytes = match fs::read(&path) { Ok(b) => b, Err(_) => { assessment.files_skipped += 1; continue; } };
        assessment.files_examined += 1;
        assessment.bytes_examined += bytes.len() as u64;
        let rel = path.strip_prefix(&root).unwrap_or(&path).to_path_buf();
        let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");

        if is_manifest(name) { manifests.insert(name.to_string()); dependency_files_seen = true; }
        if is_sensitive_env_file(name) {
            sensitive_config_seen = true;
            push_finding(&mut assessment, "ZF-CONFIG-001", "configuration", Severity::High, FindingStatus::Observed,
                "Environment file is present in the scanned repository", &rel, None,
                "File presence observed; Git tracking and secret validity are not inferred.",
                "Keep real environment files outside version control; commit only sanitized templates.");
        }

        let text = match std::str::from_utf8(&bytes) {
            Ok(t) => t,
            Err(_) => { assessment.files_skipped += 1; continue; }
        };
        for (idx, line) in text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            if looks_like_secret_assignment(&lower) || line.contains("-----BEGIN PRIVATE KEY-----") {
                sensitive_config_seen = true;
                push_finding(&mut assessment, "ZF-SECRET-001", "secrets", Severity::High, FindingStatus::NeedsReview,
                    "Possible hard-coded secret or private key material", &rel, Some(idx + 1),
                    &redact_line(line),
                    "Verify the value without copying it into reports; rotate exposed credentials and use a secret manager.");
            }
            if let Some((needle, severity, title, recommendation)) = validation_pattern(&lower) {
                validation_patterns_seen = true;
                push_finding(&mut assessment, "ZF-VALIDATION-001", "input_validation", severity, FindingStatus::NeedsReview,
                    title, &rel, Some(idx + 1), &format!("Potential pattern: {needle}"),
                    recommendation);
            }
        }
    }

    assessment.checks = vec![
        Check { id: "inventory".into(), description: "Repository file inventory completed".into(), weight: 1.0, tested: true, failure_factor: 0.0 },
        Check { id: "manifests".into(), description: "Common dependency manifest discovery".into(), weight: 1.5, tested: true, failure_factor: 0.0 },
        Check { id: "sensitive-config".into(), description: "Sensitive configuration and possible secret patterns".into(), weight: 2.0, tested: true, failure_factor: if sensitive_config_seen { 0.0 } else { 0.0 } },
        Check { id: "validation-heuristics".into(), description: "Selected source-level validation and unsafe API heuristics".into(), weight: 2.0, tested: true, failure_factor: 0.0 },
        Check { id: "dependency-audit".into(), description: "Dependency version and advisory audit".into(), weight: 3.0, tested: false, failure_factor: 0.0 },
        Check { id: "runtime-tests".into(), description: "Runtime and integration behavior verification".into(), weight: 3.0, tested: false, failure_factor: 0.0 },
        Check { id: "sandbox".into(), description: "Isolated adversarial execution and dynamic testing".into(), weight: 4.0, tested: false, failure_factor: 0.0 },
    ];
    if !dependency_files_seen { assessment.warnings.push("No supported dependency manifest was discovered; dependency audit coverage remains untested.".into()); }
    if !sensitive_config_seen { assessment.warnings.push("No selected sensitive-configuration pattern was observed; this is not proof that secrets are absent.".into()); }
    if !validation_patterns_seen { assessment.warnings.push("No selected validation anti-pattern was observed; this is not proof that source validation is safe.".into()); }
    Ok(assessment)
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
            if should_skip_dir(&name) { continue; }
            collect_files(&path, root, options, out, a)?;
        } else if entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            out.push(path);
        }
    }
    Ok(())
}

fn should_skip_dir(n: &str) -> bool {
    matches!(n, ".git" | "node_modules" | "target" | "vendor" | ".venv" | "venv" | "__pycache__" | ".next" | "dist" | "build" | ".terraform" | ".idea")
}
fn is_manifest(n: &str) -> bool {
    matches!(n, "Cargo.toml" | "Cargo.lock" | "package.json" | "package-lock.json" | "pnpm-lock.yaml" | "yarn.lock" | "pyproject.toml" | "requirements.txt" | "Pipfile" | "Pipfile.lock" | "go.mod" | "go.sum" | "pom.xml" | "build.gradle" | "Gemfile" | "composer.json")
}
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
fn push_finding(a: &mut Assessment, id: &str, category: &str, severity: Severity, status: FindingStatus, title: &str, path: &Path, line: Option<usize>, evidence: &str, recommendation: &str) {
    a.findings.push(Finding { id: id.into(), category: category.into(), severity, status, title: title.into(), path: path.to_path_buf(), line, evidence: evidence.into(), recommendation: recommendation.into() });
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn redaction_never_returns_assignment_value() {
        assert_eq!(redact_line("API_KEY=super-secret-value"), "API_KEY = [REDACTED]");
    }
    #[test] fn ignored_directories_are_explicit() {
        assert!(should_skip_dir("node_modules"));
        assert!(!should_skip_dir("src"));
    }
    #[test] fn manifests_are_detected() { assert!(is_manifest("Cargo.toml")); }
    #[test] fn tls_false_is_flagged() { assert!(validation_pattern("verify=false").is_some()); }
}
