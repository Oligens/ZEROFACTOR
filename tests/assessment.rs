use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use zerofactor::{scan_repository, ScanOptions};

fn temp_dir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("zerofactor-test-{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
    fs::create_dir_all(&p).unwrap(); p
}

#[test]
fn scans_local_tree_and_redacts_possible_secret() {
    let root = temp_dir();
    fs::write(root.join("app.py"), "API_KEY = 'do-not-leak-this-value'\nsubprocess.run(cmd, shell=True)\n").unwrap();
    fs::write(root.join("requirements.txt"), "requests==2.0\n").unwrap();
    let a = scan_repository(&root, &ScanOptions::default()).unwrap();
    assert!(a.files_examined >= 2);
    let serialized = zerofactor::report::json(&a);
    assert!(!serialized.contains("do-not-leak-this-value"));
    assert!(serialized.contains("REDACTED"));
    assert!(a.findings.iter().any(|f| f.id == "ZF-VALIDATION-001"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn reports_incomplete_coverage_when_dynamic_tests_are_absent() {
    let root = temp_dir();
    fs::write(root.join("README.md"), "hello").unwrap();
    let a = scan_repository(&root, &ScanOptions::default()).unwrap();
    assert!(a.coverage() < 1.0);
    fs::remove_dir_all(root).unwrap();
}
