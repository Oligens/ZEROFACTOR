use std::env;
use std::fs;
use std::path::PathBuf;
use zerofactor::{ingest_controlled_result, report, scan_repository, ScanOptions};

fn usage() {
    println!("ZEROFACTOR Repository Intelligence Engine\n\nUsage:\n  zerofactor scan --path <local-directory> [--format md|json] [--out <file>] [--evidence <evidence.json>] [--controlled-result <module-result.json>] [--assessment-id <id>]\n\nThe scan is local and read-only. Controlled results are offline synthetic fixtures only; importing them never contacts a target.");
}
fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") { usage(); return; }
    if args.first().map(String::as_str) != Some("scan") { eprintln!("Expected subcommand: scan"); std::process::exit(2); }
    let mut path: Option<PathBuf> = None;
    let mut format = "md".to_string();
    let mut output: Option<PathBuf> = None;
    let mut evidence_file: Option<PathBuf> = None;
    let mut controlled_results: Vec<PathBuf> = Vec::new();
    let mut assessment_id = "controlled-assessment".to_string();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--path" => { i += 1; path = args.get(i).map(PathBuf::from); }
            "--format" => { i += 1; if let Some(v) = args.get(i) { format = v.clone(); } }
            "--out" => { i += 1; output = args.get(i).map(PathBuf::from); }
            "--evidence" => { i += 1; evidence_file = args.get(i).map(PathBuf::from); }
            "--controlled-result" => { i += 1; if let Some(v) = args.get(i) { controlled_results.push(PathBuf::from(v)); } else { eprintln!("--controlled-result requires a file"); std::process::exit(2); } }
            "--assessment-id" => { i += 1; if let Some(v) = args.get(i) { assessment_id = v.clone(); } else { eprintln!("--assessment-id requires a value"); std::process::exit(2); } }
            other => { eprintln!("Unknown argument: {other}"); std::process::exit(2); }
        }
        i += 1;
    }
    let Some(path) = path else { eprintln!("Missing required --path"); std::process::exit(2); };
    if format != "md" && format != "json" { eprintln!("--format must be md or json"); std::process::exit(2); }
    match scan_repository(&path, &ScanOptions::default()) {
        Ok(mut a) => {
            if let Some(source) = evidence_file {
                match fs::read_to_string(&source).and_then(|raw| a.evidence.load_json(&raw).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))) {
                    Ok(count) => eprintln!("Loaded and verified {count} evidence records from {}", source.display()),
                    Err(e) => { eprintln!("Evidence ingestion failed: {e}"); std::process::exit(1); }
                }
            }
            for source in controlled_results {
                match ingest_controlled_result(&mut a.evidence, &source, &assessment_id) {
                    Ok(imported) => {
                        a.findings.extend(imported.findings);
                        if imported.inconclusive > 0 {
                            a.warnings.push(format!("{} module case(s) from {} are inconclusive; no finding was asserted.", imported.inconclusive, source.display()));
                        }
                        eprintln!("Imported {} {} synthetic evidence record(s) from {} (case {}).", imported.records, imported.module, source.display(), imported.case_id);
                    }
                    Err(e) => { eprintln!("Controlled evidence import failed for {}: {e}", source.display()); std::process::exit(1); }
                }
            }
            let content = if format == "json" { report::json(&a) } else { report::markdown(&a) };
            if let Some(dest) = output {
                if let Err(e) = fs::write(&dest, content) { eprintln!("Could not write report {}: {e}", dest.display()); std::process::exit(1); }
                println!("Report written to {}", dest.display());
            } else { print!("{content}"); }
        }
        Err(e) => { eprintln!("Scan failed: {e}"); std::process::exit(1); }
    }
}
