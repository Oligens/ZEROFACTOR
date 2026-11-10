use std::env;
use std::fs;
use std::path::PathBuf;
use zerofactor::{report, scan_repository, ScanOptions};

fn usage() {
    println!("ZEROFACTOR Repository Intelligence Engine\n\nUsage:\n  zerofactor scan --path <local-directory> [--format md|json] [--out <file>] [--evidence <module-result.json> ...]\n\nThe scan is local and read-only. Evidence inputs may be typed records or versioned controlled-module result envelopes. Each evidence file is validated before it is added to the report.");
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") { usage(); return; }
    if args.first().map(String::as_str) != Some("scan") { eprintln!("Expected subcommand: scan"); std::process::exit(2); }
    let mut path: Option<PathBuf> = None;
    let mut format = "md".to_string();
    let mut output: Option<PathBuf> = None;
    let mut evidence_files: Vec<PathBuf> = Vec::new();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--path" => { i += 1; path = args.get(i).map(PathBuf::from); }
            "--format" => { i += 1; if let Some(v) = args.get(i) { format = v.clone(); } }
            "--out" => { i += 1; output = args.get(i).map(PathBuf::from); }
            "--evidence" => { i += 1; if let Some(v) = args.get(i) { evidence_files.push(PathBuf::from(v)); } else { eprintln!("Missing path after --evidence"); std::process::exit(2); } }
            other => { eprintln!("Unknown argument: {other}"); std::process::exit(2); }
        }
        i += 1;
    }
    let Some(path) = path else { eprintln!("Missing required --path"); std::process::exit(2); };
    if format != "md" && format != "json" { eprintln!("--format must be md or json"); std::process::exit(2); }
    match scan_repository(&path, &ScanOptions::default()) {
        Ok(mut assessment) => {
            for source in evidence_files {
                let size = match fs::metadata(&source) {
                    Ok(metadata) => metadata.len(),
                    Err(error) => { eprintln!("Cannot inspect evidence file {}: {error}", source.display()); std::process::exit(1); }
                };
                if size > 1_048_576 {
                    eprintln!("Evidence file exceeds 1 MiB limit: {}", source.display());
                    std::process::exit(1);
                }
                let raw = match fs::read_to_string(&source) {
                    Ok(raw) => raw,
                    Err(error) => { eprintln!("Cannot read evidence file {}: {error}", source.display()); std::process::exit(1); }
                };
                match assessment.evidence.load_json(&raw) {
                    Ok(count) => eprintln!("Loaded and verified {count} evidence records from {}", source.display()),
                    Err(error) => { eprintln!("Evidence ingestion failed for {}: {error}", source.display()); std::process::exit(1); }
                }
            }
            let content = if format == "json" { report::json(&assessment) } else { report::markdown(&assessment) };
            if let Some(destination) = output {
                if let Err(error) = fs::write(&destination, content) {
                    eprintln!("Could not write report {}: {error}", destination.display());
                    std::process::exit(1);
                }
                println!("Report written to {}", destination.display());
            } else {
                print!("{content}");
            }
        }
        Err(error) => { eprintln!("Scan failed: {error}"); std::process::exit(1); }
    }
}
