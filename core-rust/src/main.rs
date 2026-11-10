use zerofactor_core::zfi::{compute_zfi, GuaranteeAssessment, GuaranteeOutcome};

fn print_help() {
    println!("ZEROFACTOR — independent security assurance toolkit\n");
    println!("Usage:\n  zerofactor --help\n  zerofactor --version\n  zerofactor zfi-demo\n");
    println!("Current build: safe assessment primitives only; no remote scanning or exploit execution.");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version") | Some("-V") => println!("zerofactor {}", env!("CARGO_PKG_VERSION")),
        Some("zfi-demo") => {
            let sample = [
                GuaranteeAssessment { guarantee_id: "authentication".into(), weight: 3.0, outcome: GuaranteeOutcome::Resisted },
                GuaranteeAssessment { guarantee_id: "input-validation".into(), weight: 2.0, outcome: GuaranteeOutcome::PartiallyInvalidated { fraction: 0.5 },
                GuaranteeAssessment { guarantee_id: "audit-integrity".into(), weight: 3.0, outcome: GuaranteeOutcome::NotTested },
            ];
            match compute_zfi(&sample) {
                Ok(result) => {
                    println!("Illustrative ZFI: {:.3}", result.score);
                    println!("Assessed guarantees: {}", result.assessed_count);
                    println!("Not tested: {}", result.not_tested_count);
                    println!("Not-tested guarantees are excluded, never counted as resistant.");
                }
                Err(error) => eprintln!("Unable to calculate ZFI: {error:?}"),
            }
        }
        _ => print_help(),
    }
}
