# ZEROFACTOR

**Independent Cybersecurity Validation & Adversarial Testing Platform**

ZEROFACTOR independently evaluates whether security guarantees declared by a system are actually enforced. It is designed to assess ATIBON and third-party systems without becoming part of their trusted computing base.

> Core principle: test security properties, reproduce failures safely, measure demonstrated impact, and preserve verifiable evidence.

## Project status

**Foundation phase — architecture and safe Rust MVP.** The current implementation contains deterministic assessment primitives only. It does not perform remote scanning, exploit execution, or production penetration testing.

## Architecture

- Rust assessment core: typed targets, findings, evidence, guarantees, and scenario metadata.
- Target intelligence and declared attack-surface inventory.
- Semantic comparison primitive for detecting differing component interpretations.
- Zero Factor Engine and weighted Zero Factor Index (ZFI).
- Scope and authorization validation.
- Simulation safety gates and resilience measurements.
- Deterministic text summary reporting.
- GitHub Actions for formatting, linting, and tests.

Read the architecture in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), security requirements in [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md), and the proposed metric in [docs/ZFI-METHODOLOGY.md](docs/ZFI-METHODOLOGY.md).

## Build and test

Requires a stable Rust toolchain.

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo run -p zerofactor-core -- --help
cargo run -p zerofactor-core -- zfi-demo
```

## Safety model

- Explicit authorization and declared scope are mandatory before active testing.
- Initial analyzers are local and read-only.
- Potentially disruptive scenarios are restricted to isolated, disposable labs.
- Findings distinguish hypotheses, observations, reproductions, and confirmations.
- Untested guarantees are reported separately and never counted as resistant.
- ZEROFACTOR does not automatically modify the assessed system.

## Repository layout

- core-rust/: assessment library and CLI.
- analyzers/: future least-privilege analyzers.
- sandbox/: future isolated scenario runners.
- integrations/: read-only-first system adapters.
- evidence/: evidence-store design and handling rules.
- dashboard/: planned assessment interface.
- docs/: architecture, security model, methodology, and roadmap.

## Metric disclaimer

ZFI is an experimental, coverage-aware research metric. It is not an industry standard, certification, or standalone measure of whether a system is secure. Scores must always be accompanied by scope, coverage, methodology version, evidence, and limitations.

## License

License selection is pending. Until a license is added, all rights are reserved by the repository owner.
