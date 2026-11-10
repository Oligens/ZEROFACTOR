# ZEROFACTOR

**Independent Cybersecurity Validation & Adversarial Testing Platform**

ZEROFACTOR evaluates whether security guarantees declared by a system are supported by source evidence and controlled tests. It is independent of the systems it assesses and is designed to evaluate ATIBON and third-party repositories without becoming part of their trusted computing base.

> Core principle: test security properties, reproduce failures safely, measure demonstrated impact, and preserve verifiable evidence.

## Current status

**Phase 1 — Repository Intelligence MVP implemented on a feature branch.** The first engine performs bounded, local, read-only source inspection. It does not execute target code, clone repositories, install packages, contact remote services, or modify the target.

## Quick start

Requirements: Rust stable (edition 2021).

```bash
cargo test
cargo run -- scan --path ../atibon --format md --out reports/atibon-assessment.md
cargo run -- scan --path ../atibon --format json --out reports/atibon-assessment.json
```

Or build a binary:

```bash
cargo build --release
./target/release/zerofactor scan --path /path/to/repository
```

The scan target must be a local directory. Only scan repositories you own or are explicitly authorized to assess.

## What the first engine checks

- Bounded local file inventory; skips common generated and vendored directories, symlinks, files over 1 MiB, and scans beyond the 20,000-file cap.
- Direct dependency declaration discovery for common Cargo, npm, Python requirements/Pipfile and Go manifests. This is inventory only, not a vulnerability/advisory audit or complete transitive dependency graph.
- Environment-file presence and possible hard-coded secret patterns; values are redacted in reports.
- Selected source-level heuristics for unsafe C string APIs, shell execution, dynamic evaluation, HTML insertion and disabled TLS verification.
- Evidence with stable IDs, relative paths, line numbers, review status, redacted evidence and remediation guidance.
- JSON and Markdown reports, experimental weighted ZFI and explicit test coverage.

## Interpreting ZFI and coverage

The experimental ZFI is calculated from explicitly recorded weighted check failures over tested check weight. Coverage is tested weight over all declared check weight. The ZFI is reported as unavailable until a confirmed source-level failure is recorded. Heuristic matches are marked `needs_review` and do not automatically count as confirmed failures. Untested dependency advisory, runtime and sandbox checks reduce coverage; they must never be interpreted as passing.

ZFI is not a probability, certification, compliance attestation, or proof of security. A low score with low coverage is not evidence that a system is safe.

## Safety model

- Explicit authorization and declared scope are mandatory for assessments.
- Initial analyzers are local and read-only.
- Potentially disruptive scenarios belong in isolated, disposable laboratories.
- Findings distinguish observed source patterns from confirmed runtime impact.
- ZEROFACTOR never modifies the assessed system or its security policy automatically.

## Architecture and governance

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Roadmap](docs/ROADMAP.md)

## License

License selection is pending. Until a license is added, all rights are reserved by the repository owner.
