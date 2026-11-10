# ZEROFACTOR

**Independent Cybersecurity Validation & Adversarial Testing Platform**

ZEROFACTOR evaluates whether security guarantees declared by a system are supported by source evidence and controlled tests. It is independent of assessed systems and is designed to assess ATIBON and third-party repositories without becoming part of their trusted computing base.

> Core principle: test security properties, reproduce failures safely, measure demonstrated impact, and preserve verifiable evidence.

## Current status

The repository intelligence MVP is merged into main. This feature branch adds the first security-platform foundations: CI dependency/advisory checks, SPDX and CycloneDX SBOM artifact generation, a guarded gVisor execution launcher, impact/evidence methodology, and a local JSON dashboard.

**These additions are foundations, not a claim that all eight platform objectives are complete.** The local scanner still parses selected direct dependency declarations only. Complete transitive resolution, complete cross-ecosystem CVE coverage, reachability analysis, verified exploitability, production-grade sandbox orchestration, active penetration-test modules, measured attack impact, and a hosted multi-user dashboard remain incomplete and require validation.

## Quick start

Requirements: Rust stable (edition 2021).

```bash
cargo test
cargo run -- scan --path ../atibon --format md --out reports/atibon-assessment.md
cargo run -- scan --path ../atibon --format json --out reports/atibon-assessment.json
```

Import the JSON report into dashboard/index.html to view local assessment metrics.

## Security and supply-chain checks

The GitHub Actions workflow in .github/workflows/security-supply-chain.yml runs cargo-audit, OSV-Scanner, and generates SPDX JSON and CycloneDX JSON SBOM artifacts. OSV-Scanner is currently non-blocking while its baseline is established. Review every advisory and generated SBOM; scanner coverage is ecosystem- and lockfile-dependent.

Local tools:

```bash
cargo install cargo-audit --locked
cargo audit
osv-scanner scan source -r .
syft dir:. -o spdx-json=sbom.spdx.json
syft dir:. -o cyclonedx-json=sbom.cdx.json
```

## Isolated execution

sandbox/run-isolated.sh requires Docker with gVisor runsc registered and refuses default-runtime fallback. It enforces no network, read-only target/root filesystem, dropped capabilities, seccomp, no-new-privileges, unprivileged execution, and resource limits. It requires an explicit, unexpired scope file and prebuilt image. Use only disposable targets with written authorization. This launcher is not yet a production multi-tenant sandbox; validate isolation independently and prefer a dedicated VM/host.

## What the original static engine checks

- Bounded local file inventory and top-level component classification.
- Partial direct dependency declaration discovery for Cargo, npm, Python and Go.
- Environment-file presence and possible hard-coded secret patterns, with redaction.
- Selected source-level heuristics for unsafe APIs and validation patterns.
- Findings with relative paths, line numbers, review status and recommendations.
- JSON and Markdown reports, experimental weighted ZFI and explicit coverage.

## Evidence interpretation

Dependency states must be distinguished: declared, resolved, advisory-matched, reachability-assessed, and exploitability-demonstrated. A CVE match is not proof of reachability or exploitation. Heuristic findings require human review.

ZFI is an experimental evidence indicator, not a probability, certification, compliance attestation, or proof of security. A clean report with low coverage does not establish safety.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Dependency intelligence and SBOM](docs/DEPENDENCY_INTELLIGENCE.md)
- [Exploitability and impact methodology](docs/EXPLOITABILITY_AND_IMPACT.md)
- [Sandbox instructions](sandbox/README.md)
- [Dashboard instructions](docs/DASHBOARD.md)

Only assess systems you own or are explicitly authorized to test. ZEROFACTOR never automatically modifies the assessed system.

## License

License selection is pending. Until a license is added, all rights are reserved by the repository owner.
