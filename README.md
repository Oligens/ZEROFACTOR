# ZEROFACTOR

**Independent Cybersecurity Validation & Adversarial Testing Platform**

ZEROFACTOR evaluates whether security guarantees declared by a system are supported by source evidence and controlled tests. It is independent of assessed systems and is designed to assess ATIBON and third-party repositories without becoming part of their trusted computing base.

> Core principle: test security properties, reproduce failures safely, measure demonstrated impact, and preserve verifiable evidence.

## Current status

The repository intelligence MVP is merged into main. The current feature branch adds dependency lockfile graph extraction, OSV advisory normalization, a manual gVisor host smoke-test workflow, a structured evidence/impact schema and local project/history dashboard foundations.

**These additions are not a claim that all platform objectives are complete.** Native graph extraction currently covers Cargo and npm dependency edges, with partial exact-version inventory for Poetry, uv, Pipfile and Go checksums. OSV-Scanner provides additional ecosystem coverage using its supported lockfile extractors. Full cross-ecosystem graph completeness, multi-database CVE coverage, reachability analysis, verified exploitability, independent gVisor escape validation, production penetration-test modules, cryptographic evidence chain of custody and secure hosted multi-user RBAC remain incomplete.

## Quick start

Requirements: Rust stable (edition 2021).

```bash
cargo test
cargo run -- scan --path ../atibon --format md --out reports/atibon-assessment.md
cargo run -- scan --path ../atibon --format json --out reports/atibon-assessment.json
```

Lockfile graph inventory (Python 3.11+):

```bash
python3 scripts/dependency_graph.py ../atibon --output reports/dependency-graph.json
```

The extractor does not install packages or execute target code. Review the graph_complete field and limitations before relying on the result.

Combine static, dependency, advisory and evidence records into one dashboard-ready assessment:

```bash\npython3 scripts/assemble_assessment.py --report reports/assessment.json --dependencies reports/dependency-graph.json --advisories reports/advisory-results.json --evidence reports/evidence.json --output reports/assessment-platform.json\n```

## Dependency and advisory checks

CI runs cargo-audit, OSV-Scanner, and generates SPDX JSON and CycloneDX JSON SBOM artifacts. Exact package versions, advisory IDs/aliases, source lockfile and scanner exit code are retained as workflow artifacts. The current OSV baseline is report-first; advisory matches do not automatically prove reachability or exploitability.

See [dependency intelligence](docs/DEPENDENCY_INTELLIGENCE.md) for supported lockfiles, database limitations and interpretation.

## Isolated execution

sandbox/run-isolated.sh requires Docker with gVisor runsc registered and refuses default-runtime fallback. It enforces no network, read-only target/root filesystem, dropped capabilities, seccomp, no-new-privileges, unprivileged execution and resource limits. It requires an explicit unexpired scope file and prebuilt image.

A manual GitHub workflow can run sandbox/verify-host.sh on a dedicated self-hosted Linux runner labelled gvisor. **The smoke test is not a sandbox escape certification.** Independent escape, side-channel and resource-exhaustion testing on a dedicated VM remains required.

## Evidence and controlled testing

schemas/evidence.schema.json defines a record linking authorization scope, test ID, result classification, observed behavior, impact dimensions, cleanup and SHA-256 artifact integrity. Current dynamic verification is only a guarded sandbox foundation and host smoke test; a general-purpose penetration-test engine is not implemented.

Only assess systems you own or are explicitly authorized to test. ZEROFACTOR never automatically modifies the assessed system.

## Dashboard

Open dashboard/index.html for local report viewing, browser-local projects and assessment history. The current role selector is a local UI convenience, **not secure RBAC or authentication**. Server-side identity, permissions, tenant isolation and encrypted persistent storage remain future work. See [dashboard limitations](docs/DASHBOARD.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Dependency intelligence](docs/DEPENDENCY_INTELLIGENCE.md)
- [Controlled testing and evidence](docs/CONTROLLED_TESTING.md)
- [Sandbox instructions](sandbox/README.md)
- [Dashboard instructions](docs/DASHBOARD.md)

## License

License selection is pending. Until a license is added, all rights are reserved by the repository owner.
