# Roadmap

## Phase 1 — Repository Intelligence MVP
- [x] Rust CLI and library
- [x] Bounded local read-only inventory
- [x] Common dependency manifest discovery and direct declaration inventory
- [x] Sensitive configuration and secret-shaped pattern detection with redaction
- [x] Selected validation / unsafe API heuristics
- [x] Findings, JSON and Markdown reports
- [x] Experimental ZFI and explicit coverage

## Phase 2 — Dependency and supply-chain intelligence
- [x] CI integration for RustSec cargo-audit
- [x] CI integration for OSV-Scanner (currently non-blocking baseline)
- [x] CI generation of SPDX JSON and CycloneDX JSON artifacts
- [ ] Native lockfile parsers for Cargo, npm/pnpm/yarn, Python and Go
- [ ] Canonical dependency graph with platform/feature provenance
- [ ] Advisory normalization, deduplication and timestamped database snapshots
- [ ] Reachability and exploitability evidence; never infer from CVE presence alone
- [ ] SBOM validation, license metadata and completeness reporting

## Phase 3 — Controlled verification
- [x] Explicit scope file format and guarded gVisor launcher foundation
- [x] Network-disabled, read-only, least-privilege resource-constrained container launch
- [ ] Signed authorization manifests and immutable audit trail
- [ ] Dedicated VM-backed sandbox orchestration, lifecycle and cleanup
- [ ] Isolation escape and resource-boundary verification suite
- [ ] Safe deterministic test-case runner, kill switch and evidence capture
- [ ] Controlled penetration-test modules for explicitly authorized lab targets
- [ ] Measured impact and repeatable pre/post-test baselines

## Phase 4 — Evidence and platform
- [x] Local JSON report dashboard foundation
- [ ] Multi-project workspaces and persistent assessment history
- [ ] Authentication, RBAC and tenant isolation
- [ ] Signed evidence bundles and chain of custody
- [ ] SARIF and professional PDF exports
- [ ] CI policy gates and integrations
- [ ] Independent ATIBON assessment profile
- [ ] Hosted dashboard, audit trail and operational monitoring

## Release gates
A feature is not considered complete until automated tests pass, security controls
are independently verified, artifacts are reproducible, and limitations are
explicitly reported. A workflow being configured does not mean a scan has passed;
a sandbox launcher does not prove host isolation; and a test finding does not
prove exploitability without reproducible evidence.
