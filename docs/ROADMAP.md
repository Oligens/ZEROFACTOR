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
- [x] CI integration for OSV-Scanner (report-first baseline)
- [x] CI generation of SPDX JSON and CycloneDX JSON artifacts
- [x] Native exact-version extraction for Cargo, npm, Poetry, uv, Pipfile and Go checksums
- [x] Initial lockfile dependency edges for Cargo and npm
- [x] OSV exact-version advisory result normalization
- [ ] Complete native graph resolution for all supported lockfile ecosystems
- [ ] Platform/feature/optional dependency provenance and graph completeness proof
- [ ] Advisory database snapshots, source freshness and multi-database deduplication
- [ ] Reachability analysis; never infer from CVE presence alone
- [ ] SBOM validation, license metadata and completeness reporting

## Phase 3 — Controlled verification
- [x] Explicit scope file format and guarded gVisor launcher
- [x] Network-disabled, read-only, least-privilege resource-constrained container launch
- [x] Host-side gVisor smoke-test script and manual self-hosted runner workflow
- [x] Evidence/impact JSON schema
- [ ] Execute host validation on a dedicated Linux + gVisor runner
- [ ] Independent sandbox escape, side-channel and resource-boundary testing
- [ ] Signed authorization manifests and immutable audit trail
- [ ] Dedicated VM-backed sandbox orchestration, lifecycle and cleanup
- [ ] Safe deterministic test-case runner, kill switch and evidence capture
- [ ] Controlled penetration-test modules for authorized lab targets
- [ ] Measured impact and repeatable pre/post-test baselines

## Phase 4 — Evidence and platform
- [x] Local JSON report dashboard foundation
- [x] Browser-local project workspace and assessment history
- [ ] Evidence records emitted and cryptographically verified by the engine
- [ ] Server-side authentication, RBAC and tenant isolation
- [ ] Signed evidence bundles and chain of custody
- [ ] SARIF and professional PDF exports
- [ ] CI policy gates and integrations
- [ ] Independent ATIBON assessment profile
- [ ] Hosted dashboard, audit trail and operational monitoring

## Release gates
A feature is not complete until automated tests pass, security controls are independently verified, artifacts are reproducible and limitations are explicit. A launcher does not prove host isolation; an advisory match does not prove exploitability; browser-side role selection is not secure RBAC.
