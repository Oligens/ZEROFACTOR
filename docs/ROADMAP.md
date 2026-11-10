# Roadmap

This roadmap distinguishes shipped inventory capabilities from future security-validation capabilities. An unchecked item is not implemented and must not be presented as an available feature.

## Phase 1 — Repository inventory and preliminary static inspection

- [x] Rust CLI and library
- [x] Bounded local, read-only file inventory
- [x] Top-level component classification
- [x] Discovery of supported dependency manifests
- [x] Partial inventory of directly declared dependencies
- [x] Sensitive configuration and secret-shaped pattern detection with redaction
- [x] Selected source-level validation / unsafe-API heuristics
- [x] Findings with paths, line numbers, review status and recommendations
- [x] JSON and Markdown reports
- [x] Experimental ZFI and explicit coverage
- [x] Unit and integration test scaffolding

**Phase 1 exclusions:** no CVE database lookup, no complete lockfile parsing, no complete transitive dependency graph, no package reachability analysis, no execution of target code, and no automatic remediation.

## Phase 2 — Complete dependency intelligence

- [ ] Complete parsers for supported package manifests and lockfiles
- [ ] Resolve complete direct and transitive dependency graphs
- [ ] Record exact package versions, source registry, integrity/checksum and provenance where available
- [ ] Generate a reproducible SBOM (CycloneDX or SPDX)
- [ ] Detect ambiguous, unsupported, malformed or incomplete dependency metadata
- [ ] Add ecosystem-specific tests and fixtures

## Phase 3 — CVE and security-advisory assessment

- [ ] Integrate trusted vulnerability/advisory sources
- [ ] Match exact package coordinates and resolved versions to advisories
- [ ] Include advisory identifier, affected-version range, fixed version, source and retrieval timestamp
- [ ] Distinguish confirmed matches, possible matches and unknowns
- [ ] Explain when a package cannot be assessed because version or provenance is missing
- [ ] Add freshness, caching and offline-data policies

**Gate:** CVE assessment must depend on reliable package identity and version resolution. Do not infer “no CVEs” from a partial direct-dependency inventory.

## Phase 4 — Isolated sandbox and controlled execution

- [ ] Define signed authorization and scope manifests
- [ ] Design disposable isolation (VM/container boundary, least privilege, no host secrets)
- [ ] Add network-deny-by-default controls and explicit egress allowlists
- [ ] Add CPU, memory, disk, process and time limits
- [ ] Add an operator kill switch and automatic teardown
- [ ] Implement controlled test-case execution only after isolation is independently validated
- [ ] Preserve immutable logs and evidence of test execution

**Gate:** the sandbox must be demonstrably isolated before any untrusted target code is executed. The current scanner never executes target code.

## Phase 5 — Dashboard and operational platform

- [ ] Dashboard for projects, repositories and assessment history
- [ ] Findings explorer with filters and evidence details
- [ ] Inventory and dependency views
- [ ] CVE/advisory views after Phase 3 is complete
- [ ] Sandbox run controls and status after Phase 4 is complete
- [ ] Access control, audit trail and secure evidence storage
- [ ] CI integrations, policy gates and signed evidence bundles

## Cross-cutting work

- [ ] Git tracked-file and history analysis
- [ ] Language-aware parsing / AST analysis
- [ ] Framework-specific configuration analyzers
- [ ] SARIF export
- [ ] Independent ATIBON assessment profile
- [ ] Enterprise reporting
