# Roadmap

## Phase 1 — Repository Intelligence MVP
- [x] Rust CLI and library
- [x] Bounded local read-only inventory
- [x] Common dependency manifest discovery and direct declaration inventory
- [x] Sensitive configuration and secret-shaped pattern detection with redaction
- [x] Selected validation / unsafe API heuristics
- [x] Findings, JSON and Markdown reports
- [x] Experimental ZFI and explicit coverage
- [x] Unit and integration test scaffolding

## Phase 2 — Deep repository intelligence
- [ ] Git tracked-file and history analysis (without exposing secret values)
- [ ] Language-aware parsing / AST analysis
- [ ] Complete lockfile parsing and reproducible SBOM
- [ ] Advisory ingestion with source, timestamp and version provenance
- [ ] Framework-specific configuration analyzers
- [ ] SARIF export

## Phase 3 — Controlled verification
- [ ] Authorization manifest and signed scope
- [ ] Isolated disposable sandbox
- [ ] Safe test-case runner with resource limits and kill switch
- [ ] Runtime validation and regression evidence

## Phase 4 — Platform
- [ ] Dashboard and multi-project workspaces
- [ ] Signed evidence bundles
- [ ] CI integrations and policy gates
- [ ] Independent ATIBON assessment profile
- [ ] Enterprise reporting and audit trail
