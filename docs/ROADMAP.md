# Roadmap

## Phase 0 — Foundation (current)
- [x] Establish independent repository and development branch.
- [x] Define modular architecture and security boundaries.
- [x] Create Rust workspace and typed finding/evidence/scope models.
- [x] Implement initial weighted ZFI calculation and unit tests.
- [x] Add semantic interpretation comparison primitive.
- [x] Add scenario safety gates.
- [x] Add Rust CI workflow.
- [ ] Verify CI on GitHub and address any failures.

## Phase 1 — Read-only repository assessment
- [ ] Local repository inventory and language detection.
- [ ] Dependency manifest and lockfile analysis.
- [ ] Secret-pattern detection with safe redaction.
- [ ] Static configuration checks and security baseline.
- [ ] SARIF/JSON evidence export and deterministic reports.

## Phase 2 — Controlled semantic testing
- [ ] Differential parsing harness with bounded input sizes.
- [ ] HTTP normalization test corpus in a local lab.
- [ ] DNS/IP canonicalization test suite.
- [ ] Reproducible test cases and regression corpus.

## Phase 3 — Isolated adversarial laboratory
- [ ] Disposable container/VM lab adapter.
- [ ] Network egress deny-by-default and resource quotas.
- [ ] Scenario runner with signed manifests and immutable run metadata.
- [ ] Recovery and integrity verification.

## Phase 4 — Independent system integrations
- [ ] ATIBON adapter (read-only first).
- [ ] Generic API, identity, network, and cloud adapters.
- [ ] Multi-run trend analysis and coverage-aware comparisons.

## Phase 5 — Assurance product
- [ ] Report portal and access controls.
- [ ] Customer engagement and authorization workflow.
- [ ] Methodology governance and independent validation.
