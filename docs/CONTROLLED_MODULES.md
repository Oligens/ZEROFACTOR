# Phase 3 — controlled test module contracts and implementation status

This document distinguishes offline evaluator implementation from live target execution. A module is not operational merely because a fixture evaluator exists.

## Global execution policy

- Default state: **disabled / not run**. No module runs because a target URL happens to be present.
- Require written authorization, exact target origin, unexpired time window and explicit module permission.
- AUTH, INPUT, FILE, RATE and RECOVERY in `scripts/controlled_modules.py` evaluate synthetic observations only. They make no network connections and do not read target files.
- The gVisor fixture adapter `sandbox/run-controlled-fixture.sh` requires a digest-pinned image, explicit module permission and fixture ID allowlisting. It runs with `--network=none`, read-only inputs, dropped capabilities and bounded resources.
- No credential guessing, password spraying, brute force, token forgery, exploit payloads, shell execution, port scanning, persistence, exfiltration or denial-of-service.
- No credentials, tokens, personal data, file contents or raw sensitive input in fixtures/evidence.
- Results are `pass`, `fail` or `inconclusive`. A fixture failure is not proof of live exploitability.
- Every result is classified `synthetic_fixture`; it is not a reproduced finding against a live system.

## Module implementations

### AUTH — authentication and authorization
Offline evaluator for synthetic 401/403 observations and role/project authorization decisions for read/list actions. Detects unexpected protected-data exposure or a mismatch between expected and observed authorization. No passwords, OTPs, tokens, account creation, role changes or live requests.

### INPUT — input validation
Offline evaluator for benign string, integer, boolean and enum boundary observations against declared constraints, including required/min/max lengths and numeric ranges. Raw input values are never emitted. No injection payloads, parser bombs or state-changing requests.

### FILE — file handling
Offline evaluator for synthetic fixture access decisions and metadata policy: declared size, allowed content type and extension. No target filesystem access, path traversal, upload, overwrite, rename, archive extraction or deletion.

### RATE — request limiting
Passive evaluator for 1–3 pre-existing observations, ordered and at least one second apart. Records observed 429/Retry-After signals. Without a signal, returns `inconclusive` unless a documented threshold is safely exceeded in supplied observations. It never sends requests or exhausts quotas.

### RECOVERY — recovery and resilience
Evaluator for operator-supplied pre/post snapshot IDs, post-recovery health/dependency observations and recovery time objective. No crash, kill, restart, failover, disk-fill, queue-flood or fault injection.

### TLS — transport security
Separate one-shot verified TLS handshake remains available. It requires explicit TLS permission, uses TLS 1.2 minimum and certificate verification, records public certificate metadata and sends no application data. Unit tests use a synthetic handshake.

## Rust evidence ingestion

`src/controlled_evidence.rs` imports the evaluator JSON result into typed Rust `EvidenceRecord` values. It:
- accepts only the five known modules and `synthetic_fixture` classification;
- checks that safety metadata asserts zero network, target-file and credential activity;
- validates check/evidence correspondence and stable safe case identifiers;
- hashes the complete JSON artifact with SHA-256 and verifies the referenced local artifact;
- maps fixture evidence to Rust `Simulated`, never `Reproduced`;
- creates findings only for failed checks, with `NeedsReview` status and an explicit `[SIMULATION]` label;
- keeps inconclusive results as evidence without manufacturing a finding;
- stages ingestion atomically and rejects duplicate evidence IDs.

CLI example:

```bash
cargo run -- scan --path ./target-repository \
  --controlled-result reports/auth.json \
  --controlled-result reports/input.json \
  --assessment-id assessment-2026-001 \
  --format json --out reports/assessment.json
```

Markdown reports show evidence provenance counts and clearly separate simulated records from reproduced and independently verified evidence. JSON reports preserve typed evidence records and impact summaries.

## Release gates

The five evaluators and networkless fixture runner are implemented as offline/synthetic adapters. They are **not operational live target modules**. Before any live adapter:
1. Dedicated disposable gVisor host validation must pass independently.
2. VM/cloud firewall and proxy egress policy must prevent direct egress, DNS rebinding and unintended destinations.
3. A separate review must approve local synthetic integration fixtures and exact route/fixture allowlists.
4. Request, body, time and concurrency caps must be enforced.
5. Cancellation, cleanup, redaction and evidence provenance tests must pass.
6. CI must pass and limitations remain explicit.

No live target, ATIBON, production account or user data was accessed during this implementation.
