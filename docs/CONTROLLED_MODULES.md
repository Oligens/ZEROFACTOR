# Phase 3 — controlled test module contracts and implementation status

This document distinguishes offline evaluator implementation from live target execution. A module is not operational merely because a fixture evaluator exists.

## Global execution policy

- Default state: **disabled / not run**. No module runs because a target URL happens to be present.
- Require written authorization, exact target origin, unexpired time window and explicit module permission.
- AUTH, INPUT, FILE, RATE and RECOVERY in `scripts/controlled_modules.py` evaluate synthetic observations only. They make no network connections and do not read target files.
- HTTPS and exact host scope validation remain mandatory for traceability; the five evaluators do not contact that host.
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

## Reproducibility and evidence

Each fixture requires a stable case ID and module identity. Results contain redacted decision metadata, authorization ID, target-origin fingerprint, UTC timestamp and generated evidence IDs. Fixture payload values are not copied into evidence. Results explicitly state zero network connections and zero target-file reads/writes.

## Release gates

The five offline evaluators are implemented and unit-tested. They are **not operational live target modules**. Before any live adapter:
1. Dedicated disposable gVisor host validation must pass independently.
2. VM/firewall egress policy must prevent DNS rebinding and unintended destinations.
3. A separate review must approve local synthetic integration fixtures and exact route/fixture allowlists.
4. Request, body, time and concurrency caps must be enforced.
5. Cancellation, cleanup, redaction and evidence provenance tests must pass.
6. CI must pass and limitations remain explicit.

No live target, ATIBON, production account or user data was accessed during this implementation.
