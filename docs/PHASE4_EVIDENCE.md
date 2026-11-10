# Phase 4 — controlled evidence ingestion and reports

## Evidence import

The Rust evidence engine accepts:
1. Existing typed `EvidenceRecord` arrays.
2. Versioned result envelopes emitted by `scripts/run_controlled_module.py` (synthetic fixture evidence).
3. Versioned result envelopes emitted by `scripts/controlled_http_adapter.py` (bounded, read-only HTTP observations).

The importer is transactional: if an envelope contains a duplicate ID, mismatched case/result, invalid provenance, unsafe safety counters, raw response body, or unsupported schema, none of that envelope is added.

Every controlled record carries:
- assessment and written-authorization identifiers;
- target-origin SHA-256 fingerprint and scope expiry;
- module/case identifiers and UTC observation time;
- result and redacted machine-readable reason;
- SHA-256 digest of the canonical evidence-record JSON.

The importer labels fixture evidence `simulated` and live read-only HTTP observations `reproduced`. A failed comparison creates a `needs_review` controlled finding. It does **not** create a confirmed vulnerability or assign a severity automatically. The hash is an integrity checksum, not a digital signature or proof that the source observation is truthful.

## Run all offline modules

```bash
python3 scripts/run_controlled_module.py --module AUTH --scope scripts/controlled-scope.json --fixture fixtures/controlled/auth.json --output reports/auth.json
python3 scripts/run_controlled_module.py --module INPUT --scope scripts/controlled-scope.json --fixture fixtures/controlled/input.json --output reports/input.json
python3 scripts/run_controlled_module.py --module FILE --scope scripts/controlled-scope.json --fixture fixtures/controlled/file.json --output reports/file.json
python3 scripts/run_controlled_module.py --module RATE --scope scripts/controlled-scope.json --fixture fixtures/controlled/rate.json --output reports/rate.json
python3 scripts/run_controlled_module.py --module RECOVERY --scope scripts/controlled-scope.json --fixture fixtures/controlled/recovery.json --output reports/recovery.json
```

The example scope is unauthorized by default. Only use a real authorization ID and set `authorized: true` when written permission exists.

## Import and generate reports

```bash
cargo run -- scan --path /path/to/assessed/repository \
  --evidence reports/auth.json \
  --evidence reports/input.json \
  --evidence reports/file.json \
  --evidence reports/rate.json \
  --evidence reports/recovery.json \
  --format json --out reports/assessment.json

cargo run -- scan --path /path/to/assessed/repository \
  --evidence reports/auth.json --evidence reports/input.json \
  --format md --out reports/assessment.md
```

Reports separate source findings from controlled review candidates and list each module's pass/fail/inconclusive counts. JSON includes the full typed evidence records, module summaries, controlled findings and impact summary. Markdown displays module summaries and review candidates.

## Live read-only adapter

The optional live adapter supports only AUTH, FILE, RATE, RECOVERY and HTTP_POSTURE:
- AUTH: GET to a route explicitly marked `protected: true`.
- FILE: HEAD only; no file content is downloaded.
- RATE: one passive observation; no request bursts or quota exhaustion.
- RECOVERY: GET health observation only; no restore/restart/failover operation.
- HTTP_POSTURE: GET only.

INPUT remains fixture-only. No POST/PUT/PATCH/DELETE, upload, credentials, cookies, response-body persistence, redirect following, DNS lookup or proxy use is supported.

A live scope must explicitly set `live_network: true`, list exact public `allowed_destination_ips`, and bind each route to an authorized module, path and GET/HEAD method. The adapter connects directly to the literal IP while retaining TLS certificate and hostname verification. It first requires `sandbox/verify-egress-policy.sh <scope.json>` to pass. The host firewall must have a default-DROP output chain and only the exact target IPs plus reviewed GitHub runner control-plane CIDRs on TCP/443. A cloud security group/network ACL must enforce the same boundary.

Run the adapter only on the dedicated disposable VM after the VM and firewall have been independently prepared:

```bash
python3 scripts/controlled_http_adapter.py --module AUTH --scope live-scope.json --output reports/auth-live.json
```

Import the result with `--evidence reports/auth-live.json`. A failed status comparison is still only a review candidate.

## Integrity limits and future work

- Per-record SHA-256 detects accidental record changes when recomputed; it does not authenticate the author or prove the target observation.
- Evidence signing, trusted timestamps, append-only chain of custody, deduplication across exported bundles and calibrated confidence remain pending.
- SARIF and PDF exports remain pending; current exports are JSON and Markdown.
- The real gVisor VM host-validation workflow has not yet been run on a dedicated ephemeral runner.
