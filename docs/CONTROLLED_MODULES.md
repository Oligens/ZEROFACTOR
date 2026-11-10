# Controlled modules — contracts and execution status

This document distinguishes synthetic evaluation from live observation. A module is not operational merely because its evaluator or HTTP adapter exists.

## Global execution policy

- Default state: **disabled / not run**. A target URL alone never starts a module.
- Require written authorization, exact target host, unexpired scope and explicit module permission.
- Offline fixture evaluators make zero network connections and do not read target files.
- The live adapter requires literal destination IP allowlisting, exact route allowlists, TLS verification and a verified VM firewall.
- No credential guessing, password spraying, brute force, token forgery, exploit payloads, shell execution, port scanning, persistence, exfiltration or denial-of-service.
- No credentials, cookies, personal data, file contents or raw response bodies in evidence.
- A failed comparison creates a `needs_review` candidate, not an automatically confirmed vulnerability.
- Every evidence record is classified as simulated fixture or controlled observation; the class is preserved in Rust reports.

## Module behavior

### AUTH — authentication and authorization
Offline fixtures compare synthetic 401/403 observations and role/project read/list decisions. The live adapter permits only GET to routes explicitly marked `protected: true`; it sends no credentials and does not attempt login or role changes. A status mismatch is a review candidate, not proof of data exposure.

### INPUT — input validation
Offline fixtures evaluate benign string, integer, boolean and enum boundaries. Active submission is disabled because it would require write-capable requests. No POST/PUT/PATCH, injection payloads or parser bombs.

### FILE — file handling
Offline fixtures evaluate access decisions and declared size/content-type/extension metadata. The live adapter is HEAD-only and captures response metadata; it never downloads, uploads, overwrites, renames, extracts or deletes a file.

### RATE — request limiting
Offline fixtures inspect pre-existing observations. The live adapter permits one passive GET observation per authorized route; it never sends bursts or exhausts quotas. Absence of a 429/Retry-After signal is inconclusive.

### RECOVERY — recovery and resilience
Offline fixtures compare operator-provided snapshots, health checks and recovery-time objectives. The live adapter may GET a health endpoint only. It never initiates restore, restart, failover, crash, disk-fill or fault injection.

### TLS — transport security
The separate TLS check performs one verified TLS 1.2+ handshake and sends no application data. Unit tests use a synthetic handshake.

### HTTP_POSTURE
The existing passive checker and live adapter use bounded GET/HEAD routes to inspect response status and metadata. Redirects are never followed and response bodies are not persisted.

## Live adapter limits

- Only HTTPS port 443 and explicit GET/HEAD methods.
- Literal public destination IPs in the authorization scope; no DNS resolution by the adapter.
- Exact hostname retained for SNI and certificate verification.
- At most 12 sequential requests, each within the authorized timeout.
- At most 64 KiB response body read for GET; body content is not written to disk.
- No proxy, cookie, auth header, request body or redirect.
- The adapter fails closed unless `sandbox/verify-egress-policy.sh <scope.json>` confirms the host output firewall is default-DROP and contains the exact target IPs in the approved TCP/443 set.
- Cloud security-group/network ACL must independently enforce the same egress boundary.
- INPUT remains fixture-only.

## Evidence and release gates

The Rust importer accepts typed records, versioned synthetic fixture envelopes and bounded controlled-observation envelopes. It validates provenance consistency, scope expiry presence, SHA-256 shape, safety counters, method restrictions and duplicate IDs transactionally.

A failed check is emitted as a `needs_review` finding with its source classification. It is not assigned severity or impact automatically. A record hash is an integrity checksum, not a signature or proof of authenticity.

No live module is operational until:
1. A real disposable gVisor VM passes host validation.
2. Host nftables and cloud egress rules are independently verified.
3. A reviewed exact-IP scope and route allowlist are approved.
4. Cancellation, cleanup, redaction and live-runner integration tests pass.
5. CI and supply-chain audit/SBOM checks pass.

No ATIBON or production target has been tested as part of these repository changes.
