# Phase 3 — controlled test module contracts

This document defines the execution contract before adding active module handlers. A module is not operational merely because its contract is documented. Every implementation must have synthetic fixtures, automated safety tests, and explicit evidence classification.

## Global execution policy

- Default state: **disabled / not run**. No module runs because a target URL happens to be present.
- Require written authorization, an exact target origin, an unexpired time window, named modules and exact route/fixture allowlists.
- Run only against disposable lab fixtures unless a separate written authorization explicitly names a staging target.
- HTTPS with certificate verification enabled. Never disable TLS verification to make a test pass.
- GET/HEAD only by default. Any future state-changing method requires a separate review, isolated synthetic fixture and explicit per-case opt-in.
- No credential guessing, password spraying, brute force, exploit payloads, shell execution, port scanning, persistence, exfiltration or denial-of-service.
- Global initial budget: 12 HTTP requests per assessment, 8 seconds per request, 30 seconds wall-clock, response body at most 64 KiB, concurrency 1. Each module has a stricter local budget below.
- Stop immediately on scope mismatch, expired authorization, redirect, TLS failure, unexpected target, rate-limit response, timeout budget exhaustion or operator cancellation.
- Do not follow redirects. A redirect is evidence to review, not permission to contact a second host.
- Never include Authorization, Cookie, Set-Cookie, tokens, passwords, file contents or personal data in evidence. Store only redacted metadata and hashes where needed.
- A module may return `pass`, `fail`, `inconclusive` or `not_run`. Missing prerequisites produce `not_run`, not pass.
- A failure is an observation, not proof of exploitability. Impact must be measured, not inferred.

## Module contracts

### AUTH — authentication and authorization

**Safe initial mode:** read-only checks of explicitly allowlisted endpoints without credentials.

- Check that protected endpoints return the documented unauthenticated status (401/403) and do not disclose protected object data.
- Never attempt passwords, OTPs, session fixation, token forgery or credential reuse.
- Authorization matrix checks require two pre-created synthetic identities with distinct roles and project ownership. Tokens are injected only at runtime from a protected local fixture; never stored in scope JSON or evidence.
- Initial maximum: 4 GET requests. No account creation, role changes, writes or deletes.
- Evidence: route identifier, status, response size, redacted content-type and expected-vs-observed decision.

### INPUT — input validation

- Prefer static schema inspection and dedicated read-only validation endpoints.
- Only benign boundary values are allowed (empty, maximum valid length, one character beyond documented maximum, wrong primitive type encoded as a query parameter).
- No SQL/command/template injection strings, parser bombs, oversized bodies or state-changing requests.
- Initial maximum: 3 GET requests and 4 KiB response per case.
- Evidence: case ID, accepted/rejected status, response class and documented constraint. Never retain raw submitted data if it could contain secrets.

### FILE — file handling

- Use synthetic, non-sensitive fixture files created before the assessment.
- Initial mode uses HEAD/GET metadata only; no upload, overwrite, rename, delete, archive extraction or traversal payload.
- Verify content type, declared length, cache headers and access decision for allowlisted fixture IDs.
- Initial maximum: 2 requests; response body disabled for HEAD or capped at 4 KiB for GET metadata.
- Evidence: fixture ID, status, content length, content type and SHA-256 only when a benign fixture body is explicitly required.

### TLS — transport security

- Perform a normal verified TLS handshake only. No downgrade negotiation, malformed handshake, certificate bypass or cipher brute force.
- Record certificate chain validation result, SAN hostname match, validity window, negotiated TLS version and cipher suite.
- No private key material is collected. Certificate public metadata may be retained.
- Initial maximum: 1 handshake per hostname.
- Evidence: hostname fingerprint, public certificate SHA-256, protocol, cipher and validity result.

### RATE — request limiting

- Observe existing rate-limit headers passively during other checks first.
- If an active observation is explicitly authorized, issue at most 3 sequential GET requests at least one second apart; never parallelize or attempt to exhaust a quota.
- Stop on 429, Retry-After, 5xx, elevated latency threshold or any service degradation.
- Never claim a rate limiter is absent based on three requests; report `inconclusive` unless an explicit documented policy threshold is safely demonstrated.
- Evidence: request count, spacing, status classes, observed rate-limit headers and elapsed time. No response body retention.

### RECOVERY — recovery and resilience

- No crash, kill, restart, disk-fill, queue-flood, failover or destructive fault injection.
- Initial mode compares operator-provided pre/post health snapshots and checks a read-only health endpoint after the operator performs a planned recovery exercise.
- Any fault injection must be a separately approved future capability restricted to disposable snapshots, with an operator kill switch and automatic teardown.
- Evidence: snapshot IDs/hashes, operator action ID, health status and recovery duration; do not infer recovery success from a single HTTP 200.

## Reproducibility requirements

Every case definition must include a stable case ID, module version, preconditions, exact target route/fixture, expected safe result, request/time budgets, cleanup owner and evidence schema. Record the ZEROFACTOR commit, test image digest, runner/kernel/runsc versions and UTC timestamps. Re-running the same case against the same fixture should produce comparable structured output.

## Release gates

A module can be marked implemented only when:
1. Unit tests prove scope validation and reject unauthorized/expired/out-of-scope cases before network activity.
2. Integration tests use a local synthetic fixture, not a third-party host.
3. Request, body, time and concurrency caps are enforced by code.
4. Cancellation and cleanup are tested.
5. Evidence is redacted, hashed and classified honestly.
6. CI passes and limitations are documented.

A module can be marked operational only after the gVisor host validation is complete on the dedicated disposable VM. The Phase 2 workflow and VM instructions are prerequisites, not proof that the host exists.
