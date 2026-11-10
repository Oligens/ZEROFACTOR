# Controlled verification and test modules

## Implemented bounded checks
- Scope-gated gVisor launcher and dedicated-host smoke-test scripts.
- `scripts/controlled_tests.py`: opt-in HTTPS posture checks for security headers and cookie flags. GET only, exact HTTPS host, no redirects, bounded response size and timeout; response bodies are not persisted.
- `scripts/tls_check.py`: one verified TLS 1.2+ handshake with public certificate metadata and no application data.
- `scripts/controlled_modules.py`: offline synthetic-fixture evaluators for AUTH, INPUT, FILE, RATE and RECOVERY.
- `sandbox/run-controlled-fixture.sh`: digest-pinned gVisor fixture adapter with `--network=none`, read-only inputs, bounded resources and fixture-ID allowlisting.
- `src/controlled_evidence.rs`: Rust ingestion of fixture outputs as `Simulated` evidence with artifact SHA-256 verification; generated findings remain `NeedsReview`.
- Structured synthetic evidence includes module/case identifiers, authorization reference and expiry, target-origin fingerprint, UTC timestamp and `synthetic_fixture` classification.

## Test suite

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

## Safety and status

The five modules currently evaluate supplied synthetic observations only. They do not test a live application, authenticate to a target, upload/download files, generate requests, exhaust rate limits or trigger recovery actions. They must not be reported as operational security checks. RATE returns inconclusive when a small passive sample cannot establish a policy result.

The gVisor fixture adapter runs without network access. The VM runner's control-plane egress must be restricted through a fixed approved HTTPS proxy and cloud firewall; see [VM egress policy](../sandbox/EGRESS_POLICY.md). Exact hostname allowlisting alone does not prevent DNS rebinding.

Dedicated gVisor host validation remains pending. Repository CI and synthetic unit tests do not prove host isolation or sandbox escape resistance. No live adapters may be enabled before the VM host and egress controls are independently verified.

## Host validation procedure
1. Use a dedicated, patched Linux VM with Docker and gVisor runsc registered.
2. Preload reviewed, digest-pinned test and module images; do not pull images during test jobs.
3. Apply and verify the VM/cloud egress policy.
4. Set ZEROFACTOR_TEST_IMAGE and run `bash sandbox/verify-host.sh`.
5. Run only the fixture adapter with a fixture ID explicitly listed in the authorization scope.
6. Preserve host/kernel/runtime versions and output in the evidence record.
7. Commission independent escape testing before making production claims.
