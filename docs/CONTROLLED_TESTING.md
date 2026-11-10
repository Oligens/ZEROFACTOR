# Controlled verification and test modules

## Implemented, bounded checks
- Scope-gated gVisor launcher and dedicated-host smoke test.
- `scripts/controlled_tests.py`: opt-in HTTPS posture checks for security headers and cookie flags. It accepts only HTTPS on an exact allowlisted hostname, requires an unexpired authorization ID, performs GET only, follows no redirects, limits response bodies to 64 KiB and uses an eight-second timeout.
- Results include response metadata, a body artifact SHA-256 and structured evidence records with measured posture dimensions.
- Rust `EvidenceIndex` validates evidence-record shape, links evidence IDs and failures to finding IDs, and aggregates impact measurements. Python assembly continues to verify local artifact hashes and attach evidence to findings.

Example:
```bash
# Copy scripts/http-scope.example.json and replace the placeholders with written authorization.
python3 scripts/controlled_tests.py --scope scripts/http-scope.json --checks security_headers cookie_flags --output reports/http-checks.json
```

These checks are passive configuration observations, not exploit attempts. They do not prove compromise or data disclosure. The target must be owned by the operator or covered by explicit written authorization. The runner is intentionally not a general-purpose shell, payload, port-scan, credential or exploit runner.

## Safety model
Dynamic checks are opt-in and must run only against disposable lab targets covered by unexpired written authorization. Current smoke tests are infrastructure checks, not a penetration-test suite and not a sandbox escape certification. Never use production credentials or real user data.

## Required future modules
Implement one deterministic module per change: authentication/authorization, input validation, file handling, TLS configuration, API rate limiting and recovery. Each requires a synthetic fixture, explicit preconditions, expected safe result, hard timeout, request cap, cleanup and regression test. No destructive payloads, credential harvesting, persistence, lateral movement, exfiltration or denial-of-service tests.

## Host validation procedure
1. Use a dedicated, patched Linux VM with Docker and gVisor runsc registered.
2. Preload a reviewed test image; the launcher never pulls an image.
3. Set ZEROFACTOR_TEST_IMAGE and run `bash sandbox/verify-host.sh`.
4. Run the scope-authorized launcher with a disposable fixture.
5. Preserve host/kernel/runtime versions and output in the evidence record.
6. Commission independent escape testing before making production claims.
