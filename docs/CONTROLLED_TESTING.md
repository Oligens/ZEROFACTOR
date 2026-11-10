# Controlled verification and test modules

## Implemented, bounded checks
- Scope-gated gVisor launcher and dedicated-host smoke test.
- `scripts/controlled_tests.py`: opt-in HTTPS posture checks for security headers and cookie flags. It accepts only HTTPS on an exact allowlisted hostname, requires an unexpired authorization ID, performs GET only, follows no redirects, limits response bodies to 64 KiB and uses an eight-second timeout.
- Results include response metadata, a body artifact SHA-256 and structured evidence records with measured posture dimensions.
- Rust `EvidenceIndex` validates evidence-record shape, links evidence IDs and failures to finding IDs, and aggregates impact measurements. Python assembly continues to verify local artifact hashes and attach evidence to findings.

## Phase 3 module contracts

See [Controlled module contracts](CONTROLLED_MODULES.md) and the JSON Schema at `scripts/controlled-scope.schema.json`. They define the authorization, route, fixture, request and time budgets for AUTH, INPUT, FILE, TLS, RATE and RECOVERY.

The contracts are design requirements, not implemented test handlers. Until a module has runtime validation, synthetic integration fixtures, bounded execution, cancellation/cleanup tests and evidence capture, it must remain `not_run`.

## Safety model
Dynamic checks are opt-in and must run only against disposable lab targets covered by unexpired written authorization. Current smoke tests are infrastructure checks, not a penetration-test suite and not a sandbox escape certification. Never use production credentials or real user data.

The current HTTP runner remains a small passive posture check. It does not yet execute the six Phase 3 modules. The dedicated gVisor host validation must pass before dynamic modules can be marked operational.

## Host validation procedure
1. Use a dedicated, patched Linux VM with Docker and gVisor runsc registered.
2. Preload a reviewed test image; the launcher never pulls an image.
3. Set ZEROFACTOR_TEST_IMAGE and run `bash sandbox/verify-host.sh`.
4. Run the scope-authorized launcher with a disposable fixture.
5. Preserve host/kernel/runtime versions and output in the evidence record.
6. Commission independent escape testing before making production claims.
