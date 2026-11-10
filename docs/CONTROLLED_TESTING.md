# Controlled verification and test modules

## Implemented foundation
- Scope-gated gVisor launcher (sandbox/run-isolated.sh).
- Host smoke-test script (sandbox/verify-host.sh) checks runtime selection, read-only mounts/root, Docker socket absence and basic limits.
- Lockfile graph extractor and OSV result normalizer.
- Evidence/impact record contract (schemas/evidence.schema.json).\n- Assessment assembler (scripts/assemble_assessment.py) attaches advisory matches to findings and links evidence IDs and measured impact through finding_id.

## Safety model
Dynamic checks are opt-in and must run only against disposable lab targets covered by unexpired written authorization. Current smoke tests are infrastructure checks, not penetration tests and not a sandbox escape certification. Never use production credentials or real user data.

## Required test modules
Implement one deterministic module per change: authentication/authorization, input validation, file handling, TLS configuration, API rate limiting and recovery. Each requires a synthetic fixture, explicit preconditions, expected safe result, hard timeout, request cap, cleanup and regression test. No destructive payloads, credential harvesting, persistence, lateral movement, exfiltration or denial-of-service tests.

## Host validation procedure
1. Use a dedicated, patched Linux VM with Docker and gVisor runsc registered.
2. Preload a reviewed test image; the launcher never pulls an image.
3. Set ZEROFACTOR_TEST_IMAGE and run bash sandbox/verify-host.sh.
4. Run the scope-authorized launcher with a disposable fixture.
5. Preserve host/kernel/runtime versions and output in the evidence record.
6. Commission independent escape testing before making production claims.
