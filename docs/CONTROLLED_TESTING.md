# Controlled verification and test modules

## Implemented bounded checks
- Scope-gated gVisor launcher and dedicated-host smoke-test scripts.
- `scripts/controlled_tests.py`: opt-in HTTPS posture checks for security headers and cookie flags. GET only, exact HTTPS host, no redirects, bounded response size and timeout; response bodies are not persisted.
- `scripts/tls_check.py`: one verified TLS 1.2+ handshake with public certificate metadata and no application data.
- `scripts/controlled_modules.py`: offline synthetic-fixture evaluators for AUTH, INPUT, FILE, RATE and RECOVERY. They require explicit module permission and valid scope, make zero network connections and do not read or modify target files.
- Structured synthetic evidence includes module/case identifiers, authorization reference, target-origin fingerprint, UTC timestamp and `synthetic_fixture` classification.

## Test suite

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
```

See [Phase 3 controlled module contracts](CONTROLLED_MODULES.md) for accepted fixture fields, limits and interpretation.

## Safety and status

The five modules currently evaluate supplied synthetic observations only. They do not test a live application, authenticate to a target, upload/download files, generate requests, exhaust rate limits or trigger recovery actions. They must not be reported as operational security checks. RATE returns inconclusive when a small passive sample cannot establish a policy result.

Exact hostname allowlisting alone does not prevent DNS rebinding. Any future live runner must enforce destination-IP egress policy at the VM/firewall layer. Dedicated gVisor host validation remains pending; repository CI and synthetic unit tests do not prove host isolation or sandbox escape resistance.

## Host validation procedure
1. Use a dedicated, patched Linux VM with Docker and gVisor runsc registered.
2. Preload a reviewed test image; the launcher never pulls an image.
3. Set ZEROFACTOR_TEST_IMAGE and run `bash sandbox/verify-host.sh`.
4. Run the scope-authorized launcher only with a disposable fixture.
5. Preserve host/kernel/runtime versions and output in the evidence record.
6. Commission independent escape testing before making production claims.
