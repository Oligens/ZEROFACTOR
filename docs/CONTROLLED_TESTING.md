# Controlled verification and test modules

## Implemented bounded checks
- Scope-gated gVisor launcher and dedicated-host smoke-test scripts.
- `scripts/controlled_tests.py`: passive HTTPS posture checks. GET only, exact HTTPS host, no redirects, bounded response size and timeout; response bodies are not persisted.
- `scripts/tls_check.py`: one verified TLS 1.2+ handshake with public certificate metadata and no application data.
- `scripts/controlled_modules.py` plus `scripts/run_controlled_module.py`: offline synthetic evaluators for AUTH, INPUT, FILE, RATE and RECOVERY, with Rust-ingestible provenance envelopes.
- `scripts/controlled_http_adapter.py`: optional sequential GET/HEAD observations for AUTH, FILE, RATE, RECOVERY and HTTP_POSTURE. It pins literal destination IPs, verifies TLS and fails closed unless the VM egress firewall verifier passes.
- Rust evidence ingestion validates versioned envelopes transactionally and exports separate simulated/observed records and review candidates in JSON/Markdown.

## Test suite

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
bash -n sandbox/run-isolated.sh sandbox/verify-host.sh sandbox/verify-egress-policy.sh
```

See [Phase 3 controlled module contracts](CONTROLLED_MODULES.md) and [Phase 4 evidence ingestion](PHASE4_EVIDENCE.md).

## Safety and status

The five fixture evaluators do not test a live application, authenticate to a target, upload/download files, generate requests, exhaust rate limits or trigger recovery actions. The live HTTP adapter is a separate bounded observation path; INPUT remains fixture-only. It never sends write methods or credentials and does not persist response bodies.

The adapter requires a scope with `live_network: true`, exact allowlisted host, literal public destination IPs and module-bound GET/HEAD routes. It does not resolve DNS. Before the first connection it runs `sandbox/verify-egress-policy.sh`, which requires a host nftables output chain with default DROP and the exact target IPs in the HTTPS allowlist. The cloud firewall/security group must also restrict egress. See [VM egress firewall](../sandbox/egress/README.md).

Dedicated gVisor host validation remains pending. Repository CI, synthetic fixtures and a structurally valid firewall policy do not prove host isolation or sandbox escape resistance.

## Host validation procedure
1. Provision a dedicated patched disposable Linux VM.
2. Install Docker Engine and gVisor runsc; verify runtime registration.
3. Preload a reviewed immutable test image.
4. Register an ephemeral one-job runner and protect the GitHub Environment.
5. Configure host nftables and cloud egress rules; verify exact target and runner IP ranges.
6. Run the manual host workflow from `main`, retain evidence, verify SHA-256 checksums and destroy/revert the VM.
7. Commission independent escape testing before production claims.
