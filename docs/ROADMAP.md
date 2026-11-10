# Roadmap

## Phase 1 — Repository intelligence and supply-chain gate
- [x] Rust CLI and bounded local read-only inventory
- [x] Dependency graph adapters and multi-source advisory policy
- [x] Fail-closed graph, inventory and SBOM consistency gate
- [x] Evidence manifest with artifact hashes and GitHub build provenance attestation

## Phase 2 — Dedicated gVisor laboratory
- [x] Dedicated VM provisioning guide for Docker Engine and gVisor runsc
- [x] Manual-only host validation workflow restricted to main
- [x] Protected GitHub Environment approval gate and read-only workflow token
- [x] Host metadata, runtime, image identity, logs and SHA-256 evidence artifact
- [x] Host smoke checks for read-only filesystem, no network, dropped capabilities, seccomp and unprivileged execution
- [x] Host firewall template and fail-closed egress policy verifier
- [ ] Create and patch the dedicated disposable Linux VM
- [ ] Install Docker and runsc on the actual VM and verify runtime registration
- [ ] Register an ephemeral one-job self-hosted runner and protect the environment
- [ ] Execute the host workflow on that runner and independently verify the evidence artifact
- [ ] Destroy/revert the VM and retain the validation record
- [ ] Independent sandbox escape, side-channel and resource-boundary assessment

**Status:** repository preparation is implemented; real-host validation is pending. CI success is not gVisor host validation.

## Phase 3 — Controlled verification modules
- [x] Initial passive HTTPS security-header and cookie checks
- [x] Scope-gated execution, GET-only requests, redirect refusal and response/time bounds
- [x] Written module contracts for AUTH, INPUT, FILE, TLS, RATE and RECOVERY
- [x] JSON Schema for explicit authorization scope, target hosts, modules and budgets
- [x] Runtime fail-closed scope validation before network operations
- [x] AUTH offline synthetic evaluator and protected-route GET observation adapter
- [x] INPUT offline synthetic evaluator; active submissions remain disabled
- [x] FILE offline metadata evaluator and HEAD-only observation adapter
- [x] RATE offline/passive evaluator; no request bursts
- [x] RECOVERY offline evaluator and health-endpoint GET observation adapter
- [x] TLS one-shot certificate and protocol verification
- [x] Literal destination-IP pinning, sequential requests and VM firewall gate
- [ ] Real VM/firewall validation and live adapter execution on approved disposable targets
- [ ] Cancellation, cleanup and live-runner integration tests

## Phase 4 — Rust evidence engine and reporting
- [x] Typed evidence records and impact measurement structures
- [x] Transactional ingestion of versioned AUTH, INPUT, FILE, RATE and RECOVERY envelopes
- [x] Ingestion of bounded controlled-observation envelopes with provenance checks
- [x] Separate simulated and observed evidence classifications
- [x] Structured needs-review findings and module summaries
- [x] JSON and Markdown reports with controlled evidence sections
- [x] Multi-file evidence import through CLI
- [ ] Cryptographic signatures for evidence bundles and authorization manifests
- [ ] Trusted timestamping and verifiable append-only chain of custody
- [ ] Evidence deduplication across bundles and calibrated confidence
- [ ] SARIF and PDF report exports with observed-vs-inferred separation

## Phase 5 — Dashboard and production security
- [x] Local-first dashboard API foundation with scrypt password hashing
- [x] Opaque sessions, CSRF checks and project-scoped Owner/Analyst/Viewer roles
- [x] Loopback-only default bind and explicit refusal of public bind
- [ ] MFA and verified account lifecycle
- [ ] Server-side RBAC hardening and automated cross-project isolation tests
- [ ] Immutable/append-only audit events with integrity verification
- [ ] Secret management and production TLS termination
- [ ] Backup policy, restore drills and recovery objectives
- [ ] Monitoring, alerting, abuse controls and operational access reviews
- [ ] Independent production security review and deployment hardening

## Release gates
A feature is not complete until automated tests pass, security controls are independently verified, artifacts are reproducible and limitations are explicit. Fixture results are not live tests. A live HTTP status mismatch is a review candidate, not proof of exploitability. A firewall verifier is not a substitute for an independent cloud network-policy review. No controlled dynamic module is operational until the dedicated gVisor host validation is complete.
