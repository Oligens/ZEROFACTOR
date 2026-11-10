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
- [x] VM egress policy script and proxy-only firewall design documented
- [ ] Create and patch the dedicated disposable Linux VM
- [ ] Install Docker and runsc on the actual VM and verify runtime registration
- [ ] Register an ephemeral one-job self-hosted runner and protect the environment
- [ ] Execute the host workflow on that runner and independently verify the evidence artifact
- [ ] Destroy/revert the VM and retain the validation record
- [ ] Independent sandbox escape, side-channel and resource-boundary assessment

**Status:** repository implementation is present; real-host validation is pending. CI success is not gVisor host validation.

## Phase 3 — Controlled verification modules
- [x] Initial passive HTTPS security-header and cookie checks
- [x] Scope-gated execution, GET-only requests, redirect refusal and response/time bounds
- [x] Written module contracts for AUTH, INPUT, FILE, TLS, RATE and RECOVERY
- [x] JSON Schema for explicit authorization scope, target hosts, modules and budgets
- [x] Runtime fail-closed scope validation before any network operation
- [x] AUTH offline synthetic evaluator for unauthenticated and role/project authorization decisions
- [x] INPUT offline synthetic evaluator for benign schema boundaries
- [x] FILE offline synthetic evaluator for fixture access and metadata policy
- [x] RATE offline evaluator for pre-existing, spaced observations only
- [x] RECOVERY offline evaluator for operator snapshots, health and recovery objectives
- [x] TLS one-shot certificate and protocol verification (unit-tested with a synthetic handshake)
- [x] Synthetic fixture regression tests and redacted evidence output for all five evaluators
- [x] Digest-pinned gVisor fixture runner with no network, read-only inputs and resource caps
- [x] Fixture-ID allowlist and scope gate for offline runner
- [ ] Live module adapters gated on independently validated gVisor host isolation
- [ ] VM/cloud firewall egress policy independently applied and verified
- [ ] DNS/IP pinning, cancellation, cleanup and live-runner integration tests

## Phase 4 — Rust evidence engine and reporting
- [x] Typed evidence records and impact measurement structures
- [x] Evidence-to-finding linkage and local artifact SHA-256 verification
- [x] Impact aggregation and assessment assembly foundations
- [x] Canonical evidence manifest, artifact hash verification and GitHub provenance attestation
- [x] Rust ingestion of AUTH, INPUT, FILE, RATE and RECOVERY synthetic result artifacts
- [x] Synthetic evidence mapped to Simulated, failed fixture findings marked NeedsReview
- [x] JSON evidence records and Markdown provenance separation
- [ ] Cryptographic signatures for evidence bundles and authorization manifests
- [ ] Trusted timestamping and verifiable append-only chain of custody
- [ ] Evidence deduplication, provenance validation and calibrated confidence
- [ ] SARIF, JSON, Markdown and PDF report exports with observed-vs-inferred separation

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
A feature is not complete until automated tests pass, security controls are independently verified, artifacts are reproducible and limitations are explicit. Offline fixture evaluators are not live tests. A launcher does not prove host isolation; an advisory match does not prove exploitability; browser-side role selection is not secure RBAC. No controlled dynamic module is operational until the dedicated gVisor host validation is complete.
