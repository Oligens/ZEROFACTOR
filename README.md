# ZEROFACTOR

**Independent Cybersecurity Validation & Adversarial Testing Platform**

ZEROFACTOR evaluates whether security guarantees declared by a system are supported by source evidence and controlled tests. It is independent of assessed systems and is designed to assess ATIBON and third-party repositories without becoming part of their trusted computing base.

> Core principle: test security properties, reproduce failures safely, measure demonstrated impact, and preserve verifiable evidence.

## Current status

The repository inventory MVP, dependency/advisory foundations and Phase 3 offline module evaluators are merged into `main`. The Rust evidence engine now has typed evidence records, transactional import of versioned controlled-module envelopes, controlled review candidates and JSON/Markdown reporting. A separate read-only HTTPS adapter is being added behind explicit destination-IP scope and a fail-closed VM firewall check.

**These additions are not a claim that all platform objectives are complete.** Native graph coverage remains incomplete for pnpm, Yarn Berry, Maven, Bundler and other ecosystems; Gradle lockfiles are inventory-only. Python constraints are not fully evaluated; Pipfile.lock and go.sum are inventory-only. OSV and RustSec are not every vulnerability database. The dedicated gVisor host workflow has not yet been run on a real ephemeral VM. The active HTTP adapter is not yet operational until that host and its firewall are independently validated. Production multi-user deployment and independently verified sandbox escape resistance remain future work.

## Quick start

Requirements: Rust stable (edition 2021), Python 3.11+.

```bash
cargo test
cargo run -- scan --path ../atibon --format md --out reports/atibon-assessment.md
cargo run -- scan --path ../atibon --format json --out reports/atibon-assessment.json
```

Lockfile inventory:

```bash
python3 scripts/dependency_graph.py ../atibon --output reports/dependency-graph.json
```

Review `graph_complete` and `limitations`; do not assume a partial inventory is a complete graph.

## Local dashboard API

```bash
python3 server/app.py
python3 -m unittest discover -s server -p 'test_*.py'
```

Open `http://127.0.0.1:8765/`. Accounts, project memberships, assessment history and roles are stored in SQLite. Roles are Owner, Analyst and Viewer. The API binds to loopback only and is not production-ready for public exposure.

## Controlled modules and evidence

Run the full test suite:

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

The five offline modules are AUTH, INPUT, FILE, RATE and RECOVERY. Run the canonical envelope generator:

```bash
python3 scripts/run_controlled_module.py --module AUTH --scope scripts/controlled-scope.json --fixture fixtures/controlled/auth.json --output reports/auth.json
```

The example scope is intentionally unauthorized. It must only be authorized when written permission exists. Offline evaluators make zero network connections and read no target files. RATE's example returns `inconclusive` when a small unthrottled sample cannot prove rate-limit absence.

Import multiple module results into the Rust engine and generate a report:

```bash
cargo run -- scan --path ../atibon \
  --evidence reports/auth.json --evidence reports/input.json \
  --evidence reports/file.json --evidence reports/rate.json \
  --evidence reports/recovery.json --format json --out reports/assessment.json
```

The report keeps simulated fixture evidence separate from live observations. Failed comparisons become `needs_review` candidates, not confirmed vulnerabilities. See [Phase 4 evidence ingestion](docs/PHASE4_EVIDENCE.md).

## Live read-only observations

The optional `scripts/controlled_http_adapter.py` supports narrowly scoped GET/HEAD observations for AUTH, FILE, RATE, RECOVERY and HTTP_POSTURE. INPUT remains fixture-only. It pins connections to literal public IPs, verifies TLS, refuses redirects, sends no credentials or request body, does not persist response bodies, and requires the VM firewall verifier to pass before any connection.

Do not use this adapter until the dedicated disposable VM, host nftables default-DROP policy and cloud egress rules have been independently verified. See [VM egress firewall](sandbox/egress/README.md).

## Isolated execution

`sandbox/run-isolated.sh` requires Docker with gVisor runsc registered and refuses default-runtime fallback. It keeps the container network disabled, mounts the target read-only, drops capabilities and applies resource limits. The manual GitHub workflow requires a dedicated ephemeral self-hosted Linux runner labelled `gvisor`. **The real-host smoke test has not yet been executed; CI success is not gVisor validation or sandbox-escape certification.**

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Dependency intelligence and CVE policy](docs/DEPENDENCY_INTELLIGENCE.md)
- [Controlled testing](docs/CONTROLLED_TESTING.md)
- [Controlled module contracts](docs/CONTROLLED_MODULES.md)
- [Phase 4 evidence ingestion](docs/PHASE4_EVIDENCE.md)
- [Dashboard API and RBAC](docs/DASHBOARD.md)
- [Sandbox instructions](sandbox/README.md)
- [Dedicated VM setup](sandbox/VM_SETUP.md)
- [VM egress firewall](sandbox/egress/README.md)

## License

License selection is pending. Until a license is added, all rights are reserved by the repository owner.
