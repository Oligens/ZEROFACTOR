# ZEROFACTOR

**Independent Cybersecurity Validation & Adversarial Testing Platform**

ZEROFACTOR evaluates whether security guarantees declared by a system are supported by source evidence and controlled tests. It is independent of assessed systems and is designed to assess ATIBON and third-party repositories without becoming part of their trusted computing base.

> Core principle: test security properties, reproduce failures safely, measure demonstrated impact, and preserve verifiable evidence.

## Current status

The repository inventory MVP and dependency/advisory foundations are merged into `main`. The platform includes bounded HTTPS posture checks, typed Rust evidence aggregation and a server-backed local dashboard with authentication and project-scoped roles.

**These additions are not a claim that all platform objectives are complete.** Native graph coverage remains incomplete for pnpm, Yarn Berry, Maven, Bundler and other ecosystems; Gradle lockfiles are inventory-only. Python constraints are not fully evaluated; Pipfile.lock and go.sum are inventory-only. CVE freshness enforcement requires trusted upstream source metadata and currently gates OSV only; RustSec remains a separate audit. The gVisor host workflow has not been executed on a dedicated host. AUTH, INPUT, FILE, RATE and RECOVERY currently evaluate synthetic fixtures only, not live targets. Production multi-user deployment and independently verified sandbox escape resistance remain future work.

## Quick start

Requirements: Rust stable (edition 2021), Python 3.11+.

```bash
cargo test
cargo run -- scan --path ../atibon --format md --out reports/atibon-assessment.md
cargo run -- scan --path ../atibon --format json --evidence reports/evidence.json --out reports/atibon-assessment.json
```

Lockfile inventory:

```bash
python3 scripts/dependency_graph.py ../atibon --output reports/dependency-graph.json
```

Review `graph_complete` and `limitations`; do not assume a partial inventory is a complete graph.

## Controlled evidence pipeline

Run the offline evaluators using synthetic fixtures and a valid scope file. The example scope is intentionally unauthorized and must remain `authorized: false` until replaced with genuine written authorization. The gVisor fixture adapter also requires the fixture ID in `fixture_ids` and a digest-pinned module image.

```bash
python3 scripts/controlled_modules.py --module AUTH --scope scripts/controlled-scope.json --fixture fixtures/controlled/auth.json --output reports/auth.json
```

Run the Rust scanner and import one or more synthetic results:

```bash
cargo run -- scan --path ../atibon \
  --controlled-result reports/auth.json \
  --controlled-result reports/input.json \
  --assessment-id assessment-2026-001 \
  --format json --out reports/assessment.json
```

Rust verifies the complete result artifact SHA-256, records each item as `Simulated`, and labels findings from failed fixtures `[SIMULATION]` / `NeedsReview`. It rejects mismatched checks, non-zero safety assertions and duplicate evidence IDs. It does not promote synthetic observations to reproduced vulnerabilities.

The five evaluators make zero network connections and do not read target files. RATE can return `inconclusive`. See [controlled testing](docs/CONTROLLED_TESTING.md), [module contracts](docs/CONTROLLED_MODULES.md) and [synthetic fixtures](fixtures/controlled/README.md).

## gVisor and network isolation

`sandbox/run-controlled-fixture.sh` executes the offline evaluator in a digest-pinned gVisor container with `--network=none`, read-only input mounts, dropped capabilities and bounded resources. The dedicated VM host still requires real validation. See [VM setup](sandbox/VM_SETUP.md) and [VM egress policy](sandbox/EGRESS_POLICY.md). The smoke test is not sandbox-escape certification.

## Local dashboard API

```bash
python3 server/app.py
python3 -m unittest discover -s server -p 'test_*.py'
```

Open `http://127.0.0.1:8765/`. Accounts, project memberships, assessment history and roles are stored in SQLite. Roles are Owner, Analyst and Viewer. The API binds to loopback only and is not production-ready for public exposure.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Dependency intelligence and CVE policy](docs/DEPENDENCY_INTELLIGENCE.md)
- [Controlled testing and evidence](docs/CONTROLLED_TESTING.md)
- [Phase 3 controlled module contracts](docs/CONTROLLED_MODULES.md)
- [Dashboard API and RBAC](docs/DASHBOARD.md)
- [Sandbox instructions](sandbox/README.md)

## License

License selection is pending. Until a license is added, all rights are reserved by the repository owner.
