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

## Local dashboard API

```bash
python3 server/app.py
python3 -m unittest discover -s server -p 'test_*.py'
```

Open `http://127.0.0.1:8765/`. Accounts, project memberships, assessment history and roles are stored in SQLite. Roles are Owner, Analyst and Viewer. The API binds to loopback only and is not production-ready for public exposure.

## Controlled checks

Run the complete Python suite:

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
```

Run an offline module using a valid scope and a synthetic fixture:

```bash
python3 scripts/controlled_modules.py --module AUTH --scope scripts/scope.json --fixture fixtures/auth.json --output reports/auth.json
```

Supported modules: AUTH, INPUT, FILE, RATE and RECOVERY. The evaluator makes zero network connections and reads no target files. See [controlled testing](docs/CONTROLLED_TESTING.md) and [module contracts](docs/CONTROLLED_MODULES.md).

The separate HTTP posture runner requires an unexpired authorization scope, exact HTTPS host allowlisting and GET-only passive checks. Do not run it against a system without written authorization.

## Isolated execution

`sandbox/run-isolated.sh` requires Docker with gVisor runsc registered and refuses default-runtime fallback. It applies network, filesystem, capability and resource controls. The manual GitHub workflow requires a dedicated self-hosted Linux runner labelled `gvisor`. **The host smoke test has not been run here and is not a sandbox escape certification.**

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
