# ZEROFACTOR

**Independent Cybersecurity Validation & Adversarial Testing Platform**

ZEROFACTOR evaluates whether security guarantees declared by a system are supported by source evidence and controlled tests. It is independent of assessed systems and is designed to assess ATIBON and third-party repositories without becoming part of their trusted computing base.

> Core principle: test security properties, reproduce failures safely, measure demonstrated impact, and preserve verifiable evidence.

## Current status

The repository inventory MVP and dependency/advisory foundations are merged into `main`. The current feature branch adds npm v1 and Yarn classic graph adapters, a fail-closed advisory severity/freshness policy, bounded HTTPS posture checks, typed Rust evidence aggregation, and a server-backed local dashboard with authentication and project-scoped roles.

**These additions are not a claim that all platform objectives are complete.** Native graph coverage remains incomplete for pnpm, Yarn Berry, Gradle, Maven, Composer, Bundler and other ecosystems. Python constraints are not fully evaluated; Pipfile.lock and go.sum are inventory-only. CVE freshness enforcement requires trusted upstream source metadata and currently gates OSV only; RustSec remains a separate audit. The gVisor host workflow has not been executed on a dedicated host. Controlled checks are passive HTTP posture checks, not a general penetration-testing engine. Production multi-user deployment and independently verified sandbox escape resistance remain future work.

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
Review `graph_complete` and `limitations`; do not assume that a partial inventory is a complete graph.

Advisory policy (requires trusted source metadata):
```bash
python3 scripts/normalize_osv.py osv-results.json --output advisory-results.json
python3 scripts/cve_policy.py advisory-results.json --source-metadata source-metadata.json --output cve-policy-result.json
```
The scan time and per-advisory modified timestamp are not a database freshness timestamp. Do not fabricate `source-metadata.json`.

## Local dashboard API

```bash
python3 server/app.py
python3 -m unittest discover -s server -p 'test_*.py'
```
Open `http://127.0.0.1:8765/`. Accounts, project memberships, assessment history and roles are stored in SQLite. Roles are Owner, Analyst and Viewer. The API binds to loopback only and is not production-ready for public exposure.

## Controlled checks

```bash
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/controlled_tests.py --scope scripts/http-scope.json --checks security_headers cookie_flags --output reports/http-checks.json
```
The HTTP runner requires an unexpired authorization scope, exact HTTPS host allowlisting and uses GET-only passive checks. See [controlled testing](docs/CONTROLLED_TESTING.md).

## Isolated execution

`sandbox/run-isolated.sh` requires Docker with gVisor runsc registered and refuses default-runtime fallback. It applies network, filesystem, capability and resource controls. The manual GitHub workflow requires a dedicated self-hosted Linux runner labelled `gvisor`. **The host smoke test has not been run here and is not a sandbox escape certification.**

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Roadmap](docs/ROADMAP.md)
- [Dependency intelligence and CVE policy](docs/DEPENDENCY_INTELLIGENCE.md)
- [Controlled testing and evidence](docs/CONTROLLED_TESTING.md)
- [Dashboard API and RBAC](docs/DASHBOARD.md)
- [Sandbox instructions](sandbox/README.md)

## License

License selection is pending. Until a license is added, all rights are reserved by the repository owner.
