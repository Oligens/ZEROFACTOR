# Dependency intelligence, lockfile resolution and CVE coverage

## Resolution levels

1. Declared: name and version constraint from a manifest.
2. Resolved: exact package version extracted from a lockfile or a trusted dependency report.
3. Graph-resolved: dependency edges reconstructed from lock data or a generated dependency tree.
4. Advisory-matched: exact package/version matched by an advisory source.
5. Reachability-assessed: vulnerable code path is present and reachable.
6. Exploitability-demonstrated: controlled reproducible test proves impact in an authorized lab.

An exact version match is not proof of reachability or exploitability. Lockfiles and generated reports describe selected platforms/configurations and may omit optional, private or target-specific dependencies.

## Native dependency graph adapters

Run:

```bash
python3 -m pip install --requirement requirements-security.txt
python3 scripts/dependency_graph.py /path/to/repository --output dependency-graph.json
```

Native dependency edges:

- Cargo.lock: exact package versions, sources, checksums and edges.
- npm package-lock v1: nested dependency tree.
- npm package-lock v2/v3 and npm-shrinkwrap: package versions, integrity and nested dependency edges.
- pnpm-lock.yaml: v5/v6 package snapshots and v9 package/snapshot sections; importer declarations are checked against locked packages.
- Yarn classic v1: package versions and edges when a selector resolves unambiguously.
- Yarn Berry v2+: YAML lock records, resolutions and dependency descriptors.
- Poetry.lock and uv.lock: package inventory and dependency-name resolution where a unique locked package exists; common exact, caret, tilde and comparison constraints are checked conservatively.
- composer.lock: Packagist packages and `require` edges, excluding platform packages.
- Gemfile.lock: RubyGems package versions and dependency edges with supported version constraints.
- Maven: pre-generated `maven-dependency-tree.txt` reports, including transitive edges.
- Gradle: pre-generated `gradle-dependencies.txt` reports, including selected versions and transitive edges. When a Gradle lockfile is also present, the report is used as the edge source.

### Maven and Gradle report inputs

ZEROFACTOR does not run Maven or Gradle against a target repository. Build tools and project plugins can execute arbitrary code, so reports must be generated in a trusted, isolated build environment and then supplied to the scanner.

Maven example:

```bash
mvn dependency:tree -DoutputType=text -DoutputFile=maven-dependency-tree.txt
```

Gradle example (repeat for every relevant configuration, retaining the report used for the assessment):

```bash
./gradlew dependencies --configuration runtimeClasspath --console=plain > gradle-dependencies.txt
```

The Gradle dependency report represents only the configuration requested. A single runtimeClasspath report does not establish compile, test, buildscript, Android variant or every platform configuration coverage. Multi-configuration coverage should be supplied and recorded separately before claiming full project coverage.

### Inventory-only / incomplete formats

- Pipfile.lock: exact pins, but the lock format does not encode the full dependency edge graph.
- go.sum: checksums and versions, not a complete module dependency graph.
- gradle.lockfile without a corresponding dependency report: exact coordinate inventory only.

Yarn Berry and pnpm now have native parsers. Maven and Gradle graph reconstruction requires the explicit pre-generated reports described above. If a Maven pom.xml exists without its dependency-tree report, or a Gradle lockfile exists without its dependency report, `graph_complete` remains false.

The extractor never installs packages or executes target code. `graph_complete` is false when a supported lockfile has unresolved edges, when only inventory is available, or when a required Maven/Gradle report is missing. Python version constraints are not fully evaluated against PEP 440; ambiguous duplicate versions are marked unresolved. Private registries, platform markers, optional dependencies and omitted lockfiles can reduce coverage.

## Multi-source advisory normalization and policy

CI runs:

- RustSec through `cargo audit --json`.
- OSV through OSV-Scanner.

Both outputs are normalized into one exact-version schema by:

```bash
python3 scripts/normalize_osv.py osv-results.json --rustsec-input rustsec-results.json --output advisory-results.json
```

Advisory aliases are correlated for the same ecosystem, package and resolved version. Source attribution is preserved in `sources[]`; a vulnerability reported by both databases is evaluated once, with both source names retained. Unknown RustSec severity is sent to manual review rather than silently assigned a severity.

Freshness metadata is obtained independently:

- OSV: HTTPS `Last-Modified` from the approved OSV snapshot host.
- RustSec: latest commit timestamp from the official RustSec/advisory-db GitHub API endpoint.

The two records are combined with `scripts/merge_source_metadata.py`. CI requires both sources to be approved and fresh. The policy blocks exact-version matches at or above the configured severity threshold, routes unknown severity or non-exact matches to review, and fails closed if either required source is absent, unapproved or stale.

Policy command:

```bash
python3 scripts/cve_policy.py advisory-results.json --source-metadata source-metadata.json --output cve-policy-result.json
```

Scanner exit code 1 means findings were reported; the findings are evaluated by policy. Exit codes greater than 1 are operational failures and block the assessment. The shared gate checks both scanner exit codes.

## Coverage limitations

- OSV and RustSec are not every vulnerability database; complete global CVE coverage cannot be promised.
- Source freshness, ecosystem mappings, aliases, withdrawn advisories, platform markers, private registries and lockfile/report quality affect results.
- Advisory match is not evidence that vulnerable code is reachable.
- A clean result with missing lockfiles or incomplete graph coverage is not a clean bill of health.
- A generated Maven or Gradle report is only as complete as the configuration and environment used to produce it.
- Review scanner exit codes, graph completeness, SBOM and advisory artifacts together.
