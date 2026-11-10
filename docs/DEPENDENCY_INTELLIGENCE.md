# Dependency intelligence, lockfile resolution and CVE coverage

## Resolution levels
1. Declared: name and version constraint from a manifest.
2. Resolved: exact package version extracted from a lockfile.
3. Graph-resolved: dependency edges reconstructed from the lockfile.
4. Advisory-matched: exact package/version matched by an advisory source.
5. Reachability-assessed: vulnerable code path is present and reachable.
6. Exploitability-demonstrated: controlled reproducible test proves impact in an authorized lab.

An exact version match is not proof of reachability or exploitability. Lockfiles describe selected platforms/features and may omit optional, private or target-specific dependencies.

## Native graph extractor
Run: `python3 scripts/dependency_graph.py /path/to/repository --output dependency-graph.json`

Native dependency edges:
- Cargo.lock: exact package versions, sources, checksums and edges.
- npm package-lock v1: nested dependency tree.
- npm package-lock v2/v3 and npm-shrinkwrap: package versions, integrity and nested dependency edges.
- Yarn classic v1: package versions and edges when a selector resolves unambiguously.
- Poetry.lock and uv.lock: package inventory and dependency-name resolution where a unique locked package exists; common exact, caret, tilde and comparison constraints are checked conservatively.\n- composer.lock: Packagist packages and `require` edges, excluding platform packages.\n- Gemfile.lock: RubyGems package versions and dependency edges with supported version constraints.\n- gradle.lockfile: exact coordinate inventory only; Gradle lockfiles do not encode dependency edges.

Inventory-only / incomplete:
- Pipfile.lock: exact pins, but the lock format does not encode the full dependency edge graph.
- go.sum: checksums and versions, not a complete module dependency graph.
- Yarn Berry, pnpm, Gradle, Maven, Composer, Bundler and other formats are not yet native graph adapters in this release. OSV-Scanner can still inventory and scan its supported formats, but that is not equivalent to ZEROFACTOR's own complete dependency graph.

The extractor never installs packages or executes target code. `graph_complete` is false when a supported lockfile has unresolved edges or when only inventory is available. Python version constraints are not fully evaluated against PEP 440; ambiguous duplicate versions are marked unresolved. A complete result for one lockfile is not a completeness claim for every ecosystem in the repository.

## Advisory sources and policy
CI runs RustSec through cargo-audit and OSV-Scanner against OSV.dev, then normalizes exact versions, advisory IDs, aliases, severity and source lockfile. SPDX JSON and CycloneDX JSON artifacts are generated alongside the reports.

Policy:
`python3 scripts/cve_policy.py advisory-results.json --source-metadata source-metadata.json --output cve-policy-result.json`

The policy blocks exact-version matches at or above the configured severity threshold, routes unknown severity or non-exact matches to review, and fails closed if a required advisory source is absent, unapproved or stale. `source-metadata.json` must contain independently obtained trusted upstream `sources[].last_updated` timestamps. An advisory's `modified` timestamp or the time of the scan is not the database's last-updated timestamp. Do not fabricate freshness metadata.

Current policy enforcement is conditional in CI: it runs only when trusted `source-metadata.json` is supplied. RustSec is currently an independent audit result and is not yet normalized into the same multi-source policy input. The configured mandatory policy source is OSV; broader multi-database enforcement remains incomplete.

## Coverage limitations
- OSV and RustSec are not every vulnerability database; complete global CVE coverage cannot be promised.
- Database freshness, ecosystem mappings, aliases, withdrawn advisories, platform markers, private registries and lockfile quality affect results.
- CVE presence is not evidence that a vulnerable function is reachable.
- A clean result with missing lockfiles or incomplete graph coverage is not a clean bill of health.
- Review scanner exit codes, graph completeness, SBOM and advisory artifacts together.
