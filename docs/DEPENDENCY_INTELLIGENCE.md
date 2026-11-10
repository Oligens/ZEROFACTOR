# Dependency intelligence, lockfile resolution and CVE coverage

## Resolution levels
1. Declared: name and version constraint from a manifest.
2. Resolved: exact package version extracted from a lockfile.
3. Graph-resolved: dependency edges reconstructed from the lockfile.
4. Advisory-matched: exact package/version sent to an advisory matcher, with advisory ID and source lockfile.
5. Reachability-assessed: vulnerable code path is present and reachable.
6. Exploitability-demonstrated: controlled reproducible test proves impact in an authorized lab.

An exact version match is not proof of reachability or exploitability. A lockfile only describes its selected platform/features and may omit optional or private dependencies.

## Native extractor
Run:
  python3 scripts/dependency_graph.py /path/to/repository --output dependency-graph.json

Current native graph extraction:
- Cargo.lock: package versions, source/checksum and lockfile dependency edges.
- npm package-lock v2/v3 and npm-shrinkwrap: package versions, integrity and nested dependency edges.
- poetry.lock and uv.lock: exact PyPI versions and declared dependency names.
- Pipfile.lock: exact pinned package versions; the file does not provide a full dependency edge graph.
- go.sum: checksummed module versions only; it is not a complete module dependency graph.

The extractor never installs packages or executes target code. Unsupported lockfile versions are reported as errors rather than silently treated as complete. Native graph coverage is therefore intentionally partial.

## CVE/advisory sources
CI combines:
- RustSec through cargo-audit for Rust crates.
- OSV-Scanner against OSV.dev for supported lockfiles across Rust, JavaScript, Python, Go and other documented ecosystems.
- SPDX JSON and CycloneDX JSON SBOM artifacts.

OSV-Scanner currently documents support for Cargo.lock, package-lock.json, pnpm-lock.yaml, yarn.lock, uv.lock, poetry.lock, Pipfile.lock, go.mod and other ecosystems. Its extractors and ecosystem coverage can change; see the [supported lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/) and [JSON output schema](https://google.github.io/osv-scanner/output/).

The CI normalizer preserves package name, ecosystem, exact version emitted by OSV-Scanner, advisory IDs/aliases, source lockfile and database timestamps where present. It does not independently reimplement version-range matching. The OSV scan exit code is retained as an artifact. The current baseline is report-first, not a blanket release gate; a separate policy gate must be enabled after the repository's baseline is reviewed.

## Coverage limitations
- OSV is not every vulnerability database; no scanner can promise complete global CVE coverage.
- Database freshness, ecosystem mappings, aliases, withdrawn advisories, platform markers, private registries and lockfile quality affect results.
- CVE presence is not evidence that a vulnerable function is reachable.
- A clean result with missing lockfiles or incomplete graph coverage is not a clean bill of health.
- Review the scanner exit code, dependency graph, SBOM and advisory artifacts together.
