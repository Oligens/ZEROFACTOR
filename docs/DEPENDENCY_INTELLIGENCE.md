# Dependency intelligence, CVE audit and SBOM

## Evidence levels
1. Declared: name and version constraint from a manifest.
2. Resolved: exact version/source from a lockfile or package-manager resolution.
3. Advisory-matched: resolved package/version matched to an advisory, with ID and database timestamp.
4. Reachability-assessed: vulnerable code path is present and reachable.
5. Exploitability-demonstrated: controlled reproducible test proves impact in an authorized lab.

A manifest-only dependency is not fully resolved. An advisory match is not proof of exploitability.

## CI integration
The security-supply-chain workflow runs cargo-audit (RustSec), OSV-Scanner and
generates SPDX JSON and CycloneDX JSON SBOM artifacts using Syft through the
Anchore action. OSV is temporarily non-blocking while the baseline is established;
Cargo audit is blocking. Production hardening should pin third-party actions to
reviewed full commit SHAs.

## Local commands
  cargo install cargo-audit --locked
  cargo audit
  osv-scanner scan source -r .
  syft dir:. -o spdx-json=sbom.spdx.json
  syft dir:. -o cyclonedx-json=sbom.cdx.json

Transitive completeness depends on lockfiles, ecosystem support, platform and
feature resolution, optional dependencies and private registries. SBOM consumers
must review metadata and omissions.
