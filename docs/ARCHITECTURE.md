# ZEROFACTOR architecture

## Trust boundary

ZEROFACTOR is an independent assessor. The assessed repository is untrusted input. The first engine runs locally, reads regular files only, does not follow symlinks, skips common generated/dependency directories, caps file count and file size, and never executes target code.

## Repository Intelligence Engine (phase 1)

**Current product boundary: inventory and preliminary static inspection only.** The engine discovers files, components, supported manifests and direct dependency declarations. It does not establish a complete software bill of materials or determine whether a dependency is vulnerable.

- **Inventory:** bounded file traversal, top-level component classification and supported manifest discovery.
- **Dependency inventory:** partial direct declarations from supported manifests; not a complete lockfile or transitive dependency graph.
- **Configuration inspection:** identify likely environment files and secret-shaped assignments; redact values before evidence is emitted.
- **Source heuristics:** flag selected unsafe APIs and validation patterns as review-required observations.
- **Evidence:** stable finding IDs, relative file path, line number, severity, status, redacted evidence and recommendation.
- **Metrics:** weighted ZFI and coverage; untested capabilities remain explicitly outside coverage.
- **Reports:** Markdown and JSON.

## Data flow

`local path -> bounded inventory -> read-only analyzers -> findings/checks -> ZFI + coverage -> JSON/Markdown`

## Planned components (not implemented)

- Complete dependency intelligence with lockfile parsing and transitive graph resolution.
- CVE/advisory matching against resolved package coordinates and exact versions.
- Language-aware AST analyzers.
- Git history and tracked-file intelligence.
- Reproducible test harnesses.
- A real isolated, disposable sandbox and controlled execution with resource limits and kill switch.
- Dashboard for project, inventory, findings and assessment management.
- Signed evidence bundles.

## Non-goals of phase 1

No remote scanning, exploit execution, package installation, dependency download, code modification, auto-remediation, or claims of certification.
