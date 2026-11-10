# ZEROFACTOR architecture

## Trust boundary

ZEROFACTOR is an independent assessor. The assessed repository is untrusted input. The first engine runs locally, reads regular files only, does not follow symlinks, skips common generated/dependency directories, caps file count and file size, and never executes target code.

## Repository Intelligence Engine (phase 1)

- **Inventory:** bounded file traversal and supported manifest discovery.
- **Configuration inspection:** identify likely environment files and secret-shaped assignments; redact values before evidence is emitted.
- **Source heuristics:** flag selected unsafe APIs and validation patterns as review-required observations.
- **Evidence:** stable finding IDs, relative file path, line number, severity, status, redacted evidence and recommendation.
- **Metrics:** weighted ZFI and coverage; untested capabilities remain explicitly outside coverage.
- **Reports:** Markdown and JSON.

## Data flow

`local path -> bounded inventory -> read-only analyzers -> findings/checks -> ZFI + coverage -> JSON/Markdown`

## Planned components

- Dependency intelligence with lockfile parsing and advisory database ingestion.
- Language-aware AST analyzers.
- Git history and tracked-file intelligence.
- Reproducible test harnesses.
- Disposable sandbox and controlled dynamic tests.
- Dashboard and signed evidence bundles.

## Non-goals of phase 1

No remote scanning, exploit execution, package installation, dependency download, code modification, auto-remediation, or claims of certification.
