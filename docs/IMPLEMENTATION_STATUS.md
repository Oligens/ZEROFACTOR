# Implementation status

Last reviewed: 2026-11-09

ZEROFACTOR is being developed as an independent assessment system. The current implementation is deliberately limited to local repository inventory and preliminary static inspection. This page is the authoritative capability-status summary.

## Available now

| Capability | Status | What it means |
|---|---|---|
| Local repository file inventory | Implemented | Bounded, read-only traversal of a local directory |
| Component discovery | Implemented | Classification of recognized top-level project directories |
| Dependency manifest discovery | Implemented, partial | Finds selected Cargo, npm, Python and Go manifests |
| Direct dependency inventory | Implemented, partial | Extracts selected declarations; versions may be ranges or incomplete |
| Sensitive configuration indicators | Implemented, heuristic | Detects selected filenames and secret-shaped patterns; redacts matching values |
| Static source heuristics | Implemented, limited | Flags selected patterns for human review; does not prove exploitability |
| JSON and Markdown reports | Implemented | CLI-generated reports with evidence, warnings and limitations |
| ZFI and coverage | Experimental | Evidence/coverage indicators only; not a probability, certification or proof of security |

## Not implemented — planned work

| Capability | Status | Planned phase |
|---|---|---|
| Complete lockfile parsing | Not implemented | Phase 2 |
| Complete direct and transitive dependency resolution | Not implemented | Phase 2 |
| Reproducible SBOM generation | Not implemented | Phase 2 |
| CVE and security-advisory audit | Not implemented | Phase 3 |
| Package reachability / exploitability analysis | Not implemented | Future research |
| Real isolated sandbox | Not implemented | Phase 4 |
| Controlled execution of target code | Not implemented | Phase 4, only after isolation validation |
| Dashboard and multi-project interface | Not implemented | Phase 5 |
| CI policy gates and signed evidence bundles | Not implemented | Phase 5 |

## Important interpretation rules

1. A dependency declaration is not proof that a package is installed or used at runtime.
2. A direct-dependency inventory is not a complete dependency graph.
3. No CVE lookup is performed. A report cannot claim that dependencies are free of known vulnerabilities.
4. A heuristic match is an observation requiring review, not a confirmed vulnerability.
5. No target code is executed. The current engine is read-only and local.
6. A clean or empty report does not prove that the target is secure.
7. Untested capabilities must remain visible as untested; they must never be treated as passing.

## Development sequence

1. Improve manifest and lockfile parsing, resolve transitive dependency graphs, and generate a reproducible SBOM.
2. Add CVE/advisory matching only after package identity and exact versions can be resolved reliably.
3. Design and validate a real disposable sandbox, including resource limits, network restrictions, a kill switch and teardown.
4. Add controlled execution only after the isolation boundary has been validated.
5. Build the dashboard on top of the stable inventory, evidence, advisory and sandbox APIs.

The current release must not advertise any planned capability as operational.
