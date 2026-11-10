# ZEROFACTOR architecture

## Mission

ZEROFACTOR independently evaluates declared security guarantees, records reproducible evidence, and measures demonstrated failures. It is not an inline firewall, an automatic remediation agent, or a replacement for a system's own monitoring.

## Architectural principles

1. Independence: the assessor must not rely solely on the target's self-reported security state.
2. Evidence before scoring: hypotheses, observations, reproductions, and confirmed findings remain distinct.
3. Scope before action: every assessment has an explicit target and authorization boundary.
4. Safe by default: local/read-only analysis first; disruptive scenarios only in isolated labs.
5. Coverage transparency: untested guarantees are reported separately and never treated as resistant.
6. Human-controlled remediation: findings do not automatically change the target.

## Components

- target_intelligence: target metadata and declared assessment context.
- attack_surface: inventory of declared interfaces and trust boundaries; no network scanner yet.
- semantic_engine: compares component interpretations to identify parser/normalization disagreement.
- zero_factor: maps evidence-backed findings to affected guarantees.
- simulation: scenario definitions and execution safety gates.
- resilience: recovery and service-degradation measurements.
- evidence: provenance metadata for collected artifacts.
- reporting: normalized summary output; additional export formats are planned.
- analyzers: future read-only analyzers for repositories, web applications, identity, network, cryptography, and AI systems.
- sandbox: future isolated execution harness, separate from the core evaluator.
- integrations: optional adapters for ATIBON and third-party systems.

## Data flow

1. Register a target and its scope.
2. Inventory interfaces and security guarantees.
3. Run an approved analyzer or lab scenario.
4. Preserve evidence and its provenance.
5. Classify each guarantee as invalidated, partially invalidated, resisted, or not tested.
6. Calculate ZFI only over assessed guarantees.
7. Produce a report with coverage, limitations, findings, and remediation guidance.

## Trust boundaries

The target, analyzer plugins, simulation runner, evidence store, and report renderer are separate trust domains. Future plugin execution must be sandboxed and must not inherit secrets or privileged credentials from the coordinator.
