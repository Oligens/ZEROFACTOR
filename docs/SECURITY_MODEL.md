# Security model and safe-use requirements

## Intended use

ZEROFACTOR is intended for authorized security assurance, defensive research, controlled adversarial testing, code review, and resilience validation.

## Non-goals

- Unauthorized access, persistence, stealth, credential theft, or destructive actions.
- Unbounded scanning or testing of public targets.
- Automatic exploitation of findings.
- Automatic policy changes on assessed systems.
- Claims that a target is secure merely because no issue was found.

## Mandatory controls

- Record the target owner/authorizer and a precise scope statement.
- Require a written authorization reference before active testing.
- Keep potentially disruptive tests inside disposable, isolated laboratories.
- Apply strict CPU, memory, time, request, and storage budgets to future runners.
- Separate orchestration from untrusted analyzers and test payloads.
- Do not store target credentials in reports or logs.
- Preserve timestamps, tool versions, configuration, and evidence provenance.
- Mark incomplete, inconclusive, and untested checks explicitly.

## Failure behavior

If scope validation, isolation, resource limits, or evidence integrity checks fail, an active scenario must not start. The coordinator should fail closed and report why.

## Current implementation boundary

The first Rust foundation contains data models, a scope validator, a semantic comparison primitive, a weighted ZFI calculation, and scenario safety gates. It does not yet implement exploit execution, remote scanning, sandbox isolation, cryptographic evidence sealing, or production reporting.
