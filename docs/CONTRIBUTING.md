# Contributing

- Keep the core deterministic and free of unsafe Rust.
- Do not add active network behavior to the core library.
- New analyzers must declare required permissions, data access, and resource limits.
- Keep hypotheses separate from confirmed findings.
- Add unit tests for parsers, scoring, scope checks, and failure paths.
- Document false-positive risks and known blind spots.
- Never add real customer secrets, tokens, or private assessment artifacts to fixtures.
