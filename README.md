# ZEROFACTOR

**Independent Cybersecurity Validation & Adversarial Testing Platform**

ZEROFACTOR is an independent platform for evaluating whether security guarantees declared by a system are actually enforced. It is designed to assess ATIBON and third-party systems without becoming part of their trusted computing base.

> Core principle: test security properties, reproduce failures safely, measure demonstrated impact, and preserve verifiable evidence.

## Project status

**Foundation phase — architecture and safe MVP scaffolding.** No production-grade penetration testing, exploit execution, or external-target scanning is implemented yet.

## Safety model

- Explicit authorization and a declared assessment scope are mandatory before active testing.
- Initial analyzers are local and read-only.
- Potentially disruptive scenarios belong in isolated, disposable laboratories.
- Findings must distinguish confirmed evidence from hypotheses and untested assumptions.
- ZEROFACTOR never changes the assessed system or its security policy automatically.

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md), and [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Quick start

The Rust workspace and CLI are being established. Build and test instructions will be added with the first executable core.

## License

License selection is pending. Until a license is added, all rights are reserved by the repository owner.
