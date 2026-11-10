# ZEROFACTOR local dashboard

Open dashboard/index.html in a modern browser and import JSON generated with:
  cargo run -- scan --path /path/to/repository --format json --out assessment.json

The dashboard runs locally and does not upload reports. It displays metrics,
coverage, finding severity/status, dependency inventory, checks and warnings.
It is a local report viewer, not a hosted multi-user platform, project database,
RBAC system or live scan console.
