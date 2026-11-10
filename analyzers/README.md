# Analyzer adapters

Analyzers are separate, least-privilege components. The first milestone is local and read-only repository analysis. Each analyzer must declare inputs, permissions, data retention, resource ceilings, supported file types, known blind spots, and evidence format. Do not load untrusted plugins into the privileged coordinator process.
