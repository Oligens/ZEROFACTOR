# Security model and safe operation

1. Obtain explicit written authorization before assessing a repository or system that is not yours.
2. Treat every target file as untrusted data. Never execute build scripts, hooks, tests, package managers, or binaries during static scanning.
3. The MVP is read-only and local. It does not clone repositories or contact network services.
4. Do not follow symbolic links. Skip generated/vendor directories and bound file count and individual file size.
5. Redact values from possible secrets before writing evidence. Reports can still contain sensitive paths and metadata; store them securely.
6. Findings produced by pattern matching are hypotheses requiring human review, not confirmed exploitable vulnerabilities.
7. A clean report does not prove the repository is secure. Unsupported languages, binary files, generated files, runtime behavior, dependencies and deployment configuration may remain untested.
8. ZEROFACTOR must never automatically change the target or apply a remediation.
9. Active testing belongs in a disposable, isolated lab with explicit scope and stop conditions.
10. The ZFI is an experimental, evidence-weighted index; it is not a probability, certification, compliance attestation or universal security rating.
