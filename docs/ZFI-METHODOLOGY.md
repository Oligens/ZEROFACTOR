# Zero Factor Index (ZFI) — initial methodology

## Purpose

ZFI is a proposed coverage-aware metric for the weighted share of assessed security guarantees that were invalidated in one declared assessment scope.

For guarantee i, let w_i be its positive importance weight and f_i its demonstrated invalidation fraction:

- confirmed invalidated: 1.0
- partially invalidated: 0.5, only when the assessment protocol defines a defensible partial state
- resisted: 0.0
- not tested: excluded from the denominator and reported separately

ZFI = sum(w_i * f_i) / sum(w_i) over assessed guarantees.

## Interpretation

- 0.0 means no assessed guarantee was invalidated in this assessment. It does not mean the target is perfectly secure.
- 1.0 means all weighted guarantees included in the assessed set were invalidated.
- A score without coverage, scope, evidence quality, and confidence context is incomplete.
- Scores from different scopes or methodologies must not be compared as if they were equivalent.

## Safeguards against misleading scores

- Never convert a missing test into a pass.
- Publish assessed and untested counts and weights.
- Keep critical guarantees visible even when aggregate scores are low.
- Record the evidence and reproduction status behind each invalidation.
- Version the guarantee catalogue and weighting methodology.
- Calibrate weights through documented risk analysis; do not choose them to make a product look better.

This metric is a research proposal, not an industry standard or certification.
