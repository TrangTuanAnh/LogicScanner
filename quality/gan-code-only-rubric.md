# LogicLab Code-Only Evaluator Rubric

This is the independent evaluator contract for the MVP. It is deliberately
limited to executable code quality; there is no browser or visual score.

| Criterion | Weight | Pass rule |
| --- | ---: | --- |
| Functionality | 0.35 | All unit/API/orchestration tests pass; trust replay is observed and stable; an unavailable HMAC behavior remains inconclusive. |
| Security boundaries | 0.30 | Tests cover scope pinning, path traversal, command allow-list, source prompt injection, artifact confinement and redaction. |
| Reliability | 0.20 | Three resets produce an identical evidence hash; run status is persisted on success and failure. |
| Maintainability | 0.15 | Ruff is clean, public schemas export JSON Schema, and the Alembic head matches the control schema. |

The weighted score must be at least 8.0/10. A failure in a security-boundary
rule is a hard failure even if the numerical score would pass.

The evaluator must report only failed checks and evidence. It must not modify
source files or declare a security finding based on static source alone.
