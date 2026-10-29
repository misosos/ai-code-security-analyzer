# Phase 6E held-out synthetic corpus (pre-registration)

Dataset version: `phase6e-heldout-synthetic-v1` (60 cases; 12 per category).

This corpus is new relative to Phase 6A–6D fixture files; it is **not** an independently authored or independently reviewed validation set. The author had full prior exposure to the rules, earlier fixtures, and prior evaluation outcomes. No independent reviewer was available (`INDEPENDENT_REVIEW_NOT_PERFORMED`). Cases are synthetic, directly authored, and use no external repository or user code.

`oracle.json` was authored from the documented rule contracts and language-level case meaning before Semgrep was run on this corpus. `manifest.json` pins the case paths and per-file SHA-256; the Oracle pins the Rule Signal, review relevance, coverage-gap category, expected rule IDs, cardinality, and match locations. All vulnerability labels are `NOT_EVALUATED`.

The corpus was committed before its first Semgrep evaluation. The first run exposed a pre-registration label error in `EJX04_worker_transform`: `Function(sourceText)()` is outside the configured `new Function(...)` pattern. The original Oracle and first run are retained; `oracle-corrections.json` records the rationale, corrected label, hashes, and the resulting corrected-Oracle evaluation. No fixture or rule was changed. This is not a result-driven performance adjustment: the case remains review-worthy but is classified as an unsupported-pattern coverage gap.

Future Oracle changes require preserving each original, a correction record, reason, and before/after metrics. Once used to guide implementation, this corpus is development data rather than an unused generalization set.

The code is static-analysis input only. No fixture command or function is executed. This dataset does not measure deployed configurations, actual exploitability, or production-repository accuracy.
