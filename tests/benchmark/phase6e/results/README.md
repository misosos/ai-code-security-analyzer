# Phase 6E result lineage

- `oracle-v1-original-evaluation.json` preserves the first complete Semgrep OSS 1.182.1 run against the pre-registration Oracle (`0fb9e05…`). That Oracle mistakenly labeled `EJX04_worker_transform` in scope; see `oracle-corrections.json`.
- `oracle-v1-corrected-evaluation-initial.json` preserves the first rerun against the corrected Oracle. Its Rule Signal counts are valid, but its relevance fields mixed cross-category pattern findings into the category-scoped denominator. The evaluator was corrected to report those observations separately, and this artifact is superseded for relevance analysis.
- `evaluation-v1-pre-metadata-correction.json` preserves the completed run before a metadata-only correction that set each React fixture language from its `.jsx`/`.tsx` extension. No source file or Rule Signal label changed. This artifact has the correct score but predates the final manifest/Oracle hashes.
- `evaluation.json` is the authoritative run against the corrected, hash-pinned manifest and Oracle. It separates category-scoped findings from cross-category observations, checks all findings remain `unverified`, and reports coverage gaps independently of Rule Signal scores.

All artifacts contain only dataset/rule IDs, case IDs, relative paths, line numbers, counts, labels, and fixed scan metadata. They contain no source lines, Semgrep free-form messages, raw JSON, or absolute paths. FP/FN outcomes are recorded; they are not pass/fail criteria.
