# Phase 6A synthetic benchmark

This is an independently authored, synthetic and static-only evaluation set. It
was designed separately from the existing development fixtures and is not a
benchmark of production repositories. No case is executed.

`manifest.json` and `oracle.json` are fixed at version
`phase6a-synthetic-v1`. The oracle labels the narrow **Rule Signal** contract;
it does not establish whether a real deployment is vulnerable. Security review
relevance is recorded separately and may be `undetermined`. No confirmed
vulnerability labels are produced.

The cases cover baseline JavaScript dynamic evaluation, React dangerous HTML,
Firestore unconditional-write syntax, experimental JavaScript eval taint, and
experimental Node.js command-injection taint. The two eval-taint rules are
scored independently. The synthetic `syntheticSafe` model is not a validated
security sanitizer. Firestore deployment and effective match scope are unknown.

Run from the repository root with the pinned Semgrep OSS installation:

```sh
SEMGREP_REQUIRED=1 uv run python tests/benchmark/evaluate.py
```

The evaluator reports case-level and finding-level metrics separately. Its
exit status reports dataset, execution, or parsing failures; false positives
and false negatives are benchmark findings and do not by themselves fail the
evaluation test. Output contains case identifiers and aggregate metadata, not
source snippets or Semgrep free-form messages.

Existing development fixtures and future external-project evaluation are
separate datasets. This set is small and purpose-built; its metrics must not be
generalized to real repositories or overall vulnerability-detection quality.
