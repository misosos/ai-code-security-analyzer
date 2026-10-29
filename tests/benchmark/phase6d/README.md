# Phase 6D synthetic generalization evaluation

`phase6d-generalization-v1` is a fixed, independently authored set of 50
synthetic static-analysis cases: ten each for JavaScript eval, React dangerous
HTML, Firestore writes, eval taint, and command-injection taint. Cases use
small project-like directory structures, including two cross-file flow
examples. No fixture code is executed, downloaded, or taken from a user or
production repository.

`manifest.json` and `oracle.json` are hash-pinned by `evaluate.py`; manifest
entries also pin each fixture file's SHA-256. The oracle
separates `expected_rule_signals` (`positive`, `negative`, `out_of_scope`) from
the manually assigned `security_review_relevance` (`review_worthy`,
`lower_priority`, `undetermined`). `confirmed_vulnerability` is
`NOT_EVALUATED`. Out-of-scope matches are reported separately and are not
silently scored as true or false positives. A failed, partial, wrong-version,
unmapped, or unexpected-rule run yields no metrics.

The synthetic `syntheticSafe` sanitizer is only the experimental rule's
declared model. These results do not measure real sanitizer security, deployed
Firestore permissions, runtime reachability, or vulnerability precision on
real repositories. Existing Phase 6A, 6B, and 6C datasets remain separate and
unchanged.

Run the real evaluation with Semgrep OSS 1.182.1:

```sh
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
  uv run --locked python tests/benchmark/phase6d/evaluate.py
```

Run integrity/scoring unit tests:

```sh
uv run --locked python -m pytest -q tests/test_phase6d_benchmark.py
```
