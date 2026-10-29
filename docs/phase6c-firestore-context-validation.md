# Phase 6C — Firestore semantic context validation

## Scope

Phase 6B exposed one regex false positive: `N14_multiline_block_comment`, where `allow write: if true;` appeared inside a closed multi-line comment. The baseline rule still provides the candidate and retains its existing ID, severity, CWE, path scope, and literal-condition behavior. A bounded lexical check now validates the exact Semgrep match span in the shared `SemgrepAdapter` before the final `ScanResult` is created.

This establishes only that a candidate span is code rather than a recognized comment or string in the bytes inspected. It does not establish that the rule file is deployed, that the Firebase project uses it, or that an access-control vulnerability is exploitable. Findings remain `unverified`.

Firebase documents `allow` statements and their supported methods (`get`, `list`, `create`, `update`, `delete`, and the `read`/`write` convenience methods). The language is Firebase's own rules language, based on CEL with additional constructs. A regular expression alone cannot distinguish code from comments and strings. This repository has no Firestore grammar; adding a general Firestore parser would exceed this Phase. The selected approach preserves Semgrep as the candidate engine and uses a small lexical validator only for the reported byte span. [Firebase Security Rules language](https://firebase.google.com/docs/rules/rules-language).

## Data flow and behavior

`Semgrep JSON → parser's Finding/raw-result alignment → bounded source snapshot → lexical span validation → ScanResult → Gate/Summary/Consumer → CLI/API/UI`

The parser's per-result ordering is used to pair each Finding with its own raw Semgrep span. Only `baseline.firestore-unconditional-write` is considered. The check validates the match's byte offsets against its line/column coordinates, then classifies every byte in the exclusive span. It does not create findings or join matches across files.

The validator recognizes `//` line comments, closed `/* ... */` block comments, and single-, double-, and backtick-quoted spans with escapes. It treats mixed spans, unterminated comments or strings, malformed coordinates, unsupported encodings, and unreadable source as ambiguous or unavailable. Only a match wholly inside a closed comment or string is removed. Unavailable or ambiguous candidates remain in the result as unverified Semgrep candidates; no public status or schema was added.

Source reads reuse the bounded no-follow regular-file reader from `code_context.py`. Files are limited to 1 MiB each; the pre-scan snapshot is limited to 512 candidate files, 16 MB total, 100,000 directory entries, and a three-second walk. A post-scan read must match the snapshot bytes before the context is used. If the target is outside those limits, is a symlink, changes, cannot be read, or has an invalid span, the candidate is retained. The byte snapshot and validation run do not prove that Semgrep atomically consumed the same bytes: a change-and-restore race remains possible.

Because filtering happens in the shared adapter result, CLI, API, React dashboard, Markdown output, and benchmark consumers receive the same Finding set. Finding IDs and surviving match locations are unchanged. Gate and Consumer policies were not modified.

The internal interpretation has three distinct levels:

1. **Pattern match** — Semgrep emitted a candidate for the regex.
2. **Context-validated security candidate** — the reported span is code rather than a recognized comment/string, with the lexical subset's limits.
3. **Confirmed vulnerability** — not provided by this tool or this Phase.

## Frozen evaluation data

Existing data was not changed:

| Set | Version | Oracle SHA-256 |
| --- | --- | --- |
| Phase 6A | `phase6a-synthetic-v1` | `d5c10325bb0ce38f9187739afb704287de1cdbab94e879d57ade152eb05e1747` |
| Phase 6B | `firestore-hardening-v1` | `37cfcd625d6d3e4029474f61809afc04e13a350e8254cd0572fca8dfd0eaba18` |
| Phase 6C | `firestore-context-v1` | `4a677997c3a0c8fee4a80cd4f04ddb22879f5fa8c3e4f82f87a615e507c94ce1` |

The Phase 6B baseline rule SHA remains `bfeb93c42ad942fda138dff3a9be8f4ccc1b137a2b547b6b29b65d98fc70a1a3`; eval and command-injection taint rule hashes remain unchanged.

Phase 6C contains 29 predeclared synthetic cases: 12 positive, 14 negative, and 3 exploratory. The oracle was frozen before executing the new lexical validator. It records the Semgrep candidate lines separately from expected final lines. In the direct pre-filter Semgrep scan, there were 20 candidate spans: 13 code declarations, four closed-comment spans (including the mixed positive/comment case), and three ambiguous exploratory spans. There were no regex candidates inside string fixtures in this run.

## Results

After shared filtering, the scored Phase 6C set had TP=12, FP=0, FN=0, TN=14; precision=1.000, recall=1.000, FPR=0.000. The three exploratory malformed-context cases were excluded from these metrics and retained as candidates because their lexical context was ambiguous. Four closed-comment spans were excluded; zero spans were excluded as strings. The normal corpus had zero unavailable contexts; injected read-failure and changed-source tests confirmed that such candidates are retained. No duplicate or scored-location mismatches remained.

| Scored set / stage | TP | FP | FN | TN | Precision | Recall | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Phase 6A Firestore before / after | 5 | 0 | 0 | 5 | 1.000 | 1.000 | 0.000 |
| Phase 6B hardening, regex-only before context | 13 | 1 | 0 | 13 | 0.929 | 1.000 | 0.071 |
| Phase 6B hardening after context | 13 | 0 | 0 | 14 | 1.000 | 1.000 | 0.000 |
| Phase 6C scored cases, regex-only candidates | 12 | 2 | 0 | 12 | 0.857 | 1.000 | 0.143 |
| Phase 6C scored cases after context | 12 | 0 | 0 | 14 | 1.000 | 1.000 | 0.000 |

For the historical Phase 6B set, the old regex observation was TP=13, FP=1, FN=0, TN=13. After context validation it was TP=13, FP=0, FN=0, TN=14. The N14 candidate (`semgrep:146af8fe21b7cc62637e1a11`, line 5) is no longer in the final `ScanResult`; its original Semgrep observation is preserved here as the pre-filter baseline. Phase 6A remains TP=5, FP=0, FN=0, TN=5.

These figures describe small synthetic development/regression sets, not generalization accuracy on Firebase projects. The Phase 6C set was used while building this filter and is not an independent final benchmark.

## Limits and security interpretation

- The scanner is a lexical subset, not a Firestore parser or compiler. It does not validate `service`, `match`, nesting, rule precedence, expression grammar, or deployment state.
- A syntactically malformed or unsupported file can yield ambiguous context; candidates are kept rather than silently suppressed.
- The scan-time byte identity is not atomic. A file changed and restored during Semgrep execution may evade the pre/post comparison.
- No Firebase Emulator, deployed project, or real application was tested.
- A surviving context-validated candidate is still not a confirmed vulnerability. It only distinguishes a reported lexical span from recognized comments and strings.

## Reproduction

```sh
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
  uv run --locked python -m pytest -q -rs tests/test_firestore_context_validation.py

SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
  uv run --locked python -m pytest -q -rs \
  tests/test_firestore_rule_hardening.py \
  tests/test_detection_benchmark.py \
  tests/test_detection_benchmark_integration.py
```

## Verification performed

- Python 3.12.7: 486 passed, 28 skipped, 0 failed. Skips are the existing opt-in Ollama tests; no model was called.
- Semgrep OSS 1.182.1 existing required integration set including this context test: 30 passed. Frozen benchmark plus Phase 6B hardening set: 17 passed.
- Frontend: typecheck and production build passed; Vitest 24 passed; Chromium mock 3 passed; real Chromium–FastAPI–Semgrep E2E 1 passed.
- `uv lock --check`, `uv sync --locked`, and `git diff --check` passed.
- The Phase 6B base commit's exact-SHA GitHub Actions run succeeded. This Phase's changes were validated locally; the resulting commit was not pushed, so no remote CI result is claimed for it.

The GitHub Actions Semgrep job is configured to run both this context test and the frozen Phase 6A/6B evaluations.
