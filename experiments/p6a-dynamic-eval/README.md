# P6-A dynamic-eval research materials

Research-only reproduction materials for the A8 false negative in `baseline.javascript-dynamic-eval`.
The product rule file is read, never modified. The full report (Korean) is
[`docs/p6a-dynamic-eval-false-negative-research.md`](../../docs/p6a-dynamic-eval-false-negative-research.md).

| Path | Contents |
| --- | --- |
| `cases/` | 26 synthetic sloppy-mode scripts, one call site each. Never executed. |
| `labels.json` | Semantic label per site (`positive` / `negative` / `undetermined`), with the probe that justifies it. |
| `semantics/` | Node probe that evaluates only the fixed string `"secret"`, strict/module syntax checks, and the recorded output (Node 24.22.2). |
| `rules/` | Rule variants derived from `rules/security-baseline.yml` by `run_p6a.py` (R0 = unchanged; X1–X5 = ablations; CA/CB/CC = candidates). Not product rules. |
| `run_p6a.py` | Harness: verifies the baseline rule SHA-256, regenerates the variants, copies the corpora to a temporary directory, runs Semgrep 1.182.1, and scores each variant. |
| `results/results.json` | Per-variant site outcomes, fixture annotation outcomes, native rule-test summaries, R1 and 6A/6D/6E deltas versus R0, and timings. |

The commands and expected results are in section 7 of the report. Timing values vary with machine load and are not a performance claim.
