# P6-A dynamic-eval research materials

Research-only reproduction materials for the A8 false negative in `baseline.javascript-dynamic-eval`.
The product rule file is read, never modified. The full report (Korean) is
[`docs/p6a-dynamic-eval-false-negative-research.md`](../../docs/p6a-dynamic-eval-false-negative-research.md).

| Path | Contents |
| --- | --- |
| `cases/` | 29 synthetic scripts, one labelled call site each (14 positive, 10 negative, 4 undetermined, 1 invalid program). |
| `labels.json` | Semantic label per site with its rationale. `added_in: P6-A-R` marks the three audit additions; no P6-A label was changed. |
| `semantics/probe.cjs`, `probe-output.txt` | Concept probe (direct vs indirect eval) and its recorded Node 24.22.2 output. |
| `semantics/execute_cases.cjs`, `case-execution.txt` | Executes every case file in a fresh `vm` context with one fixed probe string and checks the observed behaviour against its label; also compiles strict-mode `eval` bindings. |
| `semantics/browser_window_cases.cjs`, `browser-window-output.txt` | Runs the three `window` cases as classic scripts in Chromium via the frontend's locked `@playwright/test`. |
| `semantics/strict.cjs`, `module.mjs` | Strict script and ES module forms of A8 for `node --check`. |
| `rules/` | Generated from `rules/security-baseline.yml` by `run_p6a.py`: R0 (unchanged), X1–X5 (ablations), CA/CB/CC (candidates), E1/E2 (evidence probes). `--check-rules` fails if a committed file differs from the derived text. Not product rules. |
| `run_p6a.py` | Harness: verifies the baseline rule SHA-256, derives the variants, copies corpora to a temporary directory, runs Semgrep 1.182.1, scores each variant with explicit denominators, records evidence probes and AST callee shapes. |
| `results/results.json` | Deterministic results; reruns reproduce it byte for byte. |
| `results/timing.json` | Wall-clock timings only; varies per run and is not a performance claim. |

Commands and expected results are in section 7 of the report.
