# Research record: what was tested, and what it showed

Status: after the results below, **new feature expansion was put on hold.** Since 2026-11-12 the project is in maintenance: confirmed defects are fixed, and the research results here are preserved as recorded. This directory is the entry point for a reviewer who wants to check the evidence behind that decision.

The short version: four successive checks looked for a reason to keep building this product. None found one. Two experiments showed that a small script on top of Semgrep and Git did as well as or better than the product on the tasks the product was built for. Two rounds of public-source research found real workflow problems, but each was already addressed by existing tools, configuration, or a paid feature.

The detailed records are written in Korean. This index is in English.

## Where to look

| Question | Read | Verdict |
| --- | --- | --- |
| Does the product investigate a disappeared finding better than Semgrep + Git + a script? | [D1 results](../../experiments/d1-finding-disappearance/RESULTS.md), [protocol](../../experiments/d1-finding-disappearance/PROTOCOL.md) | `BASELINE_SUFFICIENT` |
| Does the product catch incomplete scans better than existing approaches? | [D2 results](../../experiments/d2-scanner-integrity/RESULTS.md), [protocol](../../experiments/d2-scanner-integrity/PROTOCOL.md) | `EVIDENCE_INSUFFICIENT` |
| Is there public evidence of an unmet AppSec workflow problem this project could address? | [U1](u1-appsec-workflow-problem-discovery.md) | `NO_PRODUCT_EVIDENCE` |
| Is there a justified upstream contribution to DefectDojo for finding identity across re-imports? | [U1 closeout](u1-closeout-defectdojo-upstream-feasibility.md) | `EVIDENCE_INSUFFICIENT` |
| What was known to be wrong with the product when expansion stopped? | [Frozen-state limitations](frozen-state-known-limitations.md) | — |

## Results in one table

| Study | Measured | Result |
| --- | --- | --- |
| D1 | 14 synthetic cases, 30 tracked findings, 3 repetitions | Stock Semgrep: 16 exact, 4 wrong. Script (227 lines): 30 exact. Product: 15 exact, 4 wrong. No arm made a false "fixed" claim. |
| D2 | 18 synthetic cases, 13 incomplete and 5 complete, 3 repetitions | Incomplete scans missed: default Semgrep 11, `--strict` 9, script (152 lines) 2, product 4 to 8 depending on mode. The product flagged no case that the script missed, and wrongly blocked 1 to 2 complete scans. |
| U1 | Public issues, vendor documentation, surveys | Five observed problems, three candidates, none selected. |
| U1 closeout | DefectDojo 3.5.101 source and seven issues/PRs | Three historical bugs are fixed. The remaining line-drift behavior is a trade-off the maintainers have already acknowledged. No pull request proposed. |

## How to check the numbers

The raw outputs of every run are committed. Re-scoring them needs only Python 3.12 and no dependencies:

```sh
python experiments/d1-finding-disappearance/evaluate.py
python experiments/d2-scanner-integrity/evaluate.py
```

Each command rewrites `results.json` in its directory from the files under `raw/`. On an unmodified checkout, `git status` shows no change afterwards. Re-running the scans themselves needs Semgrep 1.182.1 and is described in section 1 of each `RESULTS.md`.

## Provenance of the published history

The experiment documents cite commit IDs: `18b113a` and `5aa4af4` for D1, `3e83aaf` and `6707499` for D2. **Those commits are not part of this repository's public history.** They exist only in the author's local repository. The public branch was assembled afterwards from the final files, so that the path fragments described below would not be published.

The consequence is that the pre-registration order cannot be checked from the public history. In the local history, each protocol, label file, and case builder was committed before any comparison was run, and the results were committed afterwards. A reader of this repository has only the author's statement for that. Treat the "pre-registered" label accordingly.

Commit IDs `787798b` and `801f03b` in the same documents refer to the product tree the experiments ran against. `801f03b` is on the public `main` branch.

## Limits that apply to all of this

- **No independent party was involved.** The cases, the labels, the comparison scripts, and the scoring were all produced in the same AI-assisted sessions as the analysis. A script written by someone who knows the cases is weak evidence that "a script is enough". The supportable claim is narrower: there is no evidence that the product is better.
- **Synthetic and small.** All experiment targets are short, author-written JavaScript fixtures. Nothing here measures real repositories.
- **No people were measured.** No analyst time, accuracy, or preference was observed. No user interviews were conducted.
- **Two D2 cases did not behave as designed.** Cases A and F1 were labeled incomplete, but Semgrep emitted no signal for them and every arm missed them. The labels were not changed after the fact. See D2 results, section 5.
- **U1 is a search, not a survey.** "No evidence found" does not mean "no demand exists". Some sources were read only as search summaries and are marked as such.
- **Nothing in the U1 closeout was executed.** It is a reading of DefectDojo source and issues.

## Research that was stopped on purpose

| Line of work | State |
| --- | --- |
| Finding-disappearance evaluator and investigation API expansion | Stopped after D1 |
| Scanner-integrity verdicts as a differentiator | Stopped after D2 |
| Search for further differentiation candidates | Stopped after U1 |
| DefectDojo reproduction experiment | Not run; the most it could yield is a documentation note |
| Independent analysis engine, AI review integration | Remain on hold from earlier phases |

## Note on raw outputs

About 1,040 small text files (5.6 MB) are kept under `experiments/*/raw/` so that the scores can be recomputed. Temporary paths in them were replaced with `<TMP>` or `<TMP-TRUNCATED>` when the experiments were recorded.

One further replacement was made for publication. In 21 D2 files, all named `c.stderr.txt`, one line each still held the tail of a temporary directory path including a random session identifier. That fragment was replaced with `<TMP>`. Nothing else in those files changed, and no other file differs from the locally recorded results. The scoring scripts do not read these files; `evaluate.py` was run before and after the replacement and produced identical output and byte-identical `results.json` for both studies.
