# Frozen-state known limitations

Recorded 2026-11-12 against tree `19e9548` (remote `main` at `801f03b`). Feature development is frozen, so these are documented and **not fixed**. The README lists further limitations; this file holds the ones found or re-confirmed during the closing review.

## CI: the uv version pin is silently ignored

| Item | Detail |
| --- | --- |
| Where | `.github/workflows/ci.yml`, three `astral-sh/setup-uv` steps |
| What | The steps pass `uv-version: 0.11.26`. The action has no such input; the valid name is `version`. |
| Observed | CI run 42671350671 on `801f03b` (2026-11-09) shows, for all three jobs, the warning `Unexpected input(s) 'uv-version'`, then `Could not determine uv version from uv.toml or pyproject.toml. Falling back to latest.` and `Successfully installed uv version 0.13.7`. |
| Effect | CI is green, but it runs whatever uv release is newest that day instead of the intended 0.11.26. Dependency versions are still fixed by `uv.lock` and `uv sync --locked`; the tool that installs them is not. A future uv release could change CI behavior with no change in this repository. |
| Not done | The input name was not corrected. Doing so would change which uv version CI runs and needs its own verification. |

The same run also reports that `actions/checkout` and `actions/setup-python` at the pinned commits target the deprecated Node.js 20 runtime, and that `ubuntu-latest` is migrating to a newer image. Neither was addressed.

## Product: findings are identified by line and column

| Item | Detail |
| --- | --- |
| Where | `src/ai_code_security_analyzer/semgrep_parser.py`, `_finding_id` |
| What | A finding ID is a hash of rule ID, path, start line and column, and end line and column. |
| Effect | Inserting a line above a finding, or renaming its file, changes its ID. Scan comparison then reports the old finding as disappeared and a new one as appeared. Review notes and statuses keyed by ID do not carry over, and a review backup can only be restored onto an identical set of IDs. |
| Evidence | D1 cases B (line shift), C (rename), and Da (deleting the first of two identical lines, which swaps which finding is reported as remaining): the product mis-identified 4 of 30 tracked findings, the same 4 as stock Semgrep output compared by location. See [D1 results](../../experiments/d1-finding-disappearance/RESULTS.md), section 4. The backup restriction is `finding_set_mismatch` in `frontend/src/features/scans/analystReviewBackup.ts`. |

## Product: the investigation evaluator cannot reach its strongest verdict

| Item | Detail |
| --- | --- |
| Where | `src/ai_code_security_analyzer/finding_disappearance_evaluator.py` |
| What | The source-change and rule-change hypotheses are always `UNDETERMINED`, because no source snapshot or Git diff is collected. |
| Effect | Through the shipped pipeline the evaluator does not produce a supported explanation for why a finding disappeared. In D1 it gave an exact cause for 15 of 30 findings, against 30 of 30 for a 227-line script that reads `git diff`. |

## Product: scan results are capped and can be rejected by size

| Item | Detail |
| --- | --- |
| Where | `src/ai_code_security_analyzer/services/scan_service.py` (`_MAX_FINDINGS = 50`), and the Semgrep output size limit in `semgrep_adapter.py` |
| Effect | The API returns at most 50 findings. In D2 case Go (5,000 findings, a complete scan) all three product modes failed with `output_limit_exceeded` and returned no findings, which counted as a false block. See [D2 results](../../experiments/d2-scanner-integrity/RESULTS.md), sections 3 and 4. |

## Product: incomplete scans are detected less often than by a short script

In D2 the product missed 4 to 8 of 13 incomplete scans depending on mode, against 2 for a 152-line script reading Semgrep's verbose JSON. Partial scans are reported with a generic `evidence_unavailable` reason instead of the specific cause. The product flagged no incomplete scan that the script missed.

## Semgrep behavior the product inherits

Observed with Semgrep 1.182.1 in D2 and not specific to this product:

- The default run exits 0 on partial parsing, rule timeouts, rule parse errors, and zero scanned targets.
- Files over 1 MB are skipped by default, and skipped paths appear in JSON only with `--verbose`.
- A file that does not contain the strings a rule requires is not parsed at all, so a syntax error in it is not reported.
- JSON `fingerprint` and `lines` contain the placeholder `requires login` when not logged in.
