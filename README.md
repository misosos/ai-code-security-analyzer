# AI Code Security Analyzer

A local, evidence-oriented review workspace built **on top of the Semgrep CLI**. It runs trusted local Semgrep rules against a registered directory, normalizes the results into unverified candidate findings, and gives an analyst a loopback-only API and React dashboard to triage, compare, and export them.

It is a security-engineering portfolio project. It is **not** an independent detection engine, it does **not** use AI in the shipped scan path, and it does **not** prove that a vulnerability exists or has been fixed. Read [Known limitations](#known-limitations) before relying on any output, and see the [portfolio overview](docs/portfolio-overview.md) for the design story.

> Most detailed design and validation records under `docs/` are written in Korean. This README and the portfolio overview are in English.

## Project status: feature development is frozen

Four checks looked for evidence that this product improves on existing tools. None found any, so no further features are planned. The code is kept as it is, with its known defects documented and not fixed. Start with the [research record](docs/research/README.md).

| Category | What belongs here |
| --- | --- |
| Implemented | The features in [What is implemented](#what-is-implemented). They exist and are covered by tests; that says nothing about whether they help an analyst. |
| Verified by experiment | Semgrep 1.182.1 with default options exited 0 on 11 of 13 synthetic incomplete scans ([D2](experiments/d2-scanner-integrity/RESULTS.md)). Comparing findings by location mis-identifies them after a line shift, a rename, or deletion of a duplicate line ([D1](experiments/d1-finding-disappearance/RESULTS.md)). No tested approach, including this product, claimed a fix it could not support. |
| Not verified | Whether the dashboard, review notes, or exports make a human analyst faster or more accurate. No person was measured and no user was interviewed. Real-world precision and recall. |
| Refuted differentiation hypotheses | "The product explains a disappeared finding better than Semgrep + Git": a 227-line script classified 30 of 30 tracked findings correctly, the product 15 ([D1](experiments/d1-finding-disappearance/RESULTS.md)). "The product catches incomplete scans better than existing approaches": it flagged no case that a 152-line script missed, and missed more ([D2](experiments/d2-scanner-integrity/RESULTS.md)). |
| Deliberately stopped | Expansion of the finding-disappearance evaluator and investigation API; scanner-integrity verdicts as a selling point; the search for new differentiators ([U1](docs/research/u1-appsec-workflow-problem-discovery.md)); a DefectDojo upstream contribution ([U1 closeout](docs/research/u1-closeout-defectdojo-upstream-feasibility.md)). The independent engine and AI review remain on hold. |

These experiments were small, synthetic, and designed, run, and scored without an independent party. They support "no evidence the product is better", not "a script is always enough". The limits are spelled out in the [research record](docs/research/README.md#limits-that-apply-to-all-of-this).

## What is implemented

| Area | Status | Notes |
| --- | --- | --- |
| CLI `scan` (text, JSON, analyst review, Markdown review) | Implemented | Wraps Semgrep 1.182.1 with trusted local rules |
| Local FastAPI backend (`127.0.0.1:8765`) | Implemented | Token, Host and Origin checks; fixed rule-profile allowlist |
| React dashboard | Implemented | Triage, review status and notes, scan comparison, exports |
| Exports: Markdown summary, analyst review Markdown, review backup JSON, comparison Markdown, SARIF 2.1.0 | Implemented | Generated in the browser from data already received |
| Finding-disappearance investigation mode (`/api/v2`) | Implemented, bounded | Enabled only by the official launcher; evidence expires after 15 minutes |
| Baseline rules (`rules/security-baseline.yml`) | Implemented | Dynamic eval, React `dangerouslySetInnerHTML`, Firestore unconditional write |
| Experimental taint rule profiles | Experimental | Selectable in the API/dashboard and labeled experimental |
| AI review modules (`ai_review.py`, `ollama_provider.py`, code-context extraction) | Research only | Not called by the CLI, API, or dashboard |
| Isolated Semgrep worker / container sandbox | Design only | No worker is built or executed |

## Quickstart

Commands run from the repository root unless noted.

### 1. Prerequisites

| Tool | Version used by CI | Check |
| --- | --- | --- |
| Python | 3.12 (`.python-version`) | `python3 --version` |
| uv | 0.11.26 | `uv --version` |
| Semgrep CLI | **1.182.1**, on `PATH` | `semgrep --version` |
| Node.js / npm | Node 24.22.2 (`.nvmrc`; `frontend/package.json` requires `>=24 <25`) | `node --version` |

Install the pinned Semgrep the same way CI does:

```sh
uv tool install --python 3.12 'semgrep==1.182.1'
semgrep --version   # must print 1.182.1
```

Node.js is only needed for the dashboard. The CLI and API need Python, uv and Semgrep.

### 2. Install locked dependencies

```sh
uv sync --locked
uv run --locked python -m ai_code_security_analyzer --help
```

### 3. Run a sample scan (CLI)

The repository ships small positive fixtures. Copy them to a neutral directory first: scanning them in place under `tests/` returns `partial` with `no_files_scanned` (see [Troubleshooting](#troubleshooting)).

```sh
SAMPLE="$(mktemp -d)"
cp tests/fixtures/security_baseline/positive/* "$SAMPLE"/
uv run --locked python -m ai_code_security_analyzer scan \
  --path "$SAMPLE" --rules rules/security-baseline.yml
```

Expected: `Status: completed` and `Findings: 7 unverified candidate(s)` (5 high, 2 medium).

Other formats:

```sh
# Machine-readable JSON
uv run --locked python -m ai_code_security_analyzer scan --path "$SAMPLE" \
  --rules rules/security-baseline.yml --format json

# Analyst review as a NEW Markdown file (refuses to overwrite an existing file)
uv run --locked python -m ai_code_security_analyzer scan --path "$SAMPLE" \
  --rules rules/security-baseline.yml --format review-md --output review-report.md
```

`--format` accepts `text` (default), `json`, `review` and `review-md`. `--output` is only accepted with `json` or `review-md`.

| Exit code | Meaning |
| --- | --- |
| 0 | Scan completed. Findings may still be present. |
| 1 | Partial scan or result-conversion loss. Treat findings as incomplete candidates. |
| 2 | Invalid CLI arguments, local path, or output file (including an existing `--output` file). |
| 3 | Full failure (Semgrep execution, JSON handling, or report write). |

`completed=true` means the scan finished. It does **not** mean the code is safe. Every finding is unverified (`"status": "unverified"` in CLI JSON, `verification_status: "unverified"` in API responses). Reports omit source snippets and raw Semgrep JSON and identify the target by a hash, but they can still contain relative file paths and rule IDs. Review them before sharing.

### 4. Configure the local API

The API scans only directories registered through environment variables at startup. The browser cannot choose arbitrary paths.

| Variable | Required | Meaning |
| --- | --- | --- |
| `AI_CODE_SECURITY_API_TOKEN` | Yes | 43–256 characters from `[A-Za-z0-9_-]`. Required for `POST /api/v1/scans` and all `/api/v2` calls. `GET /api/v1/health` and `/api/v1/options` do not require it. |
| `AI_CODE_SECURITY_TARGET` | One of these two | A single target directory, exposed as target ID `local-project`. |
| `AI_CODE_SECURITY_TARGETS` | One of these two | JSON array of up to 32 `{"id","label","path"}` objects with absolute paths. Setting both variables is rejected. |
| `AI_CODE_SECURITY_ALLOWED_ORIGINS` | For browser use | Comma-separated exact Origins (no wildcard). Requests carrying any other `Origin` header are rejected. |
| `AI_CODE_SECURITY_RULES_DIR` | No | Trusted rules directory. Defaults to the repository `rules/`. |

Generate a token (43 URL-safe characters):

```sh
uv run --locked python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Use a dedicated value. Do not commit it or paste it into shared logs.

### 5. Start the API and dashboard

**Option A: built dashboard served by the API (single origin).** When `frontend/dist` exists, the API serves it at `/`.

```sh
(cd frontend && npm ci && npm run build)
AI_CODE_SECURITY_TARGET="$SAMPLE" \
AI_CODE_SECURITY_API_TOKEN='<your-token>' \
AI_CODE_SECURITY_ALLOWED_ORIGINS='http://127.0.0.1:8765' \
uv run --locked python -m ai_code_security_analyzer.api
```

Open `http://127.0.0.1:8765` and enter the token in the dashboard. The token is kept only in page memory and is lost on reload.

**Option B: Vite dev server.** Vite binds to `127.0.0.1:5173` and proxies only `/api` to `127.0.0.1:8765`.

```sh
# Terminal 1
cd frontend && npm ci && npm run dev
# Terminal 2 (repository root)
AI_CODE_SECURITY_TARGET="$SAMPLE" \
AI_CODE_SECURITY_API_TOKEN='<your-token>' \
AI_CODE_SECURITY_ALLOWED_ORIGINS='http://127.0.0.1:5173' \
uv run --locked python -m ai_code_security_analyzer.api
```

Open `http://127.0.0.1:5173`.

### 6. Review findings and export results

In the dashboard (UI text is Korean):

1. Choose a registered target and the **Baseline Rules** profile, then run a scan. Experimental profiles are labeled as such.
2. Select a finding to see its rule, location, severity, triage guidance, and which evidence claims were validated or restricted.
3. Set a review status and optional note per finding. This state lives **only in browser memory** (see limitations).
4. Run a second scan of the same target and profile to compare finding IDs. Comparison is blocked when either scan is partial or failed, or when findings were omitted (the API returns at most 50 findings per scan).
5. Export what you need:
   - Current-scan Markdown summary (`Markdown 다운로드`)
   - SARIF 2.1.0 file (`SARIF 다운로드`). No upload is performed.
   - Analyst review Markdown, with notes included only after explicit confirmation
   - Review backup JSON (`검토 기록 백업 JSON 다운로드`), which can be restored onto findings with the same IDs
   - Comparison Markdown for two observed scans

Exports are built from data already in the page and never re-run Semgrep. Downloaded files persist on disk, so check notes before sharing.

### Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| API exits with `local_api_configuration_required` | Token or target variable missing. Set `AI_CODE_SECURITY_API_TOKEN` and one of `AI_CODE_SECURITY_TARGET` / `AI_CODE_SECURITY_TARGETS`. |
| API exits with `local_api_configuration_invalid` | Token shorter than 43 characters or containing other characters; both target variables set; or malformed `AI_CODE_SECURITY_TARGETS` JSON (relative paths, extra keys, more than 32 entries). |
| API does not start, or a different instance answers | The launcher always binds `127.0.0.1:8765`. Check for an existing listener with `lsof -nP -iTCP:8765 -sTCP:LISTEN` and stop that instance yourself. |
| `403 origin_not_allowed` | The page's exact Origin is missing from `AI_CODE_SECURITY_ALLOWED_ORIGINS` (`http://127.0.0.1:8765` for Option A, `http://127.0.0.1:5173` for Option B). |
| `401 unauthorized` | Missing or wrong token in the dashboard. |
| Scan reports `partial` with `no_files_scanned` | The target matched no supported files, or its path falls under Semgrep's default ignore patterns (observed for a target inside `tests/`). Scan a copy in a neutral directory. |
| `semgrep_not_installed` or `version_check_failed` | Semgrep is not on `PATH` or does not run. Install `semgrep==1.182.1` as shown above. |
| CLI exit code 2 with `--output` | The output file already exists, or the format is not `json` / `review-md`. |
| `npm ci` or `node` fails | Use Node.js 24 (`.nvmrc`: 24.22.2). Other major versions are not tested. |

## Known limitations

These are current, verified limitations. A missing finding is never evidence that code is safe or fixed.

| Limitation | Detail | Evidence |
| --- | --- | --- |
| Semgrep-based scanning | All detection is performed by the Semgrep 1.182.1 CLI with this repository's rules. There is no independent analysis engine. | `src/ai_code_security_analyzer/semgrep_adapter.py` |
| AI review is not product-integrated | AI review, Ollama provider and code-context modules exist for research but are not called by the CLI, API, or dashboard. | [AI review contract](docs/ai-review-contract.md) |
| Known false negatives, including A8 | The dynamic-eval rule misses `globalThis.eval`/`window.eval`, destructured aliases, `Reflect.construct(Function, …)`, cross-function wrappers, and (A8, verified and unfixed) a local `const eval = globalThis.eval` binding. Other rules have documented scope gaps. | [R1-P record, A8](docs/r1p-dynamic-eval-rule-integration.md), [rules README](rules/README.md) |
| Partial scans are `INCOMPARABLE` | A partial or failed scan is never treated as a completed comparison. A proposed change to the partial-scan classification contract is deferred. | `frontend/src/features/scans/compare.ts`, `src/ai_code_security_analyzer/finding_disappearance_evaluator.py` |
| Investigation over-abstention (S5a), unresolved | The investigation evaluator is deliberately conservative and often returns `UNDETERMINED`. The over-abstention issue tracked as S5a is not fixed. No evaluation record for S5a is committed in this repository. | [Investigation evidence boundaries](docs/case-studies/investigation-evidence-boundaries.md) |
| No automatic proof of remediation | A finding that disappears between scans is reported as an observation, not a fix. | [ER-D9 differentiation](docs/er-d9-differentiation-assessment.md) |
| No Git integration or rename linking | Source snapshots and Git diffs are not collected. Renamed or moved files are not linked across scans. | [ER-D9 differentiation](docs/er-d9-differentiation-assessment.md) |
| Investigation evidence TTL: 15 minutes | Server-side run and session evidence is held in bounded memory and expires after 900 seconds. | `src/ai_code_security_analyzer/investigation_evidence_registry.py` |
| Review state is in memory only | Review statuses and notes are not saved automatically and are lost on reload unless exported as backup JSON. | [Phase 8C](docs/phase8c-analyst-review-state.md), [Phase 8E](docs/phase8e-analyst-review-backup-restore.md) |
| Rescan requires confirmation | When review work exists, starting a new scan asks for confirmation and points to the backup download. Only a normally completed rescan clears the previous review records. | `frontend/src/app/App.tsx` |
| Failed or partial rescans keep the previous result | If a confirmed rescan fails or returns a partial/failed status, the new result is not applied; the previous scan and its review records are restored and labeled as the previous result. To view that partial result, export a backup, clear results, and rescan. | [P5 record](docs/p5-failure-safe-review-rescan.md) |
| SARIF upload compatibility unverified | SARIF output validates against the official 2.1.0 schema, but upload to GitHub Code Scanning has not been tested. | [Phase 8M](docs/phase8m-sarif-export.md), [Phase 8N](docs/phase8n-github-code-scanning-preflight.md) |
| No improvement over Semgrep CLI + Git, and two comparisons went the other way | No study shows better detection, faster triage, or better decisions than using Semgrep with Git directly. In two synthetic comparisons a short script matched or beat the product. | [ER-D9 differentiation](docs/er-d9-differentiation-assessment.md), [D1](experiments/d1-finding-disappearance/RESULTS.md), [D2](experiments/d2-scanner-integrity/RESULTS.md) |
| Findings are identified by line and column | A line shift or file rename changes a finding's ID, so comparison reports it as disappeared and review state does not carry over. | [Frozen-state limitations](docs/research/frozen-state-known-limitations.md) |
| CI does not pin uv | The workflow passes `uv-version`, which `setup-uv` ignores; CI installs the latest uv instead of 0.11.26. Documented, not fixed. | [Frozen-state limitations](docs/research/frozen-state-known-limitations.md) |
| No execution sandbox | Semgrep runs with local rules, metrics off and a temporary `HOME`, but without OS-level network or filesystem isolation. Scan untrusted repositories only inside a separately isolated environment. | [Phase 7C-1B design](docs/phase7c1b-verifiable-worker-design.md) |
| Synthetic evaluation only | Benchmarks use small, author-written synthetic corpora. Real-world precision and recall are not measured. | [Phase 6E](docs/phase6e-heldout-sast-evaluation.md) |

## Validation

CI (`.github/workflows/ci.yml`) runs three required jobs on every push and pull request to `main`:

- **Python tests and CLI**: lockfile check, CLI entry points, full `pytest` suite
- **Semgrep 1.182.1 integration**: real local-rule tests and the synthetic benchmark suites (Phases 6A, 6D, 6E)
- **React dashboard**: typecheck, Vitest, production build, Playwright browser smoke test, and a real Chromium–FastAPI–Semgrep end-to-end test (`npm run test:e2e:real`)

Run the core checks locally:

```sh
SEMGREP_REQUIRED=1 uv run --locked python -m pytest -q -rs
(cd frontend && npm ci && npm run typecheck && npm test && npm run build)
```

## Further documentation

- [Research record](docs/research/README.md): what was tested, the verdicts, how to recompute the scores, and why development stopped
- [Portfolio overview](docs/portfolio-overview.md): problem, architecture, workflow, controls, and future work
- [Local API](docs/phase5a-local-api.md) and [React dashboard](docs/phase5b-react-dashboard.md)
- [Analyst review view](docs/analyst-review-view.md) and [Markdown review report](docs/phase3c4-markdown-review-report.md)
- [Finding-disappearance case study](docs/case-studies/finding-disappearance-investigation.md) and [reproduction record](docs/er-d1-reproducibility-record.md)
- [Baseline rule scope and limits](rules/README.md)
