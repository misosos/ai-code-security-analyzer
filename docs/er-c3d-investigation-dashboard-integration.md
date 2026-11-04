# ER-C3D — Investigation Dashboard Integration

## Scope and gate

- Base SHA: `0c923950cd63359f945f03a8c59a30409706615b`
- GitHub Actions run: `41858503487`; push/completed/success, Python tests and CLI, React dashboard, and Semgrep 1.182.1 integration succeeded; artifacts: 0.
- Worktree: `/tmp/ai-csa-er-c3d-investigation-dashboard`
- Branch: `research/er-c3d-investigation-dashboard`
- The regular `/api/v1/scans` flow remains the default. Investigation endpoints are called only after the analyst explicitly chooses investigation mode.
- This UI does not decide that a Finding was fixed, resolved, or safe. It displays the existing ER-C3C evaluation and its limitations.

## UI and client flow

The scan configuration keeps the existing compact layout. An adjacent “소멸 근거 조사 선택” disclosure exposes the mode radio controls and the full retention caveat. The default is “일반 검사”; the selected mode exists in React memory only.

`frontend/src/api/investigation.ts` implements closed request/response parsing for the ER-C3C v2 contract. It validates exact envelope keys, contract versions, the 43-character base64url handle form, every evaluation enum and limitation code, array bounds, and duplicate Finding IDs. Scan payloads pass through the existing `parseScan()`. Requests are POST JSON with the local token header, `cache: no-store`, omitted credentials, redirect errors, and no referrer. Handles are carried only in JSON bodies. Release requires HTTP 204 and does not try to parse JSON.

`EvidenceBackedScan` pairs one validated `ScanSnapshot` with the handle returned for that exact request. It is held only in component memory. The app never makes a handle for a v1 baseline. Client/server Finding IDs and categories are checked against the exact baseline/current snapshots before a server Evaluation is displayed.

The workflow is:

1. Select investigation mode.
2. Run the baseline scan through `/api/v2/investigation-scans` and save that response/handle pair as the comparison baseline.
3. Re-scan the same target and profile in investigation mode.
4. Explicitly request evaluation. The client creates a server session and evaluates it through `/api/v2/investigations` and `/api/v2/investigations/evaluate`.
5. Review the three Finding ID categories and the path/hypothesis/limitation codes.
6. Release the session first, then the no-longer-needed Run records.

A v1 baseline displays that no server evidence is attached and asks for a new investigation-mode baseline scan. Switching off the mode, clearing the baseline/results/token, replacing a baseline, or starting another scan invalidates corresponding UI state and makes a best-effort Release request. A late v2 scan response is released if its request sequence is stale. The server's absolute 15-minute TTL remains the final cleanup bound; navigation, disconnect, or browser close cannot guarantee a successful release.

## Result language and failures

The panel presents the overall comparison assessment, category counts, and per-Finding path and hypothesis states. Fixed Korean labels distinguish observed processing paths, explicit skip observations, uncollected skip data, unavailable scope data, and undetermined hypotheses. It displays the critical limitation that Finding non-observation is not evidence of remediation and source snapshots were not collected.

Known API errors map to fixed messages; arbitrary server text, handles, and tokens are not rendered. `evidence_unavailable` clears the local handles/evaluation and attempts Release; the UI asks for new investigation-mode scans. `unsupported_deployment` does not fall back to v1; the analyst must explicitly choose regular scan mode. `evaluation_busy`, `binding_rejected`, rate/resource limits, invalid requests, and connection errors have distinct fixed guidance.

Analyst review status and memo logic remain separate. Evaluation cannot update review status. Handles/manifests are excluded from Markdown, SARIF, JSON backup, and browser storage.

## Browser design and evidence

The feature uses the existing dark navy, cyan, and violet system. The optional mode is tucked into the existing scan settings; the detailed evaluation lives in the existing comparison area. No new dashboard-level summary card was added. The disclosure keeps regular-mode scan layout compact.

Automated screenshots use synthetic Findings and are not Safari acceptance evidence:

- [1440 px evaluation view](assets/er-c3d-investigation-results-1440.png)
- [390 px evaluation view](assets/er-c3d-investigation-results-390.png)

## Validation

The implementation added API parser/transport tests, workflow binding tests, a mocked browser workflow, and an actual FastAPI–Semgrep–Chromium investigation workflow. The actual test uses only a temporary synthetic project and the trusted local baseline rules. Its first run observes Finding A/B (`stable.js`, `retired.js`); the second observes A/C (`stable.js`, `added.js`). It checks the server's `shared`, `baselineOnly`, and `currentOnly` categories, the `UNDETERMINED` overall assessment, authorized body-only handles, absence of tokens/paths in the rendered page, 204 releases, and rejection of session reuse after release. It does not inject fixture truth into the evaluator.

Final local validation (Node.js 24.22.2, Python 3.12.7, Semgrep 1.182.1):

- `mise exec node@24 -- npm run typecheck`: passed.
- `mise exec node@24 -- npm test`: 190 passed across 17 files.
- `mise exec node@24 -- npm run build`: passed.
- Full Chromium Playwright suite with `CI=1` and an isolated preview port: 51 passed, including the investigation browser flow, the complete dashboard/keyboard/a11y regressions, and 320px overflow coverage.
- Dedicated Playwright WebKit suite: 2 passed.
- Investigation mocked browser flow: verifies the default is general mode, v2 is called only after explicit selection, exact v1/v2 distinction, client/server finding partition match, handle body-only use, no browser storage, release order, unsupported-deployment behavior, axe with zero violations, and no horizontal overflow at 1920, 1440, 1024, 768, 600, 390, and 320 px.
- Layout checks: at 1440 × 900 the existing results list remained `listY=724.44`, `firstRowY=784`. The start-screen mission deck is 419 px with the investigation option collapsed, under the existing 460 px regression threshold.
- `SEMGREP_REQUIRED=1 mise exec node@24 -- npm run test:e2e:real`: 3 passed. This includes the existing real Semgrep tests and the new investigation flow using actual FastAPI and Semgrep 1.182.1. The synthetic first scan observed A/B; after changing only the retired fixture and adding another synthetic match, the second scan observed A/C. The evaluation returned `shared`, `baselineOnly`, `currentOnly`, and `UNDETERMINED`; releasing made the session unavailable. No source snapshot or remediation claim was injected.
- `uv lock --check`: passed.
- `SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 uv run --locked python -m pytest -q -rs`: 646 passed, 28 opt-in Ollama tests skipped, 1 existing Starlette/AnyIO deprecation warning.
- CI Semgrep integration command against local rules and FastAPI: 19 passed, 1 existing Starlette/AnyIO deprecation warning.
- `mise exec node@24 -- npm run test:qa:safari`: 7 automation tests passed. This is Safari QA harness automation, not manual Safari acceptance.
- `git diff --check`: passed.

A first full browser run surfaced that visible radio controls added 134 px to the default scan panel and failed the existing deck-height test. The investigation option was moved into the existing scan-settings disclosure; the full Chromium suite then passed and the ordinary scan layout stayed compact. Browser-generated modifications to unrelated legacy screenshot assets were restored; only the two ER-C3D synthetic captures are retained.

Python source and API contracts were not changed in ER-C3D. The real test uses the existing backend v2 contracts and isolated server; `run-real-semgrep-e2e.mjs` now explicitly enables the investigation API for that trusted one-worker, no-reload test process. Actual macOS Safari, VoiceOver, iOS Safari, and manual 200% zoom remain pending/not verified. The screenshots and browser checks are automated evidence, not user acceptance.

## User acceptance checklist

1. Confirm a default regular scan still uses v1 and produces no Run Handle.
2. Expand “소멸 근거 조사 선택”; choose investigation mode and review the 15-minute retention and non-remediation note.
3. Run a first synthetic/project scan, then save it as the comparison baseline.
4. Re-scan the same target and rule profile in investigation mode.
5. Open the comparison panel and explicitly run “소멸 근거 조사 실행”.
6. Review `currentOnly`, `shared`, and `baselineOnly`, including path and hypothesis states and limitations.
7. Confirm the result never says the Finding was fixed or resolved.
8. Release evidence and check that the panel says it requested release.
9. Check expiry/connection failure guidance; do not expect recovery after browser reload.
10. Inspect the layout on mobile and perform actual Safari QA. Automation does not complete Safari user acceptance.

## Limits and next gate

The dashboard does not persist handles, restore them after reload, or provide per-user isolation. The local API token is shared within an installation; multi-user and multi-worker deployment remain unsupported. The UI does not force a hard API server memory cap and does not guarantee delivery of best-effort Release calls. Server evidence remains ephemeral and bounded by the backend TTL/Registry limits.

ER-C3D does not approve deployment. ER-C3E should proceed only after exact-SHA CI and user acceptance review, and should preserve the no-persistence, exact-run binding, fixed-message, fail-closed, and non-remediation properties.
