# ER-D5 재현성 기록

## 기준과 환경

- Repository: `misosos/ai-code-security-analyzer`
- 기준 SHA: `b0cdd0224f8fd436087e65e350f394ce76cf5821`
- 시작 CI: GitHub Actions Run `42172916735`, exact SHA push, success; Python, React, Semgrep jobs 성공; Artifacts 0.
- Worktree/branch: `/tmp/ai-csa-er-d5-skip-evidence-evaluation`, `research/er-d5-skip-evidence-evaluation`.
- macOS arm64, Python 3.12.7, uv 0.11.26, Semgrep OSS 1.182.1, Node.js 24.22.2.

## 독립 재현 명령

Repository root:

```bash
uv run --locked python scripts/evaluate_er_d5_skip_evidence.py
```

Frontend:

```bash
mise exec node@24 -- npm ci --no-audit --no-fund
mise exec node@24 -- npm run build
SEMGREP_REQUIRED=1 mise exec node@24 -- npm run test:e2e:real
```

Python 집중 계약/E2E:

```bash
uv run --locked pytest tests/test_semgrep_adapter.py tests/test_semgrep_parser.py tests/test_scan_evidence_manifest.py tests/test_finding_disappearance_evaluator.py tests/test_investigation_evidence_registry.py tests/test_investigation_api.py
```

ER-D2/D3 재현:

```bash
uv run --locked python scripts/evaluate_er_d2_workflow.py
uv run --locked python scripts/research_er_d3_evidence_gaps.py
```

## Synthetic Fixture와 절차

하네스는 OS 임시 디렉터리에 `stable.js`와 `retired.js`를 만들고 저장소의 trusted baseline rules를 읽는다. 첫 상태에는 두 경로 모두 `eval` Finding이 있으며, 두 번째 상태에는 `.semgrepignore`로 `retired.js`만 제외한다. 실제 v1 API에서 baseline/current를 검사하고, 같은 상태를 별도 재구성해 v2 verbose baseline/current를 검사한다. 서로 다른 invocation mode의 Runs는 한 Session으로 묶지 않는다.

v2는 실제 API에서 Run을 등록하고 Session/Evaluator를 호출한다. 내부 Registry에서 현재 Run의 검증된 ScopeEvidence를 assertion으로 확인하지만, 출력 Projection에는 Finding 분류 수, 고정 코드, 상태만 기록한다. Handle, Token, 내부 scan reference, raw Manifest/JSON, 소스 내용은 파일이나 stdout에 기록하지 않는다. 마지막에 Session 및 Run을 release하고 Session의 재사용 거부를 확인한다. 임시 fixture는 종료 시 자동 삭제한다.

## 결과

재현 스크립트 통과 출력 요약:

- Semgrep 1.182.1.
- v1 비-verbose: baseline/current 모두 `completed`; `shared=1`, `baselineOnly=1`, `currentOnly=0`; skip reason 및 `paths`는 공개 응답에 없음.
- v2 verbose: baseline `completed`; current `partial`, `completed=false`; Registry에서 `retired.js` + `semgrepignore_patterns_match` 관찰.
- Finding B: `baselineOnly`, `PATH_EXPLICITLY_SKIPPED`, `SUPPORTED`.
- 전체: `INCOMPARABLE`; Scope completeness `UNVERIFIED`.
- 제한에 `source_snapshot_not_collected`, `scope_completeness_unverified`, `loaded_rule_identity_unverified` 포함.
- Session release 후 평가: 404 `evidence_unavailable`.
- 두 실행 모드의 partition은 일치; 서로 혼합된 Session은 없음.

## 검증 결과와 계층

- 신규 실제 API 재현 스크립트: 통과.
- ER-D2 script: 통과.
- ER-D3 feasibility script: 통과.
- 6개 Backend 집중 파일: 145 passed, Starlette `BlockingPortal` deprecation warning 1개.
- Frontend typecheck: 통과.
- Vitest: 18 files, 196 passed.
- Production build: 통과.
- Actual FastAPI–Semgrep–Chromium browser suite: 3 passed.
- `uv lock --check`: 통과.
- Python 전체 suite, WebKit, axe, Safari QA scripts: 이번 D5에서 실행하지 않음.

첫 browser 실행은 `frontend/dist`가 없어 격리 API에서 `/`가 404로 실패했다. production build 후 동일한 E2E를 다시 실행했고 통과했다. root에서 npm script를 잘못 호출한 `package.json` 경로 오류도 frontend 폴더에서 다시 실행해 해결했다. 두 실패는 환경 준비 문제이며 통과로 세지 않았다.

## 재현 한계

- v1과 v2는 각기 다른 실제 Semgrep 프로세스 실행이다. Fixture 상태가 대응하지만 동일한 process/input read transaction이 아니다.
- 실제 E2E는 Semgrep 1.182.1 및 저장소 baseline rules의 특정 ignore reason에 한정된다.
- 브라우저 검증은 Chromium 자동화이지 Safari 사용자 검수가 아니다.
- 정상 0 Finding, unknown reason, traversal, wrong Target/Profile/Invocation, TTL/expiry 등은 이번 새 실제 E2E 하네스에서 모두 돌린 것이 아니라 해당 기존 synthetic contract tests로 검증한다.
- 평가자 참여가 없으므로 이해도·정확도·시간 개선은 `NOT_ESTABLISHED`.
