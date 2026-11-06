# ER-D5 — Skip Evidence 실효성 평가 결과

## 요약

실제 Semgrep OSS 1.182.1과 격리 합성 JavaScript를 사용해 비-verbose v1 API와 verbose v2 조사 API를 별도 실행으로 비교했다. 두 실행 모드 모두 Finding 변화를 `shared=1`, `baselineOnly=1`, `currentOnly=0`으로 나눴다. **v2가 추가한 정보는 baseline-only Finding B의 현재 경로가 `retired.js`이고 Semgrep이 이를 `semgrepignore_patterns_match`로 제외했다고 보고했다는 Run-bound 관찰이다.**

v2 현재 Scan은 `partial`, `completed=false`; Evaluation은 `comparability=INCOMPARABLE`, `overall_assessment=INCOMPARABLE`이었다. Finding B의 `path_observation=PATH_EXPLICITLY_SKIPPED`, `skip_hypothesis=SUPPORTED`는 제한된 검사 절차 관찰이다. 이는 수정·해결·유일 원인을 입증하지 않는다.

## 환경과 실행

- 기준 SHA: `b0cdd0224f8fd436087e65e350f394ce76cf5821`
- 시작 CI: GitHub Actions `42172916735`, push/completed/success; 필수 세 Job 성공, artifacts 0.
- 격리 worktree: `/tmp/ai-csa-er-d5-skip-evidence-evaluation`
- Python 3.12.7, uv 0.11.26, Semgrep 1.182.1, Node.js 24.22.2 (`mise`).
- 재현: `uv run --locked python scripts/evaluate_er_d5_skip_evidence.py`
- 브라우저 E2E: `SEMGREP_REQUIRED=1 mise exec node@24 -- npm run test:e2e:real` (frontend 디렉터리에서).
- Fixture: 임시 Target의 합성 `stable.js`, `retired.js`; 기존 trusted `rules/security-baseline.yml`은 읽기만 했다.

v1 baseline/current 두 호출과 v2 verbose baseline/current 두 호출은 독립 검사다. 서로 다른 invocation ID의 Run은 함께 Session에 묶지 않았다. 각 군 안에서만 정상 비교 또는 v2 Evaluation을 만들었다.

## Scenario 결과

| 항목 | 기본 비-verbose v1 | ER-D4 verbose v2 |
| --- | --- | --- |
| baseline Finding | `stable.js`, `retired.js` | `stable.js`, `retired.js` |
| current Finding | `stable.js` | `stable.js` |
| 변화 partition | shared 1, baselineOnly 1, currentOnly 0 | shared 1, baselineOnly 1, currentOnly 0 |
| current ScanStatus | `completed` | `partial` |
| `completed` | true | false |
| public 응답의 skip reason | 없음; Scope `paths` 자료도 반환하지 않음 | Finding-level projection으로 제한된 관찰 표시 |
| 내부 Run Scope | v1 endpoint는 Manifest를 공개하지 않음 | skipped `retired.js` / `semgrepignore_patterns_match`, `OBSERVED` |
| Scope completeness | 판정 불가 | `UNVERIFIED` |
| Finding B path observation | 없음 | `PATH_EXPLICITLY_SKIPPED` |
| Finding B skip hypothesis | 없음 | `SUPPORTED` |
| aggregate Evaluation | 기존 v1 ScanResponse 두 건에는 서버 ER Evaluation 없음 | `INCOMPARABLE` / `INCOMPARABLE` |

v1에서 `completed`로 보이는 것은 비-verbose 응답에 skip 상세가 노출되지 않아 parser가 해당 ignore를 부분 검사 issue로 판정하지 않았다는 현재 동작이다. 이를 Scope 완전성의 증명으로 해석하지 않는다. v1과 v2 상태 차이를 숨기거나 동일 실행 특성으로 처리하지 않았다.

## 실제 API와 UI 관찰 경계

재현 스크립트는 v1 Scan API, v2 investigation-scan, v2 session/evaluate/release를 실제 `TestClient` 요청으로 호출했다. v2 Manifest는 앱 인스턴스 Registry 안에서 확인했으며 보고서에는 내부 Run Reference, Handle, raw Manifest, raw JSON을 기록하지 않았다. API가 반환한 고정 Evaluation Projection에서 Finding 범주, path observation, 가설, limitation을 검증했다.

실제 Chromium E2E는 격리된 동적 loopback FastAPI 서버와 실제 Semgrep으로 3개 브라우저 흐름을 통과했다. 조사 화면에서 부분 검사 안내, 일반 Comparator의 blocked 상태, 평가 완료 후 세 Finding 범주, `신뢰 가능한 비교 불가`, `PATH_EXPLICITLY_SKIPPED` 메시지, 제한된 Skip 근거 표현, 취약점 해결이 아니라는 문구, Release 이후 404를 확인했다. 이는 Chromium 자동화 PASS이며 실제 macOS Safari 검수나 사용자 문구 이해도 결과가 아니다.

## 정보 차이와 M1~M6

| 평가 항목 | 기존 방식 | ER-D4 방식 | 추가 증거 | 남은 한계 |
| --- | --- | --- | --- | --- |
| M1 Information Availability | Finding ID partition은 사용 가능; skip path/reason은 unavailable | 같은 partition과 Finding별 skip 상태 | 해당 경로가 Semgrep에서 ignore 사유로 제외됐다는 사실 | 전체 Scope/규칙 완료 여부는 미확인 |
| M2 Evidence Traceability | Finding 응답과 ID 집합 차이에 부분 추적 | v2 Run의 Response/Manifest Binding 후 Evaluator Projection | 실행과 연결된 경로 및 사유 | Manifest 원문은 public UI에서 확인 불가 |
| M3 Uncertainty Disclosure | 기존 해결 미확정·비교 제한 문구 | `scan_incomplete`, `scope_completeness_unverified`, `source_snapshot_not_collected`, rule identity 제한 | 조사 한계가 구조화됨 | all evidence states가 같은 상세도로 화면에 보이는 것은 아님 |
| M4 Unsupported Claim | 대상 시나리오에서 해결/안전 주장을 하지 않음 | 동일하게 하지 않음 | 새 증거가 더 강한 해결 표현으로 확대되지 않음 | 이번 E2E 출력 범위에 한정 |
| M5 Follow-up Action Support | 기존 Rescan 안내와 파일 위치 | skip된 상대 경로와 절차 원인이 조사 범위를 좁힘 | Ignore 설정과 해당 경로를 우선 확인할 근거 | Git Diff/규칙/취약점 영향은 분석가가 별도 확인 |
| M6 Invalid Comparison Handling | v1는 일반 Finding comparison; v2 비교 불가 규칙은 없음 | partial aggregate를 `INCOMPARABLE`로 유지, Release 후 재사용 거부 | 유효한 절차 관찰과 전체 비교 불가를 함께 표현 | v1과 v2 실행을 교차 Session으로 비교할 수 없음 |

질적 범주만 사용했고 향상률·점수를 계산하지 않았다.

## 부정·경계 사례

아래는 이번 회차에서 실행한 기존 synthetic contract tests의 범위다. 모두 실제 Semgrep E2E라는 뜻은 아니다.

- Unknown skip reason, 미수집 skip field, traversal 경로, scanned/skipped 구조 및 count 제약: C1 Manifest 테스트.
- 중복/정규화 충돌 경로, incomplete run, Finding partition 오류, same Target/Profile/Invocation 문맥 및 안전한 평가: Evaluator/Manifest 테스트.
- 동일 Run, 활성 Session 참조 Run Release, TTL 만료, Session/Run Release, 재사용, 동시 평가 제한: Registry 및 API 테스트.
- 검증 경로·reason 누락/불일치는 실제 API E2E에서 고정했고, API/Registry 민감정보 비노출도 확인했다.
- 정상 0 Finding과 partial/omitted 상태의 보수적 평가: 기존 합성 Evaluator/API 테스트. 이번 실제 Semgrep 실험에는 0-Finding 사례를 포함하지 않았다.

`uv run --locked pytest tests/test_semgrep_adapter.py tests/test_semgrep_parser.py tests/test_scan_evidence_manifest.py tests/test_finding_disappearance_evaluator.py tests/test_investigation_evidence_registry.py tests/test_investigation_api.py` — **145 passed**.

## 판단과 한계

### 확인된 추가 가치

이전에는 “B가 현재 Finding 목록에 없다”까지만 확인할 수 있었다. 조사 모드에서는 “현재 Semgrep 실행이 B의 상대 경로를 `semgrepignore_patterns_match`로 제외했다고 보고했다”는 좁은 사실을 해당 실행에 결합해 제공한다. 따라서 분석가는 `.semgrepignore`/Ignore 설정과 `retired.js`를 후속 확인 대상으로 선택할 근거를 갖는다.

### 여전히 지원되지 않는 판단

- 소스가 실제로 변경됐는지, Semgrep이 특정 바이트를 읽었는지, 변경이 Finding 소멸을 일으켰는지.
- 선택된 Profile ID가 같은 실제 파일 내용 또는 Semgrep loaded rule inventory를 의미하는지.
- 제외되지 않은 경로에서 모든 규칙이 적용됐는지, 전체 Scope가 완료됐는지.
- Finding이 해결됐는지 또는 악용 가능한지.

기존 comparator의 Finding 분류와 안전성 제한 문구는 그대로 보존된다. 실제 분석가 판단 정확도·시간·생산성 효과는 `NOT_ESTABLISHED`다.

## 실패와 재시도

브라우저 E2E 첫 시도는 격리 worktree에 production `frontend/dist`가 없어서 API의 정적 화면 요청이 404가 됐다. Node 24에서 `npm run build` 후 동일 E2E를 다시 실행해 3개 흐름이 통과했다. 테스트 하네스와 제품 코드는 이 문제를 해결하기 위해 변경하지 않았다. 최초 `npm run test:e2e:real` 호출은 `frontend/`가 아닌 repository root에서 실행해 `package.json`을 찾지 못했다. 올바른 디렉터리에서 재실행했다.

## 검증 상태

- 새 재현 하네스 — 실제 API/Semgrep assertion 통과; output은 결정적 projection.
- ER-D2 재현 — 통과(기존 comparator projection 및 API 결과).
- ER-D3 실험 — 통과(A/B/C gap feasibility, rules 원본 불변 확인).
- ER-D4 API/UI 실제 Semgrep E2E — 145 Python 집중 테스트 통과; Chromium 3 passed.
- Frontend typecheck — 통과; Vitest 18 files / 196 tests 통과; Production build 통과.
- `uv lock --check` — 통과.
- Python 전체 suite, WebKit, axe, Safari QA 자동화 — 이번 Phase에서 실행하지 않음. 제품 코드는 바뀌지 않았으며 실행하지 않은 항목은 PASS로 표시하지 않는다.
- 실제 Safari 수동 QA, 200% 확대, VoiceOver/iOS, 사람 대상 효과 — 수행하지 않음.
