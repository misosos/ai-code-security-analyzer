# P5 — 실패에 안전한 분석가 검토 재검사

## 한 줄 요약

새 검사가 **정상 완료**됐을 때만 이전 검사에 작성한 분석가 검토 기록(상태·메모)을 지운다. 새 검사 요청이 실패하거나, 응답이 부분 검사·실행 실패 같은 비정상 상태이면 새 결과를 적용하지 않고 **이전 검사 결과와 그 검토 기록을 그대로 복원**한다.

- 기준 커밋: `d929770` (원격 `main` `53463a2`와 같은 tree `fb080db`)
- 범위: React 대시보드의 재검사 상태 전이만 변경. API, 공개 스키마, 백업 JSON 계약, 규칙, 벤치마크, lockfile은 변경하지 않았다.
- 저장 위치: 계속 브라우저 메모리만 사용한다. `localStorage`나 서버 저장을 추가하지 않았다.

## 1. 재검사 흐름을 담당하는 파일

| 파일 | 역할 |
| --- | --- |
| `frontend/src/app/App.tsx` | `runScan()`이 새 검사 시작, 확인 대화상자, 응답 반영, 실패 처리를 모두 담당한다. `clearResults()`는 명시적인 결과 지우기를 담당한다. |
| `frontend/src/features/scans/analystReview.ts` | 검토 기록 자료구조와 순수 함수. `hasAnalystReviewWork()`가 "지켜야 할 기록이 있는가"를 판단하고, 이번에 추가한 `rescanReplacesAnalystReview()`가 "새 결과가 기록을 대체해도 되는가"를 판단한다. |
| `frontend/src/features/scans/compare.ts` | 두 검사 비교. 부분·실패·생략 검사는 비교를 차단한다. 이번 변경으로 바뀌지 않았다. |

## 2. 검토 기록은 어디에 저장되는가

검토 기록은 React 상태 하나에만 있다. 서버나 브라우저 저장소에는 쓰지 않는다.

```tsx
// frontend/src/app/App.tsx:134
const [analystReviews, setAnalystReviews] = useState<AnalystReviewState>(emptyAnalystReviewState);
```

`AnalystReviewState`는 `finding_id → { status, note }` 형태의 `Map`이다. 기록은 **그 기록을 작성한 검사의 Finding**에 묶여 있다. 그래서 새로고침하면 사라지고, 새 검사 결과로 자동으로 옮겨지지 않는다. 같은 ID라도 다른 검사 결과에 붙이지 않는 것이 이 프로젝트의 기존 원칙이다(수동 백업 복원만 예외).

## 3. 기존 구현은 왜 기록을 잃었는가

P2(`5269581`)는 확인 대화상자와 백업 안내를 추가했지만, 기록을 지우는 시점은 그대로였다. 변경 전 `App.tsx`는 **검사를 시작하는 순간** 화면의 결과와 검토 기록을 비웠다.

```tsx
// 변경 전 frontend/src/app/App.tsx:308 (일부)
setState('scanning'); ... setScan(null); setScanContext(null);
setAnalystReviews(emptyAnalystReviewState); ...
```

그리고 실패하면 "지워졌다"고 알리기만 했다.

```tsx
// 변경 전 frontend/src/app/App.tsx:340
const clearedNote = discardsReview ? ' 확인에 따라 이전 검사의 분석가 검토 기록은 지워졌으며 복원되지 않습니다.' : '';
```

따라서 기록이 사라지는 경로는 두 가지였다.

1. **요청 실패**(네트워크 오류, 401, 409 등): 시작할 때 이미 비웠고, 실패 처리에서 되돌리지 않았다.
2. **비정상 상태 응답**(`partial`, `execution_failed` 등): 응답이 오면 무조건 새 결과로 교체했으므로 이전 기록이 사라졌다.

## 4. 새 상태 전이는 어떻게 기록을 지키는가

핵심 아이디어는 "지우기 전에 한 벌을 따로 보관하고, 정상 완료일 때만 버린다"이다.

**① 시작: 보관 후 화면 비우기.** 사용자가 확인한 경우에만 이전 작업 공간 전체(결과, 검사 설정, 기록, 검토 필터, 선택)를 `useRef`에 보관한다. 화면을 비우는 기존 동작은 유지한다. 그래서 검사 중에는 이전 Finding을 수정할 수 없고, 이전 결과가 새 결과처럼 보이지도 않는다.

```tsx
// frontend/src/app/App.tsx:301-302
if (discardsReview && scan && scanContext) retainedReviewWorkspace.current = { scan, context: scanContext, reviews: analystReviews, filter: analystReviewFilter, selectedId };
else if (scan !== null) retainedReviewWorkspace.current = null;
```

**② 응답: 정상 완료만 기록을 대체.** 판단은 순수 함수 하나로 고정했다.

```ts
// frontend/src/features/scans/analystReview.ts:94
export function rescanReplacesAnalystReview(result: Pick<ScanResponse, 'scan_status' | 'completed'>): boolean {
  return result.scan_status === 'completed' && result.completed;
}
```

```tsx
// frontend/src/app/App.tsx:331
if (retainedReviewWorkspace.current && !rescanReplacesAnalystReview(result)) {
  if (evidenceResponse) await releaseEvidenceHandle(token, 'run', evidenceResponse.run_handle);
  ...
  restoreRetainedReviewWorkspace();
```

부분·실패 상태 응답은 화면에 적용하지 않는다. 조사 모드에서 받은 서버 증거 Handle은 즉시 해제를 요청한다.

**③ 요청 실패: 보관본 그대로 복원.**

```tsx
// frontend/src/app/App.tsx:358
const retained = restoreRetainedReviewWorkspace();
```

`restoreRetainedReviewWorkspace()`(370행)는 결과·설정·기록을 **같은 묶음 그대로** 되돌린다. 기록이 원래 검사 결과와 함께 돌아오므로, 오래된 판단이 새 Finding에 붙는 일은 없다. 복원된 화면에는 이전 결과라는 표시가 나타난다.

```tsx
// frontend/src/app/App.tsx:711
{showingRetainedResult && <p className="alert warning retained-result-note" role="note">마지막 새 검사 결과는 적용되지 않았습니다. ...</p>}
```

**④ 명시적 결과 지우기**(396행)는 보관본도 함께 버린다.

### 상태 전이표

| 상황 | 검토 기록이 있을 때 | 검토 기록이 없을 때 |
| --- | --- | --- |
| 확인 대화상자에서 취소 | 검사를 시작하지 않음. 기록 유지, 백업 도구로 이동(P2 그대로) | 대화상자 없음 |
| 정상 완료 응답 | 새 결과 적용, 이전 기록 삭제(확인한 대로) | 새 결과 적용 |
| 부분 검사 응답 | **새 결과 미적용**, 이전 결과·기록 복원, 이전 결과 표시 | 부분 검사로 표시(기존 동작) |
| 실행 실패 등 비정상 상태 응답 | **새 결과 미적용**, 이전 결과·기록 복원 | 해당 상태로 표시(기존 동작) |
| 요청 실패(네트워크·인증 등) | **이전 결과·기록 복원**, 오류 알림에 유지 사실 명시 | 결과 없음, 오류 알림 |
| 검사 중 반복 실행 | 버튼 비활성화와 요청 순번으로 차단, 확인은 1회 | 동일 |
| 결과 지우기 확인 | 결과·기준·기록·보관본 모두 삭제 | 동일 |

### P2 보호 장치 유지

- 확인 대화상자는 그대로 뜬다. 문구만 실제 동작에 맞게 바꿨다: "정상 완료되면 지워짐, 실패하거나 일부만 완료되면 유지됨".
- 취소 시 백업 도구로 이동하고 버튼에 초점을 주는 동작은 그대로다.
- 반복 제출은 여전히 요청 1개, 확인 1회만 만든다.
- 정상 완료 재검사는 같은 Finding ID라도 기록을 옮기지 않는다. 수동 백업 복원만 가능하다.

### 비교 불변식

Phase 8A 원칙은 "실패한 재검사 결과를 성공 결과로 재사용하지 않는다"이다. 이번 변경은 실패한 응답을 결과로 쓰지 않는다. 복원되는 것은 **원래 수신 시각과 검사 설정을 가진 이전 결과**이고, 이전 결과라는 안내가 함께 표시된다. 비교 기준은 건드리지 않는다. 부분 검사 결과는 적용 자체를 하지 않으므로 완료 결과나 비교 가능한 결과로 취급될 수 없다.

## 5. 남아 있는 한계

1. **새로고침·창 닫기**: 기록은 메모리에만 있으므로 사라진다(의도된 개인정보 보호 동작).
2. **검토 기록이 있으면 부분 검사 결과를 볼 수 없다**: 부분 결과를 보려면 백업 JSON을 내려받고 결과를 지운 뒤 다시 검사해야 한다. 조사 모드에서 부분 검사를 기준으로 쓰는 흐름도 같은 제약을 받는다.
3. **조사 증거는 복원되지 않는다**: 새 검사를 시작할 때 이전 현재 결과의 서버 증거 Handle은 해제된다. 복원된 결과로 소멸 조사를 하려면 조사 모드로 다시 검사해야 한다.
4. **일부 화면 상태는 복원하지 않는다**: 심각도·검색 필터, 백업 미리보기, 내보내기 메시지는 초기화된다. 복원 대상은 결과, 검사 설정, 검토 기록, 검토 필터, 선택 Finding이다.
5. **정상 완료지만 생략이 있는 검사**(50건 초과)는 정상 완료로 보고 기록을 대체한다. 비교는 기존대로 차단된다.
6. **검사 도중 화면이 닫히는 경우**(컴포넌트 해제)에는 보관본도 사라진다.

## 6. 각 동작을 증명하는 테스트

변경 전 코드로 되돌려 실행하면 아래 단위·UI 테스트 8개와 브라우저 테스트 1개가 실패한다. 변경 후에는 모두 통과한다.

| 동작 | 테스트 |
| --- | --- |
| 정상 완료만 기록 대체(모든 비정상 상태 포함) | `frontend/tests/analyst-review.test.ts` › `lets only a normally completed rescan replace prior review records` |
| 확인 문구가 실제 동작과 일치 | `frontend/tests/analyst-review-ui.test.tsx` › `확인 문구는 정상 완료 시에만 기록이 지워지고 실패·부분 검사에는 유지된다고 안내한다` |
| 요청 실패 시 복원과 이전 결과 표시 | 같은 파일 › `새 검사 요청이 실패하면 이전 결과와 검토 기록을 그대로 복원하고 이전 결과임을 표시한다` |
| 부분 검사 미적용, 완료·비교 결과로 취급 안 함 | 같은 파일 › `부분 검사 응답은 검토 기록이 있으면 적용하지 않고 비교 가능하거나 완료된 결과로 취급하지 않는다` |
| 실행 실패 상태 미적용 | 같은 파일 › `실행 실패 상태 응답도 이전 결과와 검토 기록을 대체하지 않는다` |
| 기록이 없으면 기존 부분 검사 표시 유지 | 같은 파일 › `검토 기록이 없으면 부분 검사 결과를 기존처럼 부분 검사로 표시한다` |
| 복원된 기록이 새 Finding으로 옮겨지지 않음 | 같은 파일 › `복원된 기록은 다음 정상 완료 검사에서 같은 Finding ID라도 새 결과로 옮겨지지 않는다` |
| 복원 후 결과 지우기 | 같은 파일 › `복원 후 결과 지우기를 확인하면 복원 표시와 기록을 함께 지운다` |
| 반복 실행 중 대기 요청 실패 | 같은 파일 › `검사 중 반복 실행 후 대기 중인 요청이 실패해도 기록을 한 번만 확인하고 복원한다` |
| 실제 Chromium에서 실패 → 부분 → 정상 완료 전이, 접근성 검사 | `frontend/browser-tests/analyst-review.spec.ts` › `실패·부분 재검사는 이전 결과와 검토 기록을 유지하고 정상 완료 재검사만 기록을 지운다` |
| P2 취소·백업 안내·반복 제출(유지) | `analyst-review-ui.test.tsx`의 기존 P2 테스트, `analyst-review.spec.ts` › `새 검사 경고를 닫으면 ...` |

## 7. 검증 결과

| 검사 | 결과 |
| --- | --- |
| 변경 전 코드 + 새 테스트(재현) | Vitest 8 failed / 20 passed, 브라우저 테스트 1 failed |
| `npm run typecheck` | 통과 |
| `npm test`(Vitest) | 20 files, 233 tests 통과 |
| `npm run build` | 통과 |
| `npm run test:browser`(mock Playwright, Chromium) | 58 passed |
| `npm run test:e2e:real`(실제 Chromium–FastAPI–Semgrep 1.182.1) | 3 passed, 2 skipped(ER-D8/ER-D9 전용 harness에서만 실행되도록 설계됨) |
| Python 전체(`SEMGREP_REQUIRED=1 pytest -q -rs`) | 681 passed, 28 skipped(Ollama·진단용 opt-in 테스트) |

Python 전체 테스트를 브라우저 테스트와 동시에 처음 실행했을 때, 실제 Semgrep을 쓰는 테스트 5개가 `timed_out`으로 실패했다(`test_api_semgrep_e2e.py` 2개, `test_command_injection_hardening.py` 1개, `test_command_injection_phase6f.py` 2개). 이 변경은 Python 코드를 수정하지 않았다. 5개 단독 재실행과 부하 없는 전체 재실행이 모두 통과했으므로, 동시 부하로 인한 시간 초과로 판단한다. Phase 8C·8F 기록에도 같은 현상이 있다.

브라우저 테스트는 실행할 때 `docs/assets/` 아래 기존 스크린샷을 다시 생성한다. 이 변경의 범위가 아니므로 커밋 전에 원래대로 되돌렸다.
