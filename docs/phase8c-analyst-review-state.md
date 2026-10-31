# Phase 8C — 분석가 Finding 검토 상태

## 목적과 범위

검사 결과 화면에서 분석가가 각 Finding의 검토 작업 상태와 메모를 현재 브라우저 탭 메모리에서 관리한다. 이 기능은 Semgrep 및 API의 보안 판정을 대체하거나 변경하지 않는다. FastAPI, CLI, 분석 규칙, API DTO는 수정하지 않았다.

## 검토 상태의 의미

| 상태 | 의미 |
| --- | --- |
| 검토 대기 | 분석가가 아직 수동 검토 상태를 변경하지 않음 |
| 추가 확인 필요 | 추가 코드 검토 또는 재현 확인이 필요하다고 분석가가 표시함 |
| 검토 완료 | 해당 Finding에 대한 분석가의 검토 작업이 완료됨 |

세 상태 모두 작업 진행 상태만 나타낸다. `검토 완료`는 취약점 해결이나 오탐 확정이 아니며, `추가 확인 필요`도 취약점 확정이 아니다. `verification_status`, `evidence_validation_status`, severity, supported/restricted claims는 변경되지 않는다.

## 메모와 데이터 수명

- Finding ID별 상태와 메모를 독립 관리한다. 현재 API 응답의 Finding ID만 변경할 수 있다.
- 메모는 빈 값이 가능하고 UTF-8 기준 최대 2 KiB다. 초과 입력은 거부하며 이전 유효 메모를 유지한다.
- 입력은 HTML/Markdown으로 해석하지 않고 React 텍스트로 표시한다. 입력 메모를 분석하거나 요약하지 않는다.
- 자료는 현재 검사에만 연결되며 새 검사에 같은 Finding ID가 있어도 승계하지 않는다.
- 메모나 상태가 수정된 뒤 새 검사를 시작하거나 결과를 지우면 확인 대화상자가 나타난다. 취소하면 기존 작업을 유지한다.
- 새 검사 시작은 현재 결과와 검토 기록을 비우고 비교 기준은 유지한다. 결과 지우기는 현재 결과, 비교 기준, 검토 기록과 관련 필터/선택을 모두 지운다.
- localStorage, sessionStorage, IndexedDB, 서버 저장, 외부 전송을 사용하지 않는다. 새로고침 또는 탭 종료 시 검토 기록은 사라진다. 사용자가 입력한 비밀정보가 브라우저 메모리에 남지 않는다고 보장할 수 없으므로 토큰·개인정보·비밀정보를 기록하지 말라는 안내를 제공한다.

## 현황 집계와 Finding 탐색

검토 대기/추가 확인 필요/검토 완료 집계는 현재 API 응답의 표시된 Finding만 계산한다. 결과가 생략되면 생략 항목은 집계에 포함되지 않는다는 안내를 표시한다. 검토 상태 필터는 기존 검색, 심각도, 탐지 유형, 검증 상태 필터와 함께 적용된다. 선택한 항목이 필터에서 제외되면 다른 Finding 상세를 대신 선택된 것처럼 표시하지 않는다.

상태 배지와 상세 편집기는 분석가 작업 상태임을 표시하며 API의 미검증/근거 상태와 별도로 유지한다. 기존 현재 결과 및 Phase 8B 비교 Markdown 내보내기는 API 검사 자료만 사용하며 분석가 메모를 포함하지 않는다.

## 구현 파일

- `frontend/src/features/scans/analystReview.ts`: 순수 상태/메모 검증 및 집계 로직
- `frontend/src/app/App.tsx`: 현재 검사 단위 UI 상태, 확인 흐름, 목록 필터와 상세 편집기
- `frontend/src/app-shell-d5a.css`: 기존 데스크톱·모바일 UI에 스코프된 검토 UI 스타일
- `frontend/tests/analyst-review.test.ts`, `frontend/tests/analyst-review-ui.test.tsx`: 로직 및 React 회귀 테스트
- `frontend/browser-tests/analyst-review.spec.ts`: Chromium 상호작용/반응형 검증

기존 페이지의 큰 글씨와 사이버펑크 스타일을 유지한다. 분석가 검토 요약은 결과 개요 안에 배치해 Finding 목록이 불필요하게 아래로 밀리지 않도록 했다. API 응답 객체는 변경하지 않는다.

## 보안 및 한계

- 검토 기록은 세션 메모리 전용이며 영구 저장, 서버 API, 자동 동기화가 없다.
- 입력 메모는 보고서에 포함되지 않는다.
- 상태가 검사 간 승계되지 않는 대신 사용자가 새 검사/삭제를 확정하면 데이터가 사라진다.
- 메모가 보안 판정 데이터가 아니므로 결과의 검증 여부나 심각도와 결합해 안전성 점수/해결률을 만들지 않는다.
- 현재 검토 기능은 브라우저의 현재 표시된 Finding에 한정되며, 생략된 Finding을 검토하거나 기록하지 않는다.

## 검증

최종 구현에서 실행한 검증:

- `npm run typecheck`: 통과
- `npm test -- --maxWorkers=1`: 통과, 9개 파일 / 93개 테스트
- `npm run build`: 통과
- `npx playwright test --config playwright.phase8a.config.ts`: 통과, 22개 브라우저 테스트. 새 검토 흐름, 출력 비노출, 모바일·320px 오버플로, 키보드 Enter로 Finding 선택 포함
- `SEMGREP_REQUIRED=1 npm run test:e2e:real`: 통과, 합성 FastAPI–Semgrep E2E 1개
- `git diff --check`: 통과
- `SEMGREP_REQUIRED=1 uv run --locked python -m pytest -q -rs`: 최종 재실행 통과, 542 passed / 28 skipped / 1 warning

Python 첫 전체 실행에서는 브라우저/비교 E2E가 동시에 동작하던 중 Semgrep API 통합 테스트가 제한 시간 초과로 실패했다. 해당 테스트 단독 실행은 통과했고, 부하를 겹치지 않은 전체 재실행도 통과했다. 최종 전체 실행 결과를 기준으로 판단한다.

자동화 브라우저는 Chromium이다. 실제 Safari 검수, 실제 브라우저 200% 확대, axe 자동 검사는 실행하지 않아 `NOT_TESTED`다. 키보드 Finding 선택 및 모바일 탐색 회귀는 Playwright에서 검증했다.
