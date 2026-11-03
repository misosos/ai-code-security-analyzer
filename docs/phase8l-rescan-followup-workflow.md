# Phase 8L — 재검사 기반 Finding 후속 검토 워크플로

## 목적과 시작 Gate

이 기능은 Phase 8A의 정확한 Finding ID 비교 결과를 분석가의 다음 검토 행동으로 연결한다. 변화 범주는 관찰 차이이며 취약점 발생, 수정 또는 해결 판정이 아니다.

- 기준 SHA: `cfbc7756784d0256fd7f67e3408a87bc02e4d440`
- GitHub Actions Run: `41594238754`
- Gate 확인: GitHub main과 `origin/main` 일치, `push / completed / success`
- 원격 필수 작업: Python tests and CLI, React dashboard, 실제 FastAPI–Semgrep E2E, Semgrep 1.182.1 integration 성공
- Artifact: 0개

## 기존 비교 계약과 후속 검토 모델

`compareScanSnapshots()`는 변경하지 않았다. 동일 대상, 규칙 프로필, Experimental 상태, Semgrep 버전, 정상 완료, 생략 없음, 일관된 Finding 수와 고유 ID 조건을 모두 통과한 경우에만 후속 검토를 만든다.

`frontend/src/features/scans/rescanFollowup.ts`는 검증된 `ScanComparison`에 다음 정보만 덧붙이는 순수 모듈이다.

- 관찰 범주와 범주별 고정 검토 절차
- 기준 및 현재 Finding 참조
- 현재 Finding 상세 이동 가능 여부
- API 응답에 이미 존재하는 메타데이터의 필드별 차이
- 현재 검사 Finding에 대한 Phase 8K Triage 참조
- 자동 보안 판정을 막는 범주별 한계 설명

비교가 차단되면 세 범주는 모두 빈 배열이며 가상의 변화나 후속 작업을 생성하지 않는다. 입력 Finding, ScanResponse, Snapshot, Triage는 변경하지 않는다.

## 관찰 범주별 업무 흐름

### 이번 검사에서만 관찰

현재 탐지 위치와 규칙을 확인하고, 코드·파일·규칙 위치 변화 가능성과 현재 코드의 실행 조건을 검토한다. 현재 검사에 존재하므로 `현재 Finding 검토하기`로 상세와 Phase 8K Triage에 이동할 수 있다.

이 범주는 새로운 취약점 발생의 증거가 아니다.

### 양쪽 검사에서 관찰

현재 위치와 근거 연결 상태를 다시 확인한다. `rule_id`, `file_path`, `line_number`, `severity`, `finding_kind`, `evidence_validation_status`, `verification_status`만 실제 값으로 비교한다. 차이가 없더라도 코드 내용이나 보안 상태의 동일성을 주장하지 않는다.

동일 Finding ID는 이전 검토 완료나 메모를 현재 검사로 승계하는 근거가 아니다.

### 기준 검사에서만 관찰

기준 응답의 위치와 근거를 읽기 전용으로 표시한다. 현재 검사에 존재하지 않으므로 현재 Finding 이동 버튼과 분석가 상태 입력을 제공하지 않는다. 코드 이동, 규칙 매치 변화, 실제 코드 변경 여부는 별도로 확인해야 한다.

이 범주는 수정 또는 해결 완료의 증거가 아니다.

## UI와 필터 처리

기존 접을 수 있는 `검사 결과 비교` 영역 안에 후속 검토 요약을 추가했다. 선택 항목에는 규칙 ID, 위치, 도구 심각도, 현재 Triage, 메타데이터 비교, 범주 한계와 단계별 검토 절차가 표시된다.

현재 Finding 이동은 명시적인 버튼으로만 실행된다. 검색, 심각도, 탐지 유형, 검증 상태 및 분석가 검토 필터를 초기화해 대상이 숨겨지지 않게 하고, 선택 Finding 상세에 포커스를 옮긴다. 이 동작은 검토 상태와 메모를 삭제하거나 API 요청을 발생시키지 않는다.

## 분석가 기록과 데이터 보호

- 새 검사 시작 시 현재 분석가 상태와 메모를 초기화하는 기존 정책을 유지한다.
- 과거 상태 및 메모를 Snapshot에 추가하거나 자동 복사하지 않는다.
- JSON 백업/복원은 기존의 문맥 검증, 미리보기, Finding별 명시 적용 계약을 유지한다.
- localStorage, sessionStorage, IndexedDB, 서버 저장 및 외부 전송을 추가하지 않았다.
- API 토큰, 코드 원문, 절대 경로 또는 HTTP 원문을 후속 검토 모델에 넣지 않는다.

## 비교 Markdown 연계

`ai-code-security-comparison.md`에 `재검사 후속 검토 안내`를 추가했다. 세 범주의 Finding ID, 권장 확인 단계, 범주별 한계와 shared 응답 메타데이터 차이를 기록한다. 기존 Finding별 Claim, Decision, Reason Code 및 기준/현재 문맥은 그대로 보존한다.

기존 512 KiB 제한과 전체 거부 정책, Markdown 이스케이프, 고정 파일명은 유지한다. UI 결과 요약, 분석가 검토 Markdown, JSON 백업 스키마와 CLI 보고서는 변경하지 않았다.

## 실제 A,B → A,C E2E

실제 FastAPI, Semgrep 1.182.1, Chromium과 격리된 합성 프로젝트를 사용했다.

| 단계 | 실제 관찰 |
| --- | --- |
| 기준 검사 | `stable.js` A, `retired.js` B |
| 재검사 | `stable.js` A, `added.js` C |
| 이번 검사에서만 | C 1건 |
| 양쪽 검사에서 | A 1건, Finding ID 유지 |
| 기준 검사에서만 | B 1건 |

C와 A는 현재 Finding 상세로 이동했고, A의 이전 수동 상태와 메모가 자동 복원되지 않음을 확인했다. B는 과거 근거 읽기 전용으로 표시됐고 현재 이동 버튼이 없었다. 비교 보고서 다운로드로 검사 API 요청이 추가되지 않았으며 과거 메모, API 토큰, 임시 절대 경로와 합성 canary가 보고서에 포함되지 않았다.

## 자동화 화면 증거

아래 이미지는 합성 API 응답과 자동화 Chromium으로 생성했으며 실제 Safari 수동 검수 증거가 아니다.

- `docs/assets/phase8l/followup-current-only-1440.png`
- `docs/assets/phase8l/followup-shared-1440.png`
- `docs/assets/phase8l/followup-current-only-390.png`
- `docs/assets/phase8l/followup-baseline-only-390.png`

검증 폭은 1920, 1536, 1440, 1280, 1024, 768, 600, 390, 320px이며 수평 넘침이 없었다. 1440×900에서 Finding 목록 시작은 724.44px, 첫 행은 784.44px였다.

## 검증 결과

환경: Node.js 24.22.2, npm 11.19.1, Python 3.12.7, uv 0.11.26, Semgrep 1.182.1.

| 검증 | 결과 |
| --- | --- |
| TypeScript | PASS |
| Vitest 전체 | 147 PASS |
| Production build | PASS |
| Chromium 전체 | 48 PASS, axe 7개 포함 |
| Playwright WebKit | 2 PASS |
| Safari QA 스크립트 | 7 PASS |
| 실제 FastAPI–Semgrep–Chromium E2E | 2 PASS, 18.0초 |
| Python 전체 | 542 PASS, 28 SKIP, 경고 1개 |
| CI와 동일한 Semgrep 통합 묶음 | 44 PASS, 경고 1개 |
| `git diff --check` | PASS |

초기 집중 브라우저 명령은 저장소에 정의되지 않은 Playwright project 이름을 지정해 테스트가 시작되지 않았다. project 옵션을 제거해 재실행했다. 첫 집중 실행에서는 비교 상세과 현재 상세의 동일한 Triage landmark 이름에 대한 axe 위반 1건과 부정확한 검색 locator 1건이 재현됐다. landmark 이름을 문맥별로 구분하고 searchbox role을 사용한 뒤 집중 및 전체 브라우저 검증이 통과했다.

## 한계와 남은 검증

- Finding ID는 코드 스냅샷 해시가 아니며 의미적 동일성을 증명하지 않는다.
- 원본 코드 내용과 런타임 실행 경로, 실제 악용 가능성은 비교하지 않는다.
- macOS 로컬 Chromium 및 WebKit 자동화 결과이며 GitHub Linux exact SHA CI는 Push 후 별도 확인해야 한다.
- 실제 macOS Safari, 실제 200% 확대, VoiceOver, iOS Safari는 이번 Phase에서 검수하지 않았다.

`SAFARI_USER_ACCEPTANCE_PENDING`
