# Phase 8D — 분석가 검토 기록 Markdown 내보내기

## 목적과 시작 Gate

Phase 8C에서 현재 검사 세션의 메모리에만 보관하던 분석가 검토 상태와 선택 메모를 사용자가 명시적으로 Markdown 파일로 내보낼 수 있게 했다. 검토 상태는 Semgrep 판정이나 취약점 확정과 별개다.

- 저장소 기준: `misosos/ai-code-security-analyzer`
- 기준 커밋: `2d176403117b5888724e7543587decedbdcde91d`
- 원격 기준: `origin/main` 및 GitHub `main`이 기준 커밋과 일치
- GitHub Actions: Run `41275118793`, `push / completed / success`
- Python, Semgrep 1.182.1, React job: 성공
- Artifacts: 0
- 구현 worktree: `/tmp/ai-csa-phase8d`
- 구현 브랜치: `phase/8d-analyst-review-export`

원래 사용자 작업 폴더는 시작 시 `main`이 `origin/main`보다 2커밋 뒤였고 UI 수정과 미추적 검증 자료가 있었다. 해당 작업 폴더는 수정하지 않았다. 구현은 원격 기준 커밋에서 새 worktree로 분리했다.

## 사용자 흐름

1. 검사 결과에서 Finding별 수동 검토 상태와 메모를 기록한다.
2. 결과 요약의 `분석가 검토 기록 내보내기` 펼침 항목을 연다.
3. 기본값인 메모 제외로 보고서를 받거나, `메모 포함`을 선택한다.
4. 메모 포함을 선택했다면 브라우저 확인창에서 디스크 보관 및 외부 공유 위험을 다시 확인한다.
5. 확인한 경우에만 `Markdown 다운로드`를 누른다.

사용자 동작 전 자동 다운로드나 API 요청은 없다. 고정 파일명은 `ai-code-security-analyst-review.md`이며 임시 Blob URL은 다운로드 직후 정리한다.

## 보고서 내용과 범위

보고서는 현재 API 응답 한 건만 다룬다. 기준 검사와 현재 검사를 합치지 않는다. 현재 UI 필터/검색과 무관하게 검증된 응답에 포함된 모든 Finding을 Finding ID 기준으로 결정적으로 정렬한다.

포함 내용:

- 검사 대상 및 규칙 프로필의 검증된 식별 정보, Experimental 여부
- Semgrep 버전, 검사 상태, 브라우저 결과 수신 시각
- 전체·표시·생략 Finding 수
- 검토 대기·추가 확인 필요·검토 완료 집계
- Finding ID, 규칙 ID, 도구 보고 심각도, 탐지 유형, 상대 경로와 줄 번호
- API의 취약점 검증 상태, 근거 연결 검증 상태, 검증 오류 코드와 지원/제한 주장
- 선택적으로 사용자가 명시적으로 포함한 해당 Finding의 메모

수신 시각은 실제 검사 실행 시각 또는 코드 스냅샷 시각이 아님을 보고서에 명시한다. 생략 Finding은 개별 검토 현황에 포함하지 않으며, 생략 수가 0보다 크면 범위 경고를 표시한다. 부분 검사와 정상 완료되지 않은 상태도 성공으로 바꾸지 않고 실제 상태와 제한을 기록한다.

## 메모 및 데이터 보호

- 메모 포함 기본값은 해제다.
- 메모 포함은 체크박스 선택과 다운로드 직전 `window.confirm`을 모두 요구한다. 취소 시 파일 다운로드는 발생하지 않는다.
- 메모는 현재 Finding ID와 연결된 메모리 상태만 사용한다. 보고서 생성 때도 현재 응답에 없는 Finding 기록, 잘못된 상태 enum, UTF-8 2 KiB 초과 메모를 거부한다.
- 각 메모와 전체 문서는 UTF-8 크기를 검사한다. 전체 512 KiB를 넘으면 잘라내지 않고 다운로드를 거부한다.
- API 응답은 기존 `parseScan()`으로 재검증한다. 절대 경로 및 비정상 상대 경로는 거부한다. Markdown/HTML 구분자, 제어문자, Unicode 형식 문자는 기존 `escapeMarkdownText()`로 인코딩한다.
- 토큰, 소스 코드 원문, 절대 경로, HTTP 원문, stderr, 환경변수는 API 보고서 필드로 내보내지 않는다. 메모를 선택적으로 포함하면 사용자가 직접 입력한 민감정보가 파일에 포함될 수 있으므로 사전·직전 경고를 표시한다.
- 서버, localStorage, sessionStorage, IndexedDB, 외부 서비스에는 저장하지 않는다. 다운로드된 파일은 브라우저 메모리 밖의 디스크에 남을 수 있고 결과 삭제나 새로고침이 이미 받은 파일을 삭제하지 않는다.
- Phase 8A 비교 보고서와 현재 검사 결과 Markdown 보고서에는 메모가 자동 포함되지 않는다.

## 보안 의미

`검토 완료`는 분석가의 업무 상태이며 수정 완료 또는 취약점 해결을 의미하지 않는다. `추가 확인 필요`도 취약점 확정이 아니다. 검토 상태는 `verification_status`, `evidence_validation_status`, 심각도 및 API의 주장들을 변경하지 않는다. `Validated Evidence`는 근거 연결의 구조적 상태이지 취약점 확인이 아니다. 보고서는 CLI의 정식 보안 검토 보고서를 대체하지 않는다.

## 검증

저장소의 Node 버전인 24.22.2를 사용했다. 전체 브라우저 테스트는 기존 4173 포트를 사용하는 서버와 혼동하지 않도록 별도 임시 Playwright 설정 및 4183 포트에서 실행했다. 합성 테스트 데이터만 사용했다.

| 검증 | 실행 명령 | 결과 |
|---|---|---|
| TypeScript | `npm run typecheck` | PASS |
| Vitest | `npm test` | PASS — 10개 파일, 100 테스트 |
| Production build | `npm run build` | PASS |
| Chromium 브라우저 전체 | `npm run test:browser -- --config playwright.phase8d.config.ts` | PASS — 23 테스트 |
| UI-D3 목록 위치 회귀 | 전체 브라우저 테스트 내 `ui-d3.spec.ts` | PASS — 1440px 목록 시작 Y=780.8px, 기준 810px 미만 |
| Python 전체 | `uv lock --check && uv run --locked python -m pytest -q -rs` | PASS — 542 passed, 28 skipped |
| Semgrep 통합 | CI의 12개 Semgrep 관련 pytest 파일, `SEMGREP_REQUIRED=1` | PASS — 44 passed, Semgrep 1.182.1 |
| 실제 FastAPI–Chromium–Semgrep E2E | `SEMGREP_REQUIRED=1 … npm run test:e2e:real` | PASS — 브라우저 E2E 1건 |
| 보안 스키마·이스케이프·크기 테스트 | `analyst-review-markdown-export.test.ts` 포함 Vitest 전체 | PASS |
| 메모 동의·다운로드·필터 무관 전체 Finding·추가 API 호출 없음 | `analyst-review-export.spec.ts` 포함 Chromium 전체 | PASS |
| `git diff --check` / staged diff 검사 | 커밋 전 `git diff --check`, `git diff --cached --check`, 커밋 후 `git show --check HEAD` | PASS |

Python 전체 테스트에서 Ollama 관련 28건은 저장소의 명시적 옵트인 조건에 따라 건너뛰었다. 최초 CI의 모든 작업을 이 Phase HEAD 원격 CI로 재사용한 것은 아니다.

## 접근성 및 검증 한계

- 보고서 펼침은 네이티브 `details/summary`를 사용한다. 체크박스 및 다운로드는 명시적인 레이블/버튼이며 키보드로 조작 가능하다.
- Chromium은 기존 UI-D3 및 전체 viewport 회귀 테스트를 포함해 실행했고, 수평 넘침 회귀가 없었다.
- 실제 Safari 사용자 검수: `NOT_TESTED`
- 실제 200% 브라우저 확대: `NOT_TESTED`
- axe 자동 검사: `NOT_TESTED`

브라우저 확인창의 실제 문구·모양은 브라우저별 차이가 있을 수 있다. 최종 Safari 사용자 수용은 별도 검수 대상이다.
