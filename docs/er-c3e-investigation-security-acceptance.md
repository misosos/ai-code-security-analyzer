# ER-C3E — Investigation Security Acceptance

## 시작 Gate와 범위

- 기준 SHA: `ac52814006429f996dfb3c228bd4ef33ec4bfbcd`
- GitHub Actions: `41867937142`, push, completed, success
- 필수 Job: Python tests and CLI, React dashboard, Semgrep 1.182.1 integration 모두 성공
- Artifact: 0개
- 격리 worktree: `/tmp/ai-csa-er-c3e-investigation-acceptance`
- 브랜치: `research/er-c3e-investigation-acceptance`

ER-C3E는 C1 Manifest, C2 평가기, C3B Registry, C3C API와 C3D 화면을 독립 수용 관점에서 검증한다. 공개 계약이나 기능을 확장하지 않는다. 재현되는 제품 결함이 없으면 테스트와 수용 문서만 추가한다.

## 기존 조사 계약

일반 검사는 `/api/v1/scans`를 사용하며 Run Handle을 만들지 않는다. 조사 모드를 명시적으로 선택한 검사만 `/api/v2/investigation-scans`를 사용한다. 검증된 ScanResponse와 opaque Run Handle은 하나의 `EvidenceBackedScan`으로 함께 관리된다. 서버 평가를 표시하기 전에 브라우저가 baseline/current Finding ID 범주와 서버 결과를 다시 대조한다.

Registry는 프로세스 로컬 메모리에 Run 최대 4개, Session 최대 2개를 보유한다. Run과 Session TTL은 900초이며 조회로 연장되지 않는다. 평가는 한 번에 하나만 수행한다. 다중 worker, 다중 사용자 격리, 재시작 복구와 영구 저장은 지원하지 않는다.

## 정상 실무 흐름과 0 Finding

독립 브라우저 Oracle은 일반 검사가 기본이고 v2 호출이 0회임을 확인한다. 정상 완료된 0 Finding은 `검사되지 않은 문제까지 안전하다는 뜻은 아닙니다`로 표시되며 실패 검사와 구분된다.

실제 조사 E2E는 격리된 합성 프로젝트와 실제 FastAPI/Semgrep 1.182.1을 사용한다. 첫 검사 A/B, 두 번째 검사 A/C에서 `shared`, `baselineOnly`, `currentOnly`를 확인한다. Fixture 작성자가 코드 변경을 알고 있어도 Source Snapshot 증거를 평가기에 주입하지 않으며, 전체 평가는 보수적인 상태를 유지한다.

## 독립 보안 Oracle

| 검증 항목 | 계층 | 기대 결과 |
| --- | --- | --- |
| 동일 Run, 다른 Target/Profile, 외부 Registry Handle | Registry/API | binding 또는 evidence unavailable로 차단 |
| 같은 Finding ID의 다른 실행 | C2/Registry | scan reference를 혼합하지 않음 |
| v1 baseline을 조사에 사용 | Frontend | 서버 증거 없음으로 차단 |
| Client/Server Finding 범주 불일치 | Frontend | `INVESTIGATION_RESULT_CONTEXT_MISMATCH`, 결과 미표시 |
| 기준 해제 뒤 늦은 Evaluation | 신규 브라우저 Oracle | 결과 미표시, Session 해제 요청 |
| 만료·해제 Handle 재사용 | Registry/API/E2E | 정상 빈 결과 대신 `evidence_unavailable` |
| partial/omitted 검사 | C2/API | 정상 비교로 승격하지 않음 |
| 내부 증거·토큰·Handle 유출 | API/Frontend/Export | 허용된 POST body/정상 응답 외 비노출 |
| 해결·안전 확정 문구 | 신규 단위 Oracle | 고정 문구 카탈로그에서 0건 |

측정 지표는 실행한 합성·회귀 범위에 한정한다.

- 다른 Run 증거 혼합: 0건
- 만료/해제된 Handle 정상 재사용: 0건
- 취약점 자동 해결 주장: 0건
- 내부 증거 민감정보의 비인가 노출: 0건
- 불완전 검사를 정상 비교로 승격: 0건

## Binding, TTL, Release와 경쟁 상태

`RunEvidenceBundle`은 동일 `_scan_with_manifest()` 실행의 Response/Manifest 쌍을 Registry에 등록하고 Strict deserialize 후 다시 검증한다. 브라우저는 Finding 내용이 같다는 이유로 Handle을 재구성하지 않는다.

Fake Clock Registry 테스트가 Run/Session 만료, 조회 시 TTL 비연장, 평가 중 만료·Release, 반복 Release, 용량 제한을 검증한다. 실제 HTTP/E2E는 Release 뒤 재평가 거부와 서로 다른 app instance의 Handle 거부를 검증한다. 15분을 실제 대기하지 않는다.

ER-C3E가 추가한 제어된 지연 Evaluation 브라우저 테스트는 평가 중 비교 기준을 해제한다. request sequence가 변경된 뒤 도착한 응답은 화면에 적용되지 않고 이미 만든 Session은 해제된다. sleep 기반 순서 추정 대신 route Promise로 응답 시점을 제어한다.

Release는 best effort다. 탭 종료나 전송 실패 뒤 즉시 메모리 해제를 보장하지 않으며 서버 절대 TTL이 최종 보존 한계다. Python 메모리의 secure erase도 보장하지 않는다.

## API 보안과 데이터 최소화

기존 C3C 테스트는 Token 누락·오류·중복, Host/Origin, CORS preflight, strict UTF-8 JSON, duplicate key, NaN/Infinity, unknown field, Content-Type, body/chunk limit, 허위·만료 Handle, rate/resource limit, evaluation busy, 비활성 API와 공식 launcher 경계를 다룬다. 경계 거부는 Semgrep 실행 전에 발생해야 한다.

API와 화면은 내부 C1 scan_ref, Manifest, Registry payload/digest, 서버 절대 경로, 원본 코드, raw Semgrep JSON, stdout/stderr와 예외 stack을 공개하지 않는다. Handles는 인증된 응답 및 POST JSON body에서만 사용한다. URL, query, 브라우저 storage, Markdown, SARIF, JSON backup 또는 고정 오류 문구에 넣지 않는다. 기존 ScanResponse의 검증된 상대 경로는 기존 공개 계약이다.

로컬 Token은 설치 단위 공유 비밀이며 사용자별 주체가 아니다. Handle도 인증 수단이 아니다.

## Finding 설명 정확성

고정 문구는 다음 경계를 유지한다.

- `PATH_REPORTED_SCANNED`: Semgrep이 처리 경로로 보고했다는 관찰이며 모든 규칙 분석 완료가 아니다.
- `PATH_EXPLICITLY_SKIPPED`: 검사 절차의 제외 관찰이며 취약점 해결을 뜻하지 않는다.
- `PATH_NOT_REPORTED`: 수집 목록에서 보이지 않았다는 사실이며 삭제·제외·수정을 확정하지 않는다.
- `SKIP_EVIDENCE_NOT_COLLECTED`, `SCOPE_EVIDENCE_UNAVAILABLE`, `FINDING_PATH_UNAVAILABLE`, `CONFLICTING`: 증거 부족 또는 충돌을 그대로 표시한다.
- `UNDETERMINED`, `INCOMPARABLE`: 원인 판단 또는 신뢰 가능한 비교를 보류한다.
- `EXPLANATION_SUPPORTED`: 일부 검사 절차 설명의 근거이며 코드 수정이나 해결 확인이 아니다.

새 카탈로그 회귀 테스트는 모든 path observation을 열거하고 `취약점 해결 완료`, `자동 수정 확인`, `안전성 검증 완료`, `취약점이 제거됨`, `코드가 안전해짐`이 없음을 확인한다.

## 접근성, 반응형과 회귀

전체 Chromium은 키보드, focus, aria-live/alert, axe, 1920~320px overflow와 기존 일반 모드 레이아웃을 검증한다. WebKit 자동화와 Safari QA harness는 실제 Safari 사용자 수용을 대신하지 않는다. 실제 macOS Safari, 수동 200% 확대, VoiceOver와 iOS Safari는 미검증으로 남긴다.

기존 v1 ScanResponse, Finding ID, 규칙, 비교, 후속 검토, 분석가 상태/메모, Markdown, SARIF, JSON backup/restore, 검색·필터와 사이드바 계약은 변경하지 않는다. Evaluation은 분석가 검토 상태를 자동 변경하지 않는다.

## 검증 결과

최종 실행 결과는 커밋 직전 이 절에 갱신한다.

- 시작 Gate: 통과
- ER-C1/C2/C3B/C3C targeted Python: 95 passed
- 신규 Vitest와 기존 investigation unit: 12 passed
- 신규 Chromium acceptance: 2 passed
- 전체 Python: 646 passed, 28개의 명시적 opt-in Ollama 시험 skipped, 기존 Starlette/AnyIO deprecation warning 1개
- CI와 같은 Semgrep 선택 묶음: 46 passed, 기존 warning 1개. 이전 문서의 19 passed는 더 좁은/이전 선택 결과이며 이번 실행은 현재 workflow의 12개 파일 전체다.
- TypeScript typecheck: passed
- 전체 Vitest: 18 files, 192 passed
- Production build: passed
- 전체 Chromium: 53 passed. axe, 키보드, 200% CSS viewport 대리 검증, 1920~320px 반응형과 신규 경쟁 상태 Oracle 포함
- Playwright WebKit: 2 passed
- 실제 FastAPI–Semgrep–Chromium E2E: 3 passed. 실제 조사 A/B → A/C 및 Release 후 재사용 거부 포함
- Safari QA 자동화 harness: 7 passed. 실제 Safari 사용자 수용은 아님
- `uv lock --check`, `git diff --check`: passed

## 결함과 남은 위험

독립 검증 중 현재까지 제품 코드 결함은 재현되지 않았다. 첫 브라우저 시험은 production build가 없는 시험 준비 오류와 버튼 accessible name 기대값 오류였으며 제품 결함이 아니었다. 테스트 환경을 고친 뒤 통과했다.

하드 RSS 제한, 장기 실행 메모리 안정성, 다중 worker 공유, 다중 사용자 격리, 브라우저 종료 시 Release 보장과 실제 Safari/VoiceOver/iOS 수용은 제공하지 않는다. 운영 승인은 아니다.

수동 절차는 [ER-C3E 사용자 수용 점검표](er-c3e-user-acceptance-checklist.md)를 따른다. 기본 상태는 `NOT_TESTED`이며 사용자가 수행하지 않은 결과를 PASS로 기록하지 않는다.
