# Phase 8M — SARIF 2.1.0 보안 분석 결과 내보내기

## 1. 목적과 범위

현재 브라우저가 검증한 `ScanResponse`를 SARIF 2.1.0 한 개의 `run`으로 변환하고 사용자가 명시적으로 다운로드할 수 있게 했다. 생산자는 **AI Code Security Analyzer**, 탐지 엔진은 **Semgrep**으로 구분한다. 이 기능은 정적 분석 Finding을 표준 형식으로 직렬화하며 취약점 확정, GitHub 업로드 또는 외부 전송을 수행하지 않는다.

시작 기준은 `03b588e190c37ae453e3a8af77c0e5a5bbb3c31e`, GitHub Actions Run `41644046867`이다. Run은 `push / completed / success`였고 Python, React dashboard, 실제 FastAPI–Semgrep E2E, Semgrep 1.182.1 통합이 성공했으며 Artifact는 0개였다.

## 2. 변환 구조

구현은 `frontend/src/features/scans/sarifExport.ts`의 순수 변환과 다운로드 함수로 나뉜다.

| API 자료 | SARIF 위치 | 처리 |
| --- | --- | --- |
| `rule_id` | `tool.driver.rules[].id`, `results[].ruleId` | 규칙 ID별 descriptor를 한 번만 생성하고 `ruleIndex`를 일치시킨다. |
| `severity` | `results[].level` | critical/high=`error`, medium=`warning`, low/info=`note`; 원본은 `properties.originalSeverity`에 보존한다. |
| `finding_id` | `results[].properties.aiCodeSecurityAnalyzerFindingId` | 프로젝트 내부 식별자로 보존하며 fingerprint로 사용하지 않는다. |
| `file_path` | `locations[].physicalLocation.artifactLocation.uri` | 검증된 상대 경로의 각 segment를 URI 인코딩한다. 절대 경로와 순회 경로는 API 파서에서 거부된다. |
| `line_number` | `region.startLine` | 양의 정수가 제공된 경우에만 기록한다. |
| `verification_status` | result property | API의 `unverified`를 그대로 보존한다. |
| `evidence_validation_status` | result property와 message | `validated`, `rejected`, `unavailable`의 의미를 구분한다. |
| `supported_claims` | result property | Finding별 enum 배열을 그대로 복사한다. |
| `restricted_claims` | result property | Claim type, decision, reason codes를 Finding별로 보존한다. |
| `validation_error_code` | result property | `null` 또는 검증된 오류 코드를 그대로 보존한다. |
| 검사 상태와 개수 | `run.properties`, `invocations` | 전체/내보낸/생략 수와 상태를 기록한다. 정상 완료일 때만 `executionSuccessful=true`다. |

규칙 제목과 설명은 기존 `reviewGuidance.ts`의 고정 매핑을 재사용한다. 알 수 없는 Rule ID는 원본 ID와 탐지 유형별 일반 안내를 사용하며 CWE나 취약점 속성을 만들지 않는다. AI Code Security Analyzer 자체 버전이 없으므로 `driver.version`과 `semanticVersion`은 출력하지 않는다. Semgrep 버전은 탐지 엔진 속성으로만 기록한다.

## 3. 공식 SARIF 스키마 검증

OASIS SARIF 2.1.0 Errata 01 공식 스키마를 `frontend/tests/fixtures/sarif-schema-2.1.0.json`에 고정했다.

- 출처: `https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json`
- SHA-256: `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`
- 검증기: `ajv@8.20.0`, `ajv-draft-04@1.0.0`, `ajv-formats@3.0.1`
- 브라우저 런타임은 스키마나 외부 리소스를 다운로드하지 않는다. 검증 의존성은 테스트 전용이다.

단위 테스트와 합성 Chromium 다운로드, 실제 FastAPI–Semgrep–Chromium 다운로드에서 공식 스키마 검증을 통과했다.

상태: **SARIF_SCHEMA_VALIDATED**

## 4. GitHub Code Scanning 호환성 검토

GitHub 문서가 설명하는 `runs`, tool driver, rules, results, `ruleId`, 상대 artifact URI와 line 정보를 사용한다. 다만 GitHub ingestion validator와 실제 업로드는 실행하지 않았다.

현재 API에는 소스 행 내용과 코드 스냅샷이 없어서 `partialFingerprints` 또는 `primaryLocationLineHash`를 정확히 만들 수 없다. GitHub 문서상 fingerprint가 없는 API 업로드는 중복 경고가 생길 수 있고, `upload-sarif` action은 소스 파일을 이용해 fingerprint를 보완할 수 있으나 이번 범위에서 검증하지 않았다. 위치 없는 result는 SARIF 스키마에는 유효하지만 GitHub UI에서 소스 위치 기반 경고로 표시되는 정도는 확인하지 않았다.

상태:

- **GITHUB_CODE_SCANNING_COMPATIBILITY_NOT_FULLY_VERIFIED**
- **GITHUB_UPLOAD_NOT_TESTED**
- GitHub API/Actions 업로드: **NOT_IMPLEMENTED**

## 5. Evidence와 데이터 흐름 제한

`validated`는 Finding과 근거의 구조적 연결이 검증됐다는 뜻이며 취약점 확정이 아니다. `rejected`는 오탐 확정이 아니고, `unavailable`은 데이터 흐름 부재를 뜻하지 않는다. result message도 이 범위를 넘지 않게 상태별로 구분한다.

현재 API에 구조화된 Source/Sink 위치, thread flow, 수정안이 없으므로 다음 필드를 생성하지 않는다.

- `codeFlows`, `threadFlows`, `threadFlowLocations`
- `relatedLocations`
- `fixes`
- `partialFingerprints`, `fingerprints`

일반 패턴 위치를 Source나 Sink로 바꾸지 않으며, Semgrep OSS SARIF에서 과거 관찰되지 않은 구조화된 흐름을 추측하지 않는다.

## 6. 위치, 범위와 실패 상태

- 파일과 줄이 있으면 상대 URI와 `startLine`을 기록한다.
- 파일만 있으면 artifact URI만 기록한다.
- 파일이 없으면 `locations`를 만들지 않는다. 가짜 줄 1을 사용하지 않는다.
- 공백, `#`, `?`, `%`, Unicode 등은 URI segment 단위로 UTF-8 인코딩한다.
- 정상 완료이면서 생략 0건이면 응답의 모든 Finding을 결과로 내보낸다.
- 생략이 있으면 표시된 Finding만 내보내고 전체/내보낸/생략 수와 issue/limitation을 기록한다.
- 부분·실패 검사는 상태를 그대로 보존하고 `executionSuccessful=false`로 기록한다.
- Finding 0건도 빈 `results`로 기록할 뿐 코드 안전성으로 표현하지 않는다.

## 7. 출력 및 보안 정책

- 파일명: `ai-code-security-results.sarif`
- MIME type: `application/sarif+json;charset=utf-8`
- UTF-8 최대 크기: 512 KiB
- 초과 시 자르지 않고 전체 다운로드를 거부한다.
- 사용자가 버튼을 누를 때만 생성·다운로드한다.
- Blob URL은 클릭 이후 해제한다.
- 추가 API 호출이나 외부 요청을 수행하지 않는다.
- API 토큰, 소스 원문, raw Semgrep JSON, stdout/stderr, 환경변수와 절대 임시 경로를 포함하지 않는다.
- JSON은 고정 객체 구조와 `JSON.stringify`로 직렬화한다. 비신뢰 객체를 병합하지 않는다.
- 경로와 Rule ID는 저장소 구조를 드러낼 수 있으므로 UI에서 외부 공유 전 확인을 안내한다.

## 8. UI

Finding 목록 아래 기존 `보고서 및 검토 기록` 영역에 접이식 `SARIF 내보내기`를 추가했다. 현재 대상의 포함/생략 Finding 수, 취약점 확정 결과가 아니라는 점, GitHub 자동 업로드 미실행과 경로·규칙 ID 공유 주의를 표시한다. 기존 Markdown, 분석가 보고서, JSON 백업/복원은 유지한다. 내보내기 영역은 Finding 목록 뒤에 있어 1440×900 목록 위치에 영향을 주지 않았다.

## 9. 검증 결과

환경: Node.js 24.22.2, Python 3.12.7, Semgrep 1.182.1, uv 0.11.26.

| 검증 | 결과 |
| --- | --- |
| TypeScript typecheck | PASS |
| Vitest 전체 | 14 files, 165 passed |
| SARIF 단위 테스트 | 18 passed, 공식 스키마 포함 |
| Production build | PASS |
| Chromium 전체 | 49 passed |
| axe 상태 검사 | 기존 7개 상태 포함 PASS; SARIF 영역을 펼친 상태 포함 |
| WebKit | 2 passed; SARIF 다운로드 포함 |
| 실제 FastAPI–Semgrep–Chromium E2E | 2 passed; 실제 SARIF 다운로드와 공식 스키마 검증 포함 |
| Safari QA 러너 | 7 passed |
| Python 전체 | 542 passed, 28 skipped, 1 dependency deprecation warning |
| Semgrep 고정 통합 묶음 | 44 passed, 1 dependency deprecation warning |
| npm audit | 0 vulnerabilities |
| UI-D3 1440×900 | Finding 목록 Y=724.44px, 첫 행 Y=784px |

최초 Chromium 전체 실행에서는 새 SARIF 공유 경고가 기존 경고 스타일의 16px을 상속해 대형 글자 회귀 1건이 실패했다. SARIF 영역에만 18px 가독성 규칙을 적용한 뒤 집중 테스트와 전체 49개를 다시 통과했다. 실제 E2E 첫 명령은 `SEMGREP_REQUIRED=1` Gate 누락으로 검사 시작 전에 중단됐으며, 고정 Semgrep 버전을 확인하고 Gate를 명시한 재실행에서 2개가 통과했다.

세 baseline 규칙을 한 합성 다운로드에 포함한 최종 집중 테스트의 첫 실행은 기본 4173 포트에 남아 있던 다른 preview를 Playwright가 재사용해 새 SARIF UI를 찾지 못했다. 기존 프로세스를 종료하지 않고 격리 포트 4288에서 다시 실행해 1개가 통과했으며, 동적 코드 실행·React HTML 삽입·Firestore 무조건 쓰기 허용 Rule ID가 모두 다운로드에 포함됨을 확인했다.

## 10. 남은 한계

- 실제 GitHub Code Scanning 업로드와 ingestion validator는 실행하지 않았다.
- fingerprint가 없어 GitHub 경고 중복 제거를 보장하지 않는다.
- 위치 없는 결과의 GitHub 표시 방식은 검증하지 않았다.
- `codeFlows`를 만들 근거가 없다.
- macOS Safari 실제 사용자 수용 검수는 별도이며 `SAFARI_USER_ACCEPTANCE_PENDING`이다.
- Linux exact SHA CI는 Push 후에만 확인할 수 있다.
