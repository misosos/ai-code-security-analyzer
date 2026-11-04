# Phase 8N — GitHub Code Scanning 사전 진단

## 목적과 범위

Phase 8M에서 생성하는 SARIF 2.1.0을 GitHub Code Scanning에 보내기 전에, 현재 API 응답만으로 확인할 수 있는 조건과 저장소 운영자가 별도로 확인해야 하는 조건을 분리한다. 이 기능은 브라우저 안의 결정론적 진단이며 GitHub API 호출, 인증, 파일 업로드를 하지 않는다.

시작 Gate는 기준 SHA `24d1800d66e66d329b4b32d4ded5a29515dab99c`와 GitHub Actions Run `41775500284`를 확인했다. Run은 `push / completed / success`, Python tests and CLI, React dashboard, Semgrep 1.182.1 integration 모두 성공, Artifacts 0개였다. `origin/main`과 GitHub main은 기준 SHA와 일치했다.

## 검증 단계와 상태

각 항목은 `VERIFIED`, `REQUIRES_VERIFICATION`, `UNSUPPORTED`, `BLOCKED` 중 하나로 표시한다. 이 상태는 해당 항목만 나타낸다. 전체 SARIF 업로드 준비는 자동 승인하지 않으며, 완전한 로컬 응답이어도 항상 저장소·commit·권한·업로드 경로 확인을 요구한다.

| 구분 | 결과 | 의미 |
| --- | --- | --- |
| OASIS SARIF 2.1.0 스키마 | `SARIF_SCHEMA_VALIDATED` | 핀된 공식 스키마 fixture로 생성 결과 테스트 통과 |
| GitHub Code Scanning 정적 호환성 | `GITHUB_CODE_SCANNING_COMPATIBILITY_NOT_FULLY_VERIFIED` | 필드와 제한을 검토했으나 원격 저장소 검증 및 서버 처리 미실행 |
| 실제 업로드 | `GITHUB_UPLOAD_NOT_TESTED` | 업로드 기능과 Workflow 권한을 추가하지 않았음 |

사전 진단은 생성 SARIF가 현재 검증된 API 응답의 고정 생성기 출력과 정확히 일치하는지, 결과 수 및 `ruleId`/`ruleIndex` 참조가 일관적인지 확인한다. 공식 스키마 검증은 테스트에서 `frontend/tests/fixtures/sarif-schema-2.1.0.json`을 Ajv draft-04로 적용한다. fixture SHA-256은 `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e`다. 런타임은 임의 SARIF 파일을 받아들이는 범용 파서가 아니다.

## 확인 가능한 SARIF 데이터

- SARIF producer는 **AI Code Security Analyzer**, detection engine은 **Semgrep**으로 구분하며 Semgrep 버전은 API 응답 값을 사용한다.
- Rule ID는 원본 값을 보존하며 중복 규칙 descriptor를 합친다. 한 검사 내 `ruleId`와 `ruleIndex` 참조는 검증한다. 여러 실행 간 규칙 ID 안정성은 규칙 릴리스 이력을 확인해야 하므로 `REQUIRES_VERIFICATION`이다.
- 원본 심각도와 SARIF level은 별개다. 임의 CVSS나 `security-severity` 수치를 만들지 않는다.
- 위치가 있으면 상대 URI와 원래 양의 line을 유지한다. URI 경로 형식과 실제 원격 저장소 내 파일 일치는 별개다. 파일·줄이 없는 결과도 SARIF에서 누락하지 않으며 해당 Finding 위치는 추가 확인이 필요하다고 표시한다.
- Finding ID는 확장 속성의 내부 식별자로만 보존한다. GitHub fingerprint라고 취급하지 않는다. `partialFingerprints`, `primaryLocationLineHash`, 코드 행 해시를 생성하지 않는다.
- `validated`, `rejected`, `unavailable`, `unverified` 및 지원/제한 Claim을 기존 SARIF 속성에서 보존한다. 검증된 근거 연결은 취약점 확정이 아니다.
- `codeFlows`, `threadFlows`, `relatedLocations`, `fixes`는 API가 실제 근거를 제공하지 않아 만들지 않는다. Phase 3A에서 확인한 Semgrep OSS SARIF의 dataflow 한계도 그대로 유지한다.

## 경로, commit 및 fingerprint

현재 API의 상대 경로가 SARIF URI 규칙에 맞는지 검사할 수는 있지만, API에는 GitHub 저장소 식별자, commit/ref, 저장소 파일 내용 또는 분석 당시 소스 스냅샷이 없다. 따라서 다음은 모두 `REQUIRES_VERIFICATION`이다.

1. 대상 GitHub 저장소의 파일이 해당 상대 경로에 존재하는지
2. 검사 당시 소스가 업로드 대상 commit/ref와 일치하는지
3. 원격 파일 내용이 분석 당시 파일 내용과 같은지
4. Rule ID와 분석 category가 이후 실행에서도 안정적인지

GitHub 문서는 안정적인 Rule ID와 파일 경로가 경고 연결에 중요하며, fingerprint가 실행 간 경고를 연결하는 데 사용된다고 설명한다. `upload-sarif` Action은 checkout된 소스를 활용해 fingerprint를 보완할 수 있지만 코드가 분석 시점과 일치해야 한다. REST API 직접 업로드는 fingerprint가 없을 때 중복 경고 위험을 별도로 고려해야 한다. 실제 처리 결과는 이번 Phase에서 업로드하지 않아 검증되지 않았다.

## 검사 범위

정상 완료이며 생략 0건인 경우, API 응답에 표시된 모든 Finding이 SARIF 결과로 표현되는지 확인한다. 이는 분석기가 모든 문제를 탐지했다는 뜻이 아니다. 부분/실패/시간 초과 또는 생략 결과가 있으면 검사 범위를 `BLOCKED`로 표시하고 업로드 준비도 차단한다. Finding 0건은 안전성 증명이 아니다. 결과가 있는 경우 파일·줄 위치가 없어도 SARIF 결과를 임의로 제거하지 않는다.

## UI와 네트워크 경계

기존 SARIF 내보내기 접이식 영역에 사전 진단을 넣었다. 사용자가 상태, Finding별 위치 제공 상황, fingerprint 미지원, Action과 REST API 차이, 검사 범위와 업로드 전 체크리스트를 확인할 수 있다. 업로드는 수행되지 않으며 GitHub 네트워크 요청도 발생하지 않는다. 브라우저 테스트에서 SARIF 다운로드 외 추가 API 요청이 없고 외부 요청이 발생하지 않음을 확인했다.

파일에는 상대 경로와 Rule ID가 포함될 수 있으므로 외부 공유 전에 내용을 확인해야 한다. 소스 코드 원문, 인증 토큰, 절대 경로, raw Semgrep JSON은 SARIF로 넣지 않는다. 명시적인 버튼 동작만 다운로드를 시작한다. 기존 JSON 백업, Markdown 내보내기 및 분석가 상태 정책은 유지했다.

## 향후 Workflow 보안 조건

현재 `.github/workflows/ci.yml`은 `contents: read`를 사용하며 SARIF 업로드 단계가 없다. 이번 Phase는 권한을 확장하지 않았다. 향후 업로드 설계에서는 업로드 전용 job에만 필요한 `security-events: write`를 부여하는 방안을 검토할 수 있지만, job 권한 분리만으로 fork/PR의 비신뢰 코드 실행과 산출물 오염 위험이 해소되지는 않는다.

업로드 구현 전 최소한 다음을 별도로 승인·검증해야 한다.

- 저장소에서 Code Scanning을 사용할 수 있는지와 업로드 대상 저장소
- 대상 commit/ref 및 SARIF 경로가 그 commit의 소스와 일치하는지
- category, Rule ID 및 fingerprint 전략의 실행 간 안정성
- Action 또는 REST API의 선택과 중복 경고 처리
- fork/PR 신뢰 경계, 토큰 노출 및 산출물 변조 방지
- 부분 검사 또는 Finding 생략 결과의 업로드 정책
- Action SHA 고정, 임시 SARIF 보존 기간 및 로그 정책

## 검증 결과

환경: macOS, Node.js `v24.22.2`, npm `11.19.1`, Python `3.12.7`, uv `0.11.26`, Semgrep `1.182.1`. `uv lock --check` 통과. 새 의존성이나 lockfile 변경은 없었다. `npm ci` 성공, npm audit은 취약점 0건을 보고했다. npm은 `fsevents` lifecycle script가 승인되지 않았다는 경고를 냈지만 설치는 완료됐다.

| 검증 | 결과 |
| --- | --- |
| TypeScript typecheck | PASS |
| Vitest | PASS — 15 files, 180 tests |
| Production build | PASS |
| Chromium browser suite | PASS — 49 tests; UI-D3 Finding 목록 1440px Y=724.44, 첫 행 Y=784 |
| WebKit | PASS — 2 tests; 별도 재실행 2/2 |
| axe | PASS — 기존 접근성 browser suite의 axe 시나리오 포함, 사전 진단 상세 0 violations |
| Python 전체 | PASS — 542 passed, 28 선택적 Ollama tests skipped |
| Semgrep 1.182.1 CI 통합 묶음 | PASS — 44 passed |
| 실제 FastAPI–Semgrep–Chromium E2E | PASS — 2 tests, 약 30.6초 |
| Safari QA 회귀 | PASS — 7 tests |
| `git diff --check` | PASS |

Python 전체 테스트를 CI의 Semgrep 환경 변수 없이 처음 실행했을 때 실제 API–Semgrep 테스트 1개가 timeout으로 실패했다. CI와 동일하게 `SEMGREP_REQUIRED=1`, `SEMGREP_SEND_METRICS=off`, `SEMGREP_ENABLE_VERSION_CHECK=0`을 적용한 전체 재실행은 통과했고, 해당 API E2E도 별도 실행에서 2/2 통과했다.

WebKit 전체 테스트에서는 320px 화면에서 분석가 보고서의 메모 포함 레이블이 flex 항목의 기본 최소 너비로 2px 넘치는 결함을 확인했다. 좁은 화면에서 해당 레이블을 컨테이너 폭 안에서 줄바꿈하도록 제한한 뒤 WebKit 2/2 및 전체 브라우저 스위트 49/49를 통과했다. 이 수정은 SARIF 데이터나 보고서 동작을 변경하지 않는다.

## 미검증 범위와 최종 상태

- GitHub Code Scanning의 서버 측 SARIF 처리 및 업로드: `GITHUB_UPLOAD_NOT_TESTED`
- GitHub Code Scanning 완전 호환성: `GITHUB_CODE_SCANNING_COMPATIBILITY_NOT_FULLY_VERIFIED`
- 원격 저장소 파일/commit/ref와 분석 소스의 실제 동일성: 확인 불가
- GitHub 경고 deduplication의 fingerprint 결과: 확인 불가
- 실제 macOS Safari, VoiceOver, Safari 200% 확대: 이번 Phase에서 수행하지 않음 (`SAFARI_USER_ACCEPTANCE_PENDING`)
- Linux exact-SHA CI: 로컬 실행 결과로 대체하지 않으며 push 후 확인 필요

## 참고 자료

- [OASIS SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [OASIS SARIF 2.1.0 JSON Schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json)
- [GitHub SARIF 지원](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
- [GitHub SARIF 업로드 안내](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)
