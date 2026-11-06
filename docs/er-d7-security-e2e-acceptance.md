# ER-D7 Security E2E Acceptance

## 기준과 환경

- 시작 SHA: `8d90bdf2da8c23888f885ff33a50093c5f677432`
- 시작 CI: `42199589485` (`push`, completed, success, 필수 3 Job 성공, Artifact 0)
- Python 3.12.7, Semgrep OSS 1.182.1, Node.js 24
- 합성 JavaScript Target과 격리된 baseline rule 사본만 사용
- 사용자 소유 4173 포트 서버는 건드리지 않았고, 일반 Chromium 회귀는 고유 포트 `49371`에서 실행

## 실제 관찰

실제 FastAPI TestClient → ScanService → ER-D6 rule snapshot → Semgrep 경로에서 다음을 재현했다.

1. 같은 rule bytes를 사용한 독립 Run 두 건은 `SAME_SELECTED_BYTES`였다.
2. rule YAML에 주석만 추가해 Finding 동작을 유지한 두 Run은 `DIFFERENT_SELECTED_BYTES`였다.
3. `.semgrepignore`로 경로가 제외된 current Run은 `PARTIAL`이었다. Rule projection은 `UNVERIFIED`, 기존 Finding Evaluation은 `INCOMPARABLE`을 유지했다.
4. API 응답에는 SHA-256, Digest, rule content, internal Scan Reference와 절대 경로가 없었다.
5. 실제 브라우저에서 opt-in을 켜면 두 검사 모두 `/api/v2/investigation-scans/rule-bytes`를 사용하고, Evaluation UI에는 별도의 Rule Bytes panel이 표시됐다. 부분 검사 결과는 `UNVERIFIED`로 표시됐고 제한 안내가 보였다.
6. FastAPI–Semgrep–Chromium E2E는 최종 3/3 통과했다. 여기에는 실제 Skip/Partial 흐름과 신규 Rule Bytes Projection 확인이 포함된다.

이 결과는 선택된 단일 사본의 byte equality다. Semgrep이 실제로 구성한 전체 loaded rule inventory, 모든 규칙 성공, Finding 변화의 원인 또는 취약점 해결을 입증하지 않는다.

## 부정·수명 검증

Unit/contract tests는 Observation의 Scan Reference, Target, Profile, invocation, Semgrep version과 digest 길이를 검증한다. 모드가 다른 브라우저 Run은 결합하지 않는다. 동일 Run, 다른 문맥, 만료·Release, single-flight, Registry cap은 기존 Registry/API Gate를 재사용한다. sidecar byte는 stored byte cap에 포함되고 Run 제거 시 차감된다. 신규 Rule Bytes 평가도 Session 및 두 Run을 pin하며 평가 중 Release를 차단한다.

Safari QA 자동화는 기존 7/7과 investigation 4/4 통과했다. WebKit 브라우저 자동화는 2/2, 일반 Chromium 전체는 고유 포트에서 53/53 통과했다. 실제 Safari 사용자 수용은 자동화 결과로 주장하지 않는다.

## 성능과 메모리 범위

Registry의 추가 원시 evidence는 성공 Run당 32 bytes와 bounded metadata뿐이다. 실제 동일/다름 API 시험은 각 두 번의 Semgrep 실행을 포함했다. 이 단일 환경의 실행 시간은 사람의 조사 시간이나 평균 성능 개선을 뜻하지 않는다. D6의 `/tmp` 사본과 동일 사용자·권한 프로세스에 대한 잔여 TOCTOU 한계는 계속 남는다.

## 검증 기록

- 전체 Python: `675 passed, 28 skipped, 1 warning` (최종 concurrency 변경 포함)
- ER-D7 Registry/API 집중 테스트: `44 passed` (신규 pin/release 경쟁 테스트 포함)
- Frontend typecheck, 전체 Vitest (`198 passed`), production build: 통과
- 일반 Chromium: `53 passed` (고유 포트 49371)
- WebKit: `2 passed`
- 실제 FastAPI–Semgrep–Chromium: 초기 두 번은 E2E 기대값이 UI 문구/API 응답 키와 불일치해 실패. 테스트 기대를 실제 UI/API 계약에 맞춘 후 `3 passed`.
- Safari QA 자동화: `7 passed`; Investigation Safari QA 자동화: `4 passed`
- `uv lock --check`: 통과
- `git diff --check`: 통과

첫 일반 Chromium 실행은 Playwright의 로컬 설정이 사용자의 기존 4173 서버를 재사용해 해당 서버의 다른 UI 상태에 연결된 것으로 확인되어 실패했다. 서버는 종료하거나 수정하지 않았다. 이후 별도 포트의 Worktree 빌드에서 전체 통과했다.

## 남은 한계

실제 macOS Safari, VoiceOver와 iOS Safari 수동 수용은 이번 자동화 범위가 아니다. Rule Bytes projection은 전체 Semgrep loaded ruleset 동일성, 소스 변경, 검사 범위 완전성, Finding 소멸의 인과관계 또는 취약점 해결 여부를 평가하지 않는다. 운영 승인도 부여하지 않는다.
