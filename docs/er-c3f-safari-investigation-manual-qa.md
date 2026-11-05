# ER-C3F Safari 조사 수동 QA

이 도구는 합성 프로젝트와 로컬 단일 worker API를 일시적으로 실행한다. 자동 검증은 사용자 Safari 수용이 아니다. macOS Safari, VoiceOver 및 iOS Safari 수용 결과는 사용자 확인 전까지 `NOT_TESTED`다.

## 실행

Node.js 24, Python 3.12.7, uv와 Semgrep 1.182.1을 준비한다. 이 worktree의 frontend에서 실제 터미널을 열어 실행한다.

```bash
cd frontend
mise exec node@24 -- npm ci
mise exec node@24 -- npm run qa:investigation:safari
```

터미널에 표시된 loopback 주소를 Safari에서 열고 표시된 토큰을 `로컬 API 토큰`에 입력한다. 토큰을 로그, 기록, 캡처, 채팅에 남기지 않는다. 조사 수동 모드는 입출력이 터미널일 때만 시작한다. 자동 smoke에서는 토큰을 출력하지 않는다.

스크립트는 QA 소유 임시 디렉터리에 `stable.js`와 `retired.js`를 생성하고 baseline 규칙만 복사한다. 동적 loopback 포트 두 개, 정확한 Origin, 32바이트 난수 토큰, v2를 명시적으로 활성화한 단일 worker 및 access log 없는 API를 사용한다. 기본 app factory의 v2 비활성 정책은 유지된다.

## Safari 점검

1. `일반 검사`가 기본 선택인지 확인하고 프로젝트 A를 선택한다. `검사 실행` 후 Finding, 검토 상태 및 내보내기를 확인한다.
2. 검사 설정에서 `소멸 근거 조사 선택`을 펼치고 `소멸 근거 조사`를 선택한다.
3. `검사 실행`을 누른 후 `현재 결과를 비교 기준으로 저장`을 누른다. 첫 검사에서 stable과 retired가 보고돼야 한다.
4. **이때 QA 터미널에서 Enter를 한 번 누른다.** 도구가 소유한 retired 합성 파일을 변경하고 added 합성 파일을 생성한다. 사용자 프로젝트는 수정하지 않는다.
5. 같은 대상과 baseline 규칙으로 `검사 실행`을 누른다. `검사 결과 비교`를 펼쳐 `소멸 근거 조사 실행`을 누른다.
6. `양쪽 검사에서 관찰`, `기준 검사에서만 관찰`, `이번 검사에서만 관찰` 각각 한 건인지 확인한다. 경로 관찰, 가설과 `분석 한계 확인`을 읽는다.
7. Source Snapshot 미수집과 규칙 identity 미검증을 확인한다. Finding 미관찰은 수정·해결이나 안전성의 증거가 아니다.
8. `조사 증거 해제`를 누른다. 해제 요청 안내와 재조사를 위해 새 검사가 필요하다는 안내를 확인한다.
9. 200% 확대, 키보드 포커스, 좁은 창의 줄바꿈과 가로 넘침을 확인한다. 좁은 데스크톱 창은 iOS Safari 검증이 아니다.
10. 종료하려면 QA 터미널에서 Ctrl+C를 누른다. 도구는 자신이 시작한 프로세스와 자신이 만든 임시 디렉터리만 정리한다.

두 Run은 최대 15분 보관된다. 조사 scan은 분당 2회이므로 일반 검사는 v1로 먼저 실행하고, 기준 및 재검사 두 번을 조사 모드로 수행한다. 429 안내가 나오면 잠시 기다린다. 자동 재시도는 없다. Release 요청이 실패할 수 있으며 TTL이 최종 보존 한계다.

실제 만료/서버 중단, INCOMPARABLE 및 Finding 0건의 Safari 화면은 별도 조건이 필요하다. 해당 상태를 관찰하지 않았다면 수용 기록에서 `NOT_TESTED`로 둔다. 정상 0건은 코드 안전성을 증명하지 않는다.

## 자동 smoke

```bash
mise exec node@24 -- npm run test:qa:investigation:safari
```

실제 API와 Semgrep으로 인증 거부, A/B → A/C, 세 관찰 범주와 Release 후 재사용 거부를 확인한다. token과 Handle을 출력하지 않는다. 기존 `npm run qa:safari`는 별도로 유지된다.

## 경계

`AI_CODE_SECURITY_TARGET` 또는 `AI_CODE_SECURITY_TARGETS`, `AI_CODE_SECURITY_API_TOKEN`, `AI_CODE_SECURITY_ALLOWED_ORIGINS`, `AI_CODE_SECURITY_RULES_DIR`는 API 설정이다. `AI_CSA_API_PROXY_TARGET`은 Vite 프록시 설정이다. 이 도구는 안전한 값을 자식 프로세스에 설정한다.

포트 선택 후 실제 bind까지 경쟁 가능성이 있으며 bind 실패 시 시작을 중단한다. 서버 재시작 후 증거는 복구되지 않는다. 다중 worker·다중 사용자, 하드 RSS 상한과 운영 서비스는 지원하지 않는다.

## 개발 검증 기록

기준 `d78714c4184491955a3e79d9ca83efc6cd77cf2f`의 CI Run `41955262642`는 세 필수 Job 성공, Artifact 0개였다. ER-C3F 로컬 검증은 macOS, Python 3.12.7, Node.js 24.22.2, Semgrep 1.182.1에서 수행했다.

- Python 전체: 646 passed, 28 skipped, 기존 경고 1개. C1/C2/C3B/C3C 테스트가 포함된다.
- 현재 CI Semgrep integration 선택 12개 파일: 46 passed, 기존 경고 1개.
- TypeScript, Vitest 192개, production build: 통과.
- Chromium 전체 53개, WebKit 2개, axe와 200% CSS viewport 대리 검증: 통과.
- 실제 FastAPI–Semgrep–Chromium E2E 3개: 통과.
- 기존 Safari QA 자동화 7개: 통과.
- 새 조사 QA 자동화 4개: 실제 v2 A/B → A/C, 인증 거부, Release 후 재사용 거부, 비터미널 토큰 출력 차단, SIGINT/SIGTERM 및 QA 소유 Vite 비정상 종료 정리, 잘못된 Semgrep 버전 거부 확인.
- `uv lock --check`, `git diff --check`: 통과.

기존 공용 포트·프록시·소유 디렉터리 보호 테스트와 Python API 보안 테스트를 재사용했다. 무작위 포트 할당과 bind 사이의 경쟁은 남는다. 운영 TTL의 실제 15분 대기, macOS Safari 사용자 조작, VoiceOver, iOS Safari는 수행하지 않았다.

초기 과도한 병렬 실행에서는 Semgrep scan이 `timed_out`으로 실패했고 해당 실행을 중단했다. E2E와 전체 Python 및 Semgrep 묶음을 단독 재실행해 통과했다. 가상 터미널 시험의 한 차례 준비 시간 초과 뒤 단독 재실행이 통과했다. 이는 부하가 큰 환경에서 재시작이 필요할 수 있음을 뜻한다.
