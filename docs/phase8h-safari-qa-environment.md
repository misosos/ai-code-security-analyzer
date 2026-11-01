# Phase 8H — Safari QA 환경 준비 및 자동 검증

## 시작 Gate

- 저장소: `misosos/ai-code-security-analyzer`
- 기준 SHA: `aad95cd13bbbbddb24f7da5fe2a32ede6745fa4d`
- `origin/main` / GitHub `main`: 기준 SHA와 일치 확인
- GitHub Actions Run [`41327075663`](https://github.com/misosos/ai-code-security-analyzer/actions/runs/41327075663): `push / completed / success`
- Python tests and CLI: 성공
- Semgrep 1.182.1 integration: 성공
- React dashboard: 성공, 기존 Chromium browser smoke 및 FastAPI–Semgrep E2E 성공
- 아티팩트: 0
- 시작 판정: `PHASE_8H_START_GATE_GO`

원래 Desktop 작업 트리는 미커밋 파일을 포함한 상태로 보존했다. 구현은 격리 worktree `/tmp/ai-csa-phase8h`, 브랜치 `phase/8h-safari-user-acceptance`에서 수행했다.

## QA 실행 구조

`frontend/scripts/run-safari-manual-qa.mjs`는 사용자가 직접 실행할 때마다 임시 디렉터리에 합성 프로젝트 2개와 신뢰된 `security-baseline.yml` 사본을 만든다. A에는 `eval` 호출이 있는 `stable.js`, `review.js`, B에는 결과가 없는 `safe.js`를 둔다. 파일은 실행하지 않고 Semgrep 정적 분석만 수행한다.

- 실제 API: locked 환경의 FastAPI/Uvicorn, `127.0.0.1`만 수신
- 프런트엔드: Vite 개발 서버, `127.0.0.1`만 수신
- API와 프런트엔드 포트: 실행 시 동적 할당, 프런트엔드가 API 프록시 포트를 전달
- 인증: 매 실행 32바이트 난수 API 토큰, 터미널에만 출력, URL에 포함하지 않음
- 대상: `safari-synthetic-a`, `safari-synthetic-b` 두 개만 서버 시작 시 등록
- 규칙: 저장소의 baseline 규칙 사본만 사용
- 자동 저장: QA 프로젝트는 임시 저장소이며 앱 검토 기록은 메모리 정책을 유지
- 종료: Ctrl+C/SIGTERM에서 API/Vite 자식 프로세스 그룹을 종료하고 해당 실행이 만든 임시 폴더만 제거
- 다운로드한 파일: 사용자 다운로드 폴더에 남으며 QA 종료 과정에서 삭제하지 않음

`frontend/vite.config.ts`는 `AI_CSA_API_PROXY_TARGET`을 허용하되 값이 `http://127.0.0.1:<port>` 형태인지 확인한다. 기본 개발 설정은 기존 `127.0.0.1:8765` 프록시를 그대로 사용한다.

## 자동 검증 결과

실행 명령:

```sh
cd /tmp/ai-csa-phase8h/frontend
SEMGREP_REQUIRED=1 npm run test:qa:safari
```

결과: Node 내장 테스트 7개 성공(39.09초). 포함된 실제 QA smoke 테스트에서 다음을 검증했다.

- Semgrep 버전 `1.182.1`
- 대시보드 및 API 준비 상태
- 등록 옵션에서 프로젝트 A/B만 노출
- Vite 프록시가 loopback이 아닌 API 대상을 거부
- 잘못된 토큰으로 검사 요청 시 `401`
- 미등록 대상 검사 시 `404`
- 프로젝트 A에서 별도 Finding ID 2개 및 `stable.js`/`review.js` 위치 확인
- 프로젝트 B에서 Finding 0건
- API 응답에서 합성 소스 canary, 토큰, 임시 절대 경로 비노출
- smoke 실행 후 자식 서버 종료 및 QA 임시 폴더 정리
- 대화형 모드에서 loopback 주소와 임시 토큰을 터미널에만 안내
- Ctrl+C 후 정상 종료 및 임시 자료 정리
- SIGTERM 후 정상 종료 및 임시 자료 정리

Node 지원 범위는 `>=24 <25`지만 이 호스트는 Node `v22.18.0`이라 `npm ci`에서 `EBADENGINE` 경고가 있었다. 설치는 완료됐고 취약점은 보고되지 않았다. 이 버전 차이 때문에 로컬 전체 프런트엔드 테스트 결과를 Node 24 검증으로 간주하지 않는다. 기준 SHA CI는 Node 24 환경에서 통과한 근거다.

로컬 도구 정보: macOS `15.7.7 (24G720)`, Node `v22.18.0`, npm `10.9.3`, uv `0.11.26`, Semgrep `1.182.1`, Playwright `1.64.1`. Safari 앱 버전은 확인하지 않았다.

전체 회귀를 격리 worktree에서 실행한 결과:

| 검증 | 결과 |
|---|---|
| `npm run typecheck` | PASS |
| `npm test` | 11개 파일, 106개 테스트 PASS |
| `npm run build` | PASS |
| Chromium 전체 브라우저 | 37/37 PASS, 39.9초. 고유 preview 포트 `48831` 사용 |
| axe 접근성 | 7개 axe 테스트 PASS. 규칙 비활성화 없음 |
| WebKit | 2/2 PASS, 6.7초, 고유 preview 포트 `48832` |
| UI-D3 결과 위치 | 목록 시작 `757.8125px` (<810), 첫 Finding 행 `818px` (<870) |
| 실제 Phase 8F FastAPI–Semgrep–Chromium E2E | 2/2 PASS, 28.8초(러너 전체 29.9초) |
| QA 실행/정리 smoke | 6/6 PASS, A 두 Finding, B 0 Finding, 인증/allowlist 및 Ctrl+C/SIGTERM 정리 확인 |
| `uv lock --check && uv sync --locked` | PASS |
| Python 전체 | 542 PASS, 28 선택적 SKIP, 1 경고, 291.57초 |
| Semgrep 1.182.1 핵심 통합 | 44 PASS, 1 경고, 208.39초 |
| 독립 합성 탐지 벤치마크 | 17 PASS, 21.17초 |
| Phase 6D 합성 일반화 평가 | 1 PASS, 16.53초 |
| Phase 6E held-out 평가 | 1 PASS, 16.75초 |
| Phase 6J 합성 검토 자료 렌더링 | PASS |

브라우저 검증 첫 시도는 기본 preview 포트 `4173`을 기존 사용자 Vite 서버가 점유한 상태에서 설정이 이를 재사용해 잘못된 서버를 검증 대상으로 삼았다. 그 실행은 결과에서 제외했다. 해당 서버를 종료하거나 수정하지 않고, 격리 worktree 자체 production preview를 포트 `48831`에서 새로 띄워 전체 37개를 다시 실행했으며 모두 통과했다. WebKit도 자체 preview를 포트 `48832`에서 실행했다.

## 수동 사용자 검수

- 가이드: [phase8h-safari-user-acceptance-guide.md](phase8h-safari-user-acceptance-guide.md)
- 기록지: [phase8h-safari-user-acceptance-results.md](phase8h-safari-user-acceptance-results.md)
- 기존 15개 항목 검수표: [Phase 8G Safari 접근성 사용자 수용 검수표](phase8g-manual-safari-accessibility-acceptance.md)

이 작업에서는 실제 Safari 앱을 조작하지 않았다. 실제 Safari, 실제 200% 확대, Safari 네이티브 선택창, VoiceOver, iOS Safari 및 사용자 최종 평가는 `NOT_TESTED`다. Playwright WebKit/Chromium 결과는 Safari 수용 결과를 대체하지 않는다.

로컬 `npm ci --ignore-scripts`는 성공했지만 이 호스트의 Node `v22.18.0`이 저장소 요구 `>=24 <25`와 맞지 않아 `EBADENGINE` 경고가 있었다. 프런트엔드 전체 자동화는 이 버전으로 통과했으며, Node 24 환경의 이번 변경 검증은 기준 SHA의 GitHub CI가 아니라서 별도 제한으로 남긴다. 다만 기준 SHA 원격 CI는 Node 24 설정에서 성공했다.

## 결과 및 제한

QA 인프라는 실제 FastAPI 및 Semgrep을 사용해 안전한 합성 데이터로 시작, 인증, allowlist, Finding 탐지, 종료를 재현할 수 있다. 이것은 실제 macOS Safari 사용성 평가가 아니다. API/프런트엔드 동적 포트 할당은 probe 후 bind 방식이므로 극히 짧은 포트 경쟁 조건이 남으며, 이미 사용 중인 포트를 만나면 서비스 readiness 확인이 실패하고 정리한다. 네트워크 접근은 로컬 loopback으로 제한하지만, 사용 중인 컴퓨터의 다른 로컬 프로세스와 운영체제 자원은 공유한다.

검증 중 조정 사항: 첫 `typecheck`는 Vite 설정에 새 환경변수를 읽는 `process` 선언이 없어 실패했다. 기존 의존성/런타임 범위를 늘리지 않고 설정 파일에 최소 타입 선언을 추가했으며 typecheck, build 및 프록시 제한 테스트가 통과했다. QA 스모크 개발 중에는 의존성 미설치와 인증 검증을 GET options에 잘못 적용한 테스트가 한 차례 실패했다. 잠금 의존성을 설치하고 인증 경계를 실제 보호 대상인 POST scan 요청으로 검증하도록 테스트를 바로잡은 후 전체 QA 테스트가 통과했다. API 인증 코드는 변경하지 않았다.

현재 사용자 상태: `SAFARI_USER_ACCEPTANCE_PENDING`.
