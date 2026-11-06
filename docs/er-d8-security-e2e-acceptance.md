# ER-D8 Security E2E 검증

## 기준과 환경

시작 기준 `d4aaa4ef8cfbcc1817e677ca1a4224edfde15296`, GitHub Actions `42214617747`: push / completed / success, Python·React·Semgrep 1.182.1 Job 성공, Artifact 0. GitHub main과 origin/main이 기준에 일치했다. Python 3.12.7, Semgrep OSS 1.182.1, Node.js 24 환경에서 합성 대상과 로컬 baseline 규칙을 사용했다.

## 실행 결과

- `uv lock --check`: 통과.
- `PYTHONPATH=tests:. uv run pytest -q`: 675 passed, 28 skipped, 경고 1개.
- `SEMGREP_REQUIRED=1 PYTHONPATH=tests:. uv run pytest -q tests/test_semgrep_integration.py tests/test_rule_bytes_identity.py tests/test_investigation_api.py`: 38 passed.
- ER-D1 문서의 실제 재현 명령과 D2·D3·D5 재현 스크립트: 성공. D4 Skip, D6 Rule Bytes 및 D7 API는 위 집중 테스트와 실제 E2E로 확인했다.
- `mise exec node@24 -- npm run typecheck`, `npm test`, `npm run build`: 통과, Vitest 212 passed.
- `BROWSER_TEST_PREVIEW_PORT=49388 mise exec node@24 -- npm run test:browser`: Chromium 55 passed. Map이 열린 조사 화면의 axe 검사 및 320–1920px 가로 넘침 검사, 합성 시계를 이용한 표시 만료 검사 포함.
- `BROWSER_TEST_PREVIEW_PORT=49389 mise exec node@24 -- npm run test:browser:webkit`: WebKit 2 passed.
- `npm run test:qa:safari`: 7 passed. `npm run test:qa:investigation:safari`: 4 passed.
- `SEMGREP_REQUIRED=1 ... npm run test:e2e:real`: 실제 FastAPI–Semgrep–Chromium 3 passed, D8 전용 선택 사례 1 skipped.
- 동일 명령에 `D8_GAP_CASE=same`, `comment`, `off`를 각각 지정: 실제 E2E 각 1 passed. 합성 대상과 규칙 사본은 하네스 종료 시 정리한다.
- `git diff --check`: 최종 스테이징 전 확인.

초기 `uv sync --locked --extra dev`는 이 저장소가 optional extra 대신 dependency group을 사용해 실패했다. `uv sync --locked --group dev`로 설치 후 실행했다. 전체 pytest는 저장소 루트와 테스트 디렉터리를 `PYTHONPATH`에 포함해 로컬 테스트 import를 해석했다. 만료 브라우저 시험의 첫 실행은 같은 안내가 접근성 상태 영역에도 있어 선택자가 두 요소에 일치해 실패했고, 조사 패널의 상태 메시지를 지정한 뒤 통과했다. 실 Semgrep 시나리오를 한꺼번에 재실행했을 때 부하로 검사 timeout이 발생했다. 각 시나리오를 순차 실행하여 모두 통과했다.

## 보존과 한계

별도 Worktree와 충돌 없는 포트를 사용했다. 기존 4173 QA 서버는 종료하지 않았다. 브라우저 회귀 중 Worktree의 추적 캡처가 자동 갱신되어 검토 후 기준 버전으로 복원했다. 원본 Desktop 및 사용자 미추적 자료는 변경하지 않았다. 자동화 WebKit은 실제 Safari 사용자 수용이 아니다. VoiceOver, iOS Safari, 실제 15분 만료의 수동 검수 및 분석가 효율 개선은 미검증이며 운영 승인은 없다.
