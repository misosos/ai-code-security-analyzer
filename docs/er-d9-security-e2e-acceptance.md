# ER-D9 Security E2E 검증 기록

기준 `d5136502d31891efb2972e51d3d479cc3c667f41`, GitHub Actions `42230886794`: push / completed / success, 필수 Python·React·Semgrep Job 성공, Artifact 0개. 격리 Worktree `research/er-d9-real-world-acceptance`에서 작업했다.

환경: Python 3.12.7, Semgrep OSS 1.182.1, Node.js 24.22.2, 로컬 baseline 규칙과 EJS 고정 커밋의 `lib/esm`. 실제 실행 명령 `uv run python scripts/evaluate_er_d9_real_world.py --browser`는 네 쌍의 API 조사를 순차 수행한 뒤 격리된 FastAPI–Semgrep–Chromium 경로를 실행했다. [결과](er-d9-real-world-investigation-results.md)에 원본과 통제 변경을 구분했다.

실제 검사: 원본 2건, 코드 변경 기준만 1/양쪽 1, Ignore 기준만 2 및 `PARTIAL`/`INCOMPARABLE`, 규칙 사본 동일과 주석 변경은 각각 `SAME_SELECTED_BYTES`와 `DIFFERENT_SELECTED_BYTES`. 각 Session 해제 후 재평가 404. 잘못된 Token은 401, 같은 Run 연결은 409였다. UI 자동화는 경로 제외·Gap Map·후속 안내·해제를 확인했다. 초기 대상 조회에서 실제 경로를 잘못 지정해 GitHub 404가 발생했고, 고정 commit tree에서 `lib/esm/ejs.js`를 확인한 뒤 재실행했다.

## 이번 검증

- `uv lock --check`: 통과. `PYTHONPATH=tests:. uv run pytest -q`: 675 passed, 28 skipped, 기존 Starlette 경고 1건. 건너뛴 항목은 통과로 집계하지 않는다.
- `SEMGREP_REQUIRED=1 PYTHONPATH=tests:. uv run pytest -q tests/test_semgrep_integration.py tests/test_rule_bytes_identity.py tests/test_investigation_api.py`: 38 passed, 같은 경고 1건. 실제 Semgrep과 합성 계약 검사가 함께 포함된다.
- ER-D1의 문서에 기록된 TestClient 재현 명령과 ER-D2, D3, D5의 독립 재현 스크립트를 실행해 성공했다. ER-D4, D6, D7의 계약·실행 회귀는 위 Python 검사에 포함된다.
- Node 24 `npm run typecheck`, `npm test -- --run`, `npm run build`: 통과, Vitest 19개 파일 212개 테스트 통과.
- 별도 포트의 Chromium 전체: 55 passed, axe 검사 포함. WebKit: 2 passed. 기존 Safari QA 자동화: 7 passed, 조사 Safari QA 자동화: 4 passed.
- 기존 FastAPI–Semgrep–Chromium E2E: 3 passed, 선택 시나리오 2 skipped. ER-D8 합성 시나리오 동일 바이트·주석 변경·옵션 OFF를 각각 실제 서버와 Chromium으로 순차 실행해 각 1 passed. ER-D9 실제 EJS 격리 사본의 Ignore 시나리오는 1 passed.
- 실제 EJS 실험에서 Session Release 후 404를 확인했다. TTL 만료와 stale 응답은 기존 합성 자동화의 범위이며 실제 15분 만료를 기다린 수동 검수는 수행하지 않았다.

테스트는 격리 Worktree와 소유 임시 자료에서 실행했다. 기존 사용자 QA 서버와 Desktop 원본은 사용하거나 종료하지 않았다. 자동화 브라우저가 재생성한 추적 캡처는 이 Worktree의 기준 버전으로 복원했다. 제품 코드와 공개 API 계약은 변경하지 않았다. 실제 Safari와 분석가 수용은 각각 `SAFARI_MANUAL_ACCEPTANCE_PENDING`, `ANALYST_ACCEPTANCE_PENDING`이다. 운영 승인은 `NOT_APPROVED`다.
