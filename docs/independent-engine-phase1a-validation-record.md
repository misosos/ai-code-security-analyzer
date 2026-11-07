# IND-1A 검증 및 재현 기록

## 시작 Git·CI Gate

감사 시작 기준은 `d00344520eaf894189908cb7927112ce2ecd218d`, 부모는 `9dffe82ddd50b86aa8b8f1041491a094bd1187f9`다. [연구 PR #2](https://github.com/misosos/ai-code-security-analyzer/pull/2)의 head가 해당 SHA와 `research/independent-engine-phase1`에 일치했고 OPEN·미병합 상태였다. [CI 42348300560](https://github.com/misosos/ai-code-security-analyzer/actions/runs/42348300560)은 event=pull_request, 정확한 head_sha, completed/success, Python tests and CLI·React dashboard·Semgrep 1.182.1 integration 각각 success, Artifact 0개를 GitHub API로 재확인했다. push CI로 바꾸어 부르지 않는다.

Desktop은 기존 main의 다른 SHA와 추적 변경 6개·미추적 자료를 보유했다. 원본을 수정하지 않고 검증된 PR 커밋에서 별도 Worktree `research/independent-engine-phase1a`를 생성했다. 기존 IND-1 Worktree의 미추적 `.taste-skill/`, 다른 Worktree와 사용자 4173 서버도 보존했다. 이번 작업의 원격 CI는 실행되지 않았으며 기존 PR CI는 감사 변경을 검증한 결과가 아니다.

## 사전 Oracle 및 실행 계층

36개 새 합성 입력과 선언·참조 관계·기대 상태·필수 진단·판단 근거·지원 범위·취약점 미검증을 [Oracle](../tests/fixtures/independent_engine_phase1a/oracle.json)에 엔진 실행 전에 고정했다. SHA-256은 `974d08fc3f8bd451405c365d49f919d0142886f289f4125f699179eba8344614`이며 이후 변경하지 않았다. 이 Digest는 공개 합성 Oracle 무결성 값이며 제품의 비공개 Rule Bytes Digest가 아니다.

지원 구문 15개, 문서상 미지원 13개, 보수적 거부 8개다. 각 소스는 기존 16개 fixture와 바이트가 다르며 일부 구조군은 대조용으로 중복된다. 같은 에이전트의 구현 이력이 있으므로 인적 독립성과 blind holdout은 확보되지 않았다. 실행 전 계약 고정과 규격·Node parse-only 교차 확인의 제한된 독립성만 있다.

- 새 엔진 관찰: 입력마다 별도 제한 자식에서 실제 현재 Tree-sitter 엔진을 호출함. Mock 결과가 아님.
- Node.js 24: 36개 전부 `--check`만 수행. 문법 오류 1개·early error 2개는 거부, 나머지 33개는 허용되어 사전 유효성 구분과 일치했다. 분석 대상 코드는 실행하지 않음.
- 부모 격리 경계 시험: C 대기·CPU·할당·출력·signal·exit·권한 probe는 합성 시험 mode이며 JavaScript parser의 실제 오류로 위장하지 않음.
- 과거 callback: 명시적 opt-in의 고정 합성 입력으로 실제 SIGSEGV 재현. 현재 엔진의 일반 callback 없는 경로와 구분함.

## 신규 사례 결과

기대값은 수정하지 않았다. 상세 선언·관계·근거는 Oracle에, 실제 위치·진단은 [관찰 projection](independent-engine-phase1a-observations.json)에 있다. 신호 일치 결과를 취약점 정확도나 Precision/Recall로 계산하지 않는다.

| ID | 기대 상태 / 관찰 | 실제 상태 / 관찰 | 결과 |
| --- | --- | --- | --- |
| A01 | ANALYZED / DIRECT_CALL | ANALYZED / DIRECT_CALL | 일치 |
| A02 | ANALYZED / SIMPLE_ALIAS_CALL | ANALYZED / SIMPLE_ALIAS_CALL | 일치 |
| A03 | ANALYZED / SIMPLE_ALIAS_CALL | ANALYZED / SIMPLE_ALIAS_CALL | 일치 |
| A04 | PARTIAL / DIRECT_CALL | PARTIAL / DIRECT_CALL | 일치 |
| A05 | PARTIAL / 관찰 없음 | PARTIAL / 관찰 없음 | 일치 |
| A06 | PARTIAL / 관찰 없음 | PARTIAL / 관찰 없음 | 일치 |
| A07 | ANALYZED / DIRECT_CALL | ANALYZED / DIRECT_CALL | 일치 |
| A08 | PARTIAL / SIMPLE_ALIAS_CALL | PARTIAL / SIMPLE_ALIAS_CALL | 일치 |
| A09 | ANALYZED / 관찰 없음 | ANALYZED / 관찰 없음 | 일치 |
| A10 | PARTIAL / 관찰 없음 | PARTIAL / 관찰 없음 | 일치 |
| A11 | PARTIAL / 관찰 없음 | PARTIAL / 관찰 없음 | 일치 |
| A12 | ANALYZED / 관찰 없음 | ANALYZED / 관찰 없음 | 일치 |
| A13 | PARTIAL / 관찰 없음 | PARTIAL / 관찰 없음 | 일치 |
| A14 | PARTIAL / 관찰 없음 | PARTIAL / 관찰 없음 | 일치 |
| A15 | PARTIAL / 관찰 없음 | PARTIAL / 관찰 없음 | 일치 |
| A16 | PARTIAL / 관찰 없음 | ANALYZED / SIMPLE_ALIAS_CALL | **불일치** |
| A17 | PARTIAL / 관찰 없음 | ANALYZED / SIMPLE_ALIAS_CALL | **불일치** |
| A18 | PARTIAL / 관찰 없음 | ANALYZED / DIRECT_CALL | **불일치** |
| A19 | PARTIAL / 관찰 없음 | ANALYZED / DIRECT_CALL | **불일치** |
| A20 | ANALYZED / DIRECT_CALL | ANALYZED / 관찰 없음 | **불일치** |
| A21 | ANALYZED / 관찰 없음 | ANALYZED / 관찰 없음 | 일치 |
| A22 | ANALYZED / DIRECT_CALL | ANALYZED / DIRECT_CALL | 일치 |
| A23 | ANALYZED / 관찰 없음 | ANALYZED / 관찰 없음 | 일치 |
| A24 | ANALYZED / DIRECT_CALL | ANALYZED / DIRECT_CALL | 일치 |
| A25 | ANALYZED / 관찰 없음 | ANALYZED / 관찰 없음 | 일치 |
| A26 | PARTIAL / 관찰 없음 | PARTIAL / 관찰 없음 | 일치 |
| A27 | PARTIAL / 관찰 없음 | PARTIAL / 관찰 없음 | 일치 |
| A28 | PARTIAL / 관찰 없음 | PARTIAL / 관찰 없음 | 일치 |
| A29 | PARTIAL / 관찰 없음 | PARTIAL / 관찰 없음 | 일치 |
| A30 | PARTIAL / 관찰 없음 | PARTIAL / 관찰 없음 | 일치 |
| A31 | PARTIAL / 관찰 없음 | PARTIAL / 관찰 없음 | 일치 |
| A32 | ANALYZED / 관찰 없음 | ANALYZED / 관찰 없음 | 일치 |
| A33 | ANALYZED / SIMPLE_ALIAS_CALL | ANALYZED / SIMPLE_ALIAS_CALL | 일치 |
| A34 | PARSE_ERROR / 관찰 없음 | PARSE_ERROR / 관찰 없음 | 일치 |
| A35 | ANALYZED / SIMPLE_ALIAS_CALL | ANALYZED / SIMPLE_ALIAS_CALL | 일치 |
| A36 | PARTIAL / 관찰 없음 | PARTIAL / 관찰 없음 | 일치 |

신규 Oracle assertion은 **31 passed / 5 failed**이며 A16–A20의 실패를 유지했다. xfail/skip이나 기대 완화로 통과시키지 않았다. 이 실패는 [감사 보고서](independent-engine-phase1a-security-audit.md)의 IND1A-01~03과 연결된다.

기존 62개 단위 시험은 재실행에서 62 passed였다. 기존 16개 comparison fixture를 실제 Semgrep 1.182.1로 다시 실행했으며 독립 엔진의 고정 기대를 모두 충족했다. Semgrep 정상 batch는 completed/8건, 문법 오류 batch는 partial/0건과 semgrep_reported_errors였다. 최초 IND-1의 속도·정확도 우월성을 증명한 것은 아니다. 새 corpus의 실패 5개와 이 기존 통과를 별도로 해석한다.

## 재현 명령

```bash
uv sync --locked --group dev
uv lock --check
uv run python scripts/audit_ind1a.py --suite oracle
# 현재 미수정 결함 때문에 exit 1: 31 MATCH / 5 MISMATCH
uv run python -m pytest -q tests/research/ind1a/test_oracle_checks.py
# 현재 미수정 결함 때문에 exit 1: 31 passed / 5 failed
uv run python -m pytest -q tests/test_ind1a_isolation.py
uv run python scripts/audit_ind1a.py --suite isolation
# 과거 native 충돌을 선택하는 별도 명령. 일반 pytest에는 포함하지 않는다.
uv run python scripts/audit_ind1a.py --suite isolation --native-repro
mise exec node@24 -- uv run python scripts/audit_ind1a.py --suite syntax
uv run pytest -q tests/test_independent_eval_engine.py
uv run python scripts/evaluate_independent_engine_phase1.py --semgrep
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 PYTHONPATH=tests:. uv run python -m pytest -q -rs
```

회귀 프런트엔드 명령은 frontend에서 Node.js 24로 npm ci, typecheck, npm test, build, test:browser, test:browser:webkit, test:qa:safari, test:qa:investigation:safari, SEMGREP_REQUIRED=1 test:e2e:real을 실행했다. Chromium/WebKit preview 포트는 각각 49821/49822, 실제 E2E는 실행기가 할당한 별도 loopback 포트다. 기존 4173 서버를 재사용하지 않았다.

## 전체 회귀 결과

| 검증 | 실제 결과 |
| --- | --- |
| 전체 Python, Semgrep 필수, 신규 감사 포함 | **782 passed / 5 failed / 28 skipped**, 246.42초, warning 1 |
| 실패 항목 | 새 Oracle A16~A20만 실패, 기존 시험의 추가 실패 없음 |
| 기존 IND-1 집중 시험 | 62 passed, 전체에도 포함 |
| 새 Oracle 집중 시험 | 31 passed / 5 failed, 기대값 변경 없음 |
| 새 부모/자식 경계 단위 시험 | 9 passed, 전체에도 포함 |
| Node.js 24 --check | 36개 사전 유효성 분류와 일치 |
| uv lock --check / CLI·scan·API --help | PASS / PASS |
| TypeScript / Vitest / production build | PASS / 219 passed / PASS |
| Chromium 전체 / WebKit | 56 passed / 3 passed |
| axe | 기존 Chromium 접근성 시험에 포함, 해당 시험 통과 |
| 일반·조사 Safari QA 실행기 | 7 passed / 6 passed |
| 실제 FastAPI–Semgrep–Chromium | 3 passed / 2 skipped, 23.5초 |
| frozen Oracle / 문서 링크 / 공백·민감정보 패턴 | 변경 없음 / PASS / PASS |

전체 Python의 제외 28개는 기존 명시적 opt-in Ollama 시험이다. 실제 브라우저의 제외 2개는 ER-D8/D9 전용 시나리오 선택 시험이다. 미실행을 통과로 집계하지 않는다. warning은 기존 Starlette TestClient anyio alias deprecation이며 수정하지 않았다.

전체 suite exit는 **1**이다. 782개 통과를 전체 PASS로 표현하지 않는다. 새 감사 assertion은 표준 test_ 파일로 기본 수집에 포함되므로 수정 전 원격 CI도 통과한다고 기대해서는 안 된다. 신규 원격 CI는 아직 실행되지 않았다.

실제 Safari 수동 검수·VoiceOver·iOS Safari·Linux 실행은 NOT_RUN 또는 NOT_VERIFIED다. 자동 WebKit PASS를 사용자 수용으로 바꾸지 않는다. 기존 ER 개별 실험 하네스 전체를 별도로 재실행한 것은 아니다.

## 실패 기록과 자료 보호

초기 전체 실행 명령에 디렉터리와 그 안의 명시적 파일을 함께 지정했을 때 실제 수집은 감사 36개뿐이었다. 이를 전체 회귀로 집계하지 않았다. 감사 파일을 표준 test_ 이름으로 두고 기본 수집 수를 확인한 뒤 전체 suite를 다시 실행했다. 5개 실패는 일반 pytest와 향후 CI에서도 드러나며, 기존 CI assertion·정책을 약화하지 않았다.

이번 신규 Oracle의 첫 실행부터 A16–A20의 5개 불일치를 관찰했고, 명시적 pytest에서도 동일한 5개 assertion이 실패했다. Oracle 수정 이력은 없다. 과거 callback 재현은 한 번 SIGSEGV로 종료됐으며 성공 분석으로 집계하지 않는다. 메모리 제한의 미적용을 성공으로 바꾸지 않았다. 새 경계 하네스가 통과했다는 사실도 엔진의 의미 정확성이나 완전한 sandbox 성공을 뜻하지 않는다.

모든 추가 자료는 합성 코드다. 응답 projection은 닫힌 상태·진단·byte 범위·자원 설정·exit/signal·부모의 수집량만 보존한다. raw stdout/stderr, 내부 Handle, 실제 사용자 소스, Token, 절대 사용자 경로, 제품 Manifest/Registry payload를 공개 파일에 저장하지 않았다. 상대 링크·민감정보 패턴·git diff --check와 staged 검사를 수행한다.

브라우저가 생성한 이 격리 Worktree의 추적 화면 자료만 기존 커밋 내용으로 돌려 변경에서 제외했다. 미추적 캡처는 보존하고 Stage하지 않는다. 기존 engine·tests의 assertion·Semgrep/Tree-sitter 제품 경로·API·CLI·UI·규칙·CI·lockfile은 수정하지 않는다.

## 종료 결정

**IND_1A_HOLD**. 감사 자료를 완성하고 로컬 커밋하더라도 엔진 수용 GO가 아니다. 확인된 정적 계약 결함과 강제 메모리·권한 경계를 해결한 뒤 별도 수정 Phase에서 다시 검증해야 한다. 새 원격 CI는 PENDING_USER_PUSH이며 Push·PR Merge는 수행하지 않는다.

로컬 커밋의 대상은 검증이 끝난 감사·재현 자료뿐이다. 엔진 수정은 포함하지 않으며, 알려진 assertion 5개가 실패하는 상태를 명시적으로 보존한다. 이 감사 커밋을 통과한 제품 수정 또는 main 병합 가능 상태로 취급하지 않는다. 부모는 감사 기준 SHA를 유지한다.
