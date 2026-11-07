# IND-1: 독립 JavaScript AST eval 조사 프로토타입

## 시작 기준과 격리

기준 SHA는 `9dffe82ddd50b86aa8b8f1041491a094bd1187f9`다. 작업 전 GitHub main과 origin/main이 일치했고, 해당 [push CI 42336284406](https://github.com/misosos/ai-code-security-analyzer/actions/runs/42336284406)은 completed / success, 필수 Python tests and CLI·React dashboard·Semgrep 1.182.1 integration Job 각각 success, Artifact 0개였다. 기존 ER-D10 Worktree는 추적 변경 없이 미추적 `.taste-skill/`을 보유했다.

별도 Worktree와 `research/independent-engine-phase1` 브랜치를 origin/main에서 생성했다. 기존 Desktop의 미커밋 변경, 다른 Worktree, 사용자 4173 서버는 보존한다. push는 수행하지 않는다.

## 기존 구현과 차이

기존 [SemgrepAdapter](../src/ai_code_security_analyzer/semgrep_adapter.py)는 신뢰된 로컬 규칙과 등록 대상에 대해 Semgrep을 실행하고, parser와 ScanService를 거쳐 Finding·공개 ScanResponse 및 조사 증거를 만든다. 기존 [expanded_code_context](../src/ai_code_security_analyzer/expanded_code_context.py)와 [evidence_candidates](../src/ai_code_security_analyzer/evidence_candidates.py)의 Tree-sitter는 이미 보고된 Finding 위치의 문맥·근거 후보를 보조한다. 새로운 독립 탐지와 역할이 다르므로 이 경로는 재사용하거나 변경하지 않았다.

[baseline 규칙](../rules/security-baseline.yml)은 JavaScript/TypeScript `eval(...)` 또는 `new Function(...)`, React 직접 HTML 삽입, Firestore 무조건 허용 쓰기를 포함한다. IND-1은 이 규칙 전체의 대체가 아니다. Phase 6D/6E의 별칭·constructor 범위 한계, 6H의 지역 binding·framework 문맥 한계 및 기존 Eval/Taint 합성 자료를 검토했다. 신규 엔진은 기존 Finding·Evidence·Manifest·Evaluation·Registry 형식에 연결하지 않는다.

## 연구용 내부 계약

[구현](../src/ai_code_security_analyzer/research/independent_eval.py)의 `analyze_javascript(bytes, relative_label)`은 제공된 바이트만 분석한다. 파일 열기, 디렉터리 탐색, Semgrep, 외부 명령, 네트워크, JavaScript 실행, 자동 수정은 없다. 기본 API·CLI·UI 또는 패키지의 기본 실행 경로에 등록하지 않았다. 기존 설치된 Tree-sitter 0.26.0 / JavaScript grammar 0.25.0을 사용하며 새 의존성이나 외부 구현 복사는 없다.

`independent-eval-research/v1`은 별도 내부 결과다.

- `DIRECT_CALL`: 로컬 선언에 가려지지 않은 identifier `eval`과 괄호 arguments의 호출 구조.
- `SIMPLE_ALIAS_CALL`: 단일 변수 선언의 initializer가 로컬에 가려지지 않은 identifier `eval`이고, 선언·호출이 같은 함수/프로그램 단위와 같은 직선 문장 블록에 있으며 선언이 먼저인 경우. 재선언·재할당이 없을 때만 보고한다.
- 근거는 호출·callee·함수 범위·별칭 선언·초기 eval 참조의 바이트 범위와 1부터 시작하는 행/UTF-8 바이트 열이다. 끝 바이트는 exclusive다. 별칭 이름이나 원문을 결과에 보존하지 않아, 승인된 소스와 위치를 별도로 대조해야 한다.
- 각 관찰의 `verification_status`는 항상 `UNVERIFIED`다. 이름의 정적 해석과 실제 런타임의 global eval 함수 객체 동일성은 다르다. 도달 가능성, 외부 입력, 악용 가능성, 실제 취약점은 판정하지 않는다.
- 결과 상태는 `ANALYZED`, `PARTIAL`, `PARSE_ERROR`, `RESOURCE_LIMIT`, `INVALID_INPUT`, `UNAVAILABLE`다. `ANALYZED`도 안전 판정이 아니다. 문법 오류·자원 실패·parser 불가는 구분하고, 자원 실패 시 앞서 얻은 관찰을 성공 결과로 반환하지 않는다.

## Binding과 보수적 경계

AST를 반복 순회하면서 먼저 모든 선언을 모은다. 함수·블록·catch·for·switch scope, 매개변수, var hoisting, let/const, 함수 이름, import의 로컬 이름을 구분한다. 뒤에 선언되는 eval과 TDZ 가능성도 로컬 shadow로 처리한다. 구조 분해의 프로퍼티 키를 로컬 binding으로 오인하지 않는다.

모든 assignment/update를 별도 수집해 바깥 별칭이 안쪽 closure에서 바뀌는 경우도 배제한다. 재할당이 호출 뒤에 있거나 조건부여도 해당 binding의 별칭 관찰을 보류한다. CFG/SSA로 실행 순서를 증명하지 않으므로 이는 의도적인 미탐 가능성이다.

함수 경계를 넘는 별칭, 별칭 체인, 선언 후 대입으로 얻은 별칭, 블록 사이의 조건부 전달, optional/indirect/member/tagged-template 호출은 지원하지 않는다. 별칭 `const run=eval; run(x)`은 lexical scope와 선언 순서에 대한 구조적 관찰이며, eval 내부의 동적 코드나 외부 함수가 환경을 바꾸지 않는다고 증명한 것은 아니다.

`with`, 전역 eval 대입, member 쓰기, escaped identifier를 만나면 파일 전체 관찰을 보류하는 보수적 barrier를 둔다. 클래스·JSX·복잡한 매개변수 표현식의 호출은 제외 범위를 명시하고, Annex B block 함수 binding도 모호하다고 기록한다. 일반 미해결 호출도 미지원 진단으로 남겨 `PARTIAL`이 될 수 있다. 완전한 JavaScript 모듈·의미 검증이나 범용 symbol resolver는 아니다. Tree-sitter의 문법 복구/early error 판단을 JavaScript 실행 유효성 검증으로 확대하지 않는다.

## 자원·프라이버시 경계

입력은 최대 131,072 bytes, named AST node 20,000개, 깊이 128, 관찰 64개, 진단 64개다. 상한은 호출자가 낮출 수 있지만 늘릴 수 없다. 0.2초의 협력적 예산을 입력 chunk 읽기와 Python 순회에서 검사한다. 제한된 입력의 grammar 파싱 후 AST 건수·깊이를 검사하므로 **네이티브 파싱 중의 강제 시간·메모리 상한이 아니다**. parser callback 사이 또는 네이티브 내부에서 오래 걸리는 경우를 강제 종료할 수 없다. 하드 RSS 상한과 별도 프로세스 격리는 제공하지 않는다. 외부 비신뢰 대상을 운영 API에 연결하기 전에는 별도 프로세스 격리 Gate가 필요하다.

정적 상대 파일 라벨만 허용하고 절대 경로·traversal·역슬래시를 거부한다. 호출자는 비밀정보 없는 라벨을 제공해야 한다. 결과에는 소스, 인자, 식별자 이름, Digest, 내부 Node ID, 자유형 parser 예외를 보존하지 않는다. 결과는 기존 Export나 공개 보고서에 자동 연결되지 않는다.

### 실제 네이티브 실패와 대응

개발 초기에 `Parser.parse(read_callback, progress_callback=...)`를 사용했다. 고정 환경 Python 3.12.7 / Tree-sitter 0.26.0 / JavaScript grammar 0.25.0에서 블록 shadowing을 포함한 짧은 합성 입력이 exit 139로 충돌했고, faulthandler는 parse 호출의 네이티브 segmentation fault를 보고했다. 처음 비교 루프와 별도 축소 재현에서 실패했으며 성공으로 집계하지 않았다. 세부 C 원인은 독립적으로 확정하지 않았다.

[고정 버전 바인딩 소스](https://github.com/tree-sitter/py-tree-sitter/blob/v0.26.0/tree_sitter/binding/parser.c)는 bytes 입력에서 progress callback을 무시하고 callable 입력에서 별도 경로로 실행함을 보여준다. 최종 구현은 충돌한 **progress callback을 사용하지 않고** 읽기 callback과 순회 시 예산을 검사한다. 현재 시험을 통과한 것을 Tree-sitter 자체의 메모리 안전성이나 모든 입력의 무충돌 증명으로 해석하지 않는다. 기존 제품의 Tree-sitter 호출 방식이나 의존성 버전을 바꾸지 않았다.

## 재현과 검증

```bash
uv sync --locked --group dev
uv run pytest -q tests/test_independent_eval_engine.py
uv run python scripts/evaluate_independent_engine_phase1.py
# 기존 Semgrep 비교는 연구자가 명시적으로 선택한 별도 측정이다.
uv run python scripts/evaluate_independent_engine_phase1.py --semgrep
```

[단위 시험](../tests/test_independent_eval_engine.py)은 합성 구문 oracle, 위치, shadowing, 재할당, 모호한 참조, 인코딩·경로, parser 실패, 자원 경계, 결정성, 외부 명령·파일 읽기·네트워크 없이 실행되는 것을 검증한다. 위험한 progress callback은 pytest에서 재실행하지 않고, 해당 인자가 전달되지 않음을 확인한다. 초기 깊이 fixture의 괄호 수 오류는 fixture를 균형 있게 생성하도록 수정했다. parser의 PARSE_ERROR 기대를 RESOURCE_LIMIT 성공으로 바꾸지 않았다.

실제 Semgrep 비교와 측정·실패 기록은 [비교 결과](independent-engine-phase1-comparison.md)를 따른다. 전체 회귀 결과와 로컬 판정은 아래에 기록한다.

### 회귀 재실행 명령

검증일은 2026-11-07이며 macOS Apple Silicon, Python 3.12.7, uv 0.11.26, Node.js 24.22.2를 사용했다. Python 전체 suite에는 실제 Semgrep Integration·Rule Bytes·Registry·API·Manifest·Evaluator 시험이 포함된다. 실제 Semgrep을 사용하는 무거운 suite를 반복 실행할 때는 병렬 부하를 피한다.

```bash
uv lock --check
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 PYTHONPATH=tests:. uv run pytest -q -rs
cd frontend
mise exec node@24 -- npm ci
mise exec node@24 -- npm run typecheck
mise exec node@24 -- npm test -- --reporter=dot
mise exec node@24 -- npm run build
BROWSER_TEST_PREVIEW_PORT=49701 CI=1 mise exec node@24 -- npm run test:browser
BROWSER_TEST_PREVIEW_PORT=49702 CI=1 mise exec node@24 -- npm run test:browser:webkit
mise exec node@24 -- npm run test:qa:safari
mise exec node@24 -- npm run test:qa:investigation:safari
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 mise exec node@24 -- npm run test:e2e:real
```

브라우저 suite는 테스트 전용 포트와 합성 Target을 사용한다. 실행기가 생성한 이 Worktree의 추적 화면 파일만 원래 내용으로 돌려 변경 대상에서 제외하고, 미추적 `.taste-skill/` 캡처는 보존한다. 사용자 서버와 기존 Worktree의 자료를 정리하지 않는다.

### 실제 결과

| 검증 | 이번 작업의 실행 결과 |
| --- | --- |
| IND-1 집중 단위 시험 | 62 passed, 전체 suite에도 포함 |
| Python 전체, 실제 Semgrep 필수 | 742 passed / 28 skipped / warning 1, 260.59초 |
| 실제 동일 fixture 비교 | Semgrep 1.182.1, 성공 2회 projection 일치; 초기 실패 1회는 별도 기록 |
| `uv lock --check` | PASS |
| 기존 기본·scan·API `--help` | PASS |
| Node.js 24 TypeScript / Vitest / build | PASS / 219 passed / PASS |
| Chromium 전체 | 56 passed, 기존 axe 검증 포함 |
| Playwright WebKit | 3 passed |
| 일반 Safari QA 실행기 자동 시험 | 7 passed |
| 조사 Safari QA 실행기 자동 시험 | 6 passed |
| 실제 FastAPI–Semgrep–Chromium | 3 passed / 2 skipped, 24.3초 |
| 문서 상대 링크·민감정보 패턴·공백 검사 | PASS |

Python의 28개 제외는 기존 명시적 opt-in Ollama 호출·진단·pilot 시험이다. 이 작업에서 활성화하지 않았고 통과로 집계하지 않는다. warning 1개는 기존 Starlette TestClient의 anyio alias deprecation이다. 실제 브라우저 E2E의 제외 2개는 ER-D8/D9 전용 시나리오 하네스가 선택하는 시험이다. 과거 ER 개별 연구 실험 하네스 전부를 별도로 재실행한 것은 아니다. 실제 Safari 사용자 수동 검수·VoiceOver·iOS Safari는 `NOT_RUN`이다.

기존 회귀 suite의 실패는 없었다. 신규 개발 과정의 callback 충돌, 잘못 구성한 깊이 fixture, 최초 비교 실패는 위 기록과 비교 문서에 구분해 남겼다. 기존 제품 테스트를 삭제·완화하거나 timeout을 늘리지 않았다.

결과에서 원문 canary·식별자 이름이 제외됨을 단위 시험으로 확인했다. 신규 파일의 토큰 형태·Bearer·사용자 절대 경로 패턴 검색과 문서 상대 링크 검사를 수행했다. 패턴 검색만으로 모든 민감정보 부재를 증명하지는 않으며, 실제 사용자 자료를 입력으로 사용하지 않았다.

## 로컬 결론과 다음 Gate

판정은 **`IND_1_INDEPENDENT_AST_ENGINE_LOCAL_CONDITIONAL_GO`**다. 합성 입력에서 직접 호출과 제한된 별칭의 정적 binding 근거를 Semgrep 실행 없이 구별하고, shadowing·불확실성·실패를 별도로 반환하는 연구용 최소 구현을 검증했다. 실제 취약점의 정확도, 모든 JavaScript 입력 지원, 네이티브 parser의 무충돌 또는 운영 사용을 승인하는 판정이 아니다.

변경은 신규 research 모듈, 단위 시험·합성 fixture, 독립 비교 스크립트, 이 문서와 비교 결과 문서에 한정된다. 기존 CLI·API·React·Finding·Evidence·규칙·GitHub Actions·의존성 lockfile은 수정하지 않았다. 기본 분석에 자동 연결하지 않았으므로 롤백은 신규 연구 경로를 사용하지 않는 것으로 가능하다.

후속 연구는 진행할 수 있다. 외부 비신뢰 입력이나 제품 경로와의 결합은 **보류**한다. 먼저 네이티브 parser를 별도 프로세스에서 강제 CPU·메모리·시간 제한하는 방안과 crash 입력의 안전한 재현을 검증하고, 미사용 shadowing·별칭 corpus로 구조적 오탐·미탐을 재평가해야 한다. 지원 범위 확대나 공개 계약 연결은 별도 승인과 호환성 Gate가 필요하다.

로컬 커밋의 부모는 시작 SHA를 유지한다. 신규 커밋에 대한 원격 CI는 `PENDING_USER_PUSH`이며 기준 SHA의 CI 결과로 대체하지 않는다. push는 수행하지 않는다.
