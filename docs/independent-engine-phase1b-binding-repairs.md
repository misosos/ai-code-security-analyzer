# IND-1B — AST binding 결함 최소 수정

## 판정 범위와 시작 Gate

대상은 `misosos/ai-code-security-analyzer`의 연구용 독립 AST 엔진이다. 감사 기준 `1e5a366c7fa3e084856b47a30d2918882fbc096e`는 로컬 커밋이며 부모 `d00344520eaf894189908cb7927112ce2ecd218d`와 연결됨을 확인했다. 감사 브랜치는 research/independent-engine-phase1a, 역사적 결과는 IND_1A_HOLD였다. 로컬 감사 커밋의 원격 존재를 요구하거나 과거 실패 기록을 폐기하지 않았다.

[PR #2](https://github.com/misosos/ai-code-security-analyzer/pull/2)는 OPEN·미병합이며 IND-1 SHA d003445를 가리켰다. [CI 42348300560](https://github.com/misosos/ai-code-security-analyzer/actions/runs/42348300560)은 해당 SHA의 pull_request 실행, completed/success, Python tests and CLI·React dashboard·Semgrep 1.182.1 integration 각각 success, Artifact 0개였다. **이 CI는 IND-1A 또는 IND-1B의 성공 CI가 아니다.**

추적 변경 없는 감사 Worktree와 미추적 캡처를 보존하고, 감사 커밋에서 `/tmp/ai-csa-independent-engine-phase1b`, research/independent-engine-phase1b를 생성했다. Desktop의 기존 추적 변경 6개·미추적 자료, 다른 Worktree, 사용자 4173 서버를 변경하지 않았다. 원격 main은 시작 시 9dffe82ddd50b86aa8b8f1041491a094bd1187f9였다.

## 수정 전 재현과 고정 Oracle

수정 전에 기존 audit 스크립트를 새 Worktree에서 실행해 **31 MATCH / 5 MISMATCH**를 재현했다. A16~A20만 선택한 기존 pytest도 **5 failed / 31 deselected**였다. 기존 [Oracle](../tests/fixtures/independent_engine_phase1a/oracle.json)의 기대값과 체크섬 `974d08fc3f8bd451405c365d49f919d0142886f289f4125f699179eba8344614`는 수정하지 않았다.

수정 전후 실제 결과를 [별도 관찰 기록](independent-engine-phase1b-observations.json)에 보존한다. IND-1A의 감사 보고서·실패 assertion·관찰 JSON·격리 실험·원래 16개 fixture 및 62개 시험은 변경하지 않는다. 새 기록의 after는 이 문서와 함께 저장된 IND-1B 패치가 적용된 상태를 뜻하며, 부모 SHA의 미수정 코드를 검사한 것으로 표현하지 않는다.

## 근본 원인과 코드 변경

변경한 실행 코드는 [independent_eval.py](../src/ai_code_security_analyzer/research/independent_eval.py) 하나다. 결과 Enum·필드·버전은 그대로다. 선언 수집·기존 callee/별칭 판정·자원 상한·네이티브 parse 호출은 변경하지 않는다.

| 결함 | 원인 | 최소 수정 |
| --- | --- | --- |
| IND1A-01 | 선언 이름 순회가 괄호 assignment target을 풀지 않아 written/barrier 미설정 | `_write_targets()`를 분리해 괄호를 풀고 기존 assignment/update/for-in·of/delete target에 적용 |
| IND1A-02 | object pattern 내부 member를 이름으로 yield하지 않고 최상위 left만 member 검사 | 중첩 배열·객체·rest·default target에서 identifier/member/subscript를 구분 |
| IND1A-03 | switch_statement 전체를 lexical scope로 간주 | CaseBlock에 대응하는 Tree-sitter `switch_body`에만 lexical scope 생성 |

### 쓰기 target의 한계

`_pattern_names()`는 선언 전용으로 유지한다. 새 순회는 기존 쓰기 경로의 LHS만 다룬다. 괄호 안 comment를 제외한 자식 하나를 풀고, pair pattern의 value와 assignment pattern의 left만 따라간다. 프로퍼티 키·기본값·일반 member 읽기는 쓰기로 취급하지 않는다. 그 표현식 안의 실제 assignment 노드는 기존 전체 AST 쓰기 수집에서 별도로 처리된다.

Identifier 쓰기는 해당 binding을 재할당 상태로 표시하고, 가려지지 않은 전역 eval 쓰기 또는 member/subscript 쓰기는 기존 DYNAMIC_BINDING barrier를 적용한다. 해석하지 못하는 쓰기 target은 기존 UNSUPPORTED_CONSTRUCT 및 PARTIAL로 보류한다. 이를 새로 지원하는 호출 대상으로 확장하지 않는다. 예를 들어 sequence LHS는 이번 환경에서 PARTIAL/UNSUPPORTED_CONSTRUCT였으며 정상 별칭 관찰을 반환하지 않았다. JavaScript early error를 일반적으로 검증하는 기능은 여전히 없다.

### switch의 의미상 환경

discriminant는 바깥 환경에서 평가하고 CaseBlock의 let/const는 case expression과 본문에만 적용한다. var는 기존 function_scope 수집을 유지하여 함수 수준 hoisting이 판별식에도 반영된다. 바깥 매개변수의 eval shadow도 그대로 적용된다. 단순히 모든 판별식을 전역 eval로 간주하는 우회는 없다.

이 구분은 [ECMAScript SwitchStatement Evaluation](https://tc39.es/ecma262/multipage/ecmascript-language-statements-and-declarations.html#sec-switch-statement-runtime-semantics-evaluation)에 근거한다. 구현·시험은 고정 Tree-sitter JavaScript grammar 0.25.0의 switch_body 구조를 사용한다. switch case 내부 별칭 호출의 기존 문장 블록 제한은 완화하지 않았다.

## 수정 전후 결과

| 사례 | 수정 전 | 수정 후 |
| --- | --- | --- |
| A16 `(dispatch)=other` | ANALYZED / SIMPLE_ALIAS_CALL | PARTIAL / 관찰 없음 / BINDING_REASSIGNED |
| A17 `for ((dispatch) of ...)` | ANALYZED / SIMPLE_ALIAS_CALL | PARTIAL / 관찰 없음 / BINDING_REASSIGNED |
| A18 `(eval)=replacement` | ANALYZED / DIRECT_CALL | PARTIAL / 관찰 없음 / DYNAMIC_BINDING |
| A19 구조 분해 내부 member 쓰기 | ANALYZED / DIRECT_CALL | PARTIAL / 관찰 없음 / DYNAMIC_BINDING |
| A20 switch 판별식 | ANALYZED / 관찰 없음 / LOCAL_EVAL_SHADOW | ANALYZED / DIRECT_CALL |

전체 고정 Oracle은 **36 MATCH / 0 MISMATCH**다. 나머지 31개의 status·관찰·byte 범위·진단·검증 상태 projection은 수정 전후 동일했다. 상태 분포는 수정 전 ANALYZED 19 / PARTIAL 16 / PARSE_ERROR 1, 수정 후 ANALYZED 15 / PARTIAL 20 / PARSE_ERROR 1이다. 모든 입력을 PARTIAL로 만드는 방식으로 통과시키지 않았다.

## 추가 회귀

[새 시험](../tests/test_ind1b_binding_repairs.py) 30개는 다음을 확인한다.

- 괄호·comment·증가·증강 대입·for-in 및 중첩/Rest identifier 쓰기.
- 중첩 object/array member, subscript, default/member, shorthand 전역 쓰기.
- computed key·default 값의 읽기, 구조 분해 선언, 다른 binding의 쓰기는 정상 직접/별칭 관찰을 과도하게 차단하지 않음.
- switch const TDZ, default의 TDZ, var hoisting, 바깥 parameter shadow, lexical 누출 방지, 중첩 switch·block 및 기존 별칭 미지원.
- 미지원 LHS의 보류, UTF-8 byte 위치, UNVERIFIED 및 기존 결과 버전·제한 유지.

28개 정상 구문 case는 Node.js 24 `--check`로 parse-only 확인했고 전부 허용됐다. 대상 JavaScript는 실행하지 않았다. 새 정상 구문 case의 분석은 기존 제한 자식 하네스로 수행한다. 추가 자료는 합성 회귀 자료이며 blind holdout·취약점 정답 집합이 아니다. 이번 검증 범위에서 새로운 미해결 정적 결함은 관찰하지 않았지만 일반적인 정확도 우월성이나 모든 JavaScript 지원을 주장하지 않는다.

## 실행 환경과 명령

2026-11-07, macOS Apple Silicon, Python 3.12.7, uv 0.11.26, Node.js 24, Semgrep OSS 1.182.1, Tree-sitter 0.26.0 / JavaScript grammar 0.25.0. 의존성이나 lockfile을 수정하지 않았다.

```bash
uv sync --locked --group dev
uv lock --check
# 패치 전 실행은 31/5, 패치 후 같은 명령은 36/0이었다.
uv run python scripts/audit_ind1a.py --suite oracle
uv run python -m pytest -q tests/research/ind1a/test_oracle_checks.py tests/test_independent_eval_engine.py tests/test_ind1b_binding_repairs.py tests/test_ind1a_isolation.py
uv run python scripts/evaluate_independent_engine_phase1.py --semgrep
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 PYTHONPATH=tests:. uv run python -m pytest -q -rs
```

frontend에서는 Node.js 24로 npm ci, typecheck, npm test, build, test:browser, test:browser:webkit, test:qa:safari, test:qa:investigation:safari, SEMGREP_REQUIRED=1 test:e2e:real을 실행한다. Chromium/WebKit preview는 49831/49832, 실제 E2E는 실행기가 할당한 고유 loopback 포트다. 사용자 4173 서버를 재사용하지 않는다. 실행기가 생성한 이 Worktree의 추적 화면 파일만 기존 커밋으로 돌리고 미추적 캡처는 보존한다.

## 검증 결과

| 검증 | 실제 결과 |
| --- | --- |
| 수정 전 A16~A20 | 5 failed / 31 deselected, 실패 기록 보존 |
| 수정 후 고정 Oracle | 36 passed / 36 MATCH, 기대값·체크섬 불변 |
| 기존 IND-1 시험 | 62 passed, 집중·전체 suite에 포함 |
| 새 IND-1B 회귀 | 30 passed, 집중·전체 suite에 포함 |
| 집중 시험 합계 | 137 passed, 기존 격리 하네스 9개 포함 |
| 전체 Python·실제 Semgrep 필수 | **817 passed / 28 skipped / 실패 0**, 246.50초 |
| 기존 16개 실제 Semgrep 비교 | 고정 기대 통과, 정상 batch completed/8건, 문법 오류 batch partial/0건 |
| TypeScript / Vitest / build | PASS / 219 passed / PASS |
| Chromium / WebKit | 56 passed / 3 passed |
| axe | 기존 Chromium 접근성 시험에 포함, 해당 시험 통과 |
| 일반·조사 Safari QA 실행기 | 7 passed / 6 passed |
| 실제 FastAPI–Semgrep–Chromium | 3 passed / 2 skipped, 23.5초 |
| uv lock --check / 기존 CLI·scan·API --help | PASS / PASS |
| 상대 링크·민감정보 패턴·공백 검사 | PASS |

전체 Python은 845개를 수집했다. 28개 제외는 기존 명시적 opt-in Ollama 시험이다. warning 1개는 기존 Starlette TestClient anyio alias deprecation이다. 실제 브라우저의 제외 2개는 ER-D8/D9 전용 시나리오 선택 시험이다. 미실행을 통과로 집계하지 않는다. 집중·전체 건수는 중복이 있으므로 합산하지 않는다.

계획된 수정 전 5개 실패 이후, 수정 후 검증에는 실패·재시도나 timeout 완화가 없었다. 기존 assertion·Oracle 기대값·CI 조건을 변경하거나 xfail/skip을 추가하지 않았다. 실행 시간은 참고 실행 기록이며 성능 향상 또는 분석가 업무 시간 개선의 증거가 아니다.

실제 Safari 수동 검수·VoiceOver·iOS Safari·Linux 강제 제한은 이번에 수행하지 않았다. 과거 ER 개별 연구 하네스 전부를 별도로 재실행한 것은 아니다. 원격 신규 CI는 PENDING_USER_PUSH이며 기준 PR의 성공 Run으로 대체하지 않는다.

## IND1A-04와 미지원 범위

- 네이티브 충돌 이력: **CONFIRMED**, IND-1A의 실제 재현 기록을 보존. 이번에는 위험한 progress_callback을 재실행하지 않음.
- 별도 자식 실패 격리: IND-1A의 제한된 실험 범위 유지. 기존 하네스 단위 시험은 운영 sandbox 승인이 아님.
- macOS 메모리 강제 제한: **NOT_ENFORCED**.
- 파일·네트워크 제한: **NOT_ENFORCED**.
- Linux 강제 제한: **NOT_VERIFIED**.
- 운영 제품 연결: **HOLD**.

협력적 시간·파싱 후 AST 상한은 native 강제 CPU/RSS 격리가 아니다. 런타임 intrinsic identity, 실제 취약점, Source→Sink, CFG/SSA·범용 Taint·파일 간 별칭·전체 early error 검증은 지원하지 않는다. 직접 eval과 별칭 eval의 런타임 scope 의미도 동일하다고 주장하지 않는다.

CLI·API·React·Finding·Evidence·Semgrep·제품 규칙·CI·의존성은 불변이다. 기존 감사 실패 기록을 성공으로 덮어쓰지 않고 별도 수정 결과를 추가했다. Source/Token/Handle/절대 사용자 경로를 새 결과에 보존하지 않는다.

## 종료 Gate와 후속 검증

**IND_1B_LOCAL_CONDITIONAL_GO** — 확인된 정적 계약 결함 IND1A-01~03의 연구용 최소 수정에 한정한다. 고정 Oracle 36개와 추가 회귀 30개, 기존 전체 회귀에서 미해결 실패가 없었다. IND-1A의 역사적 HOLD 및 native 격리 문제를 이 판정으로 지우거나 해결됐다고 표현하지 않는다.

로컬 커밋의 부모는 감사 커밋 1e5a366c7fa3e084856b47a30d2918882fbc096e다. 변경은 연구 엔진 1개와 새 회귀 시험·수정 문서·관찰 기록만 포함한다. 원격 CI 미실행과 IND1A-04를 고려해 제품 연결 및 운영 승인은 계속 HOLD다.

다음 단계는 검증된 native 실행 경계와 OS별 자원·권한 강제를 별도 설계하고, 더 독립적인 미사용 자료로 정적 분석을 검토하는 것이다. 제품 연결은 별도 호환성·보안 Gate가 필요하다. 롤백은 이번 연구 엔진 패치를 감사 부모 상태로 되돌리는 별도 변경으로 가능하며 제품 경로의 전환은 없다. Push와 PR Merge는 수행하지 않는다.
