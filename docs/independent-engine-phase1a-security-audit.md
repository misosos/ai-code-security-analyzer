# IND-1A 독립 AST 엔진 보안 감사

## 판정과 신뢰 경계

**`IND_1A_HOLD`**. 신규 Oracle 36개 중 5개에서 문서상 보수적 binding·scope 계약과 구현 결과가 달랐다. 기존 62개 단위 시험과 16개 비교 fixture의 통과는 재확인했지만 이 결함을 배제하지 못했다. 네이티브 parser를 제품 프로세스 안에서 호출하는 현재 엔진에는 강제 메모리·권한 격리도 없다. 제품 연결, 엔진 교체, PR Merge를 승인하지 않는다.

감사 대상은 `d00344520eaf894189908cb7927112ce2ecd218d`의 [independent_eval.py](../src/ai_code_security_analyzer/research/independent_eval.py), 기존 단위 시험·16개 fixture, 비교 스크립트와 IND-1 문서다. 공격자는 향후 검사 대상으로 제공될 JavaScript 바이트를 통제한다고 가정한다. 보호 대상은 분석기 가용성, 구조적 관찰의 정확성, 원문·자격정보의 비노출이다. 현재 연구 모듈은 공개 API·CLI·UI에 연결되지 않았으므로 아래 문제를 기존 제품에 도달 가능한 원격 취약점으로 주장하지 않는다.

기존 SemgrepAdapter는 외부 프로세스·출력 상한·timeout을 사용한다. IND-1은 Python 프로세스 안에서 native Tree-sitter를 직접 호출한다. 기존 expanded_code_context와 evidence_candidates는 Finding 보조 문맥용 bytes 파싱이며 독립 탐지가 아니다. 다른 Tree-sitter 경로 전체의 보안성을 이번 제한된 감사로 승인하지 않는다.

## 방법과 독립성 한계

[새 Oracle](../tests/fixtures/independent_engine_phase1a/oracle.json)은 엔진 실행 전에 작성하고 [체크섬](../tests/fixtures/independent_engine_phase1a/oracle.sha256)으로 고정했다. 코드의 선언·참조 관계, 상태·관찰·필수 진단, 지원 여부, ECMAScript 유효성, 판단 근거, 취약점 미검증을 사례마다 포함한다. 실제 출력은 [별도 관찰 기록](independent-engine-phase1a-observations.json)에 보존한다. Oracle은 실행 후 변경하지 않았다.

동일 에이전트가 IND-1 작성에 참여했으므로 독립된 사람·팀의 감사나 blind holdout은 아니다. 기존 코드에 대한 적대적 검토, 실행 전 Oracle 고정, ECMAScript 규격 대조, 별도 Node.js 24 `--check` 문법 검증을 다른 검토 관점으로 사용했다. Node 검증은 36개 모두 사전 유효성 분류와 일치했지만 binding Oracle의 독립적 증명이나 취약점 정답 자료는 아니다. JavaScript는 실행하지 않았다.

31개 일치·5개 불일치는 이 합성 구조 계약의 결과다. 취약점 Precision/Recall, 일반화 정확도, 실제 공격 가능성을 측정한 값이 아니다. 기존 사례와 일부 구조군은 겹치며 새로운 사례가 모두 새로운 언어 기능인 것은 아니다.

기존 비교 스크립트는 독립 엔진의 fixture 기대값과 Semgrep 버전·완료/부분 상태를 검사하지만 Semgrep 파일별 매치 수 전체를 고정 Oracle로 assert하지 않는다. 따라서 스크립트 exit 0만으로 과거 비교표의 모든 숫자가 검증됐다고 볼 수 없다. 이번 감사는 실제 생성된 파일별 projection과 문서 표를 별도로 대조했다.

## 확인된 결함

### IND1A-01 — 괄호로 감싼 쓰기 target 누락

- 유형·심각도: 정적 binding 오분류 / **중간**, 재현 근거 높음. 제품 미연결로 현재 외부 노출 영향은 제한됨.
- 위치: `_pattern_names()` 및 `analyze_javascript()`의 assignment/for-in 쓰기 수집(기준 코드 138, 309–320행), 별칭 판정의 `binding.written` 검사.
- 전제: 선언된 별칭 또는 전역 eval에 괄호 target으로 쓴 뒤 호출한다.

```javascript
let dispatch = eval; (dispatch) = other; dispatch(input);
```

실제 A16은 `ANALYZED`, `SIMPLE_ALIAS_CALL`, 진단 없음이었다. A17의 `for ((dispatch) of replacements) {}`도 동일하게 재할당을 놓쳤다. A18의 `(eval) = replacement; eval(input);`는 `ANALYZED` / `DIRECT_CALL`이었다. 사전 기대는 모두 `PARTIAL`, 관찰 없음, 별칭은 `BINDING_REASSIGNED`, 전역 쓰기는 `DYNAMIC_BINDING`이다.

`_pattern_names()`는 identifier·구조 분해 pattern만 처리하고 parenthesized_expression을 풀지 않는다. 따라서 쓰기 목록이 비어 `written`이나 전역 barrier가 설정되지 않는다. 괄호는 같은 대입 참조를 가리키는데 선언 시점의 관계가 현재 호출의 근거처럼 남는다. 이는 취약점 확정 오탐이라는 뜻이 아니라 **보고한 별칭의 정적 쓰기 근거가 틀린 사례**다.

기존 시험에는 identifier 대입·array pattern·update는 있었지만 괄호 assignment/for-of target이 없었다. 수정 방향은 binding 선언 순회와 쓰기 target 순회를 분리하고, 괄호 target을 제한적으로 정규화한 뒤 같은 binding의 쓰기와 전역 변경을 무효화하는 것이다. 결과 v1 필드를 추가할 필요는 없어 보이나 기존 관찰·상태가 달라지므로 후속 수정 Phase에서 계약·회귀를 검토해야 한다.

### IND1A-02 — 구조 분해 내부 member 쓰기가 barrier를 우회

- 유형·심각도: 보수적 동적 변경 처리 누락 / **중간**, 재현 근거 높음.
- 위치: `_pattern_names()`의 pair_pattern 처리와 `analyze_javascript()` 314–323행의 최상위 `left.type` 검사.
- 전제·최소 입력:

```javascript
({value: globalThis.eval} = replacement); eval(input);
```

A19는 `ANALYZED` / `DIRECT_CALL`, 진단 없음이었다. 사전 기대는 `PARTIAL`, 관찰 없음, `DYNAMIC_BINDING`이다. object_pattern 내부의 member_expression은 binding 이름으로 yield되지 않고 최상위 left도 member가 아니어서 두 검사에서 모두 빠진다. 구체적 런타임 전역 객체 identity는 여전히 미검증이지만, 문서가 약속한 **member 쓰기 발견 시 파일 전체 보류**조차 지켜지지 않았다.

기존 시험은 `globalThis.eval = ...`와 `delete globalThis.eval`의 최상위 형태만 확인했다. 수정 방향은 구조 분해의 target을 재귀적으로 검사해 member/subscript 쓰기를 제한적으로 보류하고, 객체 프로퍼티 키·기본값 표현식과 target을 구분하는 것이다. 문서상 지원을 넓히는 작업이 아니며 기존 보수적 정책의 적용 누락을 고쳐야 한다. 공개 제품 계약은 바꾸지 않는다.

### IND1A-03 — switch CaseBlock binding이 discriminant에 잘못 적용됨

- 유형·심각도: lexical scope 경계 오류·직접 호출 누락 / **중간**, 재현 근거 높음.
- 위치: `_SCOPES`의 switch_statement(135행), 전체 switch를 새 scope로 등록하는 266–275행.

```javascript
switch (eval(input)) { case 0: let eval = other; }
```

A20의 실제 결과는 `ANALYZED`, 관찰 없음, `LOCAL_EVAL_SHADOW`였다. 기대는 전역 이름 참조 구조의 `DIRECT_CALL` 1건이다. 규격은 discriminant를 먼저 평가하고 그 뒤 CaseBlock lexical environment를 생성한다. 구현은 switch 전체에 하나의 scope를 두어 CaseBlock의 let을 discriminant까지 전파했다. 이 순서는 [ECMAScript SwitchStatement Evaluation](https://tc39.es/ecma262/multipage/ecmascript-language-statements-and-declarations.html#sec-switch-statement-runtime-semantics-evaluation)에 근거한다.

대조 사례 A21은 `case eval(input): let eval = ...`의 TDZ shadow를 올바르게 보류했다. A22는 중첩 block 안의 let과 discriminant를 구분했다. 기존 시험에는 이 세 범위를 나눠 확인하는 사례가 없었다. 수정 방향은 switch discriminant와 CaseBlock의 환경을 분리하는 것이다. 분석 한계를 이유로 switch 전체를 미지원으로 돌리는 대안도 명시적 계약 결정이 필요하며, 현재 `ANALYZED` 누락을 그대로 유지해서는 안 된다.

### IND1A-04 — native parser 장애의 제품 프로세스 전파를 막는 경계 부재

- 유형·심각도: 가용성·실행 신뢰 경계 / **높음(비신뢰 입력을 제품 프로세스에 연결할 경우)**.
- 근거 수준: 현재 함수가 in-process라는 사실과 격리 미구현은 확인됨. 과거 callback의 SIGSEGV는 별도 자식에서 재현함. **현재 callback 없는 엔진 경로의 새 SIGSEGV는 재현하지 않았음**.
- 위치: `analyze_javascript()` 186–217행의 예산·parse·파싱 후 AST 제한, 마지막 `except Exception`.

0.2초 시계는 입력 callback·Python 순회가 다시 실행될 때만 검사한다. parser가 native 내부에서 메모리를 쓰거나 멈추면 강제 종료하지 못하며, 깊이·node 제한은 AST 생성 후 적용된다. SIGSEGV·SIGKILL·OS OOM 종료를 Python `except Exception`으로 정상 복구할 수 있다고 볼 수 없다.

새 시험에서 과거 callback은 SIGSEGV 11, 연구용 부모의 C 대기 timeout은 SIGKILL 9로 구분했고 자식을 reap했다. macOS의 메모리 제한 설정은 실패했으며 128 MiB 추가 할당이 가능했다. Worker는 파일 읽기와 loopback bind도 할 수 있었다. 자세한 보호 범위와 미강제 영역은 [격리 검증](independent-engine-phase1a-isolation-validation.md)을 따른다.

기존 시험의 fake clock·AST 크기 검사는 협력적 분기만 증명했다. 프로세스 장애 전파·native 중단·OS 자원 강제를 확인하는 시험은 아니었다. 수정 방향은 제품에 연결하기 전에 별도 프로세스, 부모 종료·reap, OS별 검증된 메모리·권한 제한, 제한된 응답 검증을 별도 Phase에서 설계하는 것이다. 이번 연구 하네스를 운영 보안 Worker로 승격하지 않는다.

## 결함과 구별할 한계

- 별칭 체인·함수 간 별칭·optional/member/computed/tagged-template 호출, Function constructor, 복잡한 매개변수는 문서화된 미지원 또는 제한이다. 전체 데이터 흐름·CFG·SSA·파일 간 추적을 구현했다고 볼 수 없다.
- 재할당이 호출 뒤에 있거나 중복 var 선언이 값에 영향을 주지 않아도 보류할 수 있다. 이는 기존 계약의 의도적인 구조적 미탐 가능성이다.
- A35의 top-level break와 A36의 중복 let은 Node 문법 검사에서 거부됐다. Tree-sitter의 `has_error`는 JavaScript early error 검증과 다르다. 엔진은 각각 ANALYZED/별칭, PARTIAL/AMBIGUOUS_BINDING을 반환했다. 기존 문서에 이미 이 한계가 있으므로 별도 새 취약점으로 집계하지 않는다. ANALYZED를 실행 유효·안전으로 읽는 제품 계약은 금지해야 한다.
- 별칭 eval 호출은 직접 eval과 같은 런타임 scope 의미를 보장하지 않는다. DIRECT_CALL도 전역 intrinsic 객체 동일성, 실제 실행 또는 취약점의 증명이 아니다.
- 결과에 원문·인자·식별자·자유형 parser 예외가 자동 포함되지 않는 점은 확인했다. 상대 라벨 자체의 민감성은 호출자가 통제해야 한다. 모든 정보 유출 경로나 native 메모리 안전성을 감사한 것은 아니다.

## 다음 Phase 우선순위

1. 괄호·구조 분해 target과 switch 환경의 재현 5개를 유지한 채 최소 수정. Oracle 기대를 결과에 맞춰 변경하지 않는다.
2. 네이티브 프로세스 경계를 먼저 검증하고 실제 배포 OS의 메모리·권한 제한을 challenge 시험으로 입증한다. 적용 실패는 정상 분석으로 승격하지 않는다.
3. early error/미지원 상태의 소비 계약, 직접·별칭 호출 의미, 추가 미사용 corpus를 검토한다.
4. 이후에도 별도 공개 계약·제품 호환성 승인이 있어야 연결을 검토할 수 있다.

엔진·기존 assertion·제품 코드는 수정하지 않았다. 감사 자료의 로컬 커밋은 결함 수정이나 IND-1의 GO 재승인이 아니다. 전체 실행 결과·실패한 감사 assertion·원격 CI 경계는 [검증 기록](independent-engine-phase1a-validation-record.md)에 함께 기록한다.
