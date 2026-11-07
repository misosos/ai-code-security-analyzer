# IND-1 동일 합성 입력 비교

## 실험 조건

대상은 [고정 manifest](../tests/fixtures/independent_engine_phase1/manifest.json)의 합성 개발 fixture 16개다. 기대값은 독립 엔진의 지원 구조와 상태에 대해 사전에 고정했다. 취약점의 독립적인 정답 집합이나 미사용 holdout이 아니다. 소스를 실행하지 않고 같은 바이트를 독립 엔진과 Semgrep baseline에 제공했다. 입력 불변성은 메모리의 원본 바이트와 비교하고 임시 사본을 정리한다. 외부 저장소나 원본 사용자 소스를 사용하지 않는다.

Python 3.12.7, Tree-sitter 0.26.0, grammar 0.25.0, Semgrep OSS 1.182.1을 사용했다. [비교 스크립트](../scripts/evaluate_independent_engine_phase1.py)의 `--semgrep`만 기존 Adapter를 명시적으로 호출한다. 독립 엔진의 Semgrep 비의존성은 PATH 비우기 및 subprocess·파일 open·socket 금지 시험으로 따로 확인한다.

15개의 파싱 가능한 fixture를 한 batch로 검사하고 문법 오류 1개는 다른 batch로 분리했다. Semgrep의 status는 batch 전체의 상태이며 개별 파일이 모든 규칙에서 완료됐다는 증거로 사용하지 않는다. 전체 trusted baseline을 실행했지만 아래 관찰은 모두 `baseline.javascript-dynamic-eval`의 결과다. React/Firestore·TypeScript 범위의 우열을 평가하지 않았다.

## 실제 관찰

독립 엔진 관찰 수는 `eval`의 제한된 binding 구조 수다. Semgrep 수는 baseline의 문법 패턴 매치 수다. 서로 다른 질문이므로 건수를 취약점 수나 정확도 점수로 비교하지 않는다.

| 입력 | 독립 엔진 상태·관찰 | Semgrep 매치 | 해석 |
| --- | --- | --- | --- |
| direct.js | ANALYZED / 직접 1 | 1 | 기본 직접 호출 구조 |
| alias.js | ANALYZED / 별칭 1 | 0 | 선언과 같은 함수·블록의 단순 별칭 연결 추가 |
| text.js | ANALYZED / 0 | 0 | 문자열·주석을 호출로 보지 않음 |
| parameter_shadow.js | ANALYZED / 0 | 1 | 지역 매개변수 eval을 전역 참조로 분류하지 않음 |
| function_shadow.js | ANALYZED / 0 | 1 | 지역 함수 eval을 전역 참조로 분류하지 않음 |
| block_shadow.js | ANALYZED / 바깥 직접 1 | 2 | 안쪽 shadow와 바깥 global 참조 구조 구분 |
| reassigned.js | PARTIAL / 0 | 0 | 재할당된 별칭 판단 보류 |
| captured_write.js | PARTIAL / 0 | 0 | closure 쓰기로 별칭 판단 보류 |
| cross_function.js | PARTIAL / 0 | 0 | 함수 경계 별칭 미지원 |
| branch_alias.js | PARTIAL / 0 | 0 | 블록 사이 조건부 전달 미지원 |
| alias_chain.js | PARTIAL / 0 | 0 | 별칭 체인 미지원 |
| optional.js | PARTIAL / 0 | 1 | optional eval 호출은 최소 범위 밖 |
| indirect.js | PARTIAL / 0 | 0 | comma를 통한 간접 호출 미지원 |
| constructor.js | PARTIAL / 0 | 1 | new Function은 baseline 범위이며 IND-1 밖 |
| escaped_identifier.js | PARTIAL / 0 | 1 | escaped identifier를 보수적으로 보류 |
| syntax_error.js | PARSE_ERROR / 0 | 0, batch PARTIAL | 검사 실패·불완전성을 정상 0건으로 승격하지 않음 |

지역 이름도 보고한 Semgrep 결과를 실제 취약점 오탐으로 확정하지 않는다. baseline은 직접 구문 패턴을 보고하는 계약이고, 독립 엔진은 제한된 binding 구분을 추가했다. 반대로 IND-1이 보류한 optional·constructor 등의 차이를 Semgrep보다 더 안전한 분석이라고 주장하지 않는다. 문법 구조·관찰 위치를 비교했으며 취약점 FP/FN/정확도 지표는 산출하지 않았다.

## 반복·시간 측정

성공한 두 명령 실행에서 상태·분류·바이트 위치·진단·Semgrep 매치의 projection이 동일했다. 독립 엔진은 합계 직접 2건·별칭 1건이며, 6개 입력 ANALYZED / 9개 PARTIAL / 1개 PARSE_ERROR였다. Semgrep 정상 batch는 completed / 8 matches, 문법 오류 batch는 partial / 0 matches와 `semgrep_reported_errors`였다.

| 참고 측정 | 성공 실행 1 | 성공 실행 2 |
| --- | --- | --- |
| 독립 엔진 16개 입력 함수 호출 합계 | 1.498 ms | 1.462 ms |
| Semgrep 정상 batch, Adapter 전체 호출 | 7028.917 ms | 3421.975 ms |
| Semgrep 오류 batch, Adapter 전체 호출 | 3126.276 ms | 3354.751 ms |

독립 측정은 import된 모듈에서 함수 호출을 합산한다. Semgrep은 버전·도움말 probe, 별도 프로세스와 여러 baseline 규칙 비용을 포함한다. 경계·규칙 범위가 다르고 배경 부하·warm cache를 통제하지 않았으며 n=2다. 성능 개선율이나 실무 조사 시간 단축, 독립 엔진의 우월성을 주장하지 않는다.

최초 비교 실행은 exit 1 / `ind1_experiment_failed`로 실패했다. 당시 고정 오류가 단계별로 구분되지 않아 원인은 `NOT_DIAGNOSED`로 남긴다. 실패를 위 성공 2회에 포함하지 않았다. 이후 스크립트는 허용된 고정 실패 코드만 구분하도록 개선했으며 raw 예외·stderr·경로를 출력하지 않는다. 별도의 초기 native callback 충돌과 대응은 [구현 기록](independent-engine-phase1.md)에 보존한다.

## 남은 확인

실제 악용 가능성·전체 Source→Sink·다른 파일·런타임 intrinsic identity는 미검증이다. 재할당 이전에 실제로 유효했던 별칭도 전역 쓰기 수집으로 보류할 수 있다. 미해결 일반 함수 호출은 PARTIAL 진단을 늘릴 수 있다. 새로운 미사용 사례와 범위를 확대한 검증 없이 지원 구문을 넓히지 않는다. 외부 비신뢰 입력을 운영 API로 받기 전에는 네이티브 parser 격리와 강제 시간·메모리 제한을 별도 Gate로 검증해야 한다.
