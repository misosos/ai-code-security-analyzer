# Phase 6B — Firestore multi-operation rule hardening

## 목표 및 판정 범위

Phase 6A의 `F02_nested_write` 미탐을 수정하기 위해 `baseline.firestore-unconditional-write`의 정규식만 확장했다. 평가 대상은 `firestore.rules`에 적힌 정적 선언 신호다. Finding은 계속 `unverified`이며, 이 결과만으로 실제 배포 데이터베이스의 권한 취약성이나 접근 가능성을 확인하지 않는다.

Firebase 문서는 `read`가 `get`/`list`로, `write`가 `create`/`update`/`delete`로 분리될 수 있음을 설명한다. 조건식은 각 `allow` 작업의 허용 조건으로 동작한다. 이번 규칙은 이 작업 이름을 전체 토큰으로 인식하고 그중 쓰기 작업이 하나 이상이며 조건이 정확히 리터럴 `if true;`인 같은 줄 선언을 찾도록 했다. [Firestore 규칙 구조](https://firebase.google.com/docs/firestore/enterprise/security/rules-structure), [Security Rules 언어](https://firebase.google.com/docs/rules/rules-language).

## 변경

- Rule ID, severity `ERROR`, CWE-284, `firestore.rules` 경로 제한 유지
- 기존 단일 `write/create/update/delete`와 `read, write` 유지
- 추가: 읽기·쓰기 작업 조합, 여러 쓰기 작업, 작업 순서 변형 및 공백/탭 변화
- 읽기 전용 `read/get/list` 목록은 탐지하지 않음
- 조건은 여전히 정확한 `if true;`만 대상. `false`, 인증식, 함수 호출, 복합식은 제외
- 파일명 범위, Finding 모델/ID 계약, CLI/API/UI, Gate 및 TaintEvidence는 변경하지 않음

정규식은 작업 목록을 명시적 토큰으로 반복하고, 목록 앞부분은 작업명 구분자로만 소비한 뒤 필수 쓰기 토큰을 요구한다. 접두 부분 문자열이나 임의 문맥에서 `create`/`update` 문자열만 찾지 않는다. 자체 Firestore 파서는 추가하지 않았다.

규칙 SHA-256:

| 시점 | `rules/security-baseline.yml` SHA-256 |
| --- | --- |
| 변경 전 | `5b1f793d6e3eef1ff7bfbc98028dcc3680656661cd3664e9a3266b905f5f22c9` |
| 변경 후 | `bfeb93c42ad942fda138dff3a9be8f4ccc1b137a2b547b6b29b65d98fc70a1a3` |

Phase 6A manifest와 oracle은 그대로 보존했다.

- `phase6a-synthetic-v1` manifest SHA-256: `954f9e33359bdcd478a6edbdcc83b9aa8cb962c01e7e90c5b6f60ef1b2c23c53`
- `phase6a-synthetic-v1` oracle SHA-256: `d5c10325bb0ce38f9187739afb704287de1cdbab94e879d57ade152eb05e1747`

## 평가 방법

신규 hardening 집합은 규칙을 실행하기 전에 직접 작성해 고정했다. 27개 사례의 버전은 `firestore-hardening-v1`이며 manifest/oracle의 SHA-256은 각각 `19cfb57a0ce60b0efad6b94609d07e19a37878d85f4e4480d98e0090b63170d8`, `37cfcd625d6d3e4029474f61809afc04e13a350e8254cd0572fca8dfd0eaba18`다.

- positive 13: 단일 쓰기 권한, 복수 쓰기 권한, 읽기·쓰기 혼합, 작업 순서/공백 변형, 동일 파일 내 독립 선언 2개
- negative 14: 공개 읽기 전용, false/인증/함수/복합 조건, 행 주석, 문자열, `firestore.rules`가 아닌 파일, 유사 권한명, 다중 행 블록 주석 탐색
- 규칙 실행을 통한 사례 코드 실행은 없음

변경 전 점수는 동일한 신규 사례에 이전 규칙을 실행해 측정했다. Phase 6A Oracle은 재라벨링하지 않았다.

## 결과

Semgrep OSS 1.182.1에서 변경 전후 모두 `completed`, exit code 0으로 실행됐다. 지표는 사례 단위다. P13은 한 파일에 두 선언이 있어 매치 기대 수는 2건이며, 사례 기준 TP는 1건이다.

| 집합/시점 | TP | FP | FN | TN | Precision | Recall | FPR | 중복 Finding | 위치 불일치 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 신규 hardening, 변경 전 | 6 | 1 | 7 | 13 | 0.857 | 0.462 | 0.071 | 0 | 8 |
| 신규 hardening, 변경 후 | 13 | 1 | 0 | 13 | 0.929 | 1.000 | 0.071 | 0 | 1 |
| Phase 6A Firestore, 변경 전 | 4 | 0 | 1 | 5 | 1.000 | 0.800 | 0.000 | 0 | 1 |
| Phase 6A Firestore, 변경 후 | 5 | 0 | 0 | 5 | 1.000 | 1.000 | 0.000 | 0 | 0 |

신규 집합에서 변경 전에는 8개의 실제 Finding(positive 선언 매치 7개와 FP 1개)이 나왔다. 변경 후에는 positive 선언 매치 14개와 같은 FP 1개, 총 15개 Finding이 나왔다. 중복은 없었다. `F02_nested_write`를 포함한 7개의 신규 positive 사례가 개선되어 FN이 0이 됐다.

### 오탐 및 잔여 한계

- `N14_multiline_block_comment`: 블록 주석 내부 `allow write: if true;` 모양의 행을 regex 엔진이 line 5에서 매치했다. 이는 변경 전에도 존재한 FP이며 변경으로 늘지 않았다. 이 사례는 정규식이 Firestore 문법/주석 파서를 대체할 수 없음을 보여준다. 이 Phase에서는 자체 파서나 더 넓은 규칙을 추가하지 않았다.
- 나머지 13개 negative(읽기 전용 포함)는 매치되지 않았다.
- `N12_other_filename`은 `notes.txt`라 파일명 경계에서 제외됐다.
- P13에서 서로 다른 두 선언은 각각 한 Finding으로 보고됐고 Finding ID도 서로 달랐다.
- 오탐 0건인 기존 Phase 6A 평가만으로 실제 프로젝트의 오탐률을 추정할 수 없다.

## 교차 규칙 및 기존 동작

Phase 6A evaluator 재실행 결과:

| Rule ID | 변경 전 TP/FP/FN/TN | 변경 후 TP/FP/FN/TN |
| --- | --- | --- |
| `baseline.firestore-unconditional-write` | 4 / 0 / 1 / 5 | 5 / 0 / 0 / 5 |
| `baseline.javascript-dynamic-eval` | 5 / 0 / 0 / 5 | 5 / 0 / 0 / 5 |
| `baseline.react-dangerous-html` | 5 / 0 / 0 / 5 | 5 / 0 / 0 / 5 |
| `experimental.javascript-eval-taint` | 5 / 0 / 0 / 5 | 5 / 0 / 0 / 5 |
| `experimental.javascript-eval-taint-with-synthetic-sanitizer` | 4 / 0 / 0 / 6 | 4 / 0 / 0 / 6 |
| `experimental.javascript-command-injection-taint` | 4 / 0 / 0 / 6 | 4 / 0 / 0 / 6 |

평가 점수 밖의 알려진 교차 범주 Finding은 전후 11건으로 유지됐다. baseline 프로필의 eval-taint 파일 9건과 eval-taint 프로필의 E02 2건이다. 이들은 점수에 TN/FP로 섞이지 않고 `unscored_out_of_scope_findings`로 남는다. baseline 프로필의 전체 Finding은 23건에서 Firestore F02 한 건이 더해져 24건이 됐다. 다른 프로필은 변화가 없다.

Firestore Finding은 기존 `unverified`, severity `high`, CWE-284, 동일 Rule ID 및 Finding ID 계산 계약을 유지한다. 이 수정은 정적 신호를 추가할 뿐 실제 배포 설정, 중첩 `match`의 유효 범위, 다른 규칙 파일의 결합, Firebase 프로젝트 배포 여부를 확인하지 않는다. Firebase 문서는 Security Rules가 적용되는 경로 구조와 조건을 설명하며, 실제 효과를 확인하려면 전체 규칙 및 배포 상태를 봐야 한다. [Firebase 규칙 언어](https://firebase.google.com/docs/rules/rules-language).

## 검증 및 범위

`tests/test_firestore_rule_hardening.py`는 사전 고정 oracle, 13개 positive, strict negative, Semgrep 버전/상태, Rule ID, severity/CWE, 상대 경로, 줄, Finding ID, 중복, canary 비노출을 확인한다. 기존 baseline과 Phase 6A benchmark도 유지한다. CI Semgrep job에 hardening 실통합 테스트를 추가했다.

실제 Firebase 배포나 Emulator 기반 권한 검증은 하지 않았다. 평가 집합은 규칙 수정에 사용된 합성 개발·회귀 데이터이며 독립적인 후속 성능 평가 집합이 아니다. Phase 6C에서는 규칙을 고정한 뒤 별도 미사용 사례 또는 승인된 실제 프로젝트 자료로 일반화 성능을 평가하는 것을 권고한다.
