# D1 — Finding 소실 실무 문제 검증: 사전 등록 프로토콜

상태: `PREREGISTERED` — 이 문서, `labels.json`, `build_cases.py`는 어떤 비교 Arm도 실행하기 전에 커밋한다. 커밋 이후 정답 라벨, 판정 규칙, 성공·실패 기준은 변경하지 않는다. 구현이 이 문서와 다르게 동작하는 결함만 수정할 수 있고, 모든 수정은 결과 문서의 "프로토콜 이탈" 절에 기록한다.

## 1. 질문과 가설

핵심 질문: Semgrep OSS + Git + 합리적으로 작성한 스크립트만으로 Finding 소실의 원인을 충분히 안전하게 조사할 수 있는가?

- **H1 (검증 대상)**: 기준선 스크립트(Arm B)는 사라진 Finding의 원인을 신뢰할 만하게 구분하지 못한다.
- **H0**: Arm B가 충분하다. 이 경우 별도 증거 관리 제품이 필요하다는 근거는 이 실험에서 나오지 않는다.

이 실험은 사람의 조사 시간이나 판단 정확도를 측정하지 않는다. 도구 출력 수준의 분류 정확성만 다룬다.

## 2. 실험 대상과 환경

- 기준 트리: `787798bf56a29e458e9ab246c985b00f213469b5` (원격 main `801f03b`와 트리 해시 동일, fetch 없음).
- Semgrep OSS CLI **1.182.1** 고정. 다른 버전이면 실행을 중단한다.
- 규칙: 저장소 `rules/security-baseline.yml`의 **사본**. 원본은 읽기만 한다.
- 대상 코드: `build_cases.py`가 만드는 합성 JavaScript와 임시 Git 저장소. 제3자 코드 없음.
- 사례 저장소는 세션 임시 디렉터리에 만들고, 워크트리에는 정제된 원시 결과만 저장한다.

## 3. 사례 (14개)

각 사례는 한 디렉터리를 `base` 상태에서 `cur` 상태로 제자리 변경한다. 모든 사례에 변경하지 않는 대조 Finding `src/stable.js:4`가 있다.

| 사례 | 발생시킨 변경 |
| --- | --- |
| A | 매치 줄의 `eval(input)`을 `JSON.parse(input)`으로 교체 |
| B | 매치 위에 주석 한 줄 추가 (매치 코드 동일) |
| C | `git mv`로 파일 이름 변경 (내용 동일) |
| Da | 한 파일의 동일한 위험 줄 2개 중 첫 함수를 삭제, 둘째가 위로 이동 |
| Db | 동일한 파일 2개 중 하나 삭제 |
| E | `.semgrepignore`에 대상 파일 추가 (코드 동일) |
| F | 대상 파일을 Git 인덱스에서 제거하고 `.gitignore`에 추가 (디스크에 그대로 존재) |
| G | 규칙 파일에서 해당 규칙 제거 |
| H | 같은 규칙 ID에서 `eval` 패턴만 제거 |
| Ia | 대상 파일 끝에 구문 오류 추가 (매치 줄 불변) |
| Ib | 규칙 파일을 잘못된 YAML로 만들어 현재 검사 실패 |
| J | `eval(input)`을 `globalThis.eval(input)`으로 변경 (규칙의 문서화된 미탐, 위험 유지) |
| Ka | A의 코드 변경 + E의 제외 정책 동시 적용 |
| Kb | J의 코드 변경 + E의 제외 정책 동시 적용 |

## 4. 독립 정답 라벨

`labels.json`. 라벨은 `build_cases.py`가 적용한 변경에서만 도출하며 어떤 Arm의 출력도 참조하지 않는다. 추적 대상 Finding마다 다음을 고정한다.

- `fate`: `PERSISTS`(같은 위험 코드가 검사·규칙 범위 안에 그대로 있음) 또는 `NOT_REPORTED`
- `causes`: 세부 원인 집합. 복수 원인 사례는 집합 전체가 정답이며 단일 정답을 강제하지 않는다.
- `dangerous_code_present_after`: 변경 후 디스크에 위험 코드가 남아 있는가
- `determinable`: Semgrep 출력 + Git + 규칙 파일만으로 원인 분류가 가능한가

세부 원인과 상위 분류: `CODE_CHANGED_AT_MATCH`·`FILE_DELETED` → CODE, `SCOPE_EXCLUDED` → SCOPE, `RULE_DISABLED`·`RULE_CHANGED` → RULE, `SCAN_INCOMPLETE` → SCAN.

**조건부 라벨 (F, Ia)**: Semgrep의 실제 동작을 사전에 단정하지 않는다. 6절의 기준 관찰에서 Finding이 기대 위치에 그대로 보고되면 `PERSISTS`, 아니면 `labels.json`의 `if_reference_absent` 값을 쓴다.

## 5. 비교 Arm

세 Arm은 같은 디렉터리의 같은 두 상태를 검사한다. Semgrep 공통 옵션: `--json --metrics=off --disable-version-check --oss-only --no-autofix`, 임시 `HOME`.

### Arm A — Semgrep OSS 기존 옵션 + Git 명령 (스크립트 없음)

기계적 대역 규칙:
1. 두 상태에서 `semgrep scan --json` 실행.
2. Finding 동일성은 `(check_id, path, start.line, start.col, end.line, end.col)` 완전 일치. OSS 출력의 `fingerprint`는 `requires login`이므로 사용할 수 없다.
3. 현재 검사의 종료 코드가 0이 아니거나 JSON이 유효하지 않으면 `NO_VALID_COMPARISON`.
4. 그 외에 기준 Finding이 현재에 없으면 `DISAPPEARED`, 원인 없음. Arm A는 원인을 분류하지 않는다.
5. 수정 완료를 주장하지 않는다.

추가 기록: 현재 상태에서 `semgrep scan --json --baseline-commit <base>`의 종료 코드와 결과. 이 옵션이 소실 조사에 주는 정보를 사례별로 기록한다.

사람이 `--verbose`, `git diff -M`, 규칙 diff를 직접 읽어 내리는 판단은 측정하지 않는다(`NOT_MEASURED`). 그 판단을 자동화한 것이 Arm B다.

"순진한 해석" 보조 지표: 현재 검사가 종료 코드 0이고 Finding이 없을 때 이를 수정으로 읽으면 틀리는 사례 수. Arm A의 오판으로 계산하지 않고 별도 표기한다.

### Arm B — 합리적으로 작성한 비교 스크립트

입력: 두 상태의 `semgrep scan --json --verbose` 출력과 종료 코드, 두 상태의 규칙 파일 사본, Git 저장소(두 커밋과 작업 트리). 외부 의존성 없는 Python 표준 라이브러리와 `git`만 사용한다.

판정 규칙(고정):

1. **검사 유효성**: 어느 한쪽의 종료 코드가 0이 아니거나 JSON이 유효하지 않으면 모든 기준 Finding을 `NO_VALID_COMPARISON`으로 두고 사유를 기록한다.
2. **경로 대응**: `git diff -M --name-status base cur`로 이름 변경(R)과 삭제(D)를 구한다. Git에서 삭제됐지만 작업 트리에 파일이 있으면 삭제로 보지 않고 디스크 파일을 현재 내용으로 쓴다.
3. **줄 대응**: 기준 내용(`git show base:path`)과 현재 내용의 `git diff -U0` hunk로 기준 매치 줄 범위가 변경·삭제 hunk와 겹치는지 판정하고, 겹치지 않으면 새 줄 번호를 계산한다.
4. **현존 판정**: 매치 줄이 불변이고, 대응 경로·대응 줄에 같은 `check_id`의 현재 Finding이 있으면 `STILL_PRESENT`.
5. **원인 수집** (현존이 아닐 때, 해당하는 것을 모두 수집):
   - 매치 줄이 hunk와 겹침 → `CODE_CHANGED_AT_MATCH`
   - 파일이 Git과 디스크 모두에서 없음 → `FILE_DELETED`
   - 대응 경로가 현재 `paths.skipped`에 있거나, `paths.scanned`에 없음 → `SCOPE_EXCLUDED`
   - 현재 규칙 파일에 해당 `- id:` 블록이 없음 → `RULE_DISABLED`
   - 블록은 있으나 기준 블록과 텍스트가 다름 → `RULE_CHANGED`
   - 현재 `errors`에 대응 경로가 언급됨 → `SCAN_INCOMPLETE`
6. 원인이 하나도 없으면 `DISAPPEARED`, 원인 없음(`UNEXPLAINED`).
7. **수정 완료를 절대 주장하지 않는다.** `CODE_CHANGED_AT_MATCH`는 "수동 검토 필요"이며 수정의 증거가 아니다.

Arm B의 수정 주장은 설계상 0이다. 따라서 Arm B의 판별력은 M2와 M4로 평가한다.

### Arm C — 현재 제품의 구현된 비교·조사 기능

HTTP 계층 없이 실제 서버 코드를 프로세스 안에서 호출한다: `ScanService._scan_with_manifest`(일반, `investigation_verbose=True`), `ScanService._scan_with_rule_bytes_manifest`, `RunEvidenceRegistry`의 `register_run`/`register_rule_bytes_run`/`create_session`/`evaluate`/`evaluate_rule_bytes`. 브라우저 Comparator(`compare.ts`)는 실행하지 않는다.

세 모드를 각각 기록하고, 제품에 유리하도록 **모드별 관찰의 합집합**을 Arm C의 판정으로 쓴다.

| 제품 출력 | 정규화 |
| --- | --- |
| Evaluation의 `findings`가 비어 있는 `INCOMPARABLE`(차단), 또는 검사·등록 오류 | `NO_VALID_COMPARISON` |
| `shared` | `STILL_PRESENT` |
| `baselineOnly` | `DISAPPEARED` |
| `skip_hypothesis = SUPPORTED` | 원인 `SCOPE_EXCLUDED` 추가 |
| Rule Bytes `DIFFERENT_SELECTED_BYTES` | 원인 `RULE_FILE_CHANGED` 추가 (상위 분류 RULE. 세부 원인과 일치하지 않으므로 최대 COARSE) |
| 그 외 | 원인 없음 |

세 모드 중 하나라도 유효한 Finding 분할을 내면 그 분할을 쓴다. 제품은 수정 완료를 주장하지 않는다. `currentOnly` 수는 "가짜 신규 Finding" 보조 지표로 기록한다.

## 6. 기준 관찰

조건부 라벨과 평가 제외는 Arm A의 원시 현재 검사(비-verbose `semgrep scan --json`)로만 결정한다: 라벨의 기대 위치(`moved_to`가 있으면 그 위치)에 같은 규칙의 결과가 있는가.

## 7. 지표

추적 Finding 단위로 채점한다.

- **M1 잘못된 수정 완료 판정**: 도구가 수정을 주장했으나 `dangerous_code_present_after = true`인 수.
- **M2 원인 분류 정확성**:
  - 라벨 `PERSISTS`: `STILL_PRESENT` → EXACT, `DISAPPEARED` → WRONG(가짜 소실), `NO_VALID_COMPARISON` → NONE
  - 라벨 `NOT_REPORTED`: `STILL_PRESENT` → WRONG. `DISAPPEARED`이면 원인 집합 T와 라벨 L을 비교한다. T = L → EXACT, 상위 분류 집합이 같음 → COARSE, T가 비어 있지 않고 상위 분류가 L의 진부분집합 → PARTIAL, L에 없는 상위 분류 포함 → WRONG, T가 비어 있음 → NONE.
  - 라벨이 `{SCAN_INCOMPLETE}`뿐일 때 `NO_VALID_COMPARISON`은 EXACT.
- **M3 올바른 판단 보류**: (a) `determinable = false`인 Finding에서 판정을 보류한 비율. (b) 소실된 Finding 중 수정을 주장하지 않은 비율.
- **M4 불필요한 판단 보류**: `determinable = true`인 Finding 중 M2가 NONE인 비율.
- **M5 재현 가능한 증거의 충실성**: Arm이 절차상 남기는 산출물에 다음 7개가 있는가. Semgrep 버전, 종료 코드, 규칙 파일 해시, Git 커밋 ID, scanned/skipped 경로 목록, Finding별 매치 내용 또는 그 해시, 원시 Semgrep JSON 또는 그 다이제스트.
- **M6 필요한 수동 작업 수**: 절차 정의에서 세는 명령·판단 단계 수. 사람을 대상으로 측정한 값이 아니다.

## 8. 재현성

각 사례를 처음부터 새로 만들어 3회 반복한다. 정규화 판정이 3회 모두 같아야 한다. Arm B의 판정이 반복 간 다르면 최종 판정은 `INCONCLUSIVE`다.

## 9. 평가 제외 조건

- `base` 상태의 기준 관찰에 라벨의 추적 Finding이 없으면 그 사례를 제외하고 사유를 보고한다.
- 제외 사례가 3개를 넘으면 최종 판정은 `INCONCLUSIVE`다.
- 조건부 라벨이 `PERSISTS`로 확정된 사례는 제외하지 않고 "소실 미발생" 사례로 채점한다.

## 10. 성공·실패 기준 (최종 판정)

N은 채점된 추적 Finding 수다.

- **`BASELINE_SUFFICIENT`**: Arm B가 3회 동일, M1 = 0, WRONG = 0, (EXACT + COARSE) / N ≥ 0.90, M4 ≤ 0.10이고, Arm C가 M1~M4 어느 지표에서도 Arm B보다 낫지 않다.
- **`DIFFERENTIATION_EVIDENCE_SUPPORTED`**: (i) Arm B가 M1 ≥ 1 또는 WRONG ≥ 2 또는 (EXACT + COARSE) / N < 0.80이고 그 실패가 Arm B의 입력에 없는 증거를 요구하거나, (ii) Arm C가 M1 = 0을 유지하면서 M2의 (EXACT + COARSE) 비율에서 Arm B를 앞선다.
- **`INCONCLUSIVE`**: 그 외 모든 경우.

`BASELINE_SUFFICIENT`의 의미는 "합성 14개 사례의 도구 출력 수준에서 스크립트가 충분했다"까지다. 실제 저장소 규모, 사람의 시간·오류, 조직 내 증거 보존 요구는 이 실험의 범위 밖이다.

## 11. 보안상 실행 제한

- 합성 코드만 사용하며 어떤 대상 코드도 실행하지 않는다. Semgrep의 정적 검사만 수행한다.
- 제3자 저장소, 설치 스크립트, 네트워크 다운로드를 사용하지 않는다.
- Semgrep은 metrics off, 버전 확인 off, `--oss-only`, 임시 `HOME`으로 실행한다.
- 원시 결과를 저장할 때 임시 디렉터리 절대 경로만 `<TMP>`로 치환한다. 그 외 내용은 바꾸지 않는다.
- 프로덕션 규칙, 제품 코드, API, UI, 기존 평가 라벨을 수정하지 않는다.

## 12. 사전 지식 공개

이 프로토콜 작성 전에 같은 세션의 감사에서 다음을 이미 관찰했다. 사례 B, A, E의 Arm C 결과는 이 관찰로 예측 가능하다.

- 주석 한 줄 추가 시 제품의 Finding ID가 바뀜.
- 실제 수정과 줄 이동에 대해 제품 평가기가 같은 출력을 냄.
- `--verbose` 조사 모드는 skip된 경로가 있으면 `partial`이 됨.

Arm B 스크립트는 이 문서 커밋 이후에 작성한다. F, G, H, Ia, Ib, J, Da, Db, C, Ka, Kb에 대한 Semgrep·제품 동작은 사전에 실행해 보지 않았다.
