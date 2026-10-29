# Phase 6A — Independent Security Detection Benchmark

## 목적과 기준

Phase 6A는 기존 규칙의 **Rule Signal**을 새로 작성한 합성 코드에서 측정한다. 결과는 실제 취약점 확인 결과가 아니다. Rule Signal, 보안 검토 관련성, 실제 취약점 확정은 서로 다른 판단이다. 실제 런타임 도달성·배포 설정·권한 구성은 평가하지 않았으므로 실제 취약점 확정은 전 사례에서 `NOT_EVALUATED`다.

- 기준 커밋: `dcb6b34c83b73ab02dedb5ce40bfe5f838447c01`
- 평가 집합: `phase6a-synthetic-v1`, 50개 직접 작성 사례
- Oracle SHA-256: `d5c10325bb0ce38f9187739afb704287de1cdbab94e879d57ade152eb05e1747`
- Manifest SHA-256: `954f9e33359bdcd478a6edbdcc83b9aa8cb962c01e7e90c5b6f60ef1b2c23c53`
- Semgrep: OSS 1.182.1
- 정확한 기준 커밋의 GitHub Actions: 성공 (`40822951114`)

평가 시 사용한 규칙 파일 SHA-256:

| 프로필 | 규칙 파일 SHA-256 |
| --- | --- |
| baseline | `5b1f793d6e3eef1ff7bfbc98028dcc3680656661cd3664e9a3266b905f5f22c9` |
| eval taint | `6c0274e4c1829b55ef26361953be3d0ed9af56384fcd63968317a5e7c7ad8e8e` |
| command injection taint | `abcbe9cb181986861c1c8597b0828e14caf839d5283ad27d9e4646ce69893783` |

Manifest와 Oracle 해시 및 버전은 평가기에서 고정 검증한다. 이 평가 집합은 기존 개발용 fixture와 분리되어 있고, 외부 저장소를 가져오지 않았다. 공개 운영 코드의 성능을 대표하지 않는다.

## 데이터셋

각 주요 유형은 독립 사례 10개로 구성된다. Ground Truth의 positive/negative는 문서화된 규칙 입력 조건에 대한 신호 라벨이다. `security_review_relevance`는 별도 필드이며, 맥락을 알 수 없는 사례는 `undetermined`로 유지한다.

| 유형 | 사례 | Rule Signal positive / negative | 평가 주의 |
| --- | ---: | ---: | --- |
| JavaScript dynamic eval | 10 | 5 / 5 | 고정 상수 eval도 문법 신호 positive일 수 있으나 검토 우선순위는 낮게 둘 수 있음 |
| React dangerous HTML | 10 | 5 / 5 | 고정 HTML·출처 불명 HTML도 API 사용 신호로 평가; XSS 여부 미확정 |
| Firestore unconditional write | 10 | 5 / 5 | 파일 경로와 정규식 대상 범위 포함; 배포 여부·유효 권한 미확인 |
| Eval taint | 10 | base 규칙 5 / 5; synthetic sanitizer 규칙 4 / 6 | `syntheticSafe`는 규칙 모델의 가정이며 실제 Sanitizer가 아님 |
| Command injection taint | 10 | 4 / 6 | 명시된 요청 Source 및 `child_process` Sink 모델에 한정 |

Taint 평가 집합의 10개 사례 각각에 두 규칙을 개별 적용했다. 합계 50개 고유 파일이다. Oracle은 Semgrep 실행 전에 버전과 해시를 고정했다. 규칙 관찰 후 라벨은 변경하지 않았다.

## 실행 방법 및 측정 정책

저장소 루트에서 실행한다.

```sh
SEMGREP_REQUIRED=1 uv run python tests/benchmark/evaluate.py
```

평가기(`tests/benchmark/evaluate.py`)는 strict manifest/Oracle을 검증하고 각 로컬 규칙 프로필을 한 번씩 SemgrepAdapter로 실행한다. 기존 Adapter의 OSS 전용 옵션, no-autofix, metrics/version-check 비활성화, 60초 timeout, 2MB 출력 한도를 재사용한다. 저장소의 ignore 규칙이 테스트 코퍼스를 제외하므로, `cases/`만 임시 디렉터리로 복사해 스캔한다. 임시 디렉터리는 실행 후 제거된다.

각 규칙은 Oracle에서 그 규칙을 명시적으로 평가하는 사례에 대해서만 점수화한다. 다른 규칙 프로필에서 알려진 rule ID가 다른 사례 파일에서 관찰되면 `unscored_out_of_scope_findings`에 남기고 점수에 포함하지 않는다. 알 수 없는 rule ID, manifest 밖 파일, 위치 불일치도 별도 보고한다. partial/failed 스캔은 TP/FN으로 바꾸지 않고 전체 점수를 unavailable로 둔다. FP/FN은 CI 실패 조건이 아니다. 평가기 오류, 잘못된 Oracle, Semgrep 실패·버전 불일치는 실패다.

Finding 단위와 사례 단위 지표를 별도로 산출한다. 중복 Finding은 finding-level FP와 duplicate 수에 반영한다. 비율 분모가 0이면 JSON에서 `null`로 출력한다.

## 실제 Semgrep 결과

세 프로필 스캔 모두 Semgrep OSS 1.182.1에서 `completed`, exit code 0, issue 0건으로 끝났다.

| Rule ID | 평가 사례 P/N | Case TP/FP/FN/TN | Precision | Recall | FPR | 위치 불일치 | 중복 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `baseline.javascript-dynamic-eval` | 5 / 5 | 5 / 0 / 0 / 5 | 1.00 | 1.00 | 0.00 | 0 | 0 |
| `baseline.react-dangerous-html` | 5 / 5 | 5 / 0 / 0 / 5 | 1.00 | 1.00 | 0.00 | 0 | 0 |
| `baseline.firestore-unconditional-write` | 5 / 5 | 4 / 0 / 1 / 5 | 1.00 | 0.80 | 0.00 | 1 | 0 |
| `experimental.javascript-eval-taint` | 5 / 5 | 5 / 0 / 0 / 5 | 1.00 | 1.00 | 0.00 | 0 | 0 |
| `experimental.javascript-eval-taint-with-synthetic-sanitizer` | 4 / 6 | 4 / 0 / 0 / 6 | 1.00 | 1.00 | 0.00 | 0 | 0 |
| `experimental.javascript-command-injection-taint` | 4 / 6 | 4 / 0 / 0 / 6 | 1.00 | 1.00 | 0.00 | 0 | 0 |

Finding-level confusion counts는 이 실행에서 case-level과 같았다. 각 expected positive는 한 건씩 보고됐고 중복 Finding은 없었다. Oracle이 기대한 위치와 달랐거나 빠진 곳은 Firestore `F02_nested_write` 한 건이다.

### False negative

- **F02_nested_write**: 중첩된 `match` 안의 `allow create, update, delete: if true;`를 Firestore baseline 정규식이 보고하지 않았다. Oracle은 baseline의 명시된 정규식 문법(`read, write` 묶음 또는 단일 동사)을 기준으로 이를 positive로 사전 라벨링했다. 이 결과는 규칙 커버리지의 미탐이며 실제 Firestore 취약점 판정이 아니다. 규칙은 이번 Phase에서 변경하지 않았다.

FP와 중복 Finding은 해당 평가 범위에서 관찰되지 않았다. 이는 작은 합성 사례 집합에 대한 결과일 뿐, 실제 저장소에서 오탐이 없다는 뜻이 아니다.

## 프로필별 비점수 관찰

| 프로필 | 전체 Finding | 점수화된 Rule Signal | 알려진 Oracle 범위 밖 매치 |
| --- | ---: | ---: | ---: |
| baseline | 23 | 14 | eval-taint 카테고리의 JavaScript `eval` 9건 |
| eval taint | 11 | 9 | baseline eval 카테고리 E02에서 taint 규칙 2건 |
| command injection taint | 4 | 4 | 0 |

비점수 매치 11건은 `unscored_out_of_scope_findings`로 case ID, rule ID, 줄만 출력한다. 이를 숨기거나 TN으로 세지 않았다. E02는 별도 baseline eval 카테고리에 속하므로 eval-taint 수치에는 합산되지 않는다. 향후 평가 집합 버전을 만들 때 여러 규칙 유형이 겹치는 사례를 명시적으로 복수 라벨링할지 검토할 수 있다. 현재 Oracle을 결과에 맞춰 소급 수정하지 않았다.

평가 프로필에서 예상하지 못한 rule ID는 0건, manifest에 연결되지 않는 Finding은 0건, 점수화 범위의 중복 Finding은 0건이었다.

## Rule Signal과 검토 관련성

Rule Signal이 positive여도 개발자의 검토 가치가 낮거나 실행 문맥이 불명확할 수 있다. 예를 들어 E05의 고정 상수 eval, R03/R05의 상수 HTML은 규칙 사용 신호로 보고됐지만 그 사실만으로 취약점이 증명되지 않는다. 요청 입력의 실제 유입·정제·런타임 도달 여부는 이 정적 합성 benchmark가 평가하지 않는다. Firestore 사례는 배포 상태, 상속된 규칙, 전체 match 범위를 확인하지 않았다.

Eval taint의 synthetic sanitizer 결과는 Semgrep 규칙이 `syntheticSafe`를 모델링한 효과만 평가한다. Command injection은 제한된 `req.query.cmd`/`req.body.cmd` Source와 Node.js `exec`/`execSync` Sink 모델에 한정된다. Taint 매치는 런타임 exploitability나 전체 애플리케이션 흐름 증명이 아니다.

## 보안 및 계약 범위

- Production baseline, experimental rule, TaintEvidence 신뢰 SHA, Gate, 공개 Finding/API/CLI 계약은 변경하지 않았다.
- fixture는 정적 분석만 수행했다. 합성 함수·명령은 실행하지 않았다.
- 평가 결과는 case ID, rule ID, 위치, 집계만 기록한다. 코드 원문·Semgrep 자유 형식 메시지·실제 비밀정보는 출력하지 않는다.
- 평가기는 synthetic canary가 Finding 설명에 존재하는 테스트 입력을 넣어도 출력 결과에 복사하지 않는 단위 테스트를 포함한다.
- 전체 외부 운영 환경의 탐지 정확도, 검토 효용, confirmed vulnerability는 평가하지 않았다.

## Phase 6B 우선순위

1. Firestore 규칙에서 여러 권한 동사의 무조건 허용을 놓친 F02를 우선 조사한다. 수정은 별도 Phase에서 전후 독립 평가 집합으로 검증한다.
2. baseline/eval-taint 간 중첩 신호를 명시적으로 라벨링하는 새 benchmark 버전을 설계한다. 기존 v1 Oracle을 사후 변경하지 않는다.
3. 현실적인 애플리케이션 문맥에서 오탐 가치와 검토 효용을 별도로 평가한다. 현재 합성 Rule Signal 수치만으로 production 승격하지 않는다.
4. 이후 외부 프로젝트 코드가 필요하면 라이선스·출처·데이터 범위를 사전 검토하고 이 합성 집합과 분리한다.

## 검증 상태

기준 SHA의 원격 CI는 평가 작업 전 성공 상태였다. 이번 Phase 변경은 아직 원격 CI에 제출하지 않았으며, 최종 검증은 로컬에서 실행했다. 사람 대상 평가와 실제 운영 저장소 benchmark는 수행하지 않았다.
