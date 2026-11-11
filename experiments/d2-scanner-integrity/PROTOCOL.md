# D2 — 스캐너 무결성 문제 검증: 사전 등록 프로토콜

상태: `PREREGISTERED` — 이 문서, `labels.json`, `build_cases.py`는 어떤 Arm도 실행하기 전에 커밋한다. 이후 라벨, 판정 규칙, 성공·실패 기준을 바꾸지 않는다. 구현이 이 문서와 다르게 동작하는 결함만 수정할 수 있고, 모든 수정은 결과 문서에 기록한다.

D1(`18b113a`, `5aa4af4`)의 결과와 중단 기준은 그대로 유지한다. 이 실험은 D1의 판정을 다시 다루지 않는다.

## 1. 질문과 가설

- **Q1**: 검사 결과가 정상처럼 보여도 일부 코드가 검사되지 않았다는 사실을 놓칠 수 있는가?
- **Q2**: Semgrep 기존 옵션과 간단한 검증 스크립트로 충분히 해결되는가?
- **Q3**: 현재 프로젝트가 추가로 해결하는 문제가 있는가?

- **H1 (검증 대상)**: 현재 제품은 불완전한 검사를 구분하는 데서 기존 옵션과 최소 스크립트보다 낫다.
- **H0**: 최소 스크립트(Arm C)로 충분하다.

"완전한 검사"는 코드가 안전하다는 뜻이 아니다. 선언된 의도 범위의 모든 파일이 의도한 모든 규칙으로 분석됐다는 뜻이다.

## 2. 환경과 대상

- 기준 트리: `787798bf56a29e458e9ab246c985b00f213469b5` (원격 main `801f03b`와 트리 동일).
- Semgrep OSS CLI **1.182.1** 고정. 다르면 중단한다.
- 규칙: `rules/security-baseline.yml`의 사본. 일부 사례는 사본을 변형한다. 원본은 읽기만 한다.
- 대상: `build_cases.py`가 만드는 합성 JavaScript와 임시 Git 저장소. 제3자 코드 없음.
- 모든 Arm은 같은 디렉터리, 같은 규칙 파일, 같은 Semgrep을 쓴다.

## 3. 사례 (18개)

| 사례 | 상황 | 대응 항목 |
| --- | --- | --- |
| A | 파싱 오류가 있는 파일 + 다른 파일의 Finding | A |
| B | 유일한 위험 코드가 파싱 실패 파일 안에 있음 | B |
| Bs | 1MB 초과 파일에 위험 코드 | B |
| C | `.semgrepignore`가 위험 파일 제외 | C |
| Cd | Semgrep 기본 ignore가 `tests/` 아래 위험 파일 제외 | C |
| D | `.gitignore`된 미추적 파일에 위험 코드 | D |
| E | 규칙 파일이 잘못된 YAML | E |
| F1 | 규칙 하나의 패턴이 파싱되지 않음 | F |
| F2 | 기대한 규칙이 설정에서 조용히 빠짐 | F |
| Gt | 규칙 타임아웃 | G |
| Go | Finding 5,000건의 큰 출력 (검사는 완전) | G |
| H | 정상 코드, Finding 0건 | H |
| Hp | 정상 검사, Finding 있음 | H |
| Hm | 규칙 대상이 아닌 언어 파일이 섞인 저장소 | H |
| Hn | 선언된 제외 대상 `node_modules/` 포함 | H |
| I1 | 검사 대상이 소스 없는 다른 디렉터리 | I |
| I2 | 검사 대상 경로가 존재하지 않음 | I |
| J | 한 파일은 실제 수정, 다른 위험 파일은 새로 제외 | J |

완전한 검사 5개(Go, H, Hp, Hm, Hn)는 불필요한 차단을 측정하기 위한 것이다.

## 4. 정답 라벨과 선언된 의도

`labels.json`. 라벨은 사례의 구성 방식에서만 도출한다.

- `complete`: 선언된 의도 범위가 전부 분석됐는가.
- `reason`: 불완전한 이유의 분류 집합. `PARSE`, `SCOPE`, `RULE`, `TIMEOUT`, `SCAN_FAILED`.
- `policy_dependent`: 의도 범위가 정책 판단에 달린 사례(Cd, D). 채점에 포함하되 별도로도 보고한다.

**선언된 의도(intent manifest)**: 의도한 루트, 소스 확장자(`.js .jsx .ts .tsx`, `firestore.rules`), 선언된 제외(`node_modules/`, `.git/`), 기대 규칙 집합(프로덕션 규칙 파일의 SHA-256, 또는 사례가 규칙을 일부러 추가한 경우 `as_given`).

**조건부 라벨 (Gt)**: 타임아웃 발생 여부는 Semgrep의 동작이므로 단정하지 않는다. Arm A의 원시 JSON `errors`에 타임아웃 오류가 있으면 `complete = false`, 없으면 사례를 제외한다.

## 5. 비교 Arm

공통 Semgrep 옵션: `--json --metrics=off --disable-version-check --oss-only --no-autofix`, 임시 `HOME`, 작업 디렉터리는 규칙 디렉터리.

| Arm | 실행 | PASS 조건 |
| --- | --- | --- |
| A 기본 실행 | `semgrep scan` | 종료 코드 0 |
| B `--strict` | `semgrep scan --strict` | 종료 코드 0 |
| C 최소 스크립트 | `semgrep scan --verbose` + `integrity_check.py` | 아래 규칙에서 사유가 하나도 없음 |
| D-cli 제품 CLI | `python -m ai_code_security_analyzer scan --format json` | 종료 코드 0 |
| D-api 제품 API 경로 | `ScanService.scan` | `completed = true`이고 `issues`가 비어 있음 |
| D-inv 제품 조사 모드 | `ScanService._scan_with_manifest(investigation_verbose=True)` | 위와 같음 |

제품 설정 생성이 거부되거나 서비스가 오류를 내면 FLAG다. HTTP 계층과 대시보드는 실행하지 않는다.

Arm A와 B의 사람이 읽는 stderr 요약은 채점하지 않는다. 원문을 저장하고, 불완전 신호가 문장으로 나오는지를 결과 문서에 **사후 정성 관찰**로만 적는다.

### Arm C 규칙 (고정)

입력: verbose JSON, 종료 코드, 실제 검사 대상 경로, 규칙 파일, 선언된 의도. 표준 라이브러리만 사용한다. 해당하는 사유를 모두 수집한다.

1. 종료 코드가 0이 아니거나 JSON이 유효하지 않음 → `SCAN_FAILED`
2. `errors[]`의 각 항목 → 유형·메시지에 `Timeout`이 있으면 `TIMEOUT`, `Pars`·`Syntax`·`Lex`가 있으면 `PARSE`, `rule`·`pattern`·`config`·`YAML`이 있으면 `RULE`, 그 외 `GENERIC`
3. `paths.skipped`의 항목 중 선언된 제외에 속하지 않고, 디렉터리이거나 소스 확장자·이름에 해당하는 것 → `SCOPE`
4. 의도한 루트를 디스크에서 순회해, 선언된 제외에 속하지 않는 소스 파일 중 `paths.scanned`에 없는 것 → `SCOPE`
5. 의도 범위의 소스 파일이 하나 이상인데 `paths.scanned`가 비어 있음 → `SCOPE`
6. 규칙 파일 SHA-256이 기대값과 다름(기대값이 `as_given`이면 생략) → `RULE`. `skipped_rules`가 비어 있지 않음 → `RULE`

JSON이 유효하지 않으면 2~5는 건너뛰고 1과 6만 적용한다.

### 제품 사유의 분류

| 제품 출력 | 분류 |
| --- | --- |
| `semgrep_skipped_paths`, `no_files_scanned` | `SCOPE` |
| `semgrep_skipped_rules` | `RULE` |
| `semgrep_timeout` | `TIMEOUT` |
| `invalid_json`, `nonzero_exit`, `semgrep_launch_failed`, `semgrep_failed`, 설정 거부 | `SCAN_FAILED` |
| `semgrep_reported_errors`, `evidence_unavailable` | `GENERIC` |
| `semgrep_output_limit`, `findings_omitted` | `OUTPUT` |

## 6. 지표

- **M1 불완전한 검사를 정상으로 오인**: 라벨 `complete = false`인데 PASS인 사례 수.
- **M2 정상 검사를 불필요하게 차단**: 라벨 `complete = true`인데 FLAG인 사례 수.
- **M3 실패 원인 설명**: 올바르게 FLAG한 사례에서 사유 분류가 라벨 `reason`에 속하면 MATCH, `GENERIC`이나 사유 없음이면 GENERIC, 라벨에 없는 분류만 제시하면 WRONG.
- **M4 근거 충실도**: Arm의 산출물에 다음 7개가 있는가. 종료 코드, 오류의 유형과 경로, scanned 목록, skipped 목록과 사유, 규칙 집합 식별자(해시), Semgrep 버전, 검사 대상 식별자.
- **M5 수동 절차의 복잡성**: 절차 정의에서 센 단계 수. 사람 대상 측정이 아니다.
- **M6 재현성과 유지보수 비용**: 3회 반복의 일치 여부, 스크립트 줄 수, 의존하는 Semgrep JSON 필드 수.

## 7. 재현성과 제외

- 각 사례를 새로 만들어 3회 반복한다. Arm C의 판정이 반복 간 다르면 최종 판정은 `EVIDENCE_INSUFFICIENT`다.
- 조건부 라벨로 제외된 사례는 사유와 함께 보고한다. 제외가 3개를 넘으면 `EVIDENCE_INSUFFICIENT`다.

## 8. 최종 판정 기준

"제품의 최선 모드"는 D-cli, D-api, D-inv 중 (M1 + M2)가 가장 작은 모드다. 동률이면 M1이 작은 쪽이다.

- **문제 존재 여부(Q1)**: Arm A가 정책 의존이 아닌 사례에서 M1 ≥ 1이면 "기본 실행은 불완전한 검사를 정상으로 보이게 한다"가 이 사례들에서 관찰된 것으로 본다.
- **`EXISTING_TOOLS_SUFFICIENT`**: Arm C가 3회 동일하고 M1 = 0, M2 = 0이며, 제품의 최선 모드가 M1과 M2 어느 쪽에서도 Arm C보다 낫지 않다.
- **`SCANNER_INTEGRITY_VALUE_SUPPORTED`**: 제품의 최선 모드가 M1과 M2 모두에서 Arm C 이하이고 적어도 하나에서 엄격히 작으며, 그 차이가 Arm C의 입력(Semgrep 출력, 파일 시스템, 선언된 의도)으로는 메울 수 없다.
- **`EVIDENCE_INSUFFICIENT`**: 그 외.

판정의 적용 범위는 합성 18개 사례의 도구 출력 수준이다. 실제 저장소에서의 정확도나 사람의 업무 효과를 뜻하지 않는다.

## 9. 보안상 실행 제한

- 합성 코드만 사용하고 어떤 대상 코드도 실행하지 않는다.
- 제3자 저장소, 설치 스크립트, 네트워크 다운로드를 쓰지 않는다.
- Semgrep은 metrics off, 버전 확인 off, `--oss-only`, 임시 `HOME`으로 실행한다.
- 원시 결과에서 임시 디렉터리 절대 경로만 `<TMP>`로 치환한다.
- 제품 코드, API, UI, 프로덕션 규칙, D1 산출물을 수정하지 않는다.

## 10. 알려진 한계 (사전 명시)

- 같은 연구자가 사례, 라벨, Arm C 규칙을 같은 세션에서 설계한다. 독립 검증이 아니다.
- Arm C만 "선언된 의도"를 입력으로 받는다. Arm A, B와 제품에는 의도를 전달할 방법이 없다. 이것은 설계상의 비대칭이며 결과 해석에 명시한다.
- 합성 사례의 건수는 실제 업무에서의 발생 빈도를 나타내지 않는다.

## 11. 사전 지식 공개

이 프로토콜 작성 전에 같은 세션의 감사와 D1에서 다음을 이미 관찰했다. 사례 A, C, D, E, Hn의 일부 결과는 예측 가능하다.

- 구문 오류가 있어도 Semgrep은 종료 코드 0을 반환하고 `errors`에 `PartialParsing`을 남긴다. 제품은 이를 `partial`로 표시한다.
- `.semgrepignore` 제외는 비-verbose JSON에 나타나지 않는다. 제품 일반 모드는 `completed`, 조사 모드는 `partial`이 된다.
- 미추적 gitignore 파일은 `--verbose`에서도 scanned와 skipped 어디에도 나오지 않는다.
- 잘못된 YAML 규칙은 종료 코드 7이다.
- `node_modules`가 있으면 조사 모드는 `partial`이 된다.

`--strict`의 동작, 크기 제한, 기본 ignore, 잘못된 패턴, 규칙 누락, 타임아웃, 큰 출력, 잘못된 대상 경로에 대한 Semgrep·제품 동작은 사전에 실행해 보지 않았다. Arm C 스크립트는 이 문서 커밋 이후에 작성한다.
