# Phase 3B-1: Evidence Sufficiency Gate

## 목적과 경계

`evidence_sufficiency.py`는 고정된 claim type에 대해 입력 Finding, `ScanResult`, `TaintEvidence`의 구조와 출처가 요구 조건을 충족하는지 판정한다. 자연어 문장의 의미, 실제 악용 가능성, 규칙의 탐지 정확도를 해석하지 않는다. Gate는 AI를 호출하지 않고 Finding 상태·confirmation을 수정하지 않는다. 새 결과는 내부 전용이며 공개 CLI, Finding, ScanResult, AIReview, JSON 계약은 그대로다.

## ClaimEvaluation 계약

각 결과는 다음 값을 가진다.

- `claim_type`: `ClaimType` enum 중 하나
- `decision`: `supported`, `insufficient_evidence`, `unavailable`, `ambiguous`, `unsupported_claim`
- `reason_codes`: 닫힌 `EvidenceReason` enum 값만 허용
- `evidence_provenance`: `semgrep_observation`, `trusted_rule_declaration`, `analyzer_derived`의 조합
- `finding_id`: 연결된 Finding의 기존 불투명 ID. 경로·코드·메시지는 결과에 복사하지 않음
- `limitations`: 고정 코드만 포함

알 수 없는 claim type은 거부한다. 자유 형식 설명이나 원본 도구 진단을 reason code로 받아들이지 않는다.

## 출처 구분

| 출처 | Gate가 사용할 수 있는 정보 | 해석 제한 |
| --- | --- | --- |
| Semgrep 관찰 | 완료/부분 ScanResult, Semgrep Finding, TaintEvidence의 match 위치, 엔진 버전·scope 메타데이터 | 매치 보고 사실만 나타내며 런타임 실행·악용을 입증하지 않음 |
| 신뢰 규칙 선언 | 기존 `_trusted_declaration` 검증 결과, 규칙 ID·상대 파일 ID·SHA-256 및 고정 Source/Sink/Sanitizer 패턴 | 선언은 해당 위치에서 패턴이 실제 매치됐다는 뜻이 아님 |
| 분석기 파생 | Finding ID 재계산, 동일 Finding 중복 확인, 경로·좌표·상태 연결 및 정책 결과 | 연결 및 정책 검증 결과이며 새 코드 관찰을 만들지 않음 |

규칙 파일 해시와 선언은 Gate 호출 시 현재 신뢰 경로의 파일을 다시 확인한다. 실행 시점에 Semgrep이 읽은 바이트와 동일하다는 원자적 증명은 아니므로 선언 기반 결과에 `rule_file_at_scan_time_unproven` 제한을 붙인다. OSS scope 역시 기존 엔진 metadata 매핑 결과이므로 `analysis_scope_derived_from_engine_metadata` 제한을 표시한다.

## Claim별 정책

| Claim | 지원 조건 | 현재 A–L 합성 결과 |
| --- | --- | --- |
| `MATCH_REPORTED` | Semgrep source tool, 유효 버전·종료 상태, ScanResult의 고유하고 동일한 Finding | 지원 |
| `TAINT_RULE_MATCH_REPORTED` | 위 조건 + 완료된 scan + 정확한 TaintEvidence + OSS scope provenance + 재검증한 신뢰 규칙 해시·선언 | 지원. taint 분석 모델의 매치일 뿐 취약점 확정은 아님 |
| `SOURCE_PATTERN_DECLARED` / `SINK_PATTERN_DECLARED` | 정확히 연결된 TaintEvidence와 현재 파일의 신뢰 해시·rule ID·선언 내용 일치 | 선언으로 지원. 위치 관찰로 승격하지 않음 |
| `MATCH_LOCATION_OBSERVED` | 같은 Finding에 연결된 상대 경로와 유효한 match start/end 범위 | 지원. Sink argument가 아님 |
| `SOURCE_LOCATION_IDENTIFIED` | 양의 좌표, `available`, 관찰 필드 marker, 완료 OSS scan 및 엔진 버전 일치 | 현재 `unknown`이므로 unavailable |
| `SINK_ARGUMENT_LOCATION_IDENTIFIED` | 위와 같은 조건의 별도 Sink 위치 | 현재 `unknown`이므로 unavailable |
| `FLOW_TRACE_AVAILABLE` | 지원된 위치 단계가 TaintEvidence에 보존되어 검증돼야 함 | 현재 trace 상태는 absent이고 단계 계약도 없어 unavailable. 향후 status flag만으로 승인하지 않음 |
| `SANITIZER_MATCH_OBSERVED` | Sanitizer 선언·신뢰 해시·완료 OSS scan·구조화 관찰 marker가 모두 필요 | 현재 match status unknown이므로 unavailable |
| `SANITIZER_EFFECTIVENESS_VERIFIED` | 독립 구현 검증이 필요 | 정적 TaintEvidence만으로는 unsupported |
| `VULNERABILITY_CONFIRMED` | 독립 검증/확인 절차가 필요 | 이 Gate에서는 항상 unsupported |

taint claim은 `ScanStatus.COMPLETED`만 허용한다. `PARTIAL` 상태의 특정 고유 Finding은 `MATCH_REPORTED`로 지원할 수 있지만 `scan_partial` 제한을 보존하며, 전체 완료를 요구하는 taint claim은 `insufficient_evidence`로 처리한다. 실행 실패·미설치·잘못된 JSON·timeout·출력 제한 상태는 기존 Finding 객체가 있어도 보고된 매치로 승인하지 않는다. 완료 상태와 종료 코드·버전·issues가 서로 맞지 않으면 `scan_result_inconsistent` 또는 `engine_unverified`로 차단한다.

## 연결·불확실성 처리

- ScanResult에서 Finding ID가 0회면 `finding_not_in_scan`, 2회 이상이면 `ambiguous`다.
- 같은 ID라도 Finding 전체 값이 다르면 ID mismatch로 처리한다.
- TaintEvidence는 `association_status=exact`, Finding ID, rule ID, 상대 경로, 시작 줄, match 상태를 확인한다.
- 유효한 start/end 범위로 기존 Finding ID를 다시 계산한다. end 위치가 변조되거나 위치가 일치하지 않으면 연결을 거부한다.
- 절대 경로, `..`, 백슬래시, URI/scheme 형태의 상대 경로는 거부한다.
- 중복·모호한 evidence는 다른 Finding과 합치지 않는다.
- `unknown`은 해당 사실이 존재하지 않는다는 말이 아니라 현재 근거에서 확인할 수 없다는 뜻이다.

Gate는 내부 TaintEvidence 생성 경로를 전제로 한 결정적 정책이지, 악의적인 Python 코드가 내부 dataclass를 위조하는 것까지 방어하는 암호학적 attestation은 아니다. 따라서 파서·trusted-rule 검증과 함께 사용하며 모델 응답이나 외부 제공 JSON을 TaintEvidence로 직접 신뢰하지 않는다.

## A–L 합성 평가

Semgrep OSS 1.182.1의 기존 A–L fixture와 trusted taint 규칙을 실제 실행해 Gate를 평가했다. taint 결과 13건 모두에서 각각 `MATCH_REPORTED`, `TAINT_RULE_MATCH_REPORTED`, Source/Sink pattern 선언, `MATCH_LOCATION_OBSERVED`는 지원됐다. 각 13건의 Source 위치, Sink argument 위치, flow trace, Sanitizer match 주장은 사용할 관찰 위치·trace가 없어 unavailable이었다. Sanitizer 효과와 취약점 확정은 모두 unsupported였다.

같은 실행의 baseline dynamic-eval pattern 결과 11건은 `MATCH_REPORTED`로 지원됐고 TaintEvidence가 없으므로 taint-match 주장으로 분류되지 않았다. 이 지표는 정책 분류 건수이며 취약점 정확도·정밀도·재현율 수치가 아니다.

## 보안·호환성

- 합성 canary가 TaintEvidence, ClaimEvaluation, reason code, provenance에 포함되지 않는 테스트를 둔다.
- 코드 원문, 절대 경로, 자유 형식 Semgrep message를 ClaimEvaluation에 복사하지 않는다.
- 로컬 Ollama, 외부 LLM, 원격 규칙, Semgrep Cloud/Pro는 사용하지 않는다.
- 실제 Semgrep 검증은 기존 bounded adapter로 신뢰 규칙과 합성 fixture만 사용한다.
- Finding `unverified`, confirmation 없음, 기존 public JSON/CLI는 불변이다.
- OS 수준 네트워크 격리는 제공되지 않는다.

## 검증

기존 `tests/test_semgrep_taint_evaluation.py`의 실제 Semgrep E2E에 Gate 판정 행렬을 붙였다. 신규 `tests/test_evidence_sufficiency.py`는 claim별 조건, pattern/taint 구분, Source/Sink·trace 부재, 해시 및 ID 불일치, duplicate/ambiguous association, partial/failed scan, Sanitizer 정책, canary 비노출과 계약의 닫힌 enum을 검증한다. 실제 모델 호출은 없으며 기본 pytest의 Ollama opt-in은 설정하지 않았다.
