# Phase 3A-2: 내부 TaintEvidence 계약

## 목적과 경계

`TaintEvidence`는 실험용 Semgrep taint Finding의 보조 내부 자료다. Finding, `ScanResult`, CLI와 공개 JSON은 그대로 유지한다. 기존 `SemgrepAdapter.scan()`은 계속 `ScanResult`만 반환하고, adapter 내부 평가용 경로가 한 번 파싱한 JSON에서 Finding과 TaintEvidence를 함께 만든다. 원본 JSON은 메모리에서 처리한 뒤 반환·저장하지 않는다.

TaintEvidence는 취약점 확정이나 confirmation이 아니다. Source 위치, Sink 인자 위치, 전체 데이터 흐름을 새로 추론하지 않는다.

## 출처 분리

| 출처 | 보존하는 정보 | 의미 |
| --- | --- | --- |
| Semgrep JSON 관찰 | `check_id`, `path`, `start`, `end`, 버전, 요청/결과 엔진 종류, severity/CWE 필드의 존재 | 이 결과가 보고한 규칙과 match 위치 |
| 신뢰 규칙 파일 | 지원된 실험 규칙 ID의 `mode: taint`, Source/Sink/Sanitizer 패턴 선언, 저장소 상대 규칙 파일 ID, SHA-256 | 이 규칙 파일에 선언된 분석 패턴 |
| 분석기 파생 | Finding ID 연결, 상대 경로 정규화, 상태와 제한 코드 | 파서가 관찰 결과를 기존 Finding에 연결한 방식 |

규칙 선언은 알려진 규칙 파일의 고정 SHA-256과 rule ID가 모두 맞을 때만 노출한다. 해시가 다르면 rule ID가 같아도 선언 패턴은 비워 두고 `unavailable`로 기록한다. 해시는 근거 생성 시점에 읽은 파일 내용의 지문이다. Semgrep이 실행 도중 읽은 파일이 같은 버전이었다는 원자적 보장은 아니므로 이를 제한 사항으로 남긴다.

## 위치와 흐름 상태

- `matched_file`, `matched_start`, `matched_end`는 JSON의 `path`, `start`, `end`에서 정규화한 **Semgrep match 위치**다.
- 이 위치를 Sink 인자 위치로 승격하지 않는다. `sink_location`은 `unknown`이다.
- 규칙에 Source 패턴이 선언돼 있어도 그 Source가 실제 매치됐거나 도달했다는 뜻이 아니다. `source_location`은 JSON에 위치가 없으므로 `unknown`이다.
- Sanitizer 선언은 규칙의 분석 가정이다. Sanitizer가 특정 위치에서 매치됐는지, 구현이 안전한지는 JSON에서 확인할 수 없어 `sanitizer_match_status=unknown`이다.
- Semgrep 1.182.1 OSS 출력에서 trace 필드는 관찰되지 않았다. 따라서 `flow_trace_status=absent`이며 Source→Sink 단계를 합성하지 않는다.
- 알려지지 않은 trace 필드는 값이나 코드 조각을 저장하지 않는다. 현재는 스키마가 지원되지 않는 구조를 `unsupported`, 명백히 잘못된 외부 타입을 `malformed`로 분류한다. `available`은 지원되는 trace 스키마와 검증기가 추가되기 전까지 생성되지 않는다.

`finding_id`, rule ID, 상대 파일, 시작 줄이 원본 결과와 일치하고 ID가 유일할 때만 연결을 `exact`로 기록한다. 같은 결정적 Finding ID가 복수 결과에 재사용되거나 필드가 불일치하면 `ambiguous`와 `finding_id=None`을 사용해 근거를 섞지 않는다.

## 개인정보와 실행 경계

TaintEvidence에는 원본 코드, `extra.lines`, 자유 형식 Semgrep 메시지·오류, 절대 경로를 복사하지 않는다. 관찰한 JSON 필드 이름과 안전한 상태 코드만 남긴다. 규칙 메타데이터의 CWE 등 기존 Finding 변환 결과도 변경하지 않는다.

실제 모델 호출은 없으며, 합성 fixture만 사용한다. Adapter의 신뢰 로컬 규칙 제한, `--oss-only`, metrics/version check 비활성화, timeout 및 출력 상한은 유지한다. OS 수준 네트워크 차단은 제공하지 않는다.

## 검증 범위 및 한계

단위 테스트는 위치 정규화, 선언 해시 불일치, Source/Sink 위치 부재, trace 부재·미지원·손상, duplicate 결과, 같은 위치의 서로 다른 규칙, 잘못된 association, 경로 이탈 및 canary 비노출을 검증한다. Semgrep 전용 E2E는 1.182.1 OSS에서 A–L 합성 fixture를 다시 실행해 기존 Finding과 내부 근거가 같은 결과에서 연결되는지 확인한다.

Semgrep match를 보고했다는 사실은 규칙과 엔진의 분석 모델 결과다. 런타임 입력 도달성, 실제 Sanitizer의 안전성, Source→Sink trace 또는 취약점 악용 가능성을 단독으로 입증하지 않는다.

2026-10-28 로컬 검증 결과:

- TaintEvidence·parser·adapter 단위 테스트: 50 passed.
- 실제 Semgrep taint 평가(1.182.1): 1 passed, 0 skipped.
- CI와 같은 Semgrep 필수 테스트 집합: 5 passed, 0 skipped.
- 전체 회귀: 241 passed, 28 skipped, 0 failed. Skip은 기존 opt-in Ollama 평가다.
- `.github/workflows/ci.yml`은 변경하지 않았다. Python job의 전체 회귀가 새 단위 테스트를 실행하고, 기존 Semgrep 전용 job의 필수 taint E2E가 같은 내부 근거 경로를 검증한다.
