# ER-C2 — Finding Disappearance Evidence Evaluator

## 목적과 경계

ER-C2는 ER-C1의 실행별 `ScanEvidenceManifest`와 기존 공개 `ScanResponse`를 메모리 안에서 검증하고, 응답 Finding ID 집합의 차이 및 현재 Semgrep scope JSON이 보고한 경로 상태를 평가하는 Backend 내부 MVP다.

이 기능은 Finding이 현재 응답에서 관찰되지 않은 사실과 제한된 실행 절차 관찰을 제공한다. **Finding의 미관찰은 취약점 수정이나 해결 완료의 증거가 아니다.** 코드 내용 동일성, 의미상 Finding 동일성, 파일 삭제·이동·수정, 취약점 발생·해결, 안전성을 판단하지 않는다. LLM, 새 API, UI, 저장소, 네트워크, 추가 Semgrep 실행을 도입하지 않았다.

기준 SHA `8693e37bca597ae071d2801e7cfe16d040f11b76`, GitHub Actions Run `41812712477`은 push/completed/success였고 Python, React dashboard, Semgrep integration이 성공했으며 Artifacts는 0개였다. 구현 worktree는 `/tmp/ai-csa-er-c2-disappearance-evaluator`, 브랜치는 `research/er-c2-disappearance-evaluator`다.

## ER-C0·ER-C1·Phase 8L과의 관계

- Phase 8L의 `currentOnly` / `shared` / `baselineOnly`는 Finding ID 문자열 집합 차이다. ER-C2는 이 분류를 Python 내부에서 다시 계산하며 기존 프런트엔드 comparator를 바꾸지 않는다.
- ER-C1의 private `ScanService._scan_with_manifest()`는 기존 `ScanResponse`와 `ScanEvidenceManifest`를 하나의 Semgrep 실행에서 반환한다. 공개 `scan()`과 FastAPI DTO는 그대로다.
- 내부 소비자는 그 반환 쌍을 바로 `bind_run_evidence(response, manifest)`에 전달한다. Bundle 생성 시 manifest version/reference, target/profile, status, Semgrep version, invocation/rule file, Finding ID 목록과 count, bounded Scope 구조를 검증한다.
- `ScanResponse`에는 `scan_ref`가 없으므로 Python 객체만으로 악의적으로 위조된 in-process pair의 출처를 암호학적으로 증명할 수는 없다. Bundle은 신뢰된 `_scan_with_manifest()` 호출 직후 같은 실행 범위에서 만들도록 제한한다. 검증 함수는 우발적 혼합과 값 불일치를 차단하며, 보안 토큰이나 외부 provenance 증명으로 주장하지 않는다.
- 각 실행의 Scan Reference는 C1 생성기의 새 난수 값이며, 같은 target/profile을 재검사해도 달라야 한다. 서로 다른 실행에서 Finding ID가 같을 수 있는 정상 사례와 Scan Reference 충돌은 구분한다.

## 구현 계약

모듈: `src/ai_code_security_analyzer/finding_disappearance_evaluator.py`

계약 버전: `finding-disappearance-evaluation/v1`

주요 타입 및 함수:

- `RunEvidenceBundle(response, manifest)`: 같은 private 실행 쌍의 불변 입력 wrapper
- `bind_run_evidence(response, manifest)`: 개별 pair의 구조·값 결합 검사. 실패 시 고정 `BundleBindingError`만 발생
- `evaluate_finding_disappearance(baseline, current)`: 두 검증 bundle에 대한 순수 비교
- `FindingDisappearanceEvaluation`, `FindingEvaluation`: 불변 결과 타입
- 상태 Enum: `AssessmentStatus`, `FindingCategory`, `PathObservation`, 고정 `LimitationCode`

Evaluator는 입력 객체를 수정하지 않고 API, 파일시스템, 네트워크 또는 Semgrep을 호출하지 않는다. 응답 Finding은 최대 50건, 두 실행의 합집합은 최대 100개다. 경로 목록과 Manifest의 기존 C1 상한을 재확인하며 출력 JSON 크기는 256 KiB로 제한한다. 출력 상한 초과는 일부 결과를 남기지 않고 결과 항목이 빈 `INCOMPARABLE` 결과와 `evaluation_output_limit_exceeded`로 닫힌다. 오류 메시지에는 입력 경로, 원본 Semgrep 메시지, 토큰 또는 stdout/stderr를 넣지 않는다.

### 비교 가능성 Gate

입력 pair 내부 검증 후 다음을 요구한다.

1. 기준/current Scan Reference가 각각 유효하고 서로 다름
2. target ID, 요청 Rule Profile ID 일치
3. Semgrep 버전이 유효하며 두 실행에서 일치
4. 정규화 invocation ID와 선택된 신뢰 규칙 파일 식별자 일치
5. Manifest와 Response의 status/version/count/Finding ID가 결합됨
6. 두 검사 모두 `completed`, `completed=true`, 생략 0건

문맥 불일치, 불완전 검사, 생략 Finding, Scan Reference 충돌, 잘못된 bundle, scope 내부 충돌은 `INCOMPARABLE`이다. 불완전한 경우에도 응답에 실제 포함된 Finding의 집합 차이는 제한된 관찰로 반환될 수 있지만, 전체 검사 비교나 Finding 부재의 완전한 의미로 해석할 수 없다.

`COMPARABLE`은 관찰 집합을 비교할 수 있다는 뜻이다. 동일 규칙 바이트나 규칙 로딩 결과, 완전한 파일 scope가 입증됐다는 뜻이 아니다. 각 정상 결과에도 `rule_bytes_unverified`, `loaded_rule_identity_unverified`, `source_snapshot_not_collected`, `scope_completeness_unverified`, `scan_result_is_not_safety_proof` 제한이 남는다.

## Finding ID 범주

중복 ID, count 불일치, 응답-Manifest ID 불일치는 차단한다. ID 문자열은 정렬된 집합으로 분류해 결과 순서를 입력 배열 순서에 의존시키지 않는다.

| 범주 | 확인하는 사실 | 확인하지 않는 사실 |
| --- | --- | --- |
| `currentOnly` | ID가 현재 Response에만 있음 | 새 취약점 발생 |
| `shared` | 동일 ID가 양 Response에 있음 | 같은 코드, 같은 실행 경로, 같은 보안 상태 |
| `baselineOnly` | 기준 ID가 현재 Response에 없음 | 수정, 해결, 안전 |

Finding ID는 코드 내용 해시가 아니다. `shared` 상태에서도 소스 snapshot 가설을 평가하지 않으며, 전체 제한에 `source_snapshot_not_collected`를 보존한다.

## 경로 Scope 관찰

기준 `baselineOnly` Finding의 검증된 상대 경로만 current Manifest의 `ScopeEvidence`와 정확히 비교한다. 절대경로·경로 순회·제어문자·역슬래시·콜론·중복 또는 NFC 정규화 충돌·허용되지 않은 skip 사유·경로/크기 한도 위반을 거부한다. 결과에는 원본 파일 경로를 복사하지 않는다.

| 결과 | 조건 및 의미 |
| --- | --- |
| `PATH_REPORTED_SCANNED` | 같은 current Manifest의 `scanned` 목록이 정확한 경로를 보고함. 모든 규칙 적용 완료나 파일 바이트 동일성을 뜻하지 않음 |
| `PATH_EXPLICITLY_SKIPPED` | `skipped`가 관찰됐고 경로와 고정 allowlist 사유가 정확히 일치함. “Semgrep이 해당 경로를 skip으로 보고했다”는 좁은 절차 관찰만 지원 |
| `PATH_NOT_REPORTED` | scanned와 skipped 자료가 모두 관찰됐으나 경로가 양쪽 목록에 없음. 파일 삭제·ignore·제외 원인을 확정하지 않음 |
| `SKIP_EVIDENCE_NOT_COLLECTED` | scanned 목록에는 없고 skipped 자료는 수집하지 않음. skip이 없었다는 뜻이 아님 |
| `SCOPE_EVIDENCE_UNAVAILABLE` | 필요한 경로 근거가 없거나 사용할 수 없음 |
| `FINDING_PATH_UNAVAILABLE` | 기준 Finding에 파일 경로가 없음 |
| `CONFLICTING` | 동일 경로가 scanned와 skipped 양쪽에 있음. 임의 우선순위 없이 전체 결과를 incomparable 처리 |

`paths.scanned`는 Semgrep JSON이 보고한 처리 경로다. 전체 파일 발견, 모든 규칙 실행, 파일별 성공 또는 scope completeness를 증명하지 않는다. C1의 기본 비-verbose 실행에서 skip 상세는 없을 수 있다. 평가기는 누락된 skip을 재구성하지 않는다.

명시적 skip은 개별 `skip_hypothesis=SUPPORTED`와 전용 제한 코드로만 표현한다. completed·무생략 비교에서 모든 baselineOnly 경로가 명시적으로 skip된 경우 aggregate `EXPLANATION_SUPPORTED`는 이 검사 절차 관찰에 한정된다. 이는 해당 Finding이 사라진 유일한 원인, 수정, 해결 또는 취약점 상태를 뜻하지 않는다. partial/failed/timed-out/output-limited 검사나 생략 결과는 aggregate를 `INCOMPARABLE`로 유지해도 직접 관찰된 skip 상태는 Finding별로 남길 수 있다.

## Rule 및 Source 근거

- 같은 Profile ID, Semgrep version, invocation ID, selected rule file ID는 요청/설정 식별자의 일치다.
- C1이 `byte_identity_status=UNVERIFIED` 및 `loaded_identity_status=UNVERIFIED`로 남긴 상태는 ER-C2에서도 승격하지 않는다. 두 한계는 별도 고정 코드로 출력한다.
- Rule ID/file ID가 바뀌거나 엔진 버전·invocation/profile이 다른 경우 비교를 차단한다. 같은 profile ID가 실제 같은 규칙 바이트 적용을 증명한다고 보지 않는다.
- 일반 소스 snapshot은 수집되지 않는다. 코드 수정, 파일 이름 변경/이동, 같은 ID에서 코드 변경, 동일 코드 의미, 실제 취약점 변화는 모두 판단 불가다.
- 동일한 비교 가능한 메타데이터 또는 현재 경로가 scanned에 있었다는 관찰로 source identity를 역추론하지 않는다.

## 평가 상태와 고정 코드

개별 제한 가설은 `SUPPORTED`, `CONTRADICTED`, `UNDETERMINED`, `INCOMPARABLE`로 표현한다. `CONTRADICTED`는 동일한 좁은 skip 관찰에서 경로가 scanned로 보고된 경우에만 쓴다. 수집 실패는 반대 증거가 아니다.

전체 assessment는 `EXPLANATION_SUPPORTED`, `MULTIPLE_EXPLANATIONS_POSSIBLE`, `UNDETERMINED`, `INCOMPARABLE`을 포함하는 Enum으로 닫혀 있다. MVP는 근거 없는 복수 원인을 생성하지 않으므로 `MULTIPLE_EXPLANATIONS_POSSIBLE`을 현재 emit하지 않는다. baselineOnly가 있으나 명시적 절차 증거가 없으면 `UNDETERMINED`; 기준/current 모두 Finding이 없어도 안전 판정을 하지 않고 `UNDETERMINED`다.

상태 코드와 입력 문자열은 분리되어 있다. 결과에는 raw Semgrep 자유형 메시지, API 토큰, stdout/stderr, 소스 코드 또는 내부 절대 경로가 없다. 평가 모듈은 사용자용 한국어 문장을 만들지 않는다. 후속 화면은 고정 코드 카탈로그를 별도로 사용해야 한다.

## ER-C0 합성 시나리오 지원 범위

평가기의 기대값은 fixture 작성자가 알고 있는 실제 조작과 독립적으로 정의한다. 평가기는 제공되지 않은 실제 원인을 알아맞히지 않는다.

| # | 시나리오 | ER-C2 기대 범위 |
| ---: | --- | --- |
| 1 | 같은 코드/규칙, 동일 Finding | `shared`; 코드 동일성은 판단 불가 |
| 2 | 코드 수정 후 Finding 미관찰 | `baselineOnly`; 수정 원인 판단 불가 |
| 3 | 파일 삭제 | 경로가 current lists에 없거나 skip 미수집; 삭제 판단 불가 |
| 4 | 파일명 변경 | 기존 ID는 baselineOnly, 새 ID가 있으면 currentOnly; 이동 연결 판단 불가 |
| 5 | 파일 이동 | 동일하게 ID 집합 차이만 관찰; 이동 판단 불가 |
| 6 | Profile 변경 | `INCOMPARABLE` |
| 7 | Profile ID는 같고 규칙 bytes 변경 | 관찰 비교만 가능; rule bytes/인과 `UNDETERMINED` |
| 8 | Semgrep 버전 변경 | `INCOMPARABLE` |
| 9 | 파일 scope 제외 | 정확한 allowlisted skip만 좁게 `SUPPORTED`; 그 외 판단 불가 |
| 10 | Semgrep ignore/skip | skip 상세를 실제 수집했을 때만 절차 관찰; 미수집은 unknown |
| 11 | Partial 검사 | Finding 집합 차이는 제한 관찰; aggregate `INCOMPARABLE` |
| 12 | 생략 Finding | aggregate `INCOMPARABLE`; 생략 0 조건 미충족 |
| 13 | 파일시스템 동시 변경 | 입력 근거 미수집; `UNDETERMINED` |
| 14 | 불완전 Snapshot | 일반 Snapshot 자체가 미구현; `UNDETERMINED` |
| 15 | 동일 ID, 내용 변경 | `shared`; 내용 동일성 판단 불가 |
| 16 | 복수 원인 가능 | 강제 선택 금지; `UNDETERMINED` |
| 17 | 원인 증거 전부 부족 | `UNDETERMINED` 또는 Gate 부족 시 `INCOMPARABLE` |
| 18 | 정상 검사 Finding 0건 | 결과 0건만 기록; 안전성 주장 금지 |

이번 단계는 원인 정확도나 탐지율을 측정하지 않았다. 잘못된 자동 해결 결과가 없도록 고정 상태, 무근거 차단, synthetic 테스트를 검증했다.

## 테스트 및 실제 Semgrep 확인

테스트 파일 `tests/test_finding_disappearance_evaluator.py`는 동일/shared, currentOnly/baselineOnly, 명시 skip, scanned/skipped 충돌, skip 미수집/unavailable, partial·실패·timeout·output limit·생략, target/profile/version/invocation/rule-file mismatch, invalid manifest/binding/count/duplicate/path, missing finding path, deterministic ordering, immutable input, 민감값 비노출, 출력 크기 실패를 확인한다.

실제 Semgrep 1.182.1 테스트는 격리된 합성 `stable.js`에서 3회 실제 실행한다. 같은 코드를 두 번 스캔하면 shared Finding ID가 관찰되지만 code identity는 미확정이다. 그 뒤 합성 파일을 안전한 비매치로 바꾸고 재검사하면 baselineOnly가 되며, fixture 작성자가 변경 사실을 알아도 결과는 `UNDETERMINED`다. 일반 코드 snapshot을 만들거나 Semgrep을 평가 목적으로 추가 실행하지 않는다. 명시적 skip 검증은 C1 allowlist 구조의 독립 synthetic Manifest fixture이며, 제품 기본 CLI가 skip을 실제 수집한다고 주장하지 않는다.

## 검증 기록

실행 환경: Python 3.12.7, uv 0.11.26, Semgrep 1.182.1, Node.js 24.22.2, npm lockfile 설치.

| 검증 | 결과 |
| --- | --- |
| `uv lock --check` | PASS |
| ER-C2 evaluator 단위 및 실제 Semgrep 테스트 | 29 passed. 합성 파일에 대해 동일 Finding 재관찰 후 safe non-match 재검사 시 baselineOnly 및 UNDETERMINED 확인 |
| Python 전체 (`PYTHONPATH=tests uv run --locked python -m pytest -q -rs`) | 608 passed, 28 skipped, 경고 1개, 258.90초 |
| CI Semgrep 1.182.1 integration 묶음 | 46 passed, 경고 1개, 182.56초 |
| TypeScript typecheck | PASS |
| Vitest 전체 | 180 passed |
| Production build | PASS |
| Chromium browser 전체 | 49 passed. axe 7개 포함 |
| Playwright WebKit | 2 passed. 실제 Safari 검수가 아님 |
| Safari QA 자동 회귀 | 7 passed. QA 실행/종료 검증이며 수동 Safari 수용이 아님 |
| 실제 FastAPI–Semgrep–Chromium E2E | 2 passed |
| UI 위치 회귀 관찰 | 1440×900 Finding 목록 Y=724.44px, 첫 Finding Y=784.00px |
| `git diff --check` | PASS |

로컬 Python 환경에는 프로젝트 외부의 `tests` 패키지가 설치되어 기본 수집에서 `tests.benchmark` import가 충돌했다. 저장소의 테스트 모듈 import 방식은 유지하고 `PYTHONPATH=tests`만 지정해 전체 테스트를 재실행했으며 성공했다. 임시 `tests/__init__.py`는 시험 후 제거했고 변경 파일로 남기지 않았다.

Linux exact ER-C2 commit CI, 실제 macOS Safari, VoiceOver, iOS Safari, 수동 200% 확대는 아직 수행하지 않았다. Linux CI는 Push 후 확인 대상이다.

## 데이터 수명, 공개 계약 및 ER-C3 조건

Bundle과 Evaluation은 호출자가 메모리에 보유하는 동안에만 존재한다. DB, 파일, log, API DTO, FastAPI endpoint, frontend baseline Snapshot과의 연결은 없다. 두 검사 pair는 내부 코드가 `_scan_with_manifest()` 반환을 유지하는 수명 범위에서 직접 전달해야 한다. 프로세스 재시작 후 조회·복구 기능은 없다.

ER-C3 전에 검토할 조건:

1. 두 실행의 pair 수명을 어떤 내부 소비자가 보유할지와 명시적 폐기 시점
2. 악의적 in-process 구성자까지 막는 강한 provenance가 필요한지, 필요하다면 비밀·서명 및 수명 경계
3. 완전한 scope와 per-file errors/skips를 어떤 Semgrep 출력 계약으로 수집할지
4. immutable scan input과 Rule bytes/loading identity를 얻는 안전한 방법
5. snapshot/digest의 source privacy, retention, correlation 위험 및 접근 제어
6. 고정 fixture와 실제 Semgrep 버전별 결과를 함께 유지하는 방법
7. 기존 API/Phase 8L과 호환되는 별도 승인된 소비 계약

ER-C2에서 공개 API/UI, 영구 저장, 원격 업로드, 자동 취약점 해결 판정은 구현하지 않았다.
