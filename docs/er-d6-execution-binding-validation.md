# ER-D6 — 실행 입력 연결 검증

## 기준과 환경

- 기준 SHA `7e5864a250af8072b56a4952ca8c2230cf6da918`; GitHub Push CI `42175095045`: completed/success, 세 필수 Job 성공, artifacts 0.
- Python 3.12.7, Semgrep OSS 1.182.1, Node.js 24.22.2, uv 0.11.26, macOS arm64.
- 입력은 테스트 소유 임시 JavaScript/Firestore 파일과 기존 baseline 규칙의 격리 사본이다. 저장소의 baseline 원본은 수정하지 않았다.

## 실제 Semgrep 실험

`tests/test_rule_bytes_identity.py::test_real_semgrep_copy_binding_and_rule_id_compatibility`는 실제 Adapter와 Semgrep을 사용한다.

| 사례 | 실행된 입력 | 관찰 |
| --- | --- | --- |
| 같은 바이트 | 독립 private 실행 두 번 | `SAME_SELECTED_BYTES`; 원본 경로 실행과 사본 실행의 Rule ID/Finding ID/상대 경로가 일치 |
| 다른 바이트 | baseline 사본의 severity를 변경 | `DIFFERENT_SELECTED_BYTES`; 시험 대상 Finding ID projection은 일치 |
| 주석만 변경 | baseline 사본에 YAML 주석 추가 | `DIFFERENT_SELECTED_BYTES`; Finding ID projection은 일치 |
| 잘못된 YAML | 유효하지 않은 합성 설정 | Semgrep 실행 실패; byte 비교 `UNVERIFIED` |
| Ignore 대상 | 조사 verbose 실행에서 합성 파일을 `.semgrepignore`로 제외 | 기존 Skip path/reason을 관찰하고 `PARTIAL`을 유지; byte 비교는 `UNVERIFIED` |

합성 JavaScript와 Firestore Finding을 포함한다. 이 특정 fixture에서 사본 위치 변경이 Rule ID/Finding ID를 바꾸지 않은 관찰이지 모든 규칙·구성에 대한 호환성 증명은 아니다. 다른 규칙 파일 간 상대 참조는 지원 범위에 포함하지 않는다.

## 결정적 경계 테스트

합성 mock/contract 테스트는 사본 생성 뒤 원본 변경 및 교체, 원본 읽기 도중 변경, 사본 쓰기·교체·symlink 전환을 sleep 없이 호출 경계에서 재현한다. 사본 변경은 실패하고, 사본 생성 후 원본 변경은 이미 캡처한 입력을 바꾸지 않는다. 파일 크기 초과·누락·symlink·hard link·모의 permission failure, timeout/output limit/실행 실패, 동일 Run·다른 target/version, 미수집 증거도 확인한다. `TMPDIR` 오염 시 사본 경로가 바뀌지 않는지 확인한다.

실행 중 잠깐 변조 후 복원하는 모든 경쟁, 권한 있는 공격자, OS별 파일시스템 동작은 검증되지 않았다. private digest는 테스트 출력·API 응답으로 내보내지 않는다. 기존 Adapter의 환경 격리 테스트는 임의 환경변수가 Semgrep subprocess에 전달되지 않는지 확인한다. PATH 기반 실행 파일 신뢰와 OS 네트워크 격리는 별도 한계다.

## 기존 계약

v1/CLI와 v2 조사 경로는 새 함수를 호출하지 않는다. C1 `RuleEvidence` 필드와 의미, C2 Evaluation v1, Registry strict v1, Run TTL/Release, D4 Skip Evidence는 수정하지 않았다. 새 private observation은 Registry에 저장되지 않으므로 기존 15분 TTL이 적용된다고 주장하지 않는다. 공개 API 및 UI 결과에는 rule digest 또는 equality 필드가 없다.

## 실행 기록

최초 병렬 전체 Python 회귀에서 기존 v1 실 Semgrep 테스트가 `timed_out`을 반환했다. 해당 실행은 중단했으며 실패로 기록한다. 중간 전체 실행 두 개는 각각 사본 임시 경로/환경 경계와 부분 실행 처리의 보강을 위해 의도적으로 중단했으며 완료 결과로 세지 않는다. 최종 코드로 부하를 줄여 전체를 다시 실행해 통과했다.

- `SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 PYTHONPATH=tests uv run --locked python -m pytest -q`: **668 passed, 28 skipped**, Starlette deprecation warning 1개. 실제 Semgrep integration과 새 테스트 17건이 포함된다.
- `uv lock --check`: 통과.
- Node 24 typecheck, Vitest 18 files / 196 tests, production build: 통과.
- 격리 포트 Chromium 전체: 53 passed, axe 포함. Playwright WebKit: 2 passed.
- 실제 FastAPI–Semgrep–Chromium E2E: 3 passed.
- 기존 Safari QA 자동화: 7 passed. 조사 Safari QA 자동화: 4 passed.
- 실제 macOS Safari, VoiceOver, iOS Safari 수동 수용: 수행하지 않음.
- D1 실 Semgrep 문서 재현과 D2/D3/D5 재현 스크립트: 통과. D4 실제 API/브라우저 경로는 위 전체 회귀에 포함된다.

전체 브라우저 테스트가 새 worktree의 기존 추적 QA 캡처를 재생성해 해당 테스트 생성 변경만 기준 버전으로 복원했다. 브라우저가 만든 미추적 `.taste-skill/`은 stage하지 않고 보존했다. 기존 4173 서버와 다른 worktree는 사용하거나 종료하지 않았다.
