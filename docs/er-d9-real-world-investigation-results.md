# ER-D9 실제 조사 결과

대상과 원본 Finding 출처는 [선정 기록](er-d9-real-world-target-selection.md)을 따른다. 아래 관찰은 실제 Semgrep과 FastAPI 응답이며, UI 검증은 자동 Chromium 조작이다. 사람의 수용으로 기록하지 않는다.

| 시나리오 | 통제 조건 | 결과 |
| --- | --- | --- |
| A 원본 | 변경하지 않은 EJS `lib/esm` | v1 완료, 동적 실행 패턴 Finding 2건 |
| B 코드 변경 | 격리 사본에서 첫 `new Function` 호출 표현을 `globalThis.Function` 호출 표현으로 변경 | 기준만 1, 양쪽 1, 현재만 0; 완료, `UNDETERMINED` |
| C Ignore | 별도 격리 사본에서 `ejs.js`를 `.semgrepignore`에 추가 | 기준만 2, 양쪽 0, 현재만 0; `PARTIAL`, `INCOMPARABLE` |
| D 동일 규칙 | 별도 격리 사본에서 같은 선택 규칙 파일 바이트 사용 | 양쪽 2, `SAME_SELECTED_BYTES` |
| D 주석 변경 | 별도 규칙 사본에 주석만 추가 | 같은 Finding ID 2건, `DIFFERENT_SELECTED_BYTES` |

B에서 실험자의 `git diff --no-index`는 통제한 표현 변경을 별도로 확인했다. 해당 변경은 여전히 동적 함수를 호출할 수 있으며 안전성이나 수정 완료를 나타내지 않는다. ER의 소스 스냅샷은 미수집이다. 현재 `ejs.js`는 처리 경로로 보고됐지만 모든 규칙의 완료나 미관찰 원인을 증명하지 않는다.

C에서 두 기준 Finding은 `PATH_EXPLICITLY_SKIPPED`, Skip 가설 `SUPPORTED`였다. 내부 Registry의 제한된 관찰에서 `semgrepignore_patterns_match`를 확인했다. 공개 Evaluation은 구체적 사유를 전달하지 않으므로 UI가 특정 Ignore 파일을 직접 관찰했다고 표현하지 않는다. 일반 Comparator는 부분 검사를 차단했다. Gap Map은 경로 제외와 Ignore 설정·파일 포함 여부 확인을 제안했다. Rule Bytes는 부분 검사라 `UNVERIFIED`였다.

하네스 출력의 `ordinary_comparison`은 검사 완료 여부에 따른 연구용 간략 투영이다. 실제 Comparator 실행 결과로 측정한 값은 아니다. C의 부분 검사 차단은 별도의 실제 Chromium UI에서 확인했다.

D에서 같은 프로필 ID와 같은 Finding 집합은 선택 파일의 같은 바이트를 보장하지 않았다. 각 Equality 응답은 원시 Digest를 공개하지 않았다. 이 결과는 Semgrep의 전체 Loaded Rule Inventory, 규칙 적용 완료, 소스 변경 원인 또는 취약점 해결을 증명하지 않는다.

실제 Chromium은 조사 모드 선택, 기준·현재 실행, 일반 비교 차단, 서버 평가, Rule Bytes `UNVERIFIED`, Gap Map, Finding별 경로와 후속 작업, 증거 해제를 수행했다. 서버 Session은 해제 후 404였다. 분석가가 문구를 이해했거나 작업을 선택했다는 사용자 증언은 없다.

재현: 저장소 루트에서 Python 3.12.7·Semgrep 1.182.1을 준비하고 `uv sync --locked --group dev`, 프런트엔드에서 Node 24로 `npm ci` 및 `npm run build`를 실행한다. 이후 `uv run python scripts/evaluate_er_d9_real_world.py --browser`를 실행한다. 하네스는 고정 공개 커밋을 다운로드하고 테스트 소유 임시 사본을 정리한다. 네트워크가 없거나 upstream 커밋을 가져올 수 없으면 실패한다. 원시 응답·Token·Handle·Digest·소스는 결과 파일에 저장하지 않는다.
