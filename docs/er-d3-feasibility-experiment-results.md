# ER-D3 — Feasibility Experiment Results

## 기준과 환경

- 시작 SHA / `origin/main`: `5d23217e140451964d23a0178149111d7f08f92a`
- 기준 push CI: GitHub Actions Run `42032315083`, event `push`, completed/success; Python tests and CLI, React dashboard, Semgrep integration 모두 success; artifacts 0
- 실험 worktree branch: `research/er-d3-evidence-gap-feasibility`
- macOS, Python 3.12.7, Semgrep OSS 1.182.1
- Node.js는 이 환경에서 22.18.0이었다. Frontend 변경이 없고 Node 테스트를 실행하지 않아 Node 24 호환성을 검증한 것으로 보지 않는다.
- 입력은 합성 JavaScript와 `rules/security-baseline.yml`의 격리 사본뿐이다. 원본 규칙 파일의 바이트는 실험 전후 같았다.

## 재현 명령

저장소 루트에서 실행한다. Semgrep은 local baseline rules로만 실행하고 metrics/version check를 끈다. 규칙 다운로드나 사용자 프로젝트 접근은 없다.

```bash
SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
  uv run --locked python scripts/research_er_d3_evidence_gaps.py
```

이 harness는 64 KiB 단일 합성 파일 상한, Semgrep 총 stdout/stderr 2,000,000 byte 상한, 60초 subprocess timeout을 적용한다. 입력은 OS 임시 디렉터리 아래에서 생성하고 종료 시 제거한다. source 원문·raw JSON·hash 값은 출력하거나 파일에 보존하지 않는다. 실패는 예외/비정상 종료로 남고 정상 관찰로 대체하지 않는다.

Harness는 재현 가능한 요약 Projection을 stdout으로 출력한다. 아래는 원시 Semgrep JSON이 아니라 검증된 고정 결과 코드와 합성 파일명만 포함한 요약이다.

## Experiment A — Rule Bytes

### 방법

같은 `baseline` Profile ID와 `security-baseline.yml` selected file ID를 쓰도록 같은 원본 파일을 격리된 두 trusted rules directory에 복사했다. 두 번째 사본에 규칙 의미를 바꾸지 않는 YAML 주석을 추가했다. 각 실행은 `ScanService._scan_with_manifest()`와 실제 `SemgrepAdapter`를 거쳤다.

### 관찰

- 동일 사본을 다시 SHA-256 한 결과는 같았다.
- 주석이 추가된 사본은 원본 사본과 다른 바이트 digest였다.
- Profile ID와 selected file ID는 같았다.
- 두 실제 Semgrep 검사에서 Finding ID/path/rule projection은 같았다.
- 기존 Manifest는 두 실행 모두 bytes identity와 loaded identity를 `UNVERIFIED`로 표시했다.
- Semgrep의 내부 loaded rule inventory는 얻지 못했다.

### 해석

선택 파일 바이트 digest는 선택된 설정 파일 drift를 구별할 수 있다. 같은 Profile ID, 같은 selected file ID, 같은 Finding 집합은 바이트 동일성의 대체물이 아니다. 주석만 다른 파일의 동일 Finding 출력은 rule identity가 같았다는 뜻도 아니다. Semgrep이 실제로 로드한 집합에 관한 정보는 여전히 없다.

## Experiment B — Source Change

### 방법

합성 `stable.js`와 `retired.js`를 baseline 규칙으로 검사했다. 다음 검사 전에 `retired.js`의 합성 `eval(input)`을 `String(input)`으로 바꿨다. harness 외부 실험 관찰로만 파일 digest 차이를 비교했고, 제품 Response/Manifest에는 넣지 않았다.

### 관찰

- 실험자는 두 시점의 합성 `retired.js` 바이트가 달라졌음을 관찰했다.
- `stable.js` Finding은 두 검사에서 관찰됐다.
- `retired.js` Finding은 기준 검사에만 관찰됐다.
- Manifest에는 일반 source digest가 없고 `source_snapshot_not_collected` 제한이 남았다.
- source 원문이나 digest는 출력·저장하지 않았다.

### 해석

실험의 알려진 파일 편집은 Fixture Truth다. 분석기는 해당 digest나 편집을 입력받지 않았으므로 코드 변경을 증명하지 않았다. 별도 파일 read와 Semgrep 파일 open 사이의 TOCTOU가 남고, digest 차이가 Finding 미관찰의 원인이라는 인과 증명도 제공하지 않는다.

## Experiment C — Scope Collection

### 방법

합성 `normal.js`, `.semgrepignore`에서 제외한 `ignored.js`를 준비했다. 첫 실행은 제품 Adapter의 현재 기본 옵션을 그대로 사용했다. 두 번째는 격리 subprocess에서 같은 JSON/metrics/version/OSS/no-autofix 옵션에 `--verbose`만 추가했다. 두 결과 모두 실제 Semgrep 1.182.1 출력이다. verbose JSON은 현재 `_parse_semgrep_json_internal()`과 `parse_scope_evidence()`로 처리했다.

### 관찰

| 필드 | 기본 비-verbose | verbose 실험 |
| --- | --- | --- |
| `paths.scanned` | `normal.js` 보고 | `normal.js` 보고 |
| `paths.skipped` | JSON에 없음 | `ignored.js`, `semgrepignore_patterns_match` |
| `errors` count | 0 | 0 |
| `skipped_rules` count | 0 | 0 |
| Finding projection | dynamic eval Finding | 기본과 동일 |
| Scope completeness | `UNVERIFIED` | `UNVERIFIED` |

현재 parser는 non-empty skipped 목록을 `semgrep_skipped_paths` issue로 만든다. Adapter의 현 상태 매핑대로라면 해당 Scan은 `PARTIAL`이다. 이는 verbose 실험의 직접 JSON 결과와 현재 코드에서 결정적으로 도출한 상태다. 조사 API를 verbose로 실행한 실제 HTTP E2E는 이번 Phase에서 수행하지 않았다.

### 해석

특정 경로의 제외 원인 관찰은 개선되지만 전체 파일 발견, 모든 규칙 적용 또는 검사 완료를 입증하지 않는다. `--verbose`가 있으면 한 실행에서 일부 항목을 더 알 수 있지만 다른 자료의 부재는 여전히 `NOT_COLLECTED`이고 completeness는 계속 `UNVERIFIED`다. Skip 때문에 `PARTIAL`을 `COMPLETED`로 바꾸는 것은 안전하지 않다.

## 실행 이력과 한계

- 첫 integrated harness 시도는 `Finding` 객체를 set에 넣어 비교하면서 `TypeError: unhashable type`로 실패했다. 비교를 `(finding_id, file_path, rule_id)` 고정 projection으로 바꾸고 실제 Semgrep 결과를 재실행했다.
- 수정 후 전체 harness를 두 차례 성공 실행했다. 양쪽 출력에서 세 실험의 판정 코드와 결과가 같았다. 테스트용 token은 매 실행 새 CSPRNG 값이며 출력되지 않는다.
- 별도 scope smoke 실험에서도 기본 JSON에는 `paths.skipped`가 없고 verbose JSON에는 allowlisted ignore reason이 나타나는 것을 확인했다. 재현 harness의 최종 결과는 위 표에 기록했다.
- Scope는 한 Semgrep OSS 버전, 한 합성 JS 프로젝트, 한 ignore pattern에 한정된다. 대규모 프로젝트, 언어 parser 오류, 모든 ignore/exclude 조합, 다른 Semgrep 버전의 JSON 호환성은 검증하지 않았다.
- 파일 변경 동시성 공격, RSS 증가 통계, 다중 프로세스, 외부 launcher, 실제 사용자 코드는 시험하지 않았다.

## 명령과 검증 결과

- `uv run --locked python --version` — Python 3.12.7
- `uv run --locked semgrep --version` — 1.182.1
- `uv lock --check` — 통과
- `SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 PYTHONPATH=tests uv run --locked --group dev python -m pytest -q tests/test_scan_evidence_manifest.py tests/test_semgrep_integration.py tests/test_finding_disappearance_evaluator.py tests/test_investigation_evidence_registry.py tests/test_investigation_api.py` — 99 passed, 기존 Starlette deprecation warning 1개
- 집중 회귀에는 실제 Semgrep 통합 테스트와 Manifest, Evaluator, Registry, API 테스트가 포함된다. 테스트 전체가 실 Semgrep인 것은 아니다.
- Python 전체, Vitest, TypeScript, build, Chromium, WebKit, axe, FastAPI–Semgrep–Chromium 및 Safari QA는 제품 코드가 바뀌지 않은 연구 harness/문서 작업이므로 실행하지 않았다. 새 조사 API verbose 경로의 실 HTTP E2E도 미실행이다.
- `git diff --cached --check` — 통과.
