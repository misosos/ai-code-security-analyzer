# Phase 6D — SAST generalization and security review relevance

## 요약

Phase 6D는 기존 규칙을 수정하지 않고 새 합성 코드 50개에서 Rule Signal과 제한적인 Security Review Relevance를 각각 평가했다. 모든 유효 스캔은 Semgrep OSS 1.182.1에서 완료됐다. 점수화 대상에서는 FP/FN, 중복, 위치 불일치가 관찰되지 않았다. 다만 이 결과는 직접 작성한 작은 합성 평가 집합에 한정되며 실제 저장소의 취약점 탐지 정밀도나 재현율을 의미하지 않는다.

한 사례(`ET07_alternate_request_name`)의 최초 Oracle 라벨은 규칙 원문을 잘못 해석한 것으로 확인되어 수정했다. 원래 Oracle과 최초 유효 결과를 별도 파일로 보존하고, 정정 이유와 두 Oracle 해시를 기록했다. 규칙, Finding, Evidence Gate 및 Consumer는 수정하지 않았다.

실제 취약점은 어느 사례에서도 평가하지 않았다(`NOT_EVALUATED`). 사람 대상 사용성 평가, 실제 운영 저장소 및 배포 환경 평가는 수행하지 않았다.

## 기준과 실행 환경

- 기준 커밋: `14eccb36046aa2097a8d1f78582b6122bdf378dc`
- 기준 커밋 exact-SHA GitHub Actions: 성공, run `40835114991`
- Python: 3.12.7
- Semgrep: OSS 1.182.1
- 규칙 SHA-256:

| 규칙 파일 | SHA-256 |
| --- | --- |
| `rules/security-baseline.yml` | `bfeb93c42ad942fda138dff3a9be8f4ccc1b137a2b547b6b29b65d98fc70a1a3` |
| `rules/experimental/javascript-eval-taint.yml` | `6c0274e4c1829b55ef26361953be3d0ed9af56384fcd63968317a5e7c7ad8e8e` |
| `rules/experimental/javascript-command-injection-taint.yml` | `abcbe9cb181986861c1c8597b0828e14caf839d5283ad27d9e4646ce69893783` |

평가 명령:

```sh
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
  uv run --locked python tests/benchmark/phase6d/evaluate.py
```

세 프로필은 격리된 임시 디렉터리의 합성 사례만 검사했다. CLI, `SemgrepAdapter`, 외부 Registry 및 네트워크 입력은 평가하지 않았고, 샘플 코드의 명령이나 함수를 실행하지 않았다. Semgrep 60초 timeout과 2 MiB 출력 제한은 기존 Adapter 정책을 사용했다.

## 데이터셋과 Oracle

데이터셋은 `tests/benchmark/phase6d/` 아래에 있다. 50개 case directory를 5개 범주에 각 10개씩 구성했다. JavaScript/TypeScript 파일, JSX/TSX, Firestore `firestore.rules`, 다중 파일 helper 사례를 포함한다. 각 사례의 Rule Signal은 `positive`, `negative`, `out_of_scope` 중 하나이며 Security Review Relevance는 `review_worthy`, `lower_priority`, `undetermined` 중 하나다. 이 두 축은 실제 취약점 판정과 분리했다.

| 항목 | 버전/해시 |
| --- | --- |
| Evaluation set | `phase6d-generalization-v1` |
| Manifest SHA-256 | `3dff49a55a61fede2021afc224f037e53502a77def1f12d3d994893dda4d6cc8` |
| 최종 Oracle SHA-256 | `0d70ef57a247e31bb8bbea1258069a649ae5ead764f2a423e938c7e05e0c4ea8` |
| 최초 Oracle 보관본 SHA-256 | `af911e6c2a02d23e4ce6dcee970931002360ec13c40600964dcdd724f88df2e3` |
| Oracle 정정 기록 SHA-256 | `f0748cf517cfc1ac99e47c77ab9e97319e126c2131931931dc7db24f3b4d5a00` |

Manifest는 각 fixture 파일의 SHA-256도 고정한다. Oracle은 기대 상대 파일·줄·cardinality, 관련성 판단 근거, 알려진 제한을 보유한다. 확인된 취약점 라벨은 만들지 않는다.

### Oracle 정정 이력

초기 `ET07_alternate_request_name`은 `request.body.code`가 `req.body.code`와 다른 식별자라는 이유로 out-of-scope로 라벨링했다. 첫 유효 Semgrep 실행은 두 eval-taint 규칙에서 모두 이 사례를 보고했다. 규칙 원문은 `$REQ.body.code`이고 `$REQ`는 임의 식별자를 받을 수 있으므로, 이 사례는 현재 규칙의 구문적 Source 패턴 범위 안에 있다. 이는 대상이 실제 HTTP 요청인지 또는 외부에서 제어되는 값인지 증명하지 않는다.

원래 파일은 `oracle-v1-original.json`에 보존했다. `oracle-corrections.json`에는 기존·수정 Oracle 해시, 라벨 변경, 이유 및 최초 관찰을 기록했다. 사례를 임의로 제거하거나 규칙 결과에 맞춰 숨기지 않았으며, 수정 후 고정된 최종 Oracle로 전체 평가를 다시 실행했다.

최초 유효 Oracle 결과에서 eval taint는 base 규칙 TP=4, TN=3에 더해 out-of-scope match 1건, sanitizer 모델 규칙은 TP=3, TN=4에 out-of-scope match 1건이었다. 최종 Oracle에서는 해당 사례를 positive로 분류하여 두 규칙의 TP가 각각 5 및 4가 됐고, out-of-scope match는 0건이다. 최초 결과 JSON은 `tests/benchmark/phase6d/results/oracle-v1-original-evaluation.json`에 보존했다. 최초 실행 중 별도로 발생한 평가기 경로 접두사 매핑 오류는 유효 측정으로 인정하지 않았고 아래 평가기 검증 절에 설명했다.

## 평가 대상의 명시 범위

| 유형 | 현재 규칙의 Rule Signal 범위 | 이 평가에서 드러나는 한계 |
| --- | --- | --- |
| JavaScript dynamic eval | `eval(...)`, `new Function(...)` 직접 구문 | alias/wrapper는 범위 밖. 고정 문자열이나 미사용 함수도 문법 매치가 될 수 있다. |
| React dangerous HTML | JSX/TSX의 inline `dangerouslySetInnerHTML={{ __html: ... }}` 형태 | `createElement`, 미리 만든 props 객체, 다른 컴포넌트 안의 sink는 이 패턴 범위 밖. 값의 출처·정제 효과는 판정하지 않는다. |
| Firestore unconditional write | `firestore.rules` 안 쓰기 권한 및 문자 그대로 `if true;`; Adapter의 제한적 주석/문자열 문맥 검사 적용 | 전체 Firebase Rules 문법, 배포 여부, 중첩·상위 권한의 최종 효과는 평가하지 않는다. 불확실한 lexical 문맥은 후보를 유지한다. |
| Eval taint | `$REQ.query.code` 또는 `$REQ.body.code`에서 `eval`까지의 Semgrep taint 흐름 | `$REQ`는 변수 이름을 제한하지 않는다. 실제 요청/외부 입력 여부, 함수 간·파일 간 도달성은 입증하지 않는다. |
| Eval taint + synthetic sanitizer | 위와 같고 `syntheticSafe(...)`를 해당 규칙만 sanitizer로 모델링 | 합성 함수의 실제 정제 안전성을 평가하지 않는다. |
| Node command injection taint | 명시적으로 모델링한 `req.query.cmd`/`req.body.cmd`와 지원되는 Node `child_process.exec`/`execSync` 형식 | 요청 입력 도달성, wrapper·helper·파일 간 흐름, 실행 옵션의 모든 의미를 입증하지 않는다. |

지원 형태는 규칙과 Phase 4A 평가에서 확인된 범위에 한정한다. out-of-scope 결과는 별도 관찰하며 TN/FP로 합산하지 않는다.

## 실제 Semgrep 결과

전체 3회 프로필 스캔 모두 `completed`, exit code 0, Semgrep 1.182.1이었다. Finding 수는 baseline 25, eval taint 9, command injection 4였다. 예상하지 못한 rule ID, manifest에 연결되지 않는 Finding, 중복 또는 점수화 위치 불일치는 없었다.

아래 혼동 행렬은 **case-level Rule Signal**이다. `out_of_scope` 사례는 분모에서 제외한다.

| Rule ID | 사례 P/N/OOS | TP | FP | FN | TN | Precision | Recall | FPR | 중복/위치 불일치 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `baseline.javascript-dynamic-eval` | 6/2/2 | 6 | 0 | 0 | 2 | 1.00 | 1.00 | 0.00 | 0/0 |
| `baseline.react-dangerous-html` | 4/3/3 | 4 | 0 | 0 | 3 | 1.00 | 1.00 | 0.00 | 0/0 |
| `baseline.firestore-unconditional-write` | 5/4/1 | 5 | 0 | 0 | 4 | 1.00 | 1.00 | 0.00 | 0/0 |
| `experimental.javascript-eval-taint` | 5/3/2 | 5 | 0 | 0 | 3 | 1.00 | 1.00 | 0.00 | 0/0 |
| `experimental.javascript-eval-taint-with-synthetic-sanitizer` | 4/4/2 | 4 | 0 | 0 | 4 | 1.00 | 1.00 | 0.00 | 0/0 |
| `experimental.javascript-command-injection-taint` | 4/4/2 | 4 | 0 | 0 | 4 | 1.00 | 1.00 | 0.00 | 0/0 |

분모가 0인 지표는 `null`로 표현한다. 실제 실행에서는 해당 없음. Finding-level 지표도 같은 결과였고 중복은 0건이다.

### Security Review Relevance

다음 수치는 평가 작성자가 사례별로 사전에 기록한 제한적 관련성 판단을 **실제로 보고된 Finding 수** 기준으로 집계한 것이다. 참가자 실험, 복수 전문가 판정, 실제 취약점 검증이 아니다.

| Rule ID | 보고 Finding 중 review_worthy | lower_priority | undetermined | 놓친 review_worthy positive |
| --- | ---: | ---: | ---: | ---: |
| `baseline.javascript-dynamic-eval` | 2 | 3 | 1 | 0 |
| `baseline.react-dangerous-html` | 2 | 1 | 1 | 0 |
| `baseline.firestore-unconditional-write` | 3 | 0 | 2 | 0 |
| `experimental.javascript-eval-taint` | 4 | 0 | 1 | 0 |
| `experimental.javascript-eval-taint-with-synthetic-sanitizer` | 4 | 0 | 0 | 0 |
| `experimental.javascript-command-injection-taint` | 4 | 0 | 0 | 0 |

고정 산술식을 평가한 `EJ01`, 도달성이 확인되지 않은 오래된 helper의 `EJ09`, 상수 표현식의 `EJ10`은 dynamic-eval 패턴으로 보고됐지만 사전 oracle에서는 lower-priority로 분류했다. 고정 HTML 사례 `RH01`도 lower-priority다. 이 분류는 취약점 안전 판정이 아니라 코드 검토 우선순위 가설이다. `syntheticSafe`를 사용하는 `ET04`는 sanitizer 모델 규칙에서 제외됐지만, 실제 보안 정제가 안전하다는 결론은 아니다.

## 교차 규칙 및 실패 관찰

- Baseline 프로필은 25건을 보고했다. 이 중 10건은 `eval_taint` 범주의 사례에서 baseline direct-eval 규칙이 낸 알려진 교차 범주 신호다. 이는 해당 코드에도 실제 `eval(...)` 구문이 있기 때문이며 taint 전파 결과로 세지 않았다.
- 각 평가 범주의 점수화 결과에서 FP와 FN은 0건이다. 점수화된 positive에서 누락된 review-worthy 사례도 없다.
- 최종 Oracle에서 out-of-scope 사례 중 실제 매치는 0건이다. 수정 전 Oracle에서는 ET07이 out-of-scope match로 따로 기록됐다.
- 초기 실행에서 평가기 경로 정규화 버그 때문에 Finding 경로가 case prefix와 연결되지 않았다. 첫 버전은 이를 점수에서 제외하면서 metrics를 유효하다고 표시해 잘못된 결과를 만들 수 있었다. 이 결과는 무효로 폐기했다. 평가기를 고쳐 unmatched Finding이 하나라도 있으면 모든 지표를 unavailable로 만들고, 경로 연결 단위 테스트를 추가했다. 같은 고정 Oracle로 다시 실행한 유효 결과가 이 문서 표다.

## 기존 Phase 6A와 비교

Phase 6A와 Phase 6D는 독립된 합성 집합이며 표본 구성·범위가 달라 수치를 직접적인 성능 향상으로 해석할 수 없다.

| 규칙 | Phase 6A TP/FP/FN/TN | Phase 6D TP/FP/FN/TN |
| --- | ---: | ---: |
| JavaScript dynamic eval | 5/0/0/5 | 6/0/0/2 |
| React dangerous HTML | 5/0/0/5 | 4/0/0/3 |
| Firestore unconditional write | 4/0/1/5 | 5/0/0/4 |
| Eval taint | 5/0/0/5 | 5/0/0/3 |
| Eval taint + synthetic sanitizer | 4/0/0/6 | 4/0/0/4 |
| Command injection taint | 4/0/0/6 | 4/0/0/4 |

Phase 6A Firestore의 F02는 Phase 6B에서 규칙을 수정한 뒤 Phase 6D 시점에는 미탐이 아니었다. 따라서 이 차이는 Phase 6D의 독립 테스트에서 같은 코드가 일반화됐다는 증거가 아니며, 기존 규칙 버전도 다르다.

## 평가기 및 정보보호

평가기는 manifest와 Oracle의 고정 hash/version, 각 fixture 파일의 개별 SHA-256, 파일 경로 범위, Oracle의 라벨·위치·cardinality를 검증한다. 잘못된 위치, unmapped Finding, 예상하지 못한 rule ID, partial/failed scan, Semgrep 버전 불일치는 정상 점수를 반환하지 않는다. out-of-scope 매치는 별도로 기록한다. FP/FN이 발견돼도 CI 자체는 실패시키지 않는다.

출력에는 규칙 ID, case ID, 집계, 제한된 상대 파일·줄 관찰만 포함한다. 코드 내용, Semgrep 자유 형식 메시지, 원본 JSON, 절대 경로 및 비밀값은 보고하지 않는다. 모든 입력은 합성 값이며 실제 비밀정보가 없다.

## 한계와 Phase 6E 권고

현재 점수는 범위가 좁고 규칙의 직접 구문을 반영해 작성된 50개 synthetic cases 결과다. 일부 라벨 정정 이력 자체가 소스 정의를 Oracle에 정확히 반영하는 일의 중요성을 보여준다. 실제 애플리케이션의 프레임워크 문맥, build·deployment, 함수 호출 그래프, validation/sanitizer 구현, 런타임 도달성은 포함하지 않는다. 사람의 업무 시간이나 이해도는 측정하지 않았다.

Phase 6E 권고:

1. 규칙과 개발자가 사용한 데이터에서 완전히 분리된 held-out 평가 집합을 사전 등록하고, Oracle을 별도 리뷰로 고정한다.
2. 공개 코드가 필요하면 라이선스·출처·범위를 확인한 소규모 정적 저장소를 승인 절차와 함께 사용하고, 외부 clone은 격리된 네트워크 없는 환경에서 수행한다.
3. eval/React 규칙의 syntactic match와 낮은 우선순위 사용을 구분하는 우선순위 표현을 조사하되, 이번 단계 결과만으로 규칙 변경을 정당화하지 않는다.
4. eval-taint의 `$REQ`가 임의 식별자에 매치되는 범위와 실제 HTTP Source 인식 문제를 별도 평가한다.
5. helper·다중 파일 흐름과 React `createElement`/전처리된 props 사례를 명시적으로 라벨링하고, 미지원은 안전 판정과 분리한다.
6. Firestore는 emulator/deployed rules 검증을 별도 작업으로 설계한다. 현재 lexical validator와 Rule Signal만으로 배포 권한 효과를 확인할 수 없다.

## 검증

- Phase 6D 평가기 단위 및 실제 Semgrep 통합: `15 passed` (14 unit + 1 real integration).
- 전체 Python 회귀: `501 passed, 28 skipped, 0 failed`; skip은 기존 opt-in Ollama 테스트이고 실제 모델을 호출하지 않았다.
- 전체 회귀 명령: `SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 uv run --locked python -m pytest -q -rs`.
- Semgrep 통합: 전체 회귀에서 기존 Phase 6A/B/C, Firestore context, 신규 benchmark 통합을 모두 실행했다. 별도 Phase 6D 통합도 Semgrep OSS 1.182.1에서 완료됐다.
- Frontend: `npm ci` 성공, `npm run typecheck` 성공, `npm test` 24 passed, `npm run build` 성공.
- Chromium: mock browser 3 passed; 실제 Chromium–FastAPI–Semgrep E2E 1 passed.
- `uv lock --check`, `uv sync --locked`, `git diff --check` 통과.
- Phase 6D 결과 JSON: 최초 Oracle 실행은 `tests/benchmark/phase6d/results/oracle-v1-original-evaluation.json`, 정정 후 고정 최종 Oracle 평가는 `tests/benchmark/phase6d/results/evaluation.json`에 보존했다. 둘 다 코드 본문, Semgrep 원문 메시지, 절대 경로를 포함하지 않는다.
- 기준 커밋 exact-SHA GitHub Actions는 성공(run `40835114991`). 이번 Phase 변경은 push하지 않았으므로 Phase 6D exact-SHA 원격 CI는 미실행이다. CI 설정에는 평가 unit은 기존 Python 전체 회귀에, 필수 실제 평가 통합은 기존 Semgrep job에 추가했다.

테스트 통과와 실제 사용자 저장소에서의 탐지 품질은 별개의 주장이다. Phase 6D는 후자를 평가하지 않았다.
