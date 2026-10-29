# Phase 6E — Held-out SAST 평가 및 Security Coverage Gap 분석

## 요약

Phase 6E에서는 이전 평가 fixture와 다른 합성 코드 60개를 사전 등록하고, 변경하지 않은 규칙을 Semgrep OSS 1.182.1로 실행했다. Oracle 수정 기록을 반영한 점수화 대상에서는 6개 규칙 집합 모두 case-level TP/FP/FN/TN이 각각 다르게 관찰됐지만 FP와 FN은 없었다. 이 결과는 각 규칙의 명시된 Rule Signal 범위와 작은 합성 집합에 한정된다.

Rule Signal 결과만으로 실무적 가치를 판단할 수는 없다. 전체 60개 중 중복되지 않는 `review_worthy` 사례는 25개였으며, 12개는 선언된 범위 안, 13개는 범위 밖이었다. 범위 안의 review-worthy positive는 모두 매치됐지만 범위 밖 review-worthy 사례 중 12개는 해당 규칙 Finding이 보고되지 않았다. 이는 실제 취약점 Recall이 아니라 작성자가 사전에 기록한 제한적 관련성·범위 라벨을 기준으로 한 coverage gap이다.

실제 취약점, 배포 환경, 실제 프로젝트 정확도 및 사람 대상 사용성은 평가하지 않았다(`NOT_EVALUATED` / `NOT_TESTED`). 독립 검토자는 없었고 평가 작성자는 이전 규칙과 Phase 6A–6D 결과에 노출되어 있다.

## 시작 기준과 실행 환경

- Phase 6D 기준 SHA 및 시작 HEAD: `1ad3c917241dd60f075a9683fcb00d8a1385d362`
- 시작 시 `origin/main`도 같은 SHA였고 working tree는 깨끗했다.
- Phase 6D exact-SHA GitHub Actions: 성공, run `40841287202`.
- Python `3.12.7`, Semgrep OSS `1.182.1`.
- 기준 전체 회귀: `501 passed, 28 skipped, 0 failed`; skip은 사전 설정이 필요한 기존 Ollama opt-in 테스트였다.
- Python 회귀 명령: `SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 uv run --locked python -m pytest -q -rs`.

| 규칙 파일 | SHA-256 |
| --- | --- |
| `rules/security-baseline.yml` | `bfeb93c42ad942fda138dff3a9be8f4ccc1b137a2b547b6b29b65d98fc70a1a3` |
| `rules/experimental/javascript-eval-taint.yml` | `6c0274e4c1829b55ef26361953be3d0ed9af56384fcd63968317a5e7c7ad8e8e` |
| `rules/experimental/javascript-command-injection-taint.yml` | `abcbe9cb181986861c1c8597b0828e14caf839d5283ad27d9e4646ce69893783` |

기존 평가 Oracle은 수정되지 않았다.

| 기존 집합 | Oracle SHA-256 |
| --- | --- |
| Phase 6A | `d5c10325bb0ce38f9187739afb704287de1cdbab94e879d57ade152eb05e1747` |
| Phase 6B | `37cfcd625d6d3e4029474f61809afc04e13a350e8254cd0572fca8dfd0eaba18` |
| Phase 6C | `4a677997c3a0c8fee4a80cd4f04ddb22879f5fa8c3e4f82f87a615e507c94ce1` |
| Phase 6D 최종 Oracle | `0d70ef57a247e31bb8bbea1258069a649ae5ead764f2a423e938c7e05e0c4ea8` |

## Corpus와 독립성

데이터는 `tests/benchmark/phase6e/`에 5개 유형별 12개씩 총 60개로 구성했다. JavaScript dynamic eval, React dangerous HTML, Firestore write, eval taint, Node command injection을 포함한다. 모든 코드는 이 작업에서 직접 작성한 합성 입력이다. 외부 저장소, 실제 프로젝트, 운영 비밀정보를 사용하지 않았으며 코드는 정적 분석만 했다.

Oracle은 규칙의 문법 범위와 각 코드의 의미를 바탕으로 Semgrep 실행 전에 작성했다. manifest는 사례 경로·파일 SHA-256·규칙 SHA-256을 고정한다. 첫 사전등록 커밋은 `aad91c1445a659f8ad2f9f7a44a661bf6e906cfd`이며 push하지 않았다.

| 항목 | 값 |
| --- | --- |
| Evaluation set | `phase6e-heldout-synthetic-v1` |
| 사례 수 | 60 (유형별 12) |
| 최초 사전등록 manifest SHA-256 | `d978d326eaabfa3050e1276f1208bb3b1a8f4ff26938a988e08f4fcf366a72fd` |
| 최종 manifest SHA-256 | `0aa7c9ebf89f9f79ce737db7595cd2b795c989aa5f7de825f1a54d8e5e005c24` |
| 최초 사전등록 Oracle SHA-256 | `0fb9e05cebe47b25b26f9926096d2afee18ccb5a1c9cfbfea73e102c606fe2a5` |
| 신호 정정 후, metadata 정정 전 Oracle | `8d1c8276d8024e3ad014b9e99c1eb7d656a4cd132afc2122fc1eb40626a21136` |
| 최종 Oracle SHA-256 | `b62dd1b912305d199a640493a2ad1fae00917b65cb87450cd74e561cbb2b54fb` |
| 정정 기록 SHA-256 | `3c7530b82efc1823019962d201d74b2330d1a34657c1b407934177a8dfeadbfa` |
| 독립 리뷰 | `INDEPENDENT_REVIEW_NOT_PERFORMED` |

평가 작성자는 Phase 6A–6D 규칙, fixture, Oracle, 결과와 보고서를 사전에 모두 볼 수 있었다. 따라서 이 corpus는 이전 fixture 파일을 재사용하지 않은 새로운 집합이지만, 독립 전문가가 만든 완전한 held-out set은 아니다. 관련성 라벨은 단일 작성자의 판단이며 전문가 합의율은 없다.

### Oracle 정정 이력

첫 Semgrep 실행 후 `EJX04_worker_transform`에서 Oracle의 범위 라벨 오류를 확인했다. 코드는 `Function(sourceText)()`를 호출하며 `new`가 없다. JavaScript 동작상 동적 코드 생성에 해당할 수 있지만 baseline Rule Signal은 `eval(...)` 또는 `new Function(...)`의 직접 패턴으로 제한된다. 첫 Oracle은 이를 positive로 기록해 첫 실행에서 FN 1건으로 계산했다.

첫 Oracle과 첫 결과는 각각 `oracle-v1-original.json`, `results/oracle-v1-original-evaluation.json`에 보존했다. 코드는 변경하지 않고 해당 사례를 `out_of_scope / unsupported_pattern`으로 정정했으며 변경 이유와 전후 지표를 `oracle-corrections.json`에 기록했다. 그 결과 dynamic-eval 점수는 TP=5, FP=0, FN=1, TN=4에서 TP=5, FP=0, FN=0, TN=4로 바뀌었고, 해당 사례는 review-worthy 범위 밖 gap으로 남았다. 이 수정은 첫 결과에 맞추기 위한 성능 조정이 아니라 규칙의 사전 명시 범위와 사례의 불일치를 바로잡은 것이다.

실행 후 metadata 검토에서 React 범주의 `.jsx`와 `.tsx` fixture가 모두 `typescript`로 기록된 것을 확인했다. `manifest-v1-original.json` 및 signal 정정 직후의 Oracle을 보존하고, manifest/Oracle language를 실제 fixture 확장자에 맞게 정정했다. 이는 parser 입력 파일, 사례, 신호 라벨, expected location을 변경하지 않는다. 이 metadata 정정 전후 artifact와 사유도 같은 correction record에 남겼으며 최종 manifest·Oracle 해시를 사용해 재실행했다.

정정 Oracle을 사용한 첫 평가 JSON은 관련성 집계가 교차 범주 Finding을 범주별로 분리하지 못해 보존만 하고 최종 결과로 사용하지 않았다. 이후 language metadata를 정정한 manifest/Oracle을 사용해 평가기를 다시 실행했다. `results/evaluation.json`은 마지막 해시 고정 기준으로 수행한 최종 결과다. 결과 이력과 해시는 `tests/benchmark/phase6e/results/README.md`에 있다.

## 방법과 점수 정책

평가기는 기존 `SemgrepAdapter`와 세 개의 trusted local rule profile을 사용한다. 입력은 격리된 임시 디렉터리로 복사한다. Semgrep OSS 1.182.1, `--oss-only`, `--no-autofix`, metrics off, version check off, 기존 60초 timeout과 2 MiB 출력 제한을 유지했다. 어떤 fixture 명령이나 함수도 실행하지 않았다.

Case-level과 Finding-level 결과를 분리하고, 예상 위치·cardinality, 중복 Finding, 예기치 않은 rule ID, unmapped Finding, 교차 범주 매치, scan status를 확인한다. 실패하거나 부분 완료된 scan, 버전 불일치, Finding 경로 연결 실패, unverified 외 상태가 있으면 점수를 사용할 수 없게 한다. OOS 사례는 TP/FP/FN/TN에서 제외한다. 비점수 교차 범주 매치는 별도 관찰한다.

`Security Review Relevance`는 보고된 범주 내 Finding을 `review_worthy`, `lower_priority`, `undetermined`로 나눈 제한적 사례 판단이다. 지원된 Rule Signal이 실제 HTTP 입력, 데이터 흐름 도달성, sanitizer 효과 또는 취약점을 입증하지는 않는다. Coverage gap은 review-worthy 사례에서 선언된 규칙 범위와 지원되지 않는 형태·흐름·문맥을 별도로 집계하며 실제 취약점 재현율이라고 부르지 않는다.

## Rule Signal 결과

아래는 **case-level** 결과다. 각 범주 12건 중 OOS를 제외한 사례 수가 점수 분모다. 모든 score-eligible Finding은 정확한 예상 위치에서 한 번씩 나타났고 Finding-level 지표도 동일했다.

| 규칙 | Positive / Negative / OOS | TP | FP | FN | TN | Precision | Recall | FPR | 위치 불일치 / 중복 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `baseline.javascript-dynamic-eval` | 5 / 4 / 3 | 5 | 0 | 0 | 4 | 1.00 | 1.00 | 0.00 | 0 / 0 |
| `baseline.react-dangerous-html` | 5 / 3 / 4 | 5 | 0 | 0 | 3 | 1.00 | 1.00 | 0.00 | 0 / 0 |
| `baseline.firestore-unconditional-write` | 3 / 7 / 2 | 3 | 0 | 0 | 7 | 1.00 | 1.00 | 0.00 | 0 / 0 |
| `experimental.javascript-eval-taint` | 7 / 2 / 3 | 7 | 0 | 0 | 2 | 1.00 | 1.00 | 0.00 | 0 / 0 |
| `experimental.javascript-eval-taint-with-synthetic-sanitizer` | 6 / 3 / 3 | 6 | 0 | 0 | 3 | 1.00 | 1.00 | 0.00 | 0 / 0 |
| `experimental.javascript-command-injection-taint` | 3 / 3 / 6 | 3 | 0 | 0 | 3 | 1.00 | 1.00 | 0.00 | 0 / 0 |

이 작은 합성 집합에서는 점수화된 Rule Signal 오탐/미탐이 관찰되지 않았다. 이것은 100% 실무 정확도나 실제 취약점 정밀도·재현율을 의미하지 않는다. 고정 규칙 범위에 맞춘 60개 합성 사례의 결과다.

## Security Review Relevance

다음 표는 각 규칙 범주에 연결된 **실제 보고 Finding**의 관련성 라벨이다. 범주 밖 baseline eval 매치 8건은 아래 표에 섞지 않고 다음 절에서 별도 기록했다. OOS 사례에서 발생한 매치는 포함되어 있고 별도 표시한다.

| 규칙 | 보고 Finding: review-worthy | lower-priority | undetermined | lower-priority 비율 | undetermined 비율 |
| --- | ---: | ---: | ---: | ---: | ---: |
| JavaScript dynamic eval | 2 | 3 | 0 | 60.0% | 0.0% |
| React dangerous HTML | 2 | 2 | 1 | 40.0% | 20.0% |
| Firestore unconditional write | 3 | 0 | 1 | 0.0% | 25.0% |
| Eval taint | 2 | 1 | 4 | 14.3% | 57.1% |
| Eval taint + synthetic sanitizer model | 2 | 1 | 3 | 16.7% | 50.0% |
| Command injection taint | 4 | 0 | 0 | 0.0% | 0.0% |

Dynamic-eval의 고정 표현식 사례는 직접 규칙 매치로는 유효하지만 낮은 우선순위로 라벨링됐다. React 정적 HTML도 같은 구분이 필요하다. Eval taint의 네 건은 객체 필드 모양이 Source 패턴과 일치해도 실제 HTTP 요청인지 확인할 수 없어 `undetermined`다. Synthetic sanitizer 규칙은 `syntheticSafe` 모델 가정을 적용한 결과이며 실제 정제 안전성 평가가 아니다. Command Injection의 review-worthy 4건 중 하나는 OOS 로컬 alias 사례에서 나온 매치다.

## Security Coverage Gap

중복되는 두 eval-taint 규칙을 별도 점수화하므로 단순 합계하면 사례 수가 중복된다. 아래는 **5개 원래 유형 기준의 고유 사례** 집계다. Eval sanitizer 보조 규칙은 독립 추가 유형으로 세지 않았다.

| 유형 | 전체 review-worthy | 선언 범위 안 | 범위 밖 | Finding 미보고 review-worthy | 주요 gap |
| --- | ---: | ---: | ---: | ---: | --- |
| JavaScript dynamic eval | 4 | 2 | 2 | 2 | `Function()` 호출, constructor alias |
| React dangerous HTML | 5 | 2 | 3 | 3 | props 객체, DOM sink, `createElement` |
| Firestore | 4 | 3 | 1 | 1 | 지원 파일명 밖의 설정 문맥 |
| Eval taint | 5 | 2 | 3 | 3 | 다른 Source property, helper 및 파일 경계 |
| Command injection | 7 | 3 | 4 | 3 | `spawn`, helper 경계, 다른 Source property |
| **고유 전체** | **25** | **12** | **13** | **12** | 아래의 보수적 OOS 매치 1건 포함 |

지원 범위 안 review-worthy 사례 12건은 모두 Finding으로 보고됐다. 지원 범위 밖 review-worthy 사례 13건 중 12건은 현재 규칙에서 보고되지 않았다. 나머지 하나인 `CIX11_local_alias`는 Oracle상 `unsupported_pattern`으로 미리 분류했지만 실제 Semgrep은 Finding을 보고했다. 이를 FP나 범위 안 TP로 재분류하지 않고 OOS 매치로 기록했다. 별칭 변형이 규칙의 선언된 sink 문맥과 어떻게 연결되는지 후속 평가에서 확인해야 한다.

다른 OOS 관찰은 `FSX10_unclosed_comment`이다. lexical validator는 닫히지 않은 주석 문맥을 확정하지 못해 Semgrep 후보를 유지했다. 이 사례는 `undetermined / insufficient_information`이며 유효하게 배포된 Firestore 선언이라는 증거가 아니다. 불확실한 문맥에서 Finding을 조용히 제거하지 않는 현재의 fail-closed 동작을 보여준다.

### 보고되지 않은 review-worthy 사례

- Dynamic eval: `EJX04_worker_transform`, `EJX11_alias_constructor`
- React HTML: `RHX04_notice_content`, `RHX09_dom_api`, `RHX10_create_element`
- Firestore: `FSX09_alt_filename`
- Eval taint: `ETX07_alternate_field`, `ETX08_helper_boundary`, `ETX10_cross_file`
- Command injection: `CIX07_spawn_api`, `CIX08_helper_boundary`, `CIX09_other_property`

이것들은 이 평가에서 보안상 무관하거나 안전하다고 확인된 사례가 아니다. 표시된 gap 유형 및 제한된 문맥 안에서 review-worthy로 사전 분류됐으나 현재 규칙의 지원 범위 밖이었다.

## 교차 범주 및 관찰된 한계

Baseline profile은 총 22건을 보고했고, 이 중 8건은 eval-taint 범주 fixture에서 `baseline.javascript-dynamic-eval`이 직접 구문 매치로 보고한 교차 범주 신호였다. 3건은 review-worthy, 1건은 lower-priority, 4건은 undetermined로 사전 라벨링됐다. 이를 eval-taint 흐름 증거나 해당 유형의 Rule Signal 점수로 합산하지 않았다.

전체 profile별 scan은 baseline 22건, eval taint 13건, command injection 4건으로 모두 `completed`, exit code 0, Semgrep 1.182.1이었다. 지원되지 않은 rule ID 0, unmapped Finding 0, Finding ID 중복 0, 점수 대상 위치 불일치 0이었다. 모든 Finding은 `unverified`였다. OOS 관찰 두 건은 앞 절의 FSX10 및 CIX11이며, OOS match는 점수 대상 오탐으로 계산하지 않았다.

관찰된 실무적 제한:

- Direct pattern 규칙은 고정 코드나 검토 우선순위가 낮은 동적 실행 사용도 보고한다.
- Eval taint Source는 `$REQ.query.code` / `$REQ.body.code` 구조를 모델링하며, `$REQ`의 식별자만으로 HTTP 요청이나 외부 제어를 증명하지 않는다.
- Helper·cross-file 흐름, 다른 입력 필드, 다른 프로세스 API가 범위 밖인 경우에도 안전을 의미하지 않는다.
- React JSX 규칙은 `createElement`, 별도 props 객체 및 직접 DOM sink를 포괄하지 않는다.
- Firestore lexical 문맥 검증은 완전한 Firebase Rules parser/compiler가 아니다. 불완전 문법의 매치는 불확정 상태에서 유지될 수 있다. 배포 여부·상위 match의 최종 효과·실제 접근을 평가하지 않았다.
- Command 규칙의 한정된 Source/Sink 모델과 OOS alias 관찰은 더 넓은 Node 실행 API 지원을 입증하지 않는다.
- `syntheticSafe`는 평가 전용 sanitizer 가정이다.

## 재현과 회귀

실제 평가 명령:

```sh
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
  uv run --locked python tests/benchmark/phase6e/evaluate.py
```

필수 Semgrep 통합 테스트:

```sh
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
  uv run --locked python -m pytest -q -s tests/test_phase6e_benchmark_integration.py
```

실제 통합 테스트 결과: `1 passed` (Semgrep OSS 1.182.1). 최종 `results/evaluation.json` SHA-256은 `7866026609ddb123484ac0e61734a6c97c86151045c03202fe814bbf116a2753`이다. Python 평가기·manifest·Oracle 무결성 테스트는 별도로 포함했다. 평가기 실패/부분 scan, 경로 연결 실패, 예기치 않은 rule ID 또는 Finding 상태 변경은 정상 점수를 반환하지 않으며 FP/FN 자체는 CI 실패 조건이 아니다.

규칙, Firestore lexical validator, Finding/Evidence Gate/Consumer, FastAPI DTO, React UI, CLI 및 공개 JSON 계약은 변경하지 않았다. 최종 로컬 회귀는 `uv lock --check`, `uv sync --locked` 성공, Python 전체 `519 passed, 28 skipped, 0 failed`였다. skip은 기존 opt-in Ollama 테스트다. Node `24.22.2`에서 `npm ci`, typecheck, Vitest `24 passed`, production build, Chromium mock `3 passed`, 실제 Chromium–FastAPI–Semgrep E2E `1 passed`를 확인했다. Phase 6E 필수 Semgrep 통합은 Python 전체 회귀에서 실행되어 통과했고 별도 실행도 `1 passed`였다. Python에서는 기존 Starlette TestClient의 AnyIO alias deprecation warning 1건이 남았으나 실패는 없었다.

CI workflow는 기존 Semgrep job에 Phase 6E 필수 실행 한 단계를 추가했다. Python CI는 전체 pytest로 신규 정적 평가기 테스트를 수집한다. 새 변경은 push하지 않았으므로 Phase 6E 변경 커밋의 원격 GitHub Actions 결과는 아직 없다. 기준 Phase 6D exact-SHA run은 위와 같이 성공했다.

## 결과 해석과 다음 단계

이 corpus의 60건은 규칙 평가에 맞춰 직접 작성되었고, 작성자도 기존 구현을 알고 있었다. 결과는 실제 사용자 코드의 일반화, Firebase 배포 상태, XSS/명령 실행 가능성, 외부 입력 도달성, 실제 취약점 정밀도·재현율 또는 분석가 생산성으로 일반화할 수 없다. 사람 대상 평가도 하지 않았다.

Phase 6F 우선순위:

1. `CIX11_local_alias`의 실제 Semgrep match 근거를 독립 fixture와 AST/taint 출력으로 재현하고, 지원 문서의 alias 범위를 정합화한다. 규칙 변경은 별도 개발 데이터와 미사용 holdout에서 평가한다.
2. Eval taint Source의 식별자/객체 역할과 실제 프레임워크 입력의 차이를 측정한다. 일반 객체 필드가 만드는 낮은 확신도 Finding에 대한 방법을 검토하되, 자동 보안 판단은 하지 않는다.
3. React `createElement`/props 경유 및 Firestore 불완전 lexical 문맥을 대상으로 별도 corpus를 만들고 미탐·불확실성 보존을 측정한다.
4. 규칙 변경 후에는 이 Phase 6E corpus를 개발 회귀 데이터로 취급하고, 새 미사용 holdout과 독립 리뷰를 마련한다.
5. 실제 저장소 데이터가 필요해지는 단계에서는 라이선스·출처·검토 범위를 확정한 뒤 별도 보안·개인정보 절차로 진행한다.

실제 취약점 확인: `NOT_EVALUATED`. 실제 사용자 프로젝트 정확도 및 사람 대상 평가: `NOT_TESTED`.
