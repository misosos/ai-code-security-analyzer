# Phase 6G — React HTML Sink Coverage Pilot

## 범위와 시작 Gate

기준 커밋은 `c223b2fe6462405bf94c2b7d6f4e198fb176b776`이다. 시작 시 `main`, 로컬 HEAD, `origin/main`, 원격 `main`이 기준 SHA와 일치했고 working tree는 clean이었다. 기준 GitHub Actions Run `40858282647`은 정확한 SHA의 `push / completed / success`였으며 artifact는 0개였다. 필수 Python, Semgrep, React 및 실제 Chromium–FastAPI–Semgrep 작업도 성공했다. Semgrep OSS 버전은 1.182.1이었다.

이번 Phase는 baseline을 변경하지 않고, 변수형 JSX props와 React `createElement` 호출을 별도 실험 규칙으로 평가한다. Fixture는 직접 작성한 합성 코드이며 외부 프로젝트 코드, 실제 사용자 코드, 실행 가능한 XSS payload를 포함하지 않는다. 코드 입력은 실행하지 않았다.

## 기존 React baseline과 Phase 6E 재현

기존 `baseline.react-dangerous-html`은 JSX에서 `dangerouslySetInnerHTML={{ __html: ... }}`가 직접 쓰이는 구문을 찾는다. HTML 값의 출처, sanitizer 효과, 실제 브라우저 동작은 평가하지 않는다. React 문서도 해당 prop을 `{ __html: ... }` 형식으로 설명하고, 신뢰되지 않은 HTML은 XSS 위험을 낳을 수 있다고 경고한다. React `createElement`는 JSX의 대안이며 props 객체를 받는다. [공통 React DOM 컴포넌트 문서](https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html), [React `createElement` 문서](https://react.dev/reference/react/createElement).

Phase 6E의 세 사례를 Semgrep OSS 1.182.1과 기존 baseline으로 다시 실행한 결과는 completed, Finding 0건이었다.

| 사례 | 코드 형태 | baseline 관찰 |
| --- | --- | --- |
| `RHX04_notice_content` | `dangerouslySetInnerHTML` 값이 사전 구성 변수 | 미탐. 직접 inline object 형태가 아님 |
| `RHX09_dom_api` | 일반 DOM `node.innerHTML` | 미탐. React JSX 규칙의 대상이 아님 |
| `RHX10_create_element` | `React.createElement` props 객체 | 미탐. JSX가 아님 |

## 실험 규칙

추가 파일 `rules/experimental/react-html-sink-coverage.yml`의 ID는 `experimental.react-html-sink-coverage`다. 기본 baseline 규칙 집합에 포함되지 않는다. 규칙은 다음의 제한된 모양을 대상으로 한다.

- `react` default import가 있는 JSX에서 단순 식별자 변수로 전달되는 `dangerouslySetInnerHTML` props
- `react` default import 또는 default import alias가 있는 `$REACT.createElement(...)`의 직접 props 객체 안 `dangerouslySetInnerHTML: { __html: ... }`

Semgrep OSS 1.182.1에서 두 형태 모두 실제 fixture로 파싱·매칭되는 것을 확인했다. 구문상 import 문맥과 매치가 확인된 것이며 런타임에서 해당 값이 실제 React binding인지, 실행 경로에서 변조되지 않는지 완전히 검증한 것은 아니다. Source-to-sink 분석이나 sanitizer 평가는 없다.

다음은 제외 범위다: 일반 DOM `innerHTML`, `insertAdjacentHTML`, `document.write`, named `createElement` import, 임의 라이브러리/사용자 정의 `createElement`, helper 함수가 반환한 props, 컴포넌트·파일 간 전달, JSX member expression props, sanitizer의 실제 효과. 일반 DOM sink는 React sink와 별도 규칙 후보로 남긴다.

## Phase 6G 합성 개발 집합

`tests/fixtures/react_html_phase6g/`에는 최종 21개 사례가 있다. Ground truth와 검토 관련성은 해당 사례의 최종 규칙 검증 전에 테스트에 고정했다. 이 집합은 규칙 설계·개발에 사용한 회귀 자료이며 독립 holdout이나 운영 프로젝트 정확도 평가가 아니다. 독립 리뷰는 수행하지 않았다. 모든 사례의 취약점 확정 상태는 `NOT_EVALUATED`다.

| 집합 | 사례 수 | 예시 범위 |
| --- | ---: | --- |
| Positive | 6 | JSX 변수 props, default import alias, TSX, React.createElement 및 alias, 상수 HTML sink |
| Negative | 10 | 타 라이브러리/가짜 React, shadowed parameter, 유사 prop, 일반 객체, 텍스트 노드, 사용되지 않는 HTML, baseline 전용 inline JSX, 잘못된 변수 props 구조 |
| Out of scope | 5 | DOM innerHTML, component props 경계, helper props, named import, JSX member expression |

첫 RED 실행에서 JSX 변수 props는 세 가지 import/JSX 형태에서 매치됐고, 두 `createElement` Positive가 매치되지 않았다. `createElement` 패턴과 React import 문맥을 추가한 후 변수 props에 문자열을 대입한 N10을 hard negative로 추가했다. 초기 실험에서 식별자 props만 보는 패턴이 N10도 보고해 FP가 재현됐다. 같은 이름의 `const` props 값이 `__html` 필드를 포함한 object literal인 경우만 JSX 변수형 지원으로 제한한 뒤 N10 매치가 사라지고 두 `createElement` Positive가 유지됐다. 초기 테스트 작성 중 P1의 기대 줄을 4로 잘못 적은 위치 oracle 오류가 드러나 실제 JSX sink 위치인 5로 정정했다. 사례 라벨·기대 cardinality는 변경하지 않았다.

규칙 개선 전 단계에서 관찰한 개발 결과도 보존한다. 변수형 JSX만 있던 초안은 (TP=4, FP=0, FN=2, TN=9)이었고, `createElement` 추가 후 N10을 포함해 실행한 중간 규칙은 (TP=6, FP=1, FN=0, TN=9)이었다. N10 FP를 근거로 props object literal 문맥을 제한한 최종 규칙 결과는 아래 표와 같다. 이는 반복 사용한 개발 집합 결과이지 별도 독립 평가가 아니다.

## 실제 Semgrep 결과

최종 필수 통합 테스트는 Semgrep OSS 1.182.1을 호출했고 scan status `completed`, exit code 0, issue 0을 확인했다.

| Rule Signal 집합 | TP | FP | FN | TN | Precision | Recall | FPR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Phase 6G Positive/Negative (6/10) | 6 | 0 | 0 | 10 | 1.00 | 1.00 | 0.00 |

분모가 0인 비율은 없었다. 예상한 Positive마다 Finding 하나씩, 총 6건이 보고됐고 중복은 0건이었다. 실제 match line은 P1 5, P2 3, P3 5, P4 3, P5 3, P6 3행이었다. 예상하지 못한 Rule ID와 OOS 사례 매치는 0건이다. Finding은 전부 severity medium, CWE-79, status `unverified`였으며 confirmation은 없었다.

기존 React baseline을 같은 21개 사례에 별도로 실행하면 N8의 직접 inline JSX만 2행에서 1건 탐지됐다. 실험 규칙은 N8을 탐지하지 않았으므로 두 규칙의 중복 매치는 관찰되지 않았다. Phase 6E 사례 3개도 baseline으로 재검사해 0건을 확인했다. 별도 규칙 파일을 각자 실행한 결과이며 기존 CLI의 공개 인터페이스를 변경하지 않았다.

## 검토 관련성

실험 Finding 6건 중 사전 분류는 `review_worthy` 5건, `lower_priority` 1건(P6의 상수 HTML), `undetermined` 0건이었다. 이는 합성 코드에 대한 제한된 수동 판단이며 사용자 효용이나 실제 취약점 정밀도가 아니다. OOS 중 DOM sink와 helper/다른 API 형태에는 검토할 가치가 있을 수 있다고 라벨했지만 이번 React 실험 규칙은 보고하지 않았다. O2 child-component props는 관련성을 undetermined로 두었다.

Rule Signal 결과와 Review Relevance는 별도 지표다. 정적 sink 매치는 외부 입력 출처, 실제 렌더 여부, sanitizer 유효성 또는 XSS 악용 가능성을 입증하지 않는다. 고정 상수 HTML도 문법상 sink로 발견될 수 있다. Finding을 취약점으로 확정하지 않는다.

## 불변성 및 보안 경계

- 기존 `rules/security-baseline.yml` SHA-256은 시작과 동일한 `bfeb93c42ad942fda138dff3a9be8f4ccc1b137a2b547b6b29b65d98fc70a1a3`이다.
- Phase 6A~6F fixture, manifest, Oracle, 결과, taint 규칙과 신뢰 해시는 수정하지 않았다.
- 새 규칙 SHA-256: `a2c70b591a8e7f37b9ad17a88636a9c5ef7259f0bcc6b5946a0893e5ff73cf36`.
- 신규 테스트는 raw Semgrep JSON이나 코드 snippet을 출력하지 않으며 Finding 직렬화 결과에서 합성 canary가 없는지 확인한다.
- 새 public Finding/API/CLI 계약, Gate/Consumer, UI, dependency 및 lockfile 변경은 없다.
- 실제 XSS, 런타임 React binding, HTML 출처, sanitizer, 실제 프로젝트 정확도 및 사용자 사용성은 검증하지 않았다.

## 회귀 검증

- `uv lock --check`, `uv sync --locked`: 통과
- Semgrep 규칙 검증 및 Phase 6G 통합: 통과; Semgrep OSS 1.182.1
- 전체 Python 회귀: `526 passed, 28 skipped, 0 failed`; skipped는 기존 opt-in Ollama 평가
- Frontend Node 24.22.2: `npm ci`, typecheck, production build 통과
- Vitest: `24 passed`
- Chromium mock browser: `3 passed`
- 실제 Chromium–FastAPI–Semgrep E2E: `1 passed`
- `git diff --check`: 통과
- 원격 CI는 변경을 push하지 않았으므로 미실행이다. 신규 테스트는 기존 필수 Semgrep CI job에 연결했다.

## 재현 명령

```bash
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 \
  uv run --locked python -m pytest -q tests/test_react_html_phase6g.py
```

신규 Semgrep 테스트는 `.github/workflows/ci.yml`의 기존 Semgrep 필수 integration 단계에 추가했다. 로컬 검증은 CI 원격 실행 결과와 구분해 기록한다.

## 후속 기준

Baseline 편입 전에는 별도 미사용 사례 평가, import/shadowing 및 다양한 props 구조의 추가 검증, 오탐·중복 조사, 실제 source와 sanitizer 문맥을 판단할 수 있는 근거 계약 검토가 필요하다. DOM XSS는 별도의 Sink 후보로 평가해야 한다. 이번 합성 결과만으로 baseline 자동 편입을 권고하지 않는다.
