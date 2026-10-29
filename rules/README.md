# 로컬 보안 기준 규칙

`security-baseline.yml`은 신뢰된 로컬 Semgrep 규칙 3개로 구성한다. CLI에서 명시적으로 선택한다.

```sh
uv run python -m ai_code_security_analyzer scan --path /path/to/local-project --rules rules/security-baseline.yml --format json
```

모든 탐지는 검토 후보(`unverified`)다. 규칙의 심각도는 검토 우선순위이며 실제 악용 가능성이나 취약점 확정 상태를 뜻하지 않는다. Semgrep 원본 메시지와 일치한 코드는 공개 보고서에 싣지 않는다. `example-typescript-eval.yml`은 기존 CLI 데모용으로 유지한다.

| 규칙 ID | 목적과 탐지 근거 | CWE / 심각도 | 대상 | 주요 오탐 가능성 | 놓치는 경우 |
| --- | --- | --- | --- | --- | --- |
| `baseline.javascript-dynamic-eval` | `eval(...)` 또는 `new Function(...)`의 직접 호출을 찾아 동적 코드 실행 지점을 검토한다. | CWE-95 / ERROR → high | JavaScript·TypeScript 파일 (`.js`, `.jsx`, `.ts`, `.tsx`) | 고정된 신뢰 문자열만 실행하거나 격리된 테스트 코드인 경우 | 별칭·래퍼·다른 런타임 API를 통한 실행, 실제 입력 출처와 완화 장치 |
| `baseline.react-dangerous-html` | JSX의 `dangerouslySetInnerHTML={{ __html: ... }}` 사용을 찾아 HTML 출처와 정제 여부를 검토한다. | CWE-79 / WARNING → medium | JavaScript·TypeScript JSX 파일 (`.jsx`, `.tsx`; JSX 파서가 처리하는 파일) | 신뢰된 정적 HTML 또는 충분히 정제된 HTML인 경우 | `React.createElement` 같은 비JSX 사용, 데이터 흐름·정제의 실제 효력 |
| `baseline.firestore-unconditional-write` | `allow` 작업 목록에 `write`, `create`, `update`, `delete` 중 하나 이상이 있고 같은 줄 조건이 리터럴 `if true;`인 선언을 찾는다. 목록은 `read/get/list`와 쓰기 작업으로 구성되며 각 권한은 전체 토큰으로 일치시킨다. 단일 작업과 여러 작업의 순서·쉼표 간격 변형을 지원한다. 공유 Adapter의 제한적 lexical 검증은 닫힌 주석·문자열 안의 후보만 제외한다. | CWE-284 / ERROR → high | 이름이 `firestore.rules`인 파일만 | 의도적으로 공개 쓰기를 허용한 제한된 `match` 범위. 문맥 검증이 불가능하거나 모호하면 후보를 유지한다. | `if (true)`·복합 조건·함수 호출을 통한 허용, 제한된 lexical 범위 밖 문법, 배포된 규칙의 내용과 상속·중첩 권한 문맥 |

Firestore의 공개 읽기(`allow read: if true;`)는 사용 사례에 따라 의도된 설정일 수 있어 이 기준 규칙에서 제외한다. Firebase Security Rules는 `read`를 `get`/`list`로, `write`를 `create`/`update`/`delete`로 나눌 수 있다. regex는 Semgrep 후보를 찾고, 공통 Adapter는 해당 span이 닫힌 주석이나 문자열에 완전히 포함되는지 확인한다. 파일이 바뀌었거나 읽기·위치·문법 확인이 불가능하면 오탐일 것으로 추정해 숨기지 않고 기존 unverified 후보로 유지한다. 이는 전체 Firestore 문법 파서가 아니며, 실제 배포·상위 규칙·권한의 유효 범위는 확인하지 않는다. 문법 근거: [Firebase Security Rules 언어](https://firebase.google.com/docs/rules/rules-language). 세부 범위와 평가 결과는 `docs/phase6c-firestore-context-validation.md`를 참고한다.

합성 평가 픽스처는 `tests/fixtures/security_baseline/{positive,negative}/`에 있으며 `tests/test_security_baseline.py`에 파일별 기대 규칙 ID·줄·심각도·CWE를 명시한다. 테스트는 픽스처를 임시 디렉터리에 복사한 뒤 실제 Semgrep CLI와 기존 분석기 CLI 전체 경로로 검사한다. 테스트용 코드와 규칙은 탐지 범위 확인용이며 실서비스 취약점의 재현 사례가 아니다.

## 실험용 OSS taint 규칙

### React HTML sink coverage 실험

`experimental/react-html-sink-coverage.yml`은 기존 `baseline.react-dangerous-html`을 수정하거나 대체하지 않는 별도 실험 규칙이다. Phase 6G 합성 개발 사례에서 실제 `react` default import 문맥이 있는 JSX의 변수 `dangerouslySetInnerHTML` props와 `React.createElement`/default import 별칭의 직접 props 객체를 평가한다. Semgrep OSS 1.182.1에서 관찰된 이 구문 범위만 대상으로 하며, JSX 변수 props의 HTML 값 출처는 추적하지 않는다. 상수 HTML도 문법상 sink로 매치될 수 있어 검토 우선순위가 낮을 수 있다.

일반 DOM `innerHTML`, `insertAdjacentHTML`, `document.write`, named `createElement` import, helper 함수가 만든 props, 컴포넌트 간·파일 간 props 전달, 복잡한 alias 및 sanitizer 효력은 지원하지 않는다. React import 문맥은 정적 구문 근거이지 실제 런타임 binding이나 XSS 악용 가능성의 증명이 아니다. 모든 Finding은 `unverified`이며 취약점 확인·HTML 출처 확인·정제 안전성 확인을 뜻하지 않는다. 규칙은 실험 파일에만 있고 baseline 프로필에 자동 포함되지 않는다. 개발 사례 결과와 제한은 `docs/phase6g-react-html-sink-coverage.md`에 기록한다.

`experimental/javascript-eval-taint.yml`은 baseline에 포함되지 않는 PoC 규칙 두 개다. `experimental.javascript-eval-taint`는 `req.query.code` 및 `req.body.code`를 source, `eval`의 첫 인자를 sink로 모델링한다. 두 번째 규칙은 같은 모델에 합성 함수 `syntheticSafe(...)`를 sanitizer로 추가한다. 이는 규칙에서 이름 붙인 패턴을 신뢰한다고 가정한 실험일 뿐, 해당 함수가 실제 안전한 정제 함수라는 검증이 아니다. 다른 함수명, 검증 로직 또는 부분 조건문은 sanitizer로 인정하지 않는다.

이 규칙에서 `$REQ`는 임의의 식별자 metavariable다. 실제 Semgrep OSS 1.182.1은 `record.query.code`, `job.body.code`처럼 일반 객체의 동일한 필드 구조도 taint Source 패턴으로 매치할 수 있다. 이것은 구문상 Source→Sink 관찰이지 HTTP 요청 출처나 외부 입력 도달성 증거가 아니다. Phase 6H의 `experimental/javascript-eval-source-context.yml`은 별도 실험으로, ESM `express` default import, `const app = express()` 형태, 그리고 해당 app의 route callback 안에 있는 source를 요구한다. 그 문맥도 실제 route mount·서버 실행·요청 도달성을 입증하지 않는다. 새 source-context 규칙은 TaintEvidence 신뢰 allowlist에 등록되지 않았으며 trusted evidence claim을 생성하지 않는다. CommonJS, Router, wrapper/helper, cross-file 흐름은 실험 규칙의 지원을 보장하지 않는다. 제한과 평가 결과는 `docs/phase6h-eval-taint-source-context.md`를 참고한다.

Semgrep OSS taint 분석은 지정 source→sink 관계를 같은 함수 내 변수 할당을 따라 추적하는지 확인하는 범위다. 함수 간·파일 간 흐름은 이 평가에서 지원 보장으로 간주하지 않는다. 요청 객체의 `query`/`body` 필드 패턴은 데이터 source 정의일 뿐, 실제 사용자 도달성이나 런타임 framework 동작을 입증하지 않는다. 재현 평가와 제한은 `docs/phase3a-taint-evaluation.md` 및 `tests/fixtures/semgrep_taint/`를 참고한다.

Semgrep 1.182.1은 Git 작업 트리에서 기본적으로 추적되지 않은 파일을 검사 대상에서 제외할 수 있다. 따라서 검사 결과 0건을 모든 파일을 검사했다는 뜻으로 해석하지 말고 보고서의 검사 상태와 대상 범위를 함께 확인한다.

### Node.js command injection 실험 규칙

`experimental/javascript-command-injection-taint.yml`은 별도 PoC 규칙이다. Source는 구문상 `req.query.cmd`와 `req.body.cmd`이며, 이 패턴이 실제 HTTP 입력이라는 것을 입증하지 않는다. 기존 Sink는 `child_process.exec()`/`execSync()`의 첫 번째 인자다. Phase 6F에서는 `child_process.spawn()`의 인자 배열 원소 또는 `spawn` named import alias의 명령 문자열 중 Source 패턴이 `shell: true` 옵션을 포함한 지원 형태로 흐르는 경우만 추가로 모델링한다. 지원 형태는 직접 named import(`node:child_process`), `child_process`를 `require("child_process")`한 namespace binding(별칭 포함), 그리고 `spawn as launch` named import다. 이 확장은 Semgrep OSS 1.182.1의 합성 결과로 제한해 확인했다.

`exec`/`execSync`는 첫 번째 명령 문자열 인자에 초점을 두며, 새 `spawn` 형태는 `shell: true`가 명시된 첫 번째 명령 인자 또는 argv 원소에 초점을 둔다. `spawn` 기본값 및 `shell: false`는 이번 CWE-78 Sink 확장에 포함하지 않는다. 기본 `spawn(command, args)`는 shell을 사용하지 않는 별도 실행 의미가 있으므로 shell injection으로 단정하지 않는다. 다만 대상 프로그램이 인자를 해석하는 방식에 따른 argument injection 등 다른 위험은 이 규칙이 평가하지 않는다. `shell` 옵션을 변수로 전달하거나 복잡하게 구성한 경우, 다른 `spawn` import 형태, `execFile`/`execFileSync`, 함수 간·파일 간 흐름은 보장하지 않는다. 일반 객체 메서드, `RegExp.exec()`, mock, 다른 모듈, shadowing, 고정 명령은 대조군이다. Semgrep의 모듈 binding 인식이 `const cp = require("child_process")` 별칭도 기존 `exec` Sink와 연결할 수 있지만, 이것은 별도 Source/Sink 위치나 구조화 trace를 제공하지 않는다. 패턴 문맥은 런타임에서 import binding이 실제 Node 모듈인지, 변수가 실행 시점에 재할당되지 않았는지 완전히 증명하지 않는다. Source 패턴도 Express 입력 도달성이나 validation 부재를 증명하지 않는다.

Phase 6F 규칙 변경 후의 새 해시는 내부 TaintEvidence 레지스트리의 정확한 로컬 선언에도 고정된다. Gate/Consumer는 기존과 같은 제한된 claim만 승인하며 개별 Source/Sink 위치, 전체 trace, Sanitizer 매치·효과 또는 취약점 확정을 지원하지 않는다. Phase 6A–6E 결과와 과거 규칙 바이트는 역사 자료로 보존되며, Phase 6E 재현은 `tests/benchmark/phase6e/pinned_rules/`에 고정된 당시 규칙을 사용한다. 새 개발 집합, 변경 전 결과 및 남은 한계는 `docs/phase6f-command-injection-semantic-validation.md`에 기록한다. 규칙은 계속 experimental이며 baseline에는 포함하지 않는다. CWE-78은 규칙 메타데이터 분류이지 취약점 확정이 아니다.

## 이후 검토할 유형

- 사용자 입력 URL: 허용 스킴, 리디렉션, 네트워크 요청까지의 데이터 흐름과 배포 정책 확인이 필요하다.
- Firebase 인증과 사용자별 접근 통제: 서버·클라이언트의 권한 문맥, 실제 배포 규칙 및 데이터 모델 확인이 필요하다.
- Android 릴리스 설정: 웹용 Semgrep 규칙과 별도 대상·설정 검증이 필요하다.
- Firestore 규칙 파일 부재 또는 `allow read: if true;`: 배포 설정과 공개 의도를 확인하기 전에는 취약점으로 판정할 수 없다.

분석기는 로컬 규칙을 명시적으로 사용하고 자동 다운로드, 메트릭, 버전 확인을 비활성화한다. CLI 자체에는 OS 수준 네트워크 차단이 없다. 향후 GitHub URL 수집이나 비신뢰 저장소 분석에는 호스트 측 네트워크 차단, 읽기 전용 입력 마운트, 자격 증명 없는 환경, CPU·시간·메모리·출력 크기 제한이 필요하다. 이 조건은 현재 분석기의 보장으로 주장하지 않는다.
