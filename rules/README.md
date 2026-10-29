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
| `baseline.firestore-unconditional-write` | `allow` 작업 목록에 `write`, `create`, `update`, `delete` 중 하나 이상이 있고 같은 줄 조건이 리터럴 `if true;`인 선언을 찾는다. 목록은 `read/get/list`와 쓰기 작업으로 구성되며 각 권한은 전체 토큰으로 일치시킨다. 단일 작업과 여러 작업의 순서·쉼표 간격 변형을 지원한다. | CWE-284 / ERROR → high | 이름이 `firestore.rules`인 파일만 | 의도적으로 공개 쓰기를 허용한 제한된 `match` 범위 또는 여러 줄 블록 주석의 유사 문구 | `if (true)`·복합 조건·함수 호출을 통한 허용, 배포된 규칙의 내용과 상속·중첩 권한 문맥 |

Firestore의 공개 읽기(`allow read: if true;`)는 사용 사례에 따라 의도된 설정일 수 있어 이 기준 규칙에서 제외한다. Firebase Security Rules는 `read`를 `get`/`list`로, `write`를 `create`/`update`/`delete`로 나눌 수 있다. 이번 정규식은 쓰기 작업이 목록에 하나 이상 있는 경우만 대상으로 한다. 다만 정규식은 Firestore 파서가 아니며 여러 줄 블록 주석 안의 행 모양 선언을 완전히 해석하지 못할 수 있다. 이 경우 `firestore.rules` 안의 해당 문자열을 매치할 수 있다. 쓰기 규칙이 탐지되어도 해당 `match`의 범위, 상위 규칙 및 실제 배포 여부를 확인해야 한다. 저장소에 `firestore.rules`가 없으면 배포된 Firestore 권한 설정을 알 수 없으며 이를 취약점이나 안전성의 증거로 해석하지 않는다. 문법 근거: [Firebase Cloud Firestore Security Rules 구조](https://firebase.google.com/docs/firestore/enterprise/security/rules-structure) 및 [Security Rules 언어](https://firebase.google.com/docs/rules/rules-language).

합성 평가 픽스처는 `tests/fixtures/security_baseline/{positive,negative}/`에 있으며 `tests/test_security_baseline.py`에 파일별 기대 규칙 ID·줄·심각도·CWE를 명시한다. 테스트는 픽스처를 임시 디렉터리에 복사한 뒤 실제 Semgrep CLI와 기존 분석기 CLI 전체 경로로 검사한다. 테스트용 코드와 규칙은 탐지 범위 확인용이며 실서비스 취약점의 재현 사례가 아니다.

## 실험용 OSS taint 규칙

`experimental/javascript-eval-taint.yml`은 baseline에 포함되지 않는 PoC 규칙 두 개다. `experimental.javascript-eval-taint`는 `req.query.code` 및 `req.body.code`를 source, `eval`의 첫 인자를 sink로 모델링한다. 두 번째 규칙은 같은 모델에 합성 함수 `syntheticSafe(...)`를 sanitizer로 추가한다. 이는 규칙에서 이름 붙인 패턴을 신뢰한다고 가정한 실험일 뿐, 해당 함수가 실제 안전한 정제 함수라는 검증이 아니다. 다른 함수명, 검증 로직 또는 부분 조건문은 sanitizer로 인정하지 않는다.

Semgrep OSS taint 분석은 지정 source→sink 관계를 같은 함수 내 변수 할당을 따라 추적하는지 확인하는 범위다. 함수 간·파일 간 흐름은 이 평가에서 지원 보장으로 간주하지 않는다. 요청 객체의 `query`/`body` 필드 패턴은 데이터 source 정의일 뿐, 실제 사용자 도달성이나 런타임 framework 동작을 입증하지 않는다. 재현 평가와 제한은 `docs/phase3a-taint-evaluation.md` 및 `tests/fixtures/semgrep_taint/`를 참고한다.

Semgrep 1.182.1은 Git 작업 트리에서 기본적으로 추적되지 않은 파일을 검사 대상에서 제외할 수 있다. 따라서 검사 결과 0건을 모든 파일을 검사했다는 뜻으로 해석하지 말고 보고서의 검사 상태와 대상 범위를 함께 확인한다.

### Node.js command injection 실험 규칙

`experimental/javascript-command-injection-taint.yml`은 별도 PoC 규칙이다. 정확한 `req.query.cmd`와 `req.body.cmd` Source 패턴에서 Node `child_process.exec()` 또는 `execSync()`의 첫 번째 명령 인자까지 이어지는 흐름을 대상으로 한다. 같은 파일 안에서 `child_process`/`node:child_process` namespace import, 직접 require 호출, `const cp = require(...)` 모듈 변수, `exec`/`execSync` named import, alias named import, destructured require 및 alias destructuring 형태를 합성 fixture로 확인했다. 이 지원 범위는 Semgrep OSS 1.182.1과 해당 규칙·fixture에서 관찰한 결과다.

규칙은 command 인자 메타변수에 sink 초점을 두어 옵션 인자나 callback 인자만 tainted인 호출을 제외한다. 지역 `child_process` shadowing은 제외하고 Source도 요청 객체 이름 `req`로 제한한다. 일반 `object.exec()`, `RegExp.exec()`, mock·가짜 모듈, 고정 명령, 서로 무관한 요청 입력은 대상이 아니다. 이 제한으로 다른 요청 객체명은 놓칠 수 있다. 패턴 문맥은 런타임에서 import binding이 실제 Node 모듈인지, 변수가 실행 시점에 재할당되지 않았는지 완전히 증명하지 않는다. Source 패턴도 Express 입력 도달성이나 validation 부재를 증명하지 않는다.

현재 Semgrep OSS 1.182.1에서 합성 사례로 검증한 지원 형태, hard-negative, 탐색 결과는 `docs/phase4a1-command-injection-taint.md`와 `docs/phase4a2-command-injection-hardening.md`에 기록한다. Phase 4A-3부터 이 규칙의 정확한 상대 경로·고정 SHA-256·정규화된 선언이 내부 TaintEvidence 레지스트리에 등록되어 Gate/Consumer가 제한된 taint claim을 검증할 수 있다. 이는 구조적 선언과 match 연결만 신뢰한다. Source/Sink 개별 위치, 전체 trace, Sanitizer 매치·효과, 취약점 확정은 지원하지 않는다. 규칙은 계속 experimental이며 baseline에는 포함하지 않는다. CWE-78은 규칙 메타데이터 분류이지 취약점 확정이 아니다.

## 이후 검토할 유형

- 사용자 입력 URL: 허용 스킴, 리디렉션, 네트워크 요청까지의 데이터 흐름과 배포 정책 확인이 필요하다.
- Firebase 인증과 사용자별 접근 통제: 서버·클라이언트의 권한 문맥, 실제 배포 규칙 및 데이터 모델 확인이 필요하다.
- Android 릴리스 설정: 웹용 Semgrep 규칙과 별도 대상·설정 검증이 필요하다.
- Firestore 규칙 파일 부재 또는 `allow read: if true;`: 배포 설정과 공개 의도를 확인하기 전에는 취약점으로 판정할 수 없다.

분석기는 로컬 규칙을 명시적으로 사용하고 자동 다운로드, 메트릭, 버전 확인을 비활성화한다. CLI 자체에는 OS 수준 네트워크 차단이 없다. 향후 GitHub URL 수집이나 비신뢰 저장소 분석에는 호스트 측 네트워크 차단, 읽기 전용 입력 마운트, 자격 증명 없는 환경, CPU·시간·메모리·출력 크기 제한이 필요하다. 이 조건은 현재 분석기의 보장으로 주장하지 않는다.
