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
| `baseline.firestore-unconditional-write` | `allow write`, `create`, `update`, `delete` 또는 `read, write`가 같은 줄의 `if true;`로 무조건 허용되는 선언을 찾는다. 정규식의 줄 시작 고정으로 행 주석 속 문구는 제외한다. | CWE-284 / ERROR → high | 이름이 `firestore.rules`인 파일만 | 의도적으로 공개 쓰기를 허용한 제한된 `match` 범위 또는 여러 줄 블록 주석의 유사 문구 | `if (true)`·복합 조건·함수 호출을 통한 허용, 배포된 규칙의 내용과 상속·중첩 권한 문맥 |

Firestore의 공개 읽기(`allow read: if true;`)는 사용 사례에 따라 의도된 설정일 수 있어 이 기준 규칙에서 제외한다. 쓰기 규칙이 탐지되어도 해당 `match`의 범위와 실제 배포 여부를 확인해야 한다. 저장소에 `firestore.rules`가 없으면 배포된 Firestore 권한 설정을 알 수 없으며 이를 취약점이나 안전성의 증거로 해석하지 않는다.

합성 평가 픽스처는 `tests/fixtures/security_baseline/{positive,negative}/`에 있으며 `tests/test_security_baseline.py`에 파일별 기대 규칙 ID·줄·심각도·CWE를 명시한다. 테스트는 픽스처를 임시 디렉터리에 복사한 뒤 실제 Semgrep CLI와 기존 분석기 CLI 전체 경로로 검사한다. 테스트용 코드와 규칙은 탐지 범위 확인용이며 실서비스 취약점의 재현 사례가 아니다.

Semgrep 1.182.1은 Git 작업 트리에서 기본적으로 추적되지 않은 파일을 검사 대상에서 제외할 수 있다. 따라서 검사 결과 0건을 모든 파일을 검사했다는 뜻으로 해석하지 말고 보고서의 검사 상태와 대상 범위를 함께 확인한다.

## 이후 검토할 유형

- 사용자 입력 URL: 허용 스킴, 리디렉션, 네트워크 요청까지의 데이터 흐름과 배포 정책 확인이 필요하다.
- Firebase 인증과 사용자별 접근 통제: 서버·클라이언트의 권한 문맥, 실제 배포 규칙 및 데이터 모델 확인이 필요하다.
- Android 릴리스 설정: 웹용 Semgrep 규칙과 별도 대상·설정 검증이 필요하다.
- Firestore 규칙 파일 부재 또는 `allow read: if true;`: 배포 설정과 공개 의도를 확인하기 전에는 취약점으로 판정할 수 없다.

분석기는 로컬 규칙을 명시적으로 사용하고 자동 다운로드, 메트릭, 버전 확인을 비활성화한다. CLI 자체에는 OS 수준 네트워크 차단이 없다. 향후 GitHub URL 수집이나 비신뢰 저장소 분석에는 호스트 측 네트워크 차단, 읽기 전용 입력 마운트, 자격 증명 없는 환경, CPU·시간·메모리·출력 크기 제한이 필요하다. 이 조건은 현재 분석기의 보장으로 주장하지 않는다.
