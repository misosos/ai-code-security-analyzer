# AI Code Security Analyzer

Python 3.12와 uv로 실행하는 로컬 정적 분석 기반이다. 사용자가 명시한 신뢰된 로컬 Semgrep 규칙 파일로 디렉터리를 분석한다.

```sh
uv run python -m ai_code_security_analyzer scan --path /path/to/project --rules rules/security-baseline.yml --format json
```

`--format`은 `text`(기본값), `json`, `review`, `review-md`를 지원한다. `review`와 `review-md`는 Gate와 Evidence Consumer가 검증한 근거 및 제한을 보여주는 분석가용 출력이다. Markdown 파일은 다음처럼 명시적으로 새 파일로 저장할 수 있다. 기존 파일은 덮어쓰지 않는다.

```sh
uv run python -m ai_code_security_analyzer scan --path /path/to/project --rules rules/security-baseline.yml --format review-md --output review-report.md
```

`--output`은 JSON과 Markdown review에만 허용되며 일반 text/review는 파일로 저장하지 않는다. 보고서는 코드 조각을 포함하지 않지만 저장소 경로와 규칙 ID가 나타날 수 있으므로 외부 공유 전에 직접 검토해야 한다. 자세한 내용은 [분석가 검토 화면 안내](docs/analyst-review-view.md), [Markdown 보고서 안내](docs/phase3c4-markdown-review-report.md), [Phase 3C-2 평가 자료](docs/phase3c2-analyst-review-usability.md)를 참고한다.

| 종료 코드 | 의미 |
| --- | --- |
| 0 | 검사 완료. Finding이 있어도 정상 검사로 취급한다. |
| 1 | 일부 검사 실패 또는 결과 변환 누락. 보고된 Finding은 후보로만 취급한다. |
| 2 | CLI 인자 또는 로컬 경로가 잘못됨. |
| 3 | Semgrep 실행·JSON 처리·보고서 저장 실패 등 전체 실패. |

JSON 보고서의 `status`와 `completed`를 함께 확인한다. `completed=true`는 검사가 완료되었다는 뜻이며 코드가 안전하다는 뜻은 아니다. 모든 Semgrep Finding의 상태는 `unverified`다. 보고서는 원본 코드와 Semgrep 원본 JSON을 포함하지 않는다. 절대 경로 대신 대상 경로의 해시 식별자를 사용한다.

Semgrep은 로컬 규칙, 메트릭 비활성화, 임시 HOME으로 실행된다. CLI 자체는 OS 수준 네트워크 격리를 제공하지 않으므로 신뢰할 수 없는 저장소는 별도의 격리 환경에서 분석해야 한다. [기준 규칙의 범위와 한계](rules/README.md)를 참고한다.

향후 AI 분석용 코드 문맥은 [내부 추출 계약](docs/code-context.md)에 따라 별도로 수집한다. 기존 `scan` 명령과 공개 JSON에는 코드 조각이 포함되지 않는다.

실제 모델 호출 전 [AI 검토 계약과 Fake Provider 검증](docs/ai-review-contract.md)을 사용한다. AI 검토 결과는 기존 Finding의 확정 상태를 변경하지 않는다.

로컬 React UI 연결을 위한 FastAPI 백엔드는 명시적으로 등록한 프로젝트만 검사한다. 토큰과 target을 설정한 뒤 loopback에서 실행한다. 자세한 인증·Origin·규칙 프로필·응답 제한은 [로컬 API 안내](docs/phase5a-local-api.md)를 참고한다.

```sh
AI_CODE_SECURITY_TARGET=/path/to/project \
AI_CODE_SECURITY_API_TOKEN='<at-least-43-url-safe-random-characters>' \
uv run python -m ai_code_security_analyzer.api
```

React 대시보드 개발은 Node.js 24.22.2와 npm lockfile을 사용한다. FastAPI와 Vite를 각각 loopback에서 실행하며, Vite는 `/api` 요청만 고정된 로컬 API 주소로 프록시한다. API 서버에는 개발 Origin을 명시적으로 허용한다.

```sh
cd frontend && npm ci && npm run dev
# 별도 터미널: 기존 API 설정에 개발 Origin을 추가
AI_CODE_SECURITY_TARGET=/path/to/project \
AI_CODE_SECURITY_API_TOKEN='<at-least-43-url-safe-random-characters>' \
AI_CODE_SECURITY_ALLOWED_ORIGINS='http://127.0.0.1:5173' \
uv run python -m ai_code_security_analyzer.api
```

Vite가 표시하는 `http://127.0.0.1:5173` 주소로 접속한다. 토큰은 대시보드 메모리에만 유지되며 새로고침하면 사라진다. 상세 설정은 [React 대시보드 안내](docs/phase5b-react-dashboard.md)를 참고한다.

검사 결과에는 실행 당시 target 및 규칙 프로필이 연결되어 표시된다. **현재 검사 결과 내보내기**는 화면에 이미 수신된 결과만 사용하는 UI 전용 Markdown 요약을 다운로드하며 Semgrep을 재실행하지 않는다. 브라우저 다운로드 파일의 저장 위치와 권한은 브라우저·운영체제가 관리한다. 범위와 한계는 [Phase 5C 안내](docs/phase5c-analyst-workflow-export.md)를 참고한다.

실제 Chromium·FastAPI·Semgrep 통합 검증은 테스트용 임시 프로젝트에서 `frontend` 디렉터리에서 `SEMGREP_REQUIRED=1 npm run test:e2e:real`로 실행한다. 이 검증은 Semgrep OSS 1.182.1을 요구하며 실제 사용자 저장소를 사용하지 않는다. 보안 경계와 운영 한계는 [Phase 5D 검증 기록](docs/phase5d-browser-security-validation.md)을 참고한다.
