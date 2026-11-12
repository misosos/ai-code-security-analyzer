[한국어] | [English](README.en.md)

# SAST Review Workspace

Semgrep OSS의 정적 분석 결과를 검토하고, 기록하고, 재검사 결과와 비교하고, 내보내는 로컬 작업 공간입니다. 탐지는 Semgrep OSS 1.182.1과 로컬 규칙이 수행하며, 모든 탐지 결과(Finding)는 확정된 취약점이 아닌 미검증 후보입니다.

## 주요 기능

- Semgrep OSS 기반 정적 코드 분석 (로컬 규칙)
- Python CLI와 React 대시보드
- 탐지 결과별 검토 상태와 메모
- 재검사 결과 비교
- Markdown, SARIF 2.1.0 내보내기
- 토큰으로 보호되는 로컬 전용 FastAPI (`127.0.0.1:8765`)

## 대시보드

![대시보드 검사 결과 화면](docs/assets/readme/dashboard-results.png)

## 빠른 시작

필요한 환경: Python 3.12, [uv](https://docs.astral.sh/uv/), Semgrep 1.182.1, 대시보드를 쓸 경우 Node.js 24.

```sh
uv tool install --python 3.12 'semgrep==1.182.1'
uv sync --locked
```

CLI 검사:

```sh
SAMPLE="$(cd "$(mktemp -d)" && pwd -P)"
cp tests/fixtures/security_baseline/positive/* "$SAMPLE"/
uv run --locked python -m ai_code_security_analyzer scan \
  --path "$SAMPLE" --rules rules/security-baseline.yml
```

`Status: completed`와 `Findings: 7 unverified candidate(s)`가 출력됩니다.

대시보드:

```sh
(cd frontend && npm ci && npm run build)
TOKEN="$(uv run --locked python -c 'import secrets; print(secrets.token_urlsafe(32))')"
echo "$TOKEN"
AI_CODE_SECURITY_TARGET="$SAMPLE" \
AI_CODE_SECURITY_API_TOKEN="$TOKEN" \
AI_CODE_SECURITY_ALLOWED_ORIGINS='http://127.0.0.1:8765' \
uv run --locked python -m ai_code_security_analyzer.api
```

`http://127.0.0.1:8765`를 열고 출력된 토큰을 입력합니다.

Semgrep은 운영체제 수준에서 격리되지 않으므로, 신뢰할 수 없는 저장소는 별도로 격리된 환경에서만 검사하세요.

## 문서

- [시작하기](docs/getting-started.md): 환경변수, 개발 서버, 내보내기, 문제 해결
- [기술 개요](docs/project-overview.md): 아키텍처와 보안 통제
