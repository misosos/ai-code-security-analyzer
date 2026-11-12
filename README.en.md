[한국어](README.md) | [English]

# SAST Review Workspace

A local workspace for reviewing Semgrep OSS static-analysis results: triage them, record decisions, compare them with a rescan, and export them. Detection is done by Semgrep OSS 1.182.1 with local rules, and every finding is an unverified candidate, not a confirmed vulnerability.

## Features

- Static code analysis with Semgrep OSS (local rules)
- Python CLI and React dashboard
- Review status and notes per finding
- Comparison with a rescan
- Markdown and SARIF 2.1.0 export
- Token-protected, loopback-only FastAPI (`127.0.0.1:8765`)

## Dashboard

![Dashboard scan results](docs/assets/readme/dashboard-results.png)

## Quick start

Requirements: Python 3.12, [uv](https://docs.astral.sh/uv/), Semgrep 1.182.1, and Node.js 24 for the dashboard.

```sh
uv tool install --python 3.12 'semgrep==1.182.1'
uv sync --locked
```

CLI scan:

```sh
SAMPLE="$(cd "$(mktemp -d)" && pwd -P)"
cp tests/fixtures/security_baseline/positive/* "$SAMPLE"/
uv run --locked python -m ai_code_security_analyzer scan \
  --path "$SAMPLE" --rules rules/security-baseline.yml
```

It prints `Status: completed` and `Findings: 7 unverified candidate(s)`.

Dashboard:

```sh
(cd frontend && npm ci && npm run build)
TOKEN="$(uv run --locked python -c 'import secrets; print(secrets.token_urlsafe(32))')"
echo "$TOKEN"
AI_CODE_SECURITY_TARGET="$SAMPLE" \
AI_CODE_SECURITY_API_TOKEN="$TOKEN" \
AI_CODE_SECURITY_ALLOWED_ORIGINS='http://127.0.0.1:8765' \
uv run --locked python -m ai_code_security_analyzer.api
```

Open `http://127.0.0.1:8765` and enter the printed token.

Semgrep runs without OS-level isolation, so scan untrusted repositories only in a separately isolated environment.

## Documentation

- [Getting started](docs/getting-started.md): environment variables, dev server, exports, troubleshooting
- [Project overview](docs/project-overview.md): architecture and security controls
