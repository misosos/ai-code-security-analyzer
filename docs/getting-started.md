# Getting started

Full setup and usage guide. The [README](../README.en.md) has the shortest path to a first scan.

Commands run from the repository root unless noted.

## 1. Prerequisites

| Tool | Version | Check |
| --- | --- | --- |
| Python | 3.12 (`.python-version`) | `python3 --version` |
| uv | 0.11.26 was the intended pin. CI does not enforce it and installs the latest release (see [known limitations](known-limitations.md)). | `uv --version` |
| Semgrep CLI | **1.182.1**, on `PATH` | `semgrep --version` |
| Node.js / npm | Node 24.22.2 (`.nvmrc`; `frontend/package.json` requires `>=24 <25`) | `node --version` |

Install the pinned Semgrep the same way CI does:

```sh
uv tool install --python 3.12 'semgrep==1.182.1'
semgrep --version   # must print 1.182.1
```

Node.js is only needed for the dashboard. The CLI and API need Python, uv and Semgrep.

## 2. Install locked dependencies

```sh
uv sync --locked
uv run --locked python -m ai_code_security_analyzer --help
```

## 3. Run a sample scan (CLI)

The repository ships small positive fixtures. Copy them to a neutral directory first: scanning them in place under `tests/` returns `partial` with `no_files_scanned` (see [Troubleshooting](#troubleshooting)).

```sh
SAMPLE="$(mktemp -d)"
cp tests/fixtures/security_baseline/positive/* "$SAMPLE"/
uv run --locked python -m ai_code_security_analyzer scan \
  --path "$SAMPLE" --rules rules/security-baseline.yml
```

Expected: `Status: completed` and `Findings: 7 unverified candidate(s)` (5 high, 2 medium).

Other formats:

```sh
# Machine-readable JSON
uv run --locked python -m ai_code_security_analyzer scan --path "$SAMPLE" \
  --rules rules/security-baseline.yml --format json

# Analyst review as a NEW Markdown file (refuses to overwrite an existing file)
uv run --locked python -m ai_code_security_analyzer scan --path "$SAMPLE" \
  --rules rules/security-baseline.yml --format review-md --output review-report.md
```

`--format` accepts `text` (default), `json`, `review` and `review-md`. `--output` is only accepted with `json` or `review-md`.

| Exit code | Meaning |
| --- | --- |
| 0 | Scan completed. Findings may still be present. |
| 1 | Partial scan or result-conversion loss. Treat findings as incomplete candidates. |
| 2 | Invalid CLI arguments, local path, or output file (including an existing `--output` file). |
| 3 | Full failure (Semgrep execution, JSON handling, or report write). |

`completed=true` means the scan finished. It does **not** mean the code is safe. Every finding is unverified (`"status": "unverified"` in CLI JSON, `verification_status: "unverified"` in API responses). Reports omit source snippets and raw Semgrep JSON and identify the target by a hash, but they can still contain relative file paths and rule IDs. Review them before sharing.

## 4. Configure the local API

The API scans only directories registered through environment variables at startup. The browser cannot choose arbitrary paths.

| Variable | Required | Meaning |
| --- | --- | --- |
| `AI_CODE_SECURITY_API_TOKEN` | Yes | 43–256 characters from `[A-Za-z0-9_-]`. Required for `POST /api/v1/scans` and all `/api/v2` calls. `GET /api/v1/health` and `/api/v1/options` do not require it. |
| `AI_CODE_SECURITY_TARGET` | One of these two | A single target directory, exposed as target ID `local-project`. |
| `AI_CODE_SECURITY_TARGETS` | One of these two | JSON array of up to 32 `{"id","label","path"}` objects with absolute paths. Setting both variables is rejected. |
| `AI_CODE_SECURITY_ALLOWED_ORIGINS` | For browser use | Comma-separated exact Origins (no wildcard). Requests carrying any other `Origin` header are rejected. |
| `AI_CODE_SECURITY_RULES_DIR` | No | Trusted rules directory. Defaults to the repository `rules/`. |

Generate a token (43 URL-safe characters):

```sh
uv run --locked python -c 'import secrets; print(secrets.token_urlsafe(32))'
```

Use a dedicated value. Do not commit it or paste it into shared logs.

## 5. Start the API and dashboard

**Option A: built dashboard served by the API (single origin).** When `frontend/dist` exists, the API serves it at `/`.

```sh
(cd frontend && npm ci && npm run build)
AI_CODE_SECURITY_TARGET="$SAMPLE" \
AI_CODE_SECURITY_API_TOKEN='<your-token>' \
AI_CODE_SECURITY_ALLOWED_ORIGINS='http://127.0.0.1:8765' \
uv run --locked python -m ai_code_security_analyzer.api
```

Open `http://127.0.0.1:8765` and enter the token in the dashboard. The token is kept only in page memory and is lost on reload.

**Option B: Vite dev server.** Vite binds to `127.0.0.1:5173` and proxies only `/api` to `127.0.0.1:8765`.

```sh
# Terminal 1
cd frontend && npm ci && npm run dev
# Terminal 2 (repository root)
AI_CODE_SECURITY_TARGET="$SAMPLE" \
AI_CODE_SECURITY_API_TOKEN='<your-token>' \
AI_CODE_SECURITY_ALLOWED_ORIGINS='http://127.0.0.1:5173' \
uv run --locked python -m ai_code_security_analyzer.api
```

Open `http://127.0.0.1:5173`.

## 6. Review findings and export results

In the dashboard (UI text is Korean):

1. Choose a registered target and the **Baseline Rules** profile, then run a scan. Experimental profiles are labeled as such.
2. Select a finding to see its rule, location, severity, triage guidance, and which evidence claims were validated or restricted.
3. Set a review status and optional note per finding. This state lives **only in browser memory** (see limitations).
4. Run a second scan of the same target and profile to compare finding IDs. Finding IDs depend on line and column, so a finding whose code moved or whose file was renamed shows up as disappeared plus new. Comparison is blocked when either scan is partial or failed, or when findings were omitted (the API returns at most 50 findings per scan).
5. Export what you need:
   - Current-scan Markdown summary (`Markdown 다운로드`)
   - SARIF 2.1.0 file (`SARIF 다운로드`). No upload is performed.
   - Analyst review Markdown, with notes included only after explicit confirmation
   - Review backup JSON (`검토 기록 백업 JSON 다운로드`), which can be restored onto findings with the same IDs
   - Comparison Markdown for two observed scans

Exports are built from data already in the page and never re-run Semgrep. Downloaded files persist on disk, so check notes before sharing.

## Troubleshooting

| Symptom | Likely cause and fix |
| --- | --- |
| API exits with `local_api_configuration_required` | Token or target variable missing. Set `AI_CODE_SECURITY_API_TOKEN` and one of `AI_CODE_SECURITY_TARGET` / `AI_CODE_SECURITY_TARGETS`. |
| API exits with `local_api_configuration_invalid` | Token shorter than 43 characters or containing other characters; both target variables set; or malformed `AI_CODE_SECURITY_TARGETS` JSON (relative paths, extra keys, more than 32 entries). |
| API does not start, or a different instance answers | The launcher always binds `127.0.0.1:8765`. Check for an existing listener with `lsof -nP -iTCP:8765 -sTCP:LISTEN` and stop that instance yourself. |
| `403 origin_not_allowed` | The page's exact Origin is missing from `AI_CODE_SECURITY_ALLOWED_ORIGINS` (`http://127.0.0.1:8765` for Option A, `http://127.0.0.1:5173` for Option B). |
| `401 unauthorized` | Missing or wrong token in the dashboard. |
| Scan reports `partial` with `no_files_scanned` | The target matched no supported files, or its path falls under Semgrep's default ignore patterns (observed for a target inside `tests/`). Scan a copy in a neutral directory. |
| `semgrep_not_installed` or `version_check_failed` | Semgrep is not on `PATH` or does not run. Install `semgrep==1.182.1` as shown above. |
| CLI exit code 2 with `--output` | The output file already exists, or the format is not `json` / `review-md`. |
| `npm ci` or `node` fails | Use Node.js 24 (`.nvmrc`: 24.22.2). Other major versions are not tested. |
