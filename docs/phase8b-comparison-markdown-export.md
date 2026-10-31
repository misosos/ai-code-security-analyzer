# Phase 8B — 검사 비교 Markdown 보고서 내보내기

## 기능과 사용 방법

검사 결과 화면에서 정상 완료된 결과를 `비교 기준으로 지정`한 뒤, 같은 프로젝트와 규칙 프로필로 다시 검사합니다. 비교가 가능한 경우 `비교 보고서 내보내기` 버튼이 활성화됩니다. 다운로드는 사용자 클릭으로만 시작되며 고정 파일명은 `ai-code-security-comparison.md`입니다.

보고서는 Phase 8A의 `compareScanSnapshots()`를 다시 실행해 비교 조건과 세 그룹을 재검증합니다. 화면의 검색어, 필터, 선택된 Finding과 무관하게 세 범주의 전체 Finding을 포함합니다. 조건을 만족하지 못하면 보고서 생성 함수가 실패하며 일부 결과를 내보내지 않습니다.

## 보고서 구조

1. 문서가 두 정적 분석 결과의 관찰 차이이며 취약점 확정 또는 수정 증명이 아님을 알리는 개요
2. 검사 대상, 규칙 프로필/Experimental 상태, Semgrep 버전, 검사 상태 및 기준·현재 응답 수신 시각
3. 기준·현재 Finding 수 및 관찰 범주별 수
4. 이번 검사에서만 관찰된 Finding 전체
5. 양쪽 검사에서 관찰된 Finding 전체와 기준·현재 메타데이터
6. 기준 검사에서만 관찰된 Finding 전체
7. Finding ID 및 정적 분석 결과의 한계, 후속 수동 검토 안내

각 Finding에는 ID, 규칙 ID, 심각도, 탐지 유형, 상대 파일 위치와 줄 번호, `verification_status`, `evidence_validation_status`, 지원된 주장, 제한된 주장 및 사유 코드를 기록합니다. `validated`는 근거 연결의 구조적 검증이며 취약점 확인이 아닙니다.

## 비교 가능 조건

기준·현재 결과가 모두 존재하고 Phase 8A 비교 함수가 `comparable=true`와 그룹을 반환해야 합니다. 정상 완료, 생략 Finding 없음, 요약 수와 실제 배열 수 일치, 대상 ID·프로필 ID·Experimental 상태 일치, 동일하고 확인 가능한 Semgrep 버전, API 응답과 검사 문맥 상태 일치 및 중복 Finding ID 없음이 필요합니다. 다른 대상·프로필, 실패·부분 검사, 생략, 버전 불일치, 동일 snapshot은 차단됩니다.

## 저장 및 보안

- 결과는 기존처럼 React 메모리에만 있으며 새로고침 시 사라집니다. 보고서는 클릭 때만 브라우저에서 생성하고 로컬 다운로드로 전달합니다.
- 서버·외부 서비스 업로드, 새 API 요청, 자동 저장은 없습니다.
- 최대 크기는 UTF-8 기준 512 KiB입니다. 초과하면 축약하거나 일부 Finding을 빼지 않고 전체 다운로드를 거부합니다.
- 고정된 파일명을 사용하고 Blob URL을 만든 뒤 정리합니다.
- Markdown/HTML 구분자, 제어문자와 Unicode 형식 문자는 기존 `escapeMarkdownText()`로 이스케이프합니다. 절대 경로와 비정상 상대 경로는 보고서에 넣지 않습니다.
- 보고서는 API가 제공한 메타데이터와 검증 상태만 포함합니다. 토큰, 소스 코드 원문, 절대 경로, HTTP 원문, stderr, 임의 필드는 포함하지 않습니다.
- 보고서는 CLI의 정식 보안 검토 보고서를 대체하지 않습니다.

## Finding ID와 한계

비교는 기존 Finding ID의 정확한 일치만 사용합니다. 이 ID에는 코드 위치 정보가 포함되므로 코드 이동, 줄 번호 변경, 경로 또는 규칙 변화가 분류를 바꿀 수 있습니다. 같은 ID도 코드 내용이나 보안 상태의 불변성을 증명하지 않습니다. 이번 검사에서만 관찰된 항목은 새 취약점 확정이 아니며, 기준 검사에서만 관찰된 항목은 해결 또는 수정 완료를 뜻하지 않습니다.

## 검증 결과

검증은 Phase 8B 격리 worktree에서 실행하고, 실제 파일은 합성 API 응답만 사용했습니다.

- TypeScript: `npm run typecheck` — PASS
- Vitest: `npm test -- --maxWorkers=1` — PASS (81 tests)
- Production build: `npm run build` — PASS
- Chromium 전체 브라우저: `npx playwright test --config playwright.phase8a.config.ts` — PASS (21 tests)
- Python 전체: `SEMGREP_REQUIRED=1 uv run --locked python -m pytest -q -rs` — PASS (542 passed, 28 skipped; Semgrep 필수)
- Semgrep 실제 API 회귀: `SEMGREP_REQUIRED=1 uv run --locked python -m pytest -q tests/test_api_semgrep_e2e.py::test_api_runs_real_semgrep_and_returns_only_validated_claim_codes` — PASS, Semgrep 1.182.1
- FastAPI–Semgrep 브라우저 E2E: `SEMGREP_REQUIRED=1 npm run test:e2e:real` — PASS
- 다운로드 브라우저 검증: 고정 파일명, 세 그룹 전체 내용, 다운로드로 인한 추가 API 요청 없음 — PASS
- 레이아웃: 1920, 1440, 1024, 768, 390, 320 px — Playwright 오버플로 검사 PASS
- 실제 브라우저 200% 확대: NOT_TESTED
- 실제 Safari 사용자 수용: 별도 수동 확인 필요

## 알려진 한계

Markdown은 분석가 검토를 위한 로컬 요약입니다. 보고서에는 브라우저가 기록한 응답 수신 시각이 사용되며 실제 검사 시각이나 코드 snapshot 시각이 아닙니다. 상대 경로와 규칙 식별자는 프로젝트 구조를 드러낼 수 있어 외부 공유 전 검토해야 합니다. 새 커밋 SHA의 원격 CI는 사용자 Push 이후 별도로 확인합니다.
