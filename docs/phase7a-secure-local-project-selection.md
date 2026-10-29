# Phase 7A — 보안 로컬 프로젝트 등록 및 선택 설계

## 상태와 범위

- 기준 커밋: `fd518471d2f9c8d996d5fe35bdda2543f92413f5`
- 시작 Gate: 통과. 로컬 `main`, `origin/main`, 원격 `main`이 기준 SHA와 일치했고 작업 트리는 clean, ahead/behind 0/0이었다.
- 기준 CI: Run `40909765419`, 기준 SHA, `push / completed / success`. Python/CLI, Semgrep OSS 1.182.1, React와 실제 Chromium–FastAPI–Semgrep E2E 필수 job이 성공했다.
- 로컬 검증 런타임: `uv run python`은 Python 3.12.7, Semgrep은 1.182.1.
- 목적: 운영자가 신뢰된 설정으로 여러 로컬 프로젝트를 등록하고, 대시보드 사용자는 ID로 등록된 대상만 선택하게 한다.
- 제외: 브라우저 임의 경로 제출, 폴더 브라우징, GitHub clone, 코드 실행, 서버 API를 통한 등록·삭제.

이 문서는 구현 전에 고정하는 설계다. 구현은 이 선택을 따르며, 바뀌는 판단이 있으면 코드 검증 전에 이유를 기록한다.

## 현재 경계와 조사 결과

현재 `ApiSettings`는 단일 `target_directory`를 보유한다. `ScanService.target_options`는 `local-project` / `Local Project`를 반환하고, 스캔은 그 ID만 허용한다. `POST /api/v1/scans`는 `target_id`와 `rule_profile_id`만 받는다. 응답 DTO에는 상대 파일 경로만 포함되며 target의 절대 경로는 공개되지 않는다.

스캔 전 `_revalidate_target()`은 등록된 경로를 다시 확인하고, 내부 symlink를 거부하며, 파일 항목 수와 preflight 시간을 제한한다. 단일 스캔 lock, 규칙 프로필 allowlist, 토큰 및 Host/Origin 경계도 유지한다.

현재 `_strict_directory()`는 `Path.resolve()` 뒤 결과 경로의 symlink 구성요소를 검사한다. 따라서 원래 입력 경로의 상위 구성요소가 symlink였는지는 해소 전에 검증되지 않을 수 있다. Phase 7A에서는 원래 입력 경로 구성요소를 먼저 검사하고, 그 뒤에만 canonical path를 만든다.

## 등록 설정

### 신규 다중 프로젝트 설정

서버 시작 환경변수 `AI_CODE_SECURITY_TARGETS`에 JSON 배열을 전달한다. 각 항목은 다음 세 키만 가진다.

```json
[
  {"id": "frontend", "label": "Frontend", "path": "/absolute/path/to/frontend"},
  {"id": "service", "label": "Service", "path": "/absolute/path/to/service"}
]
```

예시 경로는 설명용이며 실제 사용자 경로를 문서나 응답에 기록하지 않는다. `path`는 서버 내부 설정으로만 사용한다. 환경변수 설정은 서버 운영자 책임이고 변경 후 서버를 재시작해야 목록이 갱신된다. HTTP 등록/삭제 endpoint는 만들지 않는다.

### 검증 규칙

- 목록은 비어 있지 않아야 하고 최대 32개다.
- ID는 ASCII `[A-Za-z0-9_-]` 1–64자로 제한하고 중복을 거부한다.
- label은 앞뒤 공백이 없는 1–128자 문자열이며 제어·format 문자를 거부한다. NFKC 정규화와 casefold 기준으로 중복 label도 거부해 선택 목록의 모호성을 줄인다.
- 항목 키는 정확히 `id`, `label`, `path`여야 한다. 알 수 없는 키, 잘못된 JSON, 잘못된 형식, 잘못된 경로는 설정 전체를 거부한다.
- 신규 경로는 절대 경로여야 한다. 경로 구성요소에 symlink가 있으면 canonicalization 전에 거부한다. 존재하는 일반 디렉터리여야 한다.
- 등록 대상끼리 동일하거나 서로 포함하는 경로는 거부한다. 각 대상과 trusted rules 디렉터리도 동일·중첩이면 거부한다.
- 오류 메시지에는 설정 오류 코드만 남기고 입력 경로, JSON 본문, 예외 원문을 외부로 내보내지 않는다.
- 설정된 프로젝트 수, ID, label은 metadata만 API로 공개한다. 실제 path와 파일시스템 identity는 서버 메모리에만 남긴다.

### 기존 단일 대상 호환

`AI_CODE_SECURITY_TARGETS`가 설정되지 않으면 기존 `AI_CODE_SECURITY_TARGET`을 계속 받는다. 상대 경로는 기존 동작과 같이 서버의 현재 작업 디렉터리를 기준으로 해석하되, 경로 구성요소 symlink 검사는 적용한다. 이때 기존 API 선택값 `local-project`와 화면 이름 `Local Project`를 그대로 유지한다. 두 환경변수가 모두 설정되면 중복·모호한 설정으로 서버 시작을 거부한다. 둘 다 없으면 기존처럼 필수 설정 누락으로 시작하지 않는다.

새 설정을 쓰는 경우 운영자는 기존 단일 대상 변수를 제거한다. CLI의 `--path` 동작에는 영향을 주지 않는다.

## 경로 및 파일시스템 검증

1. 신규 등록 경로는 절대 경로로 파싱한다.
2. `resolve()` 또는 `realpath()` 전에 경로 구성요소를 하나씩 `lstat`하여 원 경로의 중간·끝 symlink를 거부한다. `..`를 포함한 경로도 해소 전에 각 prefix를 검사한다.
3. 안전하게 canonicalize한 뒤 디렉터리인지, 다른 프로젝트 및 rules 경로와 겹치지 않는지 확인한다.
4. 등록 시 대상 디렉터리의 `(st_dev, st_ino)` identity를 서버 내부 registry에 보관한다.
5. 스캔 직전에 원래 등록된 canonical 경로의 구성요소, 현재 identity, 디렉터리 유형, 프로젝트 간/rules 겹침을 재검증한다. identity가 달라졌거나 경로가 사라진 경우 adapter를 호출하지 않고 기존의 일반 `target_not_allowed` 오류로 거부한다.
6. 기존 내부 symlink 거부, 최대 100,000 항목, 5초 preflight 제한을 선택된 대상마다 유지한다.

원래 입력 경로에서 symlink 검사 후 canonical path를 저장하기 전까지도 동시 파일시스템 변경 경쟁이 가능하다. `(st_dev, st_ino)` 및 스캔 직전 검증은 디렉터리 교체를 탐지하는 방어층이지만 OS sandbox, descriptor 기반 격리, 원자적 filesystem snapshot이 아니며 TOCTOU를 완전히 제거하지 않는다. 동일 사용자가 프로세스·파일시스템을 제어하는 위협 모델에 대한 완전한 격리를 주장하지 않는다.

## API 및 결과 연결

- `GET /api/v1/options`는 기존 `TargetOption(id, label)` 배열을 여러 항목으로 채운다. schema/API 공개 계약은 바꾸지 않는다.
- `POST /api/v1/scans` request DTO는 기존대로 target/profile ID만 받는다. path, upload, arbitrary URL 필드는 추가하지 않는다.
- 서비스는 registry에서 ID를 찾아 해당 내부 경로를 스캔한다. 알 수 없는 ID는 현재 `target_not_allowed` 응답으로 거부한다.
- Finding·Evidence Gate·EvidenceSummary·Consumer 및 응답의 `unverified` 의미는 그대로 둔다. 응답은 계속 상대 경로만 공개한다.
- 요청 당시 선택한 target ID/label은 기존 React scan context에 저장된다. 사용자가 선택을 바꾸면 이전 결과는 이전 context에 계속 연결되고 UI의 기존 설정 불일치 경고가 표시된다. 재검사 전 기존 결과를 새 대상 결과로 바꾸지 않는다.
- 내보내기는 기존 ScanResponse와 scan context를 사용하므로 이전 대상의 ID/label이 유지되며 절대 경로는 포함하지 않는다.
- 목록의 `<option>`은 안전한 label과 ID를 시각적으로 분리해 표시한다. 등록되지 않은 대상 입력 UI는 없다.

## 권한 및 운영 경계

등록·변경·제거 권한은 서버 시작 환경을 관리하는 로컬 운영자에게만 있다. 대시보드 토큰은 기존 스캔 권한만 부여하며 등록 설정을 변경하지 않는다. 목록 변경은 서버 재시작 후 적용된다. 서버는 계속 loopback에만 바인딩되고 API 인증·Host/Origin 정책, 프로필 allowlist, single-flight lock, Semgrep 60초/2 MiB 제한 및 출력 DTO를 유지한다.

환경변수는 서버 프로세스 시작 설정이다. 같은 OS 계정 또는 관리자 권한으로 프로세스 환경을 볼 수 있는 사용자에 대한 비밀 저장소라고 주장하지 않는다. 로컬 운영자와 비신뢰 브라우저 사이의 경계를 제공할 뿐 OS 계정 분리나 저장소 sandbox를 제공하지 않는다.

## 호환성 및 사용자 경험

- 기존 단일 `AI_CODE_SECURITY_TARGET` 사용자는 코드 변경 없이 `local-project` / `Local Project`를 계속 본다.
- 새 다중 등록에서는 사용자가 label과 짧은 ID를 구분할 수 있다. 절대 경로는 UI/API 어디에도 표시하지 않는다.
- Quick Start에는 운영자가 `AI_CODE_SECURITY_TARGETS`를 설정하고 서버를 재시작해야 한다는 절차를 추가한다. 임의 경로 선택이 브라우저에서 가능하다고 표현하지 않는다.
- Phase 6L에서 기록된 부분 검사 도움말의 “함께 표시된 원인” 문구와 원인 코드가 없는 응답 간 불일치는 이번 범위 밖 개선 후보로 유지한다.

## 구현 전 검증 계획

- 기존 단일 프로젝트 API/CLI 및 Finding 계약 회귀.
- 신규 설정 파서: 정상 목록, 중복 ID/정규화 label/path, malformed JSON/키, 상한, 상대·존재하지 않는 경로, rules/target 및 target/target 중첩.
- symlink: target 자체, 상위 구성요소, `..` 이전의 symlink, 내부 파일/디렉터리 symlink, 등록 후 경로 symlink 대체.
- 경로 교체: directory inode/device 변경은 adapter 실행 전 fail-closed.
- API options에 여러 ID/label만 나오며 절대 경로/canary가 없는지 검사.
- 프로젝트 A/B 선택 시 adapter가 정확한 경로를 받고 ID 오인·결과 혼합이 없는지 검증.
- 임의 ID 거부, 인증/Origin/동시 실행 기존 테스트 유지.
- 실제 Semgrep은 격리된 두 합성 프로젝트로 각각 실행하고 상대 경로 및 Finding context를 분리한다.
- 실제 Chromium E2E는 실제 FastAPI/Semgrep에 두 개의 합성 등록 프로젝트를 제공해 선택·실행·context를 확인한다.
- 전체 Python, 기존 Semgrep 1.182.1 평가, Frontend typecheck/Vitest/build/Chromium mock 및 실 브라우저 E2E를 재실행한다.

## 주요 한계

- 로컬 프로세스와 같은 사용자 권한을 가진 공격자에 대한 OS 파일시스템 격리는 아니다.
- directory identity 검사와 스캔 직전 preflight도 스캔 프로세스가 파일을 열기 전후의 모든 TOCTOU를 제거하지 않는다.
- 권한 있는 로컬 운영자가 신뢰할 프로젝트만 등록해야 한다. 이 Phase는 비신뢰 저장소 코드를 실행하지 않지만, Semgrep은 파일을 읽고 파싱한다.
- 원격 GitHub URL, 저장소 fetch/clone, 임의 폴더 선택 및 저장소별 격리는 향후 별도 위협 모델과 설계가 필요하다.

## 구현 및 검증 결과

### 구현

- 서버 시작 시 `AI_CODE_SECURITY_TARGETS`를 엄격한 JSON 배열로 읽는다. 각 객체의 키는 `id`, `label`, `path`만 허용하며 JSON 객체 내부의 중복 키도 거부한다. 설정은 64 KiB, 프로젝트 수는 32개로 제한한다. 설정 오류는 고정된 `local_api_configuration_invalid`만 노출한다.
- 기존 `AI_CODE_SECURITY_TARGET`은 `local-project` / `Local Project`로 유지된다. 둘 중 하나만 설정해야 하며, 다중 설정으로 바꾸려면 서버를 재시작한다.
- 대상 목록 API는 기존 DTO의 ID와 label만 반환한다. 요청에는 기존 `target_id`만 전달하고 서버가 내부 registry에서 경로를 선택한다. 미등록 ID는 `target_not_allowed`로 거부된다.
- 대상마다 등록 시 `(st_dev, st_ino)`를 기록하고 검사 직전에 경로 symlink, 현재 directory identity, 규칙 경로 및 다른 등록 대상과의 중첩을 재검증한다. 경로 확인이 끝나기 전에 Semgrep adapter를 만들거나 호출하지 않는다. 내부 symlink, 100,000 항목 및 5초 preflight 한도를 유지한다.
- `_strict_directory()`가 경로를 해소하기 전에 각 경로 구성요소를 검사하도록 수정했다. 상위 구성요소 symlink가 canonicalization으로 사라져 허용되던 기존 동작을 실패 테스트로 재현한 뒤 차단했다.
- 대시보드 선택 목록은 label과 ID를 함께 보여준다. 이전 결과의 검사 context와 Markdown export는 요청 당시 프로젝트 ID/label을 유지한다. Quick Start는 다중 환경변수 설정, 레거시 단일 설정, 서버 재시작을 안내한다.
- Workflow 파일은 수정하지 않았다. 기존 Semgrep job은 `tests/test_api_semgrep_e2e.py`를 실행하고 기존 React job은 실제 브라우저 E2E runner를 호출한다.

### 보안 및 계약 확인

- `TargetOption(id, label)` 및 ScanRequest의 `target_id`, `rule_profile_id` 계약은 변경하지 않았다. OpenAPI/DTO, Finding, Evidence, Gate/Consumer, CLI, 규칙, 토큰 및 Host/Origin 정책도 변경하지 않았다.
- 등록 경로는 API options, scan response, UI, 다운로드에 포함되지 않는다. 응답은 기존대로 상대 파일 경로만 제공하며 Finding은 `unverified`를 유지한다.
- 프로젝트 코드는 실행하지 않는다. 서버는 loopback 전용이며 임의 경로 입력, 업로드, Git clone 기능은 없다.
- 서버 운영자는 신뢰하는 프로젝트만 등록해야 한다. 동일 OS 사용자 권한의 공격자에 대한 샌드박스가 아니며, 스캔 전후 동시 파일시스템 변경 TOCTOU 위험을 완전히 제거하지 않는다.
- Phase 6L에서 지적된 부분 검사 원인 코드가 없을 때의 “함께 표시된 원인” 안내 문제는 변경하지 않았고 별도 UX 개선 항목으로 유지한다.

### 검증 결과

최종 검증 결과는 로컬 실행 출력에 근거한다. 원격 CI 성공을 Phase 변경분에 대해 주장하지 않는다.

- 시작 Gate: 기준 SHA와 Run `40909765419` 성공, 시작 시 working tree clean 및 ahead/behind 0/0.
- `uv lock --check`: 통과.
- `uv sync --locked --dev`: 통과.
- Python 전체 회귀: `SEMGREP_REQUIRED=1 uv run --locked python -m pytest -q -rs` 결과 542 passed, 28 skipped. Skip은 기존 opt-in Ollama 테스트다.
- Semgrep OSS: `1.182.1`; 실제 API 통합은 2 passed이며 등록된 두 합성 프로젝트 중 Finding이 있는 두 번째 프로젝트를 선택 검사했다. 첫 프로젝트는 0건, 두 번째는 `baseline.javascript-dynamic-eval` 1건과 상대 경로 `selected.js`를 반환했다.
- Node.js: `24.22.2`; `npm ci` 성공, npm audit 취약점 0, typecheck 성공, Vitest 42 passed, production build 성공, Chromium mock 3 passed.
- 실제 Chromium → FastAPI → Semgrep E2E: 1 passed. 두 번째 등록 프로젝트를 UI에서 선택했고 실제 Semgrep 1.182.1 Finding, 선택된 target ID/context, 사용자 클릭 Markdown 다운로드를 확인했다.
- `uv lock --check`, `uv sync --locked --dev`: 통과.
- `git diff --check`: 현재 통과.
- 기존 Phase 6A–6L 평가 Oracle/결과, Semgrep 규칙, `uv.lock`, `package-lock.json`, dependency: 변경하지 않음.

`npm ci` 중 npm은 `fsevents`의 install script가 승인되지 않았다는 경고를 표시했지만 설치·빌드·테스트는 통과했다. 이 의존성의 설치 스크립트 허용 정책은 변경하지 않았다.

이 Phase의 결과는 등록된 합성 프로젝트에 대한 로컬 검증이다. 실제 사용자 저장소에 대한 정확도, OS 격리, 완전한 TOCTOU 방어는 검증하거나 주장하지 않는다.
