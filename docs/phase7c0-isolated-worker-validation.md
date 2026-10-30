# Phase 7C-0 — 격리 분석 워커 실행 가능성 및 보안 검증

## 판정

**`PHASE_7C_0_ISOLATION_HOLD`**

기준 커밋에서 정의한 원격 저장소 분석 전제조건 중 비관리자 실행, 작업별 filesystem allowlist, 메모리/PID/총 디스크 quota, worker crash 정리, 독립된 분석 환경을 확인하지 못했다. 그러므로 이 환경에서는 비신뢰 저장소를 처리할 worker를 구현하거나 GitHub Intake로 넘어갈 수 없다. 기존 등록 로컬 프로젝트 기능은 계속 사용할 수 있다.

## 1. 시작 Gate

- 저장소 remote: `misosos/ai-code-security-analyzer`
- Branch: `main`
- 기준/로컬 HEAD/`origin/main`/GitHub `main`: `bc53a8c4415822576ec0c7cefe699cdabe2d119b`
- Working tree 시작 시 clean
- Ahead/behind 시작 시 `0/0`
- 기준 CI: Run `40919535112`, 정확한 SHA, `push / completed / success`
- 필수 job: `Python tests and CLI`, `Semgrep 1.182.1 integration`, `React dashboard` 모두 success. React job의 typecheck/test/build, Chromium smoke, 실제 Chromium–FastAPI–Semgrep E2E 단계도 success.

Gate 통과 후 조사와 검증을 수행했다. 최종 상태와 로컬 변경은 문서 마지막 절을 참조한다.

## 2. Phase 7B 차단 조건

Phase 7B의 `7C 착수 전 필수 증명`은 다음 여섯 항목이다.

1. Downloader와 Analyzer 분리, Analyzer의 OS 수준 egress deny.
2. scan 단위 임시 workspace, traversal/symlink race 방어 및 실제 디스크 quota.
3. redirect allowlist와 DNS pin/socket peer 검증.
4. 악성 archive와 자원 고갈 사례에 대한 fail-closed 추출기.
5. Git tree와 archive 내용의 commit identity 검증.
6. 서버 강제 종료 후 잔존 데이터 발견·정리 절차.

이번 Phase는 외부 수집을 금지했으므로 3–6번은 실행하거나 구현하지 않았다. 이들의 선행조건인 격리 worker 역시 전체 검증되지 않았다.

## 3. 조사 환경 및 런타임

- 실제 환경: macOS 15.7.7, Apple Silicon arm64.
- CI workflow: GitHub Actions `ubuntu-latest`; 현재 workflow는 일반 Python/React/Semgrep job이며 worker 전용 egress 격리, resource cgroup, worker filesystem 경계를 설정하지 않는다.
- `uv run --locked python --version`: Python 3.12.7. 시스템 `python3`는 3.14.7이므로 프로젝트 검증은 uv의 3.12.7을 사용했다.
- Semgrep OSS: `1.182.1`.
- Docker CLI는 있지만 Docker daemon socket에 연결할 수 없었다. OCI container 실행·network·quota 검증은 하지 않았다.
- VMware Fusion과 `vmrun`, QEMU 실행 파일이 설치돼 있다. `vmrun`은 기존 실행 VM이 있음을 보고했다. 그 VM은 사용자의 기존 자원일 수 있어 식별·접속·변경하지 않았고, 격리 fixture나 전용 guest가 있는지 확인하지 않았다. 따라서 사용 가능한 disposable worker로 간주하지 않는다.
- `/usr/bin/sandbox-exec`는 존재하지만 macOS man page에서 deprecated로 표시된다. `unshare`, `bwrap`, `firejail` 및 Linux cgroup은 이 macOS host에서 제공되지 않는다.
- 현재 사용자 ID는 비 root UID지만 `admin` group에 속한다. 별도 비관리자 service account는 확인·생성하지 않았다. sandbox 자식 프로세스도 이 UID/group 권한을 유지한다.

설치 여부만으로 격리 효과를 인정하지 않았다. 기존 VM을 켜거나 재설정하지 않았고, 이미지 또는 패키지를 다운로드하지 않았다.

## 4. 격리 방식 비교 및 선택

| 방식 | 현재 확인 | 보안 통제 가능성 | 이번 Phase 결론 |
|---|---|---|---|
| Docker/OCI disposable worker | CLI만 있고 daemon 접속 실패 | Linux에서는 namespace, read-only mount, capability 제거, seccomp와 cgroup 결합 가능. macOS Docker Desktop은 Linux VM 내부 동작과 host 공유 범위를 별도 검증해야 함 | 실행 불가. 이미지 pull/build/worker 실행 안 함 |
| VM worker | VMware Fusion/QEMU binary 존재, 기존 실행 VM 존재 보고 | guest boundary와 VM 단위 CPU/RAM/disk 및 NIC 설정 가능하나 host share, network mode, guest image와 cleanup 검증 필요 | 안전한 전용 guest가 확인되지 않아 기존 VM 접근 안 함 |
| macOS Seatbelt `sandbox-exec` | binary 존재, deprecated | 일부 파일 접근과 네트워크 작업을 policy로 제한 가능. 현재 사용자 권한을 바꾸지 않고, 이 probe에서 작업별 CPU/RAM/PID/disk quota를 강제하지 않음 | 부분 통제 probe만 수행. worker로 채택하지 않음 |
| 단순 subprocess/ulimit | OS resource API 존재 | timeout/CPU/per-file size 등 일부 제한. OS 계정·네트워크·전체 filesystem·총 disk 격리 대체 불가 | 단독 worker로 불충분 |

**실행 가능한 worker 방식을 선택하지 않았다.** Linux의 rootless OCI + cgroup 환경을 우선 후보로 재검증할 수 있지만, 현재 Ubuntu CI 또는 로컬에서 그 런타임·권한·네트워크 정책을 실제 확인하지 않았다. macOS 지원을 위해 별도 Linux disposable VM을 사용하더라도 같은 요구사항을 다시 검증해야 한다.

## 5. 실제 합성 probe

실제 GitHub 저장소, 외부 IP, 외부 HTTP, 실제 사용자 프로젝트는 사용하지 않았다. 임시 합성 파일과 loopback listener만 이용했다. probe는 `/private/tmp` 아래 임시 디렉터리에서 실행 후 정리했다.

### macOS Seatbelt 부분 검증

고정된 작은 Python probe에서 `sandbox-exec` policy를 사용했다. 관찰 결과:

- synthetic input 읽기: 성공.
- checkout의 README 경로 읽기: 거부.
- input fixture에 쓰기: 거부.
- 제한 출력 디렉터리에 쓰기: 성공.
- loopback TCP listener 접속: `PermissionError`로 거부되었고 listener가 연결을 받지 않음. 실제 외부 패킷은 보내지 않았다.
- 외부 DNS 조회/HTTP: 실행하지 않음.
- 실제 FastAPI 서버: 기동하지 않음. loopback listener는 네트워크 syscall 차단 probe이며 API 인증·Host 경로 시험이 아니다.

이 policy는 file-read를 넓게 허용하고 checkout subtree만 명시적으로 거부하는 probe였다. 안전한 worker처럼 OS/runtime 접근만 허용하는 strict allow-only profile은 아니며, Python runtime을 좁은 읽기 allowlist 안에서 실행하려 한 probe는 process abort(exit 134 또는 signal 6)로 끝났다. 이 실패를 정상 격리 성공으로 계산하지 않았다. 따라서 **다른 모든 사용자 파일이 차단되었다고 주장하지 않는다.**

### 일부 per-process resource limit 시험

- `RLIMIT_CPU=1초`를 설정한 합성 tight loop가 약 1초 뒤 `SIGXCPU`(return code `-24`)로 종료됐다.
- `RLIMIT_FSIZE=1 KiB` 설정에서 4 KiB 출력 시도 결과 파일은 1 KiB를 넘지 않았다. 이는 개별 파일 제한일 뿐 workspace 총량 제한이 아니다.
- macOS의 현재 `launchctl limit`/`ulimit`은 CPU와 메모리/주소 공간 등 주요 전체 제한을 `unlimited`로 보고했다. maxproc 값은 사용자 단위이며 scan별 PID quota 증거가 아니다.
- 메모리 초과, 작업별 PID 상한, workspace total disk quota, disk full, cancel/kill 뒤 workspace 및 자식 process 정리는 검증하지 않았다.

## 6. 요구 시나리오별 결과

| 번호 | 시나리오 | 결과 | 근거 및 제한 |
|---:|---|---|---|
| 1 | 격리 worker에서 정상 Semgrep 합성 검사 | **NOT_TESTED** | 기존 Semgrep regression은 host에서 성공했지만, 검증된 worker 안의 Semgrep은 실행하지 않음 |
| 2 | 외부 IP 연결 차단 | **부분 확인** | `network-outbound` policy로 loopback listener 연결 거부. 외부 IP 패킷 시험은 하지 않음 |
| 3 | DNS 및 외부 HTTP 차단 | **NOT_TESTED** | DNS lookup·HTTP 요청을 하지 않음 |
| 4 | 로컬 API 접근 차단 | **부분 확인** | loopback TCP listener 접근 거부. FastAPI route 자체는 기동·요청하지 않음 |
| 5 | 허용되지 않은 Host 경로 차단 | **NOT_TESTED** | HTTP 요청 단계 미도달. API Host middleware 별도 시험 아님 |
| 6 | 입력 read-only | **부분 확인** | fixture 읽기 성공, 쓰기 거부. strict allow-only filesystem 불가 |
| 7 | 제한된 출력만 쓰기 | **부분 확인** | 지정 출력 directory 쓰기 성공 및 input 쓰기 거부. OS/runtime 외 다른 사용자 파일 read 차단은 증명 안 됨 |
| 8 | 비관리자 사용자 | **실패** | 현재 계정이 admin group이며 별도 비관리자 worker 계정이 없음 |
| 9 | CPU/RAM/PID/disk 제한 초과 | **부분 확인** | 자식 process CPU 1초, 파일 크기 1 KiB만 강제 동작 확인. RAM/PID/총 disk quota 미확인 |
| 10 | Timeout 후 worker 및 자식 정리 | **NOT_TESTED** | 기존 Semgrep Adapter timeout unit test는 통과했으나 worker process tree를 시험하지 않음 |
| 11 | 비정상 종료 후 임시 데이터 | **NOT_TESTED** | probe harness 정상 종료 후 임시 디렉터리를 정리했음. worker 강제 종료 잔여물 시험은 아님 |
| 12 | Privacy canary 비노출 | **NOT_TESTED** | canary를 응답·로그·worker 결과 경로로 흘리는 검증은 수행하지 않음 |
| 13 | 기존 로컬 프로젝트 기능 회귀 | **통과** | 아래 회귀 결과 참조. 원격 intake와 분리된 기존 기능에 한함 |

## 7. 기존 회귀 검증

실행 환경: uv Python 3.12.7, Semgrep OSS 1.182.1. 환경 변수 `SEMGREP_REQUIRED=1`, `SEMGREP_SEND_METRICS=off`, `SEMGREP_ENABLE_VERSION_CHECK=0`.

- 집중 API/Adapter/Semgrep regression:
  `uv run --locked python -m pytest -q tests/test_semgrep_adapter.py tests/test_semgrep_integration.py tests/test_api_scan.py tests/test_api_security.py`
  → **48 passed**.
- 전체 Python 회귀:
  `uv run --locked python -m pytest -q -rs`
  → **542 passed, 28 skipped**, 1 기존 Starlette deprecation warning. Skip은 opt-in Ollama synthetic evaluation이다.
- 전체 Python 회귀는 기존 Semgrep·API/local scan 관련 테스트를 포함하며 host 환경에서 실행됐다. 격리 worker 검증 또는 외부 GitHub intake 검증 결과가 아니다.
- Frontend/Chromium 재실행: **NOT_TESTED**. 이번 Phase에서 UI/API 계약 및 production code를 변경하지 않았다.

## 8. 개인정보 및 변경 범위

- 합성 문자열만 사용했고 외부 네트워크 목적지에는 패킷을 보내지 않았다.
- 기존 VM을 사용하거나 종료하지 않았다. Docker daemon을 시작하지 않았다.
- probe 임시 파일은 harness 종료 시 정리했다. worker의 crash cleanup 증거가 아니다.
- Semgrep 규칙, 분석 엔진, API/CLI/Frontend, dependencies 및 기존 평가 자료 변경 없음.
- 변경 문서는 이 보고서 하나다. 사용자 절대 경로, credential, 코드 원문 및 privacy canary 값은 기록하지 않았다.
- 문서 공백 검사: trailing whitespace 없음. `git diff --no-index --check /dev/null <문서>`는 신규 파일 차이 때문에 exit 1이지만 공백 오류 출력은 없었다.

## 9. Phase 7C 착수 조건

현재 판정은 **격리 실행 경로가 없다**는 의미다. 다음을 만족하는 전용 환경이 준비될 때까지 Remote Scan은 fail closed여야 한다.

1. macOS와 Ubuntu에서 각각 버전·digest가 고정된 disposable Linux VM 또는 검증 가능한 OCI runtime을 준비하고, 개인/기존 VM·host credential에 접근할 수 없게 한다.
2. worker UID가 비관리자임을 확인하고, input은 검증된 synthetic workspace만 read-only bind, output은 전용 제한 directory만 허용한다.
3. egress/inbound network가 OS/VM 경계에서 차단됨을 실제 loopback sink, synthetic DNS fixture, socket syscall 정책 시험으로 확인한다. 외부 IP로 시험 패킷을 보내지 않는다.
4. memory, CPU, PID, disk, process count 및 deadline 제한이 작업별로 실제 강제됨을 초과 시험한다. macOS의 `RLIMIT_FSIZE`만으로 total disk 제한을 대체하지 않는다.
5. Semgrep 1.182.1의 신뢰 이미지 또는 로컬 설치, 규칙 bundle, 설정 및 cache 경로를 digest/해시로 고정하고, Semgrep이 synthetic input 외 경로를 읽지 못함을 확인한다.
6. timeout, cancellation, worker kill 및 host crash를 시험해 child process 종료와 잔존 workspace 탐지·정리 동작을 확인한다.
7. worker stdout/stderr/API/HTML에 source, credential, 절대 경로, canary가 없는지 자동 검사한다.

전용 환경이 없으면 별도의 승인된 CI/격리 runner를 마련한 뒤 그 환경에서만 remote intake를 개발한다. 이 보고서 완료만으로 Phase 7C archive parser, downloader, GitHub API 또는 실제 저장소 분석 착수를 허용하지 않는다.

## 최종 판정

### `PHASE_7C_0_ISOLATION_HOLD`

macOS Seatbelt의 일부 제한과 process-level CPU/per-file limit은 합성 probe에서 관찰했으나, 요구된 통합 격리 워커가 아니다. 비관리자 실행, 전면 egress deny의 DNS/HTTP 검증, strict filesystem isolation, RAM/PID/total disk quota, 강제 종료 후 cleanup 및 격리 내 Semgrep scan이 확인되지 않았다. 해당 환경에서 비신뢰 GitHub 저장소 분석은 허용할 수 없다.

---

## Phase 7C-0R — 환경 복구 조사 후속 기록

이 절은 앞의 Phase 7C-0 결과를 보존하면서 환경 상태만 다시 조사한 기록이다. 기존 HOLD를 PASS로 바꾸지 않는다.

### 시작 Gate 및 현재 상태

- 저장소 remote: `misosos/ai-code-security-analyzer`
- Branch: `main`
- Local HEAD, `origin/main`, GitHub `main`: `bc53a8c4415822576ec0c7cefe699cdabe2d119b`
- 시작 working tree: 기존 사용자 작성 문서 하나만 미추적 상태
- Ahead/behind: `0/0`
- Run `40919535112`: 정확한 SHA의 `push / completed / success`
- 필수 Python, Semgrep 1.182.1, React 및 실제 Chromium–FastAPI–Semgrep E2E 단계: 성공

Gate는 통과했다. 이 후속 조사에서도 서버, 컨테이너, VM, 외부 저장소 분석은 실행하지 않았다.

### 읽기 전용 런타임 조사

- Host: macOS 15.7.7, Apple Silicon `arm64`
- 사용자: UID 502, `admin` 그룹 소속. 전용 비관리자 worker 계정은 확인되지 않았다.
- Docker CLI: 29.8.2, 활성 context `desktop-linux`
- Docker Desktop 앱: `/Applications/Docker.app`에 설치돼 있음
- Docker daemon: 연결 불가. 활성 context의 socket 파일이 없고 Docker API 연결이 실패했다.
- Podman, Colima, Lima: 실행 파일 없음
- VMware Fusion의 `vmrun` 및 QEMU 실행 파일: 설치돼 있음. `vmrun list`에서 실행 중인 VM은 0개였으며, VM을 시작하거나 설정·이미지를 변경하지 않았다.
- 확인된 disposable Linux guest 또는 검증된 독립 worker: 없음

Docker Desktop이 설치돼 있다는 사실은 daemon의 준비나 격리 통제의 검증을 뜻하지 않는다. 앱/daemon을 시작하지 않았으며, QEMU·VMware도 guest를 준비하거나 실행하지 않았다.

### 기존 격리 증거와 이번 조사에서 추가된 증거

앞 절에 기록된 Seatbelt 부분 probe와 CPU/per-file limit 결과는 그대로 유효한 제한적 관찰이다. 이번 Phase 7C-0R에서는 새로운 worker 실행이나 Semgrep 실행을 하지 않았다.

| 통제 | Phase 7C-0R 결과 |
|---|---|
| 격리 worker에서 Semgrep 1.182.1 실행 | `NOT_TESTED` — 사용 가능한 worker runtime 없음 |
| Docker OCI runtime | `NOT_AVAILABLE` — Docker Desktop 설치, daemon 연결 불가 |
| 비관리자 UID/GID | `NOT_AVAILABLE` — 현재 계정은 `admin` 그룹, 전용 계정 없음 |
| Host 파일·프로젝트 접근 차단 | 앞 절의 부분 probe만 있음; 완전한 filesystem 격리는 미검증 |
| DNS/HTTP/TCP egress 차단 | 앞 절의 loopback 거부 probe 외에는 미검증 |
| CPU/RAM/PID/총 디스크 quota | 앞 절의 CPU 및 단일 파일 크기 제한만 부분 확인; RAM/PID/총량 quota 미검증 |
| worker timeout, 강제 종료, 자식 프로세스 및 crash cleanup | `NOT_TESTED` |
| privacy canary 격리 경로 비노출 | `NOT_TESTED` |
| macOS/Ubuntu 간 동일 통제 재현 | `NOT_TESTED` |

앞 절의 전체 Python 회귀(`542 passed, 28 skipped`)는 Phase 7C-0에서 host 환경으로 실행한 결과이며, 이번 환경 조사에서 재실행하지 않았다. 그 결과는 격리 증명이 아니다. 이번 조사에서 코드·의존성·CI 설정은 변경하지 않았다.

### 환경 복구에 필요한 다음 조치

현재 상태에서 다음 중 하나를 운영자가 준비해야 한다.

1. Docker Desktop daemon을 운영자가 명시적으로 시작하고, 신뢰된 로컬 이미지와 전용 격리 테스트 구성을 제공한다. 시작 뒤에도 rootless/비관리자 실행, 네트워크 차단, filesystem 경계, 자원 한도 및 cleanup을 각각 실제 초과 시험으로 검증해야 한다.
2. 또는 기존 사용자 VM과 분리된 disposable Linux guest/runner를 운영자가 준비한다. host 홈·credential·Docker socket 공유 없이, worker용 비관리자 계정과 실제 강제되는 network/cgroup/disk 경계를 제공해야 한다.

런타임 설치·시작, VM 생성/변경 또는 시스템 네트워크 설정 변경은 이번 조사에서 하지 않았다. 환경을 준비한 뒤에도 7B의 URL/SSRF, redirect/socket peer, archive 추출, commit-tree 동일성 및 잔존 파일 처리 차단 조건은 별도로 해결해야 한다.

### Phase 7C-0R 판정

**`PHASE_7C_0R_ENVIRONMENT_HOLD`**

필요한 격리 실행 환경이 준비되지 않았다. 따라서 필수 통제 시험과 격리 worker 내 Semgrep 검증은 시작하지 않았다. 비신뢰 GitHub 저장소를 내려받거나 분석하지 않는다. 앞 절의 `PHASE_7C_0_ISOLATION_HOLD`는 변경 없이 유지한다.

---

## Phase 7C-0R — Docker Desktop 활성화 후 재평가

이 절은 사용자가 Docker Desktop을 직접 시작한 뒤 수행한 후속 조사다. 앞선 환경 장애 기록은 당시의 관찰로 보존한다. 이 재평가에서 GitHub 저장소를 내려받지 않았다.

### 재확인한 런타임

- Branch/HEAD/`origin/main`: `main` / `bc53a8c4415822576ec0c7cefe699cdabe2d119b`
- Working tree: 이 문서 하나만 미추적. Ahead/behind `0/0`.
- Docker Desktop: 4.95.0
- Docker Engine/CLI: 29.8.2, context `desktop-linux`
- Engine: Linux ARM64, cgroup v2, seccomp builtin 지원
- 자원: 8 CPU, 약 7.75 GiB 메모리
- 조사 시 실행 중인 컨테이너: 0. 조사 후에도 잔여 컨테이너 없음.
- Docker info에는 HTTP/HTTPS proxy와 no-proxy 설정이 존재한다고 표시됐다. 실제 proxy URL이나 값을 기록하지 않았다. Proxy 설정은 `--network none` 또는 egress deny의 증거로 취급하지 않는다.

### 로컬 이미지 검토

자동 pull은 하지 않았다. 확인한 로컬 이미지 및 digest:

| 로컬 이름 | 플랫폼 | 로컬 digest / image ID |
|---|---|---|
| `python` | linux/arm64 | `sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e` |
| `python` | linux/amd64 | `sha256:2b4f19dae3a777dfc3b76730bda1e82e1f66ab2a2686fa93ca78edbfb4f04ffe` |
| `debian` | linux/amd64 | `sha256:a4672c0cb26fbdde88e38fa2dfb6c681942306680e41e4378b28770b6e79ee91` |
| `busybox` | linux/arm64 | `sha256:d82c2ab94640ded77cf76514ce6a84870761105058a4a9e51b05a8a79be97a6c` |
| `node` | linux/arm64 | `sha256:f4a1ba23ca013418f51f7d4d4673d8f8797241b68c05436a8825031a84c9f4e6` |

이미지에는 일반적인 태그가 없고, 표기된 repo digest는 각 로컬 image ID와 같다. 라벨 및 provenance 자료도 확인되지 않았다. 모든 이미지의 기본 `Config.User`는 비어 있어 기본 실행 사용자는 root다. 명시적으로 `--user`를 지정하면 UID를 바꿀 수 있지만, 이미지의 신뢰 출처를 입증하는 것은 아니다. 목록에 Semgrep 전용 이미지도 없다. 따라서 이 이미지 중 하나를 신뢰된 Semgrep worker 이미지로 승인하지 않았다.

이미지 도구 존재 여부를 알아보려는 제한된 availability probe 명령을 실행했으나, 각 이미지의 기본 command/entrypoint와 전달 인자 차이 때문에 유효하고 재현 가능한 Semgrep 버전 결과를 얻지 못했다. 해당 probe는 worker 검증으로 계산하지 않는다. 이 과정은 `--pull=never`, `--network none`, read-only root, capability 제거, no-new-privileges, 제한된 PID/RAM/CPU 설정, host bind mount 없음으로 실행했다. 결과적으로 설정 플래그를 준 한 번의 probe는 확인되지만 그 제한의 실제 강제 증거는 아니다.

Docker `none` 네트워크 객체는 `driver=null`, `internal=false`로 보였다. 이는 네트워크 객체 설정에 관한 정보일 뿐, DNS/HTTP/TCP 차단의 실제 효과를 시험한 결과가 아니다. Docker Desktop proxy가 설정돼 있으므로, 검증된 무네트워크 worker 없이 proxy 설정이나 환경변수 제거를 네트워크 차단 대용으로 취급하지 않는다.

### 요구 통제 결과

| 검증 항목 | 결과 | 판정 이유 |
|---|---|---|
| Docker Linux runtime 사용 가능 | **확인** | daemon 연결 및 Linux ARM64 Engine 정보 확인 |
| 신뢰된 worker image 및 digest/provenance | **미확인** | 로컬 이미지의 registry provenance/서명 근거 부족, 전용 Semgrep 이미지 없음 |
| 비관리자 UID/GID | **NOT_TESTED** | 이미지 기본 사용자는 root이며, 신뢰된 분석 이미지로 UID override 효과를 검증하지 않음 |
| Docker socket/host 홈/프로젝트 미마운트 | **설정상 미사용** | 제한 probe에 bind mount 없음. 실제 worker 설계 검증으로 간주하지 않음 |
| read-only 입력 및 host 파일 차단 | **NOT_TESTED** | 신뢰된 Semgrep worker와 합성 입력 mount를 사용한 접근 시험 없음 |
| 전용 출력 경로만 쓰기 및 디스크 quota | **NOT_TESTED** | 총 작업별 disk quota 강제 시험 없음 |
| `--network none` DNS/HTTP/TCP/host loopback 차단 | **NOT_TESTED** | 네트워크 객체를 조회했으나 실제 통제된 sink로 차단 시험 안 함 |
| CPU/memory/PID 제한 강제 | **NOT_TESTED** | 옵션의 런타임 초과 효과를 검증하지 않음. Desktop 전체 8 CPU/7.75 GiB 정보는 worker quota가 아님 |
| 실제 Semgrep OSS 1.182.1 실행 | **NOT_TESTED** | 신뢰된 로컬 이미지에서 유효한 Semgrep 실행을 확인하지 못함 |
| timeout, 자식 프로세스 종료 및 cleanup | **NOT_TESTED** | 신뢰된 worker process tree를 대상으로 시험 안 함 |
| 강제 종료 후 임시파일 정리 | **NOT_TESTED** | crash/kill cleanup 시험 안 함 |
| 개인정보 canary 비노출 | **NOT_TESTED** | 신뢰된 worker stdout/stderr/API 경로 검증 안 함 |
| 기존 로컬 API 동작 | **NOT_TESTED (이번 재평가)** | API 회귀를 재실행하지 않음. Phase 7C-0의 기존 host 회귀 결과와 구분함 |

### 재평가 판정

**`PHASE_7C_0R_VALIDATION_HOLD`**

Docker 런타임 환경은 사용 가능해졌으나, 로컬 이미지 신뢰성, 실제 통제 효과, 격리된 Semgrep 실행 및 cleanup이 검증되지 않았다. 이미지 provenance가 확인된 기존 worker 이미지/재현 가능한 공급망 근거를 마련하거나, 사용자가 승인한 검증된 worker 이미지를 제공해야 다음 실제 격리 시험으로 진행할 수 있다. 새로운 이미지 pull은 수행하지 않았다.

Phase 7B의 GitHub URL/SSRF, redirect와 socket peer 검증, 안전한 archive 추출, commit-tree 동일성, 작업 디렉터리 수명/잔존물 통제는 여전히 별도 선행 조건이다. 이 재평가는 GitHub Intake 구현 착수나 완료를 승인하지 않는다.

---

## Phase 7C-0S — 승인된 Worker 이미지 확보 및 정적 검증

이 단계에서는 사용자가 승인한 이미지 하나만 다운로드했다. 이미지를 빌드하거나 컨테이너로 실행하지 않았으며, GitHub 저장소나 사용자 프로젝트도 받지 않았다.

### 이미지 후보 및 공식 배포 정보

2026-10-30 공개 Docker Hub 메타데이터 확인 결과:

- 요청 태그: `semgrep/semgrep:1.182.1-nonroot`
- Docker Hub 저장소는 Semgrep, Inc.의 Verified Publisher로 표시되며, 공식 Semgrep Docker 이미지라고 설명한다.
- 태그 페이지는 태그 변경 불가(immutable)로 표시한다.
- 태그가 `linux/arm64`와 `linux/amd64` manifest를 제공한다.
- 다중 플랫폼 index digest: `sha256:0ed16bbbb23e5bf7c442df9144704d74b54ad2d003094e09905130d642f22473`
- linux/arm64 manifest digest: `sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5`
- linux/amd64 manifest digest: `sha256:09e80829f545f1cfa3681632edb60df3b6db0ca0d35db838eee362103d5eeff0`
- Docker Hub가 표시한 압축 크기: ARM64 약 421.34 MB, AMD64 약 411.59 MB.

공식 Docker Hub 저장소/태그와 Semgrep의 Docker 사용 안내를 출처 확인 근거로 삼았다. Verified Publisher 및 공식 이미지 표시는 배포자 계정·공식 배포 경로에 대한 신뢰 신호이지, 개별 이미지의 암호학적 서명 검증 결과는 아니다.

### 승인된 다운로드 및 로컬 정적 검사

실행한 다운로드는 다음 digest와 플랫폼으로 제한했다.

```text
docker pull --platform=linux/arm64 semgrep/semgrep@sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5
```

- Pull 성공. Docker의 반환 digest와 요청 ARM64 manifest digest 일치.
- 로컬 image ID 및 `RepoDigests`가 동일한 `sha256:cfb298...`를 가리킴.
- 로컬 플랫폼: `linux/arm64`.
- 로컬 이미지 크기: `1,614,851,729` bytes(약 1.61 GB, unpacked image size).
- Registry의 압축 전송 크기 표기: 약 421.34 MB. Docker가 실제 전송한 바이트 수는 별도로 계측하지 않음.
- Static image config: `USER semgrep`; `ENTRYPOINT` 없음; `CMD ["semgrep", "--help"]`; `WORKDIR /src`.
- OCI labels: source `https://github.com/semgrep/semgrep-proprietary`, revision `6f7d77ede012b0301d5051f8f5552530c17210c7`.
- 실행한 컨테이너: 없음. 따라서 실제 `semgrep --version`은 **NOT_TESTED**.

### 태그 버전과 빌드 metadata 차이

- Docker Hub 태그와 미서명 Scout SBOM component는 Semgrep `1.182.1`을 가리킨다.
- 이미지의 `DOCKER_OTEL_RESOURCE_ATTRIBUTES`에는 `vcs.ref.head.name=release-1.182.0`이 들어 있다.
- OCI revision은 `6f7d77ede012b0301d5051f8f5552530c17210c7`이다.
- 이 태그/패키지 버전과 VCS ref 간의 차이가 빌드 branch 명명인지 실제 source mismatch인지는 확인되지 않았다. 컨테이너를 실행하지 않았고, SBOM 서명 검증도 실패했으므로 실제 실행 바이너리 버전의 증거로 사용하지 않는다.

### 서명, provenance 및 SBOM 상태

Docker Scout attestation 목록은 이미지 manifest를 subject로 하는 다음 항목을 반환했다.

- CycloneDX BOM v1.6 (`https://cyclonedx.org/bom/v1.6`)
- Docker Scout provenance v0.1 (`https://scout.docker.com/provenance/v0.1`)
- Docker Scout SBOM v0.1 (`https://scout.docker.com/sbom/v0.1`)

Scout가 표시한 CycloneDX 내용에는 `pkg:pypi/semgrep@1.182.1` component가 있었지만, 이는 서명 검증되지 않은 SBOM의 내용으로만 기록한다.

Docker Scout `attest get --verify`를 CycloneDX BOM 및 Scout provenance에 각각 실행한 결과는 모두 `no matching signatures: signature not found in transparency log`로 실패했다. 이 결과는 해당 Scout attestation을 사용한 검증 경로에서 유효한 서명을 확인하지 못했다는 뜻이다. 별도 서명 방식이 전혀 없다는 증명은 아니며, 이미지 자체의 publisher 서명이 검증됐다고도 말할 수 없다. Docker Hub 공개 페이지의 Verified Publisher 표시는 암호학적 이미지 서명을 대체하지 않는다.

따라서:

- 공식 배포 경로: **확인**
- 지정 digest의 로컬 콘텐츠 일치: **확인**
- ARM64 manifest: **확인**
- Semgrep 게시자 서명: **미검증**
- Scout attestation signature verification: **실패**
- provenance attestation 존재: **Scout metadata로 확인**, 빌드 출처 신뢰성 검증은 **미완료**
- SBOM attestation 존재: **확인**, 서명과 공급자 신뢰는 **미검증**

### 이전 Scout 전송 및 캐시

앞선 승인 전 `docker scout attest list` 시도에서 `Pulling`/`Pulled`가 출력된 사실을 보존한다. 그 시도 직후의 `docker image ls semgrep/semgrep`에는 이미지가 없었다. 그때 내려받은 정확한 바이트 수나 Scout 임시 저장물의 잔존 여부는 당시 측정되지 않아 소급 확인할 수 없다.

이번 승인된 Scout indexing 후 `docker scout cache df`는 임시 이미지 캐시 위치를 `$TMPDIR/docker-scout` 아래로 표시하고, 해당 ARM64 digest에 대해 2.1 GB를 보고했다. 캐시된 SBOM 수는 0이라고 표시했다. 이전 중단 시도의 잔여물과 이번 승인된 인덱싱 생성물이 분리 식별되지 않으므로 캐시를 삭제하지 않았다. 현재 Docker image store에는 승인한 ARM64 digest가 존재하며, 다른 semgrep 이미지나 컨테이너는 확인되지 않았다.

### 단계 판정 및 다음 단계

이 Phase의 범위인 지정 이미지 다운로드와 정적 검증은 수행했다. 다만 공급망 attestation 서명 검증은 실패했고, Semgrep 실행·격리 제약·timeout 및 cleanup은 의도적으로 수행하지 않았다.

**이번 단계: 이미지 다운로드 및 정적 검증 완료.** 컨테이너 실행과 실제 Semgrep 버전 확인은 이번 승인 범위에 포함되지 않았으며 수행하지 않았다. 다음 격리 시험은 별도 실행 승인 후 해당 digest에 한해서 진행할 수 있다.

GitHub Intake 또는 Remote Scan은 시작하지 않는다. 앞서 기록된 네트워크·파일시스템·자원 한도·timeout/cleanup 시험 및 Phase 7B 수집 보안 차단 조건은 여전히 미완료다.

---

## Phase 7C-0T — Attestation 실패 분류 및 실행 승인 경계

이 절은 앞선 이미지 다운로드·정적 검증 기록을 보존하고 그 검증 실패의 의미를 더 세분화한다. 이번 조사에서는 Docker 명령, 이미지 다운로드, 컨테이너 실행을 다시 수행하지 않았다. 기존에 기록된 Docker Scout CLI 버전은 `1.26.0`이다.

### 기존 검증 명령과 신뢰 설정

기록된 두 번의 검증은 CycloneDX BOM과 Docker Scout provenance에 대해 각각 다음 형태로 실행됐다.

```text
docker scout attest get --verify --predicate --predicate-type https://cyclonedx.org/bom/v1.6 semgrep/semgrep@sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5
docker scout attest get --verify --predicate --predicate-type https://scout.docker.com/provenance/v0.1 semgrep/semgrep@sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5
```

기록된 CLI 도움말의 `--key` 기본값은 `https://registry.scout.docker.com/keyring/dhi/latest.pub`였다. 해당 공개키 경로는 Docker의 **Docker Hardened Images(DHI)** 검증 안내에서 DHI 이미지 예시와 함께 사용된다. 일반 Semgrep 이미지의 서명 키라고 확인된 것은 아니다. Docker Scout 문서도 이를 `--key`의 기본값으로 명시하며, DHI 검증 안내는 DHI용 공개키와 절차를 설명한다. 따라서 이번 시도는 DHI 키를 신뢰 기준으로 사용했으나, 그 키가 Semgrep 게시 주체의 키라는 근거는 없었다. 검증은 투명성 로그 확인을 생략하지 않았고 `--skip-tlog`를 사용하지 않았다. [Docker Scout `attestation get` 문서](https://docs.docker.com/reference/cli/docker/scout/attestation/get/), [Docker DHI 검증 안내](https://docs.docker.com/dhi/how-to/verify/)

### 실패 원인 분류

| 점검 항목 | 관찰 및 판정 |
| --- | --- |
| 이미지 digest | 기존 정적 검사에서 로컬 image ID/RepoDigest와 승인한 ARM64 manifest digest가 일치했다. 이는 받은 이미지 콘텐츠의 digest 일치 근거다. |
| Attestation 존재 | 기존 `docker scout attest list` 결과에 CycloneDX BOM, Scout provenance, Scout SBOM 항목이 있었다. 목록에 나타난 subject는 모두 선택한 ARM64 digest `sha256:cfb298…`와 일치했다. |
| 검증 명령의 결과 | BOM 및 Scout provenance의 `--verify`가 모두 `no matching signatures: signature not found in transparency log`로 실패했다. |
| 서명 자체의 부재 여부 | **판정 불가.** 이 오류만으로 registry에 서명이 전혀 없다고 증명할 수 없다. |
| 다른 키/인증서에 의한 서명 여부 | **미확인.** Semgrep 게시자에 속하는 대체 키 또는 인증서 정책을 제공해 검증한 기록이 없다. |
| 투명성 로그 상태 | **판정 불가.** 로그 항목이 없거나, 해당 키로 맞는 서명을 찾지 못했거나, 검증 경로가 그 증거를 해석하지 못한 경우를 이 오류만으로 구분할 수 없다. |
| 신뢰 주체/issuer | **미확인.** attestation을 게시하거나 생성한 주체가 Semgrep의 승인된 빌드 주체라는 issuer/identity 검증은 성립하지 않았다. |
| digest subject 불일치 | **관찰되지 않음.** 목록에서 읽은 subject digest는 지정 ARM64 manifest digest와 같았다. 이는 서명 검증 성공을 의미하지 않는다. |
| Docker Scout 한계/설정 | **기본 trust 설정 부적합 가능성이 확인됨.** 사용한 기본 키는 DHI용으로 문서화되어 있다. 그러나 이를 근거로 Scout 자체 오류라고 단정할 수는 없다. |
| Docker Hub publisher 표시 | Semgrep, Inc.의 Verified Publisher 및 공식 이미지 표시는 배포 경로의 출처 신호다. 개별 digest의 암호학적 서명이나 provenance 검증을 대체하지 않는다. [Semgrep Docker Hub 이미지](https://hub.docker.com/r/semgrep/semgrep/tags?name=nonroot) |

Docker 문서는 Scout SBOM 및 Scout provenance를 Docker Scout가 생성하는 attestation 유형으로 설명한다. 이번 이미지에서 해당 유형이 발견됐다는 사실만으로 Semgrep 빌드 시스템이 이를 서명했다거나 그 내용을 승인했다는 뜻은 아니다. 이번 `--verify` 시도에서는 유효한 서명과 투명성 로그 증거를 확인하지 못했다. DHI 문서에 있는 `--skip-tlog` 절차도 별도의 DHI 검증 맥락이며, 이번 검증 실패를 우회하거나 성공으로 바꾸는 데 사용하지 않았다. [Docker attestation 개요](https://docs.docker.com/dhi/explore/security-concepts/attestations/), [Docker DHI 검증 안내](https://docs.docker.com/dhi/how-to/verify/)

### 이미지 버전 메타데이터 차이

기존 정적 검사에서 관찰한 값은 다음과 같다.

- 태그: `1.182.1-nonroot`
- Scout가 표시한 SBOM component: Semgrep `1.182.1`
- OCI/VCS metadata의 `vcs.ref.head.name`: `release-1.182.0`
- OCI revision: `6f7d77ede012b0301d5051f8f5552530c17210c7`

왜 태그·SBOM과 VCS ref가 다른지는 확인하지 못했다. 이를 잘못된 빌드, 정상적인 branch 표기 차이 또는 다른 원인 중 하나로 추정하지 않고 **UNKNOWN**으로 둔다. SBOM은 서명 검증에 실패했으며 컨테이너도 실행하지 않았으므로, 이미지 안의 실제 Semgrep 실행 버전을 확인한 증거가 아니다. 실제 `semgrep --version` 확인은 이후 별도 실행 승인에 포함한다.

### 제한적 실행 계획과 승인 경계

현재 단계에서는 실행하지 않는다. 사용자가 공급망 검증 잔여 위험을 확인하고 별도로 승인한 경우에만 다음의 제한된 첫 실행을 제안한다.

1. 사전 로컬 이미지 존재 여부와 `linux/arm64` 및 지정 digest를 확인하고, pull 금지 옵션으로 실행한다. digest 고정은 변경 탐지를 돕지만 게시자 신뢰를 증명하지 않는다.
2. 이미지의 `semgrep` 계정에 대응하는 숫자 UID/GID를 검증한 뒤 명시한다. 현재 정적 기록에는 숫자 UID/GID가 없어 이를 이미 확인된 사실로 취급하지 않는다.
3. `--network none`, `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, 낮은 CPU/메모리/PID 상한을 사용한다. host 홈, host 프로젝트, Docker socket 및 비밀 환경변수는 제공하지 않는다.
4. 첫 컨테이너 실행은 버전과 UID/GID 확인만 수행하고, 출력은 필요한 짧은 결과로 제한한다. 실행 제한과 cleanup의 실제 효과는 이 확인만으로 검증됐다고 보지 않는다.
5. 이후 별도 승인된 검증에서만 합성 입력을 read-only로 제공해 Semgrep 실행, egress/host 접근 차단, 입력 쓰기 거부, 출력 경계, 자원 한도, timeout, 프로세스 종료 및 임시 파일 cleanup을 각각 시험한다. 모든 제한은 옵션 설정 여부와 실제 강제 효과를 구분해 기록한다.

이 계획은 승인 요청 자체가 아니며 이번 문서 갱신은 실행 동의를 뜻하지 않는다. 별도 실행 승인이 도착하기 전까지 이미지 pull, 컨테이너 생성/실행, 추가 Scout 검증은 하지 않는다. Docker Scout 임시 캐시는 이전 기록처럼 출처를 구분할 수 없으므로 삭제하지 않는다.

### 최종 판정

**`PHASE_7C_0T_EXECUTION_APPROVAL_REQUIRED`**

지정 ARM64 digest와 로컬 콘텐츠의 일치 및 공식 게시자 경로는 기존 기록으로 확인되어 이미지 출처·무결성에 중대한 불일치가 발견된 상태는 아니다. 하지만 Semgrep 게시자에 귀속된 승인 trust root, issuer/identity, 서명 및 transparency-log 검증은 완료되지 않았다. 그러므로 `ATTESTATION_VERIFIED`로 판정하지 않는다. 제한 실행을 진행하려면 사용자가 이 공급망 잔여 위험과 버전 metadata 불일치가 UNKNOWN임을 확인한 뒤, 지정 digest에 대한 별도 실행 승인을 제공해야 한다. 이 판정은 Remote Scan 또는 GitHub Intake를 승인하지 않으며, 그 전에 Phase 7C-0의 격리 강제 시험과 Phase 7B의 수집·archive·commit 동일성 차단 조건을 모두 해결해야 한다.

이 문서 갱신 동안 컨테이너 실행, 이미지 다운로드/빌드, 외부 저장소 수집, 이미지/Scout 캐시 삭제, Git commit 또는 push를 하지 않았다.

---

## Phase 7C-0U — 제한된 최초 실행 결과

이번 단계는 사용자가 승인한 지정 이미지의 최소 진단 실행만 수행했다. 외부 저장소, 사용자 프로젝트, Semgrep 규칙 분석은 실행하지 않았다.

### 시작 Gate

- 로컬 HEAD: `bc53a8c4415822576ec0c7cefe699cdabe2d119b`
- `origin/main`: 같은 SHA
- branch: `main`; 기존 미추적 검증 문서 외의 변경은 보이지 않음
- GitHub Actions Run `40919535112`: 정확한 head SHA, `push / completed / success`
- Python, Semgrep 1.182.1 integration, React dashboard 및 실제 Chromium/FastAPI/Semgrep E2E job과 해당 필수 단계가 성공
- Docker context `desktop-linux`; Engine `29.8.2`, Linux ARM64
- 로컬 이미지: `semgrep/semgrep@sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5`; image ID 및 RepoDigest 일치, `linux/arm64`, 설정 USER `semgrep`

이미지가 존재하고 digest/platform이 승인값과 일치하여 실행 전 조건을 통과했다. 이미지를 pull하거나 빌드하지 않았다.

### 실행 명령 및 결과

UID/GID 확인은 각기 별도 일회용 컨테이너에서 수행했다. 공통 실행 제한은 `--pull=never`, `--platform=linux/arm64`, `--rm`, `--network=none`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--cpus=1`, `--memory=512m`, `--pids-limit=32`였다. Docker socket, bind mount, 비밀 환경변수, host PID/network, privileged 모드는 사용하지 않았다.

```text
docker run --pull=never --platform=linux/arm64 --rm --name phase7c0u-uid-check --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --cpus=1 --memory=512m --pids-limit=32 --user=semgrep --entrypoint=id semgrep/semgrep@sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5 -u
```

- 종료 코드: `0`
- stdout: UID `1000`; root(UID 0)가 아님

```text
docker run --pull=never --platform=linux/arm64 --rm --name phase7c0u-gid-check --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --cpus=1 --memory=512m --pids-limit=32 --user=semgrep --entrypoint=id semgrep/semgrep@sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5 -g
```

- 종료 코드: `0`
- stdout: GID `1000`

Semgrep 버전 확인은 숫자 UID/GID를 명시하고 동일한 제한을 적용했다. 호스트 Python wrapper가 실행을 최대 20초로 제한했다. 첫 실행과 동일한 제한을 유지한 진단 재실행 모두 버전 출력 없이 종료 코드 `1`을 반환했다.

```text
docker run --pull=never --platform=linux/arm64 --rm --name phase7c0u-semgrep-version --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --cpus=1 --memory=512m --pids-limit=32 --user=1000:1000 semgrep/semgrep@sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5 semgrep --version
```

오류는 원문 stderr를 문서화하지 않고 분류했으며, `CACHE_OR_CONFIG_WRITE` 유형으로 나타났다. 이는 read-only 루트에서 Semgrep의 캐시 또는 설정 쓰기가 막혔을 가능성과 일치하지만, 필요한 정확한 경로와 실패 지점은 이 기록만으로 확정하지 않는다. 실제 버전 `1.182.1`은 **확인되지 않았다**. 승인 범위를 넘겨 권한, 파일시스템 쓰기 범위 또는 환경변수를 확대하지 않았고 추가 실행도 중단했다.

향후 별도 승인 시의 대안은 먼저 실패에 필요한 정확한 캐시/설정 경로를 안전하게 특정한 다음, 그 경로 하나에만 크기 제한된 `tmpfs`를 제공하는 것이다. `tmpfs`는 `noexec,nosuid,nodev` 및 작은 용량으로 제한하고 입력 파일이나 다른 host 경로는 마운트하지 않아야 한다. 현재 이 대안은 **계획일 뿐 미실행**이며, 경로 확인이나 tmpfs 사용은 이번 승인에 포함되지 않는다.

### 종료 및 검증 한계

모든 실행에 `--rm`을 사용했다. 종료 후 `docker ps -a --filter name=phase7c0u` 조회 결과 이 실행에서 만든 컨테이너는 남아 있지 않았다. 다른 컨테이너나 Docker 캐시에는 손대지 않았다.

컨테이너가 UID/GID probe를 실행했고 Docker가 지정한 옵션을 받아들였다는 사실은 해당 제한의 강제 효과를 입증하지 않는다. 네트워크 egress/DNS/host 차단, read-only 입력 거부, 허용 출력 경계, CPU·메모리·PID·디스크 quota 강제, timeout 후 자식 프로세스 종료, 강제 종료 후 cleanup은 이번 최소 실행에서 **NOT_TESTED**다. 컨테이너가 쓰기 필요 오류로 종료됐으므로 별도 제한된 임시 영역을 사용하는 Semgrep 실행도 **NOT_TESTED**다. 이미지 서명/provenance는 이전 절과 같이 **UNVERIFIED**다.

### 판정

**`PHASE_7C_0U_EXECUTION_HOLD`**

비관리자 UID/GID와 대상 digest/platform은 확인했지만, Semgrep 버전 확인이 실패하여 최소 승인 범위가 완료되지 않았다. 실제 Semgrep 실행 성공이나 격리 검증 완료로 기록하지 않는다. 다음 단계에는 실패 경로를 특정할 수 있는 별도 승인이 필요하며, 특정 경로에 제한된 임시 쓰기 영역을 제공한 뒤 버전 확인부터 재시도해야 한다. 이후에도 네트워크·파일시스템·자원 제한과 종료/cleanup의 실제 강제 시험은 별도 승인 및 검증 대상으로 남는다. GitHub Intake/Remote Scan 구현은 시작하지 않는다.

이번 단계에서 이미지 pull/build, 실제 저장소 다운로드, 사용자 파일 접근, Docker 전체 cleanup, commit 또는 push는 하지 않았다.

---

## Phase 7C-0W — Semgrep runtime 실패 증거 수집

이번 단계에서는 기존 실패를 진단하기 위해 승인된 컨테이너 실행을 **정확히 1회** 수행했다. 새 이미지, fixture, 사용자 코드, 규칙 파일은 사용하지 않았다.

### 시작 Gate 및 정적 증거

- HEAD와 `origin/main`: `bc53a8c4415822576ec0c7cefe699cdabe2d119b`
- branch: `main`; 기존 미추적 검증 문서 보존
- GitHub Actions Run `40919535112`: 정확한 head SHA, `push / completed / success`; Python, Semgrep 1.182.1 integration, React 및 실제 Chromium/FastAPI/Semgrep E2E 필수 단계 성공
- Docker Engine `29.8.2`, Linux ARM64; 지정 이미지가 로컬에 존재하고 ID/RepoDigest와 `linux/arm64` 일치
- 이미지 설정: `USER=semgrep`, `WORKDIR=/src`, `CMD=["semgrep","--help"]`, `ENTRYPOINT` 없음. `HOME`, `TMPDIR`, `TEMP`, `TMP`는 Config 환경변수에 없음.
- 이미지 history는 사용자 `semgrep`의 UID `1000`, 홈 `/home/semgrep`를 생성한 사실을 보인다. 이는 빌드 metadata이지 runtime의 실패 위치 증거는 아니다.

### 1회 진단 실행

실행한 명령은 다음과 같다. `--restart=no`를 명시했고, Docker 로그 저장 파일이나 host mount를 만들지 않았다. wrapper는 stdout/stderr를 메모리에서 합계 16 KiB까지 수집하고 15초 timeout을 적용했다. 컨테이너 종료 상태를 확인하기 위해 이 실행에서는 자동 삭제 대신 고유 이름을 사용한 뒤 해당 컨테이너만 제거했다.

```text
docker run --pull=never --platform=linux/arm64 --name phase7c0w-semgrep-version-once --restart=no --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --user=1000:1000 --cpus=1 --memory=512m --pids-limit=32 semgrep/semgrep@sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5 semgrep --version
```

| 측정 | 결과 |
| --- | --- |
| 실행 횟수 | 1 |
| Docker CLI exit code | `1` |
| Container state / exit code | `exited / 1`; Docker state error는 비어 있음. 컨테이너가 실제로 시작되어 프로세스 실패를 반환함 |
| stdout | 0 bytes, 비어 있음 |
| stderr | 1,443 bytes; Python traceback 및 아래 핵심 오류 |
| timeout / output limit | 없음 (`15s` / 합계 `16 KiB` 한도 내 종료) |
| Semgrep 버전 | **확인되지 않음**. 버전 출력 전에 import 실패 |

stderr의 원인과 직접 관련된 부분은 다음과 같다. 전체 traceback은 보관하지 않았으며, 사용자 경로나 비밀값은 출력에서 발견되지 않았다.

```text
semgrep/mcp/hooks/inject_secure_defaults.py: Path(tempfile.gettempdir()) / "semgrep-mcp" / "claude-secure-defaults-cache.md"
FileNotFoundError: [Errno 2] No usable temporary directory found in ['/tmp', '/var/tmp', '/usr/tmp', '/src']
```

### 실패 원인 분류

Semgrep 실행 파일인 `/usr/bin/pysemgrep`는 Python 3.12 wrapper다. `semgrep --version`이 Semgrep CLI import를 진행하면서 `semgrep.commands.mcp`와 `semgrep.mcp.hooks.inject_secure_defaults`를 불러왔고, 이 모듈이 `tempfile.gettempdir()`를 호출했다. Python은 `/tmp`, `/var/tmp`, `/usr/tmp`, `/src` 중 사용 가능한 임시 디렉터리를 찾지 못해 `FileNotFoundError`를 냈다. 실패는 `--version` 처리를 마치기 전 발생했다.

| 분류 | 판정 | 근거 |
| --- | --- | --- |
| A. Permission denied | 직접 확인 안 됨 | stderr에는 `PermissionError`가 없음 |
| B. Read-only file system | 직접 errno 확인 안 됨; 설정상 유력한 원인 | 실행에 `--read-only` 적용, 모든 Python 임시 디렉터리 후보를 쓸 수 없다는 오류. stderr에 `EROFS`가 직접 나오지는 않음 |
| C. Cache / Settings path | 간접 관련; 파일 쓰기까지 도달하지 않음 | MCP hook이 `semgrep-mcp/claude-secure-defaults-cache.md` 경로를 구성하려던 코드에서 `gettempdir()` 호출. 실제 해당 파일을 생성하려 한 기록은 없음 |
| D. HOME 환경변수 | 직접 원인 아님 | 이미지 Config에 `HOME` 없음. traceback은 HOME 조회가 아니라 `tempfile.gettempdir()` 실패를 가리킴 |
| E. Semgrep 실행 바이너리 오류 | 확인되지 않음 | Python wrapper가 실행되어 import traceback을 출력함 |
| F. 라이브러리/Python runtime | **오류 발생 지점 확인** | Python 3.12 `tempfile.gettempdir()`가 `FileNotFoundError`를 발생시킴 |
| G. 기타 | 해당 없음 | 추가 원인 증거 없음 |

따라서 재현된 직접 실패는 “특정 캐시 파일의 쓰기 거부”가 아니라 **read-only root에서 사용할 임시 디렉터리를 찾지 못해 CLI import가 실패한 것**이다. `/tmp`는 Python의 첫 후보이며 오류 후보 목록에 포함된다. 어떤 후보별 시도에서 어떤 OS 오류가 발생했는지까지는 traceback에 나오지 않아, 개별 경로의 errno는 **UNKNOWN**이다.

### 최소 tmpfs 대안 및 승인 경계

다음 단계에서 별도 승인을 받은 경우에만 `/tmp` 하나를 최대 16 MiB의 tmpfs로 제공하는 방안을 제안한다. 예시 설정은 `--tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,uid=1000,gid=1000,mode=700`이다. Docker 문서는 `--tmpfs`의 size, uid, gid, mode 및 `noexec`, `nosuid`, `nodev` 옵션을 설명한다. tmpfs 데이터가 메모리 제한에 포함되고 환경에 따라 swap으로 기록될 수 있다는 점도 고려해야 한다. [Docker tmpfs 문서](https://docs.docker.com/engine/storage/tmpfs/)

이 대안은 `/tmp`만 쓰기 가능하게 하고 root filesystem은 read-only로 유지한다. UID/GID `1000:1000`, `--network=none`, capability 제거, `no-new-privileges`, CPU 1, memory 512 MiB, PID 32 제한 및 이미지 digest pin도 그대로 유지해야 한다. 이번 Phase에서는 tmpfs를 마운트하거나 재실행하지 않았다. 다음 실행은 별도 사용자 승인 후에만 가능하다.

### Cleanup 및 남은 위험

- Container inspect 결과: `exited`, exit code `1`, Docker state error 없음
- `docker rm -f phase7c0w-semgrep-version-once`: exit code `0`
- 제거 후 해당 이름으로 조회한 컨테이너: 없음
- stdout/stderr는 호스트 메모리에서만 수집; 진단 파일 생성 없음
- stderr에는 token, host home/project 경로, 사용자 코드가 없었다. 기록에는 필요한 컨테이너 내부 경로와 오류 문장만 포함했다.
- 이미지 서명/provenance는 계속 **UNVERIFIED**. 이번 실행은 Semgrep 버전 검증이나 이미지 공급망 검증을 통과시키지 않는다.
- 네트워크, 파일시스템 접근, CPU/memory/PID/disk 강제 효과, 실제 Semgrep scan, 강제 종료 및 cleanup 효과는 별도 격리 시험 전까지 **NOT_TESTED**다.

### 판정

**`PHASE_7C_0W_DIAGNOSTIC_EVIDENCE_CAPTURED`**

정확한 직접 원인은 임시 디렉터리 탐색 실패로 재현됐고, Python traceback은 Semgrep MCP hook import 단계와 실패 지점을 특정했다. 유력한 최소 조치는 별도 승인 아래 `/tmp`만 제한된 tmpfs로 제공하는 것이다. 실제 Semgrep 버전은 여전히 확인되지 않았으며 이번 진단은 전체 격리 검증 통과가 아니다. GitHub Intake/Remote Scan은 시작하지 않았다.

---

## Phase 7C-0V — Read-only runtime failure 조사

이번 단계에서는 앞선 Phase 7C-0U와 같은 컨테이너 제한을 유지하며 실패 경로를 먼저 조사했다. 재실행 조건은 충족되지 않아 컨테이너를 시작하지 않았다.

### Gate 및 보존 상태

- branch `main`; HEAD와 `origin/main`은 모두 `bc53a8c4415822576ec0c7cefe699cdabe2d119b`
- GitHub Actions Run `40919535112`: head SHA 일치, `push / completed / success`
- Docker Engine 응답 정상
- 지정 이미지가 로컬에 존재하며 image ID/RepoDigest `sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5`, OS/architecture `linux/arm64` 일치
- 기존 Phase 7C-0 미추적 문서 보존. `phase7c0u` 이름의 잔존 컨테이너 없음

### 이미지 설정 및 기존 실패 증거

실행하지 않고 로컬 image config/history만 확인했다.

- `USER=semgrep`, `WORKDIR=/src`, `ENTRYPOINT=null`, `CMD=["semgrep","--help"]`
- Config 환경변수에 `HOME`이 없다.
- 이미지 history에는 UID `1000`, 홈 `/home/semgrep`로 사용자를 생성하는 빌드 단계와 `/home/semgrep/.gitconfig`를 쓰는 빌드 단계가 보인다. 이는 이미지 빌드 시점의 정보이며, 실행 시 Semgrep이 어떤 경로에 쓰려 했는지를 증명하지 않는다.
- 이전 `semgrep --version` 시도는 exit code `1`, version 출력 없음이었다. 그때 stderr 원문은 보존되지 않았고, 기록에는 `CACHE_OR_CONFIG_WRITE` 분류만 남아 있다.

따라서 정확한 쓰기 경로는 **확인 불가**다. stderr 원문이 없어 오류가 `/tmp`, `/home/semgrep` 아래 캐시, 설정 파일 또는 다른 위치를 가리켰는지 구분할 수 없다. image config/history만으로 이 빈틈을 메울 수 없다. 조사 중 컨테이너 재실행이나 이미지 추출을 하지 않았다.

### tmpfs 대안과 재실행 결정

요청된 `/tmp` 최대 16 MiB tmpfs는 경로가 실제로 `/tmp`임이 확인된 뒤에만 유효한 후보가 된다. 실패 경로가 홈 디렉터리 캐시라면 `/tmp`만 마운트하는 것은 해결책이 아닐 수 있다. 정확한 경로가 불명인 현재 상태에서 임의 경로를 쓰기 가능하게 하거나 tmpfs를 추가하지 않는다.

제한된 컨테이너 재실행은 **수행하지 않았다**. 사용자 지시상 기존 실패 경로를 확인할 수 없으면 재실행하지 않아야 하며, 현재 증거로는 경로를 확인할 수 없다. 추가 컨테이너 실행 전에 실패 stderr를 안전하게 보존·경로 정규화하여 검토할 수 있는 승인된 절차와, 실제 오류 경로에만 적용할 쓰기 한도/마운트 지점에 대한 별도 동의가 필요하다. 어느 경우에도 `--read-only`, UID/GID `1000:1000`, `--network=none` 및 기존 CPU·메모리·PID 제한을 유지해야 한다.

### 판정

**`PHASE_7C_0V_RUNTIME_HOLD`**

실패 원인의 정확한 쓰기 경로가 확인되지 않았고, 따라서 제한된 tmpfs 위치를 정당화할 근거도 없다. 실제 Semgrep 버전과 정상 종료는 확인되지 않았다. 서명/provenance 상태는 계속 **UNVERIFIED**이며 네트워크·파일시스템·자원 제한의 강제 효과와 전체 격리 검증도 미완료다. 새 이미지 다운로드, GitHub Intake, Remote Scan, 컨테이너 재실행, commit 또는 push는 하지 않았다.

---

## Phase 7C-0X — `/tmp` 제한 tmpfs 버전 확인 재시도

이번 단계에서는 승인된 이미지에 컨테이너 실행을 **정확히 1회** 수행했다. 실행 전후 지정 digest와 플랫폼을 확인했고, 추가 이미지 다운로드/빌드 없이 로컬 이미지만 사용했다.

### 시작 Gate

- branch `main`; HEAD와 `origin/main`: `bc53a8c4415822576ec0c7cefe699cdabe2d119b`
- 기존 미추적 검증 문서 보존; 실행 전 `phase7c0x-semgrep-version` 이름의 테스트 컨테이너 없음
- GitHub Actions Run `40919535112`: 정확한 head SHA, `push / completed / success`
- Docker Engine `29.8.2`, Linux ARM64
- 실행 전 및 실행 후 image ID/RepoDigest: `sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5`; 플랫폼 `linux/arm64`

### 유일한 실행 조건

```text
docker run --pull=never --platform=linux/arm64 --name phase7c0x-semgrep-version-once --restart=no --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --user=1000:1000 --cpus=1 --memory=512m --pids-limit=32 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 semgrep/semgrep@sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5 semgrep --version
```

컨테이너에 추가한 유일한 writable mount는 `/tmp`의 16 MiB tmpfs였다. Host bind mount, Docker socket, 추가 환경변수, 사용자 파일 또는 별도 실행 파일은 전달하지 않았다. Host Python wrapper가 최대 15초 실행 및 stdout/stderr 합계 16 KiB 수집 한도를 적용했다. 실제 수집량은 상한 이내였다.

### 결과 및 실패 원인

- stdout: 0 bytes, 비어 있음
- stderr: 2,385 bytes; 민감값/host 경로 없음. 필요한 내부 오류만 아래에 기록
- Docker CLI exit code: `1`
- Container inspect: `exited`, `ExitCode=1`, Docker state error 없음. 따라서 Docker가 컨테이너를 시작한 뒤 Semgrep 프로세스가 실패함
- 실행 시간: 15초 이내; timeout/output limit 없음
- Semgrep 버전: **확인되지 않음**. `--version` 출력 전에 설정 초기화에서 종료

핵심 stderr:

```text
semgrep/settings.py:114  self.save()
semgrep/settings.py:120  self.path.parent.mkdir(parents=True, exist_ok=True)
OSError: [Errno 30] Read-only file system: '/home/semgrep/.semgrep'
```

앞선 0W에서 확인한 `tempfile.gettempdir()` 실패는 이번 실행에서 재현되지 않았고, CLI 초기화는 더 진행됐다. 이는 해당 실패 지점이 통과됐음을 보여주지만, 네트워크 또는 파일시스템 차단의 전반적인 강제 효과를 시험한 것은 아니다. 이번에 확인된 직접 실패 경로는 **`/home/semgrep/.semgrep` 디렉터리 생성**이며, `SemgrepState`의 `Settings.save()`가 상위 디렉터리를 만들려다 read-only root에 막혔다. 실패는 cache 설정 파일 생성 전에 발생했다.

### 추가 쓰기 경로와 재실행 제한

버전 확인만 통과시키려면 다음 별도 승인 단계에서 `/home/semgrep/.semgrep`만 크기 제한 tmpfs로 제공하는 것이 최소 후보가 될 수 있다. UID/GID `1000:1000` 소유, mode `0700`, `noexec,nosuid,nodev` 및 작은 용량으로 제한하고, 기존 read-only root와 `/tmp` 16 MiB tmpfs를 유지하는 방안을 검토할 수 있다. 다만 Semgrep의 이후 분석이 추가 cache 경로를 요구할 수 있으므로 이 한 경로가 전체 실행에 충분하다는 뜻은 아니다.

**이번 Phase에서는 추가 mount를 만들지 않았으며 재실행하지 않았다.** `/home/semgrep/.semgrep` 쓰기는 명시된 승인 범위 밖이다. 그 경로의 tmpfs를 포함한 다음 실행은 별도 사용자 승인 후에만 가능하다. 이 단계에서 실제 버전 확인 성공으로 기록하지 않는다.

### Cleanup 및 잔여 검증

- `docker rm -f phase7c0x-semgrep-version-once`: exit code `0`; 해당 컨테이너 제거됨
- 제거 후 해당 이름의 잔존 컨테이너: 없음
- 실행 전후 이미지 digest/platform: 동일
- 진단 출력은 host 메모리에서 수집했고 파일로 저장하지 않음
- 이미지 서명/provenance: **UNVERIFIED**
- 네트워크, 파일시스템 격리의 실제 강제 효과, CPU/memory/PID/disk 제한, 전체 Semgrep 분석, 강제 종료 및 자식 프로세스 cleanup, Ubuntu CI 격리: **NOT_TESTED**

### 판정

**`PHASE_7C_0X_RUNTIME_HOLD`**

`semgrep --version`이 종료 코드 `1`로 실패했고 `1.182.1`을 확인하지 못했다. `/tmp` tmpfs는 이전 임시 디렉터리 문제를 지나 CLI가 설정 저장 단계에 도달하게 했지만, 다음의 별도 쓰기 경로 `/home/semgrep/.semgrep`가 확인됐다. 이번 실행 승인을 소진했으므로 추가 경로를 허용하거나 자동 재실행하지 않는다. LOCAL_ISOLATION_VERIFIED 또는 GitHub Intake 승인으로 해석하지 않는다.

---

## Phase 7C-0X-R — Settings 디렉터리 runtime recovery 결과

이번 단계에서는 사용자 승인 범위에 따라 지정 이미지의 컨테이너 실행을 **정확히 1회** 수행했다. 실행 전후 image ID/RepoDigest와 플랫폼이 지정된 ARM64 digest와 일치했다. 추가 이미지 pull/build, host mount 또는 외부 저장소 접근은 없었다.

### 시작 Gate

- branch `main`; HEAD와 `origin/main`: `bc53a8c4415822576ec0c7cefe699cdabe2d119b`
- GitHub Actions Run `40919535112`: 정확한 head SHA, `push / completed / success`
- Docker daemon: Engine `29.8.2`, Linux ARM64
- 실행 전 테스트 컨테이너 잔존 없음
- 실행 전후 이미지 ID/RepoDigest `sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5`, platform `linux/arm64`
- 기존 미추적 검증 문서 보존

### 실제 명령과 적용 설정

컨테이너 내부에서 실행한 명령은 `semgrep --version` 하나였다. 자동 재시작은 `no`로 설정했다.

```text
docker run --pull=never --platform=linux/arm64 --name phase7c0xr-semgrep-version-once --restart=no --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --user=1000:1000 --cpus=1 --memory=512m --pids-limit=32 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 --tmpfs /home/semgrep/.semgrep:rw,noexec,nosuid,nodev,size=4m,mode=0700,uid=1000,gid=1000 semgrep/semgrep@sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5 semgrep --version
```

호스트 wrapper는 15초 timeout 및 stdout/stderr 합계 16 KiB 상한을 적용했다. 추가 환경변수, 사용자 프로젝트, home 전체, Docker socket은 전달하지 않았다.

실행 직후 Docker inspect에서 확인된 설정:

- `ReadonlyRootfs=true`
- `Config.User=1000:1000`
- Network mode `none`, restart policy `no`
- `NanoCpus=1000000000`, memory `536870912` bytes, PID limit `32`
- `CapDrop=["ALL"]`, `SecurityOpt=["no-new-privileges"]`
- `HostConfig.Tmpfs`에는 승인된 `/tmp` 16 MiB와 `/home/semgrep/.semgrep` 4 MiB 옵션이 모두 기록됨
- inspect의 `Mounts` 배열은 비어 있었다. 따라서 HostConfig에 요청 설정이 반영된 것은 확인되지만, inspect 결과만으로 실제 커널 mount table을 독립적으로 확인했다고 주장하지 않는다.

UID/GID는 명령 인자에서 `1000:1000`으로 설정했다. 실제 UID/GID 실행 관찰은 이전 Phase 7C-0U의 별도 `id` 결과 `1000:1000`이며, 이번 컨테이너 안에서는 승인된 명령 제한 때문에 다시 `id`를 실행하지 않았다.

### stdout, stderr 및 상태

- stdout: 8 bytes, `1.182.1\n`
- stderr: 766 bytes; 사용자 코드, token, host 경로는 포함되지 않음
- Docker CLI 실행은 wrapper timeout 시점까지 종료되지 않았다. wrapper가 종료한 Docker CLI의 종료 상태는 `-9`
- timeout 시점의 Container inspect: `running`, exit code `0` (아직 종료 전이므로 최종 프로세스 exit code가 아님), Docker state error 없음
- Docker가 컨테이너를 생성하고 Semgrep 프로세스가 실행됐음은 확인됨. Semgrep 프로세스의 정상 종료 코드는 관찰되지 않음.

stderr의 핵심 오류:

```text
Semgrep failed to set the safe.directory Git config option.
error: could not lock config file /home/semgrep/.gitconfig: Read-only file system
Failed to run 'git config --global --add safe.directory *'.
```

이전 `/home/semgrep/.semgrep` 설정 디렉터리 문제를 지나 버전 문자열 출력까지 도달했다. 그 뒤 Semgrep 초기화가 Git global 설정 `/home/semgrep/.gitconfig`에 `safe.directory`를 추가하려 했으나 root filesystem이 read-only라 쓰지 못했다. 이 경로는 이번에 승인된 두 tmpfs 바깥이다. 실행은 15초 timeout까지 살아 있어 성공 조건을 충족하지 못했다.

### Cleanup 및 판정

- Timeout 후 해당 컨테이너에만 `docker kill` 실행: 종료 코드 `0`
- 해당 컨테이너에만 `docker rm -f` 실행: 종료 코드 `0`
- 제거 후 해당 이름 컨테이너: 없음
- 실행 전후 이미지 digest/platform: 동일
- stdout/stderr는 메모리에서만 수집; 파일로 저장하지 않음

**`PHASE_7C_0X_R_RUNTIME_HOLD`**

버전 문자열 `1.182.1`은 실행 출력으로 관찰됐지만, 프로세스가 정상 종료(exit 0)하지 못하고 승인 시간 내 종료되지 않아 성공 판정 기준은 충족되지 않았다. 추가 쓰기 경로 `/home/semgrep/.gitconfig`가 확인됐으므로 그 파일 또는 상위 경로를 쓰기 가능하게 하지 않는다. 이번 승인은 소진됐으며 자동 재시도는 금지한다. 다음 단계에서 이 쓰기를 피할 안전한 Semgrep 설정 방법을 정적으로 검토하거나, 필요하다면 해당 경로에 대한 별도의 구체적 권한 승인을 받아야 한다.

공급망 서명/provenance는 계속 **UNVERIFIED**다. 실제 egress 차단, 파일 접근 격리, CPU·메모리·PID·디스크 제한의 강제 효과, 비신뢰 코드 분석 격리, 강제 종료 이후 자식 프로세스 정리는 별도 미검증 항목이다. 이 결과는 `LOCAL_ISOLATION_VERIFIED` 또는 GitHub Intake 승인이 아니다.

---

## Phase 7C-0X-S — Git global 설정 리다이렉션 조사

이번 단계에서는 Git 공식 문서와 직전 실행의 stderr를 정적으로 대조했다. `GIT_CONFIG_GLOBAL=/tmp/semgrep-gitconfig`를 설정한 컨테이너 재실행은 하지 않았다.

### 시작 Gate

- branch `main`; HEAD와 `origin/main`: `bc53a8c4415822576ec0c7cefe699cdabe2d119b`
- GitHub Actions Run `40919535112`: 정확한 head SHA, `push / completed / success`
- `origin/main...HEAD`: ahead `0`, behind `0`
- Working tree 시작 상태: 기존 미추적 검증 문서만 존재; 문서를 보존함
- Docker daemon: Engine `29.8.2`, Linux ARM64 연결 정상
- 대상 이미지: 로컬 존재, RepoDigest `sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5`, `linux/arm64`
- `phase7c0xs-semgrep-version` 이름으로 잔존하는 테스트 컨테이너: 없음

### 정적 근거 및 보안 판단

직전 0X-R 실행의 실제 stderr에는 다음이 기록됐다.

```text
error: could not lock config file /home/semgrep/.gitconfig: Read-only file system
Failed to run 'git config --global --add safe.directory *'.
```

Git 공식 문서는 `GIT_CONFIG_GLOBAL`이 기본 global 설정 파일 대신 지정 파일을 사용하게 한다고 설명하며, `git config --global`은 global 설정 파일에 쓴다고 설명한다. 따라서 이 변수를 `/tmp/semgrep-gitconfig`로 지정하면 해당 명령의 global 설정 쓰기를 `/tmp` tmpfs로 돌릴 수 있다는 것이 문서에 부합하는 해석이다. 이는 **정적 문서 근거에 따른 예상**이며, 이번 단계에서는 컨테이너 안에서 동작을 재현하지 않았다. 이미지 안에 포함된 Git의 정확한 버전도 확인되지 않았다.

그러나 직전 stderr가 보여 주는 Semgrep의 쓰기 값은 `safe.directory=*`다. Git 공식 문서는 이 값을 모든 저장소를 안전한 것으로 취급하게 하는 보호 우회로 설명한다. 파일을 `/tmp`로 옮겨도 값의 의미는 바뀌지 않으며, 실행 중인 Git 프로세스의 보호 설정에 wildcard 예외를 추가한다. 사용자가 이번 Phase에서 `safe.directory=*` 사용을 명시적으로 금지했으므로 이를 허용하는 설정 리다이렉션을 적용하지 않았다.

이 조치는 실제 호스트의 사용자 Git 설정을 수정하지 않는다. 새 writable mount, 추가 환경변수, 컨테이너 실행, 추가 Git 명령, 네트워크 접근도 사용하지 않았다. 현재 증거만으로 Semgrep이 wildcard 설정 없이 이 초기화를 건너뛸 방법이 있다고 추정하지 않는다.

### 실행 및 검증 결과

- `GIT_CONFIG_GLOBAL` 적용: 안 함
- 컨테이너 재실행 횟수: `0`
- Semgrep 버전: 이번 단계에서 새로 확인하지 않음. 직전 0X-R 출력 문자열은 `1.182.1`이었지만 종료/timeout 실패로 정상 실행 검증은 아님
- 실행 종료 코드 및 timeout: 해당 없음
- stdout/stderr: 새 실행이 없어 수집하지 않음
- Cleanup: 새 컨테이너를 만들지 않았으며, 시작 시 해당 이름의 잔존 컨테이너 없음
- 이미지 digest 및 플랫폼: 시작 시 지정값과 일치
- 이미지 서명/provenance: 계속 **UNVERIFIED**

### 판정

**`PHASE_7C_0X_S_RUNTIME_HOLD`**

공식 문서상 global 설정 경로 리다이렉션은 쓰기 실패를 피할 수 있는 방향이지만, 확인된 명령에 적용하면 금지된 `safe.directory=*` 예외를 writable 경로에 기록하게 된다. 정확한 이미지 내 Git 버전과 동작은 실행하지 않아 미확인 상태다. 안전 경계와 사용자의 명시적 금지를 유지하기 위해 승인된 1회 실행은 수행하지 않았다.

이 판정은 Semgrep 버전 확인, 정상 종료, 격리 검증 또는 GitHub Intake 승인을 의미하지 않는다. 후속 검토는 Semgrep이 wildcard 예외를 추가하지 않도록 지원하는 설정/실행 경로가 있는지 신뢰된 이미지 자료 또는 공급자 문서로 확인해야 한다. 이를 확인하지 못하면 해당 이미지의 read-only 실행은 계속 HOLD다.

공식 참고 자료:

- Git `GIT_CONFIG_GLOBAL` 환경 변수: <https://git-scm.com/docs/git#Documentation/git.txt-codeGITCONFIGGLOBALcode>
- `git config --global` 쓰기 대상: <https://git-scm.com/docs/git-config#Documentation/git-config.txt---global>
- `safe.directory` 및 `*`의 보안 의미: <https://git-scm.com/docs/git-config#Documentation/git-config.txt-safedirectory>

---

## Phase 7C-0X-T — Semgrep Docker 초기화 보안 검토 및 제한 실행

이번 단계에서 기존 미추적 문서를 보존했다. 컨테이너는 지정 digest로 1회 생성·시작하고, 실행 후 해당 컨테이너만 제거했다. 추가 이미지 다운로드/빌드, 프로젝트 마운트, 네트워크 연결, Git 설정 경로 변경은 없었다.

### 시작 Gate 및 이미지

- branch `main`; HEAD와 `origin/main`: `bc53a8c4415822576ec0c7cefe699cdabe2d119b`; ahead/behind `0/0`
- GitHub Actions Run `40919535112`: 해당 SHA, `push / completed / success`
- 시작 작업 트리: 기존 미추적 검증 문서만 존재
- Docker Engine/CLI: `29.8.2`; daemon Linux ARM64
- 이미지 digest: `sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5`; 플랫폼 `linux/arm64`
- 이미지 기본 환경에 `SEMGREP_IN_DOCKER=1` 존재
- 호스트의 `SEMGREP_IN_DOCKER`: unset
- 시작 전 테스트 컨테이너: 없음

### 공식 소스 검토

Semgrep `release-1.182.0`의 `cli.py`에서 `maybe_set_git_safe_directories()`는 CLI 초기화 중 호출된다. 함수는 `env.in_docker`가 참일 때 `git config --global --add safe.directory "*"`를 실행하고, 실패는 로그로 처리한다. 같은 release의 `env.py`에서 `in_docker`는 변수가 값이 있는지보다 `SEMGREP_IN_DOCKER`가 `os.environ`에 존재하는지로 계산한다.

같은 release의 `config_resolver.py`도 이 플래그를 사용한다. Docker가 감지되면 `/src`가 비어 있지 않은지 확인하고, 일반 경로에서는 `/src`로 이동한다. 설정 파일 오류 문구에도 Docker에서 임의 호스트 경로가 마운트돼야 한다는 설명을 덧붙인다. 따라서 변수를 제거하면 `safe.directory=*` 초기화는 건너뛸 것으로 소스상 예상되지만, Docker용 `/src` 존재 검증과 해당 오류 설명도 비활성화된다. 이 버전에서 일반 스캔이 `/src`를 사용하는 경로 자체는 유지된다. 이는 release-1.182.0 소스에 대한 확인이며, 이미지 내 실제 코드 버전은 별도 검증되지 않았다.

이미지 config에는 `SEMGREP_USER_AGENT_APPEND=Docker`도 있지만, 검토한 `env.py`의 `in_docker` 판별은 별도 `SEMGREP_IN_DOCKER` 존재 검사다. 전체 Semgrep 코드베이스에서 다른 Docker 전용 동작이 없는지 exhaustively 확인한 것은 아니다.

### 환경변수 제거 사전검사

Docker 공식 문서는 `--env NAME`에 `=`가 없고 호스트에 같은 변수가 export되지 않은 경우 컨테이너에서 변수를 unset한다고 설명한다. Docker CLI v29.8.2의 공식 `ValidateEnv` 소스도 이 상황에서 `NAME`(값 없는 항목)을 반환한다. 컨테이너 생성 후 inspect의 `Config.Env`에는 `SEMGREP_IN_DOCKER` 값이 있는 형태가 아니라 이 값 없는 제거 항목이 표시됐다. Docker는 컨테이너 환경을 만들 때 이 항목을 제거하도록 정의한다. 따라서 실행 설정에서 이미지의 `SEMGREP_IN_DOCKER=1`을 unset하도록 구성됐다고 판단했다. 단, 승인된 컨테이너 명령이 `semgrep --version` 하나였으므로 프로세스의 `os.environ`을 별도 probe로 직접 출력하지는 않았다.

### 제한 실행 및 관찰 결과

컨테이너는 다음 기존 제한으로 생성됐다: `--pull=never`, `--platform=linux/arm64`, `--network=none`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--user=1000:1000`, `--cpus=1`, `--memory=512m`, `--pids-limit=32`, `--restart=no`, `/tmp` 16 MiB 및 `/home/semgrep/.semgrep` 4 MiB tmpfs. Host bind mount와 Docker socket mount는 없었다. Docker inspect에서 해당 보안 설정이 반영된 것을 확인했다.

- 컨테이너 내부 명령: `semgrep --version` 1회
- 환경 override: `--env SEMGREP_IN_DOCKER` (호스트 변수는 unset)
- stdout: Docker 로그에서 `1.182.1` 확인
- stderr: Docker 로그에서 내용 없음; `safe.directory` 설정 실패 문구는 관찰되지 않음
- 제한 시간: 30초 도달; timeout wrapper가 컨테이너를 종료
- 컨테이너 최종 상태: `exited`, exit code `137` (SIGKILL에 해당하는 컨테이너 상태); Semgrep의 정상 종료 코드는 확인되지 않음
- Docker CLI wrapper 종료 코드: 별도 수집 결과가 없어 `UNKNOWN`
- Cleanup: 해당 컨테이너 `docker rm -f` 완료; 이후 해당 이름의 컨테이너 없음
- 이미지 digest/platform 재확인: 지정값과 일치

`1.182.1` 문자열 출력은 확인됐지만 정상 종료(exit 0)는 확인되지 않았고 timeout도 발생했다. `safe.directory` 오류 로그가 보이지 않았다는 점은 참고 관찰일 뿐 설정 변경이 없었다는 독립 증거는 아니다. 공식 소스와 Docker의 unset 계약상 해당 초기화가 실행되지 않을 것으로 예상되지만, 이미지 VCS metadata는 `release-1.182.0`이며 1.182.1의 실행 코드를 직접 검증하지 않았으므로 Git 보호 우회 부재는 **NOT_VERIFIED**로 남긴다.

### 판정 및 대안

**`PHASE_7C_0X_T_RUNTIME_HOLD`**

환경변수 제거 설정은 Docker 공식 동작으로 구성됐고, Git 설정 보호를 허용하거나 쓰기 권한을 늘리지 않았다. 그러나 30초 timeout으로 컨테이너 exit code 137이 되었으므로 Phase의 성공 조건(exit 0, timeout 없음)을 충족하지 못했다. 출력 버전만으로 실행 성공을 선언하지 않는다.

공급망 서명/provenance는 계속 **UNVERIFIED**다. 네트워크·파일시스템·CPU/메모리/PID/디스크 제한의 실제 강제 효과, 합성 코드 분석, 강제 종료 후 자식 프로세스 정리, Ubuntu CI 격리는 여전히 **NOT_TESTED**다.

후속 대안은 (A) 신뢰된 출처와 재현 가능한 설치를 검증한 별도 worker 이미지, (B) Semgrep이 승인된 정확한 경로만 safe.directory에 추가하거나 Git 호출을 회피하는 공식 지원 경로, (C) 해당 이미지 사용 보류다. 이번 단계에서는 새 이미지 다운로드/빌드나 대체 실행을 하지 않았다. 비신뢰 저장소 분석을 시작하지 않는다.

공식 참고 자료:

- Semgrep `release-1.182.0` CLI 초기화: <https://github.com/semgrep/semgrep/blob/release-1.182.0/cli/src/semgrep/cli.py>
- Semgrep Docker 감지: <https://github.com/semgrep/semgrep/blob/release-1.182.0/cli/src/semgrep/env.py>
- Semgrep Docker 경로 처리: <https://github.com/semgrep/semgrep/blob/release-1.182.0/cli/src/semgrep/config_resolver.py>
- Docker 환경 변수 실행 옵션: <https://docs.docker.com/reference/cli/docker/container/run/#set-environment-variables--e---env---env-file>
- Docker CLI v29.8.2 환경 변수 파싱: <https://github.com/docker/cli/blob/v29.8.2/opts/env.go>
- Git `safe.directory=*` 보안 의미: <https://git-scm.com/docs/git-config#Documentation/git-config.txt-safedirectory>

---

## Phase 7C-0X-U — 오프라인 Semgrep 종료 진단

이 절은 직전 0X-T의 버전 출력 후 종료 지연을 진단하기 위한 단 한 번의 승인 실행을 기록한다. 앞선 HOLD 기록은 그대로 유지한다.

### 시작 Gate

- Branch: `main`; HEAD 및 `origin/main`: `bc53a8c4415822576ec0c7cefe699cdabe2d119b`; ahead/behind `0/0`.
- GitHub Actions Run `40919535112`: 해당 SHA, `push / completed / success`.
- 시작 작업 트리: 기존 미추적 `docs/phase7c0-isolated-worker-validation.md`만 존재.
- Docker daemon: Engine `29.8.2`, Linux ARM64 연결 정상.
- 대상 이미지: 로컬 존재, image ID 및 RepoDigest `sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5`, `linux/arm64`; 크기 약 1.61 GB.
- 실행 전 `phase7c0xu-offline-version` 컨테이너 없음. 호스트 `SEMGREP_IN_DOCKER` 환경변수는 unset.
- 기존 미추적 문서는 보존했다. 이미지 pull/build는 하지 않았다.

### 정적 조사 및 원인 가설

Semgrep 공식 `release-1.182.0` 소스에서 확인한 설정은 다음과 같다.

- `SEMGREP_ENABLE_VERSION_CHECK=0`: 버전 확인을 비활성화한다. 해당 소스의 `--version` 흐름은 버전 문자열을 출력한 뒤 기본 활성화된 `version_check()`를 호출하고 반환한다. 따라서 앞선 출력 이후 지연과 관련될 수 있는 가장 직접적인 후보 설정이다.
- `SEMGREP_SEND_METRICS=off`: 메트릭 전송을 끈다. 같은 `release-1.182.0` 흐름에서는 `--version` 처리가 메트릭 설정/스캔 흐름보다 먼저 반환하므로, 이 옵션은 이번 `--version` 종료 지연의 직접 원인으로 지목할 근거가 없다. 다만 승인된 설정 그대로 함께 적용했다.
- 이미지 빌드 메타데이터에는 `release-1.182.0`이 있으나 대상 이미지와 태그/SBOM 표시는 `1.182.1`이다. 1.182.0 소스 동작을 이미지 바이너리와 동일하다고 가정하지 않았다.

이 설정 변경 후 정상 종료한 관찰은 버전 확인 경로가 지연에 기여했을 가능성과 일치하지만, 이전 실행과 동일한 조건에서 설정 하나만 바꾼 대조 실험은 아니다. 따라서 인과관계는 **강한 정황이나 확정 아님**으로 기록한다. Exit 137만으로 OOM이라고 추정하지 않는다. 이번 실행에서는 Docker가 `OOMKilled=false`를 보고했다.

공식 소스:

- [Semgrep Scan_CLI.ml (`release-1.182.0`)](https://github.com/semgrep/semgrep/blob/release-1.182.0/src/osemgrep/cli_scan/Scan_CLI.ml)
- [Semgrep scan.py (`release-1.182.0`)](https://github.com/semgrep/semgrep/blob/release-1.182.0/cli/src/semgrep/commands/scan.py)

### 단 한 번의 제한 실행

Docker create 설정을 시작 전에 inspect했다. 유효 이미지 digest, `linux/arm64`, 명령 인자 `semgrep --version`, `ReadonlyRootfs=true`, `NetworkMode=none`, 사용자 `1000:1000`, CPU 1, 메모리 512 MiB, PID 32, cap drop `ALL`, `no-new-privileges`, restart `no`, 승인된 두 tmpfs가 일치했다. Host bind, Docker socket mount는 없었다. Docker inspect의 `Mounts`는 비어 있고 tmpfs는 `HostConfig.Tmpfs`에 기록됐다. 설정 확인은 실제 커널 강제 효과 시험이 아니다.

이번 실행에 추가한 환경 설정은 다음 둘뿐이다.

```text
SEMGREP_ENABLE_VERSION_CHECK=0
SEMGREP_SEND_METRICS=off
```

`SEMGREP_IN_DOCKER`는 이미지 기본값 `1`을 전달하지 않도록 Docker의 값 없는 `--env SEMGREP_IN_DOCKER` 항목으로 제거를 요청했다. 호스트 변수는 unset이었다. 사전 inspect에는 값 없는 제거 항목이 보였으며 Docker의 문서화된 동작에 따른 설정이다. 프로세스 내부 환경을 별도 명령으로 덤프하지 않았으므로 runtime 환경변수 부재 자체는 **설정 기반 확인**으로 한정한다.

실행 설정의 핵심 argv:

```text
docker create --pull=never --platform=linux/arm64 --name phase7c0xu-offline-version --restart=no --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --user=1000:1000 --cpus=1 --memory=512m --pids-limit=32 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777 --tmpfs /home/semgrep/.semgrep:rw,noexec,nosuid,nodev,size=4m,mode=0700,uid=1000,gid=1000 --env SEMGREP_ENABLE_VERSION_CHECK=0 --env SEMGREP_SEND_METRICS=off --env SEMGREP_IN_DOCKER semgrep/semgrep@sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5 semgrep --version
docker start -a phase7c0xu-offline-version
```

`docker start -a`는 위에서 생성한 한 컨테이너를 단 한 번 시작했다. Host timeout은 30초, stdout/stderr 누적 수집 상한은 합계 16 KiB였다. 자동 재시도는 하지 않았다.

### 관찰 결과

- 컨테이너 실행 횟수: 1회.
- Docker CLI `docker start -a` 종료 코드: `0`; 호스트 timeout wrapper는 timeout 없이 완료.
- Container state: `exited`; container `ExitCode=0`; `OOMKilled=false`; state error 없음.
- 시작/종료 시각(Engine UTC): `2026-10-30T06:37:35.827957803Z` / `2026-10-30T06:37:40.229984041Z`.
- Wall time: 약 `4.575s`; 30초 timeout 없음.
- stdout: `1.182.1\n` (8 bytes).
- stderr: 비어 있음 (0 bytes).
- 출력 수집 합계: 8 bytes / 16 KiB 상한.
- `.gitconfig` 또는 `safe.directory` 오류는 이번 stderr에 없었다. `SEMGREP_IN_DOCKER` 제거 설정과 정적 소스에 비추어 wildcard 초기화가 건너뛰었을 것으로 예상되나, 실제 Git 설정 파일 내용을 읽거나 Git 설정 변경을 직접 관찰하지 않았으므로 Git `safe.directory` 우회 부재는 **NOT_VERIFIED**로 남긴다. `safe.directory=*`를 설정하거나 `GIT_CONFIG_GLOBAL`을 사용하지 않았다.
- 실행 전후 image ID와 플랫폼은 지정값과 일치.
- Cleanup: 해당 컨테이너만 `docker rm`으로 제거, 종료 코드 0; 이후 이름 필터에 잔존 컨테이너 없음.

버전 문자열, 컨테이너 정상 종료, 설정 반영은 이번 테스트에서 각각 확인됐다. 이 결과는 오프라인 `semgrep --version` 실행의 성공이지 격리 강제력에 대한 포괄 검증은 아니다.

### 공급망 및 격리 상태

- 이미지 digest/platform 일치: 확인.
- 이미지 서명, provenance, 승인된 trust root: 계속 **UNVERIFIED**.
- Docker 설정의 `--network=none`, read-only root, tmpfs, 자원 제한 반영: inspect에서 확인. 실제 egress, 파일시스템 경계, CPU/RAM/PID/디스크 제한의 강제 초과 시험은 **NOT_TESTED**.
- 비신뢰 합성 프로젝트 Semgrep scan, timeout 후 자식 프로세스 정리, crash 후 잔존 파일 처리, Ubuntu 격리: **NOT_TESTED**.
- Git safe.directory 변경 없음: **NOT_VERIFIED**.
- 기존 로컬 scan 동작은 이번 한정 진단에서 재시험하지 않았다. 기준 CI 성공은 로컬 OCI 격리 증거가 아니다.

### Phase 7C-0X-U 판정

**`PHASE_7C_0X_U_OFFLINE_VERSION_VERIFIED`**

정확한 1.182.1 문자열, container exit code 0, timeout 없음, `OOMKilled=false`, 사전 inspect된 실행 제한, cleanup이 확인됐다. `SEMGREP_ENABLE_VERSION_CHECK=0`이 종료 지연을 일으켰던 경로를 제거했을 가능성이 가장 높지만, 단일 실행이므로 인과성은 확정하지 않는다. `SEMGREP_SEND_METRICS=off`는 적용됐지만 `--version` 경로에서의 원인으로 입증되지 않았다.

이 판정은 전체 격리 검증이나 Remote Scan 승인이 아니다. 서명/provenance, Git 설정 보호의 직접 증명, 실제 네트워크·filesystem·resource 강제 효과 및 crash cleanup이 남아 있으므로 비신뢰 GitHub 저장소를 수집하거나 분석하지 않는다. 앞선 HOLD 기록은 유지한다.

---

## Phase 7C-0Y — Docker 격리 강제 효과 검증

이 절은 지정된 로컬 이미지와 합성 probe에서 실제 제한 효과를 확인한 결과다. 기존 7C-0 및 후속 기록을 덮어쓰지 않는다.

### 시작 Gate 및 범위

- Branch `main`; local HEAD, `origin/main`, 원격 GitHub `main`: `bc53a8c4415822576ec0c7cefe699cdabe2d119b`; ahead/behind `0/0`.
- GitHub Actions Run `40919535112`: 정확한 SHA, `push / completed / success`. Python, Semgrep 1.182.1, React 대시보드 및 실제 Chromium–FastAPI–Semgrep E2E 필수 job/steps 성공.
- Working tree 시작 시 기존 사용자 작성 미추적 문서 하나만 존재. 이 문서를 보존했다. 별도 변경 및 테스트 컨테이너 잔존은 없었다.
- Docker Engine/CLI `29.8.2`, Linux ARM64. 대상 이미지 로컬 존재, `linux/arm64`, digest `sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5`.
- 합성 입력 외 실제 프로젝트는 사용하지 않았다. 새 이미지 다운로드/빌드, GitHub 접근, 코드 분석은 하지 않았다.

공통 probe 설정은 `--pull=never`, `--platform=linux/arm64`, `--network=none`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--user=1000:1000`, CPU 1 이하, 메모리 512 MiB 이하, PID 32 이하, `--restart=no` 및 `/tmp` 16 MiB·`/home/semgrep/.semgrep` 4 MiB tmpfs였다. 모든 probe에 오프라인 설정 `SEMGREP_ENABLE_VERSION_CHECK=0`, `SEMGREP_SEND_METRICS=off`, 값 없는 `SEMGREP_IN_DOCKER` 제거 요청을 적용했다. Host 프로젝트, 홈, Docker socket은 마운트하지 않았다. 합성 입력 시험에서만 임시 생성한 합성 입력 디렉터리 하나를 `/mnt/synthetic`에 read-only bind mount했다.

### 실제 시험 결과

| 통제 | 상태 | 실행 증거 및 범위 |
|---|---|---|
| 비관리자 UID/GID | **ENFORCED** | 컨테이너 내부 UID/GID `1000:1000`. `/proc/self/status`의 `NoNewPrivs=1`, `CapEff=0000000000000000`. |
| Docker 보안 옵션 | **CONFIGURED** | inspect에서 `ReadonlyRootfs=true`, network `none`, cap drop `ALL`, `no-new-privileges`, CPU/memory/PID 한도, restart `no` 확인. 설정 조회 자체는 각 효과를 대신하지 않는다. |
| 외부 TCP egress | **ENFORCED (시험 경로)** | no-network probe에 인터페이스/경로 정보를 기록. `203.0.113.1:9`(문서용 TEST-NET 주소) 연결 시 errno 101 `ENETUNREACH`; 실제 인터넷 서비스는 호출하지 않음. 라우트 목록은 비어 있었고 활성 인터페이스는 loopback 및 tunnel 계열 pseudo interface였음. |
| DNS egress | **ENFORCED (시험 경로)** | 설정된 resolver로 `.invalid` 합성 이름 UDP DNS 질의 시 errno 101 `ENETUNREACH`. 이전 probe에서 시험 코드의 alarm 처리 결함으로 결과를 내지 못한 시도는 실패로 보존하며, 수정 probe 결과만 성공 근거로 사용. |
| 컨테이너 proxy 우회 | **확인된 우회 없음** | 내부 HTTP/HTTPS/ALL proxy 변수 없음. Docker daemon에는 HTTP/HTTPS proxy 설정이 있지만 값은 보고서에 기록하지 않음. 네트워크 없음 상태에서 DNS/TCP가 `ENETUNREACH`였음. Docker Desktop의 모든 내부 전달 경로를 독립적으로 시험한 것은 아님. |
| Host FastAPI / Host loopback 접근 | **NOT_TESTED** | 호스트 `127.0.0.1:8765`에서 FastAPI가 수신 중이지 않았고, 호스트에서 `host.docker.internal` 이름도 확인되지 않았다. 컨테이너의 `127.0.0.1`을 Host 접근 증거로 사용하지 않았다. no-network/무경로 결과는 있으나 실제 FastAPI 서비스에 대한 연결 시험은 아니다. |
| 합성 입력 read-only | **ENFORCED** | 테스트 전용 디렉터리만 bind mount했고 inspect의 해당 mount `RW=false`. 컨테이너에서 파일 읽기 성공, 같은 파일 쓰기는 errno 30 `EROFS`; 입력은 변경되지 않음. |
| root filesystem 쓰기 제한 | **ENFORCED** | 존재하는 `/etc` 경로에 새 파일을 만드는 제한된 시도는 errno 30 `EROFS`. |
| 승인 외 홈 경로 쓰기 제한 | **ENFORCED** | `/home/semgrep/` 바로 아래 승인 설정 tmpfs 바깥 파일 쓰기는 errno 30 `EROFS`. |
| 승인 tmpfs 쓰기 | **ENFORCED** | `/tmp`와 `/home/semgrep/.semgrep`에 작은 생성/삭제 성공. 컨테이너 `/proc/mounts`에는 설정된 크기와 `noexec,nosuid,nodev`가 보임. |
| Host 홈 및 Docker socket | **CONFIGURED / 부분 확인** | inspect에서 Host bind와 Docker socket mount 없음. 컨테이너의 `/var/run/docker.sock` 및 Host-only 합성 경로가 존재하지 않음. Host의 모든 파일 경로를 전수 검사한 것은 아님. |
| 권한 상승 방지 | **ENFORCED (커널 상태 확인)** | 내부 UID 1000, 유효 capability mask 0, `NoNewPrivs=1`. 별도 setuid 프로그램 실행은 하지 않음. |
| CPU | **ENFORCED** | 0.1 CPU로 낮춘 disposable probe에서 `cpu.max=10000 100000`, 1.2초 bounded 계산 중 `nr_throttled` 12 증가, `throttled_usec` 1,081,352 증가. 목표 worker 1 CPU 제한 자체도 inspect/cgroup에서 `100000 100000`으로 확인. |
| Memory | **부분 확인** | 기본 probe에서 512 MiB 설정과 `memory.max=536870912` 확인. 별도 64 MiB 제한 probe에서 `memory.max=67108864`, `memory.peak=67108864` 관찰. bounded 96 MiB bytearray 할당/페이지 접촉은 종료 코드 0으로 끝났으며 측정 당시 `memory.current=62033920`, RSS `44648 kB`, HWM `68620 kB`. resident cgroup 한도 도달은 관찰했으나 swap 사용량/한도와 총 메모리+swap 한도는 측정하지 않았다. |
| PID | **ENFORCED** | 별도 `--pids-limit=8` probe에서 최대 7개 자식 생성 후 fork errno 11 `EAGAIN`; `pids.max=8`, `pids.events max=1`. 고정 16회만 시도했고 fork bomb은 사용하지 않음. 목표 제한 32도 기본 probe에서 cgroup에 확인. |
| tmpfs/disk | **ENFORCED (승인 tmpfs만)** | `/tmp` 16 MiB에 제한된 쓰기가 16,777,216 bytes 후 errno 28 `ENOSPC`; 설정 tmpfs 4 MiB는 4,194,304 bytes 후 errno 28. 쓰기 파일은 unlink했고 컨테이너 제거로 mount를 정리. 전체 Host disk quota 또는 임시 전체 workspace quota는 아님. |
| Git 설정 보호 | **일부 확인** | 내부에서 `SEMGREP_IN_DOCKER` 부재 확인. 읽기 전용 `git config --show-origin --get-all safe.directory` 결과는 컨테이너 global 설정의 비-wildcard 항목 1개였으며 `*` 값은 없음. 설정을 쓰거나 수정하지 않았다. 이후 Semgrep scan 자체가 실행되지 않아 scan 초기화 중 설정 변경 여부는 **NOT_VERIFIED**. |
| 출력/Privacy canary | **ENFORCED (시험 범위)** | 호스트 임시 환경변수 및 `/tmp` Host-only 합성 canary 파일은 컨테이너 환경/경로에서 보이지 않았고, inspect env·출력·컨테이너 로그에도 canary 값이 없었다. 실제 토큰은 사용하지 않았으며 proxy/토큰 환경변수 부재를 확인. |

### 메모리 제한 해석

Docker `--memory`는 cgroup의 비-swap 메모리 한도다. Docker 공식 문서는 `--memory-swap`을 별도로 주지 않으면 호스트가 지원하는 경우 memory와 swap 합계가 memory 한도의 두 배가 될 수 있다고 설명한다. 이번 단계에서는 승인된 제한 외에 `--memory-swap`을 추가하거나 변경하지 않았다. 따라서 resident/cgroup 한도 도달은 관찰했지만, memory+swap 총량의 강제 상한은 **NOT_TESTED**다. [Docker Resource constraints](https://docs.docker.com/engine/containers/resource_constraints/)

### Timeout, 자식 프로세스 및 Cleanup

- 정상 종료: base, CPU, memory, PID, tmpfs, Git 설정 및 privacy probe들이 Docker/container 종료 코드 0으로 종료.
- 실패한 첫 네트워크 probe: DNS lookup용 alarm이 시험 코드 내부 예외 처리 중 발생하여 probe 종료 코드 1. 이를 네트워크 결과로 계산하지 않았고 컨테이너 정리 후 제한 시간 UDP 질의 probe로 재시험.
- 강제 종료: 합성 Python 부모/자식(자식 1개, 둘 다 sleep) 컨테이너에서 `docker top`으로 두 프로세스를 확인한 뒤 1초 후 지정 컨테이너만 `docker kill`. Container 및 `docker start -a`는 exit 137, `OOMKilled=false`, status `exited`. `docker ps`에서 실행 중인 동일 컨테이너 없음, 해당 컨테이너 `docker rm` 성공. 컨테이너 PID namespace 종료는 확인했으나 Host 커널에서 자식 PID를 별도로 추적하지는 않았다.
- 모든 생성 컨테이너는 개별 이름을 지정하고 상태 확인 후 각각 제거했다. Docker 전체 prune/일괄 정리는 하지 않았다. 각 fixture는 임시 디렉터리 정리로 제거했다.
- 이미지 digest/platform은 유지됐고 테스트 후 실행 중/잔존 테스트 컨테이너가 없다.

### 합성 Semgrep 검사

**실행하지 않음 (`NOT_TESTED`).** 이 Phase의 요구는 선행 격리 조건이 충족된 뒤에만 Semgrep 분석을 하도록 한다. Host FastAPI 실제 접근성은 서버가 실행 중이지 않아 확인할 수 없었고, memory+swap 총량 제한 및 Semgrep scan 초기화 중 Git 설정 상태도 직접 검증하지 않았다. 통제가 미완료된 상태에서 분석으로 넘어가지 않았다. 오프라인 `semgrep --version`의 이전 성공을 Semgrep scan 격리 증거로 재사용하지 않는다.

### 공급망, Ubuntu 및 남은 차단 조건

- 이미지 digest 및 ARM64 일치: 확인.
- 이미지 서명, provenance 및 승인 trust root: **UNVERIFIED**. digest 일치는 서명/공급망 검증이 아니다.
- Docker Desktop Linux ARM64 환경에서 확인한 결과다. Ubuntu CI 격리 통제 및 재현성은 **NOT_TESTED**.
- Host FastAPI 접근 차단, memory+swap 총량, 분석 중 Git 초기화, Semgrep 분석 프로세스의 실제 filesystem/network 경계, 완전한 Host 파일 비노출 검증이 남아 있다.
- Phase 7B의 SSRF/redirect/socket peer 검증, archive 안전 추출, commit/tree 동일성, 다운로드·임시파일 crash 복구는 본 Phase의 범위 밖이며 미해결이다.

### Phase 7C-0Y 판정

**`PHASE_7C_0Y_ENFORCEMENT_HOLD`**

여러 Docker 통제의 실제 효과(네트워크 경로 차단, read-only input/root, CPU throttling, PID 상한, 승인 tmpfs 용량, 비관리자 및 `no_new_privs`, 지정 컨테이너 timeout 정리)는 관찰됐다. 그러나 Host FastAPI 접근 시험이 불가능했고, memory+swap 상한과 Semgrep scan에서의 Git 보호를 직접 검증하지 못했다. 필수 선행조건이 전부 충족되지 않았으므로 합성 Semgrep 분석은 수행하지 않았다. 이 결과를 `LOCAL_ENFORCEMENT_VERIFIED`로 올리지 않으며 GitHub Intake 구현은 차단 상태다.

## Phase 7C-0Y-R — 잔여 격리 Gate 및 합성 Semgrep 검사

이 절은 Phase 7C-0Y의 기존 결과를 보존하면서 새로 승인된 잔여 시험만 기록한다. 기존 네트워크 경로, read-only root/input, CPU, PID, tmpfs, 비관리자, timeout/cleanup 결과를 다시 시험한 것으로 간주하지 않는다.

### 시작 Gate

- 시작 branch: `main`.
- 시작 local HEAD, `origin/main`, GitHub `main`: `bc53a8c4415822576ec0c7cefe699cdabe2d119b`; ahead/behind `0/0`.
- 기존 기준 CI Run `40919535112`: 정확한 SHA의 `push / completed / success`; Python, Semgrep, React 및 실제 Chromium–FastAPI–Semgrep E2E 필수 작업 성공.
- 시작 working tree: 기존 사용자 작성 미추적 검증 문서 하나만 존재. 본 절을 같은 문서에 추가했으며 해당 문서를 삭제하거나 초기화하지 않았다.
- Docker Engine `29.8.2`, Linux ARM64, cgroup v2. 대상 이미지가 로컬에 있었고 시험 전후 image ID 및 플랫폼은 `sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5`, `linux/arm64`와 일치했다. pull/build는 하지 않았다.
- 시작 시 잔존 테스트 컨테이너는 없었다.

### 메모리 및 swap 상한

전용 memory probe 컨테이너에 `--memory=512m --memory-swap=512m`를 적용했다. 높은 부하나 고갈 시험은 하지 않고 cgroup 설정만 읽었다.

| 확인 항목 | 관찰 결과 | 판정 |
|---|---:|---|
| Docker inspect `Memory` | `536870912` bytes | **CONFIGURED** |
| Docker inspect `MemorySwap` | `536870912` bytes | **CONFIGURED** |
| cgroup v2 `memory.max` | `536870912` bytes | **ENFORCED** |
| cgroup v2 `memory.swap.max` | `0` bytes | **ENFORCED** — 컨테이너 추가 swap 허용 없음 |
| cgroup v2 `memory.swap.current` | `0` bytes | probe 관찰 시 swap 미사용 |
| probe 종료 | exit `0`, `OOMKilled=false` | PASS |

Docker Desktop 정보는 Linux ARM64, cgroup v2, 8 CPU, `MemTotal=8319770624` bytes, daemon 경고 없음이었다. Linux VM 전체의 swap 구성은 별도로 확인하지 않았다. 컨테이너의 `memory.swap.max=0`은 해당 cgroup에 대한 커널 적용 근거이며, VM 전체 swap 정책을 증명하지는 않는다. 앞 Phase에서 수행한 bounded memory probe 결과도 별도 기존 근거로 보존한다.

### Host 서비스 접근 차단

- scan 컨테이너 inspect에서 `NetworkMode=none`이었다. 이전 Phase에서 기록한 빈 route 목록과 제한된 합성 외부 TCP/DNS 시도의 `ENETUNREACH` 결과를 유지한다.
- 이번에는 실제 FastAPI를 시작·수정하지 않았고 합성 HTTP 서비스를 띄우지도 않았다. Docker Desktop의 `network=none` 컨테이너에서 Mac loopback 전용 서비스로 이어지는 안전하고 직접적인 연결 경로를 확인하지 못했다. 컨테이너 내부 `127.0.0.1`은 컨테이너 자신의 loopback이므로 Host 접근 증거로 사용하지 않았다.
- Host 서비스/API 접근 차단의 직접 통합 시험: **NOT_TESTED**. 설정과 기존 무경로·egress 근거를 실제 Host 서비스 연결 시험으로 승격하지 않는다. 바인딩 범위도 넓히지 않았다.

### Semgrep scan 중 Git 신뢰 설정

scan 전용 컨테이너에서 Docker inspect로 이미지의 `SEMGREP_IN_DOCKER=1` 기본값이 값 없는 제거 항목으로 override된 것을 확인했다. 동일 컨테이너의 고정 검증 wrapper에서도 Python 프로세스와 Semgrep 자식 프로세스 양쪽에서 변수가 부재했다. 호스트에서 해당 변수가 export되어 있지 않은 것도 확인했다.

scan 직전 및 직후에 `git config --system --get-all safe.directory`와 `git config --global --get-all safe.directory`만 읽었다. 두 시점 모두 조회 가능했고 wildcard `*`는 없었다. `/home/semgrep/.gitconfig`의 사전·사후 SHA-256 비교 결과도 같았다. `GIT_CONFIG_GLOBAL`을 설정하지 않았고 Git 설정을 쓰거나 변경하지 않았다. 실제 사용자 Git 저장소는 mount하지 않았다.

| 항목 | 결과 |
|---|---|
| `SEMGREP_IN_DOCKER` (wrapper 및 Semgrep 프로세스) | **확인됨: 부재** |
| system/global `safe.directory=*` 이전 | **없음** |
| system/global `safe.directory=*` 이후 | **없음** |
| safe.directory wildcard 신규 추가 | **없음** |
| 컨테이너 global Git 설정 파일 변경 | **관찰되지 않음** |
| Host Git 설정 접근·변경 | 없음; Host 설정을 mount하지 않음 |

이 확인은 지정 이미지와 실행 경로의 해당 container system/global 설정에 한정한다. Git 전체 설정 체계 또는 다른 Semgrep 버전의 동작을 일반화하지 않는다.

### 합성 Semgrep 검사

합성 입력과 test-only 규칙을 별도 임시 디렉터리에 만들었다. Python 파일에는 정적 `eval` 패턴과 무해한 식별용 canary가 있었으며 코드를 실행하지 않았다. 규칙 파일은 Python `eval(...)` 정적 패턴을 하나만 탐지했다. 두 입력 파일은 검사 전후 해시가 같았다.

컨테이너는 지정 ARM64 digest를 사용했고, `--pull=never`, `--network=none`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--user=1000:1000`, `--cpus=1`, `--memory=512m`, `--memory-swap=512m`, `--pids-limit=32`, `--restart=no`를 적용했다. 기존 두 tmpfs(`/tmp` 16 MiB 및 `/home/semgrep/.semgrep` 4 MiB)만 쓰기 가능했고, 합성 입력 디렉터리 하나만 `RW=false` read-only bind mount했다. Host home/project와 Docker socket은 mount하지 않았다. `SEMGREP_ENABLE_VERSION_CHECK=0`, `SEMGREP_SEND_METRICS=off`를 적용하고 `SEMGREP_IN_DOCKER`를 제거했다. Docker inspect에서 `ReadonlyRootfs=true`, `MemorySwap=536870912`, `NetworkMode=none`, mount 한 개의 `RW=false`를 확인했다.

실제 실행한 분석 인자:

```text
semgrep scan --json --metrics=off --disable-version-check --oss-only --no-autofix --config /mnt/synthetic/rules.yml -- /mnt/synthetic/project
```

wrapper는 먼저 `semgrep --version`과 Git 설정 사전 검사를 수행하고, 이후 위 scan을 한 번 실행했다. subprocess 출력은 메모리에서 합계 2 MiB로 제한하고 wrapper 자체에는 정규화된 요약만 출력했다. `--config auto`, Registry 규칙, autofix, dependency download, 외부 LLM 또는 분석 대상 코드 실행은 없었다.

| 검사 | 결과 |
|---|---|
| Semgrep 버전 | `1.182.1`; 버전 probe exit `0` |
| scan exit / timeout | exit `0`; 55초 내부 상한 내 완료, timeout 없음 |
| JSON 형식 / Semgrep errors | 유효 JSON; errors `0` |
| 기대 Finding | 정확히 `1`; test-only rule ID 일치 |
| 위치 | 합성 `synthetic.py:4:12` |
| raw scan stdout / stderr | 각각 `1816` / `569` bytes; 총합 2 MiB 미만 |
| 입력·규칙 해시 | 실행 전후 동일 |
| wildcard Git trust | scan 전후 없음; `.gitconfig` 해시 동일 |
| 테스트 컨테이너 | 종료 상태 `exited`, exit `0`, `OOMKilled=false`, PID `0` |

Finding은 정적 패턴 탐지 결과이며 실제 취약점 확정이나 비신뢰 외부 저장소 안전성 증거가 아니다.

### Privacy canary 및 Cleanup

- canary는 합성 소스에만 포함했다. Semgrep raw JSON/표준 오류에서 canary 문자열은 관찰되지 않았고, Docker 컨테이너 로그에도 없었다. 로그에는 정규화된 수치 요약만 남았다. raw JSON과 내부 경로는 공개 API로 보내지 않았으며 API privacy contract 자체는 이번 단계에서 시험하지 않았다.
- Docker create에는 Host 환경변수 전체 전달 옵션을 사용하지 않았다. 컨테이너에는 이미지 기본값과 명시한 Semgrep 오프라인 환경 설정만 적용했다. 실제 credential을 사용하지 않았다.
- 합성 입력은 read-only였고 검사 전후 해시가 동일했다. 종료된 전용 memory probe와 scan 컨테이너만 각각 제거했다. 이후 해당 container ID 조회 결과는 비어 있었고, 실행 중/잔존 테스트 컨테이너는 없었다.
- 합성 임시 디렉터리는 입력 해시가 보존된 것을 확인한 뒤 제거했다. Docker 전체 prune, 이미지 삭제, 사용자 리소스 정리는 하지 않았다. 이미지 digest는 유지됐다.
- 합성 Host HTTP 서비스는 실행하지 않았으므로 해당 리소스 정리 항목은 해당 없음이다.

### 상태 및 남은 차단 조건

| 범위 | 상태 |
|---|---|
| Memory + swap cgroup 상한 | **ENFORCED** (`memory.max=512 MiB`, `memory.swap.max=0`) |
| Phase 7C-0Y에서 이미 검증한 핵심 격리 | 기존 제한된 시험 환경의 근거로 유지; 이번 Phase에서 모두 반복하지 않음 |
| 실제 Host 서비스/API 도달성 | **NOT_TESTED** |
| Semgrep scan 중 Git wildcard trust 부재 | **확인됨** (동일 컨테이너 전후) |
| 합성 Semgrep 검사 | **PASS** (1 Finding, exit 0) |
| canary 비노출 및 테스트 자원 cleanup | **PASS** (이번 합성 시험 범위) |
| Semgrep 이미지 서명/provenance 및 승인 trust root | **UNVERIFIED** |
| Ubuntu CI 격리 | **NOT_TESTED** |
| API privacy, 실제 프로젝트, GitHub SSRF/archive/commit 동일성 | **NOT_TESTED / 별도 Gate** |

### Phase 7C-0Y-R 판정

**`PHASE_7C_0Y_R_LOCAL_CORE_VERIFIED`**

이번 제한된 Docker Desktop Linux ARM64 환경에서 memory+swap cgroup 한도와 Semgrep 1.182.1 합성 scan, 검사 중 Git `safe.directory=*` 미추가, canary 비노출 및 해당 테스트 리소스 cleanup을 확인했다. 기존 Phase 7C-0Y의 핵심 격리 근거는 재시험 결과인 것처럼 바꾸지 않고 그대로 참조한다. Host 서비스/API 직접 통합 시험은 **NOT_TESTED**다.

이 판정은 로컬 핵심 격리와 합성 scan에만 적용한다. 이미지 서명/provenance는 **UNVERIFIED**이고 Ubuntu 격리, 실제 Host API, GitHub SSRF, 안전한 archive 추출, Git tree/blob/commit 동일성 및 Remote Scan은 여전히 별도 차단 조건이다. GitHub Intake 구현 또는 운영 사용 승인은 아니다.
