# Phase 7C-0Z — Ubuntu ARM64 CI 격리 준비 및 공급망 Gate

## 결론

**`PHASE_7C_0Z_CI_DESIGN_READY`**

`ubuntu-24.04-arm`은 현재 GitHub-hosted ARM64 표준 runner로 제공된다. 그러나 이 문서는 CI 설계 준비 결과일 뿐 Docker pull/run, workflow dispatch, Ubuntu 격리 통과 또는 GitHub Intake 실행을 뜻하지 않는다. 이미지 서명과 provenance가 여전히 `UNVERIFIED`이므로 CI 이미지 신뢰 Gate는 차단 상태다.

## 1. 기준 및 시작 Gate

- 저장소: `misosos/ai-code-security-analyzer` (GitHub에서 `PUBLIC` 확인).
- 기준 SHA, local HEAD, `origin/main`, GitHub `main`: `bc53a8c4415822576ec0c7cefe699cdabe2d119b`.
- Branch `main`, ahead/behind `0/0`.
- CI Run `40919535112`: 정확한 head SHA, `push / completed / success`.
- 필수 작업 성공: `Python tests and CLI`, `Semgrep 1.182.1 integration`, `React dashboard`. React 작업 안에서 typecheck, test, build, Chromium smoke 및 required real Chromium–FastAPI–Semgrep E2E가 성공했다.
- 시작 working tree에는 기존 사용자 작성 `docs/phase7c0-isolated-worker-validation.md` 미추적 파일 하나만 있었다. 이 파일은 보존했다.
- 시작 시 `.github/workflows/ci.yml`에는 `push` 및 `pull_request` trigger가 있고, 세 job 모두 `ubuntu-latest`를 사용한다. Workflow/job 권한은 `contents: read`, checkout은 full commit SHA로 고정하고 `persist-credentials: false`다. Docker 격리 job이나 수동 격리 workflow는 없다.
- 이번 단계에서 실제 workflow 실행, Docker pull/run, 외부 저장소 다운로드, 이미지 빌드 및 공급망 검증 우회는 하지 않았다.

## 2. Phase 7C-0Y-R 로컬 근거의 적용 범위

기존 증거 원장 [phase7c0-isolated-worker-validation.md](phase7c0-isolated-worker-validation.md)의 `Phase 7C-0Y` 및 `Phase 7C-0Y-R` 기록을 변경하지 않았다. `PHASE_7C_0Y_R_LOCAL_CORE_VERIFIED`는 로컬 Docker Desktop Linux ARM64 환경에 한정된 판정이다. 다음 항목이 해당 환경에서 확인돼 있다.

- UID/GID `1000:1000`, `NoNewPrivs=1`, effective capabilities `0`.
- `network=none`과 합성 TCP/DNS probe 실패.
- read-only root 및 synthetic input, 승인 tmpfs 크기 제한.
- CPU throttling, PID 제한.
- cgroup v2 `memory.max=536870912`, `memory.swap.max=0`.
- Semgrep OSS `1.182.1` 합성 scan에서 기대 Finding 1건, exit `0`.
- scan 전후 system/global `safe.directory=*` 없음.
- 입력 무결성, canary 비노출 및 테스트 컨테이너/fixture cleanup.

이 결과를 Ubuntu runner 결과로 재사용하지 않는다. 실제 Host API 접근 차단은 **`NOT_TESTED`**, 이미지 서명/provenance와 승인 trust root는 **`UNVERIFIED`**다. Ubuntu에서 위 통제를 하나도 실행하지 않았다.

| 보안 증거 범위 | 기준 상태 | 적용 범위 |
|---|---|---|
| 로컬 핵심 격리 및 합성 Semgrep 1.182.1 scan | **`VERIFIED`** | Phase 7C-0Y-R의 지정 Docker Desktop Linux ARM64 환경만 |
| 실제 Host API 직접 접근 차단 | **`NOT_TESTED`** | 로컬 및 Ubuntu 통합 연결 시험 미완료 |
| Ubuntu ARM64 격리 실행 | **`NOT_TESTED`** | CI worker를 실행하지 않음 |
| 이미지 서명 및 provenance | **`UNVERIFIED`** | attestation 목록 관찰은 서명·issuer·trust root 검증이 아님 |
| 게시자 identity 및 승인 trust root | **`UNVERIFIED`** | 검증 정책과 신뢰 체인 미확정 |
| GitHub SSRF 방어 | **`NOT_TESTED`** | Remote Intake 미구현 |
| Archive 안전 추출 | **`NOT_TESTED`** | Remote Intake 미구현 |
| Commit/Tree/Blob 동일성 | **`NOT_TESTED`** | Remote Intake 미구현 |
| GitHub Remote Intake | **`NOT_APPROVED`** | 별도 설계·검증·승인 필요 |

## 3. Ubuntu ARM64 runner 적합성

GitHub 공식 runner 참조는 공개 저장소용 Linux ARM64 `ubuntu-24.04-arm`을 4 CPU, 16 GB RAM, 14 GB SSD 표준 runner로 명시한다. 이 저장소는 공개 저장소다. 같은 문서의 private 저장소 기준은 ARM64 2 CPU, 8 GB RAM, 14 GB SSD이며 해당 사용에는 plan별 사용량/요금이 적용될 수 있다. 따라서 현재 공개 저장소의 runner 사양을 비공개 저장소에 일반화하지 않는다. [GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)

GitHub의 ARM64 Ubuntu 24.04 image inventory는 2026-10-26의 이미지 버전 `20261026.166.1`, Ubuntu 24.04.5, ARM64, kernel `7.0.0-1017-azure`, Docker Client/Server `28.0.4`를 기재한다. `ubuntu-24.04-arm`은 rolling label이므로 향후 실행의 kernel, Docker version, architecture, cgroup mode는 매 job에서 다시 수집해야 한다. Image inventory는 cgroup v2, seccomp 활성 여부나 container quota 강제 효과를 보증하지 않는다. [Ubuntu 24.04 ARM64 runner image inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Arm64-Readme.md)

| 영역 | 확인된 문서 근거 | 실행 전 필수 runtime 확인 |
|---|---|---|
| ARM64 label | `ubuntu-24.04-arm` 명시, 표준 ARM64 runner | `runner.arch == ARM64`, `uname -m` 및 Docker platform이 ARM64인지 확인; 불일치 시 pull/run 금지 |
| Docker | Runner image inventory에 Docker client/server 포함 | `docker info`/daemon 연결, Client·Server version, OSType, Architecture 출력; Docker 미사용/daemon 불가면 HOLD |
| 권한 | Linux GitHub-hosted VM은 passwordless `sudo` 가능 | job의 host runner는 관리 권한 환경으로 취급; analyzer 컨테이너는 UID/GID `1000:1000`, root 금지 |
| cgroup v2 | Ubuntu 24.04 kernel 정보만 확인; runner image 문서는 cgroup mode를 보증하지 않음 | `/sys/fs/cgroup/cgroup.controllers`, `docker info CgroupVersion`, 컨테이너 `memory.max`, `memory.swap.max`, `cpu.max`, `pids.max` 확인 |
| seccomp/capability | image inventory에 실제 daemon security option 상태 없음 | `docker info` security options와 inspect를 확인하고, 내부 `/proc/self/status`의 `NoNewPrivs`, `CapEff` 확인 |
| tmpfs | Docker Linux tmpfs 지원 문서 존재; tmpfs는 container memory cgroup 사용량에 포함 | 실제 mount options·크기 및 제한된 write 경계 확인 |
| memory/swap | Docker는 `--memory-swap`을 memory와 합한 총량으로 정의; 두 값을 같게 주면 추가 swap 없음 | inspect 및 cgroup v2 값을 모두 확인. `memory.swap.max=0`이 아니거나 확인 불가면 HOLD |
| 네트워크 | Docker `--network=none` worker 설계 가능; Host runner의 네트워크는 계속 사용 가능 | container 내부 route/TCP/DNS probe로 egress 확인. Host-level Docker pull 단계와 analyzer network namespace를 분리 |
| job timeout | GitHub workflow에 job/step `timeout-minutes` 설정 가능 (최대 360분) | 계획값 `timeout-minutes: 15`; container Semgrep 실행 제한 60초 및 timeout probe 별도 적용 |
| runner 수명 | 각 표준 runner job은 새 VM이며 job 완료 후 VM을 decommission | 임시 파일 및 컨테이너를 명시 cleanup; `always()` cleanup은 최선 노력이며 강제 취소 뒤에는 runner VM 수명 종료가 최종 경계 |

Docker 문서는 cgroup v2가 Docker Engine 20.10부터 지원되며 kernel/runtime 선행 조건을 갖춘다고 설명하지만, GitHub runner의 실제 설정과 특정 job에서 quota가 강제되는지는 런타임 확인 대상이다. Docker `--memory-swap`의 의미와 swap limit 미지원 시 warning 가능성도 문서화되어 있으므로 옵션만 보고 통과 처리하지 않는다. [Docker cgroup v2](https://docs.docker.com/engine/containers/runmetrics/#running-docker-on-cgroup-v2), [Docker resource constraints](https://docs.docker.com/engine/containers/resource_constraints/), [Docker tmpfs mounts](https://docs.docker.com/engine/storage/tmpfs)

### 이미지 용량 및 다운로드 영향

- 실행 대상은 ARM64 플랫폼 manifest digest `sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5`다.
- 이전 Docker Hub manifest 관찰에서 multiarch index digest는 `sha256:0ed16bbbb23e5bf7c442df9144704d74b54ad2d003094e09905130d642f22473`였고, ARM64 child manifest digest는 위와 같이 달랐다. 이 digest들을 서로 바꾸어 쓰지 않는다.
- 로컬 `docker image inspect`의 unpacked size는 `1,614,851,729` bytes (약 1.61 GB)였고, 기존 Docker Hub metadata 관찰의 ARM64 compressed image size는 약 `421.34 MB`였다. CI runner별 실제 전송 크기/시간은 측정하지 않았다.
- 공개 저장소 standard runner의 CPU/RAM/disk 여유는 문서에 기재된 값이다. cold image pull은 14 GB SSD 공간을 사용하며 다른 tool 설치·workspace 사용량과 함께 확인해야 한다. Cache를 도입하거나 image를 artifact로 보관하는 설계는 이번 초안에 포함하지 않았다.
- Docker Hub 공식 안내는 현재 익명 pull에 IPv4 주소 또는 IPv6 `/64` 기준 6시간당 100회 한도 및 사용량 정책을 명시한다. GitHub-hosted egress IP는 공유될 수 있으므로 이 한도를 안정적인 전용 quota로 가정하지 않는다. 요금/속도는 확인하지 않았고 수시로 바뀔 수 있다. [Docker Hub pull usage and limits](https://docs.docker.com/docker-hub/usage/pulls/)

## 4. 이미지 신뢰 Gate 및 대안

현재 증거는 기존 원장 기록을 따른다. 로컬 digest와 ARM64 플랫폼은 확인됐고, Docker Hub Verified Publisher 표시 및 SBOM/Provenance attestation 목록은 관찰됐다. 그러나 서명 검증이 성공하지 않았고 게시자 identity, issuer, attestation subject와 승인 trust root 연결은 확인되지 않았다. 따라서 이미지 authenticity/provenance는 **`UNVERIFIED`**이며, Docker Hub의 Verified Publisher 표시나 digest 일치를 암호학적 서명 성공으로 표현하지 않는다.

| 방안 | 신뢰 근거와 확인 방법 | 재현성·SBOM | 잔여 위험 및 추가 승인 |
|---|---|---|---|
| **A. Semgrep 공식 서명/provenance** (우선) | Semgrep가 공식적으로 게시한 signer identity, issuer/trust root, transparency-log 정책을 외부 자료로 확인. ARM64 manifest digest를 직접 subject로 연결한 서명 및 SLSA provenance 검증, builder workflow/source commit 확인. 기존 attestation 실패는 재현·원인 분류 후 검증 옵션을 생략하지 않고 다시 검증 | 서명된 SBOM과 provenance의 subject digest를 동일 ARM64 manifest에 대조; source commit·빌더·의존성 결합 확인 | 현재 필요한 identity/trust policy가 미확인이고 검증 실패 상태. 검증을 통과할 때까지 pull/run 금지. verifier/tool 버전도 고정·검토 |
| **B. 자체 worker 이미지** | 공식·검증된 base image digest, 고정 Semgrep OSS source/wheel과 모든 의존성 hash, lockfile, build toolchain을 선언. 다운로드와 빌드 입력을 승인한 단계로 분리하고 빌드 중 임의 네트워크 접근 금지 | SBOM 생성 후 base/직접·전이 의존성을 확인하고, 고정된 빌드 입력·명령·환경으로 재현 빌드 비교. 빌드 provenance는 신뢰된 builder identity와 분리 보관 | 자체 Dockerfile이라고 위험이 없어지지 않음. base·PyPI packages·build tools·builder credential/provenance가 새 신뢰 사슬. 별도 구현·공급망 검증·사용 승인 필요 |
| **C. 잔여 위험 승인 후 제한 CI** | 프로젝트 책임자의 별도 명시적 위험 예외 승인 및 보호된 manual 실행 승인 기록. 정확한 digest/platform pin, `network=none`, 무권한 token, secrets 없음, synthetic-only, ephemeral runner | 결과 artifact 없음. 최소 상태 요약만 로그. 사용 목적은 격리 통제 검증뿐 | 서명/provenance 미검증 상태가 계속 남음; container/runtime 취약점·image compromise 가능성. 운영/실사용 저장소 분석 승인이 아님. 별도 승인 없으면 fail closed |

**현 결정:** A를 우선하고, A의 증거를 얻지 못하면 B를 별도 설계한다. C는 기본값이 아니며, 현재 승인된 상태도 아니다. 기존 이미지가 `UNVERIFIED`인 동안 CI Docker pull/run Gate는 닫혀 있다. `--skip-tlog`나 trust root 임의 변경으로 성공을 만들지 않는다.

## 5. 향후 CI 보안 모델

비활성 workflow 초안은 `docs/ci_drafts/phase7c-isolation-validation.yml.txt`에 둔다. 실제 실행 경로인 `.github/workflows/`에는 추가하지 않았다.

- `workflow_dispatch`만 사용하고 input을 받지 않으며 default branch 이외의 ref는 job 조건으로 거부한다. GitHub는 `workflow_dispatch` 파일이 default branch에 존재해야 trigger를 받을 수 있다고 설명한다.
- top-level 및 job `permissions: {}`; `checkout`과 third-party action을 사용하지 않는 설계이므로 Contents 권한도 불필요하다. `GITHUB_TOKEN`, 저장소 secret, OIDC, PAT는 step에 넘기지 않는다.
- 현재 초안 job은 `if: false`로 비활성화되어 있고 이미지 신뢰 Gate는 의도적으로 실패한다. 이 두 차단을 별도 승인과 독립된 attest verifier 검토 없이 제거하지 않는다.
- 이미지 pull이 승인되더라도 registry access는 runner host 단계에서만 사용한다. analyzer container는 `--network=none`. 분석 코드는 synthetic fixture만 사용하고 실행하지 않는다.
- analyzer에는 Docker socket, Host home, 실제 프로젝트, credential/env wholesale, privileged mode가 없다. root filesystem은 read-only, process UID/GID `1000:1000`; 모든 resource 한도를 적용하고 내부에서 실제 값을 확인한다.
- image는 ARM64 manifest digest와 `--platform=linux/arm64`를 고정한다. Runner label이 ARM64여도 image의 실제 `.Os/.Architecture`, image ID/repo digest를 다시 확인하고 불일치 시 실패한다.
- Job timeout은 15분, Semgrep 및 bounded probes는 별도 60초 이내. 실패 경로는 `always()` cleanup과 정확한 이름으로 생성한 container만 제거하며, 전체 Docker cleanup은 하지 않는다.
- JSON 원문, source excerpt, canary, 절대 runner 경로, stderr 원문을 로그로 출력하지 않는다. 출력은 검사 단계 상태, version, Finding count, expected rule ID 여부 등 안전한 요약만 허용한다. Artifact를 업로드하지 않는다. GitHub 문서상 workflow logs/artifacts 기본 보관은 90일이며 저장소/조직 설정에서 변경 가능하므로 실제 retention policy는 별도로 확인한다. [GitHub artifact/log retention](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/remove-workflow-artifacts)
- GitHub-hosted runner VM은 job 종료 후 폐기되지만, 이는 workflow 내 cleanup 확인을 대체하지 않는다. Timeout/취소 시 cleanup을 검사하고, 완료 후 VM decommission은 추가 경계로 본다. [Using GitHub-hosted runners](https://docs.github.com/en/actions/how-tos/manage-runners/github-hosted-runners/use-github-hosted-runners)

GitHub는 `permissions`로 `GITHUB_TOKEN` 권한 최소화를 지원하며, `pull_request_target`에는 fork에서도 read/write 권한이 부여될 수 있다고 경고한다. 이 설계는 해당 trigger를 사용하지 않는다. [Workflow syntax and permissions](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax), [Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)

향후 `SEMGREP_IN_DOCKER` 제거는 빈 문자열을 지정하지 않는다. Docker CLI 문서에 따르면 `--env NAME`처럼 값 없이 지정한 변수가 CLI 호스트 환경에 없으면 컨테이너 환경에서도 unset된다. 따라서 활성화 전에는 runner 환경에 해당 변수가 없는지 검사하고, `docker create` 이후 `Config.Env`에서 이름이 완전히 빠졌는지 확인한 뒤에만 시작해야 한다. 존재 여부가 모호하거나 값이 빈 문자열로 남으면 실행을 중단한다. [Docker `run` environment option](https://docs.docker.com/reference/cli/docker/container/run/#set-environment-variables--e---env---env-file)

## 6. CI 격리 검증 계약

각 행의 `현재 로컬 상태`는 기존 7C-0Y-R 증거이고, `Ubuntu 상태`는 아직 실행되지 않았다는 뜻이다. 설정값 확인과 강제 효과를 한 결과로 합치지 않는다.

### 1) Image digest 및 플랫폼

- **목적:** ARM64 child manifest만 실행하고 multiarch index와 혼동하지 않기.
- **시험/기대:** 신뢰 Gate 통과 후에만 `docker pull --platform=linux/arm64`를 허용; inspect `.Os=linux`, `.Architecture=arm64`, image ID/repo digest가 고정 ARM64 manifest digest와 일치.
- **실패:** trust verifier 미통과, 불일치, pull 실패 또는 실제 플랫폼 정보 없음이면 실행 중단.
- **증거/환경:** pinned verifier 결과, inspect JSON의 최소 필드; Ubuntu Docker Engine/registry 필요.
- **현재:** 로컬 digest/platform 확인. Ubuntu `NOT_TESTED`; 신뢰 `NOT_VERIFIED`.

### 2) UID/GID

- **목적:** Semgrep 프로세스가 root로 실행되지 않음.
- **시험/기대:** inspect `Config.User=1000:1000` 및 컨테이너 내부 `id` 결과 동일.
- **실패:** UID 또는 GID 0, inspect/runtime 불일치.
- **증거/환경:** inspect field와 내부 identity 요약; Docker user namespace 동작에 의존.
- **현재:** 로컬 확인; Ubuntu `NOT_TESTED`.

### 3) NoNewPrivs 및 capability

- **목적:** 권한 상승과 불필요한 capability 방지.
- **시험/기대:** inspect `no-new-privileges`, `CapDrop=ALL`; 내부 `/proc/self/status`에서 `NoNewPrivs=1`, `CapEff=0`.
- **실패:** 옵션 누락, 커널 관찰값 불일치, privilege 상승 가능성.
- **증거/환경:** Docker inspect와 cgroup/container 내부 kernel status; runner kernel/seccomp.
- **현재:** 로컬 `ENFORCED`; Ubuntu `NOT_TESTED`.

### 4) Network egress 거부

- **목적:** analyzer container가 DNS/TCP/HTTP로 외부에 연결하지 못함.
- **시험/기대:** `network=none`, route/interface 요약, 통제된 문서용 reserved IP와 `.invalid` 질의가 네트워크 경로 오류로 실패; 실제 외부 서버 접속은 하지 않음.
- **실패:** route/egress 또는 proxy 경로 성공.
- **증거/환경:** inspect, 내부 route, TCP/DNS 오류 코드; Linux network namespace 및 runner Docker.
- **현재:** 로컬 합성 경로 확인; Ubuntu `NOT_TESTED`. Host API 직접 연결은 별도 항목으로 유지.

### 5) Read-only root

- **목적:** 이미지 root filesystem 변경 방지.
- **시험/기대:** `ReadonlyRootfs=true`; 존재하는 경로에 제한된 쓰기 probe가 `EROFS`.
- **실패:** 성공한 rootfs 쓰기 또는 read-only 설정 누락.
- **증거/환경:** inspect 및 bounded write 결과; Docker mount 동작.
- **현재:** 로컬 `ENFORCED`; Ubuntu `NOT_TESTED`.

### 6) Input write 거부

- **목적:** 제공한 합성 입력을 scan 도중 수정하지 않음.
- **시험/기대:** 합성 파일만 생성한 뒤 Docker bind mount 없이 시작 전 컨테이너에 복사하고, read-only root에서 읽기는 성공하며 쓰기는 `EROFS`; 상대경로 fixture hash가 전후 동일.
- **실패:** host bind mount 존재, write 성공 또는 hash 변경.
- **증거/환경:** inspect에서 bind mount 없음, 에러 코드, 상대경로 fixture digest; Docker의 stopped-container copy와 read-only root 동작은 Ubuntu에서 별도 재현해야 함.
- **현재:** 로컬 `ENFORCED`; Ubuntu `NOT_TESTED`.

### 7) tmpfs 크기 제한

- **목적:** Semgrep 설정/임시 파일의 쓰기를 승인 영역 및 크기에 한정.
- **시험/기대:** `/tmp` 16 MiB, `/home/semgrep/.semgrep` 4 MiB; options/readback 확인 후 bounded write가 한도에서 실패.
- **실패:** mount가 없거나 다른 경로 쓰기 성공, 제한 초과.
- **증거/환경:** mount table, inspect `Tmpfs`, 제한된 write status; Linux tmpfs/cgroup memory.
- **현재:** 로컬 해당 mount 강제 확인; Ubuntu `NOT_TESTED`.

### 8) CPU 제한

- **목적:** worker가 지정 CPU quota를 넘지 않음.
- **시험/기대:** main worker inspect/cgroup `cpu.max`가 1 CPU; 짧고 bounded한 별도 probe에서 throttling counter 증가.
- **실패:** quota absent 또는 probe에서 kernel limit이 적용되지 않음.
- **증거/환경:** inspect, cgroup `cpu.max` 및 before/after throttling counters; scheduler/cgroup v2.
- **현재:** 로컬 `ENFORCED`; Ubuntu `NOT_TESTED`.

### 9) Memory/Swap

- **목적:** resident limit 512 MiB, 추가 swap 0.
- **시험/기대:** inspect Memory/MemorySwap 각각 536870912; cgroup `memory.max=536870912`, `memory.swap.max=0`; 고위험 stress 없이 확인.
- **실패:** swap limit unsupported/warning, cgroup value 불일치 또는 unreadable.
- **증거/환경:** Docker info/inspect 및 cgroup v2 readback; kernel swap controller.
- **현재:** 로컬 `ENFORCED`; Ubuntu `NOT_TESTED`.

### 10) PID 제한

- **목적:** main worker pids 32 상한 및 runtime enforcement.
- **시험/기대:** worker `pids.max=32`; 별도 disposable probe에서 작은 PID cap으로 bounded child spawn이 `EAGAIN`으로 중지.
- **실패:** pids controller 누락, limit 미적용 또는 불필요하게 많은 child 생성.
- **증거/환경:** inspect/cgroup `pids.max`, `pids.events`; cgroup v2.
- **현재:** 로컬 bounded probe 및 32 설정 확인; Ubuntu `NOT_TESTED`.

### 11) Git safe.directory 보호

- **목적:** Semgrep Docker 초기화가 wildcard trust를 추가하지 않음.
- **시험/기대:** `SEMGREP_IN_DOCKER` process environment 부재; 실제 scan 전후 system/global `safe.directory` 확인; `*` 미포함; `.gitconfig` digest 불변.
- **실패:** wildcard 발견/추가, 설정 상태 확인 실패, 실제 사용자 저장소 접근.
- **증거/환경:** 동일 container의 before/after 최소 probe; image entrypoint/env behavior.
- **현재:** 로컬 scan 전후 확인; Ubuntu `NOT_TESTED`.

### 12) Semgrep 버전

- **목적:** 대상 worker가 정확히 OSS `1.182.1` 실행.
- **시험/기대:** 내부 `semgrep --version`이 `1.182.1`, offline/version-check 설정 적용.
- **실패:** 다른 버전, 비정상 종료, 외부 telemetry/version check 시도.
- **증거/환경:** version 문자열/exit 요약; pinned image digest.
- **현재:** 로컬 확인; Ubuntu `NOT_TESTED`.

### 13) 합성 Finding

- **목적:** 규칙, scanner, output parser 경로가 무해한 fixture를 정확히 확인.
- **시험/기대:** local test-only rule 1개, Python fixture 1개(컨테이너 시작 전 `docker cp`, bind mount 없음), 코드 실행 없이 예상 Finding 정확히 1건; JSON 유효·errors 0.
- **실패:** 0/복수 Finding, 잘못된 rule ID/위치, invalid JSON, timeout.
- **증거/환경:** 메모리에서 raw JSON 검증 후 count/rule ID/relative location만 로그; trusted local fixture/rule 및 bind mount 없는 사전 복사 경로.
- **현재:** 로컬 1 Finding, exit 0; Ubuntu `NOT_TESTED`.

### 14) Timeout 및 Cleanup

- **목적:** timeout/failure/cancel 후 worker와 자원을 정리.
- **시험/기대:** Semgrep 60초 제한, 별도 bounded helper timeout; exact-name container 종료/removal, child process 없음, temp files cleanup; `always()` best effort.
- **실패:** timeout 초과, container/temp fixture 잔존, 다른 Docker 리소스 정리/변경.
- **증거/환경:** start/end/exit/OOM state, `docker inspect/ps/top`, cleanup exit; runner signal/cancel handling.
- **현재:** 로컬 timeout 및 container cleanup 시험 이력; Ubuntu `NOT_TESTED`.

### 15) Privacy canary

- **목적:** fixture marker 외 비밀값이 없고 코드/경로가 로그·artifact에 노출되지 않음.
- **시험/기대:** synthetic marker가 raw scan 내부 결과 외 wrapper/log summary에 없음; host credential/environment wholesale 전달 안 됨; artifacts 0.
- **실패:** canary/source excerpt/absolute path/secret/raw JSON이 logs, outputs 또는 artifact에 노출.
- **증거/환경:** sanitized log 검사, container env allowlist 요약, artifact count; GitHub log visibility/retention.
- **현재:** 로컬 canary 및 log 검사, API contract는 미시험; Ubuntu `NOT_TESTED`.

### 별도 Gate — 직접 시험하지 않는 범위

- Host FastAPI에 대한 실제 접근 차단은 기존 7C-0Y-R에서 **`NOT_TESTED`**다. CI synthetic Docker probe를 이것의 PASS로 기록하지 않는다.
- 이미지 signature/provenance/trust root **`UNVERIFIED`**. 위 15개 검사와 독립적인 사전조건이며 해결되지 않으면 image pull/run 금지.
- GitHub SSRF, redirects/socket peer, archive traversal/extraction, commit/tree/blob 동일성, 다운로드 workspace lifecycle은 이후 7C intake 구현 전 별도 승인 Gate다.

## 7. CI 활성화 전 체크리스트

1. Semgrep 공식 signer identity/issuer/trust root와 정확한 ARM64 digest를 연결한 검증 가능한 signature/provenance evidence를 확보하거나, 별도 C 잔여 위험 예외를 책임자가 명시 승인.
2. verifier/tool version, identity, subject digest, transparency log 및 SBOM validation 정책을 별도 리뷰하고 `--skip-tlog` 금지.
3. Ubuntu ARM64 runner runtime probe로 Docker daemon, actual ARM64, cgroup v2, seccomp, memory+swap, tmpfs, network namespace 등 필수 기능을 확인. 하나라도 `NOT_TESTED`/`NOT_VERIFIED`면 Docker run 차단.
4. CI workflow는 별도 Phase에서 승인 후 추가; 현재 `.github/workflows/`에는 초안 복사/활성화 금지. `workflow_dispatch` on default branch, job disabled-until-approved, no secrets/no `GITHUB_TOKEN` permissions.
5. pull은 trust gate 통과 후 한 번만, exact ARM64 digest/`--platform=linux/arm64`; Docker Hub 429, digest mismatch, platform mismatch는 fail closed.
6. fixture/rule과 wrapper를 검토하고 output/timeout/cleanup fail paths를 테스트; raw JSON/log/artifact는 보존하지 않음.
7. 첫 실행은 synthetic-only, manual-only, no artifact, no external source; 결과를 검토한 후에만 CI gate 통과 여부 판단.
8. Host API direct integration, supply-chain trust 및 GitHub Intake archive/commit identity는 각각 독립 gate로 남김.

## 8. 정적 검증 결과 및 범위

- 기존 `.github/workflows/ci.yml`은 읽기만 했고 변경하지 않았다.
- ARM64 manifest digest와 multiarch index digest를 분리해 기록했다.
- 신규 CI 초안은 `.github/workflows/` 바깥의 `.txt` 파일이며 `workflow_dispatch`만 기재하고 `if: false`와 고정 실패 trust gate를 둔다.
- YAML syntax, image digest, 보안 옵션, workflow trigger/permissions, link 및 문서 변경범위를 별도 검사한다.
- 실제 workflow dispatch, image pull/run, Docker build, 외부 저장소 접근은 수행하지 않는다.
- production 코드/API/Finding/Evidence/dependencies는 변경하지 않는다. 전체 회귀 테스트는 실행하지 않았다 (`NOT_TESTED`).

## 최종 판정

**`PHASE_7C_0Z_CI_DESIGN_READY`** — Ubuntu ARM64 runner 선택, 테스트 계약, trust gate, 보안 설계, disabled draft와 별도 실행 승인 조건을 정의했다. 이는 Ubuntu 검증 성공이나 신뢰되지 않은 이미지를 실행할 권한이 아니다. 현재 image pull/run 및 GitHub Intake는 공급망 검증 또는 별도 위험 예외 승인이 있을 때까지 차단 상태다.
