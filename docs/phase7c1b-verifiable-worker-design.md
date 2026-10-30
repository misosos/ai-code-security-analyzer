# Phase 7C-1B — 검증 가능한 Semgrep Worker 이미지 설계

## 판정

**`PHASE_7C_1B_WORKER_DESIGN_READY`** — 다음 단계에서 검증을 시작할 수 있는 설계 후보와 fail-closed 조건을 정했다. 이는 Base Image나 wheel의 실제 다운로드·검증, Worker 빌드, 서명, 실행 또는 Ubuntu 격리 통과를 뜻하지 않는다. 실제 이미지 신뢰 및 호환성은 모두 후속 단계 Gate로 남는다.

기존 `semgrep/semgrep` 이미지의 공급망 상태는 계속 `UNVERIFIED`다. 기존 이미지를 신뢰하기 위해 검증을 생략하는 대신, PyPI wheel과 서명/provenance 정책이 공개된 Base Image를 입력으로 삼는 별도 Worker 설계를 선택했다.

## 1. 시작 Gate 및 범위

- 저장소: `misosos/ai-code-security-analyzer`, branch `main`.
- 직전 로컬 커밋, `origin/main`, GitHub `main`: `007cacbf7f3246fd4a85433f9d98122b46bee1d1`.
- 시작 working tree clean; ahead/behind `0/0`.
- 정확한 SHA의 [GitHub Actions Run 41033603835](https://github.com/misosos/ai-code-security-analyzer/actions/runs/41033603835): `push / completed / success`; Python, Semgrep 1.182.1 integration, React 및 Chromium E2E 필수 job 성공.
- 기존 Phase 7C 격리 증거 원장과 Ubuntu CI 준비 문서는 보존했다.
- 이번 작업은 문서 설계 및 공식 자료 조사만 수행했다. Docker pull/build/run, CI 활성화, API/UI 변경, GitHub 저장소 수집은 하지 않았다.

기존 로컬 검증에서는 지정 이미지에서 Semgrep OSS 1.182.1과 합성 scan이 동작했지만 이는 로컬 Docker Desktop 검증이다. 이미지 서명·provenance와 승인 trust root는 `UNVERIFIED`; Ubuntu 격리는 `NOT_TESTED`; Remote Intake는 `NOT_APPROVED`다.

## 2. PyPI ARM64 wheel 평가

PyPI는 Semgrep 1.182.1용 `manylinux_2_34_aarch64` wheel을 공개하며 CPython/Python 3.12 호환 태그를 표시한다. 파일 크기는 약 73.9 MB이고 공개 SHA-256은 `3fdfbd68ac5eeead60983dbcd539428bbc40d01f805e0569301068d06be7eaa3`이다. wheel 태그가 요구하는 ABI는 glibc 2.34 이상이다. 이 메타데이터는 호환성 후보를 고를 근거이지, 현재 Base Image에서 실행 가능하다는 실측 결과가 아니다. [PyPI ARM64 wheel 파일과 checksum](https://pypi.org/project/semgrep/1.182.1/)

PyPI 파일 상세에는 해당 wheel의 **PyPI Publish Attestation**이 표시된다. 페이지상 publisher workflow는 GitHub Actions, 저장소는 `semgrep/semgrep-proprietary`, commit은 `4d7c7d9541cb34804ff75fd47d0e466aa27d762b`, workflow는 `pro-release.yml`이며, attestation subject는 해당 wheel과 그 SHA-256이다. 이 artifact별 attestation은 게시가 설정된 Trusted Publisher에서 왔다는 연결을 검증할 수 있는 후보 증거다. 하지만 이 Phase에서 wheel 또는 attestation을 내려받아 암호학적으로 검증하지 않았고, 조직이 그 publisher identity를 승인한 것도 아니다.

**PyPI Publish Attestation ≠ SLSA Build Provenance.** PyPI 문서는 Publish attestation이 특정 publisher/workflow에 의한 파일 게시를 증명하고, SLSA provenance는 빌드 플랫폼·입력·빌드 지침 등 artifact 생성 근거를 설명하는 별도 predicate라고 구분한다. 조사한 1.182.1 ARM64 wheel 페이지에서 확인한 유형은 PyPI Publish Attestation이다. 이를 소스부터 wheel까지의 완전한 build provenance로 부르지 않는다. PyPI release의 sdist에는 provenance가 없으므로 sdist를 빌드 입력으로 사용하는 경로는 금지한다. [PyPI attestation 유형](https://docs.pypi.org/attestations/), [PyPI attestation 소비 및 검증](https://docs.pypi.org/attestations/consuming-attestations/)

후속 wheel 승인 순서:

1. `pypi-attestations` 또는 동등한 검증기로 PyPI Integrity API의 해당 ARM64 wheel attestation을 암호학적으로 검증한다.
2. 실제 artifact SHA-256이 사전 승인된 lock 값과 정확히 일치하는지 검사한다.
3. publisher repository/workflow identity가 Semgrep의 공식 배포 주체인지 별도로 확인하고 조직 정책으로 승인한다.
4. attestation이 게시 경로만 입증하는지, SLSA build provenance도 있는지 predicate별로 구분한다.
5. 같은 검증을 전체 전이 의존성에 적용할 수 있는지 확인한다. 불가능한 파일/해시/검증 결과가 있으면 설치 및 빌드를 중단한다.

검증 경로 자체는 PyPI 문서에 나와 있지만, 이번에는 실제 파일을 받거나 검증하지 않았다. wheel에 포함된 Semgrep 실행 파일, 라이선스 고지 및 최종 컨테이너에서 실행되는 CLI가 해당 wheel과 일치하는지도 후속 단계에서 확인해야 한다. PyPI project는 `LGPL-2.1-or-later`를 표시한다. 전체 의존성 라이선스 목록과 고지 파일은 아직 감사하지 않았으며, 이를 빌드 승인 Gate로 둔다. [Semgrep PyPI 라이선스·파일 정보](https://pypi.org/project/semgrep/1.182.1/)

## 3. Base Image 후보와 신뢰 정책

| 후보 | 런타임 및 아키텍처 | 공급망 근거 | 접근·크기·한계 | 설계 판단 |
|---|---|---|---|---|
| **Chainguard Python 3.12 minimal runtime** (`cgr.dev/chainguard/python`) | 공식 directory는 Python 3.12.15, ARM64 지원을 표시한다. 이미지 설명은 Wolfi 기반 Python runtime, 기본 nonroot 사용자, 최소 runtime variant를 안내한다. Chainguard는 glibc 기반이라고 설명한다. | Python 이미지 페이지는 Free Containers의 signer를 `https://github.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main`, issuer를 `https://token.actions.githubusercontent.com`으로 검증하는 Cosign 절차를 공개한다. 이미지별 SLSA provenance, apko config, SPDX SBOM predicate도 제공한다고 설명한다. | 3.12 태그는 현재 `Contact us` 접근으로 표시되며, directory 압축 크기는 24.75 MB다. 태그·digest는 변할 수 있고, 정확한 ARM64 digest·glibc 버전·wheel 호환성은 미확인이다. | **조건부 우선 후보.** 구체적인 identity/issuer 검증 경로가 공개되어 있으나 조직이 실제 3.12 artifact를 얻고 digest/attestation을 검증·승인해야 한다. 접근이 불가하거나 정책이 맞지 않으면 HOLD. |
| **Docker Official Python 3.12 slim Bookworm** | 공식 이미지 manifest는 ARM64를 포함하고 Python 3.12 Bookworm 변형을 제공한다. Debian Bookworm의 glibc가 wheel 최소 요건을 만족하는지는 이미지의 실제 패키지로 확인해야 한다. | Docker Official Image 배포 및 소스 관리 자료는 확인 가능하지만, 이번 조사에서 이 base의 특정 digest에 대한 승인 가능한 Cosign signer identity/issuer와 서명된 provenance 검증 정책은 확립하지 못했다. | 공개 접근과 생태계 성숙도가 장점이나, 공식 이미지라는 명칭만으로 artifact signature/provenance가 성립하지 않는다. 정확한 digest 및 크기 미확인. | 호환성 비교용 후보. 조직 정책이 cryptographic signature/provenance를 요구하는 한 검증 전 선택할 수 없다. |
| **Python Alpine 3.12** | ARM64와 musl 지원. PyPI에는 ARM64 `musllinux_1_2_aarch64` Semgrep wheel 후보도 표시된다. | 이번 조사에서 특정 Alpine Python digest에 대한 승인된 image signature/provenance identity를 정하지 못했다. | musl 전용 wheel 및 C 라이브러리 호환성 검증이 필요하며, glibc wheel 경로보다 런타임 차이를 더 크게 검증해야 한다. | 서명 검증 경로가 확보되지 않아 우선 선택하지 않는다. |

Chainguard Python의 공개 자료는 Python 3.12 ARM64 변형, glibc 기반 이미지, nonroot 기본 사용자 및 서명 검증 예시를 설명한다. 공개 directory는 특정 3.12 tag의 가격/접근 제약과 이미지 크기도 표시한다. 고정 digest는 실제 접근 승인을 받고 ARM64 manifest를 선택한 뒤 기록해야 하며, 여기서는 추측하거나 사용 가능한 것으로 가정하지 않는다. [Chainguard Python 버전/아키텍처](https://images.chainguard.dev/directory/image/python/versions), [Python 이미지 개요](https://images.chainguard.dev/directory/image/python/overview), [Python 이미지 signature/provenance 검증](https://images.chainguard.dev/directory/image/python/provenance)

Chainguard 문서의 일반 검증 예시는 서명 identity와 issuer를 명시하고 SBOM/provenance attestation을 별도로 검증한다. 후속 단계에서는 문서의 예시를 그대로 복사해 PASS 처리하지 않고, 승인한 ARM64 digest를 명시하고 attestation subject digest, predicate 유형, 인증서 identity/issuer, Rekor 증거를 독립 검사한다. 태그 이동을 허용하지 않는다.

Semgrep wheel의 glibc 요구사항과 후보 base의 실제 libc는 별도 Gate다. Chainguard Python이 glibc 기반이라는 일반 설명만으로 현재 3.12 ARM64 artifact의 glibc 버전과 Semgrep wheel ABI 호환성을 확정하지 않는다. 실행 전 SBOM/apko metadata로 libc 및 Python 빌드 정보를 확인하고, 승인된 synthetic fixture에서 import/version/scan을 검증한다. [Chainguard glibc와 musl 설명](https://edu.chainguard.dev/chainguard/containers/concepts/glibc-vs-musl/)

### Base Image 승인 정책

- image index와 ARM64 child manifest digest를 각각 기록한다. 빌드 및 최종 검증은 명시한 플랫폼 child digest를 고정한다.
- Base Image 서명은 승인된 identity와 issuer를 함께 검증한다. Chainguard 후보의 문서상 값은 후보 정책이며, 적용 전 조직 승인과 exact digest 검증이 필요하다.
- SLSA provenance 및 SBOM의 `subject` digest가 선택한 이미지 artifact와 일치해야 한다.
- 예상 identity/issuer/subject 불일치, transparency 검증 실패, 서명 누락, base tag 접근 불가, OS/libc 미확인은 fail closed 처리한다.
- 검증 결과는 검증 당시 digest와 trust root 상태를 함께 기록한다. 단순 DVP/Official Image 배지나 digest pinning만으로는 통과하지 않는다.

## 4. 전체 Dependency 공급망 정책

Semgrep wheel 하나의 SHA를 확인하는 것으로 최종 Worker를 승인하지 않는다. Semgrep 1.182.1 및 전이 의존성 전체를 target `linux/aarch64`, CPython 3.12용으로 잠근다.

1. Resolver 버전과 입력 파일을 고정하고 dependency graph를 version control에서 검토 가능한 lock으로 보존한다.
2. lock은 모든 direct/transitive 배포 artifact의 정확한 버전, source, filename/platform tag 및 SHA-256을 가져야 한다. lock 파일 변경은 리뷰를 요구한다.
3. Semgrep ARM64 wheel의 hash와 attestation identity를 별도 검증한다. Semgrep sdist는 provenance가 없으므로 금지한다.
4. 전이 의존성은 wheel-only로 제한한다. 승인된 package source 외 URL/VCS/extra index를 거부하며, 임의 index fallback을 허용하지 않는다.
5. build에 사용할 wheelhouse를 먼저 검증된 acquisition 절차에서 수집한다. 컨테이너 이미지 빌드 단계는 외부 네트워크 없이 local wheelhouse만 사용한다.
6. 설치는 전 의존성 해시 검사와 binary-only를 강제한다. pip 설계 예시는 `--require-hashes --only-binary=:all: --no-index --find-links=/wheelhouse`이며, requirements lock에 전이 의존성이 모두 해시와 함께 있어야 한다. uv를 선택할 경우도 lock 일치, offline, source build 금지를 동시에 확인한다. 두 설치기를 함께 느슨하게 fallback하지 않는다.
7. 해시 없는 의존성, sdist fallback, 동적 version, Git URL, 임의 setup/build 도구 실행, 알 수 없는 패키지 저장소가 하나라도 발견되면 build를 거부한다.
8. 패키지 provenance는 파일별로 검증한다. PyPI에 provenance가 없는 파일은 checksum pin만으로 publisher identity 증명이 됐다고 하지 않는다. 사전 신뢰된 lock으로 무결성만 확인하는 제한을 명시하고, 조직의 공급망 정책이 이를 허용하지 않으면 HOLD한다.
9. 라이선스를 전체 dependency graph 기준으로 수집하고 허용 정책·필수 notices를 이미지에 포함한다. 미승인 license 또는 누락 notice는 build gate 실패다.
10. 자동 업데이트 금지. 새 버전은 새 review/change, 새 artifact hash, 새 provenance 검토 및 새 이미지 digest로 갱신한다.

PyPI는 파일별 attestation과 checksum을 연결하고, `pypi-attestations`로 repository identity와 artifact를 cryptographically verify하는 절차를 제공한다. 해당 검증 도구는 acquisition job의 검증된 버전으로 고정해야 하며, 설치 시점의 기본 pip가 provenance를 자동 검증한다고 가정하지 않는다. [PyPI artifact attestation 검증](https://docs.pypi.org/attestations/consuming-attestations/)

## 5. 비실행 Worker Dockerfile 설계

아래는 구조 설명용 의사 설계이며 실제 빌드 가능한 Dockerfile이 아니다. digest 자리표시자는 차후 승인된 조사에서 확인할 값이다. 이번 단계에서 Dockerfile 파일, 이미지 또는 CI workflow를 만들지 않는다.

```dockerfile
# Build stage: exact approved Chainguard Python 3.12 dev ARM64 digest
FROM cgr.dev/chainguard/python:3.12-dev@sha256:<APPROVED_BUILD_DIGEST> AS assemble
COPY verified-wheelhouse/ /wheelhouse/
COPY requirements.lock /inputs/requirements.lock
# Install offline, hash-required, wheel-only into a venv.
# No network, VCS sources, sdist, or unpinned build backend.

# Runtime stage: exact approved matching Python 3.12 minimal ARM64 digest
FROM cgr.dev/chainguard/python:3.12@sha256:<APPROVED_RUNTIME_DIGEST> AS worker
COPY --from=assemble --chown=<nonroot>:<nonroot> /venv /opt/semgrep-venv
COPY --chown=<nonroot>:<nonroot> worker-entrypoint.py /usr/local/bin/worker-entrypoint.py
USER <fixed-nonroot-uid>:<fixed-nonroot-gid>
ENTRYPOINT ["/usr/bin/python", "/usr/local/bin/worker-entrypoint.py"]
```

설계 조건:

- build stage와 analysis runtime은 분리한다. package acquisition에서 허용할 네트워크와 분석 컨테이너의 `--network=none`은 다른 권한 경계다. 빌드는 검증된 로컬 wheelhouse 및 미리 승인된 Base Image 외 입력을 사용하지 않도록 network-disabled build를 우선한다.
- builder는 `python:3.12-dev`에 포함된 설치 도구를 사용하더라도 그 builder image digest와 도구 SBOM/provenance를 먼저 검증한다. 최종 runtime에는 shell, pip, apk, compiler, curl, package manager를 복사하지 않는다. Semgrep의 실제 필수 동작을 확인한 뒤 Git이 필요 없으면 제외하고, 필요하면 검증된 최소 Git package를 포함해 safe.directory 동작을 별도로 검증한다.
- 두 Python base variant 간 ABI/Python patch 호환성을 확인하기 전 venv 복사를 승인하지 않는다. 호환성 불확실 시 runtime digest 하나에서 같은 Python으로 설치한 후 불필요한 도구/캐시를 제거하는 재현 가능한 대안을 비교하되 root build 권한 범위를 최소화한다.
- Semgrep distribution, Python entry points, wheel payload, license/notice, transitive package 파일만 복사한다. Semgrep의 Python package에 포함된 CLI/OCaml binaries와 필요한 공유 라이브러리를 SBOM/동적 의존성으로 확인한다. 불필요한 파일을 임의로 제거해 기능을 가정하지 않는다.
- 최종 이미지 기본 USER는 고정된 비관리자 UID/GID. 실행 시에도 `--user`를 명시한다. 실제 uid/gid는 승인된 이미지에서 검증한다.
- Wrapper는 고정된 신뢰 코드로만 제공한다. `SEMGREP_IN_DOCKER`를 공백 값으로 두지 말고 process environment에서 key 자체를 제거한다. 예컨대 Python wrapper가 allowlist 환경을 구성하고 `os.execve`로 고정된 Semgrep 실행 파일을 실행할 수 있다. 이 방식은 runtime policy/entrypoint 검증 대상이며, 환경변수 조작만으로 `safe.directory=*` 방지가 증명되지는 않는다.
- Docker image 설정 또는 runtime command로 분석 대상 경로를 유일한 positional input으로 명시하고, Git 설정 파일을 추가·변경하지 않는다. Scan 전후 Git global/system config 확인은 격리된 테스트에서 별도로 수행한다.
- 개인 홈, credential, token, Git config, 사용자의 프로젝트 및 Docker socket을 이미지에 넣지 않는다. 분석 작업 디렉터리와 `/tmp`, `/home/semgrep/.semgrep`만 필요 최소 크기 tmpfs로 runtime에 제공한다.

## 6. Runtime Security Contract

후속 worker 검증은 기존 Phase 7C 계약을 그대로 적용한다.

- `--read-only`, `--network=none`, `--cap-drop=ALL`, `no-new-privileges`, 고정 비관리자 UID/GID.
- CPU, memory, memory-swap, PID, tmpfs quota를 설정값과 cgroup/실제 bounded probe로 각각 확인.
- 합성 fixture만 read-only bind mount; 출력은 분리된 허용 디렉터리만.
- Docker socket, Host home, 실제 사용자 프로젝트, credential 및 불필요한 host 환경변수 미전달.
- 실행 60초 상한, stdout/stderr 2 MiB 상한 및 전용 container cleanup.
- version check/metrics는 승인된 명시적 환경으로 끄되, network=none 유지. 여기서 remote access를 금지하는 것은 해당 설정만으로 보장하지 않는다.
- Semgrep이 `SEMGREP_IN_DOCKER`의 존재로 Docker 안전 디렉터리를 설정하는 경로를 후속 버전의 실제 코드 또는 동작으로 검토한다. variable key 부재를 inspect하고, 합성 입력으로 scan 전후 Git config에 wildcard trust가 없는지 시험한다.
- 환경변수 누락, wildcard safe.directory, 쓰기 경계 이탈, egress, resource cap 미강제, cleanup/privacy 실패 시 scan/CI를 중단한다.

로컬 Phase 7C 증거는 이전 로컬 runtime 한정으로 보존한다. 새 자체 Worker image가 똑같이 격리를 강제한다는 의미는 아니며, 모든 Runtime Security Contract를 새 digest와 Ubuntu ARM64에서 재검증한다.

## 7. Build provenance, SBOM, image signing

Worker image의 승인 기준은 다음 자료가 선택한 **최종 ARM64 digest**를 subject로 연결해야 한다.

- Build materials: Base Image index/child digest, Semgrep wheel URL/filename/SHA-256/PyPI attestation 검증 결과, 전체 의존성 lock/hash, 빌드 도구와 version, Dockerfile 및 build scripts hash, build context manifest.
- Source identity: 저장소와 정확한 Git commit, 허용된 build workflow 경로/commit, build trigger, builder identity.
- Build execution: protected GitHub Actions workflow, 최소 permissions, secrets 미노출, pinned Actions commit, untrusted PR 코드에서 발동 금지, 재현 가능한 고정 입력.
- SBOM: 최종 image digest를 subject로 하는 SPDX 또는 CycloneDX SBOM. base, OS package, Python wheel 및 bundled binary를 포함하고 라이선스/notice까지 검토한다.
- Provenance: SLSA provenance에 final subject digest와 materials/build definition/workflow identity를 포함한다. PyPI Publish attestation을 build provenance 대신 사용하지 않는다.
- Image signature: 승인된 organization-owned GitHub Actions workflow가 Sigstore keyless로 digest를 서명. Issuer는 `https://token.actions.githubusercontent.com`; certificate identity는 추후 고정할 전용 protected workflow identity여야 한다. identity를 넓은 regexp로 풀지 않는다.
- Verification: signature와 attestation 각각에서 exact subject digest, issuer, identity, transparency-log inclusion/proof, predicate, source commit, workflow 및 materials를 검사한다. Base/Wheel이 승인됐어도 최종 image 서명/attestation 검증이 실패하면 차단한다.
- Key custody: private signing key를 repository secret로 수동 보관하지 않는 keyless 설계를 사용하되, GitHub OIDC permission 최소화 및 release workflow 보호를 선행한다. 서명 생성 주체와 검증 정책을 독립 리뷰한다.

자체 서명은 “우리 승인 workflow가 이 digest를 냈다”는 걸 증명하도록 설계할 수 있지만 Base Image, PyPI package, runner 및 workflow 자체의 무결성까지 자동 증명하지 않는다. 이전 materials 검증과 별도 역할에 의한 최종 attestation 검증이 필요하다. Sigstore는 keyless verification에 certificate identity와 issuer 명시를 요구하고 digest claim도 검증한다. [Cosign 검증 설명](https://docs.sigstore.dev/cosign/verifying/verify/)

## 8. Ubuntu ARM64 검증 계획

실제 실행은 별도 Phase의 명시 승인 후에만 한다.

1. Chainguard 3.12 ARM64 runtime/build digests의 서명, issuer, provenance, SBOM, subject를 검증한다. 실제 접근권한이 없거나 identity 정책과 다르면 HOLD.
2. Semgrep manylinux ARM64 wheel의 PyPI attestation과 SHA를 검증하고, Semgrep 배포 workflow identity를 승인한다. 모든 전이 의존성 wheel을 exact hash로 확보하며 sdist를 거부한다.
3. lock, wheelhouse, base digests, source commit 및 build tools를 봉인된 입력 manifest로 고정한 뒤, 별도 builder에서 network-disabled build를 수행한다.
4. 최종 image의 SBOM/provenance 생성, image digest 서명 및 그 서명·attestation 독립 검증.
5. image 내부에서 Python 3.12와 실제 Semgrep 1.182.1을 확인하고, 알려진 wheel checksum/attestation 및 base의 glibc ABI와 연결한다.
6. 신뢰된 local rule 1개 및 합성 코드 1개로 기대 Finding을 재현한다. 사용자/Remote repository 코드는 금지.
7. `SEMGREP_IN_DOCKER` 부재 및 scan 전후 Git wildcard safe.directory 부재를 검증한다.
8. Runtime Security Contract의 network, filesystem, CPU/memory/swap/PID/tmpfs, timeout, child-process cleanup, privacy canary 통제를 실제로 재검증한다.
9. Ubuntu `ubuntu-24.04-arm`에서 cgroup v2, Docker architecture, seccomp, quota 강제 및 cleanup을 다시 확인한다. 이는 macOS 로컬 증거와 별개다.
10. 모든 단계의 결과와 exact digest를 문서화한다. 실패 시 다음 단계로 진행하지 않고 image trust/worker 실행을 HOLD한다.

CI job은 향후 별도 최소 권한 수동 실행 workflow로 설계한다. 이번 Phase는 workflow를 생성하거나 활성화하지 않는다. 테스트 대상 코드를 실행하는 job에는 repository secrets와 불필요한 `GITHUB_TOKEN` 권한을 제공하지 않는다.

## 9. 금지 및 HOLD 조건

다음 조건은 설계 통과 이후 실제 실행 단계에서 하나라도 충족되면 fail closed다.

- Base Image exact ARM64 digest의 서명, identity/issuer, provenance 또는 subject 검증 실패.
- Base Image 3.12 접근 불가, 필요한 runtime digest를 pin할 수 없음, glibc/Python ABI 호환성 불명.
- PyPI wheel attestation identity 미승인, checksum 불일치, Semgrep sdist 또는 dependency sdist fallback.
- 모든 전이 dependency artifact version/hash/source/license를 lock·검증할 수 없음.
- installer가 전체 해시 검증을 강제하지 못하거나 network/source fallback이 남음.
- final SBOM/provenance subject가 최종 digest와 불일치하거나 승인 signer/issuer/transparency proof 부재.
- Git wildcard trust가 생성됨, network/filesystem/resource isolation 미강제, 실행·정리·privacy 검증 실패.
- Ubuntu ARM64 필수 격리 조건의 실증 실패.

금지 사항은 기존 Semgrep OSS 이미지의 신뢰 상태를 고치는 것처럼 보이게 하거나, test 통과를 공급망 검증으로 대체하지 못하게 한다. GitHub Remote Intake는 이번 판정으로 승인되지 않는다.

## 10. 실제 빌드 전 승인 조건

다음 Phase에서 제한 빌드 또는 artifact download를 시작하기 전 사용자는 별도로 다음을 승인해야 한다.

1. Base Image 공급자, 제품/접근권, 정확한 ARM64 index/child digest 검증 및 라이선스·유지보수 정책.
2. Semgrep 1.182.1 ARM64 wheel과 전체 dependency wheel을 다운로드할 승인 source, PyPI identity, hash lock 및 provenance 정책.
3. Build workflow, GitHub permissions, 네트워크 허용 범위, 이미지 registry, 서명 주체와 trust policy.
4. 빌드/서명 CI 실행, artifact·SBOM 보관 정책 및 실패 시 보존/정리 방식.
5. Ubuntu ARM64 runner의 비용·리소스·실행 제한과 synthetic-only 테스트 범위.

승인 전에는 이미지 pull, package download, build, run, attestation 생성 또는 workflow 활성화를 하지 않는다.

## 11. 검증 및 변경 파일

- 공식 출처와 PyPI wheel 파일 metadata, checksum, platform tag, publisher attestation 표시 및 Chainguard image signing/provenance 안내를 확인했다.
- 라이선스: Semgrep PyPI project의 LGPL-2.1-or-later 표기를 확인했다. 전체 dependency licenses/notice는 `NOT_TESTED`이며 다음 단계 build gate다.
- Base Image exact digest/attestation, wheel의 local cryptographic verification, dependency resolution/hash lock, Dockerfile build, Python/glibc ABI 및 Semgrep scan은 모두 `NOT_TESTED`다.
- 실제 이미지 pull/build/run, CI activation, code/API/UI change는 없었다.
- 이 문서만 변경한다. `git diff --check`, 링크/표현/보안 계약 정적 검토 후 문서만 로컬 커밋한다. Python·Frontend 회귀는 문서 전용이므로 실행하지 않는다 (`NOT_TESTED`).

## 참고 자료

- [Semgrep 1.182.1 PyPI wheel, hash 및 attestation](https://pypi.org/project/semgrep/1.182.1/)
- [PyPI attestation 유형 및 의미](https://docs.pypi.org/attestations/)
- [PyPI attestation 다운로드 및 암호학적 검증 절차](https://docs.pypi.org/attestations/consuming-attestations/)
- [Chainguard Python tag·ARM64 목록](https://images.chainguard.dev/directory/image/python/versions)
- [Chainguard Python runtime·nonroot·variant 설명](https://images.chainguard.dev/directory/image/python/overview)
- [Chainguard Python image signing, SLSA provenance, SBOM 검증](https://images.chainguard.dev/directory/image/python/provenance)
- [Chainguard glibc/musl 설명](https://edu.chainguard.dev/chainguard/containers/concepts/glibc-vs-musl/)
- [Docker Official Python image source](https://github.com/docker-library/official-images/blob/master/library/python)
- [Cosign keyless identity/issuer와 digest 검증](https://docs.sigstore.dev/cosign/verifying/verify/)
- [기존 Phase 7C 격리 증거 원장](phase7c0-isolated-worker-validation.md)
- [Ubuntu ARM64 CI 준비 및 실행 Gate](phase7c0-ubuntu-ci-readiness.md)
