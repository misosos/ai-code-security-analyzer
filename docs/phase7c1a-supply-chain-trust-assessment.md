# Phase 7C-1A — Semgrep 이미지 공급망 신뢰 평가

## 판정

**`PHASE_7C_1A_ALTERNATIVE_REQUIRED`**

이번 조사에서 대상 Docker 이미지에 적용할 Semgrep 공식 서명자 identity, issuer, 승인 trust root 및 이미지 digest를 잇는 검증 가능한 provenance 절차를 확립하지 못했다. 이는 이미지에 서명이나 provenance가 전혀 없다는 뜻은 아니다. 기존 이미지 증거와 공식 공개 자료만으로 신뢰 정책을 정할 수 없다는 뜻이다. 이미지의 운영 사용과 Ubuntu 격리 CI 실행은 승인되지 않는다.

## 1. 범위와 시작 Gate

- 조사 시각: 2026-10-30 UTC.
- 저장소: `misosos/ai-code-security-analyzer`.
- 시작 HEAD, `origin/main`, GitHub `main`: `c05de8ce453b974191fb10b2a1ab3beea65fc7ec`.
- Branch: `main`; 시작 working tree clean; ahead/behind `0/0`.
- 정확한 SHA의 GitHub Actions Run: [41031690074](https://github.com/misosos/ai-code-security-analyzer/actions/runs/41031690074), `push / completed / success`, head SHA가 시작 HEAD와 일치.
- 필수 작업 `Python tests and CLI`, `Semgrep 1.182.1 integration`, `React dashboard` 성공. React 작업에는 typecheck, 테스트, build, Chromium smoke와 실제 Chromium–FastAPI–Semgrep E2E가 포함되어 성공했다.
- 이 작업은 공개 문서 및 기존 기록 조사에 한정했다. Docker 이미지 pull/run/build, GitHub Actions 실행, 원격 저장소 수집, 사용자 프로젝트 검사는 수행하지 않았다.

대상은 `semgrep/semgrep@sha256:cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5`, 플랫폼 `linux/arm64`다. 기존 Phase 7C 증거에서 로컬 digest 일치, Semgrep 1.182.1 실행 및 합성 scan은 검증되어 있다. 그 증거는 Phase 7C-0Y-R의 로컬 Docker Desktop 환경에 한정된다.

## 2. 신뢰 주장별 상태

| 주장 | 상태 | 확인 범위와 제한 |
|---|---|---|
| A. 이미지 digest 동일성 | `VERIFIED` (관찰 범위 한정) | 기존 로컬 이미지의 ARM64 child manifest digest와 Docker Hub의 1.182.1-nonroot 플랫폼 항목이 일치한다고 기록되어 있다. multiarch index는 `sha256:0ed16bbbb23e5bf7c442df9144704d74b54ad2d003094e09905130d642f22473`로 별도 식별된다. digest 일치는 동일 바이트 식별 근거이며 게시자 또는 빌드 출처 인증은 아니다. [Docker Hub tag 목록](https://hub.docker.com/r/semgrep/semgrep/tags?name=1.182.1-nonroot) |
| B. 이미지 서명 | `UNVERIFIED` | 기존 Docker Scout 1.26.0 시도에서 `signature not found in transparency log`가 관찰됐다. 이번 조사에서는 대상 이미지에 대한 서명 검증을 재수행하지 않았다. 서명이 없다고 결론 내릴 수 없다. |
| C. 서명자 identity / issuer / trust root | `UNVERIFIED` | Docker Hub에 Semgrep, Inc. Verified Publisher 표시가 있다. 이는 게시자 표시로 관찰된 사실이며, 대상 digest를 서명한 암호학적 signer identity, OIDC issuer 또는 승인된 trust root를 확인한 사실과 다르다. [Semgrep Docker Hub](https://hub.docker.com/r/semgrep/semgrep) |
| D. Provenance subject와 이미지 digest 관계 | `UNVERIFIED` | 기존 기록에는 SBOM/Provenance attestation 목록이 관찰됐으나, 서명 및 subject digest를 승인된 trust root로 검증하지 않았다. 목록 존재는 대상 이미지와 신뢰된 provenance의 연결 증명이 아니다. |
| E. 빌드 소스 / commit / 버전 관계 | `UNKNOWN` | Docker Hub layer metadata는 image tag 및 실행 결과 1.182.1과 함께 `release-1.182.0`, revision `6f7d77ede012b0301d5051f8f5552530c17210c7`, `github.com/semgrep/semgrep-proprietary`를 표시한다. 이 metadata가 실제 build source를 인증하지 않으므로 차이의 원인은 `UNKNOWN`이다. [ARM64 image layer metadata](https://hub.docker.com/layers/semgrep/semgrep/1.182.1-nonroot/images/sha256-cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5) |
| F. SBOM과 이미지의 관계 | `UNVERIFIED` | 기존 기록상 SBOM 목록이 관찰됐으나 서명, subject digest, 대상 ARM64 manifest에 대한 연결을 검증하지 않았다. 이미지에 포함된 실제 패키지 목록 또는 해당 digest의 완전한 SBOM이라고 승인할 수 없다. |

Docker Hub는 `semgrep/semgrep`를 Semgrep, Inc.의 공식 이미지로 표시하고 Verified Publisher badge를 제공한다. 이것은 배포 주체에 관한 플랫폼 표시다. 이번 조사에서는 이를 이미지 서명으로 간주하거나 별도 이미지 서명 정책과 동일시하지 않았다. [Docker Hub trusted content 설명](https://docs.docker.com/docker-hub/repos/manage/trusted-content/)

## 3. 공식 서명 및 검증 경로 조사

Semgrep 공식 문서·저장소 및 Docker Hub 공개 자료에서 이 digest에 적용할 서명 공개 키 또는 keyless `certificate identity`와 `OIDC issuer`를 명시한 검증 지침을 찾지 못했다. 공개 Semgrep 저장소의 [release-1.182.0 Dockerfile](https://github.com/semgrep/semgrep/blob/release-1.182.0/Dockerfile)과 [Docker build/test workflow](https://github.com/semgrep/semgrep/blob/release-1.182.0/.github/workflows/build-test-docker.jsonnet)는 확인했지만, 이들은 대상 image digest의 서명 또는 빌드 provenance를 입증하지 않는다. Docker Hub layer metadata가 별도 `semgrep-proprietary` VCS source를 표시하므로 공개 저장소 파일만으로 대상 image build를 연결할 수도 없다. 따라서 값을 추측하거나 임의로 trust root에 등록하지 않았다. 이 결과는 공개 자료 조사 범위의 부재이며, 서명 자체의 부재를 입증하지 않는다.

Sigstore/Cosign 일반 검증 모델은 keyless 서명에 대해 예상 certificate identity와 OIDC issuer를 검증 입력으로 요구한다. Cosign은 서명 claim의 이미지 digest도 기본 검증한다. Attestation은 별도 `verify-attestation` 경로로 검증한다. 이 절차는 검증 방법의 기준이지, Semgrep의 identity/issuer 값을 알려주지 않는다. [Cosign signature verification](https://docs.sigstore.dev/cosign/verifying/verify/) 및 [Sigstore OIDC verification cheat sheet](https://docs.sigstore.dev/quickstart/verification-cheat-sheet/)

Docker Hub image tag 자료에서 1.182.1 tag의 multiarch index와 ARM64 child digest가 별개임을 확인할 수 있다. 서명 및 attestation 검증 때 index를 확인할지 ARM64 child manifest를 확인할지 먼저 정책으로 정하고, 다운로드·검증 도구가 실제 어떤 subject를 검증하는지 명시해야 한다. 어느 digest에 대한 서명이 다른 digest도 자동으로 입증한다고 가정하지 않는다.

## 4. Docker Scout 실패 해석

기존 기록은 Docker Scout CLI `1.26.0`에서 `signature not found in transparency log`가 반환됐다고 한다. Docker Scout `attestation get` 공식 CLI 문서의 기본 `--key`는 `https://registry.scout.docker.com/keyring/dhi/latest.pub`이다. 이는 Docker Hardened Images(DHI) 검증 키다. 별도의 Semgrep 키를 제공하지 않은 기존 명령이었다면 기본 검증 정책이 Semgrep 게시용 정책과 맞지 않았을 가능성이 있지만, 실제 실행 인자 원문이 확인되지 않는 한 그 점도 가설이다. [Docker Scout attestation get](https://docs.docker.com/reference/cli/docker/scout/attestation/get/) 및 [DHI attestation verification](https://docs.docker.com/dhi/how-to/verify/)

현재 실패로부터 구분해야 할 가설은 다음과 같으며, 어느 하나도 확정하지 않는다.

- 대상에 서명이 없거나 Rekor transparency log 항목이 없을 수 있다.
- 다른 키 또는 keyless identity를 사용했을 수 있다.
- Scout의 DHI 기본 키가 Semgrep 검증에 맞지 않았을 수 있다.
- 조회 대상과 attestation subject digest가 달랐을 수 있다.
- CLI 버전·attestation 형식·레지스트리 조회 동작이 결과에 영향을 주었을 수 있다.

`--skip-tlog`나 `insecure-ignore-tlog`로 성공을 만들지 않았다. DHI 문서의 로그 생략 절차는 Docker 공개 키로 검증하는 DHI 전용 맥락이며, 그 키를 Semgrep 이미지에 적용하거나 Rekor 증명을 생략하는 근거가 아니다. Scout 실패 하나로 “서명이 없음”, “서명 검증 도구 오류” 또는 “이미지가 위조됨” 중 어느 것도 판정하지 않는다.

## 5. Provenance, 버전 및 SBOM 출처

Docker Hub의 대상 image layer metadata는 tag `1.182.1-nonroot`, ARM64 manifest digest와 함께 VCS ref `release-1.182.0`, commit `6f7d77ede012b0301d5051f8f5552530c17210c7`, repository `github.com/semgrep/semgrep-proprietary`를 표시한다. 이는 registry 페이지가 보여주는 빌드 metadata일 뿐, 서명된 provenance가 해당 값을 검증했다는 증거는 아니다. 실행 버전과 VCS metadata의 차이가 왜 생겼는지, 이 revision이 공개 릴리스 source와 어떤 관계인지 현재 근거로 확정할 수 없다.

Semgrep 1.182.1 PyPI 배포는 별도의 참고 사례다. PyPI는 일부 개별 wheel 파일에 GitHub Actions/PyPI Publish attestation과 publisher repository metadata를 보여주고, release의 일부 파일은 provenance가 없다고 표시한다. 이는 특정 wheel checksum에 대한 증거이지 Docker ARM64 manifest digest에 대한 증거가 아니다. 이 사례를 이미지 provenance의 대체 근거로 사용하지 않는다. [PyPI semgrep 1.182.1 attestations](https://pypi.org/project/semgrep/1.182.1/)

SBOM을 신뢰하려면 최소한 서명된 attestation 또는 신뢰 가능한 검증 경로, 대상 ARM64 manifest 또는 그 상위 index와의 명시적 subject 관계, predicate 유형, 생성 주체 및 도구, 검증 정책이 필요하다. attestation 목록이나 단순 SBOM 다운로드만으로 대상 이미지와의 암호학적 연결은 성립하지 않는다.

## 6. 대안 비교 및 권고

| 방안 | 신뢰 근거 | 재현성 및 SBOM | 비용 / 잔여 위험 | 판정 |
|---|---|---|---|---|
| **A. Semgrep 공식 이미지의 서명·provenance 확보** | Semgrep이 공식적으로 지정한 signer identity 또는 공개 키, issuer, trust root, transparency-log 정책과 정확한 ARM64 digest 및 index 관계를 제공해야 한다. | 검증된 provenance의 source, commit, workflow 및 subject를 확인하고, SBOM도 같은 digest에 연결한다. | 공급자 증거를 기다려야 하나 upstream 이미지의 유지보수 이점을 보존한다. 확인 전에는 image trust가 미완료다. | **최우선 요청 경로.** Semgrep에 image digest별 서명·attestation 검증 자료를 요청한다. |
| **B. 별도 Worker 이미지 구축** | 신뢰된 base image의 digest와 증거, 고정된 Semgrep 배포물·의존성 해시 및 검증된 provenance를 사용하고 조직 자체 서명 identity를 독립적으로 승인한다. | 고정 입력과 빌드 절차를 재현하고 SBOM·빌드 provenance를 생성·서명한다. 가능하면 빌드를 재현해 비교한다. PyPI wheel provenance가 확인되더라도 정확한 선택 artifact를 별도 확인해야 한다. | base image, 패키지 레지스트리, 빌드 시스템과 빌드 계정 위험은 남는다. 운영 유지보수 및 보안 패치 책임이 증가한다. | A가 불가능할 때 설계 후보. 자체 빌드만으로 공급망 위험이 사라진다고 보지 않는다. |
| **C. 기존 digest로 제한 CI 실행** | 현재 확인된 digest 동일성과 로컬 핵심 격리 증거만 사용한다. 서명자/issuer/provenance는 계속 미검증이다. | CI에서 합성 fixture만 실행해도 provenance가 보강되지는 않는다. 로그 최소화와 결과 제한은 실행 위험만 줄인다. | 잔여 공급망 위험을 수용하는 예외다. Ubuntu runner와 CI 자체 권한·네트워크 경계도 별도 검증해야 한다. 운영 사용에는 적합하다고 판정하지 않는다. | 위험 수용 경로일 뿐 검증 성공이 아니다. **이번 작업에서 선택하거나 승인하지 않았다.** |

권고 순서는 A를 우선 요청하고, 합리적 기간 내 image-specific 증거를 받지 못하면 B를 설계 검토하는 것이다. C는 사용자가 별도 Phase에서 범위·기한·승인 주체·격리 조건을 명시해 동의할 때만 제한적인 synthetic CI 시험을 검토한다. 이번 판정은 C 승인, Ubuntu CI 활성화 또는 Remote Intake 승인이 아니다.

## 7. 후속 검증 및 승인 조건

다음 단계에서 실제 증거 검증을 요청하기 전, Semgrep이 승인된 신뢰 정책을 제공해야 한다. 최소 요청 자료:

1. 정확한 ARM64 manifest digest 및 multiarch index digest에 대한 서명 또는 attestation 참조.
2. 서명 방식, 공개 키 또는 keyless identity와 issuer, 승인 trust root, Rekor 검증 요구사항.
3. 이미지 signature와 SBOM/provenance 각각의 subject digest 및 predicate 유형.
4. build source URL, commit, workflow identity와 tag/runtime 버전 차이 설명.
5. index digest와 플랫폼별 child digest를 연결하는 공식 설명 또는 검증 가능한 OCI 인덱스.

자료가 확보되면 명시된 identity/issuer 및 trust root를 독립적으로 승인한 뒤, 제한된 별도 Phase에서 registry metadata/attestation만 대상으로 검증한다. 이미지 다운로드나 실행은 별도 승인을 받고 진행한다. 증거가 확보되지 않으면 대안 B 설계로 이동하며, 어떠한 경우에도 검증 생략 옵션으로 성공 판정을 만들지 않는다.

현재 별도 Gate:

- 이미지 서명, provenance 및 승인 trust root: `UNVERIFIED`.
- Ubuntu ARM64 격리 실행: `NOT_TESTED`.
- 실제 Host API 접근 차단: `NOT_TESTED`.
- GitHub SSRF, Archive 안전 추출 및 Commit/Tree/Blob 동일성: `NOT_TESTED`.
- GitHub Remote Intake: `NOT_APPROVED`.

## 8. 정적 검증 및 Git

- 기존 증거 원장과 Ubuntu CI 준비 문서는 수정하지 않았다.
- 이미지 다운로드, 컨테이너 실행, CI 실행, 원격 저장소 접근은 수행하지 않았다.
- 문서의 공식 근거 링크를 확인했고, 이미지 digest 및 상태 표기를 교차 점검했다.
- 문서 전용 변경이므로 Python/Frontend/Chromium 회귀 테스트는 실행하지 않았다 (`NOT_TESTED`).
- `git diff --check` 및 변경 파일 범위 검증을 수행했다.
- 로컬 커밋 후 새 SHA는 원격 CI에서 검증되지 않은 상태로 남는다. Push는 수행하지 않는다.

## 참고 자료

- [Semgrep 공식 Docker 이미지](https://hub.docker.com/r/semgrep/semgrep)
- [Semgrep 1.182.1 ARM64 image tag 및 digest](https://hub.docker.com/r/semgrep/semgrep/tags?name=1.182.1-nonroot)
- [대상 ARM64 manifest의 Docker Hub metadata](https://hub.docker.com/layers/semgrep/semgrep/1.182.1-nonroot/images/sha256-cfb298aae2cc36faf33fd47038dd619365bd78582398810f0cd1c39c94d940c5)
- [Docker Hub Verified Publisher 설명](https://docs.docker.com/docker-hub/repos/manage/trusted-content/)
- [Docker Scout attestation CLI 기본값](https://docs.docker.com/reference/cli/docker/scout/attestation/get/)
- [Docker Hardened Images 서명 검증 가이드](https://docs.docker.com/dhi/how-to/verify/)
- [Sigstore Cosign 서명 검증](https://docs.sigstore.dev/cosign/verifying/verify/)
- [Sigstore OIDC identity 검증 표](https://docs.sigstore.dev/quickstart/verification-cheat-sheet/)
- [PyPI semgrep 1.182.1 provenance 정보](https://pypi.org/project/semgrep/1.182.1/)
