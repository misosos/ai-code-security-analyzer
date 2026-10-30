# Phase 7C-1C — Worker 빌드 입력 검증

## 판정

**`PHASE_7C_1C_INPUT_HOLD`**

Semgrep 1.182.1 ARM64 wheel은 허용된 방식으로 내려받아 SHA-256을 확인했고, 해당 파일의 PyPI 게시 증명 메타데이터도 조사했다. 그러나 접근 및 신뢰 정책을 모두 충족하는 Python 3.12 ARM64 Base Image를 확정하지 못했고, 전이 의존성 전체를 해시 고정한 wheel-only 설치 closure도 아직 만들지 않았다. 따라서 제한적 Worker 이미지 빌드 입력은 준비되지 않았다.

이는 wheel이 오염됐다는 판정이 아니다. 실제 Docker pull/build/run, wheel 설치/import/실행, 전체 의존성 수집은 수행하지 않았다.

## 시작 Gate

- 저장소: `misosos/ai-code-security-analyzer`
- 브랜치: `main`
- HEAD / `origin/main` / GitHub `main`: `c5ef2736933c1d5d2efeb7a495262c4b7b44a316`
- 기준 커밋: `c5ef2736933c1d5d2efeb7a495262c4b7b44a316`
- GitHub Actions Run [41037635539](https://github.com/misosos/ai-code-security-analyzer/actions/runs/41037635539): `push / completed / success`; Python, Semgrep 1.182.1 integration, React dashboard 및 Chromium 필수 단계 성공
- 작업 전 working tree clean, `origin/main` 대비 ahead/behind `0/0`
- 기존 Phase 7C-1B 문서와 보안 증거 문서는 변경하지 않음

## Base Image 후보

| 후보 | 접근·플랫폼·호환성 관찰 | 신뢰·유지보수·라이선스 상태 | 평가 |
|---|---|---|---|
| Chainguard Python 3.12 | 공식 버전 목록은 3.12.15의 ARM64와 x86_64 지원을 표시하지만, 버전 고정 태그는 `Contact us` 접근으로 표시된다. 무료 이미지 정책은 선택된 이미지의 `latest`/`latest-dev`에 한정되며, 현재 free Python은 3.15다. 따라서 Python 3.12 artifact에 익명으로 접근할 수 있다는 증거는 없다. | Chainguard는 이미지별 서명, SLSA provenance 및 SBOM 검증 절차를 공개하고 free 이미지 signer/issuer 후보도 제시한다. 하지만 이 특정 3.12 digest를 얻거나 서명·identity·issuer·subject·SBOM을 검증하지 않았다. 유료/생산 이미지의 실제 사용 및 재배포 조건도 계약 확인 전이다. glibc 최소 버전은 해당 digest에서 확인하지 않았다. | **조건부 기술 후보이나 현재 빌드 입력으로 선택 불가.** 결제나 계정 생성을 시도하지 않았다. Python 3.12 접근 및 해당 artifact에 대한 라이선스가 먼저 확인되어야 한다. |
| Docker Official Python 3.12 slim Bookworm | Docker Official Images 목록에 `3.12-slim-bookworm` 및 ARM64가 있다. Debian Bookworm glibc는 2.36으로 wheel의 manylinux 2.34 최소 기준보다 높다. Python 3.12 및 ARM64 후보로서 기술 호환성은 유망하지만 실제 이미지에서 확인하지 않았다. | Docker Hub의 태그 페이지는 ARM64 child digest 일부를 축약해 표시한다. 이번 조사에서는 전체 고정 digest를 독립적으로 확인하지 않았고, 특정 digest에 대한 승인된 signer identity/issuer와 검증 가능한 서명·provenance/SBOM 정책을 확립하지 못했다. Docker Official Image라는 분류만으로 암호학적 신뢰를 인정하지 않는다. Python/Debian 및 종속 패키지 라이선스 notice를 함께 관리해야 한다. | **호환성 비교 후보. 신뢰 Gate 미통과.** 이미지 pull 및 실행 금지 조건을 지켰으므로 정확한 digest, 런타임 glibc, 실제 provenance는 미검증이다. |
| Ubuntu 24.04 기반 Python 3.12 | Ubuntu 24.04 ARM64 `libc6`는 glibc 2.39 계열이며 Python 3.12 runtime을 제공할 수 있어 ABI 후보가 된다. 정확한 이미지 digest 및 Python 패키지 구성은 확인하지 않았다. | Ubuntu 공식 이미지의 특정 digest에 대해 승인된 서명자 identity/issuer, 이미지 provenance와 SBOM을 연결하는 검증 정책을 이번 조사에서 확립하지 못했다. Canonical 패키지 서명은 그 자체로 합성된 OCI 이미지의 provenance를 입증하지 않는다. Ubuntu 및 포함 패키지별 라이선스/notice가 필요하다. | **기술 후보일 뿐 신뢰 입력으로 선택 불가.** |
| 별도 최소 Python runtime | 고정 버전 Python 3.12, ARM64, glibc ABI 및 검증 가능한 이미지 서명/provenance/SBOM을 함께 충족하는 추가 후보는 이번 조사에서 확정하지 못했다. Chainguard의 공개 무료 Python `latest`는 현재 3.15로, 대상 wheel의 최대 Python 태그가 3.14이므로 이 조합을 호환 후보로 취급하지 않았다. | 독자 이미지 제작은 Base Image와 패키지 공급망을 검증하고 유지해야 한다. | **후보 미확정.** |

Chainguard의 공식 페이지는 현재 3.12.15 ARM64 태그를 접근 제한으로 표시하고 free-tier 정책은 최신 태그만 제공한다고 설명한다. 이는 사용자의 계정 권한을 직접 조회한 결과가 아니며, 접근 불가를 계정 수준으로 단정하지 않는다. 이번 작업은 로그인·토큰 발급·유료 가입을 하지 않았으므로 **익명 접근 미확인 / 고정 버전 접근 제한 관찰**로 기록한다.

참고: [Chainguard Python 버전·플랫폼 목록](https://images.chainguard.dev/directory/image/python/versions), [Chainguard free 및 production image 설명](https://www.chainguard.dev/docs/chainguard/containers/overview), [Chainguard Python provenance 절차](https://images.chainguard.dev/directory/image/python/provenance), [Docker Official Python 태그](https://hub.docker.com/_/python/tags?name=3.12-slim-bookworm&page=1), [Docker Official Images Python manifest source](https://github.com/docker-library/official-images/blob/master/library/python), [Debian Bookworm glibc 버전](https://security-tracker.debian.org/tracker/source-package/glibc), [Ubuntu 24.04 ARM64 libc6](https://packages.ubuntu.com/noble/libc6).

## Semgrep ARM64 wheel 다운로드 및 검증

PyPI 공식 JSON `https://pypi.org/pypi/semgrep/1.182.1/json`에서 정확히 다음 artifact 레코드를 확인했다.

- 파일명: `semgrep-1.182.1-cp310.cp311.cp312.cp313.cp314.py310.py311.py312.py313.py314-none-manylinux_2_34_aarch64.whl`
- URL 호스트: `files.pythonhosted.org` (HTTPS)
- 메타데이터 크기: `73,888,910` bytes (90 MiB 제한 이내)
- PyPI JSON SHA-256: `3fdfbd68ac5eeead60983dbcd539428bbc40d01f805e0569301068d06be7eaa3`
- Requires-Python: `>=3.10`; 휠 태그는 CPython 3.12와 Linux ARM64를 포함
- yanked: `false`

위 URL만 요청했고 redirect를 검사해 `https://files.pythonhosted.org` 이외의 목적지를 거부했다. 전송량은 73,888,910 bytes였으며 실제 SHA-256은 `3fdfbd68ac5eeead60983dbcd539428bbc40d01f805e0569301068d06be7eaa3`으로 PyPI 메타데이터 및 예상값과 일치했다. 파일은 시스템 임시 격리 디렉터리에 저장했으며 검증 후 제거했다. 임시 파일 cleanup 성공.

Wheel은 설치, import 또는 실행하지 않았다. ZIP 멤버 목록(189개)을 확인하고 단일 `.dist-info/METADATA`(22,429 bytes)만 제한 읽기했다. 압축 해제나 다른 파일 읽기는 하지 않았다. `METADATA`는 `semgrep` 1.182.1, `License-Expression: LGPL-2.1-or-later`를 표시했다. 이 메타데이터는 실제 바이너리 실행이나 Base Image 호환성 테스트가 아니다.

## PyPI 게시 증명 및 artifact 연계

공식 PyPI Integrity API의 해당 wheel provenance JSON에서 attestations 1개를 관찰했다. 관찰한 attestation은 `https://docs.pypi.org/attestations/publish/v1` predicate의 PyPI Publish Attestation이며 subject 파일명과 SHA-256이 실제 내려받은 wheel과 일치한다. publisher 정보는 GitHub repository `semgrep/semgrep-proprietary`, workflow `pro-release.yml`을 가리킨다. PyPI release 페이지는 publishing commit `4d7c7d9541cb34804ff75fd47d0e466aa27d762b` 및 workflow 경로 `.github/workflows/pro-release.yml`을 표시한다. Integrity API 응답에는 transparency entry가 포함되어 있었다.

단, 이 단계에서는 attestation 서명, 인증서 identity/issuer, Rekor inclusion proof를 로컬 암호학 검증 도구로 검증하지 않았다. PyPI가 trusted publisher 관계를 확인했다는 UI/Integrity metadata 관찰과 로컬 검증 성공은 다르다. 이 attestation은 게시 주체·artifact 연결에 관한 publish 증명이며, 그 자체로 wheel의 소스 빌드 재현성이나 최종 Worker 이미지 provenance를 입증하지 않는다. SLSA build provenance가 이 wheel에 제공된 것으로 확인하지 않았다. 따라서 로컬 암호학 검증 상태는 **NOT_TESTED**, 승인된 publisher identity 신뢰는 **UNVERIFIED**다.

참고: [PyPI Semgrep 1.182.1 release](https://pypi.org/project/semgrep/1.182.1/), [PyPI Integrity API](https://docs.pypi.org/api/integrity/), [PyPI attestation 유형 및 한계](https://docs.pypi.org/using-pypi/package-security/provenance/), [attestation 소비·검증 절차](https://docs.pypi.org/attestations/consuming-attestations/).

## Requires-Dist 및 설치 closure

Wheel `METADATA`의 직접 `Requires-Dist`는 다음과 같다.

```text
attrs>=21.3
boltons~=21.0
certifi>=2026.10.19
click-option-group~=0.5
click~=8.4.2
colorama~=0.4.0
exceptiongroup~=1.2.0
glom>=23.3
jsonschema~=4.25.1
mcp==1.29.0
opentelemetry-api~=1.37.0
opentelemetry-sdk~=1.37.0
opentelemetry-exporter-otlp-proto-http~=1.37.0
opentelemetry-instrumentation-requests~=0.58b0
opentelemetry-instrumentation-threading~=0.58b0
packaging>=21.0
peewee~=3.14
pyjwt[crypto]<3,>=2.15.0
requests~=2.22
rich>=13.5.2
ruamel.yaml>=0.18.15
ruamel.yaml.clib==0.2.15
semantic-version~=2.10.0
tomli~=2.4.0
typing-extensions~=4.2
urllib3~=2.0
wcmatch~=8.3
pywin32==311; sys_platform == "win32"
```

`pywin32`는 Windows 전용 marker를 가진다. 위 목록은 직접 요구사항이며, 전이 의존성 버전·ARM64 wheel·SHA-256·license closure를 해결하거나 일괄 다운로드한 결과가 아니다. 특히 `pyjwt[crypto]`, `jsonschema`, `mcp`, OpenTelemetry 및 그 전이 의존성의 정확한 wheel closure는 미확정이다. 네이티브 wheel이 없는 의존성에서 sdist fallback이 발생하면 빌드 Gate를 실패시켜야 한다.

후속 closure 정책은 다음과 같이 고정한다.

1. CPython 3.12 / Linux aarch64 target으로 resolver와 입력을 고정하고 전체 전이 dependency graph를 lock한다.
2. 모든 package의 정확한 version, source URL, wheel filename, platform/ABI tag, SHA-256 및 license/notice를 보존한다.
3. 승인된 HTTPS package source에서 수집하되 redirect host를 검증하고 artifact별 크기 상한을 둔다.
4. 설치는 승인된 wheelhouse에서 offline으로만 하며 hash 필수, binary-only 조건을 적용한다. sdist/build backend 실행 또는 자동 fallback은 금지한다.
5. 설치 도구가 모든 artifact hash와 호환 wheel을 강제하지 못하거나 dependency closure가 비어 있으면 fail closed한다.
6. 재현 가능한 wheelhouse와 lock을 별도 검토·승인 전까지 완성된 것으로 간주하지 않는다.

이번 단계에서는 resolver 실행, 의존성 artifact 다운로드/설치, 전체 dependency license 조사, offline wheelhouse 검증을 하지 않았다. 프로젝트 `uv.lock`과 Python 환경은 변경하지 않았다.

## 기존 Worker 계약과의 관계

기존 Phase 7C의 검증 결과는 이전 Semgrep 컨테이너 및 로컬 Docker Desktop 환경에만 적용한다. 새 Base Image/Worker가 아래 통제를 만족한다고 이전하지 않는다.

- 비관리자 UID/GID, read-only root 및 read-only 입력
- `network=none`, `cap-drop=ALL`, `no-new-privileges`
- CPU/Memory/Swap/PID 및 제한된 tmpfs
- Host home, Docker socket, 사용자 프로젝트 미마운트
- Git `safe.directory=*` 금지
- Semgrep OSS 1.182.1, 60초 timeout, 2 MiB 출력 상한
- timeout/자식 프로세스 종료, cleanup 및 privacy canary 검증

Base Image와 wheel 준비만으로는 이 runtime contract, 이미지 provenance, SBOM, 서명 또는 Ubuntu ARM64 격리 검증이 끝나지 않는다.

## 다음 단계 빌드 전 필수 Gate

1. 공개적으로 접근 가능하거나 조직이 이미 보유한 Python 3.12 ARM64 Base Image를 지정한다. 추가 가입·결제는 전제하지 않는다.
2. exact index/ARM64 manifest digest를 확보하고 허용된 signer identity, issuer, trust root, transparency log, provenance subject 및 SBOM을 검증한다. 접근/라이선스가 확인되지 않으면 대체 후보도 동일한 신뢰 기준을 통과하기 전 HOLD한다.
3. Chainguard라면 특정 3.12 artifact의 접근권·사용/재배포 조건을 공급자 약관으로 확인한다. Docker Official Python 또는 Ubuntu 후보라면 특정 digest에 대한 검증 가능한 신뢰 증거를 별도로 확립한다.
4. PyPI wheel attestation을 로컬에서 승인된 verifier와 trust policy로 암호학 검증하고, repository/workflow/commit identity를 사전 승인한다. 서명 검증 도구를 임의 설치하거나 신뢰 키를 추가하지 않는다.
5. Python 3.12 ARM64에 대한 전체 wheel-only dependency closure, artifact hash, package source, license 및 notices를 lock하고 별도 검토한다.
6. 위 조건이 통과된 후에만 제한적 build 실행 승인을 요청한다. 이번 Phase의 wheel 다운로드 승인은 Docker pull/build/run 승인으로 확장되지 않는다.

현재 답변: A) 접근 가능한 적격 Base Image 확정 — **아니오**. B) Base Image에 적용할 신뢰 정책 정의 — **요구사항은 정의했으나 후보에 적용/검증하지 못함**. C) wheel SHA 일치 — **예**. D) PyPI attestation subject 검토 — **예, 관찰; 로컬 암호학 검증 아님**. E) 전체 wheel-only 의존성 확보 — **가능성만 설계, closure 검증 전**. F) 기존 격리 정책 충돌 — **확인된 충돌 없음; 새 Worker에 대한 검증은 미실시**. G) 제한적 빌드 승인 근거 — **아니오**.

## 검증 기록 및 변경 범위

- Gate: 통과; 기준 SHA exact CI 성공
- PyPI artifact metadata: 정확한 filename, HTTPS URL, size 및 SHA-256 일치
- Wheel 다운로드: 허용된 단일 artifact만, 90 MiB 상한 내, redirect 목적지 제한
- Wheel 검사: 제한된 METADATA read만 수행; 설치/import/실행하지 않음
- PyPI attestation: subject/publisher/workflow/transparency entry 관찰; local cryptographic verification `NOT_TESTED`
- Base image: pull/build/run하지 않음; digest와 런타임 호환성은 `NOT_TESTED`
- 의존성 closure: `NOT_TESTED`
- 전체 Python/Frontend/Chromium 회귀: 문서 전용 변경이라 이번 로컬 작업에서 재실행하지 않음 (`NOT_TESTED`); 시작 Gate의 원격 CI는 통과
- 의존성/lockfile, 코드, API, UI, 활성 workflow, 기존 보안 문서: 변경하지 않음
