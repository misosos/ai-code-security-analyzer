# U1 — AppSec 실무 문제 발견 및 제품 방향 재설정

판정: **`NO_PRODUCT_EVIDENCE`** (독립 제품 개발 근거 부족)

조사 시점: 2026-11-11. 방법: 공개 GitHub 이슈, 벤더 공식 문서, 공개 설문과 논문 초록 검색.

**이 문서의 범위와 한계를 먼저 밝힌다.**

- 사용자 인터뷰를 하지 않았다. 모든 수요 판단은 공개 자료에 근거한다.
- 검색 범위가 넓지 않았고 조사 도중 한 차례 중단됐다가 재개됐다. "찾지 못했다"는 "없다"가 아니다.
- 아래에서 "요약만"이라고 표시한 항목은 검색 요약으로만 확인했고 원문을 읽지 못했다.
- SonarQube와 CodeQL의 세부 기능은 이 단계에서 새로 확인하지 않고 이전 감사의 확인 내용을 사용했다.

## 1. D1/D2 종료 정리

| 구분 | 내용 |
| --- | --- |
| 검증된 사실 (D1) | 합성 14개 사례에서 Semgrep + Git 스크립트가 원인 분류 30/30, 제품은 15/30 정확에 4건 오판. 제품은 줄 번호로 Finding을 식별해 줄 이동과 이름 변경을 소실로 오인한다. |
| 검증된 사실 (D2) | Semgrep 기본 실행은 불완전한 검사 13개 중 11개를 종료 코드 0으로 끝냈다. 152줄 스크립트는 2건, 제품은 모드별 4~8건을 놓쳤다. 제품만 잡은 사례는 없다. |
| 미검증 가설 | 이런 오판이 실제 조직에서 얼마나 자주, 어떤 피해로 이어지는가. 스크립트를 유지하는 것이 실무에서 부담인가. |
| 실험 한계 | 사례, 라벨, 스크립트를 같은 세션에서 설계했다. 합성 소규모다. 사람을 측정하지 않았다. D2의 2개 사례는 의도한 실패를 만들지 못한 것으로 의심되나 라벨은 그대로 두었다. |

**중단한 방향**

- Finding 소실 원인 평가기와 조사 API 확장
- 스캐너 무결성 판정을 차별점으로 삼는 것
- "기존 도구보다 더 정확하다, 더 안전하다"는 종류의 우위 주장

## 2. 관찰된 실무 문제와 출처

| # | 문제 | 출처와 날짜 | 관련 도구 | 확인 수준 |
| --- | --- | --- | --- | --- |
| P1 | 재검사 때 코드 위치가 바뀌면 기존 Finding이 닫히고 새 Finding이 생겨 상태, 메모, SLA 시계, 위험 수용, Jira 연결이 끊긴다 | DefectDojo 공식 문서 "Location Drift Matching (Pro)" | DefectDojo | 문서 확인 |
| P1 | Semgrep JSON에서 줄이 바뀌자 원래 Finding이 mitigated 처리됐다는 버그 보고 | DefectDojo 이슈 #11227, 2024-11-09 개설, 2025-03-01 종료 | DefectDojo, Semgrep | 원문 확인 |
| P2 | 불완전한 검사가 성공으로 끝난다 | Semgrep 공식 문서(CI는 기본값에서 내부 오류가 나도 통과), D2 실험 | Semgrep | 문서와 실험 확인 |
| P3 | 규칙이나 엔진을 올리면 Finding이 예고 없이 변한다 | Semgrep KB "unexpected new findings", GitLab 이슈 330549 | Semgrep, GitLab SAST | 원문 확인 (아래 주 참조) |
| P4 | 경보의 상당수가 오탐이나 중복이라 무시하게 된다 | Black Duck 2025 설문, IEEE S&P 2024 실무자 인터뷰 연구(arXiv 2307.16325) | SAST 전반 | 설문은 요약만, 논문은 초록만 |
| P5 | `nosemgrep` 억제에 사유와 만료가 강제되지 않는다 | Semgrep 문서(사유 입력은 선택) | Semgrep | 문서 확인. 불편을 호소하는 이슈는 찾지 못함 |

**P3에 대한 주.** 원문을 확인한 결과 근거가 처음 생각한 것보다 좁다.

- Semgrep KB 페이지는 Registry 규칙 갱신으로 Finding이 **늘어나는** 경우만 다룬다. 엔진 업그레이드나 Finding 감소는 언급하지 않는다.
- GitLab 이슈 330549는 Semgrep 0.39.1에서 0.50.1로 올리자 하위 QA 프로젝트에서 같은 취약점을 찾지 못했고, JS/TS 규칙 해석이 바뀌어 규칙을 고쳐 해결했다는 내용이다. 개설일과 참여자 수는 페이지에서 확인하지 못했다.
- 따라서 "조용히 줄어든다"는 쪽의 근거는 이 이슈 한 건이며, 그것도 회귀 테스트가 잡아낸 사례다.

P4는 근거가 가장 많지만 벤더 설문이 대부분이라 수치는 방향만 참고한다. P5는 문제를 호소하는 사례를 찾지 못했으므로 확인된 문제로 보지 않는다.

## 3. 기존 해결책 비교

| 문제 | 기존 해결책 | 남는 틈 |
| --- | --- | --- |
| P1 식별 흔들림 | DefectDojo Pro의 Location Drift Matching(유료). Semgrep AppSec Platform의 `match_based_id`(로그인 필요). GitHub은 `upload-sarif`에서 지문이 없으면 소스로 생성. SonarQube는 라인 해시. | 로그인 없는 Semgrep OSS 출력을 DefectDojo 오픈소스판에 넣는 조합. [U1 Closeout](u1-closeout-defectdojo-upstream-feasibility.md)에서 따로 다룬다. |
| P2 불완전 검사 | GitHub tool status page가 CodeQL에 대해 파일 커버리지와 CSV 제공. `--strict`. verbose JSON 검사 스크립트. | 제3자 SARIF 업로드에 커버리지가 적용되는지 확인하지 못했다. 그 외에는 스크립트로 해결된다(D2). |
| P3 업그레이드 변동 | 버전과 규칙셋 고정, `semgrep --test`, 업그레이드를 별도 PR로 분리. | 두 버전 결과를 비교하는 작업은 D1 스크립트와 같은 종류다. |
| P4 오탐 피로 | Semgrep Assistant 등 AI 트리아지, 각 플랫폼의 우선순위 기능. | 자금력 있는 경쟁자가 밀집해 있고 이 저장소에 재사용할 자산이 없다. |
| P5 억제 관리 | 플랫폼의 Ignored 상태와 사유. `grep` 한 줄. | 스크립트로 충분하다. |

제외: P4(경쟁 과밀, 자산 없음), P5(스크립트로 충분, 수요 증거 없음).

## 4. 문제 후보

### 후보 1 — 재검사 간 트리아지 상태 유실 (P1)

| 항목 | 내용 |
| --- | --- |
| 사용자 | DefectDojo 오픈소스판과 Semgrep OSS를 함께 쓰는 AppSec 담당자 |
| 작업 | CI 검사 결과를 반복 임포트하면서 오탐 판정, 메모, SLA를 유지 |
| 현재 방식 | 재임포트와 중복 제거 설정 조정 |
| 관찰된 불편 | 위치가 바뀌면 판정과 이력이 끊긴다(벤더 문서가 명시) |
| 기존 해결책 | DefectDojo Pro, Semgrep Platform, 해시 필드 설정 |
| 한계 | 유료이거나 로그인이 필요하다. 설정은 다른 Finding을 합치는 부작용이 있다. |
| 재사용 자산 | D1 스크립트의 diff 기반 줄 대응 로직. 제품 본체는 해당 없음. |
| 비용과 위험 | 임포트 전에 안정 지문을 붙이는 수백 줄 스크립트. 오매칭 시 서로 다른 취약점이 하나로 합쳐져 미해결 건이 가려질 수 있다. |
| 증명 실험 | DefectDojo 오픈소스판에 Semgrep OSS JSON을 줄 이동 전후로 임포트해 상태가 끊기는지 관찰 |
| 중단 조건 | 문제가 재현되지 않거나 설정만으로 해결됨 |

반론: 벤더가 이미 유료 기능으로 풀었고 오픈소스 쪽 버그도 고쳐졌다. 틈이 남아 있다 해도 독립 제품이 아니라 DefectDojo에 대한 기여나 전처리 스크립트 하나가 맞는 형태다.

### 후보 2 — 조용히 불완전한 검사 (P2)

| 항목 | 내용 |
| --- | --- |
| 사용자 | CI에 Semgrep OSS를 직접 넣은 DevSecOps 담당자 |
| 관찰된 불편 | 종료 코드 0과 "성공" 표시로 끝나는 불완전 검사(D2에서 11/13) |
| 기존 해결책 | 스크립트와 의도 선언. CodeQL은 플랫폼이 제공. |
| 재사용 자산 | D2 스크립트 |
| 증명 실험 | D2의 미해결 2건을 독립 설계자가 다시 구성 |
| 중단 조건 | 스크립트가 충분하다고 확정됨 |

반론: D2에서 이미 스크립트가 제품보다 나았다. 확정되지 않은 것은 스크립트의 충분성이지 제품의 필요성이 아니다.

### 후보 3 — 규칙과 엔진 업그레이드에 따른 결과 변동 (P3)

| 항목 | 내용 |
| --- | --- |
| 사용자 | 규칙셋과 스캐너 버전을 관리하는 AppSec 담당자 |
| 관찰된 불편 | 업그레이드 후 Finding이 늘거나 줄어든다 |
| 기존 해결책 | 버전 고정, 규칙 테스트 |
| 재사용 자산 | 저장소의 합성 벤치마크와 회귀 테스트 방식 |
| 증명 실험 | 연속된 두 Semgrep 버전을 같은 코드에 돌려 줄어든 Finding을 분류 |
| 중단 조건 | 버전 고정과 두 번 실행 후 diff로 충분함 |

반론: 근거가 이슈 한 건이고, 해법은 "두 번 돌리고 비교"라는 D1과 같은 스크립트다.

## 5. 결론

하나도 제품 방향으로 선택하지 않았다. 세 후보는 각각 다음에 해당한다.

- 상용 제품이나 설정이 이미 다룬다 (후보 1)
- 스크립트가 제품보다 낫다는 것을 이 저장소의 실험이 보였다 (후보 2)
- 스크립트 수준이고 근거가 약하다 (후보 3)

## 6. 이 결론을 뒤집을 수 있는 증거

- 서로 다른 조직의 실무자 여러 명이 같은 문제를 지금 수작업으로 메우고 있다고 직접 말하는 경우
- 스크립트 유지가 부담이라는 구체적 사례(작성했다가 방치된 스크립트, 스키마 변경으로 깨진 사례)
- 독립 설계자가 만든 사례에서 D1, D2 스크립트가 실패하는 경우

## 출처

- DefectDojo: Location Drift Matching (Pro) — https://docs.defectdojo.com/triage_findings/finding_deduplication/pro__location_drift_matching/
- DefectDojo issue #11227 — https://github.com/DefectDojo/django-DefectDojo/issues/11227
- DefectDojo: About Deduplication — https://docs.defectdojo.com/triage_findings/finding_deduplication/about_deduplication/
- GitHub: SARIF support for code scanning — https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support
- Semgrep: Triage and remediation — https://docs.semgrep.dev/semgrep-code/triage-remediation
- Semgrep: Ignore files, folders, and code — https://docs.semgrep.dev/ignoring-files-folders-code
- Semgrep KB: unexpected new findings — https://docs.semgrep.dev/kb/semgrep-code/unexpected-new-findings
- GitLab issue 330549 — https://gitlab.com/gitlab-org/gitlab/-/issues/330549
- Black Duck Global DevSecOps Report (요약만) — https://www.blackduck.com/content/dam/black-duck/en-us/reports/rep-global-devsecops-report.pdf
- Ami et al., IEEE S&P 2024 (초록만) — https://arxiv.org/abs/2307.16325
