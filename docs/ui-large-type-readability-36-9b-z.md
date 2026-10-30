# Phase 36.9B-Z — 큰 글씨와 가독성 개선

## 사용자 피드백과 목표

사용자는 사이드바 구조는 좋아졌지만 본문, 메뉴, 라벨, 보조 설명, 결과 목록이 작고 서로 붙어 있어 읽기 어렵다고 했다. 특히 검사 결과와 사용 안내 화면의 정보가 촘촘하고, 넓은 화면에서도 중요한 내용이 한눈에 들어오지 않는 점을 개선 대상으로 삼았다.

사이드바와 다크 네온 테마, 검사 시작·결과·사용 안내의 정보 구조는 유지했다. 이번 변경은 타이포그래피, 내부 여백, 컨트롤 크기와 결과 행 간격에 집중했다. API, Finding/Evidence 계약과 보안 판정 의미는 변경하지 않았다.

## 시작 Gate

- 브랜치: `main`
- 작업 기준 HEAD: `d1402b5f1478f6645e4fb5be474b1d753f93401a`
- `origin/main` 및 GitHub `main`: `de83be32775b8503c1e907d47ddf79c89e0b05e3`
- 기준 HEAD는 원격보다 3개 커밋 앞서 있었으며, 이 HEAD의 CI 실행은 없었다.
- 최신 확인 성공 CI: `41048835761`, push / completed / success, SHA `de83be32775b8503c1e907d47ddf79c89e0b05e3`. 이전 SHA의 성공이며 현재 로컬 SHA 검증으로 취급하지 않았다.
- 기존 UI 작업의 미커밋 파일과 Phase 36.9B-Y 문서·화면 자료가 있었다. 삭제하거나 초기화하지 않았으며, 이번 커밋 대상에서 Y 문서와 자료를 제외했다.

## CSS 감사 및 변경 전후 측정

기존 CSS 전체에서 작은 텍스트 선언을 확인했다. 결과 화면의 심각도 수치 11–13px, 규칙 ID 12px, 모바일 결과 위치 13px, 결과 필터 13px, 시작 화면 안내 요약 12–13px, 토큰 보조 컨트롤 및 안내 12–13px, 사용 안내 본문 14px, 코드 12px 등이 있었다. 작은 컨트롤은 높이 36–44px로 정의된 구간도 있었다. 기존 선언은 유지보수상 남아 있지만, 최종 가독성 계층에서 실제 노출되는 핵심 콘텐츠를 덮어써 크기를 보장한다.

| 항목 | 기준 CSS/기존 화면 | 개선 후 브라우저 측정 |
| --- | ---: | ---: |
| 페이지 제목 (1440px) | 약 28.8px | 30.96px |
| 페이지 제목 (모바일) | 22px | 30px |
| 일반 본문 (데스크톱) | 화면별 13–17px | 17px, line-height 27.2px |
| 사용 안내 본문 | 14px | 16px, line-height 1.75 |
| 사이드바 항목 | 약 14–15px | 16px, 항목 높이 52px |
| 규칙/프로젝트 선택 | 14px, compact 구간 38px | 16px, 높이 52px |
| 실행 버튼 | 15px / 50px | 17px / 54px |
| 결과 제목 / 위치 | 14–16px / 13–15px | 17px / 15px |
| 필터 | 13–15px, 높이 36–44px | 16px, 높이 48px |
| 주요 보조 텍스트 하한 | 10–13px 선언 존재 | 브라우저 검사에서 보이는 콘텐츠 14px 이상 |

시작·안내·결과 화면의 실제 렌더링 텍스트를 Playwright TreeWalker로 조사했다. 숨김 보조기술 텍스트와 장식 요소는 제외했고, 화면에 표시되는 14px 미만 텍스트가 남지 않도록 회귀 조건으로 추가했다. 이 기준은 작은 보조 표식까지 확대하는 대신 정보성 텍스트를 읽을 수 있게 하는 목적이다.

## 변경 사항

- 제목, 페이지 설명, 카드 제목에 명확한 크기 차이를 두고 제목 아래 여백을 넓혔다.
- 기본 본문을 데스크톱 17px, 모바일 16px로 설정하고 한국어 본문 줄 간격을 1.6 이상으로 높였다.
- 사이드바 메뉴 텍스트를 16px, 메뉴 높이를 52px로 유지해 읽기와 클릭을 쉽게 했다.
- 검사 대상·규칙·토큰 입력을 52px, 검색·필터 입력을 48px로 키웠다. 토큰 지우기 버튼과 실행 버튼도 같은 조작 계층으로 키웠다.
- 결과 통계 숫자와 라벨, 상태 배너, Finding 제목·파일 위치, 선택 상세의 설명을 확대하고 카드 내부 패딩 및 그룹 사이 여백을 늘렸다.
- 검색 결과 번호, 규칙 ID, 결과 맥락의 프로젝트·규칙 코드처럼 이전에 작게 남아 있던 메타데이터도 실제 브라우저 측정 후 14px 이상으로 조정했다.
- 사용 안내의 본문을 16px, 코드 블록을 14px로 키우고 문서 폭을 제한해 한국어 문장을 편하게 따라갈 수 있도록 했다.
- 네이비 배경과 시안·마젠타·바이올렛 강조는 유지했다. 작은 영문 HUD 라벨을 늘리지 않고 기존 장식 라벨을 한국어로 바꿨다.

## 참고한 공개 패턴

코드를 복사하거나 새 UI 패키지를 설치하지 않았다. 공개 레퍼런스의 여백, 입력 그룹, 사이드바 및 목록 정보 계층을 현재 React/CSS 구조에 맞춰 다시 구성했다.

| 참고 자료 | 라이선스/범위 | 적용 포인트 |
| --- | --- | --- |
| [shadcn/ui Sidebar](https://ui.shadcn.com/docs/components/radix/sidebar), [Sidebar Blocks](https://ui.shadcn.com/blocks/sidebar) | 저장소 MIT | 사이드바와 메인 콘텐츠 분리, 활성 항목 구분, 넉넉한 조작 영역 |
| [shadcn/ui Dashboard Blocks](https://ui.shadcn.com/blocks?category=dashboard), [Input Group](https://ui.shadcn.com/docs/components/base/input-group), [라이선스](https://github.com/shadcn-ui/ui/blob/main/LICENSE.md) | MIT | 요약 수치, 도구 모음과 폼 컨트롤의 계층 |
| [Origin UI](https://originui.com/), [저장소](https://github.com/shadcn/originui) | MIT 저장소; 사이트는 COSS UI 안내로 이동 가능 | 큰 입력, 버튼·입력의 간격과 클릭 영역 |
| [DefectDojo](https://github.com/DefectDojo/django-DefectDojo), [라이선스](https://github.com/DefectDojo/django-DefectDojo/blob/master/LICENSE.md) | BSD-3-Clause | 보안 결과 목록에서 심각도와 위치를 비교하는 정보 우선순위 |

## 실제 브라우저 측정

Chromium / Playwright, zoom 100%에서 검사 시작, 검사 완료, 결과 없음, 사용 안내, 모바일 메뉴를 합성 API 데이터로 렌더링했다. 모든 대상 너비에서 문서 가로 넘침은 0px이었다.

| 화면 크기 | 본문 | 제목 | 사이드바 | 선택 컨트롤 | 결과 제목 / 위치 / 상세 설명 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1920×1080 | 17px | 36px | 248px | 52px | 17px / 15px / 15px |
| 1440×900 | 17px | 30.96px | 248px | 52px | 17px / 15px / 15px |
| 1280×800 | 17px | 30px | 248px | 52px | 17px / 15px / 15px |
| 768×1024 | 17px | 30px | 218px | 52px | 17px / 15px / 15px |
| 390×844 | 16px | 30px | 모바일 Drawer 310px | 52px | 17px / 15px / 15px |

1440×900에서 검사 시작의 제목은 y=104px, 설정 영역은 y=216–485px에 놓였다. 장식용 설명 영역은 y=588–783px였고 콘텐츠 아래 불필요한 빈 공간은 27px로 측정됐다. 검사 완료 화면의 상세 및 목록 영역은 y=828px부터 시작하므로 1440×900에서 상태·통계와 함께 목록 첫 줄의 상단이 화면 아래쪽에 걸친다. 글자 크기를 줄여 위로 당기지는 않았다. 1280×800의 결과 영역은 y=915px부터라 첫 화면에 결과 목록이 나오지 않으며, 이 짧은 뷰포트에서는 세로 스크롤이 필요하다.

720×450 CSS viewport로 200% 확대 시의 좁은 화면 대체 조건도 검사했다. 가로 넘침은 없었지만 실제 브라우저 확대 기능 자체를 조작한 검사는 아니다. Safari/WebKit, axe 자동 검사, 공식 WCAG 적합성 평가는 이번 검증에서 실행하지 않았다.

색상 토큰의 대표 조합을 계산하면 일반 텍스트 색상 `#edf5ff` / 배경 `#050816`은 약 18.15:1, 보조 텍스트 `#b3c3da` / 표면 `#0b1224`는 약 10.42:1이었다. 이는 토큰 조합의 계산이며, 모든 상태·그라데이션을 포함한 WCAG 전수 검증으로 간주하지 않는다.

## 스크린샷과 측정 파일

새 화면은 합성 데이터 기반이며 실제 취약점 결과나 실제 연결 상태를 나타내지 않는다.

- [검사 시작 1440×900](assets/ui-large-type-readability-36-9b-z/readability-audit/start-1440x900.png)
- [검사 완료 및 선택 Finding 1440×900](assets/ui-large-type-readability-36-9b-z/readability-audit/completed-and-finding-1440x900.png)
- [사용 안내 1440×900](assets/ui-large-type-readability-36-9b-z/readability-audit/guide-1440x900.png)
- [검사 결과 없음 1440×900](assets/ui-large-type-readability-36-9b-z/readability-audit/empty-results-1440x900.png)
- [검사 시작 모바일 390×844](assets/ui-large-type-readability-36-9b-z/readability-audit/start-390x844.png)
- [모바일 메뉴 390×844](assets/ui-large-type-readability-36-9b-z/readability-audit/mobile-menu-390x844.png)
- [오프라인 API 오류 1440×900](assets/ui-large-type-readability-36-9b-z/regression-captures/api-offline-1440x900.png)
- [실제 계산 스타일 측정](assets/ui-large-type-readability-36-9b-z/readability-audit/computed-style-samples.json)
- [결과 화면 영역 측정](assets/ui-large-type-readability-36-9b-z/readability-audit/responsive-result-metrics.json)

변경 전 비교 기준은 Phase 36.9B-Y에서 만든 합성 데이터 화면을 이번 증거 폴더에 보존한 [시작 화면](assets/ui-large-type-readability-36-9b-z/before/start-1440x900.png), [결과 화면](assets/ui-large-type-readability-36-9b-z/before/results-1440x900.png), [사용 안내](assets/ui-large-type-readability-36-9b-z/before/guide-1440x900.png)이다. 이전에는 시작 제목·입력 보조 문구·필터가 특히 작고, 결과의 파일 위치와 안내 본문이 12–14px 구간에 있었다. 새 화면은 더 큰 제목, 본문, 조작 영역으로 변경된 것을 스크린샷에서 확인했다.

## 테스트 결과와 제한

- `npm run typecheck`: 통과
- `npm run build`: 통과
- `npm test`: 4개 파일, 44개 테스트 통과
- `npm run test:browser`: Chromium 7개 테스트 통과. 5개 viewport에서 시작/결과/안내/모바일 메뉴, 실제 계산 스타일, 가로 넘침과 보이는 14px 미만 결과 텍스트를 확인했다.
- `SEMGREP_REQUIRED=1 npm run test:e2e:real`: 합성 프로젝트·로컬 규칙을 사용하는 Chromium–FastAPI–Semgrep E2E 1개 통과. 기존 사용자 API 서버를 중지하지 않도록 E2E 헬퍼가 임시 loopback 포트를 선택하며, 대상은 임시 합성 디렉터리다. 외부 저장소를 사용하지 않았다.
- `git diff --check`: 통과
- Safari 수동 검수, WebKit 자동화, axe, 실제 브라우저 200% 확대: 실행하지 않음.

기존 로컬 API의 `/api/v1/health`는 HTTP 200을 반환했다. 사용자가 제공한 스크린샷의 연결 오류는 현재 재현되지 않아 그 원인을 확정하지 않았다. 브라우저 E2E의 성공은 실제 사용자의 브라우저 연결 또는 실제 검사 결과를 뜻하지 않는다.

### 남은 제한

- 1280×800 및 모바일의 결과·안내는 콘텐츠가 많아 세로 스크롤이 필요하다.
- Sidebar 및 결과 작업 구조는 유지했으며 이번 단계는 레이아웃 전면 개편이 아니다.
- GitHub main의 CI는 현재 HEAD `d1402b5f…`에 대해 실행되지 않았다. 이번 로컬 변경도 원격 CI가 없다.
- 기존 Phase 36.9B-Y 변경분 일부가 같은 UI 소스 파일에 누적되어 있었다. 관련 소스·테스트 파일은 함께 커밋하지만 Y 전용 문서와 자산은 이번 커밋에 넣지 않는다.
