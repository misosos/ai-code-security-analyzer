# Phase 36.9D — 큰 글씨와 화면 가독성 개선

## 목표와 사용자 피드백

사용자는 이전 단계에서 보고된 16~17px 본문 측정에도 실제 Safari 화면의 글씨가 여전히 작다고 반복해서 피드백했다. 이번 변경은 데스크톱 본문을 18~19px 중심으로 키우고, 결과·안내·상태 문구의 축소된 CSS 오버라이드를 제거하는 데 초점을 맞췄다. 최종 가독성 수용 여부는 사용자의 실제 화면 확인 전까지 미확정이다.

## 원인 조사

Phase 36.9B-Z의 측정은 `.workspace-title > p` 등 일부 대표 요소만 확인했다. 전체 페이지의 작은 텍스트를 검사하지 않아 결과 화면의 규칙 ID, 심각도 라벨, 필터 라벨, 검사 설정 도움말, 안내 토글 등이 놓쳤다. `frontend/src/styles.css`의 정적 검색에서는 `font-size`/`font` 선언 400건, 그중 9~15px 값을 지정한 소스 행 272개가 확인됐다(중복 선택자·미디어쿼리 포함이며 렌더링 요소 수는 아님). 결과 컨텍스트 10~15px, 행 메타데이터 12~15px, 모바일 제목 22~30px 등의 규칙이 남아 있었다. 이 선택자들이 전역 본문 크기보다 우선하면서 화면별 크기를 다시 낮췄다.

이전 Playwright 캡처는 브라우저 viewport를 기록했지만 Safari의 실제 확대 설정은 측정하지 않았다. 따라서 Safari 확대율은 UNKNOWN이다. 캡처 픽셀 크기만으로 CSS px을 추론하거나 Chromium 결과를 Safari 결과로 대신하지 않는다. 작은 글씨뿐 아니라 흐린 보조색과 촘촘한 줄간격도 작게 느껴지는 데 영향을 줄 수 있다.

## 적용한 타이포그래피와 간격

새 파일 [readability.css](../frontend/src/readability.css)는 기존 스타일 뒤에서 rem 기반 읽기 토큰을 적용한다. 반응형 페이지 구조와 사이버펑크 색상·HUD 요소는 유지하고, 작은 글씨의 구체 선택자와 미디어쿼리가 핵심 텍스트를 다시 축소하지 않도록 명시적인 하한을 두었다.

| 요소 | 이전 측정 (1440×900, Z) | 이번 측정 (1440×900, Chromium) |
|---|---:|---:|
| 페이지 제목 | 30.96px | 37.44px |
| 본문 설명 | 17px | 18px |
| 사이드바 메뉴 | 16px | 19px |
| 입력 레이블 | 16px | 18px |
| 선택 입력 | 16px / 높이 52px | 18px / 높이 58px |
| 실행 버튼 | 17px / 높이 54px | 18px / 높이 60px |
| 본문 설명 줄간격 | 27.2px | 30.6px |
| 사이드바 너비 | 248px | 252px |

추가 측정: 데스크톱 Finding 제목 19px, 파일 위치 16px, 상세 설명 19px, 검색·필터 글자 19px, 사용 안내 본문 18px(줄간격 31.5px), 용어 설명 17px(줄간격 28.9px), 안내 코드 17px(줄간격 28.05px). 모바일 390px에서는 제목 32px, 본문 17px, 메뉴 18px, 입력·선택·버튼 18px, 컨트롤 높이 54px였다. 개별 selector·line-height·색상·bounding box 전체 기록은 [computed-style-samples.json](assets/ui-large-type-readability-36-9d/readability-audit/computed-style-samples.json) 및 [responsive-result-metrics.json](assets/ui-large-type-readability-36-9d/readability-audit/responsive-result-metrics.json)에 있다.

## 화면별 변경

- **검사 시작:** 제목과 설명, 입력 레이블, 선택값, 토큰 필드, 도움말, 실행 액션을 키웠다. 필드 높이와 입력 여백도 확대했다.
- **검사 결과:** 검사 컨텍스트, 상태 설명, 통계, 심각도, 검색·필터, Finding 제목·위치, 상세 근거의 글씨를 확대했다. 긴 경로·규칙 ID는 줄바꿈할 수 있도록 유지했다.
- **결과 없음:** 제목을 데스크톱 32px, 태블릿 28px, 작은 모바일 26px 이상으로 보정했다.
- **사용 안내:** 본문 18px, 용어 제목 19px, 용어 설명 17px, 코드 17px로 넓혔다. 문서가 길어지면 세로 스크롤을 허용한다.
- **레이아웃:** 데스크톱 메인 영역의 상단 여백을 소폭 줄여 결과 화면 진입을 돕고, 사이드바 너비를 viewport에 맞게 240~280px로 조정했다. 컨텐츠를 숨기거나 `transform: scale()`/`zoom`으로 축소하지 않았다.

시각적 비교 캡처는 [이전 화면](assets/ui-large-type-readability-36-9d/before/)과 [이번 렌더링](assets/ui-large-type-readability-36-9d/readability-audit/)에 있다. Finding·부분 결과·오류·API 연결 실패 캡처는 [합성 회귀 캡처](assets/ui-large-type-readability-36-9d/regression-captures/)에서 확인할 수 있다. 모든 새 화면 데이터는 테스트 전용 합성 응답이며 실제 API 연결이나 실제 프로젝트 탐지 결과가 아니다.

화면 검토에서 글씨가 이전보다 분명히 커졌고, 시작·결과·안내 화면의 주요 정보도 읽히는 것을 확인했다. 결과 화면은 상태·제한·통계가 위에 쌓여 1440×900에서 Finding 목록이 첫 화면 아래로 내려가 스크롤이 필요하다. 큰 글씨를 줄여 해결하지 않았으며, 이는 남은 정보 밀도 조정 항목이다. 선택 입력의 긴 옵션명은 한 줄 영역에서 일부 잘릴 수 있으므로 프로젝트 운영자는 짧고 알아보기 쉬운 표시 이름을 사용하는 편이 낫다.

## 대비와 접근성

대표적인 단색 팔레트 쌍의 계산 대비는 본문 `#edf5ff` 대 배경 `#050816` 18.15:1, 보조 텍스트 `#b3c3da` 대 배경 11.15:1, 흐린 보조색 `#8fa5c0` 대 배경 7.89:1, 시안 강조 `#54e8ff` 대 배경 13.64:1, 바이올렛 `#b493ff` 대 배경 8.13:1이었다. 이는 토큰 색상 쌍의 계산값이며, 반투명 표면·그라디언트·모든 상태를 포함한 WCAG 적합성 인증은 아니다. axe 검사는 설치/실행하지 않아 NOT_TESTED다.

Playwright 키보드 포커스 회귀와 모바일 메뉴 검사는 통과했다. 모바일 320px에서 가로 넘침이 없고 지정 viewport 1920×1080, 1440×900, 1280×800, 768×1024, 390×844 모두 문서 가로 넘침 0px이었다. 200% 확대는 실제 브라우저 확대가 아니라 720×450 CSS viewport 대체 시험으로만 확인했으며, 실제 Safari 확대 및 키보드 수동 검수는 NOT_TESTED다.

## 검증 결과

| 검증 | 결과 |
|---|---|
| TypeScript typecheck | PASS |
| Production build | PASS |
| Vitest | 4개 파일, 44개 테스트 PASS |
| Chromium Playwright | 7개 테스트 PASS; 타이포, 화면 전환, 합성 결과, 필터·다운로드·삭제, 모바일 메뉴 포함 |
| 합성 FastAPI–Semgrep E2E | PASS; Semgrep 1.182.1, 격리 임시 합성 프로젝트 사용 |
| 가로 넘침·글꼴 하한 | PASS; 모든 표시 텍스트 16px 이상, 모바일 본문 17px |
| WebKit / Safari | NOT_TESTED; 실행 환경에 Playwright WebKit 브라우저가 설치되어 있지 않음. 실제 Safari 확대율 UNKNOWN |
| axe / 정식 WCAG 감사 | NOT_TESTED |
| git diff --check | PASS |

UI 작업으로 FastAPI·CLI·Semgrep 동작, Finding/Evidence 계약, 인증 토큰의 메모리 보관, 코드 비공개 정책을 변경하지 않았다. 테스트는 토큰을 합성 값으로만 사용했다.

## 잔여 제한

- 사용자가 실제 Safari 화면에서 가독성을 최종 확인하지 않았다. 따라서 사용자 수용은 확정하지 않는다.
- Safari/WebKit별 글꼴 렌더링과 실제 페이지 확대율은 확인하지 못했다.
- 결과 화면은 큰 글씨를 유지한 결과 세로 스크롤이 늘었다. 1440×900에서 목록 시작까지의 여백/정보 밀도는 다음 피드백에서 검토할 수 있다.
- OS Native Select 펼침 옵션의 브라우저별 렌더링은 Chromium의 computed style로 완전히 검증할 수 없다.
- 대표 색상 대비 계산은 실제 화면의 모든 합성 배경 조합을 포함하지 않는다.
