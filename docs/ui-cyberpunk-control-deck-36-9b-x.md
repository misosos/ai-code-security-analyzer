# Phase 36.9B-X — Reference-Driven Cyberpunk Control Deck

## 작업 범위와 기준

- 작업 기준: `de83be32775b8503c1e907d47ddf79c89e0b05e3` 및 push CI Run `41048835761` (Python, Semgrep, React 통과).
- 작업 시 로컬 `main`은 `84a0ce838568060ce55d5e3400d91bdc1bdbbae0`였고, `origin/main`/GitHub `main`은 기준 SHA였다. 로컬에 앞선 Phase 커밋 2개가 있어 이 로컬 HEAD에 해당하는 CI 성공은 확인하지 못했다. 변경 사항은 보존했고 push하지 않았다.
- 범위는 React 화면, 관련 Vitest/Playwright 검사, 이 보고서와 합성 브라우저 캡처다. API, Semgrep, Finding/Evidence 계약은 변경하지 않았다.
- 제공된 두 이미지를 직접 비교했다. 목표 이미지는 넓은 SF HUD, 잘린 패널 모서리, 강약이 다른 정보 영역과 결과 목록/상세 구성이며, 현재 Safari 화면은 API 연결 실패가 드러나고 실제 선택 목록은 비활성인 상태였다. 브라우저 탭과 다른 저장소 이름이 포함된 원본 Safari 이미지는 개인정보 및 무관한 저장소 정보 보호를 위해 복사·커밋하지 않았다.

## 기존 폼 및 세로 확장 원인

이전 시작 화면은 검사 설정과 안내 영역을 2열로 두고 부모를 `align-items: stretch`로 배치했다. 안내 패널은 `min-height: 100%`와 `grid-template-rows: minmax(170px, 1fr) auto`를 사용해 짧은 문구 아래에 큰 빈 공간을 만들었다. Safari 캡처에서는 검사 제어 영역도 화면 높이에 맞춰 길게 늘어났다.

새 구조에서는 해당 `.control-stage`, `.launch-hud`, `.scan-toolbar.floating-controls` 레이아웃과 반응형 높이 규칙을 제거했다. 시작 상태는 콘텐츠 높이에 맞는 하나의 가로형 Mission Control 데크와 별도 간결한 안내 스트립을 쓴다. 검사 결과가 있으면 같은 선택 컨트롤을 낮은 높이의 compact 데크로 바꾸고 결과 영역을 앞으로 당긴다. 입력 라벨과 설명은 시작 상태에 남겨두고, 검사 중에는 반복되는 설명을 접어 높이를 줄인다.

## Reference Selection Matrix

| UI 요소 | 실제 확인한 레퍼런스 / 라이선스 | 확인한 특징 | 적용 및 선택 이유 |
|---|---|---|---|
| 프로젝트 선택 | [Origin UI Select/Combobox](https://github.com/shadcn/originui/tree/main/registry/default/ui), [MIT](https://github.com/shadcn/originui/blob/main/LICENSE.md); [shadcn/ui Native Select](https://ui.shadcn.com/docs/components/base/select), [MIT](https://github.com/shadcn-ui/ui/blob/main/LICENSE.md); [Nocturne Select](https://starside-io.github.io/nocturne/), [Apache-2.0](https://github.com/starside-io/nocturne/blob/main/LICENSE) | Origin UI는 입력형 선택 패턴, shadcn Native Select는 브라우저 기본 키보드 조작, Nocturne은 짙은 표면과 장식 화살표를 사용한다. | 네이티브 `<select>`를 유지하고 높이·화살표·색상·포커스만 새 스타일로 구성했다. API allowlist 밖 선택을 만들지 않고 Safari/키보드 동작도 브라우저에 맡긴다. |
| 검사 규칙 선택 | [shadcn/ui Input Group/Field](https://ui.shadcn.com/docs/components/base/input-group), [MIT](https://github.com/shadcn-ui/ui/blob/main/LICENSE.md); [Origin UI Select](https://github.com/shadcn/originui/tree/main/registry/default/ui), MIT; [Nocturne Form Controls](https://starside-io.github.io/nocturne/), Apache-2.0 | 필드와 보조 설명을 한 묶음으로 읽게 하고, 선택 상태를 꾸밈과 분리한다. | 명시적인 `label`, 도움말 ID 연결, 44px 네이티브 선택 컨트롤을 구성했다. 옵션은 기존 API 응답만 표시한다. |
| 인증 토큰 | [Origin UI Input](https://github.com/shadcn/originui/tree/main/registry/default/ui), MIT; [shadcn/ui Input Group](https://ui.shadcn.com/docs/components/base/input-group), MIT; [Nocturne Input](https://starside-io.github.io/nocturne/), Apache-2.0 | 입력·부가 액션·아이콘의 그룹화, 보안 입력의 명확한 역할, 사이버펑크 테두리 대비를 검토했다. | 기존 `type=password`, 메모리 내 상태, 헤더 전송 정책은 그대로 두고 입력과 지우기 액션을 하나의 토큰 콘솔로 묶었다. 새 저장소는 없다. |
| 검사 실행 | [shadcn/ui Button](https://ui.shadcn.com/docs/components/base/button), MIT; [Nocturne Button](https://starside-io.github.io/nocturne/), Apache-2.0; [Magic UI Border Beam/Shine Border](https://magicui.design/docs/components/border-beam), 소스 [MIT](https://github.com/magicuidesign/magicui/blob/main/LICENSE.md) | 역할별 버튼 위계, 비활성 상태, 절제된 선택 강조를 비교했다. | 기존 `<button type=submit>`을 충분한 크기의 단일 primary action으로 배치하고 실제 disabled/loading 상태를 유지했다. CSS 그라디언트만 사용했고 패키지나 동작 없는 장식 버튼은 추가하지 않았다. |
| 시작 화면 | [Nocturne Panel/Status/Section](https://starside-io.github.io/nocturne/), Apache-2.0; [shadcn/ui Blocks](https://ui.shadcn.com/blocks), MIT; [Spaceship Instruction Manual UI / Soft Maximalism / Asymmetrical Balance / Content-First](https://graphicdesignjunction.com/2025/12/web-design-trends-of-2026/) (편집 자료, OSS 라이선스 대상 아님) | Nocturne은 네온 레일·잘린 모서리·색 토큰을, shadcn Blocks는 작업 위계와 빈 상태를, 기사에서는 설명적인 도식·절제된 비대칭·콘텐츠 우선을 설명한다. | 검사 전에는 프로젝트 선택→규칙 검사→근거 검토의 실제 흐름을 짧은 3단계로 보여주는 안내 스트립을 둔다. 가짜 통계·스캔 애니메이션·터미널 출력은 넣지 않았다. |

Origin UI 사이트는 현재 COSS UI로 이동하므로 실제 예제는 [Origin UI GitHub 소스](https://github.com/shadcn/originui)로 확인했다. 프로젝트에는 Origin UI, shadcn/ui, Nocturne, Magic UI 코드를 복사하거나 패키지로 설치하지 않았다. 패턴만 참고하고 기존 React/CSS와 네이티브 요소로 구현해 제3자 고지 의무와 런타임 의존성을 추가하지 않았다. Graphic Design Junction 문서는 검색으로 해당 항목과 요약을 확인했으며, 처음 직접 열기 요청은 시간 초과됐다. 본문이나 자산을 복제하지 않았다.

## 구현 변경

- `App.tsx`: 기존 좌우 늘어나는 시작 폼을 단일 `.mission-deck` 폼으로 교체했다. 프로젝트/규칙 선택, 비밀번호 토큰, 지우기, 제출 버튼을 한 조작 데크에 수평 배치하고 작은 화면에서는 자연스럽게 줄바꿈한다. select에 명시적 접근성 이름을 부여하고 API가 꺼졌을 때 설명 placeholder 및 `다시 연결` 액션을 표시한다. 오류를 숨기거나 연결 성공 상태를 만들지 않는다.
- API 옵션 재시도는 별도 상태 갱신으로 실제 `/health`와 `/options`를 다시 요청한다. 연결될 때까지 선택과 검사 버튼은 계속 비활성이다.
- 시작 설명은 실제 검사 과정과 Finding의 한계를 설명하는 콘텐츠 기반 스트립으로 바꿨다. 장식 SVG는 `aria-hidden`이며 탭 순서에 들어가지 않는다.
- 결과 상태는 Mission Control을 낮게 접어 기존 Finding 목록/상세의 공간을 확보한다. 1280×800에서 첫 목록 행과 상세 시작점이 뷰포트 안에 있는지를 Playwright에서 확인한다.
- `styles.css`: 검사 제어는 비대칭 클립 모서리/부분 색 레일, 서로 다른 3열 구획과 플로팅 액션을 사용한다. 네이티브 select 화살표를 제거해 CSS caret 하나만 표시한다. focus-visible 외곽선을 유지하고 기존 reduced-motion 규칙을 보존했다.
- FastAPI, CLI, 분석 엔진, Evidence, 토큰 저장·전송, 결과 공개 범위는 수정하지 않았다.

## 브라우저 측정과 캡처

Chromium 100% zoom, 합성 API fixture, 지정 viewport를 사용했다. Safari 사용자 이미지는 Before 비교 자료로 직접 검토했으며, 그 화면의 API 오프라인 상태를 실제 성공으로 오해하지 않도록 별도 합성 오프라인 응답으로 재현했다.

1440×900 시작 화면 DOM 측정은 [`bounding-box-1440x900.json`](assets/ui-cyberpunk-control-deck-36-9b-x/bounding-box-1440x900.json)에 있다.

- 헤더: y=0, h=72px
- 페이지 제목: y=79, h=50px
- 접힌 빠른 시작: y=137, h=32px
- Mission Control: y=178, h=194px (width 1377px)
- 시작 안내: y=385, h=165px (width 1377px)
- 안내의 마지막 콘텐츠와 영역 바닥 사이 빈 공간: 18px
- 장식 SVG 안의 포커스 가능 자식: 0

이전 Safari 이미지에는 DOM 측정 도구가 적용되지 않았으므로 이전 패널 높이를 수치로 추정하지 않았다. 기존 CSS에서 확인한 강제 높이 규칙과 실제 화면을 근거로만 비교했다.

검수 캡처:

- 시작 1440×900: [`launch-1440x900.png`](assets/ui-cyberpunk-control-deck-36-9b-x/start/launch-1440x900.png)
- 시작 1920×1080: [`launch-1920x1080.png`](assets/ui-cyberpunk-control-deck-36-9b-x/start/launch-1920x1080.png)
- 사용자 Safari Before: 현재 요청에 첨부된 이미지(다른 탭 정보 보호를 위해 커밋하지 않음); 직전 캡처 비교: [이전 시작 화면](assets/ui-cyberpunk-hud-refinement-36-9b-v/before/launch-1440x900.png)
- 결과 1440×900: [`completed-1440x900.png`](assets/ui-cyberpunk-control-deck-36-9b-x/completed-1440x900.png)
- 결과 1920×1080: [`completed-1920x1080.png`](assets/ui-cyberpunk-control-deck-36-9b-x/completed-1920x1080.png)
- 결과 1280×800: [`completed-1280x800.png`](assets/ui-cyberpunk-control-deck-36-9b-x/completed-1280x800.png)
- 상세 패널: [`finding-detail-panel.png`](assets/ui-cyberpunk-control-deck-36-9b-x/finding-detail-panel.png)
- 필터 결과: [`filtered-high.png`](assets/ui-cyberpunk-control-deck-36-9b-x/filtered-high.png)
- API 연결 실패: [`api-offline-1440x900.png`](assets/ui-cyberpunk-control-deck-36-9b-x/api-offline-1440x900.png)
- 모바일 390×844: [`completed-390x844.png`](assets/ui-cyberpunk-control-deck-36-9b-x/completed-390x844.png)

검수 결과: 색상만 바뀐 것이 아니라 컨트롤의 그룹·정렬·크기, 시작 화면과 결과 화면의 상태별 구조, 빈 패널 높이가 바뀌었다. 1280×800에서 결과 시작 부분이 들어오고, 필드 포커스와 API 실패를 확인했다. 실제 1920 화면은 더 넓은 공간 때문에 아래쪽 여백이 남지만 화면을 강제로 채우는 패널은 없다. 첨부 목표와 같은 방향의 SF 장비 콘솔 조형은 강화됐으나, 실제 Safari에서 새 구현을 실행한 검수는 하지 못했다.

## 검증

| 검사 | 결과 | 근거 |
|---|---|---|
| TypeScript / 프로덕션 빌드 | PASS | `mise exec node@24 -- npm run typecheck`, `mise exec node@24 -- npm run build` |
| Vitest | PASS | 4개 파일, 43개 테스트 |
| Playwright Chromium | PASS | 5개 테스트; 320px, 390×844, 768×1024, 1280×800, 1440×900, 1920×1080; 오버플로·크기·검색·선택·내보내기·초기화·연결 실패/재시도 |
| FastAPI–Semgrep 실제 합성 E2E | PASS | `SEMGREP_REQUIRED=1 mise exec node@24 -- npm run test:e2e:real`; 임시 합성 프로젝트, 실제 FastAPI 및 Semgrep 실행 후 전용 임시 파일 정리 |
| WebKit Playwright | NOT_TESTED | 현재 로컬 Playwright WebKit 실행 파일이 없어 브라우저 설치/다운로드는 하지 않았다. |
| 실제 Safari 수동 수용 검수 | NOT_TESTED | 사용자가 제공한 Before 화면만 확인. After를 실제 Safari에서 수동 확인한 결과가 아님. |
| axe 자동 검사 | NOT_TESTED | `axe-core`가 이미 설치되어 있지 않아 새 의존성을 추가하지 않았다. |
| 접근성 | 부분 확인 | 네이티브 select, label, 탭 순서, focus-visible, 장식 SVG의 비포커스 상태를 Chromium 테스트. WCAG AA 적합성 판정은 아님. |
| 사용자 수용 피드백 | NOT_TESTED | 실제 사용자 After 검수 응답은 아직 없음. |
| `git diff --check` | PASS | 문서·코드 최종 diff에서 수행 예정. |

캡처는 합성 API 응답으로 만들어졌으며 실제 서버 연결 성공이나 실제 취약점 결과를 증명하지 않는다. 스크린샷에 토큰은 password masking 처리되어 있고 값은 synthetic이다.

## 남은 제한과 판정 범위

- 서버가 꺼졌거나 Origin이 허용되지 않으면 대상/규칙 선택이 계속 비활성이다. 시작 화면은 원인과 재시도 방법을 표시하지만 서버 설정을 대신 바꾸지는 않는다.
- WebKit/실제 Safari, axe 및 실제 사용자 수용 검수는 완료되지 않았다.
- 1920×1080 시작 화면은 콘텐츠 기반 높이를 유지해 아래쪽 공간이 남는다. 이를 가짜 대시보드 지표나 고정 높이로 채우지 않았다.
- 검증 범위는 로컬 합성 fixture와 기존 계약에 한정된다. GitHub Intake, Docker Worker, API 계약은 손대지 않았다.

판정: Chromium·합성 FastAPI/Semgrep 기준의 구현 및 시각 검토는 완료했지만, 실제 Safari·사용자 수용은 별도 검수 대상이다.
