# Phase 3C-4: Evidence-Based Markdown Analyst Report

## 목적

`review-md`는 기존 Gate → EvidenceSummary → Consumer 경로를 통과한 정적 분석 결과를 로컬 Markdown 문서로 보여준다. 취약점 확정 보고서가 아니며 새로운 분석이나 AI 판단을 추가하지 않는다. 사람 대상 이해도 평가는 `NOT_TESTED` 상태다.

## 사용법

표준 출력:

```sh
uv run python -m ai_code_security_analyzer scan \
  --path /path/to/project \
  --rules rules/security-baseline.yml \
  --format review-md
```

새 로컬 파일 생성:

```sh
uv run python -m ai_code_security_analyzer scan \
  --path /path/to/project \
  --rules rules/security-baseline.yml \
  --format review-md \
  --output review-report.md
```

`text`, `json`, `review`는 기존 형식으로 유지된다. `--output`은 `json`과 명시적 `review-md`에만 허용된다. `text`와 `review`는 파일 저장을 거부한다. 하나의 Markdown 실행은 내부 Semgrep 결과 경로를 한 번 사용해 Finding과 TaintEvidence를 함께 받는다.

## 문서 구조와 해석

보고서는 고정 제목과 안전 안내, 검사 상태·완료 여부·버전·전체 Finding 수·심각도 집계를 담은 검사 개요, Finding별 검토 카드, 공통 분석 한계, Consumer의 지원·제한 근거, 분석가 검토 작업으로 구성된다.

- Finding 번호는 표시 순서이며 위험 순위가 아니다.
- Severity는 Semgrep의 분류이고 Finding의 `unverified` 상태와 별개다.
- 지원 claim만 확인된 근거로 표시한다. 제한 claim은 decision과 고정 reason 설명을 유지한다.
- Pattern Finding은 Taint Finding으로 표시하지 않는다.
- Source/Sink 위치, trace, Sanitizer 효과가 지원되지 않으면 해당 claim을 제한 상태로 남긴다.
- 구조적 근거 검증 통과는 코드 의미 또는 취약점 검증을 뜻하지 않는다.
- checklist는 미완료 상태의 분석가 검토 제안이며 완료 기록을 저장하지 않는다.

개별 scan/finding 상태와 별도로 다음 일반 한계를 표시한다: 정상 완료는 코드 안전성을 증명하지 않고, 규칙 해시의 현재 일치는 scan 시점 바이트 동일성을 증명하지 않으며, scan 후 원본 소스가 바뀌지 않았음을 보장하지 않는다.

실패 상태에서는 개별 Finding의 supported claim을 표시하지 않는다. Partial 상태는 일부 경로 또는 규칙이 누락될 수 있음을 강조하고 기존 Gate가 허용한 개별 결과만 제공한다.

## Markdown 주입 처리

Finding ID와 rule ID는 고정 허용 문자 집합을 통과해야 표시한다. 상대 경로와 식별자는 인라인 코드 형식으로 표시하되 backtick, backslash, 제어·format 문자, 줄 구분자를 escape하고 길이를 제한한다. HTML 특수문자도 escape한다. 코드 원문, snippet, Semgrep 메시지, `extra.lines`, stderr, raw JSON/SARIF는 출력 경로에 전달하지 않는다. 사용자 입력에서 링크·이미지·HTML을 생성하는 템플릿은 없다.

이는 출력 텍스트의 고정 처리에 대한 통제다. 모든 Markdown 파서 및 렌더러의 동작을 보증하지는 않는다.

## 파일 저장 경계

보고서 저장은 사용자가 `--output`을 명시해야 한다. 기존 reporter의 검증과 신규 생성 함수를 재사용한다.

- 출력 부모 디렉터리는 이미 존재해야 하고 경로 구성 요소는 symlink가 아니어야 한다.
- 최종 출력이 이미 있거나 symlink이면 거부한다.
- 분석 대상 및 신뢰 규칙 디렉터리 내부 저장은 거부한다.
- `O_CREAT | O_EXCL` 및 지원되는 `O_NOFOLLOW`로 덮어쓰기와 최종 symlink 추적을 막고 권한 `0600`으로 생성한다.
- 생성 오류는 고정된 일반 메시지로 보고하며 파일 경로·예외 원문을 출력하지 않는다.

경로 검증과 생성 사이에 부모 디렉터리가 교체되는 OS 수준 TOCTOU를 완전히 제거하는 snapshot 또는 directory-handle 정책은 구현하지 않았다. 저장은 로컬 검토 목적이며 파일을 자동 공유·업로드하지 않는다. 상대 경로와 규칙 ID도 저장소 구조를 드러낼 수 있으므로 외부 공유 전에 사람이 검토해야 한다.

## 출력 제한과 실패

보고서는 최대 50개 Finding과 최대 512 KiB(UTF-8, 출력 개행 포함)로 제한한다. 전체 수·표시 수·생략 수를 구분하고, 생략된 항목은 개별 검증 상태를 알 수 없으며 안전하다고 판단할 수 없다고 표시한다. 바이트 상한에 걸리면 카드 전체를 생략하고 고정 요약을 사용한다. 근거와 개인정보를 자르거나 일부 claim을 조용히 삭제하지 않는다.

CLI exit code는 기존 scan 상태 정책을 따른다. Markdown 파일 쓰기가 실패하면 출력 경로를 노출하지 않는 일반 오류와 실패 종료 코드를 반환한다. 보고서 저장 실패가 scan 상태를 바꾸지는 않는다.

## 검증 범위와 한계

단위·CLI 테스트는 Taint/Pattern/0건/Partial/Failed/Consumer 실패, claim 제한, Markdown·HTML·제어문자 주입, 파일 덮어쓰기·symlink·경로 제한, 권한과 오류 비노출을 확인한다. Semgrep 통합 검증은 OSS 1.182.1 및 합성 A–L fixture를 사용해 taint 13건과 pattern 11건의 claim 표시를 대조한다.

정적 분석 결과의 의미적 취약점 정확도, 모든 Markdown 구현체의 렌더링 안전성, 사용자 가독성과 실제 사용성은 이 기능의 구조 테스트로 증명되지 않는다. 사람 대상 이해도 평가는 계속 `NOT_TESTED`다.
