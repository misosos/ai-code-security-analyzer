# 확장 코드 문맥 계약 (Phase 2C-1)

## 활성화와 범위

기본 `extract_code_context()`는 변경하지 않았다. 이 기능은 내부 Python API `extract_expanded_code_context(root, finding, end_line=None)`를 명시적으로 호출할 때만 실행되며 scan CLI·공개 scan JSON·실제 Ollama 실행 경로에는 연결되지 않는다. 이 단계에서는 확장 컨텍스트를 이용한 LLM 판단 품질을 측정하지 않았다.

구문 분석은 Tree-sitter 런타임과 공식 JavaScript 및 TypeScript 문법 패키지를 사용한다. `uv.lock`이 실제 버전을 고정한다. Python 의존성은 `tree-sitter`, `tree-sitter-javascript`, `tree-sitter-typescript`이며 각 문법은 MIT 라이선스다. 의존성은 네이티브 휠을 설치하지만 런타임에 parser 다운로드나 외부 서비스 접근을 하지 않는다. 공식 구현: [Tree-sitter Python binding](https://github.com/tree-sitter/py-tree-sitter), [JavaScript grammar](https://github.com/tree-sitter/tree-sitter-javascript), [TypeScript grammar](https://github.com/tree-sitter/tree-sitter-typescript).

지원 확장자는 `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx`다. JS 문법이 JSX를, TypeScript 문법 패키지가 TS와 TSX 파서를 제공한다. 파서가 없거나 구문 오류가 있거나 Finding이 함수·메서드 내부가 아니면 기존 Phase 2A 제한 창을 재사용하고 `fallback_reason`을 기록한다. 정규식이나 중괄호 수 세기로 함수 경계를 추정하지 않는다.

## 고정 상한과 선택 기준

- 입력 파일 1,000,000 bytes (기존 읽기 경계 재사용)
- 확장 결과 최대 40줄 및 12,288 UTF-8 bytes
- 선택된 한 줄 최대 2,048 bytes
- 파일 경로 검증, 제외 경로, `O_NOFOLLOW`, 일반 파일 및 하드 링크 검사는 기존 안전 읽기 함수를 재사용한다.
- 읽기 전후 파일 디스크립터의 device, inode, size, mtime, ctime이 달라지거나 읽은 바이트 길이가 최종 size와 다르면 `file_changed_during_read`로 거부한다.

함수 전체가 상한에 들어오면 해당 동일 함수만 수집한다. 함수가 더 크면 Finding 위치, 그 위치에 걸친 `call_expression` 후보, sink 호출 AST에서 이름이 겹치는 변수 선언과 조건문을 후보로 선택한다. “이름 일치”는 후보 선택 근거일 뿐 reaching definition, aliasing, control-flow dominance, 정제 또는 Source→Sink 관계를 증명하지 않는다. 함수가 부분 선택되면 `truncated`로 표시해 Ollama 요청을 거부한다. AST 오류나 미지원 구문은 기존 제한 문맥으로 되돌린다.

## 내부 근거와 공개 메타데이터

`InternalExpandedCodeContext`는 기존 메타데이터, 줄 번호가 붙은 마스킹 코드, `ExpandedContextMetadata`를 담는다. 확장 메타데이터는 실제 포함 구간과 선택 이유, parser, 누락 범위, 검사하지 않은 외부 함수·다른 파일, `source_flow_verified=false`를 담는다. snapshot SHA-256은 내부 진단용이며 `public_report()`에서 제외된다. 이는 안전하게 읽은 해당 추출 시점의 바이트만 식별한다. Semgrep 실행 시점의 파일 해시를 계약에 보관하지 않으므로 Semgrep이 본 코드와 같은 버전임을 보장하지 않는다. 공개 보고서에는 소스 코드가 포함되지 않는다.

AI 요청을 수동 구성할 때도 `included_line_ranges`는 실제 제공 줄에서 계산되고, `context_selection`은 선택 이유 및 누락 범위를 표시한다. 인접한 범위가 선택 이유 차이로 나뉘어 기록될 수 있지만 실제 입력의 줄 목록이 기준이다. AIReview의 citation validator는 `context.lines`의 실제 줄 사전에서만 인용을 확인하므로 bounding `CodeContext.start_line/end_line` 사이의 미포함 줄은 인용할 수 없다. 참조 검증은 구조적 검사이며 주장의 의미적 정확성을 보장하지 않는다.

마스킹·절단 상태는 확장 이유로 `available`로 바뀌지 않는다. Ollama Provider는 redacted/truncated/unavailable 컨텍스트를 직접 받은 경우도 거부한다. 기본 `run_ollama_review()`는 계속 Phase 2A 추출 경로만 사용한다. 확장 결과의 외부 전송을 승인하거나 활성화하는 기능은 이번 범위에 없다.

## 제한과 후속 평가

Tree-sitter는 구문 구조를 제공하지만 이 모듈은 타입 분석, 전체 제어 흐름, 파일 간/함수 간 호출 그래프, 변수 정의 도달성, sanitization 의미를 검증하지 않는다. parser가 성공해도 의미 분석을 했다는 뜻이 아니다. 선택된 주석과 문자열은 계속 `untrusted_source_code`다. 구문 분석으로 범위를 늘리면 악성 지시문이 포함될 면적도 커질 수 있으며 완전한 prompt injection 방어를 의미하지 않는다.

Phase 2C-2에서 동일한 합성 사례를 기존 제한 정책과 확장 정책 각각에 적용하되 모델·생성 옵션·Finding을 고정하고, 사전에 정한 기대 근거와 실제 제공 줄 목록을 비교한다. AI 판정이 나아졌다고 결론내리기 전에 인용 유효성, 의미적 주장의 수동 검토, 누락 범위 인정 여부를 별도로 기록한다.
