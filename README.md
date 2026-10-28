# AI Code Security Analyzer

Python 3.12와 uv로 실행하는 로컬 정적 분석 기반이다. 사용자가 명시한 신뢰된 로컬 Semgrep 규칙 파일로 디렉터리를 분석한다.

```sh
uv run python -m ai_code_security_analyzer scan --path /path/to/project --rules rules/security-baseline.yml --format json
```

`--format`은 `text`(기본값), `json`, `review`를 지원한다. `review`는 Gate와 Evidence Consumer가 검증한 근거 및 제한을 보여주는 분석가용 화면이다. JSON을 새 파일에 저장하려면 `--format json --output /path/to/report.json`을 사용한다. 기존 파일은 덮어쓰지 않으며 review 출력은 파일에 저장할 수 없다. 규칙 파일은 분석 대상 디렉터리 밖에 있어야 하며 원격 규칙과 자동 다운로드는 지원하지 않는다. 자세한 내용은 [분석가 검토 화면 안내](docs/analyst-review-view.md)와 [Phase 3C-2 평가 자료](docs/phase3c2-analyst-review-usability.md)를 참고한다.

| 종료 코드 | 의미 |
| --- | --- |
| 0 | 검사 완료. Finding이 있어도 정상 검사로 취급한다. |
| 1 | 일부 검사 실패 또는 결과 변환 누락. 보고된 Finding은 후보로만 취급한다. |
| 2 | CLI 인자 또는 로컬 경로가 잘못됨. |
| 3 | Semgrep 실행·JSON 처리·보고서 저장 실패 등 전체 실패. |

JSON 보고서의 `status`와 `completed`를 함께 확인한다. `completed=true`는 검사가 완료되었다는 뜻이며 코드가 안전하다는 뜻은 아니다. 모든 Semgrep Finding의 상태는 `unverified`다. 보고서는 원본 코드와 Semgrep 원본 JSON을 포함하지 않는다. 절대 경로 대신 대상 경로의 해시 식별자를 사용한다.

Semgrep은 로컬 규칙, 메트릭 비활성화, 임시 HOME으로 실행된다. CLI 자체는 OS 수준 네트워크 격리를 제공하지 않으므로 신뢰할 수 없는 저장소는 별도의 격리 환경에서 분석해야 한다. [기준 규칙의 범위와 한계](rules/README.md)를 참고한다.

향후 AI 분석용 코드 문맥은 [내부 추출 계약](docs/code-context.md)에 따라 별도로 수집한다. 기존 `scan` 명령과 공개 JSON에는 코드 조각이 포함되지 않는다.

실제 모델 호출 전 [AI 검토 계약과 Fake Provider 검증](docs/ai-review-contract.md)을 사용한다. AI 검토 결과는 기존 Finding의 확정 상태를 변경하지 않는다.
