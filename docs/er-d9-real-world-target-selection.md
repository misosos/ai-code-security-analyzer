# ER-D9 실제 대상 선정

대상은 [mde/ejs](https://github.com/mde/ejs), 소유자는 `mde`, 고정 커밋은 [`88bd19074205f01df65dc9f118fb1a0000c40ec8`](https://github.com/mde/ejs/tree/88bd19074205f01df65dc9f118fb1a0000c40ec8)이다. GitHub 메타데이터와 저장소의 [LICENSE](https://github.com/mde/ejs/blob/88bd19074205f01df65dc9f118fb1a0000c40ec8/LICENSE)에서 Apache-2.0을 확인했다.

검사 범위는 `lib/esm`의 JavaScript 3개 파일과 해당 디렉터리의 `package.json`이다. 저장소를 빌드하거나 패키지를 설치하거나 테스트·애플리케이션 코드를 실행하지 않았다. Semgrep OSS 1.182.1과 이 저장소의 로컬 `security-baseline.yml`을 사용했다.

수정하지 않은 upstream 원본의 v1 검사는 정상 완료됐고 Finding 2건이 보고됐다. 둘 다 `baseline.javascript-dynamic-eval`, 도구 심각도 `high`, 상대 경로 `ejs.js`다.

| Finding ID | 원본 위치 | 의미 |
| --- | --- | --- |
| `semgrep:201a45ca43b1845bea078056` | [ejs.js:103](https://github.com/mde/ejs/blob/88bd19074205f01df65dc9f118fb1a0000c40ec8/lib/esm/ejs.js#L103) | 규칙 패턴 매치, 취약점 확정 아님 |
| `semgrep:af4fd1e564514346a7cc6445` | [ejs.js:655](https://github.com/mde/ejs/blob/88bd19074205f01df65dc9f118fb1a0000c40ec8/lib/esm/ejs.js#L655) | 규칙 패턴 매치, 취약점 확정 아님 |

재현 하네스는 pinned Git checkout을 임시 폴더에 만들고, 검사 대상 사본과 규칙 사본을 각각 별도로 만든다. 원본 checkout의 Git 상태는 종료 전 깨끗한지 확인한다. 통제 변경은 upstream에 존재한다고 주장하지 않으며 저장소 원본이나 원격에 적용하지 않는다. 기존 합성 테스트 자료는 이 실제 대상과 별도다. 기본 규칙 3종은 제한된 패턴만 관찰하며 이 사례의 실제 악용 가능성을 평가하지 않는다.
