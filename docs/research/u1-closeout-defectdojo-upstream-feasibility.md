# U1 Closeout — DefectDojo 업스트림 기여 가능성

판정: **`EVIDENCE_INSUFFICIENT`** (코드 변경 PR을 제안할 근거가 없음)

조사 시점: 2026-11-12. 대상: DefectDojo 릴리스 3.5.101(2026-11-11, 커밋 `32aea68`)의 소스와 공개 이슈, PR.

**재현하지 않았다.** 이 문서의 모든 동작 서술은 소스와 이슈를 읽은 결과다. DefectDojo를 실행하거나 보고서를 임포트해 확인한 것은 없다. "~할 것으로 보인다"는 표현은 코드 해석에 따른 예상이다.

## 1. 질문

Semgrep OSS 결과를 DefectDojo 오픈소스판에 반복 임포트할 때, 코드 위치가 바뀐 Finding의 동일성과 검토 상태를 보존하는 문제를 업스트림에 기여할 수 있는가.

## 2. 세 이슈는 서로 다른 결함이다

| 이슈 | 경로 | 원인 | 현재 상태 |
| --- | --- | --- | --- |
| #11227 (2024-11-09) | `import-scan` + `close_old_findings`, 지문 있음 | 닫기 로직이 파서별 알고리즘을 무시하고 `hash_code`만 비교했다. 줄이 바뀌면 해시가 달라져 원본이 mitigated 처리됐다. | 수정됨. `dojo/importers/default_importer.py`의 `get_close_old_findings_queryset`이 알고리즘별로 분기한다. 회귀용 픽스처 `unittests/scans/semgrep/close_old_findings_report_line31.json` 등이 있다. |
| #11480 (2024-12-30) | Semgrep JSON, 로그인 없음 | 모든 Finding의 지문이 `"requires login"`이라 고유 ID가 전부 같았다. | 수정됨. PR #11495(2025-01-15 병합)가 이 값을 "없음"으로 처리한다. |
| #11470 (2024-12-25) | Semgrep 결과를 SARIF 타입으로 재임포트 | #11480과 같은 자리표시자 문제지만 SARIF 파서 경로다. 메인테이너가 #11480의 중복으로 닫았다. | PR #11495는 SARIF 파서를 고치지 않았다. 2026-07에 이슈 #14205에서 Semgrep OSS SARIF로 같은 증상이 다시 보고됐다. PR #15817(2026-08-28 병합)이 "한 보고서 안에서 반복되는 고유 ID는 버린다"로 일반 해결했다. |

세 건 모두 식별자를 잘못 다뤄서 멀쩡한 Finding이 닫힌 버그였다. 줄 이동 자체를 추적하지 못하는 문제와는 다른 결함이다.

## 3. 고유 ID가 없을 때의 실행 경로

3.5.101 기준 호출 관계.

1. `dojo/tools/semgrep/parser.py` — `extra.fingerprint`가 `"requires login"`이면 `unique_id_from_tool`을 설정하지 않는다. `get_description`도 `"requires login"`인 코드 조각을 버리므로 설명에는 규칙 메시지만 남는다.
2. `dojo/settings/settings.dist.py`의 `DEDUPLICATION_ALGORITHM_PER_PARSER` — Semgrep JSON Report는 `unique_id_from_tool_or_hash_code`.
3. 같은 파일의 `HASHCODE_FIELDS_PER_SCANNER` — Semgrep 항목이 없다.
4. `dojo/finding/models.py`의 `compute_hash_code` → `compute_hash_code_legacy` — 항목이 없으면 legacy 해시 `title + cwe + line + file_path + description`을 쓴다.
5. `dojo/importers/default_reimporter.py`의 `match_finding_to_candidate_reimport` — 고유 ID가 없으므로 해시 일치만으로 후보를 찾고, 첫 후보 하나를 사용한다.

따라서 줄 번호가 바뀌면 해시가 달라져 일치하는 후보가 없고, 새 Finding이 생성되며 기존 것은 닫힐 것으로 보인다. 기존 Finding에 붙은 판정과 메모는 새 Finding으로 넘어가지 않는다.

## 4. 줄 번호를 빼는 설정과 그 반례

`DD_HASHCODE_FIELDS_PER_SCANNER`로 Semgrep의 해시 필드에서 `line`을 빼면 줄 이동에는 견딘다. 대신 다음 문제가 생길 것으로 보인다.

- **같은 파일, 같은 규칙의 Finding이 같은 해시가 된다.** 로그인 없는 출력은 코드 조각이 없어 설명이 규칙 메시지뿐이므로, 메시지에 변수가 들어가지 않는 규칙은 충돌한다.
- **두 번째 Finding이 사라진다.** 같은 보고서 안의 두 건이 하나로 합쳐지거나, 이미 따로 저장돼 있던 경우 둘 다 ID가 낮은 쪽에 매칭되고 나머지는 보고서에 없는 것으로 처리돼 닫힌다.
- **판정이 엉뚱한 곳에 적용된다.** 한 건을 오탐으로 표시하면 같은 파일의 다른 실제 취약점이 그 뒤에 가려진다.

`order_reimport_candidates`에 위치 기반 후보 정렬이 있어 일부 완화될 수 있다. 정적 Finding의 줄 번호에 어떻게 작용하는지는 확인하지 못했다.

## 5. 기존 데이터와 해시

- 해시는 한 번 계산되면 다시 계산되지 않는다(`Finding.set_hash_code`). 공식 문서도 중복 제거 설정 변경이 소급 적용되지 않는다고 적는다.
- 설정만 바꾸고 재임포트하면 저장된 해시(줄 포함)와 새 해시(줄 제외)가 전부 어긋나 기존 Finding이 한꺼번에 닫히고 다시 만들어질 것으로 보인다.
- 문서가 안내하는 절차는 설정 변경 직후 `manage.py dedupe --hash_code_only --parser '<파서 이름>'`으로 해시를 다시 계산하는 것이다.
- 재계산을 해도 4절의 충돌은 남는다.

기본값을 바꾸는 PR은 업그레이드하는 모든 사용자에게 이 절차를 요구하게 된다.

## 6. 재현 계획 (실행하지 않음)

픽스처는 이 분석을 한 쪽이 아닌 사람이 만들거나, 업스트림의 기존 픽스처(`close_old_findings_report_line31.json`, `..._second_run_line24.json`)에서 지문을 `"requires login"`으로 바꿔 쓴다. 각 시나리오를 기본 설정과 줄 번호 제외 설정으로 한 번씩 돌린다.

| 시나리오 | 절차 | 기본 설정 예상 | 줄 제외 설정 예상 |
| --- | --- | --- | --- |
| A. 동일 보고서 재임포트 | 같은 파일을 같은 Test에 두 번 | 변경 0건 | 변경 0건 |
| B. 줄 이동 | 31행에서 24행으로 옮긴 보고서를 재임포트 | 기존 1건 닫힘, 새 1건 생성 | 변경 0건 |
| C. 같은 파일의 유사 Finding 2개 | 같은 규칙, 같은 파일, 다른 줄 2건을 임포트한 뒤 재임포트 | 2건 유지 | 1건으로 합쳐지거나 1건 닫힘 |
| D. 검토 상태 보존 | 1건을 오탐 표시하고 메모를 단 뒤 B를 수행 | 판정과 메모가 새 Finding에 없음 | 판정과 메모 유지. C와 결합하면 다른 건을 가림 |

기록할 값: 재임포트 응답의 생성, 닫힘, 변경 없음 건수와 각 Finding의 `hash_code`, 상태, 메모 수. 예상과 다르면 3~5절의 코드 해석이 틀린 것이다.

## 7. PR을 제안하지 않은 이유

- **같은 질문이 이미 열려 있다.** 이슈 #14707 "semgrep: hash code fields"(2026-04-17, 열림)에서 메인테이너는 줄 번호 제거가 SAST 보고서의 고전적인 절충이며, 줄 번호를 위치 정보로 다루는 더 큰 변경을 생각해 볼 수 있다고 답했다. 조사 시점에 반응 0건, 댓글 3건이었다.
- **기본값 변경은 문제를 옮길 뿐이다.** 줄 이동 대신 잘못된 병합이 생기고 기존 사용자 데이터가 흔들린다.
- **제대로 된 해법은 유료 기능과 겹친다.** 줄 이동을 추적하면서 병합을 피하는 것이 DefectDojo Pro의 Location Drift Matching이다.
- **재현 없이는 기여할 내용이 없다.** 가진 것은 코드 해석뿐이다.

## 8. 조건부 최소 기여안

6절의 재현이 예상대로 나온 경우에만 의미가 있고, 코드 변경은 포함하지 않는다.

- Semgrep 파서 문서에 한 단락: 로그인 없는 보고서는 지문이 없어 줄 번호가 포함된 legacy 해시를 쓴다는 점, 줄 번호를 빼는 설정과 부작용, 해시 재계산 절차.
- 또는 이슈 #14707에 시나리오 B, C의 재현 수치를 댓글로 남긴다.

## 9. 확인하지 못한 것

- 3~5절의 모든 런타임 동작
- `order_reimport_candidates`가 정적 Finding에 주는 영향
- 이슈 #14205의 2026-07 보고가 PR #15817로 실제 해결됐는지(PR 설명은 같은 원인을 다루지만 이슈는 조사 시점에 열려 있었다)
- 이슈 #11470의 원인은 메인테이너의 중복 판정을 따랐고 직접 분석하지 않았다

## 출처

- https://github.com/DefectDojo/django-DefectDojo/issues/11227
- https://github.com/DefectDojo/django-DefectDojo/issues/11470
- https://github.com/DefectDojo/django-DefectDojo/issues/11480
- https://github.com/DefectDojo/django-DefectDojo/pull/11495
- https://github.com/DefectDojo/django-DefectDojo/issues/14707
- https://github.com/DefectDojo/django-DefectDojo/issues/14205
- https://github.com/DefectDojo/django-DefectDojo/pull/15817
- https://github.com/DefectDojo/django-DefectDojo/releases/tag/3.5.101
- https://docs.defectdojo.com/triage_findings/finding_deduplication/os__deduplication_tuning/
- https://docs.defectdojo.com/triage_findings/finding_deduplication/pro__location_drift_matching/
