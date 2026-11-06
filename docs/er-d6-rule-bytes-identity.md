# ER-D6 — 비공개 규칙 바이트 관찰

## 범위

별도 내부 함수 `_scan_with_rule_copy()`는 선택된 baseline 규칙 파일의 바이트를 제한적으로 읽고, 그 바이트를 임시 사본으로 만들어 기존 `SemgrepAdapter`의 조사 verbose 실행에 제공한다. 반환 객체는 해당 실행의 `_ScanOutput`과 비공개 SHA-256 및 독립 실행 식별자를 함께 보유한다. 비교 함수는 두 실행의 target 디렉터리 장치/ inode, profile, private invocation, Semgrep version을 확인한 뒤 선택 파일의 바이트를 비교한다.

이 경로는 API, CLI, `ScanService`, C1 Manifest, C2 Evaluator, C3 Registry에 연결하지 않았다. 기존 v1/v2 경로와 `rule_bytes_unverified`, `loaded_rule_identity_unverified`는 그대로다. 내부 실행 식별자는 `semgrep-json-private-rule-snapshot-v1`이며 기존 Invocation ID로 등록하거나 직렬화하지 않는다.

## 수집과 수명

- 호출자는 신뢰된 rules directory와 분리된 대상 디렉터리를 제공해야 한다. 지원 프로필과 파일명은 `baseline` / `security-baseline.yml`로 제한된다.
- 기존 안전 읽기 함수는 no-follow 파일 열기, 일반 파일, 단일 hard link, 2,000,000-byte 상한, 읽기 전후 stat 확인을 수행한다. 오류는 고정 내부 오류로 반환한다.
- `TMPDIR`을 따르지 않는 POSIX 시스템 임시 디렉터리에 mode `0700` 디렉터리를 만들고, 규칙 파일을 mode `0400`으로 기록한다. 대상·원본 rules 경로와 겹치면 차단한다.
- SHA-256을 읽은 바이트로 계산하고 사본 생성 직후와 Semgrep 종료 뒤 다시 읽어 비교한다. 파일 및 디렉터리의 inode·크기·시간·권한이 바뀌면 거부한다. 기존 Adapter는 사본 디렉터리를 cwd로 하고 같은 상대 파일명을 `--config`에 전달한다.
- `COMPLETED`, exit code 0, 확인된 Semgrep version이 있는 실행만 비교 가능한 digest를 보유한다. `PARTIAL`, 타임아웃, 출력 상한, 비정상 종료, JSON 실패는 결과 상태를 그대로 보존하고 byte 비교는 `UNVERIFIED`로 둔다.
- 사본은 정상 종료와 처리 가능한 예외에서 임시 디렉터리와 함께 삭제된다. 강제 종료나 시스템 장애 시 정리는 보장되지 않는다. 반환 객체의 digest는 Python 메모리에만 있으며 호출자가 객체를 유지하는 동안 존재할 수 있다. Registry TTL이나 secure erase를 보장하지 않는다. 출력·repr에 digest나 원시 바이트를 넣지 않는다.

## 관찰의 의미

`SAME_SELECTED_BYTES` / `DIFFERENT_SELECTED_BYTES`는 두 private 실행에서 고정 사본으로 제공한 단일 파일 바이트 비교다. 자료가 없거나 실행 실패 시 `UNVERIFIED`, 같은 Run 또는 다른 문맥/버전이면 `INCOMPARABLE`이다. 같은 바이트라도 Semgrep의 로딩된 전체 규칙 집합, 환경, 파일별 규칙 적용 또는 취약점 해결을 증명하지 않는다. 주석 변경만으로도 바이트는 달라질 수 있다.

## 신뢰 경계와 잔여 위험

- POSIX의 `/tmp`가 root 또는 현재 사용자 소유이고 쓰기 가능한 공용 디렉터리라면 sticky bit가 있어야 한다. 다른 플랫폼은 닫힌 오류로 처리한다.
- 사본의 `0400`은 동일 사용자나 권한 있는 프로세스에 대한 불변성 보장이 아니다. 검사 전후 stat/hash 검사는 관찰된 교체를 감지하지만, 실행 중 사본을 바꿨다가 복원하는 모든 경쟁을 원자적으로 배제하지 않는다. rules root의 경로 구성요소도 검사와 열기 사이에 경쟁할 수 있다.
- Semgrep이 실제로 읽은 바이트를 커널 수준으로 봉인하거나 내부 loaded rule inventory를 확인하지 않는다. 일반적인 신뢰된 단일 사용자 실행 환경에서의 제한적 연결이다.
- 반환 객체는 신뢰된 내부 호출자 간 자료다. 임의의 Python 객체를 변조할 수 있는 호출자에 대한 인증이나 독립적인 Run provenance를 제공하지 않으며, 기존 Registry와 연결되지 않는다.
- 대상 문맥에 사용하는 device/inode는 로컬 호출 범위의 점검이며 삭제·재생성 후 inode 재사용까지 막는 영속 식별자는 아니다. 장기 보존이나 인증된 API 결합에는 별도 Target/Run binding이 필요하다.
- 파일당 크기는 제한하지만 private 호출의 전체 동시 실행 수와 메모리를 별도로 제한하지 않는다. 호출자가 관찰 객체를 무기한 보유할 수도 있으므로 API에 연결하기 전에 별도 수명·용량 제한이 필요하다.
- 입력은 신뢰된 self-contained baseline YAML과 그 통제된 실험 사본에 한정한다. 상대 참조·다중 파일·외부 설정 의존성은 검증하지 않았고 지원하지 않는다. 호출자 신뢰를 전제로 하며 임의 YAML의 의존성을 완전히 판별하지 않는다.
- Adapter는 metrics/version check를 끄고 임시 HOME과 제한된 환경을 사용한다. 실행 파일 탐색에 기존 `PATH`를 신뢰한다. OS 수준 네트워크 차단이나 악의적인 동일 사용자 프로세스 격리는 제공하지 않는다.
- 원시 규칙, digest, 내부 절대 경로는 공개 응답이나 로그에 추가하지 않는다. Python 메모리와 파일시스템의 즉시 덮어쓰기는 주장하지 않는다.

## 롤백

독립 모듈과 전용 테스트를 제거하면 된다. 기존 Manifest/Registry 저장 자료의 마이그레이션이나 공개 계약 롤백은 필요하지 않다. 새 경로는 제품 API 실행에 연결돼 있지 않다.
