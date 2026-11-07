# IND-1A 네이티브 실행 경계 검증

## 실제 환경과 범위

macOS 15.7.7 / build 24G720 / Apple Silicon arm64, Python 3.12.7, Tree-sitter 0.26.0, JavaScript grammar 0.25.0에서 실행했다. Linux 실측은 **`NOT_VERIFIED`**다. 연구 도구 [부모](../scripts/ind1a_isolation.py)·[자식](../scripts/ind1a_worker.py)은 기존 API·ScanService·Registry·CLI에 연결되지 않는다. 보호를 완성한 운영 sandbox가 아니다.

공격자 입력은 JavaScript 데이터로만 전달하며 eval/exec/JS 런타임으로 실행하지 않는다. Node.js 24 `--check`는 고정된 작은 합성 Oracle의 parse-only 확인이며 동적 의미 검증이 아니다.

## 부모가 실제 수행하는 일

- 선택 가능한 worker mode를 닫고 입력을 최대 131,072 bytes로 제한한다. 임의 명령·경로·parser 옵션을 외부 요청에서 받지 않는다.
- 절대 Python 실행 파일, `-I -B`, 제한된 고정 환경, 임시 cwd, `close_fds`, 새 프로세스 그룹을 사용한다. 부모의 canary 환경변수는 자식에 전달되지 않았다.
- stdin/stdout/stderr를 nonblocking selector로 처리한다. stdin 쓰기가 가득 차도 timeout 검사를 계속할 수 있다. stdout+stderr 수집 상한은 합계 16,384 bytes이며 읽기 chunk는 4,096 bytes다. 초과 감지용 chunk 및 OS pipe buffer의 생산량까지 정확히 그 값으로 묶는다는 뜻은 아니다. raw stderr는 결과에 보존하지 않는다.
- wall clock 초과나 출력 초과 시 테스트 소유 프로세스 그룹에 SIGKILL을 보내고 wait/reap한다. 비정상 exit·signal·잘못된 JSON·닫힌 결과 계약 위반은 정상 0건으로 반환하지 않는다.
- 새 자식의 core dump 0, CPU soft/hard 1/2초, 주소 공간 512 MiB, open files 64 설정을 native import 전에 시도한다. **getrlimit 값 또는 설정 성공만으로 실제 강제를 주장하지 않는다.**
- 응답은 고정 버전, 상태·진단 allowlist, 관찰 수, 원문을 제외한 범위, 항상 UNVERIFIED인 검증 상태를 확인한다. 실패 결과에 예전 관찰을 재사용하지 않는다.

Popen 생성 자체, OS 스케줄링 지연, uninterruptible kernel 상태까지 엄밀한 실시간 상한으로 보장하는 것은 아니다. 부모 자체의 crash, 전체 프로세스 트리 자원 총량, 동일 UID 공격자와 native 코드 실행 탈취에 대한 격리는 검증하지 않았다. 별도 프로세스만으로 같은 권한의 파일·네트워크·다른 프로세스 접근을 막을 수 없다.

## 실제 challenge 결과

실제 반환 코드·관찰 수치·n=1 실행 시간은 [안전한 projection](independent-engine-phase1a-observations.json)의 isolation 영역에 있다. JavaScript 소스·raw stderr·PID·토큰·Handle은 포함하지 않는다.

| 시험 | 실제 결과 | 판정 범위 |
| --- | --- | --- |
| 일반 별도 분석 | RETURNED / exit 0 | 제한된 결과 계약 검증 |
| C `sleep(30)` 호출 | WALL_TIMEOUT / -9 / reap | 부모가 협력 체크 없는 native 대기를 중단함 |
| CPU spin | SIGNALLED / -24, SIGXCPU / reap | 해당 자식의 CPU 1초 soft 제한 challenge에서 종료됨 |
| 주소 공간 64 MiB challenge | 설정 실패(None), 추가 128 MiB 할당 도달 | 메모리 제한 **NOT_ENFORCED**, 512 MiB 설정도 실패 |
| 연속 stdout | OUTPUT_LIMIT / -9 / reap | 부모 수집 상한 초과 차단, 원문 저장 없음 |
| 자식의 의도적 SIGTERM | SIGNALLED / -15 / reap | 합성 signal 분류, parser fault 재현으로 세지 않음 |
| 자식 exit 7 | NONZERO_EXIT / 7 | 정상 분석으로 승격하지 않음 |
| `{}` 응답 | INVALID_OUTPUT / exit 0 | 프로세스 성공과 유효한 분석 응답을 구분 |
| QA 소유 파일 읽기 | 가능 | 파일 접근 제한 **NOT_ENFORCED** |
| loopback socket bind | 가능 | 네트워크 권한 제한 **NOT_ENFORCED**, 외부 연결은 시도하지 않음 |
| 부모 canary 환경변수 | 상속되지 않음 | 최소 환경 전달만 확인 |
| 과거 progress callback | SIGNALLED / -11, SIGSEGV / reap | 명시적 opt-in의 별도 자식에서 재현 |

메모리 시험은 제한이 작동하지 않아도 추가 할당을 128 MiB에서 종료한다. 반환의 None은 setrlimit 실패를 뜻하며 세부 errno/자유형 예외는 수집하지 않았다. 실패의 커널 내부 원인은 확정하지 않는다. RLIMIT_CORE=0 설정을 확인했지만 OS 자체 crash 진단 파일의 생성 여부까지 전역 조사하지 않았다.

## 과거 충돌과 현재 구현

기준 IND-1의 현재 호출은 `Parser.parse(read_callback)`이며 `progress_callback`을 전달하지 않는다. 재현용 mode는 과거의 작은 고정 합성 입력에만 `progress_callback=lambda ...: False`를 전달했다. 이번 재현의 -11은 shell exit 139와 구별되는 Python subprocess의 signal 반환이다. 세부 C 원인은 확정하지 않았다.

재현용 고정 입력은 아래와 같다. JavaScript로 실행하지 않고 별도 자식의 parser에만 제공했다.

```javascript
function f(x){{let eval=other;eval(x);}eval(x);}
```

일반 pytest는 이 과거 경로를 실행하지 않는다. 하네스와 자식 양쪽에서 명시적인 opt-in을 요구한다. 아래 명령을 선택한 감사 실행에서 한 번 재현했으며, 네이티브 충돌을 기존 회귀의 성공 건수로 집계하지 않는다.

```bash
uv run python scripts/audit_ind1a.py --suite isolation
# 과거 충돌 재현까지 선택할 때만 실행. 현재 엔진의 일반 호출과 다르다.
uv run python scripts/audit_ind1a.py --suite isolation --native-repro
```

callback 제거 후 신규 Oracle의 36개는 모두 정상 응답을 반환했다. 이는 현재 경로에서 관찰된 범위의 사실이며 모든 입력의 무충돌 증명이 아니다. native SIGSEGV/OOM은 Python 예외 처리로 일반 복구할 수 없고, 협력적 timeout은 native 내부를 강제 선점하지 않는다. AST 크기 제한 역시 파싱 후에 적용된다. 고정 버전의 호출 경로는 [py-tree-sitter 바인딩 소스](https://github.com/tree-sitter/py-tree-sitter/blob/v0.26.0/tree_sitter/binding/parser.c)를 함께 검토했다.

현재 macOS에서 하드 메모리 제한을 확보하지 못했으므로 대규모 fuzzing·실제 메모리 고갈·알려지지 않은 대형 crash 입력은 시험하지 않았다. 고정된 작은 corpus와 과거의 작은 충돌 입력만 파싱했다. 메모리 probe도 제한된 추가 할당까지만 수행했다. 이러한 미검증을 네이티브 parser의 안전성 PASS로 바꾸지 않는다.

## 운영체제 차이와 후속 Gate

[Python resource 문서](https://docs.python.org/3.12/library/resource.html)는 자원 종류와 지원을 OS에 의존하는 것으로 정의한다. [Apple의 getrlimit 문서](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getrlimit.2.html)는 RSS 제한을 메모리 압력 시의 정책과 관련해 설명한다. 그것을 하드 메모리 격리로 대체해 주장하지 않는다. 오래된 문서만으로 현재 macOS의 모든 제한을 단정하지 않고 위 실측을 기준으로 삼았다.

[Linux getrlimit 명세](https://man7.org/linux/man-pages/man2/getrlimit.2.html)는 RLIMIT_AS의 virtual address space 제한과 CPU soft/hard 처리 등을 명시한다. virtual address space와 RSS는 다르며 Linux 문서 확인은 Linux에서 이 하네스가 강제됐다는 실행 증거가 아니다. 실제 Linux·컨테이너·cgroup 환경은 NOT_VERIFIED다. 설정 가능한 자원, 전체 자식 트리 총량, 메모리 강제 종료, 응답 처리 및 파일·네트워크 정책을 실제 배포 환경에서 각각 시험해야 한다.

제품 연결은 최소한 다음을 충족할 때까지 차단한다.

1. native fault와 hang이 제품 프로세스에 전파되지 않는 운영 경계 및 fail-closed 결과 계약.
2. 선택한 OS에서 실제로 강제되는 CPU·메모리·출력 제한과 종료·reap 검증.
3. 민감 파일·자격·외부 네트워크·같은 UID 권한의 노출을 줄이는 별도 OS 정책 검증.
4. 지원하지 않는 OS/제한 적용 실패에서 분석을 시작하지 않는 정책.
5. 이번 static binding 결함 수정과 공개 연결의 별도 호환성 승인.
