# ER-C0 — Finding 소멸 원인 분석 Evidence Contract 설계

## 상태와 범위

- 기준 SHA: **80336f35a699b03f0dd81c606861e5e12298d4b0**
- GitHub Actions Run **41795253631**: push/completed/success, 필수 세 작업 성공, Artifacts 0개
- 산출물: 설계 조사 및 합성 CLI 관찰
- 공개 API, Semgrep 실행 로직, Finding ID, 비교 함수, UI, CI 권한: 변경하지 않음
- ER-C1 구현: 시작하지 않음

이 문서는 이전 검사에 있던 Finding이 현재 검사에 없을 때, 확인 가능한 사실과 열려 있는 설명을 구분한다. Phase 8L의 baselineOnly는 관찰된 ID 집합 차이이며 취약점 수정·해결·안전성 판정이 아니다.

## 1. 연구 질문과 현재 비교 계약

Finding disappearance investigator가 다룰 질문은 다음과 같다.

1. 이전 경로와 규칙이 현재 검사에 실제 포함됐다는 근거가 있는가?
2. 분석기가 처리한 파일 집합과 생략·오류를 어느 수준까지 확인할 수 있는가?
3. 두 검사가 같은 규칙 내용, 엔진 및 설정을 사용했는가?
4. 분석 시점의 파일 바이트를 보존하거나 비교할 수 있는가?
5. 어느 관찰이 검사 결과의 부재를 설명하며 어떤 후보는 열려 있는가?

Phase 8L의 compareScanSnapshots는 정상 완료, 생략 0건, 개수 일관성, 중복 없는 Finding ID, 동일 대상 ID·Rule Profile ID·experimental 설정, 확인 가능한 동일 Semgrep 버전을 요구한다. 그 뒤 정확한 finding_id 문자열로 currentOnly/shared/baselineOnly를 분류한다. 파일 범위·규칙 파일 내용·코드 snapshot은 비교하지 않는다. 이 계약을 원인 판정으로 승격하지 않는다.

semgrep_parser의 Finding ID는 JSON 직렬화한 rule ID, 프로젝트 상대 경로, start/end 행·열로부터 계산한 SHA-256 앞 24자리다. 코드 내용과 검사 실행 ID는 입력에 포함되지 않는다. 같은 ID는 같은 계산 위치 입력을 의미할 뿐 같은 코드를 뜻하지 않는다. 코드 의미가 바뀌어도 위치가 같으면 ID가 유지될 수 있고, 동일 코드가 이동하면 ID가 바뀔 수 있다. 공개 ApiFinding에서는 end 좌표와 열이 제거되어 ID 원재료 전체를 재구성할 수 없다.

## 2. 현재 확보되는 증거와 경계

| 증거 | 실제 위치 | 보존 경계와 의미 |
|---|---|---|
| 요청 대상/Profile ID, 표시명, experimental | 브라우저 ScanContext | 메모리에 현재 응답 문맥으로 보존. 서버 응답에 scan execution ID나 target ID 없음. Profile ID는 선택값이지 rule contents identity가 아님. |
| Semgrep 버전, scan status, 완료 여부, Finding 총/표시/생략 수, 고정 issue/limitation 코드 | ScanResponse | 검사 상태와 aggregate omission은 남지만 처리 파일 목록, 파일별 오류, 서버 실행 시작/종료 시각은 없음. |
| Finding ID, rule ID, severity, kind, 상대 경로/줄, evidence validation, supported/restricted Claim 및 Reason | ApiFinding | 코드 원문과 Semgrep 자유 형식 메시지는 제외. verification_status는 unverified. Claims는 해당 응답 Finding에 연결됨. |
| 실제 실행 인자 | SemgrepAdapter 코드 | scan --json --metrics=off --disable-version-check --oss-only --no-autofix --config <profile 파일명> -- <target>. 실제 argv/설정 지문은 응답에 기록 안 됨. |
| 대상 등록 및 경로 확인 | ScanService | allowlist 디렉터리의 device/inode, 실행 직전 재검증, symlink 거부, 최대 100,000 항목/5초 preflight. OS 격리나 전체 검사 기간의 immutable snapshot은 아님. |
| Semgrep paths.scanned/skipped, skipped_rules, errors | parser 내부 JSON | 현재는 일부 고정 issue만 파생하고 파일별 자료는 버림. 공개 API에는 전달되지 않음. 현재 CLI 실행은 --verbose 미사용. |
| rule file hash | Taint evidence의 제한 경로 | 특정 신뢰된 Taint 선언 검증에서만 파일 상대 ID와 SHA-256 확인. 모든 profile 규칙/실제 loading의 증명이 아니며 일반 pattern 규칙의 공개 hash도 아님. |
| Firestore 파일 byte snapshot | Adapter 내부의 제한 처리 | Firestore 규칙 활성 시 제한된 파일 수/시간/크기로 firestore.rules를 사전 읽고, 특정 매치 파일을 다시 읽어 같은 바이트인지 확인한다. 특정 주석·문자열 필터에만 쓰며 전체 코드 또는 Semgrep 입력 snapshot이 아님. |
| 비교 기준/검토 기록 | 브라우저 메모리 | 기준은 명시적으로 저장. 새 검사 때 검토 기록 초기화, 자동 승계 없음. |

### 파일시스템 경계

등록 시 canonical directory와 device/inode를 기억하고, 검사 직전에 root identity, 겹치는 target, symlink 및 directory walk 제한을 확인한다. 재확인 후 Semgrep이 파일을 읽을 때까지의 race는 제거하지 않는다. 일반 프로젝트는 원본 경로에서 직접 검사된다.

read_regular_file_under_root는 단일 제한 파일 read에서 O_NOFOLLOW/O_DIRECTORY, regular file, nlink=1, 크기 제한 및 전후 stat을 확인한다. 이는 해당 read의 경계를 강화하지만 전체 walk/scan을 원자적으로 만들지 않는다.

## 3. Semgrep 1.182.1 출력의 합성 조사

격리 worktree에서 Semgrep **1.182.1**, 신뢰된 로컬 rules/security-baseline.yml, 임시 합성 JavaScript 파일만으로 실제 CLI를 실행했다. 원본 JSON은 메모리에서 요약 후 폐기했고 임시 디렉터리는 실행 종료 시 정리했다. 코드·raw JSON·로그는 저장소에 남기지 않았다.

| CLI 조건 | 관찰 |
|---|---|
| 현재 Adapter와 같은 비-verbose JSON 옵션, 정상 파일 1개와 .semgrepignore 제외 파일 1개 | Finding 1건, paths.scanned 1개 문자열 상대경로, paths.skipped 필드 없음. 제외 파일은 scanned/skipped 어디에도 나타나지 않음. |
| 동일 synthetic input에 --verbose 추가 | paths.scanned에는 처리 파일, paths.skipped에는 제외 파일 및 semgrepignore_patterns_match가 나타남. |
| 별도 fixture에서 --exclude excluded.js | 해당 파일은 paths.scanned에서 빠졌지만 비-verbose JSON에 skip 상세가 없었음. |

이는 해당 버전·옵션·합성 조건에서 관찰한 값이다. Semgrep upstream JSON interface schema는 scanned를 path array, skipped를 path와 reason이 포함된 구조로 정의한다. Upstream schema는 발전하므로 버전 고정 동작은 별도 1.182.1 fixture로 확인해야 한다. [Semgrep JSON output schema](https://github.com/semgrep/semgrep-interfaces/blob/main/semgrep_output_v1.jsonschema)

해석 제한:

- paths.scanned는 엔진이 JSON에 보고한 처리 경로다. 파일시스템 전체 manifest, 전처리 후보 전체 또는 각 파일의 모든 규칙 분석 성공 증명은 아니다.
- 현재 Adapter는 --verbose를 사용하지 않고 경로별 skip 사유를 저장하지 않는다. verbose synthetic 조건에서 값이 나왔다는 사실은 제품이 수집·보존한다는 뜻이 아니다.
- dotfile, size limit, 언어 불일치, parser/internal error 등 모든 생략이 항상 같은 방식으로 열거된다고 일반화하지 않는다. 출력이 말하지 않는 경로/사유를 Regex나 이름 추측으로 복원하지 않는다.
- skipped_rules/errors는 오류 관찰이지만 모든 규칙이 실제 적용되었다는 증명은 아니다.
- 현재 parser는 일부 내부 issue를 partial로 반영하지만 영향을 받은 파일·규칙을 API에서 연결할 수 없다.

## 4. Evidence Contract v1 초안

권장 식별자: **finding-disappearance-evidence/v1**. 공개 API DTO가 아니라 향후 서버 측의 두 scan record와 내부 증거를 연결하는 버전형 계약이다. 계약 형식 자체가 근거의 진실성을 보장하지 않으므로 source, 수집 상태, validation, 시간 범위를 분리한다.

### 4.1 타입 설계 초안

아래는 비실행 타입 초안이다. 실제 구현은 closed schema와 크기 제한을 가져야 한다.

<pre>
EvidenceStatus =
  OBSERVED | NOT_COLLECTED | UNAVAILABLE | CONFLICTING | NOT_APPLICABLE
EvidenceValidation = VALIDATED | UNVERIFIED | REJECTED
ScanCompletion = completed | partial | execution_failed | not_installed
  | invalid_json | timed_out | output_limit_exceeded

EvidenceRef {
  evidenceId: opaque ID within this contract
  kind: closed enum (SCAN_CONTEXT, RULE_FILE, ENGINE_PATHS, ...)
  scanRef: scan reference
  subjectRef: internal finding/file/rule reference or null
  status: EvidenceStatus
  validation: EvidenceValidation
  source: closed enum (API_RESPONSE, SEMGREP_JSON, TRUSTED_CONFIG, ...)
  capturedAt: timestamp of collection, not scan start time
  value: schema-bounded object or null
  limitations: closed reason codes[]
}

ScanEvidenceRecord {
  scanRef: server-generated random execution ID (not currently available)
  requestedContext: { targetId, ruleProfileId, experimental }
  execution: {
    engine: semgrep
    engineVersion: string|null
    startedAt: timestamp|null
    finishedAt: timestamp|null
    normalizedInvocationId: string|null
    status: ScanCompletion
    findingCount, displayedFindingCount, omittedFindingCount: nonnegative integers
  }
  rules: EvidenceRef[]
  scope: EvidenceRef[]
  snapshot: EvidenceRef[]
  findings: FindingObservation[]
}

FindingObservation {
  scanRef, findingId, ruleId
  filePath: relative path|null
  lineNumber: positive integer|null
  evidenceValidationStatus: validated|rejected|unavailable
  supportedClaims: existing ClaimType[]
  restrictedClaims: [{ claimType, decision, reasonCodes[] }]
}

HypothesisStatus = SUPPORTED | CONTRADICTED | UNDETERMINED | INCOMPARABLE
OverallAssessment = EXPLANATION_SUPPORTED | MULTIPLE_EXPLANATIONS_POSSIBLE
  | UNDETERMINED | INCOMPARABLE

DisappearanceHypothesis {
  cause: closed enum
  status: HypothesisStatus
  evidenceRefs: EvidenceRef IDs[]
  counterEvidenceRefs: EvidenceRef IDs[]
  statementCode: trusted UI message catalog key
  limitations: closed reason codes[]
}

FindingDisappearanceEvidenceV1 {
  contractVersion: finding-disappearance-evidence/v1
  baseline: ScanEvidenceRecord
  current: ScanEvidenceRecord
  findingAssociation: {
    baselineFindingId, currentFindingId|null
    relation: EXACT_ID | POSSIBLE_RELOCATION | AMBIGUOUS | NO_ASSOCIATION
    method: closed enum
  }
  hypotheses: DisappearanceHypothesis[]  // causes may coexist
  overallAssessment: OverallAssessment
  globalLimitations: closed reason codes[]
}
</pre>

### 4.2 의미와 상태 분리

- scanRef는 요청, 실행, 결과 및 수집 자료를 끝까지 bind한다. 현재 서버/API에는 없다.
- requestedContext와 rule evidence를 분리한다. 같은 Profile ID는 같은 규칙 바이트의 증거가 아니다.
- scope는 filesystem discovery, analyzer preflight, engine scanned/skipped, parser/result collection을 각각 둔다. 이를 filesScanned 숫자 하나로 합치지 않는다.
- Finding별 Claim/Reason은 각 scan에 원본 그대로 연결한다. 과거 Claim을 현재로 복사하거나 재평가하지 않는다.
- Evidence status는 수집 상황, validation은 출처/무결성 검증, hypothesis status는 제한된 설명의 적합성이다. 서로 대체하지 않는다.
- NOT_COLLECTED는 “없음”이 아니며 UNAVAILABLE도 “발생하지 않음”이 아니다. 증거 부족은 CONTRADICTED가 아니다.
- EXPLANATION_SUPPORTED는 직접 뒷받침된 좁은 검사 절차 설명만 뜻한다. 취약점 해결이나 유일 원인 판정이 아니다. 인과 주장은 통제된 실험 없이 UNDETERMINED로 둔다.
- 여러 supported 후보는 MULTIPLE_EXPLANATIONS_POSSIBLE, 무효한 문맥/불완전 검사로 비교할 수 없으면 INCOMPARABLE, 자료가 없으면 UNDETERMINED다.
- 자료가 서로 다른 scanRef/target에 귀속되거나 duplicate/missing partition이면 contract 오류 또는 fail-closed 상태다.

권장 언어:

- 명시 skip: “현재 Semgrep JSON은 이전 Finding 경로를 이번 실행에서 제외했다고 보고했습니다. 해당 경로가 처리되지 않았다는 관찰이며, 코드 상태나 다른 경로의 위험 여부를 판단하지 않습니다.”
- 코드 바이트 차이: “보존된 검사 입력 identity가 다릅니다. 이 차이가 Finding 부재의 원인인지는 확인되지 않았습니다.”
- ID만 미관찰: “현재 응답에서 이전 Finding ID를 관찰하지 못했습니다. 검사 범위·규칙·코드 변경 여부를 판단할 근거가 부족합니다.”
- 불완전 검사: “현재 결과는 부분/실패 응답이므로 Finding 부재를 완료된 검사 결과로 해석할 수 없습니다.”

금지: resolved/fixed/closed/remediated, “취약점 해결”, “안전 확인”, 근거 없는 confidence/확률/점수.

## 5. 원인 후보별 필요 근거와 보수적 판단

| 원인 후보 | 필요한 증거 및 현재 확보 가능성 | 확인할 수 있는 사실 / 한계 | 오판 방지 문구 |
|---|---|---|---|
| 이전 파일 경로가 제외됨 | baseline path와 같은 current scanRef의 engine paths.skipped path/reason, schema/version, status/exit. verbose 합성 출력에서 관찰 가능하나 현 Adapter는 verbose 미사용·미보존 | exact 경로가 skip으로 보고됨. 미보고 skip 또는 다른 경로를 완전 배제하지 못함 | “이번 실행이 해당 경로를 제외했다고 보고함” |
| profile 선택 변경 | 요청 profile ID. UI context에는 있으나 서버 run record에는 없음 | 선택값 차이는 알 수 있어도 어떤 rule set이 로드됐고 그 차이가 결과를 일으켰는지는 모름 | “선택한 profile이 달랐음; 영향은 확인되지 않음” |
| 같은 profile ID이나 rule bytes 변경 | 양쪽 config identity/digest 및 실행 중 무결성, engine loading/skipped rules. 특정 Taint 선언만 내부 hash 확인 가능 | 저장된 파일 바이트가 달랐음은 향후 확인 가능. Hash 자체는 실제 loaded/applied 증거가 아님 | “규칙 파일이 달랐음; Finding 부재와의 인과는 미확인” |
| 엔진/실행 설정 변경 | Semgrep version, normalized argv, 안전한 환경 allowlist, engine results. Version만 API에 있음 | 버전/설정 문맥 차이; 동일 버전도 플랫폼/설정 차이가 가능 | “엔진 문맥 차이 관찰” |
| rename/path 이동 | 양쪽 snapshot path, exact content identity, engine 처리 및 rule/match evidence | 동일 bytes가 다른 path에 있었음. Finding 의미 동일성은 별도 | “이동 후보; 같은 보안 이슈인지는 미확인” |
| 코드 바이트 변경 | 분석 입력에 bind된 양 scan content identity. 현재 미수집; Firestore 보조 snapshot만 특수 제한 | 바이트 변화 관찰. 변화가 match 소멸의 원인인지는 증명되지 않음 | “입력 바이트가 달랐으나 영향 미확인” |
| match 위치 이동 | raw match 좌표 양쪽; API에는 상대 경로/시작 줄만, column/end 없음 | 일부 위치 차이. 동일 이슈 이동 추정은 불가 | “보고 위치가 다름” |
| 후처리 필터 차이 | raw Semgrep result와 adapter filtering decision/count/reason. Firestore 주석/문자열 매치는 실제 제거 가능하나 제거 기록 없음 | 현 API에서 엔진 미탐과 adapter filtering을 구분할 수 없음 | “내부 후처리 영향 자료 미수집” |
| 부분/실패/출력 제한 | scan_status, errors, exit, counts. status 및 일부 fixed issue/omitted count 보존 | 검사가 미완료 또는 자료 일부만 반환 | omission이면 부재 판정 차단 |
| omission | 총/표시/생략 count. 개별 생략 Finding은 API에 없음 | 응답이 일부 결과를 뺌. 누락 ID/원인 불명 | “생략으로 비교하지 않음” |
| 동일 조건에서 더 이상 match 없음 | immutable 입력, 실제 동일 rule set/engine, complete scope, 성공 status, 결과 association | 현 시스템은 조건 전체를 증명하지 못함. 통제 실험에서도 특정 scanner/config의 결과 차이만 보임 | “이 조건에서 결과가 재현되지 않음; 취약점 해결은 아님” |

후보들은 상호 배타적이지 않다. 변화가 관찰되어도 그것이 결과 차이를 일으켰다고 말하려면 다른 변수를 고정한 대조 실행이나 원인별 직접 증거가 필요하다.

## 6. Rule Identity, Scan Scope, Snapshot

### Rule Identity

최소 후보: Profile ID, trusted rule path의 저장소 내부 상대 식별자, 규칙 파일 digest, digest 시점(전/후), Semgrep version, CLI 옵션 allowlist, rule config parse/skip/error 결과. 절대경로·규칙본문·환경 전체는 저장하지 않는다.

Digest는 읽은 bytes의 identity일 뿐 Semgrep이 해당 bytes를 실행에 실제 적용했다는 완전한 증거가 아니다. TOCTOU를 줄이려면 trusted config의 제한된 private snapshot을 만들어 scanner가 그 사본을 사용하게 하거나 실행 전후 digest를 대조하는 방안을 검토한다. 모든 참조 설정을 닫힌 집합으로 bind하지 못하면 UNVERIFIED다.

### Scope 증거 단계

1. **filesystem_discovered**: 제한 discovery에서 발견
2. **preflight_accepted**: ScanService allowlist/symlink 검사 통과
3. **engine_scanned**: Semgrep JSON paths.scanned
4. **engine_skipped**: paths.skipped의 path/reason/rule_id
5. **result_collected**: raw result가 parser에서 안전하게 변환·보존

단계 간 차이와 completeness를 따로 기록한다. Preflight 목록을 Semgrep 처리 목록으로 간주하지 않는다. Semgrep JSON이 보고하지 않는 ignore/size classes는 전체 scope completeness를 UNVERIFIED로 둔다. --verbose 사용은 1.182.1 버전별 합성 fixture, JSON 파싱, 출력 bytes/time 제한 검증 후에만 검토한다. raw stderr와 자유형 reason은 출력하지 않고, versioned allowlist reason만 보존한다.

### Snapshot과 TOCTOU

현재 일반 프로젝트에는 snapshot/manifest가 없다. Firestore의 bounded pre/post read는 전체 코드 입력을 대표하지 않는다.

- **전후 manifest**: size/mtime/inode/hash로 다수 변경을 감지할 수 있으나 ABA 변경과 엔진이 실제로 읽은 byte를 증명하지 못할 수 있다. 따라서 scan-time identity는 여전히 UNVERIFIED일 수 있다.
- **읽기 전용 immutable staged copy**: 안전한 no-follow copy를 검사하면 input binding이 강화된다. 그러나 source/secret을 임시 저장하며 gitignore, semgrepignore, symlink, hardlink, special file, copy 중 변경, disk exhaustion, cleanup failure를 처리해야 한다. .git을 제외하면 Semgrep의 Git ignore 동작이 달라질 수 있다.
- 어느 방식도 전체 앱 동작, 런타임 환경, 취약점 여부의 동일성을 증명하지 않는다.

### Hash 개인정보

Raw SHA-256은 추측 가능한 작은 파일을 사전 대입할 수 있고 cross-scan 동일성을 추적하게 할 수 있다. 공개 API/보고서에 내보내지 않는다. 향후 cross-run 비교가 꼭 필요하면 설치별 서버 key HMAC, 키 회전, domain separation, path/content identity 분리, 접근통제, TTL, export 금지와 equality leakage를 검토한다. HMAC도 동일 설치 안에서 동일성 링크를 노출한다. 공개 DTO 수정 전 별도 privacy review가 필요하다.

## 7. Finding association과 판정 상태

원인 후보별 상태는 SUPPORTED, CONTRADICTED, UNDETERMINED, INCOMPARABLE로 구분한다. CONTRADICTED는 동일 시간/대상/관찰 정의에 대해 직접 반대 근거가 검증된 경우에만 쓴다. 단순 수집 실패는 CONTRADICTED가 아니다.

Overall:

- **EXPLANATION_SUPPORTED**: 특정 scan procedure/scope 설명을 직접 뒷받침. 근본 원인 확정/해결 상태가 아님.
- **MULTIPLE_EXPLANATIONS_POSSIBLE**: 복수 가설이 근거와 양립.
- **UNDETERMINED**: 근거 부족 또는 인과 연결 불가.
- **INCOMPARABLE**: 필수 문맥 차이 또는 incomplete/omitted scan으로 부재 비교 부적절. 확인된 개별 관찰은 보존 가능.

초기 association은 exact Finding ID만 확정적으로 쓴다. 이동/rename 후보는 별도 검증 없이는 POSSIBLE_RELOCATION/AMBIGUOUS다. Rule+path+line 유사성만으로 같은 이슈라고 자동 합치지 않는다.

## 8. 보안 위협 모델

| 위협 | 위험 | ER-C1 통제 및 잔여 한계 |
|---|---|---|
| 검사 중 교체/ABA | 기록 snapshot과 engine input 불일치 | immutable input이 아니면 UNVERIFIED/CONFLICTING. 전후 stat만으로 ABA 배제 불가. |
| symlink/rename/path traversal | 경계 밖 파일 접근 또는 identity 혼선 | 기존 검사 유지, descriptor no-follow walk, canonical relative path, target binding 재검증. OS sandbox 아님. |
| Unicode normalization/이름 충돌 | 서로 다른 파일이 하나로 합쳐짐 | 원래 OS path identity, NFC/NFD 구분, collision rejection. 추정 병합 금지. |
| ignore/skip/size/parser 오류 | 미검사를 완료로 오인 | scanned/skipped/errors/partial 계층별 저장. 미보고 생략은 unverified. |
| 파일 수/크기/시간 과다 | CPU/memory/disk/response 소진 | hard caps; 초과 시 제한/거부하고 completeness나 원인판정 금지. |
| content hash 추측/추적 | 파일 내용 추측, 시간간 link | 공개하지 않음, 필요 시 HMAC/retention/key policy. |
| 절대경로/raw stderr/code 노출 | 사용자·OS·소스 정보 노출 | relative ID와 fixed code만 허용, raw JSON/message/stderr 폐기. |
| temp 잔류/cleanup 실패 | 임시 코드/비밀정보 잔존 | private temp, 최소 권한, finally cleanup, 잔류·crash 제한 기록 및 cleanup 검증. |
| run/target 자료 혼합 | 잘못된 finding 원인 연결 | random scanRef, 대상/profile binding, immutable bundle; mismatch면 fail closed. |
| incomplete manifest에 과한 확신 | false “해결” 오판 | completeness를 별도 evidence로 측정; boolean/confidence score 금지. |

## 9. ER-C1 독립 합성 평가 시나리오 18개

Fixture oracle의 조작 의도와 analyzer가 실제로 관찰할 수 있는 증거를 구분한다. 정답은 취약점 상태가 아니라 설명의 정당성이다.

| # | 입력 조건 | 기대 관찰/판정 |
|---:|---|---|
| 1 | 같은 코드·규칙·엔진, 동일 Finding | 두 run의 같은 ID 관찰. 보안 의미 판정은 하지 않음. |
| 2 | 코드 수정 후 Finding 미관찰, 범위 자료 complete | 바이트 변경은 관찰 가능. 통제 rerun 없으면 “변경이 원인”은 UNDETERMINED. |
| 3 | 파일 삭제 | complete immutable manifest에서만 경로 존재/부재 관찰 가능. 검사 전 파일 부재만으로 삭제 원인을 못 정함. |
| 4 | 파일명 변경, bytes 동일 | path change 및 content identity 관찰 시 relocation 후보. 이슈 의미 동일성은 UNDETERMINED. |
| 5 | 파일 위치 이동 | 새 path에서 같은 rule/match 근거도 있어야 연결 후보. heuristic-only는 AMBIGUOUS. |
| 6 | Rule Profile 변경 | 선택값 변경 관찰; 기존 strict comparison은 INCOMPARABLE. 실제 rule 영향은 미확인. |
| 7 | profile ID는 같고 rule bytes 변경 | digest integrity 통과 시 bytes 차이 관찰. loaded-rule/인과 미확인이면 UNDETERMINED. |
| 8 | Semgrep version 변경 | version 차이 관찰 및 INCOMPARABLE. 원인 확정 금지. |
| 9 | 이전 Finding path가 현재 scope에서 제외 | exact path가 현재 paths.skipped에 나타나면 해당 경로 미처리 설명 SUPPORTED. 해결/다른 경로 판정 아님. |
| 10 | ignore 또는 Semgrep skip | 명시 skip reason만 관찰. 목록 미수집이면 NOT_COLLECTED/UNAVAILABLE, “skip 없음” 금지. |
| 11 | partial scan | status/error 관찰, overall INCOMPARABLE 또는 UNDETERMINED. |
| 12 | omitted Finding | 생략 count 확인, 개별 ID 추정 금지, absence 비교 차단. |
| 13 | 검사 중 파일 변경 | 전후/in-engine evidence 충돌 시 CONFLICTING, overall UNDETERMINED. ABA도 별도 평가. |
| 14 | snapshot 불완전/cap 도달 | completeness UNVERIFIED, absence 판정 금지. |
| 15 | 동일 Finding ID지만 코드 bytes 변경 | ID와 content evidence 독립 보존. 코드 의미 동일/보안상태 동일 금지. |
| 16 | 두 가지 이상 원인 가능 | 각 supported 관찰을 나열, overall MULTIPLE_EXPLANATIONS_POSSIBLE, 단일 원인 강제 금지. |
| 17 | 필요한 증거 없음 | 상태별 NOT_COLLECTED/UNAVAILABLE, overall UNDETERMINED, 부족 자료 명시. |
| 18 | 정상 scan, Finding 0건 | 완료와 0건만 표시. 안전·취약점 부재·해결 판정 금지. |

평가지표는 unsupported causal claim 수, 불확실 상황의 올바른 abstention, 증거 연결 무결성, scope completeness, 복수 가설 보존이다. “원인을 맞힌 비율” 하나로 최적화하지 않는다. 사전 고정 oracle은 독립 파일에 두고 실행 결과를 보기 전에 검토한다.

## 10. ER-C1 안전 MVP와 차단 조건

### 구현 후보

1. 공개 API와 Phase 8L comparator는 유지한다.
2. 서버 내부에 random scanRef, 요청 context, 고정 normalized argv ID, Semgrep version/status/exit/time을 bind한다.
3. 실제 Semgrep JSON의 scanned/skipped/skipped_rules/errors만 versioned parser로 제한 수집하고 raw 자유형 문자열은 폐기한다.
4. --verbose 또는 다른 skip 수집법은 Semgrep 1.182.1 fixture와 version tests, resource cap 검증 이후에만 사용한다. JSON이 보고하지 않는 생략이 있으면 scope completeness는 UNVERIFIED.
5. run context mismatch, partial/failure, omission, duplicate IDs, conflicting snapshot이면 원인 판정을 차단 또는 INCOMPARABLE로 둔다.
6. 이전 finding의 exact path가 current explicit skipped list와 일치하고 provenance가 검증될 때만 “현재 실행이 그 경로를 skip했다고 보고”라는 좁은 scan-procedure explanation을 허용한다.
7. 코드 변경/이동, 실제 rule apply, 해결 여부는 직접 근거가 없으면 UNDETERMINED.
8. 내부 저장/보존 기간과 cleanup부터 검증한다. 공개 API/UI는 provenance 검증 이후 별도 설계한다.

### 구현 차단 조건

- scanRef가 request/adapter/result에 끝까지 bind되지 않음
- Semgrep 고정 버전별 scanned/skipped/error fixture 없음
- 미보고 ignore/dotfile/size limit과 complete scope를 구분하지 못함
- rules hash를 actual loaded configuration으로 오해함
- snapshot race, 임시 코드 보존·삭제, resource caps 계획 없음
- digest나 내부 경로가 API/log/report에 노출될 수 있음
- 사전 등록 expected oracle 없는 독립 테스트
- missing evidence를 “원인이 아님” 또는 “해결됨”으로 치환하는 fallback

MVP는 explicit skip 증거가 있는 경우의 좁은 검사 절차 설명과, 나머지의 UNDETERMINED/INCOMPARABLE만 지원해도 충분하다.

## 11. 미구현·미검증

- scan execution ID/manifest 저장, 공개 API, UI 또는 원인 판정기 없음
- 전체 소스 snapshot/일반 파일 digest/immutable scan input 없음
- 일반 rule file digest 및 loaded rule inventory의 scan 간 보존 없음
- 프로덕션 scanned/skipped 경로·사유를 현재 scan record로 보존하지 않음
- 검토 상태/메모를 다음 검사로 승계하지 않음
- 실제 filesystem race/자원고갈 동시성 stress test 미실행
- 조사에 실제 사용자 코드나 비밀정보 미사용
- CLI probe는 Semgrep 1.182.1에서 scanned 및 .semgrepignore verbose skip 한 조건을 확인했을 뿐 모든 skip class의 완전성은 입증하지 않음
- 문서 전용 변경: TypeScript/Python/Chromium/WebKit 전체 테스트 NOT_RUN

## 12. 검증과 결론

- GitHub main, origin/main, 기준 SHA가 모두 80336f35a699b03f0dd81c606861e5e12298d4b0으로 일치.
- Run 41795253631 exact head SHA 일치, push/completed/success. Python/CLI, React dashboard, Semgrep 1.182.1 integration, 실제 FastAPI–Semgrep–Chromium E2E 성공. Artifacts 0개.
- Semgrep 1.182.1 실제 합성 CLI 조사 수행.
- 18개 합성 시나리오에 보수적 관찰/abstention 기대값 정의.
- 제품 코드, API, Workflow 권한 변경 없음.
- 전체 테스트는 문서 전용이므로 NOT_RUN.

현재 시스템은 Finding 관찰 결과를 비교하지만, 왜 사라졌는지 설명할 run-bound scope/config/source snapshot evidence를 저장하지 않는다. ER-C1은 먼저 검사 실행과 Semgrep scope 자료의 provenance를 내부에서 bind해야 한다. 그 전까지 기본적으로 타당한 결론은 UNDETERMINED다.
