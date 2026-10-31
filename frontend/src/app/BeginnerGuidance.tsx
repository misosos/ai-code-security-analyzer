import type { ScanResponse } from '../api/types';

type HelpText = { title: string; description: string; nextStep: string };

const statusHelp: Record<string, HelpText> = {
  semgrep_not_installed: { title: '검사 도구를 찾지 못했습니다.', description: '검사 서버에서 Semgrep을 사용할 수 없습니다.', nextStep: '서버 실행 환경과 설치 안내를 확인한 뒤 다시 검사하세요.' },
  semgrep_timeout: { title: '검사 시간이 초과됐습니다.', description: '허용된 시간 안에 검사가 끝나지 않았습니다.', nextStep: '프로젝트의 검사 범위와 실행 환경을 확인한 뒤 다시 검사하세요.' },
  semgrep_output_limit: { title: '검사 결과가 출력 한도를 넘었습니다.', description: '결과가 정해진 크기를 넘어 전체 결과를 처리하지 못했습니다.', nextStep: '실행 환경과 프로젝트 검사 범위를 관리자와 확인한 뒤 다시 검사하세요.' },
  invalid_json: { title: '검사 결과를 읽을 수 없습니다.', description: '검사 도구가 반환한 결과 형식을 분석기가 이해하지 못했습니다.', nextStep: '도구 버전과 서버 실행 상태를 확인한 뒤 다시 검사하세요.' },
  semgrep_failed: { title: '검사 도구 실행에 실패했습니다.', description: '검사 도구가 정상 완료되지 않았습니다. 이 화면에는 자세한 오류 내용이 제공되지 않습니다.', nextStep: '서버 실행 환경을 확인하세요. 자세한 원인은 현재 제공된 정보만으로 알 수 없습니다.' },
  findings_omitted: { title: '일부 검토 후보가 화면에서 생략됐습니다.', description: '화면에는 최대 50건만 표시됩니다. 생략된 항목의 개별 근거 상태는 확인할 수 없습니다.', nextStep: '전체 수와 생략 수를 기록하고, 필요한 경우 분석 담당자에게 전체 검토 방법을 문의하세요.' },
  evidence_unavailable: { title: '분석 근거 일부를 확인할 수 없습니다.', description: '현재 결과만으로 해당 근거의 유효성을 확인할 수 없습니다.', nextStep: '표시된 매치 위치와 원본 프로젝트를 직접 확인하세요.' },
  finding_count_not_confirmed_vulnerability_count: { title: '검토 후보 수는 취약점 수가 아닙니다.', description: '표시된 수는 도구가 보고한 Finding 수입니다.', nextStep: '각 후보를 별도로 검토해 실제 취약점 여부를 확인하세요.' },
  scan_result_is_not_safety_proof: { title: '검사 결과는 안전성 증명이 아닙니다.', description: '검사에서 후보가 나오지 않아도 문제가 없다고 확정할 수 없습니다.', nextStep: '검사 범위와 도구가 지원하지 않는 코드 형태도 고려하세요.' },
  scan_partial: { title: '검사가 일부만 완료됐습니다.', description: '일부 파일이나 규칙의 결과가 빠졌을 수 있습니다.', nextStep: '화면에 원인이 제공됐다면 확인하세요. 원인을 알 수 없다면 서버 운영자에게 확인하고, 해결한 뒤 다시 검사하세요.' },
  scan_failed: { title: '검사가 완료되지 않았습니다.', description: '이 결과로 프로젝트의 안전성을 판단할 수 없습니다.', nextStep: '화면에 원인이 제공됐다면 확인하세요. 원인을 알 수 없다면 서버 운영자에게 확인하고, 해결한 뒤 다시 검사하세요.' },
  omitted_findings_not_individually_validated: { title: '생략된 후보는 개별 검증되지 않았습니다.', description: '화면에 표시되지 않은 항목의 근거 상태는 확인할 수 없습니다.', nextStep: '생략된 항목이 있다는 사실을 후속 검토자에게 전달하세요.' },
};

export function describeStatusCode(code: string): HelpText {
  return statusHelp[code] ?? {
    title: '추가 확인이 필요합니다.',
    description: '현재 제공된 정보만으로 자세한 원인을 확인할 수 없습니다.',
    nextStep: '표시된 검사 상태를 기록하고 분석 담당자에게 확인하세요.',
  };
}

export function QuickStart() {
  return <div className="guide-steps-flow">
    <ol className="guide-steps">
      <li><strong>프로젝트 선택</strong><span>서버에 등록된 검사 대상과 규칙 모음을 고릅니다.</span></li>
      <li><strong>검사 실행</strong><span>서버에서 발급한 토큰을 입력해 검사를 시작합니다.</span></li>
      <li><strong>결과 검토</strong><span>발견 항목의 파일 위치와 탐지 근거를 확인합니다.</span></li>
    </ol>
  </div>;
}

export function ServerAdminSettings() {
  return <details className="advanced-setup guide-disclosure">
    <summary>서버 관리자 설정</summary>
    <div className="quick-start-content">
      <h3>빌드된 대시보드와 분석 서버</h3>
      <p>저장소 루트에서 화면과 서버 의존성을 준비합니다.</p>
      <pre><code>{'cd frontend\nnpm ci\nnpm run build\ncd ..\nuv sync --locked --dev'}</code></pre>
      <p>서버 환경에 프로젝트 ID, 표시 이름, 절대 경로와 무작위 토큰을 설정한 뒤 재시작하세요. 생성된 토큰은 터미널에서 한 번 복사해 대시보드에 입력하고, 커밋하거나 공유하지 마세요.</p>
      <pre><code>{`export AI_CODE_SECURITY_TARGETS='[{"id":"app","label":"Application","path":"/absolute/path/to/approved/project"},{"id":"worker","label":"Worker","path":"/absolute/path/to/another/project"}]'
export AI_CODE_SECURITY_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
printf '%s\\n' "$AI_CODE_SECURITY_API_TOKEN"
export AI_CODE_SECURITY_ALLOWED_ORIGINS="http://127.0.0.1:8765"
uv run python -m ai_code_security_analyzer.api`}</code></pre>
      <p>기본 화면은 <code>http://127.0.0.1:8765</code>에서 제공합니다. 기존 단일 프로젝트 설정인 <code>AI_CODE_SECURITY_TARGET</code>도 지원하지만, 두 프로젝트 설정을 동시에 지정하면 서버가 거부합니다.</p>
      <h3>개발용 Vite 화면</h3>
      <p>서버의 허용 출처에 <code>http://127.0.0.1:5173</code>을 추가하고 다른 터미널에서 실행합니다.</p>
      <pre><code>{'cd frontend\nnpm ci\nnpm run dev'}</code></pre>
      <p>두 방식 모두 분석 서버는 <code>127.0.0.1:8765</code>에만 바인딩됩니다. 화면이 서버를 자동 실행하지 않습니다.</p>
    </div>
  </details>;
}

export function SecurityGlossary() {
  const terms = [
    ['검토 후보 (Finding)', '검사 규칙에 일치해 확인이 필요한 항목입니다. 실제 취약점 확정은 아닙니다.'],
    ['심각도 (Severity)', '검사 도구가 규칙에 따라 분류한 수준이며, 실제 악용 여부를 뜻하지 않습니다.'],
    ['미검증 (Unverified)', '실제 취약점인지 아직 확인되지 않은 상태입니다.'],
    ['근거 연결 확인 (Validated Evidence)', 'Finding과 허용된 규칙·검사 근거의 구조적 연결을 확인한 상태입니다. 취약점 확정은 아닙니다.'],
    ['규칙 모음 (Rule Profile)', '한 번의 검사에서 함께 실행하는 규칙의 묶음입니다.'],
    ['Taint', '규칙이 정한 입력 지점에서 위험할 수 있는 사용 지점까지 값이 전달되는지 분석합니다.'],
    ['Source', '규칙이 입력 출발점으로 선언한 코드 형태입니다. 실제 외부 입력이나 위치가 확인됐다는 뜻은 아닙니다.'],
    ['Sink', '규칙이 위험한 사용 지점으로 선언한 코드 형태입니다. 실제 인자 위치가 확인됐다는 뜻은 아닙니다.'],
    ['Trace', '도구가 제공하는 값 전달 경로 정보입니다. Trace가 없다고 데이터 흐름이 없다는 뜻은 아닙니다.'],
    ['Sanitizer', '입력을 변환하거나 제한하는 처리입니다. 이름만으로 실제 안전성이 확인되지는 않습니다.'],
  ];
  return <details className="glossary guide-disclosure">
    <summary>보안 용어 설명</summary>
    <dl>{terms.map(([term, description]) => <div key={term}><dt>{term}</dt><dd>{description}</dd></div>)}</dl>
    <p className="glossary-limit">규칙의 Source/Sink 선언은 실제 코드 위치 확인과 다릅니다. 취약점 여부는 매치 위치와 근거를 별도로 검토해야 합니다.</p>
  </details>;
}

export function ScanStatusGuidance({ scan }: { scan: ScanResponse }) {
  const needsAttention = scan.scan_status === 'partial' || !scan.completed;
  const statusText = scan.scan_status === 'partial'
    ? '부분 검사입니다. 일부 파일이나 규칙의 결과가 빠졌을 수 있습니다.'
    : '검사를 완료하지 못했습니다. 이 결과만으로 안전성을 판단할 수 없습니다.';
  const informationalLimitations = new Set(['finding_count_not_confirmed_vulnerability_count', 'scan_result_is_not_safety_proof']);
  const codes = [...new Set([...scan.issues, ...scan.limitations.filter((code) => !informationalLimitations.has(code))])];
  return <>
    {needsAttention && <section className={`beginner-summary ${scan.scan_status === 'partial' ? 'partial' : 'failed'}`} aria-label="쉬운 검사 결과 설명">
      <span className="summary-mark" aria-hidden="true">{scan.scan_status === 'partial' ? '!' : scan.completed ? 'i' : '×'}</span>
      <div><h3>{statusText}</h3></div>
    </section>}
    {codes.length > 0 && <details className="limitations panel" aria-label="검사 상태와 다음 행동">
      <summary>검사 문제와 다음 조치 <span>{codes.length}</span></summary>
      <div className="status-help-list">{codes.map((code) => {
        const help = describeStatusCode(code);
        return <article className="status-help" key={code}>
          <h4>{help.title}</h4><p>{help.description}</p><p><strong>다음 행동:</strong> {help.nextStep}</p>
          <details><summary>기술 코드 보기</summary><code>{code}</code></details>
        </article>;
      })}</div>
    </details>}
  </>;
}
