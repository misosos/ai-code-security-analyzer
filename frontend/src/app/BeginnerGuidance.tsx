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
  scan_partial: { title: '검사가 일부만 완료됐습니다.', description: '일부 파일이나 규칙의 결과가 빠졌을 수 있습니다.', nextStep: '함께 표시된 원인을 확인하고, 해결 후 다시 검사하세요.' },
  scan_failed: { title: '검사가 완료되지 않았습니다.', description: '이 결과로 프로젝트의 안전성을 판단할 수 없습니다.', nextStep: '함께 표시된 원인을 확인하고, 해결 후 다시 검사하세요.' },
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
  return <section className="quick-start panel" aria-label="처음 시작하기 안내">
    <details>
      <summary>처음 시작하기</summary>
      <div className="quick-start-content">
        <p>이 대시보드는 서버를 직접 실행하거나 임의 폴더를 열지 않습니다. 검사 서버에 미리 등록된 로컬 프로젝트만 검사합니다.</p>
        <ol>
          <li>검사할 프로젝트를 서버 관리자가 정하고, 서버 실행 전에 그 경로를 등록합니다.</li>
          <li>저장소 루트에서 서버를 실행할 터미널을 엽니다.</li>
          <li>아래 예시에서 프로젝트 경로를 바꾸고, 무작위 토큰을 생성해 서버 환경에 설정합니다.</li>
          <li>빌드된 대시보드는 <code>http://127.0.0.1:8765</code>에서 열립니다. 개발용 Vite 화면은 아래 별도 안내를 따릅니다.</li>
          <li>대시보드에 같은 토큰을 입력하고, 등록된 검사 대상과 규칙 묶음을 선택해 검사를 시작합니다.</li>
          <li>표시된 파일과 위치를 확인하고, 후보인지 취약점이 확인된 것인지 구분해 검토합니다.</li>
        </ol>
        <h3>빌드된 대시보드로 실행</h3>
        <p>저장소 루트에서 먼저 화면 파일을 빌드합니다.</p>
        <pre><code>{'cd frontend\nnpm ci\nnpm run build\ncd ..\nuv sync --locked --dev'}</code></pre>
        <p>그다음 저장소 루트의 서버 터미널에서 실행합니다. 프로젝트 경로를 실제 허용 대상 경로로 바꾸세요. 생성된 토큰은 터미널에 한 번 표시되므로 로컬에서 복사해 대시보드에 입력하고, 저장소에 커밋하거나 공유하지 마세요.</p>
        <pre><code>{'export AI_CODE_SECURITY_TARGET="/absolute/path/to/approved/project"\nexport AI_CODE_SECURITY_API_TOKEN="$(python3 -c \'import secrets; print(secrets.token_urlsafe(48))\')"\nprintf \'%s\\n\' "$AI_CODE_SECURITY_API_TOKEN"\nexport AI_CODE_SECURITY_ALLOWED_ORIGINS="http://127.0.0.1:8765"\nuv run python -m ai_code_security_analyzer.api'}</code></pre>
        <h3>개발용 Vite 화면으로 실행</h3>
        <p>서버 환경의 허용 출처를 <code>http://127.0.0.1:5173</code>으로 설정한 뒤, 다른 터미널에서 실행합니다.</p>
        <pre><code>{'cd frontend\nnpm ci\nnpm run dev'}</code></pre>
        <p>브라우저에서 <code>http://127.0.0.1:5173</code>을 여세요. 두 실행 방식 모두 서버는 <code>127.0.0.1:8765</code>에만 바인딩됩니다. 서버는 UI가 자동 실행하지 않습니다.</p>
      </div>
    </details>
  </section>;
}

export function SecurityGlossary() {
  const terms = [
    ['Finding', '검사 규칙이 찾아낸 검토 후보입니다. 실제 취약점인지 추가 확인이 필요합니다.'],
    ['Severity', '검사 도구가 규칙에 따라 붙인 위험도 분류입니다. 실제 악용 가능성을 확정하지 않습니다.'],
    ['Unverified', '실제 취약점인지 아직 확인되지 않은 상태입니다.'],
    ['Validated Evidence', 'Finding과 허용된 규칙·검사 근거의 구조적 연결을 확인한 상태입니다. 취약점 확정은 아닙니다.'],
    ['Taint', '규칙이 정한 입력 지점에서 위험할 수 있는 사용 지점까지의 값 전달을 검사하는 분석입니다.'],
    ['Source', '규칙이 입력 출발점으로 정한 코드 형태입니다. 실제 외부 입력이나 위치가 확인됐다는 뜻은 아닙니다.'],
    ['Sink', '규칙이 위험할 수 있는 사용 지점으로 정한 코드 형태입니다. 실제 인자 위치가 확인됐다는 뜻은 아닙니다.'],
    ['Trace', '분석 도구가 제공하는 값 전달 경로 정보입니다. 없다고 해서 흐름이 없다는 뜻은 아닙니다.'],
    ['Sanitizer', '입력을 변환하거나 제한하는 처리입니다. 이름만으로 실제 안전 효과가 확인되지는 않습니다.'],
    ['규칙 프로필', '한 번의 검사에서 함께 실행하는 규칙 묶음입니다. 실험용 프로필은 일반 정확도가 충분히 검증됐다는 뜻이 아닙니다.'],
  ];
  return <section className="glossary panel" aria-label="보안 분석 용어 도움말">
    <details>
      <summary>보안 분석 용어 쉽게 보기</summary>
      <dl>{terms.map(([term, description]) => <div key={term}><dt>{term}</dt><dd>{description}</dd></div>)}</dl>
      <p className="glossary-limit">규칙에 선언된 Source/Sink와 실제 코드 위치는 다릅니다. 근거가 검증돼도 취약점은 미확정이며, trace가 없다는 사실은 데이터 흐름 부재를 뜻하지 않습니다.</p>
    </details>
  </section>;
}

export function ScanStatusGuidance({ scan }: { scan: ScanResponse }) {
  const statusText = scan.scan_status === 'partial'
    ? '검사가 일부만 완료됐습니다. 검사되지 않은 부분의 안전성은 확인할 수 없습니다.'
    : !scan.completed
      ? '검사를 완료하지 못했습니다. 검사 결과로 프로젝트의 안전성을 판단하지 마세요.'
      : scan.finding_count > 0
        ? '보안상 확인이 필요한 코드가 발견됐습니다. 실제 취약점인지는 아직 확인되지 않았습니다.'
        : '이번 검사에서 보고된 검토 후보가 없습니다. 프로젝트가 안전하다는 뜻은 아닙니다.';
  const codes = [...new Set([...scan.limitations, ...scan.issues])];
  return <>
    <section className={`beginner-summary ${scan.scan_status === 'partial' ? 'partial' : !scan.completed ? 'failed' : ''}`} aria-label="쉬운 검사 결과 설명">
      <h3>{statusText}</h3>
      {scan.completed && scan.finding_count > 0 && <p>아래 후보는 추가 검토가 필요합니다. 이 도구가 취약점을 확정한 것은 아닙니다.</p>}
    </section>
    {codes.length > 0 && <section className="limitations panel" aria-label="검사 상태와 다음 행동">
      <h3>검사 상태와 다음 행동</h3>
      <div className="status-help-list">{codes.map((code) => {
        const help = describeStatusCode(code);
        return <article className="status-help" key={code}>
          <h4>{help.title}</h4><p>{help.description}</p><p><strong>다음 행동:</strong> {help.nextStep}</p>
          <details><summary>기술 코드 보기</summary><code>{code}</code></details>
        </article>;
      })}</div>
    </section>}
  </>;
}
