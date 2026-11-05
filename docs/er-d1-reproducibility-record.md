# ER-D1 재현성 기록

- 관찰 기준 커밋: `f5f1452d4bb3c6bebb9e5d23d7f36ffed17a131c`. CI Run `42017021481`은 push / completed / success, 세 Job 성공, Artifact 0개.
- 로컬 환경: macOS, Python 3.12.7, uv lock, Semgrep 1.182.1, Node.js 24.22.2.
- 실험: 임시 디렉터리의 합성 JavaScript, 신뢰된 로컬 baseline 규칙, FastAPI TestClient와 실제 ScanService / Manifest / Registry / Evaluation. GitHub API와 원격 규칙은 사용하지 않는다.
- 첫 시도는 macOS 임시 경로의 심볼릭 링크를 대상 검증이 거부해 `symlink_path_not_allowed`로 검사 전에 실패했다. `resolve()`로 실제 경로를 사용한 뒤 두 번의 실 Semgrep 검사와 평가가 성공했다.
- 공개 결과는 고정 코드와 합성 파일명, 범주와 상태만 포함한다. 실제 Handle, scan reference, 토큰, Manifest 원문과 원시 출력은 보존하지 않는다.

## 재현 명령

저장소 루트에서 `uv lock --check`와 `semgrep --version`으로 환경과 1.182.1을 확인한다. 아래 명령은 합성 소스와 로컬 규칙을 사용하고 별도 네트워크 서버 없이 TestClient로 HTTP 계약을 통과한다. Semgrep은 실제 프로세스로 실행된다.

```bash
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 uv run --locked python - <<'PY'
import json,tempfile,secrets
from pathlib import Path
from fastapi.testclient import TestClient
from ai_code_security_analyzer.api.app import create_app
from ai_code_security_analyzer.services.scan_service import ApiSettings, ScanService
with tempfile.TemporaryDirectory(prefix='erd1-synthetic-') as d:
 p=Path(d).resolve(); (p/'stable.js').write_text('function stable(input) { return eval(input); }\n'); (p/'retired.js').write_text('function retired(input) { return eval(input); }\n')
 token=secrets.token_urlsafe(32); headers={'X-Local-API-Token':token}; settings=ApiSettings(p,Path('rules').resolve(),token,allowed_hosts=('testserver',)); app=create_app(settings,scan_service=ScanService(settings),investigation_api_enabled=True)
 with TestClient(app) as c:
  def post(path,payload): return c.post('/api/v2/'+path,headers=headers,json=payload)
  request={'target_id':'local-project','rule_profile_id':'baseline'}
  a=post('investigation-scans',request); assert a.status_code==200; baseline=a.json(); assert baseline['scan']['scan_status']=='completed'
  (p/'retired.js').write_text('function retired(input) { return String(input); }\n'); (p/'added.js').write_text('function added(input) { return eval(input); }\n')
  b=post('investigation-scans',request); assert b.status_code==200; current=b.json(); assert current['scan']['scan_status']=='completed'
  same=post('investigations',{'baseline_handle':baseline['run_handle'],'current_handle':baseline['run_handle']}); assert same.status_code==409 and same.json()['error']=='binding_rejected'
  session=post('investigations',{'baseline_handle':baseline['run_handle'],'current_handle':current['run_handle']}); assert session.status_code==201; h=session.json()['investigation_handle']
  ev=post('investigations/evaluate',{'investigation_handle':h}); assert ev.status_code==200; result=ev.json()
  ids={x['finding_id']:x['file_path'] for x in baseline['scan']['findings']+current['scan']['findings']}; rows=[{'file':ids[x['finding_id']],**{k:v for k,v in x.items() if k!='finding_id'}} for x in result['findings']]
  assert {x['category']:x['file'] for x in rows}=={'shared':'stable.js','baselineOnly':'retired.js','currentOnly':'added.js'}; assert result['overall_assessment']=='UNDETERMINED'
  assert post('investigation-release',{'kind':'investigation','handle':h}).status_code==204
  released=post('investigations/evaluate',{'investigation_handle':h}); assert released.status_code==404 and released.json()['error']=='evidence_unavailable'
  for run in (baseline,current): assert post('investigation-release',{'kind':'run','handle':run['run_handle']}).status_code==204
  print(json.dumps({'version':result['contract_version'],'comparability':result['comparability'],'overall_assessment':result['overall_assessment'],'rows':rows,'limitations':result['limitation_codes'],'same_run_status':same.status_code,'same_run_error':same.json()['error'],'released_status':released.status_code,'released_error':released.json()['error']},ensure_ascii=False,indent=2))
PY
```

동일 Run과 Release된 Session의 재사용을 차단하는지도 검증한다. 임시 대상은 종료 시 삭제된다. OS, 규칙, Semgrep 설정이나 부하로 인한 timeout에 따라 같은 결과를 보장하지 않는다.

실제 브라우저 재현은 다음 명령을 사용한다. 기존 테스트는 실제 FastAPI, Semgrep, Chromium을 실행한다. 이는 사용자 Safari 수용과 별개의 자동 테스트다.

```bash
cd frontend
mise exec node@24 -- npm ci
mise exec node@24 -- npm run build
SEMGREP_REQUIRED=1 SEMGREP_SEND_METRICS=off SEMGREP_ENABLE_VERSION_CHECK=0 mise exec node@24 -- npm run test:e2e:real
```

정상 0 Finding과 실패 검사의 구분 및 부분 검사 등은 기존 API·평가기 테스트를 사용한다. 실제 15분 만료와 소스 동일성은 실증하지 않았다.

## 이번 실행 결과

- 위 TestClient 명령을 문서에서 추출해 실행: 성공. `COMPARABLE`, `UNDETERMINED`, 세 범주 각 1건, B의 `PATH_REPORTED_SCANNED`, 코드·규칙 가설 `UNDETERMINED`, 동일 Run 409 및 Release 후 404.
- 실제 FastAPI–Semgrep–Chromium E2E: 3 passed. 초기 시도는 production build가 없어 정적 화면 404로 3건 실패했으며, build 후 다시 실행하여 통과했다. 재현 명령에 build를 포함했다.
- `PYTHONPATH=tests`에서 API, Registry, 평가기, Scan API 집중 시험: 81 passed, 기존 경고 1개. 이 묶음에는 실제 Semgrep 시험과 fake 입력 시험이 함께 있으므로 개별 시험의 성격을 구분한다.
- 문서 전용 변경이므로 전체 Python·Vitest·WebKit·Safari QA는 이번 변경에 대해 재실행하지 않았다. 기준 커밋의 원격 CI는 별도 기록이다.
