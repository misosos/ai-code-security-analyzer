import { randomBytes } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { chmod, copyFile, mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  allocateLoopbackPort,
  removeOwnedTemporaryDirectory,
  stopProcessGroup,
  waitForHttp,
} from './safariManualQaSupport.mjs';

const frontendDirectory = resolve(fileURLToPath(new URL('..', import.meta.url)));
const repositoryDirectory = resolve(frontendDirectory, '..');
const smokeTest = process.argv.includes('--smoke-test');
const investigationTest = process.argv.includes('--investigation');
const unknownArguments = process.argv.slice(2).filter((argument) => argument !== '--smoke-test' && argument !== '--investigation');
if (unknownArguments.length) {
  process.stderr.write('usage: npm run qa:safari [-- --smoke-test]\n');
  process.exit(2);
}

let temporaryDirectory;
let apiServer;
let viteServer;
let stopping = false;
let resolveStop;
const stopRequested = new Promise((resolvePromise) => { resolveStop = resolvePromise; });
const requestStop = () => {
  stopping = true;
  resolveStop('requested');
};
const onSigint = () => requestStop();
const onSigterm = () => requestStop();
process.once('SIGINT', onSigint);
process.once('SIGTERM', onSigterm);

function spawnDetached(command, args, options) {
  const child = spawn(command, args, { detached: process.platform !== 'win32', ...options });
  child.once('error', () => {});
  return child;
}

function makeChildEnvironment(overrides, removedKeys) {
  const environment = { ...process.env, ...overrides };
  for (const key of removedKeys) delete environment[key];
  return environment;
}

function assertSafeResponse(text, { token, temporaryDirectory }) {
  const canaries = [
    token,
    temporaryDirectory,
    'SAFARI_QA_SYNTHETIC_SOURCE_CANARY',
    'return eval(input);',
  ];
  if (canaries.some((canary) => text.includes(canary))) throw new Error('qa_sensitive_data_exposed');
}

async function runSmoke(apiOrigin, webOrigin, token, projectRoot) {
  const rootResponse = await fetch(webOrigin, { cache: 'no-store' });
  if (rootResponse.status !== 200) throw new Error('qa_dashboard_unavailable');

  const authHeaders = { 'X-Local-API-Token': token, Origin: webOrigin };
  const optionsResponse = await fetch(`${webOrigin}/api/v1/options`, { headers: authHeaders, cache: 'no-store' });
  if (optionsResponse.status !== 200) throw new Error('qa_options_unavailable');
  const optionsText = await optionsResponse.text();
  assertSafeResponse(optionsText, { token, temporaryDirectory: projectRoot });
  const options = JSON.parse(optionsText);
  const targetIds = new Set(options.targets.map((target) => target.id));
  const baselineAvailable = options.rule_profiles.some((profile) => profile.id === 'baseline');
  if (!targetIds.has('safari-synthetic-a') || !targetIds.has('safari-synthetic-b') || !baselineAvailable) {
    throw new Error('qa_registered_targets_invalid');
  }

  const unauthorized = await fetch(`${apiOrigin}/api/v1/scans`, {
    method: 'POST',
    headers: { 'X-Local-API-Token': 'invalid-synthetic-token', Origin: webOrigin, 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_id: 'safari-synthetic-a', rule_profile_id: 'baseline' }),
  });
  if (unauthorized.status !== 401) throw new Error('qa_token_boundary_failed');

  const blockedTarget = await fetch(`${webOrigin}/api/v1/scans`, {
    method: 'POST',
    headers: { ...authHeaders, 'Content-Type': 'application/json' },
    body: JSON.stringify({ target_id: 'not-registered', rule_profile_id: 'baseline' }),
  });
  if (blockedTarget.status !== 404) throw new Error('qa_target_allowlist_failed');

  const scan = async (targetId) => {
    const response = await fetch(`${webOrigin}/api/v1/scans`, {
      method: 'POST',
      headers: { ...authHeaders, 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_id: targetId, rule_profile_id: 'baseline' }),
    });
    if (response.status !== 200) throw new Error('qa_synthetic_scan_failed');
    const text = await response.text();
    assertSafeResponse(text, { token, temporaryDirectory: projectRoot });
    const result = JSON.parse(text);
    if (result.scan_status !== 'completed' || result.completed !== true || result.omitted_finding_count !== 0) {
      throw new Error('qa_synthetic_scan_incomplete');
    }
    return result;
  };
  const projectA = await scan('safari-synthetic-a');
  const projectB = await scan('safari-synthetic-b');
  const projectAFiles = new Set(projectA.findings.map((finding) => finding.file_path));
  const projectAIds = new Set(projectA.findings.map((finding) => finding.finding_id));
  if (
    projectA.finding_count !== 2 || projectA.displayed_finding_count !== 2 ||
    projectAIds.size !== 2 || !projectAFiles.has('stable.js') || !projectAFiles.has('review.js') ||
    projectB.finding_count !== 0 || projectB.displayed_finding_count !== 0
  ) {
    throw new Error('qa_synthetic_findings_unexpected');
  }
  process.stdout.write(`QA smoke passed: Project A=${projectA.finding_count} findings, Project B=0 findings; auth/allowlist passed.\n`);
}

async function updateSyntheticProject(projectPath) {
  await writeFile(join(projectPath, 'retired.js'), 'function review(input) { return String(input); }\n', { mode: 0o600 });
  await writeFile(join(projectPath, 'added.js'), 'function added(input) { return eval(input); }\n', { mode: 0o600 });
}

async function runInvestigationSmoke(apiOrigin, webOrigin, token, projectPath, privateRoot) {
  const headers = { 'X-Local-API-Token': token, Origin: webOrigin, 'Content-Type': 'application/json' };
  const post = (path, body, suppliedHeaders = headers) => fetch(`${webOrigin}${path}`, {
    method: 'POST', headers: suppliedHeaders, body: JSON.stringify(body), cache: 'no-store',
  });
  const denied = await post('/api/v2/investigation-scans', { target_id: 'safari-synthetic-a', rule_profile_id: 'baseline' }, { ...headers, 'X-Local-API-Token': 'incorrect' });
  if (denied.status !== 401) throw new Error('qa_token_boundary_failed');
  const scan = async () => {
    const response = await post('/api/v2/investigation-scans', { target_id: 'safari-synthetic-a', rule_profile_id: 'baseline' });
    if (response.status !== 200) throw new Error('qa_investigation_scan_failed');
    const text = await response.text();
    assertSafeResponse(text, { token, temporaryDirectory: privateRoot });
    const payload = JSON.parse(text);
    if (payload.contract_version !== 'investigation-scan/v1' || payload.scan.scan_status !== 'completed' || payload.scan.finding_count !== 2) throw new Error('qa_synthetic_findings_unexpected');
    return payload;
  };
  const baseline = await scan();
  if (!baseline.scan.findings.some((f) => f.file_path === 'stable.js') || !baseline.scan.findings.some((f) => f.file_path === 'retired.js')) throw new Error('qa_synthetic_findings_unexpected');
  await updateSyntheticProject(projectPath);
  const current = await scan();
  if (!current.scan.findings.some((f) => f.file_path === 'stable.js') || !current.scan.findings.some((f) => f.file_path === 'added.js')) throw new Error('qa_synthetic_findings_unexpected');
  const sessionResponse = await post('/api/v2/investigations', { baseline_handle: baseline.run_handle, current_handle: current.run_handle });
  if (sessionResponse.status !== 201) throw new Error('qa_investigation_session_failed');
  const session = await sessionResponse.json();
  const evaluationResponse = await post('/api/v2/investigations/evaluate', { investigation_handle: session.investigation_handle });
  if (evaluationResponse.status !== 200) throw new Error('qa_investigation_evaluation_failed');
  const text = await evaluationResponse.text();
  assertSafeResponse(text, { token, temporaryDirectory: privateRoot });
  const evaluation = JSON.parse(text);
  for (const category of ['shared', 'baselineOnly', 'currentOnly']) if (evaluation.findings.filter((f) => f.category === category).length !== 1) throw new Error('qa_investigation_categories_invalid');
  if (evaluation.overall_assessment !== 'UNDETERMINED' || !evaluation.limitation_codes.includes('source_snapshot_not_collected')) throw new Error('qa_investigation_assessment_invalid');
  if ((await post('/api/v2/investigation-release', { kind: 'investigation', handle: session.investigation_handle })).status !== 204) throw new Error('qa_release_failed');
  if ((await post('/api/v2/investigations/evaluate', { investigation_handle: session.investigation_handle })).status !== 404) throw new Error('qa_release_reuse_failed');
  for (const handle of [baseline.run_handle, current.run_handle]) if ((await post('/api/v2/investigation-release', { kind: 'run', handle })).status !== 204) throw new Error('qa_release_failed');
  process.stdout.write('Investigation QA smoke passed: A/B -> A/C; shared=1 baselineOnly=1 currentOnly=1; released.\n');
}

try {
  if (investigationTest && !smokeTest && (!process.stdout.isTTY || !process.stdin.isTTY)) throw new Error('qa_interactive_terminal_required');
  if (investigationTest && Number(process.versions.node.split('.')[0]) !== 24) throw new Error('qa_required_node_24_unavailable');
  if (investigationTest) {
    const python = spawnSync('uv', ['run', '--locked', 'python', '--version'], { cwd: repositoryDirectory, encoding: 'utf8' });
    if (python.status !== 0 || python.stdout.trim() !== 'Python 3.12.7') throw new Error('qa_required_python_3_12_7_unavailable');
  }
  const semgrep = spawnSync('semgrep', ['--version'], { cwd: repositoryDirectory, encoding: 'utf8' });
  if (semgrep.status !== 0 || semgrep.stdout.trim() !== '1.182.1') throw new Error('qa_required_semgrep_1_182_1_unavailable');

  temporaryDirectory = await mkdtemp(join(await realpath(tmpdir()), 'ai-csa-safari-manual-'));
  const projectAPath = join(temporaryDirectory, 'project-a');
  const projectBPath = join(temporaryDirectory, 'project-b');
  const trustedRulesPath = join(temporaryDirectory, 'trusted-rules');
  await Promise.all([mkdir(projectAPath, { mode: 0o700 }), mkdir(projectBPath, { mode: 0o700 })]);
  await mkdir(trustedRulesPath, { mode: 0o700 });
  const ruleSource = join(repositoryDirectory, 'rules', 'security-baseline.yml');
  const ruleTarget = join(trustedRulesPath, 'security-baseline.yml');
  await copyFile(ruleSource, ruleTarget);
  await chmod(ruleTarget, 0o600);
  await writeFile(join(projectAPath, 'stable.js'), [
    'function stable(input) {',
    '  return eval(input);',
    '}',
    '// SAFARI_QA_SYNTHETIC_SOURCE_CANARY',
    '',
  ].join('\n'), { mode: 0o600 });
  await writeFile(join(projectAPath, investigationTest ? 'retired.js' : 'review.js'), [
    'function review(input) {',
    '  return eval(input);',
    '}',
    '',
  ].join('\n'), { mode: 0o600 });
  await writeFile(join(projectBPath, 'safe.js'), [
    'function safe(input) {',
    '  return String(input);',
    '}',
    '',
  ].join('\n'), { mode: 0o600 });

  const apiPort = await allocateLoopbackPort();
  const frontendPort = await allocateLoopbackPort([apiPort]);
  const apiOrigin = `http://127.0.0.1:${apiPort}`;
  const webOrigin = `http://127.0.0.1:${frontendPort}`;
  const token = randomBytes(32).toString('base64url');
  const apiEnvironment = makeChildEnvironment({
    AI_CODE_SECURITY_TARGETS: JSON.stringify([
      { id: 'safari-synthetic-a', label: 'Safari QA 합성 프로젝트 A', path: projectAPath },
      { id: 'safari-synthetic-b', label: 'Safari QA 합성 프로젝트 B', path: projectBPath },
    ]),
    AI_CODE_SECURITY_RULES_DIR: trustedRulesPath,
    AI_CODE_SECURITY_API_TOKEN: token,
    AI_CODE_SECURITY_ALLOWED_ORIGINS: webOrigin,
    SEMGREP_REQUIRED: '1',
    SEMGREP_SEND_METRICS: 'off',
    SEMGREP_ENABLE_VERSION_CHECK: '0',
  }, ['AI_CODE_SECURITY_TARGET']);
  const apiEntrypoint = [
    'import sys, uvicorn',
    'from ai_code_security_analyzer.api.app import create_app_from_env',
    "uvicorn.run(create_app_from_env(investigation_api_enabled=" + (investigationTest ? "True" : "False") + "), host='127.0.0.1', port=int(sys.argv[1]), access_log=False, reload=False, workers=1)",
  ].join('; ');
  apiServer = spawnDetached('uv', ['run', '--locked', 'python', '-c', apiEntrypoint, String(apiPort)], {
    cwd: repositoryDirectory,
    env: apiEnvironment,
    stdio: 'ignore',
  });
  await waitForHttp(`${apiOrigin}/api/v1/health`, async (response) => {
    if (response.status !== 200) return false;
    const health = await response.json();
    return health.status === 'ok' && health.service === 'ai-code-security-analyzer';
  }, { child: apiServer, isStopping: () => stopping });

  const viteEnvironment = makeChildEnvironment({ AI_CSA_API_PROXY_TARGET: apiOrigin }, [
    'AI_CODE_SECURITY_API_TOKEN', 'AI_CODE_SECURITY_TARGET', 'AI_CODE_SECURITY_TARGETS',
    'AI_CODE_SECURITY_RULES_DIR', 'AI_CODE_SECURITY_ALLOWED_ORIGINS',
  ]);
  viteServer = spawnDetached('npm', ['run', 'dev', '--', '--host', '127.0.0.1', '--port', String(frontendPort), '--strictPort'], {
    cwd: frontendDirectory,
    env: viteEnvironment,
    stdio: smokeTest || investigationTest ? 'ignore' : 'inherit',
  });
  await waitForHttp(webOrigin, async (response) => response.status === 200, {
    child: viteServer,
    isStopping: () => stopping,
  });

  if (investigationTest && !smokeTest) {
    const probe = await fetch(`${webOrigin}/api/v2/investigations/evaluate`, {
      method: 'POST', cache: 'no-store',
      headers: { 'X-Local-API-Token': token, Origin: webOrigin, 'Content-Type': 'application/json' },
      body: JSON.stringify({ investigation_handle: 'A'.repeat(43) }),
      signal: AbortSignal.timeout(5_000),
    });
    if (probe.status !== 404 || (await probe.json()).error !== 'evidence_unavailable') throw new Error('qa_investigation_api_unavailable');
  }

  if (smokeTest) {
    if (investigationTest) await runInvestigationSmoke(apiOrigin, webOrigin, token, projectAPath, temporaryDirectory);
    else await runSmoke(apiOrigin, webOrigin, token, temporaryDirectory);
  } else if (!stopping) {
    process.stdout.write('\nSafari 수동 QA 서버가 준비됐습니다. 아래 주소와 토큰은 이 터미널에서만 사용하세요.\n');
    process.stdout.write(`접속 주소: ${webOrigin}\n`);
    process.stdout.write('로컬 API 토큰: ' + token + '\n');
    process.stdout.write('토큰을 채팅, 문서, 스크린샷에 복사하지 마세요. 검수 후 Ctrl+C로 종료하세요.\n');
    if (investigationTest) {
      process.stdout.write('기준 검사를 저장한 뒤 이 터미널에서 Enter를 눌러 합성 A/B를 A/C로 변경하세요.\n');
      process.stdin.resume();
      process.stdin.once('data', async () => {
        try { await updateSyntheticProject(projectAPath); process.stdout.write('합성 프로젝트가 A/C로 변경됐습니다. 재검사를 실행하세요.\n'); }
        catch { process.stderr.write('qa_fixture_update_failed\n'); requestStop(); }
      });
    }
    const unexpectedExit = new Promise((resolvePromise) => {
      apiServer.once('close', () => resolvePromise('api'));
      viteServer.once('close', () => resolvePromise('frontend'));
    });
    const exitReason = await Promise.race([stopRequested, unexpectedExit]);
    if (exitReason !== 'requested') throw new Error('qa_service_stopped');
  }
} catch (error) {
  const code = error instanceof Error && /^qa_[a-z0-9_]+$/.test(error.message) ? error.message : 'qa_start_failed';
  process.stderr.write(`${code}\n`);
  process.exitCode = 1;
} finally {
  if (investigationTest && !smokeTest) process.stdin.pause();
  process.removeListener('SIGINT', onSigint);
  process.removeListener('SIGTERM', onSigterm);
  await Promise.all([stopProcessGroup(viteServer), stopProcessGroup(apiServer)]);
  if (temporaryDirectory) {
    try {
      await removeOwnedTemporaryDirectory(temporaryDirectory);
      process.stdout.write('qa_cleanup=complete\n');
    } catch {
      process.stderr.write('qa_cleanup_failed\n');
      process.exitCode = 1;
    }
  }
}
