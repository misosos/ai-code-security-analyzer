import { randomBytes } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { copyFile, mkdtemp, mkdir, realpath, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const frontendDirectory = resolve(fileURLToPath(new URL('..', import.meta.url)));
const repositoryDirectory = resolve(frontendDirectory, '..');
const port = 8765;
const origin = `http://127.0.0.1:${port}`;
const temporaryDirectory = await mkdtemp(join(await realpath(tmpdir()), 'aicsa-real-browser-e2e-'));
const targetDirectory = join(temporaryDirectory, 'synthetic-project');
const secondTargetDirectory = join(temporaryDirectory, 'synthetic-project-selected');
const rulesDirectory = join(temporaryDirectory, 'trusted-rules');
const token = randomBytes(32).toString('base64url');
const canary = 'SYNTHETIC_BROWSER_CANARY_MUST_NOT_LEAK';
let server;

function assertPortFree() {
  return new Promise((resolvePromise, reject) => {
    const probe = net.createServer();
    probe.once('error', () => reject(new Error('e2e_loopback_port_unavailable')));
    probe.listen(port, '127.0.0.1', () => probe.close((error) => error ? reject(new Error('e2e_loopback_port_unavailable')) : resolvePromise()));
  });
}

async function waitForServer(child) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error('e2e_api_server_failed_to_start');
    try {
      const response = await fetch(`${origin}/api/v1/health`, { signal: AbortSignal.timeout(500), cache: 'no-store' });
      const payload = await response.json();
      if (response.status === 200 && payload.status === 'ok' && payload.service === 'ai-code-security-analyzer') return;
      throw new Error('e2e_api_health_invalid');
    } catch (error) {
      if (error instanceof Error && error.message === 'e2e_api_health_invalid') throw error;
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 150));
    }
  }
  throw new Error('e2e_api_server_start_timeout');
}

async function stopServer(child) {
  if (!child || child.exitCode !== null) return;
  const closed = new Promise((resolvePromise) => child.once('close', resolvePromise));
  try { process.kill(-child.pid, 'SIGTERM'); } catch { child.kill('SIGTERM'); }
  const graceful = await Promise.race([closed.then(() => true), new Promise((resolvePromise) => setTimeout(() => resolvePromise(false), 5_000))]);
  if (!graceful && child.exitCode === null) {
    try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); }
    await closed;
  }
}

try {
  if (process.env.SEMGREP_REQUIRED !== '1') throw new Error('SEMGREP_REQUIRED_must_be_1');
  const semgrep = spawnSync('semgrep', ['--version'], { cwd: repositoryDirectory, encoding: 'utf8' });
  if (semgrep.status !== 0 || semgrep.stdout.trim() !== '1.182.1') throw new Error('required_semgrep_1_182_1_unavailable');
  await assertPortFree();
  await mkdir(targetDirectory);
  await mkdir(secondTargetDirectory);
  await mkdir(join(rulesDirectory, 'experimental'), { recursive: true });
  for (const relativeRule of [
    'security-baseline.yml',
    'experimental/javascript-eval-taint.yml',
    'experimental/javascript-command-injection-taint.yml',
  ]) {
    await copyFile(join(repositoryDirectory, 'rules', relativeRule), join(rulesDirectory, relativeRule));
  }
  await writeFile(join(targetDirectory, 'sample.js'), [
    'function handle(req) {',
    "  const marker = 'SYNTHETIC_BROWSER_CANARY_MUST_NOT_LEAK';",
    "  const childProcess = require('child_process');",
    '  childProcess.exec(req.query.cmd);',
    '}',
    '',
  ].join('\n'), { mode: 0o600 });
  await writeFile(join(secondTargetDirectory, 'selected-project.js'), [
    'function handle(req) {',
    `  const marker = '${canary}';`,
    "  const childProcess = require('child_process');",
    '  childProcess.exec(req.query.cmd);',
    '}',
    '',
  ].join('\n'), { mode: 0o600 });

  server = spawn('uv', ['run', '--locked', 'python', '-m', 'ai_code_security_analyzer.api'], {
    cwd: repositoryDirectory,
    env: {
      ...process.env,
      AI_CODE_SECURITY_TARGETS: JSON.stringify([
        { id: 'synthetic-primary', label: 'Synthetic Primary', path: targetDirectory },
        { id: 'synthetic-selected', label: 'Synthetic Selected', path: secondTargetDirectory },
      ]),
      AI_CODE_SECURITY_RULES_DIR: rulesDirectory,
      AI_CODE_SECURITY_API_TOKEN: token,
      AI_CODE_SECURITY_ALLOWED_ORIGINS: origin,
      SEMGREP_REQUIRED: '1',
      SEMGREP_SEND_METRICS: 'off',
      SEMGREP_ENABLE_VERSION_CHECK: '0',
    },
    detached: process.platform !== 'win32',
    stdio: 'ignore',
  });
  await waitForServer(server);
  const test = spawnSync('npm', ['run', 'test:browser:real'], {
    cwd: frontendDirectory,
    env: {
      ...process.env,
      BROWSER_E2E_BASE_URL: origin,
      BROWSER_E2E_API_TOKEN: token,
      BROWSER_E2E_PRIVATE_PATH: temporaryDirectory,
      BROWSER_E2E_OUTPUT_DIR: join(temporaryDirectory, 'playwright-results'),
      SEMGREP_REQUIRED: '1',
    },
    stdio: 'inherit',
  });
  if (test.status !== 0) throw new Error('real_browser_semgrep_e2e_failed');
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : 'real_browser_semgrep_e2e_failed'}\n`);
  process.exitCode = 1;
} finally {
  await stopServer(server);
  await rm(temporaryDirectory, { recursive: true, force: true });
}
