import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, realpath, stat } from 'node:fs/promises';
import { createServer } from 'node:http';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  allocateLoopbackPort,
  removeOwnedTemporaryDirectory,
  stopProcessGroup,
  waitForHttp,
} from './safariManualQaSupport.mjs';

const scriptPath = fileURLToPath(new URL('./run-safari-manual-qa.mjs', import.meta.url));
const frontendDirectory = fileURLToPath(new URL('..', import.meta.url));

test('동적 포트는 loopback에서 열 수 있고 제외한 포트는 재사용하지 않는다', async () => {
  const firstPort = await allocateLoopbackPort();
  const secondPort = await allocateLoopbackPort([firstPort]);
  assert.notEqual(firstPort, secondPort);
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(firstPort, '127.0.0.1', resolve);
  });
  await new Promise((resolve) => server.close(resolve));
});

test('HTTP 준비 확인은 응답 조건을 검증한다', async () => {
  const server = createServer((_request, response) => response.end('ok'));
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  try {
    const response = await waitForHttp(`http://127.0.0.1:${address.port}`, async (candidate) =>
      candidate.status === 200 && (await candidate.text()) === 'ok');
    assert.equal(response.status, 200);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('Vite API 프록시는 비-loopback 대상을 거부한다', () => {
  const viteCli = fileURLToPath(new URL('../node_modules/vite/bin/vite.js', import.meta.url));
  const result = spawnSync(process.execPath, [viteCli, '--host', '127.0.0.1', '--port', '48833', '--strictPort'], {
    cwd: frontendDirectory,
    env: { ...process.env, AI_CSA_API_PROXY_TARGET: 'http://example.invalid:8080' },
    encoding: 'utf8',
    timeout: 15_000,
  });
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}\n${result.stderr}`, /api_proxy_target_must_be_loopback/);
});

test('서버 종료 시 실행 그룹과 QA 소유 임시 폴더를 정리한다', async () => {
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], {
    detached: process.platform !== 'win32',
    stdio: 'ignore',
  });
  await new Promise((resolve, reject) => {
    child.once('spawn', resolve);
    child.once('error', reject);
  });
  await stopProcessGroup(child, 1000);
  assert.ok(child.exitCode !== null || child.signalCode !== null);

  const temporaryRoot = await realpath(tmpdir());
  const ownedDirectory = await mkdtemp(join(temporaryRoot, 'ai-csa-safari-manual-test-'));
  await removeOwnedTemporaryDirectory(ownedDirectory);
  await assert.rejects(stat(ownedDirectory), { code: 'ENOENT' });
  await assert.rejects(removeOwnedTemporaryDirectory(join(temporaryRoot, 'not-owned-directory')), /qa_cleanup_path_not_owned/);
});

test('Safari QA smoke는 실제 API 인증·allowlist·A/B 합성 검사와 종료 정리를 검증한다', { timeout: 240_000 }, async () => {
  const result = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scriptPath, '--smoke-test'], {
      cwd: frontendDirectory,
      env: { ...process.env, SEMGREP_REQUIRED: '1' },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
    child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (code) => resolve({ code, stdout, stderr }));
  });
  assert.equal(result.code, 0, `${result.stderr}\n${result.stdout}`);
  assert.match(result.stdout, /Project A=2 findings, Project B=0 findings; auth\/allowlist passed/);
  assert.match(result.stdout, /qa_cleanup=complete/);
  assert.doesNotMatch(result.stdout + result.stderr, /SAFARI_QA_SYNTHETIC_SOURCE_CANARY|ai-csa-safari-manual-[^\s]+|[A-Za-z0-9_-]{43,}/);
});

async function verifyManualStopSignal(signal) {
  const child = spawn(process.execPath, [scriptPath], {
    cwd: frontendDirectory,
    env: { ...process.env, SEMGREP_REQUIRED: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', (chunk) => { stdout += chunk; });
  child.stderr.setEncoding('utf8').on('data', (chunk) => { stderr += chunk; });
  const ready = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('qa_ready_timeout')), 60_000);
    const inspect = () => {
      if (stdout.includes('접속 주소:') && stdout.includes('로컬 API 토큰:')) {
        clearTimeout(timeout);
        resolve();
      }
    };
    child.stdout.on('data', inspect);
    child.once('error', (error) => { clearTimeout(timeout); reject(error); });
    child.once('close', (code) => {
      if (!stdout.includes('접속 주소:') || !stdout.includes('로컬 API 토큰:')) {
        clearTimeout(timeout);
        reject(new Error(`qa_exited_before_ready:${code}:${stderr}`));
      }
    });
  });
  try {
    await ready;
    const urlMatch = stdout.match(/접속 주소: (http:\/\/127\.0\.0\.1:\d+)/);
    const tokenMatch = stdout.match(/로컬 API 토큰: ([A-Za-z0-9_-]{43})/);
    assert.ok(urlMatch);
    assert.ok(tokenMatch);
    assert.equal(new URL(urlMatch[1]).hostname, '127.0.0.1');
    assert.equal(new URL(urlMatch[1]).search, '');
    assert.equal(new URL(urlMatch[1]).hash, '');
    const withoutTokenLine = stdout.replace(tokenMatch[0], '로컬 API 토큰: [redacted-in-test]');
    assert.doesNotMatch(withoutTokenLine + stderr, new RegExp(tokenMatch[1]));
    const exited = new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (code, signal) => resolve({ code, signal }));
    });
    child.kill(signal);
    const exit = await exited;
    assert.equal(exit.code, 0);
    assert.equal(exit.signal, null);
    assert.match(stdout, /qa_cleanup=complete/);
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolve) => child.once('close', resolve));
    }
  }
}

test('대화형 Safari QA는 토큰을 터미널에만 안내하고 Ctrl+C에서 종료·정리한다', { timeout: 90_000 }, () =>
  verifyManualStopSignal('SIGINT'));

test('대화형 Safari QA는 SIGTERM에서도 서버와 임시 자료를 정리한다', { timeout: 90_000 }, () =>
  verifyManualStopSignal('SIGTERM'));
