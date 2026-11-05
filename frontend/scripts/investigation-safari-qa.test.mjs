import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const script = fileURLToPath(new URL('./run-safari-manual-qa.mjs', import.meta.url));
const cwd = fileURLToPath(new URL('..', import.meta.url));

test('실제 조사 QA smoke는 인증, A/B → A/C, 평가와 해제를 검증하고 토큰을 출력하지 않는다', { timeout: 240_000 }, async () => {
  const result = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script, '--investigation', '--smoke-test'], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    child.stdout.on('data', (chunk) => { output += chunk; });
    child.stderr.on('data', (chunk) => { output += chunk; });
    child.once('error', reject);
    child.once('close', (code) => resolve({ code, output }));
  });
  assert.equal(result.code, 0, result.output);
  assert.match(result.output, /shared=1 baselineOnly=1 currentOnly=1; released/);
  assert.match(result.output, /qa_cleanup=complete/);
  assert.doesNotMatch(result.output, /[A-Za-z0-9_-]{43,}|ai-csa-safari-manual-[^\s]+|SAFARI_QA_SYNTHETIC_SOURCE_CANARY/);
});

test('수동 조사 QA는 터미널이 아닌 출력에 토큰을 내보내지 않는다', { timeout: 15_000 }, async () => {
  const result = await new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script, '--investigation'], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    child.stdout.on('data', (chunk) => { output += chunk; });
    child.stderr.on('data', (chunk) => { output += chunk; });
    child.once('error', reject);
    child.once('close', (code) => resolve({ code, output }));
  });
  assert.notEqual(result.code, 0);
  assert.match(result.output, /qa_interactive_terminal_required/);
  assert.doesNotMatch(result.output, /로컬 API 토큰:|[A-Za-z0-9_-]{43,}/);
});

test('조사 QA 터미널은 신호와 서버 비정상 종료에서 소유 자료를 정리한다', { timeout: 180_000 }, async () => {
  const source = `
import os, pty, select, signal, subprocess, sys, time, re
for sig in (signal.SIGINT, signal.SIGTERM, None):
    master, slave = pty.openpty()
    child = subprocess.Popen([sys.argv[1], sys.argv[2], '--investigation'], stdin=slave, stdout=slave, stderr=slave, cwd=sys.argv[3], close_fds=True)
    os.close(slave)
    data = b''
    deadline = time.monotonic() + 60
    while '기준 검사를 저장한 뒤'.encode() not in data and child.poll() is None and time.monotonic() < deadline:
        readable, _, _ = select.select([master], [], [], 0.2)
        if readable:
            try: data += os.read(master, 65536)
            except OSError: break
    if '기준 검사를 저장한 뒤'.encode() not in data:
        child.terminate(); child.wait(timeout=15); raise SystemExit('qa_terminal_not_ready')
    if sig is None:
        processes = subprocess.check_output(['ps', '-axo', 'pid=,ppid=,command='], text=True)
        vite_pid = next((int(parts[0]) for line in processes.splitlines() if (parts := line.strip().split(None, 2)) and len(parts) == 3 and int(parts[1]) == child.pid and 'npm run dev' in parts[2]), None)
        if vite_pid is None: child.terminate(); child.wait(timeout=15); raise SystemExit('qa_owned_vite_not_found')
        os.killpg(vite_pid, signal.SIGTERM)
    else:
        child.send_signal(sig)
    deadline = time.monotonic() + 20
    while child.poll() is None and time.monotonic() < deadline:
        readable, _, _ = select.select([master], [], [], 0.2)
        if readable:
            try: data += os.read(master, 65536)
            except OSError: break
    if child.poll() is None:
        child.kill(); child.wait(); raise SystemExit('qa_terminal_stop_timeout')
    while select.select([master], [], [], 0)[0]:
        try:
            chunk = os.read(master, 65536)
            if not chunk: break
            data += chunk
        except OSError: break
    os.close(master)
    if child.returncode != (1 if sig is None else 0) or b'qa_cleanup=complete' not in data: raise SystemExit('qa_terminal_cleanup_failed_' + str(child.returncode) + '_' + str(b'qa_cleanup=complete' in data))
print('qa_terminal_signals_passed')
`;
  const result = await new Promise((resolve, reject) => {
    const child = spawn('python3.12', ['-c', source, process.execPath, script, cwd], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    child.stdout.on('data', (chunk) => { output += chunk; });
    child.stderr.on('data', (chunk) => { output += chunk; });
    child.once('error', reject);
    child.once('close', (code) => resolve({ code, output }));
  });
  assert.equal(result.code, 0, result.output);
  assert.match(result.output, /qa_terminal_signals_passed/);
  assert.doesNotMatch(result.output, /[A-Za-z0-9_-]{43,}/);
});

test('잘못된 Semgrep 버전은 서버 생성 전에 거부한다', { timeout: 30_000 }, async () => {
  const { mkdtemp, writeFile, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join, delimiter } = await import('node:path');
  const temporary = await mkdtemp(join(tmpdir(), 'ai-csa-qa-version-test-'));
  try {
    await writeFile(join(temporary, 'semgrep'), '#!/bin/sh\nprintf "0.0.0\\n"\n', { mode: 0o700 });
    const result = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [script, '--investigation', '--smoke-test'], {
        cwd, env: { ...process.env, PATH: `${temporary}${delimiter}${process.env.PATH}` }, stdio: ['ignore', 'pipe', 'pipe'],
      });
      let output = '';
      child.stdout.on('data', (chunk) => { output += chunk; });
      child.stderr.on('data', (chunk) => { output += chunk; });
      child.once('error', reject);
      child.once('close', (code) => resolve({ code, output }));
    });
    assert.notEqual(result.code, 0);
    assert.match(result.output, /qa_required_semgrep_1_182_1_unavailable/);
    assert.doesNotMatch(result.output, /로컬 API 토큰:|qa_cleanup=complete/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
