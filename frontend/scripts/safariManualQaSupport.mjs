import { lstat, realpath, rm } from 'node:fs/promises';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { basename, dirname, resolve } from 'node:path';

export function allocateLoopbackPort(excludedPorts = []) {
  return new Promise((resolvePromise, reject) => {
    const probe = net.createServer();
    probe.once('error', () => reject(new Error('qa_loopback_port_unavailable')));
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      if (!address || typeof address === 'string' || excludedPorts.includes(address.port)) {
        probe.close(() => reject(new Error('qa_loopback_port_unavailable')));
        return;
      }
      probe.close((error) => error
        ? reject(new Error('qa_loopback_port_unavailable'))
        : resolvePromise(address.port));
    });
  });
}

export async function waitForHttp(url, predicate, { child, timeoutMs = 30_000, isStopping = () => false } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (isStopping()) throw new Error('qa_startup_interrupted');
    if (child && (child.exitCode !== null || child.signalCode !== null)) throw new Error('qa_service_failed_to_start');
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(500), cache: 'no-store' });
      if (await predicate(response)) return response;
    } catch (error) {
      if (error instanceof Error && error.message.startsWith('qa_')) throw error;
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 150));
  }
  throw new Error('qa_service_start_timeout');
}

export async function stopProcessGroup(child, graceMs = 5_000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const closed = new Promise((resolvePromise) => child.once('close', resolvePromise));
  try {
    if (child.pid) process.kill(-child.pid, 'SIGTERM');
    else child.kill('SIGTERM');
  } catch {
    try { child.kill('SIGTERM'); } catch { return; }
  }
  const graceful = await Promise.race([
    closed.then(() => true),
    new Promise((resolvePromise) => setTimeout(() => resolvePromise(false), graceMs)),
  ]);
  if (!graceful && child.exitCode === null && child.signalCode === null) {
    try {
      if (child.pid) process.kill(-child.pid, 'SIGKILL');
      else child.kill('SIGKILL');
    } catch {
      try { child.kill('SIGKILL'); } catch { /* process already exited */ }
    }
    await closed;
  }
}

export async function removeOwnedTemporaryDirectory(path) {
  const temporaryRoot = await realpath(tmpdir());
  const candidate = resolve(path);
  if (
    dirname(candidate) !== temporaryRoot ||
    !basename(candidate).startsWith('ai-csa-safari-manual-')
  ) {
    throw new Error('qa_cleanup_path_not_owned');
  }
  let info;
  try { info = await lstat(candidate); } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return;
    throw new Error('qa_cleanup_failed');
  }
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error('qa_cleanup_path_not_owned');
  await rm(candidate, { recursive: true, force: false });
}
