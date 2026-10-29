import { parseHealth, parseOptions, parseScan, type Health, type Options, type ScanResponse } from './types';

export class ApiError extends Error {
  constructor(readonly status: number, readonly code: string) { super(code); }
}

async function request(path: string, token?: string, body?: object): Promise<unknown> {
  const headers = new Headers();
  if (token) headers.set('X-Local-API-Token', token);
  if (body) headers.set('Content-Type', 'application/json');
  let response: Response;
  try {
    response = await fetch(path, { method: body ? 'POST' : 'GET', headers, body: body ? JSON.stringify(body) : undefined, cache: 'no-store', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer' });
  } catch { throw new ApiError(0, 'connection_error'); }
  let value: unknown;
  try { value = await response.json(); } catch { throw new ApiError(response.status, 'invalid_api_response'); }
  if (!response.ok) {
    const code = typeof value === 'object' && value !== null && 'error' in value && typeof value.error === 'string' && /^[a-z_]{1,64}$/.test(value.error) ? value.error : 'request_failed';
    throw new ApiError(response.status, code);
  }
  return value;
}

export const api = {
  async health(): Promise<Health> { return parseHealth(await request('/api/v1/health')); },
  async options(): Promise<Options> { return parseOptions(await request('/api/v1/options')); },
  async scan(token: string, targetId: string, ruleProfileId: string): Promise<ScanResponse> {
    return parseScan(await request('/api/v1/scans', token, { target_id: targetId, rule_profile_id: ruleProfileId }));
  },
};
