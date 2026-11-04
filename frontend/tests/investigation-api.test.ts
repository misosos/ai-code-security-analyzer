import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError } from '../src/api/client';
import { investigationApi, parseInvestigationEvaluation, parseInvestigationScan, parseInvestigationSession } from '../src/api/investigation';
import { investigationErrorMessage } from '../src/features/scans/investigationMessages';

const scan = {
  scan_status: 'completed', completed: true, semgrep_version: '1.182.1',
  finding_count: 0, displayed_finding_count: 0, omitted_finding_count: 0,
  severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  issues: [], findings: [], limitations: ['finding_count_not_confirmed_vulnerability_count', 'scan_result_is_not_safety_proof'],
};
const findingId = `semgrep:${'a'.repeat(24)}`;
const evaluation = {
  contract_version: 'finding-disappearance-evaluation/v1', comparability: 'COMPARABLE', overall_assessment: 'UNDETERMINED',
  findings: [{ finding_id: findingId, category: 'baselineOnly', path_observation: 'SKIP_EVIDENCE_NOT_COLLECTED', skip_hypothesis: 'UNDETERMINED', source_snapshot_hypothesis: 'UNDETERMINED', rule_identity_hypothesis: 'UNDETERMINED' }],
  limitation_codes: ['source_snapshot_not_collected', 'scope_completeness_unverified', 'skip_details_not_collected'],
};
const handle = 'A'.repeat(43);

describe('investigation response parsers', () => {
  it('accepts exact versioned scan and session envelopes with opaque handles', () => {
    expect(parseInvestigationScan({ contract_version: 'investigation-scan/v1', run_handle: handle, scan }).scan.scan_status).toBe('completed');
    expect(parseInvestigationSession({ contract_version: 'investigation-session/v1', investigation_handle: handle }).investigation_handle).toBe(handle);
  });

  it('rejects wrong versions, handle shapes, and unknown envelope fields', () => {
    expect(() => parseInvestigationScan({ contract_version: 'v0', run_handle: handle, scan })).toThrow('invalid_api_response');
    expect(() => parseInvestigationScan({ contract_version: 'investigation-scan/v1', run_handle: 'short', scan })).toThrow('invalid_api_response');
    expect(() => parseInvestigationScan({ contract_version: 'investigation-scan/v1', run_handle: handle, scan, scan_ref: 'internal' })).toThrow('invalid_api_response');
  });

  it('rejects unknown enum values, extra fields, duplicate IDs, and oversized arrays', () => {
    expect(parseInvestigationEvaluation(evaluation).findings[0].category).toBe('baselineOnly');
    expect(() => parseInvestigationEvaluation({ ...evaluation, findings: [{ ...evaluation.findings[0], path_observation: 'PATH_WAS_SAFE' }] })).toThrow('invalid_api_response');
    expect(() => parseInvestigationEvaluation({ ...evaluation, extra: true })).toThrow('invalid_api_response');
    expect(() => parseInvestigationEvaluation({ ...evaluation, findings: [evaluation.findings[0], evaluation.findings[0]] })).toThrow('invalid_api_response');
  });
});

describe('investigation API transport', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('sends v2 handles only in POST bodies with local token and privacy fetch options', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ contract_version: 'investigation-session/v1', investigation_handle: handle }), { status: 201 }));
    vi.stubGlobal('fetch', fetchMock);
    await investigationApi.createSession('local-secret', handle, 'B'.repeat(43));
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v2/investigations');
    expect(init.method).toBe('POST');
    expect(init.cache).toBe('no-store');
    expect(init.credentials).toBe('omit');
    expect(init.redirect).toBe('error');
    expect(init.referrerPolicy).toBe('no-referrer');
    expect(new Headers(init.headers).get('X-Local-API-Token')).toBe('local-secret');
    expect(init.body).toBe(JSON.stringify({ baseline_handle: handle, current_handle: 'B'.repeat(43) }));
  });

  it('treats release 204 as success without parsing a JSON body', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal('fetch', fetchMock);
    await expect(investigationApi.release('token', 'run', handle)).resolves.toBeUndefined();
  });

  it('maps only fixed server error codes and does not surface arbitrary response text', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: 'evidence_unavailable' }), { status: 404 })));
    await expect(investigationApi.evaluate('token', handle)).rejects.toMatchObject({ status: 404, code: 'evidence_unavailable' });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ error: 'secret-handle-leaked' }), { status: 500 })));
    await expect(investigationApi.evaluate('token', handle)).rejects.toBeInstanceOf(ApiError);
    await expect(investigationApi.evaluate('token', handle)).rejects.toMatchObject({ code: 'request_failed' });
  });

  it('keeps fixed Korean error guidance distinct for evaluation busy and unsupported deployment', () => {
    expect(investigationErrorMessage(409, 'evaluation_busy')).toContain('다른 증거 평가가 진행 중');
    expect(investigationErrorMessage(409, 'binding_rejected')).toContain('검사 문맥이 일치하지 않아');
    expect(investigationErrorMessage(503, 'unsupported_deployment')).toContain('공식 단일 Worker 실행');
    expect(investigationErrorMessage(413, 'response_limit_exceeded')).toContain('허용 크기');
    expect(investigationErrorMessage(400, 'host_not_allowed')).toContain('Host');
    expect(investigationErrorMessage(500, 'secret-handle-value')).not.toContain('secret-handle-value');
  });
});
