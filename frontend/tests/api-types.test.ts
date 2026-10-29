import { describe, expect, it } from 'vitest';
import { parseScan } from '../src/api/types';

const valid = {
  scan_status:'completed',completed:true,semgrep_version:'1.182.1',finding_count:1,displayed_finding_count:1,omitted_finding_count:0,
  severity_counts:{critical:0,high:1,medium:0,low:0,info:0},issues:[],limitations:['scan_result_is_not_safety_proof'],
  findings:[{finding_id:'semgrep:0123456789abcdef01234567',rule_id:'rule.safe',severity:'high',verification_status:'unverified',finding_kind:'pattern',file_path:'src/main.js',line_number:1,evidence_validation_status:'validated',supported_claims:['match_reported'],restricted_claims:[{claim_type:'flow_trace_available',decision:'unavailable',reason_codes:['flow_trace_absent']}],validation_error_code:null}],
};

describe('closed Phase 5A API response contract',()=>{
  it('accepts a response that conforms to the current API enums and accounting',()=>{ expect(parseScan(valid).findings[0]?.supported_claims).toEqual(['match_reported']); });
  it.each([
    ['unknown scan status',{...valid,scan_status:'success'}],
    ['unknown claim',{...valid,findings:[{...valid.findings[0],supported_claims:['MATCH_REPORTED']}]}],
    ['unknown reason',{...valid,findings:[{...valid.findings[0],restricted_claims:[{claim_type:'flow_trace_available',decision:'unavailable',reason_codes:['secret_reason']}]}]}],
    ['unknown issue',{...valid,issues:['new_issue']}],
    ['extra Finding field',{...valid,findings:[{...valid.findings[0],message:'raw code'}]}],
    ['duplicate finding id',{...valid,findings:[valid.findings[0],valid.findings[0]],finding_count:2,displayed_finding_count:2,severity_counts:{critical:0,high:2,medium:0,low:0,info:0}}],
    ['contradictory claim',{...valid,findings:[{...valid.findings[0],supported_claims:['flow_trace_available']}]}],
  ] as const)('rejects %s',(_label,payload)=>{ expect(()=>parseScan(payload)).toThrow('invalid_api_response'); });
});
