// Explicit fixed-origin classification; a proposed Authority never authorizes it.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { scanTreeForByteEvidence } from './b007-byte-evidence-scan-q015.mjs';
const AUTHORITY='docs/pilot/authorities/fixed-origin-policy-successor-q015.json';
const AUTHORITY_SHA='d9c58aa1cd329bcb9f5c83ceea216c0427d7d3ed968d69f2dfc8c007be7076be';
const GATE='scripts/ci/validate/supply-chain.mjs';
const GATE_SHA='57a9f1a69193506d9b80075342395e86fa2028f7eb5d3ab015f02095d0c8e1f2';
const SCAN_SHA='d08c0f1da9e6b6c04aa91f0bdee0ae655e0c7b2baf301efc613a789ef5baa5b3';
const OLD_SHA='0e7bd7b810be7bb80ab89d3e62a4285911e39fb3e7c13b2c4d729ed957521fa6';
const Q002_SHA='214d271c85245bac4f009e524e841f59411291d1ea6c09cc068066b131f6ca7b';
export const FIXED_ORIGIN_FINDING=Object.freeze({file:'docs/pilot/runtime/harness-runtime-closure-b007.ts',hazard:'DEEPSEEK_ENDPOINT',bytes:6427,sha256:'1dedde689c31337dc0a29102239a828a9873003f80945d5c456eef5614d8512f'});
function heldBytes(repo,relative) {
 const full=path.join(repo,relative);
 const before=fs.lstatSync(full,{bigint:true});
 if(!before.isFile()||before.nlink!==1n||before.size>8388608n)throw new Error('nonregular/aliased/oversized policy artifact: '+relative);
 const fd=fs.openSync(full,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_CLOEXEC);
 try {
  const opened=fs.fstatSync(fd,{bigint:true}),raw=fs.readFileSync(fd),after=fs.fstatSync(fd,{bigint:true}),atPath=fs.lstatSync(full,{bigint:true});
  for(const k of ['dev','ino','size','mode','nlink','uid','gid','mtimeNs','ctimeNs'])if(before[k]!==opened[k]||opened[k]!==after[k]||after[k]!==atPath[k])throw new Error('policy artifact changed while held: '+relative);
  if(BigInt(raw.length)!==before.size)throw new Error('short policy artifact read: '+relative);
  return {raw,sha256:createHash('sha256').update(raw).digest('hex')};
 }finally{fs.closeSync(fd);}
}
// Pure decision function for adversarial fixture coverage. The live gate obtains
// every fact itself; callers cannot provide substitute authorization to it.
export function classifyFixedOriginEvidence(originalFindings,byteEvidence,facts) {
 const problems=[],accepted=[],blocking=[];
 const expected={authority_sha256:AUTHORITY_SHA,authorization_state:'OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI',current_gate_sha256:GATE_SHA,original_scanner_sha256:SCAN_SHA,original_validator_snapshot_sha256:OLD_SHA,q002_authority_sha256:Q002_SHA};
 for(const [k,v] of Object.entries(expected))if(facts?.[k]!==v)problems.push('exact authorization or gate identity mismatch: '+k);
 if(typeof facts?.owner_instruction!=='string'||!facts.owner_instruction.length)problems.push('explicit Owner instruction absent');
 if(byteEvidence?.scan_complete!==true||!Array.isArray(byteEvidence?.findings))problems.push('complete byte-bound scan unavailable');
 const rows=Array.isArray(byteEvidence?.findings)?byteEvidence.findings:[];
 const projection=rows.map(({file,hazard})=>({file,hazard}));
 if(!isDeepStrictEqual(originalFindings,projection))problems.push('original complete scan and byte-bound complete scan disagree');
 for(const row of rows) {
  if(problems.length===0&&isDeepStrictEqual(row,FIXED_ORIGIN_FINDING)&&accepted.length===0)accepted.push(row);
  else blocking.push(row);
 }
 if(accepted.length!==1)problems.push('exact single fixed-origin finding absent or unapproved');
 return {decision_id:'AIPT-MVP-B007-OWNER-Q015',result:problems.length||blocking.length?'FAIL':'PASS',problems,original_unfiltered_findings:originalFindings,byte_bound_findings:rows,accepted_findings:accepted,blocking_findings:blocking,complete_original_scan_retained:true,no_scan_exemptions:true,local_online_CI_acceptance_claim:false,runtime_ready:false,paid_callable:false};
}
export function inspectFixedOriginPolicy(repo,originalFindings) {
 try {
  const held=heldBytes(repo,AUTHORITY),authority=JSON.parse(held.raw);
  const facts={authority_sha256:held.sha256,authorization_state:authority.state,owner_instruction:authority.owner_instruction,current_gate_sha256:heldBytes(repo,GATE).sha256,original_scanner_sha256:heldBytes(repo,'scripts/ci/lib/scan.mjs').sha256,original_validator_snapshot_sha256:heldBytes(repo,'docs/pilot/evidence/task0-q015/original-supply-chain.mjs').sha256,q002_authority_sha256:heldBytes(repo,'docs/pilot/authorities/wire-budget-closure-successor.json').sha256};
  const evidence=scanTreeForByteEvidence(repo);
  return classifyFixedOriginEvidence(originalFindings,evidence,facts);
 }catch(error){return {decision_id:'AIPT-MVP-B007-OWNER-Q015',result:'FAIL',problems:['policy/scanning failure: '+error.message],original_unfiltered_findings:originalFindings,accepted_findings:[],blocking_findings:originalFindings,runtime_ready:false,paid_callable:false};}
}
