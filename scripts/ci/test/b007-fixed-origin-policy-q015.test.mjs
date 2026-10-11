import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanTreeForHazards } from '../lib/scan.mjs';
import { scanTreeForByteEvidence } from '../lib/b007-byte-evidence-scan-q015.mjs';
import { classifyFixedOriginEvidence, inspectFixedOriginPolicy, FIXED_ORIGIN_FINDING } from '../lib/b007-fixed-origin-policy-q015.mjs';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const fixedRaw=fs.readFileSync(path.join(root,FIXED_ORIGIN_FINDING.file));
const project=rows=>rows.map(({file,hazard})=>({file,hazard}));
const facts=()=>({authority_sha256:'d9c58aa1cd329bcb9f5c83ceea216c0427d7d3ed968d69f2dfc8c007be7076be',authorization_state:'OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI',owner_instruction:'HYPOTHETICAL_NONCANON_UNIT_FIXTURE_ONLY',current_gate_sha256:'57a9f1a69193506d9b80075342395e86fa2028f7eb5d3ab015f02095d0c8e1f2',original_scanner_sha256:'d08c0f1da9e6b6c04aa91f0bdee0ae655e0c7b2baf301efc613a789ef5baa5b3',original_validator_snapshot_sha256:'0e7bd7b810be7bb80ab89d3e62a4285911e39fb3e7c13b2c4d729ed957521fa6',q002_authority_sha256:'214d271c85245bac4f009e524e841f59411291d1ea6c09cc068066b131f6ca7b'});
const evidence=rows=>({scan_complete:true,findings:rows});
test('hypothetical exact facts classify one retained finding; this is not Owner authorization',()=>{const v=classifyFixedOriginEvidence(project([FIXED_ORIGIN_FINDING]),evidence([FIXED_ORIGIN_FINDING]),facts());assert.equal(v.result,'PASS');assert.deepEqual(v.accepted_findings,[FIXED_ORIGIN_FINDING]);assert.equal(v.runtime_ready,false);assert.equal(v.paid_callable,false);});
for(const [key,value]of [['authority_sha256','0'.repeat(64)],['authorization_state','PROPOSAL_ONLY_NOT_OWNER_AUTHORIZED'],['owner_instruction',null],['current_gate_sha256','0'.repeat(64)],['original_scanner_sha256','0'.repeat(64)],['original_validator_snapshot_sha256','0'.repeat(64)],['q002_authority_sha256','0'.repeat(64)]])test('reject substituted or absent exact approval fact '+key,()=>{const f=facts();f[key]=value;const v=classifyFixedOriginEvidence(project([FIXED_ORIGIN_FINDING]),evidence([FIXED_ORIGIN_FINDING]),f);assert.equal(v.result,'FAIL');assert.equal(v.accepted_findings.length,0);});
for(const [key,value]of [['file','other.ts'],['hazard','OPENAI_ENDPOINT'],['bytes',6428],['sha256','0'.repeat(64)]])test('reject substituted finding '+key,()=>{const row={...FIXED_ORIGIN_FINDING,[key]:value};const v=classifyFixedOriginEvidence(project([row]),evidence([row]),facts());assert.equal(v.result,'FAIL');assert.equal(v.accepted_findings.length,0);});
test('extra endpoint/secret/prompt findings block without erasing the known finding',()=>{for(const hazard of ['OPENAI_ENDPOINT','API_KEY_LIKE','CHAT_TRANSCRIPT_MARKER']){const extra={file:'extra.ts',hazard,bytes:99,sha256:'1'.repeat(64)};const rows=[FIXED_ORIGIN_FINDING,extra];const v=classifyFixedOriginEvidence(project(rows),evidence(rows),facts());assert.equal(v.result,'FAIL');assert.equal(v.accepted_findings.length,1);assert.deepEqual(v.blocking_findings,[extra]);}});
test('duplicate approved finding blocks',()=>{const rows=[FIXED_ORIGIN_FINDING,FIXED_ORIGIN_FINDING];const v=classifyFixedOriginEvidence(project(rows),evidence(rows),facts());assert.equal(v.result,'FAIL');assert.equal(v.blocking_findings.length,1);});
test('two scans disagree or incomplete scan blocks',()=>{let v=classifyFixedOriginEvidence([],evidence([FIXED_ORIGIN_FINDING]),facts());assert.equal(v.result,'FAIL');v=classifyFixedOriginEvidence(project([FIXED_ORIGIN_FINDING]),{scan_complete:false,findings:[FIXED_ORIGIN_FINDING]},facts());assert.equal(v.result,'FAIL');});
function fixture(t,raw){const r=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q015-source-byte-fixture-'));t.after(()=>fs.rmSync(r,{recursive:true,force:true}));const p=path.join(r,FIXED_ORIGIN_FINDING.file);fs.mkdirSync(path.dirname(p),{recursive:true});fs.writeFileSync(p,raw);return {r,p};}
test('complete original and byte-bound scans agree on exact source bytes',t=>{const {r}=fixture(t,fixedRaw);const original=scanTreeForHazards(r),bound=scanTreeForByteEvidence(r);assert.deepEqual(original,project(bound.findings));assert.deepEqual(bound.findings,[FIXED_ORIGIN_FINDING]);});
for(const [kind,extra]of [['credential','\n// '+('sk-'+'x'.repeat(30))+'\n'],['prompt','\n'+('system'+': private fixture')+'\n'],['other_endpoint','\n// '+('api.'+'openai.com')+'\n']])test('same fixed file with appended '+kind+' is refused even when original scanner stops at first hit',t=>{const {r}=fixture(t,Buffer.concat([fixedRaw,Buffer.from(extra)]));const original=scanTreeForHazards(r),bound=scanTreeForByteEvidence(r);assert.deepEqual(original,project(bound.findings));const v=classifyFixedOriginEvidence(original,bound,facts());assert.equal(v.result,'FAIL');assert.equal(v.accepted_findings.length,0);assert.notEqual(bound.findings[0].sha256,FIXED_ORIGIN_FINDING.sha256);});
test('source replacement with same matching label fails its scanned-buffer identity',t=>{const {r,p}=fixture(t,fixedRaw);const original=scanTreeForHazards(r);fs.writeFileSync(p,Buffer.concat([fixedRaw,Buffer.from('\n// changed\n')]));const bound=scanTreeForByteEvidence(r);const v=classifyFixedOriginEvidence(original,bound,facts());assert.equal(v.result,'FAIL');assert.equal(v.accepted_findings.length,0);});
test('byte-bound scan rejects symlink and invalid UTF8 rather than authorizing',t=>{const {r,p}=fixture(t,fixedRaw);fs.unlinkSync(p);fs.symlinkSync('/dev/null',p);assert.throws(()=>scanTreeForByteEvidence(r));fs.unlinkSync(p);fs.writeFileSync(p,Buffer.from([255]));assert.throws(()=>scanTreeForByteEvidence(r));});
test('live policy rejects missing Authority/scanner/original validator; no substitute facts accepted',t=>{const {r}=fixture(t,fixedRaw);const v=inspectFixedOriginPolicy(r,scanTreeForHazards(r));assert.equal(v.result,'FAIL');assert.equal(v.accepted_findings.length,0);});
test('live Authority state permits only its exact classification and never model execution',()=>{
 const authority=JSON.parse(fs.readFileSync(path.join(root,'docs/pilot/authorities/fixed-origin-policy-successor-q015.json')));
 const v=inspectFixedOriginPolicy(root,scanTreeForHazards(root));
 assert.equal(v.runtime_ready,false);assert.equal(v.paid_callable,false);
 if(authority.state==='OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI') {
  assert.equal(v.result,'PASS');assert.deepEqual(v.accepted_findings,[FIXED_ORIGIN_FINDING]);
  assert.deepEqual(v.blocking_findings,[]);assert.deepEqual(v.problems,[]);
 } else {
  assert.equal(v.result,'FAIL');assert.equal(v.accepted_findings.length,0);
  assert.ok(v.problems.some(p=>p.includes('authorization_state')));
 }
});
