import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Q018_AUTHORITY,Q018_AUTHORITY_SHA,Q018_QUALIFICATION,Q018_QUALIFICATION_SHA,Q018_CURRENT_GATE_SHA,Q018_MODIFIED_PATHS,Q018_NEW_PATHS,Q018_ROUTES,qualification,currentQualificationProblems,historicalLockProjection,historicalLicenseInventory,classifyQ018OriginEvidence,heldQ018Bytes,verifySDK,fixedRouteTarget,historicalEnvironment } from '../lib/b007-toolchain-security-q018.mjs';
import { FIXED_ORIGIN_FINDING } from '../lib/b007-fixed-origin-policy-q015.mjs';
const source=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const hash=b=>createHash('sha256').update(b).digest('hex');
const copy=v=>JSON.parse(JSON.stringify(v));
const original=[{file:FIXED_ORIGIN_FINDING.file,hazard:FIXED_ORIGIN_FINDING.hazard}];
const scan=()=>({scan_complete:true,findings:[copy(FIXED_ORIGIN_FINDING)]});
const facts=()=>({q018_authority_sha256:Q018_AUTHORITY_SHA,q018_qualification_sha256:Q018_QUALIFICATION_SHA,q015_authority_sha256:'d9c58aa1cd329bcb9f5c83ceea216c0427d7d3ed968d69f2dfc8c007be7076be',authorization_state:'OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI',owner_instruction:'批准',current_gate_sha256:Q018_CURRENT_GATE_SHA,original_scanner_sha256:'d08c0f1da9e6b6c04aa91f0bdee0ae655e0c7b2baf301efc613a789ef5baa5b3',original_validator_snapshot_sha256:'0e7bd7b810be7bb80ab89d3e62a4285911e39fb3e7c13b2c4d729ed957521fa6',q002_authority_sha256:'214d271c85245bac4f009e524e841f59411291d1ea6c09cc068066b131f6ca7b',original_Q015_current_identity_result:'FAIL'});
test('Q018 current qualification matches exact approved pins and complete22 inventory',()=>assert.deepEqual(currentQualificationProblems(source),[]));
test('historical projections retain exact B001/B003/B004 facts without current qualification claims',()=>{
 const q=qualification(source),lock=JSON.parse(fs.readFileSync(path.join(source,'tools/toolchain.lock.json'))),h=historicalLockProjection(source,lock),l=historicalLicenseInventory(source);
 assert.equal(lock.toolchains.go.version,'1.26.9');assert.equal(h.toolchains.go.version,'1.26.6');
 assert.deepEqual(h.toolchains.go,q.historical_qualifications.toolchains_go);assert.deepEqual(l,q.historical_qualifications.licenses);
 assert.equal(l.records.find(r=>r.id==='golang.org/x/text').version,'v0.39.0');assert.equal(q.current_licenses.records.find(r=>r.id==='golang.org/x/text').version,'v0.41.0');
 assert.equal(q.new_runtime_HIGH_accepted,false);assert.equal(q.runtime_ready,false);assert.equal(q.paid_callable,false);assert.equal(q.qual_runs,0);
});
test('Q018 exact18+8 and six historical routes remain closed',()=>{
 const a=JSON.parse(fs.readFileSync(path.join(source,Q018_AUTHORITY)));assert.equal(Q018_MODIFIED_PATHS.length,18);assert.equal(Q018_NEW_PATHS.length,8);assert.equal(Q018_ROUTES.length,6);
 assert.deepEqual(a.current_modified_paths,Q018_MODIFIED_PATHS);assert.deepEqual(a.new_exact_paths,Q018_NEW_PATHS);
 assert.throws(()=>fixedRouteTarget(source,'../../../anything'),/unknown Q018 historical route/);
 assert.throws(()=>fixedRouteTarget(source,'sh -c anything'),/unknown Q018 historical route/);
});
for(const route of Q018_ROUTES)test('historical route rejects current source before any SDK execution: '+route,()=>{
 const target=fixedRouteTarget(source,route);
 assert.match(target.commit,/^[a-f0-9]{40}$/);assert.match(target.tree,/^[a-f0-9]{40}$/);
 assert.throws(()=>historicalEnvironment(source,source,route),/historical target is not exact fixed clean Git source/);
});
test('new current origin classifier retains single exact finding and incomplete runtime gates',()=>{
 const v=classifyQ018OriginEvidence(original,scan(),facts());assert.equal(v.result,'PASS');assert.equal(v.accepted_findings.length,1);assert.equal(v.runtime_ready,false);assert.equal(v.paid_callable,false);assert.equal(v.original_Q015_current_identity_result,'FAIL');
});
for(const key of Object.keys(facts()))test('current classifier rejects identity/authorization substitution: '+key,()=>{
 const f=facts();f[key]='substituted';const v=classifyQ018OriginEvidence(original,scan(),f);assert.equal(v.result,'FAIL');assert.equal(v.accepted_findings.length,0);assert.ok(v.problems.some(p=>p.includes(key)));
});
for(const [name,change]of[
 ['incomplete scan',s=>s.scan_complete=false],
 ['changed decoded source bytes',s=>s.findings[0].sha256='0'.repeat(64)],
 ['changed decoded source size',s=>s.findings[0].bytes++],
 ['duplicate approved-looking finding',s=>s.findings.push(copy(s.findings[0]))],
 ['different file with same hazard',s=>s.findings[0].file='docs/pilot/runtime/extra.ts'],
 ['additional ordinary blocking hazard',s=>s.findings.push({file:'extra.json',hazard:'SYNTHETIC_HAZARD',bytes:10,sha256:'0'.repeat(64)})],
 ['missing fixed origin',s=>s.findings=[]],
])test('current classifier rejects '+name,()=>{
 const s=scan();change(s);const v=classifyQ018OriginEvidence(original,s,facts());assert.equal(v.result,'FAIL');
});
test('classifier rejects disagreement between both complete unfiltered scans',()=>assert.equal(classifyQ018OriginEvidence([],scan(),facts()).result,'FAIL'));
function fixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q018-current-proof-test-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const a=JSON.parse(fs.readFileSync(path.join(source,Q018_AUTHORITY)));
 const paths=new Set([Q018_AUTHORITY,...a.bindings.map(b=>b.path),'.go-version','go.mod','go.sum','tools/toolchain.lock.json','tools/supply-chain/licenses.json','internal/pilot/runtime_namespace_test.go']);
 for(const p of paths){fs.mkdirSync(path.dirname(path.join(root,p)),{recursive:true});fs.copyFileSync(path.join(source,p),path.join(root,p));}
 assert.deepEqual(currentQualificationProblems(root),[]);return root;
}
for(const [name,relative,mutate]of[
 ['Owner absent',Q018_AUTHORITY,p=>fs.unlinkSync(p)],
 ['Owner proposal cannot activate',Q018_AUTHORITY,p=>{const v=JSON.parse(fs.readFileSync(p));v.state='PROPOSAL_ONLY';v.owner_instruction=null;fs.writeFileSync(p,JSON.stringify(v));}],
 ['qualification body altered',Q018_QUALIFICATION,p=>fs.appendFileSync(p,' ')],
 ['current Go downgrade','.go-version',p=>fs.writeFileSync(p,'1.26.6\n')],
 ['extra graph member','go.mod',p=>fs.appendFileSync(p,'require example.invalid/extra v1.0.0\n')],
 ['runtime H1 corrupted','go.sum',p=>fs.appendFileSync(p,'extra checksum\n')],
 ['current SDK record substituted','tools/toolchain.lock.json',p=>{const v=JSON.parse(fs.readFileSync(p));v.toolchains.go.version='1.26.6';fs.writeFileSync(p,JSON.stringify(v));}],
 ['old security qualifier promoted to current','tools/supply-chain/licenses.json',p=>{const v=JSON.parse(fs.readFileSync(p));v.records.find(r=>r.id==='golang.org/x/text').version='v0.39.0';fs.writeFileSync(p,JSON.stringify(v));}],
 ['unapproved license identity','tools/supply-chain/licenses.json',p=>{const v=JSON.parse(fs.readFileSync(p));v.records.push({id:'example.invalid/extra',license:'MIT'});fs.writeFileSync(p,JSON.stringify(v));}],
 ['namespace diagnostics broadened','internal/pilot/runtime_namespace_test.go',p=>fs.appendFileSync(p,'\n// unapproved assertion\n')],
])test('actual current qualification fails closed: '+name,t=>{const root=fixture(t);mutate(path.join(root,relative));assert.ok(currentQualificationProblems(root).length>0);});
test('in-memory actual current lock and license drift rejected independently of unchanged disk',()=>{
 const lock=JSON.parse(fs.readFileSync(path.join(source,'tools/toolchain.lock.json'))),licenses=JSON.parse(fs.readFileSync(path.join(source,'tools/supply-chain/licenses.json')));
 lock.toolchains.go.source_verification.verified_at='invented';licenses.records.find(r=>r.id==='golang.org/x/sync').q018_requalification.license_file_sha256='0'.repeat(64);
 const p=currentQualificationProblems(source,{lock,licenses});assert.ok(p.some(p=>p.includes('current Go lock')));assert.ok(p.some(p=>p.includes('full22 license inventory')));
});
function sdkFixture(t){
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q018-SDK-counterfactual-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));fs.mkdirSync(path.join(root,'bin'));
 const raw=Buffer.from('counterfactual bytes; never executed\n');fs.writeFileSync(path.join(root,'bin/go'),raw,{mode:0o700});
 return {root,spec:{version:'COUNTERFACTUAL_NOT_QUALIFIED_SDK',files:[{relative:'bin/go',bytes:raw.length,sha256:hash(raw),executable:true}],directories:['.','bin']}};
}
test('pure SDK member checker checks complete physical set without executing any member',t=>{
 const {root,spec}=sdkFixture(t);const r=verifySDK(root,spec);assert.equal(r.files,1);assert.equal(r.version,'COUNTERFACTUAL_NOT_QUALIFIED_SDK');
});
for(const [name,mutate]of[
 ['missing compiler',root=>fs.unlinkSync(path.join(root,'bin/go'))],
 ['substituted compiler bytes',root=>fs.appendFileSync(path.join(root,'bin/go'),'changed')],
 ['extra unpacked member',root=>fs.writeFileSync(path.join(root,'extra'),'extra')],
 ['extra unpacked directory',root=>fs.mkdirSync(path.join(root,'extra'))],
 ['aliased compiler',root=>fs.linkSync(path.join(root,'bin/go'),path.join(root,'alias'))],
 ['symlinked compiler',root=>{fs.unlinkSync(path.join(root,'bin/go'));fs.symlinkSync('/dev/null',path.join(root,'bin/go'));}],
 ['lost executable bit',root=>fs.chmodSync(path.join(root,'bin/go'),0o600)],
])test('SDK member checker rejects '+name+' before any SDK execution',t=>{const {root,spec}=sdkFixture(t);mutate(root);assert.throws(()=>verifySDK(root,spec));});
test('held current proof bytes reject aliases and symbolic links',t=>{
 const {root}=sdkFixture(t),p=path.join(root,'bin/go');fs.linkSync(p,path.join(root,'alias'));assert.throws(()=>heldQ018Bytes(p),/aliased/);assert.throws(()=>heldQ018Bytes(path.join(root,'alias')),/aliased/);
});
for(const args of [[],['--unknown'],['--q015-full23','--repo','/tmp'],['--b001-launcher','--race'],['sh','-c','anything']])test('CLI rejects arbitrary/multiple target arguments: '+JSON.stringify(args),()=>{
 const r=spawnSync(process.execPath,[path.join(source,'scripts/ci/lib/b007-toolchain-security-q018.mjs'),...args],{cwd:source,encoding:'utf8'});assert.equal(r.error,undefined);assert.equal(r.signal,null);assert.equal(r.status,1);assert.match(r.stderr,/exact one fixed CLI route|unknown or unapproved/);
});
