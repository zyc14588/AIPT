import { isDeepStrictEqual as deepEqual } from 'node:util';
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Q018_AUTHORITY,Q018_AUTHORITY_SHA,Q018_QUALIFICATION,Q018_QUALIFICATION_SHA,Q018_CURRENT_GATE_SHA,Q018_MODIFIED_PATHS,Q018_NEW_PATHS,Q018_ROUTES,qualification,currentQualificationProblems,historicalLockProjection,historicalLicenseInventory,classifyQ018OriginEvidence,heldQ018Bytes,verifySDK,fixedRouteTarget,historicalEnvironment,Q019_AUTHORITY,Q019_PROPOSAL,Q021_AUTHORITY,Q021_PROPOSAL,q021Approved,verifyQ021CurrentSDK,withQ021VerifiedCurrentSDK,prepareQ021FixedCloneOrigins, Q022_AUTHORITY, Q022_PROPOSAL, Q022_WORK_PATHS, Q022_NEW_PATHS, Q022_BASELINE, q022Approved, q022SourceProblems, q022RevisionProblems, prepareQ022FixedCloneOrigin, q022OriginalTestSource, cleanupQ022OriginalTestSources, Q023_AUTHORITY, Q023_PROPOSAL, Q023_BASELINE, Q023_BASELINE_TREE, Q023_WORK_PATHS, Q023_NEW_PATHS, q023Approved, q023Proposal, q023SourceProblems, q023RevisionProblems, q023LifecycleProblems, prepareQ023FixedCloneOrigin, q023OriginalTestSource, cleanupQ023OriginalTestSources, runQ023FixedP1Reverification, q023FixedP1ReportProblems, Q024_AUTHORITY, Q024_PROPOSAL, Q024_BASELINE, Q024_BASELINE_TREE, Q024_ORIGINAL_CANDIDATE, Q024_TEST, Q024_WORK_PATHS, Q024_NEW_PATHS, q024Approved, q024Proposal, q024SourceProblems, q024RevisionProblems, q024LifecycleProblems, prepareQ024FixedCloneOrigin, q024OriginalTestSource, cleanupQ024OriginalTestSources, Q025_AUTHORITY, Q025_PROPOSAL, Q025_BASELINE, Q025_BASELINE_TREE, Q025_PARENT, Q025_TEST, Q025_WORK_PATHS, Q025_NEW_PATHS, q025Approved, q025Proposal, q025SourceProblems, q025RevisionProblems, q025LifecycleProblems, q025Topology, prepareQ025FixedCloneOrigin, q025OriginalTestSource, cleanupQ025OriginalTestSources, Q026_AUTHORITY, Q026_PROPOSAL, Q026_BASELINE, Q026_BASELINE_TREE, Q026_PARENT, Q026_OBSERVER, Q026_TEST, Q026_WORK_PATHS, Q026_NEW_PATHS, q026Approved, q026Proposal, q026SourceProblems, q026RevisionProblems, q026LifecycleProblems, q026Topology, prepareQ026FixedCloneOrigin, q026OriginalTestSource, cleanupQ026OriginalTestSources, Q027_AUTHORITY, Q027_PROPOSAL, Q027_BASELINE, Q027_BASELINE_TREE, Q027_PARENT, Q027_OBSERVER, Q027_TEST, Q027_WORK_PATHS, Q027_NEW_PATHS, q027Approved, q027Proposal, q027SourceProblems, q027RevisionProblems, q027LifecycleProblems, q027Topology, prepareQ027FixedCloneOrigin, q027OriginalTestSource, cleanupQ027OriginalTestSources, Q028_AUTHORITY, Q028_PROPOSAL, Q028_BASELINE, Q028_BASELINE_TREE, Q028_PARENT, Q028_OBSERVER, Q028_TEST, Q028_WORK_PATHS, Q028_NEW_PATHS, q028Approved, q028Proposal, q028SourceProblems, q028RevisionProblems, q028LifecycleProblems, q028Topology, prepareQ028FixedCloneOrigin, q028OriginalTestSource, cleanupQ028OriginalTestSources, Q032_AUTHORITY, Q032_PROPOSAL, Q032_BASELINE, Q032_BASELINE_TREE, Q032_WORK_PATHS, Q032_NEW_PATHS, q032Present, q032Approved, q032Proposal, q032SourceProblems, q032RevisionProblems, q032LifecycleProblems, q032Topology, prepareQ032FixedCloneOrigin, q032OriginalTestSource, cleanupQ032OriginalTestSources, prepareQ032CurrentSDK, q032CurrentGoVersion } from '../lib/b007-toolchain-security-q018.mjs';
import { FIXED_ORIGIN_FINDING } from '../lib/b007-fixed-origin-policy-q015.mjs';
import {successorProblems as q025SuccessorProblems,cleanupSnapshots as q025CleanupPredecessors} from '../lib/b007-successor.mjs';
const q032CurrentSource=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const q028CurrentSource=q032OriginalTestSource(q032CurrentSource);
test.after(cleanupQ032OriginalTestSources);
const q027CurrentSource=q028OriginalTestSource(q028CurrentSource);
test.after(cleanupQ028OriginalTestSources);
const q026CurrentSource=q027OriginalTestSource(q027CurrentSource);
test.after(cleanupQ027OriginalTestSources);
const q025CurrentSource=q026OriginalTestSource(q026CurrentSource);
test.after(cleanupQ026OriginalTestSources);
const q024CurrentSource=q025OriginalTestSource(q025CurrentSource);
test.after(cleanupQ025OriginalTestSources);
const q023CurrentSource=q024OriginalTestSource(q024CurrentSource);
test.after(cleanupQ024OriginalTestSources);
const currentSource=q023OriginalTestSource(q023CurrentSource);
test.after(cleanupQ023OriginalTestSources);
const source=q022OriginalTestSource(currentSource);
test.after(cleanupQ022OriginalTestSources);
// Test input only. The acquired current SDK stays the exact raw15045 SDK.
// The old complete repack test runs unchanged against its own temporary copy.
function q032PrepareLegacySDKTestInput() {
 if(!q032Present(q032CurrentSource))return {adapted:false};
 const originalEnvironment=process.env.AIPT_Q021_REAL_TEST_SDK,originalPath=process.env.PATH;
 if(originalEnvironment!==undefined){
  const proof=verifyQ021CurrentSDK(source,originalEnvironment);
  assert.equal(proof.identity_class,'PINNED_CI_REPACK_LOGICAL_IDENTITY');
  return {adapted:false,explicit_test_input:true,input:originalEnvironment,proof,originalPath};
 }
 let rawRoot;
 for(const bin of (originalPath??'').split(path.delimiter))if(bin){
  const go=path.join(path.resolve(bin),'go');
  if(fs.existsSync(go)){
   const s=fs.lstatSync(go);
   assert.ok(s.isFile()&&!s.isSymbolicLink());
   rawRoot=path.dirname(path.dirname(go));
   assert.equal(fs.realpathSync(rawRoot),rawRoot);
   break;
  }
 }
 assert.ok(rawRoot,'Q032 original complete SDK test input absent; no skipped positive');
 const rawProof=verifyQ021CurrentSDK(source,rawRoot);
 assert.equal(rawProof.files,15045);
 assert.equal(rawProof.directories,1667);
 assert.equal(fs.existsSync(path.join(rawRoot,'setup.sh')),false);
 const spec=qualification(source).SDKs.find(s=>s.version==='1.26.9');
 let owned=null,owner=null,input=null,retired=false,environmentInstalled=false;
 function retire(){
  const errors=[];
  // Restore our process-local variable independently of directory validation.
  if(environmentInstalled){
   if(process.env.AIPT_Q021_REAL_TEST_SDK!==input)errors.push(new Error('Q032 test input environment changed before restoration'));
   try{
    if(originalEnvironment===undefined)delete process.env.AIPT_Q021_REAL_TEST_SDK;
    else process.env.AIPT_Q021_REAL_TEST_SDK=originalEnvironment;
    environmentInstalled=false;
   }catch(error){errors.push(error);}
  }
  if(owned&&!retired){
   try{
    if(owner===null)throw new Error('Q032 test input identity unconfirmed; retained '+owned);
    const current=fs.lstatSync(owned,{bigint:true});
    assert.ok(current.isDirectory()&&!current.isSymbolicLink());
    for(const key of ['dev','ino','uid','gid','mode'])assert.equal(current[key],owner[key]);
    let removalError=null;
    try{q025TestRetire(owned);}catch(error){removalError=error;}
    try{fs.lstatSync(owned);}catch(absence){
     if(absence.code==='ENOENT')retired=true;
     else errors.push(absence);
    }
    if(removalError)throw removalError;
    if(!retired)throw new Error('Q032 test input removal not confirmed; retained '+owned);
   }catch(error){errors.push(error);}
  }
  if(errors.length)throw new AggregateError(errors,'Q032 test input retirement errors; directory '+(retired?'retired':'retained or not created')+'; path '+owned);
 }
 try{
  owned=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q032-legacy-repack-test-input-'));
  input=path.join(owned,'input');
  const initial=fs.lstatSync(owned,{bigint:true});
  assert.ok(initial.isDirectory()&&!initial.isSymbolicLink());
  assert.equal(initial.uid,BigInt(process.getuid()));
  owner=initial;
  assert.equal(initial.mode&0o777n,0o700n);
  test.after(retire);
  let copyError=null;
  try{
  withQ021VerifiedCurrentSDK(source,rawRoot,()=>{
   try{
   fs.mkdirSync(input,{mode:0o700});
   for(const relative of spec.directories.filter(x=>x!=='.').sort((a,b)=>a.split('/').length-b.split('/').length||a.localeCompare(b)))fs.mkdirSync(path.join(input,relative),{mode:0o700});
   for(const expected of spec.files){
    const held=heldQ018Bytes(path.join(rawRoot,expected.relative),expected.bytes);
    assert.equal(held.bytes,expected.bytes);
    assert.equal(held.sha256,expected.sha256);
    assert.equal(held.executable,expected.executable);
    fs.writeFileSync(path.join(input,expected.relative),held.raw,{flag:'wx',mode:expected.executable?0o700:0o600});
   }
   // Exact previously accepted non-executable Q021 marker, never executed.
   const marker=Buffer.from("set -e\n\nGO_VERSION=1.26.9\nARCH=x64\n\nGO_TOOLCACHE_PATH=$AGENT_TOOLSDIRECTORY/go\nGO_TOOLCACHE_VERSION_PATH=$GO_TOOLCACHE_PATH/$GO_VERSION\nGO_TOOLCACHE_VERSION_ARCH_PATH=$GO_TOOLCACHE_VERSION_PATH/$ARCH\n\necho \"Check if Go hostedtoolcache folder exist...\"\nif [ ! -d $GO_TOOLCACHE_PATH ]; then\n    mkdir -p $GO_TOOLCACHE_PATH\nfi\n\necho \"Delete Go $GO_VERSION if installed\"\nrm -rf $GO_TOOLCACHE_VERSION_PATH\n\necho \"Create Go $GO_VERSION folder\"\nmkdir -p $GO_TOOLCACHE_VERSION_ARCH_PATH\n\necho \"Copy Go binaries to hostedtoolcache folder\"\ncp -R ./* $GO_TOOLCACHE_VERSION_ARCH_PATH\nrm $GO_TOOLCACHE_VERSION_ARCH_PATH/setup.sh\n\necho \"Create complete file\"\ntouch $GO_TOOLCACHE_VERSION_PATH/$ARCH.complete\n\n",'utf8');
   assert.equal(marker.length,694);
   assert.equal(createHash('sha256').update(marker).digest('hex'),'ae49e39291a8c0731482cc314c56e368380d9a7fff45f0c6416361f31120e3e7');
   fs.writeFileSync(path.join(input,'setup.sh'),marker,{flag:'wx',mode:0o600});
   }catch(error){copyError=error;throw error;}
  });
  }catch(error){
   if(copyError&&copyError!==error)throw new AggregateError([copyError,error],'Q032 test input copy and source post-verification both failed');
   throw error;
  }
  const proof=verifyQ021CurrentSDK(source,input);
  assert.deepEqual(proof,{version:'1.26.9',files:15046,directories:1667,identity_class:'PINNED_CI_REPACK_LOGICAL_IDENTITY',official_payload_members_match:true,complete_fixed_archive_identity:false,original_official_raw_archive_identity:false,setup_sh_executed:false});
  assert.equal(process.env.PATH,originalPath);
  assert.equal(process.env.AIPT_Q021_REAL_TEST_SDK,originalEnvironment);
  process.env.AIPT_Q021_REAL_TEST_SDK=input;
  environmentInstalled=true;
  console.log(JSON.stringify({schema:'aipt.Q032.owned-legacy-repack-test-input/v1',raw_SDK:rawRoot,owned_test_input:input,raw_files:15045,repack_files:15046,directories:1667,marker_executed:false,official_archive_identity_promoted:false,production_SDK_or_PATH_mutated:false}));
  return {adapted:true,input,rawRoot,proof,originalPath};
 }catch(primary){
  try{retire();}catch(cleanup){throw new AggregateError([primary,cleanup],'Q032 test input failed and owned cleanup did not complete');}
  throw primary;
 }
}
const q032LegacySDKTestInput=q032PrepareLegacySDKTestInput();

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

// All original53 bodies above remain intact. These checks read a real complete
// pinned SDK and never execute any SDK program, model, database or namespace.
function q021RealInput() {
 const candidates=[];
 if(process.env.AIPT_Q021_REAL_TEST_SDK)candidates.push(process.env.AIPT_Q021_REAL_TEST_SDK);
 if(process.env.GOROOT)candidates.push(process.env.GOROOT);
 for(const bin of (process.env.PATH??'').split(path.delimiter))if(bin)candidates.push(path.dirname(path.resolve(bin)));
 for(const root of [...new Set(candidates)])try{
  if(fs.existsSync(path.join(root,'setup.sh'))&&verifyQ021CurrentSDK(source,root).identity_class==='PINNED_CI_REPACK_LOGICAL_IDENTITY')return root;
 }catch{/* Only the exact complete pinned repack can become this test input. */}
 throw new Error('Q021 full real exact repack test input unavailable; no skipped positive');
}
function q021TestScope(t,input) {
 const owned=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q021-real-SDK-test-')),root=path.join(owned,'SDK');
 fs.mkdirSync(root,{mode:0o700});
 const spec=qualification(source).SDKs.find(s=>s.version==='1.26.9');
 for(const rel of spec.directories.filter(d=>d!=='.').sort((a,b)=>a.split('/').length-b.split('/').length||a.localeCompare(b)))fs.mkdirSync(path.join(root,rel),{mode:0o700});
 for(const f of [...spec.files,{relative:'setup.sh'}])fs.copyFileSync(path.join(input,f.relative),path.join(root,f.relative));
 t.after(()=>{
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const n of fs.readdirSync(p))walk(path.join(p,n));}else if(s.isFile()){bytes+=s.size;files++;}};
  walk(owned);fs.rmSync(owned,{recursive:true,force:true});assert.equal(fs.existsSync(owned),false);
  console.log(JSON.stringify({owned_scratch:owned,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0}));
 });
 return {owned,root,spec};
}
function q021PatchFS(replacements,body) {
 const original=Object.fromEntries(Object.keys(replacements).map(k=>[k,fs[k]]));
 try{for(const [k,fn]of Object.entries(replacements))fs[k]=fn(original[k]);return body();}
 finally{for(const [k,fn]of Object.entries(original))fs[k]=fn;}
}
function q021AuthorityFixture(owned,name) {
 const repo=path.join(owned,name);fs.mkdirSync(repo,{mode:0o700});
 for(const rel of [Q018_AUTHORITY,Q019_AUTHORITY,Q019_PROPOSAL,Q021_AUTHORITY,Q021_PROPOSAL,Q018_QUALIFICATION]){
  const p=path.join(repo,rel);fs.mkdirSync(path.dirname(p),{recursive:true});fs.copyFileSync(path.join(source,rel),p);fs.chmodSync(p,0o600);
 }
 assert.equal(q021Approved(repo),true);return repo;
}
test('Q021 complete real SDK qualification and controlled read-only boundaries',async t=>{
 const input=q021RealInput(),{owned,root,spec}=q021TestScope(t,input);
 const marker=path.join(root,'setup.sh'),markerBytes=fs.readFileSync(marker),go=path.join(root,'bin/go');
 const goBytes=fs.readFileSync(go),goMode=fs.statSync(go).mode&0o777;
 await t.test('exact15046 repack passes without official raw-archive promotion or SDK mutations',()=>{
  const methods=['mkdirSync','mkdtempSync','copyFileSync','writeFileSync','chmodSync','fchmodSync','renameSync','unlinkSync','rmSync','rmdirSync','truncateSync','ftruncateSync','writeSync'];
  const replacements=Object.fromEntries(methods.map(k=>[k,()=>()=>{throw new Error('unexpected SDK adapter mutation '+k);} ]));
  const v=q021PatchFS(replacements,()=>verifyQ021CurrentSDK(source,root));
  assert.deepEqual(v,{version:'1.26.9',files:15046,directories:1667,identity_class:'PINNED_CI_REPACK_LOGICAL_IDENTITY',official_payload_members_match:true,complete_fixed_archive_identity:false,original_official_raw_archive_identity:false,setup_sh_executed:false});
 });
 await t.test('original official15045 verifier and official adapter path retain their result',()=>{
  fs.unlinkSync(marker);
  try{assert.deepEqual(verifyQ021CurrentSDK(source,root),verifySDK(root,spec));assert.equal(verifySDK(root,spec).files,15045);}
  finally{fs.writeFileSync(marker,markerBytes,{mode:0o600});}
 });
 await t.test('caller-provided SDK spec or option is rejected before qualification',()=>assert.throws(()=>verifyQ021CurrentSDK(source,root,{files:[]}),/no caller SDK spec/));
 for(const [name,apply,restore]of[
  ['marker hash',()=>fs.writeFileSync(marker,Buffer.alloc(694)),()=>fs.writeFileSync(marker,markerBytes)],
  ['marker size',()=>fs.appendFileSync(marker,'x'),()=>fs.writeFileSync(marker,markerBytes)],
  ['marker executable bit',()=>fs.chmodSync(marker,0o700),()=>fs.chmodSync(marker,0o600)],
  ['extra file',()=>fs.writeFileSync(path.join(root,'extra'),'unexpected'),()=>fs.unlinkSync(path.join(root,'extra'))],
  ['extra directory',()=>fs.mkdirSync(path.join(root,'extra')),()=>fs.rmdirSync(path.join(root,'extra'))],
  ['missing compiler',()=>fs.renameSync(go,path.join(owned,'go-held')),()=>fs.renameSync(path.join(owned,'go-held'),go)],
  ['compiler execute bit',()=>fs.chmodSync(go,0o600),()=>fs.chmodSync(go,goMode)],
  ['hard-linked marker',()=>fs.linkSync(marker,path.join(owned,'marker-alias')),()=>fs.unlinkSync(path.join(owned,'marker-alias'))],
  ['symlinked marker',()=>{fs.unlinkSync(marker);fs.symlinkSync('/dev/null',marker);},()=>{fs.unlinkSync(marker);fs.writeFileSync(marker,markerBytes,{mode:0o600});}],
  ['FIFO marker',()=>{fs.unlinkSync(marker);const z=spawnSync('/usr/bin/mkfifo',[marker]);assert.equal(z.error,undefined);assert.equal(z.status,0);},()=>{fs.unlinkSync(marker);fs.writeFileSync(marker,markerBytes,{mode:0o600});}],
 ])await t.test('complete qualification rejects '+name,()=>{apply();try{assert.throws(()=>verifyQ021CurrentSDK(source,root));}finally{restore();}});
 await t.test('physical ancestry and root reject symbolic aliases',()=>{
  const alias=path.join(owned,'alias');fs.symlinkSync(root,alias);
  try{assert.throws(()=>verifyQ021CurrentSDK(source,alias),/nonphysical/);}finally{fs.unlinkSync(alias);}
  const parentAlias=path.join(owned,'parent-alias');fs.symlinkSync(owned,parentAlias);
  try{assert.throws(()=>verifyQ021CurrentSDK(source,path.join(parentAlias,'SDK')),/nonphysical/);}finally{fs.unlinkSync(parentAlias);}
 });
 for(const [name,change]of [
  ['absent authority',p=>fs.unlinkSync(p)],
  ['proposal state',p=>{const v=JSON.parse(fs.readFileSync(p));v.state='PROPOSAL_ONLY';fs.writeFileSync(p,JSON.stringify(v));}],
  ['altered authority bytes',p=>fs.appendFileSync(p,' ')],
 ])await t.test('exact Owner boundary rejects '+name,()=>{
  const repo=q021AuthorityFixture(owned,'authority-'+name.replaceAll(' ','-'));change(path.join(repo,Q021_AUTHORITY));
  assert.equal(q021Approved(repo),false);assert.throws(()=>verifyQ021CurrentSDK(repo,root),/exact approved Owner/);
 });
 await t.test('altered or absent bound proposal is rejected',()=>{
  const repo=q021AuthorityFixture(owned,'proposal-negative'),p=path.join(repo,Q021_PROPOSAL);
  fs.appendFileSync(p,' ');assert.throws(()=>verifyQ021CurrentSDK(repo,root),/exact approved Owner/);
  fs.unlinkSync(p);assert.throws(()=>verifyQ021CurrentSDK(repo,root),/exact approved Owner/);
 });
 await t.test('first root acquisition rejects a substituted directory and leaves it intact',()=>{
  const saved=path.join(owned,'saved-SDK');let replaced=false;
  try{
   assert.throws(()=>q021PatchFS({openSync:original=>(p,...args)=>{
    if(!replaced&&typeof p==='string'&&p.startsWith('/proc/self/fd/')&&p.endsWith('/SDK')){
     replaced=true;fs.renameSync(root,saved);fs.mkdirSync(root,{mode:0o700});fs.writeFileSync(path.join(root,'sentinel'),'owned foreign sentinel');
    }
    return original(p,...args);
   }},()=>verifyQ021CurrentSDK(source,root)),/directory replaced/);
   assert.equal(replaced,true);assert.equal(fs.readFileSync(path.join(root,'sentinel'),'utf8'),'owned foreign sentinel');
  }finally{if(replaced){fs.rmSync(root,{recursive:true});fs.renameSync(saved,root);}}
 });
 await t.test('held descendant directory rejects replacement during enumeration',()=>{
  const bin=path.join(root,'bin'),saved=path.join(owned,'saved-bin');let replaced=false;
  try{
   assert.throws(()=>q021PatchFS({readdirSync:original=>(p,...args)=>{
    if(!replaced&&typeof p==='string'&&p.startsWith('/proc/self/fd/')&&fs.readlinkSync(p)===bin){
     replaced=true;fs.renameSync(bin,saved);fs.mkdirSync(bin);fs.writeFileSync(path.join(bin,'sentinel'),'owned foreign bin');
    }
    return original(p,...args);
   }},()=>verifyQ021CurrentSDK(source,root)),/directory identity changed/);
   assert.equal(replaced,true);assert.equal(fs.readFileSync(path.join(bin,'sentinel'),'utf8'),'owned foreign bin');
  }finally{if(replaced){fs.rmSync(bin,{recursive:true});fs.renameSync(saved,bin);}}
 });
 await t.test('first file acquisition rejects an inode substitute',()=>{
  const saved=path.join(owned,'saved-go');let replaced=false;
  try{
   assert.throws(()=>q021PatchFS({openSync:original=>(p,...args)=>{
    if(!replaced&&typeof p==='string'&&p.startsWith('/proc/self/fd/')&&p.endsWith('/go')&&fs.readlinkSync(path.dirname(p))===path.dirname(go)){
     replaced=true;fs.renameSync(go,saved);fs.writeFileSync(go,goBytes,{mode:goMode});
    }
    return original(p,...args);
   }},()=>verifyQ021CurrentSDK(source,root)),/member replaced/);
   assert.equal(replaced,true);assert.deepEqual(fs.readFileSync(go),goBytes);
  }finally{if(replaced){fs.unlinkSync(go);fs.renameSync(saved,go);}}
 });
 await t.test('full stream detects content changed while its file descriptor is held',()=>{
  let changed=false;
  try{
   assert.throws(()=>q021PatchFS({readSync:original=>(fd,...args)=>{
    const n=original(fd,...args);
    if(!changed&&fs.readlinkSync('/proc/self/fd/'+fd)===go){changed=true;const modified=Buffer.from(goBytes);modified[modified.length-1]^=1;fs.writeFileSync(go,modified);}
    return n;
   }},()=>verifyQ021CurrentSDK(source,root)),/full SDK member identity changed/);
   assert.equal(changed,true);
  }finally{fs.writeFileSync(go,goBytes);}
 });
 await t.test('read failure closes every tracked file and directory descriptor',()=>{
  const opened=new Set();let failed=false;
  q021PatchFS({
   openSync:original=>(...args)=>{const fd=original(...args);opened.add(fd);return fd;},
   closeSync:original=>fd=>{opened.delete(fd);return original(fd);},
   readSync:original=>(fd,...args)=>{if(fs.readlinkSync('/proc/self/fd/'+fd)===go){failed=true;throw new Error('SYNTHETIC_READ_FAILURE');}return original(fd,...args);},
  },()=>assert.throws(()=>verifyQ021CurrentSDK(source,root),/SYNTHETIC_READ_FAILURE/));
  assert.equal(failed,true);assert.equal(opened.size,0);
 });
 await t.test('both sides of a synchronous action stream the complete SDK again',()=>{
  let streamed=0;let called=0;
  const value=q021PatchFS({readSync:original=>(fd,...args)=>{const n=original(fd,...args);if(fs.readlinkSync('/proc/self/fd/'+fd).startsWith(root+'/'))streamed+=n;return n;}},()=>withQ021VerifiedCurrentSDK(source,root,()=>{called++;return 'SYNTHETIC_METADATA_RESULT_NOT_SDK_EXECUTION';}));
  assert.equal(value,'SYNTHETIC_METADATA_RESULT_NOT_SDK_EXECUTION');assert.equal(called,1);
  assert.ok(streamed>=4*(spec.files.reduce((sum,f)=>sum+f.bytes,0)+694));
 });
 await t.test('post-action verification rejects a visible change even when action fails',()=>{
  let called=false;
  try{assert.throws(()=>withQ021VerifiedCurrentSDK(source,root,()=>{called=true;fs.appendFileSync(marker,'x');throw new Error('SYNTHETIC_COMMAND_FAILURE');}),/Q021.*changed SDK member/);assert.equal(called,true);}
  finally{fs.writeFileSync(marker,markerBytes);}
 });
 await t.test('unchanged failed action still rechecks and preserves its failure',()=>{
  assert.throws(()=>withQ021VerifiedCurrentSDK(source,root,()=>{throw new Error('SYNTHETIC_COMMAND_FAILURE');}),/SYNTHETIC_COMMAND_FAILURE/);
 });
 await t.test('byte-identical inode replacement across action remains a failure',()=>{
  const saved=path.join(owned,'saved-marker');
  try{assert.throws(()=>withQ021VerifiedCurrentSDK(source,root,()=>{fs.renameSync(marker,saved);fs.writeFileSync(marker,markerBytes,{mode:0o600});}),/SDK changed across current metadata command/);}
  finally{fs.unlinkSync(marker);fs.renameSync(saved,marker);}
 });
 // Instantaneous same-UID replacement and restoration is an accepted trust
 // limitation, not an executed negative or a claim of atomic path execution.
 assert.equal(verifyQ021CurrentSDK(source,root).files,15046);
});

function q021OwnedGit(repo,args,allowed=[0]) {
 const r=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,...args],{encoding:'utf8',env:{...process.env,GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 assert.equal(r.error,undefined);assert.equal(r.signal,null);assert.ok(allowed.includes(r.status),r.stderr);
 return {status:r.status,stdout:r.stdout.trim()};
}
function q021CloneOriginFixture(t) {
 const owned=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q021-fixed-origin-test-')),repo=path.join(owned,'source');
 t.after(()=>{
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){bytes+=s.size;files++;}};
  walk(owned);fs.rmSync(owned,{recursive:true,force:true});assert.equal(fs.existsSync(owned),false);
  console.log(JSON.stringify({owned_scratch:owned,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0}));
 });
 fs.mkdirSync(repo,{mode:0o700});
 q021OwnedGit(source,['clone','--no-local','--no-checkout',source,repo]);
 const paths=q021OwnedGit(source,['ls-files','--cached','--others','--exclude-standard']).stdout.split('\n');
 assert.equal(new Set(paths).size,652);
 q021OwnedGit(repo,['checkout','--force','--detach','5f3f6353d744f6674de7cb610a8d8e9b9220c02a']);
 for(const relative of paths){const dest=path.join(repo,relative);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(path.join(source,relative),dest);}
 q021OwnedGit(repo,['add','--all']);
 q021OwnedGit(repo,['-c','user.name=Synthetic Q021 Clone Probe','-c','user.email=probe@example.invalid','-c','core.hooksPath=/dev/null','commit','-m','Synthetic single-BASE current652 CI checkout']);
 const allRefs=q021OwnedGit(repo,['for-each-ref','--format=%(refname)']).stdout.split('\n').filter(Boolean);
 for(const ref of allRefs)q021OwnedGit(repo,['update-ref','--no-deref','-d',ref]);
 q021OwnedGit(repo,['update-ref','refs/heads/main','5f3f6353d744f6674de7cb610a8d8e9b9220c02a']);
 q021OwnedGit(repo,['update-ref','refs/remotes/origin/main','5f3f6353d744f6674de7cb610a8d8e9b9220c02a']);
 const fixed=[['pr27','ec76d9c5cba0c32f3bb58c2a0abb9602f9ebe2d8'],['pr28','f7c3736acd3524240ec178dc81e0a1c72a690930'],['pr29','d9228b80329380aafc9282f6ce72aa5c0eb30b11']];
 for(const [name,commit]of fixed)q021OwnedGit(repo,['update-ref','refs/remotes/origin/synthetic-history-'+name,commit]);
 return {owned,repo,paths,fixed};
}
function q021OwnedRefState(repo) {return q021OwnedGit(repo,['for-each-ref','--format=%(refname) %(objectname) %(symref)']).stdout;}
test('Q021 fixed local clone preparation preserves the original history and fails closed',async t=>{
 await t.test('remote-only sibling objects are absent before preparation and exact after one atomic fixed-ref preparation',s=>{
  const {owned,repo,paths,fixed}=q021CloneOriginFixture(s);
  const before=paths.map(relative=>({relative,sha256:hash(fs.readFileSync(path.join(repo,relative))),mode:fs.statSync(path.join(repo,relative)).mode}));
  const head=q021OwnedGit(repo,['rev-parse','HEAD']).stdout,tree=q021OwnedGit(repo,['rev-parse','HEAD^{tree}']).stdout;
  const index=fs.readFileSync(path.join(repo,'.git/index'));
  const clone=name=>{const dest=path.join(owned,name);q021OwnedGit(repo,['clone','--no-local','--no-checkout',repo,dest]);return dest;};
  const absent=clone('before');for(const [,commit]of fixed)assert.equal(q021OwnedGit(absent,['cat-file','-e',commit+'^{commit}'],[128]).status,128);
  const v=prepareQ021FixedCloneOrigins(repo);assert.equal(v.result,'PASS_Q021_FIXED_LOCAL_CLONE_ORIGINS_PREPARED');assert.equal(v.full_HIGH_or_CI_or_runtime_accepted,false);
  const exact=clone('after');for(const [name,commit]of fixed){assert.equal(q021OwnedGit(exact,['cat-file','-e',commit+'^{commit}']).status,0);assert.equal(q021OwnedGit(repo,['rev-parse','refs/heads/codex/q021-fixed-history-'+name]).stdout,commit);}
  const refs=q021OwnedRefState(repo);assert.equal(prepareQ021FixedCloneOrigins(repo).result,v.result);assert.equal(q021OwnedRefState(repo),refs);
  assert.deepEqual(paths.map(relative=>({relative,sha256:hash(fs.readFileSync(path.join(repo,relative))),mode:fs.statSync(path.join(repo,relative)).mode})),before);
  assert.equal(q021OwnedGit(repo,['rev-parse','HEAD']).stdout,head);assert.equal(q021OwnedGit(repo,['rev-parse','HEAD^{tree}']).stdout,tree);
  assert.equal(q021OwnedGit(repo,['rev-parse','refs/remotes/origin/main']).stdout,'5f3f6353d744f6674de7cb610a8d8e9b9220c02a');assert.deepEqual(fs.readFileSync(path.join(repo,'.git/index')),index);
 });
 await t.test('an existing incorrect fixed local ref rejects the complete transaction without any ref changes',s=>{
  const {repo}=q021CloneOriginFixture(s);q021OwnedGit(repo,['update-ref','refs/heads/codex/q021-fixed-history-pr28','5f3f6353d744f6674de7cb610a8d8e9b9220c02a']);
  const before=q021OwnedRefState(repo);assert.throws(()=>prepareQ021FixedCloneOrigins(repo),/overwrite forbidden/);assert.equal(q021OwnedRefState(repo),before);
 });
 await t.test('protected source drift is rejected before any fixed local ref creation',s=>{
  const {repo}=q021CloneOriginFixture(s);fs.appendFileSync(path.join(repo,'go.mod'),'\n// synthetic forbidden drift\n');
  const before=q021OwnedRefState(repo);assert.throws(()=>prepareQ021FixedCloneOrigins(repo),/prerequisites failed/);assert.equal(q021OwnedRefState(repo),before);
 });
});

// Live654 checks are separate from every retained original652 test case.
function q022CurrentFixture(t) {
 const owned=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q022-current654-test-')),repo=path.join(owned,'source');
 t.after(()=>{
  let bytes=0,files=0,dirs=0;const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const n of fs.readdirSync(p))walk(path.join(p,n));}else if(s.isFile()){bytes+=s.size;files++;}else throw new Error('unexpected owned Q022 artifact');};
  walk(owned);fs.rmSync(owned,{recursive:true,force:true});assert.equal(fs.existsSync(owned),false);
  console.log(JSON.stringify({owned_scratch:owned,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0}));
 });
 q021OwnedGit(currentSource,['clone','--no-local','--no-checkout',currentSource,repo]);
 q021OwnedGit(repo,['checkout','--detach','5f3f6353d744f6674de7cb610a8d8e9b9220c02a']);
 q021OwnedGit(repo,['update-ref','refs/remotes/origin/main','5f3f6353d744f6674de7cb610a8d8e9b9220c02a']);
 const paths=q021OwnedGit(currentSource,['ls-files','--cached','--others','--exclude-standard','-z']).stdout.split('\0').filter(Boolean);assert.equal(new Set(paths).size,654);
 for(const relative of paths){const dest=path.join(repo,relative);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(path.join(currentSource,relative),dest);fs.chmodSync(dest,fs.statSync(path.join(currentSource,relative)).mode&0o777);}
 return {repo,owned};
}
test('Q022 live654 exact pair preserves fixed PR30 full652 history and requires local positive',()=>{
 assert.equal(q022Approved(currentSource),true);assert.deepEqual(q022SourceProblems(currentSource),[]);
 assert.deepEqual(q022RevisionProblems(currentSource,Q022_BASELINE,{original:true}),[]);
 assert.ok(q022RevisionProblems(currentSource,'5f3f6353d744f6674de7cb610a8d8e9b9220c02a',{original:true}).length);
 const p=JSON.parse(fs.readFileSync(path.join(currentSource,Q022_PROPOSAL)));assert.equal(p.baseline652.length,652);assert.equal(p.protected646.length,646);assert.equal(p.mandatory_local_positive.SKIP_or_FAIL_keeps_admission_closed,true);assert.equal(p.namespace_fixture_contract.required_1_always_rejects_unavailability,true);
});
for(const [name,mutate]of[
 ['missing Authority',r=>fs.unlinkSync(path.join(r,Q022_AUTHORITY))],
 ['missing bound proposal',r=>fs.unlinkSync(path.join(r,Q022_PROPOSAL))],
 ['proposal-state instead of approval',r=>{const f=path.join(r,Q022_AUTHORITY),v=JSON.parse(fs.readFileSync(f));v.state='PROPOSAL_ONLY';fs.writeFileSync(f,JSON.stringify(v));}],
 ['Authority appended byte',r=>fs.appendFileSync(path.join(r,Q022_AUTHORITY),' ')],
 ['bound proposal appended byte',r=>fs.appendFileSync(path.join(r,Q022_PROPOSAL),' ')],
 ['altered Q021 Owner history',r=>fs.appendFileSync(path.join(r,Q021_AUTHORITY),' ')],
 ['changed namespace marker',r=>{const f=path.join(r,'internal/pilot/runtime_namespace_test.go');fs.writeFileSync(f,fs.readFileSync(f,'utf8').replace('AIPT_OPTIONAL_NS_USER_HANDLE_EACCES','AIPT_OPTIONAL_NS_ANY_ERROR'));}],
 ['changed exact workflow',r=>fs.appendFileSync(path.join(r,'.github/workflows/ci.yml'),'\n# broadened\n')],
 ['changed protected646 bytes',r=>fs.appendFileSync(path.join(r,'internal/operational/runtime.go'),'\n// forbidden\n')],
 ['changed protected646 executable mode',r=>fs.chmodSync(path.join(r,'internal/operational/runtime.go'),0o700)],
 ['changed allowed program executable mode',r=>fs.chmodSync(path.join(r,Q022_WORK_PATHS[2]),0o700)],
 ['changed new Authority executable mode',r=>fs.chmodSync(path.join(r,Q022_AUTHORITY),0o700)],
 ['unknown untracked source',r=>fs.writeFileSync(path.join(r,'q022-unapproved-source.txt'),'unexpected\n')],
])test('Q022 exact current guard refuses '+name,t=>{const {repo}=q022CurrentFixture(t);mutate(repo);assert.ok(q022SourceProblems(repo).length>0);});
test('Q022 exact CI dependency exclusion accepts only untracked generated node_modules',t=>{
 const {repo}=q022CurrentFixture(t);const n=path.join(repo,'node_modules/generated/package.json');fs.mkdirSync(path.dirname(n),{recursive:true});fs.writeFileSync(n,'{}\n');
 assert.ok(q022SourceProblems(repo).some(v=>v.includes('working source set changed')));
 fs.appendFileSync(path.join(repo,'.git/info/exclude'),'\nnode_modules/\n');assert.deepEqual(q022SourceProblems(repo),[]);
 fs.writeFileSync(path.join(repo,'unrelated-generated.txt'),'unexpected\n');assert.ok(q022SourceProblems(repo).length);fs.unlinkSync(path.join(repo,'unrelated-generated.txt'));
 q021OwnedGit(repo,['add','-f','--','node_modules/generated/package.json']);assert.ok(q022SourceProblems(repo).some(v=>v.includes('working source set changed')));
 assert.notEqual(q021OwnedGit(repo,['ls-files','--','node_modules/**',':(glob)**/node_modules/**']).stdout,'');
});
test('Q022 fixed PR30 ref creation is exact, idempotent, refuses overwrite/options/symbolic refs',t=>{
 const {repo}=q022CurrentFixture(t),ref='refs/heads/codex/q022-fixed-history-pr30';
 const index=fs.readFileSync(path.join(repo,'.git/index')),head=q021OwnedGit(repo,['rev-parse','HEAD']).stdout;
 const result=prepareQ022FixedCloneOrigin(repo);assert.equal(result.commit,Q022_BASELINE);assert.equal(result.full_HIGH_or_CI_or_runtime_accepted,false);
 const exact=q021OwnedRefState(repo);assert.equal(prepareQ022FixedCloneOrigin(repo).result,result.result);assert.equal(q021OwnedRefState(repo),exact);
 assert.deepEqual(fs.readFileSync(path.join(repo,'.git/index')),index);assert.equal(q021OwnedGit(repo,['rev-parse','HEAD']).stdout,head);
 assert.throws(()=>prepareQ022FixedCloneOrigin(repo,{commit:head}),/no caller targets/);
 q021OwnedGit(repo,['update-ref',ref,head]);const wrong=q021OwnedRefState(repo);assert.throws(()=>prepareQ022FixedCloneOrigin(repo),/overwrite forbidden/);assert.equal(q021OwnedRefState(repo),wrong);
 q021OwnedGit(repo,['update-ref','--no-deref','-d',ref]);q021OwnedGit(repo,['symbolic-ref',ref,'refs/heads/main']);const symbolic=q021OwnedRefState(repo);assert.throws(()=>prepareQ022FixedCloneOrigin(repo),/symbolic/);assert.equal(q021OwnedRefState(repo),symbolic);
});

// Q023 cases use live656. The original101 cases above use fixed654/nested652.
function q023OwnedGit(repo,args,statuses=[0]) {
 const r=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,...args],{encoding:'utf8',env:{...process.env,GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 assert.equal(r.error,undefined);assert.equal(r.signal,null);assert.ok(statuses.includes(r.status),r.stderr);return r.stdout.trim();
}
function q023SDKFixture(t) {
 const owned=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q023-sdk-boundary-')),repo=path.join(owned,'source');
 t.after(()=>{
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){bytes+=s.size;files++;}};
  walk(owned);fs.rmSync(owned,{recursive:true,force:true});assert.equal(fs.existsSync(owned),false);
  console.log(JSON.stringify({owned_scratch:owned,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0}));
 });
 q023OwnedGit(q023CurrentSource,['clone','--no-local','--no-checkout',q023CurrentSource,repo]);
 q023OwnedGit(repo,['checkout','--detach','5f3f6353d744f6674de7cb610a8d8e9b9220c02a']);
 q023OwnedGit(repo,['update-ref','refs/remotes/origin/main','5f3f6353d744f6674de7cb610a8d8e9b9220c02a']);
 q023OwnedGit(repo,['config','core.hooksPath','/dev/null']);
 const paths=q023OwnedGit(q023CurrentSource,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);
 assert.equal(new Set(paths).size,656);
 for(const relative of paths){const dest=path.join(repo,relative);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(path.join(q023CurrentSource,relative),dest);}
 return {owned,repo,paths};
}
test('Q023 binds exact5plus2/649 source and retains fixed654 and definition251 without acceptance grants',()=>{
 assert.equal(q023Approved(q023CurrentSource),true);assert.deepEqual(q023SourceProblems(q023CurrentSource),[]);
 const p=q023Proposal(q023CurrentSource);assert.equal(p.baseline654.length,654);assert.equal(p.protected649.length,649);
 assert.equal(Q023_WORK_PATHS.length,5);assert.equal(Q023_NEW_PATHS.length,2);
 assert.equal(p.new_fixed_P1_route.fixed_definition251.length,251);assert.equal(p.new_fixed_P1_route.verification_target.source_count,232);
 assert.equal(p.original_PR31_CI.FAIL,2);assert.equal(p.old_source654_HIGH_not_transferred_to656,true);
 assert.equal(p.runtime_ready,false);assert.equal(p.paid_callable,false);assert.equal(p.qualification_runs_authorized,0);
 assert.deepEqual(q023RevisionProblems(q023CurrentSource,Q023_BASELINE,{original:true}),[]);
 assert.ok(q023RevisionProblems(q023CurrentSource,'5f3f6353d744f6674de7cb610a8d8e9b9220c02a',{original:true}).length);
});
test('Q023 original101 SDK and helpers, historical bodies and six routes remain complete',()=>{
 const relative='scripts/ci/test/b007-toolchain-security-q018.test.mjs',old=fs.readFileSync(path.join(currentSource,relative),'utf8'),live=fs.readFileSync(path.join(q023CurrentSource,relative),'utf8');
 assert.ok(live.slice(live.indexOf('const hash=')).startsWith(old.slice(old.indexOf('const hash='))));
 const file='scripts/ci/lib/b007-toolchain-security-q018.mjs',original=fs.readFileSync(path.join(currentSource,file),'utf8'),next=fs.readFileSync(path.join(q023CurrentSource,file),'utf8');
 for(const marker of ['export function verifySDK(root,spec) {','export function historicalEnvironment(repo,target,route) {','function snapshot(repo,commit,tree) {','export function runFixedHistoricalCLI(repo,route) {','function q021CloneState(repo) {','function q021CloneRef(repo,ref) {','export function prepareQ021FixedCloneOrigins(repo) {']){
  const start=original.indexOf(marker),fragment=original.slice(start,original.indexOf('\n}\n',start)+3);assert.ok(next.includes(fragment),marker);
 }
 assert.equal(Q018_ROUTES.length,6);
 assert.ok(next.includes("else if(command==='--p1-reverification')runFixedHistoricalCLI(repo,'P1_REVERIFICATION');"));
 assert.ok(next.includes("else if(command==='--q023-fixed-p1-reverification')runQ023FixedP1Reverification(repo);"));
});
for(const [name,mutate]of[
 ['missing Authority',r=>fs.unlinkSync(path.join(r,Q023_AUTHORITY))],
 ['missing bound proposal',r=>fs.unlinkSync(path.join(r,Q023_PROPOSAL))],
 ['proposal-state instead of approval',r=>{const f=path.join(r,Q023_AUTHORITY),v=JSON.parse(fs.readFileSync(f));v.state='PROPOSAL_ONLY';fs.writeFileSync(f,JSON.stringify(v));}],
 ['Authority appended byte',r=>fs.appendFileSync(path.join(r,Q023_AUTHORITY),' ')],
 ['bound proposal appended byte',r=>fs.appendFileSync(path.join(r,Q023_PROPOSAL),' ')],
 ['prior Q022 Authority rewrite',r=>fs.appendFileSync(path.join(r,Q022_AUTHORITY),' ')],
 ['protected namespace fixture rewrite',r=>fs.appendFileSync(path.join(r,'internal/pilot/runtime_namespace_test.go'),'\n// unapproved\n')],
 ['protected operational bytes',r=>fs.appendFileSync(path.join(r,'internal/operational/runtime.go'),'\n// unapproved\n')],
 ['exact workflow rewrite',r=>fs.appendFileSync(path.join(r,'.github/workflows/ci.yml'),'\n# unapproved\n')],
 ['protected executable mode',r=>fs.chmodSync(path.join(r,'internal/operational/runtime.go'),0o700)],
 ['allowed program executable mode',r=>fs.chmodSync(path.join(r,Q023_WORK_PATHS[1]),0o700)],
 ['Owner record executable mode',r=>fs.chmodSync(path.join(r,Q023_AUTHORITY),0o700)],
 ['symbolic program alias',r=>{const f=path.join(r,Q023_WORK_PATHS[1]);fs.unlinkSync(f);fs.symlinkSync('/dev/null',f);}],
 ['hardlinked protected source',r=>fs.linkSync(path.join(r,'internal/operational/runtime.go'),path.join(r,'hardlink-extra.go'))],
 ['unknown untracked source',r=>fs.writeFileSync(path.join(r,'q023-extra.go'),'unapproved\n')],
])test('Q023 current656 boundary refuses '+name,t=>{const {repo}=q023SDKFixture(t);mutate(repo);assert.ok(q023SourceProblems(repo).length>0);});
test('Q023 retains exclusion only for untracked generated node_modules and refuses a tracked or unrelated addition',t=>{
 const {repo}=q023SDKFixture(t);const n=path.join(repo,'node_modules/generated/package.json');fs.mkdirSync(path.dirname(n),{recursive:true});fs.writeFileSync(n,'{}\n');
 assert.ok(q023SourceProblems(repo).length);fs.appendFileSync(path.join(repo,'.git/info/exclude'),'\nnode_modules/\n');assert.deepEqual(q023SourceProblems(repo),[]);
 fs.writeFileSync(path.join(repo,'unrelated-generated.txt'),'unexpected\n');assert.ok(q023SourceProblems(repo).length);fs.unlinkSync(path.join(repo,'unrelated-generated.txt'));
 q023OwnedGit(repo,['add','-f','--','node_modules/generated/package.json']);assert.ok(q023SourceProblems(repo).length);
});
test('Q023 fixed PR31 origin preparation is exact and idempotent, preserving source/HEAD/tree/index/main',t=>{
 const {repo,paths}=q023SDKFixture(t),ref='refs/heads/codex/q023-fixed-history-pr31';
 const before=paths.map(relative=>({relative,sha256:hash(fs.readFileSync(path.join(repo,relative))),mode:fs.statSync(path.join(repo,relative)).mode}));
 const index=fs.readFileSync(path.join(repo,'.git/index')),identity=q023OwnedGit(repo,['rev-parse','HEAD','HEAD^{tree}','refs/remotes/origin/main']);
 const v=prepareQ023FixedCloneOrigin(repo);assert.equal(v.commit,Q023_BASELINE);assert.equal(v.tree,Q023_BASELINE_TREE);assert.equal(v.full_HIGH_or_CI_or_runtime_accepted,false);
 const refs=q023OwnedGit(repo,['for-each-ref','--format=%(refname) %(objectname) %(symref)']);
 assert.equal(prepareQ023FixedCloneOrigin(repo).result,v.result);assert.equal(q023OwnedGit(repo,['for-each-ref','--format=%(refname) %(objectname) %(symref)']),refs);
 assert.equal(q023OwnedGit(repo,['rev-parse',ref]),Q023_BASELINE);assert.deepEqual(fs.readFileSync(path.join(repo,'.git/index')),index);
 assert.equal(q023OwnedGit(repo,['rev-parse','HEAD','HEAD^{tree}','refs/remotes/origin/main']),identity);
 assert.deepEqual(paths.map(relative=>({relative,sha256:hash(fs.readFileSync(path.join(repo,relative))),mode:fs.statSync(path.join(repo,relative)).mode})),before);
 assert.throws(()=>prepareQ023FixedCloneOrigin(repo,{commit:Q023_BASELINE}),/no caller targets/);
});
test('Q023 existing wrong or dangling symbolic PR31 ref fails before source or ref changes',t=>{
 const {repo}=q023SDKFixture(t),ref='refs/heads/codex/q023-fixed-history-pr31';
 q023OwnedGit(repo,['update-ref',ref,'5f3f6353d744f6674de7cb610a8d8e9b9220c02a']);
 const before=q023OwnedGit(repo,['for-each-ref','--format=%(refname) %(objectname) %(symref)']);
 assert.throws(()=>prepareQ023FixedCloneOrigin(repo),/overwrite forbidden/);assert.equal(q023OwnedGit(repo,['for-each-ref','--format=%(refname) %(objectname) %(symref)']),before);
 q023OwnedGit(repo,['update-ref','--no-deref','-d',ref]);q023OwnedGit(repo,['symbolic-ref',ref,'refs/heads/dangling-unregistered']);
 assert.throws(()=>prepareQ023FixedCloneOrigin(repo),/symbolic/);assert.equal(q023OwnedGit(repo,['symbolic-ref',ref]),'refs/heads/dangling-unregistered');
});
test('Q023 P1 function and CLI refuse caller target/argv/options before SDK or target execution',t=>{
 const {repo}=q023SDKFixture(t);assert.throws(()=>runQ023FixedP1Reverification(repo,{target:Q023_BASELINE}),/no caller target/);
 assert.throws(()=>runQ023FixedP1Reverification(),/no caller target/);
 const cli=spawnSync(process.execPath,['scripts/ci/lib/b007-toolchain-security-q018.mjs','--q023-fixed-p1-reverification','--target',Q023_BASELINE],{cwd:repo,encoding:'utf8',env:process.env});
 assert.equal(cli.error,undefined);assert.equal(cli.signal,null);assert.equal(cli.status,1);assert.match(cli.stderr,/exact one fixed CLI route/);
});
test('Q023 new P1 entry rejects changed source before selecting or executing the historical SDK',t=>{
 const {repo}=q023SDKFixture(t);fs.writeFileSync(path.join(repo,'unapproved-before-P1.txt'),'unapproved\n');
 assert.throws(()=>runQ023FixedP1Reverification(repo),/exact Owner\/source656 prerequisites failed/);
});

// Q023 F2 regressions use only pure report objects; no target or SDK execution.
function q023P1ReportGolden() {return {
 "b001_regression": "PASS",
 "definition_commit": "8d6a438d051fb635e769285215e70536958a8f42",
 "definition_tree": "9ef6f121bd0d9a6484d7cc39a22450250e9ac489",
 "details": [
  "ok: exact-target-identity success",
  "ok: authority-validator success",
  "ok: b001-historical-validator success",
  "ok: effective-authority-resolution success",
  "ok: go-test-all-at-target success"
 ],
 "effective_authority_identities": "PASS",
 "formal_evidence_blocker": "REPAIR_CANDIDATE_INDEPENDENT_ACCEPTANCE_PENDING",
 "formal_evidence_eligible": false,
 "go_test_all": "PASS",
 "go_test_diagnostics": null,
 "historical_merge_ci_claimed_pass": false,
 "jobs": [
  {
   "conclusion": "success",
   "name": "exact-target-identity",
   "passed": true
  },
  {
   "conclusion": "success",
   "name": "authority-validator",
   "passed": true
  },
  {
   "conclusion": "success",
   "name": "b001-historical-validator",
   "passed": true
  },
  {
   "conclusion": "success",
   "name": "effective-authority-resolution",
   "passed": true
  },
  {
   "conclusion": "success",
   "name": "go-test-all-at-target",
   "passed": true
  }
 ],
 "modified_target_worktree_used": false,
 "original_merge_ci": "ABSENT",
 "real_model_calls": 0,
 "real_playtest_executed": false,
 "recovery_not_historical_ci": true,
 "requested_target_sha": "169f9bd006dabb88eb653ab09a33b0eef5eadaed",
 "resolved_target_sha": "169f9bd006dabb88eb653ab09a33b0eef5eadaed",
 "result": "PASS",
 "schema": "aipt.public.post-merge-reverification-candidate-run/v1",
 "target_checkout": "DETACHED_EXACT_COMMIT",
 "target_clean": true,
 "target_tree": "9cf551e7bc70d4354ca21d62a2bd456ed6f401bb",
 "task_id": "UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001",
 "validator_identities": [
  {
   "path": "scripts/ci/validate/p1-b000-authority.mjs",
   "role": "AUTHORITY_VALIDATOR_IDENTITY",
   "sha256": "c6f0c8e01397200ce15f48bf1fc2412d9db477dddc37d3f99e0478d26956dd0c"
  },
  {
   "path": "scripts/ci/validate/mvp-b001.mjs",
   "role": "B001_HISTORICAL_VALIDATOR_IDENTITY",
   "sha256": "319c8d4a3466c20d14e2d5fc74cc246c9b796d36f884fcc39e2b0a25317351c4"
  }
 ],
 "workflow_definition_sha256": "3ad13fa061727190d7363815053b39bede7d88c4d00ded3aa51a190b31b0e053"
};}

test('Q023 exact typed unchanged P1 report accepts only the complete fixed five-PASS/no-grant report',()=>{
 const report=q023P1ReportGolden(),before=copy(report);assert.deepEqual(q023FixedP1ReportProblems(report),[]);assert.deepEqual(report,before);
 assert.ok(q023FixedP1ReportProblems(report,{target:Q023_BASELINE}).length);assert.ok(q023FixedP1ReportProblems().length);
});
for(const key of ['target_clean','modified_target_worktree_used','historical_merge_ci_claimed_pass','formal_evidence_eligible','recovery_not_historical_ci','real_playtest_executed']){
 for(const [label,value] of [['missing',undefined],['null',null],['zero',0],['one',1],['false-string','false'],['true-string','true'],['opposite',!q023P1ReportGolden()[key]]])
  test('Q023 typed P1 report refuses '+key+' '+label,()=>{const r=q023P1ReportGolden();if(value===undefined)delete r[key];else r[key]=value;assert.ok(q023FixedP1ReportProblems(r).length);});
}
for(const key of ['schema','task_id','result','definition_commit','definition_tree','requested_target_sha','resolved_target_sha','target_tree','target_checkout','original_merge_ci','formal_evidence_blocker','b001_regression','effective_authority_identities','go_test_all','workflow_definition_sha256'])
 for(const [label,value] of [['missing',undefined],['null',null],['substituted','unapproved']])
  test('Q023 fixed P1 report refuses '+key+' '+label,()=>{const r=q023P1ReportGolden();if(value===undefined)delete r[key];else r[key]=value;assert.ok(q023FixedP1ReportProblems(r).length);});
for(const [label,report] of [['undefined',undefined],['null',null],['array',[]],['true',true],['zero',0],['string','PASS']])
 test('Q023 fixed P1 report refuses non-report '+label,()=>assert.ok(q023FixedP1ReportProblems(report).length));
for(const [label,mutate] of [
 ['model count missing',r=>delete r.real_model_calls],['model count null',r=>r.real_model_calls=null],['model count false',r=>r.real_model_calls=false],['model count string',r=>r.real_model_calls='0'],['model count positive',r=>r.real_model_calls=1],
 ['diagnostics missing',r=>delete r.go_test_diagnostics],['diagnostics wrong type',r=>r.go_test_diagnostics=false],['unknown runtime grant',r=>r.runtime_ready=true],
 ['jobs missing',r=>delete r.jobs],['jobs null',r=>r.jobs=null],['jobs object',r=>r.jobs={}],['jobs shortened',r=>r.jobs.pop()],['jobs added',r=>r.jobs.push(copy(r.jobs[0]))],['jobs reordered',r=>r.jobs.reverse()],
 ['details missing',r=>delete r.details],['details substituted',r=>r.details[0]='ok'],['validator missing',r=>delete r.validator_identities],['validator reordered',r=>r.validator_identities.reverse()],['validator hash changed',r=>r.validator_identities[0].sha256='0'.repeat(64)],
])test('Q023 fixed P1 report refuses '+label,()=>{const r=q023P1ReportGolden();mutate(r);assert.ok(q023FixedP1ReportProblems(r).length);});
for(let index=0;index<5;index++)for(const [label,mutate] of [
 ['passed missing',j=>delete j.passed],['passed null',j=>j.passed=null],['passed zero',j=>j.passed=0],['passed one',j=>j.passed=1],['passed string',j=>j.passed='true'],['passed false',j=>j.passed=false],
 ['name changed',j=>j.name='unapproved'],['conclusion changed',j=>j.conclusion='failure'],['unknown job grant',j=>j.formal_evidence_eligible=true],
])test('Q023 fixed P1 report refuses job '+index+' '+label,()=>{const r=q023P1ReportGolden();mutate(r.jobs[index]);assert.ok(q023FixedP1ReportProblems(r).length);});

// Q024 cases use only the live658 source; every original281 case uses fixed834f.
function q024OwnedGit(repo,args,statuses=[0]) {
 const r=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,...args],{encoding:'utf8',env:{...process.env,GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 assert.equal(r.error,undefined);assert.equal(r.signal,null);assert.ok(statuses.includes(r.status),r.stderr);return r.stdout.trim();
}
function q024SDKFixture(t) {
 const owned=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q024-sdk-boundary-')),repo=path.join(owned,'source');
 t.after(()=>{
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){bytes+=s.size;files++;}};
  walk(owned);fs.rmSync(owned,{recursive:true,force:true});assert.equal(fs.existsSync(owned),false);
  console.log(JSON.stringify({owned_scratch:owned,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0}));
 });
 q024OwnedGit(q024CurrentSource,['clone','--no-local','--no-checkout',q024CurrentSource,repo]);
 q024OwnedGit(repo,['checkout','--detach',Q024_BASELINE]);q024OwnedGit(repo,['update-ref','refs/remotes/origin/main',Q024_BASELINE]);q024OwnedGit(repo,['config','core.hooksPath','/dev/null']);
 const paths=q024OwnedGit(q024CurrentSource,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);assert.equal(new Set(paths).size,658);
 for(const relative of paths){const dest=path.join(repo,relative);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(path.join(q024CurrentSource,relative),dest);}
 return {owned,repo,paths};
}
test('Q024 exact paired authority binds only reviewed nonleader fixture, protected651 and failed4of5 successor',()=>{
 assert.equal(q024Approved(q024CurrentSource),true);assert.deepEqual(q024SourceProblems(q024CurrentSource),[]);
 const p=q024Proposal(q024CurrentSource);assert.equal(p.baseline656.length,656);assert.equal(p.protected651.length,651);assert.equal(Q024_WORK_PATHS.length,5);assert.equal(Q024_NEW_PATHS.length,2);
 assert.equal(p.original_PR32_merge_CI.PASS,4);assert.equal(p.original_PR32_merge_CI.FAIL,1);assert.equal(p.original_PR32_merge_CI.accepted,false);
 assert.equal(p.runtime_ready,false);assert.equal(p.paid_callable,false);assert.equal(p.qualification_runs_authorized,0);assert.equal(p.generic_followon_permission,false);
 assert.deepEqual(q024RevisionProblems(q024CurrentSource,Q024_BASELINE,{original:true}),[]);
 assert.deepEqual(q024RevisionProblems(q024CurrentSource,Q024_ORIGINAL_CANDIDATE,{original:true}),[]);
 assert.ok(q024RevisionProblems(q024CurrentSource,Q023_BASELINE,{original:true}).length);
});
test('Q024 original281 SDK bodies, four original programs and three Q021 helpers remain byte complete',()=>{
 const file='scripts/ci/test/b007-toolchain-security-q018.test.mjs',old=fs.readFileSync(path.join(q023CurrentSource,file),'utf8'),live=fs.readFileSync(path.join(q024CurrentSource,file),'utf8');
 assert.ok(live.slice(live.indexOf('const hash=')).startsWith(old.slice(old.indexOf('const hash='))));
 assert.equal(q024OwnedGit(q023CurrentSource,['rev-parse','HEAD']),Q024_ORIGINAL_CANDIDATE);assert.equal(q024OwnedGit(q023CurrentSource,['rev-parse','HEAD^{tree}']),Q024_BASELINE_TREE);
 const lib='scripts/ci/lib/b007-toolchain-security-q018.mjs',original=fs.readFileSync(path.join(q023CurrentSource,lib),'utf8'),next=fs.readFileSync(path.join(q024CurrentSource,lib),'utf8');
 for(const marker of ['export function verifySDK(root,spec) {','export function historicalEnvironment(repo,target,route) {','function snapshot(repo,commit,tree) {','export function runFixedHistoricalCLI(repo,route) {','function q021CloneState(repo) {','function q021CloneRef(repo,ref) {','export function prepareQ021FixedCloneOrigins(repo) {']){
  const start=original.indexOf(marker),fragment=original.slice(start,original.indexOf('\n}\n',start)+3);assert.ok(next.includes(fragment),marker);
 }
});
for(const [name,mutate]of[
 ['missing Authority',r=>fs.unlinkSync(path.join(r,Q024_AUTHORITY))],
 ['missing proposal',r=>fs.unlinkSync(path.join(r,Q024_PROPOSAL))],
 ['Authority appended byte',r=>fs.appendFileSync(path.join(r,Q024_AUTHORITY),' ')],
 ['proposal appended byte',r=>fs.appendFileSync(path.join(r,Q024_PROPOSAL),' ')],
 ['proposal instead of approval',r=>{const f=path.join(r,Q024_AUTHORITY),v=JSON.parse(fs.readFileSync(f));v.state='PROPOSAL_ONLY';fs.writeFileSync(f,JSON.stringify(v));}],
 ['retained Q023 Authority rewrite',r=>fs.appendFileSync(path.join(r,Q023_AUTHORITY),' ')],
 ['protected production source rewrite',r=>fs.appendFileSync(path.join(r,'internal/operational/runtime.go'),'\n// unapproved\n')],
 ['reviewed test rewrite',r=>fs.appendFileSync(path.join(r,Q024_TEST),'\n// unapproved\n')],
 ['frozen workflow rewrite',r=>fs.appendFileSync(path.join(r,'.github/workflows/ci.yml'),'\n# unapproved\n')],
 ['protected executable mode',r=>fs.chmodSync(path.join(r,'internal/operational/runtime.go'),0o700)],
 ['work executable mode',r=>fs.chmodSync(path.join(r,Q024_WORK_PATHS[1]),0o700)],
 ['Owner executable mode',r=>fs.chmodSync(path.join(r,Q024_AUTHORITY),0o700)],
 ['symbolic program alias',r=>{const f=path.join(r,Q024_WORK_PATHS[1]);fs.unlinkSync(f);fs.symlinkSync('/dev/null',f);}],
 ['hardlinked protected source',r=>fs.linkSync(path.join(r,'internal/operational/runtime.go'),path.join(r,'q024-hardlink.go'))],
 ['unknown source addition',r=>fs.writeFileSync(path.join(r,'q024-unknown.go'),'unapproved\n')],
])test('Q024 source boundary rejects '+name,t=>{const {repo}=q024SDKFixture(t);mutate(repo);assert.ok(q024SourceProblems(repo).length);});
test('Q024 preserves only untracked generated node_modules exclusion and rejects tracked or unrelated extras',t=>{
 const {repo}=q024SDKFixture(t),n=path.join(repo,'node_modules/generated/package.json');fs.mkdirSync(path.dirname(n),{recursive:true});fs.writeFileSync(n,'{}\n');
 assert.ok(q024SourceProblems(repo).length);fs.appendFileSync(path.join(repo,'.git/info/exclude'),'\nnode_modules/\n');assert.deepEqual(q024SourceProblems(repo),[]);
 fs.writeFileSync(path.join(repo,'q024-extra-generated.txt'),'unexpected\n');assert.ok(q024SourceProblems(repo).length);fs.unlinkSync(path.join(repo,'q024-extra-generated.txt'));
 q024OwnedGit(repo,['add','-f','--','node_modules/generated/package.json']);assert.ok(q024SourceProblems(repo).length);
});
test('Q024 fixed834f clone origin is idempotent and preserves full658 source, HEAD, tree, index and main',t=>{
 const {repo,paths}=q024SDKFixture(t),index=fs.readFileSync(path.join(repo,'.git/index')),identity=q024OwnedGit(repo,['rev-parse','HEAD','HEAD^{tree}','refs/remotes/origin/main']);
 const source=paths.map(p=>[p,hash(fs.readFileSync(path.join(repo,p)))]),v=prepareQ024FixedCloneOrigin(repo);
 assert.equal(v.commit,Q024_ORIGINAL_CANDIDATE);assert.equal(v.tree,Q024_BASELINE_TREE);assert.equal(v.full_HIGH_or_CI_or_runtime_accepted,false);
 const refs=q024OwnedGit(repo,['for-each-ref','--format=%(refname) %(objectname) %(symref)']);assert.equal(prepareQ024FixedCloneOrigin(repo).result,v.result);assert.equal(q024OwnedGit(repo,['for-each-ref','--format=%(refname) %(objectname) %(symref)']),refs);
 assert.deepEqual(fs.readFileSync(path.join(repo,'.git/index')),index);assert.equal(q024OwnedGit(repo,['rev-parse','HEAD','HEAD^{tree}','refs/remotes/origin/main']),identity);assert.deepEqual(paths.map(p=>[p,hash(fs.readFileSync(path.join(repo,p)))]),source);
 assert.throws(()=>prepareQ024FixedCloneOrigin(repo,{commit:Q024_BASELINE}),/no caller targets/);
});
test('Q024 wrong or dangling symbolic fixed original ref is rejected without overwriting references',t=>{
 const {repo}=q024SDKFixture(t),ref='refs/heads/codex/q024-fixed-history-pr32-candidate';q024OwnedGit(repo,['update-ref',ref,Q024_BASELINE]);
 const before=q024OwnedGit(repo,['for-each-ref','--format=%(refname) %(objectname) %(symref)']);assert.throws(()=>prepareQ024FixedCloneOrigin(repo),/overwrite forbidden/);assert.equal(q024OwnedGit(repo,['for-each-ref','--format=%(refname) %(objectname) %(symref)']),before);
 q024OwnedGit(repo,['update-ref','--no-deref','-d',ref]);q024OwnedGit(repo,['symbolic-ref',ref,'refs/heads/q024-dangling']);assert.throws(()=>prepareQ024FixedCloneOrigin(repo),/symbolic/);assert.equal(q024OwnedGit(repo,['symbolic-ref',ref]),'refs/heads/q024-dangling');
});

function q025TestGit(repo,args) {
 const r=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,...args],{encoding:'utf8',env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0',GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_SYSTEM:'/dev/null'}});
 assert.equal(r.error,undefined);assert.equal(r.status,0,r.stderr);return r.stdout.trim();
}
function q025TestRetire(root) {
 let bytes=0,files=0,dirs=0;const seen=new Set();
 const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){files++;const id=s.dev+':'+s.ino;if(!seen.has(id)){bytes+=s.size;seen.add(id);}}else if(!s.isSymbolicLink())throw new Error('unexpected owned Q025 fixture member');};
 walk(root);fs.rmSync(root,{recursive:true,force:true});assert.equal(fs.existsSync(root),false);
 console.log(JSON.stringify({owned_scratch:root,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0}));
}
function q025SDKFixture(t) {
 const owned=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q025-SDK-fixture-')),repo=path.join(owned,'source');t.after(()=>q025TestRetire(owned));
 const r=spawnSync('/usr/bin/git',['clone','--no-local','--no-checkout',q025CurrentSource,repo],{encoding:'utf8'});assert.equal(r.error,undefined);assert.equal(r.status,0,r.stderr);
 q025TestGit(repo,['config','core.hooksPath','/dev/null']);q025TestGit(repo,['checkout','--detach',Q025_BASELINE]);q025TestGit(repo,['update-ref','refs/remotes/origin/main',Q025_BASELINE]);
 const paths=q025TestGit(q025CurrentSource,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);assert.equal(new Set(paths).size,661);
 for(const relative of new Set(paths)){const from=path.join(q025CurrentSource,relative),dest=path.join(repo,relative);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(from,dest);fs.chmodSync(dest,fs.statSync(from).mode&0o777);}
 return repo;
}
test('Q025 retains complete original301 SDK test bodies at accepted PR33 source658',()=>{
 const file='scripts/ci/test/b007-toolchain-security-q018.test.mjs',old=fs.readFileSync(path.join(q024CurrentSource,file),'utf8'),live=fs.readFileSync(path.join(q025CurrentSource,file),'utf8');
 assert.ok(live.slice(live.indexOf('const hash=')).startsWith(old.slice(old.indexOf('const hash='))));
 assert.equal(q025TestGit(q024CurrentSource,['rev-parse','HEAD']),Q025_BASELINE);assert.equal(q025TestGit(q024CurrentSource,['rev-parse','HEAD^{tree}']),Q025_BASELINE_TREE);
 assert.deepEqual(q024SourceProblems(q024CurrentSource),[]);assert.deepEqual(q025SourceProblems(q025CurrentSource),[]);
});
for(const [name,change]of [
 ['Owner authority removed',r=>fs.unlinkSync(path.join(r,Q025_AUTHORITY))],
 ['paired proposal removed',r=>fs.unlinkSync(path.join(r,Q025_PROPOSAL))],
 ['Owner bytes changed',r=>fs.appendFileSync(path.join(r,Q025_AUTHORITY),' ')],
 ['paired proposal bytes changed',r=>fs.appendFileSync(path.join(r,Q025_PROPOSAL),' ')],
 ['Owner approval changed to proposal',r=>{const p=path.join(r,Q025_AUTHORITY),v=JSON.parse(fs.readFileSync(p));v.state='PROPOSAL_ONLY';v.owner_instruction=null;fs.writeFileSync(p,JSON.stringify(v));}],
 ['Parent identity changed',r=>fs.appendFileSync(path.join(r,Q025_PARENT),'\n// unapproved prefix change\n')],
 ['negative tests changed',r=>fs.appendFileSync(path.join(r,Q025_TEST),'\n// unapproved coverage change\n')],
 ['protected runtime changed',r=>fs.appendFileSync(path.join(r,'internal/pilot/memory_lifecycle.go'),'\n// forbidden\n')],
 ['retained Q024 authority changed',r=>fs.appendFileSync(path.join(r,Q024_AUTHORITY),' ')],
 ['retained workflow changed',r=>fs.appendFileSync(path.join(r,'.github/workflows/ci.yml'),'\n')],
 ['unauthorized source added',r=>fs.writeFileSync(path.join(r,'unauthorized-prefix-source.txt'),'unapproved')],
 ['Parent executable mode',r=>fs.chmodSync(path.join(r,Q025_PARENT),0o755)],
 ['new test executable mode',r=>fs.chmodSync(path.join(r,Q025_TEST),0o755)],
 ['Parent replaced by symbolic link',r=>{const p=path.join(r,Q025_PARENT),other=path.join(r,'owned-parent-alias');fs.renameSync(p,other);fs.symlinkSync(other,p);}],
 ['Parent given a hardlink alias',r=>fs.linkSync(path.join(r,Q025_PARENT),path.join(r,'owned-parent-hardlink'))],
])test('Q025 mandatory source guard rejects '+name,t=>{const r=q025SDKFixture(t);change(r);assert.ok(q025SourceProblems(r).length);});
test('Q025 fixed clone origin preserves exact bafa and six original refs with checkout/main/index/source',t=>{
 const r=q025SDKFixture(t),before={head:q025TestGit(r,['rev-parse','HEAD']),tree:q025TestGit(r,['rev-parse','HEAD^{tree}']),main:q025TestGit(r,['rev-parse','refs/remotes/origin/main']),index:hash(fs.readFileSync(q025TestGit(r,['rev-parse','--path-format=absolute','--git-path','index'])))};
 const v=prepareQ025FixedCloneOrigin(r);assert.equal(v.commit,Q025_BASELINE);assert.equal(v.fixed_origins.length,7);assert.equal(v.SDK_program_or_mutation,0);assert.equal(v.network_requests,0);assert.equal(v.full_HIGH_or_CI_or_runtime_accepted,false);
 assert.deepEqual({head:q025TestGit(r,['rev-parse','HEAD']),tree:q025TestGit(r,['rev-parse','HEAD^{tree}']),main:q025TestGit(r,['rev-parse','refs/remotes/origin/main']),index:hash(fs.readFileSync(q025TestGit(r,['rev-parse','--path-format=absolute','--git-path','index'])))},before);
 assert.equal(prepareQ025FixedCloneOrigin(r).commit,Q025_BASELINE);
 assert.throws(()=>prepareQ025FixedCloneOrigin(r,{target:Q024_BASELINE}),/no caller/);
});
for(const [name,change]of [
 ['different existing fixed ref',r=>q025TestGit(r,['update-ref','refs/heads/codex/q025-fixed-history-pr33-merge',Q024_BASELINE])],
 ['symbolic fixed ref',r=>q025TestGit(r,['symbolic-ref','refs/heads/codex/q025-fixed-history-pr33-merge','refs/heads/owned-fixed-alias'])],
])test('Q025 fixed clone origin rejects '+name,t=>{const r=q025SDKFixture(t);change(r);assert.throws(()=>prepareQ025FixedCloneOrigin(r),/fixed clone ref|symbolic/);});
test('Q025 accepted baseline revision cannot be replaced with a caller target',()=>{
 assert.deepEqual(q025RevisionProblems(q025CurrentSource,Q025_BASELINE,{baseline:true}),[]);
 assert.ok(q025RevisionProblems(q025CurrentSource,Q024_BASELINE,{baseline:true}).length);
 assert.throws(()=>q025OriginalTestSource(q025CurrentSource,Q024_BASELINE),/no caller/);
});

test('Q025 fixed P1 source selector accepts current661 without weakening original658',()=>{
 assert.deepEqual(q023SourceProblems(q025CurrentSource),[]);
 assert.deepEqual(q023SourceProblems(q025CurrentSource),q025SourceProblems(q025CurrentSource));
 assert.deepEqual(q024SourceProblems(q024CurrentSource),[]);
});
for(const [name,change]of [
 ['reviewed Parent changed',r=>fs.appendFileSync(path.join(r,Q025_PARENT),'\n// forbidden P1 prefix\n')],
 ['protected go.sum changed',r=>fs.appendFileSync(path.join(r,'go.sum'),'\n')],
 ['paired Q025 authority changed',r=>fs.appendFileSync(path.join(r,Q025_AUTHORITY),' ')],
 ['accepted main replaced by older baseline',r=>q025TestGit(r,['update-ref','refs/remotes/origin/main',Q024_BASELINE])],
])test('Q025 fixed P1 direct source selector rejects '+name,t=>{
 const r=q025SDKFixture(t);change(r);const direct=q023SourceProblems(r);assert.ok(direct.length);assert.deepEqual(direct,q025SourceProblems(r));
});
test('Q025 predecessor cleanup retains borrowed complete original test context',t=>{
 const r=q025SDKFixture(t),original=q025OriginalTestSource(q025CurrentSource);
 assert.equal(original,q024CurrentSource);assert.deepEqual(q025SuccessorProblems(r),[]);
 q025CleanupPredecessors();assert.equal(fs.existsSync(original),true);assert.deepEqual(q024SourceProblems(original),[]);
 assert.deepEqual(q025SuccessorProblems(r),[]);q025CleanupPredecessors();
 assert.equal(q025TestGit(original,['rev-parse','HEAD']),Q025_BASELINE);
});

for(const [name,ref,commit]of [
 ['wrong retained PR29 ref','refs/heads/codex/q021-fixed-history-pr29',Q024_BASELINE],
 ['dangling symbolic retained PR31 ref','refs/heads/codex/q023-fixed-history-pr31',null],
])test('Q025 atomic seven-ref preparation refuses '+name,t=>{
 const r=q025SDKFixture(t);
 if(commit)q025TestGit(r,['update-ref',ref,commit]);else q025TestGit(r,['symbolic-ref',ref,'refs/heads/owned-missing-history-target']);
 assert.throws(()=>prepareQ025FixedCloneOrigin(r),/fixed clone ref|symbolic/);
 const probe=spawnSync('/usr/bin/git',['--no-optional-locks','-C',r,'show-ref','--verify','--quiet','refs/heads/codex/q025-fixed-history-pr33-merge'],{encoding:'utf8'});
 assert.equal(probe.error,undefined);assert.equal(probe.status,1);
});

function q026Git(repo,args){const r=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,...args],{encoding:'utf8'});assert.equal(r.error,undefined);assert.equal(r.status,0,r.stderr);return r.stdout.trim();}
function q026Fixture(t){const owned=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q026-owned-fixture-')),repo=path.join(owned,'source');t.after(()=>q025TestRetire(owned));const r=spawnSync('/usr/bin/git',['clone','--no-local','--no-checkout',q026CurrentSource,repo],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);q026Git(repo,['config','core.hooksPath','/dev/null']);q026Git(repo,['config','user.name','Synthetic Q026 Probe']);q026Git(repo,['config','user.email','probe@example.invalid']);q026Git(repo,['checkout','--detach',Q026_BASELINE]);q026Git(repo,['update-ref','refs/remotes/origin/main',Q026_BASELINE]);const names=q026Git(q026CurrentSource,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);assert.equal(new Set(names).size,665);for(const name of new Set(names)){const src=path.join(q026CurrentSource,name),dst=path.join(repo,name);fs.mkdirSync(path.dirname(dst),{recursive:true});fs.copyFileSync(src,dst);fs.chmodSync(dst,fs.statSync(src).mode&0o777);}q026Git(repo,['add','--',...Q026_WORK_PATHS,...Q026_NEW_PATHS]);return repo;}
function q026Candidate(repo){q026Git(repo,['commit','-m','Synthetic exact Q026 candidate']);return q026Git(repo,['rev-parse','HEAD']);}
function q026Merge(repo,candidate,parents=[Q026_BASELINE,candidate],tree=q026Git(repo,['rev-parse',candidate+'^{tree}'])){return q026Git(repo,['commit-tree',tree,...parents.flatMap(v=>['-p',v]),'-m','Synthetic Q026 normal merge']);}

test('Q026 retains complete original329 SDK bodies at exact accepted PR34',()=>{const f='scripts/ci/test/b007-toolchain-security-q018.test.mjs',old=fs.readFileSync(path.join(q025CurrentSource,f),'utf8'),live=fs.readFileSync(path.join(q026CurrentSource,f),'utf8');assert.ok(live.slice(live.indexOf('const hash=')).startsWith(old.slice(old.indexOf('const hash='))));assert.equal(q026Git(q025CurrentSource,['rev-parse','HEAD']),Q026_BASELINE);assert.deepEqual(q025SourceProblems(q025CurrentSource),[]);assert.deepEqual(q026SourceProblems(q026CurrentSource),[]);});
for(const [name,change]of [
 ['Owner authority removed',r=>fs.unlinkSync(path.join(r,Q026_AUTHORITY))],['paired proposal removed',r=>fs.unlinkSync(path.join(r,Q026_PROPOSAL))],['Owner bytes changed',r=>fs.appendFileSync(path.join(r,Q026_AUTHORITY),' ')],['proposal bytes changed',r=>fs.appendFileSync(path.join(r,Q026_PROPOSAL),' ')],
 ...[Q026_PARENT,Q026_OBSERVER,Q026_TEST].map(file=>['runtime/test bytes changed '+file,r=>fs.appendFileSync(path.join(r,file),'\n// forbidden\n')]),
 ['protected PREP changed',r=>fs.appendFileSync(path.join(r,'internal/pilot/task0_preparation.go'),'\n// forbidden\n')],['protected old prefix test changed',r=>fs.appendFileSync(path.join(r,Q025_TEST),'\n// forbidden\n')],['unapproved file added',r=>fs.writeFileSync(path.join(r,'unapproved-ready-source.txt'),'unapproved')],
 ['observer executable mode',r=>fs.chmodSync(path.join(r,Q026_OBSERVER),0o755)],['hardlink alias',r=>fs.linkSync(path.join(r,Q026_OBSERVER),path.join(r,'unapproved-alias'))],['symbolic observer',r=>{const p=path.join(r,Q026_OBSERVER),a=path.join(r,'unapproved-target');fs.renameSync(p,a);fs.symlinkSync(a,p);}]
])test('Q026 source rejects '+name,t=>{const r=q026Fixture(t);change(r);assert.ok(q026SourceProblems(r).length);});
test('Q026 prepares exactly eight retained local origins without SDK/network/grant',t=>{const r=q026Fixture(t);const v=prepareQ026FixedCloneOrigin(r);assert.equal(v.commit,Q026_BASELINE);assert.equal(v.fixed_origins.length,8);assert.equal(v.network_requests,0);assert.equal(v.SDK_program_or_mutation,0);assert.equal(v.full_HIGH_or_CI_or_runtime_accepted,false);assert.throws(()=>prepareQ026FixedCloneOrigin(r,{target:Q025_BASELINE}),/no caller/);});
test('Q026 forbids replacing a differing existing fixed ref',t=>{const r=q026Fixture(t);q026Git(r,['update-ref','refs/heads/codex/q026-fixed-history-pr34-merge',Q025_BASELINE]);assert.throws(()=>prepareQ026FixedCloneOrigin(r),/differs/);});
test('Q026 forbids symbolic fixed origin aliases',t=>{const r=q026Fixture(t);q026Git(r,['symbolic-ref','refs/heads/codex/q026-fixed-history-pr34-merge','refs/heads/codex/absent']);assert.throws(()=>prepareQ026FixedCloneOrigin(r),/symbolic/);});

function q027Git(repo,args){const r=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,...args],{encoding:'utf8'});assert.equal(r.error,undefined);assert.equal(r.status,0,r.stderr);return r.stdout.trim();}
function q027Fixture(t){const owned=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q027-owned-fixture-')),repo=path.join(owned,'source');t.after(()=>q025TestRetire(owned));const r=spawnSync('/usr/bin/git',['clone','--no-local','--no-checkout',q027CurrentSource,repo],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);q027Git(repo,['config','core.hooksPath','/dev/null']);q027Git(repo,['config','user.name','Synthetic Q027 Probe']);q027Git(repo,['config','user.email','probe@example.invalid']);q027Git(repo,['checkout','--detach',Q027_BASELINE]);q027Git(repo,['update-ref','refs/remotes/origin/main',Q027_BASELINE]);const names=q027Git(q027CurrentSource,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);assert.equal(new Set(names).size,669);for(const name of new Set(names)){const src=path.join(q027CurrentSource,name),dst=path.join(repo,name);fs.mkdirSync(path.dirname(dst),{recursive:true});fs.copyFileSync(src,dst);fs.chmodSync(dst,fs.statSync(src).mode&0o777);}q027Git(repo,['add','--',...Q027_WORK_PATHS,...Q027_NEW_PATHS]);return repo;}
function q027Candidate(repo){q027Git(repo,['commit','-m','Synthetic exact Q027 candidate']);return q027Git(repo,['rev-parse','HEAD']);}
function q027Merge(repo,candidate,parents=[Q027_BASELINE,candidate],tree=q027Git(repo,['rev-parse',candidate+'^{tree}'])){return q027Git(repo,['commit-tree',tree,...parents.flatMap(v=>['-p',v]),'-m','Synthetic Q027 normal merge']);}

test('Q027 retains complete original346 SDK bodies at exact accepted PR35',()=>{const f='scripts/ci/test/b007-toolchain-security-q018.test.mjs',old=fs.readFileSync(path.join(q026CurrentSource,f),'utf8'),live=fs.readFileSync(path.join(q027CurrentSource,f),'utf8');assert.ok(live.slice(live.indexOf('const hash=')).startsWith(old.slice(old.indexOf('const hash='))));assert.equal(q027Git(q026CurrentSource,['rev-parse','HEAD']),Q027_BASELINE);assert.deepEqual(q026SourceProblems(q026CurrentSource),[]);assert.deepEqual(q027SourceProblems(q027CurrentSource),[]);});
for(const [name,change]of [
 ['Owner authority removed',r=>fs.unlinkSync(path.join(r,Q027_AUTHORITY))],['paired proposal removed',r=>fs.unlinkSync(path.join(r,Q027_PROPOSAL))],['Owner bytes changed',r=>fs.appendFileSync(path.join(r,Q027_AUTHORITY),' ')],['proposal bytes changed',r=>fs.appendFileSync(path.join(r,Q027_PROPOSAL),' ')],
 ...[Q027_PARENT,Q027_OBSERVER,Q027_TEST].map(file=>['runtime/test bytes changed '+file,r=>fs.appendFileSync(path.join(r,file),'\n// forbidden\n')]),
 ['protected PREP changed',r=>fs.appendFileSync(path.join(r,'internal/pilot/task0_preparation.go'),'\n// forbidden\n')],['protected old READY test changed',r=>fs.appendFileSync(path.join(r,Q025_TEST),'\n// forbidden\n')],['unapproved file added',r=>fs.writeFileSync(path.join(r,'unapproved-ready-source.txt'),'unapproved')],
 ['observer executable mode',r=>fs.chmodSync(path.join(r,Q027_OBSERVER),0o755)],['hardlink alias',r=>fs.linkSync(path.join(r,Q027_OBSERVER),path.join(r,'unapproved-alias'))],['symbolic observer',r=>{const p=path.join(r,Q027_OBSERVER),a=path.join(r,'unapproved-target');fs.renameSync(p,a);fs.symlinkSync(a,p);}]
])test('Q027 source rejects '+name,t=>{const r=q027Fixture(t);change(r);assert.ok(q027SourceProblems(r).length);});
test('Q027 prepares exactly nine retained local origins without SDK/network/grant',t=>{const r=q027Fixture(t);const v=prepareQ027FixedCloneOrigin(r);assert.equal(v.commit,Q027_BASELINE);assert.equal(v.fixed_origins.length,9);assert.equal(v.network_requests,0);assert.equal(v.SDK_program_or_mutation,0);assert.equal(v.full_HIGH_or_CI_or_runtime_accepted,false);assert.throws(()=>prepareQ027FixedCloneOrigin(r,{target:Q026_BASELINE}),/no caller/);});
test('Q027 forbids replacing a differing existing fixed ref',t=>{const r=q027Fixture(t);q027Git(r,['update-ref','refs/heads/codex/q027-fixed-history-pr35-merge',Q026_BASELINE]);assert.throws(()=>prepareQ027FixedCloneOrigin(r),/differs/);});
test('Q027 forbids symbolic fixed origin aliases',t=>{const r=q027Fixture(t);q027Git(r,['symbolic-ref','refs/heads/codex/q027-fixed-history-pr35-merge','refs/heads/codex/absent']);assert.throws(()=>prepareQ027FixedCloneOrigin(r),/symbolic/);});


function q028Git(repo,args){const r=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,...args],{encoding:'utf8'});assert.equal(r.error,undefined);assert.equal(r.status,0,r.stderr);return r.stdout.trim();}
function q028Fixture(t){const owned=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q028-owned-fixture-')),repo=path.join(owned,'source');t.after(()=>q025TestRetire(owned));const r=spawnSync('/usr/bin/git',['clone','--no-local','--no-checkout',q028CurrentSource,repo],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);q028Git(repo,['config','core.hooksPath','/dev/null']);q028Git(repo,['config','user.name','Synthetic Q028 Probe']);q028Git(repo,['config','user.email','probe@example.invalid']);q028Git(repo,['checkout','--detach',Q028_BASELINE]);q028Git(repo,['update-ref','refs/remotes/origin/main',Q028_BASELINE]);const names=q028Git(q028CurrentSource,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);assert.equal(new Set(names).size,673);for(const name of new Set(names)){const src=path.join(q028CurrentSource,name),dst=path.join(repo,name);fs.mkdirSync(path.dirname(dst),{recursive:true});fs.copyFileSync(src,dst);fs.chmodSync(dst,fs.statSync(src).mode&0o777);}q028Git(repo,['add','--',...Q028_WORK_PATHS,...Q028_NEW_PATHS]);return repo;}
function q028Candidate(repo){q028Git(repo,['commit','-m','Synthetic exact Q028 candidate']);return q028Git(repo,['rev-parse','HEAD']);}
function q028Merge(repo,candidate,parents=[Q028_BASELINE,candidate],tree=q028Git(repo,['rev-parse',candidate+'^{tree}'])){return q028Git(repo,['commit-tree',tree,...parents.flatMap(v=>['-p',v]),'-m','Synthetic Q028 normal merge']);}

test('Q028 retains complete original SDK bodies at exact accepted PR37',()=>{const f='scripts/ci/test/b007-toolchain-security-q018.test.mjs',old=fs.readFileSync(path.join(q027CurrentSource,f),'utf8'),live=fs.readFileSync(path.join(q028CurrentSource,f),'utf8');assert.ok(live.slice(live.indexOf('const hash=')).startsWith(old.slice(old.indexOf('const hash='))));assert.equal(q028Git(q027CurrentSource,['rev-parse','HEAD']),Q028_BASELINE);assert.deepEqual(q027SourceProblems(q027CurrentSource),[]);assert.deepEqual(q028SourceProblems(q028CurrentSource),[]);});
for(const [name,change]of [
 ['Owner authority removed',r=>fs.unlinkSync(path.join(r,Q028_AUTHORITY))],['paired proposal removed',r=>fs.unlinkSync(path.join(r,Q028_PROPOSAL))],['Owner bytes changed',r=>fs.appendFileSync(path.join(r,Q028_AUTHORITY),' ')],['proposal bytes changed',r=>fs.appendFileSync(path.join(r,Q028_PROPOSAL),' ')],
 ...[Q028_PARENT,Q028_OBSERVER,Q028_TEST].map(file=>['runtime/test bytes changed '+file,r=>fs.appendFileSync(path.join(r,file),'\n// forbidden\n')]),
 ['protected PREP changed',r=>fs.appendFileSync(path.join(r,'internal/pilot/task0_preparation.go'),'\n// forbidden\n')],['protected old READY test changed',r=>fs.appendFileSync(path.join(r,Q025_TEST),'\n// forbidden\n')],['unapproved file added',r=>fs.writeFileSync(path.join(r,'unapproved-ready-source.txt'),'unapproved')],
 ['observer executable mode',r=>fs.chmodSync(path.join(r,Q028_OBSERVER),0o755)],['hardlink alias',r=>fs.linkSync(path.join(r,Q028_OBSERVER),path.join(r,'unapproved-alias'))],['symbolic observer',r=>{const p=path.join(r,Q028_OBSERVER),a=path.join(r,'unapproved-target');fs.renameSync(p,a);fs.symlinkSync(a,p);}]
])test('Q028 source rejects '+name,t=>{const r=q028Fixture(t);change(r);assert.ok(q028SourceProblems(r).length);});
test('Q028 prepares exactly ten retained local origins without SDK/network/grant',t=>{const r=q028Fixture(t);const v=prepareQ028FixedCloneOrigin(r);assert.equal(v.commit,Q028_BASELINE);assert.equal(v.fixed_origins.length,10);assert.equal(v.network_requests,0);assert.equal(v.SDK_program_or_mutation,0);assert.equal(v.full_HIGH_or_CI_or_runtime_accepted,false);assert.throws(()=>prepareQ028FixedCloneOrigin(r,{target:Q027_BASELINE}),/no caller/);});
test('Q028 forbids replacing a differing existing fixed ref',t=>{const r=q028Fixture(t);q028Git(r,['update-ref','refs/heads/codex/q028-fixed-history-pr37-merge',Q027_BASELINE]);assert.throws(()=>prepareQ028FixedCloneOrigin(r),/differs/);});
test('Q028 forbids symbolic fixed origin aliases',t=>{const r=q028Fixture(t);q028Git(r,['symbolic-ref','refs/heads/codex/q028-fixed-history-pr37-merge','refs/heads/codex/absent']);assert.throws(()=>prepareQ028FixedCloneOrigin(r),/symbolic/);});

function q032Git(repo,args){const r=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,...args],{encoding:'utf8'});assert.equal(r.error,undefined);assert.equal(r.status,0,r.stderr);return r.stdout.trim();}
test.after(q025CleanupPredecessors);
function q032Fixture(t){const owned=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q032-source-fixture-')),repo=path.join(owned,'source');t.after(()=>q025TestRetire(owned));const r=spawnSync('/usr/bin/git',['clone','--no-local','--no-checkout',q032CurrentSource,repo],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);q032Git(repo,['config','core.hooksPath','/dev/null']);q032Git(repo,['config','user.name','Synthetic Q032 Probe']);q032Git(repo,['config','user.email','probe@example.invalid']);q032Git(repo,['checkout','--detach',Q032_BASELINE]);q032Git(repo,['update-ref','refs/remotes/origin/main',Q032_BASELINE]);const names=q032Git(q032CurrentSource,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);assert.equal(new Set(names).size,675);for(const name of new Set(names)){const src=path.join(q032CurrentSource,name),dst=path.join(repo,name);fs.mkdirSync(path.dirname(dst),{recursive:true});fs.copyFileSync(src,dst);fs.chmodSync(dst,fs.statSync(src).mode&0o777);}q032Git(repo,['add','--',...Q032_WORK_PATHS,...Q032_NEW_PATHS]);return repo;}
function q032Candidate(repo){q032Git(repo,['commit','-m','Synthetic exact Q032 Q033 candidate']);return q032Git(repo,['rev-parse','HEAD']);}
test('Q032 Q033 retain all complete original SDK test bodies at exact PR38',()=>{const f='scripts/ci/test/b007-toolchain-security-q018.test.mjs',old=fs.readFileSync(path.join(q028CurrentSource,f),'utf8'),live=fs.readFileSync(path.join(q032CurrentSource,f),'utf8');assert.ok(live.slice(live.indexOf('const hash=')).startsWith(old.slice(old.indexOf('const hash='))));assert.equal(q032Git(q028CurrentSource,['rev-parse','HEAD']),Q032_BASELINE);assert.deepEqual(q028SourceProblems(q028CurrentSource),[]);assert.deepEqual(q032SourceProblems(q032CurrentSource),[]);});
for(const [name,change]of [
 ['authority absent',r=>fs.unlinkSync(path.join(r,Q032_AUTHORITY))],['proposal absent',r=>fs.unlinkSync(path.join(r,Q032_PROPOSAL))],['authority altered',r=>fs.appendFileSync(path.join(r,Q032_AUTHORITY),' ')],['proposal altered',r=>fs.appendFileSync(path.join(r,Q032_PROPOSAL),' ')],
 ['frozen aggregate',r=>fs.appendFileSync(path.join(r,'scripts/ci/run-checks.mjs'),'\n// forbidden\n')],['frozen production PREP',r=>fs.appendFileSync(path.join(r,'internal/pilot/task0_preparation.go'),'\n// forbidden\n')],['frozen action lock',r=>fs.appendFileSync(path.join(r,'tools/ci-actions.lock.json'),' ')],['SDK verifier core',r=>{const p=path.join(r,'scripts/ci/lib/b007-toolchain-security-q018.mjs');fs.writeFileSync(p,fs.readFileSync(p,'utf8').replace("throw new Error('special SDK member')","throw new Error('changed SDK member')"));}],
 ['workflow entry removed',r=>{const p=path.join(r,'.github/workflows/ci.yml');fs.writeFileSync(p,fs.readFileSync(p,'utf8').replace(' --q032-prepare-current-sdk',' --unknown-current-sdk'));}],['workflow adapter body changed',r=>fs.appendFileSync(path.join(r,'scripts/ci/validate/workflow.mjs'),'\n// forbidden\n')],['extra source',r=>fs.writeFileSync(path.join(r,'unapproved-sdk-source.txt'),'forbidden')],['executable work path',r=>fs.chmodSync(path.join(r,Q032_AUTHORITY),0o755)],['hardlink alias',r=>fs.linkSync(path.join(r,Q032_AUTHORITY),path.join(r,'unapproved-alias'))],['symbolic authority',r=>{const p=path.join(r,Q032_AUTHORITY),a=path.join(r,'unapproved-target');fs.renameSync(p,a);fs.symlinkSync(a,p);}]
])test('Q032 Q033 source rejects '+name,t=>{const r=q032Fixture(t);change(r);assert.ok(q032SourceProblems(r).length);});
test('Q032 prepares exactly eleven immutable fixed clone origins without SDK or network',t=>{const r=q032Fixture(t),v=prepareQ032FixedCloneOrigin(r);assert.equal(v.fixed_origins.length,11);assert.equal(v.commit,Q032_BASELINE);assert.equal(v.network_requests,0);assert.equal(v.SDK_program_or_mutation,0);assert.equal(v.full_HIGH_or_CI_or_runtime_accepted,false);assert.throws(()=>prepareQ032FixedCloneOrigin(r,{target:Q028_BASELINE}),/no caller/);});
test('Q032 fixed origins refuse replacement and symbolic aliases',t=>{const r=q032Fixture(t),ref='refs/heads/codex/q032-fixed-history-pr38-merge';q032Git(r,['update-ref',ref,Q028_BASELINE]);assert.throws(()=>prepareQ032FixedCloneOrigin(r),/cannot be overwritten/);q032Git(r,['update-ref','-d',ref]);q032Git(r,['symbolic-ref',ref,'refs/heads/codex/absent']);assert.throws(()=>prepareQ032FixedCloneOrigin(r),/symbolic/);});
test('Q032 public acquisition/version routes reject extra caller arguments before effects',()=>{assert.throws(()=>prepareQ032CurrentSDK(q032CurrentSource,{url:'forbidden'}),/no caller/);assert.throws(()=>q032CurrentGoVersion(q032CurrentSource,{args:['env']}),/no caller/);});

// Drive the actual acquisition functions with real owned files and synthetic
// command returns. SDK internals use the unchanged physical/hash verifiers on
// an explicitly tiny test archive. This never qualifies a real15045 SDK or CI.
function q032AcquisitionHarness(t,fault='none') {
 const fixture=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q032-acquisition-probe-')),heldFailureFDs=new Set();t.after(()=>{for(const fd of heldFailureFDs)fs.closeSync(fd);q025TestRetire(fixture);});
 const temp=path.join(fixture,'job');fs.mkdirSync(temp,{mode:0o700});const pathFile=path.join(temp,'add-path');fs.writeFileSync(pathFile,'',{flag:'wx',mode:0o600});
 const payload=Buffer.from('synthetic fixed archive bytes, no executable SDK'),archive={url:'https://example.invalid/fixed-test-only.tar.gz',filename:'test-only.tar.gz',bytes:payload.length,sha256:hash(payload)};
 const go=Buffer.from('synthetic go payload; never execute'),note=Buffer.from('synthetic contributor payload');
 const tiny={version:'1.26.9',files:[{relative:'CONTRIBUTING.md',bytes:note.length,sha256:hash(note),executable:false},{relative:'bin/go',bytes:go.length,sha256:hash(go),executable:true}],directories:['.','bin']};
 const fakeSpec={version:'1.26.9',archive,files:Array.from({length:15045},()=>({relative:'test-only-placeholder'})),directories:Array.from({length:1667},()=>'.')};
 const source=fs.readFileSync(path.join(q032CurrentSource,'scripts/ci/lib/b007-toolchain-security-q018.mjs'),'utf8');
 const first=source.indexOf('\nexport function verifySDK(root,spec) {')+1,middle=source.indexOf('\nconst q021StatFields=')+1,last=source.indexOf('\nfunction q021QualifiedSDK(repo,root) {')+1;
 assert.ok(first>=0&&middle>first&&last>middle);
 const core=Function('fs','path','createHash','equal','heldQ018Bytes',source.slice(first,last).replace(/^export /gm,'')+'\nreturn {verifySDK,q021PhysicalSDK,q021Same};')(fs,path,createHash,deepEqual,heldQ018Bytes);
 const acqStart=source.indexOf('// Q032/Q033: fixed job-owned acquisition;'),acqEnd=source.indexOf('const SOURCE_IDENTITIES=');assert.ok(acqStart>=0&&acqEnd>acqStart);
 const env={CI:'true',GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:'zyc14588/AIPT',GITHUB_JOB:'toolchain',RUNNER_OS:'Linux',RUNNER_ARCH:'X64',GOENV:'off',GOTOOLCHAIN:'local',GITHUB_RUN_ID:'1',GITHUB_RUN_ATTEMPT:'1',GITHUB_WORKSPACE:fixture,GITHUB_EVENT_NAME:'pull_request',GITHUB_REF:'refs/pull/1/merge',RUNNER_TEMP:temp,GITHUB_PATH:pathFile,PATH:'/usr/bin:/bin'};
 let commands=0,extracts=0,SDKExecutions=0,diagnostics=[],initialStatFaultUsed=false;
 const physical=root=>core.q021PhysicalSDK(root,tiny);
 const qualify=(_,root)=>{const a=physical(root);core.verifySDK(root,tiny);const b=physical(root);assert.deepEqual(a,b);return {version:'1.26.9',files:15045,directories:1667,complete_fixed_archive_identity:true};};
 const fakeSpawn=(program,args,options)=>{
  commands++;const fd=options.stdio[3],owned=path.dirname(fs.realpathSync('/proc/self/fd/'+fd));
  assert.deepEqual(options.env,{PATH:'/usr/bin:/bin',LANG:'C.UTF-8'});
  if(program==='/usr/bin/curl'){
   assert.deepEqual(args,['--disable','--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--max-redirs','3','--connect-timeout','20','--max-time','240','--output','/proc/self/fd/3',archive.url]);
   if(fault==='download-exit')return {pid:1234,status:22,signal:null};
   if(fault==='unknown-spawn')return {pid:0,status:null,signal:null,error:new Error('synthetic unknown spawn')};
   if(fault==='signal')return {pid:1234,status:null,signal:'SIGTERM'};
   fs.writeSync(fd,fault==='archive-digest'?Buffer.alloc(payload.length,65):fault==='archive-size'?payload.subarray(1):payload);
   if(fault==='archive-nlink')fs.linkSync(path.join(owned,archive.filename),path.join(owned,'archive-alias'));
   if(fault==='archive-replacement'){fs.renameSync(path.join(owned,archive.filename),path.join(owned,'held-original'));fs.writeFileSync(path.join(owned,archive.filename),payload,{mode:0o600});}
   if(fault==='owner-replacement'){fs.renameSync(owned,owned+'-original');fs.mkdirSync(owned,{mode:0o700});fs.writeFileSync(path.join(owned,'borrowed-sentinel'),'untouched');}
  }else{
   assert.equal(program,'/usr/bin/tar');extracts++;if(fault==='extract-exit')return {pid:1234,status:2,signal:null};
   assert.deepEqual(args,['--no-same-owner','--no-same-permissions','-xzf','/proc/self/fd/3','-C',owned]);
   const sdk=path.join(owned,'go');fs.mkdirSync(path.join(sdk,'bin'),{recursive:true});fs.writeFileSync(path.join(sdk,'bin/go'),go,{mode:0o755});fs.writeFileSync(path.join(sdk,'CONTRIBUTING.md'),note,{mode:0o644});
   if(fault==='member-executable')fs.chmodSync(path.join(sdk,'CONTRIBUTING.md'),0o777);
   if(fault==='member-nlink')fs.linkSync(path.join(sdk,'CONTRIBUTING.md'),path.join(owned,'member-alias'));
   if(fault==='member-digest')fs.writeFileSync(path.join(sdk,'CONTRIBUTING.md'),Buffer.alloc(note.length,65));
   if(fault==='member-missing')fs.unlinkSync(path.join(sdk,'CONTRIBUTING.md'));
   if(fault==='member-extra')fs.writeFileSync(path.join(sdk,'extra'),'unapproved');
   if(fault==='member-symbolic'){fs.unlinkSync(path.join(sdk,'CONTRIBUTING.md'));fs.symlinkSync(path.join(fixture,'outside-sentinel'),path.join(sdk,'CONTRIBUTING.md'));}
  }
  return {pid:1234,status:0,signal:null};
 };
 fs.writeFileSync(path.join(fixture,'outside-sentinel'),'outside unchanged');
 const wrappedFS={...fs,
  mkdtempSync:prefix=>{if(fault==='root-allocation'&&prefix===path.join(temp,'aipt-q032-sdk-'))throw new Error('synthetic root allocation failure');return fs.mkdtempSync(prefix);},
  lstatSync:(p,...args)=>{if(fault==='initial-owner-stat'&&!initialStatFaultUsed&&typeof p==='string'&&path.dirname(p)===temp&&path.basename(p).startsWith('aipt-q032-sdk-')){initialStatFaultUsed=true;throw new Error('synthetic initial owner stat failure');}return fs.lstatSync(p,...args);},
  fchmodSync:(fd,...args)=>{if(fault==='receipt-mode-close'&&fs.realpathSync('/proc/self/fd/'+fd).endsWith('/acquisition-receipt.json'))throw new Error('synthetic receipt mode failure');return fs.fchmodSync(fd,...args);},
  fsyncSync:fd=>{if(['receipt-sync','receipt-sync-close'].includes(fault)&&fs.realpathSync('/proc/self/fd/'+fd).endsWith('/acquisition-receipt.json'))throw new Error('synthetic receipt sync failure');return fs.fsyncSync(fd);},
  openSync:(p,...args)=>{if(fault==='path-open'&&p===pathFile)throw new Error('synthetic PATH open');return fs.openSync(p,...args);},
  writeFileSync:(fd,...args)=>{if(['receipt-write','receipt-write-close'].includes(fault)&&typeof fd==='number'&&fs.realpathSync('/proc/self/fd/'+fd).endsWith('/acquisition-receipt.json'))throw new Error('synthetic receipt write');return fs.writeFileSync(fd,...args);},
  writeSync:(fd,buffer,...args)=>{if(['path-short','path-partial','rollback-failure','rollback-close-failure','partial-close-failure','short-close-failure'].includes(fault)&&fs.realpathSync('/proc/self/fd/'+fd)===pathFile){if(['path-short','short-close-failure'].includes(fault))return 0;fs.writeSync(fd,buffer,0,3,0);throw new Error('synthetic partial PATH write');}return fs.writeSync(fd,buffer,...args);},
  ftruncateSync:(fd,len)=>{if(['rollback-failure','rollback-close-failure'].includes(fault)&&fs.realpathSync('/proc/self/fd/'+fd)===pathFile)throw new Error('synthetic rollback failure');return fs.ftruncateSync(fd,len);},
  closeSync:fd=>{if(['receipt-close','receipt-write-close','receipt-sync-close','receipt-mode-close'].includes(fault)&&fs.realpathSync('/proc/self/fd/'+fd).endsWith('/acquisition-receipt.json')){heldFailureFDs.add(fd);throw new Error('synthetic receipt close failure');}if(['rollback-close-failure','partial-close-failure','short-close-failure','success-close-failure'].includes(fault)&&fs.realpathSync('/proc/self/fd/'+fd)===pathFile){heldFailureFDs.add(fd);throw new Error('synthetic PATH close failure');}return fs.closeSync(fd);}
 };
 const fakeProcess={platform:'linux',arch:'x64',version:'v24.19.0',getuid:()=>process.getuid(),env,stderr:{write:s=>diagnostics.push(s)}};
 const names=['fs','path','createHash','spawnSync','equal','process','q032SourceProblems','q032Topology','git','sdkSpec','Q032_ARCHIVE','q021Same','verifyQ021CurrentSDK','q021PhysicalSDK','Q018_QUALIFICATION_SHA','Q032_AUTHORITY_SHA','Q032_PROPOSAL_SHA','heldQ018Bytes','withQ021VerifiedCurrentSDK','run'];
 const values=[wrappedFS,path,createHash,fakeSpawn,deepEqual,fakeProcess,()=>[],()=>({problems:[],candidate:{commit:'a'.repeat(40)}}),(_,args)=>args.at(-1)==='HEAD^{tree}'?'b'.repeat(40):'a'.repeat(40),()=>fakeSpec,archive,core.q021Same,qualify,physical,Q018_QUALIFICATION_SHA,'test-authority','test-proposal',heldQ018Bytes,(_,root,action)=>{const a=physical(root),v=action();assert.deepEqual(a,physical(root));return v;},()=>{SDKExecutions++;return {stdout:'go version go1.26.9 linux/amd64\n',stderr:''};}];
 const api=Function(...names,source.slice(acqStart,acqEnd).replace(/^export /gm,'')+'\nreturn {prepareQ032CurrentSDK,q032CurrentGoVersion,q032BoundCurrentRoot,q032HeldArchive};')(...values);
 return {api,fixture,temp,pathFile,env,archive,facts:()=>({commands,extracts,SDKExecutions,diagnostics}),roots:()=>fs.readdirSync(temp).filter(n=>n.startsWith('aipt-q032-sdk-')).map(n=>path.join(temp,n))};
}
test('Q032 actual acquisition control uses held archive, full tiny original verifiers and binds the published SDK',t=>{const h=q032AcquisitionHarness(t);const r=h.api.prepareQ032CurrentSDK(h.fixture);assert.equal(r.result,'PASS_Q032_JOB_OWNED_OFFICIAL_SDK_QUALIFIED_AND_PATH_PUBLISHED');assert.equal(r.SDK_registry_changed,false);assert.equal(h.facts().commands,2);assert.equal(h.facts().extracts,1);const bin=fs.readFileSync(h.pathFile,'utf8').trim();assert.equal(h.roots().length,1);assert.equal(fs.existsSync(path.join(h.roots()[0],h.archive.filename)),false);h.env.PATH=bin+path.delimiter+'/usr/bin:/bin';assert.equal(h.api.q032BoundCurrentRoot(h.fixture),path.dirname(bin));assert.equal(h.api.q032CurrentGoVersion(h.fixture).version,'go version go1.26.9 linux/amd64');assert.equal(h.facts().SDKExecutions,1);});
for(const fault of ['archive-digest','archive-size','archive-nlink','archive-replacement','download-exit','extract-exit','member-executable','member-nlink','member-digest','member-missing','member-extra','member-symbolic','receipt-write','path-open','path-short','path-partial'])test('Q032 fails closed and retires only owned joined scratch: '+fault,t=>{const h=q032AcquisitionHarness(t,fault);assert.throws(()=>h.api.prepareQ032CurrentSDK(h.fixture),error=>{assert.equal(error.q032Failure.owned_directory_retired,true);assert.equal(error.q032Failure.publication_uncertain,false);return true;});assert.equal(h.roots().length,0);assert.equal(fs.readFileSync(h.pathFile,'utf8'),'');assert.equal(fs.readFileSync(path.join(h.fixture,'outside-sentinel'),'utf8'),'outside unchanged');assert.equal(h.facts().SDKExecutions,0);if(fault.startsWith('archive-')||fault==='download-exit')assert.equal(h.facts().extracts,0);});
for(const fault of ['unknown-spawn','signal','rollback-failure','owner-replacement'])test('Q032 retains uncertain ownership/publication and never falls back: '+fault,t=>{const h=q032AcquisitionHarness(t,fault);assert.throws(()=>h.api.prepareQ032CurrentSDK(h.fixture),error=>{assert.equal(error.q032Failure.owned_directory_retired,false);assert.equal(error.q032Failure.owned_directory_retained,true);return true;});assert.ok(h.roots().length);assert.equal(h.facts().SDKExecutions,0);assert.equal(fs.readFileSync(path.join(h.fixture,'outside-sentinel'),'utf8'),'outside unchanged');if(fault==='owner-replacement'){const root=h.roots().find(r=>!r.endsWith('-original'));assert.equal(fs.readFileSync(path.join(root,'borrowed-sentinel'),'utf8'),'untouched');}});
for(const fault of ['rollback-close-failure','partial-close-failure','short-close-failure','success-close-failure'])test('Q032 publication uncertainty never decreases when close also fails: '+fault,t=>{const h=q032AcquisitionHarness(t,fault);assert.throws(()=>h.api.prepareQ032CurrentSDK(h.fixture),error=>{assert.equal(error.q032Failure.publication_uncertain,true);assert.equal(error.q032Failure.owned_directory_retired,false);assert.equal(error.q032Failure.owned_directory_retained,true);if(fault==='rollback-close-failure'){assert.equal(error.message,'synthetic partial PATH write');assert.equal(error.q032RollbackError,'synthetic rollback failure');assert.equal(error.q032CloseError,'synthetic PATH close failure');}return true;});assert.equal(h.roots().length,1);assert.equal(h.facts().SDKExecutions,0);});
test('Q032 rejects fallback, changed receipt and changed acquired member before Go',t=>{const h=q032AcquisitionHarness(t);h.api.prepareQ032CurrentSDK(h.fixture);assert.throws(()=>h.api.q032CurrentGoVersion(h.fixture),/fallback forbidden/);const bin=fs.readFileSync(h.pathFile,'utf8').trim();h.env.PATH=bin+path.delimiter+'/usr/bin:/bin';const receipt=path.join(h.roots()[0],'acquisition-receipt.json');fs.chmodSync(receipt,0o600);assert.throws(()=>h.api.q032CurrentGoVersion(h.fixture),/receipt ownership/);fs.chmodSync(receipt,0o400);const sdk=path.dirname(bin);fs.chmodSync(path.join(sdk,'CONTRIBUTING.md'),0o777);assert.throws(()=>h.api.q032CurrentGoVersion(h.fixture),/changed SDK member/);assert.equal(h.facts().SDKExecutions,0);});
for(const [key,value]of [['GITHUB_ACTIONS','false'],['GITHUB_JOB','unapproved'],['GITHUB_RUN_ATTEMPT','2'],['GOROOT','/unapproved'],['GOTOOLCHAIN','auto']])test('Q032 acquisition refuses ambient environment drift before commands: '+key,t=>{const h=q032AcquisitionHarness(t);h.env[key]=value;assert.throws(()=>h.api.prepareQ032CurrentSDK(h.fixture),/Q032/);assert.equal(h.facts().commands,0);assert.equal(h.roots().length,0);});

test('Q032 legacy repack regression input never promotes or mutates the acquired raw SDK',()=>{
 const value=q032LegacySDKTestInput;
 assert.equal(process.env.PATH,value.originalPath);
 assert.equal(process.env.AIPT_Q021_REAL_TEST_SDK,value.input);
 assert.deepEqual(verifyQ021CurrentSDK(source,value.input),value.proof);
 assert.equal(value.proof.files,15046);
 assert.equal(value.proof.complete_fixed_archive_identity,false);
 assert.equal(value.proof.original_official_raw_archive_identity,false);
 assert.equal(value.proof.setup_sh_executed,false);
 if(value.adapted){
  assert.equal(fs.existsSync(path.join(value.rawRoot,'setup.sh')),false);
  assert.equal(verifyQ021CurrentSDK(source,value.rawRoot).files,15045);
  assert.notEqual(value.input,value.rawRoot);
 }else assert.equal(value.explicit_test_input,true);
});

for(const fault of ['root-allocation','initial-owner-stat'])test('Q032 initialization failure retains exact allocation and identity facts: '+fault,t=>{
 const h=q032AcquisitionHarness(t,fault);assert.throws(()=>h.api.prepareQ032CurrentSDK(h.fixture),error=>{
  assert.equal(error.message,fault==='root-allocation'?'synthetic root allocation failure':'synthetic initial owner stat failure');
  assert.equal(error.q032Failure.owned_directory_allocation_returned,fault==='initial-owner-stat');
  assert.equal(error.q032Failure.owned_directory_identity_established,false);assert.equal(error.q032Failure.owned_directory_retired,false);assert.equal(error.q032Failure.owned_directory_retained,fault==='initial-owner-stat');
  assert.equal(error.q032Failure.owned_directory,fault==='initial-owner-stat'?h.roots()[0]:null);assert.equal(error.q032Failure.receipt_close_uncertain,false);return true;
 });assert.equal(h.facts().commands,0);assert.equal(h.facts().SDKExecutions,0);assert.equal(h.roots().length,fault==='initial-owner-stat'?1:0);assert.equal(fs.readFileSync(h.pathFile,'utf8'),'');assert.equal(h.facts().diagnostics.length,1);
});
for(const fault of ['receipt-close','receipt-write-close','receipt-sync-close','receipt-mode-close'])test('Q032 receipt unknown close preserves primary facts and its owned directory: '+fault,t=>{
 const h=q032AcquisitionHarness(t,fault);assert.throws(()=>h.api.prepareQ032CurrentSDK(h.fixture),error=>{
  assert.equal(error.message,{'receipt-close':'synthetic receipt close failure','receipt-write-close':'synthetic receipt write','receipt-sync-close':'synthetic receipt sync failure','receipt-mode-close':'synthetic receipt mode failure'}[fault]);
  assert.equal(error.q032ReceiptCloseError,'synthetic receipt close failure');assert.equal(error.q032ReceiptCloseUncertain,true);
  assert.equal(error.q032Failure.receipt_close_uncertain,true);assert.equal(error.q032Failure.receipt_path,path.join(h.roots()[0],'acquisition-receipt.json'));
  assert.equal(error.q032Failure.owned_directory_retired,false);assert.equal(error.q032Failure.owned_directory_retained,true);assert.equal(error.q032Failure.publication_uncertain,false);return true;
 });assert.equal(h.roots().length,1);assert.equal(h.facts().commands,2);assert.equal(h.facts().SDKExecutions,0);assert.equal(fs.readFileSync(h.pathFile,'utf8'),'');
});
test('Q032 receipt write or sync failure after confirmed close retires only joined owned input',t=>{
 for(const fault of ['receipt-write','receipt-sync']){
  const h=q032AcquisitionHarness(t,fault);assert.throws(()=>h.api.prepareQ032CurrentSDK(h.fixture),error=>{assert.equal(error.q032Failure.receipt_close_uncertain,false);assert.equal(error.q032Failure.owned_directory_retired,true);return true;});assert.equal(h.roots().length,0);assert.equal(fs.readFileSync(h.pathFile,'utf8'),'');assert.equal(h.facts().SDKExecutions,0);
 }
});
