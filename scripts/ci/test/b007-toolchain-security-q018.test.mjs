import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { Q018_AUTHORITY,Q018_AUTHORITY_SHA,Q018_QUALIFICATION,Q018_QUALIFICATION_SHA,Q018_CURRENT_GATE_SHA,Q018_MODIFIED_PATHS,Q018_NEW_PATHS,Q018_ROUTES,qualification,currentQualificationProblems,historicalLockProjection,historicalLicenseInventory,classifyQ018OriginEvidence,heldQ018Bytes,verifySDK,fixedRouteTarget,historicalEnvironment,Q019_AUTHORITY,Q019_PROPOSAL,Q021_AUTHORITY,Q021_PROPOSAL,q021Approved,verifyQ021CurrentSDK,withQ021VerifiedCurrentSDK,prepareQ021FixedCloneOrigins } from '../lib/b007-toolchain-security-q018.mjs';
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
