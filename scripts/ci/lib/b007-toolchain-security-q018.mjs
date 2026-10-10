// Exact Q018 successor: current qualification and fixed offline historical domains.
// No production grants, arbitrary targets, shell execution or scan exclusions.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { isDeepStrictEqual as equal } from 'node:util';
import { fileURLToPath } from 'node:url';
import { scanTreeForByteEvidence } from './b007-byte-evidence-scan-q015.mjs';
import { inspectFixedOriginPolicy as inspectOldPolicy, FIXED_ORIGIN_FINDING } from './b007-fixed-origin-policy-q015.mjs';

export const Q018_AUTHORITY='docs/pilot/authorities/toolchain-dependency-security-successor-q018.json';
export const Q018_QUALIFICATION='docs/pilot/evidence/task0-q018/toolchain-dependency-qualification.json';
export const Q018_DOMAINS='docs/pilot/evidence/task0-q018/historical-toolchain-domains.json';
export const Q018_AUTHORITY_SHA='c9c157c12e19833373b9a610db3de68a1bcd19f3ab71aa2b3e94dc2fcd5962b4';
export const Q018_QUALIFICATION_SHA='d653e2e51d97b7f2a3e5c48da8e72d20982ef908de3fa65812a21dd739ee8284';
export const Q018_CURRENT_GATE_SHA='56b7497e976c89bedecb9c1621f22d0f7b5c35f6c7d8474741e84f878cbdccb6';
export const Q018_MODIFIED_PATHS=Object.freeze([".go-version","go.mod","go.sum","tools/toolchain.lock.json","tools/supply-chain/licenses.json","scripts/ci/lib/constants.mjs","scripts/ci/validate/toolchain-lock.mjs","scripts/ci/validate/supply-chain.mjs","scripts/ci/validate/storage.mjs","scripts/ci/validate/defer-016.mjs","scripts/ci/sbom/generate-sbom.mjs","scripts/ci/validate/sbom.mjs",".github/workflows/ci.yml","scripts/ci/validate/workflow.mjs","scripts/ci/lib/b007-successor.mjs","scripts/ci/test/b007-lifecycle.test.mjs","scripts/ci/run-checks.mjs","internal/pilot/runtime_namespace_test.go"]);
export const Q018_NEW_PATHS=Object.freeze(["docs/pilot/authorities/toolchain-dependency-security-successor-q018.json","docs/pilot/proposals/toolchain-dependency-security-q018.json","scripts/ci/lib/b007-toolchain-security-q018.mjs","scripts/ci/test/b007-toolchain-security-q018.test.mjs","docs/pilot/evidence/task0-q018/PR28-original-CI-failure.json","docs/pilot/evidence/task0-q018/toolchain-dependency-qualification.json","docs/pilot/evidence/task0-q018/historical-toolchain-domains.json","docs/pilot/evidence/task0-q018/namespace-fixture-source-contract.json"]);
// Q019 is a separate exact smoke exception. The original Q01818+8 arrays,
// authority, qualification and historical source inventory remain immutable.
export const Q019_AUTHORITY='docs/pilot/authorities/toolchain-smoke-current-pin-successor-q019.json';
export const Q019_PROPOSAL='docs/pilot/proposals/toolchain-smoke-current-pin-q019.json';
export const Q019_AUTHORITY_SHA='11a0f1931f8351a7b6107a7079da5b1cce3d3240e0ca33001c487937ebafeb25';
export const Q019_PROPOSAL_SHA='688b2608fb36538faa7bee811a22e5873dd85295e324df811da9072018dcab1b';
export const Q019_SMOKE='internal/toolchainsmoke/toolchainsmoke_test.go';
export const Q019_SMOKE_SHA='2945b831b5fb54bc9c2ae7e4ae04a7a5001c1e6b87fe62e717e2f8929c56076e';
export const Q019_ORIGINAL_SMOKE_SHA='96c0832d08b3b6bf7ff7028eec05036680c54f27047a9f0d2f47f3c0d11dd504';
export const Q019_NEW_PATHS=Object.freeze([Q019_AUTHORITY,Q019_PROPOSAL]);
const Q019_WORK_PATHS=Object.freeze([Q019_SMOKE,'scripts/ci/lib/b007-toolchain-security-q018.mjs','scripts/ci/lib/b007-successor.mjs','scripts/ci/test/b007-lifecycle.test.mjs']);
// Separate Q021 authority; all Q018/Q019 constants and historical arrays remain fixed.
export const Q021_AUTHORITY='docs/pilot/authorities/ci-sdk-direct-qualified-repack-successor-q021.json';
export const Q021_PROPOSAL='docs/pilot/proposals/ci-sdk-direct-qualified-repack-q021.json';
export const Q021_AUTHORITY_SHA='8cfaa7438164745e0e3b0c932b80636461682bf187d380dbac44ce5a3fba1739';
export const Q021_PROPOSAL_SHA='9a4e4248433f1cf4c48599927ac36c0d1ea66325877870c3365c6cac89a5ad87';
export const Q021_WORK_PATHS=Object.freeze(['scripts/ci/lib/b007-toolchain-security-q018.mjs','scripts/ci/test/b007-toolchain-security-q018.test.mjs','scripts/ci/lib/b007-successor.mjs','scripts/ci/test/b007-lifecycle.test.mjs']);
export const Q021_NEW_PATHS=Object.freeze([Q021_AUTHORITY,Q021_PROPOSAL]);
export const Q021_BASELINE='d9228b80329380aafc9282f6ce72aa5c0eb30b11';
const Q021_MARKER=Object.freeze({relative:'setup.sh',bytes:694,sha256:'ae49e39291a8c0731482cc314c56e368380d9a7fff45f0c6416361f31120e3e7',executable:false});
const SOURCE_IDENTITIES=Object.freeze({
 ".go-version": "9217820457f2d1ed92ceeeae09665269e17dd7e14e79bab94ac86e8d7b1773c3",
 "go.mod": "cf3112b30af966cfd43a6f98d98fecccc7298455dddef805a07df53c20a97ac0",
 "go.sum": "b90c1ce39e44b933baf4b2d6c8674e41f9d66d8b71b1d94e93923d3441c5f469",
 "tools/toolchain.lock.json": "99e3cee560de7c914d39ffa3b797e10035773aa2326f5f9a57e9b14dd196690f",
 "tools/supply-chain/licenses.json": "791861118588ef648f34a79567712b26b031005c1a9373a4dc76e926c07374fe",
 "scripts/ci/lib/constants.mjs": "79d3d0e6714aca4f515507c36a56acf33daf52f1d018eee8ae606bdfb1aeee72",
 "scripts/ci/validate/toolchain-lock.mjs": "fc36ca17598ec4ce376f30090caf7d866a3c5eec8f1560158a61bcd96ab22704",
 "scripts/ci/validate/supply-chain.mjs": "56b7497e976c89bedecb9c1621f22d0f7b5c35f6c7d8474741e84f878cbdccb6",
 "scripts/ci/validate/storage.mjs": "6fbce89447143649c5b1b797031c0a84813b5c45e5dab6d53f0e42518afd74e9",
 "scripts/ci/validate/defer-016.mjs": "531b488d63e3c138eb3928178ad46166b85826f43e1838bcb1662e62b07aaea0",
 "scripts/ci/sbom/generate-sbom.mjs": "1cd8881a51b4025bca55281eb5cfea04b7fb058a35a9bb4270334685c0a54dbf",
 "scripts/ci/validate/sbom.mjs": "7c478b2cda2c0864ade477e8a8cc91e884a24f769a4c674cf5338895ffc953c8",
 ".github/workflows/ci.yml": "46623c4a81e2fdfe489c8d14eb46d9dc0fd31ca7f6b699f8f217e0f7e557798d",
 "scripts/ci/validate/workflow.mjs": "3becc03aaae1c1a088147190a09688d90abe9e141e1d732064cc519040d8ff0a",
 "scripts/ci/lib/b007-successor.mjs": "3c0aecefb36bbef576c4ad65e95af3313e855a6d94023aa3c447a413aabd01d9",
 "scripts/ci/test/b007-lifecycle.test.mjs": "c2cbea2b78d622e9285ef565a7b970dc152406c294d81d88f30162de1f175fca",
 "scripts/ci/run-checks.mjs": "4c7373700fc63c13ddb39b17a6adb4714cd0ca33b0289857c46b171e0e96a52a",
 "internal/pilot/runtime_namespace_test.go": "4b60755568336b8c446df43b45cd2d60b4befaa9f0358254d6a086ea5e9d7458"
});
const OLD_Q015_AUTHORITY='d9c58aa1cd329bcb9f5c83ceea216c0427d7d3ed968d69f2dfc8c007be7076be';
const OLD_SCANNER='d08c0f1da9e6b6c04aa91f0bdee0ae655e0c7b2baf301efc613a789ef5baa5b3';
const OLD_SNAPSHOT='0e7bd7b810be7bb80ab89d3e62a4285911e39fb3e7c13b2c4d729ed957521fa6';
const OLD_Q002='214d271c85245bac4f009e524e841f59411291d1ea6c09cc068066b131f6ca7b';
const CURRENT_FIXTURE='4b60755568336b8c446df43b45cd2d60b4befaa9f0358254d6a086ea5e9d7458';
const BASE='5f3f6353d744f6674de7cb610a8d8e9b9220c02a';
const F7='f7c3736acd3524240ec178dc81e0a1c72a690930';
export const Q018_ROUTES=Object.freeze(['B007_PREDECESSOR_BASE','STANDALONE_8D6A','B001_LAUNCHER','B001_LAUNCHER_RACE','P1_REVERIFICATION','Q015_FULL23_F7']);
const hash=raw=>createHash('sha256').update(raw).digest('hex');
const clone=v=>JSON.parse(JSON.stringify(v));

export function heldQ018Bytes(full,maxBytes=8388608) {
 const before=fs.lstatSync(full,{bigint:true});
 if(!before.isFile()||before.nlink!==1n||before.size>BigInt(maxBytes))throw new Error('nonregular/aliased/oversized Q018 artifact');
 const fd=fs.openSync(full,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try {
  const opened=fs.fstatSync(fd,{bigint:true}),raw=fs.readFileSync(fd),after=fs.fstatSync(fd,{bigint:true}),atPath=fs.lstatSync(full,{bigint:true});
  for(const k of ['dev','ino','size','mode','nlink','uid','gid','mtimeNs','ctimeNs'])if(before[k]!==opened[k]||opened[k]!==after[k]||after[k]!==atPath[k])throw new Error('Q018 artifact changed while held');
  if(BigInt(raw.length)!==before.size)throw new Error('short Q018 artifact read');
  return {raw,bytes:raw.length,sha256:hash(raw),executable:Boolean(Number(before.mode)&0o111)};
 }finally{fs.closeSync(fd);}
}
function json(repo,rel,digest) {
 const v=heldQ018Bytes(path.join(repo,rel));if(digest&&v.sha256!==digest)throw new Error('Q018 exact identity mismatch: '+rel);return JSON.parse(v.raw);
}
export function qualification(repo) {return json(repo,Q018_QUALIFICATION,Q018_QUALIFICATION_SHA);}
export function q018Approved(repo) {
 try {
  const a=json(repo,Q018_AUTHORITY,Q018_AUTHORITY_SHA);
  return a.decision_id==='AIPT-MVP-B007-OWNER-Q018'&&a.state==='OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI'&&a.owner_instruction==='批准'&&!a.generic_followon_permission&&!a.production_namespace_changes_authorized&&!a.new_DIAG_or_extra_budget_authorized&&!a.runtime_ready&&!a.paid_callable&&a.qualification_runs_authorized===0;
 }catch{return false;}
}
export function q019Approved(repo) {
 try {
  if(!q018Approved(repo))return false;
  const a=json(repo,Q019_AUTHORITY,Q019_AUTHORITY_SHA);
  const proposal=heldQ018Bytes(path.join(repo,Q019_PROPOSAL));
  return a.decision_id==='AIPT-MVP-B007-OWNER-Q019'&&a.state==='OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI'&&a.owner_instruction==='批准'
   &&equal(a.current_work_paths,Q019_WORK_PATHS)&&equal(a.new_exact_public_paths,Q019_NEW_PATHS)
   &&a.approved_private_contract.sha256==='27e987d761e4b377e85a42316cdabb260afcdee0b0e6d3c75a3613fd47d7851a'
   &&a.actual_Owner_approval_registration.sha256==='f8a4a898ad030620c6d179a9b055efaba6a2ed15a207d70e1867f27bb5491850'
   &&a.retained_Q018_authority.path===Q018_AUTHORITY&&a.retained_Q018_authority.sha256===Q018_AUTHORITY_SHA
   &&a.retained_Q018_qualification_sha256===Q018_QUALIFICATION_SHA
   &&a.proposal_binding.path===Q019_PROPOSAL&&a.proposal_binding.sha256===Q019_PROPOSAL_SHA
   &&proposal.sha256===Q019_PROPOSAL_SHA&&proposal.bytes===a.proposal_binding.bytes
   &&a.smoke.path===Q019_SMOKE&&equal(a.smoke.original,{bytes:789,sha256:Q019_ORIGINAL_SMOKE_SHA})
   &&equal(a.smoke.approved_current,{bytes:635,sha256:Q019_SMOKE_SHA})
   &&a.combined_source_count===650&&a.unchanged_f7_protected_paths===621
   &&a.original_Q01818plus8_scope_and_authority_unchanged&&a.historical_f7_smoke_go1_26_6_retained
   &&!a.generic_followon_permission&&!a.production_namespace_changes_authorized&&!a.new_DIAG_or_extra_budget_authorized
   &&!a.runtime_ready&&!a.paid_callable&&a.qualification_runs_authorized===0;
 }catch{return false;}
}
export function currentQualificationProblems(repo,{lock,licenses}={}) {
 const p=[];
 try {
  if(!q018Approved(repo))throw new Error('Q018 exact Owner authorization absent');
  const a=json(repo,Q018_AUTHORITY,Q018_AUTHORITY_SHA),q=qualification(repo);
  for(const b of a.bindings){const v=heldQ018Bytes(path.join(repo,b.path));if(v.bytes!==b.bytes||v.sha256!==b.sha256)p.push('Q018 exact bound evidence changed: '+b.path);}
  const actualLock=lock??json(repo,'tools/toolchain.lock.json');
  const actualLicenses=licenses??json(repo,'tools/supply-chain/licenses.json');
  if(!equal(actualLock.toolchains?.go,q.current_go_lock))p.push('Q018 current Go lock differs from full archive/source/license qualification');
  if(!equal(actualLock.q018_qualification,{path:Q018_QUALIFICATION,sha256:Q018_QUALIFICATION_SHA,old_B003_historical_go:'1.26.6',current_go:'1.26.9'}))p.push('Q018 current Go provenance binding changed');
  const expectedLicenses=clone(q.current_licenses);
  expectedLicenses.historical_qualifications={path:Q018_QUALIFICATION,sha256:Q018_QUALIFICATION_SHA,scope:'IMMUTABLE_PRE_Q018_FULL_LICENSE_INVENTORY_NOT_CURRENT_VULNERABILITY_STATUS'};
  if(!equal(actualLicenses,expectedLicenses))p.push('Q018 current full22 license inventory differs from qualified versions, roles, SPDX and history binding');
  for(const b of q.pins){const v=heldQ018Bytes(path.join(repo,b.path));if(v.bytes!==b.bytes||v.sha256!==b.sha256)p.push('Q018 exact current pin changed: '+b.path);}
  if(heldQ018Bytes(path.join(repo,'internal/pilot/runtime_namespace_test.go')).sha256!==CURRENT_FIXTURE)p.push('Q018 diagnostics-only fixture identity changed');
 }catch(e){p.push('Q018 qualification fails closed: '+e.message);}
 return p;
}
export function q021Approved(repo) {
 try {
  if(!q019Approved(repo))return false;
  const a=json(repo,Q021_AUTHORITY,Q021_AUTHORITY_SHA),p=heldQ018Bytes(path.join(repo,Q021_PROPOSAL));
  return a.decision_id==='AIPT-MVP-B007-OWNER-Q021'&&a.state==='OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI'
   &&a.owner_instruction==='批准Q021限定后继，并按全部验收条件继续（推荐）'
   &&equal(a.current_work_paths,Q021_WORK_PATHS)&&equal(a.new_exact_public_paths,Q021_NEW_PATHS)
   &&a.approved_private_contract.sha256==='0ff994445b1cd8df002abee6a63a2564b852f59a0d10cbf6817bdf8851dc30cc'
   &&a.actual_Owner_approval_registration.sha256==='4616431db448c4c7d694c9cdf604352deaa7c8368bcfed727c16fc0f6724c03f'
   &&a.retained_Q018_authority_sha256===Q018_AUTHORITY_SHA&&a.retained_Q019_authority_sha256===Q019_AUTHORITY_SHA
   &&a.retained_Q018_qualification_sha256===Q018_QUALIFICATION_SHA
   &&a.proposal_binding.path===Q021_PROPOSAL&&a.proposal_binding.sha256===Q021_PROPOSAL_SHA
   &&p.sha256===Q021_PROPOSAL_SHA&&p.bytes===a.proposal_binding.bytes
   &&a.baseline.commit===Q021_BASELINE&&a.baseline.tree==='9d72bf5c1a08114f66ff3a154487f02e15492733'&&equal(a.baseline.parents,[BASE])
   &&a.combined_source_count===652&&a.protected_current_paths===646
   &&a.SDK_execution_interval_source_stability_owner_accepted&&a.cannot_guarantee_same_UID_instant_replace_restore_detection
   &&!a.SDK_copy_write_chmod_registry_retirement_authorized&&!a.generic_followon_permission&&!a.production_namespace_changes_authorized
   &&!a.new_DIAG_or_extra_budget_authorized&&!a.runtime_ready&&!a.paid_callable&&a.qualification_runs_authorized===0&&a.separate_final_Owner_merge_approval_required;
 }catch{return false;}
}
function q021Proposal(repo) {
 if(!q021Approved(repo))throw new Error('Q021 exact approved Owner authority/proposal absent or changed');
 return json(repo,Q021_PROPOSAL,Q021_PROPOSAL_SHA);
}
export function q021SourceProblems(repo) {
 const p=currentQualificationProblems(repo);
 try {
  const q=q021Proposal(repo),expected=new Set([...q.protected646.map(f=>f.relative),...Q021_WORK_PATHS,...Q021_NEW_PATHS]);
  if(q.protected646.length!==646||expected.size!==652)throw new Error('Q021 exact646/652 scope invalid');
  const observed=git(repo,['ls-files','--cached','--others','--exclude-standard']).split('\n').filter(Boolean);
  if(!equal([...new Set(observed)].sort(),[...expected].sort()))p.push('Q018/Q019/Q021 exact650-to652 working source set changed');
  for(const f of q.protected646){
   const v=heldQ018Bytes(path.join(repo,f.relative));
   if(v.bytes!==f.bytes||v.sha256!==f.sha256||v.executable!==(f.git_mode==='100755'))p.push('Q018/Q019/Q021 protected exact650 origin changed: '+f.relative);
  }
  for(const file of Q021_WORK_PATHS)heldQ018Bytes(path.join(repo,file));
 }catch(e){p.push('Q018/Q019/Q021 source contract fails closed: '+e.message);}
 return p;
}
// Fresh Git blobs, never a caller's claimed manifest or cached source acceptance.
export function q021RevisionProblems(repo,revision,{baseline=false}={}) {
 const p=[];
 try {
  const q=q021Proposal(repo),expected=baseline?q.baseline650:q.protected646;
  const tree=git(repo,['ls-tree','-rz','--full-tree',revision]).split('\0').filter(Boolean).map(line=>{
   const [header,relative]=line.split('\t'),[mode,type,oid]=header.split(' ');
   if(type!=='blob'||!['100644','100755'].includes(mode))throw new Error('nonregular Q021 Git source');
   return {relative,mode,oid};
  });
  const paths=new Set(baseline?q.baseline650.map(f=>f.relative):[...q.protected646.map(f=>f.relative),...Q021_WORK_PATHS,...Q021_NEW_PATHS]);
  if(tree.length!==paths.size||!equal(tree.map(f=>f.relative).sort(),[...paths].sort()))throw new Error('Q021 exact committed650/652 source set changed');
  const child=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,'cat-file','--batch'],{input:tree.map(f=>f.oid+'\n').join(''),maxBuffer:64*1024*1024,env:{PATH:'/usr/bin:/bin',GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
  if(child.error||child.signal||child.status!==0)throw new Error('Q021 full committed blob read failed');
  let offset=0;const actual=new Map();
  for(const f of tree){
   const end=child.stdout.indexOf(10,offset);if(end<0)throw new Error('short Q021 Git header');
   const [oid,type,sizeText]=child.stdout.subarray(offset,end).toString().split(' '),size=Number(sizeText);offset=end+1;
   if(type!=='blob'||oid!==f.oid||!Number.isSafeInteger(size)||size<0||offset+size>=child.stdout.length)throw new Error('invalid Q021 Git blob');
   const raw=child.stdout.subarray(offset,offset+size);offset+=size;
   if(child.stdout[offset++]!==10)throw new Error('short Q021 Git blob');
   actual.set(f.relative,{bytes:size,sha256:hash(raw),git_mode:f.mode,git_blob_oid:oid});
  }
  if(offset!==child.stdout.length)throw new Error('additional Q021 Git output');
  for(const f of expected){const v=actual.get(f.relative);if(!equal(v,{bytes:f.bytes,sha256:f.sha256,git_mode:f.git_mode,git_blob_oid:f.git_blob_oid}))p.push('Q021 protected exact650 Git origin changed: '+f.relative);}
  if(!baseline)for(const [file,digest]of [[Q021_AUTHORITY,Q021_AUTHORITY_SHA],[Q021_PROPOSAL,Q021_PROPOSAL_SHA]])if(actual.get(file)?.sha256!==digest)p.push('Q021 committed Owner record changed: '+file);
 }catch(e){p.push('Q021 full source revision fails closed: '+e.message);}
 return p;
}
// Fixed local Git metadata preparation is separate from the read-only SDK
// qualifier. It only makes the already-required sibling candidates available
// to unchanged nested clones; it does not select or authorize another source.
const q021CloneOrigins=Object.freeze([
 Object.freeze({ref:'refs/heads/codex/q021-fixed-history-pr27',commit:'ec76d9c5cba0c32f3bb58c2a0abb9602f9ebe2d8',tree:'9ab33633cdf943571ca3693c15a53b4f0b3d2dd5'}),
 Object.freeze({ref:'refs/heads/codex/q021-fixed-history-pr28',commit:F7,tree:'bd09b4e24b8cb2c7db15bdb43cbd3d3fc8c9bcea'}),
 Object.freeze({ref:'refs/heads/codex/q021-fixed-history-pr29',commit:Q021_BASELINE,tree:'9d72bf5c1a08114f66ff3a154487f02e15492733'}),
]);
function q021CloneState(repo) {
 const q=q021Proposal(repo),paths=[...q.protected646.map(f=>f.relative),...Q021_WORK_PATHS,...Q021_NEW_PATHS].sort();
 const identity=p=>{const v=heldQ018Bytes(p);return {bytes:v.bytes,sha256:v.sha256,executable:v.executable};};
 return {head:git(repo,['rev-parse','HEAD']),tree:git(repo,['rev-parse','HEAD^{tree}']),main:git(repo,['rev-parse','refs/remotes/origin/main']),
  index:identity(git(repo,['rev-parse','--path-format=absolute','--git-path','index'])),
  source:paths.map(relative=>({relative,...identity(path.join(repo,relative))}))};
}
function q021CloneFacts(repo,origin) {
 if(git(repo,['show','--no-show-signature','-s','--format=%H%n%T%n%P',origin.commit])!==[origin.commit,origin.tree,BASE].join('\n'))throw new Error('Q021 fixed clone origin SHA/tree/unique BASE parent changed');
}
function q021CloneRef(repo,ref) {
 const value=git(repo,['for-each-ref','--format=%(refname)%00%(objectname)%00%(symref)',ref]);
 if(value==='')return null;
 const fields=value.split('\0');
 if(fields.length!==3||fields[0]!==ref||fields[2]!==''||!/^[a-f0-9]{40}$/u.test(fields[1]))throw new Error('Q021 fixed local clone ref is symbolic, nested or invalid');
 return fields[1];
}
export function prepareQ021FixedCloneOrigins(repo) {
 if(arguments.length!==1)throw new Error('Q021 fixed clone origins accept no caller targets or options');
 const problems=[...q021SourceProblems(repo),...q021RevisionProblems(repo,Q021_BASELINE,{baseline:true})];
 if(problems.length)throw new Error('Q021 fixed clone origin prerequisites failed: '+problems.join('; '));
 const before=q021CloneState(repo),commands=[];
 for(const origin of q021CloneOrigins){
  q021CloneFacts(repo,origin);const actual=q021CloneRef(repo,origin.ref);
  if(actual!==null&&actual!==origin.commit)throw new Error('Q021 existing fixed local clone ref differs; overwrite forbidden');
  commands.push((actual===null?'create ':'verify ')+origin.ref+' '+origin.commit);
 }
 // --no-deref and one transaction make a raced create/verify fail atomically.
 run('/usr/bin/git',['--no-optional-locks','-C',repo,'update-ref','--no-deref','--stdin'],
  {input:'start\n'+commands.join('\n')+'\nprepare\ncommit\n',env:{...process.env,GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(!equal(before,q021CloneState(repo)))throw new Error('Q021 source/HEAD/tree/index/origin-main changed during fixed clone preparation');
 const after=[...q021SourceProblems(repo),...q021RevisionProblems(repo,Q021_BASELINE,{baseline:true})];
 if(after.length)throw new Error('Q021 fixed clone origin postcheck failed: '+after.join('; '));
 for(const origin of q021CloneOrigins){q021CloneFacts(repo,origin);if(q021CloneRef(repo,origin.ref)!==origin.commit)throw new Error('Q021 fixed local clone ref postcheck changed');}
 return {result:'PASS_Q021_FIXED_LOCAL_CLONE_ORIGINS_PREPARED',fixed_refs:q021CloneOrigins.map(v=>({...v})),
  source_HEAD_tree_index_origin_main_unchanged:true,SDK_program_or_mutation:0,network_requests:0,model_DIAG_QUAL:0,
  full_HIGH_or_CI_or_runtime_accepted:false};
}
// These projections are used ONLY by the named historical pure validators.
// Current records are independently and mandatorily checked above; the full
// historical validators/tests also replay at their original fixed Git targets.
export function historicalLockProjection(repo,current) {
 const v=clone(current);v.toolchains.go=clone(qualification(repo).historical_qualifications.toolchains_go);delete v.q018_qualification;return v;
}
export function historicalLicenseInventory(repo) {return clone(qualification(repo).historical_qualifications.licenses);}
export function approvedCurrentSHA(relative) {return SOURCE_IDENTITIES[relative]??null;}
export function q018SourceProblems(repo) {
 if(fs.existsSync(path.join(repo,Q021_AUTHORITY))||fs.existsSync(path.join(repo,Q021_PROPOSAL)))return q021SourceProblems(repo);
 const p=currentQualificationProblems(repo);
 try {
  if(!q019Approved(repo))throw new Error('Q019 exact approved smoke Owner authority/proposal absent or changed');
  const smoke=heldQ018Bytes(path.join(repo,Q019_SMOKE));
  if(smoke.bytes!==635||smoke.sha256!==Q019_SMOKE_SHA||smoke.executable)p.push('Q019 exact approved current smoke changed');
  for(const [file,digest]of Object.entries(SOURCE_IDENTITIES))if(heldQ018Bytes(path.join(repo,file)).sha256!==digest)p.push('Q018 exact approved current source changed: '+file);
  const a=json(repo,Q018_AUTHORITY,Q018_AUTHORITY_SHA);
  if(!equal(a.current_modified_paths,Q018_MODIFIED_PATHS)||!equal(a.new_exact_paths,Q018_NEW_PATHS))p.push('Q01818+8 exact path scope changed');
  const d=domains(repo),expected=new Set([...d.source_f7_640.map(f=>f.path),...Q018_NEW_PATHS,...Q019_NEW_PATHS]);
  const originalSmoke=d.source_f7_640.find(f=>f.path===Q019_SMOKE);
  if(!originalSmoke||originalSmoke.bytes!==789||originalSmoke.sha256!==Q019_ORIGINAL_SMOKE_SHA||originalSmoke.executable)throw new Error('Q019 original f7 smoke binding changed');
  const observed=git(repo,['ls-files','--cached','--others','--exclude-standard']).split('\n').filter(Boolean);
  if(!equal([...new Set(observed)].sort(),[...expected].sort()))p.push('Q018/Q019 exact650 working source set changed');
  for(const f of d.source_f7_640){
   if(Q018_MODIFIED_PATHS.includes(f.path)||f.path===Q019_SMOKE)continue;
   const v=heldQ018Bytes(path.join(repo,f.path));if(v.bytes!==f.bytes||v.sha256!==f.sha256||v.executable!==f.executable)p.push('Q018 protected original f7 bytes changed: '+f.path);
  }
 }catch(e){p.push('Q018 source contract fails closed: '+e.message);}
 return p;
}

// New pure decision function; original Q015 policy/test/scanners stay unchanged.
// The live entry derives all facts and complete unfiltered scans itself.
export function classifyQ018OriginEvidence(originalFindings,byteEvidence,facts) {
 const p=[],accepted=[],blocking=[];
 const expected={q018_authority_sha256:Q018_AUTHORITY_SHA,q018_qualification_sha256:Q018_QUALIFICATION_SHA,q015_authority_sha256:OLD_Q015_AUTHORITY,authorization_state:'OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI',owner_instruction:'批准',current_gate_sha256:Q018_CURRENT_GATE_SHA,original_scanner_sha256:OLD_SCANNER,original_validator_snapshot_sha256:OLD_SNAPSHOT,q002_authority_sha256:OLD_Q002,original_Q015_current_identity_result:'FAIL'};
 for(const [k,v]of Object.entries(expected))if(facts?.[k]!==v)p.push('exact Q018 authorization or gate identity mismatch: '+k);
 if(byteEvidence?.scan_complete!==true||!Array.isArray(byteEvidence?.findings))p.push('complete byte-bound scan unavailable');
 const rows=Array.isArray(byteEvidence?.findings)?byteEvidence.findings:[];
 if(!equal(originalFindings,rows.map(({file,hazard})=>({file,hazard}))))p.push('original complete scan and byte-bound complete scan disagree');
 for(const row of rows){if(p.length===0&&equal(row,FIXED_ORIGIN_FINDING)&&accepted.length===0)accepted.push(row);else blocking.push(row);}
 if(accepted.length!==1)p.push('exact single fixed-origin finding absent or unapproved');
 return {decision_id:'AIPT-MVP-B007-OWNER-Q018',result:p.length||blocking.length?'FAIL':'PASS',problems:p,original_unfiltered_findings:originalFindings,byte_bound_findings:rows,accepted_findings:accepted,blocking_findings:blocking,complete_original_scan_retained:true,no_scan_exemptions:true,original_Q015_current_identity_result:facts?.original_Q015_current_identity_result,local_online_CI_acceptance_claim:false,runtime_ready:false,paid_callable:false};
}
export function inspectQ018OriginPolicy(repo,originalFindings) {
 try {
  const p=q018SourceProblems(repo);if(p.length)throw new Error(p.join('; '));
  const a=json(repo,Q018_AUTHORITY,Q018_AUTHORITY_SHA);
  const old=inspectOldPolicy(repo,originalFindings);
  if(old.result!=='FAIL'||!old.problems.some(p=>p==='exact authorization or gate identity mismatch: current_gate_sha256'))throw new Error('original Q015 current gate identity FAIL was not retained');
  const facts={q018_authority_sha256:heldQ018Bytes(path.join(repo,Q018_AUTHORITY)).sha256,q018_qualification_sha256:heldQ018Bytes(path.join(repo,Q018_QUALIFICATION)).sha256,q015_authority_sha256:heldQ018Bytes(path.join(repo,'docs/pilot/authorities/fixed-origin-policy-successor-q015.json')).sha256,authorization_state:a.state,owner_instruction:a.owner_instruction,current_gate_sha256:heldQ018Bytes(path.join(repo,'scripts/ci/validate/supply-chain.mjs')).sha256,original_scanner_sha256:heldQ018Bytes(path.join(repo,'scripts/ci/lib/scan.mjs')).sha256,original_validator_snapshot_sha256:heldQ018Bytes(path.join(repo,'docs/pilot/evidence/task0-q015/original-supply-chain.mjs')).sha256,q002_authority_sha256:heldQ018Bytes(path.join(repo,'docs/pilot/authorities/wire-budget-closure-successor.json')).sha256,original_Q015_current_identity_result:old.result};
  return classifyQ018OriginEvidence(originalFindings,scanTreeForByteEvidence(repo),facts);
 }catch(e){return {decision_id:'AIPT-MVP-B007-OWNER-Q018',result:'FAIL',problems:['Q018 policy/scanning failure: '+e.message],original_unfiltered_findings:originalFindings,accepted_findings:[],blocking_findings:originalFindings,runtime_ready:false,paid_callable:false};}
}

function directory(full,create=false) {
 if(create&&!fs.existsSync(full))fs.mkdirSync(full,{recursive:true,mode:0o700});
 const s=fs.lstatSync(full);if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0)throw new Error('Q018 owned private domain directory required');return full;
}
function stateRoot() {return directory(path.join('/tmp','aipt-q018-toolchain-domains-'+process.getuid()),true);}
function localAssetRoot(repo) {
 for(let p=path.resolve(repo),i=0;i<12;i++,p=path.dirname(p)){
  const candidate=path.join(p,'.b001-toolcache','q018-qualified-sdks-001');if(fs.existsSync(candidate))return candidate;
  if(path.dirname(p)===p)break;
 }
 return null;
}
function sdkSpec(repo,version){const s=qualification(repo).SDKs.find(s=>s.version===version);if(!s)throw new Error('unknown SDK version');return s;}
// Accept only a complete file/directory set whose logical hashes, sizes and
// executable bits match the independently accepted fixed official archive.
// Ambient GOROOT/PATH never authorizes a historical compiler.
export function verifySDK(root,spec) {
 const rootStat=fs.lstatSync(root);if(!rootStat.isDirectory()||rootStat.isSymbolicLink())throw new Error('nonphysical SDK root');
 const actualFiles=[],actualDirs=[];
 const walk=(dir,rel)=>{
  actualDirs.push(rel);
  for(const e of fs.readdirSync(dir,{withFileTypes:true})){
   const r=rel==='.'?e.name:rel+'/'+e.name;const full=path.join(dir,e.name);
   if(e.isDirectory()&&!e.isSymbolicLink())walk(full,r);
   else if(e.isFile()&&!e.isSymbolicLink())actualFiles.push(r);
   else throw new Error('special SDK member');
  }
 };
 walk(root,'.');
 const expectedFiles=spec.files.map(f=>f.relative).sort();
 if(!equal(actualFiles.sort(),expectedFiles)||!equal(actualDirs.sort(),spec.directories))throw new Error('incomplete or additional SDK members');
 for(const f of spec.files){const v=heldQ018Bytes(path.join(root,f.relative),f.bytes);if(v.bytes!==f.bytes||v.sha256!==f.sha256||v.executable!==f.executable)throw new Error('SDK full member identity mismatch: '+f.relative);}
 return {version:spec.version,files:spec.files.length,directories:spec.directories.length,complete_fixed_archive_identity:true};
}
const q021StatFields=['dev','ino','size','mode','nlink','uid','gid','mtimeNs','ctimeNs'];
const q021AncestorFields=['dev','ino','mode','uid','gid'];
function q021Same(a,b) {return q021StatFields.every(k=>a[k]===b[k]);}
function q021PhysicalSDK(root,spec) {
 if(typeof root!=='string'||!path.isAbsolute(root)||root!==path.normalize(root)||root==='/'||root.includes('\0'))throw new Error('Q021 absolute physical SDK path required');
 const chain=[],identities=new Map(),files=[],dirs=[],buffer=Buffer.allocUnsafe(1<<20);
 const fileSpecs=new Map(spec.files.map(f=>[f.relative,f])),dirSpecs=new Set(spec.directories);
 const dirFlags=fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_DIRECTORY;
 const remember=(rel,s)=>identities.set(rel,q021StatFields.map(k=>String(s[k])));
 const heldDirectory=(location,ancestor=false)=>{
  const before=fs.lstatSync(location,{bigint:true});if(!before.isDirectory()||before.isSymbolicLink())throw new Error('Q021 nonphysical SDK directory');
  const fd=fs.openSync(location,dirFlags);
  const same=(a,b)=>(ancestor?q021AncestorFields:q021StatFields).every(k=>a[k]===b[k]);
  try{if(!same(before,fs.fstatSync(fd,{bigint:true}))||!same(before,fs.lstatSync(location,{bigint:true})))throw new Error('Q021 SDK directory replaced while opening');return {fd,location,before,same};}catch(e){fs.closeSync(fd);throw e;}
 };
 const stable=d=>{if(!d.same(d.before,fs.fstatSync(d.fd,{bigint:true}))||!d.same(d.before,fs.lstatSync(d.location,{bigint:true})))throw new Error('Q021 SDK directory identity changed');};
 try {
  chain.push(heldDirectory('/',true));
  const parts=root.slice(1).split('/');
  for(const [i,part]of parts.entries()){
   if(!part||part==='.'||part==='..')throw new Error('Q021 invalid SDK path segment');
   const d=heldDirectory('/proc/self/fd/'+chain.at(-1).fd+'/'+part,i!==parts.length-1);chain.push(d);
  }
  const walk=(d,relative)=>{
   stable(d);dirs.push(relative);remember(relative,d.before);
   for(const name of fs.readdirSync('/proc/self/fd/'+d.fd)){
    if(!name||name==='.'||name==='..'||name.includes('/'))throw new Error('Q021 invalid SDK member name');
    const rel=relative==='.'?name:relative+'/'+name,location='/proc/self/fd/'+d.fd+'/'+name,before=fs.lstatSync(location,{bigint:true});
    if(before.isDirectory()&&!before.isSymbolicLink()){
     if(!dirSpecs.has(rel))throw new Error('Q021 additional SDK directory');
     const child=heldDirectory(location);try{walk(child,rel);}finally{fs.closeSync(child.fd);}
    }else{
     const expected=fileSpecs.get(rel);
     if(!expected||!before.isFile()||before.nlink!==1n||before.size!==BigInt(expected.bytes)||Boolean(Number(before.mode)&0o111)!==expected.executable)throw new Error('Q021 nonregular/aliased/additional/changed SDK member: '+rel);
     const fd=fs.openSync(location,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
     try {
      if(!q021Same(before,fs.fstatSync(fd,{bigint:true})))throw new Error('Q021 SDK member replaced while opening');
      const digest=createHash('sha256');let bytes=0,n;
      while((n=fs.readSync(fd,buffer,0,buffer.length,null))>0){bytes+=n;if(bytes>expected.bytes)throw new Error('Q021 SDK member grew');digest.update(buffer.subarray(0,n));}
      if(bytes!==expected.bytes||digest.digest('hex')!==expected.sha256||!q021Same(before,fs.fstatSync(fd,{bigint:true}))||!q021Same(before,fs.lstatSync(location,{bigint:true})))throw new Error('Q021 full SDK member identity changed: '+rel);
      files.push(rel);remember(rel,before);
     }finally{fs.closeSync(fd);}
    }
   }
   stable(d);
  };
  walk(chain.at(-1),'.');
  if(!equal(files.sort(),[...fileSpecs.keys()].sort())||!equal(dirs.sort(),spec.directories))throw new Error('Q021 incomplete or additional SDK members');
  for(const d of chain)stable(d);
  return {identities:[...identities].sort(([a],[b])=>a.localeCompare(b)),ancestry:chain.map(d=>q021AncestorFields.map(k=>String(d.before[k])))};
 }finally{for(const d of chain.reverse())fs.closeSync(d.fd);}
}
function q021QualifiedSDK(repo,root) {
 q021Proposal(repo);
 const official=sdkSpec(repo,'1.26.9');
 if(official.files.length!==15045||official.directories.length!==1667||official.files.some(f=>f.relative==='setup.sh'))throw new Error('Q021 fixed qualification derivation changed');
 const markerPresent=fs.existsSync(path.join(root,'setup.sh'));
 const spec=markerPresent?{...official,files:[...official.files,Q021_MARKER]}:official;
 const before=q021PhysicalSDK(root,spec);
 // Preserve the original verifier exactly; do not promote its derived-spec
 // archive flag into an official raw-archive provenance claim for a repack.
 const original=verifySDK(root,spec),after=q021PhysicalSDK(root,spec);
 if(!equal(before,after))throw new Error('Q021 SDK changed between complete verifications');
 const proof=markerPresent?{version:'1.26.9',files:15046,directories:1667,identity_class:'PINNED_CI_REPACK_LOGICAL_IDENTITY',official_payload_members_match:true,complete_fixed_archive_identity:false,original_official_raw_archive_identity:false,setup_sh_executed:false}:original;
 return {proof,identity:after};
}
export function verifyQ021CurrentSDK(repo,root) {
 if(arguments.length!==2)throw new Error('Q021 accepts no caller SDK spec or options');
 return q021QualifiedSDK(repo,root).proof;
}
export function withQ021VerifiedCurrentSDK(repo,root,action) {
 if(arguments.length!==3||typeof action!=='function')throw new Error('Q021 synchronous action required');
 const before=q021QualifiedSDK(repo,root);let value;
 try{value=action();if(value&&typeof value.then==='function')throw new Error('Q021 asynchronous action not authorized');}
 finally{const after=q021QualifiedSDK(repo,root);if(!equal(before.identity,after.identity))throw new Error('Q021 SDK changed across current metadata command');}
 return value;
}
function currentSDKProof(repo,root) {
 if(fs.existsSync(path.join(repo,Q021_AUTHORITY))||fs.existsSync(path.join(repo,Q021_PROPOSAL)))return verifyQ021CurrentSDK(repo,root);
 return verifySDK(root,sdkSpec(repo,'1.26.9'));
}
function currentMetadata(repo,root,args,options) {
 if(q021Approved(repo))return withQ021VerifiedCurrentSDK(repo,root,()=>run(path.join(root,'bin/go'),args,options));
 currentSDKProof(repo,root);try{return run(path.join(root,'bin/go'),args,options);}finally{currentSDKProof(repo,root);}
}
function historicalRoot(repo) {
 const assets=localAssetRoot(repo);if(assets)return path.join(assets,'go1.26.6-linux-amd64');
 const registration=path.join(stateRoot(),'registered-historical-SDK.json');
 if(fs.existsSync(registration)){
  const held=heldQ018Bytes(registration),r=JSON.parse(held.raw);
  if(fs.lstatSync(registration).uid!==process.getuid()||(fs.lstatSync(registration).mode&0o777)!==0o400||r.schema!=='aipt.q018-fixed-qualified-historical-SDK-location/v1'||r.version!=='1.26.6'||r.archive_sha256!==sdkSpec(repo,'1.26.6').archive.sha256||r.qualification_sha256!==Q018_QUALIFICATION_SHA||typeof r.root!=='string'||!path.isAbsolute(r.root))throw new Error('fixed prepared historical SDK registration changed');
  // This registered location is never sufficient by itself: every member
  // is requalified against the fixed archive before any historical Go use.
  return r.root;
 }
 return path.join(stateRoot(),'SDK','go1.26.6');
}
function currentRoot(repo) {
 const assets=localAssetRoot(repo);if(assets)return path.join(assets,'go1.26.9-linux-amd64');
 for(const p of (process.env.PATH??'').split(path.delimiter)){
  if(!p)continue;const full=path.join(p,'go');if(fs.existsSync(full))return path.dirname(path.dirname(fs.realpathSync(full)));
 }
 throw new Error('current fixed SDK absent');
}
function run(program,args,options={}) {
 const r=spawnSync(program,args,{stdin:'ignore',encoding:'utf8',maxBuffer:64*1024*1024,...options});
 if(r.error||r.signal||r.status!==0)throw new Error('fixed Q018 subprocess failed: '+path.basename(program)+' ('+(r.status??r.signal??'spawn-error')+')');return r;
}
function git(repo,args){return run('/usr/bin/git',['--no-optional-locks','-C',repo,...args],{env:{...process.env,GIT_OPTIONAL_LOCKS:'0'}}).stdout.trim();}
function domains(repo) {const a=json(repo,Q018_AUTHORITY,Q018_AUTHORITY_SHA),b=a.bindings.find(b=>b.path===Q018_DOMAINS);if(!b)throw new Error('fixed domain binding absent');return json(repo,Q018_DOMAINS,b.sha256);}
export function fixedRouteTarget(repo,route) {
 if(!Q018_ROUTES.includes(route))throw new Error('unknown Q018 historical route');
 const d=domains(repo);
 if(route==='STANDALONE_8D6A')return d.fixed_standalone;
 if(route==='Q015_FULL23_F7')return d.fixed_predecessor;
 if(route==='B007_PREDECESSOR_BASE')return d.BASE;
 // The original immutable launcher/P1 entry itself must also run from the
 // exact fixed clean f7 source before it resolves its accepted nested sources.
 return {commit:F7,tree:d.fixed_predecessor.tree};
}
function checkTarget(repo,target,route) {
 const spec=fixedRouteTarget(repo,route);
 if(git(target,['rev-parse','HEAD'])!==spec.commit||git(target,['rev-parse','HEAD^{tree}'])!==spec.tree||git(target,['status','--porcelain=v1','--untracked-files=all'])!=='')throw new Error('historical target is not exact fixed clean Git source');
}
function cacheIdentity(repo,cache) {
 const d=domains(repo);
 for(const m of d.historical15_cache_identities){
  const prefix=path.join(cache,'cache/download',m.module,'@v',m.version);
  const mh=heldQ018Bytes(prefix+'.mod');if(mh.sha256!==m.raw_go_mod_sha256||heldQ018Bytes(prefix+'.ziphash').raw.toString().trim()!==m.module_h1)throw new Error('fixed historical module cache missing or changed');
 }
 return true;
}
function domainPaths() {
 const root=directory(path.join(stateRoot(),'historical'),true);const out={};
 for(const name of ['gocache','gomodcache','gotmp','gopath'])out[name]=directory(path.join(root,name),true);return out;
}
function environment(root,p,{offline=true,DSN=false}={}) {
 const env={PATH:[path.join(root,'bin'),path.dirname(process.execPath),'/usr/bin','/bin'].join(path.delimiter),GOROOT:root,HOME:os.homedir(),TMPDIR:p.gotmp,GOTMPDIR:p.gotmp,GOCACHE:p.gocache,GOMODCACHE:p.gomodcache,GOPATH:p.gopath,GOENV:'off',GOTOOLCHAIN:'local',GOWORK:'off',GOFLAGS:'-mod=readonly',GOOS:'linux',GOARCH:'amd64',GOAMD64:'v1',GOEXPERIMENT:'',GODEBUG:'',CGO_ENABLED:'1',GOPRIVATE:'',GONOPROXY:'',GONOSUMDB:'',GOPROXY:offline?'off':'https://proxy.golang.org',GOSUMDB:offline?'off':'sum.golang.org',GIT_OPTIONAL_LOCKS:'0'};
 if(process.env.npm_execpath)env.npm_execpath=process.env.npm_execpath;
 if(DSN){if(process.env.AIPT_POSTGRES_DSN!=='postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable'||process.env.AIPT_REQUIRE_POSTGRES_INTEGRATION!=='1')throw new Error('fixed test-only loopback PostgreSQL contract absent');env.AIPT_POSTGRES_DSN=process.env.AIPT_POSTGRES_DSN;env.AIPT_REQUIRE_POSTGRES_INTEGRATION='1';}
 return env;
}
export function historicalEnvironment(repo,target,route) {
 if(!q018Approved(repo))throw new Error('historical route lacks Q018 approval');
 checkTarget(repo,target,route);const root=historicalRoot(repo),spec=sdkSpec(repo,'1.26.6');verifySDK(root,spec);
 const p=domainPaths();cacheIdentity(repo,p.gomodcache);
 const env=environment(root,p,{DSN:route==='B001_LAUNCHER'||route==='B001_LAUNCHER_RACE'});
 // SDK identity is complete before this metadata-only offline verification.
 // It independently recomputes all selected module ZIP and source-directory H1.
 const verified=run(path.join(root,'bin/go'),['mod','verify'],{cwd:target,env});
 if(verified.stdout.trim()!=='all modules verified')throw new Error('historical complete module cache verification did not PASS');
 return env;
}
function snapshot(repo,commit,tree) {
 const target=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q018-fixed-source-'));
 try {
  run('/usr/bin/git',['clone','--no-local','--no-checkout',repo,target]);git(target,['checkout','--detach',commit]);git(target,['update-ref','refs/remotes/origin/main',BASE]);
  if(git(target,['rev-parse','HEAD^{tree}'])!==tree||git(target,['status','--porcelain=v1','--untracked-files=all'])!=='')throw new Error('fixed source snapshot identity changed');
  return target;
 }catch(e){fs.rmSync(target,{recursive:true,force:true});throw e;}
}
export function prepareDomains(repo) {
 if(!q018Approved(repo))throw new Error('Q018 preparation lacks exact authorization');
 const current=currentRoot(repo);currentSDKProof(repo,current);
 if(q021Approved(repo))prepareQ021FixedCloneOrigins(repo);
 const old=historicalRoot(repo),spec=sdkSpec(repo,'1.26.6');
 if(!fs.existsSync(old)){
  const parent=directory(path.join(stateRoot(),'SDK'),true),tmp=fs.mkdtempSync(path.join(parent,'fixed-archive-'));
  try {
   const archive=path.join(tmp,spec.archive.filename);
   run('/usr/bin/curl',['--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--max-redirs','3','--connect-timeout','20','--max-time','240','--output',archive,spec.archive.url]);
   const bytes=fs.readFileSync(archive);const st=fs.lstatSync(archive);if(!st.isFile()||st.nlink!==1||bytes.length!==spec.archive.bytes||hash(bytes)!==spec.archive.sha256)throw new Error('fixed official historical archive mismatch');
   run('/usr/bin/tar',['--no-same-owner','--no-same-permissions','-xzf',archive,'-C',tmp]);
   verifySDK(path.join(tmp,'go'),spec);fs.renameSync(path.join(tmp,'go'),old);
  }finally{fs.rmSync(tmp,{recursive:true,force:true});}
 }
 const oldProof=verifySDK(old,spec),p=domainPaths();
 const registry=path.join(stateRoot(),'registered-historical-SDK.json');
 const registered={schema:'aipt.q018-fixed-qualified-historical-SDK-location/v1',version:'1.26.6',archive_sha256:spec.archive.sha256,qualification_sha256:Q018_QUALIFICATION_SHA,root:old};
 if(fs.existsSync(registry)){
  if(!equal(JSON.parse(heldQ018Bytes(registry).raw),registered))throw new Error('prepared historical SDK location differs from fixed registration');
 }else{
  const fd=fs.openSync(registry,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  try{fs.writeFileSync(fd,JSON.stringify(registered)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  fs.chmodSync(registry,0o400);
 }
 let cacheReady=false;try{cacheIdentity(repo,p.gomodcache);cacheReady=true;}catch{/* Exact download/graph checks below seed an owned separate cache. */}
 if(!cacheReady){
  const fixed=domains(repo).fixed_predecessor,target=snapshot(repo,fixed.commit,fixed.tree);
  try {
   const prep=directory(path.join(stateRoot(),'current-metadata-prep'),true),prepPaths={gomodcache:p.gomodcache};
   for(const name of ['gocache','gopath','gotmp'])prepPaths[name]=directory(path.join(prep,name),true);
   const env=environment(current,prepPaths,{offline:false});const graph=currentMetadata(repo,current,['list','-m','-mod=readonly','-json','all'],{cwd:target,env});
   const objects=parseJSONStream(graph.stdout),selected=Object.fromEntries(objects.filter(m=>!m.Main).map(m=>[m.Path,m.Version]));
   if(!equal(selected,domains(repo).historical15_graph)||objects.some(m=>m.Replace||m.Error))throw new Error('historical prep selected graph exceeds exact15');
   currentMetadata(repo,current,['mod','download','-json','all'],{cwd:target,env});cacheIdentity(repo,p.gomodcache);
  }finally{fs.rmSync(target,{recursive:true,force:true});}
 }
 return {result:'PASS_FIXED_CURRENT_AND_HISTORICAL_DOMAINS_PREPARED',current_version:'1.26.9',historical_sdk:oldProof,historical_modules:15,historical_execution_offline:true,current_GITHUB_PATH_changed:false,model_DIAG_QUAL:0};
}
function parseJSONStream(text) {
 const rows=[];let depth=0,start=-1,inString=false,escape=false;
 for(let i=0;i<text.length;i++){const c=text[i];if(inString){if(escape)escape=false;else if(c==='\\')escape=true;else if(c==='"')inString=false;continue;}if(c==='"'){inString=true;continue;}if(c==='{'){if(depth++===0)start=i;}if(c==='}'&&--depth===0){rows.push(JSON.parse(text.slice(start,i+1)));start=-1;}}
 if(depth!==0||inString||start!==-1)throw new Error('invalid fixed graph JSON stream');return rows;
}
export function runFixedHistoricalCLI(repo,route) {
 if(!['B001_LAUNCHER','B001_LAUNCHER_RACE','P1_REVERIFICATION','Q015_FULL23_F7'].includes(route))throw new Error('CLI route is not explicitly approved');
 const d=domains(repo),fixed=d.fixed_predecessor,target=snapshot(repo,fixed.commit,fixed.tree);
 try {
  const env=historicalEnvironment(repo,target,route),entry=route.startsWith('B001_')?['scripts/ci/validate/mvp-b001.mjs','--historical-launcher-integration',...(route==='B001_LAUNCHER_RACE'?['--race']:[])]:route==='P1_REVERIFICATION'?['scripts/ci/validate/p1-b000-post-merge-reverification.mjs']:['--test','--test-reporter=tap','scripts/ci/test/b007-fixed-origin-policy-q015.test.mjs'];
  if(route==='Q015_FULL23_F7'){
   for(const f of d.source_f7_640){const actual=heldQ018Bytes(path.join(target,f.path));if(actual.bytes!==f.bytes||actual.sha256!==f.sha256||actual.executable!==f.executable)throw new Error('Q015 exactf7 full source changed');}
  }
  const r=spawnSync(process.execPath,entry,{cwd:target,env,encoding:'utf8',maxBuffer:64*1024*1024});
  if(r.stdout)process.stdout.write(r.stdout);if(r.stderr)process.stderr.write(r.stderr);
  if(r.error||r.signal||r.status!==0)throw new Error('fixed historical CLI route did not PASS');
  if(route==='Q015_FULL23_F7'&&!/^# tests 23$/m.test(r.stdout))throw new Error('Q015 full23 test count not retained');
  return {result:'PASS',route,commit:fixed.commit,tree:fixed.tree,historical_go:'1.26.6',offline:true,actual_owned_Wait:true,exit_code:0,model_DIAG_QUAL:0};
 }finally{fs.rmSync(target,{recursive:true,force:true});}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try {
  if(process.argv.length!==3)throw new Error('exact one fixed CLI route argument required');
  const command=process.argv[2],repo=process.cwd();
  if(command==='--prepare-domains')process.stdout.write(JSON.stringify(prepareDomains(repo))+'\n');
  else if(command==='--q015-full23')runFixedHistoricalCLI(repo,'Q015_FULL23_F7');
  else if(command==='--b001-launcher')runFixedHistoricalCLI(repo,'B001_LAUNCHER');
  else if(command==='--b001-launcher-race')runFixedHistoricalCLI(repo,'B001_LAUNCHER_RACE');
  else if(command==='--p1-reverification')runFixedHistoricalCLI(repo,'P1_REVERIFICATION');
  else throw new Error('unknown or unapproved Q018 CLI route');
 }catch(error){process.stderr.write('Q018 fixed-domain failure: '+error.message+'\n');process.exitCode=1;}
}
