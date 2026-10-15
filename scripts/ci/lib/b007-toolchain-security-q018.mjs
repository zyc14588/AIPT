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
// Separate Q022 selector: original Q018/Q019/Q021 records and historical pins remain fixed.
export const Q022_AUTHORITY='docs/pilot/authorities/ci-generated-metadata-optional-namespace-fixture-successor-q022.json';
export const Q022_PROPOSAL='docs/pilot/proposals/ci-generated-metadata-optional-namespace-fixture-q022.json';
export const Q022_AUTHORITY_SHA='4754ce5584bba167307d236d86540c728e950b2b2938b92d6af0f3d8a2c70180';
export const Q022_PROPOSAL_SHA='8af81a37585bc71273071cda45c32888d8487adf479e93fc7947a60f93c5b873';
export const Q022_BASELINE='307935c68577077ef1f8e5a1dfefcb492c162263';
export const Q022_BASELINE_TREE='f0c832a0f5f64856ff60821b19e0ca60608517b7';
export const Q022_WORK_PATHS=Object.freeze(['.github/workflows/ci.yml','internal/pilot/runtime_namespace_test.go',...Q021_WORK_PATHS]);
export const Q022_NEW_PATHS=Object.freeze([Q022_AUTHORITY,Q022_PROPOSAL]);
export const Q022_FIXTURE_SHA='e974e63047cbdb3a2a9c4eb1d96e59759438fde34e22d41f135b0c5b8f4299dd';
export const Q022_WORKFLOW_SHA='9b138bc93705e1dc58b9d5a7be11b3e80a450c84669762e64f0e6f5413e56606';
const Q022_HISTORY_REF='refs/heads/codex/q022-fixed-history-pr30';
export function q022Present(repo) {
 return Q022_NEW_PATHS.some(file=>{try{fs.lstatSync(path.join(repo,file));return true;}catch(e){return e.code!=='ENOENT';}});
}
export function q022Approved(repo) {
 try {
  if(!q021Approved(repo))return false;
  const a=json(repo,Q022_AUTHORITY,Q022_AUTHORITY_SHA),p=heldQ018Bytes(path.join(repo,Q022_PROPOSAL));
  return a.decision_id==='AIPT-MVP-B007-OWNER-Q022'&&a.state==='OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI'&&a.owner_instruction==='批准'
   &&equal(a.current_work_paths,Q022_WORK_PATHS)&&equal(a.new_exact_public_paths,Q022_NEW_PATHS)
   &&a.approved_private_contract.sha256==='cff90e12144c8ebb9a23ecd88f82caccc23ecfe8ae0599e16ff6cf581c897022'
   &&a.actual_Owner_approval_registration.sha256==='ba1650edda1a4ee7100518b5641bdf05faa498c232682c158e46aefbe200ac77'
   &&a.proposal_binding.path===Q022_PROPOSAL&&a.proposal_binding.sha256===Q022_PROPOSAL_SHA&&p.sha256===Q022_PROPOSAL_SHA&&p.bytes===a.proposal_binding.bytes
   &&a.baseline.commit===Q022_BASELINE&&a.baseline.tree===Q022_BASELINE_TREE&&equal(a.baseline.parents,[BASE])
   &&a.retained_Q021_authority_sha256===Q021_AUTHORITY_SHA&&a.retained_Q021_proposal_sha256===Q021_PROPOSAL_SHA
   &&a.combined_source_count===654&&a.protected_current_paths===646&&a.local_required1_positive_mandatory
   &&a.public_optional_namespace_skip_is_not_positive_evidence&&a.separate_final_Owner_merge_approval_required
   &&!a.generic_followon_permission&&!a.production_namespace_changes_authorized&&!a.SDK_copy_write_chmod_registry_retirement_authorized
   &&!a.new_DIAG_or_extra_budget_authorized&&!a.runtime_ready&&!a.paid_callable&&a.qualification_runs_authorized===0;
 }catch{return false;}
}
function q022Proposal(repo) {
 if(!q022Approved(repo))throw new Error('Q021/Q022 exact paired approved Owner authority/proposal absent or changed');
 const q=json(repo,Q022_PROPOSAL,Q022_PROPOSAL_SHA);
 if(q.baseline652.length!==652||q.protected646.length!==646||!equal(q.work_paths,Q022_WORK_PATHS)||!equal(q.new_paths,Q022_NEW_PATHS))throw new Error('Q021/Q022 exact652/646/6+2 scope invalid');
 return q;
}
export function q022SourceProblems(repo) {
 if(q023Present(repo))return q023SourceProblems(repo);
 const p=currentQualificationProblems(repo);
 try {
  const q=q022Proposal(repo),expected=[...q.protected646.map(v=>v.relative),...Q022_WORK_PATHS,...Q022_NEW_PATHS].sort();
  if(new Set(expected).size!==654)throw new Error('Q021/Q022 duplicate or incomplete exact654 source');
  const observed=git(repo,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean).sort();
  if(!equal([...new Set(observed)],expected))p.push('Q021/Q022 exact650-to654 working source set changed');
  for(const f of q.protected646){const v=heldQ018Bytes(path.join(repo,f.relative));if(v.bytes!==f.bytes||v.sha256!==f.sha256||v.executable!==(f.git_mode==='100755'))p.push('Q021/Q022 protected exact650 origin changed: '+f.relative);}
  for(const file of [...Q022_WORK_PATHS,...Q022_NEW_PATHS]){const v=heldQ018Bytes(path.join(repo,file));if(v.executable)p.push('Q021/Q022 current work execution mode changed: '+file);}
  for(const f of q.current_fixed_sources){const v=heldQ018Bytes(path.join(repo,f.relative));if(v.bytes!==f.bytes||v.sha256!==f.sha256||v.executable)p.push('Q021/Q022 exact current fixed source changed: '+f.relative);}
 }catch(e){p.push('Q021/Q022 source contract fails closed: '+e.message);}
 return p;
}
// Read every Git blob. An original-history selector accepts only the fixed PR30 commit.
export function q022RevisionProblems(repo,revision,{original=false}={}) {
 if(!original&&q023Present(repo))return q023RevisionProblems(repo,revision);
 const p=[];
 try {
  const q=q022Proposal(repo),resolved=git(repo,['rev-parse',revision+'^{commit}']);
  if(original&&resolved!==Q022_BASELINE)throw new Error('Q021/Q022 original history must be the fixed PR30 commit');
  const old=resolved===Q022_BASELINE,expected=old?q.baseline652:q.protected646;
  if(old&&git(repo,['show','--no-show-signature','-s','--format=%H%n%T%n%P',resolved])!==[Q022_BASELINE,Q022_BASELINE_TREE,BASE].join('\n'))throw new Error('Q021/Q022 original PR30 SHA/tree/soleBASE parent changed');
  const tree=git(repo,['ls-tree','-rz','--full-tree',resolved]).split('\0').filter(Boolean).map(line=>{
   const [header,relative]=line.split('\t'),[mode,type,oid]=header.split(' ');
   if(type!=='blob'||!['100644','100755'].includes(mode)||!relative)throw new Error('Q021/Q022 nonregular Git source');
   return {relative,mode,oid};
  });
  const paths=(old?q.baseline652.map(v=>v.relative):[...q.protected646.map(v=>v.relative),...Q022_WORK_PATHS,...Q022_NEW_PATHS]).sort();
  if(tree.length!==paths.length||new Set(paths).size!==paths.length||!equal(tree.map(v=>v.relative).sort(),paths))throw new Error('Q021/Q022 exact committed652/654 source set changed');
  const child=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,'cat-file','--batch'],{input:tree.map(v=>v.oid+'\n').join(''),maxBuffer:64*1024*1024,env:{PATH:'/usr/bin:/bin',GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
  if(child.error||child.signal||child.status!==0)throw new Error('Q021/Q022 complete Git blob read failed');
  let offset=0;const actual=new Map();
  for(const f of tree){
   const end=child.stdout.indexOf(10,offset);if(end<0)throw new Error('short Q022 Git header');
   const [oid,type,sizeText]=child.stdout.subarray(offset,end).toString().split(' '),size=Number(sizeText);offset=end+1;
   if(type!=='blob'||oid!==f.oid||!Number.isSafeInteger(size)||size<0||offset+size>=child.stdout.length)throw new Error('invalid Q022 Git blob');
   const raw=child.stdout.subarray(offset,offset+size);offset+=size;
   if(child.stdout[offset++]!==10||createHash('sha1').update('blob '+size+'\0').update(raw).digest('hex')!==oid)throw new Error('Q022 Git object identity mismatch');
   actual.set(f.relative,{bytes:size,sha256:hash(raw),git_mode:f.mode,git_blob_oid:oid});
  }
  if(offset!==child.stdout.length)throw new Error('additional Q022 Git output');
  for(const f of expected){if(!equal(actual.get(f.relative),{bytes:f.bytes,sha256:f.sha256,git_mode:f.git_mode,git_blob_oid:f.git_blob_oid}))p.push('Q021/Q022 protected exact650 Git origin changed: '+f.relative);}
  if(!old){
   for(const f of q.current_fixed_sources){const v=actual.get(f.relative);if(v?.bytes!==f.bytes||v.sha256!==f.sha256||v.git_mode!=='100644')p.push('Q021/Q022 committed fixed current source changed: '+f.relative);}
   for(const file of Q022_WORK_PATHS)if(actual.get(file)?.git_mode!=='100644')p.push('Q021/Q022 committed work mode changed: '+file);
   for(const [file,digest]of [[Q022_AUTHORITY,Q022_AUTHORITY_SHA],[Q022_PROPOSAL,Q022_PROPOSAL_SHA]])if(actual.get(file)?.sha256!==digest||actual.get(file)?.git_mode!=='100644')p.push('Q021/Q022 committed Owner record changed: '+file);
  }
 }catch(e){p.push('Q021/Q022 full source revision fails closed: '+e.message);}
 return p;
}
function q022CloneState(repo) {
 const q=q022Proposal(repo),paths=[...q.protected646.map(v=>v.relative),...Q022_WORK_PATHS,...Q022_NEW_PATHS].sort();
 const identity=p=>{const v=heldQ018Bytes(p);return {bytes:v.bytes,sha256:v.sha256,executable:v.executable};};
 return {head:git(repo,['rev-parse','HEAD']),tree:git(repo,['rev-parse','HEAD^{tree}']),main:git(repo,['rev-parse','refs/remotes/origin/main']),index:identity(git(repo,['rev-parse','--path-format=absolute','--git-path','index'])),source:paths.map(relative=>({relative,...identity(path.join(repo,relative))}))};
}
function q022CloneRef(repo) {
 const probe=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,'symbolic-ref','-q','refs/heads/codex/q022-fixed-history-pr30'],{encoding:'utf8',env:{PATH:'/usr/bin:/bin',GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(probe.error||probe.signal||![0,1].includes(probe.status))throw new Error('Q022 fixed ref symbolic probe failed');
 if(probe.status===0)throw new Error('Q022 fixed local clone ref is symbolic, including a dangling target');
 return q021CloneRef(repo,Q022_HISTORY_REF);
}
export function prepareQ022FixedCloneOrigin(repo) {
 if(arguments.length!==1)throw new Error('Q022 fixed clone origin accepts no caller targets or options');
 const problems=[...q022SourceProblems(repo),...q022RevisionProblems(repo,Q022_BASELINE,{original:true})];
 if(problems.length)throw new Error('Q021/Q022 fixed clone origin prerequisites failed: '+problems.join('; '));
 const before=q022CloneState(repo),existing=q022CloneRef(repo);
 if(existing!==null&&existing!==Q022_BASELINE)throw new Error('Q022 existing fixed local clone ref differs; overwrite forbidden');
 // Original Q021 preparation and its three fixed references stay unchanged.
 prepareQ021FixedCloneOrigins(repo);
 run('/usr/bin/git',['--no-optional-locks','-C',repo,'update-ref','--no-deref','--stdin'],{input:'start\n'+(existing===null?'create ':'verify ')+Q022_HISTORY_REF+' '+Q022_BASELINE+'\nprepare\ncommit\n',env:{...process.env,GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(!equal(before,q022CloneState(repo)))throw new Error('Q022 source/HEAD/tree/index/origin-main changed during fixed clone preparation');
 const after=[...q022SourceProblems(repo),...q022RevisionProblems(repo,Q022_BASELINE,{original:true})];
 if(after.length||q022CloneRef(repo)!==Q022_BASELINE)throw new Error('Q022 fixed clone origin postcheck failed: '+after.join('; '));
 return {result:'PASS_Q022_FIXED_PR30_LOCAL_CLONE_ORIGIN_PREPARED',fixed_ref:Q022_HISTORY_REF,commit:Q022_BASELINE,tree:Q022_BASELINE_TREE,source_HEAD_tree_index_origin_main_unchanged:true,SDK_program_or_mutation:0,network_requests:0,model_DIAG_QUAL:0,full_HIGH_or_CI_or_runtime_accepted:false};
}
// Original test cases keep their652 assumptions at the fully verified fixed
// PR30 snapshot. Appended Q022 cases explicitly use the separate live654 root.
const q022OriginalTestSources=new Map();
export function q022OriginalTestSource(repo) {
 if(arguments.length!==1)throw new Error('Q022 original test source accepts no caller targets');
 if(!q022Present(repo))return repo;
 if(q022OriginalTestSources.has(repo))return q022OriginalTestSources.get(repo);
 prepareQ022FixedCloneOrigin(repo);
 const target=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q022-original-pr30-tests-'));
 try {
  run('/usr/bin/git',['clone','--no-local','--no-checkout',repo,target]);
  git(target,['checkout','--detach',Q022_BASELINE]);git(target,['update-ref','refs/remotes/origin/main',BASE]);
  if(git(target,['status','--porcelain=v1','--untracked-files=all'])!=='')throw new Error('Q022 original test snapshot is not clean');
  const q=q022Proposal(repo);
  for(const f of q.baseline652){const v=heldQ018Bytes(path.join(target,f.relative));if(v.bytes!==f.bytes||v.sha256!==f.sha256||v.executable!==(f.git_mode==='100755'))throw new Error('Q022 original test physical source changed: '+f.relative);}
  if(git(target,['rev-parse','HEAD^{tree}'])!==Q022_BASELINE_TREE||git(target,['ls-files','-z']).split('\0').filter(Boolean).length!==652)throw new Error('Q022 original test tree/source count changed');
  prepareQ021FixedCloneOrigins(target);
  q022OriginalTestSources.set(repo,target);return target;
 }catch(e){fs.rmSync(target,{recursive:true,force:true});throw e;}
}
export function cleanupQ022OriginalTestSources() {
 for(const target of q022OriginalTestSources.values()){
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){bytes+=s.size;files++;}else throw new Error('unexpected owned Q022 snapshot artifact');};
  walk(target);fs.rmSync(target,{recursive:true,force:true});if(fs.existsSync(target))throw new Error('owned Q022 test snapshot not retired');
  console.log(JSON.stringify({owned_scratch:target,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0}));
 }
 q022OriginalTestSources.clear();
}

// Owner Q023 fixes the definition context; it grants no generic route or source.
export const Q023_AUTHORITY='docs/pilot/authorities/fixed-p1-definition-context-successor-q023.json';
export const Q023_PROPOSAL='docs/pilot/proposals/fixed-p1-definition-context-q023.json';
export const Q023_AUTHORITY_SHA='96c5bb8c3b7e911ba7e71711ec112b7298221df87c05e41cdfe97d6d80c934e1';
export const Q023_PROPOSAL_SHA='0deb8a23deec0c829f99eef55cde53bd198456ff18d61c236651f4da7995abb9';
export const Q023_WORKFLOW_SHA='5c0f81fa51bc51b494f8cb768a080262f64d4b3eed0e0c3c3ba8eddc3f56b4ef';
export const Q023_BASELINE='0e1f2670bc866b5076cd8e3478398c9d9042e6b3';
export const Q023_BASELINE_TREE='d212ca68dfa826c430a8f7e851d8382666ccd3cb';
export const Q023_WORK_PATHS=Object.freeze(['.github/workflows/ci.yml','scripts/ci/lib/b007-toolchain-security-q018.mjs','scripts/ci/test/b007-toolchain-security-q018.test.mjs','scripts/ci/lib/b007-successor.mjs','scripts/ci/test/b007-lifecycle.test.mjs']);
export const Q023_NEW_PATHS=Object.freeze([Q023_AUTHORITY,Q023_PROPOSAL]);
const Q023_HISTORY_REF='refs/heads/codex/q023-fixed-history-pr31';
const Q023_DEFINITION='8d6a438d051fb635e769285215e70536958a8f42';
const Q023_DEFINITION_TREE='9ef6f121bd0d9a6484d7cc39a22450250e9ac489';
const Q023_TARGET='169f9bd006dabb88eb653ab09a33b0eef5eadaed';
const Q023_TARGET_TREE='9cf551e7bc70d4354ca21d62a2bd456ed6f401bb';
export function q023Present(repo) {
 return Q023_NEW_PATHS.some(file=>{try{fs.lstatSync(path.join(repo,file));return true;}catch(e){return e.code!=='ENOENT';}});
}
export function q023Approved(repo) {
 try {
  if(!q022Approved(repo))return false;
  const a=json(repo,Q023_AUTHORITY,Q023_AUTHORITY_SHA),p=heldQ018Bytes(path.join(repo,Q023_PROPOSAL));
  return a.decision_id==='AIPT-MVP-B007-OWNER-Q023'&&a.state==='OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI'&&a.owner_instruction==='批准'
   &&equal(a.current_work_paths,Q023_WORK_PATHS)&&equal(a.new_exact_public_paths,Q023_NEW_PATHS)
   &&a.approved_private_contract.sha256==='9a59c7a2e9b0218b2ea7fe0d8ac547a3e88f30a86b127b6a886e56770c8defa1'
   &&a.actual_Owner_approval_registration.sha256==='4696ed1e9613ef7053e06f2e23dc97b9618b00e6f8f6e8dc0c9a23d7090aa3fd'
   &&a.proposal_binding.path===Q023_PROPOSAL&&a.proposal_binding.sha256===Q023_PROPOSAL_SHA&&p.sha256===Q023_PROPOSAL_SHA&&p.bytes===a.proposal_binding.bytes
   &&a.baseline.commit===Q023_BASELINE&&a.baseline.tree===Q023_BASELINE_TREE&&equal(a.baseline.parents,[BASE])
   &&a.retained_Q022_authority_sha256===Q022_AUTHORITY_SHA&&a.retained_Q022_proposal_sha256===Q022_PROPOSAL_SHA
   &&a.combined_source_count===656&&a.protected_current_paths===649&&a.local_required1_positive_mandatory
   &&a.public_optional_namespace_skip_is_not_positive_evidence&&a.separate_final_Owner_merge_approval_required
   &&a.SDK_execution_interval_source_stability_owner_accepted&&a.cannot_guarantee_same_UID_instant_replace_restore_detection
   &&!a.generic_followon_permission&&!a.SDK_copy_write_chmod_registry_retirement_authorized
   &&!a.new_DIAG_or_extra_budget_authorized&&!a.runtime_ready&&!a.paid_callable&&a.qualification_runs_authorized===0;
 }catch{return false;}
}
export function q023Proposal(repo) {
 if(!q023Approved(repo))throw new Error('Q023 exact paired approved Owner authority/proposal absent or changed');
 const q=json(repo,Q023_PROPOSAL,Q023_PROPOSAL_SHA);
 if(q.baseline654.length!==654||q.protected649.length!==649||!equal(q.work_paths,Q023_WORK_PATHS)||!equal(q.new_paths,Q023_NEW_PATHS))throw new Error('Q023 exact654/649/5+2 scope invalid');
 return q;
}
// Full streams are checked against each Git object's actual identity.
function q023CommittedSource(repo,revision) {
 const resolved=git(repo,['rev-parse',revision+'^{commit}']);
 const tree=git(repo,['ls-tree','-rz','--full-tree',resolved]).split('\0').filter(Boolean).map(line=>{
  const [header,relative]=line.split('\t'),[mode,type,oid]=header.split(' ');
  if(type!=='blob'||!['100644','100755'].includes(mode)||!relative)throw new Error('Q023 nonregular Git source');
  return {relative,mode,oid};
 });
 const child=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,'cat-file','--batch'],{input:tree.map(v=>v.oid+'\n').join(''),maxBuffer:64*1024*1024,env:{PATH:'/usr/bin:/bin',GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(child.error||child.signal||child.status!==0)throw new Error('Q023 complete Git blob read failed');
 let offset=0;const actual=new Map();
 for(const f of tree){
  const end=child.stdout.indexOf(10,offset);if(end<0)throw new Error('short Q023 Git header');
  const [oid,type,sizeText]=child.stdout.subarray(offset,end).toString().split(' '),size=Number(sizeText);offset=end+1;
  if(type!=='blob'||oid!==f.oid||!Number.isSafeInteger(size)||size<0||offset+size>=child.stdout.length)throw new Error('invalid Q023 Git blob');
  const raw=child.stdout.subarray(offset,offset+size);offset+=size;
  if(child.stdout[offset++]!==10||createHash('sha1').update('blob '+size+'\0').update(raw).digest('hex')!==oid)throw new Error('Q023 Git object identity mismatch');
  actual.set(f.relative,{bytes:size,sha256:hash(raw),git_mode:f.mode,git_blob_oid:oid});
 }
 if(offset!==child.stdout.length||actual.size!==tree.length)throw new Error('additional or duplicate Q023 Git output');
 return actual;
}
export function q023RevisionProblems(repo,revision,{original=false}={}) {
 if(!original&&q024Present(repo))return q024RevisionProblems(repo,revision);
 const p=[];
 try {
  const q=q023Proposal(repo),resolved=git(repo,['rev-parse',revision+'^{commit}']);
  if(original&&resolved!==Q023_BASELINE)throw new Error('Q023 original history must be the fixed failed PR31 commit');
  const old=resolved===Q023_BASELINE;
  if(old&&git(repo,['show','--no-show-signature','-s','--format=%H%n%T%n%P',resolved])!==[Q023_BASELINE,Q023_BASELINE_TREE,BASE].join('\n'))throw new Error('Q023 original PR31 SHA/tree/soleBASE parent changed');
  const actual=q023CommittedSource(repo,resolved);
  const expected=old?q.baseline654:q.protected649;
  const paths=(old?q.baseline654.map(v=>v.relative):[...q.protected649.map(v=>v.relative),...Q023_WORK_PATHS,...Q023_NEW_PATHS]).sort();
  if(actual.size!==paths.length||new Set(paths).size!==paths.length||!equal([...actual.keys()].sort(),paths))throw new Error('Q023 exact committed654/656 source set changed');
  for(const f of expected)if(!equal(actual.get(f.relative),{bytes:f.bytes,sha256:f.sha256,git_mode:f.git_mode,git_blob_oid:f.git_blob_oid}))p.push('Q023 protected exact654 Git origin changed: '+f.relative);
  if(!old){
   for(const file of [...Q023_WORK_PATHS,...Q023_NEW_PATHS])if(actual.get(file)?.git_mode!=='100644')p.push('Q023 committed work or Owner mode changed: '+file);
   for(const [file,digest]of [[Q023_AUTHORITY,Q023_AUTHORITY_SHA],[Q023_PROPOSAL,Q023_PROPOSAL_SHA],['.github/workflows/ci.yml',Q023_WORKFLOW_SHA]])if(actual.get(file)?.sha256!==digest)p.push('Q023 committed exact Owner or workflow changed: '+file);
  }
 }catch(e){p.push('Q023 full source revision fails closed: '+e.message);}
 return p;
}
function q023Facts(repo,revision) {
 const parts=git(repo,['show','--no-show-signature','-s','--format=%H%n%T%n%P',revision]).split('\n');
 return {commit:parts[0],tree:parts[1],parents:parts[2]?parts[2].split(' '):[]};
}
function q023FixedDefinitionProblems(repo) {
 const p=[];
 try {
  const q=q023Proposal(repo),r=q.new_fixed_P1_route;
  if(git(repo,['show','--no-show-signature','-s','--format=%H%n%T%n%P',Q023_DEFINITION])!==[Q023_DEFINITION,Q023_DEFINITION_TREE,'bdace30f311bfa953846569e06a892a2ed59acd3'].join('\n'))throw new Error('Q023 fixed definition SHA/tree/parent changed');
  if(git(repo,['show','--no-show-signature','-s','--format=%H%n%T%n%P',Q023_TARGET])!==[Q023_TARGET,Q023_TARGET_TREE,'eede815e818d87362605f55d5bfd2a0460e6e130 c9f7729f666d11716c04d7682da16044ca965236'].join('\n'))throw new Error('Q023 original target SHA/tree/parents changed');
  const definition=q023CommittedSource(repo,Q023_DEFINITION),target=q023CommittedSource(repo,Q023_TARGET);
  if(definition.size!==251||r.fixed_definition251.length!==251||target.size!==232||!equal([...definition.keys()].sort(),r.fixed_definition251.map(v=>v.relative).sort()))throw new Error('Q023 complete fixed definition251/target232 changed');
  for(const f of r.fixed_definition251)if(!equal(definition.get(f.relative),{bytes:f.bytes,sha256:f.sha256,git_mode:f.git_mode,git_blob_oid:f.git_blob_oid}))p.push('Q023 fixed definition Git source changed: '+f.relative);
 }catch(e){p.push('Q023 fixed P1 definition fails closed: '+e.message);}
 return p;
}
// A fixed failed PR31 can host construction only while main stays BASE.
// Every accepted candidate/merge and all later history preserve all656 files.
export function q023LifecycleProblems(repo) {
 if(q024Present(repo))return q024LifecycleProblems(repo);
 const p=[];
 try {
  p.push(...q023RevisionProblems(repo,Q023_BASELINE,{original:true}),...q023FixedDefinitionProblems(repo));
  const head=git(repo,['rev-parse','HEAD^{commit}']),main=git(repo,['rev-parse','refs/remotes/origin/main^{commit}']);
  if(git(repo,['rev-parse',BASE+'^{tree}'])!=='d91062ddb99d781a825e272a6365ed4effe97350')throw new Error('Q023 accepted BASE tree changed');
  const contains=(revision,ancestor)=>git(repo,['rev-list','--first-parent',revision]).split('\n').includes(ancestor);
  const topology=revision=>{
   if(revision===BASE)return null;
   if(!contains(revision,BASE))throw new Error('Q023 checkout/main lacks first-parent BASE');
   const f=q023Facts(repo,revision);
   if(equal(f.parents,[BASE]))return {candidate:f,merge:null};
   const merges=git(repo,['rev-list','--first-parent',BASE+'..'+revision]).split('\n').filter(Boolean).map(id=>q023Facts(repo,id)).filter(m=>m.parents.length===2&&m.parents[0]===BASE&&equal(q023Facts(repo,m.parents[1]).parents,[BASE])&&m.tree===q023Facts(repo,m.parents[1]).tree);
   if(merges.length!==1)throw new Error('Q023 no unique identical-tree Candidate/Base merge');
   return {candidate:q023Facts(repo,merges[0].parents[1]),merge:merges[0]};
  };
  const h=topology(head),m=topology(main);
  if(main!==BASE&&!m?.merge)throw new Error('Q023 accepted main is not exact BASE or identical-tree merge');
  if(h&&m&&h.candidate.commit!==m.candidate.commit)throw new Error('Q023 checkout/main Candidate disagreement');
  const selected=h??m;
  if(!selected)return p;
  if(selected.candidate.commit===Q023_BASELINE){
   if(head!==Q023_BASELINE||main!==BASE||selected.merge)throw new Error('Q023 failed PR31 cannot authorize accepted main or merge');
   return p;
  }
  p.push(...q023RevisionProblems(repo,selected.candidate.commit));
  const candidate=q023CommittedSource(repo,selected.candidate.commit);
  for(const [file,want]of candidate){
   const actual=heldQ018Bytes(path.join(repo,file));
   if(actual.bytes!==want.bytes||actual.sha256!==want.sha256||actual.executable!==(want.git_mode==='100755'))p.push('Q023 working656 differs from exact Candidate: '+file);
  }
  for(const revision of new Set([head,main])){
   if(revision===BASE)continue;
   p.push(...q023RevisionProblems(repo,revision));
   const current=revision===head?h:m;const since=current.merge?.commit??current.candidate.commit;
   const touched=git(repo,['log','--first-parent','--full-history','--format=','--name-only',since+'..'+revision]).split('\n').filter(Boolean);
   if(touched.length)p.push('Q023 full656 source history changed after exact Candidate/merge: '+[...new Set(touched)].join(', '));
  }
 }catch(e){p.push('Q023 complete lifecycle fails closed: '+e.message);}
 return p;
}
export function q023SourceProblems(repo) {
 if(q032Present(repo))return q032SourceProblems(repo);
 if(q028Present(repo))return q028SourceProblems(repo);
 if(q027Present(repo))return q027SourceProblems(repo);
 if(q026Present(repo))return q026SourceProblems(repo);
 if(q025Present(repo))return q025SourceProblems(repo);
 if(q024Present(repo))return q024SourceProblems(repo);
 const p=currentQualificationProblems(repo);
 try {
  const q=q023Proposal(repo),expected=[...q.protected649.map(v=>v.relative),...Q023_WORK_PATHS,...Q023_NEW_PATHS].sort();
  if(new Set(expected).size!==656)throw new Error('Q023 duplicate or incomplete exact656 source');
  const observed=git(repo,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);
  if(!equal([...new Set(observed)].sort(),expected))p.push('Q023 exact654-to656 working source set changed');
  for(const f of q.protected649){const actual=heldQ018Bytes(path.join(repo,f.relative));if(actual.bytes!==f.bytes||actual.sha256!==f.sha256||actual.executable!==(f.git_mode==='100755'))p.push('Q023 protected exact654 origin changed: '+f.relative);}
  for(const file of [...Q023_WORK_PATHS,...Q023_NEW_PATHS])if(heldQ018Bytes(path.join(repo,file)).executable)p.push('Q023 current work or Owner execution mode changed: '+file);
  if(heldQ018Bytes(path.join(repo,'.github/workflows/ci.yml')).sha256!==Q023_WORKFLOW_SHA)p.push('Q023 exact fixed P1 workflow changed');
  p.push(...q023LifecycleProblems(repo));
 }catch(e){p.push('Q023 source contract fails closed: '+e.message);}
 return [...new Set(p)];
}
function q023CloneState(repo) {
 const q=q023Proposal(repo),identity=file=>{const v=heldQ018Bytes(file);return {bytes:v.bytes,sha256:v.sha256,executable:v.executable};};
 const paths=[...q.protected649.map(v=>v.relative),...Q023_WORK_PATHS,...Q023_NEW_PATHS].sort();
 return {head:git(repo,['rev-parse','HEAD']),tree:git(repo,['rev-parse','HEAD^{tree}']),main:git(repo,['rev-parse','refs/remotes/origin/main']),index:identity(git(repo,['rev-parse','--path-format=absolute','--git-path','index'])),source:paths.map(relative=>({relative,...identity(path.join(repo,relative))}))};
}
function q023CloneRef(repo) {
 const probe=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,'symbolic-ref','-q',Q023_HISTORY_REF],{encoding:'utf8',env:{PATH:'/usr/bin:/bin',GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(probe.error||probe.signal||![0,1].includes(probe.status))throw new Error('Q023 fixed ref symbolic probe failed');
 if(probe.status===0)throw new Error('Q023 fixed local clone ref is symbolic, including a dangling target');
 return q021CloneRef(repo,Q023_HISTORY_REF);
}
export function prepareQ023FixedCloneOrigin(repo) {
 if(arguments.length!==1)throw new Error('Q023 fixed clone origin accepts no caller targets or options');
 const p=q023SourceProblems(repo);if(p.length)throw new Error('Q023 fixed clone origin prerequisites failed: '+p.join('; '));
 const before=q023CloneState(repo),existing=q023CloneRef(repo);
 if(existing!==null&&existing!==Q023_BASELINE)throw new Error('Q023 existing fixed local clone ref differs; overwrite forbidden');
 prepareQ022FixedCloneOrigin(repo);
 run('/usr/bin/git',['--no-optional-locks','-C',repo,'update-ref','--no-deref','--stdin'],{input:'start\n'+(existing===null?'create ':'verify ')+Q023_HISTORY_REF+' '+Q023_BASELINE+'\nprepare\ncommit\n',env:{...process.env,GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(!equal(before,q023CloneState(repo)))throw new Error('Q023 source/HEAD/tree/index/origin-main changed during fixed clone preparation');
 const after=q023SourceProblems(repo);if(after.length||q023CloneRef(repo)!==Q023_BASELINE)throw new Error('Q023 fixed clone origin postcheck failed: '+after.join('; '));
 return {result:'PASS_Q023_FIXED_PR31_LOCAL_CLONE_ORIGIN_PREPARED',fixed_ref:Q023_HISTORY_REF,commit:Q023_BASELINE,tree:Q023_BASELINE_TREE,source_HEAD_tree_index_origin_main_unchanged:true,SDK_program_or_mutation:0,network_requests:0,model_DIAG_QUAL:0,full_HIGH_or_CI_or_runtime_accepted:false};
}
const q023OriginalTestSources=new Map();
export function q023OriginalTestSource(repo) {
 if(arguments.length!==1)throw new Error('Q023 original test source accepts no caller targets');
 if(!q023Present(repo))return repo;
 if(q023OriginalTestSources.has(repo))return q023OriginalTestSources.get(repo);
 prepareQ023FixedCloneOrigin(repo);
 const target=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q023-original-pr31-tests-'));
 try {
  run('/usr/bin/git',['clone','--no-local','--no-checkout',repo,target]);
  git(target,['checkout','--detach',Q023_BASELINE]);git(target,['update-ref','refs/remotes/origin/main',BASE]);
  const q=q023Proposal(repo);
  if(git(target,['status','--porcelain=v1','--untracked-files=all'])!==''||git(target,['rev-parse','HEAD^{tree}'])!==Q023_BASELINE_TREE)throw new Error('Q023 original test654 identity/cleanliness changed');
  for(const f of q.baseline654){const v=heldQ018Bytes(path.join(target,f.relative));if(v.bytes!==f.bytes||v.sha256!==f.sha256||v.executable!==(f.git_mode==='100755'))throw new Error('Q023 original test654 physical source changed: '+f.relative);}
  if(git(target,['ls-files','-z']).split('\0').filter(Boolean).length!==654)throw new Error('Q023 original test654 source count changed');
  prepareQ022FixedCloneOrigin(target);
  q023OriginalTestSources.set(repo,target);return target;
 }catch(e){fs.rmSync(target,{recursive:true,force:true});throw e;}
}
export function cleanupQ023OriginalTestSources() {
 for(const target of q023OriginalTestSources.values()){
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const n of fs.readdirSync(p))walk(path.join(p,n));}else if(s.isFile()){bytes+=s.size;files++;}else throw new Error('unexpected owned Q023 test snapshot artifact');};
  walk(target);fs.rmSync(target,{recursive:true,force:true});if(fs.existsSync(target))throw new Error('owned Q023 test snapshot not retired');
  console.log(JSON.stringify({owned_scratch:target,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0}));
 }
 q023OriginalTestSources.clear();
}

// Owner Q024: one exact test fixture and one child of the preserved failed merge.
export const Q024_AUTHORITY='docs/pilot/authorities/nonleader-thread-fixture-successor-q024.json';
export const Q024_PROPOSAL='docs/pilot/proposals/nonleader-thread-fixture-q024.json';
export const Q024_AUTHORITY_SHA='6ec03075ad38de04906f70c9fd96c2b5fdcd46fc9b37ffd305fb4a55b7d81168';
export const Q024_PROPOSAL_SHA='687b901f714d86efb04ef7eb9afabbf1749c55fd98e85d7e8cddd0c2797e9ac8';
export const Q024_BASELINE='19a928d1c03715ecc99d04e9a43bc6a337ad1426';
export const Q024_ORIGINAL_CANDIDATE='834f1830315a0eb025e62745435cc36b672a668e';
export const Q024_BASELINE_TREE='a759945b4a705d535f7e9da7b41132edada2b5a0';
export const Q024_TEST='internal/pilot/memory_lifecycle_test.go';
export const Q024_TEST_SHA='712fa0c55ed3e4753fbe9fbc4ae032309d8be4ac55a66428d82f9fbaf67983fd';
export const Q024_WORK_PATHS=Object.freeze([Q024_TEST,'scripts/ci/lib/b007-toolchain-security-q018.mjs','scripts/ci/test/b007-toolchain-security-q018.test.mjs','scripts/ci/lib/b007-successor.mjs','scripts/ci/test/b007-lifecycle.test.mjs']);
export const Q024_NEW_PATHS=Object.freeze([Q024_AUTHORITY,Q024_PROPOSAL]);
const Q024_HISTORY_REF='refs/heads/codex/q024-fixed-history-pr32-candidate';
export function q024Present(repo) {
 return Q024_NEW_PATHS.some(file=>{try{fs.lstatSync(path.join(repo,file));return true;}catch(e){return e.code!=='ENOENT';}});
}
export function q024Approved(repo) {
 try {
  if(!q023Approved(repo))return false;
  const a=json(repo,Q024_AUTHORITY,Q024_AUTHORITY_SHA),p=heldQ018Bytes(path.join(repo,Q024_PROPOSAL));
  return a.decision_id==='AIPT-MVP-B007-OWNER-Q024'&&a.state==='OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI'&&a.owner_instruction==='批准'
   &&equal(a.current_work_paths,Q024_WORK_PATHS)&&equal(a.new_exact_public_paths,Q024_NEW_PATHS)
   &&a.approved_private_contract.sha256==='c39608568ecd2efd1b4a939eb9e950d2d7da42288eaae502f575ba1499fe466a'
   &&a.actual_Owner_approval_registration.sha256==='685cf92bad6cd2a1e8074e4493d64dea2c2fa009a6edc408f3e049e199fd555d'
   &&a.approved_material.sha256==='348ab4b31877cdc9d51005782e9e3b35752c43d8d09bd354fab94c43e965f173'
   &&a.proposal_binding.path===Q024_PROPOSAL&&a.proposal_binding.sha256===Q024_PROPOSAL_SHA&&p.sha256===Q024_PROPOSAL_SHA&&p.bytes===a.proposal_binding.bytes
   &&a.baseline.merge_commit===Q024_BASELINE&&a.baseline.merge_tree===Q024_BASELINE_TREE&&equal(a.baseline.merge_parents,[BASE,Q024_ORIGINAL_CANDIDATE])
   &&a.baseline.candidate_commit===Q024_ORIGINAL_CANDIDATE&&a.baseline.candidate_tree===Q024_BASELINE_TREE&&equal(a.baseline.candidate_parents,[BASE])
   &&a.baseline.merge_CI_jobs_PASS===4&&a.baseline.merge_CI_jobs_FAIL===1&&a.baseline.merge_CI_accepted===false
   &&a.retained_Q023_authority_sha256===Q023_AUTHORITY_SHA&&a.retained_Q023_proposal_sha256===Q023_PROPOSAL_SHA
   &&a.frozen_workflow_sha256===Q023_WORKFLOW_SHA&&a.test_binding.bytes===10670&&a.test_binding.sha256===Q024_TEST_SHA
   &&a.combined_source_count===658&&a.protected_current_paths===651&&a.local_required1_positive_mandatory&&a.public_optional_namespace_skip_is_not_positive_evidence
   &&a.same_independent_agent_and_Root_full658_HIGH_and_exact_CI_each5_required&&a.separate_final_Owner_merge_approval_required
   &&a.SDK_execution_interval_source_stability_owner_accepted&&a.cannot_guarantee_same_UID_instant_replace_restore_detection
   &&!a.generic_followon_permission&&!a.SDK_copy_write_chmod_registry_retirement_authorized&&!a.production_runtime_changes_authorized
   &&!a.new_DIAG_or_extra_budget_authorized&&!a.runtime_ready&&!a.paid_callable&&a.qualification_runs_authorized===0;
 }catch{return false;}
}
export function q024Proposal(repo) {
 if(!q024Approved(repo))throw new Error('Q024 exact paired approved Owner authority/proposal absent or changed');
 const q=json(repo,Q024_PROPOSAL,Q024_PROPOSAL_SHA);
 if(q.baseline656.length!==656||q.protected651.length!==651||!equal(q.work_paths,Q024_WORK_PATHS)||!equal(q.new_paths,Q024_NEW_PATHS)
  ||!equal(q.protected651,q.baseline656.filter(v=>!Q024_WORK_PATHS.includes(v.relative))))throw new Error('Q024 exact656/651/5+2 scope invalid');
 return q;
}
export function q024RevisionProblems(repo,revision,{original=false}={}) {
 const p=[];
 try {
  const q=q024Proposal(repo),resolved=git(repo,['rev-parse',revision+'^{commit}']);
  const old=[Q024_BASELINE,Q024_ORIGINAL_CANDIDATE].includes(resolved);
  if(original&&!old)throw new Error('Q024 original source must be exact PR32 candidate or failed merge');
  if(old){
   const parents=resolved===Q024_BASELINE?[BASE,Q024_ORIGINAL_CANDIDATE]:[BASE];
   if(!equal(q023Facts(repo,resolved),{commit:resolved,tree:Q024_BASELINE_TREE,parents}))throw new Error('Q024 fixed original SHA/tree/ordered parents changed');
  }
  const actual=q023CommittedSource(repo,resolved),expected=old?q.baseline656:q.protected651;
  const paths=(old?q.baseline656.map(v=>v.relative):[...q.protected651.map(v=>v.relative),...Q024_WORK_PATHS,...Q024_NEW_PATHS]).sort();
  if(actual.size!==paths.length||new Set(paths).size!==paths.length||!equal([...actual.keys()].sort(),paths))throw new Error('Q024 exact committed656/658 source set changed');
  for(const f of expected)if(!equal(actual.get(f.relative),{bytes:f.bytes,sha256:f.sha256,git_mode:f.git_mode,git_blob_oid:f.git_blob_oid}))p.push('Q024 frozen original/protected Git source changed: '+f.relative);
  if(!old){
   for(const file of [...Q024_WORK_PATHS,...Q024_NEW_PATHS])if(actual.get(file)?.git_mode!=='100644')p.push('Q024 committed work/Owner mode changed: '+file);
   for(const [file,digest]of [[Q024_AUTHORITY,Q024_AUTHORITY_SHA],[Q024_PROPOSAL,Q024_PROPOSAL_SHA],[Q024_TEST,Q024_TEST_SHA],['.github/workflows/ci.yml',Q023_WORKFLOW_SHA]])if(actual.get(file)?.sha256!==digest)p.push('Q024 committed exact Owner/test/workflow changed: '+file);
  }
 }catch(e){p.push('Q024 full source revision fails closed: '+e.message);}
 return p;
}
// No descendant, arbitrary parent, alternate candidate, or second successor is accepted.
export function q024Topology(repo) {
 let head=null,main=null,candidate=null,merge=null;
 const problems=[];
 try {
  q024Proposal(repo);head=git(repo,['rev-parse','HEAD^{commit}']);main=git(repo,['rev-parse','refs/remotes/origin/main^{commit}']);
  const original=q023Facts(repo,Q024_BASELINE);
  if(!equal(original,{commit:Q024_BASELINE,tree:Q024_BASELINE_TREE,parents:[BASE,Q024_ORIGINAL_CANDIDATE]})
   ||!equal(q023Facts(repo,Q024_ORIGINAL_CANDIDATE),{commit:Q024_ORIGINAL_CANDIDATE,tree:Q024_BASELINE_TREE,parents:[BASE]}))throw new Error('Q024 actual fixed failed merge ancestry changed');
  const select=revision=>{
   if(revision===Q024_BASELINE)return null;
   const history=git(repo,['rev-list','--first-parent',Q024_BASELINE+'..'+revision]).split('\n').filter(Boolean),f=q023Facts(repo,revision);
   if(!git(repo,['rev-list','--first-parent',revision]).split('\n').includes(Q024_BASELINE)||history.length!==1||history[0]!==revision)throw new Error('Q024 unexpected first-parent history or later rewrite/restore');
   if(equal(f.parents,[Q024_BASELINE]))return {candidate:f,merge:null};
   if(f.parents.length!==2||f.parents[0]!==Q024_BASELINE)throw new Error('Q024 unexpected candidate or merge parents');
   const c=q023Facts(repo,f.parents[1]);
   if(!equal(c.parents,[Q024_BASELINE])||c.tree!==f.tree)throw new Error('Q024 merge must have ordered failed-baseline/candidate parents and identical tree');
   return {candidate:c,merge:f};
  };
  const h=select(head),m=select(main);
  if(main!==Q024_BASELINE&&!m?.merge)throw new Error('Q024 main must be fixed failed merge or one identical-tree normal successor merge');
  if(head===Q024_BASELINE&&main!==Q024_BASELINE)throw new Error('Q024 old construction cannot host accepted successor main');
  if(h&&m&&h.candidate.commit!==m.candidate.commit)throw new Error('Q024 checkout/main disagree on exact successor candidate');
  const selected=h??m;candidate=selected?.candidate??null;merge=h?.merge??m?.merge??null;
 }catch(e){problems.push('Q024 exact single-successor topology fails closed: '+e.message);}
 return {head,main,candidate,merge,problems,failed_baseline:Q024_BASELINE,original_failed_merge_CI_accepted:false};
}
export function q024LifecycleProblems(repo) {
 const p=[];
 try {
  p.push(...q024RevisionProblems(repo,Q024_BASELINE,{original:true}),...q024RevisionProblems(repo,Q024_ORIGINAL_CANDIDATE,{original:true}),
   ...q023RevisionProblems(repo,Q023_BASELINE,{original:true}),...q022RevisionProblems(repo,Q022_BASELINE,{original:true}),
   ...q021RevisionProblems(repo,Q021_BASELINE,{baseline:true}),...q023FixedDefinitionProblems(repo));
  if(git(repo,['rev-parse',BASE+'^{tree}'])!=='d91062ddb99d781a825e272a6365ed4effe97350')throw new Error('Q024 frozen accepted BASE tree changed');
  q023CommittedSource(repo,BASE);
  for(const [id,tree]of [['f7c3736acd3524240ec178dc81e0a1c72a690930','bd09b4e24b8cb2c7db15bdb43cbd3d3fc8c9bcea'],['ec76d9c5cba0c32f3bb58c2a0abb9602f9ebe2d8','9ab33633cdf943571ca3693c15a53b4f0b3d2dd5']]){
   if(!equal(q023Facts(repo,id),{commit:id,tree,parents:[BASE]}))throw new Error('Q024 prior failed fixed source ancestry changed');
   q023CommittedSource(repo,id);
  }
  const t=q024Topology(repo);p.push(...t.problems);if(t.problems.length)return [...new Set(p)];
  if(!t.candidate)return [...new Set(p)];
  p.push(...q024RevisionProblems(repo,t.candidate.commit));
  const candidate=q023CommittedSource(repo,t.candidate.commit);
  for(const [file,want]of candidate){const actual=heldQ018Bytes(path.join(repo,file));if(actual.bytes!==want.bytes||actual.sha256!==want.sha256||actual.executable!==(want.git_mode==='100755'))p.push('Q024 working658 differs from exact Candidate: '+file);}
  for(const revision of new Set([t.head,t.main]))if(revision!==Q024_BASELINE)p.push(...q024RevisionProblems(repo,revision));
 }catch(e){p.push('Q024 complete original/successor lifecycle fails closed: '+e.message);}
 return [...new Set(p)];
}
export function q024SourceProblems(repo) {
 const p=currentQualificationProblems(repo);
 try {
  const q=q024Proposal(repo),expected=[...q.protected651.map(v=>v.relative),...Q024_WORK_PATHS,...Q024_NEW_PATHS].sort();
  if(new Set(expected).size!==658)throw new Error('Q024 duplicate or incomplete exact658 source');
  const observed=git(repo,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);
  if(!equal([...new Set(observed)].sort(),expected))p.push('Q024 exact working658 source set changed');
  for(const f of q.protected651){const actual=heldQ018Bytes(path.join(repo,f.relative));if(actual.bytes!==f.bytes||actual.sha256!==f.sha256||actual.executable!==(f.git_mode==='100755'))p.push('Q024 protected651 source changed: '+f.relative);}
  for(const file of [...Q024_WORK_PATHS,...Q024_NEW_PATHS])if(heldQ018Bytes(path.join(repo,file)).executable)p.push('Q024 work/Owner execution mode changed: '+file);
  const test=heldQ018Bytes(path.join(repo,Q024_TEST));if(test.bytes!==10670||test.sha256!==Q024_TEST_SHA)p.push('Q024 exact reviewed nonleader test changed');
  if(heldQ018Bytes(path.join(repo,'.github/workflows/ci.yml')).sha256!==Q023_WORKFLOW_SHA)p.push('Q024 frozen fixed P1 workflow changed');
  p.push(...q024LifecycleProblems(repo));
 }catch(e){p.push('Q024 exact approved source contract fails closed: '+e.message);}
 return [...new Set(p)];
}
function q024CloneState(repo) {
 const q=q024Proposal(repo),identity=file=>{const v=heldQ018Bytes(file);return {bytes:v.bytes,sha256:v.sha256,executable:v.executable};};
 const paths=[...q.protected651.map(v=>v.relative),...Q024_WORK_PATHS,...Q024_NEW_PATHS].sort();
 return {head:git(repo,['rev-parse','HEAD']),tree:git(repo,['rev-parse','HEAD^{tree}']),main:git(repo,['rev-parse','refs/remotes/origin/main']),index:identity(git(repo,['rev-parse','--path-format=absolute','--git-path','index'])),source:paths.map(relative=>({relative,...identity(path.join(repo,relative))}))};
}
function q024CloneRef(repo) {
 const probe=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,'symbolic-ref','-q',Q024_HISTORY_REF],{encoding:'utf8',env:{PATH:'/usr/bin:/bin',GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(probe.error||probe.signal||![0,1].includes(probe.status))throw new Error('Q024 fixed ref symbolic probe failed');
 if(probe.status===0)throw new Error('Q024 fixed clone ref is symbolic, including a dangling target');
 return q021CloneRef(repo,Q024_HISTORY_REF);
}
export function prepareQ024FixedCloneOrigin(repo) {
 if(arguments.length!==1)throw new Error('Q024 fixed clone origin accepts no caller targets or options');
 const p=q024SourceProblems(repo);if(p.length)throw new Error('Q024 fixed original clone prerequisites failed: '+p.join('; '));
 const before=q024CloneState(repo),existing=q024CloneRef(repo);
 if(existing!==null&&existing!==Q024_ORIGINAL_CANDIDATE)throw new Error('Q024 existing fixed original ref differs; overwrite forbidden');
 prepareQ023FixedCloneOrigin(repo);
 run('/usr/bin/git',['--no-optional-locks','-C',repo,'update-ref','--no-deref','--stdin'],{input:'start\n'+(existing===null?'create ':'verify ')+Q024_HISTORY_REF+' '+Q024_ORIGINAL_CANDIDATE+'\nprepare\ncommit\n',env:{...process.env,GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(!equal(before,q024CloneState(repo)))throw new Error('Q024 source/HEAD/tree/index/main changed during fixed origin preparation');
 const after=q024SourceProblems(repo);if(after.length||q024CloneRef(repo)!==Q024_ORIGINAL_CANDIDATE)throw new Error('Q024 fixed original clone postcheck failed: '+after.join('; '));
 return {result:'PASS_Q024_FIXED_PR32_CANDIDATE_LOCAL_CLONE_ORIGIN_PREPARED',fixed_ref:Q024_HISTORY_REF,commit:Q024_ORIGINAL_CANDIDATE,tree:Q024_BASELINE_TREE,source_HEAD_tree_index_origin_main_unchanged:true,SDK_program_or_mutation:0,network_requests:0,model_DIAG_QUAL:0,full_HIGH_or_CI_or_runtime_accepted:false};
}
const q024OriginalTestSources=new Map();
export function q024OriginalTestSource(repo) {
 if(arguments.length!==1)throw new Error('Q024 original test source accepts no caller targets');
 if(!q024Present(repo))return repo;
 if(q024OriginalTestSources.has(repo))return q024OriginalTestSources.get(repo);
 prepareQ024FixedCloneOrigin(repo);
 const target=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q024-original-pr32-tests-'));
 try {
  run('/usr/bin/git',['clone','--no-local','--no-checkout',repo,target]);
  git(target,['checkout','--detach',Q024_ORIGINAL_CANDIDATE]);git(target,['update-ref','refs/remotes/origin/main',BASE]);
  const q=q024Proposal(repo);
  if(git(target,['status','--porcelain=v1','--untracked-files=all'])!==''||git(target,['rev-parse','HEAD^{tree}'])!==Q024_BASELINE_TREE)throw new Error('Q024 original test656 identity/cleanliness changed');
  for(const f of q.baseline656){const v=heldQ018Bytes(path.join(target,f.relative));if(v.bytes!==f.bytes||v.sha256!==f.sha256||v.executable!==(f.git_mode==='100755'))throw new Error('Q024 original test656 physical source changed: '+f.relative);}
  if(git(target,['ls-files','-z']).split('\0').filter(Boolean).length!==656)throw new Error('Q024 original test656 source count changed');
  prepareQ023FixedCloneOrigin(target);
  q024OriginalTestSources.set(repo,target);return target;
 }catch(e){fs.rmSync(target,{recursive:true,force:true});throw e;}
}
export function cleanupQ024OriginalTestSources() {
 for(const target of q024OriginalTestSources.values()){
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){bytes+=s.size;files++;}else throw new Error('unexpected owned Q024 snapshot artifact');};
  walk(target);fs.rmSync(target,{recursive:true,force:true});if(fs.existsSync(target))throw new Error('owned Q024 test snapshot not retired');
  console.log(JSON.stringify({owned_scratch:target,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0}));
 }
 q024OriginalTestSources.clear();
}

// Q025 adds one prefix-only observation; the original Parent attempt stays consumed.
export const Q025_AUTHORITY='docs/pilot/authorities/parent-prefix-observation-successor-q025.json';
export const Q025_PROPOSAL='docs/pilot/proposals/parent-prefix-observation-q025.json';
export const Q025_AUTHORITY_SHA='39fb7ac93be046ef5e468074bd94c197bd17295a9d3605c12c96c293f8711fa1';
export const Q025_PROPOSAL_SHA='3c5eceacb7d0fe4e1ae858f0421184cb95b15f65d64eb0b11309d549b0d9037b';
export const Q025_BASELINE='bafa3e60659b89cd565a484d305be5cf87d44d4b';
export const Q025_BASELINE_TREE='22a6307a6ed84a56c602657e78d0bba0e2409f62';
export const Q025_ORIGINAL_CANDIDATE='66ada2addfb2f6ac35ddb75d79a3eac70b89f3dc';
export const Q025_PARENT='internal/pilot/task0_parent.go';
export const Q025_TEST='internal/pilot/task0_parent_prefix_observation_test.go';
export const Q025_PARENT_SHA='a72a977f9eef07bfddb8191cb776edcb8b7ddf3564f4954e8d8d24ff2f02e692';
export const Q025_TEST_SHA='fbc6d3c3a4f67d1c18ac803dd994a8fb1a63448593a6eb9dfd203320745f59cb';
export const Q025_WORK_PATHS=Object.freeze([Q025_PARENT,'scripts/ci/lib/b007-toolchain-security-q018.mjs','scripts/ci/lib/b007-successor.mjs','scripts/ci/test/b007-toolchain-security-q018.test.mjs','scripts/ci/test/b007-lifecycle.test.mjs']);
export const Q025_NEW_PATHS=Object.freeze([Q025_TEST,Q025_AUTHORITY,Q025_PROPOSAL]);
const Q025_HISTORY_REF='refs/heads/codex/q025-fixed-history-pr33-merge';
export function q025Present(repo) {
 return [Q025_AUTHORITY,Q025_PROPOSAL].some(file=>{try{fs.lstatSync(path.join(repo,file));return true;}catch(e){return e.code!=='ENOENT';}});
}
export function q025Approved(repo) {
 try {
  if(!q024Approved(repo))return false;
  const a=json(repo,Q025_AUTHORITY,Q025_AUTHORITY_SHA),p=heldQ018Bytes(path.join(repo,Q025_PROPOSAL));
  return a.decision_id==='AIPT-MVP-B007-OWNER-Q025'&&a.state==='OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI'&&a.owner_instruction==='批准'
   &&equal(a.current_work_paths,Q025_WORK_PATHS)&&equal(a.new_exact_public_paths,Q025_NEW_PATHS)
   &&a.approved_private_contract.sha256==='b29849baf8415a30bbaf6d5d3426d8f8535618770b624effe9f934138bf24af4'
   &&a.actual_Owner_approval_registration.sha256==='09d789dae9bfe52cd769901730ed00fad8b69b1b0f3fc1e1f3142eae24c9721b'
   &&a.approved_material.sha256==='dc9b386734bf52fdb0ea02e3486a10aeea999c9ac04edacf376bb0566083acdb'
   &&a.proposal_binding.path===Q025_PROPOSAL&&a.proposal_binding.sha256===Q025_PROPOSAL_SHA&&p.sha256===Q025_PROPOSAL_SHA&&p.bytes===a.proposal_binding.bytes
   &&equal(a.baseline,{commit:Q025_BASELINE,tree:Q025_BASELINE_TREE,parents:[Q024_BASELINE,Q025_ORIGINAL_CANDIDATE]})
   &&a.retained_Q024_authority_sha256===Q024_AUTHORITY_SHA&&a.retained_Q024_proposal_sha256===Q024_PROPOSAL_SHA
   &&a.parent_binding.sha256===Q025_PARENT_SHA&&a.test_binding.sha256===Q025_TEST_SHA
   &&a.combined_source_count===661&&a.protected_current_paths===653&&a.distinct_prefix_maximum_attempts===1
   &&a.stop_before_context_environment_and_PREP&&a.reject_provider_credential_presence_before_input&&a.fixed_nonsecret_observation_only
   &&a.same_independent_agent_and_Root_full661_HIGH_and_exact_CI_each5_required&&a.separate_final_Owner_merge_approval_required
   &&a.SDK_execution_interval_source_stability_owner_accepted&&a.cannot_guarantee_same_UID_instant_replace_restore_detection
   &&!a.generic_followon_permission&&!a.SDK_copy_write_chmod_registry_retirement_authorized&&!a.original_Parent_or_DIAG_retry_authorized
   &&!a.new_DIAG_or_extra_budget_authorized&&!a.runtime_ready&&!a.paid_callable&&!a.valid_START_MODEL_permitted&&a.qualification_runs_authorized===0;
 }catch{return false;}
}
export function q025Proposal(repo) {
 if(!q025Approved(repo))throw new Error('Q025 exact paired Owner authority/proposal absent or changed');
 const q=json(repo,Q025_PROPOSAL,Q025_PROPOSAL_SHA);
 if(q.baseline658.length!==658||q.protected653.length!==653||!equal(q.work_paths,Q025_WORK_PATHS)||!equal(q.new_paths,Q025_NEW_PATHS)
  ||!equal(q.protected653,q.baseline658.filter(v=>!Q025_WORK_PATHS.includes(v.relative))))throw new Error('Q025 exact658/653/5+3 scope invalid');
 return q;
}
function q025Select(repo,revision) {
 if(revision===Q025_BASELINE)return null;
 const f=q023Facts(repo,revision),history=git(repo,['rev-list','--first-parent',Q025_BASELINE+'..'+revision]).split('\n').filter(Boolean);
 if(!git(repo,['rev-list','--first-parent',revision]).split('\n').includes(Q025_BASELINE)||history.length!==1||history[0]!==revision)throw new Error('Q025 later or foreign first-parent history forbidden');
 if(equal(f.parents,[Q025_BASELINE]))return {candidate:f,merge:null};
 if(f.parents.length!==2||f.parents[0]!==Q025_BASELINE)throw new Error('Q025 candidate/merge ordered parents changed');
 const candidate=q023Facts(repo,f.parents[1]);
 if(!equal(candidate.parents,[Q025_BASELINE])||candidate.tree!==f.tree)throw new Error('Q025 normal merge requires exact direct candidate and identical tree');
 return {candidate,merge:f};
}
export function q025RevisionProblems(repo,revision,{baseline=false}={}) {
 const p=[];
 try {
  const q=q025Proposal(repo),resolved=git(repo,['rev-parse',revision+'^{commit}']),old=resolved===Q025_BASELINE;
  if(baseline&&!old)throw new Error('Q025 original source must be exact accepted PR33 merge');
  if(old){if(!equal(q023Facts(repo,resolved),{commit:Q025_BASELINE,tree:Q025_BASELINE_TREE,parents:[Q024_BASELINE,Q025_ORIGINAL_CANDIDATE]}))throw new Error('Q025 accepted baseline SHA/tree/ordered parents changed');}
  else q025Select(repo,resolved);
  const actual=q023CommittedSource(repo,resolved),expected=old?q.baseline658:q.protected653;
  const paths=(old?q.baseline658.map(v=>v.relative):[...q.protected653.map(v=>v.relative),...Q025_WORK_PATHS,...Q025_NEW_PATHS]).sort();
  if(actual.size!==paths.length||new Set(paths).size!==paths.length||!equal([...actual.keys()].sort(),paths))throw new Error('Q025 exact committed658/661 source set changed');
  for(const f of expected)if(!equal(actual.get(f.relative),{bytes:f.bytes,sha256:f.sha256,git_mode:f.git_mode,git_blob_oid:f.git_blob_oid}))p.push('Q025 frozen baseline/protected Git source changed: '+f.relative);
  if(!old){
   for(const file of [...Q025_WORK_PATHS,...Q025_NEW_PATHS])if(actual.get(file)?.git_mode!=='100644')p.push('Q025 committed work/Owner mode changed: '+file);
   for(const [file,digest]of [[Q025_AUTHORITY,Q025_AUTHORITY_SHA],[Q025_PROPOSAL,Q025_PROPOSAL_SHA],[Q025_PARENT,Q025_PARENT_SHA],[Q025_TEST,Q025_TEST_SHA]])if(actual.get(file)?.sha256!==digest)p.push('Q025 committed exact Owner/runtime/test changed: '+file);
   const changed=git(repo,['diff','--name-status','--no-renames',Q025_BASELINE,resolved]).split('\n').filter(Boolean).map(line=>line.split('\t'));
   if(!equal(changed.map(v=>v[1]).sort(),[...Q025_WORK_PATHS,...Q025_NEW_PATHS].sort())||changed.some(([kind,file])=>kind!==(Q025_NEW_PATHS.includes(file)?'A':'M')))throw new Error('Q025 exact5modified+3added commit delta changed');
  }
 }catch(e){p.push('Q025 complete source revision fails closed: '+e.message);}
 return p;
}
export function q025Topology(repo) {
 let head=null,main=null,candidate=null,merge=null;const problems=[];
 try {
  q025Proposal(repo);head=git(repo,['rev-parse','HEAD^{commit}']);main=git(repo,['rev-parse','refs/remotes/origin/main^{commit}']);
  if(!equal(q023Facts(repo,Q025_BASELINE),{commit:Q025_BASELINE,tree:Q025_BASELINE_TREE,parents:[Q024_BASELINE,Q025_ORIGINAL_CANDIDATE]})
   ||!equal(q023Facts(repo,Q025_ORIGINAL_CANDIDATE),{commit:Q025_ORIGINAL_CANDIDATE,tree:Q025_BASELINE_TREE,parents:[Q024_BASELINE]}))throw new Error('Q025 fixed accepted PR33 candidate/merge identity changed');
  const h=q025Select(repo,head),m=q025Select(repo,main);
  if(main!==Q025_BASELINE&&!m?.merge)throw new Error('Q025 accepted main must be fixed baseline or one normal merge');
  if(head===Q025_BASELINE&&main!==Q025_BASELINE)throw new Error('Q025 old construction cannot host accepted successor main');
  if(h&&m&&h.candidate.commit!==m.candidate.commit)throw new Error('Q025 checkout and main disagree on exact candidate');
  candidate=(h??m)?.candidate??null;merge=h?.merge??m?.merge??null;
 }catch(e){problems.push('Q025 exact single-successor topology fails closed: '+e.message);}
 return {head,main,candidate,merge,problems,accepted_baseline:Q025_BASELINE,original_Parent_entry_consumed:true,original_Parent_or_DIAG_retry_authorized:false};
}
export function q025LifecycleProblems(repo) {
 const p=[];
 try {
  p.push(...q025RevisionProblems(repo,Q025_BASELINE,{baseline:true}),...q024RevisionProblems(repo,Q025_BASELINE),...q024RevisionProblems(repo,Q025_ORIGINAL_CANDIDATE),
   ...q024RevisionProblems(repo,Q024_BASELINE,{original:true}),...q024RevisionProblems(repo,Q024_ORIGINAL_CANDIDATE,{original:true}),
   ...q023RevisionProblems(repo,Q023_BASELINE,{original:true}),...q022RevisionProblems(repo,Q022_BASELINE,{original:true}),...q021RevisionProblems(repo,Q021_BASELINE,{baseline:true}),...q023FixedDefinitionProblems(repo));
  if(git(repo,['rev-parse',BASE+'^{tree}'])!=='d91062ddb99d781a825e272a6365ed4effe97350')throw new Error('Q025 frozen accepted B006 BASE tree changed');
  q023CommittedSource(repo,BASE);
  for(const [id,tree]of [['f7c3736acd3524240ec178dc81e0a1c72a690930','bd09b4e24b8cb2c7db15bdb43cbd3d3fc8c9bcea'],['ec76d9c5cba0c32f3bb58c2a0abb9602f9ebe2d8','9ab33633cdf943571ca3693c15a53b4f0b3d2dd5']]){
   if(!equal(q023Facts(repo,id),{commit:id,tree,parents:[BASE]}))throw new Error('Q025 preserved failed source ancestry changed');q023CommittedSource(repo,id);
  }
  const t=q025Topology(repo);p.push(...t.problems);if(t.problems.length||!t.candidate)return [...new Set(p)];
  for(const revision of new Set([t.head,t.main,t.candidate.commit]))if(revision!==Q025_BASELINE)p.push(...q025RevisionProblems(repo,revision));
  for(const [file,want]of q023CommittedSource(repo,t.candidate.commit)){const actual=heldQ018Bytes(path.join(repo,file));if(actual.bytes!==want.bytes||actual.sha256!==want.sha256||actual.executable!==(want.git_mode==='100755'))p.push('Q025 working661 differs from exact candidate: '+file);}
 }catch(e){p.push('Q025 complete retained/successor lifecycle fails closed: '+e.message);}
 return [...new Set(p)];
}
export function q025SourceProblems(repo) {
 const p=currentQualificationProblems(repo);
 try {
  const q=q025Proposal(repo),expected=[...q.protected653.map(v=>v.relative),...Q025_WORK_PATHS,...Q025_NEW_PATHS].sort();
  const observed=git(repo,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);
  if(new Set(expected).size!==661||!equal([...new Set(observed)].sort(),expected))p.push('Q025 exact working661 source set changed');
  for(const f of q.protected653){const actual=heldQ018Bytes(path.join(repo,f.relative));if(actual.bytes!==f.bytes||actual.sha256!==f.sha256||actual.executable!==(f.git_mode==='100755'))p.push('Q025 protected653 source changed: '+f.relative);}
  for(const file of [...Q025_WORK_PATHS,...Q025_NEW_PATHS])if(heldQ018Bytes(path.join(repo,file)).executable)p.push('Q025 work/Owner execution mode changed: '+file);
  for(const [file,digest]of [[Q025_PARENT,Q025_PARENT_SHA],[Q025_TEST,Q025_TEST_SHA]])if(heldQ018Bytes(path.join(repo,file)).sha256!==digest)p.push('Q025 exact reviewed runtime/test changed: '+file);
  p.push(...q025LifecycleProblems(repo));
 }catch(e){p.push('Q025 exact approved source contract fails closed: '+e.message);}
 return [...new Set(p)];
}
function q025CloneState(repo) {
 const q=q025Proposal(repo),identity=file=>{const v=heldQ018Bytes(file);return {bytes:v.bytes,sha256:v.sha256,executable:v.executable};};
 const paths=[...q.protected653.map(v=>v.relative),...Q025_WORK_PATHS,...Q025_NEW_PATHS].sort();
 return {head:git(repo,['rev-parse','HEAD']),tree:git(repo,['rev-parse','HEAD^{tree}']),main:git(repo,['rev-parse','refs/remotes/origin/main']),index:identity(git(repo,['rev-parse','--path-format=absolute','--git-path','index'])),source:paths.map(relative=>({relative,...identity(path.join(repo,relative))}))};
}
function q025ExactCloneRef(repo,ref) {
 const probe=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,'symbolic-ref','-q',ref],{encoding:'utf8',env:{PATH:'/usr/bin:/bin',GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(probe.error||probe.signal||![0,1].includes(probe.status))throw new Error('Q025 fixed clone-ref probe failed');
 if(probe.status===0)throw new Error('Q025 fixed clone ref is symbolic, including a dangling target');
 return q021CloneRef(repo,ref);
}
function q025FixedCloneOrigins() {
 return [
  ...q021CloneOrigins,
  {ref:Q022_HISTORY_REF,commit:Q022_BASELINE,tree:Q022_BASELINE_TREE},
  {ref:Q023_HISTORY_REF,commit:Q023_BASELINE,tree:Q023_BASELINE_TREE},
  {ref:Q024_HISTORY_REF,commit:Q024_ORIGINAL_CANDIDATE,tree:Q024_BASELINE_TREE},
  {ref:Q025_HISTORY_REF,commit:Q025_BASELINE,tree:Q025_BASELINE_TREE},
 ];
}
export function prepareQ025FixedCloneOrigin(repo) {
 if(arguments.length!==1)throw new Error('Q025 accepts no caller clone targets/options');
 const p=q025SourceProblems(repo);if(p.length)throw new Error('Q025 fixed clone prerequisites failed: '+p.join('; '));
 const before=q025CloneState(repo),origins=q025FixedCloneOrigins(),commands=[];
 if(origins.length!==7||new Set(origins.map(v=>v.ref)).size!==7)throw new Error('Q025 exact seven retained/current clone refs changed');
 for(const origin of origins){
  const parents=origin.commit===Q025_BASELINE?[Q024_BASELINE,Q025_ORIGINAL_CANDIDATE]:[BASE];
  if(!equal(q023Facts(repo,origin.commit),{commit:origin.commit,tree:origin.tree,parents}))throw new Error('Q025 fixed clone history SHA/tree/parents changed');
  const existing=q025ExactCloneRef(repo,origin.ref);
  if(existing!==null&&existing!==origin.commit)throw new Error('Q025 existing fixed clone ref differs; overwrite forbidden');
  commands.push((existing===null?'create ':'verify ')+origin.ref+' '+origin.commit);
 }
 run('/usr/bin/git',['--no-optional-locks','-C',repo,'update-ref','--no-deref','--stdin'],{input:'start\n'+commands.join('\n')+'\nprepare\ncommit\n',env:{...process.env,GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(!equal(before,q025CloneState(repo)))throw new Error('Q025 source/HEAD/tree/index/main changed during fixed clone preparation');
 const after=q025SourceProblems(repo);if(after.length||origins.some(v=>q025ExactCloneRef(repo,v.ref)!==v.commit))throw new Error('Q025 fixed clone postcheck failed');
 return {result:'PASS_Q025_FIXED_PR33_AND_SIX_RETAINED_LOCAL_CLONE_ORIGINS_PREPARED',fixed_ref:Q025_HISTORY_REF,commit:Q025_BASELINE,tree:Q025_BASELINE_TREE,fixed_origins:origins,source_HEAD_tree_index_origin_main_unchanged:true,SDK_program_or_mutation:0,network_requests:0,model_DIAG_QUAL:0,full_HIGH_or_CI_or_runtime_accepted:false};
}
const q025OriginalTestSources=new Map();
const q025PredecessorSources=new Map();

function q025CreateOriginalSource(repo) {
 prepareQ025FixedCloneOrigin(repo);
 const target=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q025-original-pr33-tests-'));
 try {
  run('/usr/bin/git',['clone','--no-local','--no-checkout',repo,target]);
  git(target,['checkout','--detach',Q025_BASELINE]);git(target,['update-ref','refs/remotes/origin/main',Q025_BASELINE]);
  const q=q025Proposal(repo);
  if(git(target,['status','--porcelain=v1','--untracked-files=all'])!==''||git(target,['rev-parse','HEAD^{tree}'])!==Q025_BASELINE_TREE)throw new Error('Q025 original658 identity/cleanliness changed');
  for(const f of q.baseline658){const actual=heldQ018Bytes(path.join(target,f.relative));if(actual.bytes!==f.bytes||actual.sha256!==f.sha256||actual.executable!==(f.git_mode==='100755'))throw new Error('Q025 original658 source changed: '+f.relative);}
  if(git(target,['ls-files','-z']).split('\0').filter(Boolean).length!==658)throw new Error('Q025 original source count changed');
  prepareQ024FixedCloneOrigin(target);
  return target;
 }catch(e){fs.rmSync(target,{recursive:true,force:true});throw e;}
}
export function q025OriginalTestSource(repo) {
 if(arguments.length!==1)throw new Error('Q025 original test source accepts no caller targets');
 if(!q025Present(repo))return repo;
 if(q025OriginalTestSources.has(repo))return q025OriginalTestSources.get(repo);
 const target=q025CreateOriginalSource(repo);q025OriginalTestSources.set(repo,target);return target;
}
export function q025PredecessorSource(repo) {
 if(arguments.length!==1)throw new Error('Q025 predecessor source accepts no caller targets');
 if(!q025Present(repo))return repo;
 if(q025PredecessorSources.has(repo))return q025PredecessorSources.get(repo);
 const target=q025CreateOriginalSource(repo);q025PredecessorSources.set(repo,target);return target;
}
export function cleanupQ025PredecessorSources() {
 const retired=[];
 for(const target of q025PredecessorSources.values()){
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){bytes+=s.size;files++;}else throw new Error('unexpected owned Q025 predecessor snapshot');};
  walk(target);fs.rmSync(target,{recursive:true,force:true});if(fs.existsSync(target))throw new Error('owned Q025 predecessor snapshot not retired');
  retired.push({owned_scratch:target,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0});
 }
 q025PredecessorSources.clear();return retired;
}

export function cleanupQ025OriginalTestSources() {
 for(const target of q025OriginalTestSources.values()){
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){bytes+=s.size;files++;}else throw new Error('unexpected owned Q025 snapshot artifact');};
  walk(target);fs.rmSync(target,{recursive:true,force:true});if(fs.existsSync(target))throw new Error('owned Q025 test snapshot not retired');
  console.log(JSON.stringify({owned_scratch:target,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0}));
 }
 q025OriginalTestSources.clear();
}

export const Q026_AUTHORITY='docs/pilot/authorities/preparation-ready-observation-successor-q026.json';
export const Q026_PROPOSAL='docs/pilot/proposals/preparation-ready-observation-q026.json';
export const Q026_AUTHORITY_SHA='6146e23896717c65b7e6e1dd5e6468dd2132c40f431d6fd11250a119da5bbc00';
export const Q026_PROPOSAL_SHA='8b059fd5179fbb5da5590bbe28b2371b667d4e29f9129bc0a5239d3ca5ddde2c';
export const Q026_BASELINE='ead7858764229c08b2041e1bad93402a49883929';
export const Q026_BASELINE_TREE='22ab8a84ce456e37fb47d72b7ad5f6aab942df37';
export const Q026_ORIGINAL_CANDIDATE='e9d8f8637301915b75389e4ecaece1d4038cefb2';
export const Q026_PARENT='internal/pilot/task0_parent.go';
export const Q026_OBSERVER='internal/pilot/task0_preparation_ready_observation.go';
export const Q026_OBSERVER_SHA='ca3416a8db0e7fd3229352a41a86ea7d38415cf71ed8f9f29062dc1a4cee9f09';
export const Q026_TEST='internal/pilot/task0_preparation_ready_observation_test.go';
export const Q026_PARENT_SHA='abacf429b4857db179060e27f5f27a9e1bb4088f9b88e6ff06622606c807eed1';
export const Q026_TEST_SHA='fc43c7f0ca25ab39de39df47eaf80367c0bf899f166ea34f262c49d38aa7b1cd';
export const Q026_WORK_PATHS=Object.freeze([Q026_PARENT,'scripts/ci/lib/b007-toolchain-security-q018.mjs','scripts/ci/lib/b007-successor.mjs','scripts/ci/test/b007-toolchain-security-q018.test.mjs','scripts/ci/test/b007-lifecycle.test.mjs']);
export const Q026_NEW_PATHS=Object.freeze([Q026_OBSERVER,Q026_TEST,Q026_AUTHORITY,Q026_PROPOSAL]);
const Q026_HISTORY_REF='refs/heads/codex/q026-fixed-history-pr34-merge';
export function q026Present(repo) {
 return [Q026_AUTHORITY,Q026_PROPOSAL].some(file=>{try{fs.lstatSync(path.join(repo,file));return true;}catch(e){return e.code!=='ENOENT';}});
}
export function q026Approved(repo) {
 try {
  if(!q025Approved(repo))return false;
  const a=json(repo,Q026_AUTHORITY,Q026_AUTHORITY_SHA),p=heldQ018Bytes(path.join(repo,Q026_PROPOSAL));
  return a.decision_id==='AIPT-MVP-B007-OWNER-Q026'&&a.state==='OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI'&&a.owner_instruction==='批准'
   &&equal(a.current_work_paths,Q026_WORK_PATHS)&&equal(a.new_exact_public_paths,Q026_NEW_PATHS)
   &&a.approved_private_contract.sha256==='443cce4f7659e923d6282db3e229d03281a395ed615ee136f96456a1e70fdb16'
   &&a.actual_Owner_approval_registration.sha256==='9dfd1145befd6b19a16e6d561fe8942655394d71960771d2d9ef194f16184440'
   &&a.approved_material.sha256==='d6bc31ec91a3b3c48eaa9e508ecf26f5a443659a567a8c2353fe55ca64995af6'
   &&a.proposal_binding.path===Q026_PROPOSAL&&a.proposal_binding.sha256===Q026_PROPOSAL_SHA&&p.sha256===Q026_PROPOSAL_SHA&&p.bytes===a.proposal_binding.bytes
   &&equal(a.baseline,{commit:Q026_BASELINE,tree:Q026_BASELINE_TREE,parents:[Q025_BASELINE,Q026_ORIGINAL_CANDIDATE]})
   &&a.retained_Q025_authority_sha256===Q025_AUTHORITY_SHA&&a.retained_Q025_proposal_sha256===Q025_PROPOSAL_SHA
   &&a.parent_binding.sha256===Q026_PARENT_SHA&&a.test_binding.sha256===Q026_TEST_SHA&&a.observer_binding.sha256===Q026_OBSERVER_SHA
   &&a.maximum_direct_PREP_children===1&&!a.parent_sends_ADMIT_CONFIRMED_or_CA_messages&&equal(a.fixed_child_marker,{"name": "DEEPSEEK_API_KEY", "value": "AIPT_Q026_READY_OBSERVATION_ONLY_NOT_A_PROVIDER_CREDENTIAL", "reason": "Original immutable PREP rejects an empty credential field before READY. The marker passes that original syntax-only nonempty check while being no provider credential; parent rejects inherited key presence and never reads or copies a real key. No ADMIT can be sent."})
   &&a.combined_source_count===665&&a.protected_current_paths===656&&a.distinct_READY_maximum_attempts===1
   &&a.stop_before_PREP_admission&&a.reject_provider_credential_presence_before_input&&a.fixed_nonsecret_observation_only
   &&a.same_independent_agent_and_Root_full665_HIGH_and_exact_CI_each5_required&&a.separate_final_Owner_merge_approval_required
   &&a.SDK_execution_interval_source_stability_owner_accepted&&a.cannot_guarantee_same_UID_instant_replace_restore_detection
   &&!a.generic_followon_permission&&!a.SDK_copy_write_chmod_registry_retirement_authorized&&!a.original_Parent_or_DIAG_retry_authorized
   &&!a.new_DIAG_or_extra_budget_authorized&&!a.runtime_ready&&!a.paid_callable&&!a.valid_START_MODEL_permitted&&a.qualification_runs_authorized===0;
 }catch{return false;}
}
export function q026Proposal(repo) {
 if(!q026Approved(repo))throw new Error('Q026 exact paired Owner authority/proposal absent or changed');
 const q=json(repo,Q026_PROPOSAL,Q026_PROPOSAL_SHA);
 if(q.baseline661.length!==661||q.protected656.length!==656||!equal(q.work_paths,Q026_WORK_PATHS)||!equal(q.new_paths,Q026_NEW_PATHS)
  ||!equal(q.protected656,q.baseline661.filter(v=>!Q026_WORK_PATHS.includes(v.relative))))throw new Error('Q026 exact661/656/5+4 scope invalid');
 return q;
}
function q026Select(repo,revision) {
 if(revision===Q026_BASELINE)return null;
 const f=q023Facts(repo,revision),history=git(repo,['rev-list','--first-parent',Q026_BASELINE+'..'+revision]).split('\n').filter(Boolean);
 if(!git(repo,['rev-list','--first-parent',revision]).split('\n').includes(Q026_BASELINE)||history.length!==1||history[0]!==revision)throw new Error('Q026 later or foreign first-parent history forbidden');
 if(equal(f.parents,[Q026_BASELINE]))return {candidate:f,merge:null};
 if(f.parents.length!==2||f.parents[0]!==Q026_BASELINE)throw new Error('Q026 candidate/merge ordered parents changed');
 const candidate=q023Facts(repo,f.parents[1]);
 if(!equal(candidate.parents,[Q026_BASELINE])||candidate.tree!==f.tree)throw new Error('Q026 normal merge requires exact direct candidate and identical tree');
 return {candidate,merge:f};
}
export function q026RevisionProblems(repo,revision,{baseline=false}={}) {
 const p=[];
 try {
  const q=q026Proposal(repo),resolved=git(repo,['rev-parse',revision+'^{commit}']),old=resolved===Q026_BASELINE;
  if(baseline&&!old)throw new Error('Q026 original source must be exact accepted PR34 merge');
  if(old){if(!equal(q023Facts(repo,resolved),{commit:Q026_BASELINE,tree:Q026_BASELINE_TREE,parents:[Q025_BASELINE,Q026_ORIGINAL_CANDIDATE]}))throw new Error('Q026 accepted baseline SHA/tree/ordered parents changed');}
  else q026Select(repo,resolved);
  const actual=q023CommittedSource(repo,resolved),expected=old?q.baseline661:q.protected656;
  const paths=(old?q.baseline661.map(v=>v.relative):[...q.protected656.map(v=>v.relative),...Q026_WORK_PATHS,...Q026_NEW_PATHS]).sort();
  if(actual.size!==paths.length||new Set(paths).size!==paths.length||!equal([...actual.keys()].sort(),paths))throw new Error('Q026 exact committed658/665 source set changed');
  for(const f of expected)if(!equal(actual.get(f.relative),{bytes:f.bytes,sha256:f.sha256,git_mode:f.git_mode,git_blob_oid:f.git_blob_oid}))p.push('Q026 frozen baseline/protected Git source changed: '+f.relative);
  if(!old){
   for(const file of [...Q026_WORK_PATHS,...Q026_NEW_PATHS])if(actual.get(file)?.git_mode!=='100644')p.push('Q026 committed work/Owner mode changed: '+file);
   for(const [file,digest]of [[Q026_AUTHORITY,Q026_AUTHORITY_SHA],[Q026_PROPOSAL,Q026_PROPOSAL_SHA],[Q026_PARENT,Q026_PARENT_SHA],[Q026_TEST,Q026_TEST_SHA],[Q026_OBSERVER,Q026_OBSERVER_SHA]])if(actual.get(file)?.sha256!==digest)p.push('Q026 committed exact Owner/runtime/test changed: '+file);
   const changed=git(repo,['diff','--name-status','--no-renames',Q026_BASELINE,resolved]).split('\n').filter(Boolean).map(line=>line.split('\t'));
   if(!equal(changed.map(v=>v[1]).sort(),[...Q026_WORK_PATHS,...Q026_NEW_PATHS].sort())||changed.some(([kind,file])=>kind!==(Q026_NEW_PATHS.includes(file)?'A':'M')))throw new Error('Q026 exact5modified+4added commit delta changed');
  }
 }catch(e){p.push('Q026 complete source revision fails closed: '+e.message);}
 return p;
}
export function q026Topology(repo) {
 let head=null,main=null,candidate=null,merge=null;const problems=[];
 try {
  q026Proposal(repo);head=git(repo,['rev-parse','HEAD^{commit}']);main=git(repo,['rev-parse','refs/remotes/origin/main^{commit}']);
  if(!equal(q023Facts(repo,Q026_BASELINE),{commit:Q026_BASELINE,tree:Q026_BASELINE_TREE,parents:[Q025_BASELINE,Q026_ORIGINAL_CANDIDATE]})
   ||!equal(q023Facts(repo,Q026_ORIGINAL_CANDIDATE),{commit:Q026_ORIGINAL_CANDIDATE,tree:Q026_BASELINE_TREE,parents:[Q025_BASELINE]}))throw new Error('Q026 fixed accepted PR34 candidate/merge identity changed');
  const h=q026Select(repo,head),m=q026Select(repo,main);
  if(main!==Q026_BASELINE&&!m?.merge)throw new Error('Q026 accepted main must be fixed baseline or one normal merge');
  if(head===Q026_BASELINE&&main!==Q026_BASELINE)throw new Error('Q026 old construction cannot host accepted successor main');
  if(h&&m&&h.candidate.commit!==m.candidate.commit)throw new Error('Q026 checkout and main disagree on exact candidate');
  candidate=(h??m)?.candidate??null;merge=h?.merge??m?.merge??null;
 }catch(e){problems.push('Q026 exact single-successor topology fails closed: '+e.message);}
 return {head,main,candidate,merge,problems,accepted_baseline:Q026_BASELINE,original_Parent_entry_consumed:true,original_Parent_or_DIAG_retry_authorized:false};
}
export function q026LifecycleProblems(repo) {
 const p=[];
 try {
  p.push(...q026RevisionProblems(repo,Q026_BASELINE,{baseline:true}),...q025RevisionProblems(repo,Q026_BASELINE),...q025RevisionProblems(repo,Q026_ORIGINAL_CANDIDATE));
  p.push(...q025RevisionProblems(repo,Q025_BASELINE,{baseline:true}),...q024RevisionProblems(repo,Q025_BASELINE),...q024RevisionProblems(repo,Q025_ORIGINAL_CANDIDATE),
   ...q024RevisionProblems(repo,Q024_BASELINE,{original:true}),...q024RevisionProblems(repo,Q024_ORIGINAL_CANDIDATE,{original:true}),
   ...q023RevisionProblems(repo,Q023_BASELINE,{original:true}),...q022RevisionProblems(repo,Q022_BASELINE,{original:true}),...q021RevisionProblems(repo,Q021_BASELINE,{baseline:true}),...q023FixedDefinitionProblems(repo));
  if(git(repo,['rev-parse',BASE+'^{tree}'])!=='d91062ddb99d781a825e272a6365ed4effe97350')throw new Error('Q026 frozen accepted B006 BASE tree changed');
  q023CommittedSource(repo,BASE);
  for(const [id,tree]of [['f7c3736acd3524240ec178dc81e0a1c72a690930','bd09b4e24b8cb2c7db15bdb43cbd3d3fc8c9bcea'],['ec76d9c5cba0c32f3bb58c2a0abb9602f9ebe2d8','9ab33633cdf943571ca3693c15a53b4f0b3d2dd5']]){
   if(!equal(q023Facts(repo,id),{commit:id,tree,parents:[BASE]}))throw new Error('Q026 preserved failed source ancestry changed');q023CommittedSource(repo,id);
  }
  const t=q026Topology(repo);p.push(...t.problems);if(t.problems.length||!t.candidate)return [...new Set(p)];
  for(const revision of new Set([t.head,t.main,t.candidate.commit]))if(revision!==Q026_BASELINE)p.push(...q026RevisionProblems(repo,revision));
  for(const [file,want]of q023CommittedSource(repo,t.candidate.commit)){const actual=heldQ018Bytes(path.join(repo,file));if(actual.bytes!==want.bytes||actual.sha256!==want.sha256||actual.executable!==(want.git_mode==='100755'))p.push('Q026 working665 differs from exact candidate: '+file);}
 }catch(e){p.push('Q026 complete retained/successor lifecycle fails closed: '+e.message);}
 return [...new Set(p)];
}
export function q026SourceProblems(repo) {
 const p=currentQualificationProblems(repo);
 try {
  const q=q026Proposal(repo),expected=[...q.protected656.map(v=>v.relative),...Q026_WORK_PATHS,...Q026_NEW_PATHS].sort();
  const observed=git(repo,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);
  if(new Set(expected).size!==665||!equal([...new Set(observed)].sort(),expected))p.push('Q026 exact working665 source set changed');
  for(const f of q.protected656){const actual=heldQ018Bytes(path.join(repo,f.relative));if(actual.bytes!==f.bytes||actual.sha256!==f.sha256||actual.executable!==(f.git_mode==='100755'))p.push('Q026 protected656 source changed: '+f.relative);}
  for(const file of [...Q026_WORK_PATHS,...Q026_NEW_PATHS])if(heldQ018Bytes(path.join(repo,file)).executable)p.push('Q026 work/Owner execution mode changed: '+file);
  for(const [file,digest]of [[Q026_PARENT,Q026_PARENT_SHA],[Q026_TEST,Q026_TEST_SHA],[Q026_OBSERVER,Q026_OBSERVER_SHA]])if(heldQ018Bytes(path.join(repo,file)).sha256!==digest)p.push('Q026 exact reviewed runtime/test changed: '+file);
  p.push(...q026LifecycleProblems(repo));
 }catch(e){p.push('Q026 exact approved source contract fails closed: '+e.message);}
 return [...new Set(p)];
}
function q026CloneState(repo) {
 const q=q026Proposal(repo),identity=file=>{const v=heldQ018Bytes(file);return {bytes:v.bytes,sha256:v.sha256,executable:v.executable};};
 const paths=[...q.protected656.map(v=>v.relative),...Q026_WORK_PATHS,...Q026_NEW_PATHS].sort();
 return {head:git(repo,['rev-parse','HEAD']),tree:git(repo,['rev-parse','HEAD^{tree}']),main:git(repo,['rev-parse','refs/remotes/origin/main']),index:identity(git(repo,['rev-parse','--path-format=absolute','--git-path','index'])),source:paths.map(relative=>({relative,...identity(path.join(repo,relative))}))};
}
function q026ExactCloneRef(repo,ref) {
 const probe=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,'symbolic-ref','-q',ref],{encoding:'utf8',env:{PATH:'/usr/bin:/bin',GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(probe.error||probe.signal||![0,1].includes(probe.status))throw new Error('Q026 fixed clone-ref probe failed');
 if(probe.status===0)throw new Error('Q026 fixed clone ref is symbolic, including a dangling target');
 return q021CloneRef(repo,ref);
}
function q026FixedCloneOrigins() {return [...q025FixedCloneOrigins(),{ref:Q026_HISTORY_REF,commit:Q026_BASELINE,tree:Q026_BASELINE_TREE}];}
export function prepareQ026FixedCloneOrigin(repo) {
 if(arguments.length!==1)throw new Error('Q026 accepts no caller clone targets/options');
 const p=q026SourceProblems(repo);if(p.length)throw new Error('Q026 fixed clone prerequisites failed: '+p.join('; '));
 const before=q026CloneState(repo),origins=q026FixedCloneOrigins(),commands=[];
 if(origins.length!==8||new Set(origins.map(v=>v.ref)).size!==8)throw new Error('Q026 exact eight retained/current clone refs changed');
 for(const origin of origins){
  const parents=origin.commit===Q026_BASELINE?[Q025_BASELINE,Q026_ORIGINAL_CANDIDATE]:origin.commit===Q025_BASELINE?[Q024_BASELINE,Q025_ORIGINAL_CANDIDATE]:[BASE];
  if(!equal(q023Facts(repo,origin.commit),{commit:origin.commit,tree:origin.tree,parents}))throw new Error('Q026 fixed clone history SHA/tree/parents changed');
  const existing=q026ExactCloneRef(repo,origin.ref);
  if(existing!==null&&existing!==origin.commit)throw new Error('Q026 existing fixed clone ref differs; overwrite forbidden');
  commands.push((existing===null?'create ':'verify ')+origin.ref+' '+origin.commit);
 }
 run('/usr/bin/git',['--no-optional-locks','-C',repo,'update-ref','--no-deref','--stdin'],{input:'start\n'+commands.join('\n')+'\nprepare\ncommit\n',env:{...process.env,GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(!equal(before,q026CloneState(repo)))throw new Error('Q026 source/HEAD/tree/index/main changed during fixed clone preparation');
 const after=q026SourceProblems(repo);if(after.length||origins.some(v=>q026ExactCloneRef(repo,v.ref)!==v.commit))throw new Error('Q026 fixed clone postcheck failed');
 return {result:'PASS_Q026_FIXED_PR34_AND_SEVEN_RETAINED_LOCAL_CLONE_ORIGINS_PREPARED',fixed_ref:Q026_HISTORY_REF,commit:Q026_BASELINE,tree:Q026_BASELINE_TREE,fixed_origins:origins,source_HEAD_tree_index_origin_main_unchanged:true,SDK_program_or_mutation:0,network_requests:0,model_DIAG_QUAL:0,full_HIGH_or_CI_or_runtime_accepted:false};
}
const q026OriginalTestSources=new Map();
const q026PredecessorSources=new Map();

function q026CreateOriginalSource(repo) {
 prepareQ026FixedCloneOrigin(repo);
 const target=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q026-original-pr34-tests-'));
 try {
  run('/usr/bin/git',['clone','--no-local','--no-checkout',repo,target]);
  git(target,['checkout','--detach',Q026_BASELINE]);git(target,['update-ref','refs/remotes/origin/main',Q026_BASELINE]);
  const q=q026Proposal(repo);
  if(git(target,['status','--porcelain=v1','--untracked-files=all'])!==''||git(target,['rev-parse','HEAD^{tree}'])!==Q026_BASELINE_TREE)throw new Error('Q026 original661 identity/cleanliness changed');
  for(const f of q.baseline661){const actual=heldQ018Bytes(path.join(target,f.relative));if(actual.bytes!==f.bytes||actual.sha256!==f.sha256||actual.executable!==(f.git_mode==='100755'))throw new Error('Q026 original661 source changed: '+f.relative);}
  if(git(target,['ls-files','-z']).split('\0').filter(Boolean).length!==661)throw new Error('Q026 original source count changed');
  prepareQ025FixedCloneOrigin(target);
  return target;
 }catch(e){fs.rmSync(target,{recursive:true,force:true});throw e;}
}
export function q026OriginalTestSource(repo) {
 if(arguments.length!==1)throw new Error('Q026 original test source accepts no caller targets');
 if(!q026Present(repo))return repo;
 if(q026OriginalTestSources.has(repo))return q026OriginalTestSources.get(repo);
 const target=q026CreateOriginalSource(repo);q026OriginalTestSources.set(repo,target);return target;
}
export function q026PredecessorSource(repo) {
 if(arguments.length!==1)throw new Error('Q026 predecessor source accepts no caller targets');
 if(!q026Present(repo))return repo;
 if(q026PredecessorSources.has(repo))return q026PredecessorSources.get(repo);
 const target=q026CreateOriginalSource(repo);q026PredecessorSources.set(repo,target);return target;
}
export function cleanupQ026PredecessorSources() {
 const retired=[];
 for(const target of q026PredecessorSources.values()){
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){bytes+=s.size;files++;}else throw new Error('unexpected owned Q026 predecessor snapshot');};
  walk(target);fs.rmSync(target,{recursive:true,force:true});if(fs.existsSync(target))throw new Error('owned Q026 predecessor snapshot not retired');
  retired.push({owned_scratch:target,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0});
 }
 q026PredecessorSources.clear();return retired;
}

export function cleanupQ026OriginalTestSources() {
 for(const target of q026OriginalTestSources.values()){
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){bytes+=s.size;files++;}else throw new Error('unexpected owned Q026 snapshot artifact');};
  walk(target);fs.rmSync(target,{recursive:true,force:true});if(fs.existsSync(target))throw new Error('owned Q026 test snapshot not retired');
  console.log(JSON.stringify({owned_scratch:target,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0}));
 }
 q026OriginalTestSources.clear();
}


export const Q027_AUTHORITY='docs/pilot/authorities/preparation-admitted-observation-successor-q027.json';
export const Q027_PROPOSAL='docs/pilot/proposals/preparation-admitted-observation-q027.json';
export const Q027_AUTHORITY_SHA='7fb0853c089476ad704010888ee5b16fc1ef41bf84087d33d2f5e9727da7c5f6';
export const Q027_PROPOSAL_SHA='c58350c5f87d0fd26bafa2d14bee872f6cf502964adcef04ab3b02c5cc07031a';
export const Q027_BASELINE='eab05ed492f0f811906be4c8903727a29dcaf059';
export const Q027_BASELINE_TREE='21013b21890ccbce979f7544fc671d61b15d290f';
export const Q027_ORIGINAL_CANDIDATE='bba272cc266f088383aec9b37f8ecfb3478472a4';
export const Q027_PARENT='internal/pilot/task0_parent.go';
export const Q027_OBSERVER='internal/pilot/task0_preparation_admitted_observation.go';
export const Q027_OBSERVER_SHA='3b4ba1501caa3b534d0b6dacb8675b5f23eb70a7edc5722be87384eea9cb159b';
export const Q027_TEST='internal/pilot/task0_preparation_admitted_observation_test.go';
export const Q027_PARENT_SHA='c0dcd7b1bd0f592a0a697aa75d969ff8840678abbdb565aa51e60fe27430b2c5';
export const Q027_TEST_SHA='0b0f0f09aac29449e9bf73b1555721c3f3bc5287e0a6a8cec7213c360fe7a213';
export const Q027_WORK_PATHS=Object.freeze([Q027_PARENT,'scripts/ci/lib/b007-toolchain-security-q018.mjs','scripts/ci/lib/b007-successor.mjs','scripts/ci/test/b007-toolchain-security-q018.test.mjs','scripts/ci/test/b007-lifecycle.test.mjs']);
export const Q027_NEW_PATHS=Object.freeze([Q027_OBSERVER,Q027_TEST,Q027_AUTHORITY,Q027_PROPOSAL]);
const Q027_HISTORY_REF='refs/heads/codex/q027-fixed-history-pr35-merge';
export function q027Present(repo) {
 return [Q027_AUTHORITY,Q027_PROPOSAL].some(file=>{try{fs.lstatSync(path.join(repo,file));return true;}catch(e){return e.code!=='ENOENT';}});
}
export function q027Approved(repo) {
 try {
  if(!q026Approved(repo))return false;
  const a=json(repo,Q027_AUTHORITY,Q027_AUTHORITY_SHA),p=heldQ018Bytes(path.join(repo,Q027_PROPOSAL));
  return a.decision_id==='AIPT-MVP-B007-OWNER-Q027'&&a.state==='OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI'&&a.owner_instruction==='批准'
   &&equal(a.current_work_paths,Q027_WORK_PATHS)&&equal(a.new_exact_public_paths,Q027_NEW_PATHS)
   &&a.actual_Owner_approval_registration.sha256==='30f711dd077730d9aa8651bfcc7e00ef46f74c9e69ecc6c5c617af20b4306976'&&a.approved_material.sha256==='2cbab0088fe938dc7b1e0a169c22747a9b99552df8a20efbe16cf99c1171ca26'
   &&a.proposal_binding.path===Q027_PROPOSAL&&a.proposal_binding.sha256===Q027_PROPOSAL_SHA&&p.sha256===Q027_PROPOSAL_SHA&&p.bytes===a.proposal_binding.bytes
   &&equal(a.baseline,{commit:Q027_BASELINE,tree:Q027_BASELINE_TREE,parents:[Q026_BASELINE,Q027_ORIGINAL_CANDIDATE]})
   &&a.retained_Q026_authority_sha256===Q026_AUTHORITY_SHA&&a.retained_Q026_proposal_sha256===Q026_PROPOSAL_SHA
   &&a.parent_binding.sha256===Q027_PARENT_SHA&&a.test_binding.sha256===Q027_TEST_SHA&&a.observer_binding.sha256===Q027_OBSERVER_SHA
   &&a.maximum_direct_PREP_children===1&&a.parent_sends_exactly_one_ADMIT_only&&a.stop_before_CONFIRMED&&equal(a.fixed_child_marker,{"name": "DEEPSEEK_API_KEY", "value": "AIPT_Q027_ADMITTED_OBSERVATION_ONLY_NOT_A_PROVIDER_CREDENTIAL", "reason": "Only the original immutable PREP syntax check; never a provider credential. Parent rejects inherited field presence. No CONFIRMED or model access."})
   &&a.combined_source_count===669&&a.protected_current_paths===660&&a.distinct_ADMITTED_maximum_attempts===1
   &&a.reject_provider_credential_presence_before_input&&a.fixed_nonsecret_observation_only
   &&a.same_independent_agent_and_Root_full669_HIGH_and_exact_CI_each5_required&&a.separate_final_Owner_merge_approval_required
   &&a.SDK_execution_interval_source_stability_owner_accepted&&a.cannot_guarantee_same_UID_instant_replace_restore_detection
   &&!a.generic_followon_permission&&!a.SDK_copy_write_chmod_registry_retirement_authorized&&!a.original_Parent_or_DIAG_retry_authorized&&!a.original_Q025_or_Q026_repeat_authorized
   &&!a.new_DIAG_or_extra_budget_authorized&&!a.runtime_ready&&!a.paid_callable&&!a.valid_START_MODEL_permitted&&a.qualification_runs_authorized===0;
 }catch{return false;}
}
export function q027Proposal(repo) {
 if(!q027Approved(repo))throw new Error('Q027 exact paired Owner authority/proposal absent or changed');
 const q=json(repo,Q027_PROPOSAL,Q027_PROPOSAL_SHA);
 if(q.baseline665.length!==665||q.protected660.length!==660||!equal(q.work_paths,Q027_WORK_PATHS)||!equal(q.new_paths,Q027_NEW_PATHS)
  ||!equal(q.protected660,q.baseline665.filter(v=>!Q027_WORK_PATHS.includes(v.relative))))throw new Error('Q027 exact665/660/5+4 scope invalid');
 return q;
}
function q027Select(repo,revision) {
 if(revision===Q027_BASELINE)return null;
 const f=q023Facts(repo,revision),history=git(repo,['rev-list','--first-parent',Q027_BASELINE+'..'+revision]).split('\n').filter(Boolean);
 if(!git(repo,['rev-list','--first-parent',revision]).split('\n').includes(Q027_BASELINE)||history.length!==1||history[0]!==revision)throw new Error('Q027 later or foreign first-parent history forbidden');
 if(equal(f.parents,[Q027_BASELINE]))return {candidate:f,merge:null};
 if(f.parents.length!==2||f.parents[0]!==Q027_BASELINE)throw new Error('Q027 candidate/merge ordered parents changed');
 const candidate=q023Facts(repo,f.parents[1]);
 if(!equal(candidate.parents,[Q027_BASELINE])||candidate.tree!==f.tree)throw new Error('Q027 normal merge requires exact direct candidate and identical tree');
 return {candidate,merge:f};
}
export function q027RevisionProblems(repo,revision,{baseline=false}={}) {
 const p=[];
 try {
  const q=q027Proposal(repo),resolved=git(repo,['rev-parse',revision+'^{commit}']),old=resolved===Q027_BASELINE;
  if(baseline&&!old)throw new Error('Q027 original source must be exact accepted PR35 merge');
  if(old){if(!equal(q023Facts(repo,resolved),{commit:Q027_BASELINE,tree:Q027_BASELINE_TREE,parents:[Q026_BASELINE,Q027_ORIGINAL_CANDIDATE]}))throw new Error('Q027 accepted baseline SHA/tree/ordered parents changed');}
  else q027Select(repo,resolved);
  const actual=q023CommittedSource(repo,resolved),expected=old?q.baseline665:q.protected660;
  const paths=(old?q.baseline665.map(v=>v.relative):[...q.protected660.map(v=>v.relative),...Q027_WORK_PATHS,...Q027_NEW_PATHS]).sort();
  if(actual.size!==paths.length||new Set(paths).size!==paths.length||!equal([...actual.keys()].sort(),paths))throw new Error('Q027 exact committed665/669 source set changed');
  for(const f of expected)if(!equal(actual.get(f.relative),{bytes:f.bytes,sha256:f.sha256,git_mode:f.git_mode,git_blob_oid:f.git_blob_oid}))p.push('Q027 frozen baseline/protected Git source changed: '+f.relative);
  if(!old){
   for(const file of [...Q027_WORK_PATHS,...Q027_NEW_PATHS])if(actual.get(file)?.git_mode!=='100644')p.push('Q027 committed work/Owner mode changed: '+file);
   for(const [file,digest]of [[Q027_AUTHORITY,Q027_AUTHORITY_SHA],[Q027_PROPOSAL,Q027_PROPOSAL_SHA],[Q027_PARENT,Q027_PARENT_SHA],[Q027_TEST,Q027_TEST_SHA],[Q027_OBSERVER,Q027_OBSERVER_SHA]])if(actual.get(file)?.sha256!==digest)p.push('Q027 committed exact Owner/runtime/test changed: '+file);
   const changed=git(repo,['diff','--name-status','--no-renames',Q027_BASELINE,resolved]).split('\n').filter(Boolean).map(line=>line.split('\t'));
   if(!equal(changed.map(v=>v[1]).sort(),[...Q027_WORK_PATHS,...Q027_NEW_PATHS].sort())||changed.some(([kind,file])=>kind!==(Q027_NEW_PATHS.includes(file)?'A':'M')))throw new Error('Q027 exact5modified+4added commit delta changed');
  }
 }catch(e){p.push('Q027 complete source revision fails closed: '+e.message);}
 return p;
}
export function q027Topology(repo) {
 let head=null,main=null,candidate=null,merge=null;const problems=[];
 try {
  q027Proposal(repo);head=git(repo,['rev-parse','HEAD^{commit}']);main=git(repo,['rev-parse','refs/remotes/origin/main^{commit}']);
  if(!equal(q023Facts(repo,Q027_BASELINE),{commit:Q027_BASELINE,tree:Q027_BASELINE_TREE,parents:[Q026_BASELINE,Q027_ORIGINAL_CANDIDATE]})
   ||!equal(q023Facts(repo,Q027_ORIGINAL_CANDIDATE),{commit:Q027_ORIGINAL_CANDIDATE,tree:Q027_BASELINE_TREE,parents:[Q026_BASELINE]}))throw new Error('Q027 fixed accepted PR35 candidate/merge identity changed');
  const h=q027Select(repo,head),m=q027Select(repo,main);
  if(main!==Q027_BASELINE&&!m?.merge)throw new Error('Q027 accepted main must be fixed baseline or one normal merge');
  if(head===Q027_BASELINE&&main!==Q027_BASELINE)throw new Error('Q027 old construction cannot host accepted successor main');
  if(h&&m&&h.candidate.commit!==m.candidate.commit)throw new Error('Q027 checkout and main disagree on exact candidate');
  candidate=(h??m)?.candidate??null;merge=h?.merge??m?.merge??null;
 }catch(e){problems.push('Q027 exact single-successor topology fails closed: '+e.message);}
 return {head,main,candidate,merge,problems,accepted_baseline:Q027_BASELINE,original_Parent_entry_consumed:true,original_Parent_or_DIAG_retry_authorized:false};
}
export function q027LifecycleProblems(repo) {
 const p=[];
 try {
  p.push(...q027RevisionProblems(repo,Q027_BASELINE,{baseline:true}),...q026RevisionProblems(repo,Q027_BASELINE),...q026RevisionProblems(repo,Q027_ORIGINAL_CANDIDATE));
  p.push(...q026RevisionProblems(repo,Q026_BASELINE,{baseline:true}),...q025RevisionProblems(repo,Q026_BASELINE),...q025RevisionProblems(repo,Q026_ORIGINAL_CANDIDATE));
  p.push(...q025RevisionProblems(repo,Q025_BASELINE,{baseline:true}),...q024RevisionProblems(repo,Q025_BASELINE),...q024RevisionProblems(repo,Q025_ORIGINAL_CANDIDATE),
   ...q024RevisionProblems(repo,Q024_BASELINE,{original:true}),...q024RevisionProblems(repo,Q024_ORIGINAL_CANDIDATE,{original:true}),
   ...q023RevisionProblems(repo,Q023_BASELINE,{original:true}),...q022RevisionProblems(repo,Q022_BASELINE,{original:true}),...q021RevisionProblems(repo,Q021_BASELINE,{baseline:true}),...q023FixedDefinitionProblems(repo));
  if(git(repo,['rev-parse',BASE+'^{tree}'])!=='d91062ddb99d781a825e272a6365ed4effe97350')throw new Error('Q027 frozen accepted B006 BASE tree changed');
  q023CommittedSource(repo,BASE);
  for(const [id,tree]of [['f7c3736acd3524240ec178dc81e0a1c72a690930','bd09b4e24b8cb2c7db15bdb43cbd3d3fc8c9bcea'],['ec76d9c5cba0c32f3bb58c2a0abb9602f9ebe2d8','9ab33633cdf943571ca3693c15a53b4f0b3d2dd5']]){
   if(!equal(q023Facts(repo,id),{commit:id,tree,parents:[BASE]}))throw new Error('Q027 preserved failed source ancestry changed');q023CommittedSource(repo,id);
  }
  const t=q027Topology(repo);p.push(...t.problems);if(t.problems.length||!t.candidate)return [...new Set(p)];
  for(const revision of new Set([t.head,t.main,t.candidate.commit]))if(revision!==Q027_BASELINE)p.push(...q027RevisionProblems(repo,revision));
  for(const [file,want]of q023CommittedSource(repo,t.candidate.commit)){const actual=heldQ018Bytes(path.join(repo,file));if(actual.bytes!==want.bytes||actual.sha256!==want.sha256||actual.executable!==(want.git_mode==='100755'))p.push('Q027 working669 differs from exact candidate: '+file);}
 }catch(e){p.push('Q027 complete retained/successor lifecycle fails closed: '+e.message);}
 return [...new Set(p)];
}
export function q027SourceProblems(repo) {
 const p=currentQualificationProblems(repo);
 try {
  const q=q027Proposal(repo),expected=[...q.protected660.map(v=>v.relative),...Q027_WORK_PATHS,...Q027_NEW_PATHS].sort();
  const observed=git(repo,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);
  if(new Set(expected).size!==669||!equal([...new Set(observed)].sort(),expected))p.push('Q027 exact working665 source set changed');
  for(const f of q.protected660){const actual=heldQ018Bytes(path.join(repo,f.relative));if(actual.bytes!==f.bytes||actual.sha256!==f.sha256||actual.executable!==(f.git_mode==='100755'))p.push('Q027 protected660 source changed: '+f.relative);}
  for(const file of [...Q027_WORK_PATHS,...Q027_NEW_PATHS])if(heldQ018Bytes(path.join(repo,file)).executable)p.push('Q027 work/Owner execution mode changed: '+file);
  for(const [file,digest]of [[Q027_PARENT,Q027_PARENT_SHA],[Q027_TEST,Q027_TEST_SHA],[Q027_OBSERVER,Q027_OBSERVER_SHA]])if(heldQ018Bytes(path.join(repo,file)).sha256!==digest)p.push('Q027 exact reviewed runtime/test changed: '+file);
  p.push(...q027LifecycleProblems(repo));
 }catch(e){p.push('Q027 exact approved source contract fails closed: '+e.message);}
 return [...new Set(p)];
}
function q027CloneState(repo) {
 const q=q027Proposal(repo),identity=file=>{const v=heldQ018Bytes(file);return {bytes:v.bytes,sha256:v.sha256,executable:v.executable};};
 const paths=[...q.protected660.map(v=>v.relative),...Q027_WORK_PATHS,...Q027_NEW_PATHS].sort();
 return {head:git(repo,['rev-parse','HEAD']),tree:git(repo,['rev-parse','HEAD^{tree}']),main:git(repo,['rev-parse','refs/remotes/origin/main']),index:identity(git(repo,['rev-parse','--path-format=absolute','--git-path','index'])),source:paths.map(relative=>({relative,...identity(path.join(repo,relative))}))};
}
function q027ExactCloneRef(repo,ref) {
 const probe=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,'symbolic-ref','-q',ref],{encoding:'utf8',env:{PATH:'/usr/bin:/bin',GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(probe.error||probe.signal||![0,1].includes(probe.status))throw new Error('Q027 fixed clone-ref probe failed');
 if(probe.status===0)throw new Error('Q027 fixed clone ref is symbolic, including a dangling target');
 return q021CloneRef(repo,ref);
}
function q027FixedCloneOrigins() {return [...q026FixedCloneOrigins(),{ref:Q027_HISTORY_REF,commit:Q027_BASELINE,tree:Q027_BASELINE_TREE}];}
export function prepareQ027FixedCloneOrigin(repo) {
 if(arguments.length!==1)throw new Error('Q027 accepts no caller clone targets/options');
 const p=q027SourceProblems(repo);if(p.length)throw new Error('Q027 fixed clone prerequisites failed: '+p.join('; '));
 const before=q027CloneState(repo),origins=q027FixedCloneOrigins(),commands=[];
 if(origins.length!==9||new Set(origins.map(v=>v.ref)).size!==9)throw new Error('Q027 exact nine retained/current clone refs changed');
 for(const origin of origins){
  const parents=origin.commit===Q027_BASELINE?[Q026_BASELINE,Q027_ORIGINAL_CANDIDATE]:origin.commit===Q026_BASELINE?[Q025_BASELINE,Q026_ORIGINAL_CANDIDATE]:origin.commit===Q025_BASELINE?[Q024_BASELINE,Q025_ORIGINAL_CANDIDATE]:[BASE];
  if(!equal(q023Facts(repo,origin.commit),{commit:origin.commit,tree:origin.tree,parents}))throw new Error('Q027 fixed clone history SHA/tree/parents changed');
  const existing=q027ExactCloneRef(repo,origin.ref);
  if(existing!==null&&existing!==origin.commit)throw new Error('Q027 existing fixed clone ref differs; overwrite forbidden');
  commands.push((existing===null?'create ':'verify ')+origin.ref+' '+origin.commit);
 }
 run('/usr/bin/git',['--no-optional-locks','-C',repo,'update-ref','--no-deref','--stdin'],{input:'start\n'+commands.join('\n')+'\nprepare\ncommit\n',env:{...process.env,GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(!equal(before,q027CloneState(repo)))throw new Error('Q027 source/HEAD/tree/index/main changed during fixed clone preparation');
 const after=q027SourceProblems(repo);if(after.length||origins.some(v=>q027ExactCloneRef(repo,v.ref)!==v.commit))throw new Error('Q027 fixed clone postcheck failed');
 return {result:'PASS_Q027_FIXED_PR35_AND_EIGHT_RETAINED_LOCAL_CLONE_ORIGINS_PREPARED',fixed_ref:Q027_HISTORY_REF,commit:Q027_BASELINE,tree:Q027_BASELINE_TREE,fixed_origins:origins,source_HEAD_tree_index_origin_main_unchanged:true,SDK_program_or_mutation:0,network_requests:0,model_DIAG_QUAL:0,full_HIGH_or_CI_or_runtime_accepted:false};
}
const q027OriginalTestSources=new Map();
const q027PredecessorSources=new Map();

function q027CreateOriginalSource(repo) {
 prepareQ027FixedCloneOrigin(repo);
 const target=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q027-original-pr35-tests-'));
 try {
  run('/usr/bin/git',['clone','--no-local','--no-checkout',repo,target]);
  git(target,['checkout','--detach',Q027_BASELINE]);git(target,['update-ref','refs/remotes/origin/main',Q027_BASELINE]);
  const q=q027Proposal(repo);
  if(git(target,['status','--porcelain=v1','--untracked-files=all'])!==''||git(target,['rev-parse','HEAD^{tree}'])!==Q027_BASELINE_TREE)throw new Error('Q027 original661 identity/cleanliness changed');
  for(const f of q.baseline665){const actual=heldQ018Bytes(path.join(target,f.relative));if(actual.bytes!==f.bytes||actual.sha256!==f.sha256||actual.executable!==(f.git_mode==='100755'))throw new Error('Q027 original661 source changed: '+f.relative);}
  if(git(target,['ls-files','-z']).split('\0').filter(Boolean).length!==665)throw new Error('Q027 original source count changed');
  prepareQ026FixedCloneOrigin(target);
  return target;
 }catch(e){fs.rmSync(target,{recursive:true,force:true});throw e;}
}
export function q027OriginalTestSource(repo) {
 if(arguments.length!==1)throw new Error('Q027 original test source accepts no caller targets');
 if(!q027Present(repo))return repo;
 if(q027OriginalTestSources.has(repo))return q027OriginalTestSources.get(repo);
 const target=q027CreateOriginalSource(repo);q027OriginalTestSources.set(repo,target);return target;
}
export function q027PredecessorSource(repo) {
 if(arguments.length!==1)throw new Error('Q027 predecessor source accepts no caller targets');
 if(!q027Present(repo))return repo;
 if(q027PredecessorSources.has(repo))return q027PredecessorSources.get(repo);
 const target=q027CreateOriginalSource(repo);q027PredecessorSources.set(repo,target);return target;
}
export function cleanupQ027PredecessorSources() {
 const retired=[];
 for(const target of q027PredecessorSources.values()){
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){bytes+=s.size;files++;}else throw new Error('unexpected owned Q027 predecessor snapshot');};
  walk(target);fs.rmSync(target,{recursive:true,force:true});if(fs.existsSync(target))throw new Error('owned Q027 predecessor snapshot not retired');
  retired.push({owned_scratch:target,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0});
 }
 q027PredecessorSources.clear();return retired;
}

export function cleanupQ027OriginalTestSources() {
 for(const target of q027OriginalTestSources.values()){
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){bytes+=s.size;files++;}else throw new Error('unexpected owned Q027 snapshot artifact');};
  walk(target);fs.rmSync(target,{recursive:true,force:true});if(fs.existsSync(target))throw new Error('owned Q027 test snapshot not retired');
  console.log(JSON.stringify({owned_scratch:target,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0}));
 }
 q027OriginalTestSources.clear();
}

export const Q028_AUTHORITY='docs/pilot/authorities/preparation-ca-ready-observation-successor-q028.json';
export const Q028_PROPOSAL='docs/pilot/proposals/preparation-ca-ready-observation-q028.json';
export const Q028_AUTHORITY_SHA='cf8fb14d8fa2edc885612f4fcdb6a8e007fb751ab13c188e26ca5e0836f79831';
export const Q028_PROPOSAL_SHA='899e4a7fe9d387cb433520c4a1fb35b3d8df13571ebc9a01c6a2358b7516849f';
export const Q028_BASELINE='6a05518e68a380bdeecd677525ca5d69d0194294';
export const Q028_BASELINE_TREE='8734a93d6d836199464c9a2a6e4f8dc6a8dc6083';
export const Q028_ORIGINAL_CANDIDATE='9c86f857aa1c740e596108d3abf6a70112cab8f1';
export const Q028_PARENT='internal/pilot/task0_parent.go';
export const Q028_OBSERVER='internal/pilot/task0_preparation_ca_ready_observation.go';
export const Q028_OBSERVER_SHA='cc2b82007cba193315507322cecc0e96ae59ddc5d893f985df289698af78052f';
export const Q028_TEST='internal/pilot/task0_preparation_ca_ready_observation_test.go';
export const Q028_PARENT_SHA='0ad98fe6f4c3c66e10caa78792adab562752793d9e7bebf509c037861ef8471c';
export const Q028_TEST_SHA='3c52587873511867391b4a3fb8f9826e8616f1dd6e59b3e903b6a5c2fce4385b';
export const Q028_WORK_PATHS=Object.freeze([Q028_PARENT,'scripts/ci/lib/b007-toolchain-security-q018.mjs','scripts/ci/lib/b007-successor.mjs','scripts/ci/test/b007-toolchain-security-q018.test.mjs','scripts/ci/test/b007-lifecycle.test.mjs']);
export const Q028_NEW_PATHS=Object.freeze([Q028_OBSERVER,Q028_TEST,Q028_AUTHORITY,Q028_PROPOSAL]);
const Q028_HISTORY_REF='refs/heads/codex/q028-fixed-history-pr37-merge';
export function q028Present(repo) {
 return [Q028_AUTHORITY,Q028_PROPOSAL].some(file=>{try{fs.lstatSync(path.join(repo,file));return true;}catch(e){return e.code!=='ENOENT';}});
}
export function q028Approved(repo) {
 try {
  if(!q027Approved(repo))return false;
  const a=json(repo,Q028_AUTHORITY,Q028_AUTHORITY_SHA),p=heldQ018Bytes(path.join(repo,Q028_PROPOSAL));
  return a.schema==='aipt.b007.preparation-ca-ready-observation-q028-authority/v1'&&a.decision_id==='AIPT-MVP-B007-OWNER-Q028'&&a.state==='OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI'&&a.owner_instruction==='批准'
   &&equal(a.current_work_paths,Q028_WORK_PATHS)&&equal(a.new_exact_public_paths,Q028_NEW_PATHS)
   &&a.actual_Owner_approval_registration.sha256==='3f130cfddd1355181f3c204a4ea8ccbd84da89c7b848704e7daac4401cec21bf'&&a.approved_material.sha256==='33de2c25528cbcdec8a4c518ecb8f726ad19cc52b82edaf05ea8ee6abbb8679f'
   &&equal(a.mandatory_design_conditions,[{"condition":"明确沿用原 materialize+SETUP握手完成后、CA_READY前的全线程零能力边界。不能提前永久降为零能力后绕过原tmpfs/SETUP权限前提，也不能扩大SETUP的CAP_SETFCAP、PREP后置Cap0或主机权限。","id":"C1"},{"condition":"新Parent模式不得继承旧p.retire()杀PREP来代替SETUP Wait。SETUP join未知时Parent/PREP/外层持续保留输入和CA；正常返回必须先有SETUP真实Cmd.Wait或明确NoSpawn，再有Parent对PREP真实Wait，再有外层对Parent真实Wait。","id":"C2"},{"condition":"新PREP是独立固定入口与绑定，不能调用RunAcceptedTask0Preparation、完整admitCA或生产业务路径后假设停住。采用受限固定原语/专用代码验证完整CA_READY后不发送CA_ADMIT/CA_RESAMPLE/CA_CONFIRMED；SETUP不收到CREATE或任何业务角色请求。","id":"C3"},{"condition":"PREP及SETUP两层都须在Start前保持强Cmd/control/input owner，取得真实ProcessState/Wait或严格NoSpawn；不能盲沿用旧launchTask0Setup的Start后owner布局。可在新固定观测文件实现所需所有权；若必须修改受保护helper，先新Owner决定。","id":"C4"},{"condition":"新固定Parent/PREP映像与专用绑定逐字节/SHA/来源资格证明，原a20/b05、既有静态程序和四once claim保持历史不变。外环境固定无凭据，PREP仅新固定非凭据marker；不读真实连接/秘密/GGUF正文，不写原DB/budget/evidence/key。","id":"C5"},{"condition":"两层固定无秘密类型收据绑定各自nonce/generation/映像/CA和目录身份，区分SETUP创建、NoSpawn、真实Wait、退出/错误、PREP真实Wait。PID消失、kill请求、外层Wait、PREP exit=-1、CA_READY标签均不能替代SETUP Wait。持续signals/软期限/封存错误不能释放未知owner；失败消费唯一新claim且不重试。","id":"C6"},{"condition":"5M4A/673/保护664只为预计，不是已验证路径集合。旧Parent签名/生产nil分支、Q025/Q026/Q027、原生产PREP/CA admission/SETUP/privilege/retained-input代码均冻结。需要其他路径、原合同/角色、权限或一般后继时停止并另给具体Owner材料，不能为凑计数削弱回收。","id":"C7"},{"condition":"Owner批准后才做隔离无模型/DB写/真实claim的可行性与失效检查。完整新源码/SDK/H1/依赖回归、同代理与Root、精确candidateCI5、另批最终merge、mergeCI5、具体FD3/4/5与signal/Wait准入、实际一次见证全部仍需实际完成。原8生产门禁、USD5非QUAL/QUAL0不提升，不关闭B007/MVP。","id":"C8"}])
   &&a.proposal_binding.path===Q028_PROPOSAL&&a.proposal_binding.sha256===Q028_PROPOSAL_SHA&&p.sha256===Q028_PROPOSAL_SHA&&p.bytes===a.proposal_binding.bytes
   &&equal(a.baseline,{commit:Q028_BASELINE,tree:Q028_BASELINE_TREE,parents:[Q027_BASELINE,Q028_ORIGINAL_CANDIDATE]})
   &&a.retained_Q027_authority_sha256===Q027_AUTHORITY_SHA&&a.retained_Q027_proposal_sha256===Q027_PROPOSAL_SHA
   &&a.parent_binding.sha256===Q028_PARENT_SHA&&a.test_binding.sha256===Q028_TEST_SHA&&a.observer_binding.sha256===Q028_OBSERVER_SHA
   &&a.combined_source_count===673&&a.protected_current_paths===664&&a.maximum_direct_PREP_children===1&&a.maximum_SETUP_children===1&&a.distinct_CA_READY_maximum_attempts===1
   &&equal(a.fixed_child_marker,{"name":"DEEPSEEK_API_KEY","value":"AIPT_Q028_CA_READY_OBSERVATION_ONLY_NOT_A_PROVIDER_CREDENTIAL","reason":"Fixed dedicated no-model PREP marker only. Parent rejects inherited credential presence; SETUP never receives credentials or CREATE."})&&equal(a.original_four_claims_consumed,[1,1,1,1])&&a.isolated_NONCANON_acceptance_sha256==='c3a1350f00e2c3390face1db8aea551c24d01d1b38da74866a84768b6c87879c'
   &&a.materialize_and_SETUP_admission_before_PREP_all_thread_Cap0===true&&a.dedicated_fixed_PREP_entry_and_new_images_required===true&&a.parent_CA_ADMIT_CA_RESAMPLE_CA_CONFIRMED_forbidden===true&&a.SETUP_CREATE_and_business_requests_forbidden===true&&a.pre_Start_strong_PREP_and_SETUP_owners_required===true&&a.SETUP_actual_Wait_or_NoSpawn_then_PREP_actual_Wait_then_outer_actual_Wait_required===true&&a.unknown_two_level_or_outer_join_retains_holders_and_signals_forever===true&&a.old_PREP_kill_never_substitutes_SETUP_Wait===true&&a.reject_provider_credential_presence_before_input===true&&a.fixed_nonsecret_observation_only===true&&a.same_independent_agent_and_Root_full673_HIGH_and_exact_CI_each5_required===true&&a.separate_final_Owner_merge_approval_required===true&&a.SDK_execution_interval_source_stability_owner_accepted===true&&a.cannot_guarantee_same_UID_instant_replace_restore_detection===true&&a.isolated_NONCANON_feasibility_accepted_component_only===true
   &&!a.generic_followon_permission&&!a.SDK_copy_write_chmod_registry_retirement_authorized&&!a.original_Parent_or_DIAG_retry_authorized&&!a.original_Q025_Q026_Q027_repeat_authorized
   &&!a.new_DIAG_or_extra_budget_authorized&&!a.runtime_ready&&!a.paid_callable&&!a.valid_START_MODEL_permitted&&a.qualification_runs_authorized===0&&a.original_budget_usd==='5.00'&&a.all8_production_gates==='OPEN'&&a.B007==='OPEN';
 }catch{return false;}
}

export function q028Proposal(repo) {
 if(!q028Approved(repo))throw new Error('Q028 exact paired Owner authority/proposal absent or changed');
 const q=json(repo,Q028_PROPOSAL,Q028_PROPOSAL_SHA);
 if(q.baseline669.length!==669||q.protected664.length!==664||!equal(q.work_paths,Q028_WORK_PATHS)||!equal(q.new_paths,Q028_NEW_PATHS)
  ||!equal(q.protected664,q.baseline669.filter(v=>!Q028_WORK_PATHS.includes(v.relative))))throw new Error('Q028 exact669/664/5+4 scope invalid');
 return q;
}
function q028Select(repo,revision) {
 if(revision===Q028_BASELINE)return null;
 const f=q023Facts(repo,revision),history=git(repo,['rev-list','--first-parent',Q028_BASELINE+'..'+revision]).split('\n').filter(Boolean);
 if(!git(repo,['rev-list','--first-parent',revision]).split('\n').includes(Q028_BASELINE)||history.length!==1||history[0]!==revision)throw new Error('Q028 later or foreign first-parent history forbidden');
 if(equal(f.parents,[Q028_BASELINE]))return {candidate:f,merge:null};
 if(f.parents.length!==2||f.parents[0]!==Q028_BASELINE)throw new Error('Q028 candidate/merge ordered parents changed');
 const candidate=q023Facts(repo,f.parents[1]);
 if(!equal(candidate.parents,[Q028_BASELINE])||candidate.tree!==f.tree)throw new Error('Q028 normal merge requires exact direct candidate and identical tree');
 return {candidate,merge:f};
}
export function q028RevisionProblems(repo,revision,{baseline=false}={}) {
 const p=[];
 try {
  const q=q028Proposal(repo),resolved=git(repo,['rev-parse',revision+'^{commit}']),old=resolved===Q028_BASELINE;
  if(baseline&&!old)throw new Error('Q028 original source must be exact accepted PR37 merge');
  if(old){if(!equal(q023Facts(repo,resolved),{commit:Q028_BASELINE,tree:Q028_BASELINE_TREE,parents:[Q027_BASELINE,Q028_ORIGINAL_CANDIDATE]}))throw new Error('Q028 accepted baseline SHA/tree/ordered parents changed');}
  else q028Select(repo,resolved);
  const actual=q023CommittedSource(repo,resolved),expected=old?q.baseline669:q.protected664;
  const paths=(old?q.baseline669.map(v=>v.relative):[...q.protected664.map(v=>v.relative),...Q028_WORK_PATHS,...Q028_NEW_PATHS]).sort();
  if(actual.size!==paths.length||new Set(paths).size!==paths.length||!equal([...actual.keys()].sort(),paths))throw new Error('Q028 exact committed669/673 source set changed');
  for(const f of expected)if(!equal(actual.get(f.relative),{bytes:f.bytes,sha256:f.sha256,git_mode:f.git_mode,git_blob_oid:f.git_blob_oid}))p.push('Q028 frozen baseline/protected Git source changed: '+f.relative);
  if(!old){
   for(const file of [...Q028_WORK_PATHS,...Q028_NEW_PATHS])if(actual.get(file)?.git_mode!=='100644')p.push('Q028 committed work/Owner mode changed: '+file);
   for(const [file,digest]of [[Q028_AUTHORITY,Q028_AUTHORITY_SHA],[Q028_PROPOSAL,Q028_PROPOSAL_SHA],[Q028_PARENT,Q028_PARENT_SHA],[Q028_TEST,Q028_TEST_SHA],[Q028_OBSERVER,Q028_OBSERVER_SHA]])if(actual.get(file)?.sha256!==digest)p.push('Q028 committed exact Owner/runtime/test changed: '+file);
   const changed=git(repo,['diff','--name-status','--no-renames',Q028_BASELINE,resolved]).split('\n').filter(Boolean).map(line=>line.split('\t'));
   if(!equal(changed.map(v=>v[1]).sort(),[...Q028_WORK_PATHS,...Q028_NEW_PATHS].sort())||changed.some(([kind,file])=>kind!==(Q028_NEW_PATHS.includes(file)?'A':'M')))throw new Error('Q028 exact5modified+4added commit delta changed');
  }
 }catch(e){p.push('Q028 complete source revision fails closed: '+e.message);}
 return p;
}
export function q028Topology(repo) {
 let head=null,main=null,candidate=null,merge=null;const problems=[];
 try {
  q028Proposal(repo);head=git(repo,['rev-parse','HEAD^{commit}']);main=git(repo,['rev-parse','refs/remotes/origin/main^{commit}']);
  if(!equal(q023Facts(repo,Q028_BASELINE),{commit:Q028_BASELINE,tree:Q028_BASELINE_TREE,parents:[Q027_BASELINE,Q028_ORIGINAL_CANDIDATE]})
   ||!equal(q023Facts(repo,Q028_ORIGINAL_CANDIDATE),{commit:Q028_ORIGINAL_CANDIDATE,tree:Q028_BASELINE_TREE,parents:[Q027_BASELINE]}))throw new Error('Q028 fixed accepted PR37 candidate/merge identity changed');
  const h=q028Select(repo,head),m=q028Select(repo,main);
  if(main!==Q028_BASELINE&&!m?.merge)throw new Error('Q028 accepted main must be fixed baseline or one normal merge');
  if(head===Q028_BASELINE&&main!==Q028_BASELINE)throw new Error('Q028 old construction cannot host accepted successor main');
  if(h&&m&&h.candidate.commit!==m.candidate.commit)throw new Error('Q028 checkout and main disagree on exact candidate');
  candidate=(h??m)?.candidate??null;merge=h?.merge??m?.merge??null;
 }catch(e){problems.push('Q028 exact single-successor topology fails closed: '+e.message);}
 return {head,main,candidate,merge,problems,accepted_baseline:Q028_BASELINE,original_Parent_entry_consumed:true,original_Parent_or_DIAG_retry_authorized:false};
}
export function q028LifecycleProblems(repo) {
 const p=[];
 try {
  p.push(...q028RevisionProblems(repo,Q028_BASELINE,{baseline:true}),...q027RevisionProblems(repo,Q028_BASELINE),...q027RevisionProblems(repo,Q028_ORIGINAL_CANDIDATE));
  p.push(...q027RevisionProblems(repo,Q027_BASELINE,{baseline:true}),...q026RevisionProblems(repo,Q027_BASELINE),...q026RevisionProblems(repo,Q027_ORIGINAL_CANDIDATE));
  p.push(...q026RevisionProblems(repo,Q026_BASELINE,{baseline:true}),...q025RevisionProblems(repo,Q026_BASELINE),...q025RevisionProblems(repo,Q026_ORIGINAL_CANDIDATE));
  p.push(...q025RevisionProblems(repo,Q025_BASELINE,{baseline:true}),...q024RevisionProblems(repo,Q025_BASELINE),...q024RevisionProblems(repo,Q025_ORIGINAL_CANDIDATE),
   ...q024RevisionProblems(repo,Q024_BASELINE,{original:true}),...q024RevisionProblems(repo,Q024_ORIGINAL_CANDIDATE,{original:true}),
   ...q023RevisionProblems(repo,Q023_BASELINE,{original:true}),...q022RevisionProblems(repo,Q022_BASELINE,{original:true}),...q021RevisionProblems(repo,Q021_BASELINE,{baseline:true}),...q023FixedDefinitionProblems(repo));
  if(git(repo,['rev-parse',BASE+'^{tree}'])!=='d91062ddb99d781a825e272a6365ed4effe97350')throw new Error('Q028 frozen accepted B006 BASE tree changed');
  q023CommittedSource(repo,BASE);
  for(const [id,tree]of [['f7c3736acd3524240ec178dc81e0a1c72a690930','bd09b4e24b8cb2c7db15bdb43cbd3d3fc8c9bcea'],['ec76d9c5cba0c32f3bb58c2a0abb9602f9ebe2d8','9ab33633cdf943571ca3693c15a53b4f0b3d2dd5']]){
   if(!equal(q023Facts(repo,id),{commit:id,tree,parents:[BASE]}))throw new Error('Q028 preserved failed source ancestry changed');q023CommittedSource(repo,id);
  }
  const t=q028Topology(repo);p.push(...t.problems);if(t.problems.length||!t.candidate)return [...new Set(p)];
  for(const revision of new Set([t.head,t.main,t.candidate.commit]))if(revision!==Q028_BASELINE)p.push(...q028RevisionProblems(repo,revision));
  for(const [file,want]of q023CommittedSource(repo,t.candidate.commit)){const actual=heldQ018Bytes(path.join(repo,file));if(actual.bytes!==want.bytes||actual.sha256!==want.sha256||actual.executable!==(want.git_mode==='100755'))p.push('Q028 working673 differs from exact candidate: '+file);}
 }catch(e){p.push('Q028 complete retained/successor lifecycle fails closed: '+e.message);}
 return [...new Set(p)];
}
export function q028SourceProblems(repo) {
 const p=currentQualificationProblems(repo);
 try {
  const q=q028Proposal(repo),expected=[...q.protected664.map(v=>v.relative),...Q028_WORK_PATHS,...Q028_NEW_PATHS].sort();
  const observed=git(repo,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);
  if(new Set(expected).size!==673||!equal([...new Set(observed)].sort(),expected))p.push('Q028 exact working673 source set changed');
  for(const f of q.protected664){const actual=heldQ018Bytes(path.join(repo,f.relative));if(actual.bytes!==f.bytes||actual.sha256!==f.sha256||actual.executable!==(f.git_mode==='100755'))p.push('Q028 protected664 source changed: '+f.relative);}
  for(const file of [...Q028_WORK_PATHS,...Q028_NEW_PATHS])if(heldQ018Bytes(path.join(repo,file)).executable)p.push('Q028 work/Owner execution mode changed: '+file);
  for(const [file,digest]of [[Q028_PARENT,Q028_PARENT_SHA],[Q028_TEST,Q028_TEST_SHA],[Q028_OBSERVER,Q028_OBSERVER_SHA]])if(heldQ018Bytes(path.join(repo,file)).sha256!==digest)p.push('Q028 exact reviewed runtime/test changed: '+file);
  p.push(...q028LifecycleProblems(repo));
 }catch(e){p.push('Q028 exact approved source contract fails closed: '+e.message);}
 return [...new Set(p)];
}
function q028CloneState(repo) {
 const q=q028Proposal(repo),identity=file=>{const v=heldQ018Bytes(file);return {bytes:v.bytes,sha256:v.sha256,executable:v.executable};};
 const paths=[...q.protected664.map(v=>v.relative),...Q028_WORK_PATHS,...Q028_NEW_PATHS].sort();
 return {head:git(repo,['rev-parse','HEAD']),tree:git(repo,['rev-parse','HEAD^{tree}']),main:git(repo,['rev-parse','refs/remotes/origin/main']),index:identity(git(repo,['rev-parse','--path-format=absolute','--git-path','index'])),source:paths.map(relative=>({relative,...identity(path.join(repo,relative))}))};
}
function q028ExactCloneRef(repo,ref) {
 const probe=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,'symbolic-ref','-q',ref],{encoding:'utf8',env:{PATH:'/usr/bin:/bin',GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(probe.error||probe.signal||![0,1].includes(probe.status))throw new Error('Q028 fixed clone-ref probe failed');
 if(probe.status===0)throw new Error('Q028 fixed clone ref is symbolic, including a dangling target');
 return q021CloneRef(repo,ref);
}
function q028FixedCloneOrigins() {return [...q027FixedCloneOrigins(),{ref:Q028_HISTORY_REF,commit:Q028_BASELINE,tree:Q028_BASELINE_TREE}];}
export function prepareQ028FixedCloneOrigin(repo) {
 if(arguments.length!==1)throw new Error('Q028 accepts no caller clone targets/options');
 const p=q028SourceProblems(repo);if(p.length)throw new Error('Q028 fixed clone prerequisites failed: '+p.join('; '));
 const before=q028CloneState(repo),origins=q028FixedCloneOrigins(),commands=[];
 if(origins.length!==10||new Set(origins.map(v=>v.ref)).size!==10)throw new Error('Q028 exact ten retained/current clone refs changed');
 for(const origin of origins){
  const parents=origin.commit===Q028_BASELINE?[Q027_BASELINE,Q028_ORIGINAL_CANDIDATE]:origin.commit===Q027_BASELINE?[Q026_BASELINE,Q027_ORIGINAL_CANDIDATE]:origin.commit===Q026_BASELINE?[Q025_BASELINE,Q026_ORIGINAL_CANDIDATE]:origin.commit===Q025_BASELINE?[Q024_BASELINE,Q025_ORIGINAL_CANDIDATE]:[BASE];
  if(!equal(q023Facts(repo,origin.commit),{commit:origin.commit,tree:origin.tree,parents}))throw new Error('Q028 fixed clone history SHA/tree/parents changed');
  const existing=q028ExactCloneRef(repo,origin.ref);
  if(existing!==null&&existing!==origin.commit)throw new Error('Q028 existing fixed clone ref differs; overwrite forbidden');
  commands.push((existing===null?'create ':'verify ')+origin.ref+' '+origin.commit);
 }
 run('/usr/bin/git',['--no-optional-locks','-C',repo,'update-ref','--no-deref','--stdin'],{input:'start\n'+commands.join('\n')+'\nprepare\ncommit\n',env:{...process.env,GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(!equal(before,q028CloneState(repo)))throw new Error('Q028 source/HEAD/tree/index/main changed during fixed clone preparation');
 const after=q028SourceProblems(repo);if(after.length||origins.some(v=>q028ExactCloneRef(repo,v.ref)!==v.commit))throw new Error('Q028 fixed clone postcheck failed');
 return {result:'PASS_Q028_FIXED_PR37_AND_NINE_RETAINED_LOCAL_CLONE_ORIGINS_PREPARED',fixed_ref:Q028_HISTORY_REF,commit:Q028_BASELINE,tree:Q028_BASELINE_TREE,fixed_origins:origins,source_HEAD_tree_index_origin_main_unchanged:true,SDK_program_or_mutation:0,network_requests:0,model_DIAG_QUAL:0,full_HIGH_or_CI_or_runtime_accepted:false};
}
const q028OriginalTestSources=new Map();
const q028PredecessorSources=new Map();

function q028CreateOriginalSource(repo) {
 prepareQ028FixedCloneOrigin(repo);
 const target=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q028-original-pr37-tests-'));
 try {
  run('/usr/bin/git',['clone','--no-local','--no-checkout',repo,target]);
  git(target,['checkout','--detach',Q028_BASELINE]);git(target,['update-ref','refs/remotes/origin/main',Q028_BASELINE]);
  const q=q028Proposal(repo);
  if(git(target,['status','--porcelain=v1','--untracked-files=all'])!==''||git(target,['rev-parse','HEAD^{tree}'])!==Q028_BASELINE_TREE)throw new Error('Q028 original669 identity/cleanliness changed');
  for(const f of q.baseline669){const actual=heldQ018Bytes(path.join(target,f.relative));if(actual.bytes!==f.bytes||actual.sha256!==f.sha256||actual.executable!==(f.git_mode==='100755'))throw new Error('Q028 original669 source changed: '+f.relative);}
  if(git(target,['ls-files','-z']).split('\0').filter(Boolean).length!==669)throw new Error('Q028 original source count changed');
  prepareQ027FixedCloneOrigin(target);
  return target;
 }catch(e){fs.rmSync(target,{recursive:true,force:true});throw e;}
}
export function q028OriginalTestSource(repo) {
 if(arguments.length!==1)throw new Error('Q028 original test source accepts no caller targets');
 if(!q028Present(repo))return repo;
 if(q028OriginalTestSources.has(repo))return q028OriginalTestSources.get(repo);
 const target=q028CreateOriginalSource(repo);q028OriginalTestSources.set(repo,target);return target;
}
export function q028PredecessorSource(repo) {
 if(arguments.length!==1)throw new Error('Q028 predecessor source accepts no caller targets');
 if(!q028Present(repo))return repo;
 if(q028PredecessorSources.has(repo))return q028PredecessorSources.get(repo);
 const target=q028CreateOriginalSource(repo);q028PredecessorSources.set(repo,target);return target;
}
export function cleanupQ028PredecessorSources() {
 const retired=[];
 for(const target of q028PredecessorSources.values()){
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){bytes+=s.size;files++;}else throw new Error('unexpected owned Q028 predecessor snapshot');};
  walk(target);fs.rmSync(target,{recursive:true,force:true});if(fs.existsSync(target))throw new Error('owned Q028 predecessor snapshot not retired');
  retired.push({owned_scratch:target,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0});
 }
 q028PredecessorSources.clear();return retired;
}

export function cleanupQ028OriginalTestSources() {
 for(const target of q028OriginalTestSources.values()){
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){bytes+=s.size;files++;}else throw new Error('unexpected owned Q028 snapshot artifact');};
  walk(target);fs.rmSync(target,{recursive:true,force:true});if(fs.existsSync(target))throw new Error('owned Q028 test snapshot not retired');
  console.log(JSON.stringify({owned_scratch:target,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0}));
 }
 q028OriginalTestSources.clear();
}




// Exact Q032 acquisition plus the separately approved Q033 workflow adapter.
export const Q032_AUTHORITY='docs/pilot/authorities/ci-owned-official-sdk-acquisition-successor-q032.json';
export const Q032_PROPOSAL='docs/pilot/proposals/ci-owned-official-sdk-acquisition-q032.json';
export const Q032_AUTHORITY_SHA='2a2c6c9ed7b0384e50009748765bf7f4acaaecbae90271190d7b5f571df72eca';
export const Q032_PROPOSAL_SHA='9a17efa4eb9178b424a9f197cc644bb2e0580e1a51355e46d88ce2aa21ca8b90';
export const Q032_BASELINE='ab93c5c35281ef7d33a2bb2514fde8ee849c7f16';
export const Q032_BASELINE_TREE='c461bb1e866b833ecf746c317c340ced601543cc';
export const Q032_ORIGINAL_CANDIDATE='95507b1e3a5df7fd321165fb33711afa9989bbb4';
export const Q032_WORK_PATHS=Object.freeze([".github/workflows/ci.yml","scripts/ci/lib/b007-toolchain-security-q018.mjs","scripts/ci/lib/b007-successor.mjs","scripts/ci/test/b007-toolchain-security-q018.test.mjs","scripts/ci/test/b007-lifecycle.test.mjs","scripts/ci/validate/workflow.mjs"]);
export const Q032_NEW_PATHS=Object.freeze([Q032_AUTHORITY,Q032_PROPOSAL]);
const Q032_WORKFLOW_SHA='1801e78b63b0de4ca52ff2bc2367671eb895913e10e3e11d0f15fb8879fc6a27';
const Q032_ORIGINAL_VALIDATOR_SHA='3becc03aaae1c1a088147190a09688d90abe9e141e1d732064cc519040d8ff0a';
const Q032_ADAPTER_SHA='627a4ec15671f724e3ec7ddcf5f803ab85c21a3b3e45111108468b5c200718bc';
const Q032_ORIGINAL_RUN_SHA='599304756ba297d1459c6709c875a12199ca01443ba28295cfe7877b06966d24';
const Q032_ORIGINAL_REPORT_SHA='d0074e095e6c2e4b77bf3069b6f462f91468196bb6e903357d268435e8ec5778';
const Q032_SDK_CORE_SHA='40927dff4a726903bec78ff331904f29a032618d57a6be97f4311e257f8bc78a';
const Q032_VALIDATOR_IMPORT="import { q032Present, runQ032WorkflowValidation } from '../lib/b007-toolchain-security-q018.mjs';\n";
const Q032_VALIDATOR_WRAPPER="export function run(ctx) {\n  if (q032Present(ctx.repo)) return runQ032WorkflowValidation(ctx, originalRun);\n  return originalRun(ctx);\n}\n\nfunction originalRun(ctx) {";
const Q032_ARCHIVE=Object.freeze({url:'https://dl.google.com/go/go1.26.9.linux-amd64.tar.gz',filename:'go1.26.9.linux-amd64.tar.gz',bytes:66935201,sha256:'42d158b4d8f7b61ac0a830567c940a86098fb7aac52e467a5ebec03ef5cc2f8d'});
const Q032_HISTORY_REF='refs/heads/codex/q032-fixed-history-pr38-merge';
export function q032Present(repo) {
 return [Q032_AUTHORITY,Q032_PROPOSAL].some(file=>{try{fs.lstatSync(path.join(repo,file));return true;}catch(e){return e.code!=='ENOENT';}});
}
export function q032Approved(repo) {
 try{
  if(!q028Approved(repo))return false;
  const a=json(repo,Q032_AUTHORITY,Q032_AUTHORITY_SHA),p=heldQ018Bytes(path.join(repo,Q032_PROPOSAL));
  return a.schema==='aipt.b007.ci-owned-official-SDK-q032-q033-authority/v1'&&equal(a.decision_ids,['AIPT-MVP-B007-OWNER-Q032','AIPT-MVP-B007-OWNER-Q033'])&&a.state==='OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI'&&a.owner_instruction==='批准'
   &&equal(a.current_work_paths,Q032_WORK_PATHS)&&equal(a.new_exact_public_paths,Q032_NEW_PATHS)&&a.combined_source_count===675&&a.protected_current_paths===667
   &&a.Q032_approval_sha256==='0c57aa11d5f150cc58eb8eb11fb897a78384673b463cb4c7bee4caa3d5a14c25'&&a.Q033_approval_sha256==='b4d31065b0fdab70af8d7fff145257689a023e1adb7c6a080448163b06c70aef'
   &&a.proposal_binding.path===Q032_PROPOSAL&&a.proposal_binding.sha256===Q032_PROPOSAL_SHA&&p.sha256===Q032_PROPOSAL_SHA&&p.bytes===a.proposal_binding.bytes
   &&equal(a.baseline,{commit:Q032_BASELINE,tree:Q032_BASELINE_TREE,parents:[Q028_BASELINE,Q032_ORIGINAL_CANDIDATE]})&&equal(a.archive,Q032_ARCHIVE)&&a.retained_Q028_authority_sha256===Q028_AUTHORITY_SHA&&a.retained_Q028_proposal_sha256===Q028_PROPOSAL_SHA&&a.qualification_sha256===Q018_QUALIFICATION_SHA
   &&a.fixed_current_workflow_sha256===Q032_WORKFLOW_SHA&&a.original_workflow_validator_sha256===Q032_ORIGINAL_VALIDATOR_SHA&&a.exact_validator_adapter_sha256===Q032_ADAPTER_SHA&&a.original_complete_workflow_report_sha256===Q032_ORIGINAL_REPORT_SHA&&a.original_SDK_core_sha256===Q032_SDK_CORE_SHA
   &&equal(a.original_four_claims_consumed,[1,1,1,1])&&a.original_budget_usd==='5.00'&&a.qualification_runs_authorized===0&&a.all8_production_gates==='OPEN'&&a.B007==='OPEN'
   &&a.full675_same_agent_Root_and_candidate_merge_CI_each5_required===true&&a.separate_exact_public_source_body_destination_release_required===true&&a.separate_final_Owner_merge_approval_required===true&&a.Q028_C1_C8_remaining_admission_unchanged===true&&a.SDK_execution_interval_source_stability_owner_accepted===true&&a.cannot_guarantee_same_UID_instant_replace_restore_detection===true
   &&!a.generic_followon_permission&&!a.preinstalled_SDK_mutation_or_fallback_authorized&&!a.SDK_qualification_or_dependency_registry_change_authorized&&!a.production_Go_or_namespace_changes_authorized&&!a.original_Parent_or_DIAG_retry_authorized&&!a.new_DIAG_or_extra_budget_authorized&&!a.runtime_ready&&!a.paid_callable&&!a.valid_START_MODEL_permitted;
 }catch{return false;}
}
export function q032Proposal(repo) {
 if(!q032Approved(repo))throw new Error('Q032/Q033 exact paired approvals/proposal absent or changed');
 const q=json(repo,Q032_PROPOSAL,Q032_PROPOSAL_SHA);
 if(q.baseline673.length!==673||q.protected667.length!==667||!equal(q.work_paths,Q032_WORK_PATHS)||!equal(q.new_paths,Q032_NEW_PATHS)||!equal(q.protected667,q.baseline673.filter(v=>!Q032_WORK_PATHS.includes(v.relative)))||!equal(q.archive,Q032_ARCHIVE))throw new Error('Q032/Q033 exact673/667/6+2 scope invalid');
 return q;
}
function q032Select(repo,revision) {
 if(revision===Q032_BASELINE)return null;
 const f=q023Facts(repo,revision),history=git(repo,['rev-list','--first-parent',Q032_BASELINE+'..'+revision]).split('\n').filter(Boolean);
 if(!git(repo,['rev-list','--first-parent',revision]).split('\n').includes(Q032_BASELINE)||history.length!==1||history[0]!==revision)throw new Error('Q032 later or foreign first-parent history forbidden');
 if(equal(f.parents,[Q032_BASELINE]))return {candidate:f,merge:null};
 if(f.parents.length!==2||f.parents[0]!==Q032_BASELINE)throw new Error('Q032 ordered candidate/normal merge parents changed');
 const candidate=q023Facts(repo,f.parents[1]);if(!equal(candidate.parents,[Q032_BASELINE])||candidate.tree!==f.tree)throw new Error('Q032 normal merge requires exact sole-baseline child and identical tree');
 return {candidate,merge:f};
}
export function q032RevisionProblems(repo,revision,{baseline=false}={}) {
 const p=[];
 try{
  const q=q032Proposal(repo),resolved=git(repo,['rev-parse',revision+'^{commit}']),old=resolved===Q032_BASELINE;
  if(baseline&&!old)throw new Error('Q032 original source must be exact accepted PR38 merge');
  if(old){if(!equal(q023Facts(repo,resolved),{commit:Q032_BASELINE,tree:Q032_BASELINE_TREE,parents:[Q028_BASELINE,Q032_ORIGINAL_CANDIDATE]}))throw new Error('Q032 original baseline SHA/tree/parents changed');}else q032Select(repo,resolved);
  const actual=q023CommittedSource(repo,resolved),expected=old?q.baseline673:q.protected667,paths=(old?q.baseline673.map(v=>v.relative):[...q.protected667.map(v=>v.relative),...Q032_WORK_PATHS,...Q032_NEW_PATHS]).sort();
  if(actual.size!==paths.length||new Set(paths).size!==paths.length||!equal([...actual.keys()].sort(),paths))throw new Error('Q032 exact committed673/675 source set changed');
  for(const f of expected)if(!equal(actual.get(f.relative),{bytes:f.bytes,sha256:f.sha256,git_mode:f.git_mode,git_blob_oid:f.git_blob_oid}))p.push('Q032 protected baseline/Git source changed: '+f.relative);
  if(!old){
   for(const file of [...Q032_WORK_PATHS,...Q032_NEW_PATHS])if(actual.get(file)?.git_mode!=='100644')p.push('Q032 committed work/Owner mode changed: '+file);
   for(const [file,digest]of [[Q032_AUTHORITY,Q032_AUTHORITY_SHA],[Q032_PROPOSAL,Q032_PROPOSAL_SHA],['.github/workflows/ci.yml',Q032_WORKFLOW_SHA],['scripts/ci/validate/workflow.mjs',Q032_ADAPTER_SHA]])if(actual.get(file)?.sha256!==digest)p.push('Q032 committed exact Owner/workflow/adapter changed: '+file);
   const delta=git(repo,['diff','--name-status','--no-renames',Q032_BASELINE,resolved]).split('\n').filter(Boolean).map(s=>s.split('\t'));
   if(!equal(delta.map(v=>v[1]).sort(),[...Q032_WORK_PATHS,...Q032_NEW_PATHS].sort())||delta.some(([kind,file])=>kind!==(Q032_NEW_PATHS.includes(file)?'A':'M')))throw new Error('Q032 exact6modified+2added delta changed');
  }
 }catch(e){p.push('Q032 complete source revision fails closed: '+e.message);}
 return p;
}
export function q032Topology(repo) {
 let head=null,main=null,candidate=null,merge=null;const problems=[];
 try{
  q032Proposal(repo);head=git(repo,['rev-parse','HEAD^{commit}']);main=git(repo,['rev-parse','refs/remotes/origin/main^{commit}']);
  if(!equal(q023Facts(repo,Q032_BASELINE),{commit:Q032_BASELINE,tree:Q032_BASELINE_TREE,parents:[Q028_BASELINE,Q032_ORIGINAL_CANDIDATE]})||!equal(q023Facts(repo,Q032_ORIGINAL_CANDIDATE),{commit:Q032_ORIGINAL_CANDIDATE,tree:Q032_BASELINE_TREE,parents:[Q028_BASELINE]}))throw new Error('Q032 fixed PR38 candidate/merge identity changed');
  const h=q032Select(repo,head),m=q032Select(repo,main);
  if(main!==Q032_BASELINE&&!m?.merge)throw new Error('Q032 accepted main must be fixed baseline or one normal merge');
  if(head===Q032_BASELINE&&main!==Q032_BASELINE)throw new Error('Q032 old construction cannot host accepted successor main');
  if(h&&m&&h.candidate.commit!==m.candidate.commit)throw new Error('Q032 checkout/main exact candidate disagree');
  candidate=(h??m)?.candidate??null;merge=h?.merge??m?.merge??null;
 }catch(e){problems.push('Q032 exact one-successor topology fails closed: '+e.message);}
 return {head,main,candidate,merge,problems,accepted_baseline:Q032_BASELINE,original_Parent_entry_consumed:true,original_Parent_or_DIAG_retry_authorized:false};
}
export function q032LifecycleProblems(repo) {
 const p=[];
 try{
  p.push(...q032RevisionProblems(repo,Q032_BASELINE,{baseline:true}),...q028RevisionProblems(repo,Q032_BASELINE),...q028RevisionProblems(repo,Q032_ORIGINAL_CANDIDATE));
  p.push(...q028RevisionProblems(repo,Q028_BASELINE,{baseline:true}),...q027RevisionProblems(repo,Q028_BASELINE),...q027RevisionProblems(repo,Q028_ORIGINAL_CANDIDATE));
  p.push(...q027RevisionProblems(repo,Q027_BASELINE,{baseline:true}),...q026RevisionProblems(repo,Q027_BASELINE),...q026RevisionProblems(repo,Q027_ORIGINAL_CANDIDATE));
  p.push(...q026RevisionProblems(repo,Q026_BASELINE,{baseline:true}),...q025RevisionProblems(repo,Q026_BASELINE),...q025RevisionProblems(repo,Q026_ORIGINAL_CANDIDATE));
  p.push(...q025RevisionProblems(repo,Q025_BASELINE,{baseline:true}),...q024RevisionProblems(repo,Q025_BASELINE),...q024RevisionProblems(repo,Q025_ORIGINAL_CANDIDATE),
   ...q024RevisionProblems(repo,Q024_BASELINE,{original:true}),...q024RevisionProblems(repo,Q024_ORIGINAL_CANDIDATE,{original:true}),
   ...q023RevisionProblems(repo,Q023_BASELINE,{original:true}),...q022RevisionProblems(repo,Q022_BASELINE,{original:true}),...q021RevisionProblems(repo,Q021_BASELINE,{baseline:true}),...q023FixedDefinitionProblems(repo));
  if(git(repo,['rev-parse',BASE+'^{tree}'])!=='d91062ddb99d781a825e272a6365ed4effe97350')throw new Error('Q028 frozen accepted B006 BASE tree changed');
  q023CommittedSource(repo,BASE);
  for(const [id,tree]of [['f7c3736acd3524240ec178dc81e0a1c72a690930','bd09b4e24b8cb2c7db15bdb43cbd3d3fc8c9bcea'],['ec76d9c5cba0c32f3bb58c2a0abb9602f9ebe2d8','9ab33633cdf943571ca3693c15a53b4f0b3d2dd5']]){
   if(!equal(q023Facts(repo,id),{commit:id,tree,parents:[BASE]}))throw new Error('Q028 preserved failed source ancestry changed');q023CommittedSource(repo,id);
  }

  const t=q032Topology(repo);p.push(...t.problems);if(t.problems.length||!t.candidate)return [...new Set(p)];
  for(const revision of new Set([t.head,t.main,t.candidate.commit]))if(revision!==Q032_BASELINE)p.push(...q032RevisionProblems(repo,revision));
  for(const [file,want]of q023CommittedSource(repo,t.candidate.commit)){const actual=heldQ018Bytes(path.join(repo,file));if(actual.bytes!==want.bytes||actual.sha256!==want.sha256||actual.executable!==(want.git_mode==='100755'))p.push('Q032 working675 differs from exact candidate: '+file);}
 }catch(e){p.push('Q032 complete retained/successor lifecycle fails closed: '+e.message);}
 return [...new Set(p)];
}
function q032PreservedCoreProblems(repo) {
 const p=[];
 const source=heldQ018Bytes(path.join(repo,'scripts/ci/lib/b007-toolchain-security-q018.mjs')).raw.toString();
 const a=source.indexOf('\nexport function verifySDK(root,spec) {')+1,z=source.indexOf('\nfunction currentSDKProof(repo,root) {')+1;
 if(a<0||z<=a||hash(source.slice(a,z))!==Q032_SDK_CORE_SHA)p.push('Q032 original SDK verification/identity core changed');
 const adapter=heldQ018Bytes(path.join(repo,'scripts/ci/validate/workflow.mjs'));
 const text=adapter.raw.toString();
 if(adapter.sha256!==Q032_ADAPTER_SHA||text.split(Q032_VALIDATOR_IMPORT).length!==2||text.split(Q032_VALIDATOR_WRAPPER).length!==2||hash(text.replace(Q032_VALIDATOR_IMPORT,'').replace(Q032_VALIDATOR_WRAPPER,'export function run(ctx) {'))!==Q032_ORIGINAL_VALIDATOR_SHA)p.push('Q033 exact adapter must preserve complete original validator');
 return p;
}
export function q032SourceProblems(repo) {
 const p=currentQualificationProblems(repo);
 try{
  const q=q032Proposal(repo),expected=[...q.protected667.map(v=>v.relative),...Q032_WORK_PATHS,...Q032_NEW_PATHS].sort(),observed=git(repo,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);
  if(new Set(expected).size!==675||!equal([...new Set(observed)].sort(),expected))p.push('Q032 exact working675 source set changed');
  for(const f of q.protected667){const actual=heldQ018Bytes(path.join(repo,f.relative));if(actual.bytes!==f.bytes||actual.sha256!==f.sha256||actual.executable!==(f.git_mode==='100755'))p.push('Q032 protected667 source changed: '+f.relative);}
  for(const file of [...Q032_WORK_PATHS,...Q032_NEW_PATHS])if(heldQ018Bytes(path.join(repo,file)).executable)p.push('Q032 work/Owner executable mode changed: '+file);
  if(heldQ018Bytes(path.join(repo,'.github/workflows/ci.yml')).sha256!==Q032_WORKFLOW_SHA)p.push('Q032 exact reviewed current workflow changed');
  p.push(...q032PreservedCoreProblems(repo),...q032LifecycleProblems(repo));
 }catch(e){p.push('Q032 exact approved source contract fails closed: '+e.message);}
 return [...new Set(p)];
}
function q032CloneState(repo) {
 const q=q032Proposal(repo),identity=file=>{const v=heldQ018Bytes(file);return {bytes:v.bytes,sha256:v.sha256,executable:v.executable};};
 const paths=[...q.protected667.map(v=>v.relative),...Q032_WORK_PATHS,...Q032_NEW_PATHS].sort();
 return {head:git(repo,['rev-parse','HEAD']),tree:git(repo,['rev-parse','HEAD^{tree}']),main:git(repo,['rev-parse','refs/remotes/origin/main']),index:identity(git(repo,['rev-parse','--path-format=absolute','--git-path','index'])),source:paths.map(relative=>({relative,...identity(path.join(repo,relative))}))};
}
function q032FixedCloneOrigins(){return [...q028FixedCloneOrigins(),{ref:Q032_HISTORY_REF,commit:Q032_BASELINE,tree:Q032_BASELINE_TREE}];}
export function prepareQ032FixedCloneOrigin(repo) {
 if(arguments.length!==1)throw new Error('Q032 accepts no caller clone targets/options');
 const problems=q032SourceProblems(repo);if(problems.length)throw new Error('Q032 fixed clone prerequisites failed: '+problems.join('; '));
 const before=q032CloneState(repo),origins=q032FixedCloneOrigins(),commands=[];
 if(origins.length!==11||new Set(origins.map(v=>v.ref)).size!==11)throw new Error('Q032 exact eleven fixed clone origins changed');
 for(const origin of origins){
  const parents=origin.commit===Q032_BASELINE?[Q028_BASELINE,Q032_ORIGINAL_CANDIDATE]:origin.commit===Q028_BASELINE?[Q027_BASELINE,Q028_ORIGINAL_CANDIDATE]:origin.commit===Q027_BASELINE?[Q026_BASELINE,Q027_ORIGINAL_CANDIDATE]:origin.commit===Q026_BASELINE?[Q025_BASELINE,Q026_ORIGINAL_CANDIDATE]:origin.commit===Q025_BASELINE?[Q024_BASELINE,Q025_ORIGINAL_CANDIDATE]:[BASE];
  if(!equal(q023Facts(repo,origin.commit),{commit:origin.commit,tree:origin.tree,parents}))throw new Error('Q032 fixed history SHA/tree/parents changed');
  const existing=q028ExactCloneRef(repo,origin.ref);if(existing!==null&&existing!==origin.commit)throw new Error('Q032 differing fixed clone ref cannot be overwritten');
  commands.push((existing===null?'create ':'verify ')+origin.ref+' '+origin.commit);
 }
 run('/usr/bin/git',['--no-optional-locks','-C',repo,'update-ref','--no-deref','--stdin'],{input:'start\n'+commands.join('\n')+'\nprepare\ncommit\n',env:{...process.env,GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 if(!equal(before,q032CloneState(repo)))throw new Error('Q032 source/HEAD/tree/main/index changed during fixed clone preparation');
 const after=q032SourceProblems(repo);if(after.length||origins.some(v=>q028ExactCloneRef(repo,v.ref)!==v.commit))throw new Error('Q032 fixed clone origin postcheck failed');
 return {result:'PASS_Q032_ELEVEN_FIXED_ORIGINS_PREPARED',commit:Q032_BASELINE,tree:Q032_BASELINE_TREE,fixed_origins:origins,source_HEAD_tree_index_origin_main_unchanged:true,SDK_program_or_mutation:0,network_requests:0,model_DIAG_QUAL:0,full_HIGH_or_CI_or_runtime_accepted:false};
}
const q032OriginalTestSources=new Map(),q032PredecessorSources=new Map();
function q032CreateOriginalSource(repo) {
 prepareQ032FixedCloneOrigin(repo);const target=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q032-original-pr38-'));
 try{
  run('/usr/bin/git',['clone','--no-local','--no-checkout',repo,target]);git(target,['checkout','--detach',Q032_BASELINE]);git(target,['update-ref','refs/remotes/origin/main',Q032_BASELINE]);
  const q=q032Proposal(repo);
  if(git(target,['status','--porcelain=v1','--untracked-files=all'])!==''||git(target,['rev-parse','HEAD^{tree}'])!==Q032_BASELINE_TREE||git(target,['ls-files','-z']).split('\0').filter(Boolean).length!==673)throw new Error('Q032 exact clean original673 identity changed');
  for(const f of q.baseline673){const actual=heldQ018Bytes(path.join(target,f.relative));if(actual.bytes!==f.bytes||actual.sha256!==f.sha256||actual.executable!==(f.git_mode==='100755'))throw new Error('Q032 original673 physical source changed: '+f.relative);}
  prepareQ028FixedCloneOrigin(target);return target;
 }catch(e){fs.rmSync(target,{recursive:true,force:true});throw e;}
}
export function q032OriginalTestSource(repo) {
 if(arguments.length!==1)throw new Error('Q032 original tests accept no caller targets');
 if(!q032Present(repo))return repo;if(!q032OriginalTestSources.has(repo))q032OriginalTestSources.set(repo,q032CreateOriginalSource(repo));return q032OriginalTestSources.get(repo);
}
export function q032PredecessorSource(repo) {
 if(arguments.length!==1)throw new Error('Q032 predecessor accepts no caller targets');
 if(!q032Present(repo))return repo;if(!q032PredecessorSources.has(repo))q032PredecessorSources.set(repo,q032CreateOriginalSource(repo));return q032PredecessorSources.get(repo);
}
function q032RetireSources(sources) {
 const retired=[];
 for(const target of sources.values()){
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){bytes+=s.size;files++;}else throw new Error('unexpected owned Q032 source artifact');};
  walk(target);fs.rmSync(target,{recursive:true});if(fs.existsSync(target))throw new Error('owned Q032 source not retired');retired.push({owned_scratch:target,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0});
 }
 sources.clear();return retired;
}
export function cleanupQ032PredecessorSources(){return q032RetireSources(q032PredecessorSources);}
export function cleanupQ032OriginalTestSources(){for(const r of q032RetireSources(q032OriginalTestSources))console.log(JSON.stringify(r));}
export function runQ032WorkflowValidation(ctx,originalRun) {
 let original=null;const problems=[];let target=null;
 try{
  if(arguments.length!==2||typeof originalRun!=='function'||hash(originalRun.toString())!==Q032_ORIGINAL_RUN_SHA)throw new Error('Q033 exact complete original run function required');
  problems.push(...q032SourceProblems(ctx.repo));if(problems.length)throw new Error('Q032 current source/workflow validation failed');
  target=q032PredecessorSource(ctx.repo);
  if(heldQ018Bytes(path.join(target,'scripts/ci/validate/workflow.mjs')).sha256!==Q032_ORIGINAL_VALIDATOR_SHA||heldQ018Bytes(path.join(target,'.github/workflows/ci.yml')).sha256!=='5c0f81fa51bc51b494f8cb768a080262f64d4b3eed0e0c3c3ba8eddc3f56b4ef')throw new Error('Q033 fixed original validator/workflow identity changed');
  original=originalRun({repo:target});
  if(original?.result!=='PASS'||hash(JSON.stringify(original))!==Q032_ORIGINAL_REPORT_SHA)throw new Error('Q033 complete unfiltered fixed-ab93 original workflow report changed or failed');
  problems.push(...q032SourceProblems(ctx.repo));
 }catch(e){problems.push(e.message);}
 finally{try{cleanupQ032PredecessorSources();}catch(e){problems.push(e.message);}}
 return {name:'workflow',result:problems.length?'FAIL':'PASS',details:problems.length?problems.map(v=>'FAIL: '+v):['ok: exact approved Q032/Q033 current675 workflow/source/history identity','ok: complete unchanged original workflow validation and every original negative probe passed at fixed ab93'],current_workflow:{sha256:Q032_WORKFLOW_SHA,source_files:675,protected_original:667,mode:'EXACT_Q032_Q033_CURRENT_SOURCE_WORKFLOW_GUARD'},original_complete_workflow_report:original,original_validation_target:{commit:Q032_BASELINE,tree:Q032_BASELINE_TREE,mode:'COMPLETE_UNCHANGED_ORIGINAL_AT_FIXED_AB93'},original_rejection_of_Q032_draft_retained:true,external_github_requests:0,model_DIAG_QUAL:0,runtime_ready:false,paid_callable:false};
}

// Q032/Q033: fixed job-owned acquisition; original SDK verifiers stay intact.
const Q032_RECEIPT='acquisition-receipt.json';
const q032OwnerFields=['dev','ino','uid','gid','mode'];
function q032OwnerIdentity(s) {return q032OwnerFields.map(k=>String(s[k]));}
function q032PhysicalDirectory(location,{privateMode=false}={}) {
 if(typeof location!=='string'||!path.isAbsolute(location)||location!==path.normalize(location)||location==='/'||/[\r\n\0]/.test(location))throw new Error('Q032 physical absolute directory required');
 const s=fs.lstatSync(location,{bigint:true});
 if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==BigInt(process.getuid())||fs.realpathSync(location)!==location||(privateMode&&(s.mode&0o777n)!==0o700n))throw new Error('Q032 directory identity/owner/mode rejected');
 return q032OwnerIdentity(s);
}
function q032AssertOwned(location,identity) {
 if(!equal(q032PhysicalDirectory(location,{privateMode:true}),identity))throw new Error('Q032 owned acquisition directory replaced');
}
function q032Context(repo) {
 if(process.platform!=='linux'||process.arch!=='x64'||process.version!=='v24.19.0')throw new Error('Q032 fixed Linux x64 Node24.19.0 required');
 const e=process.env;
 if(e.CI!=='true'||e.GITHUB_ACTIONS!=='true'||e.GITHUB_REPOSITORY!=='zyc14588/AIPT'||!['toolchain','supply-chain','storage-postgres'].includes(e.GITHUB_JOB)||e.RUNNER_OS!=='Linux'||e.RUNNER_ARCH!=='X64'||e.GOENV!=='off'||e.GOTOOLCHAIN!=='local'||e.GOROOT)throw new Error('Q032 exact current CI job/environment required');
 if(!/^[1-9][0-9]*$/.test(e.GITHUB_RUN_ID??'')||e.GITHUB_RUN_ATTEMPT!=='1'||path.resolve(e.GITHUB_WORKSPACE??'')!==path.resolve(repo))throw new Error('Q032 exact job/workspace/initial attempt required');
 if(!((e.GITHUB_EVENT_NAME==='pull_request'&&/^refs\/pull\/[1-9][0-9]*\/merge$/.test(e.GITHUB_REF??''))||(e.GITHUB_EVENT_NAME==='push'&&e.GITHUB_REF==='refs/heads/main')))throw new Error('Q032 current PR/main event required');
 const problems=q032SourceProblems(repo),topology=q032Topology(repo);
 if(problems.length||topology.problems.length||!topology.candidate)throw new Error('Q032 current exact source/candidate gate failed: '+problems.join('; '));
 const temp=e.RUNNER_TEMP;q032PhysicalDirectory(temp);
 return {run_id:e.GITHUB_RUN_ID,attempt:e.GITHUB_RUN_ATTEMPT,job:e.GITHUB_JOB,workspace:path.resolve(repo),head:git(repo,['rev-parse','HEAD']),tree:git(repo,['rev-parse','HEAD^{tree}']),temp};
}
function q032ArchiveSpec(repo) {
 const s=sdkSpec(repo,'1.26.9');
 if(!equal(s.archive,Q032_ARCHIVE)||s.files.length!==15045||s.directories.length!==1667||s.files.some(f=>f.relative==='setup.sh'))throw new Error('Q032 original official archive derivation changed');
 return s;
}
function q032Command(program,args,commands,{archiveFD=null}={}) {
 if(!['/usr/bin/curl','/usr/bin/tar'].includes(program))throw new Error('Q032 fixed acquisition command required');
 const row={program,args:[...args],attempt_registered_before_spawn:true,returned:false,pid:null,status:null,signal:null,direct_child_waited:false,all_command_owners_retired:false};commands.push(row);
 let child;
 try {child=spawnSync(program,args,{stdin:'ignore',encoding:'utf8',maxBuffer:65536,stdio:archiveFD===null?['ignore','pipe','pipe']:['ignore','pipe','pipe',archiveFD],env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8'}});}
 catch(error){row.error=String(error.message);throw error;}
 row.returned=true;row.pid=child.pid??null;row.status=child.status??null;row.signal=child.signal??null;
 row.direct_child_waited=Number.isInteger(child.pid)&&child.pid>0&&(Number.isInteger(child.status)||typeof child.signal==='string');
 // A normal synchronous exit also lets the fixed curl/tar program finish
 // its own helpers. Spawn/signal/transport uncertainty retains the directory.
 row.all_command_owners_retired=row.direct_child_waited&&Number.isInteger(child.status)&&!child.signal&&!child.error;
 if(child.error)row.error=String(child.error.message);
 if(!row.all_command_owners_retired||child.status!==0)throw new Error('Q032 acquisition command failed: '+path.basename(program)+' ('+(child.status??child.signal??'unknown-spawn')+')');
 return row;
}
function q032HeldArchive(fd,location,spec) {
 const before=fs.lstatSync(location,{bigint:true}),held=fs.fstatSync(fd,{bigint:true});
 if(!before.isFile()||before.nlink!==1n||before.uid!==BigInt(process.getuid())||(before.mode&0o777n)!==0o600n||before.size!==BigInt(spec.archive.bytes)||!q021Same(before,held))throw new Error('Q032 archive physical size/owner/identity mismatch');
 const digest=createHash('sha256'),buffer=Buffer.allocUnsafe(1<<20);let count=0,n;
 while((n=fs.readSync(fd,buffer,0,buffer.length,count))>0){count+=n;if(count>spec.archive.bytes)throw new Error('Q032 archive grew');digest.update(buffer.subarray(0,n));}
 if(count!==spec.archive.bytes||digest.digest('hex')!==spec.archive.sha256||!q021Same(before,fs.fstatSync(fd,{bigint:true}))||!q021Same(before,fs.lstatSync(location,{bigint:true})))throw new Error('Q032 fixed official archive digest/stability mismatch');
 return before;
}
function q032WriteReceipt(location,value) {
 const fd=fs.openSync(location,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
 let primary=null;
 try{fs.writeFileSync(fd,JSON.stringify(value)+'\n');fs.fchmodSync(fd,0o400);fs.fsyncSync(fd);}catch(error){primary=error;}
 try{fs.closeSync(fd);}catch(close){
  primary??=close;
  primary.q032ReceiptCloseError=String(close.message);
  primary.q032ReceiptCloseUncertain=true;
  primary.q032ReceiptPath=location;
 }
 if(primary)throw primary;
}
function q032Publication(location,root,owner) {
 if(typeof location!=='string'||!path.isAbsolute(location)||location!==path.normalize(location)||/[\r\n\0]/.test(location))throw new Error('Q032 exact GITHUB_PATH file required');
 const temp=process.env.RUNNER_TEMP;
 if(!location.startsWith(temp+path.sep)||fs.realpathSync(path.dirname(location))!==path.dirname(location))throw new Error('Q032 GITHUB_PATH must be physical within job temporary input');
 q032AssertOwned(root,owner);
 const before=fs.lstatSync(location,{bigint:true});
 if(!before.isFile()||before.nlink!==1n||before.uid!==BigInt(process.getuid())||before.size!==0n||(before.mode&0o111n)!==0n)throw new Error('Q032 GITHUB_PATH must be fresh regular owned single-link input');
 const fd=fs.openSync(location,fs.constants.O_RDWR|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 let touched=false,primary=null;
 try {
  if(!q021Same(before,fs.fstatSync(fd,{bigint:true}))||!q021Same(before,fs.lstatSync(location,{bigint:true})))throw new Error('Q032 GITHUB_PATH replaced while opening');
  const payload=Buffer.from(path.join(root,'go/bin')+'\n');touched=true;
  if(fs.writeSync(fd,payload,0,payload.length,0)!==payload.length)throw new Error('Q032 GITHUB_PATH short write');
  fs.fsyncSync(fd);
  const after=fs.fstatSync(fd,{bigint:true}),atPath=fs.lstatSync(location,{bigint:true});
  if(!equal(q032OwnerIdentity(before),q032OwnerIdentity(after))||after.nlink!==1n||!q021Same(after,atPath)||!fs.readFileSync(fd).equals(payload))throw new Error('Q032 GITHUB_PATH publication identity/body mismatch');
  q032AssertOwned(root,owner);
 }catch(error){
  primary=error;
  if(touched){
   try{
    if(!equal(q032OwnerIdentity(before),q032OwnerIdentity(fs.fstatSync(fd,{bigint:true})))||!equal(q032OwnerIdentity(before),q032OwnerIdentity(fs.lstatSync(location,{bigint:true}))))throw new Error('publication input replaced');
    fs.ftruncateSync(fd,0);fs.fsyncSync(fd);
    if(fs.fstatSync(fd,{bigint:true}).size!==0n||fs.lstatSync(location,{bigint:true}).size!==0n)throw new Error('publication rollback incomplete');
   }catch(rollback){error.q032PublicationUncertain=true;error.q032RollbackError=String(rollback.message);}
  }
  throw error;
 }finally{
  try{fs.closeSync(fd);}catch(close){
   if(primary){primary.q032PublicationUncertain=true;primary.q032CloseError=String(close.message);}
   else{close.q032PublicationUncertain=true;throw close;}
  }
 }
 return true;
}
function q032RetireFailedRoot(root,owner,commands) {
 if(commands.some(c=>!c.all_command_owners_retired))return false;
 q032AssertOwned(root,owner);
 fs.rmSync(root,{recursive:true});
 if(fs.existsSync(root))throw new Error('Q032 failed owned directory not retired');
 return true;
}
export function prepareQ032CurrentSDK(repo) {
 if(arguments.length!==1)throw new Error('Q032 acquisition accepts no caller URL/version/path/spec/options');
 const context=q032Context(repo),spec=q032ArchiveSpec(repo),commands=[];
 let root=null,owner=null,fd=null,published=false,publicationUncertain=false,receiptCloseUncertain=false,receipt=null;
 try {
  root=fs.mkdtempSync(path.join(context.temp,'aipt-q032-sdk-'));
  owner=q032PhysicalDirectory(root,{privateMode:true});
  const archive=path.join(root,Q032_ARCHIVE.filename);
  fd=fs.openSync(archive,fs.constants.O_RDWR|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  q032Command('/usr/bin/curl',['--disable','--fail','--silent','--show-error','--location','--proto','=https','--proto-redir','=https','--max-redirs','3','--connect-timeout','20','--max-time','240','--output','/proc/self/fd/3',Q032_ARCHIVE.url],commands,{archiveFD:fd});
  q032AssertOwned(root,owner);const archiveIdentity=q032HeldArchive(fd,archive,spec);
  q032Command('/usr/bin/tar',['--no-same-owner','--no-same-permissions','-xzf','/proc/self/fd/3','-C',root],commands,{archiveFD:fd});
  if(!q021Same(archiveIdentity,fs.fstatSync(fd,{bigint:true}))||!q021Same(archiveIdentity,fs.lstatSync(archive,{bigint:true})))throw new Error('Q032 held archive changed during extraction');
  q032AssertOwned(root,owner);
  const sdk=path.join(root,'go'),proof=verifyQ021CurrentSDK(repo,sdk);
  if(!equal(proof,{version:'1.26.9',files:15045,directories:1667,complete_fixed_archive_identity:true}))throw new Error('Q032 raw official SDK qualification proof mismatch');
  const identity=q021PhysicalSDK(sdk,spec);
  const post=q032Context(repo);if(!equal(context,post))throw new Error('Q032 job/source changed during acquisition');
  fs.closeSync(fd);fd=null;
  if(!q021Same(archiveIdentity,fs.lstatSync(archive,{bigint:true})))throw new Error('Q032 archive changed before retirement');
  fs.unlinkSync(archive);q032AssertOwned(root,owner);
  receipt={schema:'aipt.q032.owned-official-SDK-acquisition-receipt/v1',context,owner,SDK_root:sdk,archive:Q032_ARCHIVE,qualification_sha256:Q018_QUALIFICATION_SHA,authority_sha256:Q032_AUTHORITY_SHA,proposal_sha256:Q032_PROPOSAL_SHA,sdk_identity:identity,proof,commands,SDK_registry_changed:false,archive_retired:true,formal_CA_READY_model_DIAG_QUAL:0};
  q032WriteReceipt(path.join(root,Q032_RECEIPT),receipt);
  // Re-read the complete original SDK identity after receipt persistence and
  // immediately before the only PATH publication; nothing falls back to PATH.
  if(!equal(identity,q021PhysicalSDK(sdk,spec)))throw new Error('Q032 SDK changed before PATH publication');
  published=q032Publication(process.env.GITHUB_PATH,root,owner);
  return {result:'PASS_Q032_JOB_OWNED_OFFICIAL_SDK_QUALIFIED_AND_PATH_PUBLISHED',version:'1.26.9',files:15045,directories:1667,archive_sha256:Q032_ARCHIVE.sha256,archive_retired:true,SDK_required_until_job_end:true,all_acquisition_commands_actual_waited:commands.every(c=>c.all_command_owners_retired),SDK_registry_changed:false,formal_CA_READY_model_DIAG_QUAL:0};
 }catch(error){
  publicationUncertain=Boolean(error.q032PublicationUncertain);
  receiptCloseUncertain=Boolean(error.q032ReceiptCloseUncertain);
  if(fd!==null){try{fs.closeSync(fd);fd=null;}catch(close){error.q032ArchiveCloseError=String(close.message);}}
  let retired=false;
  if(root!==null&&owner!==null&&fd===null&&!published&&!publicationUncertain&&!receiptCloseUncertain){try{retired=q032RetireFailedRoot(root,owner,commands);}catch(cleanup){error.q032CleanupError=String(cleanup.message);}}
  error.q032Failure={commands,owned_directory:root,owned_directory_allocation_returned:root!==null,owned_directory_identity_established:owner!==null,owned_directory_retired:retired,owned_directory_retained:root!==null&&!retired,publication_uncertain:publicationUncertain,receipt_close_uncertain:receiptCloseUncertain,receipt_path:error.q032ReceiptPath??null,original_error_retained:true};
  try{process.stderr.write('Q032_FIXED_ACQUISITION_FAILURE '+JSON.stringify(error.q032Failure)+'\n');}catch{/* Original error stays primary. */}
  throw error;
 }
}
function q032BoundCurrentRoot(repo) {
 const context=q032Context(repo),spec=q032ArchiveSpec(repo);
 let selected=null;
 for(const entry of (process.env.PATH??'').split(path.delimiter)){
  if(!entry)continue;
  const go=path.join(entry,'go');
  if(fs.existsSync(go)){selected={entry,go};break;}
 }
 if(!selected||!path.isAbsolute(selected.entry)||selected.entry!==path.normalize(selected.entry)||!selected.entry.startsWith(context.temp+path.sep)||fs.realpathSync(selected.entry)!==selected.entry||fs.realpathSync(selected.go)!==selected.go)throw new Error('Q032 selected Go is not the published physical owned SDK; fallback forbidden');
 const sdk=path.dirname(selected.entry),root=path.dirname(sdk);
 if(path.basename(sdk)!=='go'||path.basename(selected.entry)!=='bin'||!/^aipt-q032-sdk-[A-Za-z0-9]+$/.test(path.basename(root))||path.dirname(root)!==context.temp)throw new Error('Q032 selected SDK has no fixed owned acquisition layout');
 const owner=q032PhysicalDirectory(root,{privateMode:true}),location=path.join(root,Q032_RECEIPT),s=fs.lstatSync(location,{bigint:true});
 if(s.uid!==BigInt(process.getuid())||s.nlink!==1n||(s.mode&0o777n)!==0o400n)throw new Error('Q032 acquisition receipt ownership/mode changed');
 const r=JSON.parse(heldQ018Bytes(location).raw);
 if(!equal(Object.keys(r).sort(),['schema','context','owner','SDK_root','archive','qualification_sha256','authority_sha256','proposal_sha256','sdk_identity','proof','commands','SDK_registry_changed','archive_retired','formal_CA_READY_model_DIAG_QUAL'].sort())||r.schema!=='aipt.q032.owned-official-SDK-acquisition-receipt/v1'||!equal(r.context,context)||!equal(r.owner,owner)||r.SDK_root!==sdk||!equal(r.archive,Q032_ARCHIVE)||r.qualification_sha256!==Q018_QUALIFICATION_SHA||r.authority_sha256!==Q032_AUTHORITY_SHA||r.proposal_sha256!==Q032_PROPOSAL_SHA||!equal(r.proof,{version:'1.26.9',files:15045,directories:1667,complete_fixed_archive_identity:true})||r.commands.length!==2||r.commands.some(c=>!c.all_command_owners_retired||!c.direct_child_waited||c.status!==0||c.signal!==null)||r.SDK_registry_changed!==false||r.archive_retired!==true||r.formal_CA_READY_model_DIAG_QUAL!==0)throw new Error('Q032 fixed acquisition receipt/source/job binding mismatch');
 if(fs.existsSync(path.join(root,Q032_ARCHIVE.filename))||!equal(r.sdk_identity,q021PhysicalSDK(sdk,spec)))throw new Error('Q032 published SDK differs from fresh acquired identity');
 return sdk;
}
export function q032CurrentGoVersion(repo) {
 if(arguments.length!==1)throw new Error('Q032 fixed Go-version entry accepts no caller arguments/options');
 const root=q032BoundCurrentRoot(repo),value=withQ021VerifiedCurrentSDK(repo,root,()=>run(path.join(root,'bin/go'),['version'],{cwd:repo,env:{...process.env,GOROOT:root,GOENV:'off',GOTOOLCHAIN:'local',GOTELEMETRY:'off'}}));
 if(value.stdout!=='go version go1.26.9 linux/amd64\n'||value.stderr!=='')throw new Error('Q032 exact protected current Go version mismatch');
 q032BoundCurrentRoot(repo);
 return {result:'PASS_Q032_EXACT_OWNED_CURRENT_GO_VERSION',version:value.stdout.trim(),original_complete_SDK_checks_before_after:true,formal_CA_READY_model_DIAG_QUAL:0};
}

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
  const q022=q022Present(repo);
  if(q022&&!q022Approved(repo))throw new Error('Q021/Q022 exact approved fixture/workflow authority absent or changed');
  if(heldQ018Bytes(path.join(repo,'internal/pilot/runtime_namespace_test.go')).sha256!==(q022?Q022_FIXTURE_SHA:CURRENT_FIXTURE))p.push('Q018 diagnostics-only or exact Q022 fixture identity changed');
  const q023=q023Present(repo);
  if(q023&&!q023Approved(repo))throw new Error('Q023 exact approved fixed P1 authority absent or changed');
  const q032=q032Present(repo);
  if(q032&&!q032Approved(repo))throw new Error('Q032/Q033 exact paired workflow authority absent or changed');
  if(q022&&heldQ018Bytes(path.join(repo,'.github/workflows/ci.yml')).sha256!==(q032?Q032_WORKFLOW_SHA:q023?Q023_WORKFLOW_SHA:Q022_WORKFLOW_SHA))p.push('Q021/Q022/Q023/Q032 exact approved workflow identity changed');
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
 if(q022Present(repo))return q022SourceProblems(repo);
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
 if(!baseline&&q022Present(repo))return q022RevisionProblems(repo,revision);
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
 if(q032Present(repo))return q032SourceProblems(repo);
 if(q028Present(repo))return q028SourceProblems(repo);
 if(q027Present(repo))return q027SourceProblems(repo);
 if(q026Present(repo))return q026SourceProblems(repo);
 if(q025Present(repo))return q025SourceProblems(repo);
 if(q022Present(repo))return q022SourceProblems(repo);
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
     const q031Rejected=!expected||!before.isFile()||before.nlink!==1n||before.size!==BigInt(expected.bytes)||Boolean(Number(before.mode)&0o111)!==expected.executable;
     if(rel==='CONTRIBUTING.md'&&spec.version==='1.26.9'){
      try{
       const q031Record={schema:'aipt.q031.fixed-Q021-original-validation-stat/v1',observation:'SAME_CAPTURED_VALIDATION_STAT_NOT_SDK_QUALIFICATION',member:'CONTRIBUTING.md',version:'1.26.9',expected:expected?{bytes:String(expected.bytes),executable:expected.executable}:null,metadata:Object.fromEntries(q021StatFields.map(k=>[k,String(before[k])])),regular:before.isFile(),original_predicate_rejected:q031Rejected,SDK_qualified:false,additional_SDK_body_reads:0};
       const q031Line=JSON.stringify(q031Record)+'\n';
       if(Buffer.byteLength(q031Line)<=4096)fs.writeSync(2,q031Line);
      }catch{}
     }
     if(q031Rejected)throw new Error('Q021 nonregular/aliased/additional/changed SDK member: '+rel);
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
 if(q032Present(repo))return q032BoundCurrentRoot(repo);
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
 if(q032Present(repo))prepareQ032FixedCloneOrigin(repo);else if(q028Present(repo))prepareQ028FixedCloneOrigin(repo);else if(q027Present(repo))prepareQ027FixedCloneOrigin(repo);else if(q026Present(repo))prepareQ026FixedCloneOrigin(repo);else if(q025Present(repo))prepareQ025FixedCloneOrigin(repo);else if(q024Present(repo))prepareQ024FixedCloneOrigin(repo);else if(q023Present(repo))prepareQ023FixedCloneOrigin(repo);else if(q022Present(repo))prepareQ022FixedCloneOrigin(repo);else if(q021Approved(repo))prepareQ021FixedCloneOrigins(repo);
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
  if(command==='--q032-prepare-current-sdk')process.stdout.write(JSON.stringify(prepareQ032CurrentSDK(repo))+'\n');
  else if(command==='--q032-current-go-version')process.stdout.write(JSON.stringify(q032CurrentGoVersion(repo))+'\n');
  else if(command==='--prepare-domains')process.stdout.write(JSON.stringify(prepareDomains(repo))+'\n');
  else if(command==='--q015-full23')runFixedHistoricalCLI(repo,'Q015_FULL23_F7');
  else if(command==='--b001-launcher')runFixedHistoricalCLI(repo,'B001_LAUNCHER');
  else if(command==='--b001-launcher-race')runFixedHistoricalCLI(repo,'B001_LAUNCHER_RACE');
  else if(command==='--p1-reverification')runFixedHistoricalCLI(repo,'P1_REVERIFICATION');
  else if(command==='--q023-fixed-p1-reverification')runQ023FixedP1Reverification(repo);
  else throw new Error('unknown or unapproved Q018 CLI route');
 }catch(error){process.stderr.write('Q018 fixed-domain failure: '+error.message+'\n');process.exitCode=1;}
}

// Pure contract for the unchanged fixed251 P1 program's exact five-job report.
export function q023FixedP1ReportProblems(report) {
 if(arguments.length!==1)return ['Q023 exact P1 report requires one report and no caller options'];
 const jobs=['exact-target-identity','authority-validator','b001-historical-validator','effective-authority-resolution','go-test-all-at-target'];
 const expected={
  schema:'aipt.public.post-merge-reverification-candidate-run/v1',
  task_id:'UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001',
  result:'PASS',
  definition_commit:Q023_DEFINITION,
  definition_tree:Q023_DEFINITION_TREE,
  requested_target_sha:Q023_TARGET,
  resolved_target_sha:Q023_TARGET,
  target_tree:Q023_TARGET_TREE,
  target_checkout:'DETACHED_EXACT_COMMIT',
  target_clean:true,
  modified_target_worktree_used:false,
  jobs:jobs.map(name=>({name,passed:true,conclusion:'success'})),
  original_merge_ci:'ABSENT',
  historical_merge_ci_claimed_pass:false,
  formal_evidence_eligible:false,
  formal_evidence_blocker:'REPAIR_CANDIDATE_INDEPENDENT_ACCEPTANCE_PENDING',
  recovery_not_historical_ci:true,
  real_model_calls:0,
  real_playtest_executed:false,
  b001_regression:'PASS',
  effective_authority_identities:'PASS',
  go_test_all:'PASS',
  go_test_diagnostics:null,
  workflow_definition_sha256:'3ad13fa061727190d7363815053b39bede7d88c4d00ded3aa51a190b31b0e053',
  validator_identities:[
   {path:'scripts/ci/validate/p1-b000-authority.mjs',role:'AUTHORITY_VALIDATOR_IDENTITY',sha256:'c6f0c8e01397200ce15f48bf1fc2412d9db477dddc37d3f99e0478d26956dd0c'},
   {path:'scripts/ci/validate/mvp-b001.mjs',role:'B001_HISTORICAL_VALIDATOR_IDENTITY',sha256:'319c8d4a3466c20d14e2d5fc74cc246c9b796d36f884fcc39e2b0a25317351c4'}
  ],
  details:jobs.map(name=>'ok: '+name+' success')
 };
 return equal(report,expected)?[]:['Q023 exact typed P1 report/target/five-job/no-grant binding failed'];
}

// New fixed route retains the original P1 program and all five report conditions.
export function runQ023FixedP1Reverification(repo) {
 if(arguments.length!==1)throw new Error('Q023 accepts no caller target/argv/options');
 const problems=q023SourceProblems(repo);
 if(problems.length)throw new Error('Q023 exact Owner/source656 prerequisites failed: '+problems.join('; '));
 const proposal=q023Proposal(repo),fixed=fixedRouteTarget(repo,'STANDALONE_8D6A');
 if(fixed.commit!=='8d6a438d051fb635e769285215e70536958a8f42'||fixed.tree!=='9ef6f121bd0d9a6484d7cc39a22450250e9ac489')throw new Error('Q023 fixed definition identity changed');
 const target=snapshot(repo,fixed.commit,fixed.tree);
 const fullDefinition=()=>{
  const rows=proposal.new_fixed_P1_route.fixed_definition251;
  if(rows.length!==251||!equal(git(target,['ls-files','-z']).split('\0').filter(Boolean).sort(),rows.map(v=>v.relative).sort()))throw new Error('Q023 incomplete definition251');
  for(const f of rows){const actual=heldQ018Bytes(path.join(target,f.relative));if(actual.bytes!==f.bytes||actual.sha256!==f.sha256||actual.executable!==(f.git_mode==='100755'))throw new Error('Q023 definition physical source changed: '+f.relative);}
  if(git(target,['rev-parse','HEAD'])!==fixed.commit||git(target,['rev-parse','HEAD^{tree}'])!==fixed.tree||git(target,['status','--porcelain=v1','--untracked-files=all'])!=='')throw new Error('Q023 definition identity/cleanliness changed');
 };
 try {
  fullDefinition();const env=historicalEnvironment(repo,target,'STANDALONE_8D6A');
  const child=spawnSync(process.execPath,['scripts/ci/validate/p1-b000-post-merge-reverification.mjs'],{cwd:target,env,encoding:'utf8',maxBuffer:64*1024*1024});
  if(child.stdout)process.stdout.write(child.stdout);if(child.stderr)process.stderr.write(child.stderr);
  fullDefinition();verifySDK(env.GOROOT,sdkSpec(repo,'1.26.6'));cacheIdentity(repo,env.GOMODCACHE);
  const postH1=run(path.join(env.GOROOT,'bin/go'),['mod','verify'],{cwd:target,env});
  if(postH1.stdout.trim()!=='all modules verified')throw new Error('Q023 historical15 post H1 failed');
  if(child.error||child.signal||child.status!==0)throw new Error('Q023 fixed P1 did not PASS');
  const r=JSON.parse(child.stdout);
  const reportProblems=q023FixedP1ReportProblems(r);if(reportProblems.length)throw new Error(reportProblems.join('; '));
  const after=q023SourceProblems(repo);if(after.length)throw new Error('Q023 source656 postcheck failed: '+after.join('; '));
  return {result:'PASS',route:'Q023_FIXED_8D6A_P1_REVERIFICATION',definition_commit:fixed.commit,verification_target:r.resolved_target_sha,historical_go:'1.26.6',offline:true,actual_owned_Wait:true,model_DIAG_QUAL:0,formal_evidence_eligible:false};
 }finally{fs.rmSync(target,{recursive:true,force:true});}
}
