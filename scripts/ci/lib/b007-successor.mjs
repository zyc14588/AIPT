// Explicit Owner-authorized B007 successor. Historical B006 bytes never change.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { isDeepStrictEqual as equal } from 'node:util';
import { git, out, rows, blob, read, facts, inventory, firstParentContains, sha } from './b006-successor.mjs';
export { git, out, rows, blob, read, facts, inventory, firstParentContains, sha };
export const BASE='5f3f6353d744f6674de7cb610a8d8e9b9220c02a';
export const BASE_TREE='d91062ddb99d781a825e272a6365ed4effe97350';
export const TASK='AIPT-MVP-B007';
export const STATUS='docs/authority/registry/project-status.json';
export const AUTHORITY='docs/authority/registry/b007-predecessor-gates-successor.json';
export const START='docs/authority/registry/b007-start.json';
export const AUTHORITY_SHA='605fd163c5c2245ae7088c849b82d35de6d04783b37639f48001a7b22de35d06';
export const START_SHA='10801eb5375506e6ab65fb82dd805bb0a424fe3ce2fde64efceeda786806e964';
export const DECISION='B007-PREDECESSOR-GATES-AND-DIAGNOSTIC-PILOT-Q001=A';
export const MUTABLE=new Set(['package.json','scripts/ci/run-checks.mjs',STATUS,'docs/authority/PROJECT_STATUS.md','docs/milestones/MVP.md']);
export const Q002_AUTHORITY='docs/pilot/authorities/wire-budget-closure-successor.json';
export const Q002_AUTHORITY_SHA='214d271c85245bac4f009e524e841f59411291d1ea6c09cc068066b131f6ca7b';
export const Q002_SOURCE='docs/pilot/runtime/harness-runtime-closure-b007.ts';
export const Q003_AUTHORITY='docs/pilot/authorities/task0-supplemental-input-annex.json';
export const Q003_AUTHORITY_SHA='ee801db456897f11429238c3ffdbc08cca2a7d40009ea3ad1adee658eafc63e5';
export const Q003_ANNEX='docs/pilot/inputs/task0-input-annex-v1.json';
export const Q003_ANNEX_SHA='5f4ecf19c84a384245071c3f23f491a8c1fe4c8dcae0326a7123a3d6000566f5';
export const Q004_AUTHORITY='docs/pilot/authorities/local-runtime-closure-successor.json';
export const Q004_AUTHORITY_SHA='a7c7495cd97e950a9c9112df089bff6dfae913fadc9c3c751ce4c63e913277a5';
export const Q004_PROPOSAL='docs/pilot/proposals/local-runtime-closure-q004.json';
export const Q004_PROPOSAL_SHA='2f79115263cc092df179ce67ad9d5ac4a20d12465866c30ed97c0e77df49dbba';
export const Q005_AUTHORITY='docs/pilot/authorities/independent-reviewer-continuity-successor.json';
export const Q005_AUTHORITY_SHA='36e407df12116790b619f18a2b9200cac6289b298a46aff39fa94419c27df2e3';
export const EXACT=new Map([[AUTHORITY,AUTHORITY_SHA],[START,START_SHA],[Q002_AUTHORITY,Q002_AUTHORITY_SHA],[Q002_SOURCE,'1dedde689c31337dc0a29102239a828a9873003f80945d5c456eef5614d8512f'],[Q003_AUTHORITY,Q003_AUTHORITY_SHA],[Q003_ANNEX,Q003_ANNEX_SHA],[Q004_AUTHORITY,Q004_AUTHORITY_SHA],[Q004_PROPOSAL,Q004_PROPOSAL_SHA],[Q005_AUTHORITY,Q005_AUTHORITY_SHA]]);
export const Q009_AUTHORITY='docs/pilot/authorities/task0-prototype-source-successor-q009.json';
export const Q009_AUTHORITY_SHA='1d6c9600cbd3ff2917146c8c4a80647c70f9e17641f565944e4c948dc541e032';
export const Q009_ANNEX='docs/pilot/inputs/task0-prototype-input-annex-v2.json';
export const Q009_ANNEX_SHA='0dba7a660e147dec4536f7b272b73a2e768b2a04986be6a4e71880eb316229cc';
export const Q009_REVIEW='docs/pilot/reviews/q009-exact-source-adoption.json';
export const Q009_REVIEW_SHA='4732a423d5235780eb8e560c7d523f3846f4c4b59a4f8548caca0b6c5fd93024';
export const Q009_CI='docs/pilot/evidence/task0-q009/evidence-index.json';
export const Q009_CI_SHA='508d65a46b8ff87dc9edb3153bc4f635147d391dfed20e48e80842f39158c1c2';
export const Q009_ADAPTER='docs/pilot/inputs/task0-runtime-adapter-input-v2.json';
export const Q009_ADAPTER_SHA='2d8346b616726c1466d0abe48510d657008a1447712e789dc47ae94f4b941133';
export const Q009_GATEWAY='docs/pilot/runtime/task0-game-gateway.mjs';
export const Q009_GATEWAY_SHA='805e82a71d16f974e209ab0d3b8d8ae3d5f273239b1f96e3f31bc6d4cfb648a2';
const Q009_CI_FILES=new Map([
 ['docs/pilot/evidence/task0-q009/candidate-jobs.json','10e932ad29e5235a5119a0d7965ba7a7d39dabc9b95534e03d727892722fc36a'],
 ['docs/pilot/evidence/task0-q009/candidate-run.json','524069645fe3845ed8cb9e36e41b009a5ff2b8b9cfdd150883549bc7bbbf74c4'],
 ['docs/pilot/evidence/task0-q009/merge-jobs.json','ae8f03ecc0c62bedcbc3b7da1ee517be32762b618b876eeca921718e5d472c25'],
 ['docs/pilot/evidence/task0-q009/merge-run.json','01ae6f7811758f56978777467bf9d9bd58611777a41a3901506c1348bcc8effb'],
 ['docs/pilot/evidence/task0-q009/origin-control.json','912d4e04cb2385886637f55e7ed30baa52ea2e91ddb655b9a4e2ae13999b49d5'],
]);
for(const pair of [[Q009_AUTHORITY,Q009_AUTHORITY_SHA],[Q009_ANNEX,Q009_ANNEX_SHA],[Q009_REVIEW,Q009_REVIEW_SHA],[Q009_CI,Q009_CI_SHA],[Q009_ADAPTER,Q009_ADAPTER_SHA],[Q009_GATEWAY,Q009_GATEWAY_SHA],...Q009_CI_FILES])EXACT.set(...pair);
export const Q009_SOURCE={package_id:'UNREGISTERED-TASK0-PROTOTYPE-V2',schema:'unregistered.task0-prototype-package/v2',repository:'zyc14588/UNREGISTERED',commit:'d37ae9b38bce84f8bfc164306fee2bebf73178b7',tree:'d802d28c7275e3e75ada5d6ef3edeb7fb57eb7b9',canonical_sha256:'f87f011f8c57c3eef371ad1e8f5569effd035957158fd17ba7fa63655c86e13d'};
export const Q011_AUTHORITY='docs/pilot/authorities/private-evidence-successor-q011.json';
export const Q011_AUTHORITY_SHA='57edcd5470a8be49f5089040df4165243a1de6e893299cf510241529c61e878d';
EXACT.set(Q011_AUTHORITY,Q011_AUTHORITY_SHA);
export const Q012_AUTHORITY='docs/pilot/authorities/system-ca-preparation-bridge-successor-q012.json';
export const Q012_AUTHORITY_SHA='f0d82ca89af129aec85bbcb1a00282516dd060308b209e21f4af2434be9c74cf';
EXACT.set(Q012_AUTHORITY,Q012_AUTHORITY_SHA);
export const Q013_AUTHORITY='docs/pilot/authorities/system-ca-readonly-tmpfs-successor-q013.json';
export const Q013_AUTHORITY_SHA='7227316d4d2a4efcbf61d957853cd5fb73c66757df765d08de1cf8dd2a497425';
EXACT.set(Q013_AUTHORITY,Q013_AUTHORITY_SHA);
export const Q014_AUTHORITY='docs/pilot/authorities/fixed-namespace-setup-successor-q014.json';
export const Q014_AUTHORITY_SHA='be7639384a7621828e0a67fa23e983c4bbdbafeea426e05294d441717c3ed5ff';
EXACT.set(Q014_AUTHORITY,Q014_AUTHORITY_SHA);

export const Q015_AUTHORITY="docs/pilot/authorities/fixed-origin-policy-successor-q015.json";
export const Q015_AUTHORITY_SHA="d9c58aa1cd329bcb9f5c83ceea216c0427d7d3ed968d69f2dfc8c007be7076be";
export const Q015_GATE="scripts/ci/validate/supply-chain.mjs";
export const Q015_GATE_SHA="57a9f1a69193506d9b80075342395e86fa2028f7eb5d3ab015f02095d0c8e1f2";
EXACT.set("docs/pilot/authorities/fixed-origin-policy-successor-q015.json","d9c58aa1cd329bcb9f5c83ceea216c0427d7d3ed968d69f2dfc8c007be7076be");
EXACT.set("docs/pilot/evidence/task0-q015/original-supply-chain.mjs","0e7bd7b810be7bb80ab89d3e62a4285911e39fb3e7c13b2c4d729ed957521fa6");
EXACT.set("docs/pilot/evidence/task0-q015/PR27-original-CI-failure.json","d108b729bd4872a14653a081d27dd679ab7d384589a266da4e1793c96594b8af");
EXACT.set("scripts/ci/lib/b007-fixed-origin-policy-q015.mjs","95d09660e81591055c43b026f6f73896df17ef7615dc931ad363d80c44214f3e");
EXACT.set("scripts/ci/lib/b007-byte-evidence-scan-q015.mjs","6a93733f2b29769778cb05ddae1c878c60b6fbe6650b299497b3577e8701cf88");
EXACT.set("scripts/ci/test/b007-fixed-origin-policy-q015.test.mjs","09b6e10cc3dabef4bc549b63b0bd809bf56c8e07c8690d2f23264579946bf616");

export const Q016_AUTHORITY='docs/pilot/authorities/evidence-gate-routing-successor-q016.json';
export const Q016_AUTHORITY_SHA='8506ca89438dd7ba9782a2f835e57013e928c869904d61697ab35e05f86845cb';
const Q016_PACKAGE_SHA='981f3c441122d0d31f4e66632c4e1572ea23808f2fe1c34a7562fe8a096b7fcf';
const Q016_AGGREGATE_SHA='47a2b6aabed5956a6459d4944bb92d5bc63031bacd5fb35f7618db11f011f08f';
const Q016_EVIDENCE_SHA='6f6cffc0dc642382e4d72c650743df57f3c62eacfee21088087e9a201f8bf97b';
EXACT.set(Q016_AUTHORITY,Q016_AUTHORITY_SHA);
function q016Approved(repo) {
 try {const raw=read(repo,Q016_AUTHORITY);const a=JSON.parse(raw);return sha(raw)===Q016_AUTHORITY_SHA&&a.state==='OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI'&&typeof a.owner_instruction==='string'&&a.owner_instruction.length>0;}catch{return false;}
}

export const Q017_AUTHORITY='docs/pilot/authorities/namespace-low-descriptor-fixture-successor-q017.json';
export const Q017_AUTHORITY_SHA='93358000cba6dfc425a7270d44cdae199181c768e7b8591cfd186bb4aee4736d';
export const Q017_FIXTURE='internal/pilot/runtime_namespace_test.go';
const Q017_FIXTURE_SHA='6ee906289bf19447bf8e0b3c3f79d4aec2bdc6eaf54e6abe7645df4020d03be2';
EXACT.set(Q017_AUTHORITY,Q017_AUTHORITY_SHA);
EXACT.set(Q017_FIXTURE,Q017_FIXTURE_SHA);
function q017Approved(repo) {
 try {const raw=read(repo,Q017_AUTHORITY);const a=JSON.parse(raw);return sha(raw)===Q017_AUTHORITY_SHA&&a.state==='OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI'&&typeof a.owner_instruction==='string'&&a.owner_instruction.trim().length>0&&q015Approved(repo)&&q016Approved(repo);}catch{return false;}
}

function q015Approved(repo) {
 try{const raw=read(repo,Q015_AUTHORITY);return sha(raw)===Q015_AUTHORITY_SHA&&JSON.parse(raw).state==='OWNER_AUTHORIZED_PENDING_FULL_REVIEW_AND_EXACT_CI';}catch{return false;}
}
function exactQ015Gate(repo,file,bytes,revision,t) {
 if(file!==Q015_GATE||sha(bytes??'')!==Q015_GATE_SHA||!q015Approved(repo))return false;
 if(!revision)return true;
 const merged=t.merge&&firstParentContains(repo,revision,t.merge.commit);
 const expected=merged?t.merge.commit:t.candidate?.commit;
 const changes=rows(repo,['log','--first-parent','--full-history','--format=%H',BASE+'..'+revision,'--',file]);
 return Boolean(expected)&&equal(changes,[expected]);
}
function q015ReplacementScopeProblems(repo,t) {
 const p=[];
 if(!q015Approved(repo))p.push('Q015 explicit Owner decision pending; proposed policy cannot authorize a replacement');
 const old='ec76d9c5cba0c32f3bb58c2a0abb9602f9ebe2d8';
 if(facts(repo,old)?.tree!=='9ab33633cdf943571ca3693c15a53b4f0b3d2dd5'||!equal(facts(repo,old)?.parents,[BASE]))return [...p,'Q015 original failed Candidate identity unavailable or changed'];
 const original=inventory(repo,old);
 const changed=new Set(['internal/pilot/runtime_helper_protocol_test.go',Q015_GATE,'scripts/ci/lib/b007-successor.mjs','scripts/ci/test/b007-lifecycle.test.mjs']);
 const additions=new Set(["docs/pilot/authorities/fixed-origin-policy-successor-q015.json", "docs/pilot/evidence/task0-q015/original-supply-chain.mjs", "docs/pilot/evidence/task0-q015/PR27-original-CI-failure.json", "scripts/ci/lib/b007-fixed-origin-policy-q015.mjs", "scripts/ci/lib/b007-byte-evidence-scan-q015.mjs", "scripts/ci/test/b007-fixed-origin-policy-q015.test.mjs"]);
 if(q016Approved(repo)){changed.add('package.json');changed.add('scripts/ci/run-checks.mjs');additions.add(Q016_AUTHORITY);}
 if(q017Approved(repo)){changed.add(Q017_FIXTURE);additions.add(Q017_AUTHORITY);}
 if(t.candidate) {
  const current=inventory(repo,t.candidate.commit);
  for(const [file,entry]of original)if(!changed.has(file)&&!equal(current.get(file),entry))p.push('Q015 unapproved replacement changed original implementation: '+file);
  for(const file of current.keys())if(!original.has(file)&&!additions.has(file))p.push('Q015 unapproved replacement addition: '+file);
  if(q016Approved(repo))for(const [file,digest]of [['package.json',Q016_PACKAGE_SHA],['scripts/ci/run-checks.mjs',Q016_AGGREGATE_SHA]])if(sha(blob(repo,t.candidate.commit,file)??'')!==digest)p.push('Q016 exact evidence route differs: '+file);
  if(q017Approved(repo)&&sha(blob(repo,t.candidate.commit,Q017_FIXTURE)??'')!==Q017_FIXTURE_SHA)p.push('Q017 replacement differs from exact test-child-only fixture bytes');
  const b=blob(repo,t.candidate.commit,'internal/pilot/runtime_helper_protocol_test.go');
  if(sha(b??'')!=='8839aa2547341898cab998716709cf6f3c2f27731565a8d747a955949968a45f')p.push('Q015 replacement test differs from exact format-only bytes');
 }
 return p;
}

const Q011_ADDITIVE_FILES=new Set(['internal/evidence/private_audit_ready.go','internal/evidence/private_audit_types.go','internal/evidence/private_audit_ready_test.go','internal/evidence/private_audit_postgres_integration_test.go','schemas/evidence/private/v1/aipt-private-audit-ready.schema.json']);
export const GATES=['mvp-b002','mvp-b003','mvp-b004','mvp-b005','int001-closeout-authority','mvp-b006'];
const NEW_FILES=new Set([...EXACT.keys(),'scripts/ci/lib/b007-successor.mjs','scripts/ci/lib/b007-lifecycle.mjs','scripts/ci/validate/b007-approved-predecessors.mjs','scripts/ci/validate/mvp-b007.mjs','scripts/ci/test/b007-lifecycle.test.mjs']);
export function allowedNew(p) {
  return NEW_FILES.has(p)||Q011_ADDITIVE_FILES.has(p)||/^(?:internal\/pilot|cmd\/aipt-pilot)\/[a-z0-9_]+\.go$/u.test(p)||/^(?:docs\/pilot|testdata\/pilot\/v1)\/[a-zA-Z0-9_./-]+$/u.test(p)&&!p.split('/').some(x=>x==='..'||x==='.');
}
export function expectedPackage(repo) {
  const pkg=JSON.parse(blob(repo,BASE,'package.json'));
  pkg.description='AIPT deterministic AI-seated TRPG table testing system. M0 and B001-B006 are closed; B007 is the sole authorized diagnostic pilot, with strict USD5/attempt/token/time caps; qualification remains unexecuted.';
  for(const gate of GATES) pkg.scripts['check:'+gate]='node scripts/ci/validate/b007-approved-predecessors.mjs --gate '+gate;
  if(q016Approved(repo))pkg.scripts['check:evidence']='node scripts/ci/validate/b007-approved-predecessors.mjs --gate evidence';
  Object.assign(pkg.scripts,{'check:mvp-b007':'node scripts/ci/validate/mvp-b007.mjs','test:b007-lifecycle':'node --test scripts/ci/test/b007-lifecycle.test.mjs','test:pilot':'go test ./internal/pilot -count=1'});
  return Buffer.from(JSON.stringify(pkg,null,2)+'\n');
}
export function expectedAggregate(repo) {
  let value=blob(repo,BASE,'scripts/ci/run-checks.mjs').toString()
    .replace("from './lib/b006-successor.mjs'","from './lib/b007-successor.mjs'")
    .replace("import { run as runMvpB006 } from './validate/mvp-b006.mjs';","import { run as runMvpB007 } from './validate/mvp-b007.mjs';")
    .replace('  runMvpB006(ctx),',"  runApprovedPredecessor(ctx, { gate: 'mvp-b006' }),\n  runMvpB007(ctx),");
  if(q016Approved(repo))value=value.replace("import { run as runEvidence } from './validate/evidence.mjs';\n",'').replace('  runEvidence(ctx),',"  runApprovedPredecessor(ctx, { gate: 'evidence' }),");
  return Buffer.from(value);
}
function workingEntry(repo,p) {
  const stat=fs.lstatSync(path.join(repo,p));
  if(!stat.isFile()) throw new Error('nonregular working artifact: '+p);
  const b=read(repo,p);
  return {mode:stat.mode&0o111?'100755':'100644',oid:crypto.createHash('sha1').update('blob '+b.length+'\0').update(b).digest('hex')};
}
function statusProblems(base,status,baselineAllowed) {
  if(baselineAllowed&&equal(base,status)) return [];
  const p=[];
  const exact=(actual,expected,label)=>{if(!equal(actual,expected))p.push('frozen predecessor status changed: '+label);};
  exact(Object.keys(status).sort(),Object.keys(base).sort(),'root keys');
  for(const [k,v] of Object.entries(base)) if(!['as_of','authority_snapshot_id','tracks','repositories','runtime'].includes(k)) exact(status[k],v,k);
  exact(Object.keys(status.repositories??{}).sort(),Object.keys(base.repositories).sort(),'repository keys');
  for(const [k,v] of Object.entries(base.repositories)) if(k!=='AIPT')exact(status.repositories?.[k],v,k);
  exact(Object.keys(status.repositories?.AIPT??{}).filter(k=>k!=='mvp_b007').sort(),Object.keys(base.repositories.AIPT).sort(),'AIPT keys');
  for(const [k,v] of Object.entries(base.repositories.AIPT))exact(status.repositories?.AIPT?.[k],v,'AIPT.'+k);
  exact(Object.keys(status.runtime??{}).sort(),Object.keys(base.runtime).sort(),'runtime keys');
  for(const [k,v] of Object.entries(base.runtime))if(k!=='status')exact(status.runtime?.[k],v,'runtime.'+k);
  exact(Object.keys(status.tracks??{}).sort(),Object.keys(base.tracks).sort(),'track keys');
  for(const [k,v] of Object.entries(base.tracks))if(k!=='AIPT-STANDALONE')exact(status.tracks?.[k],v,k);
  const before=base.tracks['AIPT-STANDALONE'],track=status.tracks?.['AIPT-STANDALONE'];
  const mutable=new Set(['construction','current_batch','next_serial_batch','next_batch_state','next_batch_authorized','next_batch_started','batch_history','global_wip']);
  exact(Object.keys(track??{}).sort(),Object.keys(before).sort(),'standalone keys');
  for(const [k,v] of Object.entries(before))if(!mutable.has(k))exact(track?.[k],v,'standalone.'+k);
  exact(Object.keys(track?.batch_history??{}).sort(),Object.keys(before.batch_history).sort(),'batch history keys');
  for(const [k,v] of Object.entries(before.batch_history))if(k!==TASK)exact(track?.batch_history?.[k],v,'batch_history.'+k);
  const b=status.repositories?.AIPT?.mvp_b007;
  if(track?.construction!=='IN_PROGRESS'||track.current_batch!==TASK||track.global_wip!==1||track.batch_history?.[TASK]!=='IN_PROGRESS'||track.next_serial_batch!=='AIPT-MVP-B008'||track.next_batch_state!=='NOT_AUTHORIZED'||track.next_batch_authorized!==false||track.next_batch_started!==false) p.push('B007 sole-WIP1/current/next tuple changed');
  if(b?.state!=='IN_PROGRESS'||b.authorized_by_task!==TASK||b.authority_path!==START||b.base_commit!==BASE||b.base_tree!==BASE_TREE||b.decision_id!==DECISION||b.predecessor_gate_authority_sha256!==AUTHORITY_SHA||b.closure_successor_decision!=='B007-WIRE-BUDGET-CLOSURE-SUCCESSOR-Q002=A'||b.closure_successor_authority_sha256!==Q002_AUTHORITY_SHA||b.task0_supplemental_input_decision!=='B007-TASK0-SUPPLEMENTAL-INPUT-ANNEX-Q003=A'||b.task0_supplemental_input_authority_sha256!==Q003_AUTHORITY_SHA||b.task0_input_annex_sha256!==Q003_ANNEX_SHA||b.local_runtime_closure_decision_id!=='B007-LOCAL-RUNTIME-CLOSURE-SUCCESSOR-Q004=A'||b.local_runtime_closure_authority_path!==Q004_AUTHORITY||b.local_runtime_closure_authority_sha256!==Q004_AUTHORITY_SHA||b.independent_reviewer_continuity_decision_id!=='B007-INDEPENDENT-REVIEWER-CONTINUITY-Q005=A'||b.independent_reviewer_continuity_authority_path!==Q005_AUTHORITY||b.independent_reviewer_continuity_authority_sha256!==Q005_AUTHORITY_SHA||b.diagnostic_budget_usd!=='5.00'||b.qualification_execution_authorized!==false||b.qualification_runs_executed!==0||b.runtime_ready!==false||b.public_ci_real_model_calls!==0) p.push('B007 authority/budget/nonqualification binding changed');
  if(!Number.isSafeInteger(b?.real_model_calls)||b.real_model_calls<0||b.real_model_calls>33||!Number.isSafeInteger(b?.diagnostic_runs_executed)||b.diagnostic_runs_executed<0||b.diagnostic_runs_executed>1) p.push('B007 diagnostic counts exceed approved ceilings');
  if(b?.task0_prototype_source_decision_id!=='AIPT-MVP-B007-OWNER-Q009'||b.task0_prototype_source_authority_path!==Q009_AUTHORITY||b.task0_prototype_source_authority_sha256!==Q009_AUTHORITY_SHA||b.task0_prototype_input_annex_sha256!==Q009_ANNEX_SHA||b.task0_prototype_source_review_sha256!==Q009_REVIEW_SHA||b.task0_prototype_ci_evidence_sha256!==Q009_CI_SHA||!equal(b.task0_prototype_source_package,Q009_SOURCE))p.push('B007 Q009 exact source authority/annex/CI binding changed');
  if(b?.private_evidence_successor_decision_id!=='AIPT-MVP-B007-OWNER-Q011'||b.private_evidence_successor_authority_path!==Q011_AUTHORITY||b.private_evidence_successor_authority_sha256!==Q011_AUTHORITY_SHA||b.private_evidence_full_acceptance!==false)p.push('B007 Q011 private evidence authority or construction status changed');
  if(b?.system_ca_preparation_bridge_decision_id!=='AIPT-MVP-B007-OWNER-Q012'||b.system_ca_preparation_bridge_authority_path!==Q012_AUTHORITY||b.system_ca_preparation_bridge_authority_sha256!==Q012_AUTHORITY_SHA||b.system_ca_preparation_bridge_feasibility!=='FAILED_SEALED_MEMFD_BIND_ERRNO_22'||b.system_ca_preparation_bridge_full_acceptance!==false||b.system_ca_materialization_successor_authorized!==true||b.pending_owner_decision!==null)p.push('B007 Q012/Q013 preserved failure and Q014 approval status changed');
  if(b?.system_ca_materialization_successor_decision_id!=='AIPT-MVP-B007-OWNER-Q013'||b.system_ca_materialization_successor_authority_path!==Q013_AUTHORITY||b.system_ca_materialization_successor_authority_sha256!==Q013_AUTHORITY_SHA||b.system_ca_materialization_successor_feasibility!=='FAILED_NESTED_UID_MAP_WRITE_EPERM_TRACE_DIAGNOSIS_ONLY'||b.system_ca_materialization_successor_full_acceptance!==false)p.push('B007 Q013 exact authority and incomplete acceptance changed');
  if(b?.fixed_namespace_setup_successor_decision_id!=='AIPT-MVP-B007-OWNER-Q014'||b.fixed_namespace_setup_successor_authority_path!==Q014_AUTHORITY||b.fixed_namespace_setup_successor_authority_sha256!==Q014_AUTHORITY_SHA||b.fixed_namespace_setup_successor_authorized!==true||b.fixed_namespace_setup_successor_feasibility!=='PASS_SCOPED_FIRST_FIXTURE_READONLY_VERIFIED_061_FULL_ACCEPTANCE_OPEN'||b.fixed_namespace_setup_successor_scoped_review_sha256!=='eb41903887975a416d152efa7431c4f571698ab6fbdb2c2c6f016c8b88b31f63'||b.fixed_namespace_setup_successor_full_acceptance!==false)p.push('B007 Q014 exact authority and incomplete acceptance changed');
  return p;
}
// This is an offline check of an Owner-accepted local online attestation. It
// neither requests GitHub nor claims an offline cryptographic CI signature.
export function sourceAdoptionProblems(repo) {
 const p=[];
 try {
  const get=(file,digest)=>{const raw=read(repo,file);if(sha(raw)!==digest)throw new Error('Q009 frozen source control identity changed: '+file);return JSON.parse(raw);};
  const a=get(Q009_AUTHORITY,Q009_AUTHORITY_SHA),annex=get(Q009_ANNEX,Q009_ANNEX_SHA),review=get(Q009_REVIEW,Q009_REVIEW_SHA),ci=get(Q009_CI,Q009_CI_SHA);
  if(a.decision_id!=='AIPT-MVP-B007-OWNER-Q009'||!equal(a.source_package,Q009_SOURCE)||a.package_entries!==45||a.canonical!==false||a.future_generic_repair_policy_authorized!==false||a.retained_q003_authority_sha256!==Q003_AUTHORITY_SHA||a.retained_q003_annex_sha256!==Q003_ANNEX_SHA||a.source_review.sha256!==Q009_REVIEW_SHA||a.ci_evidence.sha256!==Q009_CI_SHA||a.runtime_ready!==false||a.paid_callable!==false)p.push('Q009 source approval scope differs from exact accepted authority');
  if(annex.schema!=='aipt.public.b007-task0-prototype-input-annex/v2'||annex.authority_path!==Q009_AUTHORITY||annex.authority_sha256!==Q009_AUTHORITY_SHA||annex.retained_q003_authority_sha256!==Q003_AUTHORITY_SHA||annex.retained_q003_annex_sha256!==Q003_ANNEX_SHA||annex.source_adoption_review_sha256!==Q009_REVIEW_SHA||annex.online_ci_evidence_sha256!==Q009_CI_SHA||!equal(annex.source_package,Q009_SOURCE)||annex.runtime_ready!==false||annex.qualification_eligible!==false)p.push('Q009 input closure does not bind its exact source controls');
  const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
  const adapter=get(Q009_ADAPTER,Q009_ADAPTER_SHA);
  if(!equal(adapter.source_package,Q009_SOURCE)||adapter.source_annex_sha256!==Q009_ANNEX_SHA||adapter.retained_q003_annex_sha256!==Q003_ANNEX_SHA||adapter.runtime_ready!==false||adapter.qualification_eligible!==false)p.push('Q009 new runtime-adapter input changed its accepted source/scope');
  if(sha(read(repo,Q009_GATEWAY))!==Q009_GATEWAY_SHA)p.push('Q009 frozen source control identity changed: game gateway');
  const m=annex.source_manifest,old=get(Q003_ANNEX,Q003_ANNEX_SHA);
  if(m.entries.length!==45||m.canonical!==false||m.lifecycle!=='PROTOTYPE'||sha(canonical(m))!==Q009_SOURCE.canonical_sha256)p.push('Q009 exact 45-entry PROTOTYPE manifest changed');
  for(const row of [...old.preserved_base_files,...old.supplemental_inputs])if(!m.entries.some(e=>e.path===row.path&&e.sha256===row.sha256&&(!row.bytes||e.bytes===row.bytes)))p.push('Q009 changed retained Q003 source: '+row.path);
  if(review.result!=='PASS_SCOPED_EXACT_SOURCE_ACCEPTANCE_ONLY'||review.scope_pass!==true||review.new_confirmed_findings!==0||!equal(review.source_package,Q009_SOURCE)||review.ci_evidence_sha256!==Q009_CI_SHA||review.production_driver_acceptance!==false||review.runtime_ready!==false||review.full_runtime_HIGH!=='OPEN'||review.privacy_HIGH!=='OPEN')p.push('Q009 source-only independent review cannot establish runtime readiness');
  if(ci.schema!=='aipt.public.b007-exact-game-source-ci-evidence/v1'||!equal(ci.source_package,Q009_SOURCE)||ci.accepted_baseline_commit!=='fe0965977447caf8cd7b6e58252bc1b991b7cc6f'||ci.candidate_commit!=='76e79aa7536b42406f1cb77baa5844073b5d7fe7'||!equal(ci.required_jobs,['aipt-content-gate','task0-prototype-check'])||ci.files.length!==5||ci.cryptographic_ci_signature_claim!==false||ci.public_ci_github_api_queries!==false||ci.aipt_runtime_acceptance!==false)p.push('Q009 CI evidence scope/identity changed');
  const held=new Map();
  for(const row of ci.files){if(Q009_CI_FILES.get(row.path)!==row.sha256||held.has(row.path)||read(repo,row.path).length!==row.bytes)throw new Error('Q009 CI index file identity mismatch');held.set(row.path,get(row.path,row.sha256));}
  for(const [kind,head,branch,id]of [['candidate',ci.candidate_commit,'codex/unregistered-task0-retry-catastrophe-repair',37686394237],['merge',Q009_SOURCE.commit,'main',37686735678]]) {
   const r=held.get('docs/pilot/evidence/task0-q009/'+kind+'-run.json'),j=held.get('docs/pilot/evidence/task0-q009/'+kind+'-jobs.json');
   if(!r?.local_online_observation||!j?.local_online_observation||r.run.id!==id||r.run.head_sha!==head||r.run.head_branch!==branch||r.run.event!=='push'||r.run.run_attempt!==1||r.run.status!=='completed'||r.run.conclusion!=='success'||r.run.workflow_id!==336437725||r.run.path!=='.github/workflows/aipt-content-gate.yml'||!equal(r.run.repository,{id:1334368477,full_name:'zyc14588/UNREGISTERED',private:false})||!equal(r.run.head_repository,r.run.repository)||j.total_count!==2||j.jobs.length!==2||!equal(j.jobs.map(x=>x.name).sort(),ci.required_jobs)||j.jobs.some(x=>x.run_id!==id||x.head_sha!==head||x.head_branch!==branch||x.run_attempt!==1||x.status!=='completed'||x.conclusion!=='success'))p.push('Q009 exact '+kind+' push CI required jobs are not completed/success');
  }
  const origin=held.get('docs/pilot/evidence/task0-q009/origin-control.json');
  if(origin?.origin_pass!==true||origin.local_online_verification!==true||origin.merge_commit!==Q009_SOURCE.commit||origin.merge_tree!==Q009_SOURCE.tree||!equal(origin.merge_parents,[ci.accepted_baseline_commit,ci.candidate_commit])||origin.package_entries!==45||origin.canonical_package_sha256!==Q009_SOURCE.canonical_sha256||origin.workflow_sha256!==ci.workflow_sha256)p.push('Q009 exact online merge origin proof changed');
  const module=read(repo,'internal/pilot/task0_source.go').toString();
  for(const [name,value]of [['Task0PrototypeAnnexSHA',Q009_ANNEX_SHA],['Task0PrototypeAuthoritySHA',Q009_AUTHORITY_SHA],['Task0PrototypeAdoptionReviewSHA',Q009_REVIEW_SHA],['Task0PrototypeCIEvidenceSHA',Q009_CI_SHA]])if(!new RegExp(name+'\\s*=\\s*"'+value+'"','u').test(module))p.push('Q009 Go loader control identity changed: '+name);
  const sourceBlock=module.match(/var task0PrototypeSourceBinding = runcore\.SourcePackageBinding\{([^}]+)\}/u)?.[1]??'';
  for(const [field,value]of [['PackageID',Q009_SOURCE.package_id],['Schema',Q009_SOURCE.schema],['Repository',Q009_SOURCE.repository],['Commit',Q009_SOURCE.commit],['Tree',Q009_SOURCE.tree],['CanonicalSHA256',Q009_SOURCE.canonical_sha256]])if(!new RegExp(field+':\\s*"'+value+'"','u').test(sourceBlock))p.push('Q009 Go containing source binding changed: '+field);
  const core=read(repo,'internal/pilot/task0_core.go').toString();
  for(const [name,value]of [['Task0RuntimeAdapterSHA',Q009_ADAPTER_SHA],['Task0RuntimeAdapterCanonicalSHA',sha(canonical(adapter))],['Task0GameGatewaySHA',Q009_GATEWAY_SHA]])if(!new RegExp(name+'\\s*=\\s*"'+value+'"','u').test(core))p.push('Q009 Go driver control identity changed: '+name);
 }catch(e){p.push('Q009 source adoption validation failed closed: '+e.message);}
 return p;
}
function projectedBytesProblems(repo,p,bytes,baselineAllowed) {
  const base=blob(repo,BASE,p);
  if(baselineAllowed&&base?.equals(bytes))return [];
  if(p==='package.json')return bytes?.equals(expectedPackage(repo))?[]:['bounded B007 package entrypoints changed'];
  if(p==='scripts/ci/run-checks.mjs')return bytes?.equals(expectedAggregate(repo))?[]:['bounded B007 aggregate routing changed'];
  if(p===STATUS) {
    try {const s=JSON.parse(bytes);return [...(!bytes.equals(Buffer.from(JSON.stringify(s,null,2)+'\n'))?['B007 status is not canonical JSON']:[]),...statusProblems(JSON.parse(blob(repo,BASE,STATUS)),s,baselineAllowed)];}
    catch{return ['B007 status is missing or unreadable'];}
  }
  // New progress text is additive. All accepted historical prose stays byte-identical.
  const split=base.indexOf(10);
  return bytes&&bytes.subarray(0,split+1).equals(base.subarray(0,split+1))&&bytes.toString().endsWith(base.subarray(split+1).toString())&&bytes.length>=base.length&&bytes.length-base.length<=16384?[]:['historical status/milestone prose changed: '+p];
}
export function topology(repo) {
  const head=out(repo,['rev-parse','HEAD^{commit}']),main=out(repo,['rev-parse','refs/remotes/origin/main^{commit}']);
  const p=[];
  if(facts(repo,BASE)?.tree!==BASE_TREE||!head||!main||!firstParentContains(repo,head,BASE)||!firstParentContains(repo,main,BASE))p.push('exact accepted B006 base and checkout/main first-parent lineage required');
  const candidateFor=(id)=>{
    if(id===BASE)return null;
    const f=facts(repo,id);
    if(equal(f?.parents,[BASE]))return {candidate:f,merge:null};
    const merges=rows(repo,['rev-list','--first-parent',BASE+'..'+id]).map(c=>facts(repo,c)).filter(m=>m?.parents.length===2&&m.parents[0]===BASE&&equal(facts(repo,m.parents[1])?.parents,[BASE])&&m.tree===facts(repo,m.parents[1])?.tree);
    if(merges.length!==1)return null;
    return {candidate:facts(repo,merges[0].parents[1]),merge:merges[0]};
  };
  const h=candidateFor(head),m=candidateFor(main);
  if(head!==BASE&&!h)p.push('B007 HEAD has no exact Candidate/Base or identical-tree merge lineage');
  if(main!==BASE&&!m?.merge)p.push('accepted main must be exact BASE or a verified identical-tree B007 merge lineage');
  if(h&&m&&h.candidate.commit!==m.candidate.commit)p.push('B007 checkout and accepted main disagree on Candidate');
  return {head,main,candidate:h?.candidate??m?.candidate??null,merge:h?.merge??m?.merge??null,problems:p};
}
export function successorProblems(repo) {
  const p=sourceAdoptionProblems(repo);
  try {
    const t=topology(repo);p.push(...t.problems);p.push(...q015ReplacementScopeProblems(repo,t));
    if(!q016Approved(repo))p.push('Q016 explicit Owner decision pending; proposed evidence routing cannot authorize a replacement');
    if(!q017Approved(repo))p.push('Q017 explicit Owner decision pending; proposed test fixture cannot authorize a replacement');
    const baseline=inventory(repo,BASE);
    for(const revision of new Set([t.head,t.main])) {
      if(!revision)continue;
      const tree=inventory(repo,revision);
      const touched=new Set(rows(repo,['log','--first-parent','--full-history','--format=','--name-only',BASE+'..'+revision]));
      for(const [file,entry] of baseline)if(!MUTABLE.has(file)&&(!equal(tree.get(file),entry)||touched.has(file))&&!exactQ015Gate(repo,file,blob(repo,revision,file),revision,t))p.push('protected predecessor bytes/history changed on '+revision+': '+file);
      for(const file of touched)if(!baseline.has(file)&&!allowedNew(file))p.push('unauthorized additive history path: '+file);
      for(const [file,entry] of tree)if(!baseline.has(file)&&(!allowedNew(file)||!['100644','100755'].includes(entry.mode)))p.push('unauthorized/nonregular new tree artifact: '+file);
      for(const [file,digest] of EXACT) {
        const versions=rows(repo,['log','--first-parent','--full-history','--format=%H',BASE+'..'+revision,'--',file]);
        const introductions=rows(repo,['log','--first-parent','--format=%H','--diff-filter=A',BASE+'..'+revision,'--',file]);
        if(versions.length&&(introductions.length!==1||versions.length!==1||sha(blob(repo,revision,file)??'')!==digest))p.push('immutable B007 Owner authority history changed: '+file);
      }
      for(const file of MUTABLE) {
        const ids=new Set([revision,...rows(repo,['log','--first-parent','--full-history','--format=%H',BASE+'..'+revision,'--',file])]);
        for(const id of ids) {
          const merged=t.merge&&firstParentContains(repo,id,t.merge.commit);
          p.push(...projectedBytesProblems(repo,file,blob(repo,id,file),!merged).map(x=>'bounded projection/history on '+revision+' at '+id+': '+x));
        }
      }
      if(t.candidate&&(firstParentContains(repo,revision,t.candidate.commit)||t.merge&&firstParentContains(repo,revision,t.merge.commit))) {
        for(const file of tree.keys())if(allowedNew(file)&&!file.startsWith('docs/pilot/')) {
          const c=inventory(repo,t.candidate.commit).get(file);
          const since=t.merge&&firstParentContains(repo,revision,t.merge.commit)?t.merge.commit:t.candidate.commit;
          if(!equal(tree.get(file),c)||rows(repo,['log','--first-parent','--full-history','--format=%H',since+'..'+revision,'--',file]).length) p.push('B007 committed implementation changed after Candidate: '+file);
        }
      }
    }
    for(const [file,entry] of baseline)if(!MUTABLE.has(file)&&!equal(workingEntry(repo,file),entry)&&!exactQ015Gate(repo,file,read(repo,file),null,t))p.push('protected predecessor working artifact changed: '+file);
    for(const file of MUTABLE)p.push(...projectedBytesProblems(repo,file,read(repo,file),false));
    for(const [file,digest] of EXACT)if(sha(read(repo,file))!==digest)p.push('exact B007 Owner authority changed: '+file);
    for(const file of rows(repo,['ls-files','--cached','--others','--exclude-standard'])) {
      if(!baseline.has(file)&&!allowedNew(file))p.push('unauthorized working path: '+file);
      if(!baseline.has(file))workingEntry(repo,file);
    }
    if(t.candidate)for(const [file,entry] of inventory(repo,t.candidate.commit))if(!MUTABLE.has(file)&&!file.startsWith('docs/pilot/')&&!equal(workingEntry(repo,file),entry))p.push('working B007 implementation differs from exact Candidate: '+file);
  }catch(e){p.push('B007 successor guard failed closed: '+e.message);}
  return [...new Set(p)];
}
const snapshots=new Map();
function snapshot(repo) {
  if(snapshots.has(repo))return snapshots.get(repo);
  const target=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-b007-accepted-b006-'));
  try {
    const clone=spawnSync('git',['clone','--no-local','--no-checkout',repo,target],{encoding:'utf8'});
    if(clone.error||clone.status!==0||git(target,['checkout','--detach',BASE])===null||git(target,['update-ref','refs/remotes/origin/main',BASE])===null||facts(target,'HEAD')?.tree!==BASE_TREE||out(target,['status','--porcelain=v1','--untracked-files=all'])!=='')throw new Error('exact immutable B006 replay expansion failed');
    snapshots.set(repo,target);return target;
  }catch(e){fs.rmSync(target,{recursive:true,force:true});throw e;}
}
export function cleanupSnapshots(){for(const p of snapshots.values())fs.rmSync(p,{recursive:true,force:true});snapshots.clear();}
export function runApprovedPredecessor(ctx,args={}) {
  const evidence=args.gate==='evidence'&&q016Approved(ctx.repo);
  const p=GATES.includes(args.gate)||evidence?successorProblems(ctx.repo):['unknown or unapproved B007 predecessor gate'];let report=null;
  if(p.length===0)try {
    const target=snapshot(ctx.repo);
    if(evidence&&sha(read(target,'scripts/ci/validate/evidence.mjs'))!==Q016_EVIDENCE_SHA)throw new Error('Q016 exact immutable historical evidence entry differs');
    const entry=evidence?['scripts/ci/validate/evidence.mjs']:args.gate==='mvp-b006'?['scripts/ci/validate/mvp-b006.mjs']:['scripts/ci/validate/b006-approved-predecessors.mjs','--gate',args.gate];
    const env=Object.fromEntries(Object.entries(process.env).filter(([k])=>!k.startsWith('GITHUB_')));
    const r=spawnSync(process.execPath,[path.join(target,entry[0]),...entry.slice(1),'--repo',target],{cwd:target,env,encoding:'utf8',maxBuffer:32*1024*1024});
    try{report=JSON.parse(r.stdout);}catch{/* Invalid reports fail closed. */}
    if(r.error||r.signal||r.status!==0||report?.result!=='PASS')p.push('unchanged accepted B006 predecessor replay failed: '+args.gate);
  }catch(e){p.push(e.message);}
  return {result:p.length?'FAIL':'PASS',task_id:TASK,details:p.length?p.map(x=>'FAIL: '+x):['ok: exact accepted B006 predecessor gate PASS','ok: current checkout/main and complete first-parent histories preserve closed predecessor bytes and status'],historical_gate:report,validation_target:{commit:BASE,tree:BASE_TREE,mode:evidence?'EXACT_ACCEPTED_B006_WITH_OWNER_AUTHORIZED_B007_EVIDENCE_Q016_GUARD':'EXACT_ACCEPTED_B006_WITH_OWNER_AUTHORIZED_B007_GUARD'},predecessor_gate_authority:evidence?{path:Q016_AUTHORITY,sha256:Q016_AUTHORITY_SHA,decision_id:'AIPT-MVP-B007-OWNER-Q016'}:{path:AUTHORITY,sha256:AUTHORITY_SHA,decision_id:DECISION},external_github_requests:0,real_model_calls:0};
}
