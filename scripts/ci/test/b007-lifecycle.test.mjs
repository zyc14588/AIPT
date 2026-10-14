import test from 'node:test';
import assert from 'node:assert/strict';
import { Q018_AUTHORITY, Q018_MODIFIED_PATHS, Q019_AUTHORITY, Q019_PROPOSAL, Q019_SMOKE, Q021_AUTHORITY, Q021_PROPOSAL, Q021_WORK_PATHS, Q022_AUTHORITY, Q022_PROPOSAL, Q022_WORK_PATHS, Q022_NEW_PATHS, Q022_BASELINE, q022Approved, q022SourceProblems, q022RevisionProblems, prepareQ022FixedCloneOrigin, q022OriginalTestSource, cleanupQ022OriginalTestSources, Q023_AUTHORITY, Q023_PROPOSAL, Q023_BASELINE, Q023_BASELINE_TREE, Q023_WORK_PATHS, Q023_NEW_PATHS, q023Approved, q023Proposal, q023SourceProblems, q023RevisionProblems, q023LifecycleProblems, prepareQ023FixedCloneOrigin, q023OriginalTestSource, cleanupQ023OriginalTestSources, runQ023FixedP1Reverification, Q024_AUTHORITY, Q024_PROPOSAL, Q024_BASELINE, Q024_BASELINE_TREE, Q024_ORIGINAL_CANDIDATE, Q024_TEST, Q024_WORK_PATHS, Q024_NEW_PATHS, q024Approved, q024Proposal, q024SourceProblems, q024RevisionProblems, q024LifecycleProblems, prepareQ024FixedCloneOrigin, q024OriginalTestSource, cleanupQ024OriginalTestSources, Q025_AUTHORITY, Q025_PROPOSAL, Q025_BASELINE, Q025_BASELINE_TREE, Q025_PARENT, Q025_TEST, Q025_WORK_PATHS, Q025_NEW_PATHS, q025Approved, q025Proposal, q025SourceProblems, q025RevisionProblems, q025LifecycleProblems, q025Topology, prepareQ025FixedCloneOrigin, q025OriginalTestSource, cleanupQ025OriginalTestSources, Q026_AUTHORITY, Q026_PROPOSAL, Q026_BASELINE, Q026_BASELINE_TREE, Q026_PARENT, Q026_OBSERVER, Q026_TEST, Q026_WORK_PATHS, Q026_NEW_PATHS, q026Approved, q026Proposal, q026SourceProblems, q026RevisionProblems, q026LifecycleProblems, q026Topology, prepareQ026FixedCloneOrigin, q026OriginalTestSource, cleanupQ026OriginalTestSources, Q027_AUTHORITY, Q027_PROPOSAL, Q027_BASELINE, Q027_BASELINE_TREE, Q027_PARENT, Q027_OBSERVER, Q027_TEST, Q027_WORK_PATHS, Q027_NEW_PATHS, q027Approved, q027Proposal, q027SourceProblems, q027RevisionProblems, q027LifecycleProblems, q027Topology, prepareQ027FixedCloneOrigin, q027OriginalTestSource, cleanupQ027OriginalTestSources, Q028_AUTHORITY, Q028_PROPOSAL, Q028_BASELINE, Q028_BASELINE_TREE, Q028_PARENT, Q028_OBSERVER, Q028_TEST, Q028_WORK_PATHS, Q028_NEW_PATHS, q028Approved, q028Proposal, q028SourceProblems, q028RevisionProblems, q028LifecycleProblems, q028Topology, prepareQ028FixedCloneOrigin, q028OriginalTestSource, cleanupQ028OriginalTestSources } from '../lib/b007-toolchain-security-q018.mjs';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { BASE,Q015_GATE,Q016_AUTHORITY,Q017_AUTHORITY,Q017_FIXTURE,runApprovedPredecessor,cleanupSnapshots,START,AUTHORITY,Q002_AUTHORITY,Q002_SOURCE,Q003_AUTHORITY,Q003_ANNEX,Q004_AUTHORITY,Q004_PROPOSAL,Q005_AUTHORITY,Q009_AUTHORITY,Q009_ANNEX,Q009_REVIEW,Q009_CI,Q009_ADAPTER,Q009_GATEWAY,Q011_AUTHORITY,STATUS,MUTABLE,allowedNew,successorProblems,rows } from '../lib/b007-successor.mjs';
import { resolveB007 } from '../lib/b007-lifecycle.mjs';
import { inspectConstruction } from '../validate/mvp-b007.mjs';
const q028CurrentSource=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
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
function git(repo,args){const r=spawnSync('git',['-C',repo,...args],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);assert.equal(r.error,undefined);return r.stdout.trim();}
function fixture(t){
 const repo=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-b007-guard-probe-'));
 t.after(()=>fs.rmSync(repo,{recursive:true,force:true}));
 const r=spawnSync('git',['clone','--no-local','--no-checkout',source,repo],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);
 git(repo,['checkout','--detach',BASE]);git(repo,['update-ref','refs/remotes/origin/main',BASE]);
 git(repo,['config','user.name','Synthetic B007 Probe']);git(repo,['config','user.email','probe@example.invalid']);
 for(const p of rows(source,['ls-files','--cached','--others','--exclude-standard']))if(MUTABLE.has(p)||allowedNew(p)||p===Q015_GATE||Q018_MODIFIED_PATHS.includes(p)||p===Q019_SMOKE){
  fs.mkdirSync(path.dirname(path.join(repo,p)),{recursive:true});fs.copyFileSync(path.join(source,p),path.join(repo,p));
 }
 return repo;
}
function commit(repo,message){git(repo,['add','-A']);git(repo,['commit','-m',message]);return git(repo,['rev-parse','HEAD']);}
function write(repo,p,v){fs.writeFileSync(path.join(repo,p),JSON.stringify(v,null,2)+'\n');}
function rejected(repo,pattern){const p=successorProblems(repo);assert.ok(p.some(x=>pattern.test(x)),JSON.stringify(p));}
test('authorized B007 draft preserves actual fixed predecessors and reports construction only',t=>{const r=fixture(t);assert.deepEqual(successorProblems(r),[]);assert.equal(resolveB007(r).phase,'AUTHORIZED_CONSTRUCTION');});
test('B007 public construction inspection preserves incomplete runtime and one unused diagnostic',t=>{const r=fixture(t);const v=inspectConstruction(r);assert.deepEqual(v.problems,[]);assert.equal(v.lifecycle.runtime_ready,false);assert.equal(v.publication.result,'PASS');});
test('B007 public construction inspection rejects a missing parent entry test',t=>{const r=fixture(t);const p=path.join(r,'internal/pilot/task0_preparation_test.go');fs.writeFileSync(p,fs.readFileSync(p,'utf8').replace('func TestTask0ParentControlNeverAcceptsQualificationOrLocators(', 'func RemovedNONCANONRequiredCoverage('));assert.ok(inspectConstruction(r).problems.some(x=>x.includes('required executable rejection coverage')));});
test('B007 public construction inspection rejects diagnostic metadata promoted without actual acceptance',t=>{const r=fixture(t);const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.AIPT.mvp_b007.diagnostic_runs_executed=1;write(r,STATUS,s);assert.ok(inspectConstruction(r).problems.some(x=>x.includes('zero actual model/DIAG/QUAL')));});
test('Q011 permits exactly five additive predecessor-module files',()=>{
 for(const p of ['internal/evidence/private_audit_ready.go','internal/evidence/private_audit_types.go','internal/evidence/private_audit_ready_test.go','internal/evidence/private_audit_postgres_integration_test.go','schemas/evidence/private/v1/aipt-private-audit-ready.schema.json'])assert.equal(allowedNew(p),true,p);
 for(const p of ['internal/evidence/private_other.go','internal/evidence/private_audit_ready_extra.go','schemas/evidence/private/v1/extra.schema.json','internal/runcontrol/private_reports.go'])assert.equal(allowedNew(p),false,p);
});
for(const [name,mutate,pattern]of[
 ['Q015 protected supply-chain successor bytes changed',r=>fs.appendFileSync(path.join(r,Q015_GATE),'\n// corruption\n'),/protected predecessor working|Q018 exact approved current source|Q018 protected original f7 bytes/],
 ['old operational entry mutation',r=>fs.appendFileSync(path.join(r,'internal/operational/runtime.go'),'\n// corruption\n'),/protected predecessor working|Q018 exact approved current source|Q018 protected original f7 bytes/],
 ['frozen migration mutation',r=>fs.appendFileSync(path.join(r,'internal/storage/postgres/migrations/000001_ledger.sql'),'\n-- corruption\n'),/protected predecessor working|Q018 exact approved current source|Q018 protected original f7 bytes/],
 ['original B004 closure mutation',r=>fs.appendFileSync(path.join(r,'scripts/ci/harness-runtime-closure.ts'),'\n// corruption\n'),/protected predecessor working|Q018 exact approved current source|Q018 protected original f7 bytes/],
 ['Owner authority whitespace rewrite',r=>fs.appendFileSync(path.join(r,AUTHORITY),' '),/exact B007 Owner authority/],
 ['Q002 authority whitespace rewrite',r=>fs.appendFileSync(path.join(r,Q002_AUTHORITY),' '),/exact B007 Owner authority/],
 ['Q005 authority byte rewrite',r=>fs.appendFileSync(path.join(r,Q005_AUTHORITY),' '),/exact B007 Owner authority/],
 ['Q011 approved private evidence authority rewrite',r=>fs.appendFileSync(path.join(r,Q011_AUTHORITY),' '),/exact B007 Owner authority/],
 ['Q011 status authority unbinding',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.AIPT.mvp_b007.private_evidence_successor_authority_sha256='0'.repeat(64);write(r,STATUS,s);},/Q011 private evidence authority/],
 ['Q011 component construction falsely promoted to full acceptance',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.AIPT.mvp_b007.private_evidence_full_acceptance=true;write(r,STATUS,s);},/Q011 private evidence authority/],
 ['Q009 accepted source authority byte rewrite',r=>fs.appendFileSync(path.join(r,Q009_AUTHORITY),' '),/Q009 frozen source control|exact B007 Owner authority/],
 ['Q009 accepted 45-source annex rewrite',r=>fs.appendFileSync(path.join(r,Q009_ANNEX),' '),/Q009 frozen source control|exact B007 Owner authority/],
 ['Q009 source-only review rewritten as runtime acceptance',r=>{const v=JSON.parse(fs.readFileSync(path.join(r,Q009_REVIEW)));v.runtime_ready=true;write(r,Q009_REVIEW,v);},/Q009 frozen source control|exact B007 Owner authority/],
 ['Q009 candidate CI hash substituted in the evidence index',r=>{const v=JSON.parse(fs.readFileSync(path.join(r,Q009_CI)));v.candidate_commit='0'.repeat(40);write(r,Q009_CI,v);},/Q009 frozen source control|exact B007 Owner authority/],
 ['Q009 exact merge job replaced by a pending job',r=>{const p='docs/pilot/evidence/task0-q009/merge-jobs.json';const v=JSON.parse(fs.readFileSync(path.join(r,p)));v.jobs[0].status='queued';write(r,p,v);},/Q009 frozen source control|exact B007 Owner authority/],
 ['Q009 source status binding changed',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.AIPT.mvp_b007.task0_prototype_source_package.commit='0'.repeat(40);write(r,STATUS,s);},/Q009 exact source authority/],
 ['Q009 old 17-source annex silently replaced by new source annex',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.AIPT.mvp_b007.task0_input_annex_sha256=s.repositories.AIPT.mvp_b007.task0_prototype_input_annex_sha256;write(r,STATUS,s);},/authority\/budget/],
 ['Q009 source adapter identity rewrite',r=>fs.appendFileSync(path.join(r,Q009_ADAPTER),' '),/Q009 frozen source control|exact B007 Owner authority/],
 ['Q009 executable gateway rewrite',r=>fs.appendFileSync(path.join(r,Q009_GATEWAY),'\n// substitution\n'),/Q009 frozen source control|exact B007 Owner authority/],
 ['Q009 Go source binding replacement',r=>{const p=path.join(r,'internal/pilot/task0_source.go');fs.writeFileSync(p,fs.readFileSync(p,'utf8').replace('d37ae9b38bce84f8bfc164306fee2bebf73178b7','0'.repeat(40)));},/Go containing source binding changed/],
 ['Q009 Go gateway binding replacement',r=>{const p=path.join(r,'internal/pilot/task0_core.go');fs.writeFileSync(p,fs.readFileSync(p,'utf8').replace('805e82a71d16f974e209ab0d3b8d8ae3d5f273239b1f96e3f31bc6d4cfb648a2','0'.repeat(64)));},/Go driver control identity changed/],
 ['Q005 authority status unbinding',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.AIPT.mvp_b007.independent_reviewer_continuity_authority_sha256='0'.repeat(64);write(r,STATUS,s);},/authority\/budget/],
 ['Q005 decision status unbinding',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.AIPT.mvp_b007.independent_reviewer_continuity_decision_id='unapproved';write(r,STATUS,s);},/authority\/budget/],
 ['Q004 authority byte rewrite',r=>fs.appendFileSync(path.join(r,Q004_AUTHORITY),' '),/exact B007 Owner authority/],
 ['Q004 approved proposal byte rewrite',r=>fs.appendFileSync(path.join(r,Q004_PROPOSAL),' '),/exact B007 Owner authority/],
 ['Q004 authority status unbinding',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.AIPT.mvp_b007.local_runtime_closure_authority_sha256='0'.repeat(64);write(r,STATUS,s);},/authority\/budget/],
 ['Q004 decision status unbinding',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.AIPT.mvp_b007.local_runtime_closure_decision_id='unapproved';write(r,STATUS,s);},/authority\/budget/],
 ['Q003 authority whitespace rewrite',r=>fs.appendFileSync(path.join(r,Q003_AUTHORITY),' '),/exact B007 Owner authority/],
 ['Q003 annex byte mutation',r=>fs.appendFileSync(path.join(r,Q003_ANNEX),' '),/exact B007 Owner authority/],
 ['Q003 authority status unbinding',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.AIPT.mvp_b007.task0_supplemental_input_authority_sha256='0'.repeat(64);write(r,STATUS,s);},/authority\/budget/],
 ['Q002 approved source byte mutation',r=>fs.appendFileSync(path.join(r,Q002_SOURCE),'\n// corruption\n'),/exact B007 Owner authority/],
 ['Q002 authority status unbinding',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.AIPT.mvp_b007.closure_successor_authority_sha256='0'.repeat(64);write(r,STATUS,s);},/authority\/budget/],
 ['Owner start removal',r=>fs.unlinkSync(path.join(r,START)),/failed closed/],
 ['B006 reopened',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.AIPT.mvp_b006.state='IN_PROGRESS';write(r,STATUS,s);},/frozen predecessor status/],
 ['integration reopened',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.tracks['AIPT-STANDALONE'].batch_history['INT-AIPT-UNREGISTERED-MVP-001']='NOT_STARTED';write(r,STATUS,s);},/frozen predecessor status/],
 ['future batch activated',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.tracks['AIPT-STANDALONE'].next_batch_started=true;write(r,STATUS,s);},/sole-WIP1/],
 ['qualification metadata promotion',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.AIPT.mvp_b007.qualification_runs_executed=1;write(r,STATUS,s);},/nonqualification/],
 ['unauthorized budget increase',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.AIPT.mvp_b007.diagnostic_budget_usd='6.00';write(r,STATUS,s);},/budget/],
 ['new dependency',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,'package.json')));s.dependencies={evil:'1'};write(r,'package.json',s);},/bounded B007 package/],
 ['old required test removal',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,'package.json')));delete s.scripts['test:run-core'];write(r,'package.json',s);},/bounded B007 package/],
 ['old milestone rewrite',r=>fs.appendFileSync(path.join(r,'docs/milestones/MVP.md'),'historical corruption\n'),/historical status\/milestone prose/],
 ['symlinked new pilot source',r=>{const p=path.join(r,'internal/pilot/budget.go');fs.unlinkSync(p);fs.symlinkSync('/dev/null',p);},/nonregular/],
 ['absent accepted main',r=>git(r,['update-ref','-d','refs/remotes/origin/main']),/checkout\/main/],
])test('current guard rejects '+name,t=>{const r=fixture(t);mutate(r);rejected(r,pattern);});
for(const p of [Q015_GATE,Q016_AUTHORITY,Q017_AUTHORITY,Q017_FIXTURE,'scripts/ci/validate/evidence.mjs','scripts/ci/run-checks.mjs','internal/evidence/remote_provenance.go','package.json',STATUS,AUTHORITY,Q002_AUTHORITY,Q002_SOURCE,Q003_AUTHORITY,Q003_ANNEX,Q004_AUTHORITY,Q004_PROPOSAL,Q005_AUTHORITY,Q009_AUTHORITY,Q009_ANNEX,Q009_REVIEW,Q009_CI,Q009_ADAPTER,Q009_GATEWAY,Q011_AUTHORITY,'docs/pilot/evidence/task0-q009/merge-jobs.json'])test('clean older checkout cannot hide main rewrite/restore: '+p,t=>{
 const r=fixture(t);const candidate=commit(r,'Synthetic B007 Candidate');assert.deepEqual(successorProblems(r),[]);
 git(r,['switch','-c','synthetic-main',BASE]);git(r,['merge','--no-ff','--no-edit',candidate]);const merge=git(r,['rev-parse','HEAD']);git(r,['update-ref','refs/remotes/origin/main',merge]);assert.deepEqual(successorProblems(r),[]);
 const original=fs.readFileSync(path.join(r,p));
 if(p===STATUS){const v=JSON.parse(original);v.repositories.AIPT.mvp_b006.state='IN_PROGRESS';write(r,p,v);}else fs.appendFileSync(path.join(r,p),'\n// synthetic corruption\n');
 commit(r,'Synthetic corrupt main');fs.writeFileSync(path.join(r,p),original);const restored=commit(r,'Synthetic restore');git(r,['update-ref','refs/remotes/origin/main',restored]);git(r,['checkout','--detach',candidate]);
 rejected(r,/history changed|projection\/history/);
});
test('B007 committed Candidate implementation cannot mutate in a clean older checkout/main successor',t=>{
 const r=fixture(t);const candidate=commit(r,'Synthetic Candidate');
 git(r,['switch','-c','synthetic-main',BASE]);git(r,['merge','--no-ff','--no-edit',candidate]);fs.appendFileSync(path.join(r,'internal/pilot/budget.go'),'\n// unauthorized post-Candidate mutation\n');const changed=commit(r,'Synthetic changed implementation');git(r,['update-ref','refs/remotes/origin/main',changed]);git(r,['checkout','--detach',candidate]);
 rejected(r,/committed implementation changed/);
});

test('Q016 evidence wrapper replays the complete frozen gate at exact accepted BASE',t=>{
 const r=fixture(t);t.after(cleanupSnapshots);commit(r,'Synthetic Q016 exact Candidate');
 const v=runApprovedPredecessor({repo:r},{gate:'evidence'});
 assert.equal(v.result,'PASS',JSON.stringify(v));assert.equal(v.historical_gate.result,'PASS');
 assert.equal(v.validation_target.commit,BASE);assert.equal(v.validation_target.mode,'EXACT_ACCEPTED_B006_WITH_OWNER_AUTHORIZED_B007_EVIDENCE_Q016_GUARD');
 assert.equal(v.predecessor_gate_authority.path,Q016_AUTHORITY);assert.equal(v.external_github_requests,0);assert.equal(v.real_model_calls,0);
});
for(const [name,mutate]of[
 ['Owner authority removed',r=>fs.unlinkSync(path.join(r,Q016_AUTHORITY))],
 ['Owner decision still proposal',r=>{const a=JSON.parse(fs.readFileSync(path.join(r,Q016_AUTHORITY)));a.state='PROPOSAL_ONLY_NO_OWNER_DECISION';a.owner_instruction=null;write(r,Q016_AUTHORITY,a);}],
 ['Owner authority byte rewrite',r=>fs.appendFileSync(path.join(r,Q016_AUTHORITY),' ')],
 ['package restored to unapproved direct gate',r=>{const a=JSON.parse(fs.readFileSync(path.join(r,'package.json')));a.scripts['check:evidence']='node scripts/ci/validate/evidence.mjs';write(r,'package.json',a);}],
 ['aggregate restored to unapproved direct gate',r=>{const p=path.join(r,'scripts/ci/run-checks.mjs');fs.writeFileSync(p,fs.readFileSync(p,'utf8').replace("  runApprovedPredecessor(ctx, { gate: 'evidence' }),",'  runEvidence(ctx),'));}],
 ['current frozen evidence bytes altered',r=>fs.appendFileSync(path.join(r,'scripts/ci/validate/evidence.mjs'),'\n// unapproved inventory change\n')],
 ['accepted main removed',r=>git(r,['update-ref','-d','refs/remotes/origin/main'])],
])test('Q016 evidence replay is blocked before running historical gate: '+name,t=>{
 const r=fixture(t);t.after(cleanupSnapshots);mutate(r);const v=runApprovedPredecessor({repo:r},{gate:'evidence'});
 assert.equal(v.result,'FAIL');assert.equal(v.historical_gate,null);
});
test('Q016 bounded routing cannot authorize any other predecessor gate',t=>{
 const r=fixture(t);const v=runApprovedPredecessor({repo:r},{gate:'evidence-other'});assert.equal(v.result,'FAIL');assert.equal(v.historical_gate,null);
});
test('Q016 replacement still rejects changed Q011 implementation after synthetic commit',t=>{
 const r=fixture(t);fs.appendFileSync(path.join(r,'internal/evidence/private_audit_ready.go'),'\n// unapproved replacement\n');commit(r,'Synthetic forbidden private implementation change');
 rejected(r,/Q015 unapproved replacement changed original implementation/);
});
test('Q016 replacement still rejects an unrelated new file after synthetic commit',t=>{
 const r=fixture(t);fs.writeFileSync(path.join(r,'unapproved-evidence-skip.txt'),'not approved\n');commit(r,'Synthetic unrelated addition');
 rejected(r,/Q015 unapproved replacement addition/);
});

for(const [name,mutate]of[
 ['Owner authority removed',r=>fs.unlinkSync(path.join(r,Q017_AUTHORITY))],
 ['Owner decision still proposal',r=>{const a=JSON.parse(fs.readFileSync(path.join(r,Q017_AUTHORITY)));a.state='PROPOSAL_ONLY_NO_OWNER_DECISION';a.owner_instruction=null;write(r,Q017_AUTHORITY,a);}],
 ['Owner authority byte rewrite',r=>fs.appendFileSync(path.join(r,Q017_AUTHORITY),' ')],
 ['exact fixture allocator setting changed',r=>{const p=path.join(r,Q017_FIXTURE);fs.writeFileSync(p,fs.readFileSync(p,'utf8').replace('MALLOC_ARENA_MAX=1','MALLOC_ARENA_MAX=2'));}],
])test('Q017 fixture proposal is blocked before historical replay: '+name,t=>{
 const r=fixture(t);t.after(cleanupSnapshots);mutate(r);const v=runApprovedPredecessor({repo:r},{gate:'evidence'});
 assert.equal(v.result,'FAIL');assert.equal(v.historical_gate,null);
});
test('Q017 replacement rejects committed fixture bytes beyond the exact child-only repair',t=>{
 const r=fixture(t);fs.appendFileSync(path.join(r,Q017_FIXTURE),'\n// unapproved assertion change\n');commit(r,'Synthetic forbidden fixture repair');
 rejected(r,/Q017 replacement differs from exact test-child-only fixture bytes|exact B007 Owner authority changed|Q018 diagnostics-only fixture identity changed/);
});
test('Q017 test fixture permission cannot authorize production namespace changes',t=>{
 const r=fixture(t);fs.appendFileSync(path.join(r,'internal/pilot/runtime_namespace.go'),'\n// unapproved production change\n');commit(r,'Synthetic forbidden runtime repair');
 rejected(r,/Q015 unapproved replacement changed original implementation/);
});

for(const [name,mutate]of[
 ['Owner authority removed',r=>fs.unlinkSync(path.join(r,Q018_AUTHORITY))],
 ['Owner decision still proposal',r=>{const v=JSON.parse(fs.readFileSync(path.join(r,Q018_AUTHORITY)));v.state='PROPOSAL_ONLY_NOT_OWNER_AUTHORIZED';v.owner_instruction=null;write(r,Q018_AUTHORITY,v);} ],
 ['Owner authority bytes rewritten',r=>fs.appendFileSync(path.join(r,Q018_AUTHORITY),' ')],
 ['current Go pins downgraded',r=>fs.writeFileSync(path.join(r,'.go-version'),'1.26.6\n')],
 ['namespace diagnostics assertions broadened',r=>fs.appendFileSync(path.join(r,Q017_FIXTURE),'\n// unapproved assertions\n')],
])test('Q018 current source fails closed before historical replay: '+name,t=>{
 const r=fixture(t);t.after(cleanupSnapshots);mutate(r);const v=runApprovedPredecessor({repo:r},{gate:'evidence'});
 assert.equal(v.result,'FAIL');assert.equal(v.historical_gate,null);
});

// Q019 keeps every original96 case and adds only its exact smoke/routing scope.
for(const [name,mutate]of[
 ['Owner authority removed',r=>fs.unlinkSync(path.join(r,Q019_AUTHORITY))],
 ['Owner decision still proposal',r=>{const v=JSON.parse(fs.readFileSync(path.join(r,Q019_AUTHORITY)));v.state='PROPOSAL_ONLY_NO_OWNER_DECISION';v.owner_instruction=null;write(r,Q019_AUTHORITY,v);}],
 ['Owner authority bytes rewritten',r=>fs.appendFileSync(path.join(r,Q019_AUTHORITY),' ')],
 ['bound proposal removed',r=>fs.unlinkSync(path.join(r,Q019_PROPOSAL))],
 ['bound proposal bytes rewritten',r=>fs.appendFileSync(path.join(r,Q019_PROPOSAL),' ')],
 ['smoke downgraded to historical Go',r=>{const p=path.join(r,Q019_SMOKE);fs.writeFileSync(p,fs.readFileSync(p,'utf8').replaceAll('go1.26.9','go1.26.6'));}],
 ['smoke changed to any other version',r=>{const p=path.join(r,Q019_SMOKE);fs.writeFileSync(p,fs.readFileSync(p,'utf8').replaceAll('go1.26.9','go1.26.10'));}],
 ['compiler assertion removed',r=>{const p=path.join(r,Q019_SMOKE);fs.writeFileSync(p,fs.readFileSync(p,'utf8').replace(/\tif runtime\.Compiler != "gc" \{\n\t\tt\.Fatalf\("unexpected compiler %q, want gc", runtime\.Compiler\)\n\t\}\n/u,''));}],
 ['unlisted source addition',r=>fs.writeFileSync(path.join(r,'docs/pilot/unapproved-q019-followon.json'),'{}\n')],
])test('Q019 exact smoke scope is blocked before historical replay: '+name,t=>{
 const r=fixture(t);t.after(cleanupSnapshots);mutate(r);
 const v=runApprovedPredecessor({repo:r},{gate:'evidence'});
 assert.equal(v.result,'FAIL');assert.equal(v.historical_gate,null);
 assert.ok(v.details.some(x=>/Q019|exact650/u.test(x)),JSON.stringify(v));
});
for(const p of [Q019_SMOKE,Q019_AUTHORITY,Q019_PROPOSAL])test('Q019 clean older checkout cannot hide main rewrite/restore: '+p,t=>{
 const r=fixture(t);t.after(cleanupSnapshots);
 const candidate=commit(r,'Synthetic exact Q019 Candidate');assert.deepEqual(successorProblems(r),[]);
 git(r,['switch','-c','synthetic-main',BASE]);git(r,['merge','--no-ff','--no-edit',candidate]);
 const merge=git(r,['rev-parse','HEAD']);git(r,['update-ref','refs/remotes/origin/main',merge]);
 assert.deepEqual(successorProblems(r),[]);
 const original=fs.readFileSync(path.join(r,p));fs.appendFileSync(path.join(r,p),'\n// synthetic Q019 corruption\n');
 commit(r,'Synthetic Q019 corrupt main');fs.writeFileSync(path.join(r,p),original);
 const restored=commit(r,'Synthetic Q019 restore');git(r,['update-ref','refs/remotes/origin/main',restored]);
 git(r,['checkout','--detach',candidate]);
 const v=runApprovedPredecessor({repo:r},{gate:'evidence'});
 assert.equal(v.result,'FAIL');assert.equal(v.historical_gate,null);
 assert.ok(v.details.some(x=>/history changed/u.test(x)),JSON.stringify(v));
});
test('exact original f7 history permits only the approved650 working construction delta',t=>{
 const r=fixture(t);
 git(r,['checkout','--force','--detach','f7c3736acd3524240ec178dc81e0a1c72a690930']);
 for(const p of rows(source,['ls-files','--cached','--others','--exclude-standard']))if(MUTABLE.has(p)||allowedNew(p)||p===Q015_GATE||Q018_MODIFIED_PATHS.includes(p)||p===Q019_SMOKE){
  fs.mkdirSync(path.dirname(path.join(r,p)),{recursive:true});fs.copyFileSync(path.join(source,p),path.join(r,p));
 }
 assert.deepEqual(successorProblems(r),[]);
});
test('exact original f7 aggregate never authorizes restored old current working bytes',t=>{
 const r=fixture(t);t.after(cleanupSnapshots);
 const old=spawnSync('git',['-C',r,'show','f7c3736acd3524240ec178dc81e0a1c72a690930:scripts/ci/run-checks.mjs']);
 assert.equal(old.status,0);assert.equal(old.error,undefined);
 fs.writeFileSync(path.join(r,'scripts/ci/run-checks.mjs'),old.stdout);
 const v=runApprovedPredecessor({repo:r},{gate:'evidence'});
 assert.equal(v.result,'FAIL');assert.equal(v.historical_gate,null);
 assert.ok(v.details.some(x=>/bounded B007 aggregate routing changed/u.test(x)),JSON.stringify(v));
});

// Original110 cases remain intact; Q021 adds only its bounded4+2 successor.
for(const [name,mutate]of[
 ['Owner authority absent',r=>fs.unlinkSync(path.join(r,Q021_AUTHORITY))],
 ['Owner decision still proposal',r=>{const p=path.join(r,Q021_AUTHORITY);fs.chmodSync(p,0o600);const v=JSON.parse(fs.readFileSync(p));v.state='PROPOSAL_ONLY';v.owner_instruction=null;write(r,Q021_AUTHORITY,v);}],
 ['Owner bytes changed',r=>{const p=path.join(r,Q021_AUTHORITY);fs.chmodSync(p,0o600);fs.appendFileSync(p,' ');}],
 ['bound proposal absent',r=>fs.unlinkSync(path.join(r,Q021_PROPOSAL))],
 ['bound proposal bytes changed',r=>{const p=path.join(r,Q021_PROPOSAL);fs.chmodSync(p,0o600);fs.appendFileSync(p,' ');}],
 ['protected workflow changed',r=>fs.appendFileSync(path.join(r,'.github/workflows/ci.yml'),'\n# changed\n')],
 ['protected module graph changed',r=>fs.appendFileSync(path.join(r,'go.sum'),'changed\n')],
 ['protected current public status changed',r=>fs.appendFileSync(path.join(r,STATUS),' ')],
 ['protected fixed qualification changed',r=>fs.appendFileSync(path.join(r,'docs/pilot/evidence/task0-q018/toolchain-dependency-qualification.json'),' ')],
 ['protected current execution mode changed',r=>fs.chmodSync(path.join(r,'internal/operational/runtime.go'),0o700)],
 ['unexpected source addition',r=>fs.writeFileSync(path.join(r,'docs/pilot/q021-unapproved-extra.json'),'{}\n')],
 ['missing work source',r=>fs.unlinkSync(path.join(r,Q021_WORK_PATHS[0]))],
])test('Q021 full652 source blocks historical replay: '+name,t=>{
 const r=fixture(t);t.after(cleanupSnapshots);mutate(r);
 const v=runApprovedPredecessor({repo:r},{gate:'evidence'});
 assert.equal(v.result,'FAIL');assert.equal(v.historical_gate,null);
 assert.ok(v.details.some(x=>/Q021|exact650|protected exact650/u.test(x)),JSON.stringify(v));
});
for(const p of [...Q021_WORK_PATHS,Q021_AUTHORITY,Q021_PROPOSAL,STATUS])test('Q021 all work/Owner/protected paths reject main rewrite and restore: '+p,t=>{
 const r=fixture(t);t.after(cleanupSnapshots);
 const candidate=commit(r,'Synthetic exact Q021 Candidate');assert.deepEqual(successorProblems(r),[]);
 git(r,['switch','-c','synthetic-q021-main',BASE]);git(r,['merge','--no-ff','--no-edit',candidate]);
 const merge=git(r,['rev-parse','HEAD']);git(r,['update-ref','refs/remotes/origin/main',merge]);
 assert.deepEqual(successorProblems(r),[]);
 const file=path.join(r,p),original=fs.readFileSync(file);fs.chmodSync(file,0o600);fs.appendFileSync(file,'\n// synthetic Q021 corruption\n');
 commit(r,'Synthetic Q021 corrupt main');fs.writeFileSync(file,original);
 const restored=commit(r,'Synthetic Q021 restore');git(r,['update-ref','refs/remotes/origin/main',restored]);
 git(r,['checkout','--detach',candidate]);
 const v=runApprovedPredecessor({repo:r},{gate:'evidence'});
 assert.equal(v.result,'FAIL');assert.equal(v.historical_gate,null);
 assert.ok(v.details.some(x=>/Q021.*history changed|history changed/u.test(x)),JSON.stringify(v));
});
test('Q021 prospective replacement cannot inherit a non-BASE parent',t=>{
 const r=fixture(t);t.after(cleanupSnapshots);
 commit(r,'Synthetic initial Q021 Candidate');fs.appendFileSync(path.join(r,Q021_WORK_PATHS[0]),'\n// synthetic successor\n');
 commit(r,'Synthetic impermissible extra Candidate parent');
 assert.ok(successorProblems(r).some(x=>/Candidate\/Base|lineage/u.test(x)));
});
test('Q021 original failed PR29 remains exact and permits only its4+2 construction',t=>{
 const r=fixture(t);
 git(r,['checkout','--force','--detach','d9228b80329380aafc9282f6ce72aa5c0eb30b11']);
 for(const p of [...Q021_WORK_PATHS,Q021_AUTHORITY,Q021_PROPOSAL]){const dest=path.join(r,p);fs.mkdirSync(path.dirname(dest),{recursive:true});if(fs.existsSync(dest))fs.chmodSync(dest,0o600);fs.copyFileSync(path.join(source,p),dest);}
 assert.deepEqual(successorProblems(r),[]);
});

function q022LiveFixture(t) {
 const repo=fixture(t);
 for(const relative of [...Q022_WORK_PATHS,...Q022_NEW_PATHS]){const dest=path.join(repo,relative);fs.mkdirSync(path.dirname(dest),{recursive:true});if(fs.existsSync(dest))fs.chmodSync(dest,0o600);fs.copyFileSync(path.join(currentSource,relative),dest);fs.chmodSync(dest,fs.statSync(path.join(currentSource,relative)).mode&0o777);}
 return repo;
}
test('Q022 live654 construction retains original307935c652 and mandatory local positive',t=>{
 const repo=q022LiveFixture(t);assert.deepEqual(successorProblems(repo),[]);assert.deepEqual(q022RevisionProblems(repo,Q022_BASELINE,{original:true}),[]);
 const candidate=commit(repo,'Synthetic exact Q022 soleBASE candidate');assert.deepEqual(successorProblems(repo),[]);
 assert.deepEqual(q022RevisionProblems(repo,candidate),[]);
});
test('Q022 original failed PR30 permits only exact6+2 current construction',t=>{
 const repo=q022LiveFixture(t);git(repo,['checkout','--force','--detach',Q022_BASELINE]);
 for(const relative of [...Q022_WORK_PATHS,...Q022_NEW_PATHS]){const dest=path.join(repo,relative);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(path.join(currentSource,relative),dest);}
 assert.deepEqual(successorProblems(repo),[]);
});
for(const [name,mutate]of[
 ['Owner Authority absent',r=>fs.unlinkSync(path.join(r,Q022_AUTHORITY))],
 ['Owner proposal absent',r=>fs.unlinkSync(path.join(r,Q022_PROPOSAL))],
 ['Owner Authority byte change',r=>fs.appendFileSync(path.join(r,Q022_AUTHORITY),' ')],
 ['baseline tree substitution',r=>{const f=path.join(r,Q022_PROPOSAL),v=JSON.parse(fs.readFileSync(f));v.baseline.tree='0'.repeat(40);fs.writeFileSync(f,JSON.stringify(v));}],
 ['Q021 history changed',r=>fs.appendFileSync(path.join(r,Q021_PROPOSAL),' ')],
 ['namespace required bypass',r=>{const f=path.join(r,'internal/pilot/runtime_namespace_test.go');fs.writeFileSync(f,fs.readFileSync(f,'utf8').replace('contextErr == nil && !required','contextErr == nil && true'));}],
 ['production namespace bytes changed',r=>fs.appendFileSync(path.join(r,'internal/pilot/runtime_namespace.go'),'\n// forbidden\n')],
 ['source outside654',r=>fs.writeFileSync(path.join(r,'q022-unknown.txt'),'forbidden\n')],
])test('Q022 successor refuses before historical replay: '+name,t=>{
 const repo=q022LiveFixture(t);t.after(cleanupSnapshots);mutate(repo);const v=runApprovedPredecessor({repo},{gate:'evidence'});assert.equal(v.result,'FAIL');assert.equal(v.historical_gate,null);
});
for(const relative of [...Q022_WORK_PATHS,...Q022_NEW_PATHS])test('Q022 complete654 history rejects rewrite then restore: '+relative,t=>{
 const repo=q022LiveFixture(t);t.after(cleanupSnapshots);const candidate=commit(repo,'Synthetic Q022 candidate');
 git(repo,['switch','-c','synthetic-q022-main',BASE]);git(repo,['merge','--no-ff','--no-edit',candidate]);const merge=git(repo,['rev-parse','HEAD']);git(repo,['update-ref','refs/remotes/origin/main',merge]);assert.deepEqual(successorProblems(repo),[]);
 const f=path.join(repo,relative),bytes=fs.readFileSync(f);fs.appendFileSync(f,'\n// synthetic forbidden Q022 history\n');commit(repo,'Synthetic Q022 corrupted main');fs.writeFileSync(f,bytes);const restore=commit(repo,'Synthetic Q022 restored bytes');git(repo,['update-ref','refs/remotes/origin/main',restore]);git(repo,['checkout','--detach',candidate]);
 const result=runApprovedPredecessor({repo},{gate:'evidence'});assert.equal(result.result,'FAIL');assert.equal(result.historical_gate,null);assert.ok(result.details.some(v=>/history changed/u.test(v)),JSON.stringify(result));
});

// Q023 cases use live656; all original149 cases/helper bodies remain above.
function q023LifecycleFixture(t,head=BASE) {
 const owned=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q023-lifecycle-')),repo=path.join(owned,'source');
 t.after(()=>{
  let bytes=0,files=0,dirs=0;
  const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){bytes+=s.size;files++;}};
  walk(owned);fs.rmSync(owned,{recursive:true,force:true});assert.equal(fs.existsSync(owned),false);
  console.log(JSON.stringify({owned_scratch:owned,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0}));
 });
 const r=spawnSync('/usr/bin/git',['clone','--no-local','--no-checkout',q023CurrentSource,repo],{encoding:'utf8'});assert.equal(r.error,undefined);assert.equal(r.status,0,r.stderr);
 git(repo,['checkout','--detach',head]);git(repo,['update-ref','refs/remotes/origin/main',BASE]);
 git(repo,['config','user.name','Synthetic Q023 Probe']);git(repo,['config','user.email','probe@example.invalid']);git(repo,['config','core.hooksPath','/dev/null']);
 const paths=rows(q023CurrentSource,['ls-files','--cached','--others','--exclude-standard']);assert.equal(new Set(paths).size,656);
 for(const relative of paths){const dest=path.join(repo,relative);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(path.join(q023CurrentSource,relative),dest);}
 return repo;
}
function q023Merge(repo,candidate) {
 git(repo,['switch','-c','synthetic-q023-main',BASE]);git(repo,['merge','--no-ff','--no-edit',candidate]);
 const merge=git(repo,['rev-parse','HEAD']);git(repo,['update-ref','refs/remotes/origin/main',merge]);return merge;
}
test('Q023 all original149 lifecycle cases and helpers retain their complete fixed654 bodies',()=>{
 const relative='scripts/ci/test/b007-lifecycle.test.mjs',old=fs.readFileSync(path.join(currentSource,relative),'utf8'),next=fs.readFileSync(path.join(q023CurrentSource,relative),'utf8');
 assert.ok(next.slice(next.indexOf('function git(repo,args)')).startsWith(old.slice(old.indexOf('function git(repo,args)'))));
});
test('Q023 exact BASE construction and fixed failed PR31 construction pass without accepting that PR',t=>{
 for(const head of [BASE,Q023_BASELINE]){
  const repo=q023LifecycleFixture(t,head);assert.deepEqual(q023LifecycleProblems(repo),[]);assert.deepEqual(successorProblems(repo),[]);
  const proposal=q023Proposal(repo);assert.equal(proposal.original_PR31_CI.FAIL,2);assert.equal(proposal.runtime_ready,false);assert.equal(proposal.paid_callable,false);
 }
});
test('Q023 full656 single-BASE Candidate and identical-tree merge preserve all source and history',t=>{
 const repo=q023LifecycleFixture(t);const candidate=commit(repo,'Synthetic Q023 full656 Candidate');
 assert.deepEqual(q023RevisionProblems(repo,candidate),[]);assert.deepEqual(q023SourceProblems(repo),[]);assert.deepEqual(successorProblems(repo),[]);
 const merge=q023Merge(repo,candidate);assert.equal(git(repo,['rev-parse',merge+'^{tree}']),git(repo,['rev-parse',candidate+'^{tree}']));
 assert.deepEqual(q023LifecycleProblems(repo),[]);assert.deepEqual(q023SourceProblems(repo),[]);assert.deepEqual(successorProblems(repo),[]);
});
test('Q023 rejects a successor whose parent is failed PR31 instead of accepted BASE',t=>{
 const repo=q023LifecycleFixture(t,Q023_BASELINE);commit(repo,'Synthetic forbidden PR31 parent');
 assert.ok(q023LifecycleProblems(repo).length);assert.ok(successorProblems(repo).length);
});
test('Q023 failed PR31 cannot be promoted to an accepted identical-tree main merge',t=>{
 const repo=q023LifecycleFixture(t,Q023_BASELINE);git(repo,['reset','--hard','HEAD']);
 git(repo,['switch','-c','synthetic-failed-pr31-main',BASE]);git(repo,['merge','--no-ff','--no-edit',Q023_BASELINE]);
 const merge=git(repo,['rev-parse','HEAD']);git(repo,['update-ref','refs/remotes/origin/main',merge]);
 for(const relative of rows(q023CurrentSource,['ls-files','--cached','--others','--exclude-standard'])){const dest=path.join(repo,relative);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(path.join(q023CurrentSource,relative),dest);}
 assert.ok(q023LifecycleProblems(repo).some(v=>/failed PR31 cannot authorize/.test(v)));assert.ok(successorProblems(repo).length);
});
for(const [name,mutate]of[
 ['unknown additive pilot path',r=>fs.writeFileSync(path.join(r,'docs/pilot/q023-unapproved.txt'),'unexpected\n')],
 ['missing Q023 Authority',r=>fs.unlinkSync(path.join(r,Q023_AUTHORITY))],
 ['missing Q023 proposal',r=>fs.unlinkSync(path.join(r,Q023_PROPOSAL))],
 ['changed old Q022 Authority',r=>fs.appendFileSync(path.join(r,Q022_AUTHORITY),' ')],
 ['protected namespace rewrite',r=>fs.appendFileSync(path.join(r,Q017_FIXTURE),'\n// unapproved\n')],
 ['protected operational rewrite',r=>fs.appendFileSync(path.join(r,'internal/operational/runtime.go'),'\n// unapproved\n')],
 ['new workflow mode',r=>fs.chmodSync(path.join(r,'.github/workflows/ci.yml'),0o700)],
 ['new Owner mode',r=>fs.chmodSync(path.join(r,Q023_AUTHORITY),0o700)],
 ['exact P1 selector rewrite',r=>{const f=path.join(r,'.github/workflows/ci.yml');fs.writeFileSync(f,fs.readFileSync(f,'utf8').replace('--q023-fixed-p1-reverification','--p1-reverification'));}],
 ['missing accepted main',r=>git(r,['update-ref','-d','refs/remotes/origin/main'])],
])test('Q023 lifecycle rejects '+name,t=>{const repo=q023LifecycleFixture(t);mutate(repo);assert.ok(successorProblems(repo).length);});
for(const relative of [...Q023_WORK_PATHS,...Q023_NEW_PATHS,Q022_AUTHORITY,Q022_PROPOSAL,Q017_FIXTURE,'internal/operational/runtime.go','package.json','go.mod',STATUS])test('Q023 complete source history rejects hidden main rewrite/restore: '+relative,t=>{
 const repo=q023LifecycleFixture(t);const candidate=commit(repo,'Synthetic Q023 Candidate');q023Merge(repo,candidate);assert.deepEqual(successorProblems(repo),[]);
 const original=fs.readFileSync(path.join(repo,relative));fs.appendFileSync(path.join(repo,relative),'\n// synthetic corruption\n');commit(repo,'Synthetic Q023 corrupt main');
 fs.writeFileSync(path.join(repo,relative),original);const restored=commit(repo,'Synthetic Q023 restore');git(repo,['update-ref','refs/remotes/origin/main',restored]);git(repo,['checkout','--detach',candidate]);
 assert.ok(q023LifecycleProblems(repo).some(v=>/source history changed/.test(v)));assert.ok(successorProblems(repo).length);
});

// Q023 F1 regression: checkout can remain the exact Candidate after main merges it.
test('Q023 Candidate checkout retains legitimate main merge and rejects later main source rewrite/restore',t=>{
 const repo=q023LifecycleFixture(t),candidate=commit(repo,'Synthetic Q023 Candidate retained checkout'),merge=q023Merge(repo,candidate);
 git(repo,['checkout','--detach',candidate]);
 assert.deepEqual(q023LifecycleProblems(repo),[]);assert.deepEqual(q023SourceProblems(repo),[]);assert.deepEqual(successorProblems(repo),[]);
 // A later identical empty commit preserves source, while a hidden rewrite/restore cannot.
 git(repo,['checkout','--detach',merge]);git(repo,['commit','--allow-empty','-m','Synthetic source-preserving merge descendant']);
 const later=git(repo,['rev-parse','HEAD']);git(repo,['update-ref','refs/remotes/origin/main',later]);git(repo,['checkout','--detach',candidate]);
 assert.deepEqual(q023LifecycleProblems(repo),[]);assert.deepEqual(successorProblems(repo),[]);
 git(repo,['checkout','--detach',later]);const file=path.join(repo,Q023_PROPOSAL),original=fs.readFileSync(file);
 fs.appendFileSync(file,' ');commit(repo,'Synthetic forbidden main rewrite');fs.writeFileSync(file,original);
 const restored=commit(repo,'Synthetic hidden main restore');git(repo,['update-ref','refs/remotes/origin/main',restored]);git(repo,['checkout','--detach',candidate]);
 assert.ok(q023LifecycleProblems(repo).some(v=>/source history changed/.test(v)));assert.ok(successorProblems(repo).length);
});

test('Q023 merged HEAD cannot hide its own later source rewrite/restore while main stays the accepted merge',t=>{
 const repo=q023LifecycleFixture(t),candidate=commit(repo,'Synthetic Q023 Candidate'),merge=q023Merge(repo,candidate);
 assert.deepEqual(q023LifecycleProblems(repo),[]);
 const file=path.join(repo,'.github/workflows/ci.yml'),original=fs.readFileSync(file);
 fs.appendFileSync(file,'\n# forbidden checkout rewrite\n');commit(repo,'Synthetic forbidden merged HEAD source rewrite');
 fs.writeFileSync(file,original);commit(repo,'Synthetic hidden merged HEAD restore');
 assert.equal(git(repo,['rev-parse','refs/remotes/origin/main']),merge);
 assert.ok(q023LifecycleProblems(repo).some(v=>/source history changed/.test(v)));assert.ok(successorProblems(repo).length);
});

// Q024 synthetic probes never publish, admit CI, start a model, or mutate a SDK.
function q024LifeGit(repo,args) {
 const r=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,...args],{encoding:'utf8',env:{...process.env,GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0'}});
 assert.equal(r.error,undefined);assert.equal(r.signal,null);assert.equal(r.status,0,r.stderr);return r.stdout.trim();
}
function q024LifeFixture(t) {
 const repo=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q024-lifecycle-probe-'));
 t.after(()=>{
  let bytes=0,files=0,dirs=0;const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const n of fs.readdirSync(p))walk(path.join(p,n));}else if(s.isFile()){bytes+=s.size;files++;}};
  walk(repo);fs.rmSync(repo,{recursive:true,force:true});assert.equal(fs.existsSync(repo),false);console.log(JSON.stringify({owned_scratch:repo,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0}));
 });
 q024LifeGit(q024CurrentSource,['clone','--no-local','--no-checkout',q024CurrentSource,repo]);q024LifeGit(repo,['checkout','--detach',Q024_BASELINE]);q024LifeGit(repo,['update-ref','refs/remotes/origin/main',Q024_BASELINE]);
 q024LifeGit(repo,['config','core.hooksPath','/dev/null']);q024LifeGit(repo,['config','user.name','Synthetic Q024 Probe']);q024LifeGit(repo,['config','user.email','q024-probe@example.invalid']);
 const paths=rows(q024CurrentSource,['ls-files','--cached','--others','--exclude-standard']);assert.equal(new Set(paths).size,658);
 for(const relative of paths){const dest=path.join(repo,relative);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(path.join(q024CurrentSource,relative),dest);}
 q024LifeGit(repo,['add','--',...Q024_WORK_PATHS,...Q024_NEW_PATHS]);return repo;
}
function q024LifeCandidate(repo,message='Synthetic Q024 candidate') {
 q024LifeGit(repo,['commit','-m',message]);return q024LifeGit(repo,['rev-parse','HEAD']);
}
function q024LifeMerge(repo,candidate,{tree=null,parents=null}={}) {
 const body=tree??q024LifeGit(repo,['rev-parse',candidate+'^{tree}']),p=parents??[Q024_BASELINE,candidate];
 return q024LifeGit(repo,['commit-tree',body,...p.flatMap(v=>['-p',v]),'-m','Synthetic Q024 normal-merge shape']);
}
test('Q024 original180 lifecycle test bodies remain complete and failed merge provides construction only',()=>{
 const file='scripts/ci/test/b007-lifecycle.test.mjs',old=fs.readFileSync(path.join(q023CurrentSource,file),'utf8'),live=fs.readFileSync(path.join(q024CurrentSource,file),'utf8');
 assert.ok(live.slice(live.indexOf('function git(')).startsWith(old.slice(old.indexOf('function git('))));assert.deepEqual(q024SourceProblems(q024CurrentSource),[]);
 assert.equal(q024LifeGit(q023CurrentSource,['rev-parse','HEAD']),Q024_ORIGINAL_CANDIDATE);const v=resolveB007(q024CurrentSource);assert.deepEqual(v.problems,[]);assert.equal(v.runtime_ready,false);assert.equal(v.qualification_runs_executed,0);
});
test('Q024 accepts a complete synthetic658 sole-failed-merge-parent candidate without production grants',t=>{
 const repo=q024LifeFixture(t),candidate=q024LifeCandidate(repo),v=resolveB007(repo);assert.deepEqual(successorProblems(repo),[]);assert.deepEqual(q024LifecycleProblems(repo),[]);assert.equal(v.candidate.commit,candidate);assert.equal(v.merge,null);assert.equal(v.runtime_ready,false);assert.equal(v.qualification_runs_executed,0);
 assert.deepEqual(q024RevisionProblems(repo,candidate),[]);assert.ok(q024RevisionProblems(repo,candidate,{original:true}).length);
});
test('Q024 accepts only identical-tree ordered failed-baseline/candidate normal merge and common candidate',t=>{
 const repo=q024LifeFixture(t),candidate=q024LifeCandidate(repo),merge=q024LifeMerge(repo,candidate);q024LifeGit(repo,['checkout','--detach',merge]);q024LifeGit(repo,['update-ref','refs/remotes/origin/main',merge]);
 assert.deepEqual(successorProblems(repo),[]);const v=resolveB007(repo);assert.equal(v.candidate.commit,candidate);assert.equal(v.merge.commit,merge);assert.equal(v.runtime_ready,false);
 q024LifeGit(repo,['checkout','--detach',candidate]);assert.deepEqual(q024SourceProblems(repo),[]);
});
test('Q024 rejects candidate-shaped accepted main',t=>{
 const repo=q024LifeFixture(t),candidate=q024LifeCandidate(repo);q024LifeGit(repo,['update-ref','refs/remotes/origin/main',candidate]);assert.ok(q024LifecycleProblems(repo).length);
});
test('Q024 rejects a successor candidate whose sole parent is the earlier BASE',t=>{
 const repo=q024LifeFixture(t),tree=q024LifeGit(repo,['write-tree']),candidate=q024LifeGit(repo,['commit-tree',tree,'-p',BASE,'-m','Synthetic wrong old BASE parent']);q024LifeGit(repo,['checkout','--detach',candidate]);assert.ok(q024LifecycleProblems(repo).length);
});
test('Q024 rejects extra candidate parents',t=>{
 const repo=q024LifeFixture(t),tree=q024LifeGit(repo,['write-tree']),candidate=q024LifeGit(repo,['commit-tree',tree,'-p',Q024_BASELINE,'-p',BASE,'-m','Synthetic extra parent']);q024LifeGit(repo,['checkout','--detach',candidate]);assert.ok(q024LifecycleProblems(repo).length);
});
test('Q024 rejects reversed normal-merge parents',t=>{
 const repo=q024LifeFixture(t),candidate=q024LifeCandidate(repo),merge=q024LifeMerge(repo,candidate,{parents:[candidate,Q024_BASELINE]});q024LifeGit(repo,['checkout','--detach',merge]);q024LifeGit(repo,['update-ref','refs/remotes/origin/main',merge]);assert.ok(q024LifecycleProblems(repo).length);
});
test('Q024 rejects a normal merge with a different tree',t=>{
 const repo=q024LifeFixture(t),candidate=q024LifeCandidate(repo),merge=q024LifeMerge(repo,candidate,{tree:Q024_BASELINE_TREE});q024LifeGit(repo,['checkout','--detach',merge]);q024LifeGit(repo,['update-ref','refs/remotes/origin/main',merge]);assert.ok(q024LifecycleProblems(repo).length);
});
test('Q024 rejects different checkout and accepted-main candidates even with identical source trees',t=>{
 const repo=q024LifeFixture(t),one=q024LifeCandidate(repo,'Synthetic candidate one'),merge=q024LifeMerge(repo,one),tree=q024LifeGit(repo,['rev-parse',one+'^{tree}']),two=q024LifeGit(repo,['commit-tree',tree,'-p',Q024_BASELINE,'-m','Synthetic candidate two']);
 q024LifeGit(repo,['checkout','--detach',two]);q024LifeGit(repo,['update-ref','refs/remotes/origin/main',merge]);assert.notEqual(one,two);assert.ok(q024LifecycleProblems(repo).length);
});
test('Q024 rejects working implementation changes after its exact candidate',t=>{
 const repo=q024LifeFixture(t);q024LifeCandidate(repo);fs.appendFileSync(path.join(repo,Q024_WORK_PATHS[1]),'\n// changed after candidate\n');assert.ok(q024SourceProblems(repo).length);
});
test('Q024 rejects even byte-restoring history after its candidate',t=>{
 const repo=q024LifeFixture(t);q024LifeCandidate(repo);const file=Q024_WORK_PATHS[1],original=fs.readFileSync(path.join(repo,file));fs.appendFileSync(path.join(repo,file),'\n// transient rewrite\n');q024LifeGit(repo,['add','--',file]);q024LifeGit(repo,['commit','-m','Synthetic forbidden rewrite']);fs.writeFileSync(path.join(repo,file),original);q024LifeGit(repo,['add','--',file]);q024LifeGit(repo,['commit','-m','Synthetic forbidden restoration']);assert.ok(q024SourceProblems(repo).length);
});
test('Q024 rejects empty descendant commits and additional normal successors',t=>{
 const repo=q024LifeFixture(t),candidate=q024LifeCandidate(repo);q024LifeGit(repo,['commit','--allow-empty','-m','Synthetic extra successor']);assert.ok(q024LifecycleProblems(repo).length);
 q024LifeGit(repo,['checkout','--detach',candidate]);const merge=q024LifeMerge(repo,candidate);q024LifeGit(repo,['checkout','--detach',merge]);q024LifeGit(repo,['update-ref','refs/remotes/origin/main',merge]);q024LifeGit(repo,['commit','--allow-empty','-m','Synthetic extra after merge']);assert.ok(q024LifecycleProblems(repo).length);
});
test('Q024 rejects a committed protected runtime source change',t=>{
 const repo=q024LifeFixture(t),file='internal/operational/runtime.go';fs.appendFileSync(path.join(repo,file),'\n// unapproved runtime rewrite\n');q024LifeGit(repo,['add','--',file]);const candidate=q024LifeCandidate(repo);assert.ok(q024RevisionProblems(repo,candidate).length);assert.ok(successorProblems(repo).length);
});

function q025LifeGit(repo,args) {
 const r=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,...args],{encoding:'utf8',env:{PATH:'/usr/bin:/bin',LANG:'C.UTF-8',GIT_OPTIONAL_LOCKS:'0',GIT_TERMINAL_PROMPT:'0',GIT_CONFIG_GLOBAL:'/dev/null',GIT_CONFIG_SYSTEM:'/dev/null'}});
 assert.equal(r.error,undefined);assert.equal(r.status,0,r.stderr);return r.stdout.trim();
}
function q025LifeRetire(root) {
 let bytes=0,files=0,dirs=0;const seen=new Set();
 const walk=p=>{const s=fs.lstatSync(p);if(s.isDirectory()&&!s.isSymbolicLink()){dirs++;for(const name of fs.readdirSync(p))walk(path.join(p,name));}else if(s.isFile()){files++;const id=s.dev+':'+s.ino;if(!seen.has(id)){bytes+=s.size;seen.add(id);}}else if(!s.isSymbolicLink())throw new Error('unexpected owned Q025 lifecycle fixture member');};
 walk(root);fs.rmSync(root,{recursive:true,force:true});assert.equal(fs.existsSync(root),false);
 console.log(JSON.stringify({owned_scratch:root,retired_after_join:true,removed_bytes:bytes,removed_files:files,removed_directories:dirs,SDK_program_executions:0,model_DB_namespace_DIAG_QUAL:0}));
}
function q025LifeFixture(t) {
 const owned=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q025-lifecycle-')),repo=path.join(owned,'source');t.after(()=>q025LifeRetire(owned));
 const r=spawnSync('/usr/bin/git',['clone','--no-local','--no-checkout',q025CurrentSource,repo],{encoding:'utf8'});assert.equal(r.error,undefined);assert.equal(r.status,0,r.stderr);
 q025LifeGit(repo,['config','user.name','Synthetic Q025 Probe']);q025LifeGit(repo,['config','user.email','probe@example.invalid']);q025LifeGit(repo,['config','core.hooksPath','/dev/null']);q025LifeGit(repo,['checkout','--detach',Q025_BASELINE]);q025LifeGit(repo,['update-ref','refs/remotes/origin/main',Q025_BASELINE]);
 const paths=q025LifeGit(q025CurrentSource,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);assert.equal(new Set(paths).size,661);
 for(const relative of new Set(paths)){const from=path.join(q025CurrentSource,relative),dest=path.join(repo,relative);fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(from,dest);fs.chmodSync(dest,fs.statSync(from).mode&0o777);}
 q025LifeGit(repo,['add','--',...Q025_WORK_PATHS,...Q025_NEW_PATHS]);return repo;
}
function q025LifeCandidate(repo,message='Synthetic Q025 exact candidate') {
 q025LifeGit(repo,['commit','-m',message]);return q025LifeGit(repo,['rev-parse','HEAD']);
}
function q025LifeMerge(repo,candidate,{tree=null,parents=null}={}) {
 return q025LifeGit(repo,['commit-tree',tree??q025LifeGit(repo,['rev-parse',candidate+'^{tree}']),...(parents??[Q025_BASELINE,candidate]).flatMap(v=>['-p',v]),'-m','Synthetic Q025 normal merge']);
}
test('Q025 retains all original193 lifecycle cases at exact accepted PR33 with no runtime grant',()=>{
 const file='scripts/ci/test/b007-lifecycle.test.mjs',old=fs.readFileSync(path.join(q024CurrentSource,file),'utf8'),live=fs.readFileSync(path.join(q025CurrentSource,file),'utf8');
 assert.ok(live.slice(live.indexOf('function git(')).startsWith(old.slice(old.indexOf('function git('))));assert.equal(q025LifeGit(q024CurrentSource,['rev-parse','HEAD']),Q025_BASELINE);
 assert.deepEqual(q024SourceProblems(q024CurrentSource),[]);assert.deepEqual(q025SourceProblems(q025CurrentSource),[]);
 const v=resolveB007(q025CurrentSource);assert.deepEqual(v.problems,[]);assert.equal(v.runtime_ready,false);assert.equal(v.qualification_runs_executed,0);
});
test('Q025 accepts only complete sole-bafa-parent661 candidate without DIAG/model grant',t=>{
 const r=q025LifeFixture(t),candidate=q025LifeCandidate(r);assert.deepEqual(successorProblems(r),[]);assert.deepEqual(q025LifecycleProblems(r),[]);assert.deepEqual(q025RevisionProblems(r,candidate),[]);
 const v=resolveB007(r);assert.equal(v.candidate.commit,candidate);assert.equal(v.merge,null);assert.equal(v.runtime_ready,false);assert.equal(v.qualification_runs_executed,0);
 assert.ok(q025RevisionProblems(r,candidate,{baseline:true}).length);
});
test('Q025 accepts only identical-tree ordered baseline/candidate normal merge and same candidate',t=>{
 const r=q025LifeFixture(t),candidate=q025LifeCandidate(r),merge=q025LifeMerge(r,candidate);q025LifeGit(r,['checkout','--detach',merge]);q025LifeGit(r,['update-ref','refs/remotes/origin/main',merge]);
 assert.deepEqual(successorProblems(r),[]);const v=resolveB007(r);assert.equal(v.candidate.commit,candidate);assert.equal(v.merge.commit,merge);assert.equal(v.runtime_ready,false);
 q025LifeGit(r,['checkout','--detach',candidate]);assert.deepEqual(q025SourceProblems(r),[]);
});
test('Q025 rejects a candidate used as accepted main',t=>{
 const r=q025LifeFixture(t),candidate=q025LifeCandidate(r);q025LifeGit(r,['update-ref','refs/remotes/origin/main',candidate]);assert.ok(q025LifecycleProblems(r).length);
});
for(const [name,parents]of [
 ['earlier Q024 baseline',[Q024_BASELINE]],['extra candidate parent',[Q025_BASELINE,Q024_BASELINE]],
])test('Q025 rejects '+name,t=>{
 const r=q025LifeFixture(t),candidate=q025LifeGit(r,['commit-tree',q025LifeGit(r,['write-tree']),...parents.flatMap(v=>['-p',v]),'-m','Synthetic unauthorized candidate']);q025LifeGit(r,['checkout','--detach',candidate]);assert.ok(q025LifecycleProblems(r).length);
});
test('Q025 rejects reversed merge parents',t=>{
 const r=q025LifeFixture(t),candidate=q025LifeCandidate(r),merge=q025LifeMerge(r,candidate,{parents:[candidate,Q025_BASELINE]});q025LifeGit(r,['checkout','--detach',merge]);q025LifeGit(r,['update-ref','refs/remotes/origin/main',merge]);assert.ok(q025LifecycleProblems(r).length);
});
test('Q025 rejects differing normal merge tree',t=>{
 const r=q025LifeFixture(t),candidate=q025LifeCandidate(r),merge=q025LifeMerge(r,candidate,{tree:Q025_BASELINE_TREE});q025LifeGit(r,['checkout','--detach',merge]);q025LifeGit(r,['update-ref','refs/remotes/origin/main',merge]);assert.ok(q025LifecycleProblems(r).length);
});
test('Q025 rejects alternate checkout and main candidates with identical trees',t=>{
 const r=q025LifeFixture(t),one=q025LifeCandidate(r,'Synthetic candidate one'),merge=q025LifeMerge(r,one),two=q025LifeGit(r,['commit-tree',q025LifeGit(r,['rev-parse',one+'^{tree}']),'-p',Q025_BASELINE,'-m','Synthetic candidate two']);
 q025LifeGit(r,['checkout','--detach',two]);q025LifeGit(r,['update-ref','refs/remotes/origin/main',merge]);assert.notEqual(one,two);assert.ok(q025LifecycleProblems(r).length);
});
for(const file of [Q025_PARENT,'scripts/ci/lib/b007-toolchain-security-q018.mjs'])test('Q025 rejects working bytes changed after candidate: '+file,t=>{
 const r=q025LifeFixture(t);q025LifeCandidate(r);fs.appendFileSync(path.join(r,file),'\n// forbidden after exact candidate\n');assert.ok(q025SourceProblems(r).length);
});
test('Q025 rejects byte-restoring and empty successor history',t=>{
 const r=q025LifeFixture(t);const candidate=q025LifeCandidate(r),file=Q025_WORK_PATHS[1],old=fs.readFileSync(path.join(r,file));fs.appendFileSync(path.join(r,file),'\n// rewrite\n');q025LifeGit(r,['add','--',file]);q025LifeGit(r,['commit','-m','Synthetic forbidden rewrite']);fs.writeFileSync(path.join(r,file),old);q025LifeGit(r,['add','--',file]);q025LifeGit(r,['commit','-m','Synthetic forbidden restore']);assert.ok(q025SourceProblems(r).length);
 q025LifeGit(r,['checkout','--detach',candidate]);q025LifeGit(r,['commit','--allow-empty','-m','Synthetic extra empty child']);assert.ok(q025LifecycleProblems(r).length);
});
test('Q025 rejects later history after normal merge',t=>{
 const r=q025LifeFixture(t),candidate=q025LifeCandidate(r),merge=q025LifeMerge(r,candidate);q025LifeGit(r,['checkout','--detach',merge]);q025LifeGit(r,['update-ref','refs/remotes/origin/main',merge]);q025LifeGit(r,['commit','--allow-empty','-m','Synthetic extra merge child']);assert.ok(q025LifecycleProblems(r).length);
});
for(const file of ['internal/pilot/memory_lifecycle.go','cmd/aipt-pilot/main.go'])test('Q025 rejects a committed protected653 runtime change: '+file,t=>{
 const r=q025LifeFixture(t);fs.appendFileSync(path.join(r,file),'\n// unauthorized runtime\n');q025LifeGit(r,['add','--',file]);const candidate=q025LifeCandidate(r);assert.ok(q025RevisionProblems(r,candidate).length);assert.ok(successorProblems(r).length);
});
test('Q025 unchanged predecessor entry rejects changed prefix before any historical replay',t=>{
 const r=q025LifeFixture(t);fs.appendFileSync(path.join(r,Q025_PARENT),'\n// unauthorized prefix\n');const v=runApprovedPredecessor({repo:r},{gate:'evidence'});assert.equal(v.result,'FAIL');assert.equal(v.historical_gate,null);assert.equal(v.external_github_requests,0);assert.equal(v.real_model_calls,0);
});

function q026Git(repo,args){const r=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,...args],{encoding:'utf8'});assert.equal(r.error,undefined);assert.equal(r.status,0,r.stderr);return r.stdout.trim();}
function q026Fixture(t){const owned=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q026-owned-fixture-')),repo=path.join(owned,'source');t.after(()=>q025LifeRetire(owned));const r=spawnSync('/usr/bin/git',['clone','--no-local','--no-checkout',q026CurrentSource,repo],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);q026Git(repo,['config','core.hooksPath','/dev/null']);q026Git(repo,['config','user.name','Synthetic Q026 Probe']);q026Git(repo,['config','user.email','probe@example.invalid']);q026Git(repo,['checkout','--detach',Q026_BASELINE]);q026Git(repo,['update-ref','refs/remotes/origin/main',Q026_BASELINE]);const names=q026Git(q026CurrentSource,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);assert.equal(new Set(names).size,665);for(const name of new Set(names)){const src=path.join(q026CurrentSource,name),dst=path.join(repo,name);fs.mkdirSync(path.dirname(dst),{recursive:true});fs.copyFileSync(src,dst);fs.chmodSync(dst,fs.statSync(src).mode&0o777);}q026Git(repo,['add','--',...Q026_WORK_PATHS,...Q026_NEW_PATHS]);return repo;}
function q026Candidate(repo){q026Git(repo,['commit','-m','Synthetic exact Q026 candidate']);return q026Git(repo,['rev-parse','HEAD']);}
function q026Merge(repo,candidate,parents=[Q026_BASELINE,candidate],tree=q026Git(repo,['rev-parse',candidate+'^{tree}'])){return q026Git(repo,['commit-tree',tree,...parents.flatMap(v=>['-p',v]),'-m','Synthetic Q026 normal merge']);}

test('Q026 retains all original209 lifecycle bodies and grants no runtime',()=>{const f='scripts/ci/test/b007-lifecycle.test.mjs',old=fs.readFileSync(path.join(q025CurrentSource,f),'utf8'),live=fs.readFileSync(path.join(q026CurrentSource,f),'utf8');assert.ok(live.slice(live.indexOf('function git(')).startsWith(old.slice(old.indexOf('function git('))));const v=resolveB007(q026CurrentSource);assert.deepEqual(v.problems,[]);assert.equal(v.runtime_ready,false);assert.equal(v.qualification_runs_executed,0);});
test('Q026 accepts only sole-ead-parent665 candidate then identical ordered normal merge',t=>{const r=q026Fixture(t),candidate=q026Candidate(r);assert.deepEqual(successorProblems(r),[]);assert.deepEqual(q026LifecycleProblems(r),[]);assert.deepEqual(q026RevisionProblems(r,candidate),[]);const m=q026Merge(r,candidate);q026Git(r,['checkout','--detach',m]);q026Git(r,['update-ref','refs/remotes/origin/main',m]);assert.deepEqual(q026LifecycleProblems(r),[]);assert.deepEqual(successorProblems(r),[]);assert.equal(q026Topology(r).original_Parent_or_DIAG_retry_authorized,false);});
for(const [name,parents]of [['earlier baseline',[Q025_BASELINE]],['extra candidate parent',[Q026_BASELINE,Q025_BASELINE]]])test('Q026 rejects '+name,t=>{const r=q026Fixture(t),c=q026Git(r,['commit-tree',q026Git(r,['write-tree']),...parents.flatMap(v=>['-p',v]),'-m','Synthetic invalid candidate']);q026Git(r,['checkout','--detach',c]);assert.ok(q026LifecycleProblems(r).length);});
test('Q026 rejects candidate as accepted main',t=>{const r=q026Fixture(t),c=q026Candidate(r);q026Git(r,['update-ref','refs/remotes/origin/main',c]);assert.ok(q026LifecycleProblems(r).length);});
for(const reversed of [false,true])test('Q026 rejects '+(reversed?'reversed merge parents':'different merge tree'),t=>{const r=q026Fixture(t),c=q026Candidate(r),m=q026Merge(r,c,reversed?[c,Q026_BASELINE]:[Q026_BASELINE,c],reversed?undefined:Q026_BASELINE_TREE);q026Git(r,['checkout','--detach',m]);q026Git(r,['update-ref','refs/remotes/origin/main',m]);assert.ok(q026LifecycleProblems(r).length);});
test('Q026 rejects later empty candidate or merge history',t=>{const r=q026Fixture(t),c=q026Candidate(r);q026Git(r,['commit','--allow-empty','-m','Synthetic extra history']);assert.ok(q026LifecycleProblems(r).length);q026Git(r,['checkout','--detach',q026Merge(r,c)]);q026Git(r,['commit','--allow-empty','-m','Synthetic extra merge history']);assert.ok(q026LifecycleProblems(r).length);});
for(const file of ['internal/pilot/task0_preparation.go','cmd/aipt-pilot/main.go',Q025_TEST])test('Q026 rejects committed protected656 change '+file,t=>{const r=q026Fixture(t);fs.appendFileSync(path.join(r,file),'\n// unauthorized\n');q026Git(r,['add','--',file]);const c=q026Candidate(r);assert.ok(q026RevisionProblems(r,c).length);assert.ok(successorProblems(r).length);});
test('Q026 rejects mutation of working CI after exact candidate',t=>{const r=q026Fixture(t);q026Candidate(r);fs.appendFileSync(path.join(r,'scripts/ci/lib/b007-successor.mjs'),'\n// forbidden\n');assert.ok(q026SourceProblems(r).length);});
test('Q026 predecessor entry rejects malformed observer before historical replay',t=>{const r=q026Fixture(t);fs.appendFileSync(path.join(r,Q026_OBSERVER),'\n// forbidden\n');const v=runApprovedPredecessor({repo:r},{gate:'evidence'});assert.equal(v.result,'FAIL');assert.equal(v.historical_gate,null);assert.equal(v.external_github_requests,0);assert.equal(v.real_model_calls,0);});

function q027Git(repo,args){const r=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,...args],{encoding:'utf8'});assert.equal(r.error,undefined);assert.equal(r.status,0,r.stderr);return r.stdout.trim();}
function q027Fixture(t){const owned=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q027-owned-fixture-')),repo=path.join(owned,'source');t.after(()=>q025LifeRetire(owned));const r=spawnSync('/usr/bin/git',['clone','--no-local','--no-checkout',q027CurrentSource,repo],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);q027Git(repo,['config','core.hooksPath','/dev/null']);q027Git(repo,['config','user.name','Synthetic Q027 Probe']);q027Git(repo,['config','user.email','probe@example.invalid']);q027Git(repo,['checkout','--detach',Q027_BASELINE]);q027Git(repo,['update-ref','refs/remotes/origin/main',Q027_BASELINE]);const names=q027Git(q027CurrentSource,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);assert.equal(new Set(names).size,669);for(const name of new Set(names)){const src=path.join(q027CurrentSource,name),dst=path.join(repo,name);fs.mkdirSync(path.dirname(dst),{recursive:true});fs.copyFileSync(src,dst);fs.chmodSync(dst,fs.statSync(src).mode&0o777);}q027Git(repo,['add','--',...Q027_WORK_PATHS,...Q027_NEW_PATHS]);return repo;}
function q027Candidate(repo){q027Git(repo,['commit','-m','Synthetic exact Q027 candidate']);return q027Git(repo,['rev-parse','HEAD']);}
function q027Merge(repo,candidate,parents=[Q027_BASELINE,candidate],tree=q027Git(repo,['rev-parse',candidate+'^{tree}'])){return q027Git(repo,['commit-tree',tree,...parents.flatMap(v=>['-p',v]),'-m','Synthetic Q027 normal merge']);}

test('Q027 retains all original222 lifecycle bodies and grants no runtime',()=>{const f='scripts/ci/test/b007-lifecycle.test.mjs',old=fs.readFileSync(path.join(q026CurrentSource,f),'utf8'),live=fs.readFileSync(path.join(q027CurrentSource,f),'utf8');assert.ok(live.slice(live.indexOf('function git(')).startsWith(old.slice(old.indexOf('function git('))));const v=resolveB007(q027CurrentSource);assert.deepEqual(v.problems,[]);assert.equal(v.runtime_ready,false);assert.equal(v.qualification_runs_executed,0);});
test('Q027 accepts only sole-eab-parent669 candidate then identical ordered normal merge',t=>{const r=q027Fixture(t),candidate=q027Candidate(r);assert.deepEqual(successorProblems(r),[]);assert.deepEqual(q027LifecycleProblems(r),[]);assert.deepEqual(q027RevisionProblems(r,candidate),[]);const m=q027Merge(r,candidate);q027Git(r,['checkout','--detach',m]);q027Git(r,['update-ref','refs/remotes/origin/main',m]);assert.deepEqual(q027LifecycleProblems(r),[]);assert.deepEqual(successorProblems(r),[]);assert.equal(q027Topology(r).original_Parent_or_DIAG_retry_authorized,false);});
for(const [name,parents]of [['earlier baseline',[Q026_BASELINE]],['extra candidate parent',[Q027_BASELINE,Q026_BASELINE]]])test('Q027 rejects '+name,t=>{const r=q027Fixture(t),c=q027Git(r,['commit-tree',q027Git(r,['write-tree']),...parents.flatMap(v=>['-p',v]),'-m','Synthetic invalid candidate']);q027Git(r,['checkout','--detach',c]);assert.ok(q027LifecycleProblems(r).length);});
test('Q027 rejects candidate as accepted main',t=>{const r=q027Fixture(t),c=q027Candidate(r);q027Git(r,['update-ref','refs/remotes/origin/main',c]);assert.ok(q027LifecycleProblems(r).length);});
for(const reversed of [false,true])test('Q027 rejects '+(reversed?'reversed merge parents':'different merge tree'),t=>{const r=q027Fixture(t),c=q027Candidate(r),m=q027Merge(r,c,reversed?[c,Q027_BASELINE]:[Q027_BASELINE,c],reversed?undefined:Q027_BASELINE_TREE);q027Git(r,['checkout','--detach',m]);q027Git(r,['update-ref','refs/remotes/origin/main',m]);assert.ok(q027LifecycleProblems(r).length);});
test('Q027 rejects later empty candidate or merge history',t=>{const r=q027Fixture(t),c=q027Candidate(r);q027Git(r,['commit','--allow-empty','-m','Synthetic extra history']);assert.ok(q027LifecycleProblems(r).length);q027Git(r,['checkout','--detach',q027Merge(r,c)]);q027Git(r,['commit','--allow-empty','-m','Synthetic extra merge history']);assert.ok(q027LifecycleProblems(r).length);});
for(const file of ['internal/pilot/task0_preparation.go','cmd/aipt-pilot/main.go',Q025_TEST])test('Q027 rejects committed protected660 change '+file,t=>{const r=q027Fixture(t);fs.appendFileSync(path.join(r,file),'\n// unauthorized\n');q027Git(r,['add','--',file]);const c=q027Candidate(r);assert.ok(q027RevisionProblems(r,c).length);assert.ok(successorProblems(r).length);});
test('Q027 rejects mutation of working CI after exact candidate',t=>{const r=q027Fixture(t);q027Candidate(r);fs.appendFileSync(path.join(r,'scripts/ci/lib/b007-successor.mjs'),'\n// forbidden\n');assert.ok(q027SourceProblems(r).length);});
test('Q027 predecessor entry rejects malformed observer before historical replay',t=>{const r=q027Fixture(t);fs.appendFileSync(path.join(r,Q027_OBSERVER),'\n// forbidden\n');const v=runApprovedPredecessor({repo:r},{gate:'evidence'});assert.equal(v.result,'FAIL');assert.equal(v.historical_gate,null);assert.equal(v.external_github_requests,0);assert.equal(v.real_model_calls,0);});


function q028Git(repo,args){const r=spawnSync('/usr/bin/git',['--no-optional-locks','-C',repo,...args],{encoding:'utf8'});assert.equal(r.error,undefined);assert.equal(r.status,0,r.stderr);return r.stdout.trim();}
function q028Fixture(t){const owned=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-q028-owned-fixture-')),repo=path.join(owned,'source');t.after(()=>q025LifeRetire(owned));const r=spawnSync('/usr/bin/git',['clone','--no-local','--no-checkout',q028CurrentSource,repo],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);q028Git(repo,['config','core.hooksPath','/dev/null']);q028Git(repo,['config','user.name','Synthetic Q028 Probe']);q028Git(repo,['config','user.email','probe@example.invalid']);q028Git(repo,['checkout','--detach',Q028_BASELINE]);q028Git(repo,['update-ref','refs/remotes/origin/main',Q028_BASELINE]);const names=q028Git(q028CurrentSource,['ls-files','--cached','--others','--exclude-standard','-z']).split('\0').filter(Boolean);assert.equal(new Set(names).size,673);for(const name of new Set(names)){const src=path.join(q028CurrentSource,name),dst=path.join(repo,name);fs.mkdirSync(path.dirname(dst),{recursive:true});fs.copyFileSync(src,dst);fs.chmodSync(dst,fs.statSync(src).mode&0o777);}q028Git(repo,['add','--',...Q028_WORK_PATHS,...Q028_NEW_PATHS]);return repo;}
function q028Candidate(repo){q028Git(repo,['commit','-m','Synthetic exact Q028 candidate']);return q028Git(repo,['rev-parse','HEAD']);}
function q028Merge(repo,candidate,parents=[Q028_BASELINE,candidate],tree=q028Git(repo,['rev-parse',candidate+'^{tree}'])){return q028Git(repo,['commit-tree',tree,...parents.flatMap(v=>['-p',v]),'-m','Synthetic Q028 normal merge']);}

test('Q028 retains all original lifecycle bodies and grants no runtime',()=>{const f='scripts/ci/test/b007-lifecycle.test.mjs',old=fs.readFileSync(path.join(q027CurrentSource,f),'utf8'),live=fs.readFileSync(path.join(q028CurrentSource,f),'utf8');assert.ok(live.slice(live.indexOf('function git(')).startsWith(old.slice(old.indexOf('function git('))));const v=resolveB007(q028CurrentSource);assert.deepEqual(v.problems,[]);assert.equal(v.runtime_ready,false);assert.equal(v.qualification_runs_executed,0);});
test('Q028 accepts only sole-6a-parent673 candidate then identical ordered normal merge',t=>{const r=q028Fixture(t),candidate=q028Candidate(r);assert.deepEqual(successorProblems(r),[]);assert.deepEqual(q028LifecycleProblems(r),[]);assert.deepEqual(q028RevisionProblems(r,candidate),[]);const m=q028Merge(r,candidate);q028Git(r,['checkout','--detach',m]);q028Git(r,['update-ref','refs/remotes/origin/main',m]);assert.deepEqual(q028LifecycleProblems(r),[]);assert.deepEqual(successorProblems(r),[]);assert.equal(q028Topology(r).original_Parent_or_DIAG_retry_authorized,false);});
for(const [name,parents]of [['earlier baseline',[Q027_BASELINE]],['extra candidate parent',[Q028_BASELINE,Q027_BASELINE]]])test('Q028 rejects '+name,t=>{const r=q028Fixture(t),c=q028Git(r,['commit-tree',q028Git(r,['write-tree']),...parents.flatMap(v=>['-p',v]),'-m','Synthetic invalid candidate']);q028Git(r,['checkout','--detach',c]);assert.ok(q028LifecycleProblems(r).length);});
test('Q028 rejects candidate as accepted main',t=>{const r=q028Fixture(t),c=q028Candidate(r);q028Git(r,['update-ref','refs/remotes/origin/main',c]);assert.ok(q028LifecycleProblems(r).length);});
for(const reversed of [false,true])test('Q028 rejects '+(reversed?'reversed merge parents':'different merge tree'),t=>{const r=q028Fixture(t),c=q028Candidate(r),m=q028Merge(r,c,reversed?[c,Q028_BASELINE]:[Q028_BASELINE,c],reversed?undefined:Q028_BASELINE_TREE);q028Git(r,['checkout','--detach',m]);q028Git(r,['update-ref','refs/remotes/origin/main',m]);assert.ok(q028LifecycleProblems(r).length);});
test('Q028 rejects later empty candidate or merge history',t=>{const r=q028Fixture(t),c=q028Candidate(r);q028Git(r,['commit','--allow-empty','-m','Synthetic extra history']);assert.ok(q028LifecycleProblems(r).length);q028Git(r,['checkout','--detach',q028Merge(r,c)]);q028Git(r,['commit','--allow-empty','-m','Synthetic extra merge history']);assert.ok(q028LifecycleProblems(r).length);});
for(const file of ['internal/pilot/task0_preparation.go','cmd/aipt-pilot/main.go',Q025_TEST])test('Q028 rejects committed protected664 change '+file,t=>{const r=q028Fixture(t);fs.appendFileSync(path.join(r,file),'\n// unauthorized\n');q028Git(r,['add','--',file]);const c=q028Candidate(r);assert.ok(q028RevisionProblems(r,c).length);assert.ok(successorProblems(r).length);});
test('Q028 rejects mutation of working CI after exact candidate',t=>{const r=q028Fixture(t);q028Candidate(r);fs.appendFileSync(path.join(r,'scripts/ci/lib/b007-successor.mjs'),'\n// forbidden\n');assert.ok(q028SourceProblems(r).length);});
test('Q028 predecessor entry rejects malformed observer before historical replay',t=>{const r=q028Fixture(t);fs.appendFileSync(path.join(r,Q028_OBSERVER),'\n// forbidden\n');const v=runApprovedPredecessor({repo:r},{gate:'evidence'});assert.equal(v.result,'FAIL');assert.equal(v.historical_gate,null);assert.equal(v.external_github_requests,0);assert.equal(v.real_model_calls,0);});
