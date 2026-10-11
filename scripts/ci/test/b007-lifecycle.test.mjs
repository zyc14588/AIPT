import test from 'node:test';
import assert from 'node:assert/strict';
import { Q018_AUTHORITY, Q018_MODIFIED_PATHS, Q019_AUTHORITY, Q019_PROPOSAL, Q019_SMOKE, Q021_AUTHORITY, Q021_PROPOSAL, Q021_WORK_PATHS, Q022_AUTHORITY, Q022_PROPOSAL, Q022_WORK_PATHS, Q022_NEW_PATHS, Q022_BASELINE, q022Approved, q022SourceProblems, q022RevisionProblems, prepareQ022FixedCloneOrigin, q022OriginalTestSource, cleanupQ022OriginalTestSources, Q023_AUTHORITY, Q023_PROPOSAL, Q023_BASELINE, Q023_BASELINE_TREE, Q023_WORK_PATHS, Q023_NEW_PATHS, q023Approved, q023Proposal, q023SourceProblems, q023RevisionProblems, q023LifecycleProblems, prepareQ023FixedCloneOrigin, q023OriginalTestSource, cleanupQ023OriginalTestSources, runQ023FixedP1Reverification } from '../lib/b007-toolchain-security-q018.mjs';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { BASE,Q015_GATE,Q016_AUTHORITY,Q017_AUTHORITY,Q017_FIXTURE,runApprovedPredecessor,cleanupSnapshots,START,AUTHORITY,Q002_AUTHORITY,Q002_SOURCE,Q003_AUTHORITY,Q003_ANNEX,Q004_AUTHORITY,Q004_PROPOSAL,Q005_AUTHORITY,Q009_AUTHORITY,Q009_ANNEX,Q009_REVIEW,Q009_CI,Q009_ADAPTER,Q009_GATEWAY,Q011_AUTHORITY,STATUS,MUTABLE,allowedNew,successorProblems,rows } from '../lib/b007-successor.mjs';
import { resolveB007 } from '../lib/b007-lifecycle.mjs';
import { inspectConstruction } from '../validate/mvp-b007.mjs';
const q023CurrentSource=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
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
