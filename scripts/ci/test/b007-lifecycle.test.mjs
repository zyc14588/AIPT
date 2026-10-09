import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { BASE,START,AUTHORITY,Q002_AUTHORITY,Q002_SOURCE,Q003_AUTHORITY,Q003_ANNEX,Q004_AUTHORITY,Q004_PROPOSAL,Q005_AUTHORITY,Q009_AUTHORITY,Q009_ANNEX,Q009_REVIEW,Q009_CI,Q009_ADAPTER,Q009_GATEWAY,Q011_AUTHORITY,STATUS,MUTABLE,allowedNew,successorProblems,rows } from '../lib/b007-successor.mjs';
import { resolveB007 } from '../lib/b007-lifecycle.mjs';
import { inspectConstruction } from '../validate/mvp-b007.mjs';
const source=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
function git(repo,args){const r=spawnSync('git',['-C',repo,...args],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);assert.equal(r.error,undefined);return r.stdout.trim();}
function fixture(t){
 const repo=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-b007-guard-probe-'));
 t.after(()=>fs.rmSync(repo,{recursive:true,force:true}));
 const r=spawnSync('git',['clone','--no-local','--no-checkout',source,repo],{encoding:'utf8'});assert.equal(r.status,0,r.stderr);
 git(repo,['checkout','--detach',BASE]);git(repo,['update-ref','refs/remotes/origin/main',BASE]);
 git(repo,['config','user.name','Synthetic B007 Probe']);git(repo,['config','user.email','probe@example.invalid']);
 for(const p of rows(source,['ls-files','--cached','--others','--exclude-standard']))if(MUTABLE.has(p)||allowedNew(p)){
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
 ['old operational entry mutation',r=>fs.appendFileSync(path.join(r,'internal/operational/runtime.go'),'\n// corruption\n'),/protected predecessor working/],
 ['frozen migration mutation',r=>fs.appendFileSync(path.join(r,'internal/storage/postgres/migrations/000001_ledger.sql'),'\n-- corruption\n'),/protected predecessor working/],
 ['original B004 closure mutation',r=>fs.appendFileSync(path.join(r,'scripts/ci/harness-runtime-closure.ts'),'\n// corruption\n'),/protected predecessor working/],
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
for(const p of ['internal/evidence/remote_provenance.go','package.json',STATUS,AUTHORITY,Q002_AUTHORITY,Q002_SOURCE,Q003_AUTHORITY,Q003_ANNEX,Q004_AUTHORITY,Q004_PROPOSAL,Q005_AUTHORITY,Q009_AUTHORITY,Q009_ANNEX,Q009_REVIEW,Q009_CI,Q009_ADAPTER,Q009_GATEWAY,Q011_AUTHORITY,'docs/pilot/evidence/task0-q009/merge-jobs.json'])test('clean older checkout cannot hide main rewrite/restore: '+p,t=>{
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
