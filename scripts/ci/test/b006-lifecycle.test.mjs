import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { BASE, ENGINE, REPAIR, START, REGRESSION, GATE_AUTHORITY, STATUS, successorProblems, facts, blob, sha } from '../lib/b006-successor.mjs';
import { resolveB006, candidateProblems, RECORDS, CI, REVIEW, expectedRecords, expectedClosedStatus, ciProblems, KNOWN_FINDINGS } from '../lib/b006-lifecycle.mjs';

const source=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../../..');
const current=resolveB006(source);const candidate=current.candidate?.commit;
function command(repo,args) {
 const r=spawnSync('git',['-C',repo,...args],{encoding:'utf8',env:Object.fromEntries(Object.entries(process.env).filter(([k])=>!k.startsWith('GITHUB_')))});
 assert.equal(r.status,0,r.stderr);return r.stdout.trim();
}
function fixture(t) {
 assert.ok(candidate,'tests require the exact committed B006 Candidate');
 const repo=fs.mkdtempSync(path.join(os.tmpdir(),'aipt-b006-lifecycle-probe-'));
 t.after(()=>fs.rmSync(repo,{recursive:true,force:true}));
 const cloned=spawnSync('git',['clone','--no-local','--no-checkout',source,repo],{encoding:'utf8'});assert.equal(cloned.status,0,cloned.stderr);
 command(repo,['config','user.name','AIPT Synthetic Lifecycle Probe']);command(repo,['config','user.email','probe@example.invalid']);
 command(repo,['checkout','--detach',candidate]);command(repo,['update-ref','refs/remotes/origin/main',BASE]);return repo;
}
function write(repo,p,value) {const target=path.join(repo,p);fs.mkdirSync(path.dirname(target),{recursive:true});fs.writeFileSync(target,typeof value==='string'?value:JSON.stringify(value,null,2)+'\n');}
function commit(repo,message) {command(repo,['add','-A']);command(repo,['commit','-m',message]);return command(repo,['rev-parse','HEAD']);}
function rejected(repo,pattern) {const p=successorProblems(repo);assert.ok(p.length>0,'unauthorized successor unexpectedly accepted');assert.ok(p.some((x)=>pattern.test(x)),JSON.stringify(p));}

test('exact approved Candidate guard accepts every unchanged predecessor plus the specified repair',t=>{
 const repo=fixture(t);assert.deepEqual(successorProblems(repo),[]);assert.deepEqual(candidateProblems(repo,candidate),[]);assert.equal(resolveB006(repo).phase,'CANDIDATE');
});
for (const [label,mutate,pattern] of [
 ['restore original empty-RNG bug',r=>write(r,ENGINE,blob(r,BASE,ENGINE).toString()),/exact approved/],
 ['change an additional engine byte',r=>fs.appendFileSync(path.join(r,ENGINE),'\n// unauthorized engine mutation\n'),/exact approved/],
 ['alter Owner decision',r=>fs.appendFileSync(path.join(r,REPAIR),' '),/Owner authority/],
 ['remove repair authority',r=>fs.unlinkSync(path.join(r,REPAIR)),/failed closed/],
 ['alter original start authority',r=>fs.appendFileSync(path.join(r,START),' '),/Owner authority/],
 ['alter separate gate successor authority',r=>fs.appendFileSync(path.join(r,GATE_AUTHORITY),' '),/Owner authority/],
 ['delete executable regression',r=>fs.unlinkSync(path.join(r,REGRESSION)),/failed closed/],
 ['rewrite frozen migration',r=>fs.appendFileSync(path.join(r,'internal/storage/postgres/migrations/000001_ledger.sql'),'\n-- unauthorized\n'),/predecessor working/],
 ['reopen B002 accepted status',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.AIPT.mvp_b002.state='IN_PROGRESS';write(r,STATUS,s);},/predecessor status/],
 ['redirect a required predecessor CI entrypoint',r=>{const p=JSON.parse(fs.readFileSync(path.join(r,'package.json')));p.scripts['test:run-core']='node --version';write(r,'package.json',p);},/predecessor script/],
 ['S01 integration history reopened',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.tracks['AIPT-STANDALONE'].batch_history['INT-AIPT-UNREGISTERED-MVP-001']='NOT_STARTED';write(r,STATUS,s);},/accepted batch history/],
 ['S02 next batch points backwards',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.tracks['AIPT-STANDALONE'].next_serial_batch='INT-AIPT-UNREGISTERED-MVP-001';write(r,STATUS,s);},/authorized construction/],
 ['S05 global WIP increased',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.tracks['AIPT-STANDALONE'].global_wip=2;write(r,STATUS,s);},/authorized construction/],
 ['S06 B004 source reopened',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.AIPT.mvp_b004.state='IN_PROGRESS';write(r,STATUS,s);},/predecessor status/],
 ['S07 external package drift',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.repositories.UNREGISTERED.verified_head='0'.repeat(40);write(r,STATUS,s);},/external repository authority/],
 ['external predecessor tuple drift',r=>{const s=JSON.parse(fs.readFileSync(path.join(r,STATUS)));s.tracks['AIPT-STANDALONE'].external_serial_predecessor.status='IN_PROGRESS';write(r,STATUS,s);},/standalone predecessor projection/],
 ['symlink a protected runtime',r=>{const p='internal/evidence/remote_provenance.go';fs.unlinkSync(path.join(r,p));fs.symlinkSync('/dev/null',path.join(r,p));},/failed closed/],
 ]) test('current guard rejects '+label,t=>{const repo=fixture(t);mutate(repo);rejected(repo,pattern);});

for (const [label,p,historyPattern] of [
 ['frozen predecessor','internal/evidence/remote_provenance.go',/predecessor bytes\/history/],
 ['B002 engine',ENGINE,/unauthorized engine version/],
 ['successor Owner authority',REPAIR,/authority\/test was rewritten/],
 ['bounded package entrypoints','package.json',/approved B006 exception bytes\/history/],
 ['bounded aggregate entry','scripts/ci/run-checks.mjs',/approved B006 exception bytes\/history/],
 ['bounded synchronized fixture','packages/model-harness-gateway/test/fixture-acp-worker.ts',/approved B006 exception bytes\/history/],

 ]) test('clean older checkout cannot hide accepted main '+label+' rewrite and restore',t=>{
 const repo=fixture(t);const original=fs.readFileSync(path.join(repo,p));
 command(repo,['switch','-c','synthetic-main']);fs.appendFileSync(path.join(repo,p),'\n// synthetic corruption\n');commit(repo,'synthetic rewrite');
 fs.writeFileSync(path.join(repo,p),original);const restored=commit(repo,'synthetic restore');command(repo,['update-ref','refs/remotes/origin/main',restored]);
 command(repo,['checkout','--detach',candidate]);rejected(repo,historyPattern);
});
test('an absent accepted main cannot fall back to a historical-only pass',t=>{
 const repo=fixture(t);command(repo,['update-ref','-d','refs/remotes/origin/main']);rejected(repo,/accepted main/);
});
test('B007 or game scope cannot enter the direct B006 Candidate',t=>{
 const repo=fixture(t);write(repo,'internal/pilot/unauthorized.go','package pilot\n');command(repo,['add','-A']);command(repo,['commit','--amend','--no-edit']);
 assert.ok(candidateProblems(repo,command(repo,['rev-parse','HEAD'])).some((p)=>p.includes('scope drift')));
});
test('a self-asserted partial CLOSED record before the merge is rejected',t=>{
 const repo=fixture(t);write(repo,RECORDS[2],{event:'CLOSED',effective:true});const head=commit(repo,'synthetic premature self-closeout');command(repo,['update-ref','refs/remotes/origin/main',head]);
 assert.equal(resolveB006(repo).phase,'REJECTED');
});
function syntheticCatalogue(merge) {
 return {schema:'aipt.public.verified-ci-evidence/v1',version:'1.0.0',task_id:'AIPT-MVP-B006',repository:'zyc14588/AIPT',workflow_path:'.github/workflows/ci.yml',workflow_sha256:sha(blob(source,BASE,'.github/workflows/ci.yml')),
 acceptance:{decision_id:'B006-B002-ZERO-RNG-REPAIR-Q001=A',mode:'LOCAL_ONLINE_GITHUB_ACTIONS_VERIFICATION',offline_trust_basis:'OWNER_ACCEPTED_IMMUTABLE_MAIN_CI_CATALOGUE',verified_at:'2026-10-06T00:00:00.000Z'},
 run:{id:101,head_sha:merge.commit,head_branch:'main',event:'push',status:'completed',conclusion:'success',run_attempt:1},
 jobs:['b000-retro (fixed B000 commit, read-only expansion)','toolchain (ubuntu-24.04)','toolchain (ubuntu-26.04)','supply-chain (R4-Q023 gates)','storage-postgres (ephemeral PostgreSQL 18.4 integration)'].map((name,i)=>({id:201+i,name,head_sha:merge.commit,status:'completed',conclusion:'success'}))};
}
test('synthetic exact five-job catalogue accepts, with every SHA/job/trust mutation rejecting',()=>{
 const merge={commit:'1'.repeat(40)};const value=syntheticCatalogue(merge);const workflow=value.workflow_sha256;
 assert.deepEqual(ciProblems(value,merge,workflow),[]);
 for(const mutate of [v=>{v.run.head_sha='2'.repeat(40);},v=>{v.jobs[4].conclusion='skipped';},v=>{v.jobs.pop();},v=>{v.jobs[0].id=v.jobs[1].id;},v=>{v.jobs[0].name='other';},v=>{v.acceptance.mode='OFFLINE_SELF_ASSERTED';},v=>{v.run.event='pull_request';},v=>{v.workflow_sha256='0'.repeat(64);},v=>{v.extra=true;}]) {const bad=structuredClone(value);mutate(bad);assert.ok(ciProblems(bad,merge,workflow).length,'bad catalogue accepted');}
});
function syntheticClosed(repo) {
 command(repo,['switch','-c','synthetic-merge',BASE]);command(repo,['merge','--no-ff','--no-edit',candidate]);
 const merge=facts(repo,'HEAD');const c=facts(repo,candidate);assert.equal(merge.tree,c.tree);const ci=syntheticCatalogue(merge);
 const review={schema:'aipt.public.independent-security-review/v1',task_id:'AIPT-MVP-B006',source:'LOCAL_INDEPENDENT_CODEX_AGENT',agent:'b005_independent_security_review',access:'READ_ONLY',candidate_commit:c.commit,candidate_tree:c.tree,result:'PASS',open_findings:[],closed_findings:[...KNOWN_FINDINGS],independent_probe_count:1,report_sha256:'0'.repeat(64)};
 write(repo,CI,ci);write(repo,REVIEW,review);expectedRecords(repo,c,merge,ci).forEach((r,i)=>write(repo,RECORDS[i],r));write(repo,STATUS,expectedClosedStatus(repo,c,merge,ci,review));
 for(const p of ['docs/authority/PROJECT_STATUS.md','docs/milestones/MVP.md']) fs.appendFileSync(path.join(repo,p),'\nSynthetic closeout fixture only. No actual CI or qualification claim.\n');
 const closed=commit(repo,'synthetic canonical closeout');command(repo,['update-ref','refs/remotes/origin/main',closed]);
 const resolved=resolveB006(repo);assert.equal(resolved.phase,'CLOSED_HISTORICAL_REPLAY',JSON.stringify(resolved.problems));
 assert.deepEqual(successorProblems(repo),[]);return closed;
}
test('synthetic canonical closeout accepts, but accepted evidence rewrite and restore rejects even from older checkout',t=>{
 const repo=fixture(t);const closed=syntheticClosed(repo);
 const ci=JSON.parse(fs.readFileSync(path.join(repo,CI)));
 fs.appendFileSync(path.join(repo,CI),' ');commit(repo,'synthetic corrupt accepted CI');write(repo,CI,ci);const restore=commit(repo,'synthetic restore accepted CI');command(repo,['update-ref','refs/remotes/origin/main',restore]);command(repo,['checkout','--detach',closed]);
 assert.equal(resolveB006(repo).phase,'REJECTED');
});

for (const p of ['package.json','scripts/ci/run-checks.mjs']) {
 test('exact merge cannot revert '+p+' to BASE on newer main behind older checkout',t=>{
  const repo=fixture(t);command(repo,['switch','-c','synthetic-merge',BASE]);command(repo,['merge','--no-ff','--no-edit',candidate]);
  const merge=command(repo,['rev-parse','HEAD']);assert.deepEqual(successorProblems(repo),[]);
  write(repo,p,blob(repo,BASE,p).toString());const revoked=commit(repo,'synthetic post-merge BASE revocation');
  command(repo,['update-ref','refs/remotes/origin/main',revoked]);command(repo,['checkout','--detach',merge]);
  rejected(repo,/approved B006 exception bytes\/history/);
 });
 for (const restore of [false,true]) test('closed '+p+' BASE revocation'+(restore?' and Candidate restoration':'')+' cannot hide behind older closed checkout',t=>{
  const repo=fixture(t);const closed=syntheticClosed(repo);const accepted=fs.readFileSync(path.join(repo,p));
  write(repo,p,blob(repo,BASE,p).toString());let latest=commit(repo,'synthetic closed BASE revocation');
  if(restore){fs.writeFileSync(path.join(repo,p),accepted);latest=commit(repo,'synthetic closed Candidate restore');}
  command(repo,['update-ref','refs/remotes/origin/main',latest]);command(repo,['checkout','--detach',closed]);
  rejected(repo,/approved B006 exception bytes\/history/);
  assert.equal(resolveB006(repo).phase,'REJECTED');
 });
}

for (const p of [CI,REVIEW,...RECORDS,STATUS]) {
 for (const mode of ['compact','duplicate-key']) test('introduced '+p+' rejects '+mode+' bytes even with identical parsed values',t=>{
  const repo=fixture(t);syntheticClosed(repo);const value=JSON.parse(fs.readFileSync(path.join(repo,p)));
  const compact=JSON.stringify(value);const key=Object.keys(value)[0];
  const wire=mode==='compact'?compact+'\n':'{'+JSON.stringify(key)+':"SYNTHETIC_INVALID_SHADOW",'+compact.slice(1)+'\n';
  write(repo,p,wire);command(repo,['add','-A']);command(repo,['commit','--amend','--no-edit']);
  const altered=command(repo,['rev-parse','HEAD']);command(repo,['update-ref','refs/remotes/origin/main',altered]);
  const resolved=resolveB006(repo);assert.equal(resolved.phase,'REJECTED');
  assert.ok(resolved.problems.some((p)=>p.includes('not exact canonical bytes')),JSON.stringify(resolved.problems));
  if(p===CI) assert.ok(resolved.problems.some((p)=>p.includes('actual introduced CI blob')),JSON.stringify(resolved.problems));
 });
}

for(const [label,mutate] of [
 ['B002 state',s=>{s.repositories.AIPT.mvp_b002.state='IN_PROGRESS';}],
 ['integration history',s=>{s.tracks['AIPT-STANDALONE'].batch_history['INT-AIPT-UNREGISTERED-MVP-001']='NOT_STARTED';}],
 ['external repository identity',s=>{s.repositories.UNREGISTERED.verified_head='0'.repeat(40);}],
 ['runtime registration',s=>{s.runtime.harness_installation='UNAUTHORIZED';}],
 ]) for(const closed of [false,true]) test('frozen predecessor '+label+' rewrite and restore rejects behind older '+(closed?'closed':'Candidate')+' checkout',t=>{
 const repo=fixture(t);const older=closed?syntheticClosed(repo):candidate;const original=fs.readFileSync(path.join(repo,STATUS));
 const value=JSON.parse(original);mutate(value);write(repo,STATUS,value);commit(repo,'synthetic frozen status rewrite');
 fs.writeFileSync(path.join(repo,STATUS),original);const restored=commit(repo,'synthetic frozen status restore');
 command(repo,['update-ref','refs/remotes/origin/main',restored]);command(repo,['checkout','--detach',older]);
 rejected(repo,/frozen predecessor status\/history/);
});
test('closed B006 status rewrite and restore rejects behind older closed checkout',t=>{
 const repo=fixture(t);const closed=syntheticClosed(repo);const original=fs.readFileSync(path.join(repo,STATUS));
 const value=JSON.parse(original);value.repositories.AIPT.mvp_b006.state='IN_PROGRESS';write(repo,STATUS,value);commit(repo,'synthetic B006 closed status rewrite');
 fs.writeFileSync(path.join(repo,STATUS),original);const restored=commit(repo,'synthetic B006 closed status restore');command(repo,['update-ref','refs/remotes/origin/main',restored]);command(repo,['checkout','--detach',closed]);
 const resolved=resolveB006(repo);assert.equal(resolved.phase,'REJECTED');assert.ok(resolved.problems.some(p=>p.includes('closed status/history')));
});
test('review cannot omit any known independent blocker from closed findings',t=>{
 const repo=fixture(t);syntheticClosed(repo);const review=JSON.parse(fs.readFileSync(path.join(repo,REVIEW)));
 review.closed_findings=review.closed_findings.slice(0,1);write(repo,REVIEW,review);command(repo,['add','-A']);command(repo,['commit','--amend','--no-edit']);command(repo,['update-ref','refs/remotes/origin/main',command(repo,['rev-parse','HEAD'])]);
 const resolved=resolveB006(repo);assert.equal(resolved.phase,'REJECTED');assert.ok(resolved.problems.some(p=>p.includes('independent review')));
});
