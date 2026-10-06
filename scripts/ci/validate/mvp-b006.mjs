#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { runAsMain } from '../lib/cli.mjs';
import { runPublicationHygiene } from '../lib/publication-hygiene.mjs';
import { successorProblems, BASE, TASK, STATUS, REPAIR_SHA, GATE_AUTHORITY, GATE_AUTHORITY_SHA, GATE_DECISION, read } from '../lib/b006-successor.mjs';
import { resolveB006, REQUIRED, CLOSEOUT_PATHS } from '../lib/b006-lifecycle.mjs';

function execute(repo, label, command, args, jsonGo = false, timeoutMs = 180000) {
 const env=Object.fromEntries(Object.entries(process.env).filter(([k])=>!k.startsWith('GITHUB_')));
 const r=spawnSync(command,args,{cwd:repo,env,encoding:'utf8',maxBuffer:16*1024*1024,timeout:timeoutMs});
 const events=jsonGo ? r.stdout?.split('\n').filter(Boolean).flatMap((line)=>{try{return [JSON.parse(line)];}catch{return [];}})??[] : [];
 const tests=events.filter((e)=>e.Action==='pass'&&e.Test).length;
 const skip=events.filter((e)=>e.Action==='skip'&&e.Test).map((e)=>e.Test);
 const good=!r.error&&!r.signal&&r.status===0&&(!jsonGo||tests>=100);
 return {label,result:good?'PASS':'FAIL',passed_tests:jsonGo?tests:null,skipped_tests:skip,problem:good?null:(r.error?.message??(r.stderr+'\n'+r.stdout).slice(-3000))};
}
export function run(ctx) {
 const p=successorProblems(ctx.repo);const lifecycle=resolveB006(ctx.repo);p.push(...lifecycle.problems);
 let publication=null;const checks=[];
 try {
  const status=JSON.parse(read(ctx.repo,STATUS));const track=status.tracks['AIPT-STANDALONE'];const b=status.repositories.AIPT.mvp_b006;
  if (b.runtime_ready!==false||b.qualification_runs_executed!==0||b.model_calls!==0||b.public_ci_real_model_calls!==0||b.real_playtest_executed!==false||status.integration_closeouts['INT-AIPT-UNREGISTERED-MVP-001'].execution.rerun_performed!==false) p.push('B006 promoted runtime/model/qualification or historical integration claims');
  if (['CANDIDATE','LEGAL_MERGE'].includes(lifecycle.phase) && (b.state!=='IN_PROGRESS'||track.current_batch!==TASK||track.global_wip!==1||track.batch_history[TASK]!=='IN_PROGRESS'||track.next_serial_batch!=='AIPT-MVP-B007'||track.next_batch_authorized!==false||track.next_batch_started!==false||b.predecessor_repair_authority?.sha256!==REPAIR_SHA||b.predecessor_gate_authority?.path!==GATE_AUTHORITY||b.predecessor_gate_authority?.sha256!==GATE_AUTHORITY_SHA||b.predecessor_gate_authority?.decision_id!==GATE_DECISION)) p.push('B006 current/next/WIP/Owner-repair state is not the authorized construction tuple');
  const matrix=JSON.parse(read(ctx.repo,'testdata/run-control/v1/b006-security-matrix.json'));
  if (matrix.schema!=='aipt.public.b006-security-matrix/v1'||matrix.cases.length!==14||new Set(matrix.cases.map((c)=>c.id)).size!==14) p.push('B006 security matrix inventory drift');
  for (const c of matrix.cases) if (!/^C(?:0[1-9]|1[0-4])$/u.test(c.id)||!read(ctx.repo,c.test_path).toString().includes('func '+c.test_name+'(')) p.push('security case lacks its executable test: '+c.id);
  const goPG=read(ctx.repo,'internal/storage/postgres/b006_control_integration_test.go').toString();
  if (!goPG.includes('func TestPostgresIntegrationB006WebAndRPCShareQueueAndImmutableManifest(')||!goPG.includes('func TestPostgresIntegrationB006RunCoreReplayAndWorkerWIP(')) p.push('B006 PostgreSQL tests are not selected by the retained public integration workflow');
  const scope=[...new Set([...(lifecycle.paths??REQUIRED),...(['CLOSEOUT_PROPOSAL','CLOSED_HISTORICAL_REPLAY'].includes(lifecycle.phase)?CLOSEOUT_PATHS:[])])];
  publication=runPublicationHygiene({repo:ctx.repo,files:scope});if (publication.result!=='PASS'||publication.coverage!=='complete'||!publication.required_detectors_executed) p.push('B006 publication hygiene failed or was incomplete');
  if (p.length===0) {
   checks.push(execute(ctx.repo,'deterministic embedded UI artifact',process.execPath,['packages/web-ui/scripts/build-control.mjs','--check']));
   checks.push(execute(ctx.repo,'strict UI public wire and export contracts',process.execPath,['--test','packages/web-ui/test/controls.test.ts']));
   checks.push(execute(ctx.repo,'actual Git successor/lifecycle attack probes',process.execPath,['--test','scripts/ci/test/b006-lifecycle.test.mjs'],false,300000));
   checks.push(execute(ctx.repo,'shared controls HTTP RPC worker Core unit/race tests','go',['test','-race','-json','./internal/runcontrol','./internal/web','./internal/operational','./cmd/aipt-control','./internal/runcore','-count=1'],true));
   for (const c of checks) if (c.result!=='PASS') p.push(c.label+': '+c.problem);
  }
 }catch(error){p.push('B006 validator failed closed: '+error.message);}
 return {result:p.length?'FAIL':'PASS',task_id:TASK,base_commit:BASE,lifecycle_phase:lifecycle.phase,head_commit:lifecycle.head,candidate:lifecycle.candidate??null,
  details:p.length?p.map((x)=>'FAIL: '+x):['ok: operational HTTP/stdio use one PostgreSQL-authoritative service','ok: the exact Owner-approved B002 nil/empty clone successor is checked separately from immutable legacy replay','ok: strict requests, loopback/CSRF, public held report export, WIP/lease/stop and truthful readiness have executable negative coverage','ok: exact Candidate/Base merge and append-only independent CI/review closeout rules pass'],
  checks,publication_hygiene:publication,external_github_requests:0,real_model_calls:0,qualification_runs_executed:0,runtime_ready:false,production_executor_configured:false,production_game_driver:'B007_PENDING',postgresql_coverage:{public_ci:'RETAINED_FULL_INTEGRATION_SELECTOR_INCLUDES_B006',local_race:'REQUIRED_FOR_CLOSEOUT',public_b006_postgres_race_claimed:false}};
}
runAsMain(import.meta.url,'mvp-b006',run);
