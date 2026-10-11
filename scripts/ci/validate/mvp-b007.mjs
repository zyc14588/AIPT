#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { runAsMain } from '../lib/cli.mjs';
import { runPublicationHygiene } from '../lib/publication-hygiene.mjs';
import { resolveB007 } from '../lib/b007-lifecycle.mjs';
import { STATUS, MUTABLE, allowedNew, rows } from '../lib/b007-successor.mjs';

// A construction check can pass before the accepted candidate/merge CI exists.
// It never authenticates a runtime binding, completes B007, authorizes a model
// call, consumes the one diagnostic or invents its evidence. The accepted
// private launch requires the separate full review and exact online CI grant.
const requiredTests = new Map([
 ['TestTask0PreparationOpensOnlyExactPrivateRegularSource', 'internal/pilot/task0_preparation_test.go'],
 ['TestTask0PreparationConnectionHasNoSelectorOrAmbientCredential', 'internal/pilot/task0_preparation_test.go'],
 ['TestTask0PreparationRootPinsRejectAliasingAndRename', 'internal/pilot/task0_preparation_test.go'],
 ['TestTask0ParentControlNeverAcceptsQualificationOrLocators', 'internal/pilot/task0_preparation_test.go'],
 ['TestTask0ExecutorRejectsMissingAuthorityWithoutOpeningRuntime', 'internal/pilot/task0_executor_test.go'],
 ['TestPreparedLocalMissingAcceptanceCannotStartOrExposeProof', 'internal/pilot/pilot_local_test.go'],
]);

export function inspectConstruction(repo) {
 const lifecycle=resolveB007(repo);const problems=[...lifecycle.problems];let publication=null;
 try {
  const status=JSON.parse(fs.readFileSync(path.join(repo,STATUS),'utf8'));
  const b=status.repositories.AIPT.mvp_b007;
  if(b.state!=='IN_PROGRESS'||b.runtime_ready!==false||b.real_model_calls!==0||b.diagnostic_runs_executed!==0||b.qualification_runs_executed!==0||b.qualification_execution_authorized!==false||b.private_evidence_full_acceptance!==false||b.public_ci_real_model_calls!==0) problems.push('construction must preserve pending full acceptance and zero actual model/DIAG/QUAL claims');
  for(const [name,file] of requiredTests) {
   const code=fs.readFileSync(path.join(repo,file),'utf8');
   if(!code.includes('func '+name+'(')) problems.push('required executable rejection coverage is absent: '+name);
  }
  const command=fs.readFileSync(path.join(repo,'cmd/aipt-pilot/main.go'),'utf8');
  for(const value of ['var acceptedParentBindingSHA string','var acceptedPreparationBindingSHA string','pilot.RunAcceptedTask0Parent(acceptedParentBindingSHA)','pilot.RunAcceptedTask0Preparation(acceptedPreparationBindingSHA)']) if(!command.includes(value)) problems.push('externally compiled, unbound-by-default entry is absent');
  const scope=rows(repo,['ls-files','--cached','--others','--exclude-standard']).filter(p=>MUTABLE.has(p)||allowedNew(p));
  publication=runPublicationHygiene({repo,files:scope});
  if(publication.result!=='PASS'||publication.coverage!=='complete'||!publication.required_detectors_executed) problems.push('public construction publication hygiene failed or was incomplete');
 } catch { problems.push('B007 construction inspection failed closed'); }
 return {lifecycle,problems,publication};
}

function componentCheck(repo) {
 // Public CI cannot inherit credentials, private source/fixture selectors or
 // database routes from the caller. Optional private checks remain pending.
 const keep=new Set(['PATH','HOME','TMPDIR','CC','CXX','GOTOOLCHAIN','GOCACHE','GOMODCACHE','GOPATH','GOFLAGS','GOPROXY','GOSUMDB','CGO_ENABLED']);
 const env=Object.fromEntries(Object.entries(process.env).filter(([k])=>keep.has(k)));
 const command=['test','-race','-count=1','-json','./internal/pilot','./internal/evidence'];
 const p=spawnSync('go',command,{cwd:repo,env,encoding:'utf8',maxBuffer:32*1024*1024,timeout:300000});
 const events=(p.stdout??'').split('\n').flatMap(line=>{try{return [JSON.parse(line)];}catch{return [];}});
 const terminal=events.filter(e=>e.Test&&['pass','fail','skip'].includes(e.Action));
 const pass=terminal.filter(e=>e.Action==='pass');const fail=terminal.filter(e=>e.Action==='fail');const skip=terminal.filter(e=>e.Action==='skip').map(e=>e.Test);
 const missing=[...requiredTests.keys()].filter(name=>!pass.some(e=>e.Test===name));
 const good=!p.error&&!p.signal&&p.status===0&&pass.length>=100&&fail.length===0&&missing.length===0;
 return {result:good?'PASS':'FAIL',classification:'PUBLIC_NON_CANON_COMPONENT_CHECK_ONLY',command:['go',...command],exit_code:p.status,passed_tests:pass.length,failed_tests:fail.length,skipped_tests:skip,missing_required_pass_tests:missing,problem:good?null:'component race check failed or required rejection coverage did not pass',real_model_calls:0,application_github_requests:0,full_runtime_acceptance:false};
}

export function run(ctx) {
 const {lifecycle,problems,publication}=inspectConstruction(ctx.repo);const checks=[];
 if(problems.length===0) {
  const c=componentCheck(ctx.repo);checks.push(c);if(c.result!=='PASS') problems.push(c.problem);
 }
 return {result:problems.length?'FAIL':'PASS',task_id:'AIPT-MVP-B007',validation_scope:'AUTHORIZED_CONSTRUCTION_ONLY',lifecycle_phase:lifecycle.phase,
  details:problems.length?problems.map(x=>'FAIL: '+x):['ok: exact predecessor/Owner authority and sole-WIP construction guards','ok: new Parent/PREP source and executable rejection tests retain default unbound launch','ok: public code hygiene and offline component race checks; private production acceptance remains pending'],
  checks,publication_hygiene:publication,completion_acceptance:'PENDING_FULL_REVIEW_EXACT_CI_AND_ONE_REAL_DIAGNOSTIC',first_blocking_gate:'Q011_PRIVATE_EVIDENCE_AND_COMPLETE_AUTHENTICATED_TASK0_DRIVER_ACCEPTANCE',
  gate_pass:false,b007_completed:false,runtime_ready:false,paid_callable:false,private_evidence_full_acceptance:false,real_model_calls:0,diagnostic_runs_executed:0,qualification_runs_executed:0,external_github_requests:0};
}
runAsMain(import.meta.url,'mvp-b007',run);
