import fs from 'node:fs';
import path from 'node:path';
import { isDeepStrictEqual as equal } from 'node:util';
import { validateInstance } from './json-schema.mjs';
import { lifecycleRecordSha256, resolveEffectiveAuthority, AUTHORITY_LIFECYCLE_MODEL, AUTHORITY_LIFECYCLE_EVENTS, AUTHORITY_LIFECYCLE_ORDERING } from './authority-lifecycle.mjs';
import { BASE, BASE_TREE, TASK, STATUS, ENGINE, REPAIR, START, REGRESSION, GATE_AUTHORITY, sha, read, blob, facts, out, rows, git, inventory, firstParentContains } from './b006-successor.mjs';

export const KNOWN_FINDINGS = ["LOCAL-B006-B002-ZERO-RNG-REPLAY-001", "LOCAL-B006-CONFIG-SELF-DEPENDENCY-001", "LOCAL-B006-WORKER-CANCELLED-COMPLETION-001", "LOCAL-B006-SUCCESSOR-EXCEPTION-HISTORY-001", "LOCAL-B006-LIFECYCLE-CI-BYTE-BINDING-001", "LOCAL-B006-PREDECESSOR-STATUS-HISTORY-001"];

export const RECORD_ROOT = 'docs/authority/registry/authority-lifecycle/records/aipt-mvp-b006';
export const RECORDS = ['001-merged.json', '002-post-merge-verified.json', '003-closed.json'].map((p) => RECORD_ROOT + '/' + p);
export const CI = 'docs/authority/registry/verified-ci-evidence/aipt-mvp-b006/post-merge-ci.json';
export const REVIEW = 'docs/authority/registry/b006-independent-review.json';
export const CLOSEOUT_PATHS = [...RECORDS, CI, REVIEW, STATUS, 'docs/authority/PROJECT_STATUS.md', 'docs/milestones/MVP.md'].sort();
export const REQUIRED = [ENGINE, REPAIR, START, REGRESSION, GATE_AUTHORITY, STATUS, 'package.json', 'scripts/ci/run-checks.mjs',
 'scripts/ci/lib/b006-successor.mjs', 'scripts/ci/lib/b006-lifecycle.mjs', 'scripts/ci/validate/b006-approved-predecessors.mjs', 'scripts/ci/validate/mvp-b006.mjs', 'scripts/ci/test/b006-lifecycle.test.mjs',
 'docs/run-control/OPERATIONAL_CONTROLS_V1.md', 'testdata/run-control/v1/b006-security-matrix.json',
 'internal/runcontrol/service.go', 'internal/runcontrol/catalog.go', 'internal/runcontrol/catalog_test.go', 'internal/runcontrol/worker.go', 'internal/runcontrol/reports.go', 'internal/runcontrol/rpc.go', 'internal/runcontrol/postgres.go',
 'internal/operational/runtime.go', 'cmd/aipt-control/main.go', 'internal/web/operational.go', 'internal/web/operational_test.go', 'internal/web/operational/index.html', 'internal/web/operational/controls.js', 'internal/web/operational/controls.css',
 'internal/storage/postgres/b006_control_integration_test.go', 'packages/web-ui/src/controls.ts', 'packages/web-ui/test/controls.test.ts', 'packages/web-ui/scripts/build-control.mjs', 'packages/model-harness-gateway/test/fixture-acp-worker.ts'];
const OLD_ALLOWED = new Set([ENGINE, STATUS, 'package.json', 'scripts/ci/run-checks.mjs', 'docs/authority/PROJECT_STATUS.md', 'docs/milestones/MVP.md', 'packages/model-harness-gateway/test/fixture-acp-worker.ts']);
export function allowedCandidatePath(p) {
 return OLD_ALLOWED.has(p) || [REPAIR, START, REGRESSION, GATE_AUTHORITY, 'docs/run-control/OPERATIONAL_CONTROLS_V1.md', 'testdata/run-control/v1/b006-security-matrix.json', 'scripts/ci/lib/b006-successor.mjs', 'scripts/ci/lib/b006-lifecycle.mjs', 'scripts/ci/validate/b006-approved-predecessors.mjs', 'scripts/ci/validate/mvp-b006.mjs', 'scripts/ci/test/b006-lifecycle.test.mjs', 'internal/storage/postgres/b006_control_integration_test.go', 'internal/web/operational.go', 'internal/web/operational_test.go', 'internal/web/operational/index.html', 'internal/web/operational/controls.js', 'internal/web/operational/controls.css', 'packages/web-ui/src/controls.ts', 'packages/web-ui/test/controls.test.ts', 'packages/web-ui/scripts/build-control.mjs'].includes(p) || /^(?:internal\/runcontrol|internal\/operational|cmd\/aipt-control)\/[a-z0-9_]+\.go$/u.test(p);
}
export function changed(repo, base, revision) { return rows(repo, ['diff', '--name-only', '--no-renames', base, revision]).sort(); }
export function candidateProblems(repo, candidate) {
 const problems = [];
 if (['97fa4c6de50fcc1339c61e271c7b31430a611eff','ff7462b1a25047f7e042cf4963b4363f4cc64ec9','f1194fe197ae98bc7db9f8c04946c6b245bda339','e3a3e5084123345a1c9a838d73fd9309632a783d'].includes(candidate)) problems.push('known independent CONFIG/worker cancellation/exception/status history FAIL Candidate cannot receive acceptance');
 const f = facts(repo, candidate); const paths = f ? changed(repo, BASE, candidate) : [];
 if (!f || !equal(f.parents, [BASE]) || facts(repo, BASE)?.tree !== BASE_TREE) problems.push('B006 Candidate must be a direct single-parent successor of exact accepted B005 closeout');
 if (paths.some((p) => !allowedCandidatePath(p)) || REQUIRED.some((p) => !paths.includes(p))) problems.push('B006 Candidate has scope drift or missing required controls/repair/gates');
 for (const p of paths) if (!['100644', '100755'].includes(inventory(repo, candidate).get(p)?.mode)) problems.push('B006 Candidate contains a deleted/nonregular artifact: ' + p);
 return problems;
}
function legalMerge(repo, revision) {
 const merge = facts(repo, revision); const candidate = merge?.parents.length === 2 ? facts(repo, merge.parents[1]) : null;
 if (merge?.parents[0] !== BASE || !candidate || !equal(candidate.parents, [BASE]) || merge.tree !== candidate.tree || candidateProblems(repo, candidate.commit).length) return null;
 return { merge, candidate };
}
const CI_NAMES = ['b000-retro (fixed B000 commit, read-only expansion)', 'toolchain (ubuntu-24.04)', 'toolchain (ubuntu-26.04)', 'supply-chain (R4-Q023 gates)', 'storage-postgres (ephemeral PostgreSQL 18.4 integration)'].sort();
function keys(value, expected) { return value && typeof value === 'object' && !Array.isArray(value) && equal(Object.keys(value).sort(), [...expected].sort()); }
function positive(value) { return Number.isSafeInteger(value) && value > 0; }
export function ciProblems(value, merge, workflowSha) {
 const p = [];
 if (!keys(value, ['schema','version','task_id','repository','workflow_path','workflow_sha256','acceptance','run','jobs']) || value.schema !== 'aipt.public.verified-ci-evidence/v1' || value.version !== '1.0.0' || value.task_id !== TASK || value.repository !== 'zyc14588/AIPT' || value.workflow_path !== '.github/workflows/ci.yml' || value.workflow_sha256 !== workflowSha) p.push('B006 CI catalogue identity/workflow drift');
 const a = value?.acceptance; const r = value?.run; const jobs = value?.jobs;
 if (!keys(a, ['decision_id','mode','offline_trust_basis','verified_at']) || a.decision_id !== 'B006-B002-ZERO-RNG-REPAIR-Q001=A' || a.mode !== 'LOCAL_ONLINE_GITHUB_ACTIONS_VERIFICATION' || a.offline_trust_basis !== 'OWNER_ACCEPTED_IMMUTABLE_MAIN_CI_CATALOGUE' || typeof a.verified_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(a.verified_at) || !Number.isFinite(Date.parse(a.verified_at))) p.push('B006 CI catalogue lacks the authorized independent local online acceptance basis');
 if (!keys(r, ['id','head_sha','head_branch','event','status','conclusion','run_attempt']) || !positive(r.id) || !positive(r.run_attempt) || r.head_sha !== merge?.commit || r.head_branch !== 'main' || r.event !== 'push' || r.status !== 'completed' || r.conclusion !== 'success') p.push('B006 CI is not an exact successful main merge run');
 if (!Array.isArray(jobs) || jobs.length !== 5 || !equal(jobs.map((j) => j?.name).sort(), CI_NAMES) || new Set(jobs.map((j) => j?.id)).size !== 5 || jobs.some((j) => !keys(j, ['id','name','head_sha','status','conclusion']) || !positive(j.id) || j.head_sha !== merge?.commit || j.status !== 'completed' || j.conclusion !== 'success')) p.push('B006 CI must contain all five distinct exact successful jobs');
 return p;
}
function postFacts(ci) { return { run_id: ci.run.id, head_sha: ci.run.head_sha, conclusion: 'success', jobs_passed: 5, jobs_failed: 0, jobs_skipped: 0 }; }
export function expectedRecords(repo, candidate, merge, ci) {
 const identity = { task_id: TASK, artifact_id: TASK, artifact_path: 'internal/runcontrol/service.go', artifact_sha256: sha(blob(repo, candidate.commit, 'internal/runcontrol/service.go')), candidate_commit: candidate.commit, candidate_tree: candidate.tree, semantic_snapshot_state: 'CANDIDATE_FROZEN', semantic_snapshot_accepted: false };
 const records = [];
 for (let i = 0; i < 3; i++) {
  const event = ['MERGED','POST_MERGE_VERIFIED','CLOSED'][i];
  records.push({ schema:'aipt.public.authority-lifecycle-record/v1', record_id:TASK + '-LIFECYCLE-00' + (i+1) + '-' + event.replaceAll('_','-'), task_id:TASK, semantic_artifact_identity:identity, event, event_sequence:i+1,
   predecessor_lifecycle_record:i === 0 ? null : { record_id:records[i-1].record_id, record_sha256:lifecycleRecordSha256(records[i-1]) },
   authority_basis:{model_id:AUTHORITY_LIFECYCLE_MODEL,authorized_by_task:TASK,authorization_kind:'ACCEPTED_LIFECYCLE_MODEL'},
   event_evidence:i === 0 ? {kind:'GIT_MERGE',merge_identity:merge} : i === 1 ? {kind:'POST_MERGE_CI',post_merge_evidence:postFacts(ci)} : {kind:'GOVERNANCE_CLOSEOUT',closeout_identity:{commit_source:'CONTAINING_GIT_COMMIT',governance_only:true,owner_authorized:true}},
   record_identity:{identity_scheme:'IMMUTABLE_GIT_BLOB_AT_ACCEPTED_COMMIT',path:RECORDS[i],accepted_commit_source:'CONTAINING_GIT_COMMIT',append_only:true},created_by_task:TASK,
   provenance:{source_task:TASK,source_commit:i === 0 ? candidate.commit : merge.commit,source_tree:candidate.tree,record_creation_authority:'MERGE_AND_CLOSEOUT_AIPT_MVP_B006',record_creator_task:TASK,historical_evidence_claimed_only_if_proven:true},effective:i === 2 });
 }
 return records;
}
export function reviewProblems(review, candidate) {
 return keys(review, ['schema','task_id','source','agent','access','candidate_commit','candidate_tree','result','open_findings','closed_findings','independent_probe_count','report_sha256']) && review.schema === 'aipt.public.independent-security-review/v1' && review.task_id === TASK && review.source === 'LOCAL_INDEPENDENT_CODEX_AGENT' && review.agent === 'b005_independent_security_review' && review.access === 'READ_ONLY' && review.candidate_commit === candidate?.commit && review.candidate_tree === candidate?.tree && review.result === 'PASS' && equal(review.open_findings, []) && Array.isArray(review.closed_findings) && equal([...review.closed_findings].sort(), [...KNOWN_FINDINGS].sort()) && positive(review.independent_probe_count) && /^[a-f0-9]{64}$/u.test(review.report_sha256) ? [] : ['B006 independent review does not bind a PASS for the exact Candidate and authorized repair'];
}
export function expectedClosedStatus(repo, candidate, merge, ci, review) {
 const status = JSON.parse(blob(repo, candidate.commit, STATUS)); const track = status.tracks['AIPT-STANDALONE'];
 status.authority_snapshot_id = 'AIPT-MVP-B006-CLOSEOUT-001'; track.construction = 'IDLE_WAITING_NEXT_BATCH'; track.current_batch = 'NO_ACTIVE_BATCH'; track.global_wip = 0; track.batch_history[TASK] = 'MERGED_CLOSED';
 const b = status.repositories.AIPT.mvp_b006;
 Object.assign(b, { state:'MERGED_CLOSED', implementation_status:'ACCEPTED_OPERATIONAL_CONTROLS_AND_EXPLICIT_B002_SUCCESSOR_REPAIR',public_candidate_status:'ACCEPTED',public_ci_status:'POST_MERGE_5_OF_5_AND_INDEPENDENT_SECURITY_ACCEPTED',open_findings:[],closed_findings:review.closed_findings,independent_security_acceptance:'PASS',candidate:{commit:candidate.commit,tree:candidate.tree},merge,post_merge_ci:{...postFacts(ci),independent_catalogue_path:CI,independent_catalogue_sha256:sha(JSON.stringify(ci,null,2)+'\n')},runtime_ready:false,first_blocking_gate:'B007_REAL_DRIVER_AND_DIAGNOSTIC_PILOT' });
 status.runtime.status='B006 is MERGED_CLOSED after exact merge CI 5/5 and the same independent read-only Codex review. Shared PostgreSQL-authoritative Web/stdio controls and the explicitly authorized B002 empty-RNG clone successor are accepted. Original B002/B005 closeouts and failures remain immutable. Production game driver, real diagnostic pilot and qualification remain pending; runtime_ready=false, qualification Runs=0/8.';
 return status;
}
function acceptedClosure(repo, head, main, proposal = false) {
 const p = []; const source = proposal ? head : main;
 const additions = RECORDS.map((file) => rows(repo, ['log','--first-parent','--format=%H','--diff-filter=A',source,'--',file]));
 if (additions.some((x) => x.length !== 1) || new Set(additions.map((x) => x[0])).size !== 1) return {problems:['B006 lifecycle introduction is partial, duplicate or missing']};
 const closeout = additions[0][0]; const closeFacts = facts(repo,closeout); const pair = closeFacts?.parents.length === 1 ? legalMerge(repo,closeFacts.parents[0]) : null;
 if (!pair || !equal(changed(repo,closeFacts.parents[0],closeout),CLOSEOUT_PATHS) || !firstParentContains(repo,head,closeout)) return {problems:['B006 closeout is not an exact governance-only direct successor of the authorized merge/current ancestry']};
 const {candidate,merge}=pair; let ci,review,records,status;
 try {ci=JSON.parse(blob(repo,closeout,CI));review=JSON.parse(blob(repo,closeout,REVIEW));records=RECORDS.map((f)=>JSON.parse(blob(repo,closeout,f)));status=JSON.parse(blob(repo,closeout,STATUS));}
 catch {return {problems:['B006 closeout artifacts unreadable']};}
 // Accepted evidence hashes bind the introduced bytes, not a parsed approximation.
 // Exact canonical JSON also rejects duplicate keys discarded by JSON.parse.
 for (const [file,value] of [[CI,ci],[REVIEW,review],...RECORDS.map((file,i)=>[file,records[i]]),[STATUS,status]]) {
  if (!blob(repo,closeout,file)?.equals(Buffer.from(JSON.stringify(value,null,2)+'\n'))) p.push('B006 introduced closeout JSON is not exact canonical bytes: '+file);
 }
 if (status.repositories?.AIPT?.mvp_b006?.post_merge_ci?.independent_catalogue_sha256!==sha(blob(repo,closeout,CI)??Buffer.alloc(0))) p.push('B006 status catalogue digest does not bind the actual introduced CI blob');
 p.push(...ciProblems(ci,merge,sha(blob(repo,merge.commit,'.github/workflows/ci.yml'))),...reviewProblems(review,candidate));
 const schema=JSON.parse(read(repo,'schemas/authority-lifecycle/v1/aipt-authority-lifecycle-record.schema.json'));
 if (!equal(records,expectedRecords(repo,candidate,merge,ci))) p.push('B006 lifecycle canonical identities/provenance/hash links differ');
 for (const record of records) p.push(...validateInstance(schema,record).errors.map((e)=>e.message));
 if (!equal(status,expectedClosedStatus(repo,candidate,merge,ci,review))) p.push('B006 closeout status is not the exact accepted projection');
 const immutable=[...RECORDS,CI,REVIEW]; const frozenBusiness=changed(repo,BASE,candidate.commit).filter((f)=>![STATUS,'docs/authority/PROJECT_STATUS.md','docs/milestones/MVP.md'].includes(f));
 for (const revision of new Set([head,source])) {
  if (rows(repo,['log','--first-parent','--full-history','--format=%H',closeout+'..'+revision,'--',...immutable]).length) p.push('accepted B006 lifecycle/independent evidence history rewritten on '+revision);
  if (!equal(rows(repo,['ls-tree','-r','--name-only',revision,'--',RECORD_ROOT]).sort(),[...RECORDS].sort()) || !equal(rows(repo,['ls-tree','-r','--name-only',revision,'--',path.posix.dirname(CI)]),[CI])) p.push('accepted B006 evidence inventory changed');
  for (const f of frozenBusiness) if (!blob(repo,candidate.commit,f)?.equals(blob(repo,revision,f)??Buffer.alloc(0)) || rows(repo,['log','--first-parent','--full-history','--format=%H',merge.commit+'..'+revision,'--',f]).length) p.push('accepted B006 business/history changed on '+revision+': '+f);
  const statusVersions=[revision,...rows(repo,['log','--first-parent','--full-history','--format=%H',closeout+'..'+revision,'--',STATUS])];
  for (const id of new Set(statusVersions)) {
   try {
    const value=JSON.parse(blob(repo,id,STATUS));
    if (!equal(value.repositories?.AIPT?.mvp_b006,status.repositories.AIPT.mvp_b006) || value.tracks?.['AIPT-STANDALONE']?.batch_history?.[TASK]!=='MERGED_CLOSED') p.push('accepted B006 closed status/history reopened or rewritten on '+revision+' at '+id);
   } catch {p.push('accepted B006 closed status/history missing or unreadable on '+revision+' at '+id);}
  }
 }
 for (const f of [...immutable,...frozenBusiness]) {try {const accepted=blob(repo,immutable.includes(f)?closeout:candidate.commit,f);if (!accepted?.equals(read(repo,f))) p.push('accepted B006 working artifact changed: '+f);}catch {p.push('accepted B006 working artifact missing: '+f);}}
 const current=JSON.parse(read(repo,STATUS));
 if (!equal(current.repositories?.AIPT?.mvp_b006,status.repositories.AIPT.mvp_b006) || current.tracks?.['AIPT-STANDALONE']?.batch_history?.[TASK] !== 'MERGED_CLOSED') p.push('accepted B006 status reopened or rewritten');
 if (p.length===0) {
  const ids=records.map((r)=>r.record_id);const resolution=resolveEffectiveAuthority({semantic_artifact_identity:records[0].semantic_artifact_identity,records,
   policy:{model_id:AUTHORITY_LIFECYCLE_MODEL,events:AUTHORITY_LIFECYCLE_EVENTS,ordering:AUTHORITY_LIFECYCLE_ORDERING,canonical_truth_source:'ACCEPTED_APPEND_ONLY_LIFECYCLE_RECORD_CHAIN',semantic_fields_are_snapshot_metadata:true,semantic_artifact_mutation_permitted:false,unlisted_transition:'REJECT',closed_terminal:true},
   record_acceptance:Object.fromEntries(records.map((r,i)=>[r.record_id,{accepted:true,commit:closeout,commit_ordinal:1,first_parent_ancestry:true,path:RECORDS[i],introduced_sha256:sha(blob(repo,closeout,RECORDS[i])),current_sha256:sha(read(repo,RECORDS[i])),canonical_record_sha256:lifecycleRecordSha256(r)}])),authority_basis_acceptance:Object.fromEntries(ids.map((id)=>[id,true])),
   evidence_catalogue:{merge_commits:{[merge.commit]:{tree:merge.tree,parents:merge.parents,accepted_ancestry:true}},post_merge_runs:{[String(ci.run.id)]:postFacts(ci)},closeout_records:{[ids[2]]:{commit:closeout,governance_only:true,owner_authorized:true}}},expected_accepted_record_ids:ids,expected_lifecycle_state:'CLOSED'});
  p.push(...resolution.problems); if (!resolution.effective) p.push('B006 effective CLOSED authority unresolved');
 }
 return {problems:p,candidate,merge,closeout,ci,review,paths:changed(repo,BASE,candidate.commit),phase:proposal?'CLOSEOUT_PROPOSAL':'CLOSED_HISTORICAL_REPLAY'};
}
export function resolveB006(repo) {
 const head=out(repo,['rev-parse','HEAD^{commit}']);const main=out(repo,['rev-parse','refs/remotes/origin/main^{commit}']);
 try {
  const onMain=RECORDS.some((f)=>rows(repo,['log','--first-parent','--format=%H','--diff-filter=A',main,'--',f]).length);
  if (onMain) {const closure=acceptedClosure(repo,head,main);return {...closure,head,main,phase:closure.problems.length?'REJECTED':closure.phase};}
  const workingRecords=RECORDS.filter((f)=>fs.existsSync(path.join(repo,f)));
  if (workingRecords.length) {const closure=acceptedClosure(repo,head,main,true);return {...closure,head,main,phase:closure.problems.length?'REJECTED':closure.phase};}
  const f=facts(repo,head);const merge=legalMerge(repo,head);
  if (merge) return {phase:'LEGAL_MERGE',...merge,head,main,paths:changed(repo,BASE,merge.candidate.commit),problems:[]};
  if (f && equal(f.parents,[BASE])) {const p=candidateProblems(repo,head);return {phase:p.length?'REJECTED':'CANDIDATE',head,main,candidate:f,paths:changed(repo,BASE,head),problems:p};}
  return {phase:'REJECTED',head,main,problems:['B006 has no exact Candidate/Base merge or accepted closeout topology']};
 }catch(error){return {phase:'REJECTED',head,main,problems:['B006 lifecycle failed closed: '+error.message]};}
}
