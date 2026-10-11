// Construction is never promoted to accepted pilot/qualification by metadata.
import { BASE, TASK, topology, successorProblems } from './b007-successor.mjs';
export function resolveB007(repo) {
 const t=topology(repo);const problems=successorProblems(repo);
 return {...t,task_id:TASK,phase:problems.length?'REJECTED':t.head===BASE?'AUTHORIZED_CONSTRUCTION':t.merge?'MERGED_PENDING_DIAGNOSTIC_AND_ACCEPTANCE':'CANDIDATE_PENDING_DIAGNOSTIC_AND_ACCEPTANCE',problems,runtime_ready:false,qualification_runs_executed:0};
}
