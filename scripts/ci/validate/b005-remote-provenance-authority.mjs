#!/usr/bin/env node
// Governance-only validator for
// AIPT-MVP-B005-REMOTE-PROVENANCE-AUTHORITY-001.
//
// This gate validates only the frozen Authority, its projections, candidate
// scope, publication hygiene, and A01-A11 governance mutations. It performs
// no GitHub request in normal CI mode, model/provider request, B005 runtime repair, integration
// rerun, playtest, or qualification execution.
import fs from 'node:fs';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { createHash } from 'node:crypto';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import https from 'node:https';
import { rootCertificates } from 'node:tls';
import { fileURLToPath } from 'node:url';
import { AUTHORITY_LIFECYCLE_MODEL, AUTHORITY_LIFECYCLE_EVENTS, AUTHORITY_LIFECYCLE_ORDERING, lifecycleRecordSha256, resolveEffectiveAuthority } from '../lib/authority-lifecycle.mjs';
import { git, parseArgs, runAsMain } from '../lib/cli.mjs';
import { checkSchemaDocument, validateInstance } from '../lib/json-schema.mjs';
import { runPublicationHygiene } from '../lib/publication-hygiene.mjs';

const TASK_ID = 'AIPT-MVP-B005-REMOTE-PROVENANCE-AUTHORITY-001';
const PARENT_BATCH = 'AIPT-MVP-B005';
const POLICY_ID = 'ONLINE_GITHUB_REMOTE_PROVENANCE_V1';
const BASE_COMMIT = 'c07e1aae94f681733ad73c1800423248bcc72376';
const BASE_TREE = '828defa8ea85a757b43d1a04ce05016ebeea9020';
const BRANCH = `task/${TASK_ID}`;
const POLICY_PATH = 'docs/authority/registry/remote-provenance-policy.json';
const SCHEMA_PATH = 'schemas/remote-provenance/v1/aipt-remote-provenance-policy.schema.json';
const HUMAN_PATH = 'docs/authority/amendments/AIPT_MVP_B005_REMOTE_PROVENANCE_AUTHORITY_001.md';
const STATUS_PATH = 'docs/authority/registry/project-status.json';

const EXPECTED_CHANGED_PATHS = Object.freeze([
  'docs/authority/DECISION_MATRIX.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/README.md',
  HUMAN_PATH,
  POLICY_PATH,
  'docs/evidence/README.md',
  'package.json',
  SCHEMA_PATH,
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/b005-remote-provenance-authority.mjs',
].sort());

const EXPECTED = Object.freeze({
  refinement: Object.freeze(['R9-Q004', 'R10-Q005']),
  preserved: Object.freeze(['R0-Q004', 'R0-Q012', 'R9-Q004', 'R10-Q005', 'R11-Q003', 'R11-Q004']),
  acceptedForms: Object.freeze([
    'https://github.com/<owner>/<repo>',
    'https://github.com/<owner>/<repo>.git',
  ]),
  forbiddenRepositoryComponents: Object.freeze([
    'USERINFO', 'PASSWORD', 'TOKEN', 'QUERY', 'FRAGMENT', 'CONTROL_CHARACTER',
    'NON_HTTPS_SCHEME', 'NON_GITHUB_COM_HOST', 'EXTRA_PATH_SEGMENT',
  ]),
  failureConditions: Object.freeze([
    'DNS_FAILURE', 'TLS_FAILURE', 'TIMEOUT', 'HTTP_403', 'HTTP_404', 'HTTP_429',
    'HTTP_5XX', 'OVERSIZED_RESPONSE', 'MALFORMED_RESPONSE', 'COMMIT_MISMATCH',
    'TREE_MISMATCH', 'REDIRECT',
  ]),
  receiptFields: Object.freeze([
    'schema', 'version', 'policy_id', 'provider', 'repository', 'commit', 'tree', 'status',
  ]),
  forbiddenReceiptFields: Object.freeze([
    'verification_timestamp', 'http_headers', 'github_request_id', 'etag', 'rate_limit_state',
    'ip', 'hostname', 'local_path', 'credential', 'github_response_body', 'temporary_endpoint',
  ]),
  probes: Object.freeze(['P01', 'P02', 'P03', 'P04', 'P05', 'P06', 'P07', 'P08', 'P09', 'P10', 'P11', 'P12']),
  openFindings: Object.freeze([
    Object.freeze({ id: 'csf_a1972a15d20bffccad42fbdb', severity: 'HIGH', state: 'OPEN_REQUIRES_R1' }),
    Object.freeze({ id: 'csf_4c0f54541fae325dd26494b0', severity: 'MEDIUM', state: 'OPEN_REQUIRES_R1' }),
    Object.freeze({ id: 'csf_b28e7fb44b3e754d93704fa2', severity: 'MEDIUM', state: 'OPEN_REQUIRES_R1' }),
  ]),
  fixedFindings: Object.freeze([
    'csf_79ae442f21f33ad95cc698f3',
    'csf_2e89d096e9e5fc0fb26494b0',
    'csf_1b9288ef93ab4e203b070db6',
  ]),
});

const REQUIRED_DECISIONS = Object.freeze({
  'R0-Q004': Object.freeze({ choice: 'B', qualifier: '多仓库分别权威，以不可变 Commit 清单绑定' }),
  'R0-Q012': Object.freeze({ choice: 'A', qualifier: '权威仓库公开，可由 GPT/Codex 基于远端 Commit 只读审计' }),
  'R9-Q004': Object.freeze({ choice: 'B', qualifier: '只有已推送权威远端的不可变 Commit 可正式审计' }),
  'R10-Q005': Object.freeze({ choice: 'A', qualifier: 'Codex 只读远端仓库和输入证据，仅写独立审计输出目录' }),
  'R11-Q003': Object.freeze({ choice: 'C', qualifier: '只读 source-mirror、可销毁 verification-worktree、持久可写 audit-output 三工作区' }),
  'R11-Q004': Object.freeze({ choice: 'B', qualifier: 'Codex 获得 GitHub 只读网络访问和只读凭据' }),
});

function read(repo, relative) {
  return fs.readFileSync(path.join(repo, relative), 'utf8');
}

function readJSON(repo, relative) {
  return JSON.parse(read(repo, relative));
}

function gitResult(repo, args) {
  return git(repo, args, { check: false });
}

function resultLines(result) {
  return result?.status === 0 ? result.stdout.split('\n').filter(Boolean) : [];
}

function gitOut(repo, args) {
  const result = gitResult(repo, args);
  return result.status === 0 ? result.stdout.trim() : null;
}

function commitFacts(repo, commit) {
  const row = gitOut(repo, ['rev-list', '--parents', '-n', '1', commit]);
  if (!row) return null;
  const [resolved, ...parents] = row.split(/\s+/u);
  const tree = gitOut(repo, ['rev-parse', `${resolved}^{tree}`]);
  return tree ? { commit: resolved, tree, parents } : null;
}

function schemaStrictObjectProblems(schema) {
  const problems = [];
  const pending = [['#', schema]];
  while (pending.length > 0) {
    const [location, value] = pending.pop();
    if (value === null || typeof value !== 'object') continue;
    if (!Array.isArray(value) && value.type === 'object' && value.additionalProperties !== false) {
      problems.push(`${location} object is not additionalProperties=false`);
    }
    for (const [key, child] of Object.entries(value)) {
      if (child !== null && typeof child === 'object') pending.push([`${location}/${key}`, child]);
    }
  }
  return problems;
}

function equalProblem(problems, label, actual, expected) {
  if (!isDeepStrictEqual(actual, expected)) problems.push(`${label} differs from the frozen Authority`);
}

function policySemanticProblems(policy) {
  const problems = [];
  if (policy.schema !== 'aipt.remote-provenance-policy/v1' || policy.version !== '1.0.0' ||
      policy.policy_id !== POLICY_ID) {
    problems.push('policy identity is not the frozen v1 decision');
  }
  if (policy.authority?.task_id !== TASK_ID || policy.authority?.parent_batch !== PARENT_BATCH ||
      policy.authority?.owner_decision !== 'B005-PROV-Q001=A' ||
      policy.authority?.authority_gap !== 'REMOTE_PROVENANCE_VERIFICATION_UNDERSPECIFIED' ||
      policy.authority?.candidate_state !== 'PRIVATE_GOVERNANCE_CANDIDATE_FROZEN' ||
      policy.authority?.implementation_state !== 'AUTHORITY_DEFINED_IMPLEMENTATION_PENDING_R1' ||
      policy.authority?.remote_commit_authority_weakened !== false) {
    problems.push('Authority identity, gap, state, or non-weakening assertion drifted');
  }
  equalProblem(problems, 'operational refinement set', policy.authority?.operational_refinement_of, EXPECTED.refinement);
  equalProblem(problems, 'preserved decision set', policy.authority?.preserved_decisions, EXPECTED.preserved);
  const blocked = policy.blocked_b005_merge;
  if (blocked?.commit !== BASE_COMMIT || blocked?.tree !== BASE_TREE || blocked?.ci_run !== 33767358596 ||
      blocked?.ci_conclusion !== 'success' || blocked?.post_merge_security !== 'FAIL' ||
      blocked?.lifecycle_records_created !== false || blocked?.accepted_as_final_merge !== false) {
    problems.push('blocked B005 merge facts drifted or were promoted to accepted');
  }
  if (policy.supported_provider !== 'GITHUB_PUBLIC_HTTPS_API_V1' ||
      policy.supported_repository_class !== 'PUBLIC_GITHUB_REPOSITORY' ||
      policy.private_repo_support !== 'NOT_SUPPORTED_BY_THIS_MVP_POLICY' ||
      policy.non_github_support !== 'NOT_SUPPORTED_BY_THIS_MVP_POLICY') {
    problems.push('GitHub public provider/repository closed set was broadened');
  }
  equalProblem(problems, 'accepted repository forms', policy.repository_identity?.accepted_forms, EXPECTED.acceptedForms);
  equalProblem(problems, 'forbidden repository components', policy.repository_identity?.forbidden_components, EXPECTED.forbiddenRepositoryComponents);
  if (policy.repository_identity?.canonical_origin !== 'https://github.com' ||
      policy.repository_identity?.parsed_identity !== 'EXACT_OWNER_AND_REPO' ||
      policy.repository_identity?.invalid_identity_policy !== 'FAIL_CLOSED') {
    problems.push('repository identity boundary drifted');
  }
  if (policy.verification_mode !== 'ONLINE_AUTHORITATIVE_EXACT_COMMIT_AND_TREE_ON_GENERATE_AND_INDEPENDENT_VERIFY') {
    problems.push('online exact Commit/Tree generation and independent verification are not both required');
  }
  const remote = policy.remote_verification;
  if (remote?.api_scheme !== 'HTTPS_ONLY' || remote?.api_host !== 'api.github.com' || remote?.method !== 'GET' ||
      remote?.path_template !== '/repos/{owner}/{repo}/git/commits/{commit}' ||
      remote?.endpoint_source !== 'BUILT_IN_FIXED' || remote?.caller_configurable_endpoint !== false ||
      remote?.caller_configurable_base_url !== false || remote?.caller_configurable_proxy_endpoint !== false ||
      remote?.branch_lookup !== 'FORBIDDEN' || remote?.tag_lookup !== 'FORBIDDEN' ||
      remote?.local_mirror_lookup_as_remote_proof !== 'FORBIDDEN' ||
      remote?.exact_commit_sha_required !== true || remote?.exact_tree_sha_required !== true ||
      remote?.successful_response_policy !== 'EXACT_OBJECT_SUCCESS_ONLY' ||
      remote?.tls_policy !== 'STANDARD_VALIDATED_TLS' || remote?.user_controlled_ca !== 'FORBIDDEN' ||
      remote?.environment_http_proxy !== 'FORBIDDEN' || remote?.timeout_policy !== 'BOUNDED_CONNECTION_AND_READ' ||
      remote?.response_body_policy !== 'BOUNDED' || remote?.json_decoding_policy !== 'BOUNDED') {
    problems.push('fixed authoritative GitHub endpoint or bounded network semantics drifted');
  }
  if (policy.authentication_mode !== 'NO_CREDENTIAL' || policy.redirect_policy !== 'FAIL_CLOSED_NO_FOLLOW') {
    problems.push('public no-auth or redirect fail-closed boundary drifted');
  }
  const claim = policy.reserved_claim;
  if (claim?.value !== 'VERIFIED_IMMUTABLE_REMOTE_COMMIT' || claim?.classification !== 'RESERVED_PROVENANCE_CLAIM' ||
      claim?.minting_authority !== 'BUILT_IN_AUTHORITY_APPROVED_GITHUB_PUBLIC_HTTPS_API_V1_PRODUCTION_VERIFIER_ONLY' ||
      claim?.production_caller_injected_verifier !== 'FORBIDDEN' ||
      claim?.test_seam !== 'UNEXPORTED_PACKAGE_INTERNAL_ONLY') {
    problems.push('reserved provenance claim can be minted outside the built-in production verifier');
  }
  const mirror = policy.local_mirror_role;
  if (mirror?.role !== 'SOURCE_CONTENT_CACHE_AND_LOCAL_OBJECT_CONSISTENCY_CHECK' ||
      mirror?.maximum_claim !== 'LOCAL_OBJECT_MATCH' || mirror?.remote_provenance_authority !== false ||
      mirror?.origin_url_equality_is_remote_proof !== false || mirror?.object_presence_is_remote_proof !== false ||
      mirror?.uid_ownership_is_remote_proof !== false || mirror?.fallback_on_remote_failure !== 'FORBIDDEN') {
    problems.push('local mirror was promoted above non-authoritative cache/consistency semantics');
  }
  const failure = policy.failure_policy;
  if (failure?.default !== 'FAIL_CLOSED' ||
      failure?.remote_unavailable !== 'BLOCKED_REMOTE_PROVENANCE_UNAVAILABLE' ||
      failure?.unsupported_provider !== 'REMOTE_PROVENANCE_PROVIDER_UNSUPPORTED' ||
      failure?.mirror_fallback !== 'FORBIDDEN') {
    problems.push('unsupported/unavailable/fallback failure policy drifted');
  }
  equalProblem(problems, 'fail-closed condition set', failure?.fail_closed_conditions, EXPECTED.failureConditions);
  const receipt = policy.receipt_contract;
  equalProblem(problems, 'receipt required fields', receipt?.required_fields, EXPECTED.receiptFields);
  equalProblem(problems, 'receipt forbidden fields', receipt?.forbidden_fields, EXPECTED.forbiddenReceiptFields);
  if (receipt?.schema !== 'aipt.remote-provenance/v1' || receipt?.version !== '1.0.0' ||
      receipt?.additional_properties !== false || receipt?.policy_id !== POLICY_ID ||
      receipt?.provider !== 'GITHUB_PUBLIC_HTTPS_API_V1' ||
      receipt?.status !== 'VERIFIED_IMMUTABLE_REMOTE_COMMIT' ||
      receipt?.repository_field !== 'CANONICAL_HTTPS_GITHUB_REPOSITORY' ||
      receipt?.canonical_bytes !== 'DETERMINISTIC_CANONICAL_JSON_PLUS_LF' ||
      receipt?.same_fact_tuple_same_bytes !== true) {
    problems.push('deterministic remote provenance receipt contract drifted');
  }
  const binding = policy.audit_ready_binding;
  if (binding?.generation_remote_verification !== 'REQUIRED_FRESH_ONLINE' ||
      binding?.independent_verification_remote_verification !== 'REQUIRED_FRESH_ONLINE' ||
      binding?.cached_claim_only !== 'FORBIDDEN' ||
      binding?.receipt_binding !== 'REQUIRED_IN_DETERMINISTIC_BUNDLE_AND_ROOT' ||
      binding?.manifest_remote_verification_consistency !== 'REQUIRED' ||
      binding?.legacy_raw_capture_v1_changed !== false) {
    problems.push('AUDIT_READY online freshness, binding, or legacy RAW_CAPTURE boundary drifted');
  }
  if (policy.ci_testing?.external_github_requests !== 0 || policy.ci_testing?.model_provider_requests !== 0 ||
      policy.ci_testing?.remote_test_transport !== 'UNEXPORTED_FAKE_TRANSPORT_OR_LOOPBACK_SYNTHETIC_ENDPOINT' ||
      policy.ci_testing?.production_endpoint_modifiable_by_caller !== false) {
    problems.push('public CI or production endpoint test boundary drifted');
  }
  equalProblem(problems, 'required R1 security probes', policy.required_r1_security_probes, EXPECTED.probes);
  equalProblem(problems, 'open R1 finding dispositions', policy.finding_disposition?.open_r1_findings, EXPECTED.openFindings);
  equalProblem(problems, 'preserved fixed findings', policy.finding_disposition?.fixed_findings_preserved, EXPECTED.fixedFindings);
  if (policy.finding_disposition?.authority_marks_open_findings_fixed !== false) {
    problems.push('Authority incorrectly marks an R1 security finding fixed');
  }
  const scope = policy.scope;
  if (scope?.governance_only !== true || scope?.runtime_implementation_change !== 'FORBIDDEN' ||
      scope?.int001_validator_change !== 'FORBIDDEN' || scope?.b005_r1_recovery_started !== false ||
      scope?.parent_batch_state !== 'IN_PROGRESS' || scope?.global_wip !== 1 ||
      scope?.next_batch !== 'AIPT-MVP-B006' || scope?.next_batch_state !== 'NOT_STARTED_NOT_AUTHORIZED' ||
      scope?.public_disclosure !== 'REAUTHORIZATION_REQUIRED' || scope?.publicly_pushed !== false) {
    problems.push('governance-only, serial WIP, disclosure, or stop boundary drifted');
  }
  return problems;
}

function statusProblems(status) {
  const problems = [];
  const standalone = status?.tracks?.['AIPT-STANDALONE'];
  const b005 = status?.repositories?.AIPT?.mvp_b005;
  if (standalone?.construction !== 'IN_PROGRESS' || standalone?.current_batch !== PARENT_BATCH ||
      standalone?.batch_history?.[PARENT_BATCH] !== 'IN_PROGRESS' || standalone?.global_wip !== 1) {
    problems.push('B005 is not the sole IN_PROGRESS batch at GLOBAL_WIP 1');
  }
  if (standalone?.next_serial_batch !== 'AIPT-MVP-B006' || standalone?.next_batch_state !== 'NOT_AUTHORIZED' ||
      standalone?.next_batch_authorized !== false || standalone?.next_batch_started !== false ||
      standalone?.batch_history?.['AIPT-MVP-B006'] !== 'NOT_STARTED') {
    problems.push('B006 was authorized, started, or projected outside the frozen stop state');
  }
  if (b005?.task_id !== PARENT_BATCH || b005?.state !== 'IN_PROGRESS' || b005?.publicly_pushed !== false ||
      b005?.public_ci_status !== 'NOT_STARTED_AWAITING_OWNER_DISCLOSURE_AUTHORIZATION') {
    problems.push('machine B005 project status no longer preserves IN_PROGRESS/private disclosure state');
  }
  return problems;
}

function decisionProblems(decisionRegistry) {
  const problems = [];
  const records = new Map((decisionRegistry?.records ?? []).map((record) => [record.decision_id, record]));
  for (const [id, expected] of Object.entries(REQUIRED_DECISIONS)) {
    const actual = records.get(id);
    if (!actual || actual.choice !== expected.choice || actual.qualifier !== expected.qualifier ||
        actual.status !== 'ACTIVE' || !isDeepStrictEqual(actual.superseded_by, [])) {
      problems.push(`${id} is absent, non-ACTIVE, superseded, or semantically changed`);
    }
  }
  return problems;
}

function documentProblems(repo, revision = null) {
  const problems = [];
  const requirements = Object.freeze({
    [HUMAN_PATH]: [
      'LOCAL_OBJECT_PRESENT != VERIFIED_IMMUTABLE_REMOTE_COMMIT',
      'operational refinement of `R9-Q004` and `R10-Q005`',
      'PRIVATE_GOVERNANCE_CANDIDATE_FROZEN',
      'PUBLIC_DISCLOSURE_REAUTHORIZATION_REQUIRED',
    ],
    'docs/authority/README.md': [POLICY_ID, 'MERGED_POST_MERGE_SECURITY_BLOCKED', 'IMPLEMENTATION_PENDING_R1'],
    'docs/authority/PROJECT_STATUS.md': [POLICY_ID, 'MERGED_POST_MERGE_SECURITY_BLOCKED', 'NOT_ACCEPTED'],
    'docs/authority/DECISION_MATRIX.md': [POLICY_ID, 'B005-PROV-Q001=A', 'local mirror'],
    'docs/evidence/README.md': [
      'MERGED_POST_MERGE_SECURITY_BLOCKED',
      '`OFFLINE_REMOTE_PROVENANCE_MODEL` | `NOT_ACCEPTED`',
      '`ONLINE_GITHUB_REMOTE_PROVENANCE_V1` | `AUTHORITY_DEFINED_IMPLEMENTATION_PENDING_R1`',
    ],
  });
  for (const [relative, tokens] of Object.entries(requirements)) {
    let contents;
    try { contents = revision ? gitText(repo, revision, relative) : read(repo, relative); if (contents === null) throw new Error('missing frozen projection'); } catch { problems.push(`${relative} is missing or unreadable`); continue; }
    for (const token of tokens) {
      if (!contents.includes(token)) problems.push(`${relative} omits required Authority projection ${token}`);
    }
  }
  return problems;
}

function currentBranch(repo) {
  return gitOut(repo, ['branch', '--show-current']) || process.env.GITHUB_HEAD_REF ||
    (process.env.GITHUB_REF?.startsWith('refs/heads/') ? process.env.GITHUB_REF.slice('refs/heads/'.length) : 'DETACHED');
}

function workingInventory(repo) {
  const committed = resultLines(gitResult(repo, ['diff', '--name-only', '--no-renames', BASE_COMMIT, 'HEAD']));
  const tracked = resultLines(gitResult(repo, ['diff', '--name-only', '--no-renames']));
  const staged = resultLines(gitResult(repo, ['diff', '--cached', '--name-only', '--no-renames']));
  const untracked = resultLines(gitResult(repo, ['ls-files', '--others', '--exclude-standard']));
  return [...new Set([...committed, ...tracked, ...staged, ...untracked]
    .filter((relative) => relative && !relative.split('/').includes('node_modules')))].sort();
}

function committedCandidate(repo) {
  const additions = resultLines(gitResult(repo, [
    'log', '--reverse', '--format=%H', '--diff-filter=A', `${BASE_COMMIT}..HEAD`, '--', POLICY_PATH,
  ]));
  if (additions.length !== 1) return null;
  const facts = commitFacts(repo, additions[0]);
  if (!facts || !isDeepStrictEqual(facts.parents, [BASE_COMMIT])) return null;
  return facts;
}

function changedPaths(repo, from, to) {
  return resultLines(gitResult(repo, ['diff', '--name-only', '--no-renames', from, to])).sort();
}

const CI_CATALOGUE_PATH = `docs/authority/registry/verified-ci-evidence/${TASK_ID.toLowerCase()}/post-merge-ci.json`;
const CI_REPOSITORY = 'zyc14588/AIPT';
const CI_WORKFLOW_PATH = '.github/workflows/ci.yml';
const CI_JOB_NAMES = Object.freeze([
  'b000-retro (fixed B000 commit, read-only expansion)',
  'toolchain (ubuntu-24.04)', 'toolchain (ubuntu-26.04)',
  'supply-chain (R4-Q023 gates)', 'storage-postgres (ephemeral PostgreSQL 18.4 integration)',
].sort());
const CI_ACCEPTANCE = Object.freeze({
  decision_id: 'B005-GOV-CI-Q001=A',
  mode: 'LOCAL_ONLINE_GITHUB_ACTIONS_VERIFICATION',
  offline_trust_basis: 'OWNER_ACCEPTED_IMMUTABLE_MAIN_CI_CATALOGUE',
});

function exactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    isDeepStrictEqual(Object.keys(value).sort(), [...keys].sort());
}
function positiveID(value) { return Number.isSafeInteger(value) && value > 0; }

// This is an Owner-accepted attestation collected independently of lifecycle
// records. Offline replay trusts its immutable introduction on accepted main;
// it does not claim a cryptographic proof of the GitHub API response.
function ciCatalogueProblems(catalogue, merge, workflowSha256) {
  const problems = [];
  if (!exactKeys(catalogue, ['schema', 'version', 'task_id', 'repository', 'workflow_path', 'workflow_sha256', 'acceptance', 'run', 'jobs']) ||
      catalogue.schema !== 'aipt.public.verified-ci-evidence/v1' || catalogue.version !== '1.0.0' ||
      catalogue.task_id !== TASK_ID || catalogue.repository !== CI_REPOSITORY ||
      catalogue.workflow_path !== CI_WORKFLOW_PATH || catalogue.workflow_sha256 !== workflowSha256) {
    problems.push('independent CI catalogue identity/workflow is invalid');
  }
  const acceptance = catalogue?.acceptance;
  if (!exactKeys(acceptance, [...Object.keys(CI_ACCEPTANCE), 'verified_at']) ||
      Object.entries(CI_ACCEPTANCE).some(([key, value]) => acceptance?.[key] !== value) ||
      typeof acceptance?.verified_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(acceptance.verified_at) ||
      !Number.isFinite(Date.parse(acceptance.verified_at))) {
    problems.push('independent CI catalogue lacks the authorized local online acceptance basis');
  }
  const run = catalogue?.run;
  if (!exactKeys(run, ['id', 'head_sha', 'head_branch', 'event', 'status', 'conclusion', 'run_attempt']) ||
      !positiveID(run?.id) || !positiveID(run?.run_attempt) || run?.head_sha !== merge?.commit ||
      run?.head_branch !== 'main' || run?.event !== 'push' || run?.status !== 'completed' || run?.conclusion !== 'success') {
    problems.push('independent CI catalogue is not a successful exact main merge run');
  }
  const jobs = catalogue?.jobs;
  if (!Array.isArray(jobs) || jobs.length !== 5 ||
      !isDeepStrictEqual(jobs.map((job) => job?.name).sort(), CI_JOB_NAMES) ||
      new Set(jobs.map((job) => job?.id)).size !== 5 || jobs.some((job) =>
        !exactKeys(job, ['id', 'name', 'head_sha', 'status', 'conclusion']) || !positiveID(job.id) ||
        job.head_sha !== merge?.commit || job.status !== 'completed' || job.conclusion !== 'success')) {
    problems.push('independent CI catalogue does not prove all five exact successful jobs');
  }
  return problems;
}

function ciPostFacts(catalogue) {
  return { run_id: catalogue.run.id, head_sha: catalogue.run.head_sha, conclusion: catalogue.run.conclusion,
    jobs_passed: catalogue.jobs.length, jobs_failed: 0, jobs_skipped: 0 };
}

// Explicit local acceptance mode only. The normal public CI gate never calls
// this collector. Endpoint, TLS roots, body size and deadlines are fixed.
async function collectPostMergeCI(repo, args) {
  if (process.env.GITHUB_ACTIONS === 'true') throw new Error('local CI evidence collection is forbidden in public CI');
  if (Object.keys(args).some((key) => !['repo', 'collect-post-merge-ci', 'run-id'].includes(key)) ||
      args['collect-post-merge-ci'] !== true || !/^[1-9][0-9]{0,15}$/u.test(String(args['run-id'] ?? ''))) {
    throw new Error('local CI collection arguments are invalid');
  }
  const scope = candidateScope(repo);
  const merge = scope.candidate ? exactGovernanceMerge(repo, scope.candidate, gitOut(repo, ['rev-parse', 'HEAD'])) : null;
  if (!merge || scope.problems.length > 0) throw new Error('local CI collection requires the exact clean governance merge');
  const runID = Number(args['run-id']);
  if (!positiveID(runID)) throw new Error('local CI run identity is invalid');
  const get = (relative) => new Promise((resolve, reject) => {
    const request = https.request({
      protocol: 'https:', hostname: 'api.github.com', port: 443, method: 'GET', path: relative,
      ca: rootCertificates, agent: false, signal: AbortSignal.timeout(15000),
      headers: { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'AIPT-Governance-CI-Acceptance' },
    }, (response) => {
      if (response.statusCode !== 200) { response.destroy(); reject(new Error('authoritative CI API did not return exact success')); return; }
      const chunks = []; let bytes = 0;
      response.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > 512 * 1024) { response.destroy(); reject(new Error('authoritative CI response exceeded bound')); return; }
        chunks.push(chunk);
      });
      response.on('error', () => reject(new Error('authoritative CI response unavailable')));
      response.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { reject(new Error('authoritative CI response is malformed')); }
      });
    });
    request.setTimeout(5000, () => request.destroy());
    request.on('error', () => reject(new Error('authoritative CI request unavailable')));
    request.end();
  });
  const runPath = `/repos/${CI_REPOSITORY}/actions/runs/${runID}`;
  const before = await get(runPath);
  if (before.repository?.full_name !== CI_REPOSITORY || before.head_repository?.full_name !== CI_REPOSITORY ||
      before.path !== CI_WORKFLOW_PATH || !positiveID(before.run_attempt)) throw new Error('authoritative CI repository/workflow mismatch');
  const jobResponse = await get(`${runPath}/attempts/${before.run_attempt}/jobs?per_page=100`);
  const after = await get(runPath);
  const runKeys = ['id', 'head_sha', 'head_branch', 'event', 'status', 'conclusion', 'run_attempt'];
  const select = (value, keys) => Object.fromEntries(keys.map((key) => [key, value[key]]));
  const run = select(before, runKeys);
  if (!isDeepStrictEqual(run, select(after, runKeys)) || after.repository?.full_name !== CI_REPOSITORY ||
      after.head_repository?.full_name !== CI_REPOSITORY || after.path !== CI_WORKFLOW_PATH ||
      jobResponse.total_count !== 5 || !Array.isArray(jobResponse.jobs) || jobResponse.jobs.length !== 5) {
    throw new Error('authoritative CI identity changed or job inventory is incomplete');
  }
  const catalogue = {
    schema: 'aipt.public.verified-ci-evidence/v1', version: '1.0.0', task_id: TASK_ID, repository: CI_REPOSITORY,
    workflow_path: CI_WORKFLOW_PATH, workflow_sha256: digest(gitText(repo, merge.commit, CI_WORKFLOW_PATH)),
    acceptance: { ...CI_ACCEPTANCE, verified_at: new Date().toISOString() }, run,
    jobs: jobResponse.jobs.map((job) => select(job, ['id', 'name', 'head_sha', 'status', 'conclusion']))
      .sort((left, right) => left.name.localeCompare(right.name)),
  };
  if (ciCatalogueProblems(catalogue, merge, catalogue.workflow_sha256).length > 0) throw new Error('authoritative CI facts did not pass exact acceptance');
  const destination = path.join(repo, CI_CATALOGUE_PATH);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, `${JSON.stringify(catalogue, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return { result: 'PASS', mode: CI_ACCEPTANCE.mode, task_id: TASK_ID,
    catalogue_path: CI_CATALOGUE_PATH, catalogue_sha256: digest(read(repo, CI_CATALOGUE_PATH)),
    head_sha: merge.commit, run_id: runID, jobs_passed: 5, external_github_requests: 3, model_provider_requests: 0 };
}

const LIFECYCLE_ROOT = `docs/authority/registry/authority-lifecycle/records/${TASK_ID.toLowerCase()}`;
const LIFECYCLE_PATHS = Object.freeze([
  `${LIFECYCLE_ROOT}/001-merged.json`,
  `${LIFECYCLE_ROOT}/002-post-merge-verified.json`,
  `${LIFECYCLE_ROOT}/003-closed.json`,
]);
const CLOSEOUT_PATHS = new Set([...LIFECYCLE_PATHS, CI_CATALOGUE_PATH, STATUS_PATH, 'docs/authority/PROJECT_STATUS.md']);
const FROZEN_PATHS = Object.freeze([POLICY_PATH, SCHEMA_PATH, HUMAN_PATH, 'scripts/ci/validate/b005-remote-provenance-authority.mjs']);
const LIFECYCLE_POLICY = Object.freeze({
  model_id: AUTHORITY_LIFECYCLE_MODEL,
  events: AUTHORITY_LIFECYCLE_EVENTS,
  ordering: AUTHORITY_LIFECYCLE_ORDERING,
  canonical_truth_source: 'ACCEPTED_APPEND_ONLY_LIFECYCLE_RECORD_CHAIN',
  semantic_fields_are_snapshot_metadata: true,
  semantic_artifact_mutation_permitted: false,
  unlisted_transition: 'REJECT',
  closed_terminal: true,
});

function digest(value) { return createHash('sha256').update(value).digest('hex'); }
function gitText(repo, revision, relative) {
  const result = gitResult(repo, ['show', `${revision}:${relative}`]);
  return result.status === 0 ? result.stdout : null;
}
function firstParentContains(repo, descendant, ancestor) {
  return resultLines(gitResult(repo, ['rev-list', '--first-parent', descendant])).includes(ancestor);
}
function exactGovernanceMerge(repo, candidate, revision) {
  const facts = commitFacts(repo, revision);
  return facts && facts.tree === candidate.tree && isDeepStrictEqual(facts.parents, [BASE_COMMIT, candidate.commit]) ? facts : null;
}
function findGovernanceMerge(repo, candidate, revision) {
  const matches = resultLines(gitResult(repo, ['rev-list', '--first-parent', `${BASE_COMMIT}..${revision}`]))
    .map((commit) => exactGovernanceMerge(repo, candidate, commit)).filter(Boolean);
  return matches.length === 1 ? matches[0] : null;
}

// A later batch may replay this frozen gate only after a canonical closeout
// was introduced on accepted main, not merely because record files exist in
// its working tree. The current record bytes must still match that commit.
function acceptedGovernanceCloseout(repo, candidate, head, { proposal = false } = {}) {
  const problems = [];
  // Proposal mode checks identical contents/topology without granting accepted authority.
  const acceptedMain = proposal ? head : gitOut(repo, ['rev-parse', 'refs/remotes/origin/main^{commit}']);
  if (!acceptedMain || !firstParentContains(repo, acceptedMain, BASE_COMMIT)) return { accepted: false, problems };
  const introductions = LIFECYCLE_PATHS.map((relative) => resultLines(gitResult(repo, [
    'log', '--first-parent', '--reverse', '--format=%H', '--diff-filter=A', acceptedMain, '--', relative,
  ])));
  if (introductions.every((rows) => rows.length === 0)) return { accepted: false, problems };
  if (introductions.some((rows) => rows.length !== 1) || new Set(introductions.map((rows) => rows[0])).size !== 1) {
    return { accepted: false, problems: ['accepted governance lifecycle is incomplete, forked, or not introduced by one closeout'] };
  }
  const closeoutCommit = introductions[0][0];
  if (!firstParentContains(repo, head, closeoutCommit)) return { accepted: false, problems };
  const closeout = commitFacts(repo, closeoutCommit);
  const merge = findGovernanceMerge(repo, candidate, closeoutCommit);
  const closeoutPaths = merge ? changedPaths(repo, merge.commit, closeoutCommit) : [];
  if (!merge || !isDeepStrictEqual(closeout?.parents, [merge.commit]) ||
      closeoutPaths.some((relative) => !CLOSEOUT_PATHS.has(relative)) ||
      (LIFECYCLE_PATHS.some((relative) => !closeoutPaths.includes(relative)) || !closeoutPaths.includes(CI_CATALOGUE_PATH))) {
    problems.push('accepted closeout is not an exact governance-only direct child of the legal merge');
  }
  try {
    const frozenStatus = JSON.parse(gitText(repo, candidate.commit, STATUS_PATH));
    const closeoutStatus = JSON.parse(gitText(repo, closeoutCommit, STATUS_PATH));
    if (!isDeepStrictEqual(closeoutStatus, frozenStatus) || statusProblems(closeoutStatus).length > 0) {
      problems.push('accepted governance closeout status differs from the frozen B005 construction snapshot');
    }
  } catch {
    problems.push('accepted governance closeout status snapshot is unreadable');
  }
  const inventory = resultLines(gitResult(repo, ['ls-tree', '-r', '--name-only', acceptedMain, '--', LIFECYCLE_ROOT]));
  if (!isDeepStrictEqual(inventory.sort(), [...LIFECYCLE_PATHS].sort())) problems.push('accepted lifecycle has missing or unexpected record paths');
  let records;
  try {
    records = LIFECYCLE_PATHS.map((relative) => {
      const introduced = gitText(repo, closeoutCommit, relative);
      if (introduced === null || gitText(repo, acceptedMain, relative) !== introduced || read(repo, relative) !== introduced) {
        problems.push(`accepted lifecycle record changed: ${relative}`);
      }
      return JSON.parse(introduced);
    });
    const recordSchema = readJSON(repo, 'schemas/authority-lifecycle/v1/aipt-authority-lifecycle-record.schema.json');
    for (const record of records) for (const error of validateInstance(recordSchema, record).errors) problems.push(error.message);
  } catch {
    return { accepted: false, problems: [...problems, 'accepted lifecycle records are unreadable'] };
  }
  let catalogue;
  try {
    const introduced = gitText(repo, closeoutCommit, CI_CATALOGUE_PATH);
    const catalogueIntroductions = resultLines(gitResult(repo, [
      'log', '--first-parent', '--format=%H', '--diff-filter=A', acceptedMain, '--', CI_CATALOGUE_PATH,
    ]));
    if (!isDeepStrictEqual(catalogueIntroductions, [closeoutCommit]) || introduced === null ||
        gitText(repo, acceptedMain, CI_CATALOGUE_PATH) !== introduced || read(repo, CI_CATALOGUE_PATH) !== introduced) {
      problems.push('independent CI catalogue lacks immutable accepted-main provenance');
    }
    catalogue = JSON.parse(introduced);
    problems.push(...ciCatalogueProblems(catalogue, merge, digest(gitText(repo, merge?.commit ?? candidate.commit, CI_WORKFLOW_PATH) ?? '')));
  } catch {
    problems.push('independent CI catalogue is missing or unreadable');
  }
  const independentlyVerifiedPost = catalogue && problems.length === 0 ? ciPostFacts(catalogue) : null;
  const identity = {
    task_id: TASK_ID, artifact_id: TASK_ID, artifact_path: POLICY_PATH,
    artifact_sha256: digest(gitText(repo, candidate.commit, POLICY_PATH) ?? ''),
    candidate_commit: candidate.commit, candidate_tree: candidate.tree,
    semantic_snapshot_state: 'PRIVATE_GOVERNANCE_CANDIDATE_FROZEN', semantic_snapshot_accepted: false,
  };
  const ids = ['MERGED', 'POST-MERGE-VERIFIED', 'CLOSED'].map((event, index) =>
    `${TASK_ID}-LIFECYCLE-00${index + 1}-${event}`);
  const acceptance = Object.fromEntries(records.map((record, index) => [record.record_id, {
    accepted: true, commit: closeoutCommit, commit_ordinal: 1, first_parent_ancestry: true,
    path: LIFECYCLE_PATHS[index], introduced_sha256: digest(gitText(repo, closeoutCommit, LIFECYCLE_PATHS[index]) ?? ''),
    current_sha256: digest(read(repo, LIFECYCLE_PATHS[index])), canonical_record_sha256: lifecycleRecordSha256(record),
  }]));
  const resolution = resolveEffectiveAuthority({
    semantic_artifact_identity: identity, records, policy: LIFECYCLE_POLICY,
    record_acceptance: acceptance, authority_basis_acceptance: Object.fromEntries(ids.map((id) => [id, true])),
    evidence_catalogue: {
      merge_commits: merge ? { [merge.commit]: { tree: merge.tree, parents: merge.parents, accepted_ancestry: true } } : {},
      post_merge_runs: independentlyVerifiedPost ? { [String(independentlyVerifiedPost.run_id)]: independentlyVerifiedPost } : {},
      closeout_records: { [ids[2]]: { commit: closeoutCommit, governance_only: true, owner_authorized: true } },
    },
    expected_accepted_record_ids: ids, expected_lifecycle_state: 'CLOSED',
  });
  problems.push(...resolution.problems);
  if (gitResult(repo, ['merge-base', '--is-ancestor', 'd12218f69a31884382e78c7c168b4677b5de8d87', closeoutCommit]).status !== 0) {
    problems.push('canonical accepted lifecycle model is not on closeout ancestry');
  }
  const valid = problems.length === 0 && resolution.result === 'ACCEPT' && resolution.effective;
  return { accepted: !proposal && valid, proposal_valid: proposal && valid,
    problems, closeoutCommit, closeoutPaths, merge, resolution };
}

function candidateScope(repo) {
  const base = commitFacts(repo, BASE_COMMIT);
  const candidate = committedCandidate(repo);
  const branch = currentBranch(repo);
  const head = gitOut(repo, ['rev-parse', 'HEAD^{commit}']);
  const dirtyPaths = [...new Set([
    ...resultLines(gitResult(repo, ['diff', '--name-only', '--no-renames'])),
    ...resultLines(gitResult(repo, ['diff', '--cached', '--name-only', '--no-renames'])),
  ])].sort();
  let inventory = candidate ? changedPaths(repo, BASE_COMMIT, candidate.commit) : workingInventory(repo);
  const candidateInventory = [...inventory];
  const postCandidatePaths = candidate ? changedPaths(repo, candidate.commit, head) : [];
  const problems = [];
  let phase = 'REJECTED';
  let lifecycle = { accepted: false, problems: [] };
  if (candidate && head === candidate.commit) phase = 'CANDIDATE';
  else if (candidate && exactGovernanceMerge(repo, candidate, head)) phase = 'LEGAL_MERGE';
  else if (candidate) {
    lifecycle = acceptedGovernanceCloseout(repo, candidate, head);
    if (lifecycle.accepted) {
      phase = 'CLOSED_AUTHORITY_REPLAY';
      inventory = [...new Set([...inventory, ...lifecycle.closeoutPaths])].sort();
    } else {
      inventory = [...new Set([...inventory, ...postCandidatePaths, ...dirtyPaths])].sort();
      const merge = findGovernanceMerge(repo, candidate, head);
      const descendants = merge ? resultLines(gitResult(repo, ['rev-list', '--first-parent', `${merge.commit}..${head}`])) : [];
      const linearCloseout = descendants.length === 1 && isDeepStrictEqual(commitFacts(repo, head)?.parents, [merge.commit]);
      if (merge && linearCloseout && postCandidatePaths.every((relative) => CLOSEOUT_PATHS.has(relative)) &&
          LIFECYCLE_PATHS.every((relative) => postCandidatePaths.includes(relative)) && postCandidatePaths.includes(CI_CATALOGUE_PATH)) {
        phase = 'GOVERNANCE_CLOSEOUT_PROPOSAL';
        problems.push(...acceptedGovernanceCloseout(repo, candidate, head, { proposal: true }).problems);
      } else problems.push('post-candidate changes or topology are outside the authorized merge/closeout scope');
    }
  } else if ((branch === BRANCH || /^task\/AIPT-MVP-B005-REMOTE-PROVENANCE-AUTHORITY-001-R[1-9][0-9]*$/u.test(branch)) && head === BASE_COMMIT) {
    phase = 'CONSTRUCTION';
  }
  if (dirtyPaths.length > 0 && phase !== 'CONSTRUCTION') {
    inventory = [...new Set([...inventory, ...dirtyPaths])].sort();
    problems.push('tracked working state differs from the immutable validation target');
  }
  if (base?.commit !== BASE_COMMIT || base?.tree !== BASE_TREE) problems.push('frozen B005 merge base commit/tree is unavailable or drifted');
  if (phase === 'REJECTED') problems.push('Authority candidate is not an authorized exact candidate, merge, or lifecycle successor');
  if (!isDeepStrictEqual(candidateInventory, EXPECTED_CHANGED_PATHS)) problems.push('governance Candidate changed-path inventory differs from the exact authorized set');
  problems.push(...lifecycle.problems);
  const implementationFiles = inventory.filter((relative) =>
    relative.startsWith('internal/') || relative.startsWith('cmd/') || relative.startsWith('packages/') ||
    relative.startsWith('storage/') || relative.startsWith('UNREGISTERED/') ||
    relative.includes('/migrations/') || relative === 'scripts/ci/validate/int001-closeout-authority.mjs');
  if (implementationFiles.length !== 0) problems.push('governance validation scope includes a protected implementation path');
  if (candidate) for (const relative of FROZEN_PATHS) {
    let current; try { current = read(repo, relative); } catch { current = null; }
    if (gitText(repo, candidate.commit, relative) !== current) problems.push(`frozen Authority artifact changed after Candidate: ${relative}`);
  }
  return { problems, phase, branch, candidate, inventory, implementationFiles, lifecycle, postCandidatePaths };
}

function corePolicyProblems(policy, schema, status) {
  const schemaResult = validateInstance(schema, policy);
  return [
    ...schemaResult.errors.map((error) => `policy schema: ${error.message}`),
    ...policySemanticProblems(policy),
    ...statusProblems(status),
  ];
}

function negativeGovernanceProbes(policy, schema, status) {
  const probes = [];
  const run = (id, label, mutate) => {
    const copy = { policy: structuredClone(policy), status: structuredClone(status) };
    let actual = 'REJECT';
    let threw = false;
    try {
      mutate(copy);
      if (corePolicyProblems(copy.policy, schema, copy.status).length === 0) actual = 'ACCEPT';
    } catch {
      threw = true;
      actual = 'ERROR';
    }
    probes.push({ id, label, expected: 'REJECT', actual, threw, matched: !threw && actual === 'REJECT' });
  };
  run('A01', 'local mirror can mint remote claim', ({ policy: copy }) => {
    copy.local_mirror_role.maximum_claim = 'VERIFIED_IMMUTABLE_REMOTE_COMMIT';
  });
  run('A02', 'caller verifier can mint reserved claim', ({ policy: copy }) => {
    copy.reserved_claim.production_caller_injected_verifier = 'ALLOWED';
  });
  run('A03', 'offline-only remote verification', ({ policy: copy }) => {
    copy.verification_mode = 'OFFLINE_ONLY';
  });
  run('A04', 'non-GitHub provider silently accepted', ({ policy: copy }) => {
    copy.supported_provider = 'GENERIC_HTTPS_PROVIDER';
  });
  run('A05', 'private repository silently accepted', ({ policy: copy }) => {
    copy.private_repo_support = 'SUPPORTED';
  });
  run('A06', 'redirect allowed', ({ policy: copy }) => {
    copy.redirect_policy = 'FOLLOW';
  });
  run('A07', 'credential required', ({ policy: copy }) => {
    copy.authentication_mode = 'GITHUB_CREDENTIAL_REQUIRED';
  });
  run('A08', 'network failure falls back to mirror', ({ policy: copy }) => {
    copy.failure_policy.mirror_fallback = 'ALLOWED';
  });
  run('A09', 'receipt contains verification timestamp', ({ policy: copy }) => {
    copy.receipt_contract.required_fields.push('verification_timestamp');
  });
  run('A10', 'B005 marked closed', ({ status: copy }) => {
    copy.tracks['AIPT-STANDALONE'].batch_history['AIPT-MVP-B005'] = 'MERGED_CLOSED';
    copy.repositories.AIPT.mvp_b005.state = 'MERGED_CLOSED';
  });
  run('A11', 'B006 started', ({ status: copy }) => {
    copy.tracks['AIPT-STANDALONE'].batch_history['AIPT-MVP-B006'] = 'IN_PROGRESS';
    copy.tracks['AIPT-STANDALONE'].next_batch_started = true;
  });
  return probes;
}

function statusForScope(repo, scope) {
  return scope.phase === 'CLOSED_AUTHORITY_REPLAY'
    ? JSON.parse(gitText(repo, scope.candidate.commit, STATUS_PATH))
    : readJSON(repo, STATUS_PATH);
}

// Actual Git descendants exercise the same scope and snapshot selection used
// by the gate. All fixtures are disposable local clones; no remote is read.
function governanceSuccessorProbes(repo, candidate) {
  if (!candidate) return [];
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-governance-successor-probes-'));
  const fixture = path.join(root, 'repo');
  const probes = [];
  const environment = { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_NO_LAZY_FETCH: '1' };
  for (const key of Object.keys(environment)) if (key.startsWith('GITHUB_')) delete environment[key];
  const execute = (args, cwd = fixture) => {
    const result = spawnSync('git', ['-c', 'commit.gpgsign=false', ...args], { cwd, env: environment, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
    if (result.error || result.status !== 0) throw new Error('synthetic Git scope fixture operation failed');
    return result.stdout.trim();
  };
  const addCommit = (relative, contents) => {
    fs.mkdirSync(path.dirname(path.join(fixture, relative)), { recursive: true });
    fs.writeFileSync(path.join(fixture, relative), contents);
    execute(['add', '--', relative]);
    execute(['commit', '-q', '-m', 'synthetic successor scope probe']);
    return execute(['rev-parse', 'HEAD']);
  };
  const check = (id, label, expected, condition) => probes.push({ id, label, expected, actual: condition ? expected : 'MISMATCH', matched: condition });
  try {
    execute(['clone', '--no-local', '--quiet', repo, fixture], root);
    execute(['config', 'user.name', 'Governance Scope Probe']);
    execute(['config', 'user.email', 'governance-probe@example.invalid']);
    execute(['checkout', '--detach', candidate.commit]);
    execute(['update-ref', 'refs/remotes/origin/main', BASE_COMMIT]);
    let scope = candidateScope(fixture);
    check('S01', 'exact immutable Candidate', 'ACCEPT', scope.phase === 'CANDIDATE' && scope.problems.length === 0);
    const implementation = 'internal/governance_successor_probe.go';
    addCommit(implementation, 'package synthetic\n');
    scope = candidateScope(fixture);
    check('S02', 'unmerged protected implementation descendant', 'REJECT',
      scope.problems.length > 0 && scope.inventory.includes(implementation) && scope.implementationFiles.includes(implementation));
    execute(['reset', '--hard', candidate.commit]);
    const publication = 'governance-successor-publication-probe.txt';
    addCommit(publication, 'synthetic unexpected publication member\n');
    scope = candidateScope(fixture);
    check('S03', 'unmerged additional publication member', 'REJECT', scope.problems.length > 0 && scope.inventory.includes(publication));
    execute(['checkout', '--detach', BASE_COMMIT]);
    execute(['merge', '--no-ff', '--no-edit', '-m', 'synthetic legal governance merge', candidate.commit]);
    const merge = commitFacts(fixture, 'HEAD');
    scope = candidateScope(fixture);
    check('S04', 'exact two-parent governance merge', 'ACCEPT', scope.phase === 'LEGAL_MERGE' && scope.problems.length === 0);

    const fixtureCatalogue = {
      schema: 'aipt.public.verified-ci-evidence/v1', version: '1.0.0', task_id: TASK_ID, repository: CI_REPOSITORY,
      workflow_path: CI_WORKFLOW_PATH, workflow_sha256: digest(gitText(fixture, merge.commit, CI_WORKFLOW_PATH)),
      acceptance: { ...CI_ACCEPTANCE, verified_at: '2026-10-06T00:00:00.000Z' },
      run: { id: 1, head_sha: merge.commit, head_branch: 'main', event: 'push', status: 'completed', conclusion: 'success', run_attempt: 1 },
      jobs: CI_JOB_NAMES.map((name, index) => ({ id: index + 1, name, head_sha: merge.commit, status: 'completed', conclusion: 'success' })),
    };
    const writeFixtureCatalogue = (catalogue = fixtureCatalogue) => {
      fs.mkdirSync(path.dirname(path.join(fixture, CI_CATALOGUE_PATH)), { recursive: true });
      fs.writeFileSync(path.join(fixture, CI_CATALOGUE_PATH), `${JSON.stringify(catalogue, null, 2)}\n`);
    };
    const templateRoot = 'docs/authority/registry/authority-lifecycle/records/int-aipt-unregistered-mvp-001-closeout-authority-001';
    const templateNames = ['001-merged.json', '002-post-merge-verified.json', '003-closed.json'];
    const records = templateNames.map((name, index) => {
      const record = readJSON(repo, `${templateRoot}/${name}`);
      record.task_id = TASK_ID;
      record.record_id = `${TASK_ID}-LIFECYCLE-00${index + 1}-${['MERGED', 'POST-MERGE-VERIFIED', 'CLOSED'][index]}`;
      record.semantic_artifact_identity = {
        task_id: TASK_ID, artifact_id: TASK_ID, artifact_path: POLICY_PATH,
        artifact_sha256: digest(gitText(fixture, candidate.commit, POLICY_PATH)),
        candidate_commit: candidate.commit, candidate_tree: candidate.tree,
        semantic_snapshot_state: 'PRIVATE_GOVERNANCE_CANDIDATE_FROZEN', semantic_snapshot_accepted: false,
      };
      record.authority_basis.authorized_by_task = TASK_ID;
      record.record_identity.path = LIFECYCLE_PATHS[index];
      record.created_by_task = TASK_ID;
      record.provenance = {
        source_task: TASK_ID, source_commit: index === 0 ? candidate.commit : merge.commit,
        source_tree: candidate.tree, record_creation_authority: TASK_ID, record_creator_task: TASK_ID,
        historical_evidence_claimed_only_if_proven: true,
      };
      if (index === 0) record.event_evidence.merge_identity = { commit: merge.commit, tree: merge.tree, parents: merge.parents };
      if (index === 1) record.event_evidence.post_merge_evidence = {
        run_id: 1, head_sha: merge.commit, conclusion: 'success', jobs_passed: 5, jobs_failed: 0, jobs_skipped: 0,
      };
      return record;
    });
    records.forEach((record, index) => {
      record.predecessor_lifecycle_record = index === 0 ? null : {
        record_id: records[index - 1].record_id, record_sha256: lifecycleRecordSha256(records[index - 1]),
      };
      fs.mkdirSync(path.dirname(path.join(fixture, LIFECYCLE_PATHS[index])), { recursive: true });
      fs.writeFileSync(path.join(fixture, LIFECYCLE_PATHS[index]), `${JSON.stringify(record, null, 2)}\n`);
    });
    writeFixtureCatalogue();
    execute(['add', '--', ...LIFECYCLE_PATHS, CI_CATALOGUE_PATH]);
    execute(['commit', '-q', '-m', 'synthetic governance closeout records and independently supplied CI catalogue']);
    const closeout = execute(['rev-parse', 'HEAD']);
    let status = readJSON(fixture, STATUS_PATH);
    status.tracks['AIPT-STANDALONE'].batch_history[PARENT_BATCH] = 'MERGED_CLOSED';
    status.tracks['AIPT-STANDALONE'].construction = 'NO_ACTIVE_BATCH';
    status.tracks['AIPT-STANDALONE'].current_batch = null;
    status.tracks['AIPT-STANDALONE'].global_wip = 0;
    addCommit(STATUS_PATH, `${JSON.stringify(status, null, 2)}\n`);
    scope = candidateScope(fixture);
    check('S05', 'unaccepted record files cannot authorize a later phase', 'REJECT',
      !scope.lifecycle.accepted && (scope.problems.length > 0 || statusProblems(statusForScope(fixture, scope)).length > 0));

    // Only the fixture's explicitly accepted main may activate this chain.
    execute(['update-ref', 'refs/remotes/origin/main', closeout]);
    scope = candidateScope(fixture);
    check('S06', 'accepted CLOSED governance replays a frozen status after B005 closes', 'ACCEPT',
      scope.phase === 'CLOSED_AUTHORITY_REPLAY' && scope.problems.length === 0 &&
      statusProblems(statusForScope(fixture, scope)).length === 0 && statusProblems(status).length > 0);
    status.tracks['AIPT-STANDALONE'].construction = 'IN_PROGRESS';
    status.tracks['AIPT-STANDALONE'].current_batch = 'AIPT-MVP-B006';
    status.tracks['AIPT-STANDALONE'].global_wip = 1;
    addCommit(STATUS_PATH, `${JSON.stringify(status, null, 2)}\n`);
    scope = candidateScope(fixture);
    check('S07', 'accepted CLOSED governance permits a later batch status', 'ACCEPT',
      scope.phase === 'CLOSED_AUTHORITY_REPLAY' && scope.problems.length === 0 && statusProblems(statusForScope(fixture, scope)).length === 0);
    const mutated = JSON.parse(read(fixture, LIFECYCLE_PATHS[2]));
    mutated.event_evidence.closeout_identity.owner_authorized = false;
    addCommit(LIFECYCLE_PATHS[2], `${JSON.stringify(mutated, null, 2)}\n`);
    scope = candidateScope(fixture);
    check('S08', 'accepted lifecycle mutation cannot enable historical replay', 'REJECT',
      !scope.lifecycle.accepted && scope.problems.length > 0);

    execute(['checkout', '--detach', merge.commit]);
    records.forEach((record, index) => {
      fs.mkdirSync(path.dirname(path.join(fixture, LIFECYCLE_PATHS[index])), { recursive: true });
      fs.writeFileSync(path.join(fixture, LIFECYCLE_PATHS[index]), `${JSON.stringify(record, null, 2)}\n`);
    });
    const unauthorizedCloseoutStatus = readJSON(fixture, STATUS_PATH);
    unauthorizedCloseoutStatus.tracks['AIPT-STANDALONE'].batch_history[PARENT_BATCH] = 'MERGED_CLOSED';
    unauthorizedCloseoutStatus.tracks['AIPT-STANDALONE'].current_batch = 'AIPT-MVP-B006';
    fs.writeFileSync(path.join(fixture, STATUS_PATH), `${JSON.stringify(unauthorizedCloseoutStatus, null, 2)}\n`);
    writeFixtureCatalogue();
    execute(['add', '--', ...LIFECYCLE_PATHS, CI_CATALOGUE_PATH, STATUS_PATH]);
    execute(['commit', '-q', '-m', 'synthetic unauthorized status in governance closeout']);
    execute(['update-ref', 'refs/remotes/origin/main', execute(['rev-parse', 'HEAD'])]);
    scope = candidateScope(fixture);
    check('S09', 'accepted governance closeout cannot close B005 or start B006', 'REJECT',
      !scope.lifecycle.accepted && scope.problems.some((problem) => problem.includes('closeout status differs')));

    const alternateCloseout = (recordSet, catalogue, label) => {
      execute(['checkout', '--detach', merge.commit]);
      recordSet.forEach((record, index) => {
        fs.mkdirSync(path.dirname(path.join(fixture, LIFECYCLE_PATHS[index])), { recursive: true });
        fs.writeFileSync(path.join(fixture, LIFECYCLE_PATHS[index]), `${JSON.stringify(record, null, 2)}\n`);
      });
      if (catalogue) writeFixtureCatalogue(catalogue);
      execute(['add', '--', ...LIFECYCLE_PATHS, ...(catalogue ? [CI_CATALOGUE_PATH] : [])]);
      execute(['commit', '-q', '-m', label]);
      execute(['update-ref', 'refs/remotes/origin/main', execute(['rev-parse', 'HEAD'])]);
      return candidateScope(fixture);
    };
    scope = alternateCloseout(records, null, 'synthetic lifecycle self-assertion without CI catalogue');
    check('S10', 'successful lifecycle claim alone cannot prove CI', 'REJECT',
      !scope.lifecycle.accepted && scope.problems.some((problem) => problem.includes('CI catalogue')));
    const selfAsserted = structuredClone(records);
    selfAsserted[1].event_evidence.post_merge_evidence.run_id = 2;
    selfAsserted[2].predecessor_lifecycle_record.record_sha256 = lifecycleRecordSha256(selfAsserted[1]);
    scope = alternateCloseout(selfAsserted, fixtureCatalogue, 'synthetic lifecycle CI claim disagrees with independent catalogue');
    check('S11', 'lifecycle CI facts must match the independent catalogue', 'REJECT',
      !scope.lifecycle.accepted && scope.problems.some((problem) => problem.includes('accepted evidence catalogue')));
    const failedJobs = structuredClone(fixtureCatalogue);
    failedJobs.jobs[0].conclusion = 'failure';
    scope = alternateCloseout(records, failedJobs, 'synthetic unsuccessful independent CI job');
    check('S12', 'every independently catalogued CI job must pass', 'REJECT',
      !scope.lifecycle.accepted && scope.problems.some((problem) => problem.includes('five exact successful jobs')));
    execute(['checkout', '--detach', closeout]);
    execute(['update-ref', 'refs/remotes/origin/main', closeout]);
    const rewrittenCatalogue = structuredClone(fixtureCatalogue);
    rewrittenCatalogue.acceptance.verified_at = '2026-10-06T01:00:00.000Z';
    addCommit(CI_CATALOGUE_PATH, `${JSON.stringify(rewrittenCatalogue, null, 2)}\n`);
    scope = candidateScope(fixture);
    check('S13', 'accepted independent CI catalogue is immutable', 'REJECT',
      !scope.lifecycle.accepted && scope.problems.some((problem) => problem.includes('immutable accepted-main provenance')));
    const collector = spawnSync(process.execPath, [path.join(fixture, 'scripts/ci/validate/b005-remote-provenance-authority.mjs'),
      '--collect-post-merge-ci', '--run-id', '1'], {
      cwd: fixture, env: { ...environment, GITHUB_ACTIONS: 'true' }, encoding: 'utf8', maxBuffer: 1024 * 1024,
    });
    let collectorReport; try { collectorReport = JSON.parse(collector.stdout); } catch { collectorReport = null; }
    check('S14', 'public CI cannot invoke the local online collector', 'REJECT',
      !collector.error && collector.status === 1 && collectorReport?.error === 'CI_EVIDENCE_ACCEPTANCE_FAILED');

    alternateCloseout(records, fixtureCatalogue, 'synthetic unaccepted closeout status change');
    const proposalStatus = readJSON(fixture, STATUS_PATH);
    proposalStatus.authority_snapshot_id = 'UNAUTHORIZED-GOVERNANCE-PROJECTION';
    // Amend only this disposable fixture to keep a direct closeout child.
    fs.writeFileSync(path.join(fixture, STATUS_PATH), `${JSON.stringify(proposalStatus, null, 2)}\n`);
    execute(['add', '--', STATUS_PATH]);
    execute(['commit', '--amend', '--no-edit', '-q']);
    execute(['update-ref', 'refs/remotes/origin/main', BASE_COMMIT]);
    scope = candidateScope(fixture);
    check('S15', 'closeout proposal cannot change an unrelated machine status field', 'REJECT',
      !scope.lifecycle.accepted && scope.problems.some((problem) => problem.includes('closeout status differs')));
    alternateCloseout(records, failedJobs, 'synthetic unaccepted closeout with failed CI job');
    execute(['update-ref', 'refs/remotes/origin/main', BASE_COMMIT]);
    scope = candidateScope(fixture);
    check('S16', 'closeout proposal must validate independent CI job contents', 'REJECT',
      !scope.lifecycle.accepted && scope.problems.some((problem) => problem.includes('five exact successful jobs')));
  } catch {
    probes.push({ id: 'S-ENV', label: 'synthetic Git successor fixture execution', expected: 'PASS', actual: 'ERROR', matched: false });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
  return probes;
}

function publicationSummary(report, gameBodyLeaks) {
  const counts = report.counts ?? {};
  return {
    result: report.result,
    secret_leaks: (counts.credential_leaks ?? 0) + (counts.token_leaks ?? 0) +
      (counts.environment_secret_leaks ?? 0) + (counts.credential_reference_leaks ?? 0),
    credential_leaks: (counts.credential_leaks ?? 0) + (counts.token_leaks ?? 0) +
      (counts.credential_reference_leaks ?? 0),
    private_prompt_leaks: counts.private_prompt_leaks ?? 0,
    private_asset_locator_leaks: counts.private_asset_locator_leaks ?? 0,
    private_path_leaks: counts.private_path_leaks ?? 0,
    game_body_leaks: gameBodyLeaks,
    detector_report: report,
  };
}

export function run(ctx) {
  const details = [];
  let policy;
  let schema;
  let projectStatus;
  let decisionRegistry;
  try {
    policy = readJSON(ctx.repo, POLICY_PATH);
    schema = readJSON(ctx.repo, SCHEMA_PATH);
    projectStatus = readJSON(ctx.repo, STATUS_PATH);
    decisionRegistry = readJSON(ctx.repo, 'docs/authority/registry/decisions.json');
  } catch (error) {
    return {
      result: 'FAIL',
      task_id: TASK_ID,
      details: [`FAIL: Authority input unreadable: ${error.message}`],
      schema_validation: 'FAIL',
      authority_validation: 'FAIL',
      negative_probes: [],
      unexpected_acceptances: 0,
      uncaught_validation_errors: 0,
    };
  }

  const scope = candidateScope(ctx.repo);
  const historical = scope.phase === 'CLOSED_AUTHORITY_REPLAY';
  if (historical) {
    try {
      projectStatus = statusForScope(ctx.repo, scope);
      decisionRegistry = JSON.parse(gitText(ctx.repo, scope.candidate.commit, 'docs/authority/registry/decisions.json'));
    } catch {
      scope.problems.push('frozen Candidate status/decision snapshot is unreadable');
    }
  }
  const schemaMeta = checkSchemaDocument(schema);
  const strictObjects = schemaStrictObjectProblems(schema);
  const policySchema = validateInstance(schema, policy);
  const semantics = policySemanticProblems(policy);
  const statusIssues = statusProblems(projectStatus);
  const decisions = decisionProblems(decisionRegistry);
  const documents = documentProblems(ctx.repo, historical ? scope.candidate.commit : null);
  const probes = negativeGovernanceProbes(policy, schema, projectStatus);
  const unexpectedAcceptances = probes.filter((probe) => probe.actual === 'ACCEPT').length;
  const uncaughtErrors = probes.filter((probe) => probe.threw).length;
  const probeFailures = probes.filter((probe) => !probe.matched);
  const successorProbes = governanceSuccessorProbes(ctx.repo, scope.candidate);
  const successorFailures = successorProbes.filter((probe) => !probe.matched);
  const gameBodyLeaks = scope.inventory.some((relative) => relative.startsWith('UNREGISTERED/')) ? 1 : 0;
  const publication = publicationSummary(runPublicationHygiene({
    repo: ctx.repo,
    files: scope.inventory.filter((relative) => fs.existsSync(path.join(ctx.repo, relative))),
  }), gameBodyLeaks);

  for (const problem of schemaMeta.errors) details.push(`FAIL: policy meta-schema: ${problem}`);
  for (const problem of strictObjects) details.push(`FAIL: policy schema strictness: ${problem}`);
  for (const error of policySchema.errors) details.push(`FAIL: policy instance: ${error.message}`);
  for (const problem of semantics) details.push(`FAIL: policy semantics: ${problem}`);
  for (const problem of statusIssues) details.push(`FAIL: project status: ${problem}`);
  for (const problem of decisions) details.push(`FAIL: decision preservation: ${problem}`);
  for (const problem of documents) details.push(`FAIL: human projection: ${problem}`);
  for (const problem of scope.problems) details.push(`FAIL: candidate scope: ${problem}`);
  for (const probe of probes) {
    details.push(probe.matched
      ? `ok: ${probe.id} ${probe.label} -> REJECT`
      : `FAIL: ${probe.id} ${probe.label} expected REJECT, got ${probe.actual}`);
  }
  for (const probe of successorProbes) details.push(probe.matched ? `ok: ${probe.id} ${probe.label} -> ${probe.actual}` : `FAIL: ${probe.id} ${probe.label} got ${probe.actual}`);
  if (publication.result !== 'PASS') details.push('FAIL: publication hygiene did not pass with complete zero-leak coverage');
  if (gameBodyLeaks !== 0) details.push('FAIL: governance Candidate includes a game-body path');

  const result = details.every((entry) => !entry.startsWith('FAIL:')) &&
    probeFailures.length === 0 && successorFailures.length === 0 && unexpectedAcceptances === 0 && uncaughtErrors === 0 &&
    publication.result === 'PASS' && gameBodyLeaks === 0
    ? 'PASS'
    : 'FAIL';
  if (result === 'PASS') {
    details.unshift(
      'ok: ONLINE_GITHUB_REMOTE_PROVENANCE_V1 exact policy and strict schema',
      'ok: R9-Q004 preserved; local object presence is never remote provenance',
      historical ? 'ok: accepted CLOSED governance is replayed against its frozen Candidate status, without restricting later batch status' : 'ok: B005 remains IN_PROGRESS at GLOBAL_WIP 1 and B006 remains NOT_STARTED/NOT_AUTHORIZED',
      'ok: governance-only Candidate changes zero implementation files',
    );
  }
  return {
    result,
    task_id: TASK_ID,
    parent_batch: PARENT_BATCH,
    policy_id: POLICY_ID,
    details,
    schema_validation: schemaMeta.errors.length === 0 && strictObjects.length === 0 && policySchema.errors.length === 0 ? 'PASS' : 'FAIL',
    authority_validation: semantics.length === 0 && statusIssues.length === 0 && decisions.length === 0 &&
      documents.length === 0 && scope.problems.length === 0 ? 'PASS' : 'FAIL',
    negative_probes: probes,
    negative_probe_result: probeFailures.length === 0 && uncaughtErrors === 0 ? 'PASS' : 'FAIL',
    negative_probe_count: probes.length,
    successor_scope_probes: successorProbes,
    successor_scope_probe_count: successorProbes.length,
    successor_scope_probe_result: successorFailures.length === 0 ? 'PASS' : 'FAIL',
    unexpected_acceptances: unexpectedAcceptances,
    uncaught_validation_errors: uncaughtErrors,
    publication_hygiene: publication,
    candidate_scope: {
      phase: scope.phase,
      branch: scope.branch,
      candidate_commit: scope.candidate?.commit ?? null,
      candidate_tree: scope.candidate?.tree ?? null,
      changed_files: scope.inventory,
      scope_subject: historical ? 'FROZEN_GOVERNANCE_CANDIDATE_AND_ACCEPTED_CLOSEOUT' : 'CURRENT_GOVERNANCE_VALIDATION_TARGET',
      post_candidate_changed_files: scope.postCandidatePaths,
      accepted_closeout_commit: scope.lifecycle.closeoutCommit ?? null,
      ci_evidence_trust_basis: historical ? CI_ACCEPTANCE.offline_trust_basis : null,
      ci_evidence_catalogue_path: historical ? CI_CATALOGUE_PATH : null,
      governance_only: scope.implementationFiles.length === 0,
      implementation_files_changed: scope.implementationFiles.length,
    },
    external_github_requests: 0,
    model_provider_requests: 0,
    b005_r1_recovery_started: false,
    status_validation_target: historical ? 'FROZEN_CANDIDATE_SNAPSHOT' : 'CURRENT_GOVERNANCE_PHASE',
    current_batch_runtime_qualification_claimed: false,
  };
}

if (path.resolve(process.argv[1] ?? '') === fileURLToPath(import.meta.url) && process.argv.includes('--collect-post-merge-ci')) {
  const args = parseArgs(process.argv.slice(2));
  try {
    const report = await collectPostMergeCI(path.resolve(args.repo || process.cwd()), args);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } catch {
    process.stdout.write(`${JSON.stringify({ result: 'FAIL', mode: CI_ACCEPTANCE.mode, error: 'CI_EVIDENCE_ACCEPTANCE_FAILED' })}\n`);
    process.exitCode = 1;
  }
} else {
  runAsMain(import.meta.url, 'b005-remote-provenance-authority', run);
}
