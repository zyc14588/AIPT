#!/usr/bin/env node
// Governance-only validator for
// AIPT-MVP-B005-REMOTE-PROVENANCE-AUTHORITY-001.
//
// This gate validates only the frozen Authority, its projections, candidate
// scope, publication hygiene, and A01-A11 governance mutations. It performs
// no GitHub request, model/provider request, B005 runtime repair, integration
// rerun, playtest, or qualification execution.
import fs from 'node:fs';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { git, runAsMain } from '../lib/cli.mjs';
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

function documentProblems(repo) {
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
    try { contents = read(repo, relative); } catch { problems.push(`${relative} is missing or unreadable`); continue; }
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

function candidateScope(repo) {
  const base = commitFacts(repo, BASE_COMMIT);
  const candidate = committedCandidate(repo);
  const branch = currentBranch(repo);
  let inventory;
  let phase;
  if (candidate) {
    inventory = changedPaths(repo, BASE_COMMIT, candidate.commit);
    phase = candidate.commit === gitOut(repo, ['rev-parse', 'HEAD^{commit}']) ? 'CANDIDATE' : 'SUCCESSOR';
  } else {
    inventory = workingInventory(repo);
    phase = branch === BRANCH && gitOut(repo, ['rev-parse', 'HEAD^{commit}']) === BASE_COMMIT
      ? 'CONSTRUCTION'
      : 'REJECTED';
  }
  const implementationFiles = inventory.filter((relative) =>
    relative.startsWith('internal/') || relative.startsWith('cmd/') || relative.startsWith('packages/') ||
    relative.startsWith('storage/') || relative.startsWith('UNREGISTERED/') ||
    relative.includes('/migrations/') || relative === 'scripts/ci/validate/int001-closeout-authority.mjs');
  const problems = [];
  if (base?.commit !== BASE_COMMIT || base?.tree !== BASE_TREE) problems.push('frozen B005 merge base commit/tree is unavailable or drifted');
  if (phase === 'REJECTED') problems.push('Authority candidate is not construction on the exact branch/base or a direct single-commit Candidate');
  if (!isDeepStrictEqual(inventory, EXPECTED_CHANGED_PATHS)) problems.push('governance Candidate changed-path inventory differs from the exact authorized set');
  if (implementationFiles.length !== 0) problems.push('governance Candidate changes an implementation or protected INT001 path');
  if (candidate) {
    for (const relative of [POLICY_PATH, SCHEMA_PATH, HUMAN_PATH, 'scripts/ci/validate/b005-remote-provenance-authority.mjs']) {
      const candidateBlob = gitResult(repo, ['show', `${candidate.commit}:${relative}`]);
      let current;
      try { current = read(repo, relative); } catch { current = null; }
      if (candidateBlob.status !== 0 || current === null || candidateBlob.stdout !== current) {
        problems.push(`frozen Authority artifact changed after Candidate: ${relative}`);
      }
    }
  }
  return { problems, phase, branch, candidate, inventory, implementationFiles };
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

  const schemaMeta = checkSchemaDocument(schema);
  const strictObjects = schemaStrictObjectProblems(schema);
  const policySchema = validateInstance(schema, policy);
  const semantics = policySemanticProblems(policy);
  const statusIssues = statusProblems(projectStatus);
  const decisions = decisionProblems(decisionRegistry);
  const documents = documentProblems(ctx.repo);
  const scope = candidateScope(ctx.repo);
  const probes = negativeGovernanceProbes(policy, schema, projectStatus);
  const unexpectedAcceptances = probes.filter((probe) => probe.actual === 'ACCEPT').length;
  const uncaughtErrors = probes.filter((probe) => probe.threw).length;
  const probeFailures = probes.filter((probe) => !probe.matched);
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
  if (publication.result !== 'PASS') details.push('FAIL: publication hygiene did not pass with complete zero-leak coverage');
  if (gameBodyLeaks !== 0) details.push('FAIL: governance Candidate includes a game-body path');

  const result = details.every((entry) => !entry.startsWith('FAIL:')) &&
    probeFailures.length === 0 && unexpectedAcceptances === 0 && uncaughtErrors === 0 &&
    publication.result === 'PASS' && gameBodyLeaks === 0
    ? 'PASS'
    : 'FAIL';
  if (result === 'PASS') {
    details.unshift(
      'ok: ONLINE_GITHUB_REMOTE_PROVENANCE_V1 exact policy and strict schema',
      'ok: R9-Q004 preserved; local object presence is never remote provenance',
      'ok: B005 remains IN_PROGRESS at GLOBAL_WIP 1 and B006 remains NOT_STARTED/NOT_AUTHORIZED',
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
    unexpected_acceptances: unexpectedAcceptances,
    uncaught_validation_errors: uncaughtErrors,
    publication_hygiene: publication,
    candidate_scope: {
      phase: scope.phase,
      branch: scope.branch,
      candidate_commit: scope.candidate?.commit ?? null,
      candidate_tree: scope.candidate?.tree ?? null,
      changed_files: scope.inventory,
      governance_only: scope.implementationFiles.length === 0,
      implementation_files_changed: scope.implementationFiles.length,
    },
    external_github_requests: 0,
    model_provider_requests: 0,
    b005_r1_recovery_started: false,
  };
}

runAsMain(import.meta.url, 'b005-remote-provenance-authority', run);
