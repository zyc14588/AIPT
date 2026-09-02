#!/usr/bin/env node
// INT-AIPT-UNREGISTERED-MVP-001 governance-only closeout registration gate.
//
// This validator never executes the integration, a model, or a provider call.
// It validates the immutable read-only fixed-pair record, the exact status
// projection, the governance-only Git topology, publication hygiene, and the
// preserved B001-B004 / external-source authority boundaries. Optional local
// arguments revalidate the already-existing evidence bytes and source checkout.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { git, runAsMain } from '../lib/cli.mjs';
import { checkSchemaDocument, validateInstance } from '../lib/json-schema.mjs';
import { runPublicationHygiene } from '../lib/publication-hygiene.mjs';

const AUTHORITY_TASK = 'INT-AIPT-UNREGISTERED-MVP-001-CLOSEOUT-AUTHORITY-001';
const INTEGRATION_TASK = 'INT-AIPT-UNREGISTERED-MVP-001';
const BRANCH = `task/${AUTHORITY_TASK}`;
const BASE_COMMIT = 'c65075691e0b9503a8e3bd9da1220bf319354a26';
const BASE_TREE = 'bd2fa7d7374f1bbff44c1f5aa4746a86f68d41eb';
const PACKAGE_COMMIT = 'fe0965977447caf8cd7b6e58252bc1b991b7cc6f';
const PACKAGE_TREE = '34597e79c586fb034256daa32d67640692ec589d';
const SOURCE_COMMIT = '358d6d9d08a86818e34fd0c0d9a62bfe66e73abe';
const SOURCE_TREE = '5585271c78d1fe5cd8357c7b36a501bee34f0240';
const SOURCE_DIGEST = '605b4a72dda8348fc51245f0d0947d69cc47b174346bb9f14b378fb703ff594d';
const PACKAGE_MANIFEST_SHA256 = '99683081677f5ac098dc94ee1221b4ae1fd5a75b416da7094276dbf694bb23bd';
const RUNTIME_ADAPTER_SHA256 = 'b6b80ef8b671414ca7bc34b7e65510db9a3bad5910996f43ea92120ecaec773d';
const INTEGRATION_MANIFEST_SHA256 = 'de553465a6bd79e0c0ccb89af678721f132d9fe98ec39a41136402a5386ca164';
const STAGE_EVIDENCE_ROOT_SHA256 = 'dc105e0a5159bd62d42f2a8177dd943160d127446fcbaf146097253bfa71ec06';
const LOCAL_CLOSEOUT_SHA256 = 'd6a7380cf33a8530cc1e863bbb5705b2143be8f6108fb45cb8cdbe2fef592ccb';
const FINAL_EVIDENCE_ROOT_SHA256 = '7ce5014d1951f21d88ca838ef1f7e14fb802b2d8c8c03db6aa3cc902f75cb777';
const FINAL_STATE_HASH = '8264e9b4a0ed8bc631001a931854ef8b0915be2efb94e5d9c6c0faead8373a6f';
const RECORD_SHA256 = '1f22028561c90619755314eedb50869bb40e78b4ef55458e35eb654bf8d9ebc2';
const B005_BASE_COMMIT = '176f33d8f20f94a77ab688f4869e944b6ffe97c6';
const B005_BASE_TREE = '210320957a35633bcf766a3d88ea50a3493bd0fc';

const SCHEMA_PATH = 'schemas/integration-lifecycle/v1/aipt-read-only-integration-closeout.schema.json';
const RECORD_PATH = 'docs/authority/registry/integration-closeouts/int-aipt-unregistered-mvp-001-closeout.json';
const STATUS_PATH = 'docs/authority/registry/project-status.json';
const BATCH_GRAPH_PATH = 'docs/authority/registry/batch-graph.json';
const B004_CLOSED_RECORD = 'docs/authority/registry/authority-lifecycle/records/aipt-mvp-b004/003-closed.json';

const REQUIRED_CANDIDATE_PATHS = Object.freeze([
  'docs/authority/BATCH_DEPENDENCY_GRAPH.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/README.md',
  'docs/authority/amendments/INT_AIPT_UNREGISTERED_MVP_001_CLOSEOUT_AUTHORITY_001.md',
  RECORD_PATH,
  STATUS_PATH,
  'package.json',
  SCHEMA_PATH,
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/int001-closeout-authority.mjs',
]);
const ALLOWED_CANDIDATE_PATHS = new Set([
  ...REQUIRED_CANDIDATE_PATHS,
  '.github/workflows/ci.yml',
]);
const IMMUTABLE_SEMANTIC_PATHS = Object.freeze([
  'docs/authority/amendments/INT_AIPT_UNREGISTERED_MVP_001_CLOSEOUT_AUTHORITY_001.md',
  RECORD_PATH,
  SCHEMA_PATH,
]);

function read(repo, relative) {
  return fs.readFileSync(path.join(repo, relative), 'utf8');
}

function readJSON(repo, relative) {
  return JSON.parse(read(repo, relative));
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function gitResult(repo, args) {
  return git(repo, args, { check: false });
}

function gitOut(repo, args) {
  const result = gitResult(repo, args);
  return result.status === 0 ? result.stdout.trim() : null;
}

function lines(result) {
  return result?.status === 0 ? result.stdout.split('\n').filter(Boolean) : [];
}

function commitFacts(repo, commit) {
  const row = gitOut(repo, ['rev-list', '--parents', '-n', '1', commit]);
  if (!row) return null;
  const [resolved, ...parents] = row.split(/\s+/u);
  const tree = gitOut(repo, ['rev-parse', `${commit}^{tree}`]);
  return tree ? { commit: resolved, tree, parents } : null;
}

function isAncestor(repo, ancestor, descendant) {
  return gitResult(repo, ['merge-base', '--is-ancestor', ancestor, descendant]).status === 0;
}

function currentBranch(repo) {
  return gitOut(repo, ['branch', '--show-current']) || process.env.GITHUB_HEAD_REF ||
    (process.env.GITHUB_REF?.startsWith('refs/heads/')
      ? process.env.GITHUB_REF.slice('refs/heads/'.length) : 'DETACHED');
}

function changedPaths(repo, from, to) {
  return lines(gitResult(repo, ['diff', '--name-only', '--no-renames', from, to])).sort();
}

function workingPaths(repo) {
  const committed = changedPaths(repo, BASE_COMMIT, 'HEAD');
  const tracked = lines(gitResult(repo, ['diff', '--name-only', '--no-renames']));
  const staged = lines(gitResult(repo, ['diff', '--cached', '--name-only', '--no-renames']));
  const untracked = lines(gitResult(repo, ['ls-files', '--others', '--exclude-standard']));
  return [...new Set([...committed, ...tracked, ...staged, ...untracked]
    .filter((relative) => !relative.split('/').includes('node_modules')))].sort();
}

function worktreeDirty(repo) {
  return lines(gitResult(repo, ['status', '--porcelain=v1', '--untracked-files=all']))
    .some((line) => !line.includes('node_modules/'));
}

function linearCandidate(repo, candidate) {
  const rows = lines(gitResult(repo, ['rev-list', '--reverse', '--parents', `${BASE_COMMIT}..${candidate}`]));
  if (rows.length === 0) return false;
  let previous = BASE_COMMIT;
  for (const row of rows) {
    const [commit, ...parents] = row.split(/\s+/u);
    if (parents.length !== 1 || parents[0] !== previous) return false;
    previous = commit;
  }
  return previous === candidate;
}

function candidateScopeProblems(paths) {
  const problems = [];
  const unauthorized = paths.filter((relative) => !ALLOWED_CANDIDATE_PATHS.has(relative));
  const missing = REQUIRED_CANDIDATE_PATHS.filter((relative) => !paths.includes(relative));
  if (unauthorized.length > 0) problems.push(`scope contains unauthorized paths: ${unauthorized.join(', ')}`);
  if (missing.length > 0) problems.push(`scope misses required paths: ${missing.join(', ')}`);
  return problems;
}

function candidateSemanticImmutabilityProblems(repo, candidate) {
  const problems = [];
  for (const relative of IMMUTABLE_SEMANTIC_PATHS) {
    const accepted = gitResult(repo, ['show', `${candidate}:${relative}`]);
    if (accepted.status !== 0 || accepted.stdout !== read(repo, relative)) {
      problems.push(`accepted semantic artifact changed after Candidate: ${relative}`);
    }
  }
  return problems;
}

function classifyTopologyFacts(facts) {
  if (!facts.baseExact || !facts.sourceAncestor || !facts.scopeValid || !facts.requiredPresent) return 'REJECTED';
  if (facts.kind === 'CONSTRUCTION') {
    return facts.branch === BRANCH && facts.head === BASE_COMMIT ? 'CONSTRUCTION' : 'REJECTED';
  }
  if (facts.kind === 'CANDIDATE') {
    return facts.branch === BRANCH && facts.linear && facts.parentCount === 1 ? 'CANDIDATE' : 'REJECTED';
  }
  if (facts.kind === 'MERGE') {
    return facts.mergeParent1 === BASE_COMMIT && facts.candidateLinear && facts.mergeTree === facts.candidateTree
      ? 'LEGAL_MERGE' : 'REJECTED';
  }
  if (facts.kind === 'SUCCESSOR') {
    return facts.mergeParent1 === BASE_COMMIT && facts.candidateLinear && facts.mergeTree === facts.candidateTree &&
      facts.mergeOnFirstParent && facts.semanticArtifactsImmutable ? 'POST_MERGE_SUCCESSOR' : 'REJECTED';
  }
  return 'REJECTED';
}

function resolveTopology(repo) {
  const head = gitOut(repo, ['rev-parse', 'HEAD^{commit}']);
  const headFacts = commitFacts(repo, head);
  const branch = currentBranch(repo);
  const baseExact = commitFacts(repo, BASE_COMMIT)?.tree === BASE_TREE;
  const sourceAncestor = Boolean(head && isAncestor(repo, BASE_COMMIT, head));
  const dirty = worktreeDirty(repo);
  // Dirty work on the original authority branch is its construction phase.
  // Once the accepted closeout merge is on the first-parent chain, later
  // successor work must not be mistaken for a rewrite of that old Candidate.
  if (dirty && (branch === BRANCH || head === BASE_COMMIT)) {
    const scopePaths = workingPaths(repo);
    const scopeProblems = candidateScopeProblems(scopePaths);
    const facts = {
      kind: 'CONSTRUCTION', baseExact, sourceAncestor, scopeValid: scopeProblems.length === 0,
      requiredPresent: REQUIRED_CANDIDATE_PATHS.every((relative) => scopePaths.includes(relative)),
      branch, head,
    };
    return { phase: classifyTopologyFacts(facts), head, headFacts, branch, candidate: null, scopePaths, scopeProblems };
  }

  const parent1 = headFacts?.parents[0] ?? null;
  const parent2 = headFacts?.parents[1] ?? null;
  if (headFacts?.parents.length === 2 && parent1 === BASE_COMMIT) {
    const candidateFacts = commitFacts(repo, parent2);
    const scopePaths = changedPaths(repo, BASE_COMMIT, parent2);
    const scopeProblems = candidateScopeProblems(scopePaths);
    const facts = {
      kind: 'MERGE', baseExact, sourceAncestor, scopeValid: scopeProblems.length === 0,
      requiredPresent: REQUIRED_CANDIDATE_PATHS.every((relative) => scopePaths.includes(relative)),
      mergeParent1: parent1, candidateLinear: linearCandidate(repo, parent2),
      mergeTree: headFacts.tree, candidateTree: candidateFacts?.tree,
    };
    return { phase: classifyTopologyFacts(facts), head, headFacts, branch, candidate: parent2, scopePaths, scopeProblems };
  }

  if (branch === BRANCH && headFacts?.parents.length === 1) {
    const scopePaths = changedPaths(repo, BASE_COMMIT, head);
    const scopeProblems = candidateScopeProblems(scopePaths);
    const facts = {
      kind: 'CANDIDATE', baseExact, sourceAncestor, scopeValid: scopeProblems.length === 0,
      requiredPresent: REQUIRED_CANDIDATE_PATHS.every((relative) => scopePaths.includes(relative)),
      branch, linear: linearCandidate(repo, head), parentCount: headFacts.parents.length,
    };
    return { phase: classifyTopologyFacts(facts), head, headFacts, branch, candidate: head, scopePaths, scopeProblems };
  }

  const firstParent = lines(gitResult(repo, ['rev-list', '--first-parent', '--reverse', `${BASE_COMMIT}..${head}`]));
  const merge = commitFacts(repo, firstParent[0]);
  const candidate = merge?.parents[1] ?? null;
  const candidateFacts = candidate ? commitFacts(repo, candidate) : null;
  const scopePaths = candidate ? changedPaths(repo, BASE_COMMIT, candidate) : [];
  const scopeProblems = candidateScopeProblems(scopePaths);
  const immutableProblems = candidate ? candidateSemanticImmutabilityProblems(repo, candidate) : ['accepted Candidate unavailable'];
  const facts = {
    kind: 'SUCCESSOR', baseExact, sourceAncestor, scopeValid: scopeProblems.length === 0,
    requiredPresent: REQUIRED_CANDIDATE_PATHS.every((relative) => scopePaths.includes(relative)),
    mergeParent1: merge?.parents[0], candidateLinear: Boolean(candidate && linearCandidate(repo, candidate)),
    mergeTree: merge?.tree, candidateTree: candidateFacts?.tree,
    mergeOnFirstParent: Boolean(merge && firstParent.includes(merge.commit)),
    semanticArtifactsImmutable: immutableProblems.length === 0,
  };
  return {
    phase: classifyTopologyFacts(facts), head, headFacts, branch, candidate,
    acceptedMerge: merge?.commit ?? null, scopePaths, scopeProblems: [...scopeProblems, ...immutableProblems],
  };
}

function strictObjectProblems(node, location = '#') {
  const problems = [];
  if (node === null || typeof node !== 'object' || Array.isArray(node)) return problems;
  if (node.type === 'object' && node.additionalProperties !== false) problems.push(`${location} object is not fail-closed`);
  for (const [key, value] of Object.entries(node)) {
    if (key === 'properties' || key === '$defs') {
      for (const [name, child] of Object.entries(value)) {
        problems.push(...strictObjectProblems(child, `${location}/${key}/${name}`));
      }
    } else if (key === 'items' || key === 'not') {
      problems.push(...strictObjectProblems(value, `${location}/${key}`));
    } else if (['oneOf', 'anyOf', 'allOf'].includes(key)) {
      value.forEach((child, index) => problems.push(...strictObjectProblems(child, `${location}/${key}/${index}`)));
    }
  }
  return problems;
}

const EXPECTED_ARTIFACT_HASHES = Object.freeze({
  package_manifest_sha256: PACKAGE_MANIFEST_SHA256,
  runtime_adapter_sha256: RUNTIME_ADAPTER_SHA256,
  integration_manifest_sha256: INTEGRATION_MANIFEST_SHA256,
  stage_evidence_root_sha256: STAGE_EVIDENCE_ROOT_SHA256,
  local_closeout_record_sha256: LOCAL_CLOSEOUT_SHA256,
  final_evidence_root_sha256: FINAL_EVIDENCE_ROOT_SHA256,
});

function recordSemanticProblems(schema, record) {
  const problems = validateInstance(schema, record).errors.map((error) => `closeout schema: ${error.message}`);
  const exact = (actual, expected, label) => {
    if (!isDeepStrictEqual(actual, expected)) problems.push(`${label} is not exact`);
  };
  exact(record?.schema, 'aipt.public.read-only-integration-closeout/v1', 'record schema identity');
  exact(record?.record_id, `${INTEGRATION_TASK}-CLOSEOUT-001`, 'record id');
  exact(record?.task_id, INTEGRATION_TASK, 'integration task id');
  exact(record?.state, 'CLOSED', 'integration state');
  exact(record?.classification, 'FIXED_PAIR_RUNTIME_CONFORMANCE_SMOKE_PASS', 'classification');
  exact(record?.closeout_kind, 'READ_ONLY_INTEGRATION', 'closeout kind');
  exact(record?.integration_kind, 'READ_ONLY_FIXED_PAIR', 'integration kind');
  exact(record?.repository_merge_performed, false, 'repository merge flag');
  exact(record?.fixed_pair, {
    aipt_source: { repository: 'zyc14588/AIPT', commit: BASE_COMMIT, tree: BASE_TREE },
    unregistered_package: { repository: 'zyc14588/UNREGISTERED', commit: PACKAGE_COMMIT, tree: PACKAGE_TREE },
    unregistered_nested_source: {
      repository: 'zyc14588/UNREGISTERED', commit: SOURCE_COMMIT, tree: SOURCE_TREE,
      source_digest_sha256: SOURCE_DIGEST,
    },
    integration_subject: {
      package_id: 'zyc14588/agent-sim', package_version: '1.0.0',
      test_unit_id: 'UNREGISTERED-T000-VERTICAL-SLICE',
    },
  }, 'fixed pair');
  exact(record?.artifact_hashes, EXPECTED_ARTIFACT_HASHES, 'artifact hashes');
  exact(record?.execution, {
    stage: 'PASS', local_closeout: 'PASS', source_stage_result: 'INTEGRATION_STAGE_PASS',
    source_local_closeout_result: 'PASS_READ_ONLY_CLOSED', frozen_evidence_revalidation: 'PASS',
    rerun_performed: false,
  }, 'execution result');
  exact(record?.replay, { result: 'PASS', hash_match: true, final_state_hash: FINAL_STATE_HASH, rng_used: false }, 'replay');
  exact(record?.security, {
    result: 'PASS', credential_leaks: 0, hidden_information_leaks: 0, private_prompt_leaks: 0,
    private_asset_locator_leaks: 0, game_body_copied: false,
  }, 'security result');
  exact(record?.model_execution, {
    remote_real_model_calls: 0, local_real_model_calls: 0, provider_network_calls: 0,
  }, 'model execution counts');
  exact(record?.qualification, { counts_toward_qualification: false, qualification_runs_executed: 0 }, 'qualification boundary');
  exact(record?.owner_authorization, {
    authorized: true, authorized_by: 'Owner',
    execution_directive: 'OWNER_CLOSEOUT_INT-AIPT-UNREGISTERED-MVP-001-001',
    registration_directive: 'FORMAL_CLOSEOUT_REGISTRATION_001', authority_task: AUTHORITY_TASK,
  }, 'Owner authorization');
  exact(record?.record_identity, {
    identity_scheme: 'IMMUTABLE_GIT_BLOB_AT_ACCEPTED_COMMIT', path: RECORD_PATH,
    accepted_commit_source: 'CONTAINING_GIT_COMMIT', append_only: true,
  }, 'record identity');
  exact(record?.provenance, {
    governance_gap: 'READ_ONLY_INTEGRATION_CLOSEOUT_NOT_PERSISTED_IN_MACHINE_AUTHORITY',
    source_task: INTEGRATION_TASK, registration_task: AUTHORITY_TASK,
    source_evidence_basis: 'EXISTING_FROZEN_CLOSEOUT_BYTES', source_repositories_mutated: false,
    historical_evidence_claimed_only_if_proven: true,
  }, 'provenance');
  exact(record?.open_findings, [], 'open findings');
  return problems;
}

function expectedIntegrationProjection() {
  return {
    task_id: INTEGRATION_TASK,
    state: 'CLOSED',
    classification: 'FIXED_PAIR_RUNTIME_CONFORMANCE_SMOKE_PASS',
    closeout_kind: 'READ_ONLY_INTEGRATION',
    integration_kind: 'READ_ONLY_FIXED_PAIR',
    repository_merge_performed: false,
    canonical_record: {
      schema: 'aipt.public.read-only-integration-closeout/v1',
      record_id: `${INTEGRATION_TASK}-CLOSEOUT-001`, path: RECORD_PATH, sha256: RECORD_SHA256,
    },
    fixed_pair: {
      aipt_commit: BASE_COMMIT, aipt_tree: BASE_TREE,
      unregistered_package_commit: PACKAGE_COMMIT, unregistered_package_tree: PACKAGE_TREE,
      unregistered_source_commit: SOURCE_COMMIT, unregistered_source_tree: SOURCE_TREE,
    },
    execution: { stage: 'PASS', local_closeout: 'PASS', rerun_performed: false },
    model_execution: { remote_real_model_calls: 0, local_real_model_calls: 0, provider_network_calls: 0 },
    qualification: { counts_toward_qualification: false, qualification_runs_executed: 0 },
    security: {
      result: 'PASS', credential_leaks: 0, hidden_information_leaks: 0, private_prompt_leaks: 0,
      private_asset_locator_leaks: 0, game_body_copied: false,
    },
    registration_authority_task: AUTHORITY_TASK,
    closed: true,
    open_findings: [],
  };
}

function expectedStatus(repo) {
  const baseline = gitResult(repo, ['show', `${BASE_COMMIT}:${STATUS_PATH}`]);
  if (baseline.status !== 0) throw new Error('exact baseline project status is unavailable');
  const expected = JSON.parse(baseline.stdout);
  expected.authority_snapshot_id = `${INTEGRATION_TASK}-CLOSEOUT-REGISTRATION-001`;
  const standalone = expected.tracks['AIPT-STANDALONE'];
  standalone.construction = 'IDLE_WAITING_NEXT_BATCH';
  standalone.current_batch = 'NO_ACTIVE_BATCH';
  standalone.next_serial_batch = 'AIPT-MVP-B005';
  standalone.next_batch_state = 'NOT_AUTHORIZED';
  standalone.next_batch_authorized = false;
  standalone.next_batch_started = false;
  standalone.batch_history[INTEGRATION_TASK] = 'MERGED_CLOSED';
  standalone.batch_history['AIPT-MVP-B005'] = 'NOT_STARTED';
  standalone.global_wip = 0;
  expected.integration_closeouts = { [INTEGRATION_TASK]: expectedIntegrationProjection() };
  return expected;
}

function expectedActiveB005Status(repo) {
  const expected = expectedStatus(repo);
  expected.as_of = '2026-09-03';
  expected.authority_snapshot_id = 'AIPT-MVP-B005-CONSTRUCTION-001';
  const standalone = expected.tracks['AIPT-STANDALONE'];
  standalone.construction = 'IN_PROGRESS';
  standalone.current_batch = 'AIPT-MVP-B005';
  standalone.next_serial_batch = 'AIPT-MVP-B006';
  standalone.batch_history['AIPT-MVP-B005'] = 'IN_PROGRESS';
  standalone.global_wip = 1;
  expected.repositories.AIPT.mvp_b005 = {
    task_id: 'AIPT-MVP-B005',
    state: 'IN_PROGRESS',
    start_authority: 'OWNER_DIRECTIVE_AIPT-MVP-B005',
    base: { commit: B005_BASE_COMMIT, tree: B005_BASE_TREE },
    predecessor: {
      task_id: INTEGRATION_TASK,
      state: 'CLOSED',
      canonical_closeout_sha256: RECORD_SHA256,
      integration_manifest_sha256: INTEGRATION_MANIFEST_SHA256,
      final_evidence_root_sha256: FINAL_EVIDENCE_ROOT_SHA256,
      rerun_performed: false,
    },
    scope: 'RUN_EVIDENCE_CLOSURE_AUDIT_READY_ONLY',
    risk: 'evidence-integrity',
    raw_capture_backward_compatible: true,
    audit_ready_generator_implemented: true,
    audit_ready_verifier_implemented: true,
    run_evidence_closure_implemented: true,
    replay_contract_implemented: true,
    defect_family_occurrence_contracts_implemented: true,
    report_contract_and_lifecycle_implemented: true,
    deterministic_export_implemented: true,
    content_addressed_chunking_implemented: true,
    encryption_implemented: false,
    signing_implemented: false,
    audit_result_generator_implemented: false,
    synthetic_public_postgresql_18_4_gate: 'PASS',
    negative_probe_count: 35,
    unexpected_acceptances: 0,
    real_model_calls: 0,
    provider_network_calls: 0,
    real_playtest_executed: false,
    qualification_runs_executed: 0,
    new_migration: 'NONE',
    runtime_ready: false,
    first_blocking_gate: 'IPC',
    publicly_pushed: false,
    public_ci_status: 'NOT_STARTED_AWAITING_OWNER_DISCLOSURE_AUTHORIZATION',
    open_findings: [],
  };
  expected.runtime.status = 'AIPT-MVP-B005 is the sole active construction batch at GLOBAL_WIP 1; it adds offline AUDIT_READY evidence closure only, does not change Launcher gates, and runtime_ready remains false at IPC with no playtest or qualification Run started';
  return expected;
}

function statusSemanticProblems(repo, status) {
  const problems = [];
  const historical = expectedStatus(repo);
  const activeB005 = expectedActiveB005Status(repo);
  const isHistorical = isDeepStrictEqual(status, historical);
  const isActiveB005 = isDeepStrictEqual(status, activeB005);
  if (!isHistorical && !isActiveB005) {
    problems.push('project-status projection differs from both the exact read-only closeout and authorized B005 successor transitions');
  }
  const standalone = status?.tracks?.['AIPT-STANDALONE'];
  const predecessorClosed = standalone?.batch_history?.['AIPT-MVP-B004'] === 'MERGED_CLOSED' &&
    standalone?.batch_history?.[INTEGRATION_TASK] === 'MERGED_CLOSED';
  const sharedNextBoundary = standalone?.next_batch_state === 'NOT_AUTHORIZED' &&
    standalone?.next_batch_authorized === false && standalone?.next_batch_started === false;
  const historicalTuple = standalone?.batch_history?.['AIPT-MVP-B005'] === 'NOT_STARTED' &&
    standalone?.next_serial_batch === 'AIPT-MVP-B005' && standalone?.construction === 'IDLE_WAITING_NEXT_BATCH' &&
    standalone?.current_batch === 'NO_ACTIVE_BATCH' && standalone?.global_wip === 0;
  const activeTuple = standalone?.batch_history?.['AIPT-MVP-B005'] === 'IN_PROGRESS' &&
    standalone?.batch_history?.['AIPT-MVP-B006'] === 'NOT_STARTED' &&
    standalone?.next_serial_batch === 'AIPT-MVP-B006' && standalone?.construction === 'IN_PROGRESS' &&
    standalone?.current_batch === 'AIPT-MVP-B005' && standalone?.global_wip === 1;
  if (!predecessorClosed || !sharedNextBoundary || (!historicalTuple && !activeTuple)) {
    problems.push('project-status predecessor/current/next/WIP tuple is not an allowed exact transition');
  }
  const integration = status?.integration_closeouts?.[INTEGRATION_TASK];
  if (!isDeepStrictEqual(integration, expectedIntegrationProjection())) {
    problems.push('project-status integration closeout projection is not exact');
  }
  return problems;
}

function sourceIntegrityProblems(repo, head) {
  const problems = [];
  const base = commitFacts(repo, BASE_COMMIT);
  if (base?.commit !== BASE_COMMIT || base?.tree !== BASE_TREE) problems.push('fixed AIPT source commit/tree is unavailable or drifted');
  if (!head || !isAncestor(repo, BASE_COMMIT, head)) problems.push('current Candidate does not descend from the fixed AIPT source');
  for (const relative of [BATCH_GRAPH_PATH, B004_CLOSED_RECORD]) {
    const baseline = gitResult(repo, ['show', `${BASE_COMMIT}:${relative}`]);
    if (baseline.status !== 0 || baseline.stdout !== read(repo, relative)) {
      problems.push(`frozen historical governance artifact changed: ${relative}`);
    }
  }
  const status = readJSON(repo, STATUS_PATH);
  const baselineStatus = JSON.parse(gitResult(repo, ['show', `${BASE_COMMIT}:${STATUS_PATH}`]).stdout);
  for (const key of ['mvp_b001', 'mvp_b002', 'mvp_b003', 'mvp_b004']) {
    if (!isDeepStrictEqual(status?.repositories?.AIPT?.[key], baselineStatus?.repositories?.AIPT?.[key])) {
      problems.push(`frozen ${key} semantics changed`);
    }
  }
  if (!isDeepStrictEqual(status?.repositories?.UNREGISTERED, baselineStatus?.repositories?.UNREGISTERED)) {
    problems.push('UNREGISTERED authority projection changed');
  }
  return problems;
}

function revalidateEvidenceBytes(directory) {
  if (!directory) return { result: 'PASS', mode: 'FROZEN_HASH_BINDING', problems: [] };
  const problems = [];
  const expected = new Map([
    ['integration-closeout.json', LOCAL_CLOSEOUT_SHA256],
    ['integration-manifest.json', INTEGRATION_MANIFEST_SHA256],
    ['evidence-manifest.json', STAGE_EVIDENCE_ROOT_SHA256],
    ['final-evidence-manifest.json', FINAL_EVIDENCE_ROOT_SHA256],
  ]);
  for (const [filename, digest] of expected) {
    try {
      const raw = fs.readFileSync(path.join(directory, filename));
      if (sha256(raw) !== digest) problems.push(`${filename} byte identity drifted`);
    } catch {
      problems.push(`${filename} is unavailable for direct byte revalidation`);
    }
  }
  try {
    const closeout = JSON.parse(fs.readFileSync(path.join(directory, 'integration-closeout.json'), 'utf8'));
    if (closeout?.task_id !== INTEGRATION_TASK || closeout?.state !== 'CLOSED' ||
        closeout?.result !== 'FIXED_PAIR_RUNTIME_CONFORMANCE_SMOKE_PASS' ||
        closeout?.stage_evidence_root_sha256 !== STAGE_EVIDENCE_ROOT_SHA256 ||
        closeout?.integration_manifest_sha256 !== INTEGRATION_MANIFEST_SHA256 ||
        closeout?.fixed_pair?.aipt_commit !== BASE_COMMIT || closeout?.fixed_pair?.aipt_tree !== BASE_TREE ||
        closeout?.fixed_pair?.unregistered_package_commit !== PACKAGE_COMMIT ||
        closeout?.fixed_pair?.unregistered_package_tree !== PACKAGE_TREE ||
        closeout?.fixed_pair?.unregistered_source_commit !== SOURCE_COMMIT ||
        closeout?.fixed_pair?.unregistered_source_tree !== SOURCE_TREE ||
        closeout?.replay?.hash_match !== true || closeout?.replay?.live_final_state_hash !== FINAL_STATE_HASH ||
        closeout?.replay?.replayed_final_state_hash !== FINAL_STATE_HASH ||
        closeout?.qualification?.counts_toward_qualification !== false ||
        closeout?.qualification?.qualification_runs_executed !== 0 ||
        closeout?.model_execution?.remote_deepseek_real_calls !== 0 ||
        closeout?.model_execution?.local_llamacpp_real_calls !== 0 ||
        closeout?.model_execution?.provider_network_calls !== 0 ||
        closeout?.security?.credential_leaks !== 0 || closeout?.security?.hidden_information_leaks !== 0 ||
        closeout?.security?.private_prompt_leaks !== 0) {
      problems.push('local closeout semantic fields differ from the frozen public registration');
    }
  } catch {
    problems.push('local closeout JSON is unreadable');
  }
  return { result: problems.length === 0 ? 'PASS' : 'FAIL', mode: 'DIRECT_EXISTING_BYTES', problems };
}

function revalidateExternalSource(checkout) {
  if (!checkout) return { result: 'PASS', mode: 'MACHINE_AUTHORITY_BINDING', problems: [] };
  const problems = [];
  const packageFacts = commitFacts(checkout, 'HEAD');
  const nestedFacts = commitFacts(checkout, SOURCE_COMMIT);
  if (packageFacts?.commit !== PACKAGE_COMMIT || packageFacts?.tree !== PACKAGE_TREE) {
    problems.push('external package checkout commit/tree drifted');
  }
  if (nestedFacts?.commit !== SOURCE_COMMIT || nestedFacts?.tree !== SOURCE_TREE) {
    problems.push('external nested source commit/tree drifted');
  }
  const status = gitResult(checkout, ['status', '--porcelain=v1', '--untracked-files=all']);
  if (status.status !== 0 || status.stdout.trim() !== '') problems.push('external source checkout is not clean/read-only in fact');
  return { result: problems.length === 0 ? 'PASS' : 'FAIL', mode: 'DIRECT_CLEAN_CHECKOUT', problems };
}

function recordNegativeProbes(schema, record) {
  const definitions = [
    ['R01', 'state reopened', (copy) => { copy.state = 'IN_PROGRESS'; }],
    ['R02', 'unknown property', (copy) => { copy.unapproved = true; }],
    ['R03', 'fixed AIPT source drift', (copy) => { copy.fixed_pair.aipt_source.commit = '0'.repeat(40); }],
    ['R04', 'external package tree drift', (copy) => { copy.fixed_pair.unregistered_package.tree = '0'.repeat(40); }],
    ['R05', 'stage evidence root drift', (copy) => { copy.artifact_hashes.stage_evidence_root_sha256 = '0'.repeat(64); }],
    ['R06', 'final evidence root drift', (copy) => { copy.artifact_hashes.final_evidence_root_sha256 = '0'.repeat(64); }],
    ['R07', 'replay hash drift', (copy) => { copy.replay.final_state_hash = '0'.repeat(64); }],
    ['R08', 'real model call added', (copy) => { copy.model_execution.remote_real_model_calls = 1; }],
    ['R09', 'qualification inflation', (copy) => { copy.qualification.counts_toward_qualification = true; }],
    ['R10', 'hidden leak added', (copy) => { copy.security.hidden_information_leaks = 1; }],
    ['R11', 'repository merge fabricated', (copy) => { copy.repository_merge_performed = true; }],
    ['R12', 'Owner authorization removed', (copy) => { copy.owner_authorization.authorized = false; }],
  ];
  return definitions.map(([id, label, mutate]) => {
    const copy = structuredClone(record);
    let threw = false;
    let actual = 'ACCEPT';
    try { mutate(copy); actual = recordSemanticProblems(schema, copy).length > 0 ? 'REJECT' : 'ACCEPT'; } catch { threw = true; }
    return { id, label, expected: 'REJECT', actual, threw, matched: !threw && actual === 'REJECT' };
  });
}

function statusNegativeProbes(repo, status) {
  const definitions = [
    ['S01', 'integration returned to NOT_STARTED', (copy) => { copy.tracks['AIPT-STANDALONE'].batch_history[INTEGRATION_TASK] = 'NOT_STARTED'; }],
    ['S02', 'next batch points back to integration', (copy) => { copy.tracks['AIPT-STANDALONE'].next_serial_batch = INTEGRATION_TASK; }],
    ['S03', 'unauthorized successor authorized', (copy) => { copy.tracks['AIPT-STANDALONE'].next_batch_authorized = true; }],
    ['S04', 'unauthorized successor started', (copy) => { copy.tracks['AIPT-STANDALONE'].next_batch_started = true; }],
    ['S05', 'GLOBAL_WIP exceeds exact state', (copy) => { copy.tracks['AIPT-STANDALONE'].global_wip += 1; }],
    ['S06', 'B004 source reopened', (copy) => { copy.repositories.AIPT.mvp_b004.state = 'IN_PROGRESS'; }],
    ['S07', 'UNREGISTERED package drift', (copy) => { copy.repositories.UNREGISTERED.verified_head = '0'.repeat(40); }],
    ['S08', 'integration merge fabricated in projection', (copy) => { copy.integration_closeouts[INTEGRATION_TASK].repository_merge_performed = true; }],
    ['S09', 'canonical closeout digest drift', (copy) => { copy.integration_closeouts[INTEGRATION_TASK].canonical_record.sha256 = '0'.repeat(64); }],
  ];
  return definitions.map(([id, label, mutate]) => {
    const copy = structuredClone(status);
    let threw = false;
    let actual = 'ACCEPT';
    try { mutate(copy); actual = statusSemanticProblems(repo, copy).length > 0 ? 'REJECT' : 'ACCEPT'; } catch { threw = true; }
    return { id, label, expected: 'REJECT', actual, threw, matched: !threw && actual === 'REJECT' };
  });
}

function topologyNegativeProbes() {
  const candidate = {
    kind: 'CANDIDATE', baseExact: true, sourceAncestor: true, scopeValid: true, requiredPresent: true,
    branch: BRANCH, linear: true, parentCount: 1,
  };
  const merge = {
    kind: 'MERGE', baseExact: true, sourceAncestor: true, scopeValid: true, requiredPresent: true,
    mergeParent1: BASE_COMMIT, candidateLinear: true, mergeTree: 'same', candidateTree: 'same',
  };
  const successor = {
    kind: 'SUCCESSOR', baseExact: true, sourceAncestor: true, scopeValid: true, requiredPresent: true,
    mergeParent1: BASE_COMMIT, candidateLinear: true, mergeTree: 'same', candidateTree: 'same',
    mergeOnFirstParent: true, semanticArtifactsImmutable: true,
  };
  const definitions = [
    ['T01', 'valid Candidate', candidate, 'CANDIDATE'],
    ['T02', 'wrong authority Base', { ...candidate, baseExact: false }, 'REJECTED'],
    ['T03', 'wrong Candidate branch', { ...candidate, branch: 'main' }, 'REJECTED'],
    ['T04', 'implementation scope drift', { ...candidate, scopeValid: false }, 'REJECTED'],
    ['T05', 'legal governance merge', merge, 'LEGAL_MERGE'],
    ['T06', 'wrong merge first parent', { ...merge, mergeParent1: '0'.repeat(40) }, 'REJECTED'],
    ['T07', 'merge tree mismatch', { ...merge, mergeTree: 'different' }, 'REJECTED'],
    ['T08', 'valid post-merge successor', successor, 'POST_MERGE_SUCCESSOR'],
    ['T09', 'accepted record rewritten', { ...successor, semanticArtifactsImmutable: false }, 'REJECTED'],
  ];
  return definitions.map(([id, label, facts, expected]) => {
    let actual = 'REJECTED';
    let threw = false;
    try { actual = classifyTopologyFacts(facts); } catch { threw = true; }
    return { id, label, expected, actual, threw, matched: !threw && actual === expected };
  });
}

export function run(ctx, args = {}) {
  const problems = [];
  let schema;
  let record;
  let status;
  let topology;
  try {
    schema = readJSON(ctx.repo, SCHEMA_PATH);
    record = readJSON(ctx.repo, RECORD_PATH);
    status = readJSON(ctx.repo, STATUS_PATH);
    topology = resolveTopology(ctx.repo);
  } catch (error) {
    return {
      result: 'FAIL', task_id: AUTHORITY_TASK, integration_task: INTEGRATION_TASK,
      details: [`FAIL: closeout authority inputs are unreadable: ${error.message}`],
      external_model_calls: 0, qualification_runs_executed: 0,
    };
  }

  problems.push(...checkSchemaDocument(schema).errors.map((problem) => `schema document: ${problem}`));
  problems.push(...strictObjectProblems(schema).map((problem) => `schema document: ${problem}`));
  problems.push(...recordSemanticProblems(schema, record));
  const recordText = read(ctx.repo, RECORD_PATH);
  if (recordText !== `${JSON.stringify(record, null, 2)}\n`) problems.push('canonical closeout record is not canonical pretty JSON');
  if (sha256(recordText) !== RECORD_SHA256) problems.push('canonical closeout record byte identity drifted');
  const statusText = read(ctx.repo, STATUS_PATH);
  if (statusText !== `${JSON.stringify(status, null, 2)}\n`) problems.push('project status is not canonical pretty JSON');
  problems.push(...statusSemanticProblems(ctx.repo, status));
  problems.push(...sourceIntegrityProblems(ctx.repo, topology.head));
  if (topology.phase === 'REJECTED') problems.push('governance Candidate/merge/successor topology is rejected');
  problems.push(...topology.scopeProblems);

  const evidence = revalidateEvidenceBytes(args['evidence-dir']);
  problems.push(...evidence.problems.map((problem) => `evidence revalidation: ${problem}`));
  const externalSource = revalidateExternalSource(args['unregistered-checkout']);
  problems.push(...externalSource.problems.map((problem) => `external source revalidation: ${problem}`));

  const publication = runPublicationHygiene({ repo: ctx.repo, files: topology.scopePaths });
  if (publication.result !== 'PASS') {
    problems.push(`publication hygiene failed: coverage=${publication.coverage} findings=${publication.findings.length} errors=${publication.errors.length}`);
  }

  const probes = [
    ...recordNegativeProbes(schema, record),
    ...statusNegativeProbes(ctx.repo, status),
    ...topologyNegativeProbes(),
  ];
  for (const probe of probes) {
    if (!probe.matched) problems.push(`${probe.id} ${probe.label} expected ${probe.expected}, got ${probe.actual}${probe.threw ? ' (threw)' : ''}`);
  }

  const implementationFiles = topology.scopePaths.filter((relative) =>
    relative.startsWith('internal/') || relative.startsWith('packages/') ||
    relative.startsWith('schemas/run-') || relative.startsWith('schemas/model/') ||
    relative.startsWith('schemas/orchestration/'));
  const unregisteredFiles = topology.scopePaths.filter((relative) =>
    relative.startsWith('UNREGISTERED/') || relative.startsWith('unregistered/'));
  if (implementationFiles.length > 0) problems.push(`implementation files changed: ${implementationFiles.join(', ')}`);
  if (unregisteredFiles.length > 0) problems.push(`UNREGISTERED files changed: ${unregisteredFiles.join(', ')}`);

  const details = problems.length === 0 ? [
    `ok: ${topology.phase} descends from exact AIPT source ${BASE_COMMIT}/${BASE_TREE}`,
    `ok: canonical ${INTEGRATION_TASK} record validates and binds byte identity ${RECORD_SHA256}`,
    `ok: frozen integration manifest, stage root, local closeout, final root and replay hash are exact (${evidence.mode})`,
    `ok: fixed external package/source identities are exact (${externalSource.mode})`,
    status.tracks?.['AIPT-STANDALONE']?.current_batch === 'AIPT-MVP-B005'
      ? 'ok: read-only integration remains CLOSED/MERGED_CLOSED-without-merge while authorized B005 is the sole WIP1 successor and B006 remains unauthorized/not-started'
      : 'ok: project status is CLOSED/MERGED_CLOSED-without-merge, WIP0, and points to unauthorized/not-started B005',
    'ok: B001-B004 semantics, B004 closeout, batch graph and UNREGISTERED authority projection remain unchanged',
    `ok: all ${probes.length} schema/status/topology probes matched without uncaught validation errors`,
    `ok: publication hygiene scanned ${publication.files_scanned} governance files with complete coverage and zero findings`,
  ] : problems.map((problem) => `FAIL: ${problem}`);

  return {
    result: problems.length === 0 ? 'PASS' : 'FAIL',
    task_id: AUTHORITY_TASK,
    integration_task: INTEGRATION_TASK,
    details,
    lifecycle_phase: topology.phase,
    base_commit: BASE_COMMIT,
    base_tree: BASE_TREE,
    head_commit: topology.head,
    head_tree: topology.headFacts?.tree ?? null,
    branch: topology.branch,
    changed_paths: topology.scopePaths,
    read_only_integration_schema: problems.some((problem) => problem.startsWith('schema')) ? 'FAIL' : 'PASS',
    canonical_closeout_record: problems.some((problem) => problem.includes('closeout record')) ? 'FAIL' : 'PASS',
    project_status_transition: problems.some((problem) => problem.includes('project-status')) ? 'FAIL' : 'PASS',
    historical_lifecycle_integrity: problems.some((problem) => problem.includes('historical') || problem.includes('semantics changed')) ? 'FAIL' : 'PASS',
    evidence_revalidation: { result: evidence.result, mode: evidence.mode },
    external_source_revalidation: { result: externalSource.result, mode: externalSource.mode },
    publication_hygiene: publication,
    governance_only: implementationFiles.length === 0 && unregisteredFiles.length === 0,
    implementation_files_changed: implementationFiles.length,
    unregistered_files_changed: unregisteredFiles.length,
    negative_probe_count: probes.length,
    unexpected_acceptances: probes.filter((probe) => probe.expected === 'REJECT' && probe.actual !== 'REJECT').length,
    uncaught_validation_errors: probes.filter((probe) => probe.threw).length,
    integration_rerun_performed: false,
    remote_real_model_calls: 0,
    local_real_model_calls: 0,
    provider_network_calls: 0,
    qualification_runs_executed: 0,
    hidden_information_leaks: 0,
    public_disclosure_reauthorization_required: true,
    publicly_pushed: false,
    next_batch: status.tracks?.['AIPT-STANDALONE']?.next_serial_batch ?? null,
    next_batch_authorized: status.tracks?.['AIPT-STANDALONE']?.next_batch_authorized ?? null,
    next_batch_started: status.tracks?.['AIPT-STANDALONE']?.next_batch_started ?? null,
  };
}

runAsMain(import.meta.url, 'int001-closeout-authority', run);
