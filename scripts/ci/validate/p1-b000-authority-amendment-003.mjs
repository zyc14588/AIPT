#!/usr/bin/env node
// UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-003 validator.
//
// Keeps frozen semantic validation on exact historical identities and validates
// current/effective state only through generic append-only lifecycle records.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { checkSchemaDocument, validateInstance } from '../lib/json-schema.mjs';
import {
  AUTHORITY_LIFECYCLE_EVENTS,
  AUTHORITY_LIFECYCLE_MODEL,
  AUTHORITY_LIFECYCLE_ORDERING,
  classifySelfCloseoutBootstrap,
  lifecycleRecordSha256,
  resolveEffectiveAuthority,
  selfCloseoutBootstrapExpired,
  validateAppendOnlyRecordSet,
  validateImmutableSemanticIdentity,
  validateLifecyclePolicy,
  validateLifecycleProjection,
} from '../lib/authority-lifecycle.mjs';
import { runAsMain } from '../lib/cli.mjs';

const TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-003';
const AUTHORITY_TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-001';
const BRANCH = `task/${TASK_ID}`;
const BASE_COMMIT = '005ec002e7d8bcccd83d3f3994fddf9da30ff82a';
const BASE_TREE = '1b173e129ccb3df1e1a9bc80385f9dc4f530b6ca';
const A2_TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-002';
const A2_CANDIDATE = '45067db875b7bc3ee657ef117ae13ce55ce2af85';
const A2_TREE = '1b173e129ccb3df1e1a9bc80385f9dc4f530b6ca';
const A2_MERGE = BASE_COMMIT;
const A2_CI_RUN = 33131896928;
const CLOSED_GOVERNANCE_COMMIT = '8d6a438d051fb635e769285215e70536958a8f42';
const CLOSED_GOVERNANCE_TREE = '9ef6f121bd0d9a6484d7cc39a22450250e9ac489';
const A2_MACHINE_SHA = '1ecce52415f4c1fff93383250d2e4df88d8aa381d93e81711681534d59df72e5';
const AUTHORITY_VALIDATOR_SHA = 'c6f0c8e01397200ce15f48bf1fc2412d9db477dddc37d3f99e0478d26956dd0c';
const B001_VALIDATOR_SHA = '319c8d4a3466c20d14e2d5fc74cc246c9b796d36f884fcc39e2b0a25317351c4';
const MIGRATION_SHA = '47f02a5a2129473caa0db5e359a0b294a01b2a96329d9f6fa08ac87cc429c997';

const HUMAN_PATH = 'docs/authority/amendments/UNREGISTERED_AIPT_P1_B000_AUTHORITY_AMENDMENT_003.md';
const MACHINE_PATH = 'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-003.json';
const ARTIFACT_PATH = 'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-003-artifacts.json';
const REGISTRY_PATH = 'docs/authority/registry/authority-lifecycle/registry.json';
const AMENDMENT_SCHEMA_PATH = 'schemas/authority-amendment/v3/aipt-authority-lifecycle-amendment.schema.json';
const RECORD_SCHEMA_PATH = 'schemas/authority-lifecycle/v1/aipt-authority-lifecycle-record.schema.json';
const LIBRARY_PATH = 'scripts/ci/lib/authority-lifecycle.mjs';
const VALIDATOR_PATH = 'scripts/ci/validate/p1-b000-authority-amendment-003.mjs';

const A2_FROZEN = Object.freeze({
  'docs/authority/amendments/UNREGISTERED_AIPT_P1_B000_AUTHORITY_AMENDMENT_002.md':
    'f5c8d2c39d7624ec3709e9413386dca7be85fef59232cd82b8d64cbf835b832d',
  'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-002.json': A2_MACHINE_SHA,
  'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-002-p0-inventory.json':
    'e1b3b1353a1c7cbba570bdc6ae1fdc5ad5b60a25082f6896d37ec50a71afc958',
  'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-002-predecessor-evidence.json':
    '08e9bcc0a1bb5f73686a73cf0ee3d42999e1fd84053982e71662b2b4616f003c',
  'scripts/ci/validate/p1-b000-authority-amendment-002.mjs':
    'c2ef1e825674006f3ef82b2aa65e65b343d8ebc0e9a51725f11e09669abcd383',
});

const PROTECTED = Object.freeze({
  'scripts/ci/validate/p1-b000-authority.mjs': AUTHORITY_VALIDATOR_SHA,
  'scripts/ci/validate/mvp-b001.mjs': B001_VALIDATOR_SHA,
  'internal/storage/postgres/migrations/000002_playtest_queue.sql': MIGRATION_SHA,
});

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

function read(repo, relative) {
  return fs.readFileSync(path.join(repo, relative));
}

function text(repo, relative) {
  return read(repo, relative).toString('utf8');
}

function readJSON(repo, relative) {
  return JSON.parse(text(repo, relative));
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function clone(value) {
  return structuredClone(value);
}

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sorted(values) {
  return [...values].sort((left, right) => Buffer.compare(Buffer.from(left), Buffer.from(right)));
}

function sameSet(left, right) {
  return Array.isArray(left) && Array.isArray(right) && same(sorted(left), sorted(right));
}

function gitCall(repo, args, encoding = 'utf8') {
  return spawnSync('git', ['-C', repo, ...args], {
    encoding,
    maxBuffer: 64 * 1024 * 1024,
  });
}

function gitOut(repo, args) {
  const result = gitCall(repo, args);
  if (result.error || result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${result.error?.message ?? result.stderr.trim()}`);
  }
  return result.stdout.trim();
}

function parentsOf(repo, commit) {
  return gitOut(repo, ['show', '-s', '--format=%P', commit]).split(/\s+/u).filter(Boolean);
}

function gitPathExists(repo, commit, relative) {
  const result = gitCall(repo, ['cat-file', '-e', `${commit}:${relative}`]);
  return !result.error && result.status === 0;
}

function changedPaths(repo, base, target = 'HEAD', includeWorktree = false) {
  const paths = new Set();
  const collect = (result, label) => {
    if (result.error || result.status !== 0) {
      throw new Error(`${label}: ${result.error?.message ?? result.stderr?.toString('utf8').trim()}`);
    }
    for (const item of result.stdout.toString('utf8').split('\0').filter(Boolean)) paths.add(item);
  };
  collect(gitCall(repo, ['diff', '--name-only', '--no-renames', '-z', base, target], null), 'cannot read committed scope');
  if (includeWorktree) {
    collect(gitCall(repo, ['diff', '--name-only', '--no-renames', '-z'], null), 'cannot read worktree scope');
    collect(gitCall(repo, ['diff', '--cached', '--name-only', '--no-renames', '-z'], null), 'cannot read staged scope');
    collect(gitCall(repo, ['ls-files', '--others', '--exclude-standard', '-z'], null), 'cannot read untracked scope');
  }
  return sorted(paths);
}

function schemaProblems(schema, instance, label) {
  const problems = [];
  for (const error of checkSchemaDocument(schema).errors) problems.push(`${label} schema: ${error}`);
  if (problems.length === 0) {
    for (const error of validateInstance(schema, instance).errors) problems.push(`${label}: ${error.message}`);
  }
  return problems;
}

function semanticIdentity({
  taskId = A2_TASK_ID,
  artifactId = A2_TASK_ID,
  artifactPath = 'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-002.json',
  artifactSha = A2_MACHINE_SHA,
  candidate = A2_CANDIDATE,
  tree = A2_TREE,
  snapshotState = 'CANDIDATE_FROZEN',
  snapshotAccepted = false,
} = {}) {
  return {
    task_id: taskId,
    artifact_id: artifactId,
    artifact_path: artifactPath,
    artifact_sha256: artifactSha,
    candidate_commit: candidate,
    candidate_tree: tree,
    semantic_snapshot_state: snapshotState,
    semantic_snapshot_accepted: snapshotAccepted,
  };
}

function lifecycleRecord({ id, taskId, identity, event, sequence, predecessor, basisTask, evidence, relative }) {
  return {
    schema: 'aipt.public.authority-lifecycle-record/v1',
    record_id: id,
    task_id: taskId,
    semantic_artifact_identity: identity,
    event,
    event_sequence: sequence,
    predecessor_lifecycle_record: predecessor,
    authority_basis: {
      model_id: AUTHORITY_LIFECYCLE_MODEL,
      authorized_by_task: basisTask,
      authorization_kind: taskId === TASK_ID ? 'SELF_CLOSEOUT_BOOTSTRAP' : 'ACCEPTED_LIFECYCLE_MODEL',
    },
    event_evidence: evidence,
    record_identity: {
      identity_scheme: 'IMMUTABLE_GIT_BLOB_AT_ACCEPTED_COMMIT',
      path: relative,
      accepted_commit_source: 'CONTAINING_GIT_COMMIT',
      append_only: true,
    },
    created_by_task: basisTask,
    provenance: {
      source_task: taskId,
      source_commit: event === 'MERGED' ? identity.candidate_commit : A2_MERGE,
      source_tree: identity.candidate_tree,
      record_creation_authority: basisTask,
      record_creator_task: basisTask,
      historical_evidence_claimed_only_if_proven: true,
    },
    effective: event === 'CLOSED',
  };
}

function syntheticChain({
  identity = semanticIdentity(),
  taskId = identity.task_id,
  slug = 'unregistered-aipt-p1-b000-authority-amendment-002',
  mergeCommit = A2_MERGE,
  mergeTree = identity.candidate_tree,
  mergeParents = ['8d6a438d051fb635e769285215e70536958a8f42', identity.candidate_commit],
  runId = A2_CI_RUN,
  basisTask = TASK_ID,
  acceptanceCommit = 'c'.repeat(40),
} = {}) {
  const root = `docs/authority/registry/authority-lifecycle/records/${slug}`;
  const ids = [
    `${taskId}-LIFECYCLE-001-MERGED`,
    `${taskId}-LIFECYCLE-002-POST-MERGE-VERIFIED`,
    `${taskId}-LIFECYCLE-003-CLOSED`,
  ];
  const merged = lifecycleRecord({
    id: ids[0], taskId, identity, event: 'MERGED', sequence: 1, predecessor: null, basisTask,
    relative: `${root}/001-merged.json`,
    evidence: { kind: 'GIT_MERGE', merge_identity: { commit: mergeCommit, tree: mergeTree, parents: mergeParents } },
  });
  const post = lifecycleRecord({
    id: ids[1], taskId, identity, event: 'POST_MERGE_VERIFIED', sequence: 2,
    predecessor: { record_id: merged.record_id, record_sha256: lifecycleRecordSha256(merged) }, basisTask,
    relative: `${root}/002-post-merge-verified.json`,
    evidence: {
      kind: 'POST_MERGE_CI',
      post_merge_evidence: {
        run_id: runId, head_sha: mergeCommit, conclusion: 'success', jobs_passed: 5, jobs_failed: 0, jobs_skipped: 0,
      },
    },
  });
  const closed = lifecycleRecord({
    id: ids[2], taskId, identity, event: 'CLOSED', sequence: 3,
    predecessor: { record_id: post.record_id, record_sha256: lifecycleRecordSha256(post) }, basisTask,
    relative: `${root}/003-closed.json`,
    evidence: {
      kind: 'GOVERNANCE_CLOSEOUT',
      closeout_identity: { commit_source: 'CONTAINING_GIT_COMMIT', governance_only: true, owner_authorized: true },
    },
  });
  const records = [merged, post, closed];
  const recordAcceptance = Object.fromEntries(records.map((record) => [record.record_id, {
    accepted: true,
    commit: acceptanceCommit,
    commit_ordinal: 1,
    first_parent_ancestry: true,
    path: record.record_identity.path,
    introduced_sha256: lifecycleRecordSha256(record),
    current_sha256: lifecycleRecordSha256(record),
    canonical_record_sha256: lifecycleRecordSha256(record),
  }]));
  const authorityBasis = Object.fromEntries(records.map((record) => [record.record_id, true]));
  const evidenceCatalogue = {
    merge_commits: {
      [mergeCommit]: { tree: mergeTree, parents: mergeParents, accepted_ancestry: true },
    },
    post_merge_runs: {
      [String(runId)]: post.event_evidence.post_merge_evidence,
    },
    closeout_records: {
      [closed.record_id]: { commit: acceptanceCommit, governance_only: true, owner_authorized: true },
    },
  };
  return { identity, records, ids, recordAcceptance, authorityBasis, evidenceCatalogue };
}

function resolutionInput(chain, count = chain.records.length, overrides = {}) {
  const records = chain.records.slice(0, count);
  const ids = records.map((record) => record.record_id);
  return {
    semantic_artifact_identity: chain.identity,
    records,
    policy: LIFECYCLE_POLICY,
    record_acceptance: chain.recordAcceptance,
    authority_basis_acceptance: chain.authorityBasis,
    evidence_catalogue: chain.evidenceCatalogue,
    expected_accepted_record_ids: ids,
    expected_lifecycle_state: count === 0 ? 'SEMANTIC_ONLY' : AUTHORITY_LIFECYCLE_EVENTS[count - 1],
    ...overrides,
  };
}

function bootstrapPolicy(amendment) {
  const bootstrap = amendment.self_closeout_bootstrap;
  return {
    task_id: TASK_ID,
    base_commit: BASE_COMMIT,
    candidate_allowed_paths: bootstrap.candidate_allowed_paths,
    closeout_allowed_paths: bootstrap.closeout_allowed_paths,
  };
}

function validBootstrapFacts(amendment, lifecycleClass = 'VALID_DIRECT_SELF_CLOSEOUT') {
  const candidate = {
    commit: 'd'.repeat(40), tree: 'e'.repeat(40), parent: BASE_COMMIT,
    ordinary_commit_count: 1, contains_merge: false,
    changed_paths: amendment.self_closeout_bootstrap.candidate_allowed_paths,
  };
  const merge = {
    commit: 'f'.repeat(40), tree: candidate.tree, parent_count: 2,
    first_parent: BASE_COMMIT, second_parent: candidate.commit,
    candidate_tree_preserved: true, accepted: true, post_merge_verified: true,
  };
  const successor = {
    depth: 1, parent_count: 1, parent: merge.commit,
    changed_paths: amendment.self_closeout_bootstrap.closeout_allowed_paths,
    governance_only: true, semantic_mutation: false, business_code_changed: false,
    other_task_records: false, record_count: 3,
  };
  return {
    task_id: TASK_ID,
    lifecycle_class: lifecycleClass,
    closed_before_commit: false,
    bootstrap_use_count: 0,
    candidate,
    merge: lifecycleClass === 'VALID_CANDIDATE' ? null : merge,
    successor: lifecycleClass === 'VALID_DIRECT_SELF_CLOSEOUT' ? successor : null,
  };
}

function negativeProbeResults(amendment, recordSchema) {
  const results = [];
  const add = (id, matched, observed) => results.push({ id, matched: matched === true, observed });
  const chain = syntheticChain();
  const resolve = (input) => resolveEffectiveAuthority(input);
  const noRecords = resolve(resolutionInput(chain, 0));
  const merged = resolve(resolutionInput(chain, 1));
  const post = resolve(resolutionInput(chain, 2));
  const full = resolve(resolutionInput(chain));
  add('A3-N01', noRecords.result === 'ACCEPT' && !noRecords.effective && noRecords.lifecycle_state === 'SEMANTIC_ONLY', noRecords.lifecycle_state);
  add('A3-N02', merged.result === 'ACCEPT' && !merged.effective && merged.lifecycle_state === 'MERGED', merged.lifecycle_state);
  add('A3-N03', post.result === 'ACCEPT' && !post.effective && post.lifecycle_state === 'POST_MERGE_VERIFIED', post.lifecycle_state);
  add('A3-N04', full.result === 'ACCEPT' && full.effective && full.lifecycle_state === 'CLOSED', full.lifecycle_state);

  const postFirst = clone(chain);
  postFirst.records = [postFirst.records[1]];
  add('A3-N05', resolve({ ...resolutionInput(postFirst), expected_accepted_record_ids: [postFirst.records[0].record_id] }).result === 'REJECT', 'REJECT');
  const closeBeforePost = clone(chain);
  closeBeforePost.records = [closeBeforePost.records[0], closeBeforePost.records[2]];
  add('A3-N06', resolve({ ...resolutionInput(closeBeforePost), expected_accepted_record_ids: closeBeforePost.records.map((v) => v.record_id) }).result === 'REJECT', 'REJECT');
  const duplicateClosed = clone(chain);
  const extraClosed = clone(duplicateClosed.records[2]);
  extraClosed.record_id = `${extraClosed.record_id}-DUPLICATE`;
  extraClosed.event_sequence = 4;
  duplicateClosed.records.push(extraClosed);
  duplicateClosed.recordAcceptance[extraClosed.record_id] = clone(duplicateClosed.recordAcceptance[duplicateClosed.records[2].record_id]);
  duplicateClosed.authorityBasis[extraClosed.record_id] = true;
  add('A3-N07', resolve(resolutionInput(duplicateClosed)).result === 'REJECT', 'REJECT');

  const wrongCandidate = clone(chain);
  wrongCandidate.records[1].semantic_artifact_identity.candidate_commit = '0'.repeat(40);
  add('A3-N08', resolve(resolutionInput(wrongCandidate)).result === 'REJECT', 'REJECT');
  const wrongTree = clone(chain);
  wrongTree.records[0].semantic_artifact_identity.candidate_tree = '0'.repeat(40);
  add('A3-N09', resolve(resolutionInput(wrongTree)).result === 'REJECT', 'REJECT');
  const unrelatedTask = clone(chain);
  unrelatedTask.records[1].task_id = 'UNRELATED-AUTHORITY-TASK';
  add('A3-N10', resolve(resolutionInput(unrelatedTask)).result === 'REJECT', 'REJECT');
  const fork = clone(chain);
  const forkRecord = clone(fork.records[1]);
  forkRecord.record_id = `${forkRecord.record_id}-FORK`;
  fork.records.push(forkRecord);
  fork.recordAcceptance[forkRecord.record_id] = clone(fork.recordAcceptance[fork.records[1].record_id]);
  fork.authorityBasis[forkRecord.record_id] = true;
  add('A3-N11', resolve(resolutionInput(fork)).result === 'REJECT', 'REJECT');
  const nondeterministicPolicy = clone(LIFECYCLE_POLICY);
  nondeterministicPolicy.ordering.primary = 'filesystem_mtime_DESCENDING';
  add('A3-N12', resolve(resolutionInput(chain, 3, { policy: nondeterministicPolicy })).result === 'REJECT', 'REJECT');
  const mutatedSemantic = clone(chain.identity);
  mutatedSemantic.artifact_sha256 = '0'.repeat(64);
  add('A3-N13', validateImmutableSemanticIdentity(chain.identity, mutatedSemantic).result === 'REJECT', 'REJECT');
  add('A3-N14', chain.identity.semantic_snapshot_accepted === false && full.effective === true, full.effective ? 'ACCEPT' : 'REJECT');
  const optimisticIdentity = clone(chain.identity);
  optimisticIdentity.semantic_snapshot_accepted = true;
  const optimistic = syntheticChain({ identity: optimisticIdentity });
  const optimisticNoRecords = resolve(resolutionInput(optimistic, 0));
  add('A3-N15', optimisticNoRecords.result === 'ACCEPT' && !optimisticNoRecords.effective, 'NOT_EFFECTIVE');
  add('A3-N16', noRecords.result === 'ACCEPT' && !noRecords.effective, 'NOT_ACCEPTED');
  const badProjection = { canonical_source: 'ACCEPTED_APPEND_ONLY_LIFECYCLE_RECORD_CHAIN', lifecycle_state: 'MERGED', effective: false, lifecycle_record_ids: full.ordered_record_ids };
  add('A3-N17', validateLifecycleProjection(badProjection, full).result === 'REJECT', 'REJECT');
  const rewritten = clone(chain.records);
  rewritten[0].provenance.source_commit = '0'.repeat(40);
  const appendDelete = validateAppendOnlyRecordSet(chain.records, chain.records.slice(0, 2));
  const appendRewrite = validateAppendOnlyRecordSet(chain.records, rewritten);
  add('A3-N18', appendDelete.result === 'REJECT' && appendRewrite.result === 'REJECT', 'REJECT');

  const bootstrap = bootstrapPolicy(amendment);
  const directFacts = validBootstrapFacts(amendment);
  add('A3-N19', classifySelfCloseoutBootstrap(directFacts, bootstrap).result === 'ACCEPT', 'ACCEPT');
  const multiHop = validBootstrapFacts(amendment, 'MULTI_HOP_SUCCESSOR');
  multiHop.successor = { ...directFacts.successor, depth: 2 };
  add('A3-N20', classifySelfCloseoutBootstrap(multiHop, bootstrap).result === 'REJECT', 'REJECT');
  const semanticMutation = validBootstrapFacts(amendment);
  semanticMutation.successor.semantic_mutation = true;
  add('A3-N21', classifySelfCloseoutBootstrap(semanticMutation, bootstrap).result === 'REJECT', 'REJECT');
  const business = validBootstrapFacts(amendment);
  business.successor.business_code_changed = true;
  add('A3-N22', classifySelfCloseoutBootstrap(business, bootstrap).result === 'REJECT', 'REJECT');
  const twice = validBootstrapFacts(amendment);
  twice.bootstrap_use_count = 1;
  add('A3-N23', classifySelfCloseoutBootstrap(twice, bootstrap).result === 'REJECT', 'REJECT');
  const afterClosed = validBootstrapFacts(amendment);
  afterClosed.closed_before_commit = true;
  const a3Identity = semanticIdentity({
    taskId: TASK_ID,
    artifactId: TASK_ID,
    artifactPath: MACHINE_PATH,
    artifactSha: '6'.repeat(64),
    candidate: 'd'.repeat(40),
    tree: 'e'.repeat(40),
  });
  const a3Chain = syntheticChain({
    identity: a3Identity,
    slug: 'unregistered-aipt-p1-b000-authority-amendment-003',
    mergeCommit: 'f'.repeat(40),
    mergeTree: a3Identity.candidate_tree,
    mergeParents: [BASE_COMMIT, a3Identity.candidate_commit],
    runId: 333,
  });
  const a3Closed = resolve(resolutionInput(a3Chain));
  add('A3-N24', classifySelfCloseoutBootstrap(afterClosed, bootstrap).result === 'REJECT' &&
    selfCloseoutBootstrapExpired(TASK_ID, a3Closed) === true, 'REJECT');

  add('A3-N25', full.result === 'ACCEPT' && full.effective && chain.identity.candidate_commit === A2_CANDIDATE, 'ACCEPT');
  const wrongMerge = clone(chain);
  wrongMerge.records[0].event_evidence.merge_identity.commit = '0'.repeat(40);
  add('A3-N26', resolve(resolutionInput(wrongMerge)).result === 'REJECT', 'REJECT');
  const fakePost = clone(chain);
  fakePost.records[1].event_evidence.post_merge_evidence.run_id = 1;
  add('A3-N27', resolve(resolutionInput(fakePost)).result === 'REJECT', 'REJECT');
  const falseClosed = resolutionInput(chain, 2, { expected_lifecycle_state: 'CLOSED', expected_accepted_record_ids: chain.ids });
  add('A3-N28', resolve(falseClosed).result === 'REJECT', 'REJECT');
  add('A3-N29', full.effective === true && noRecords.effective === false, 'LIFECYCLE_CHAIN_USED');

  const futureIdentity = semanticIdentity({
    taskId: 'FUTURE-GOVERNANCE-AUTHORITY-AMENDMENT-004',
    artifactId: 'FUTURE-GOVERNANCE-AUTHORITY-AMENDMENT-004',
    artifactPath: 'docs/authority/registry/future-governance-authority-amendment-004.json',
    artifactSha: '1'.repeat(64), candidate: '2'.repeat(40), tree: '3'.repeat(40),
  });
  const future = syntheticChain({
    identity: futureIdentity,
    slug: 'future-governance-authority-amendment-004',
    mergeCommit: '4'.repeat(40), mergeTree: futureIdentity.candidate_tree,
    mergeParents: ['5'.repeat(40), futureIdentity.candidate_commit], runId: 444,
  });
  const futureResolution = resolve(resolutionInput(future));
  add('A3-N30', futureResolution.result === 'ACCEPT' && futureResolution.effective, 'ACCEPT');

  const schemaValid = chain.records.every((record) => validateInstance(recordSchema, record).valid);
  if (!schemaValid) results.push({ id: 'A3-SCHEMA-SYNTHETIC', matched: false, observed: 'REJECT' });
  return results;
}

function validateMachineAuthority(amendment, registry) {
  const problems = [];
  const canonical = amendment.canonical_lifecycle_authority;
  const a2 = amendment.authority_basis?.amendment_002;
  const recovery = amendment.amendment_002_recovery;
  const bootstrap = amendment.self_closeout_bootstrap;
  const closedReplay = amendment.validation_contract?.closed_governance_replay_target;
  if (amendment.amendment_id !== TASK_ID || amendment.amendment_sequence !== 3 ||
      amendment.authority_task_id !== AUTHORITY_TASK_ID || amendment.authority_state !== 'CANDIDATE_FROZEN' ||
      amendment.semantic_snapshot_accepted !== false) problems.push('Amendment-003 root semantic snapshot identity drifted');
  if (canonical?.model_id !== AUTHORITY_LIFECYCLE_MODEL || canonical?.truth_source !== 'ACCEPTED_APPEND_ONLY_LIFECYCLE_RECORD_CHAIN' ||
      canonical?.semantic_fields_are_snapshot_metadata !== true || canonical?.semantic_artifact_mutation_permitted !== false ||
      canonical?.project_status_is_projection_only !== true || canonical?.latest_file_wins !== false ||
      canonical?.current_main_descendant_implies_acceptance !== false || canonical?.conflict_policy !== 'FAIL_CLOSED') {
    problems.push('canonical semantic/lifecycle separation or truth source drifted');
  }
  if (a2?.candidate !== A2_CANDIDATE || a2?.candidate_tree !== A2_TREE || a2?.merge !== A2_MERGE ||
      a2?.merge_tree !== A2_TREE || a2?.merge_ci?.run_id !== A2_CI_RUN || a2?.merge_ci?.head_sha !== A2_MERGE ||
      a2?.merge_ci?.conclusion !== 'success' || a2?.merge_ci?.jobs_passed !== 5 ||
      a2?.merged !== true || a2?.post_merge_verified !== true || a2?.closed !== false) {
    problems.push('Amendment-002 exact merged/post-merge/not-closed facts drifted');
  }
  if (recovery?.semantic_artifact_sha256 !== A2_MACHINE_SHA || recovery?.semantic_candidate_commit !== A2_CANDIDATE ||
      recovery?.semantic_candidate_tree !== A2_TREE || recovery?.merge_commit !== A2_MERGE || recovery?.merge_tree !== A2_TREE ||
      recovery?.post_merge_ci_run !== A2_CI_RUN || recovery?.semantic_mutation_permitted !== false ||
      recovery?.current_closeout_claim !== false || recovery?.recovery_uses_amendment_003_bootstrap !== false ||
      !sameSet(recovery?.recovery_record_paths, [
        'docs/authority/registry/authority-lifecycle/records/unregistered-aipt-p1-b000-authority-amendment-002/001-merged.json',
        'docs/authority/registry/authority-lifecycle/records/unregistered-aipt-p1-b000-authority-amendment-002/002-post-merge-verified.json',
        'docs/authority/registry/authority-lifecycle/records/unregistered-aipt-p1-b000-authority-amendment-002/003-closed.json',
      ])) problems.push('Amendment-002 recovery identity/path/authorization contract drifted');
  if (bootstrap?.rule_id !== 'AMENDMENT_003_SELF_CLOSEOUT_BOOTSTRAP' || bootstrap?.task_id !== TASK_ID ||
      bootstrap?.base_commit !== BASE_COMMIT || bootstrap?.candidate_branch !== BRANCH ||
      !same(bootstrap?.eligible_classes, ['VALID_CANDIDATE', 'VALID_LEGAL_MERGE', 'VALID_DIRECT_SELF_CLOSEOUT']) ||
      bootstrap?.direct_child_depth !== 1 || bootstrap?.governance_only !== true || bootstrap?.single_use !== true ||
      bootstrap?.use_count_before_closeout !== 0 || bootstrap?.permission_expires_when !== 'AMENDMENT_003_CLOSED' ||
      bootstrap?.post_closeout_bootstrap_use !== 'REJECT' || bootstrap?.other_task_use !== 'REJECT' ||
      bootstrap?.semantic_mutation !== 'REJECT' || bootstrap?.business_change !== 'REJECT') {
    problems.push('Amendment-003 self-closeout bootstrap is not exact, direct, single-use and terminal');
  }
  if (closedReplay?.commit !== CLOSED_GOVERNANCE_COMMIT || closedReplay?.tree !== CLOSED_GOVERNANCE_TREE ||
      !same(closedReplay?.gates, ['repair', 'closeout', 'reverification']) ||
      closedReplay?.current_successor_head_permitted !== false ||
      closedReplay?.github_execution_identity_inherited !== false) {
    problems.push('closed-governance exact accepted-target replay contract drifted');
  }
  const scope = amendment.scope;
  if (scope?.governance_only !== true || scope?.business_code_changed !== false || scope?.p0_validator_modified !== false ||
      scope?.amendment_002_modified !== false || scope?.authority_validator_modified !== false ||
      scope?.b001_validator_modified !== false || scope?.playtest_package_schema_modified !== false ||
      scope?.runtime_adapter_schema_modified !== false || scope?.historical_migration_modified !== false ||
      scope?.run_core_implemented !== false || scope?.agent_orchestration_implemented !== false ||
      scope?.real_model_gateway_implemented !== false || scope?.real_model_calls !== 0 || scope?.real_playtest_executed !== false) {
    problems.push('governance-only scope or runtime boundary drifted');
  }
  if (amendment.lifecycle?.accepted !== false || amendment.lifecycle?.merge_authorized !== false ||
      amendment.lifecycle?.self_closeout_authorized !== false || amendment.lifecycle?.amendment_002_closeout_authorized !== false ||
      amendment.lifecycle?.b000_implementation_started !== false || amendment.lifecycle?.next_task_authorized !== false) {
    problems.push('candidate stop boundary drifted');
  }
  if (registry?.model_id !== AUTHORITY_LIFECYCLE_MODEL || registry?.canonical_truth_source !== 'ACCEPTED_APPEND_ONLY_LIFECYCLE_RECORD_CHAIN' ||
      registry?.canonical_activation?.authorized_by_task !== TASK_ID || registry?.canonical_activation?.requires_state !== 'CLOSED' ||
      registry?.record_contract?.file_presence_alone_is_acceptance !== false ||
      registry?.record_contract?.acceptance_requires_containing_commit_on_accepted_first_parent_ancestry !== true ||
      !same(registry?.ordering, AUTHORITY_LIFECYCLE_ORDERING) || registry?.closed_terminal !== true ||
      registry?.projection_policy?.projection_is_independent_authority !== false ||
      registry?.legacy_adapter_policy?.parallel_mutable_lifecycle_source !== false ||
      registry?.general_purpose?.task_specific_framework_branching !== false) {
    problems.push('generic lifecycle registry, activation, ordering or single-source policy drifted');
  }
  if (!Array.isArray(registry?.historical_migration_anchors) || registry.historical_migration_anchors.length !== 3 ||
      registry.historical_migration_anchors.some((anchor) => anchor.new_event_claim_fabricated !== false)) {
    problems.push('historical migration anchors are incomplete or fabricate events');
  }
  return problems;
}

function validateFrozenFiles(repo) {
  const problems = [];
  for (const [relative, expected] of Object.entries({ ...A2_FROZEN, ...PROTECTED })) {
    try {
      const actual = sha256(read(repo, relative));
      if (actual !== expected) problems.push(`${relative} SHA-256 drifted: ${actual}`);
      const baseBlob = gitCall(repo, ['show', `${BASE_COMMIT}:${relative}`], null);
      if (baseBlob.error || baseBlob.status !== 0 || sha256(baseBlob.stdout) !== expected) {
        problems.push(`${relative} exact Base blob identity is not reproducible`);
      }
    } catch (error) {
      problems.push(`${relative} unreadable: ${error.message}`);
    }
  }
  return problems;
}

function validateArtifactManifest(repo, manifest) {
  const problems = [];
  if (manifest?.schema !== 'aipt.public.authority-amendment-artifact-manifest/v3' || manifest?.task_id !== TASK_ID ||
      !Array.isArray(manifest?.artifacts) || manifest.artifacts.length < 7) {
    return ['Amendment-003 artifact manifest root is invalid'];
  }
  const paths = manifest.artifacts.map((entry) => entry.path);
  if (new Set(paths).size !== paths.length) problems.push('Amendment-003 artifact manifest has duplicate paths');
  for (const entry of manifest.artifacts) {
    try {
      if (!/^[0-9a-f]{64}$/u.test(entry.sha256) || sha256(read(repo, entry.path)) !== entry.sha256) {
        problems.push(`Amendment-003 artifact hash mismatch: ${entry.path}`);
      }
    } catch (error) {
      problems.push(`Amendment-003 artifact unreadable: ${entry.path}: ${error.message}`);
    }
  }
  return problems;
}

function classifyActualLifecycle(repo, amendment) {
  const problems = [];
  try {
    const head = gitOut(repo, ['rev-parse', 'HEAD']);
    const headTree = gitOut(repo, ['rev-parse', 'HEAD^{tree}']);
    const status = gitOut(repo, ['status', '--porcelain=v1', '--untracked-files=all']);
    const branchResult = gitCall(repo, ['branch', '--show-current']);
    const githubBranch = process.env.GITHUB_REF?.startsWith('refs/heads/')
      ? process.env.GITHUB_REF.slice('refs/heads/'.length)
      : '';
    const branch = (process.env.GITHUB_HEAD_REF || githubBranch || branchResult.stdout || '').trim();
    const policy = bootstrapPolicy(amendment);
    const githubPr = process.env.GITHUB_EVENT_NAME === 'pull_request';
    let phase = 'UNKNOWN';
    let classification = null;
    let changed = [];
    let candidate = null;
    let candidateTree = null;
    let merge = null;
    let closeoutCommit = null;

    if (head === BASE_COMMIT && status !== '') {
      phase = 'WORKTREE_STAGE';
      changed = changedPaths(repo, BASE_COMMIT, 'HEAD', true);
      const facts = validBootstrapFacts(amendment, 'VALID_CANDIDATE');
      facts.candidate = {
        ...facts.candidate, commit: 'd'.repeat(40), tree: 'e'.repeat(40), changed_paths: changed,
      };
      classification = classifySelfCloseoutBootstrap(facts, policy);
      if (branch !== BRANCH) problems.push(`worktree stage branch must be ${BRANCH}`);
    } else {
      const headParents = parentsOf(repo, head);
      if (githubPr && headParents.length === 2 && headParents[0] === BASE_COMMIT) {
        phase = 'CANDIDATE_PR_CHECK';
        candidate = headParents[1];
      } else if (headParents.length === 1 && headParents[0] === BASE_COMMIT) {
        phase = 'VALID_CANDIDATE';
        candidate = head;
      } else if (headParents.length === 2 && headParents[0] === BASE_COMMIT) {
        phase = 'VALID_LEGAL_MERGE';
        candidate = headParents[1];
        merge = head;
      } else if (headParents.length === 1) {
        const possibleMerge = headParents[0];
        const mergeParents = parentsOf(repo, possibleMerge);
        if (mergeParents.length === 2 && mergeParents[0] === BASE_COMMIT) {
          phase = 'VALID_DIRECT_SELF_CLOSEOUT';
          merge = possibleMerge;
          candidate = mergeParents[1];
          closeoutCommit = head;
        } else {
          const mergeList = gitOut(repo, ['rev-list', '--first-parent', '--merges', '--reverse', `${BASE_COMMIT}..${head}`])
            .split('\n').filter(Boolean);
          const acceptedMerge = mergeList.find((commit) => {
            const parents = parentsOf(repo, commit);
            return parents.length === 2 && parents[0] === BASE_COMMIT &&
              parentsOf(repo, parents[1]).length === 1 && parentsOf(repo, parents[1])[0] === BASE_COMMIT;
          });
          if (acceptedMerge) {
            const successors = gitOut(repo, ['rev-list', '--first-parent', '--reverse', `${acceptedMerge}..${head}`])
              .split('\n').filter(Boolean);
            const direct = successors[0] ?? null;
            const directParents = direct ? parentsOf(repo, direct) : [];
            const directPaths = direct ? changedPaths(repo, acceptedMerge, direct) : [];
            if (successors.length > 1 && directParents.length === 1 && directParents[0] === acceptedMerge &&
                sameSet(directPaths, amendment.self_closeout_bootstrap.closeout_allowed_paths) &&
                amendment.self_closeout_bootstrap.closeout_allowed_paths.every((relative) => gitPathExists(repo, direct, relative))) {
              phase = 'BOOTSTRAP_EXPIRED';
              merge = acceptedMerge;
              candidate = parentsOf(repo, acceptedMerge)[1];
              closeoutCommit = direct;
            }
          }
        }
      }
      if (!candidate) problems.push('checkout is not the Amendment-003 candidate, legal merge or direct self-closeout');
      else {
        const candidateParents = parentsOf(repo, candidate);
        candidateTree = gitOut(repo, ['rev-parse', `${candidate}^{tree}`]);
        changed = changedPaths(repo, BASE_COMMIT, candidate);
        const candidateFacts = {
          commit: candidate, tree: candidateTree, parent: candidateParents[0] ?? null,
          ordinary_commit_count: Number(gitOut(repo, ['rev-list', '--count', `${BASE_COMMIT}..${candidate}`])),
          contains_merge: gitOut(repo, ['rev-list', '--merges', `${BASE_COMMIT}..${candidate}`]) !== '',
          changed_paths: changed,
        };
        if (phase === 'VALID_CANDIDATE' || phase === 'CANDIDATE_PR_CHECK') {
          classification = classifySelfCloseoutBootstrap({
            task_id: TASK_ID, lifecycle_class: 'VALID_CANDIDATE', closed_before_commit: false,
            bootstrap_use_count: 0, candidate: candidateFacts, merge: null, successor: null,
          }, policy);
          if (branch !== BRANCH) problems.push(`candidate branch must be ${BRANCH}`);
        } else if (phase === 'VALID_LEGAL_MERGE') {
          classification = classifySelfCloseoutBootstrap({
            task_id: TASK_ID, lifecycle_class: 'VALID_LEGAL_MERGE', closed_before_commit: false,
            bootstrap_use_count: 0, candidate: candidateFacts,
            merge: {
              commit: merge, tree: headTree, parent_count: 2, first_parent: BASE_COMMIT,
              second_parent: candidate, candidate_tree_preserved: headTree === candidateTree,
              accepted: true, post_merge_verified: false,
            }, successor: null,
          }, policy);
        } else if (phase === 'VALID_DIRECT_SELF_CLOSEOUT') {
          const mergeTree = gitOut(repo, ['rev-parse', `${merge}^{tree}`]);
          const closeoutPaths = changedPaths(repo, merge, head);
          classification = classifySelfCloseoutBootstrap({
            task_id: TASK_ID, lifecycle_class: 'VALID_DIRECT_SELF_CLOSEOUT', closed_before_commit: false,
            bootstrap_use_count: 0, candidate: candidateFacts,
            merge: {
              commit: merge, tree: mergeTree, parent_count: 2, first_parent: BASE_COMMIT,
              second_parent: candidate, candidate_tree_preserved: mergeTree === candidateTree,
              accepted: true, post_merge_verified: true,
            },
            successor: {
              depth: 1, parent_count: 1, parent: merge, changed_paths: closeoutPaths,
              governance_only: true,
              semantic_mutation: closeoutPaths.some((relative) => amendment.self_closeout_bootstrap.forbidden_exact_paths.includes(relative)),
              business_code_changed: closeoutPaths.some((relative) => /^(?:internal|cmd|packages)\//u.test(relative)),
              other_task_records: closeoutPaths.some((relative) => !amendment.self_closeout_bootstrap.closeout_allowed_paths.includes(relative)),
              record_count: closeoutPaths.length,
            },
          }, policy);
        } else if (phase === 'BOOTSTRAP_EXPIRED') {
          classification = { result: 'ACCEPT', classification: 'BOOTSTRAP_EXPIRED', problems: [] };
        }
      }
      if (status !== '') problems.push('frozen candidate/merge/closeout checkout is not clean');
    }
    if (classification?.result !== 'ACCEPT') problems.push(...(classification?.problems ?? ['bootstrap topology was not classified']));
    return { phase, classification: classification?.classification ?? 'REJECTED', changed_paths: changed, candidate, candidate_tree: candidateTree, merge, closeout_commit: closeoutCommit, head, head_tree: headTree, problems };
  } catch (error) {
    return { phase: 'UNKNOWN', classification: 'REJECTED', changed_paths: [], candidate: null, candidate_tree: null, merge: null, closeout_commit: null, head: null, head_tree: null, problems: [error.message] };
  }
}

function validateActualA3LifecycleRecords(repo, lifecycle, recordSchema) {
  const problems = [];
  try {
    const closeoutCommit = lifecycle.closeout_commit;
    if (!closeoutCommit || !lifecycle.merge || !lifecycle.candidate || !lifecycle.candidate_tree) {
      return { result: 'REJECT', effective: false, problems: ['actual A3 lifecycle topology is incomplete'] };
    }
    const relativePaths = [
      'docs/authority/registry/authority-lifecycle/records/unregistered-aipt-p1-b000-authority-amendment-003/001-merged.json',
      'docs/authority/registry/authority-lifecycle/records/unregistered-aipt-p1-b000-authority-amendment-003/002-post-merge-verified.json',
      'docs/authority/registry/authority-lifecycle/records/unregistered-aipt-p1-b000-authority-amendment-003/003-closed.json',
    ];
    const records = relativePaths.map((relative) => readJSON(repo, relative));
    for (let index = 0; index < records.length; index += 1) {
      for (const error of validateInstance(recordSchema, records[index]).errors) {
        problems.push(`${relativePaths[index]}: ${error.message}`);
      }
    }
    const identity = semanticIdentity({
      taskId: TASK_ID,
      artifactId: TASK_ID,
      artifactPath: MACHINE_PATH,
      artifactSha: sha256(read(repo, MACHINE_PATH)),
      candidate: lifecycle.candidate,
      tree: lifecycle.candidate_tree,
    });
    const expectedIds = [
      `${TASK_ID}-LIFECYCLE-001-MERGED`,
      `${TASK_ID}-LIFECYCLE-002-POST-MERGE-VERIFIED`,
      `${TASK_ID}-LIFECYCLE-003-CLOSED`,
    ];
    if (!same(records.map((record) => record.record_id), expectedIds) ||
        !same(records.map((record) => record.record_identity?.path), relativePaths)) {
      problems.push('actual A3 record IDs or paths are not exact');
    }
    const mergeParents = parentsOf(repo, lifecycle.merge);
    const postEvidence = records[1]?.event_evidence?.post_merge_evidence;
    const recordAcceptance = {};
    for (let index = 0; index < records.length; index += 1) {
      const record = records[index];
      const relative = relativePaths[index];
      const introduced = gitCall(repo, ['show', `${closeoutCommit}:${relative}`], null);
      const current = read(repo, relative);
      if (introduced.error || introduced.status !== 0 || gitPathExists(repo, lifecycle.merge, relative)) {
        problems.push(`${relative} was not newly introduced by the direct closeout commit`);
        continue;
      }
      recordAcceptance[record.record_id] = {
        accepted: true,
        commit: closeoutCommit,
        commit_ordinal: 1,
        first_parent_ancestry: true,
        path: relative,
        introduced_sha256: sha256(introduced.stdout),
        current_sha256: sha256(current),
        canonical_record_sha256: lifecycleRecordSha256(record),
      };
      const expectedSourceCommit = index === 0 ? lifecycle.candidate : lifecycle.merge;
      if (record.created_by_task !== TASK_ID || record.provenance?.source_task !== TASK_ID ||
          record.provenance?.source_commit !== expectedSourceCommit ||
          record.provenance?.source_tree !== lifecycle.candidate_tree ||
          record.authority_basis?.authorized_by_task !== TASK_ID ||
          record.authority_basis?.authorization_kind !== 'SELF_CLOSEOUT_BOOTSTRAP') {
        problems.push(`${relative} creator/authority/source provenance is not exact`);
      }
    }
    const authorityBasis = Object.fromEntries(expectedIds.map((id) => [id, true]));
    const evidenceCatalogue = {
      merge_commits: {
        [lifecycle.merge]: {
          tree: gitOut(repo, ['rev-parse', `${lifecycle.merge}^{tree}`]),
          parents: mergeParents,
          accepted_ancestry: true,
        },
      },
      post_merge_runs: postEvidence && Number.isInteger(postEvidence.run_id)
        ? { [String(postEvidence.run_id)]: postEvidence }
        : {},
      closeout_records: {
        [expectedIds[2]]: { commit: closeoutCommit, governance_only: true, owner_authorized: true },
      },
    };
    const resolution = resolveEffectiveAuthority({
      semantic_artifact_identity: identity,
      records,
      policy: LIFECYCLE_POLICY,
      record_acceptance: recordAcceptance,
      authority_basis_acceptance: authorityBasis,
      evidence_catalogue: evidenceCatalogue,
      expected_accepted_record_ids: expectedIds,
      expected_lifecycle_state: 'CLOSED',
    });
    problems.push(...resolution.problems);
    const closeoutRecords = relativePaths.map((relative) => JSON.parse(
      gitCall(repo, ['show', `${closeoutCommit}:${relative}`]).stdout,
    ));
    const appendOnly = validateAppendOnlyRecordSet(closeoutRecords, records);
    problems.push(...appendOnly.problems);
    if (!selfCloseoutBootstrapExpired(TASK_ID, resolution)) {
      problems.push('A3 CLOSED chain did not permanently expire the bootstrap');
    }
    return {
      result: problems.length === 0 && resolution.result === 'ACCEPT' && resolution.effective ? 'ACCEPT' : 'REJECT',
      effective: problems.length === 0 && resolution.effective,
      resolution,
      problems,
    };
  } catch (error) {
    return { result: 'REJECT', effective: false, problems: [`actual A3 lifecycle record validation failed: ${error.message}`] };
  }
}

function runExactA2SemanticReplay(repo) {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-a3-a2-semantic-'));
  try {
    const cloneResult = spawnSync('git', ['clone', '--no-local', '--no-checkout', repo, target], {
      encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
    });
    if (cloneResult.error || cloneResult.status !== 0) {
      return { result: 'FAIL', problem: `exact A2 clone failed: ${cloneResult.error?.message ?? cloneResult.stderr.trim()}` };
    }
    const checkout = gitCall(target, ['checkout', '--detach', A2_MERGE]);
    if (checkout.error || checkout.status !== 0 || gitOut(target, ['rev-parse', 'HEAD']) !== A2_MERGE ||
        gitOut(target, ['rev-parse', 'HEAD^{tree}']) !== A2_TREE ||
        gitOut(target, ['status', '--porcelain=v1', '--untracked-files=all']) !== '') {
      return { result: 'FAIL', problem: 'exact A2 merge checkout identity is not clean/reproducible' };
    }
    const validator = path.join(target, 'scripts/ci/validate/p1-b000-authority-amendment-002.mjs');
    const execution = spawnSync(process.execPath, [validator, '--repo', target], {
      cwd: target,
      encoding: 'utf8',
      env: Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GITHUB_'))),
      maxBuffer: 64 * 1024 * 1024,
    });
    let report = null;
    try { report = JSON.parse(execution.stdout); } catch { report = null; }
    if (execution.error || execution.signal || execution.status !== 0 || report?.result !== 'PASS' ||
        report?.lifecycle_phase !== 'LEGAL_MERGE' || report?.candidate_commit !== A2_CANDIDATE ||
        report?.candidate_tree !== A2_TREE || report?.required_negative_probes !== 'PASS' ||
        report?.uncaught_validation_errors !== 0) {
      return {
        result: 'FAIL',
        problem: `exact A2 semantic replay failed: ${execution.error?.message ?? (execution.stderr.trim() || report?.details?.filter((item) => item.startsWith('FAIL:')).join('; ') || 'invalid report')}`,
      };
    }
    return { result: 'PASS', target_commit: A2_MERGE, target_tree: A2_TREE, report };
  } catch (error) {
    return { result: 'FAIL', problem: `exact A2 semantic replay error: ${error.message}` };
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
}

function runExactClosedGovernanceReplay(repo, gate) {
  const definitions = {
    repair: 'p1-b000-authority-repair',
    closeout: 'p1-b000-authority-closeout',
    reverification: 'p1-b000-post-merge-reverification',
  };
  const validatorName = definitions[gate];
  if (!validatorName) return { result: 'FAIL', problem: `unsupported closed-governance gate: ${gate}` };
  const target = fs.mkdtempSync(path.join(os.tmpdir(), `aipt-a3-${gate}-`));
  try {
    const cloneResult = spawnSync('git', ['clone', '--no-local', '--no-checkout', repo, target], {
      encoding: 'utf8', maxBuffer: 64 * 1024 * 1024,
    });
    if (cloneResult.error || cloneResult.status !== 0) {
      return { result: 'FAIL', problem: `exact closed-governance clone failed: ${cloneResult.error?.message ?? cloneResult.stderr.trim()}` };
    }
    const checkout = gitCall(target, ['checkout', '--detach', CLOSED_GOVERNANCE_COMMIT]);
    if (checkout.error || checkout.status !== 0 || gitOut(target, ['rev-parse', 'HEAD']) !== CLOSED_GOVERNANCE_COMMIT ||
        gitOut(target, ['rev-parse', 'HEAD^{tree}']) !== CLOSED_GOVERNANCE_TREE ||
        gitOut(target, ['status', '--porcelain=v1', '--untracked-files=all']) !== '') {
      return { result: 'FAIL', problem: 'exact closed-governance target identity is not clean/reproducible' };
    }
    const validator = path.join(target, `scripts/ci/validate/${validatorName}.mjs`);
    const execution = spawnSync(process.execPath, [validator, '--repo', target], {
      cwd: target,
      encoding: 'utf8',
      env: Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GITHUB_'))),
      maxBuffer: 64 * 1024 * 1024,
    });
    let report = null;
    try { report = JSON.parse(execution.stdout); } catch { report = null; }
    const reportIdentityValid = gate === 'reverification'
      ? report?.schema === 'aipt.public.post-merge-reverification-candidate-run/v1' &&
        report?.task_id === 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001' &&
        report?.resolved_target_sha === '169f9bd006dabb88eb653ab09a33b0eef5eadaed' &&
        report?.target_tree === '9cf551e7bc70d4354ca21d62a2bd456ed6f401bb'
      : report?.name === validatorName;
    if (execution.error || execution.signal || execution.status !== 0 || report?.result !== 'PASS' ||
        !reportIdentityValid) {
      return {
        result: 'FAIL',
        problem: `exact closed-governance ${gate} replay failed: ${execution.error?.message ?? (execution.stderr.trim() || report?.details?.filter((item) => item.startsWith('FAIL:')).join('; ') || 'invalid report')}`,
      };
    }
    return {
      result: 'PASS', gate, validator_name: validatorName,
      target_commit: CLOSED_GOVERNANCE_COMMIT, target_tree: CLOSED_GOVERNANCE_TREE,
      report,
    };
  } catch (error) {
    return { result: 'FAIL', problem: `exact closed-governance ${gate} replay error: ${error.message}` };
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
}

export function run(ctx, args = {}) {
  if (typeof args['closed-governance-gate'] === 'string') {
    const replay = runExactClosedGovernanceReplay(ctx.repo, args['closed-governance-gate']);
    return {
      result: replay.result === 'PASS' ? 'PASS' : 'FAIL',
      task_id: TASK_ID,
      details: replay.result === 'PASS'
        ? [`ok: ${replay.gate} validator PASS on exact accepted Base closeout ${CLOSED_GOVERNANCE_COMMIT}/${CLOSED_GOVERNANCE_TREE}`]
        : [`FAIL: ${replay.problem}`],
      closed_governance_replay: replay.result,
      validation_target: replay.result === 'PASS'
        ? { mode: 'EXACT_ACCEPTED_AIPT_BASE_CLOSEOUT', commit: replay.target_commit, tree: replay.target_tree }
        : null,
      merge_eligible: false,
      merge_authorized: false,
    };
  }
  const details = [];
  let pass = true;
  const ok = (message) => details.push(`ok: ${message}`);
  const fail = (message) => { pass = false; details.push(`FAIL: ${message}`); };
  let amendment;
  let registry;
  let manifest;
  let amendmentSchema;
  let recordSchema;
  try {
    amendment = readJSON(ctx.repo, MACHINE_PATH);
    registry = readJSON(ctx.repo, REGISTRY_PATH);
    manifest = readJSON(ctx.repo, ARTIFACT_PATH);
    amendmentSchema = readJSON(ctx.repo, AMENDMENT_SCHEMA_PATH);
    recordSchema = readJSON(ctx.repo, RECORD_SCHEMA_PATH);
  } catch (error) {
    return { result: 'FAIL', task_id: TASK_ID, details: [`FAIL: Amendment-003 input unreadable: ${error.message}`], required_negative_probes: 'NOT_RUN' };
  }

  for (const problem of schemaProblems(amendmentSchema, amendment, 'Amendment-003')) fail(problem);
  if (schemaProblems(amendmentSchema, amendment, 'Amendment-003').length === 0) ok('Amendment-003 schema is supported and machine authority conforms');
  const recordSchemaProblems = checkSchemaDocument(recordSchema).errors;
  for (const problem of recordSchemaProblems) fail(`lifecycle record schema: ${problem}`);
  if (recordSchemaProblems.length === 0) ok('generic lifecycle record schema uses the supported fail-closed subset');
  const policyResult = validateLifecyclePolicy(LIFECYCLE_POLICY);
  for (const problem of policyResult.problems) fail(problem);
  if (policyResult.result === 'ACCEPT') ok('canonical lifecycle policy externalizes state with deterministic ordering');

  const machineProblems = validateMachineAuthority(amendment, registry);
  for (const problem of machineProblems) fail(problem);
  if (machineProblems.length === 0) ok('machine Authority freezes generic lifecycle, projection, recovery and self-closeout contracts');

  const frozenProblems = validateFrozenFiles(ctx.repo);
  for (const problem of frozenProblems) fail(problem);
  if (frozenProblems.length === 0) ok('Amendment-002 semantics/validator, protected validators and historical migration are byte-identical');

  const manifestProblems = validateArtifactManifest(ctx.repo, manifest);
  for (const problem of manifestProblems) fail(problem);
  if (manifestProblems.length === 0) ok(`all ${manifest.artifacts.length} Amendment-003 semantic/infrastructure artifact hashes verified`);

  const lifecycle = classifyActualLifecycle(ctx.repo, amendment);
  for (const problem of lifecycle.problems) fail(`lifecycle: ${problem}`);
  if (lifecycle.problems.length === 0) ok(`${lifecycle.phase} topology and exact stage scope verified`);
  const actualLifecycleRecords = ['VALID_DIRECT_SELF_CLOSEOUT', 'BOOTSTRAP_EXPIRED'].includes(lifecycle.phase)
    ? validateActualA3LifecycleRecords(ctx.repo, lifecycle, recordSchema)
    : { result: 'NOT_APPLICABLE', effective: false, problems: [] };
  for (const problem of actualLifecycleRecords.problems) fail(`actual lifecycle record: ${problem}`);
  if (actualLifecycleRecords.result === 'ACCEPT') {
    ok(`actual Amendment-003 CLOSED record chain is immutable/effective; bootstrap ${lifecycle.phase === 'BOOTSTRAP_EXPIRED' ? 'remains expired' : 'expires now'}`);
  }

  const a2Replay = args['skip-exact-a2-replay'] === true
    ? { result: 'SKIPPED', problem: null }
    : runExactA2SemanticReplay(ctx.repo);
  if (a2Replay.result === 'FAIL') fail(a2Replay.problem);
  else if (a2Replay.result === 'PASS') ok('Amendment-002 semantic validator PASS on exact legal merge identity, not current successor HEAD');

  const a2Recovery = syntheticChain();
  const a2RecoveryResolution = resolveEffectiveAuthority(resolutionInput(a2Recovery));
  if (a2RecoveryResolution.result !== 'ACCEPT' || !a2RecoveryResolution.effective ||
      a2Recovery.identity.artifact_sha256 !== A2_MACHINE_SHA) fail('Amendment-002 exact immutable semantic recovery simulation failed');
  else ok('Amendment-002 exact MERGED/POST_MERGE_VERIFIED/CLOSED recovery simulation resolves effective without semantic mutation');

  const bootstrap = bootstrapPolicy(amendment);
  const candidateSimulation = classifySelfCloseoutBootstrap(validBootstrapFacts(amendment, 'VALID_CANDIDATE'), bootstrap);
  const mergeSimulation = classifySelfCloseoutBootstrap(validBootstrapFacts(amendment, 'VALID_LEGAL_MERGE'), bootstrap);
  const closeoutSimulation = classifySelfCloseoutBootstrap(validBootstrapFacts(amendment), bootstrap);
  if ([candidateSimulation, mergeSimulation, closeoutSimulation].some((result) => result.result !== 'ACCEPT')) {
    fail('Amendment-003 candidate/legal-merge/direct-self-closeout simulation failed');
  } else ok('Amendment-003 candidate, legal merge and direct governance-only self-closeout simulations PASS');

  const probes = negativeProbeResults(amendment, recordSchema);
  for (const probe of probes) if (!probe.matched) fail(`${probe.id} did not match required result (${probe.observed})`);
  const expectedProbeIds = amendment.validation_contract.required_negative_probe_ids;
  const coreProbes = probes.filter((probe) => /^A3-N\d{2}$/u.test(probe.id));
  if (coreProbes.length === 30 && same(coreProbes.map((probe) => probe.id), expectedProbeIds) && coreProbes.every((probe) => probe.matched)) {
    ok('all A3-N01 through A3-N30 lifecycle, recovery, projection and bootstrap probes matched');
  } else fail('required A3-N01 through A3-N30 probe set is incomplete or out of order');

  const packageJSON = readJSON(ctx.repo, 'package.json');
  const aggregate = text(ctx.repo, 'scripts/ci/run-checks.mjs');
  const workflow = text(ctx.repo, '.github/workflows/ci.yml');
  const authorityIndex = text(ctx.repo, 'docs/authority/README.md');
  const wiring = [
    ['package command', packageJSON.scripts?.['check:p1-b000-authority-amendment-003'] === `node ${VALIDATOR_PATH}`],
    ['closed repair package routing', packageJSON.scripts?.['check:p1-b000-authority-repair'] === `node ${VALIDATOR_PATH} --closed-governance-gate repair`],
    ['closed closeout package routing', packageJSON.scripts?.['check:p1-b000-authority-closeout'] === `node ${VALIDATOR_PATH} --closed-governance-gate closeout`],
    ['closed reverification package routing', packageJSON.scripts?.['check:p1-b000-post-merge-reverification'] === `node ${VALIDATOR_PATH} --closed-governance-gate reverification`],
    ['aggregate import/call', aggregate.includes('runP1B000AuthorityAmendment003') && aggregate.includes('runP1B000AuthorityAmendment003(ctx)') && !aggregate.includes('runP1B000AuthorityAmendment002(ctx)')],
    ['focused CI command', workflow.includes('pnpm run check:p1-b000-authority-amendment-003')],
    ['exact A2 CI semantic replay', workflow.includes('A3_A2_SEMANTIC_TARGET') && workflow.includes(A2_MERGE) && workflow.includes(A2_TREE)],
    ['stable closed-governance CI entrypoints', workflow.includes('run: pnpm run check:p1-b000-authority-repair\n') &&
      workflow.includes('run: pnpm run check:p1-b000-authority-closeout\n') &&
      workflow.includes('run: pnpm run check:p1-b000-post-merge-reverification\n')],
    ['authority index', authorityIndex.includes('unregistered-aipt-p1-b000-authority-amendment-003.json') && authorityIndex.includes('UNREGISTERED_AIPT_P1_B000_AUTHORITY_AMENDMENT_003.md') && authorityIndex.includes('registry/authority-lifecycle/registry.json')],
  ];
  for (const [label, present] of wiring) present ? ok(`${label} wiring present`) : fail(`${label} wiring missing`);

  const unresolvedPattern = /<(?:actual|candidate|commit|tree|sha256|run_id|path)>|\bTBD\b|\bTODO\b/u;
  const unresolvedPaths = [HUMAN_PATH, MACHINE_PATH, REGISTRY_PATH, ARTIFACT_PATH];
  const unresolved = unresolvedPaths.filter((relative) => unresolvedPattern.test(text(ctx.repo, relative)));
  for (const relative of unresolved) fail(`unresolved placeholder in ${relative}`);
  if (unresolved.length === 0) ok('Amendment-003 authority artifacts contain no unresolved placeholders');

  const unexpectedAcceptances = coreProbes.filter((probe) => !probe.matched).length;
  const amendment002CurrentBytesModified = Object.entries(A2_FROZEN)
    .some(([relative, expected]) => sha256(read(ctx.repo, relative)) !== expected);
  const syntheticBootstrapModel = {
    candidate_classifier: candidateSimulation.result === 'ACCEPT' ? 'PASS' : 'FAIL',
    legal_merge_classifier: mergeSimulation.result === 'ACCEPT' ? 'PASS' : 'FAIL',
    direct_governance_closeout_classifier: closeoutSimulation.result === 'ACCEPT' ? 'PASS' : 'FAIL',
    multi_hop_successor: probes.find((probe) => probe.id === 'A3-N20')?.matched ? 'REJECTED' : 'FAIL',
    business_successor: probes.find((probe) => probe.id === 'A3-N22')?.matched ? 'REJECTED' : 'FAIL',
    semantic_mutation_successor: probes.find((probe) => probe.id === 'A3-N21')?.matched ? 'REJECTED' : 'FAIL',
    bootstrap_expires_after_closeout: probes.find((probe) => probe.id === 'A3-N24')?.matched === true,
  };
  return {
    result: pass ? 'PASS' : 'FAIL',
    task_id: TASK_ID,
    authority_task_id: AUTHORITY_TASK_ID,
    details,
    lifecycle_phase: lifecycle.phase,
    lifecycle_classification: lifecycle.classification,
    actual_lifecycle_records: actualLifecycleRecords.result,
    candidate_commit: lifecycle.candidate,
    candidate_tree: lifecycle.candidate_tree,
    changed_paths: lifecycle.changed_paths,
    amendment_002_semantic_replay: a2Replay.result,
    amendment_002_recovery_simulation: a2RecoveryResolution.result === 'ACCEPT' && a2RecoveryResolution.effective ? 'PASS' : 'FAIL',
    amendment_002_semantic_artifacts_modified: amendment002CurrentBytesModified,
    self_closeout_model: syntheticBootstrapModel,
    lifecycle_validator: policyResult.result === 'ACCEPT' ? 'PASS' : 'FAIL',
    effective_authority_resolver: a2RecoveryResolution.result === 'ACCEPT' && a2RecoveryResolution.effective ? 'PASS' : 'FAIL',
    required_negative_probes: coreProbes.length === 30 && coreProbes.every((probe) => probe.matched) ? 'PASS' : 'FAIL',
    required_negative_probe_count: coreProbes.length,
    unexpected_acceptances: unexpectedAcceptances,
    uncaught_validation_errors: 0,
    protected_authority_validator_unchanged: sha256(read(ctx.repo, 'scripts/ci/validate/p1-b000-authority.mjs')) === AUTHORITY_VALIDATOR_SHA,
    protected_b001_validator_unchanged: sha256(read(ctx.repo, 'scripts/ci/validate/mvp-b001.mjs')) === B001_VALIDATOR_SHA,
    historical_migration_unchanged: sha256(read(ctx.repo, 'internal/storage/postgres/migrations/000002_playtest_queue.sql')) === MIGRATION_SHA,
    business_code_changed: false,
    b000_implementation_started: false,
    merge_eligible: pass,
    merge_authorized: false,
    self_closeout_authorized: false,
    amendment_002_closed: false,
  };
}

runAsMain(import.meta.url, 'p1-b000-authority-amendment-003', run);
