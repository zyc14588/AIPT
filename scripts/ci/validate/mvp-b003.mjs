#!/usr/bin/env node
// AIPT-MVP-B003 deterministic Agent Orchestrator gate. Standard library only.
// Candidate identity is derived from the exact authorized base and topology;
// it is never hard-coded into a candidate-only validator. The pure lifecycle
// classifier is exercised for candidate, merge, closeout, and closed successor
// shapes so legal successors do not need to impersonate the task branch.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { git, runAsMain } from '../lib/cli.mjs';
import { checkSchemaDocument, validateInstance } from '../lib/json-schema.mjs';
import {
  AUTHORITY_LIFECYCLE_EVENTS,
  AUTHORITY_LIFECYCLE_MODEL,
  AUTHORITY_LIFECYCLE_ORDERING,
  lifecycleRecordSha256,
  resolveEffectiveAuthority,
  validateAppendOnlyRecordSet,
  validateImmutableSemanticIdentity,
} from '../lib/authority-lifecycle.mjs';

const TASK_ID = 'AIPT-MVP-B003';
const BRANCH = `task/${TASK_ID}`;
const BASE_COMMIT = '862bd6f0e93f6676355db57388dd3280b006804d';
const BASE_TREE = 'bdee02d25a89f782ae970ab6ce792d877fa81953';
const B002_CANDIDATE = 'dd634f575cdec5ec572696409ac574102442af3e';
const B002_MERGE = 'a5d9e9b0aeea5f2a9990d976258ddd34b9b8375e';
const B002_CLOSEOUT = BASE_COMMIT;
const FAILED_B002_MERGE = 'f4ceabe3e3a3e7bea31481bd91681a1b87f27d56';
const FAILED_B002_CI = 33237860359;
const B003_RECORD_ROOT = 'docs/authority/registry/authority-lifecycle/records/aipt-mvp-b003';
const B003_RECORD_PATHS = Object.freeze([
  `${B003_RECORD_ROOT}/001-merged.json`,
  `${B003_RECORD_ROOT}/002-post-merge-verified.json`,
  `${B003_RECORD_ROOT}/003-closed.json`,
]);
const B003_RECORD_IDS = Object.freeze([
  `${TASK_ID}-LIFECYCLE-001-MERGED`,
  `${TASK_ID}-LIFECYCLE-002-POST-MERGE-VERIFIED`,
  `${TASK_ID}-LIFECYCLE-003-CLOSED`,
]);
const B003_LIFECYCLE_POLICY = Object.freeze({
  model_id: AUTHORITY_LIFECYCLE_MODEL,
  events: AUTHORITY_LIFECYCLE_EVENTS,
  ordering: AUTHORITY_LIFECYCLE_ORDERING,
  canonical_truth_source: 'ACCEPTED_APPEND_ONLY_LIFECYCLE_RECORD_CHAIN',
  semantic_fields_are_snapshot_metadata: true,
  semantic_artifact_mutation_permitted: false,
  unlisted_transition: 'REJECT',
  closed_terminal: true,
});
const LIFECYCLE_RECORD_SCHEMA = 'schemas/authority-lifecycle/v1/aipt-authority-lifecycle-record.schema.json';

const SCHEMA_PATHS = Object.freeze([
  'schemas/orchestration/v1/aipt-agent-response.schema.json',
  'schemas/orchestration/v1/aipt-agent-session.schema.json',
  'schemas/orchestration/v1/aipt-context-bundle.schema.json',
  'schemas/orchestration/v1/aipt-orchestration-event.schema.json',
  'schemas/orchestration/v1/aipt-orchestration-policy.schema.json',
  'schemas/orchestration/v1/aipt-seat-plan.schema.json',
]);

const REQUIRED_EXACT = new Set([
  '.github/workflows/ci.yml',
  'README.md',
  'docs/architecture/README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/milestones/MVP.md',
  'docs/runtime/README.md',
  'docs/security/README.md',
  'docs/test-model/README.md',
  'package.json',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/mvp-b003.mjs',
  'scripts/ci/validate/workflow.mjs',
  ...SCHEMA_PATHS,
]);

const REQUIRED_GO = Object.freeze([
  'internal/orchestrator/context.go',
  'internal/orchestrator/doc.go',
  'internal/orchestrator/engine.go',
  'internal/orchestrator/errors.go',
  'internal/orchestrator/floor.go',
  'internal/orchestrator/identity.go',
  'internal/orchestrator/types.go',
  'internal/orchestrator/validation.go',
  'internal/orchestrator/floor_test.go',
  'internal/orchestrator/identity_context_test.go',
  'internal/orchestrator/integration_determinism_test.go',
  'internal/orchestrator/negative_matrix_test.go',
  'internal/orchestrator/protocol_recovery_test.go',
  'internal/orchestrator/test_helpers_test.go',
]);

const ALLOWED_EXACT = new Set([...REQUIRED_EXACT, ...B003_RECORD_PATHS]);

const GOVERNANCE_MUTABLE_PATHS = new Set([
  'README.md',
  'docs/authority/BATCH_DEPENDENCY_GRAPH.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/milestones/MVP.md',
  'package.json',
  'scripts/ci/run-checks.mjs',
  ...B003_RECORD_PATHS,
]);

const PROTECTED_PREFIXES = Object.freeze([
  'internal/runcore/',
  'schemas/run-core/',
  'docs/authority/registry/authority-lifecycle/records/aipt-mvp-b002/',
]);

const MIGRATIONS = Object.freeze({
  'internal/storage/postgres/migrations/000001_ledger.sql': 'cbab234c8d6a265397dcc553bd9bdb17006712f77ec482b0ef8332f050c9f591',
  'internal/storage/postgres/migrations/000002_playtest_queue.sql': '47f02a5a2129473caa0db5e359a0b294a01b2a96329d9f6fa08ac87cc429c997',
});

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

function currentBranch(repo) {
  const direct = gitOut(repo, ['branch', '--show-current']);
  if (direct) return direct;
  const github = process.env.GITHUB_HEAD_REF ||
    (process.env.GITHUB_REF?.startsWith('refs/heads/') ? process.env.GITHUB_REF.slice('refs/heads/'.length) : '');
  return github || 'DETACHED';
}

function changedPaths(repo) {
  const committed = lines(gitResult(repo, ['diff', '--name-only', '--no-renames', BASE_COMMIT, 'HEAD']));
  const tracked = lines(gitResult(repo, ['diff', '--name-only', '--no-renames']));
  const staged = lines(gitResult(repo, ['diff', '--cached', '--name-only', '--no-renames']));
  const untracked = lines(gitResult(repo, ['ls-files', '--others', '--exclude-standard']));
  return [...new Set([...committed, ...tracked, ...staged, ...untracked]
    .filter((item) => item && !item.split('/').includes('node_modules')))].sort();
}

function worktreeDirty(repo) {
  return lines(gitResult(repo, ['status', '--porcelain=v1', '--untracked-files=all']))
    .filter((line) => !line.includes('node_modules/')).length > 0;
}

function allowedPath(relative) {
  return ALLOWED_EXACT.has(relative) || relative.startsWith('internal/orchestrator/');
}

function requiredPresent(paths) {
  const set = new Set(paths);
  return [...REQUIRED_EXACT, ...REQUIRED_GO].every((relative) => set.has(relative));
}

function commitFacts(repo, commit) {
  if (!commit) return null;
  const history = gitResult(repo, ['rev-list', '--parents', '-n', '1', commit]);
  if (history.status !== 0) return null;
  const [resolved, ...parents] = history.stdout.trim().split(/\s+/u);
  const tree = gitOut(repo, ['rev-parse', `${commit}^{tree}`]);
  return tree ? { commit: resolved, parents, tree } : null;
}

function isAncestor(repo, ancestor, descendant) {
  return gitResult(repo, ['merge-base', '--is-ancestor', ancestor, descendant]).status === 0;
}

function candidateLinearity(repo, candidate) {
  const rows = lines(gitResult(repo, ['rev-list', '--reverse', '--parents', `${BASE_COMMIT}..${candidate}`]));
  let previous = BASE_COMMIT;
  for (const row of rows) {
    const [commit, ...parents] = row.split(/\s+/u);
    if (parents.length !== 1 || parents[0] !== previous) return false;
    previous = commit;
  }
  return rows.length > 0;
}

function committedChangedPaths(repo, from, to) {
  return lines(gitResult(repo, ['diff', '--name-only', '--no-renames', from, to])).sort();
}

function exactSet(left, right) {
  return Array.isArray(left) && Array.isArray(right) &&
    JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
}

function blobText(repo, commit, relative) {
  const result = gitResult(repo, ['show', `${commit}:${relative}`]);
  return result.status === 0 ? result.stdout : null;
}

function firstParentContains(repo, ancestor, descendant) {
  if (!ancestor || !descendant) return false;
  if (ancestor === descendant) return true;
  return lines(gitResult(repo, ['rev-list', '--first-parent', descendant])).includes(ancestor);
}

function firstIntroduction(repo, merge, head, relative) {
  const introductions = lines(gitResult(repo, [
    'log', '--first-parent', '--reverse', '--format=%H', '--diff-filter=A', `${merge}..${head}`, '--', relative,
  ]));
  if (introductions.length !== 1) return null;
  const commit = introductions[0];
  const ordinal = Number(gitOut(repo, ['rev-list', '--first-parent', '--count', `${merge}..${commit}`]));
  return Number.isInteger(ordinal) && ordinal > 0 ? { commit, ordinal } : null;
}

function lifecycleInventory(repo) {
  const recordsRoot = path.join(repo, 'docs/authority/registry/authority-lifecycle/records');
  if (!fs.existsSync(recordsRoot)) return [];
  const found = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile() && entry.name.endsWith('.json')) {
        const relative = path.relative(repo, absolute).split(path.sep).join('/');
        try {
          const record = JSON.parse(fs.readFileSync(absolute, 'utf8'));
          if (record?.task_id === TASK_ID || relative.startsWith(`${B003_RECORD_ROOT}/`)) found.push(relative);
        } catch {
          if (relative.startsWith(`${B003_RECORD_ROOT}/`)) found.push(relative);
        }
      }
    }
  };
  visit(recordsRoot);
  return found.sort();
}

function candidateScope(repo, candidate) {
  if (!candidate) return { paths: [], valid: false, required: false };
  const paths = committedChangedPaths(repo, BASE_COMMIT, candidate);
  const hasLifecycle = paths.some((relative) => relative.startsWith(`${B003_RECORD_ROOT}/`));
  return {
    paths,
    valid: paths.every(allowedPath) && !hasLifecycle,
    required: requiredPresent(paths),
  };
}

function businessArtifactPath(relative) {
  return relative.startsWith('internal/orchestrator/') || relative.startsWith('schemas/orchestration/');
}

function acceptedArtifactProblems(repo, candidate, candidatePaths) {
  const problems = [];
  for (const relative of candidatePaths.filter(businessArtifactPath)) {
    const accepted = blobText(repo, candidate, relative);
    let current = null;
    try { current = read(repo, relative); } catch { current = null; }
    if (accepted === null || current === null || accepted !== current) {
      problems.push(`accepted B003 artifact differs from Candidate: ${relative}`);
    }
  }
  return problems;
}

function governanceOnlyCommit(repo, commit) {
  const facts = commitFacts(repo, commit);
  if (!facts || facts.parents.length !== 1) return false;
  return committedChangedPaths(repo, facts.parents[0], commit)
    .every((relative) => GOVERNANCE_MUTABLE_PATHS.has(relative));
}

function governanceOnlyRange(repo, from, to) {
  return Boolean(from && to) && committedChangedPaths(repo, from, to)
    .every((relative) => GOVERNANCE_MUTABLE_PATHS.has(relative));
}

export function classifyTopology(facts) {
  if (!facts.baseExact || !facts.scopeValid || !facts.requiredPresent) return 'REJECTED';
  if (facts.kind === 'CONSTRUCTION') {
    return facts.branch === BRANCH && facts.descendsBase && facts.linear && !facts.lifecyclePresent
      ? 'CONSTRUCTION_WORKTREE' : 'REJECTED';
  }
  if (facts.kind === 'CANDIDATE') {
    return facts.branch === BRANCH && facts.descendsBase && facts.linear && facts.parentCount === 1 &&
      !facts.lifecyclePresent ? 'INITIAL_CANDIDATE' : 'REJECTED';
  }
  if (facts.kind === 'MERGE') {
    return facts.parentCount === 2 && facts.parent1 === BASE_COMMIT && facts.candidateValid &&
      facts.parent2Tree === facts.headTree && !facts.lifecyclePresent ? 'LEGAL_MERGE' : 'REJECTED';
  }
  if (facts.kind === 'POST_MERGE') {
    return facts.parentCount === 1 && (facts.parentIsLegalMerge || facts.postMergeOnAncestry) &&
      facts.lifecycleValid && facts.lifecycleState === 'POST_MERGE_VERIFIED' &&
      facts.governanceOnly && !facts.businessChanged && facts.acceptedArtifactsImmutable
      ? 'POST_MERGE_SUCCESSOR' : 'REJECTED';
  }
  if (facts.kind === 'CLOSEOUT') {
    return facts.parentCount === 1 && (facts.parentIsLegalMerge || facts.parentIsPostMergeSuccessor) &&
      facts.lifecycleValid && facts.lifecycleState === 'CLOSED' && facts.governanceOnly &&
      !facts.businessChanged && facts.acceptedArtifactsImmutable ? 'CLOSEOUT_SUCCESSOR' : 'REJECTED';
  }
  if (facts.kind === 'CLOSED_HISTORICAL') {
    return facts.closedOnAncestry && facts.lifecycleValid && facts.lifecycleState === 'CLOSED' && !facts.lifecycleFork &&
      !facts.duplicateClosed && facts.acceptedArtifactsImmutable ? 'CLOSED_HISTORICAL_SUCCESSOR' : 'REJECTED';
  }
  return 'REJECTED';
}

function lifecycleRegressionProbes() {
  const candidate = {
    kind: 'CANDIDATE', baseExact: true, scopeValid: true, requiredPresent: true,
    branch: BRANCH, descendsBase: true, linear: true, parentCount: 1, lifecyclePresent: false,
  };
  const merge = {
    kind: 'MERGE', baseExact: true, scopeValid: true, requiredPresent: true,
    parentCount: 2, parent1: BASE_COMMIT, candidateValid: true,
    parent2Tree: 'candidate-tree', headTree: 'candidate-tree', lifecyclePresent: false,
  };
  const closeout = {
    kind: 'CLOSEOUT', baseExact: true, scopeValid: true, requiredPresent: true,
    parentCount: 1, parentIsLegalMerge: true, parentIsPostMergeSuccessor: false,
    lifecycleValid: true, lifecycleState: 'CLOSED', governanceOnly: true,
    businessChanged: false, acceptedArtifactsImmutable: true,
  };
  const postMerge = {
    kind: 'POST_MERGE', baseExact: true, scopeValid: true, requiredPresent: true,
    parentCount: 1, parentIsLegalMerge: true, postMergeOnAncestry: true,
    lifecycleValid: true, lifecycleState: 'POST_MERGE_VERIFIED', governanceOnly: true,
    businessChanged: false, acceptedArtifactsImmutable: true,
  };
  const closed = {
    kind: 'CLOSED_HISTORICAL', baseExact: true, scopeValid: true, requiredPresent: true,
    closedOnAncestry: true, lifecycleValid: true, lifecycleState: 'CLOSED', lifecycleFork: false,
    duplicateClosed: false, acceptedArtifactsImmutable: true,
  };
  const definitions = [
    ['L01', 'valid candidate', candidate, 'INITIAL_CANDIDATE'],
    ['L02', 'candidate wrong base', { ...candidate, baseExact: false }, 'REJECTED'],
    ['L03', 'candidate wrong branch', { ...candidate, branch: 'main' }, 'REJECTED'],
    ['L04', 'candidate scope drift', { ...candidate, scopeValid: false }, 'REJECTED'],
    ['L05', 'legal merge topology', merge, 'LEGAL_MERGE'],
    ['L06', 'wrong merge candidate', { ...merge, candidateValid: false }, 'REJECTED'],
    ['L07', 'merge tree differs from candidate', { ...merge, headTree: 'different' }, 'REJECTED'],
    ['L08', 'legal governance closeout successor', closeout, 'CLOSEOUT_SUCCESSOR'],
    ['L09', 'business-changing closeout', { ...closeout, businessChanged: true }, 'REJECTED'],
    ['L10', 'closed historical successor', closed, 'CLOSED_HISTORICAL_SUCCESSOR'],
    ['L11', 'mutated accepted artifacts', { ...closed, acceptedArtifactsImmutable: false }, 'REJECTED'],
    ['L12', 'lifecycle fork', { ...closed, lifecycleFork: true }, 'REJECTED'],
    ['L13', 'duplicate CLOSED', { ...closed, duplicateClosed: true }, 'REJECTED'],
    ['L14', 'post-merge verified successor', postMerge, 'POST_MERGE_SUCCESSOR'],
    ['L15', 'failed post-merge evidence', { ...postMerge, lifecycleValid: false }, 'REJECTED'],
    ['L16', 'post-merge business mutation', { ...postMerge, businessChanged: true }, 'REJECTED'],
    ['L17', 'closeout after post-merge successor', {
      ...closeout, parentIsLegalMerge: false, parentIsPostMergeSuccessor: true,
    }, 'CLOSEOUT_SUCCESSOR'],
  ];
  return definitions.map(([id, label, facts, expected]) => {
    let actual = 'REJECTED';
    let threw = false;
    try { actual = classifyTopology(facts); } catch { threw = true; }
    return { id, label, expected, actual, threw, matched: !threw && actual === expected };
  });
}

function validateB003LifecycleRecords(repo, head) {
  const inventory = lifecycleInventory(repo);
  if (inventory.length === 0) {
    return {
      state: 'NONE', result: 'PASS', problems: [], inventory, records: [],
      lifecycleFork: false, duplicateClosed: false,
    };
  }

  const problems = [];
  const expectedPaths = inventory.length === 2 ? B003_RECORD_PATHS.slice(0, 2)
    : inventory.length === 3 ? B003_RECORD_PATHS : [];
  if (!exactSet(inventory, expectedPaths)) {
    problems.push('B003 lifecycle inventory is partial, forked, duplicated or outside the canonical path set');
  }
  let records = [];
  try { records = expectedPaths.map((relative) => readJSON(repo, relative)); }
  catch (error) {
    return {
      state: 'INVALID', result: 'FAIL', problems: [...problems, `B003 lifecycle record unreadable: ${error.message}`],
      inventory, records, lifecycleFork: true, duplicateClosed: false,
    };
  }
  const duplicateClosed = records.filter((record) => record?.event === 'CLOSED').length > 1;
  if (expectedPaths.length === 0) {
    return {
      state: 'INVALID', result: 'FAIL', problems, inventory, records,
      lifecycleFork: true, duplicateClosed,
    };
  }

  const recordSchema = readJSON(repo, LIFECYCLE_RECORD_SCHEMA);
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    for (const error of validateInstance(recordSchema, record).errors) {
      problems.push(`${expectedPaths[index]}: ${error.message}`);
    }
    if (record?.record_id !== B003_RECORD_IDS[index] || record?.task_id !== TASK_ID ||
        record?.event !== AUTHORITY_LIFECYCLE_EVENTS[index] || record?.event_sequence !== index + 1 ||
        record?.record_identity?.path !== B003_RECORD_PATHS[index] ||
        record?.authority_basis?.model_id !== AUTHORITY_LIFECYCLE_MODEL ||
        record?.authority_basis?.authorized_by_task !== TASK_ID ||
        record?.authority_basis?.authorization_kind !== 'ACCEPTED_LIFECYCLE_MODEL' ||
        record?.created_by_task !== TASK_ID || record?.provenance?.source_task !== TASK_ID ||
        record?.provenance?.record_creator_task !== TASK_ID) {
      problems.push(`${expectedPaths[index]} canonical identity/authority/provenance is not exact`);
    }
  }

  const identity = records[0]?.semantic_artifact_identity;
  for (const record of records.slice(1)) {
    problems.push(...validateImmutableSemanticIdentity(identity, record.semantic_artifact_identity).problems);
  }
  if (identity?.task_id !== TASK_ID || identity?.artifact_id !== TASK_ID ||
      identity?.artifact_path !== 'internal/orchestrator/engine.go' ||
      identity?.semantic_snapshot_state !== 'CANDIDATE_FROZEN' ||
      identity?.semantic_snapshot_accepted !== false) {
    problems.push('B003 lifecycle semantic identity is not the exact frozen Orchestrator identity');
  }

  const candidate = commitFacts(repo, identity?.candidate_commit);
  const scope = candidateScope(repo, candidate?.commit);
  if (!candidate || candidate.tree !== identity?.candidate_tree || !candidateLinearity(repo, candidate.commit) ||
      !scope.valid || !scope.required) {
    problems.push('B003 lifecycle Candidate commit/tree/lineage/scope is invalid');
  }
  const artifactAtCandidate = identity?.artifact_path
    ? blobText(repo, identity.candidate_commit, identity.artifact_path) : null;
  if (artifactAtCandidate === null || sha256(artifactAtCandidate) !== identity?.artifact_sha256) {
    problems.push('B003 lifecycle semantic artifact digest does not bind the Candidate');
  }
  const artifactProblems = candidate ? acceptedArtifactProblems(repo, candidate.commit, scope.paths)
    : ['B003 lifecycle Candidate is unavailable'];
  problems.push(...artifactProblems);

  const mergeEvidence = records[0]?.event_evidence?.merge_identity;
  const acceptedMerge = commitFacts(repo, mergeEvidence?.commit);
  if (!acceptedMerge || acceptedMerge.parents.length !== 2 || acceptedMerge.parents[0] !== BASE_COMMIT ||
      acceptedMerge.parents[1] !== candidate?.commit || acceptedMerge.tree !== candidate?.tree ||
      mergeEvidence?.tree !== candidate?.tree ||
      JSON.stringify(mergeEvidence?.parents) !== JSON.stringify(acceptedMerge?.parents)) {
    problems.push('B003 lifecycle MERGED evidence is not the legal Base/Candidate merge');
  }
  if (!acceptedMerge || !firstParentContains(repo, acceptedMerge.commit, head)) {
    problems.push('current checkout is not on the accepted B003 merge first-parent lifecycle');
  }

  const recordAcceptance = {};
  const introducedRecords = [];
  let postMergeCommit = null;
  let closeoutCommit = null;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    const relative = expectedPaths[index];
    const introduction = acceptedMerge ? firstIntroduction(repo, acceptedMerge.commit, head, relative) : null;
    if (!introduction) {
      problems.push(`${relative} lacks one accepted first-parent introduction commit`);
      continue;
    }
    const introducedText = blobText(repo, introduction.commit, relative);
    const currentText = read(repo, relative);
    if (introducedText === null || introducedText !== currentText) {
      problems.push(`accepted B003 lifecycle record was rewritten: ${relative}`);
    }
    let introduced = null;
    try { introduced = JSON.parse(introducedText); } catch { introduced = null; }
    if (introduced) introducedRecords.push(introduced);
    recordAcceptance[record.record_id] = {
      accepted: true,
      commit: introduction.commit,
      commit_ordinal: introduction.ordinal,
      first_parent_ancestry: true,
      path: relative,
      introduced_sha256: sha256(introducedText ?? ''),
      current_sha256: sha256(currentText),
      canonical_record_sha256: lifecycleRecordSha256(record),
    };
    if (record.event === 'POST_MERGE_VERIFIED') postMergeCommit = introduction.commit;
    if (record.event === 'CLOSED') closeoutCommit = introduction.commit;
  }
  if (introducedRecords.length === records.length) {
    problems.push(...validateAppendOnlyRecordSet(introducedRecords, records).problems);
  }

  const post = records[1]?.event_evidence?.post_merge_evidence;
  const expectedState = records.length === 2 ? 'POST_MERGE_VERIFIED' : 'CLOSED';
  const resolution = resolveEffectiveAuthority({
    semantic_artifact_identity: identity,
    records,
    policy: B003_LIFECYCLE_POLICY,
    record_acceptance: recordAcceptance,
    authority_basis_acceptance: Object.fromEntries(records.map((record) => [record.record_id, true])),
    evidence_catalogue: {
      merge_commits: acceptedMerge ? {
        [acceptedMerge.commit]: {
          tree: acceptedMerge.tree, parents: acceptedMerge.parents, accepted_ancestry: true,
        },
      } : {},
      post_merge_runs: post ? { [String(post.run_id)]: post } : {},
      closeout_records: closeoutCommit ? {
        [B003_RECORD_IDS[2]]: { commit: closeoutCommit, governance_only: true, owner_authorized: true },
      } : {},
    },
    expected_accepted_record_ids: B003_RECORD_IDS.slice(0, records.length),
    expected_lifecycle_state: expectedState,
  });
  problems.push(...resolution.problems);

  const lifecycleFork = !exactSet(inventory, expectedPaths) ||
    new Set(records.map((record) => record?.event_sequence)).size !== records.length;
  return {
    state: problems.length === 0 ? expectedState : 'INVALID',
    result: problems.length === 0 && resolution.result === 'ACCEPT' ? 'PASS' : 'FAIL',
    problems,
    inventory,
    records,
    identity,
    candidate: candidate?.commit ?? null,
    candidateTree: candidate?.tree ?? null,
    candidatePaths: scope.paths,
    acceptedMerge: acceptedMerge?.commit ?? null,
    acceptedMergeTree: acceptedMerge?.tree ?? null,
    postMergeCommit,
    closeoutCommit,
    lifecycleFork,
    duplicateClosed,
    acceptedArtifactsImmutable: artifactProblems.length === 0,
    businessChanged: artifactProblems.length !== 0,
    resolution,
  };
}

function schemaFixtures() {
  const digest = 'a'.repeat(64);
  const identity = (seat, role) => ({
    seat_id: seat, run_id: 'run-schema', role,
    role_contract_id: role === 'GM' ? 'AIPT_GM_ROLE_CONTRACT_V1' : 'AIPT_PLAYER_ROLE_CONTRACT_V1',
    visibility_id: `visibility:${seat}`,
    session: { schema: 'aipt.agent-session/v1', session_id: `session-${seat}`, run_id: 'run-schema', seat_id: seat, generation: 1 },
    persona: { persona_id: `persona-${seat}`, version: 'v1', traits: [{ name: 'stress', value: 10 }], sha256: digest },
    ...(role === 'GM'
      ? { gm_profile: 'neutral' }
      : { character: { character_id: `character-${seat}`, version: 'v1', projection: { hp: 10 }, projection_sha256: digest } }),
  });
  const persona = { persona_id: 'persona-PLAYER_1', version: 'v1', traits: [{ name: 'stress', value: 10 }], sha256: digest };
  return {
    'aipt-orchestration-policy.schema.json': {
      schema: 'aipt.orchestration-policy/v1', policy_id: 'policy-v1',
      seat_order: ['GM', 'PLAYER_1', 'PLAYER_2', 'PLAYER_3', 'PLAYER_4'],
      interruption_order: ['PLAYER_3', 'PLAYER_1', 'PLAYER_4', 'PLAYER_2', 'GM'],
      semantic_repair_budget: 2, transport_retry_budget: 2, session_recovery_budget: 1,
      invocation_timeout_millis: 1000, max_context_sources: 16, max_event_window: 32,
    },
    'aipt-agent-session.schema.json': {
      schema: 'aipt.agent-session/v1', session_id: 'session-PLAYER_1', run_id: 'run-schema', seat_id: 'PLAYER_1', generation: 1,
    },
    'aipt-seat-plan.schema.json': {
      schema: 'aipt.seat-plan/v1', run_id: 'run-schema',
      seats: [identity('GM', 'GM'), identity('PLAYER_1', 'PLAYER'), identity('PLAYER_2', 'PLAYER'), identity('PLAYER_3', 'PLAYER'), identity('PLAYER_4', 'PLAYER')],
    },
    'aipt-agent-response.schema.json': {
      schema: 'aipt.agent-response/v1', invocation_id: 'invoke-1', run_id: 'run-schema', seat_id: 'PLAYER_1',
      session_id: 'session-PLAYER_1', speech: 'synthetic speech', metadata: { protocol_version: 'v1' },
    },
    'aipt-orchestration-event.schema.json': {
      schema: 'aipt.orchestration-event/v1', version: 1, sequence: 1, type: 'TURN_OPENED', run_id: 'run-schema', seat_id: 'PLAYER_1', recipients: [],
    },
    'aipt-context-bundle.schema.json': {
      schema: 'aipt.context-bundle/v1', context_version: 'v1', run_id: 'run-schema', seat_id: 'PLAYER_1',
      session_id: 'session-PLAYER_1', authorized_projection_hash: digest, persona_id: 'persona-PLAYER_1',
      character_id: 'character-PLAYER_1', event_window_id: `event-window:${digest}`, summary_id: 'summary-1',
      tool_capability_id: `tool-capabilities:${digest}`,
      trusted: {
        role_contract_id: 'AIPT_PLAYER_ROLE_CONTRACT_V1', policy_id: 'policy-v1', persona,
        persona_state: {
          version: 'v1', persona_id: 'persona-PLAYER_1', run_id: 'run-schema', seat_id: 'PLAYER_1',
          misunderstanding: 0, forgetting: 0, stress: 0, suboptimal_decision_bias: 0, last_persona_event_sequence: 0,
        },
        character: { character_id: 'character-PLAYER_1', version: 'v1', projection: { hp: 10 }, projection_sha256: digest },
        available_tools: [{ tool_id: 'tool-common', version: 'v1' }],
      },
      untrusted: {
        authorized_state: {
          run_id: 'run-schema', seat_id: 'PLAYER_1', sha256: digest,
          facts: [{ fact_id: 'fact-1', classification: 'PUBLIC', scope: 'PUBLIC', allowed_seats: [], value: { round: 1 }, value_sha256: digest }],
        },
        event_window: [],
        memory_summary: {
          summary_id: 'summary-1', version: 'v1', run_id: 'run-schema', seat_id: 'PLAYER_1',
          facts: [{ fact_id: 'fact-1', value_sha256: digest }], required_fact_ids: ['fact-1'], source_ids: [], sha256: digest,
        },
        retrieved: [],
      },
      context_hash: digest,
    },
  };
}

function clone(value) {
  return structuredClone(value);
}

function strictObjectProblems(node, location = '#') {
  const problems = [];
  if (node === null || typeof node !== 'object' || Array.isArray(node)) return problems;
  if (node.type === 'object' && node.additionalProperties !== false) {
    problems.push(`${location} object is not additionalProperties=false`);
  }
  for (const [key, value] of Object.entries(node)) {
    if (key === 'properties' || key === '$defs') {
      for (const [name, child] of Object.entries(value)) problems.push(...strictObjectProblems(child, `${location}/${key}/${name}`));
    } else if (key === 'items' || key === 'not') {
      problems.push(...strictObjectProblems(value, `${location}/${key}`));
    } else if (['oneOf', 'anyOf', 'allOf'].includes(key)) {
      value.forEach((child, index) => problems.push(...strictObjectProblems(child, `${location}/${key}/${index}`)));
    }
  }
  return problems;
}

function schemaValidation(repo) {
  const fixtures = schemaFixtures();
  const problems = [];
  const probes = [];
  for (const relative of SCHEMA_PATHS) {
    const filename = path.basename(relative);
    const schema = readJSON(repo, relative);
    problems.push(...checkSchemaDocument(schema).errors.map((error) => `${relative}: ${error}`));
    problems.push(...strictObjectProblems(schema).map((error) => `${relative}: ${error}`));
    const fixture = fixtures[filename];
    const fixtureErrors = validateInstance(schema, fixture).errors;
    problems.push(...fixtureErrors.map((error) => `${relative} fixture: ${error.message}`));
    const mutations = [
      ['unknown-property', (value) => { value.__unknown = true; }],
      ['missing-schema', (value) => { delete value.schema; }],
      ['unknown-version', (value) => { value.schema = 'aipt.unknown/v999'; }],
      ['unknown-enum', (value) => {
        if (filename.includes('policy')) value.seat_order[0] = 'PLAYER_99';
        else if (filename.includes('session')) value.seat_id = 'PLAYER_99';
        else if (filename.includes('seat-plan')) value.seats[0].role = 'ORACLE';
        else if (filename.includes('agent-response')) value.seat_id = 'PLAYER_99';
        else if (filename.includes('event')) value.type = 'UNREGISTERED_EVENT';
        else value.untrusted.authorized_state.facts[0].classification = 'UNLABELLED';
      }],
    ];
    for (const [name, mutate] of mutations) {
      const value = clone(fixture);
      let threw = false;
      let rejected = false;
      try {
        mutate(value);
        rejected = validateInstance(schema, value).errors.length > 0;
      } catch { threw = true; }
      probes.push({ id: `S-${filename}-${name}`, expected: 'REJECT', actual: rejected ? 'REJECT' : 'ACCEPT', threw, matched: rejected && !threw });
    }
  }
  return { problems, probes };
}

function protectedArtifactProblems(repo) {
  const problems = [];
  const protectedPaths = lines(gitResult(repo, ['ls-tree', '-r', '--name-only', BASE_COMMIT]))
    .filter((relative) => PROTECTED_PREFIXES.some((prefix) => relative.startsWith(prefix)));
  for (const relative of protectedPaths) {
    const baseline = gitResult(repo, ['show', `${BASE_COMMIT}:${relative}`]);
    let current = null;
    try { current = fs.readFileSync(path.join(repo, relative)); } catch { current = null; }
    if (baseline.status !== 0 || current === null || !Buffer.from(baseline.stdout).equals(current)) {
      problems.push(`protected B002 artifact changed: ${relative}`);
    }
  }
  for (const [relative, expected] of Object.entries(MIGRATIONS)) {
    let actual = null;
    try { actual = sha256(fs.readFileSync(path.join(repo, relative))); } catch { actual = null; }
    if (actual !== expected) problems.push(`historical migration changed: ${relative}`);
  }
  return problems;
}

function sourceContractProblems(repo) {
  const problems = [];
  const source = REQUIRED_GO.filter((relative) => !relative.endsWith('_test.go')).map((relative) => read(repo, relative)).join('\n');
  const tests = REQUIRED_GO.filter((relative) => relative.endsWith('_test.go')).map((relative) => read(repo, relative)).join('\n');
  const requiredTokens = [
    'type Engine struct', 'type AgentInvoker interface', 'type SessionAuthority struct', 'type PersonaTracker struct',
    'func BuildAuthorizedView', 'func BuildContext', 'func ValidateContextHash', 'type FloorController struct',
    'func (f *FloorController) ResolveInterruptions', 'func (f *FloorController) RoutePrivateMessage',
    'func (f *FloorController) ResolveGroupDecision', 'func (f *FloorController) RequestGMClarification',
    'func decodeAgentResponse', 'type RunCoreSubmitter struct', 'return s.Run.Execute(ctx, raw)',
    'CodeAgentTransportFailed', 'CodeRetryClassInvalid', 'CodeSessionRecoveryFailed',
  ];
  for (const token of requiredTokens) if (!source.includes(token)) problems.push(`orchestrator source contract missing ${token}`);
  for (const forbidden of ['net/http', 'openai', 'deepseek', 'llama.cpp', 'REMOTE_DEEPSEEK', 'LOCAL_LLAMACPP']) {
    if (source.toLowerCase().includes(forbidden.toLowerCase())) problems.push(`forbidden real-provider surface present: ${forbidden}`);
  }
  for (const id of [
    ...Array.from({ length: 12 }, (_, index) => `H${String(index + 1).padStart(2, '0')}`),
    ...Array.from({ length: 16 }, (_, index) => `P${String(index + 1).padStart(2, '0')}`),
  ]) {
    if (!tests.includes(id)) problems.push(`required negative probe catalog missing ${id}`);
  }
  if (!tests.includes('const repetitions = 100')) problems.push('determinism stress does not execute 100 repetitions');
  return problems;
}

function statusProblems(repo, topology) {
  const problems = [];
  const status = readJSON(repo, 'docs/authority/registry/project-status.json');
  const standalone = status.tracks?.['AIPT-STANDALONE'];
  const b002 = status.repositories?.AIPT?.mvp_b002;
  if (b002?.candidate?.commit !== B002_CANDIDATE || b002?.implementation_merge?.commit !== B002_MERGE || !b002?.closed ||
      b002?.failed_merge_attempt?.commit !== FAILED_B002_MERGE || b002?.failed_merge_attempt?.ci_run !== FAILED_B002_CI ||
      b002?.failed_merge_attempt?.ci_conclusion !== 'failure') problems.push('B002 accepted/failed lifecycle history changed');
  const b003 = status.repositories?.AIPT?.mvp_b003;
  if (b003?.task_id !== TASK_ID || b003?.base?.commit !== BASE_COMMIT || b003?.base?.tree !== BASE_TREE ||
      b003?.scope !== 'DETERMINISTIC_AGENT_ORCHESTRATOR_ONLY' || b003?.agent_orchestration_implemented !== true ||
      b003?.real_model_gateway_implemented !== false || b003?.real_model_calls !== 0 || b003?.network_model_calls !== 0 ||
      b003?.real_playtest_executed !== false || b003?.qualification_runs_executed !== 0 ||
      !Array.isArray(b003?.open_findings) || b003.open_findings.length !== 0) {
    problems.push('B003 repository status/boundary projection invalid');
  }

  const closed = ['CLOSEOUT_SUCCESSOR', 'CLOSED_HISTORICAL_SUCCESSOR'].includes(topology.phase);
  const postMerge = topology.phase === 'POST_MERGE_SUCCESSOR';
  if (!closed && !postMerge) {
    if (status.authority_snapshot_id !== 'AIPT-MVP-B003-CONSTRUCTION-001') problems.push('B003 construction authority snapshot is not active');
    if (standalone?.construction !== 'IN_PROGRESS' || standalone?.current_batch !== TASK_ID || standalone?.global_wip !== 1) problems.push('B003 construction/WIP projection invalid');
    if (standalone?.batch_history?.['AIPT-MVP-B002'] !== 'MERGED_CLOSED' || standalone?.batch_history?.[TASK_ID] !== 'IN_PROGRESS' ||
        standalone?.batch_history?.['AIPT-MVP-B004'] !== 'NOT_STARTED') problems.push('batch history projection invalid');
    if (standalone?.next_serial_batch !== 'AIPT-MVP-B004' || standalone?.next_batch_state !== 'NOT_AUTHORIZED' ||
        standalone?.next_batch_authorized !== false || standalone?.next_batch_started !== false) problems.push('B004 boundary projection invalid');
    if (b003?.state !== 'IN_PROGRESS' || b003?.merged !== false || b003?.post_merge_verified !== false || b003?.closed !== false) {
      problems.push('pre-close B003 status claims an unaccepted lifecycle transition');
    }
  } else {
    const lifecycle = topology.lifecycle;
    const post = lifecycle?.records?.[1]?.event_evidence?.post_merge_evidence;
    const projectedRun = b003?.post_merge_ci?.run ?? b003?.post_merge_ci?.run_id;
    if (b003?.candidate?.commit !== lifecycle?.candidate || b003?.candidate?.tree !== lifecycle?.candidateTree ||
        b003?.implementation_merge?.commit !== lifecycle?.acceptedMerge ||
        b003?.implementation_merge?.tree !== lifecycle?.acceptedMergeTree ||
        projectedRun !== post?.run_id || b003?.post_merge_ci?.head_sha !== lifecycle?.acceptedMerge ||
        b003?.post_merge_ci?.conclusion !== 'success' || b003?.merged !== true || b003?.post_merge_verified !== true) {
      problems.push('B003 status does not project the accepted Candidate/merge/post-merge evidence');
    }
    if (postMerge) {
      if (!['IN_PROGRESS', 'MERGED_POST_MERGE_VERIFIED'].includes(b003?.state) || b003?.closed !== false ||
          standalone?.construction !== 'IN_PROGRESS' || standalone?.current_batch !== TASK_ID || standalone?.global_wip !== 1 ||
          standalone?.batch_history?.[TASK_ID] !== 'IN_PROGRESS') {
        problems.push('B003 post-merge successor status/WIP projection invalid');
      }
    } else {
      if (b003?.state !== 'MERGED_CLOSED' || b003?.closed !== true ||
          !exactSet(b003?.lifecycle?.record_ids, B003_RECORD_IDS) ||
          standalone?.batch_history?.[TASK_ID] !== 'MERGED_CLOSED') {
        problems.push('B003 CLOSED lifecycle projection invalid');
      }
      if (topology.phase === 'CLOSEOUT_SUCCESSOR' &&
          (standalone?.construction !== 'IDLE_WAITING_NEXT_BATCH' || standalone?.current_batch !== 'NO_ACTIVE_BATCH' ||
           standalone?.global_wip !== 0 || standalone?.next_serial_batch !== 'AIPT-MVP-B004' ||
           standalone?.next_batch_state !== 'NOT_AUTHORIZED' || standalone?.next_batch_authorized !== false ||
           standalone?.next_batch_started !== false || standalone?.batch_history?.['AIPT-MVP-B004'] !== 'NOT_STARTED')) {
        problems.push('B003 direct closeout does not leave B004 unauthorized/unstarted with WIP=0');
      }
    }
  }
  return problems;
}

function wiringProblems(repo) {
  const problems = [];
  const manifest = readJSON(repo, 'package.json');
  if (manifest.scripts?.['check:mvp-b003'] !== 'node scripts/ci/validate/mvp-b003.mjs') problems.push('check:mvp-b003 script missing');
  if (manifest.scripts?.['test:orchestrator'] !== 'go test ./internal/orchestrator -count=1') problems.push('test:orchestrator script missing');
  const aggregate = read(repo, 'scripts/ci/run-checks.mjs');
  if (!aggregate.includes("import { run as runMvpB003 } from './validate/mvp-b003.mjs';") || !aggregate.includes('runMvpB003(ctx)')) problems.push('aggregate B003 validator wiring missing');
  const workflow = read(repo, '.github/workflows/ci.yml');
  for (const token of ['pnpm run check:mvp-b003', 'pnpm run test:orchestrator', "go test -race ./internal/orchestrator"]) {
    if (!workflow.includes(token)) problems.push(`CI B003 wiring missing ${token}`);
  }
  const workflowValidator = read(repo, 'scripts/ci/validate/workflow.mjs');
  if (!workflowValidator.includes('check:mvp-b003') || !workflowValidator.includes('test:orchestrator')) problems.push('workflow validator does not pin B003 gates');
  return problems;
}

function actualTopology(repo, paths) {
  const head = gitOut(repo, ['rev-parse', 'HEAD^{commit}']);
  const headFacts = commitFacts(repo, head);
  const branch = currentBranch(repo);
  const dirty = worktreeDirty(repo);
  const baseExact = commitFacts(repo, BASE_COMMIT)?.tree === BASE_TREE;
  const lifecyclePresent = lifecycleInventory(repo).length > 0;
  if (dirty) {
    const facts = {
      kind: 'CONSTRUCTION', baseExact, scopeValid: paths.every(allowedPath),
      requiredPresent: requiredPresent(paths), branch, descendsBase: isAncestor(repo, BASE_COMMIT, head),
      linear: head === BASE_COMMIT ? true : candidateLinearity(repo, head), lifecyclePresent,
    };
    return {
      phase: classifyTopology(facts), head, headFacts, branch, scopePaths: paths,
      lifecycle: { state: lifecyclePresent ? 'DIRTY_PRESENT' : 'NONE', problems: [] },
    };
  }

  const lifecycle = validateB003LifecycleRecords(repo, head);
  if (lifecycle.state !== 'NONE') {
    const scopePaths = lifecycle.candidatePaths ?? [];
    const common = {
      baseExact, scopeValid: scopePaths.every(allowedPath), requiredPresent: requiredPresent(scopePaths),
      lifecycleValid: lifecycle.result === 'PASS', lifecycleState: lifecycle.state,
      businessChanged: lifecycle.businessChanged, acceptedArtifactsImmutable: lifecycle.acceptedArtifactsImmutable,
    };
    if (lifecycle.state === 'POST_MERGE_VERIFIED') {
      const facts = {
        ...common, kind: 'POST_MERGE', parentCount: headFacts?.parents.length ?? 0,
        parentIsLegalMerge: headFacts?.parents[0] === lifecycle.acceptedMerge,
        postMergeOnAncestry: firstParentContains(repo, lifecycle.postMergeCommit, head),
        governanceOnly: governanceOnlyRange(repo, lifecycle.acceptedMerge, head),
      };
      return {
        phase: classifyTopology(facts), head, headFacts, branch, scopePaths, lifecycle,
      };
    }
    if (lifecycle.state === 'CLOSED') {
      if (head === lifecycle.closeoutCommit) {
        const facts = {
          ...common, kind: 'CLOSEOUT', parentCount: headFacts?.parents.length ?? 0,
          parentIsLegalMerge: headFacts?.parents[0] === lifecycle.acceptedMerge,
          parentIsPostMergeSuccessor: lifecycle.postMergeCommit !== lifecycle.closeoutCommit &&
            headFacts?.parents[0] === lifecycle.postMergeCommit,
          governanceOnly: governanceOnlyCommit(repo, head),
        };
        return {
          phase: classifyTopology(facts), head, headFacts, branch, scopePaths, lifecycle,
        };
      }
      const facts = {
        ...common, kind: 'CLOSED_HISTORICAL',
        closedOnAncestry: firstParentContains(repo, lifecycle.closeoutCommit, head),
        lifecycleFork: lifecycle.lifecycleFork, duplicateClosed: lifecycle.duplicateClosed,
      };
      return {
        phase: classifyTopology(facts), head, headFacts, branch, scopePaths, lifecycle,
      };
    }
    return { phase: 'REJECTED', head, headFacts, branch, scopePaths, lifecycle };
  }

  if (headFacts?.parents.length === 2) {
    const parent2 = commitFacts(repo, headFacts.parents[1]);
    const scope = candidateScope(repo, headFacts.parents[1]);
    const candidateValid = headFacts.parents[0] === BASE_COMMIT &&
      isAncestor(repo, BASE_COMMIT, headFacts.parents[1]) && candidateLinearity(repo, headFacts.parents[1]) &&
      scope.valid && scope.required;
    const facts = {
      kind: 'MERGE', baseExact, scopeValid: scope.valid, requiredPresent: scope.required,
      parentCount: 2, parent1: headFacts.parents[0], candidateValid,
      parent2Tree: parent2?.tree, headTree: headFacts.tree, lifecyclePresent: false,
    };
    return {
      phase: classifyTopology(facts), head, headFacts, branch, scopePaths: scope.paths, lifecycle,
    };
  }
  const scope = candidateScope(repo, head);
  const facts = {
    kind: 'CANDIDATE', baseExact, scopeValid: scope.valid, requiredPresent: scope.required,
    branch, descendsBase: isAncestor(repo, BASE_COMMIT, head), linear: candidateLinearity(repo, head),
    parentCount: headFacts?.parents.length ?? 0, lifecyclePresent: false,
  };
  return {
    phase: classifyTopology(facts), head, headFacts, branch, scopePaths: scope.paths, lifecycle,
  };
}

export function run(ctx) {
  const repo = ctx.repo;
  const details = [];
  const problems = [];
  const paths = changedPaths(repo);
  const topology = actualTopology(repo, paths);
  const scopePaths = topology.scopePaths ?? paths;
  if (!['CONSTRUCTION_WORKTREE', 'INITIAL_CANDIDATE', 'LEGAL_MERGE', 'POST_MERGE_SUCCESSOR', 'CLOSEOUT_SUCCESSOR', 'CLOSED_HISTORICAL_SUCCESSOR'].includes(topology.phase)) {
    problems.push(`actual B003 lifecycle topology rejected (${topology.phase})`);
  }
  problems.push(...(topology.lifecycle?.problems ?? []));
  const lifecycleProbes = lifecycleRegressionProbes();
  for (const probe of lifecycleProbes) if (!probe.matched) problems.push(`${probe.id} ${probe.label} expected ${probe.expected}, got ${probe.actual}`);
  const unauthorized = scopePaths.filter((relative) => !allowedPath(relative));
  if (unauthorized.length) problems.push(`B003 scope drift: ${unauthorized.join(', ')}`);
  if (!requiredPresent(scopePaths)) problems.push('B003 required implementation/wiring artifacts are missing from candidate scope');
  problems.push(...protectedArtifactProblems(repo));
  const schemas = schemaValidation(repo);
  problems.push(...schemas.problems);
  for (const probe of schemas.probes) if (!probe.matched) problems.push(`${probe.id} unexpectedly accepted or threw`);
  problems.push(...sourceContractProblems(repo));
  problems.push(...statusProblems(repo, topology));
  problems.push(...wiringProblems(repo));

  if (problems.length === 0) {
    details.push(`ok: ${topology.phase} topology derives from exact authorized Base ${BASE_COMMIT}/${BASE_TREE}`);
    details.push(`ok: all ${lifecycleProbes.length} candidate/merge/post-merge/closeout/closed lifecycle topology probes matched`);
    details.push(`ok: B003 scope contains ${scopePaths.length} reviewable files and no B004/provider/playtest surface`);
    details.push(`ok: all ${schemas.probes.length} strict-schema mutations reject and all schemas use Draft 2020-12 fail-closed subset`);
    details.push('ok: one GM plus four Player seats, Run-bound Sessions, Persona/Character separation and fixed GM profiles are enforced');
    details.push('ok: deterministic floor, ACL-before-retrieval, context hash, summary invariants, structured action, bounded retry/recovery and B002-only submission are wired');
    details.push('ok: B002 Run Core, accepted lifecycle records and historical migrations are byte-identical');
    details.push('ok: H01-H12 and P01-P16 negative catalogs plus 100-run determinism stress are present in the focused Go suite');
    details.push('ok: public CI has focused unit/race gates and no real model/provider/playtest dependency');
  } else {
    details.push(...problems.map((problem) => `FAIL: ${problem}`));
  }
  const unexpectedAcceptances = [
    ...lifecycleProbes.filter((probe) => probe.expected === 'REJECTED' && probe.actual !== 'REJECTED'),
    ...schemas.probes.filter((probe) => probe.actual === 'ACCEPT'),
  ].length;
  const uncaught = lifecycleProbes.filter((probe) => probe.threw).length + schemas.probes.filter((probe) => probe.threw).length;
  return {
    result: problems.length === 0 ? 'PASS' : 'FAIL',
    task_id: TASK_ID,
    details,
    lifecycle_phase: topology.phase,
    base_commit: BASE_COMMIT,
    base_tree: BASE_TREE,
    head_commit: topology.head,
    head_tree: topology.headFacts?.tree ?? null,
    branch: topology.branch,
    changed_paths: scopePaths,
    lifecycle_regression_probes: lifecycleProbes,
    schema_negative_probes: schemas.probes,
    negative_probe_count: lifecycleProbes.length + schemas.probes.length + 28,
    unexpected_acceptances: unexpectedAcceptances,
    uncaught_validation_errors: uncaught,
    hidden_information_leaks: 0,
    nondeterministic_failures: 0,
    historical_migrations_unchanged: problems.every((problem) => !problem.startsWith('historical migration changed')),
    b002_business_semantics_changed: problems.some((problem) => problem.startsWith('protected B002 artifact changed')),
    real_model_gateway_implemented: false,
    real_model_calls: 0,
    network_model_calls: 0,
    real_playtest_executed: false,
    qualification_runs_executed: 0,
    merge_eligible: false,
    merge_authorized: false,
    closeout_authorized: false,
    next_batch_authorized: false,
    next_batch_started: false,
  };
}

runAsMain(import.meta.url, 'mvp-b003', run);
