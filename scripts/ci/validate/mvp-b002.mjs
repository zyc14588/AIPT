#!/usr/bin/env node
// AIPT-MVP-B002 deterministic Run Core gate. Node.js standard library only.
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

const TASK_ID = 'AIPT-MVP-B002';
const BRANCH = `task/${TASK_ID}`;
const BASE_COMMIT = '411bf2997cd0f10ba1a022ac687d27a1bd19eb36';
const BASE_TREE = 'd1daaeede13a2ba07c3b528c1792ef9fd5600a63';
const MAIN_BRANCH = 'main';
const ORIGINAL_CANDIDATE = 'd81f201d57e62c9983bac67509513367ef369b64';
const ORIGINAL_CANDIDATE_TREE = '3cbac715845e746ae07969077a5b66c9da8fbd40';
const FAILED_MERGE = 'f4ceabe3e3a3e7bea31481bd91681a1b87f27d56';
const FAILED_MERGE_TREE = ORIGINAL_CANDIDATE_TREE;
const FAILED_MERGE_PARENTS = Object.freeze([BASE_COMMIT, ORIGINAL_CANDIDATE]);
const FAILED_MERGE_CI = Object.freeze({
  run_id: 33237860359,
  head_sha: FAILED_MERGE,
  conclusion: 'failure',
  jobs_passed: 3,
  jobs_failed: 2,
});
const R1_REPAIR_PATHS = Object.freeze([
  '.github/workflows/ci.yml',
  'package.json',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/historical-governance.mjs',
  'scripts/ci/validate/mvp-b002.mjs',
  'scripts/ci/validate/workflow.mjs',
]);
const B002_RECORD_ROOT = 'docs/authority/registry/authority-lifecycle/records/aipt-mvp-b002';
const B002_RECORD_PATHS = Object.freeze([
  `${B002_RECORD_ROOT}/001-merged.json`,
  `${B002_RECORD_ROOT}/002-post-merge-verified.json`,
  `${B002_RECORD_ROOT}/003-closed.json`,
]);
const B002_RECORD_IDS = Object.freeze([
  `${TASK_ID}-LIFECYCLE-001-MERGED`,
  `${TASK_ID}-LIFECYCLE-002-POST-MERGE-VERIFIED`,
  `${TASK_ID}-LIFECYCLE-003-CLOSED`,
]);
const B002_LIFECYCLE_POLICY = Object.freeze({
  model_id: AUTHORITY_LIFECYCLE_MODEL,
  events: AUTHORITY_LIFECYCLE_EVENTS,
  ordering: AUTHORITY_LIFECYCLE_ORDERING,
  canonical_truth_source: 'ACCEPTED_APPEND_ONLY_LIFECYCLE_RECORD_CHAIN',
  semantic_fields_are_snapshot_metadata: true,
  semantic_artifact_mutation_permitted: false,
  unlisted_transition: 'REJECT',
  closed_terminal: true,
});
const PREDECESSOR = 'UNREGISTERED-AIPT-P1-B000';
const PREDECESSOR_MERGE = 'fe0965977447caf8cd7b6e58252bc1b991b7cc6f';
const MIGRATIONS = Object.freeze({
  'internal/storage/postgres/migrations/000001_ledger.sql': 'cbab234c8d6a265397dcc553bd9bdb17006712f77ec482b0ef8332f050c9f591',
  'internal/storage/postgres/migrations/000002_playtest_queue.sql': '47f02a5a2129473caa0db5e359a0b294a01b2a96329d9f6fa08ac87cc429c997',
});
const LIFECYCLE_PATHS = [
  'docs/authority/registry/authority-lifecycle/records/unregistered-aipt-p1-b000/001-merged.json',
  'docs/authority/registry/authority-lifecycle/records/unregistered-aipt-p1-b000/002-post-merge-verified.json',
  'docs/authority/registry/authority-lifecycle/records/unregistered-aipt-p1-b000/003-closed.json',
];
const SCHEMA_PATHS = [
  'schemas/run-core/v1/aipt-run-binding.schema.json',
  'schemas/run-core/v1/aipt-action-proposal.schema.json',
  'schemas/run-core/v1/aipt-run-state.schema.json',
  'schemas/run-core/v1/aipt-run-event.schema.json',
  'schemas/run-core/v1/aipt-run-projection.schema.json',
  'schemas/run-core/v1/aipt-action-receipt.schema.json',
];
const RUN_CORE_FILES = [
  'internal/runcore/doc.go', 'internal/runcore/engine.go', 'internal/runcore/errors.go',
  'internal/runcore/postgres.go', 'internal/runcore/projection.go', 'internal/runcore/replay.go',
  'internal/runcore/rng.go', 'internal/runcore/types.go', 'internal/runcore/validation.go',
  'internal/runcore/runcore_test.go', 'internal/runcore/postgres_integration_test.go',
];
const POSTGRES_B002_FILES = Object.freeze([
  'internal/storage/postgres/errors.go',
  'internal/storage/postgres/hash.go',
  'internal/storage/postgres/ledger.go',
  'internal/storage/postgres/ledger_test.go',
  'internal/storage/postgres/verify.go',
]);
const BUSINESS_ARTIFACTS = Object.freeze([
  ...RUN_CORE_FILES,
  ...SCHEMA_PATHS,
  ...POSTGRES_B002_FILES,
]);
const REQUIRED_CHANGED = new Set([
  '.github/workflows/ci.yml', 'README.md', 'docs/architecture/README.md',
  'docs/authority/BATCH_DEPENDENCY_GRAPH.md', 'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json', 'docs/milestones/MVP.md',
  'docs/runtime/README.md', 'docs/security/README.md', 'docs/storage/README.md',
  'docs/test-model/README.md', 'package.json', 'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/historical-governance.mjs',
  'scripts/ci/validate/mvp-b001-regression.mjs', 'scripts/ci/validate/mvp-b002.mjs',
  'scripts/ci/validate/workflow.mjs',
  'internal/storage/postgres/errors.go', 'internal/storage/postgres/hash.go',
  'internal/storage/postgres/ledger.go', 'internal/storage/postgres/ledger_test.go',
  'internal/storage/postgres/verify.go',
  ...RUN_CORE_FILES,
  ...SCHEMA_PATHS,
]);
const ALLOWED_CHANGED = new Set(REQUIRED_CHANGED);

function read(repo, relative) {
  return fs.readFileSync(path.join(repo, relative), 'utf8');
}

function readJSON(repo, relative) {
  return JSON.parse(read(repo, relative));
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function gitOut(repo, args) {
  const result = git(repo, args, { check: false });
  return result.status === 0 ? result.stdout.trim() : null;
}

function changedPaths(repo) {
  const committed = gitOut(repo, ['diff', '--name-only', '--no-renames', BASE_COMMIT, 'HEAD'])?.split('\n').filter(Boolean) ?? [];
  const worktree = gitOut(repo, ['diff', '--name-only', '--no-renames'])?.split('\n').filter(Boolean) ?? [];
  const staged = gitOut(repo, ['diff', '--cached', '--name-only', '--no-renames'])?.split('\n').filter(Boolean) ?? [];
  const untracked = gitOut(repo, ['ls-files', '--others', '--exclude-standard'])?.split('\n').filter(Boolean) ?? [];
  return [...new Set([...committed, ...worktree, ...staged, ...untracked]
    .filter((item) => item && !item.split('/').includes('node_modules')))].sort();
}

function lines(result) {
  return result?.status === 0 ? result.stdout.split('\n').filter(Boolean) : [];
}

function commitFacts(repo, commit) {
  if (!commit) return null;
  const history = git(repo, ['rev-list', '--parents', '-n', '1', commit], { check: false });
  if (history.status !== 0) return null;
  const [resolved, ...parents] = history.stdout.trim().split(/\s+/u);
  const tree = git(repo, ['rev-parse', `${commit}^{tree}`], { check: false });
  const subject = git(repo, ['show', '-s', '--format=%s', commit], { check: false });
  return tree.status === 0
    ? { commit: resolved, parents, tree: tree.stdout.trim(), subject: subject.stdout.trim() }
    : null;
}

function isAncestor(repo, ancestor, descendant) {
  return git(repo, ['merge-base', '--is-ancestor', ancestor, descendant], { check: false }).status === 0;
}

function committedChangedPaths(repo, from, to) {
  return lines(git(repo, ['diff', '--name-only', '--no-renames', from, to], { check: false })).sort();
}

function worktreeChangedPaths(repo) {
  const tracked = [
    ...lines(git(repo, ['diff', '--name-only', '--no-renames'], { check: false })),
    ...lines(git(repo, ['diff', '--cached', '--name-only', '--no-renames'], { check: false })),
  ];
  const untracked = lines(git(repo, ['ls-files', '--others', '--exclude-standard'], { check: false }));
  return [...new Set([...tracked, ...untracked]
    .filter((item) => item && !item.split('/').includes('node_modules')))].sort();
}

function candidateChangedPaths(repo, candidate, includeWorktree) {
  const committed = committedChangedPaths(repo, BASE_COMMIT, candidate);
  return includeWorktree
    ? [...new Set([...committed, ...worktreeChangedPaths(repo)])].sort()
    : committed;
}

function repairChangedPaths(repo, candidate, includeWorktree) {
  const committed = committedChangedPaths(repo, ORIGINAL_CANDIDATE, candidate);
  return includeWorktree
    ? [...new Set([...committed, ...worktreeChangedPaths(repo)])].sort()
    : committed;
}

function exactSet(left, right) {
  return Array.isArray(left) && Array.isArray(right) &&
    JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
}

function candidateLineage(repo, candidate) {
  const merges = lines(git(repo, ['rev-list', '--merges', `${BASE_COMMIT}..${candidate}`], { check: false }));
  const history = lines(git(repo, ['rev-list', '--reverse', '--parents', `${BASE_COMMIT}..${candidate}`], { check: false }));
  let previous = BASE_COMMIT;
  let linear = history.length > 0;
  for (const entry of history) {
    const [commit, ...parents] = entry.split(/\s+/u);
    if (parents.length !== 1 || parents[0] !== previous) linear = false;
    previous = commit;
  }
  return {
    descendsBase: isAncestor(repo, BASE_COMMIT, candidate),
    descendsOriginal: isAncestor(repo, ORIGINAL_CANDIDATE, candidate),
    merges,
    linear,
    commitCount: history.length,
  };
}

function blobText(repo, commit, relative) {
  const result = git(repo, ['show', `${commit}:${relative}`], { check: false });
  return result.status === 0 ? result.stdout : null;
}

function currentBusinessEquivalent(repo, candidate) {
  const problems = [];
  for (const relative of BUSINESS_ARTIFACTS) {
    const candidateValue = blobText(repo, candidate, relative);
    let currentValue = null;
    try { currentValue = read(repo, relative); } catch { currentValue = null; }
    if (candidateValue === null || currentValue === null || candidateValue !== currentValue) {
      problems.push(`B002 business artifact differs from accepted Candidate: ${relative}`);
    }
  }
  return { result: problems.length === 0 ? 'PASS' : 'FAIL', problems };
}

function originalBusinessEquivalent(repo, candidate, includeWorktree) {
  const repair = repairChangedPaths(repo, candidate, includeWorktree);
  const unauthorized = repair.filter((relative) => !R1_REPAIR_PATHS.includes(relative));
  return {
    result: unauthorized.length === 0 ? 'PASS' : 'FAIL',
    repair_paths: repair,
    unauthorized_paths: unauthorized,
    problems: unauthorized.map((relative) => `R1 changed non-routing artifact relative to original Candidate: ${relative}`),
  };
}

function firstParentContains(repo, ancestor, descendant) {
  if (ancestor === descendant) return true;
  return lines(git(repo, ['rev-list', '--first-parent', descendant], { check: false })).includes(ancestor);
}

function firstIntroduction(repo, merge, head, relative) {
  const introductions = lines(git(repo, [
    'log', '--first-parent', '--reverse', '--format=%H', '--diff-filter=A', `${merge}..${head}`, '--', relative,
  ], { check: false }));
  if (introductions.length !== 1) return null;
  const commit = introductions[0];
  const ordinal = Number(gitOut(repo, ['rev-list', '--first-parent', '--count', `${merge}..${commit}`]));
  return Number.isInteger(ordinal) && ordinal > 0 ? { commit, ordinal } : null;
}

function lifecycleInventory(repo) {
  const parent = path.join(repo, path.dirname(B002_RECORD_ROOT));
  if (!fs.existsSync(parent)) return [];
  const found = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile() && entry.name.endsWith('.json')) {
        const relative = path.relative(repo, absolute).split(path.sep).join('/');
        try {
          const value = JSON.parse(fs.readFileSync(absolute, 'utf8'));
          if (value?.task_id === TASK_ID || relative.startsWith(`${B002_RECORD_ROOT}/`)) found.push(relative);
        } catch {
          if (relative.startsWith(`${B002_RECORD_ROOT}/`)) found.push(relative);
        }
      }
    }
  };
  visit(parent);
  return found.sort();
}

function businessSemanticPath(relative) {
  return BUSINESS_ARTIFACTS.includes(relative);
}

function validateB002LifecycleRecords(repo, head) {
  const inventory = lifecycleInventory(repo);
  if (inventory.length === 0) return { state: 'NONE', result: 'PASS', problems: [], inventory };
  const problems = [];
  if (!exactSet(inventory, B002_RECORD_PATHS)) {
    problems.push('B002 lifecycle inventory is partial, forked, duplicated or outside the canonical path set');
  }
  let records = [];
  try { records = B002_RECORD_PATHS.map((relative) => readJSON(repo, relative)); }
  catch (error) {
    return { state: 'INVALID', result: 'FAIL', problems: [...problems, `B002 lifecycle record unreadable: ${error.message}`], inventory };
  }
  const recordSchema = readJSON(repo, 'schemas/authority-lifecycle/v1/aipt-authority-lifecycle-record.schema.json');
  for (let index = 0; index < records.length; index += 1) {
    for (const error of validateInstance(recordSchema, records[index]).errors) {
      problems.push(`${B002_RECORD_PATHS[index]}: ${error.message}`);
    }
    const record = records[index];
    if (record?.record_id !== B002_RECORD_IDS[index] || record?.task_id !== TASK_ID ||
        record?.event !== AUTHORITY_LIFECYCLE_EVENTS[index] || record?.event_sequence !== index + 1 ||
        record?.record_identity?.path !== B002_RECORD_PATHS[index] ||
        record?.authority_basis?.authorized_by_task !== TASK_ID ||
        record?.authority_basis?.authorization_kind !== 'ACCEPTED_LIFECYCLE_MODEL' ||
        record?.created_by_task !== TASK_ID || record?.provenance?.source_task !== TASK_ID ||
        record?.provenance?.record_creator_task !== TASK_ID) {
      problems.push(`${B002_RECORD_PATHS[index]} canonical identity/authority/provenance is not exact`);
    }
  }
  const identity = records[0]?.semantic_artifact_identity;
  for (const record of records.slice(1)) problems.push(...validateImmutableSemanticIdentity(identity, record.semantic_artifact_identity).problems);
  if (identity?.task_id !== TASK_ID || identity?.artifact_id !== TASK_ID ||
      identity?.semantic_snapshot_state !== 'CANDIDATE_FROZEN' || identity?.semantic_snapshot_accepted !== false ||
      !businessSemanticPath(identity?.artifact_path)) {
    problems.push('B002 lifecycle semantic identity is not an exact frozen business artifact identity');
  }
  const candidate = commitFacts(repo, identity?.candidate_commit);
  if (!candidate || candidate.tree !== identity?.candidate_tree) problems.push('B002 lifecycle Candidate commit/tree is unreadable or inconsistent');
  const artifactAtCandidate = identity?.artifact_path ? blobText(repo, identity.candidate_commit, identity.artifact_path) : null;
  let currentArtifact = null;
  try { currentArtifact = identity?.artifact_path ? read(repo, identity.artifact_path) : null; } catch { currentArtifact = null; }
  if (artifactAtCandidate === null || sha256(artifactAtCandidate) !== identity?.artifact_sha256 ||
      currentArtifact !== artifactAtCandidate) {
    problems.push('B002 lifecycle semantic artifact bytes differ from the accepted Candidate');
  }
  const lineage = candidate ? candidateLineage(repo, candidate.commit) : { descendsBase: false, descendsOriginal: false, merges: ['invalid'], linear: false };
  const equivalence = candidate ? originalBusinessEquivalent(repo, candidate.commit, false) : { result: 'FAIL', repair_paths: [], problems: ['Candidate missing'] };
  if (!lineage.descendsBase || !lineage.descendsOriginal || !lineage.linear || lineage.merges.length !== 0 ||
      !exactSet(equivalence.repair_paths, R1_REPAIR_PATHS)) {
    problems.push('B002 lifecycle Candidate is not the exact linear R1 routing-only descendant of the original Candidate');
  }
  problems.push(...equivalence.problems);
  const mergeEvidence = records[0]?.event_evidence?.merge_identity;
  const acceptedMerge = commitFacts(repo, mergeEvidence?.commit);
  if (!acceptedMerge || acceptedMerge.commit === FAILED_MERGE ||
      !exactSet(acceptedMerge.parents, [FAILED_MERGE, candidate?.commit]) ||
      acceptedMerge.parents?.[0] !== FAILED_MERGE || acceptedMerge.parents?.[1] !== candidate?.commit ||
      acceptedMerge.tree !== candidate?.tree || mergeEvidence?.tree !== candidate?.tree ||
      JSON.stringify(mergeEvidence?.parents) !== JSON.stringify(acceptedMerge.parents)) {
    problems.push('B002 lifecycle MERGED evidence is not the legal second merge over the exact failed first merge context');
  }
  if (!acceptedMerge || !isAncestor(repo, acceptedMerge.commit, head) || !firstParentContains(repo, acceptedMerge.commit, head)) {
    problems.push('current successor is not on the accepted B002 merge first-parent lifecycle');
  }
  const recordAcceptance = {};
  const introducedRecords = [];
  let closeoutCommit = null;
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    const relative = B002_RECORD_PATHS[index];
    const introduction = acceptedMerge ? firstIntroduction(repo, acceptedMerge.commit, head, relative) : null;
    if (!introduction) {
      problems.push(`${relative} lacks a unique accepted first-parent introduction commit`);
      continue;
    }
    const introducedText = blobText(repo, introduction.commit, relative);
    const currentText = read(repo, relative);
    if (introducedText === null || introducedText !== currentText) problems.push(`accepted B002 lifecycle record was rewritten: ${relative}`);
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
    if (record.event === 'CLOSED') closeoutCommit = introduction.commit;
  }
  if (introducedRecords.length === records.length) problems.push(...validateAppendOnlyRecordSet(introducedRecords, records).problems);
  const post = records[1]?.event_evidence?.post_merge_evidence;
  const resolution = resolveEffectiveAuthority({
    semantic_artifact_identity: identity,
    records,
    policy: B002_LIFECYCLE_POLICY,
    record_acceptance: recordAcceptance,
    authority_basis_acceptance: Object.fromEntries(B002_RECORD_IDS.map((id) => [id, true])),
    evidence_catalogue: {
      merge_commits: acceptedMerge ? { [acceptedMerge.commit]: { tree: acceptedMerge.tree, parents: acceptedMerge.parents, accepted_ancestry: true } } : {},
      post_merge_runs: post ? { [String(post.run_id)]: post } : {},
      closeout_records: closeoutCommit ? { [B002_RECORD_IDS[2]]: { commit: closeoutCommit, governance_only: true, owner_authorized: true } } : {},
    },
    expected_accepted_record_ids: B002_RECORD_IDS,
    expected_lifecycle_state: 'CLOSED',
  });
  problems.push(...resolution.problems);
  const currentBusiness = candidate ? currentBusinessEquivalent(repo, candidate.commit) : { result: 'FAIL', problems: ['Candidate missing'] };
  problems.push(...currentBusiness.problems);
  const status = readJSON(repo, 'docs/authority/registry/project-status.json');
  const standalone = status.tracks?.['AIPT-STANDALONE'];
  const pending = status.repositories?.AIPT?.pending_candidate;
  const projected = status.repositories?.AIPT?.mvp_b002;
  let projectionConsistent = standalone?.batch_history?.[TASK_ID] === 'MERGED_CLOSED' && pending?.task_id !== TASK_ID;
  if (projected !== undefined) {
    projectionConsistent = projectionConsistent && projected?.task_id === TASK_ID && projected?.state === 'MERGED_CLOSED' &&
      projected?.candidate?.commit === candidate?.commit && projected?.candidate?.tree === candidate?.tree &&
      projected?.implementation_merge?.commit === acceptedMerge?.commit && projected?.implementation_merge?.tree === acceptedMerge?.tree &&
      projected?.post_merge_ci?.run === post?.run_id && projected?.post_merge_ci?.head_sha === acceptedMerge?.commit &&
      projected?.post_merge_ci?.conclusion === 'success' && projected?.closed === true;
  }
  if (!projectionConsistent) problems.push('B002 project-status projection contradicts the canonical CLOSED lifecycle');
  const closeout = commitFacts(repo, closeoutCommit);
  const directCloseout = closeout?.parents?.length === 1 && closeout.parents[0] === acceptedMerge?.commit &&
    records.every((record) => recordAcceptance[record.record_id]?.commit === closeoutCommit);
  return {
    state: problems.length === 0 ? 'CLOSED' : 'INVALID',
    result: problems.length === 0 && resolution.result === 'ACCEPT' && resolution.effective ? 'PASS' : 'FAIL',
    problems,
    inventory,
    records,
    identity,
    candidate: candidate?.commit ?? null,
    candidateTree: candidate?.tree ?? null,
    acceptedMerge: acceptedMerge?.commit ?? null,
    acceptedMergeTree: acceptedMerge?.tree ?? null,
    closeoutCommit,
    directCloseout,
    resolution,
    projectionConsistent,
    businessUnchanged: currentBusiness.result === 'PASS',
  };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function schemaFixtures() {
  const binding = {
    schema: 'aipt.run-binding/v1', run_id: 'run-validator',
    manifest: { id: 'manifest-1', schema: 'aipt.run-manifest/v1', canonical_sha256: '1'.repeat(64) },
    runtime_adapter_input: { id: 'adapter-input-1', schema: 'aipt.runtime-adapter-input/v1', canonical_sha256: '2'.repeat(64) },
    source_package: {
      package_id: 'package-1', schema: 'aipt.playtest-package/v1', repository: 'fixture/game',
      commit: '3'.repeat(40), tree: '4'.repeat(40), canonical_sha256: '5'.repeat(64),
    },
  };
  const proposal = {
    schema: 'aipt.action-proposal/v1', action_id: 'action-1', run_id: binding.run_id,
    actor_id: 'actor-1', action_type: 'fixture.increment/v1', expected_sequence: 1,
    source: { kind: 'RULE_ID', reference: 'RULE-SYNTHETIC-001' }, payload: { delta: 1 },
    rng_requests: [{ stream_id: 'checks', count: 1 }],
    temporary_ruling: {
      ruling_id: 'ruling-1', scope: 'synthetic', reason: 'synthetic public fixture',
      reversible: true, valid_through_sequence: 3,
    },
  };
  const state = {
    schema: 'aipt.run-state/v1', binding, sequence: 2,
    rng_version: 'AIPT_RNG_HMAC_SHA256_V1', commitment_version: 'AIPT_SEED_COMMITMENT_SHA256_V1',
    seed_commitment: '6'.repeat(64), rng_cursors: { checks: 1 }, domain_state: { counter: 1 },
  };
  const event = {
    schema: 'aipt.run-event/v1', version: 1, kind: 'AIPT_RUN_ACTION_COMMITTED_V1',
    run_id: binding.run_id, sequence: 2, binding,
    rng_version: state.rng_version, commitment_version: state.commitment_version,
    seed_commitment: state.seed_commitment, before_state_hash: '7'.repeat(64),
    after_state: state, after_state_hash: '8'.repeat(64), action: {
      proposal, proposal_sha256: '9'.repeat(64),
      rng_draws: [{ version: state.rng_version, stream_id: 'checks', draw_index: 1, value_hex: '0123456789abcdef' }],
    },
  };
  const projection = {
    schema: 'aipt.run-projection/v1', run_id: binding.run_id, manifest_id: binding.manifest.id,
    sequence: 2, state_sha256: '8'.repeat(64), domain_state: { counter: 1 },
  };
  const receipt = {
    schema: 'aipt.action-receipt/v1', run_id: binding.run_id, action_id: proposal.action_id,
    sequence: 2, event_hash: 'a'.repeat(64), state_hash: '8'.repeat(64), projection_hash: 'b'.repeat(64),
    rng_draws: event.action.rng_draws,
  };
  return { binding, proposal, state, event, projection, receipt };
}

function sourceContractProblems(repo) {
  const problems = [];
  const engine = read(repo, 'internal/runcore/engine.go');
  const replay = read(repo, 'internal/runcore/replay.go');
  const rng = read(repo, 'internal/runcore/rng.go');
  const types = read(repo, 'internal/runcore/types.go');
  const errors = read(repo, 'internal/runcore/errors.go');
  const postgres = read(repo, 'internal/runcore/postgres.go');
  const ledger = read(repo, 'internal/storage/postgres/ledger.go');
  const verify = read(repo, 'internal/storage/postgres/verify.go');
  const execute = engine.slice(engine.indexOf('func (r *Run) Execute'));
  const ordered = [
    'decodeProposal(rawProposal)', 'handler.ValidatePayload', 'authorizer.Authorize',
    'validateRuleSource(proposal.Source)', 'rules.ValidateRuleSource',
    'proposal.ExpectedSequence != current.Sequence', 'handler.ValidatePrecondition',
    'validateInvariants(current)', 'consumeRNG', 'handler.Apply', 'validateInvariants(next)',
    'store.Append', 'Project(next)', 'r.state = cloneState(next)',
  ];
  let prior = -1;
  for (const token of ordered) {
    const index = execute.indexOf(token);
    if (index === -1 || index <= prior) problems.push(`action pipeline token missing/out of order: ${token}`);
    prior = index;
  }
  const requiredTokens = [
    [types, 'AIPT_RNG_HMAC_SHA256_V1'], [types, 'AIPT_SEED_COMMITMENT_SHA256_V1'],
    [types, 'ExpectedSequence int64'], [types, 'TemporaryRuling'], [types, 'ValidThroughSequence'],
    [rng, 'hmac.New(sha256.New, seed)'], [rng, 'VerifySeedCommitment'],
    [replay, 'VerifyLedgerEvents(events)'], [replay, 'ExpectedFinalStateHash'],
    [postgres, 'pgx.RepeatableRead'], [ledger, 'ExpectedSequence *int64'],
    [verify, 'func VerifyLedgerEvents'], [errors, 'REPLAY_STATE_MISMATCH'],
  ];
  for (const [text, token] of requiredTokens) if (!text.includes(token)) problems.push(`required Run Core token missing: ${token}`);
  for (const code of [
    'INVALID_ACTION', 'UNAUTHORIZED_ACTION', 'RULE_REFERENCE_REQUIRED', 'RULE_VALIDATION_FAILED',
    'STATE_CONFLICT', 'INVARIANT_VIOLATION', 'RNG_INVALID', 'RNG_COMMITMENT_MISMATCH',
    'LEDGER_COMMIT_FAILED', 'REPLAY_INVALID', 'REPLAY_STATE_MISMATCH',
  ]) if (!errors.includes(`"${code}"`)) problems.push(`stable error code missing: ${code}`);
  const production = RUN_CORE_FILES.filter((item) => item.endsWith('.go') && !item.endsWith('_test.go'))
    .map((item) => read(repo, item)).join('\n');
  for (const forbidden of [
    /"net\/http"/u, /"os\/exec"/u, /"math\/rand"/u, /time\s*\.\s*Now\s*\(/u,
    /OPENAI_API_KEY/iu, /DEEPSEEK/iu, /LLAMACPP/iu, /REMOTE_DEEPSEEK/iu,
    /json:"(?:root_)?seed(?:,|")/u, /UNREGISTERED-[A-Z0-9-]+/u,
  ]) if (forbidden.test(production)) problems.push(`forbidden runtime dependency or embedded authority matched ${forbidden}`);
  if (/func\s+\(.*\)\s+Unwrap\s*\(/u.test(errors)) problems.push('structured Run Core errors expose private causes through Unwrap');
  return problems;
}

function schemaProbeResults(schemas, fixtures) {
  const cases = [];
  const add = (name, schemaName, base, mutate) => {
    const value = clone(base); mutate(value);
    cases.push({ name, rejected: validateInstance(schemas[schemaName], value).valid === false });
  };
  add('binding unknown field', 'binding', fixtures.binding, (v) => { v.seed = 'secret'; });
  add('binding missing Manifest', 'binding', fixtures.binding, (v) => { delete v.manifest; });
  add('binding invalid repository', 'binding', fixtures.binding, (v) => { v.source_package.repository = 'not-a-repo'; });
  add('binding invalid digest', 'binding', fixtures.binding, (v) => { v.manifest.canonical_sha256 = 'ABC'; });
  add('proposal unknown field', 'proposal', fixtures.proposal, (v) => { v.state = {}; });
  add('proposal missing source', 'proposal', fixtures.proposal, (v) => { delete v.source; });
  add('proposal unknown source kind', 'proposal', fixtures.proposal, (v) => { v.source.kind = 'MODEL_DECIDES'; });
  add('proposal unsafe sequence', 'proposal', fixtures.proposal, (v) => { v.expected_sequence = 9007199254740992; });
  add('proposal invalid stream', 'proposal', fixtures.proposal, (v) => { v.rng_requests[0].stream_id = 'bad stream'; });
  add('proposal zero draws', 'proposal', fixtures.proposal, (v) => { v.rng_requests[0].count = 0; });
  add('ruling invalid validity', 'proposal', fixtures.proposal, (v) => { v.temporary_ruling.valid_through_sequence = 1; });
  add('state unknown field', 'state', fixtures.state, (v) => { v.authoritative_cache = {}; });
  add('state unknown RNG version', 'state', fixtures.state, (v) => { v.rng_version = 'UNKNOWN'; });
  add('state invalid RNG cursor', 'state', fixtures.state, (v) => { v.rng_cursors.checks = 0; });
  add('event unknown field', 'event', fixtures.event, (v) => { v.seed = 'secret'; });
  add('event unknown version', 'event', fixtures.event, (v) => { v.version = 2; });
  add('event unknown RNG version', 'event', fixtures.event, (v) => { v.rng_version = 'UNKNOWN'; });
  add('event binding nested unknown field', 'event', fixtures.event, (v) => { v.binding.root_seed = 'secret'; });
  add('event state nested unknown field', 'event', fixtures.event, (v) => { v.after_state.authoritative_cache = {}; });
  add('event action nested unknown field', 'event', fixtures.event, (v) => { v.action.model_output = {}; });
  add('event proposal nested unknown source', 'event', fixtures.event, (v) => { v.action.proposal.source.kind = 'MODEL_DECIDES'; });
  add('action event missing action', 'event', fixtures.event, (v) => { delete v.action; });
  add('action event missing before hash', 'event', fixtures.event, (v) => { delete v.before_state_hash; });
  add('genesis carrying action evidence', 'event', fixtures.event, (v) => { v.kind = 'AIPT_RUN_STARTED_V1'; v.sequence = 1; });
  add('projection unknown authority field', 'projection', fixtures.projection, (v) => { v.authoritative = true; });
  add('projection bad state hash', 'projection', fixtures.projection, (v) => { v.state_sha256 = 'bad'; });
  add('receipt seed leakage field', 'receipt', fixtures.receipt, (v) => { v.root_seed = 'secret'; });
  add('receipt bad draw version', 'receipt', fixtures.receipt, (v) => { v.rng_draws[0].version = 'UNKNOWN'; });
  return cases;
}

function collectB002LifecycleFacts(repo, env = process.env) {
  const head = gitOut(repo, ['rev-parse', 'HEAD^{commit}']);
  const headCommit = commitFacts(repo, head);
  const branch = gitOut(repo, ['symbolic-ref', '--short', 'HEAD']);
  const originMain = gitOut(repo, ['rev-parse', 'refs/remotes/origin/main^{commit}']);
  const github = {
    present: env.GITHUB_ACTIONS === 'true',
    event: env.GITHUB_EVENT_NAME || null,
    ref: env.GITHUB_REF || null,
    headRef: env.GITHUB_HEAD_REF || null,
    baseRef: env.GITHUB_BASE_REF || null,
    sha: env.GITHUB_SHA || null,
  };
  const taskBinding = github.present
    ? github.event === 'push' && github.ref === `refs/heads/${BRANCH}`
    : branch === BRANCH;
  const mainBinding = github.present
    ? github.event === 'push' && github.ref === `refs/heads/${MAIN_BRANCH}`
    : branch === MAIN_BRANCH;
  const prBinding = github.present && github.event === 'pull_request' &&
    /^refs\/pull\/\d+\/(?:head|merge)$/u.test(github.ref || '') &&
    github.headRef === BRANCH && github.baseRef === MAIN_BRANCH;
  const lifecycle = validateB002LifecycleRecords(repo, head);
  let phase = 'UNKNOWN';
  if (lifecycle.state !== 'NONE') {
    phase = head === lifecycle.closeoutCommit ? 'CLOSEOUT_SUCCESSOR' : 'CLOSED_HISTORICAL';
  } else if (head === FAILED_MERGE) {
    phase = 'FAILED_MERGE_ATTEMPT';
  } else if (taskBinding) {
    phase = originMain === BASE_COMMIT ? 'INITIAL_CANDIDATE' : 'RECOVERY_CANDIDATE_R1';
  } else if ((mainBinding || prBinding) && headCommit?.parents?.length === 2) {
    phase = 'LEGAL_ACCEPTED_MERGE';
  }
  const candidate = lifecycle.candidate ??
    (phase === 'LEGAL_ACCEPTED_MERGE' ? headCommit?.parents?.[1] :
      (phase === 'INITIAL_CANDIDATE' || phase === 'RECOVERY_CANDIDATE_R1' ? head : null));
  const candidateCommit = commitFacts(repo, candidate);
  const includeWorktree = !github.present && candidate === head;
  const lineage = candidate ? candidateLineage(repo, candidate) : {
    descendsBase: false, descendsOriginal: false, merges: [], linear: false, commitCount: 0,
  };
  const repair = candidate ? originalBusinessEquivalent(repo, candidate, includeWorktree) : {
    result: 'FAIL', repair_paths: [], unauthorized_paths: [], problems: ['Candidate unavailable'],
  };
  const scopePaths = candidate ? candidateChangedPaths(repo, candidate, includeWorktree) : [];
  const scopeValid = candidate !== null && scopePaths.every((relative) => ALLOWED_CHANGED.has(relative)) &&
    [...REQUIRED_CHANGED].every((relative) => scopePaths.includes(relative));
  const failedMerge = commitFacts(repo, FAILED_MERGE);
  const failedLifecyclePaths = lines(git(repo, ['ls-tree', '-r', '--name-only', FAILED_MERGE, '--', B002_RECORD_ROOT], { check: false }));
  return {
    phase,
    baseCommit: BASE_COMMIT,
    baseTree: gitOut(repo, ['rev-parse', `${BASE_COMMIT}^{tree}`]),
    head,
    headTree: headCommit?.tree ?? null,
    headCommit,
    branch,
    originMain,
    github,
    taskBinding,
    mainBinding,
    prBinding,
    candidate,
    candidateTree: candidateCommit?.tree ?? null,
    candidateCommit,
    lineage,
    repairPaths: repair.repair_paths,
    businessSemanticsChanged: repair.result !== 'PASS',
    businessProblems: repair.problems,
    scopePaths,
    scopeValid,
    worktreeClean: worktreeChangedPaths(repo).length === 0,
    failedMerge,
    failedMergeCI: FAILED_MERGE_CI,
    failedLifecycleRecordsCreated: failedLifecyclePaths.length !== 0,
    lifecycle,
  };
}

function validateB002LifecycleFacts(facts) {
  const problems = [];
  try {
    if (facts.baseCommit !== BASE_COMMIT || facts.baseTree !== BASE_TREE) problems.push('exact B002 Base identity drifted');
    if (facts.github?.present && facts.github.sha !== facts.head) problems.push('GITHUB_SHA is not checked-out HEAD');
    if (facts.failedMerge?.commit !== FAILED_MERGE || facts.failedMerge?.tree !== FAILED_MERGE_TREE ||
        JSON.stringify(facts.failedMerge?.parents) !== JSON.stringify(FAILED_MERGE_PARENTS)) {
      problems.push('first failed B002 merge identity drifted');
    }
    if (facts.failedMergeCI?.run_id !== FAILED_MERGE_CI.run_id || facts.failedMergeCI?.head_sha !== FAILED_MERGE ||
        facts.failedMergeCI?.conclusion !== 'failure' || facts.failedMergeCI?.jobs_passed !== 3 ||
        facts.failedMergeCI?.jobs_failed !== 2) {
      problems.push('first B002 merge CI is not permanently classified as failure');
    }
    if (facts.failedLifecycleRecordsCreated) problems.push('failed first B002 merge has lifecycle records and must never be promoted');
    const candidateRequired = !['FAILED_MERGE_ATTEMPT', 'UNKNOWN'].includes(facts.phase);
    if (candidateRequired) {
      if (!facts.candidate || !facts.candidateTree || !facts.lineage?.descendsBase || !facts.lineage?.linear ||
          facts.lineage?.merges?.length !== 0) problems.push('B002 Candidate lineage is not linear/zero-merge from exact Base');
      if (!facts.scopeValid) problems.push('B002 Candidate Base diff is outside the frozen B002 scope or misses required artifacts');
      if (!facts.worktreeClean) problems.push('B002 lifecycle checkout is not clean');
    }
    switch (facts.phase) {
      case 'INITIAL_CANDIDATE':
        if (!facts.taskBinding || facts.originMain !== BASE_COMMIT) problems.push('initial Candidate is not bound to task branch and exact Base origin/main');
        if (facts.candidate !== ORIGINAL_CANDIDATE || facts.candidateTree !== ORIGINAL_CANDIDATE_TREE) {
          problems.push('initial Candidate is not the exact original B002 Candidate/tree');
        }
        if (facts.lifecycle?.state !== 'NONE') problems.push('initial Candidate unexpectedly carries B002 lifecycle records');
        break;
      case 'RECOVERY_CANDIDATE_R1':
        if (!facts.taskBinding || facts.originMain !== FAILED_MERGE) problems.push('R1 recovery Candidate is not bound to exact f4ceabe origin/main');
        if (!facts.lineage?.descendsOriginal || facts.candidate === ORIGINAL_CANDIDATE ||
            !exactSet(facts.repairPaths, R1_REPAIR_PATHS) || facts.businessSemanticsChanged) {
          problems.push('R1 recovery Candidate is not the exact routing-only descendant of d81f201');
        }
        if (facts.lifecycle?.state !== 'NONE') problems.push('R1 recovery Candidate must not fabricate lifecycle records');
        break;
      case 'LEGAL_ACCEPTED_MERGE':
        if (!facts.mainBinding && !facts.prBinding) problems.push('second merge is not bound to main push or exact task-to-main PR');
        if (!facts.headCommit || facts.headCommit.parents?.length !== 2 ||
            facts.headCommit.parents[0] !== FAILED_MERGE || facts.headCommit.parents[1] !== facts.candidate ||
            facts.headCommit.tree !== facts.candidateTree || facts.head === FAILED_MERGE) {
          problems.push('second B002 merge parents/tree are not exact');
        }
        if (![FAILED_MERGE, facts.head].includes(facts.originMain)) problems.push('second merge origin/main is not exact parent1 or pushed merge HEAD');
        if (!facts.lineage?.descendsOriginal || !exactSet(facts.repairPaths, R1_REPAIR_PATHS) || facts.businessSemanticsChanged) {
          problems.push('second merge Candidate is not the authorized routing-only R1 lineage');
        }
        if (facts.lifecycle?.state !== 'NONE') problems.push('post-merge HEAD must not pre-create lifecycle closeout records');
        break;
      case 'CLOSEOUT_SUCCESSOR':
      case 'CLOSED_HISTORICAL': {
        const lifecycle = facts.lifecycle;
        if (lifecycle?.result !== 'PASS' || lifecycle?.state !== 'CLOSED' ||
            lifecycle?.resolution?.lifecycle_state !== 'CLOSED' || lifecycle?.resolution?.effective !== true ||
            lifecycle?.acceptedMerge === FAILED_MERGE || lifecycle?.candidate !== facts.candidate ||
            lifecycle?.candidateTree !== facts.candidateTree || lifecycle?.projectionConsistent !== true ||
            lifecycle?.businessUnchanged !== true || lifecycle?.records?.length !== 3 ||
            new Set(lifecycle?.records?.map((record) => record.event)).size !== 3 ||
            !exactSet(lifecycle?.records?.map((record) => record.record_id), B002_RECORD_IDS)) {
          problems.push('canonical B002 CLOSED lifecycle/identity/projection is invalid');
        }
        if (!facts.lineage?.descendsOriginal || !exactSet(facts.repairPaths, R1_REPAIR_PATHS) || facts.businessSemanticsChanged) {
          problems.push('closed B002 semantic Candidate is not the routing-only R1 lineage');
        }
        if (facts.phase === 'CLOSEOUT_SUCCESSOR' && (!lifecycle?.directCloseout || facts.head !== lifecycle?.closeoutCommit)) {
          problems.push('B002 closeout successor is not the direct governance lifecycle child of accepted merge');
        }
        break;
      }
      case 'FAILED_MERGE_ATTEMPT':
        problems.push('f4ceabe is permanently FAILED_MERGE_ATTEMPT and cannot be accepted or closed');
        break;
      default:
        problems.push('checkout cannot be classified into an authorized B002 lifecycle mode');
    }
  } catch (error) {
    problems.push(`structured B002 lifecycle fact validation error: ${error.message}`);
  }
  return { result: problems.length === 0 ? 'PASS' : 'FAIL', phase: facts.phase, problems };
}

function syntheticLifecycleRecords() {
  return B002_RECORD_IDS.map((recordId, index) => ({
    record_id: recordId,
    event: AUTHORITY_LIFECYCLE_EVENTS[index],
  }));
}

function b002LifecycleRegressionChecks() {
  const oid = (character) => character.repeat(40);
  const base = {
    phase: 'INITIAL_CANDIDATE', baseCommit: BASE_COMMIT, baseTree: BASE_TREE,
    head: ORIGINAL_CANDIDATE, headTree: ORIGINAL_CANDIDATE_TREE,
    headCommit: { commit: ORIGINAL_CANDIDATE, tree: ORIGINAL_CANDIDATE_TREE, parents: [BASE_COMMIT] },
    branch: BRANCH, originMain: BASE_COMMIT,
    github: { present: false, event: null, ref: null, headRef: null, baseRef: null, sha: null },
    taskBinding: true, mainBinding: false, prBinding: false,
    candidate: ORIGINAL_CANDIDATE, candidateTree: ORIGINAL_CANDIDATE_TREE,
    lineage: { descendsBase: true, descendsOriginal: true, merges: [], linear: true, commitCount: 1 },
    repairPaths: [], businessSemanticsChanged: false, businessProblems: [],
    scopePaths: [...REQUIRED_CHANGED], scopeValid: true, worktreeClean: true,
    failedMerge: { commit: FAILED_MERGE, tree: FAILED_MERGE_TREE, parents: [...FAILED_MERGE_PARENTS] },
    failedMergeCI: { ...FAILED_MERGE_CI }, failedLifecycleRecordsCreated: false,
    lifecycle: { state: 'NONE', result: 'PASS', problems: [], inventory: [] },
  };
  const recoveryCandidate = oid('a');
  const recoveryTree = oid('b');
  const recovery = {
    ...clone(base), phase: 'RECOVERY_CANDIDATE_R1', head: recoveryCandidate, headTree: recoveryTree,
    headCommit: { commit: recoveryCandidate, tree: recoveryTree, parents: [ORIGINAL_CANDIDATE] },
    originMain: FAILED_MERGE, candidate: recoveryCandidate, candidateTree: recoveryTree,
    lineage: { ...base.lineage, commitCount: 2 }, repairPaths: [...R1_REPAIR_PATHS],
  };
  const legalMerge = oid('c');
  const legal = {
    ...clone(recovery), phase: 'LEGAL_ACCEPTED_MERGE', head: legalMerge, headTree: recoveryTree,
    headCommit: { commit: legalMerge, tree: recoveryTree, parents: [FAILED_MERGE, recoveryCandidate] },
    branch: MAIN_BRANCH, originMain: legalMerge, taskBinding: false, mainBinding: true,
  };
  const closeoutCommit = oid('d');
  const closedLifecycle = {
    state: 'CLOSED', result: 'PASS', problems: [], records: syntheticLifecycleRecords(),
    candidate: recoveryCandidate, candidateTree: recoveryTree,
    acceptedMerge: legalMerge, acceptedMergeTree: recoveryTree,
    closeoutCommit, directCloseout: true, projectionConsistent: true, businessUnchanged: true,
    resolution: { result: 'ACCEPT', lifecycle_state: 'CLOSED', effective: true },
  };
  const closeout = {
    ...clone(legal), phase: 'CLOSEOUT_SUCCESSOR', head: closeoutCommit, headTree: oid('e'),
    headCommit: { commit: closeoutCommit, tree: oid('e'), parents: [legalMerge] },
    originMain: closeoutCommit, lifecycle: clone(closedLifecycle),
  };
  const later = oid('f');
  const historical = {
    ...clone(closeout), phase: 'CLOSED_HISTORICAL', head: later, headTree: oid('1'),
    headCommit: { commit: later, tree: oid('1'), parents: [closeoutCommit] },
    originMain: later, lifecycle: { ...clone(closedLifecycle), directCloseout: false },
  };
  const cases = [
    ['R1-06', 'initial B002 Candidate', base, 'PASS'],
    ['R1-07', 'exact recovery Candidate over f4ceabe', recovery, 'PASS'],
    ['R1-08', 'arbitrary origin/main drift', { ...clone(recovery), originMain: oid('9') }, 'FAIL'],
    ['R1-09', 'recovery Candidate changes Run Core business', { ...clone(recovery), businessSemanticsChanged: true }, 'FAIL'],
    ['R1-10', 'recovery Candidate contains merge', { ...clone(recovery), lineage: { ...recovery.lineage, merges: [oid('8')], linear: false } }, 'FAIL'],
    ['R1-11', 'synthetic second legal merge', legal, 'PASS'],
    ['R1-12', 'second merge wrong parent2', { ...clone(legal), headCommit: { ...legal.headCommit, parents: [FAILED_MERGE, oid('7')] } }, 'FAIL'],
    ['R1-13', 'second merge tree differs from Candidate', { ...clone(legal), headCommit: { ...legal.headCommit, tree: oid('6') } }, 'FAIL'],
    ['R1-14', 'second merge carries unauthorized content', { ...clone(legal), repairPaths: [...R1_REPAIR_PATHS, 'internal/runcore/engine.go'] }, 'FAIL'],
    ['R1-15', 'synthetic B002 closeout successor', closeout, 'PASS'],
    ['R1-16', 'B002 CLOSED historical later successor', historical, 'PASS'],
    ['R1-17', 'B002 CLOSED chain fork', { ...clone(historical), lifecycle: { ...clone(historical.lifecycle), records: [...syntheticLifecycleRecords(), { record_id: `${TASK_ID}-FORK`, event: 'POST_MERGE_VERIFIED' }] } }, 'FAIL'],
    ['R1-18', 'duplicate B002 CLOSED', { ...clone(historical), lifecycle: { ...clone(historical.lifecycle), records: [...syntheticLifecycleRecords(), { record_id: `${TASK_ID}-DUPLICATE-CLOSED`, event: 'CLOSED' }] } }, 'FAIL'],
  ];
  return cases.map(([id, label, facts, expected]) => {
    let actual = 'FAIL';
    let threw = false;
    try { actual = validateB002LifecycleFacts(facts).result; } catch { threw = true; }
    return { id, label, expected, actual, threw, matched: !threw && actual === expected };
  });
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push(`ok: ${message}`);
  const fail = (message) => { pass = false; details.push(`FAIL: ${message}`); };
  try {
    const lifecycleFacts = collectB002LifecycleFacts(ctx.repo);
    const lifecycleValidation = validateB002LifecycleFacts(lifecycleFacts);
    lifecycleValidation.problems.forEach(fail);
    if (lifecycleValidation.result === 'PASS') {
      ok(`${lifecycleValidation.phase} topology, exact failed-merge context and lifecycle routing verified`);
    }
    const lifecycleProbes = b002LifecycleRegressionChecks();
    lifecycleProbes.filter((probe) => !probe.matched).forEach((probe) =>
      fail(`${probe.id} ${probe.label} expected ${probe.expected}, got ${probe.actual}${probe.threw ? ' (threw)' : ''}`));
    if (lifecycleProbes.every((probe) => probe.matched)) {
      ok(`R1-06..R1-18: all ${lifecycleProbes.length} B002 lifecycle/recovery regressions matched`);
    }
    const head = lifecycleFacts.head;
    const headTree = lifecycleFacts.headTree;
    const changed = lifecycleFacts.scopePaths;
    if (lifecycleFacts.baseTree === BASE_TREE && lifecycleFacts.lineage.descendsBase) {
      ok(`exact B002 Base ${BASE_COMMIT}/${BASE_TREE} anchors the semantic Candidate`);
    }
    if (lifecycleFacts.scopeValid) ok(`frozen B002 Candidate scope contains exactly ${changed.length} reviewable files`);
    if (!lifecycleFacts.businessSemanticsChanged) {
      ok(`original Candidate ${ORIGINAL_CANDIDATE}/${ORIGINAL_CANDIDATE_TREE} differs only by the six authorized R1 routing files`);
    }
    if (lifecycleFacts.failedMerge?.tree === ORIGINAL_CANDIDATE_TREE && !lifecycleFacts.failedLifecycleRecordsCreated) {
      ok(`first merge ${FAILED_MERGE} is permanently FAILED_MERGE_ATTEMPT; CI ${FAILED_MERGE_CI.run_id}=failure and no lifecycle records exist`);
    }

    for (const [relative, digest] of Object.entries(MIGRATIONS)) {
      if (sha256(read(ctx.repo, relative)) !== digest) fail(`historical migration drifted: ${relative}`);
    }
    const migrationInventory = fs.readdirSync(path.join(ctx.repo, 'internal/storage/postgres/migrations')).sort();
    if (JSON.stringify(migrationInventory) !== JSON.stringify(['000001_ledger.sql', '000002_playtest_queue.sql'])) {
      fail(`migration inventory drifted: ${JSON.stringify(migrationInventory)}`);
    } else ok('historical migrations are byte-identical and no B002 migration exists');

    for (const relative of [
      'docs/authority/registry/batch-graph.json', 'docs/authority/registry/decisions.json',
      ...LIFECYCLE_PATHS,
    ]) {
      const base = git(ctx.repo, ['show', `${BASE_COMMIT}:${relative}`], { check: false });
      if (base.status !== 0 || base.stdout !== read(ctx.repo, relative)) fail(`frozen authority artifact changed: ${relative}`);
    }
    if (!details.some((item) => item.includes('frozen authority artifact'))) ok('batch graph, decisions, and predecessor lifecycle records are byte-identical');

    const records = LIFECYCLE_PATHS.map((relative) => readJSON(ctx.repo, relative));
    for (let index = 0; index < records.length; index += 1) {
      const record = records[index];
      if (record.task_id !== PREDECESSOR || record.event_sequence !== index + 1 ||
          record.event !== ['MERGED', 'POST_MERGE_VERIFIED', 'CLOSED'][index]) fail(`predecessor lifecycle record ${index + 1} is malformed`);
      if (index === 0 && record.event_evidence?.merge_identity?.commit !== PREDECESSOR_MERGE) fail('predecessor accepted merge identity drifted');
      if (index === 1 && (record.event_evidence?.post_merge_evidence?.run_id !== 33186880614 ||
          record.event_evidence?.post_merge_evidence?.head_sha !== PREDECESSOR_MERGE ||
          record.event_evidence?.post_merge_evidence?.conclusion !== 'success')) fail('predecessor post-merge CI identity drifted');
      if (index > 0) {
        const link = record.predecessor_lifecycle_record;
        if (link?.record_id !== records[index - 1].record_id || link?.record_sha256 !== lifecycleRecordSha256(records[index - 1])) {
          fail(`predecessor lifecycle digest link ${index + 1} drifted`);
        }
      }
    }
    if (records[2]?.effective !== true || records[2]?.event !== 'CLOSED') fail('predecessor is not effectively CLOSED');
    else ok('canonical append-only lifecycle resolves UNREGISTERED-AIPT-P1-B000 as CLOSED/effective');

    const status = readJSON(ctx.repo, 'docs/authority/registry/project-status.json');
    const standalone = status.tracks?.['AIPT-STANDALONE'];
    const pending = status.repositories?.AIPT?.pending_candidate;
    const closedMode = ['CLOSEOUT_SUCCESSOR', 'CLOSED_HISTORICAL'].includes(lifecycleFacts.phase);
    if (!closedMode) {
      if (standalone?.construction !== 'IN_PROGRESS' || standalone?.current_batch !== TASK_ID ||
          standalone?.next_serial_batch !== 'AIPT-MVP-B003' || standalone?.next_batch_state !== 'NOT_AUTHORIZED' ||
          standalone?.next_batch_authorized !== false || standalone?.next_batch_started !== false ||
          standalone?.global_wip !== 1 || standalone?.batch_history?.[PREDECESSOR] !== 'MERGED_CLOSED' ||
          standalone?.batch_history?.[TASK_ID] !== 'IN_PROGRESS' ||
          standalone?.batch_history?.['AIPT-MVP-B003'] !== 'NOT_STARTED') fail('B002 project-status WIP/serial state is not exact');
      else ok('project status is exact B002 IN_PROGRESS / GLOBAL_WIP=1 / B003 unauthorized');
      if (pending?.task_id !== TASK_ID || pending?.state !== 'IN_PROGRESS' || pending?.branch !== BRANCH ||
          pending?.base?.commit !== BASE_COMMIT || pending?.base?.tree !== BASE_TREE ||
          pending?.merge_authorized !== false || pending?.closeout_authorized !== false ||
          pending?.real_model_calls !== 0 || pending?.real_playtest_executed !== false) fail('B002 pending Candidate boundary is malformed');
      else ok('B002 Candidate remains merge/closeout unauthorized with zero model calls/playtests');
    } else if (lifecycleFacts.lifecycle.projectionConsistent) {
      ok('B002 CLOSED project-status remains a derived projection of the canonical lifecycle chain');
    }

    const schemas = {};
    for (const relative of SCHEMA_PATHS) {
      const document = readJSON(ctx.repo, relative);
      const checked = checkSchemaDocument(document);
      if (checked.errors.length) checked.errors.forEach((problem) => fail(`${relative}: ${problem}`));
      schemas[path.basename(relative).replace('aipt-', '').replace('.schema.json', '').replaceAll('-', '_')] = document;
    }
    const normalizedSchemas = {
      binding: readJSON(ctx.repo, SCHEMA_PATHS[0]), proposal: readJSON(ctx.repo, SCHEMA_PATHS[1]),
      state: readJSON(ctx.repo, SCHEMA_PATHS[2]), event: readJSON(ctx.repo, SCHEMA_PATHS[3]),
      projection: readJSON(ctx.repo, SCHEMA_PATHS[4]), receipt: readJSON(ctx.repo, SCHEMA_PATHS[5]),
    };
    const fixtures = schemaFixtures();
    for (const key of Object.keys(fixtures)) {
      const result = validateInstance(normalizedSchemas[key], fixtures[key]);
      if (!result.valid) fail(`${key} positive schema fixture failed: ${result.errors.map((item) => item.message).join('; ')}`);
    }
    const probes = schemaProbeResults(normalizedSchemas, fixtures);
    probes.filter((probe) => !probe.rejected).forEach((probe) => fail(`negative schema probe accepted: ${probe.name}`));
    if (probes.every((probe) => probe.rejected)) ok(`all ${probes.length} schema/security mutations reject`);

    const sourceProblems = sourceContractProblems(ctx.repo);
    sourceProblems.forEach(fail);
    if (sourceProblems.length === 0) ok('Run Core source contract covers ordered gates, atomic ledger boundary, versioned RNG, projection, replay and stable errors');

    const packageJSON = readJSON(ctx.repo, 'package.json');
    const aggregate = read(ctx.repo, 'scripts/ci/run-checks.mjs');
    const workflow = read(ctx.repo, '.github/workflows/ci.yml');
    if (packageJSON.scripts?.['check:mvp-b002'] !== 'node scripts/ci/validate/mvp-b002.mjs' ||
        packageJSON.scripts?.['test:run-core'] !== 'go test ./internal/runcore -count=1' ||
        packageJSON.scripts?.['check:mvp-b001'] !== 'node scripts/ci/validate/mvp-b001-regression.mjs' ||
        packageJSON.scripts?.['check:p1-b000-authority'] !== 'node scripts/ci/validate/historical-governance.mjs --gate p1-b000-authority' ||
        packageJSON.scripts?.['check:p1-b000-authority-amendment'] !== 'node scripts/ci/validate/historical-governance.mjs --gate p1-b000-authority-amendment' ||
        packageJSON.scripts?.['check:p1-b000-authority-amendment-003'] !== 'node scripts/ci/validate/historical-governance.mjs --gate p1-b000-authority-amendment-003' ||
        packageJSON.scripts?.['check:p1-b000-authority-amendment-003:historical-replay'] !== 'node scripts/ci/validate/historical-governance.mjs --gate p1-b000-authority-amendment-003 --historical-only' ||
        packageJSON.scripts?.['check:authority-lifecycle-current'] !== 'node scripts/ci/validate/historical-governance.mjs --gate p1-b000-authority-amendment-003 --current-only') fail('package B002/historical-regression commands are not exact');
    if (!aggregate.includes("import { run as runMvpB002 } from './validate/mvp-b002.mjs'") || !aggregate.includes('runMvpB002(ctx)')) fail('aggregate B002 gate is not wired');
    if (!aggregate.includes('runHistoricalGovernance(ctx)') || aggregate.includes('runP1B000Authority(ctx)') ||
        aggregate.includes('runP1B000AuthorityAmendment(ctx)') || aggregate.includes('runP1B000AuthorityAmendment003(ctx)')) {
      fail('aggregate historical authority/lifecycle replay is not wired');
    }
    for (const command of [
      'pnpm run check:p1-b000-authority-amendment-003', 'pnpm run check:mvp-b002', 'pnpm run test:run-core',
      "go test ./internal/runcore -run '^TestPostgresIntegrationRunCoreAtomicConcurrencyReplay$' -count=1 -v",
      "go test -race ./internal/runcore -run '^TestPostgresIntegrationRunCoreAtomicConcurrencyReplay$' -count=1 -v",
    ]) if (!workflow.includes(command)) fail(`workflow B002 command missing: ${command}`);
    if (workflow.includes('run: node scripts/ci/validate/p1-b000-authority-amendment-003.mjs') ||
        !workflow.includes('Replay Amendment-003 exact immutable closeout and validate current canonical lifecycle integrity') ||
        !workflow.includes('B002 lifecycle-aware candidate merge closeout deterministic Run Core validator')) {
      fail('workflow closed A3 or B002 lifecycle routing is not exact');
    }
    if (!details.some((item) => item.includes('not wired') || item.includes('command missing') || item.includes('commands are not exact'))) {
      ok('standalone, aggregate, unit, PostgreSQL and race CI gates are wired');
    }

    if (!closedMode) {
      for (const [relative, tokens] of Object.entries({
        'README.md': [TASK_ID, 'GLOBAL_WIP = 1', 'merge_authorized = false', 'B003'],
        'docs/architecture/README.md': ['Deterministic Run Core', 'PostgreSQL', 'derived'],
        'docs/authority/PROJECT_STATUS.md': [TASK_ID, BASE_COMMIT, BASE_TREE, 'merge_authorized = false'],
        'docs/runtime/README.md': [TASK_ID, 'AIPT_RNG_HMAC_SHA256_V1', 'replay'],
        'docs/security/README.md': ['seed commitment', 'fail-closed', 'real model calls = 0'],
        'docs/storage/README.md': ['ExpectedSequence', 'authoritative', '000002_playtest_queue.sql'],
        'docs/test-model/README.md': [TASK_ID, 'synthetic', 'PostgreSQL 18.4'],
      })) {
        const value = read(ctx.repo, relative);
        for (const token of tokens) if (!value.includes(token)) fail(`${relative} is missing B002 truth token: ${token}`);
      }
      if (!details.some((item) => item.includes('truth token'))) ok('human documentation states the exact B002 scope and runtime boundaries');
    }

    const unexpected = probes.filter((probe) => !probe.rejected).length +
      lifecycleProbes.filter((probe) => probe.expected === 'FAIL' && probe.actual === 'PASS').length;
    const uncaught = lifecycleProbes.filter((probe) => probe.threw).length;
    const candidateMode = ['INITIAL_CANDIDATE', 'RECOVERY_CANDIDATE_R1'].includes(lifecycleFacts.phase);
    return {
      result: pass ? 'PASS' : 'FAIL', task_id: TASK_ID, details,
      lifecycle_phase: lifecycleFacts.phase,
      base_commit: BASE_COMMIT, base_tree: BASE_TREE,
      original_candidate: ORIGINAL_CANDIDATE, original_candidate_tree: ORIGINAL_CANDIDATE_TREE,
      failed_merge_attempt: FAILED_MERGE, failed_merge_tree: FAILED_MERGE_TREE,
      failed_merge_ci: FAILED_MERGE_CI, failed_merge_ci_preserved_as_failure: true,
      lifecycle_records_created_for_failed_merge: lifecycleFacts.failedLifecycleRecordsCreated,
      candidate_commit: lifecycleFacts.candidate, candidate_tree: lifecycleFacts.candidateTree,
      head_commit: head, head_tree: headTree,
      branch: BRANCH, changed_paths: changed, r1_repair_paths: lifecycleFacts.repairPaths,
      business_semantics_changed: lifecycleFacts.businessSemanticsChanged,
      negative_probes: pass ? 'PASS' : 'FAIL',
      negative_probe_count: probes.length + lifecycleProbes.length,
      lifecycle_regression_probes: lifecycleProbes,
      unexpected_acceptances: unexpected, uncaught_validator_errors: uncaught,
      predecessor_closed: records[2]?.effective === true, historical_migrations_unchanged: true,
      new_migration: 'NONE', real_model_calls: 0, real_playtest_executed: false,
      next_batch_authorized: false, next_batch_started: false,
      merge_eligible: pass && candidateMode, merge_authorized: false, closeout_authorized: false,
    };
  } catch (error) {
    return {
      result: 'FAIL', task_id: TASK_ID,
      details: [...details, `FAIL: structured B002 validator error: ${error.message}`],
      negative_probes: 'NOT_RUN', unexpected_acceptances: 0, uncaught_validator_errors: 1,
      real_model_calls: 0, real_playtest_executed: false,
      merge_eligible: false, merge_authorized: false, closeout_authorized: false,
    };
  }
}

runAsMain(import.meta.url, 'mvp-b002', run);
