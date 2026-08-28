// Generic Authority lifecycle acceptance and effective-state resolver.
//
// Semantic artifacts are immutable snapshots.  Current lifecycle truth is
// derived only from accepted append-only records and their immutable Git
// acceptance context.  This module is deliberately task-agnostic; concrete
// Amendments supply identities, evidence catalogues and bootstrap policy.
import { createHash } from 'node:crypto';

export const AUTHORITY_LIFECYCLE_MODEL =
  'IMMUTABLE_SEMANTICS_APPEND_ONLY_LIFECYCLE_V1';

export const AUTHORITY_LIFECYCLE_EVENTS = Object.freeze([
  'MERGED',
  'POST_MERGE_VERIFIED',
  'CLOSED',
]);

export const AUTHORITY_LIFECYCLE_ORDERING = Object.freeze({
  primary: 'event_sequence_ASCENDING',
  secondary: 'explicit_predecessor_digest_chain',
  tertiary: 'accepted_commit_ordinal_ASCENDING',
  filesystem_enumeration_authoritative: false,
  filesystem_mtime_authoritative: false,
  lexical_latest_filename_authoritative: false,
  current_branch_contents_authoritative: false,
});

const GIT_OID = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const REPO_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))(?!.*\\).+/u;

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function own(value, key) {
  return object(value) && Object.prototype.hasOwnProperty.call(value, key);
}

function exactKeys(value, expected) {
  return object(value) && deepEqual(Object.keys(value).sort(), [...expected].sort());
}

function deepEqual(left, right) {
  if (left === right) return true;
  if (typeof left !== typeof right || left === null || right === null) return false;
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) && left.length === right.length &&
      left.every((item, index) => deepEqual(item, right[index]));
  }
  if (!object(left) || !object(right)) return false;
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return deepEqual(leftKeys, rightKeys) &&
    leftKeys.every((key) => deepEqual(left[key], right[key]));
}

function canonicalValue(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (!object(value)) throw new Error('canonical lifecycle values must be JSON values');
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalValue(value[key])]));
}

export function canonicalLifecycleJSON(value) {
  return JSON.stringify(canonicalValue(value));
}

export function lifecycleRecordSha256(record) {
  return createHash('sha256').update(canonicalLifecycleJSON(record), 'utf8').digest('hex');
}

function semanticIdentityProblems(identity) {
  const problems = [];
  if (!object(identity)) return ['semantic artifact identity is not an object'];
  if (!exactKeys(identity, [
    'task_id', 'artifact_id', 'artifact_path', 'artifact_sha256',
    'candidate_commit', 'candidate_tree', 'semantic_snapshot_state',
    'semantic_snapshot_accepted',
  ])) problems.push('semantic artifact identity has missing or unknown fields');
  if (typeof identity.task_id !== 'string' || identity.task_id.length === 0) {
    problems.push('semantic task identity is missing');
  }
  if (typeof identity.artifact_id !== 'string' || identity.artifact_id.length === 0) {
    problems.push('semantic artifact ID is missing');
  }
  if (typeof identity.artifact_path !== 'string' || !REPO_PATH.test(identity.artifact_path)) {
    problems.push('semantic artifact path is invalid');
  }
  if (typeof identity.artifact_sha256 !== 'string' || !SHA256.test(identity.artifact_sha256)) {
    problems.push('semantic artifact SHA-256 is invalid');
  }
  if (typeof identity.candidate_commit !== 'string' || !GIT_OID.test(identity.candidate_commit)) {
    problems.push('semantic candidate commit is invalid');
  }
  if (typeof identity.candidate_tree !== 'string' || !GIT_OID.test(identity.candidate_tree)) {
    problems.push('semantic candidate tree is invalid');
  }
  if (typeof identity.semantic_snapshot_state !== 'string' || identity.semantic_snapshot_state.length === 0) {
    problems.push('semantic snapshot state is missing');
  }
  if (typeof identity.semantic_snapshot_accepted !== 'boolean') {
    problems.push('semantic snapshot accepted flag is not boolean');
  }
  return problems;
}

export function validateLifecyclePolicy(policy) {
  const problems = [];
  try {
    if (!object(policy)) return { result: 'REJECT', problems: ['lifecycle policy is not an object'] };
    if (policy.model_id !== AUTHORITY_LIFECYCLE_MODEL) problems.push('lifecycle model identity is unsupported');
    if (!deepEqual(policy.events, AUTHORITY_LIFECYCLE_EVENTS)) problems.push('lifecycle event sequence is not exact');
    if (!deepEqual(policy.ordering, AUTHORITY_LIFECYCLE_ORDERING)) {
      problems.push('lifecycle ordering is not deterministic or permits filesystem/mtime authority');
    }
    if (policy.canonical_truth_source !== 'ACCEPTED_APPEND_ONLY_LIFECYCLE_RECORD_CHAIN') {
      problems.push('canonical lifecycle truth source is not the accepted record chain');
    }
    if (policy.semantic_fields_are_snapshot_metadata !== true ||
        policy.semantic_artifact_mutation_permitted !== false ||
        policy.unlisted_transition !== 'REJECT' ||
        policy.closed_terminal !== true) {
      problems.push('semantic/lifecycle separation or fail-closed transition policy drifted');
    }
  } catch (error) {
    problems.push(`malformed lifecycle policy: ${error.message}`);
  }
  return { result: problems.length === 0 ? 'ACCEPT' : 'REJECT', problems };
}

function recordShapeProblems(record) {
  const problems = [];
  if (!object(record)) return ['lifecycle record is not an object'];
  if (!exactKeys(record, [
    'schema', 'record_id', 'task_id', 'semantic_artifact_identity', 'event',
    'event_sequence', 'predecessor_lifecycle_record', 'authority_basis',
    'event_evidence', 'record_identity', 'created_by_task', 'provenance',
    'effective',
  ])) problems.push('record has missing or unknown top-level fields');
  if (record.schema !== 'aipt.public.authority-lifecycle-record/v1') problems.push('record schema identity is unsupported');
  if (typeof record.record_id !== 'string' || record.record_id.length === 0) problems.push('record ID is missing');
  if (typeof record.task_id !== 'string' || record.task_id.length === 0) problems.push('record task ID is missing');
  problems.push(...semanticIdentityProblems(record.semantic_artifact_identity));
  if (!AUTHORITY_LIFECYCLE_EVENTS.includes(record.event)) problems.push('record event is unsupported');
  if (!Number.isInteger(record.event_sequence) || record.event_sequence < 1) problems.push('record sequence is invalid');
  if (!(record.predecessor_lifecycle_record === null || object(record.predecessor_lifecycle_record))) {
    problems.push('record predecessor is neither null nor an object');
  } else if (object(record.predecessor_lifecycle_record) &&
      (!exactKeys(record.predecessor_lifecycle_record, ['record_id', 'record_sha256']) ||
       typeof record.predecessor_lifecycle_record.record_id !== 'string' ||
       !SHA256.test(record.predecessor_lifecycle_record.record_sha256 || ''))) {
    problems.push('record predecessor identity/digest is malformed');
  }
  if (!object(record.authority_basis) ||
      !exactKeys(record.authority_basis, ['model_id', 'authorized_by_task', 'authorization_kind']) ||
      record.authority_basis.model_id !== AUTHORITY_LIFECYCLE_MODEL ||
      typeof record.authority_basis.authorized_by_task !== 'string' ||
      !['SELF_CLOSEOUT_BOOTSTRAP', 'ACCEPTED_LIFECYCLE_MODEL', 'HISTORICAL_BACKFILL']
        .includes(record.authority_basis.authorization_kind)) {
    problems.push('record authority basis is invalid');
  }
  if (!object(record.event_evidence)) problems.push('record event evidence is missing');
  if (!object(record.record_identity) ||
      !exactKeys(record.record_identity, ['identity_scheme', 'path', 'accepted_commit_source', 'append_only']) ||
      record.record_identity.identity_scheme !== 'IMMUTABLE_GIT_BLOB_AT_ACCEPTED_COMMIT' ||
      record.record_identity.append_only !== true ||
      record.record_identity.accepted_commit_source !== 'CONTAINING_GIT_COMMIT' ||
      typeof record.record_identity.path !== 'string' || !REPO_PATH.test(record.record_identity.path)) {
    problems.push('record immutable Git identity is invalid');
  }
  if (typeof record.created_by_task !== 'string' || record.created_by_task.length === 0) {
    problems.push('record creator task is missing');
  }
  if (!object(record.provenance) || !exactKeys(record.provenance, [
    'source_task', 'source_commit', 'source_tree', 'record_creation_authority',
    'record_creator_task', 'historical_evidence_claimed_only_if_proven',
  ]) || typeof record.provenance.source_task !== 'string' ||
      !GIT_OID.test(record.provenance.source_commit || '') ||
      !GIT_OID.test(record.provenance.source_tree || '') ||
      typeof record.provenance.record_creation_authority !== 'string' ||
      typeof record.provenance.record_creator_task !== 'string' ||
      record.provenance.historical_evidence_claimed_only_if_proven !== true) {
    problems.push('record provenance is malformed');
  }
  if (typeof record.effective !== 'boolean') problems.push('record effective assertion is not boolean');
  return problems;
}

function evidenceProblems(record, semanticIdentity, evidenceCatalogue, acceptanceFact) {
  const problems = [];
  const evidence = record.event_evidence;
  if (!object(evidence)) return ['event evidence is not an object'];

  if (record.event === 'MERGED') {
    const merge = evidence.merge_identity;
    if (evidence.kind !== 'GIT_MERGE' || !object(merge) || !GIT_OID.test(merge.commit || '') ||
        !GIT_OID.test(merge.tree || '') || !Array.isArray(merge.parents) || merge.parents.length !== 2 ||
        !merge.parents.every((parent) => GIT_OID.test(parent)) ||
        merge.parents[1] !== semanticIdentity.candidate_commit || merge.tree !== semanticIdentity.candidate_tree) {
      problems.push('MERGED evidence does not bind the exact candidate/tree and two-parent merge');
    } else {
      const acceptedMerge = evidenceCatalogue?.merge_commits?.[merge.commit];
      if (!object(acceptedMerge) || acceptedMerge.accepted_ancestry !== true ||
          acceptedMerge.tree !== merge.tree || !deepEqual(acceptedMerge.parents, merge.parents)) {
        problems.push('MERGED evidence is absent from the accepted ancestry catalogue');
      }
    }
  }

  if (record.event === 'POST_MERGE_VERIFIED') {
    const post = evidence.post_merge_evidence;
    if (evidence.kind !== 'POST_MERGE_CI' || !object(post) || !Number.isInteger(post.run_id) || post.run_id < 1 ||
        !GIT_OID.test(post.head_sha || '') || post.conclusion !== 'success' ||
        !Number.isInteger(post.jobs_passed) || post.jobs_passed < 1 ||
        post.jobs_failed !== 0 || !Number.isInteger(post.jobs_skipped) || post.jobs_skipped < 0) {
      problems.push('POST_MERGE_VERIFIED evidence is malformed or not successful');
    } else {
      const acceptedRun = evidenceCatalogue?.post_merge_runs?.[String(post.run_id)];
      if (!object(acceptedRun) || !deepEqual(acceptedRun, post)) {
        problems.push('post-merge evidence is not in the accepted evidence catalogue');
      }
    }
  }

  if (record.event === 'CLOSED') {
    const closeout = evidence.closeout_identity;
    if (evidence.kind !== 'GOVERNANCE_CLOSEOUT' || !object(closeout) ||
        closeout.commit_source !== 'CONTAINING_GIT_COMMIT' ||
        closeout.governance_only !== true || closeout.owner_authorized !== true) {
      problems.push('CLOSED evidence is not an owner-authorized governance-only containing commit');
    }
    const acceptedCloseout = evidenceCatalogue?.closeout_records?.[record.record_id];
    if (!object(acceptedCloseout) || acceptedCloseout.commit !== acceptanceFact?.commit ||
        acceptedCloseout.governance_only !== true || acceptedCloseout.owner_authorized !== true) {
      problems.push('CLOSED record is not bound to accepted closeout commit evidence');
    }
  }
  return problems;
}

function expectedStateForCount(count) {
  return count === 0 ? 'SEMANTIC_ONLY' : AUTHORITY_LIFECYCLE_EVENTS[count - 1] ?? 'INVALID';
}

// Resolve one semantic artifact through its accepted lifecycle chain.  All
// malformed input becomes a structured REJECT; callers never receive a thrown
// validation error.
export function resolveEffectiveAuthority(input) {
  const problems = [];
  try {
    const policyResult = validateLifecyclePolicy(input?.policy);
    problems.push(...policyResult.problems);
    const semanticIdentity = input?.semantic_artifact_identity;
    problems.push(...semanticIdentityProblems(semanticIdentity));
    const records = Array.isArray(input?.records) ? input.records : [];
    if (!Array.isArray(input?.records)) problems.push('lifecycle records are not an array');

    const shapeResults = records.map((record, index) => ({
      index,
      problems: recordShapeProblems(record),
    }));
    for (const result of shapeResults) {
      for (const problem of result.problems) problems.push(`record[${result.index}]: ${problem}`);
    }

    if (problems.length > 0) {
      return {
        result: 'REJECT', lifecycle_state: 'INVALID', effective: false,
        task_id: semanticIdentity?.task_id ?? null,
        ordered_record_ids: [], problems, uncaught_validation_errors: 0,
      };
    }

    const ordered = [...records].sort((left, right) =>
      left.event_sequence - right.event_sequence ||
      Buffer.compare(Buffer.from(left.record_id), Buffer.from(right.record_id)));
    const ids = ordered.map((record) => record.record_id);
    if (new Set(ids).size !== ids.length) problems.push('duplicate lifecycle record ID');
    const sequences = ordered.map((record) => record.event_sequence);
    if (new Set(sequences).size !== sequences.length) problems.push('lifecycle sequence fork');

    let previous = null;
    let previousAcceptanceOrdinal = -1;
    let resolvedMergeCommit = null;
    const recordPaths = new Set();
    for (let index = 0; index < ordered.length; index += 1) {
      const record = ordered[index];
      const expectedSequence = index + 1;
      const expectedEvent = AUTHORITY_LIFECYCLE_EVENTS[index];
      if (record.event_sequence !== expectedSequence) problems.push(`sequence ${record.event_sequence} is not contiguous`);
      if (record.event !== expectedEvent) problems.push(`event ${record.event} is invalid at sequence ${expectedSequence}`);
      if (record.task_id !== semanticIdentity.task_id) problems.push(`record ${record.record_id} belongs to an unrelated task`);
      if (!deepEqual(record.semantic_artifact_identity, semanticIdentity)) {
        problems.push(`record ${record.record_id} references the wrong semantic identity`);
      }
      if (record.effective !== (record.event === 'CLOSED')) {
        problems.push(`record ${record.record_id} effective assertion disagrees with its event`);
      }
      if (recordPaths.has(record.record_identity.path)) {
        problems.push(`record ${record.record_id} reuses a lifecycle record path`);
      }
      recordPaths.add(record.record_identity.path);
      if (previous === null) {
        if (record.predecessor_lifecycle_record !== null) problems.push('first lifecycle record has a predecessor');
      } else {
        const expectedPredecessor = {
          record_id: previous.record_id,
          record_sha256: lifecycleRecordSha256(previous),
        };
        if (!deepEqual(record.predecessor_lifecycle_record, expectedPredecessor)) {
          problems.push(`record ${record.record_id} predecessor ID/digest does not bind the prior record`);
        }
      }

      const acceptanceFact = input?.record_acceptance?.[record.record_id];
      if (!object(acceptanceFact) || acceptanceFact.accepted !== true ||
          !GIT_OID.test(acceptanceFact.commit || '') || !Number.isInteger(acceptanceFact.commit_ordinal) ||
          acceptanceFact.commit_ordinal < 0 || acceptanceFact.first_parent_ancestry !== true ||
          acceptanceFact.path !== record.record_identity.path ||
          !SHA256.test(acceptanceFact.introduced_sha256 || '') ||
          acceptanceFact.introduced_sha256 !== acceptanceFact.current_sha256 ||
          acceptanceFact.canonical_record_sha256 !== lifecycleRecordSha256(record)) {
        problems.push(`record ${record.record_id} lacks immutable accepted Git provenance`);
      } else if (acceptanceFact.commit_ordinal < previousAcceptanceOrdinal) {
        problems.push(`record ${record.record_id} accepted commit ordering regressed`);
      } else {
        previousAcceptanceOrdinal = acceptanceFact.commit_ordinal;
      }

      if (input?.authority_basis_acceptance?.[record.record_id] !== true) {
        problems.push(`record ${record.record_id} authority basis is not accepted`);
      }
      problems.push(...evidenceProblems(record, semanticIdentity, input?.evidence_catalogue, acceptanceFact)
        .map((problem) => `record ${record.record_id}: ${problem}`));
      if (record.event === 'MERGED') {
        resolvedMergeCommit = record.event_evidence.merge_identity?.commit ?? null;
      } else if (record.event === 'POST_MERGE_VERIFIED' &&
          record.event_evidence.post_merge_evidence?.head_sha !== resolvedMergeCommit) {
        problems.push(`record ${record.record_id} post-merge evidence targets a different merge`);
      }
      previous = record;
    }

    const expectedIds = input?.expected_accepted_record_ids;
    if (expectedIds !== undefined && (!Array.isArray(expectedIds) || !deepEqual(ids, expectedIds))) {
      problems.push('accepted lifecycle record registry disagrees with the resolved chain');
    }
    if (input?.expected_lifecycle_state !== undefined &&
        input.expected_lifecycle_state !== expectedStateForCount(ordered.length)) {
      problems.push('expected accepted lifecycle state disagrees with record chain');
    }
    if (ordered.length > AUTHORITY_LIFECYCLE_EVENTS.length) problems.push('event exists after terminal CLOSED');

    const lifecycleState = problems.length === 0 ? expectedStateForCount(ordered.length) : 'INVALID';
    const effective = problems.length === 0 && lifecycleState === 'CLOSED';
    return {
      result: problems.length === 0 ? 'ACCEPT' : 'REJECT',
      task_id: semanticIdentity.task_id,
      lifecycle_state: lifecycleState,
      effective,
      ordered_record_ids: ids,
      problems,
      uncaught_validation_errors: 0,
    };
  } catch (error) {
    return {
      result: 'REJECT', lifecycle_state: 'INVALID', effective: false,
      task_id: input?.semantic_artifact_identity?.task_id ?? null,
      ordered_record_ids: [], problems: [`malformed lifecycle input: ${error.message}`],
      uncaught_validation_errors: 0,
    };
  }
}

// Compare a previously accepted record set with a successor checkout.  This
// detects deletion and rewrite independently from chain completeness.
export function validateAppendOnlyRecordSet(previousRecords, currentRecords) {
  const problems = [];
  try {
    if (!Array.isArray(previousRecords) || !Array.isArray(currentRecords)) {
      return { result: 'REJECT', problems: ['append-only record sets must be arrays'] };
    }
    const current = new Map();
    for (const record of currentRecords) {
      if (!object(record) || typeof record.record_id !== 'string' || current.has(record.record_id)) {
        problems.push('current lifecycle record set has malformed or duplicate identities');
        continue;
      }
      current.set(record.record_id, lifecycleRecordSha256(record));
    }
    for (const record of previousRecords) {
      if (!object(record) || typeof record.record_id !== 'string') {
        problems.push('previous accepted lifecycle record is malformed');
        continue;
      }
      if (!current.has(record.record_id)) problems.push(`accepted lifecycle record deleted: ${record.record_id}`);
      else if (current.get(record.record_id) !== lifecycleRecordSha256(record)) {
        problems.push(`accepted lifecycle record rewritten: ${record.record_id}`);
      }
    }
  } catch (error) {
    problems.push(`malformed append-only comparison: ${error.message}`);
  }
  return { result: problems.length === 0 ? 'ACCEPT' : 'REJECT', problems };
}

export function validateLifecycleProjection(projection, resolution) {
  const problems = [];
  try {
    if (!object(projection) || !object(resolution)) {
      return { result: 'REJECT', problems: ['projection or lifecycle resolution is not an object'] };
    }
    if (projection.lifecycle_state !== resolution.lifecycle_state ||
        projection.effective !== resolution.effective ||
        !deepEqual(projection.lifecycle_record_ids, resolution.ordered_record_ids) ||
        projection.canonical_source !== 'ACCEPTED_APPEND_ONLY_LIFECYCLE_RECORD_CHAIN') {
      problems.push('projection disagrees with canonical lifecycle resolution');
    }
  } catch (error) {
    problems.push(`malformed lifecycle projection: ${error.message}`);
  }
  return { result: problems.length === 0 ? 'ACCEPT' : 'REJECT', problems };
}

export function validateImmutableSemanticIdentity(expectedIdentity, currentIdentity) {
  const problems = [];
  try {
    problems.push(...semanticIdentityProblems(expectedIdentity));
    problems.push(...semanticIdentityProblems(currentIdentity));
    if (problems.length === 0 && !deepEqual(expectedIdentity, currentIdentity)) {
      problems.push('frozen semantic artifact identity was mutated');
    }
  } catch (error) {
    problems.push(`malformed semantic identity comparison: ${error.message}`);
  }
  return { result: problems.length === 0 ? 'ACCEPT' : 'REJECT', problems };
}

function exactSet(left, right) {
  return Array.isArray(left) && Array.isArray(right) &&
    deepEqual([...left].sort(), [...right].sort());
}

// Pure classifier for the one-time Amendment bootstrap.  It is separate from
// normal lifecycle validation so an expired bootstrap can never authorize a
// later task.
export function classifySelfCloseoutBootstrap(facts, policy) {
  const problems = [];
  try {
    if (!object(facts) || !object(policy)) {
      return { result: 'REJECT', classification: 'REJECTED', problems: ['bootstrap facts/policy malformed'] };
    }
    if (facts.task_id !== policy.task_id) problems.push('bootstrap task identity mismatch');
    if (!['VALID_CANDIDATE', 'VALID_LEGAL_MERGE', 'VALID_DIRECT_SELF_CLOSEOUT'].includes(facts.lifecycle_class)) {
      problems.push('lifecycle class is not bootstrap eligible');
    }
    if (facts.closed_before_commit === true || facts.bootstrap_use_count !== 0) {
      problems.push('bootstrap already expired or was previously used');
    }
    const candidate = facts.candidate;
    if (!object(candidate) || candidate.parent !== policy.base_commit || candidate.ordinary_commit_count !== 1 ||
        candidate.contains_merge !== false || !exactSet(candidate.changed_paths, policy.candidate_allowed_paths)) {
      problems.push('candidate is not the exact direct governance Amendment candidate');
    }
    if (facts.lifecycle_class !== 'VALID_CANDIDATE') {
      const merge = facts.merge;
      if (!object(merge) || merge.parent_count !== 2 || merge.first_parent !== policy.base_commit ||
          merge.second_parent !== candidate.commit || merge.tree !== candidate.tree ||
          merge.candidate_tree_preserved !== true || merge.accepted !== true) {
        problems.push('legal merge evidence is not exact');
      }
    }
    if (facts.lifecycle_class === 'VALID_DIRECT_SELF_CLOSEOUT') {
      const successor = facts.successor;
      if (!object(successor) || successor.depth !== 1 || successor.parent_count !== 1 ||
          successor.parent !== facts.merge?.commit ||
          !exactSet(successor.changed_paths, policy.closeout_allowed_paths) ||
          successor.governance_only !== true || successor.semantic_mutation !== false ||
          successor.business_code_changed !== false || successor.other_task_records !== false ||
          successor.record_count !== AUTHORITY_LIFECYCLE_EVENTS.length ||
          facts.merge?.post_merge_verified !== true) {
        problems.push('self-closeout successor is not the exact direct governance-only record commit');
      }
    }
  } catch (error) {
    problems.push(`malformed bootstrap topology: ${error.message}`);
  }
  return {
    result: problems.length === 0 ? 'ACCEPT' : 'REJECT',
    classification: problems.length === 0 ? facts.lifecycle_class : 'REJECTED',
    problems,
  };
}

export function selfCloseoutBootstrapExpired(taskId, resolution) {
  return object(resolution) && resolution.result === 'ACCEPT' &&
    resolution.lifecycle_state === 'CLOSED' && resolution.effective === true &&
    resolution.task_id === taskId && typeof taskId === 'string' && taskId.length > 0;
}
