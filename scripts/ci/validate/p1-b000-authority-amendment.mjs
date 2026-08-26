#!/usr/bin/env node
// UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-001 validator.
// Standard-library only. This validates append-only governance authorization;
// it does not repair either frozen validator and performs no network call.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { git, runAsMain } from '../lib/cli.mjs';
import { checkSchemaDocument, validateInstance } from '../lib/json-schema.mjs';
import { checkMigrationContract } from './mvp-b001.mjs';
import { validateGraph } from './mvp-bootstrap.mjs';

const TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-001';
const AUTHORITY_TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-001';
const BRANCH = `task/${TASK_ID}`;
const AUTHORITY_CANDIDATE = 'c9f7729f666d11716c04d7682da16044ca965236';
const AUTHORITY_TREE = '9cf551e7bc70d4354ca21d62a2bd456ed6f401bb';
const AUTHORITY_MERGE = '169f9bd006dabb88eb653ab09a33b0eef5eadaed';
const AUTHORITY_PARENTS = [
  'eede815e818d87362605f55d5bfd2a0460e6e130',
  AUTHORITY_CANDIDATE,
];

const HUMAN_PATH = 'docs/authority/amendments/UNREGISTERED_AIPT_P1_B000_AUTHORITY_AMENDMENT_001.md';
const AMENDMENT_PATH = 'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-001.json';
const ARTIFACT_PATH = 'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-001-artifacts.json';
const BASE_MANIFEST_PATH = 'docs/authority/registry/unregistered-aipt-p1-b000-authority-artifacts.json';
const AMENDMENT_SCHEMA_PATH = 'schemas/authority-amendment/v1/aipt-authority-amendment.schema.json';
const SUPERSESSION_SCHEMA_PATH = 'schemas/authority-amendment/v1/aipt-authority-validator-supersession.schema.json';
const RECOVERY_SCHEMA_PATH = 'schemas/authority-amendment/v1/aipt-post-merge-reverification-evidence.schema.json';
const VALIDATOR_PATH = 'scripts/ci/validate/p1-b000-authority-amendment.mjs';
const SUPERSESSION_DIRECTORY = 'docs/authority/registry/authority-validator-supersessions';
const RECOVERY_DIRECTORY = 'docs/authority/registry/post-merge-reverification';

const ORIGINAL_AUTHORITY_VALIDATOR = 'scripts/ci/validate/p1-b000-authority.mjs';
const ORIGINAL_AUTHORITY_VALIDATOR_SHA = 'f5ed47898ad13b193cd685ae9649c18cada3a6fb5893c1810867c91869ad8c7c';
const ORIGINAL_B001_VALIDATOR = 'scripts/ci/validate/mvp-b001.mjs';
const ORIGINAL_B001_VALIDATOR_SHA = 'ba29c75b68c282484cbdceeb7ae035c010b51181ce8e2b5f5b54b9c11a241aaf';
const MIGRATION_PATH = 'internal/storage/postgres/migrations/000002_playtest_queue.sql';
const MIGRATION_SHA = '47f02a5a2129473caa0db5e359a0b294a01b2a96329d9f6fa08ac87cc429c997';

const BASE_HASHES = Object.freeze({
  'docs/authority/UNREGISTERED_AIPT_P1_B000_AUTHORITY.md': '787e1a1a278905d69cd9e000badec8c4143060dcb136e4b0da3d2fb7a12c3ede',
  'docs/authority/registry/unregistered-aipt-p1-b000-authority.json': 'a9845bb74dac409ee243b7024e23aae271ab13c75e18116ae2513853cc02eed6',
  'schemas/playtest-package/v1/aipt-playtest-package.schema.json': '88e55b63c8a6366c872edf0d886202a5c375e224c801433364332ddc4e4e7549',
  'schemas/runtime-adapter-input/v1/aipt-runtime-adapter-input.schema.json': '935b88f2409e604d01a13657a7790dae16e19ebe0c4e96f054c580102ec17413',
  [ORIGINAL_AUTHORITY_VALIDATOR]: ORIGINAL_AUTHORITY_VALIDATOR_SHA,
  [BASE_MANIFEST_PATH]: '3e7d5ee752ac01ae4034fdaf2ec71231bb4f58eca9174e99619d0a13b200cd4f',
});

const STAGE_PATHS = Object.freeze([
  '.github/workflows/ci.yml',
  'docs/authority/README.md',
  HUMAN_PATH,
  ARTIFACT_PATH,
  AMENDMENT_PATH,
  'package.json',
  AMENDMENT_SCHEMA_PATH,
  SUPERSESSION_SCHEMA_PATH,
  RECOVERY_SCHEMA_PATH,
  'scripts/ci/run-checks.mjs',
  VALIDATOR_PATH,
].sort());

const ARTIFACT_PATHS = Object.freeze([
  HUMAN_PATH,
  AMENDMENT_PATH,
  AMENDMENT_SCHEMA_PATH,
  SUPERSESSION_SCHEMA_PATH,
  RECOVERY_SCHEMA_PATH,
  VALIDATOR_PATH,
]);

const ARTIFACT_ROLES = Object.freeze([
  'HUMAN_READABLE_AUTHORITY_AMENDMENT',
  'MACHINE_EXECUTION_AUTHORITY_AMENDMENT',
  'AUTHORITY_AMENDMENT_SCHEMA_V1',
  'AUTHORITY_VALIDATOR_SUPERSESSION_SCHEMA_V1',
  'POST_MERGE_REVERIFICATION_EVIDENCE_SCHEMA_V1',
  'AUTHORITY_AMENDMENT_VALIDATOR_IDENTITY',
]);

const FORBIDDEN_CHANGES = Object.freeze([
  'MODIFY_BASE_HUMAN_AUTHORITY',
  'MODIFY_BASE_MACHINE_AUTHORITY',
  'MODIFY_BASE_AUTHORITY_ARTIFACT_MANIFEST',
  'WEAKEN_ARTIFACT_HASH_VALIDATION',
  'REMOVE_ANCESTRY_VALIDATION',
  'REMOVE_CANDIDATE_IDENTITY_VALIDATION',
  'REMOVE_SCOPE_VALIDATION',
  'REMOVE_NEGATIVE_LIFECYCLE_CHECKS',
  'ACCEPT_UNAUTHORIZED_COMMITS',
  'ACCEPT_ARTIFACT_DRIFT',
  'ACCEPT_ILLEGAL_LIFECYCLE_TRANSITION',
  'CHANGE_PLAYTEST_PACKAGE_CONTRACT',
  'CHANGE_RUNTIME_ADAPTER_INPUT_CONTRACT',
  'CHANGE_B000_OBJECTIVE_OR_NON_GOALS',
  'CHANGE_B001_BUSINESS_SEMANTICS',
  'TREAT_REAL_FAILED_CI_AS_RECOVERABLE',
  'CLAIM_ABSENT_HISTORICAL_CI_AS_PASS',
  'VERIFY_OLD_SHA_WITH_MODIFIED_WORKTREE',
  'START_B000_IMPLEMENTATION',
  'START_POSTMERGE_REPAIR_IN_THIS_TASK',
]);

const REQUIRED_ROLE_CONSTRAINTS = Object.freeze({
  AUTHORITY_VALIDATOR_IDENTITY: [
    'SUPPORT_CANDIDATE_MERGED_POST_MERGE_CLOSED_TOPOLOGY',
    'PRESERVE_ARTIFACT_HASH_VALIDATION',
    'PRESERVE_ANCESTRY_VALIDATION',
    'PRESERVE_CANDIDATE_IDENTITY_VALIDATION',
    'PRESERVE_SCOPE_VALIDATION',
    'PRESERVE_NEGATIVE_LIFECYCLE_CHECKS',
    'REJECT_UNAUTHORIZED_COMMITS',
    'REJECT_ARTIFACT_DRIFT',
    'REJECT_ILLEGAL_LIFECYCLE_TRANSITIONS',
  ],
  B001_HISTORICAL_VALIDATOR_IDENTITY: [
    'PRESERVE_B001_BUSINESS_SEMANTICS',
    'CLOSED_USES_IMMUTABLE_ACCEPTED_CLOSEOUT_IDENTITY',
    'ACTIVE_CANDIDATE_REQUIRES_PENDING_CANDIDATE',
    'INVALID_COMBINATION_RETURNS_STRUCTURED_FAIL',
    'PRESERVE_CAMPAIGN_SUITE_CASE_RUN',
    'PRESERVE_ATTEMPT_INTERNAL_ONLY',
    'PRESERVE_RUN_MANIFEST_IMMUTABILITY',
    'PRESERVE_POSTGRESQL_QUEUE_AUTHORITY',
    'PRESERVE_WIP_ONE_LEASE_HEARTBEAT_EXPIRY_RECOVERY',
    'PRESERVE_APPEND_ONLY_ATTEMPT_HISTORY',
  ],
});

const ROLE_BASES = Object.freeze({
  AUTHORITY_VALIDATOR_IDENTITY: {
    path: ORIGINAL_AUTHORITY_VALIDATOR,
    sha256: ORIGINAL_AUTHORITY_VALIDATOR_SHA,
  },
  B001_HISTORICAL_VALIDATOR_IDENTITY: {
    path: ORIGINAL_B001_VALIDATOR,
    sha256: ORIGINAL_B001_VALIDATOR_SHA,
  },
});

const NEGATIVE_CASES = Object.freeze([
  ['A01', 'unknown base authority'],
  ['A02', 'wrong base candidate'],
  ['A03', 'wrong merge commit'],
  ['A04', 'wrong original artifact manifest hash'],
  ['A05', 'unknown supersession role'],
  ['A06', 'supersession missing old hash'],
  ['A07', 'supersession old hash mismatch'],
  ['A08', 'supersession without accepted amendment'],
  ['A09', 'multiple conflicting supersessions'],
  ['A10', 'mutation of original artifact manifest'],
  ['A11', 'amendment attempts to change package schema'],
  ['A12', 'amendment attempts to change runtime-adapter schema'],
  ['A13', 'amendment attempts to weaken ancestry validation'],
  ['A14', 'unresolved placeholder'],
  ['A15', 'recovery used after real CI failure'],
  ['A16', 'recovery target SHA mismatch'],
  ['A17', 'recovery target tree mismatch'],
  ['A18', 'recovery evidence missing validator identity'],
  ['A19', 'recovery evidence missing workflow identity'],
  ['A20', 'non-deterministic amendment ordering'],
]);

function read(repo, relative) {
  return fs.readFileSync(path.join(repo, relative));
}

function text(repo, relative) {
  return read(repo, relative).toString('utf8');
}

function readJSON(repo, relative) {
  return JSON.parse(text(repo, relative));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function byteSort(values) {
  return [...values].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
}

function sameSet(a, b) {
  return same(byteSort(new Set(a)), byteSort(new Set(b)));
}

function hasAll(values, required) {
  return Array.isArray(values) && required.every((value) => values.includes(value));
}

function gitBlob(repo, revision, relative) {
  const cp = spawnSync('git', ['-C', repo, 'show', `${revision}:${relative}`], { encoding: null });
  if (cp.status !== 0) return null;
  return cp.stdout;
}

function gitOut(repo, args) {
  const cp = git(repo, args, { check: false });
  return cp.status === 0 ? cp.stdout.trim() : null;
}

function listRecordFiles(repo, relativeDirectory) {
  const absolute = path.join(repo, relativeDirectory);
  if (!fs.existsSync(absolute)) return [];
  const stat = fs.lstatSync(absolute);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`${relativeDirectory} is not a real directory`);
  return byteSort(fs.readdirSync(absolute))
    .filter((name) => name.endsWith('.json'))
    .map((name) => {
      const relative = `${relativeDirectory}/${name}`;
      const fileStat = fs.lstatSync(path.join(repo, relative));
      if (!fileStat.isFile() || fileStat.isSymbolicLink()) throw new Error(`${relative} is not a regular file`);
      return relative;
    });
}

function changedPaths(repo, base = AUTHORITY_MERGE) {
  const tracked = git(repo, ['diff', '--name-only', '--no-renames', base], { check: false });
  const untracked = git(repo, ['ls-files', '--others', '--exclude-standard'], { check: false });
  const lines = (cp) => cp.status === 0 ? cp.stdout.split('\n').filter(Boolean) : [];
  return byteSort(new Set([...lines(tracked), ...lines(untracked)]
    .filter((relative) => !relative.split('/').includes('node_modules'))));
}

function schemaProblems(schema, instance, label) {
  const problems = [];
  for (const error of checkSchemaDocument(schema).errors) problems.push(`${label} schema: ${error}`);
  for (const error of validateInstance(schema, instance).errors) problems.push(`${label} instance: ${error.message}`);
  return problems;
}

export function validateAmendmentPolicy(amendment, context = {}) {
  const problems = [];
  const expectedBaseManifest = context.baseManifestBytes;
  if (amendment.schema !== 'aipt.public.authority-amendment/v1' || amendment.amendment_id !== TASK_ID ||
      amendment.amendment_sequence !== 1 || amendment.authority_task_id !== AUTHORITY_TASK_ID) {
    problems.push('amendment/base Authority identity is not exact');
  }
  if (amendment.authority_candidate_commit !== AUTHORITY_CANDIDATE ||
      amendment.authority_candidate_tree !== AUTHORITY_TREE) {
    problems.push('base Authority Candidate identity is not exact');
  }
  if (amendment.authority_merge_commit !== AUTHORITY_MERGE ||
      amendment.authority_merge_tree !== AUTHORITY_TREE ||
      !same(amendment.authority_merge_parents, AUTHORITY_PARENTS) || amendment.authority_pr !== 6) {
    problems.push('base Authority merge identity/topology is not exact');
  }
  if (amendment.base_authority_artifact_manifest !== BASE_MANIFEST_PATH ||
      amendment.base_authority_artifact_manifest_sha256 !== BASE_HASHES[BASE_MANIFEST_PATH]) {
    problems.push('base Authority artifact manifest binding is not exact');
  }
  if (expectedBaseManifest && sha256(expectedBaseManifest) !== amendment.base_authority_artifact_manifest_sha256) {
    problems.push('base Authority artifact manifest bytes do not match the frozen binding');
  }
  if (!same(amendment.amendment_reason?.map((entry) => entry.finding_id), ['F1', 'F2', 'F3'])) {
    problems.push('F1-F3 Amendment reason inventory is not exact');
  }

  const changes = amendment.authorized_changes ?? [];
  const authorityChange = changes.find((entry) => entry.role === 'AUTHORITY_VALIDATOR_IDENTITY');
  const b001Change = changes.find((entry) => entry.role === 'B001_HISTORICAL_VALIDATOR_IDENTITY');
  const recoveryChange = changes.find((entry) => entry.role === 'POST_MERGE_REVERIFICATION_DEFINITION');
  if (changes.length !== 3 || !authorityChange || !b001Change || !recoveryChange) {
    problems.push('authorized change inventory is not the exact three constrained roles');
  }
  if (authorityChange?.path !== ORIGINAL_AUTHORITY_VALIDATOR ||
      authorityChange?.old_sha256 !== ORIGINAL_AUTHORITY_VALIDATOR_SHA ||
      !hasAll(authorityChange?.semantic_constraints, REQUIRED_ROLE_CONSTRAINTS.AUTHORITY_VALIDATOR_IDENTITY)) {
    problems.push('Authority validator supersession authorization is incomplete or drifted');
  }
  if (b001Change?.path !== ORIGINAL_B001_VALIDATOR ||
      b001Change?.old_sha256 !== ORIGINAL_B001_VALIDATOR_SHA ||
      !hasAll(b001Change?.semantic_constraints, REQUIRED_ROLE_CONSTRAINTS.B001_HISTORICAL_VALIDATOR_IDENTITY)) {
    problems.push('B001 historical validator repair authorization is incomplete or drifted');
  }
  if (recoveryChange?.path !== RECOVERY_DIRECTORY ||
      !hasAll(recoveryChange?.semantic_constraints, [
        'WORKFLOW_AND_VALIDATORS_FROM_ACCEPTED_REPAIR_CANDIDATE',
        'CHECKOUT_EXACT_REQUESTED_TARGET_SHA',
        'REAL_FAILED_CI_NOT_OVERRIDABLE',
      ])) {
    problems.push('post-merge reverification authorization is incomplete or drifted');
  }
  if (changes.some((entry) => [
    'schemas/playtest-package/v1/aipt-playtest-package.schema.json',
    'schemas/runtime-adapter-input/v1/aipt-runtime-adapter-input.schema.json',
  ].includes(entry.path))) {
    problems.push('Amendment attempts to authorize a protected package or adapter schema change');
  }
  if (!same(amendment.forbidden_changes, FORBIDDEN_CHANGES)) {
    problems.push('forbidden semantic-change inventory is incomplete or reordered');
  }

  const original = amendment.supersession_policy?.original_frozen_authority_validator_identity;
  if (original?.role !== 'ORIGINAL_FROZEN_AUTHORITY_VALIDATOR_IDENTITY' ||
      original?.artifact_role !== 'AUTHORITY_VALIDATOR_IDENTITY' ||
      original?.path !== ORIGINAL_AUTHORITY_VALIDATOR || original?.sha256 !== ORIGINAL_AUTHORITY_VALIDATOR_SHA ||
      original?.historical_identity_remains_authoritative !== true ||
      original?.deletion_or_overwrite_of_history_permitted !== false) {
    problems.push('original frozen Authority validator identity is not permanently preserved');
  }
  const allowedRoles = amendment.supersession_policy?.allowed_roles ?? [];
  const expectedAllowedRoles = Object.entries(ROLE_BASES).map(([role, value]) => ({
    role, path: value.path, required_initial_old_sha256: value.sha256,
  }));
  if (!same(allowedRoles, expectedAllowedRoles)) problems.push('allowed supersession roles/initial hashes are not exact');
  if (amendment.supersession_policy?.record_schema !== SUPERSESSION_SCHEMA_PATH ||
      amendment.supersession_policy?.record_directory !== SUPERSESSION_DIRECTORY ||
      amendment.supersession_policy?.record_timing !== 'APPEND_AFTER_THE_REPAIR_ARTIFACT_COMMIT_IT_NAMES' ||
      amendment.supersession_policy?.repair_candidate_self_reference_permitted !== false ||
      amendment.supersession_policy?.record_commit_must_descend_from_repair_candidate_commit !== true ||
      amendment.supersession_policy?.conflicting_same_role_records !== 'REJECT_UNLESS_EXPLICIT_CONTIGUOUS_CHAIN' ||
      amendment.supersession_policy?.unknown_role !== 'REJECT' ||
      amendment.supersession_policy?.unaccepted_amendment !== 'REJECT') {
    problems.push('supersession discovery, conflict or acceptance policy drifted');
  }

  const resolution = amendment.effective_authority_resolution;
  if (resolution?.algorithm !== 'IMMUTABLE_BASE_THEN_ORDERED_ACCEPTED_AMENDMENTS_THEN_ACCEPTED_SUPERSESSION_CHAIN' ||
      resolution?.amendment_ordering?.primary !== 'amendment_sequence_ASCENDING' ||
      resolution?.amendment_ordering?.secondary !== 'accepted_merge_first_parent_ancestry_ASCENDING' ||
      resolution?.amendment_ordering?.unique_sequence_required !== true ||
      resolution?.amendment_ordering?.filesystem_mtime_permitted !== false ||
      resolution?.amendment_ordering?.directory_enumeration_order_permitted !== false ||
      resolution?.latest_file_wins !== false || resolution?.latest_main_hash_wins !== false ||
      resolution?.unaccepted_record_effective !== false || resolution?.conflict_policy !== 'FAIL_CLOSED') {
    problems.push('effective Authority resolution is mutable, ambiguous or fail-open');
  }
  if (resolution?.base_identity?.authority_task_id !== AUTHORITY_TASK_ID ||
      resolution?.base_identity?.candidate_commit !== AUTHORITY_CANDIDATE ||
      resolution?.base_identity?.merge_commit !== AUTHORITY_MERGE ||
      resolution?.base_identity?.merge_tree !== AUTHORITY_TREE ||
      resolution?.base_identity?.artifact_manifest_sha256 !== BASE_HASHES[BASE_MANIFEST_PATH]) {
    problems.push('effective Authority resolver is not anchored to the exact immutable base');
  }

  const recovery = amendment.post_merge_reverification_policy;
  if (recovery?.evidence_schema !== RECOVERY_SCHEMA_PATH || recovery?.original_merge_check_run !== 'ABSENT' ||
      recovery?.historical_merge_ci !== 'NOT_CLAIMED_PASS' ||
      recovery?.verification_target_sha !== AUTHORITY_MERGE || recovery?.verification_target_tree !== AUTHORITY_TREE ||
      recovery?.approved_candidate_commit !== AUTHORITY_CANDIDATE || recovery?.approved_candidate_tree !== AUTHORITY_TREE ||
      recovery?.real_failed_ci_overridable !== false || recovery?.recovery_is_historical_ci !== false ||
      recovery?.workflow_contract?.run_head_sha_is_verification_target !== false ||
      recovery?.workflow_contract?.execution_identity_distinct_from_verification_target !== true ||
      recovery?.workflow_contract?.definition_source !== 'ACCEPTED_POSTMERGE_REPAIR_CANDIDATE_ONLY' ||
      !hasAll(recovery?.prohibited_when_any, ['REAL_REQUIRED_CI_RAN_AND_FAILED', 'REAL_REQUIRED_CI_CONCLUSION_FAILURE'])) {
    problems.push('post-merge recovery policy could falsify history, target the wrong tree or override real failed CI');
  }

  if (amendment.acceptance?.accepted !== false || amendment.acceptance?.append_only_acceptance !== true ||
      amendment.acceptance?.merge_authorized !== false || amendment.acceptance?.repair_authorized_before_acceptance !== false ||
      amendment.acceptance?.closeout_authorized !== false ||
      amendment.acceptance?.acceptance_event?.record_mutation_required !== false ||
      amendment.lifecycle?.repair_task_state !== 'NOT_AUTHORIZED_NOT_STARTED' ||
      amendment.lifecycle?.b000_implementation_state !== 'NOT_AUTHORIZED_NOT_STARTED') {
    problems.push('candidate acceptance/merge/repair/closeout boundary is not fail-closed');
  }
  const bootstrap = amendment.acceptance?.candidate_ci_bootstrap;
  const legacyStageCommands = [
    'pnpm run check:m0-development-pass',
    'pnpm run check:mvp-b001',
    'pnpm run check:mvp-bootstrap',
    'pnpm run check:p1-b000-authority',
    'pnpm run check',
  ];
  if (bootstrap?.classifier_command !== `node ${VALIDATOR_PATH} --ci-bootstrap-classify` ||
      !same(bootstrap?.exact_legacy_stage_commands_not_executed, legacyStageCommands) ||
      bootstrap?.legacy_stage_results_not_claimed_pass !== true ||
      bootstrap?.aggregate_result_not_claimed_pass !== true ||
      bootstrap?.unclassified_checkout_behavior !== 'EXECUTE_ALL_LEGACY_STAGE_COMMANDS' ||
      bootstrap?.required_amendment_command !== 'pnpm run check:p1-b000-authority-amendment' ||
      bootstrap?.go_test_all_unconditional !== true || bootstrap?.business_contract_gates_unconditional !== true ||
      bootstrap?.post_merge_exact_amendment_merge_supported !== true) {
    problems.push('candidate CI bootstrap is not the exact fail-closed legacy-stage carve-out');
  }
  if (!same(amendment.scope?.allowed_paths, STAGE_PATHS) || amendment.scope?.default_write_policy !== 'DENY' ||
      amendment.scope?.business_code_changed !== false || amendment.scope?.frozen_authority_semantics_changed !== false ||
      amendment.scope?.repair_started !== false || amendment.scope?.b000_implementation_started !== false) {
    problems.push('Amendment path and business/repair scope boundary drifted');
  }
  if (amendment.provenance?.owner_authorization?.authorized !== true ||
      amendment.provenance?.owner_authorization?.task_id !== TASK_ID ||
      amendment.provenance?.authority_merge?.candidate_preserved !== true ||
      amendment.provenance?.authority_merge?.ancestry_verified !== true ||
      amendment.provenance?.authority_merge?.merge_tree_equals_candidate_tree !== true ||
      amendment.provenance?.authority_merge?.no_unauthorized_commit_in_merge !== true ||
      amendment.provenance?.historical_ci_fact?.original_merge_check_run !== 'ABSENT' ||
      amendment.provenance?.historical_ci_fact?.historical_pass_claimed !== false ||
      amendment.provenance?.append_only !== true || amendment.provenance?.base_authority_modified !== false ||
      amendment.provenance?.original_artifact_manifest_modified !== false) {
    problems.push('Owner authorization, base provenance or immutable historical CI fact drifted');
  }

  const serialized = JSON.stringify(amendment);
  if (/\b(?:TBD|TODO|FIXME|XXX)\b|<actual>|<sha>|<commit>|\{\{[^}]+\}\}/i.test(serialized)) {
    problems.push('unresolved placeholder appears in the Amendment record');
  }
  return problems;
}

function validateSupersessionRecords(records, schema, options = {}) {
  const problems = [];
  const ids = new Set();
  const byRole = new Map();
  for (const record of records) {
    for (const problem of schemaProblems(schema, record, `supersession ${record?.record_id ?? 'unknown'}`)) problems.push(problem);
    if (ids.has(record.record_id)) problems.push(`duplicate supersession record_id ${record.record_id}`);
    ids.add(record.record_id);
    if (!ROLE_BASES[record.role]) {
      problems.push(`unknown supersession role ${record.role}`);
      continue;
    }
    if (record.path !== ROLE_BASES[record.role].path) problems.push(`supersession path does not match role ${record.role}`);
    if (record.amendment_id !== TASK_ID || record.amendment_acceptance?.accepted !== true) {
      problems.push(`supersession ${record.record_id} lacks accepted Amendment provenance`);
    }
    if (!hasAll(record.semantic_constraints, REQUIRED_ROLE_CONSTRAINTS[record.role])) {
      problems.push(`supersession ${record.record_id} weakens required semantic constraints`);
    }
    if (record.old_sha256 === record.new_sha256) problems.push(`supersession ${record.record_id} does not change identity`);
    if (!byRole.has(record.role)) byRole.set(record.role, []);
    byRole.get(record.role).push(record);
  }

  for (const [role, unsorted] of byRole) {
    const chain = [...unsorted].sort((a, b) => a.chain_sequence - b.chain_sequence ||
      Buffer.compare(Buffer.from(a.record_id), Buffer.from(b.record_id)));
    let previous = null;
    let expectedOld = ROLE_BASES[role].sha256;
    for (let index = 0; index < chain.length; index += 1) {
      const record = chain[index];
      if (record.chain_sequence !== index + 1) problems.push(`${role} chain sequence is not contiguous from one`);
      if (record.old_sha256 !== expectedOld) problems.push(`${role} chain old_sha256 does not equal the prior effective identity`);
      if (index === 0 && record.predecessor_record_id !== null) problems.push(`${role} first link has a predecessor`);
      if (index > 0 && record.predecessor_record_id !== previous.record_id) problems.push(`${role} predecessor link is not explicit and contiguous`);
      expectedOld = record.new_sha256;
      previous = record;

      if (!options.skipGit && options.repo) {
        const acceptance = record.amendment_acceptance;
        const candidateTree = gitOut(options.repo, ['rev-parse', `${acceptance.candidate_commit}^{tree}`]);
        const mergeTree = gitOut(options.repo, ['rev-parse', `${acceptance.merge_commit}^{tree}`]);
        const mergeParents = gitOut(options.repo, ['show', '-s', '--format=%P', acceptance.merge_commit])?.split(/\s+/);
        if (candidateTree !== acceptance.candidate_tree || mergeTree !== acceptance.merge_tree ||
            !same(mergeParents, acceptance.merge_parents) || acceptance.merge_tree !== acceptance.candidate_tree) {
          problems.push(`supersession ${record.record_id} Amendment acceptance Git topology is invalid`);
        }
        const amendmentAncestor = git(options.repo, ['merge-base', '--is-ancestor', acceptance.merge_commit, record.repair_candidate_commit], { check: false });
        if (amendmentAncestor.status !== 0) problems.push(`repair Candidate for ${record.record_id} does not descend from accepted Amendment merge`);
        const repairedBlob = gitBlob(options.repo, record.repair_candidate_commit, record.path);
        if (!repairedBlob || sha256(repairedBlob) !== record.new_sha256) {
          problems.push(`repair Candidate does not contain declared new identity for ${record.record_id}`);
        }
      }
    }
  }
  return problems;
}

export function validateRecoveryEvidence(evidence, schema, options = {}) {
  const problems = schemaProblems(schema, evidence, `recovery ${evidence?.evidence_id ?? 'unknown'}`);
  if (evidence.authority_task_id !== AUTHORITY_TASK_ID || evidence.amendment_id !== TASK_ID) {
    problems.push('recovery evidence authority/amendment identity is wrong');
  }
  if (evidence.original_merge_ci?.check_run !== 'ABSENT' || evidence.original_merge_ci?.conclusion !== null ||
      evidence.original_merge_ci?.historical_merge_ci_claim !== 'NOT_CLAIMED_PASS') {
    problems.push('recovery evidence attempts to replace an existing or failed CI run or falsify historical PASS');
  }
  if (evidence.candidate_identity?.commit !== AUTHORITY_CANDIDATE || evidence.candidate_identity?.tree !== AUTHORITY_TREE ||
      evidence.merge_identity?.commit !== AUTHORITY_MERGE || evidence.merge_identity?.tree !== AUTHORITY_TREE ||
      !same(evidence.merge_identity?.parents, AUTHORITY_PARENTS)) {
    problems.push('recovery evidence Candidate or merge provenance is not exact');
  }
  const target = evidence.verification_target;
  if (target?.requested_target_sha !== AUTHORITY_MERGE || target?.resolved_target_sha !== AUTHORITY_MERGE ||
      target?.target_tree !== AUTHORITY_TREE || target?.clean_checkout !== true || target?.modified_worktree_used !== false) {
    problems.push('recovery verification target SHA/tree/clean checkout binding is invalid');
  }
  const identities = evidence.validator_identities ?? [];
  if (!sameSet(identities.map((entry) => entry.role), Object.keys(ROLE_BASES))) {
    problems.push('recovery evidence lacks the exact Authority and B001 validator identities');
  }
  const repair = evidence.repair_authority;
  const definition = evidence.workflow_execution?.workflow_definition_identity;
  if (!repair || !definition || definition.source_repair_task_id !== repair.repair_task_id ||
      definition.commit !== repair.accepted_repair_candidate_commit ||
      identities.some((entry) => entry.source_repair_candidate_commit !== repair.accepted_repair_candidate_commit)) {
    problems.push('workflow and validator identities do not come from the accepted repair Candidate');
  }
  if ((evidence.jobs ?? []).length === 0 || evidence.jobs.some((job) => job.conclusion !== 'success') ||
      evidence.b001_regression !== 'PASS' || evidence.effective_authority_identities !== 'PASS' ||
      evidence.result !== 'PASS') {
    problems.push('recovery required suite, B001 regression or effective identities did not all pass');
  }
  if (evidence.provenance?.execution_identity_distinct_from_verification_target !== true ||
      evidence.provenance?.recovery_not_historical_ci !== true) {
    problems.push('workflow execution identity is conflated with verification target or historical CI');
  }
  if (!options.skipGit && options.repo && definition && repair) {
    const targetTree = gitOut(options.repo, ['rev-parse', `${target.resolved_target_sha}^{tree}`]);
    if (targetTree !== target.target_tree) problems.push('resolved recovery target Git tree differs from evidence');
    const workflowBlob = gitBlob(options.repo, repair.accepted_repair_candidate_commit, definition.path);
    if (!workflowBlob || sha256(workflowBlob) !== definition.sha256) problems.push('workflow definition Git identity is not reproducible');
    for (const identity of identities) {
      const blob = gitBlob(options.repo, repair.accepted_repair_candidate_commit, identity.path);
      if (!blob || sha256(blob) !== identity.sha256) problems.push(`validator Git identity is not reproducible: ${identity.path}`);
    }
  }
  return problems;
}

function syntheticSupersession() {
  return {
    schema: 'aipt.public.authority-validator-supersession/v1',
    record_id: 'REPAIR-001-AUTHORITY-VALIDATOR-SUPERSESSION-001',
    chain_sequence: 1,
    predecessor_record_id: null,
    role: 'AUTHORITY_VALIDATOR_IDENTITY',
    path: ORIGINAL_AUTHORITY_VALIDATOR,
    old_sha256: ORIGINAL_AUTHORITY_VALIDATOR_SHA,
    new_sha256: '1'.repeat(64),
    amendment_id: TASK_ID,
    repair_task_id: 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001',
    repair_candidate_commit: '6'.repeat(40),
    reason: 'Lifecycle-aware repair constrained by the accepted Amendment.',
    semantic_constraints: [...REQUIRED_ROLE_CONSTRAINTS.AUTHORITY_VALIDATOR_IDENTITY],
    regression_evidence: {
      suite_identity: '2'.repeat(64), result: 'PASS',
      commands: ['node scripts/ci/validate/p1-b000-authority.mjs'],
      negative_probe_count: 1, b001_regression: 'PASS',
    },
    amendment_acceptance: {
      accepted: true, candidate_commit: '3'.repeat(40), candidate_tree: '4'.repeat(40),
      merge_commit: '5'.repeat(40), merge_tree: '4'.repeat(40),
      merge_parents: ['2'.repeat(40), '3'.repeat(40)], owner_approved: true,
      candidate_ci_run_id: 1, candidate_ci_conclusion: 'success',
    },
    repair_acceptance: {
      state: 'ACCEPTED', independent_acceptance: 'PASS', candidate_ci_run_id: 2,
      candidate_ci_conclusion: 'success',
    },
    provenance: {
      created_by_task: 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001',
      append_only: true, original_identity_preserved: true,
    },
  };
}

function syntheticRecoveryEvidence() {
  const repairCommit = '6'.repeat(40);
  return {
    schema: 'aipt.public.post-merge-reverification-evidence/v1',
    evidence_id: 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-RECOVERY-001',
    authority_task_id: AUTHORITY_TASK_ID,
    amendment_id: TASK_ID,
    original_merge_ci: { check_run: 'ABSENT', conclusion: null, historical_merge_ci_claim: 'NOT_CLAIMED_PASS' },
    candidate_identity: { commit: AUTHORITY_CANDIDATE, tree: AUTHORITY_TREE, verified: true },
    merge_identity: {
      commit: AUTHORITY_MERGE, tree: AUTHORITY_TREE, parents: [...AUTHORITY_PARENTS],
      ancestry_verified: true, tree_equals_candidate: true, no_unauthorized_content: true,
    },
    workflow_execution: {
      workflow_run_id: 123, event: 'workflow_dispatch', run_head_sha: '7'.repeat(40),
      workflow_definition_identity: {
        path: '.github/workflows/post-merge-reverification.yml', commit: repairCommit,
        tree: '8'.repeat(40), sha256: '9'.repeat(64),
        source_repair_task_id: 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001',
      },
    },
    verification_target: {
      requested_target_sha: AUTHORITY_MERGE, resolved_target_sha: AUTHORITY_MERGE,
      target_tree: AUTHORITY_TREE, checkout_mode: 'DETACHED_EXACT_COMMIT',
      clean_checkout: true, modified_worktree_used: false,
    },
    validator_identities: [
      { role: 'AUTHORITY_VALIDATOR_IDENTITY', path: ORIGINAL_AUTHORITY_VALIDATOR, sha256: 'a'.repeat(64), source_repair_candidate_commit: repairCommit },
      { role: 'B001_HISTORICAL_VALIDATOR_IDENTITY', path: ORIGINAL_B001_VALIDATOR, sha256: 'b'.repeat(64), source_repair_candidate_commit: repairCommit },
    ],
    jobs: [{ name: 'required-ci-equivalent', conclusion: 'success' }],
    b001_regression: 'PASS',
    effective_authority_identities: 'PASS',
    repair_authority: {
      repair_task_id: 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001',
      accepted_repair_candidate_commit: repairCommit, accepted_repair_candidate_tree: '8'.repeat(40),
      independent_acceptance: 'PASS',
    },
    result: 'PASS',
    provenance: {
      execution_identity_distinct_from_verification_target: true,
      append_only: true, recovery_not_historical_ci: true,
    },
  };
}

function negativeProbeResults(amendment, supersessionSchema, recoverySchema, baseManifestBytes) {
  const probes = [];
  const recordProbe = (id, mutate, context = {}) => {
    const value = clone(amendment);
    mutate(value);
    probes.push({ id, rejected: validateAmendmentPolicy(value, { baseManifestBytes, ...context }).length > 0 });
  };
  const supersessionProbe = (id, mutate, count = 1) => {
    const first = syntheticSupersession();
    mutate(first);
    const records = [first];
    if (count === 2) records.push(syntheticSupersession());
    probes.push({ id, rejected: validateSupersessionRecords(records, supersessionSchema, { skipGit: true }).length > 0 });
  };
  const recoveryProbe = (id, mutate) => {
    const evidence = syntheticRecoveryEvidence();
    mutate(evidence);
    probes.push({ id, rejected: validateRecoveryEvidence(evidence, recoverySchema, { skipGit: true }).length > 0 });
  };

  recordProbe('A01', (v) => { v.authority_task_id = 'UNKNOWN-AUTHORITY'; });
  recordProbe('A02', (v) => { v.authority_candidate_commit = '0'.repeat(40); });
  recordProbe('A03', (v) => { v.authority_merge_commit = '0'.repeat(40); });
  recordProbe('A04', (v) => { v.base_authority_artifact_manifest_sha256 = '0'.repeat(64); });
  supersessionProbe('A05', (v) => { v.role = 'UNKNOWN_ROLE'; });
  supersessionProbe('A06', (v) => { delete v.old_sha256; });
  supersessionProbe('A07', (v) => { v.old_sha256 = '0'.repeat(64); });
  supersessionProbe('A08', (v) => { v.amendment_acceptance.accepted = false; });
  supersessionProbe('A09', () => {}, 2);
  const mutatedManifest = Buffer.concat([baseManifestBytes, Buffer.from('\n')]);
  probes.push({ id: 'A10', rejected: validateAmendmentPolicy(amendment, { baseManifestBytes: mutatedManifest }).length > 0 });
  recordProbe('A11', (v) => { v.authorized_changes[0].path = 'schemas/playtest-package/v1/aipt-playtest-package.schema.json'; });
  recordProbe('A12', (v) => { v.authorized_changes[0].path = 'schemas/runtime-adapter-input/v1/aipt-runtime-adapter-input.schema.json'; });
  recordProbe('A13', (v) => {
    v.authorized_changes[0].semantic_constraints = v.authorized_changes[0].semantic_constraints
      .filter((item) => item !== 'PRESERVE_ANCESTRY_VALIDATION');
  });
  recordProbe('A14', (v) => { v.amendment_reason[0].summary = 'TBD'; });
  recoveryProbe('A15', (v) => { v.original_merge_ci = { check_run: 'PRESENT', conclusion: 'failure', historical_merge_ci_claim: 'PASS' }; });
  recoveryProbe('A16', (v) => { v.verification_target.resolved_target_sha = '0'.repeat(40); });
  recoveryProbe('A17', (v) => { v.verification_target.target_tree = '0'.repeat(40); });
  recoveryProbe('A18', (v) => { v.validator_identities.pop(); });
  recoveryProbe('A19', (v) => { delete v.workflow_execution.workflow_definition_identity; });
  recordProbe('A20', (v) => { v.effective_authority_resolution.amendment_ordering.primary = 'filesystem_mtime_DESCENDING'; });
  return probes;
}

function validateGitBase(repo) {
  const problems = [];
  const candidateTree = gitOut(repo, ['rev-parse', `${AUTHORITY_CANDIDATE}^{tree}`]);
  const mergeTree = gitOut(repo, ['rev-parse', `${AUTHORITY_MERGE}^{tree}`]);
  const mergeParents = gitOut(repo, ['show', '-s', '--format=%P', AUTHORITY_MERGE])?.split(/\s+/);
  if (candidateTree !== AUTHORITY_TREE || mergeTree !== AUTHORITY_TREE || !same(mergeParents, AUTHORITY_PARENTS)) {
    problems.push('immutable Authority Candidate/merge Git objects are missing or drifted');
  }
  const ancestor = git(repo, ['merge-base', '--is-ancestor', AUTHORITY_MERGE, 'HEAD'], { check: false });
  if (ancestor.status !== 0) problems.push('Authority merge is not an ancestor of current HEAD');
  for (const [relative, expected] of Object.entries(BASE_HASHES)) {
    const blob = gitBlob(repo, AUTHORITY_MERGE, relative);
    if (!blob || sha256(blob) !== expected) problems.push(`base Authority historical Git identity drifted: ${relative}`);
    if (relative !== ORIGINAL_AUTHORITY_VALIDATOR) {
      try {
        if (sha256(read(repo, relative)) !== expected) problems.push(`immutable base Authority working-tree artifact drifted: ${relative}`);
      } catch (error) {
        problems.push(`immutable base Authority artifact unreadable: ${relative}: ${error.message}`);
      }
    }
  }
  return problems;
}

function validateArtifactManifest(repo, manifest) {
  const problems = [];
  if (manifest?.schema !== 'aipt.public.authority-amendment-artifacts/v1' || manifest?.amendment_id !== TASK_ID ||
      manifest?.hash_algorithm !== 'SHA-256' || manifest?.self_hash_excluded !== true ||
      manifest?.candidate_git_identity_embedded !== false ||
      !same(manifest?.artifacts?.map((item) => item.path), ARTIFACT_PATHS) ||
      !same(manifest?.artifacts?.map((item) => item.role), ARTIFACT_ROLES)) {
    problems.push('Amendment artifact manifest shape, inventory or roles drifted');
    return problems;
  }
  for (const artifact of manifest.artifacts) {
    try {
      if (sha256(read(repo, artifact.path)) !== artifact.sha256) problems.push(`Amendment artifact hash mismatch: ${artifact.path}`);
    } catch (error) {
      problems.push(`Amendment artifact unreadable: ${artifact.path}: ${error.message}`);
    }
  }
  return problems;
}

function validateB001Baseline(repo, supersessions) {
  const problems = [];
  const b001Records = supersessions.filter((record) => record.role === 'B001_HISTORICAL_VALIDATOR_IDENTITY');
  if (b001Records.length === 0 && sha256(read(repo, ORIGINAL_B001_VALIDATOR)) !== ORIGINAL_B001_VALIDATOR_SHA) {
    problems.push('B001 validator changed without an authorized supersession record');
  }
  if (sha256(read(repo, MIGRATION_PATH)) !== MIGRATION_SHA) problems.push('B001 historical queue migration SHA-256 drifted');
  const migrationFiles = new Map([
    ['000001_ledger.sql', text(repo, 'internal/storage/postgres/migrations/000001_ledger.sql')],
    ['000002_playtest_queue.sql', text(repo, MIGRATION_PATH)],
  ]);
  for (const problem of checkMigrationContract(migrationFiles)) problems.push(`B001 migration contract: ${problem}`);
  const graphPath = 'docs/authority/registry/batch-graph.json';
  const statusPath = 'docs/authority/registry/project-status.json';
  const graphSha = 'd2d9e4bb1ec00d777eede076796dabe854b509fed96252d03fcb670dcb631219';
  const statusSha = '879bb387ff03843661c9d5ed71d541282ddacb10756034d61e5d25cd56257587';
  if (sha256(read(repo, graphPath)) !== graphSha || sha256(gitBlob(repo, AUTHORITY_MERGE, graphPath) ?? Buffer.alloc(0)) !== graphSha) {
    problems.push('canonical 13-item batch graph bytes drifted from the Authority merge');
  }
  const graph = readJSON(repo, graphPath);
  for (const problem of validateGraph(graph)) problems.push(`batch graph: ${problem}`);
  if (sha256(read(repo, statusPath)) !== statusSha || sha256(gitBlob(repo, AUTHORITY_MERGE, statusPath) ?? Buffer.alloc(0)) !== statusSha) {
    problems.push('historical B001 CLOSED project status bytes drifted from the Authority merge');
  }
  const status = readJSON(repo, statusPath);
  const standalone = status.tracks?.['AIPT-STANDALONE'];
  const aipt = status.repositories?.AIPT;
  const b001 = aipt?.mvp_b001;
  if (status.authority_snapshot_id !== 'AIPT-MVP-B001-CLOSEOUT-001' ||
      standalone?.construction !== 'IDLE_WAITING_NEXT_BATCH' ||
      standalone?.current_batch !== 'NO_ACTIVE_BATCH' || standalone?.global_wip !== 0 ||
      standalone?.next_serial_batch !== 'UNREGISTERED-AIPT-P1-B000' ||
      standalone?.next_batch_state !== 'NOT_AUTHORIZED' ||
      standalone?.next_batch_authorized !== false || standalone?.next_batch_started !== false ||
      standalone?.batch_history?.['AIPT-MVP-B001'] !== 'MERGED_CLOSED' ||
      standalone?.batch_history?.['UNREGISTERED-AIPT-P1-B000'] !== 'NOT_STARTED' ||
      Object.hasOwn(aipt ?? {}, 'pending_candidate') || b001?.state !== 'MERGED_CLOSED' ||
      b001?.merged !== true || b001?.post_merge_verified !== true || b001?.closed !== true ||
      b001?.candidate?.commit !== '85ef3489405694cf0764867a97fb21b09fda5894' ||
      b001?.implementation_merge?.commit !== 'ad8e39b23f5888cfb9a7f8f15f9dd996964d8f16' ||
      b001?.post_merge_ci?.conclusion !== 'success') {
    problems.push('historical B001 CLOSED/WIP0/no-pending-Candidate lifecycle identity drifted');
  }
  const protectedPaths = [
    'schemas/testplan', 'schemas/run-manifest', 'internal/testplan',
    'internal/storage/postgres/migrations', 'internal/storage/postgres/queue.go',
    'internal/storage/postgres/queue_errors.go', 'internal/storage/postgres/queue_types.go',
    'internal/storage/postgres/queue_test.go', 'internal/storage/postgres/queue_integration_test.go',
  ];
  const diff = git(repo, ['diff', '--name-only', '--no-renames', AUTHORITY_MERGE, '--', ...protectedPaths], { check: false });
  if (diff.status !== 0 || diff.stdout.trim() !== '') problems.push('B001 protected schemas, code or migration surface changed');
  return problems;
}

function validateCurrentRoleIdentities(repo, records) {
  const problems = [];
  for (const [role, base] of Object.entries(ROLE_BASES)) {
    const chain = records.filter((record) => record.role === role)
      .sort((a, b) => a.chain_sequence - b.chain_sequence);
    const accepted = chain.filter((record) => record.repair_acceptance?.state === 'ACCEPTED' &&
      record.repair_acceptance?.independent_acceptance === 'PASS');
    const pending = chain.filter((record) => record.repair_acceptance?.state === 'CANDIDATE_FROZEN');
    let expected = accepted.length > 0 ? accepted.at(-1).new_sha256 : base.sha256;
    if (pending.length === 1 && pending[0].old_sha256 === expected) expected = pending[0].new_sha256;
    if (pending.length > 1) problems.push(`${role} has more than one pending repair Candidate`);
    try {
      if (sha256(read(repo, base.path)) !== expected) problems.push(`${role} current bytes do not match the resolved accepted or staged identity`);
    } catch (error) {
      problems.push(`${role} current path unreadable: ${error.message}`);
    }
  }
  return problems;
}

function validateAmendmentOrdering(repo, amendment) {
  const problems = [];
  const registry = path.join(repo, 'docs/authority/registry');
  const entries = byteSort(fs.readdirSync(registry).filter((name) => name.endsWith('.json')));
  const records = [];
  for (const name of entries) {
    const value = JSON.parse(fs.readFileSync(path.join(registry, name), 'utf8'));
    if (value?.schema === 'aipt.public.authority-amendment/v1') records.push(value);
  }
  const ids = records.map((record) => record.amendment_id);
  const sequences = records.map((record) => record.amendment_sequence);
  if (new Set(ids).size !== ids.length) problems.push('amendment ID is not unique');
  if (new Set(sequences).size !== sequences.length) problems.push('amendment sequence is not unique');
  const ordered = [...records].sort((a, b) => a.amendment_sequence - b.amendment_sequence ||
    Buffer.compare(Buffer.from(a.amendment_id), Buffer.from(b.amendment_id)));
  if (!same(ordered.map((record) => record.amendment_sequence),
    Array.from({ length: ordered.length }, (_, index) => index + 1))) {
    problems.push('amendment ordering is not a contiguous deterministic sequence');
  }
  if (!records.some((record) => record.amendment_id === amendment.amendment_id)) problems.push('current Amendment is dangling from registry discovery');
  return problems;
}

function classifyLifecycle(repo, env = process.env) {
  const problems = [];
  const head = gitOut(repo, ['rev-parse', 'HEAD^{commit}']);
  const headTree = gitOut(repo, ['rev-parse', 'HEAD^{tree}']);
  const branch = gitOut(repo, ['symbolic-ref', '--short', 'HEAD']);
  const github = env.GITHUB_ACTIONS === 'true';
  const event = env.GITHUB_EVENT_NAME || null;
  const ref = env.GITHUB_REF || null;
  const headRef = env.GITHUB_HEAD_REF || null;
  const mergesOutput = gitOut(repo, ['rev-list', '--merges', '--reverse', `${AUTHORITY_MERGE}..HEAD`]);
  const merges = mergesOutput ? mergesOutput.split('\n').filter(Boolean) : [];
  const changed = changedPaths(repo);
  let phase = 'SUCCESSOR';
  let amendmentOnly = false;

  const branchCandidate = (!github && branch === BRANCH) ||
    (github && event === 'push' && ref === `refs/heads/${BRANCH}`) ||
    (github && event === 'pull_request' && headRef === BRANCH);
  if (branchCandidate) {
    phase = head === AUTHORITY_MERGE ? 'ACTIVE_WORKTREE' : event === 'pull_request' ? 'PULL_REQUEST_CHECK' : 'CANDIDATE_FROZEN';
    if (github && env.GITHUB_SHA !== head) problems.push('GITHUB_SHA is not checked-out Amendment HEAD');
    let candidate = head;
    if (event === 'pull_request') {
      if (/\/merge$/.test(ref || '')) {
        const parents = gitOut(repo, ['show', '-s', '--format=%P', head])?.split(/\s+/) ?? [];
        const candidateTree = parents[1] ? gitOut(repo, ['rev-parse', `${parents[1]}^{tree}`]) : null;
        if (merges.length !== 1 || merges[0] !== head || parents.length !== 2 ||
            parents[0] !== AUTHORITY_MERGE || gitOut(repo, ['rev-parse', `${head}^{tree}`]) !== candidateTree) {
          problems.push('synthetic Amendment PR merge does not preserve exact base/Candidate topology');
        }
        candidate = parents[1] ?? head;
      } else if (/\/head$/.test(ref || '')) {
        if (merges.length !== 0) problems.push('Amendment PR head contains a merge after the Authority merge');
      } else {
        problems.push('Amendment pull_request ref is neither a head nor synthetic merge ref');
      }
    } else if (merges.length !== 0) {
      problems.push('Amendment Candidate lineage contains a merge after the Authority merge');
    }
    if (!same(changed, STAGE_PATHS)) problems.push(`Amendment Candidate path set drifted: ${JSON.stringify(changed)}`);
    const candidateMerges = gitOut(repo, ['rev-list', '--merges', `${AUTHORITY_MERGE}..${candidate}`]);
    if (candidateMerges) problems.push('Amendment Candidate itself contains a merge');
    const count = Number(gitOut(repo, ['rev-list', '--count', `${AUTHORITY_MERGE}..${candidate}`]) ?? '-1');
    if (head !== AUTHORITY_MERGE && (count < 1 || count > 3)) problems.push('Amendment Candidate must contain one to three ordinary commits');
    amendmentOnly = problems.length === 0;
  } else if ((!github && branch === 'main') || (github && event === 'push' && ref === 'refs/heads/main')) {
    const first = merges[0] ?? null;
    if (first) {
      const parents = gitOut(repo, ['show', '-s', '--format=%P', first])?.split(/\s+/) ?? [];
      const candidate = parents[1];
      const candidateTree = candidate ? gitOut(repo, ['rev-parse', `${candidate}^{tree}`]) : null;
      const mergeTree = gitOut(repo, ['rev-parse', `${first}^{tree}`]);
      if (parents.length !== 2 || parents[0] !== AUTHORITY_MERGE || mergeTree !== candidateTree) {
        problems.push('accepted Amendment merge topology does not preserve its Candidate tree');
      }
      phase = head === first ? 'MERGED' : 'SUCCESSOR';
      if (head === first) {
        const mergeChanged = git(repo, ['diff', '--name-only', '--no-renames', `${first}^1`, first], { check: false });
        const names = mergeChanged.status === 0 ? byteSort(mergeChanged.stdout.split('\n').filter(Boolean)) : [];
        if (!same(names, STAGE_PATHS)) problems.push('Amendment merge path set differs from Candidate scope');
        amendmentOnly = problems.length === 0;
      }
    } else {
      problems.push('main does not contain an accepted Amendment merge after the base Authority merge');
    }
  } else if (merges.length === 0) {
    problems.push('checkout is neither the exact Amendment branch nor a successor of its accepted merge');
  }
  return { problems, phase, head, headTree, branch, changed, merges, amendmentOnly };
}

export function run(ctx, args = {}) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push(`ok: ${message}`);
  const fail = (message) => { pass = false; details.push(`FAIL: ${message}`); };
  let amendment, artifactManifest, amendmentSchema, supersessionSchema, recoverySchema, baseManifestBytes;
  try {
    amendment = readJSON(ctx.repo, AMENDMENT_PATH);
    artifactManifest = readJSON(ctx.repo, ARTIFACT_PATH);
    amendmentSchema = readJSON(ctx.repo, AMENDMENT_SCHEMA_PATH);
    supersessionSchema = readJSON(ctx.repo, SUPERSESSION_SCHEMA_PATH);
    recoverySchema = readJSON(ctx.repo, RECOVERY_SCHEMA_PATH);
    baseManifestBytes = read(ctx.repo, BASE_MANIFEST_PATH);
  } catch (error) {
    return { result: 'FAIL', details: [`FAIL: Amendment input unreadable: ${error.message}`], negative_probes: 'NOT_RUN' };
  }

  for (const problem of schemaProblems(amendmentSchema, amendment, 'Amendment')) fail(problem);
  if (checkSchemaDocument(amendmentSchema).errors.length === 0) ok('Authority Amendment schema uses the supported fail-closed JSON Schema subset');
  for (const [label, schema] of [['supersession', supersessionSchema], ['recovery evidence', recoverySchema]]) {
    const schemaErrors = checkSchemaDocument(schema).errors;
    for (const error of schemaErrors) fail(`${label} schema: ${error}`);
    if (schemaErrors.length === 0) ok(`${label} schema uses the supported fail-closed JSON Schema subset`);
  }

  const policyProblems = validateAmendmentPolicy(amendment, { baseManifestBytes });
  for (const problem of policyProblems) fail(problem);
  if (policyProblems.length === 0) ok('Amendment policy is exact, append-only and fail-closed');

  const gitProblems = validateGitBase(ctx.repo);
  for (const problem of gitProblems) fail(problem);
  if (gitProblems.length === 0) ok('base Authority Candidate, merge, historical blobs and immutable working-tree artifacts are exact');

  const artifactProblems = validateArtifactManifest(ctx.repo, artifactManifest);
  for (const problem of artifactProblems) fail(problem);
  if (artifactProblems.length === 0) ok(`all ${ARTIFACT_PATHS.length} Amendment artifact SHA-256 identities verified`);

  let supersessionFiles = [];
  let recoveryFiles = [];
  try {
    supersessionFiles = listRecordFiles(ctx.repo, SUPERSESSION_DIRECTORY);
    recoveryFiles = listRecordFiles(ctx.repo, RECOVERY_DIRECTORY);
  } catch (error) {
    fail(error.message);
  }
  const supersessions = supersessionFiles.map((relative) => readJSON(ctx.repo, relative));
  const supersessionProblems = validateSupersessionRecords(supersessions, supersessionSchema, { repo: ctx.repo });
  for (const problem of supersessionProblems) fail(problem);
  if (supersessionProblems.length === 0) ok(`${supersessions.length} discovered supersession records form valid explicit chains`);
  const identityProblems = validateCurrentRoleIdentities(ctx.repo, supersessions);
  for (const problem of identityProblems) fail(problem);
  if (identityProblems.length === 0) ok('original/effective Authority and B001 validator identities resolve exactly');

  const recoveryEvidence = recoveryFiles.map((relative) => readJSON(ctx.repo, relative));
  const recoveryProblems = recoveryEvidence.flatMap((evidence) =>
    validateRecoveryEvidence(evidence, recoverySchema, { repo: ctx.repo }));
  for (const problem of recoveryProblems) fail(problem);
  if (recoveryProblems.length === 0) ok(`${recoveryEvidence.length} discovered post-merge recovery evidence records satisfy the narrow exact-target contract`);

  const orderingProblems = validateAmendmentOrdering(ctx.repo, amendment);
  for (const problem of orderingProblems) fail(problem);
  if (orderingProblems.length === 0) ok('Amendment IDs and sequences resolve deterministically without file-recency authority');

  const b001Problems = validateB001Baseline(ctx.repo, supersessions);
  for (const problem of b001Problems) fail(problem);
  if (b001Problems.length === 0) ok('13-item batch graph and B001 CLOSED/WIP0 lifecycle, Campaign/Suite/Case/Run, internal Attempt, immutable Manifest and PostgreSQL queue/lease/WIP1 baseline are protected');

  const lifecycle = classifyLifecycle(ctx.repo);
  for (const problem of lifecycle.problems) fail(`lifecycle: ${problem}`);
  if (lifecycle.problems.length === 0) ok(`${lifecycle.phase} lifecycle and exact Amendment scope verified`);

  const placeholderTargets = [HUMAN_PATH, AMENDMENT_PATH, AMENDMENT_SCHEMA_PATH, SUPERSESSION_SCHEMA_PATH, RECOVERY_SCHEMA_PATH];
  const placeholder = /\b(?:TBD|TODO|FIXME|XXX)\b|<actual>|<sha>|<commit>|\{\{[^}]+\}\}/i;
  for (const relative of placeholderTargets) if (placeholder.test(text(ctx.repo, relative))) fail(`unresolved placeholder appears in ${relative}`);
  if (!placeholderTargets.some((relative) => placeholder.test(text(ctx.repo, relative)))) ok('Amendment authority artifacts contain no unresolved placeholders');

  const packageJSON = readJSON(ctx.repo, 'package.json');
  const aggregate = text(ctx.repo, 'scripts/ci/run-checks.mjs');
  const workflow = text(ctx.repo, '.github/workflows/ci.yml');
  const index = text(ctx.repo, 'docs/authority/README.md');
  for (const [label, condition] of [
    ['package command', packageJSON.scripts?.['check:p1-b000-authority-amendment'] === `node ${VALIDATOR_PATH}`],
    ['aggregate import/call', aggregate.includes('runP1B000AuthorityAmendment') && aggregate.includes('runP1B000AuthorityAmendment(ctx)')],
    ['candidate CI focused command', workflow.includes('pnpm run check:p1-b000-authority-amendment')],
    ['candidate CI bootstrap classification', workflow.includes('--ci-bootstrap-classify')],
    ['authority index', index.includes('unregistered-aipt-p1-b000-authority-amendment-001.json') && index.includes('UNREGISTERED_AIPT_P1_B000_AUTHORITY_AMENDMENT_001.md')],
  ]) {
    if (condition) ok(`${label} wiring present`); else fail(`${label} wiring missing`);
  }
  const legacyCondition = "if: steps.authority_amendment_classify.outputs.applicable != 'true'";
  for (const command of amendment.acceptance?.candidate_ci_bootstrap?.exact_legacy_stage_commands_not_executed ?? []) {
    const escaped = command.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pattern = new RegExp(`${legacyCondition.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\n\\s+run: ${escaped}`);
    if (!pattern.test(workflow)) fail(`candidate CI legacy-stage condition missing for ${command}`);
  }
  if (!workflow.includes("if: steps.authority_amendment_classify.outputs.applicable == 'true'\n        run: pnpm run check:p1-b000-authority-amendment") ||
      workflow.includes('continue-on-error:')) {
    fail('candidate CI focused Amendment gate is missing, conditional binding drifted, or failure masking is present');
  } else ok('candidate CI exact bootstrap carve-out is fail-closed and never masks failures');

  const probes = negativeProbeResults(amendment, supersessionSchema, recoverySchema, baseManifestBytes);
  for (let index = 0; index < probes.length; index += 1) {
    const [expectedID, label] = NEGATIVE_CASES[index];
    const probe = probes[index];
    if (probe.id !== expectedID || !probe.rejected) fail(`${expectedID} ${label} was not rejected`);
  }
  const rejectedCount = probes.filter((probe, index) => probe.id === NEGATIVE_CASES[index][0] && probe.rejected).length;
  if (rejectedCount === NEGATIVE_CASES.length) ok('all A01-A20 Amendment, supersession and recovery mutations reject');

  const baseResult = pass ? 'PASS' : 'FAIL';
  const bootstrapApplicable = baseResult === 'PASS' && lifecycle.amendmentOnly;
  if (args['ci-bootstrap-classify'] === true && !bootstrapApplicable) {
    fail('checkout is not an exact validated Amendment-only Candidate or merge');
  }
  return {
    result: pass ? 'PASS' : 'FAIL',
    details,
    task_id: TASK_ID,
    authority_task_id: AUTHORITY_TASK_ID,
    authority_candidate_commit: AUTHORITY_CANDIDATE,
    authority_merge_commit: AUTHORITY_MERGE,
    authority_merge_tree: AUTHORITY_TREE,
    lifecycle_phase: lifecycle.phase,
    candidate_commit: lifecycle.phase === 'CANDIDATE_FROZEN' ? lifecycle.head : null,
    candidate_tree: lifecycle.phase === 'CANDIDATE_FROZEN' ? lifecycle.headTree : null,
    changed_paths: lifecycle.changed,
    amendment_validator: pass ? 'PASS' : 'FAIL',
    negative_probes: rejectedCount === NEGATIVE_CASES.length ? 'PASS' : 'FAIL',
    negative_probe_count: probes.length,
    b001_regression: b001Problems.length === 0 ? 'PASS' : 'FAIL',
    original_validator_unchanged: sha256(read(ctx.repo, ORIGINAL_AUTHORITY_VALIDATOR)) === ORIGINAL_AUTHORITY_VALIDATOR_SHA,
    original_merge_check_run: 'ABSENT',
    historical_merge_ci_claimed_pass: false,
    supersession_record_count: supersessions.length,
    recovery_evidence_count: recoveryEvidence.length,
    unresolved_placeholders: placeholderTargets.filter((relative) => placeholder.test(text(ctx.repo, relative))).length,
    bootstrap_ci_applicable: bootstrapApplicable,
    business_code_changed: false,
    repair_started: false,
    b000_implementation_started: false,
    merge_authorized: false,
  };
}

runAsMain(import.meta.url, 'p1-b000-authority-amendment', run);
