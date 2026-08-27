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
const REVISION_TASK_ID = `${TASK_ID}-R1`;
const AUTHORITY_TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-001';
const BRANCH = `task/${REVISION_TASK_ID}`;
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
const CLOSEOUT_SCHEMA_PATH = 'schemas/authority-amendment/v1/aipt-authority-amendment-closeout.schema.json';
const VALIDATOR_PATH = 'scripts/ci/validate/p1-b000-authority-amendment.mjs';
const SUPERSESSION_DIRECTORY = 'docs/authority/registry/authority-validator-supersessions';
const RECOVERY_DIRECTORY = 'docs/authority/registry/post-merge-reverification';
const CLOSEOUT_DIRECTORY = 'docs/authority/registry/authority-amendment-closeouts';
const CLOSEOUT_PATH = `${CLOSEOUT_DIRECTORY}/unregistered-aipt-p1-b000-authority-amendment-001-closeout.json`;
const SUPERSEDED_CANDIDATE = '00c9a25ea3df7436339a104de4c412d6d6f39322';
const SUPERSEDED_CANDIDATE_TREE = 'f308f1885112e0826dc6be4b70b0d7713d1a8dba';
const SUPERSEDED_CANDIDATE_CI = 32987673859;
const PRIOR_R1_CANDIDATE = '2296eb5ec90c64976b014663d04faff4530b4c48';
const PRIOR_R1_CANDIDATE_TREE = 'f05010b18f63c9833e5ed2c2d7f1cdad212fe844';
const PRIOR_R1_CANDIDATE_CI = 33039836247;
const REPAIR_TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001';

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
  CLOSEOUT_SCHEMA_PATH,
  SUPERSESSION_SCHEMA_PATH,
  RECOVERY_SCHEMA_PATH,
  'scripts/ci/run-checks.mjs',
  VALIDATOR_PATH,
].sort());

const ARTIFACT_PATHS = Object.freeze([
  HUMAN_PATH,
  AMENDMENT_PATH,
  AMENDMENT_SCHEMA_PATH,
  CLOSEOUT_SCHEMA_PATH,
  SUPERSESSION_SCHEMA_PATH,
  RECOVERY_SCHEMA_PATH,
  VALIDATOR_PATH,
]);

const ARTIFACT_ROLES = Object.freeze([
  'HUMAN_READABLE_AUTHORITY_AMENDMENT',
  'MACHINE_EXECUTION_AUTHORITY_AMENDMENT',
  'AUTHORITY_AMENDMENT_SCHEMA_V1',
  'AUTHORITY_AMENDMENT_CLOSEOUT_SCHEMA_V1',
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

const REVISION_NEGATIVE_CASES = Object.freeze([
  ['R01', 'legal direct governance closeout successor'],
  ['R02', 'successor modifies validator'],
  ['R03', 'successor modifies business code'],
  ['R04', 'successor modifies Base Authority'],
  ['R05', 'successor modifies frozen Amendment semantics'],
  ['R06', 'second-generation successor'],
  ['R07', 'unrelated main successor'],
  ['R08', 'F1 exact fingerprint'],
  ['R09', 'F1 different failure'],
  ['R10', 'F2 exact fingerprint'],
  ['R11', 'F2 different TypeError'],
  ['R12', 'third legacy validator failure'],
  ['R13', 'validator hash changed'],
  ['R14', 'Amendment-specific validator failure'],
  ['R15', 'B001 business regression'],
  ['R16', 'real CI unrelated failure'],
  ['R17', 'closeout allowed-path escape'],
  ['R18', 'duplicate closeout successor'],
  ['R19', 'bootstrap use after Amendment CLOSED'],
  ['R20', 'bootstrap use by POSTMERGE-REPAIR-001'],
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

export function classifyBootstrapTopology(facts) {
  const problems = [];
  const allowedClasses = ['CANDIDATE', 'LEGAL_MERGE', 'BOOTSTRAP_CLOSEOUT_SUCCESSOR'];
  if (facts.taskId !== REVISION_TASK_ID || facts.taskId === REPAIR_TASK_ID) {
    problems.push('bootstrap task identity is not the accepted R1 identity');
  }
  if (!allowedClasses.includes(facts.lifecycleClass)) problems.push('lifecycle class is not bootstrap-eligible');
  if (facts.closedBeforeCommit === true) problems.push('bootstrap permission already expired at CLOSED');
  if (facts.candidate?.parent !== AUTHORITY_MERGE || facts.candidate?.ordinaryCommitCount !== 2 ||
      facts.candidate?.containsMerge !== false || facts.candidate?.containsSupersededCandidate !== false ||
      facts.candidate?.priorAttemptCommit !== PRIOR_R1_CANDIDATE ||
      facts.candidate?.priorAttemptTree !== PRIOR_R1_CANDIDATE_TREE ||
      !same(facts.candidate?.changedPaths, STAGE_PATHS)) {
    problems.push('replacement Candidate is not the exact two-commit R1 lineage');
  }

  if (['LEGAL_MERGE', 'BOOTSTRAP_CLOSEOUT_SUCCESSOR'].includes(facts.lifecycleClass)) {
    const merge = facts.merge;
    if (merge?.parentCount !== 2 || merge?.firstParent !== AUTHORITY_MERGE ||
        merge?.secondParent !== facts.candidate?.commit || merge?.tree !== facts.candidate?.tree ||
        merge?.candidateTree !== facts.candidate?.tree || merge?.candidateTreePreserved !== true) {
      problems.push('Amendment merge is not the exact legal no-fast-forward replacement merge');
    }
  }

  if (facts.lifecycleClass === 'BOOTSTRAP_CLOSEOUT_SUCCESSOR') {
    const successor = facts.successor;
    if (successor?.depth !== 1 || successor?.parentCount !== 1 ||
        successor?.parent !== facts.merge?.commit || successor?.priorCloseoutRecordPresent !== false ||
        successor?.closeoutRecordCount !== 1 || successor?.duplicateCloseout !== false ||
        !same(successor?.changedPaths, [CLOSEOUT_PATH])) {
      problems.push('closeout successor is not the unique direct exact-path governance child');
    }
    if (successor?.businessCodeChanged !== false || successor?.validatorRepairExecuted !== false ||
        successor?.b000ImplementationStarted !== false) {
      problems.push('closeout successor crosses the governance-only execution boundary');
    }
  } else if (facts.successor != null) {
    problems.push('non-closeout lifecycle class unexpectedly carries successor state');
  }
  return {
    accepted: problems.length === 0,
    classification: problems.length === 0 ? facts.lifecycleClass : 'REJECTED',
    problems,
  };
}

function expectedF1Failures(changedPathsValue, executionContext = {}) {
  const failures = ['FAIL: authority Candidate contains a merge commit'];
  if (executionContext.github_actions === true && executionContext.event_name === 'push') {
    failures.push('FAIL: authority Candidate push is not bound to the exact authority branch');
  } else if (executionContext.github_actions !== true) {
    failures.push('FAIL: local authority checkout is not the exact authority branch');
  }
  failures.push(`FAIL: authority candidate path set drifted: ${JSON.stringify(changedPathsValue)}`);
  return failures;
}

export function classifyLegacyDefect(observation, expectedChangedPaths = []) {
  const problems = [];
  if (observation.executed !== true || observation.status !== 1 || observation.signal != null) {
    problems.push('legacy validator was not executed to the exact expected exit state');
  }
  if (observation.defect_id === 'F1') {
    if (observation.validator !== ORIGINAL_AUTHORITY_VALIDATOR || observation.sha256 !== ORIGINAL_AUTHORITY_VALIDATOR_SHA) {
      problems.push('F1 validator path or frozen SHA-256 drifted');
    }
    if ((observation.stderr ?? '').trim() !== '') problems.push('F1 emitted unexpected stderr');
    const report = observation.report;
    const executionContext = observation.execution_context ?? {};
    if (executionContext.github_actions === true && !['push', 'pull_request'].includes(executionContext.event_name)) {
      problems.push('F1 GitHub lifecycle context is not a supported push or pull_request event');
    }
    if (!report || report.schema !== 'aipt.public.b001-validator-report/v1' || report.name !== 'p1-b000-authority' ||
        report.result !== 'FAIL' || report.task_id !== AUTHORITY_TASK_ID || report.negative_probes !== 'PASS' ||
        report.negative_probe_count !== 39 || report.real_model_calls !== 0 || report.real_playtest_executed !== false ||
        report.implementation_started !== false || report.merge_authorized !== false ||
        !same(report.changed_paths, expectedChangedPaths)) {
      problems.push('F1 structured report identity, protected baseline or lifecycle path inventory drifted');
    }
    const failures = Array.isArray(report?.details) ? report.details.filter((line) => line.startsWith('FAIL:')) : [];
    if (!same(failures, expectedF1Failures(expectedChangedPaths, executionContext))) {
      problems.push('F1 failure set is not the exact known candidate-only topology defect');
    }
  } else if (observation.defect_id === 'F2') {
    if (observation.validator !== ORIGINAL_B001_VALIDATOR || observation.sha256 !== ORIGINAL_B001_VALIDATOR_SHA) {
      problems.push('F2 validator path or frozen SHA-256 drifted');
    }
    if ((observation.stdout ?? '').trim() !== '' || observation.report != null) problems.push('F2 unexpectedly emitted a structured stdout report');
    const stderr = (observation.stderr ?? '').replaceAll('\r\n', '\n');
    const firstLine = stderr.split('\n').find((line) => line.startsWith('TypeError:')) ?? '';
    if (firstLine !== "TypeError: Cannot set properties of undefined (setting 'merge_authorized')") {
      problems.push('F2 TypeError identity drifted');
    }
    const applicationFrames = [...stderr.matchAll(/scripts\/ci\/(?:validate\/mvp-b001\.mjs|lib\/cli\.mjs):(\d+):(\d+)/g)]
      .map((match) => `${match[0].slice(match[0].indexOf('scripts/ci/'))}`);
    const expectedFrames = [
      'scripts/ci/validate/mvp-b001.mjs:692:102',
      'scripts/ci/validate/mvp-b001.mjs:695:85',
      'scripts/ci/validate/mvp-b001.mjs:695:29',
      'scripts/ci/validate/mvp-b001.mjs:981:24',
      'scripts/ci/lib/cli.mjs:47:18',
      'scripts/ci/validate/mvp-b001.mjs:999:1',
    ];
    if (!same(applicationFrames, expectedFrames)) problems.push('F2 stable application failure sites drifted');
    const normalizedLines = stderr.split('\n')
      .map((line) => line.replace(/file:\/\/\/.*?\/scripts\/ci\//, 'scripts/ci/').trim())
      .filter(Boolean);
    const exactNormalizedPrefix = [
      `${ORIGINAL_B001_VALIDATOR}:692`,
      "['merge authorization forged', (v) => { v.repositories.AIPT.pending_candidate.merge_authorized = true; }],",
      '^',
      "TypeError: Cannot set properties of undefined (setting 'merge_authorized')",
      `at ${ORIGINAL_B001_VALIDATOR}:692:102`,
      `at ${ORIGINAL_B001_VALIDATOR}:695:85`,
      'at Array.map (<anonymous>)',
      `at statusMutationChecks (${ORIGINAL_B001_VALIDATOR}:695:29)`,
      `at run (${ORIGINAL_B001_VALIDATOR}:981:24)`,
      'at runAsMain (scripts/ci/lib/cli.mjs:47:18)',
      `at ${ORIGINAL_B001_VALIDATOR}:999:1`,
    ];
    const internalLines = normalizedLines.slice(exactNormalizedPrefix.length);
    const internalPatterns = [
      /^at ModuleJob\.run \(node:internal\/modules\/esm\/module_job:\d+:\d+\)$/,
      /^at async (?:onImport\.tracePromise\.__proto__ \()?node:internal\/modules\/esm\/loader:\d+:\d+\)?$/,
      /^at async asyncRunEntryPointWithESMLoader \(node:internal\/modules\/run_main:\d+:\d+\)$/,
      /^Node\.js v\d+\.\d+\.\d+$/,
    ];
    if (!same(normalizedLines.slice(0, exactNormalizedPrefix.length), exactNormalizedPrefix) ||
        internalLines.length !== internalPatterns.length ||
        internalLines.some((line, index) => !internalPatterns[index].test(line)) ||
        (stderr.match(/^TypeError:/gm) ?? []).length !== 1) {
      problems.push('F2 stderr contains an additional error or failure class');
    }
  } else {
    problems.push('unknown legacy defect identity');
  }
  return {
    accepted: problems.length === 0,
    classification: problems.length === 0 ? 'KNOWN_PREEXISTING_BOOTSTRAP_DEFECT' : 'REJECTED',
    defect_id: observation.defect_id,
    problems,
  };
}

export function classifyBootstrapDecision(input) {
  const topology = classifyBootstrapTopology(input.topology);
  const problems = [...topology.problems];
  if (input.amendmentValidator !== 'PASS') problems.push('Amendment-specific validator did not PASS');
  if (input.b001BusinessRegression !== 'PASS') problems.push('B001 business regression did not PASS');
  if (input.realCiUnrelatedFailure === true) problems.push('real CI contains an unrelated required failure');
  const observations = input.observations ?? [];
  if (observations.length !== 2 || !same(observations.map((item) => item.defect_id), ['F1', 'F2'])) {
    problems.push('legacy observation inventory is not exactly F1 and F2');
  }
  const classifications = observations.map((observation) =>
    classifyLegacyDefect(observation, input.expectedChangedPaths));
  for (const classification of classifications) {
    for (const problem of classification.problems) problems.push(`${classification.defect_id}: ${problem}`);
  }
  return {
    accepted: problems.length === 0,
    classification: problems.length === 0 ? topology.classification : 'REJECTED',
    legacy: classifications,
    problems,
  };
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

  const revision = amendment.revision;
  const superseded = revision?.supersedes_candidate;
  if (revision?.revision_task_id !== REVISION_TASK_ID || revision?.accepted_amendment_identity !== TASK_ID ||
      revision?.revision_kind !== 'REPLACEMENT_BEFORE_MERGE' ||
      revision?.semantic_change !== 'BOOTSTRAP_CLOSEOUT_SUCCESSOR_ONLY' ||
      !same(revision?.changed_semantics, [
        'BOOTSTRAP_CLOSEOUT_SUCCESSOR_ACCEPTANCE',
        'DIRECTLY_REQUIRED_CI_CLASSIFIER_SEMANTICS',
      ]) || superseded?.commit !== SUPERSEDED_CANDIDATE || superseded?.tree !== SUPERSEDED_CANDIDATE_TREE ||
      superseded?.ci_run !== SUPERSEDED_CANDIDATE_CI || superseded?.merged !== false ||
      superseded?.classification !== 'SUPERSEDED_BEFORE_MERGE' ||
      superseded?.reason !== 'BOOTSTRAP_CLOSEOUT_MODEL_INCOMPLETE' || superseded?.history_preserved !== true ||
      !same(revision?.prior_revision_attempts, [{
        commit: PRIOR_R1_CANDIDATE,
        tree: PRIOR_R1_CANDIDATE_TREE,
        ci_run: PRIOR_R1_CANDIDATE_CI,
        conclusion: 'failure',
        failed_stage: 'BOOTSTRAP_CLASSIFIER',
        reason: 'F1_GITHUB_PUSH_CONTEXT_VARIANT_NOT_MODELLED',
        recovery_override: false,
        provenance_preserved: true,
      }]) ||
      revision?.validator_repair_performed !== false || revision?.base_authority_modified !== false ||
      revision?.b000_contract_modified !== false) {
    problems.push('R1 replacement provenance or minimal semantic-change inventory drifted');
  }

  const bootstrapRule = amendment.bootstrap_closeout_successor;
  const successorRule = bootstrapRule?.closeout_successor;
  if (bootstrapRule?.rule_id !== 'AMENDMENT_BOOTSTRAP_CLOSEOUT_SUCCESSOR_RULE_V1' ||
      bootstrapRule?.accepted_amendment_id !== TASK_ID || bootstrapRule?.revision_task_id !== REVISION_TASK_ID ||
      !same(bootstrapRule?.eligible_lifecycle_classes, ['CANDIDATE', 'LEGAL_MERGE', 'BOOTSTRAP_CLOSEOUT_SUCCESSOR']) ||
      bootstrapRule?.replacement_candidate?.branch !== BRANCH ||
      bootstrapRule?.replacement_candidate?.base_commit !== AUTHORITY_MERGE ||
      bootstrapRule?.replacement_candidate?.base_tree !== AUTHORITY_TREE ||
      bootstrapRule?.replacement_candidate?.ordinary_commit_count !== 2 ||
      bootstrapRule?.replacement_candidate?.superseded_candidate_is_not_ancestor !== true ||
      bootstrapRule?.legal_merge?.first_parent !== AUTHORITY_MERGE ||
      bootstrapRule?.legal_merge?.second_parent !== 'CURRENT_APPROVED_REPLACEMENT_CANDIDATE' ||
      bootstrapRule?.legal_merge?.merge_tree_equals_candidate_tree !== true ||
      bootstrapRule?.legal_merge?.real_merge_ci_required !== true ||
      successorRule?.maximum_depth !== 1 || successorRule?.commit_parent_count !== 1 ||
      successorRule?.parent_rule !== 'PARENT_EQUALS_ACCEPTED_AMENDMENT_MERGE_COMMIT' ||
      successorRule?.governance_only !== true || successorRule?.record_schema !== CLOSEOUT_SCHEMA_PATH ||
      successorRule?.record_path !== CLOSEOUT_PATH || !same(successorRule?.exact_allowed_paths, [CLOSEOUT_PATH]) ||
      successorRule?.only_transition !== 'MERGED_THROUGH_POST_MERGE_VERIFIED_TO_CLOSED' ||
      successorRule?.business_code_changed !== false || successorRule?.validator_repair_executed !== false ||
      successorRule?.b000_implementation_started !== false || bootstrapRule?.single_use !== true ||
      bootstrapRule?.permission_expires_when !== 'AMENDMENT_CLOSED' ||
      bootstrapRule?.duplicate_closeout_successor !== 'REJECT' || bootstrapRule?.repair_task_bootstrap_use !== 'REJECT' ||
      !same(bootstrapRule?.rejected_lifecycle_classes, [
        'UNRELATED_SUCCESSOR', 'MULTI_HOP_SUCCESSOR', 'BUSINESS_SUCCESSOR',
        'VALIDATOR_REPAIR_SUCCESSOR', 'UNKNOWN_TOPOLOGY',
      ])) {
    problems.push('bootstrap closeout successor rule is not exact, direct, single-use and default-deny');
  }
  const requiredCloseoutForbidden = [
    ORIGINAL_AUTHORITY_VALIDATOR, ORIGINAL_B001_VALIDATOR,
    'docs/authority/UNREGISTERED_AIPT_P1_B000_AUTHORITY.md',
    'docs/authority/registry/unregistered-aipt-p1-b000-authority.json',
    BASE_MANIFEST_PATH, HUMAN_PATH, AMENDMENT_PATH, ARTIFACT_PATH,
    AMENDMENT_SCHEMA_PATH, CLOSEOUT_SCHEMA_PATH, SUPERSESSION_SCHEMA_PATH, RECOVERY_SCHEMA_PATH,
    '.github/workflows/ci.yml', 'package.json', 'scripts/ci/run-checks.mjs', VALIDATOR_PATH,
  ];
  if (!same(successorRule?.forbidden_exact_paths, requiredCloseoutForbidden) ||
      !same(successorRule?.forbidden_path_prefixes, [
        'internal/', 'cmd/', 'packages/', 'schemas/playtest-package/', 'schemas/runtime-adapter-input/',
      ])) {
    problems.push('closeout forbidden paths are incomplete, reordered or widened');
  }

  const fingerprints = amendment.legacy_defect_fingerprints;
  if (fingerprints?.classification !== 'KNOWN_PREEXISTING_BOOTSTRAP_DEFECT' ||
      fingerprints?.exact_failure_count !== 2 || fingerprints?.raw_execution_required !== true ||
      fingerprints?.raw_stdout_stderr_preserved !== true || fingerprints?.skipping_permitted !== false ||
      fingerprints?.F1?.validator !== ORIGINAL_AUTHORITY_VALIDATOR ||
      fingerprints?.F1?.sha256 !== ORIGINAL_AUTHORITY_VALIDATOR_SHA ||
      fingerprints?.F1?.failure_class !== 'STRUCTURED_VALIDATOR_FAIL' || fingerprints?.F1?.exit_status !== 1 ||
      !same(fingerprints?.F1?.lifecycle_context_messages, {
        LOCAL: 'local authority checkout is not the exact authority branch',
        GITHUB_PUSH: 'authority Candidate push is not bound to the exact authority branch',
        GITHUB_PULL_REQUEST: 'NO_BRANCH_FAILURE_BECAUSE_FROZEN_VALIDATOR_ONLY_BRANCH_GATES_PUSH',
      }) ||
      fingerprints?.F1?.additional_failure !== 'REJECT' ||
      fingerprints?.F2?.validator !== ORIGINAL_B001_VALIDATOR ||
      fingerprints?.F2?.sha256 !== ORIGINAL_B001_VALIDATOR_SHA ||
      fingerprints?.F2?.failure_class !== 'UNCAUGHT_TYPE_ERROR' || fingerprints?.F2?.exit_status !== 1 ||
      fingerprints?.F2?.error_message !== "Cannot set properties of undefined (setting 'merge_authorized')" ||
      fingerprints?.F2?.additional_error !== 'REJECT' || fingerprints?.hash_change !== 'REJECT' ||
      fingerprints?.unknown_failure_class !== 'REJECT' || fingerprints?.third_failure !== 'REJECT' ||
      fingerprints?.artifact_ancestry_scope_or_provenance_failure !== 'REJECT') {
    problems.push('legacy defect fingerprints are not exact, executed and fail-closed');
  }

  const ci = amendment.ci_contract;
  if (ci?.classifier_command !== `node ${VALIDATOR_PATH} --ci-bootstrap-classify` ||
      !same(ci?.classifier_pipeline, [
        'RUN_LEGACY_VALIDATORS', 'CAPTURE_RAW_RESULT', 'VERIFY_EXACT_FROZEN_HASH',
        'VERIFY_EXACT_DEFECT_FINGERPRINT', 'FAIL_UNLESS_ONLY_F1_AND_F2_MATCH', 'EMIT_BOOTSTRAP_ROUTE',
      ]) || ci?.candidate_ci?.real_run_required !== true || ci?.legal_merge_ci?.real_run_required !== true ||
      ci?.closeout_ci?.real_run_required !== true || ci?.legacy_validator_results?.executed !== true ||
      ci?.legacy_validator_results?.raw_result !== 'FAIL' || ci?.legacy_validator_results?.claimed_pass !== false ||
      ci?.required_amendment_command !== 'pnpm run check:p1-b000-authority-amendment' ||
      ci?.go_test_all_unconditional !== true || ci?.business_contract_gates_unconditional !== true ||
      ci?.real_failed_ci_overridable !== false || ci?.bootstrap_available_to_postmerge_repair !== false ||
      ci?.expires_after_closeout !== true) {
    problems.push('candidate/merge/closeout CI classifier contract drifted or masks failure');
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
  if (bootstrap?.classifier_command !== `node ${VALIDATOR_PATH} --ci-bootstrap-classify` ||
      !same(bootstrap?.legacy_validators_executed, [ORIGINAL_AUTHORITY_VALIDATOR, ORIGINAL_B001_VALIDATOR]) ||
      bootstrap?.raw_failure_evidence_preserved !== true || !same(bootstrap?.exact_known_defects_only, ['F1', 'F2']) ||
      bootstrap?.legacy_results_claimed_pass !== false || bootstrap?.unknown_or_additional_failure !== 'FAIL' ||
      bootstrap?.unclassified_pre_closeout_successor !== 'FAIL' ||
      bootstrap?.post_closeout_behavior !== 'BOOTSTRAP_EXPIRED_EXECUTE_NORMAL_GATES' ||
      bootstrap?.required_amendment_command !== 'pnpm run check:p1-b000-authority-amendment' ||
      bootstrap?.go_test_all_unconditional !== true || bootstrap?.business_contract_gates_unconditional !== true) {
    problems.push('candidate CI bootstrap does not execute and fingerprint the exact F1/F2 validators');
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

export function validateCloseoutRecord(record, schema, lifecycle) {
  const problems = schemaProblems(schema, record, `closeout ${record?.closeout_id ?? 'unknown'}`);
  if (record?.schema !== 'aipt.public.authority-amendment-closeout/v1' ||
      record?.closeout_id !== `${TASK_ID}-CLOSEOUT-001` || record?.amendment_id !== TASK_ID ||
      record?.revision_task_id !== REVISION_TASK_ID) {
    problems.push('closeout record identity is not exact');
  }
  const identity = record?.accepted_identity;
  if (identity?.candidate_commit !== lifecycle.candidate || identity?.candidate_tree !== lifecycle.candidateTree ||
      identity?.merge_commit !== lifecycle.amendmentMerge || identity?.merge_tree !== lifecycle.amendmentMergeTree ||
      !same(identity?.merge_parents, [AUTHORITY_MERGE, lifecycle.candidate]) ||
      lifecycle.amendmentMergeTree !== lifecycle.candidateTree) {
    problems.push('closeout accepted Candidate/merge identity does not match exact Git topology');
  }
  if (record?.candidate_ci?.head_sha !== lifecycle.candidate || record?.candidate_ci?.conclusion !== 'success' ||
      record?.candidate_ci?.jobs_failed !== 0 || record?.amendment_merge_ci?.head_sha !== lifecycle.amendmentMerge ||
      record?.amendment_merge_ci?.conclusion !== 'success' || record?.amendment_merge_ci?.jobs_failed !== 0 ||
      record?.candidate_ci?.run_id === record?.amendment_merge_ci?.run_id) {
    problems.push('closeout candidate and legal-merge CI evidence is missing, failed, conflated or bound to the wrong SHA');
  }
  const verification = record?.post_merge_verification;
  const requiredPassFields = [
    'amendment_validator', 'amendment_artifact_hashes', 'base_authority_immutability',
    'effective_authority_resolution', 'amendment_ordering', 'amendment_provenance',
    'lifecycle_transition', 'closeout_path_policy', 'b001_business_regression',
    'go_test_all', 'negative_probes',
  ];
  if (requiredPassFields.some((field) => verification?.[field] !== 'PASS') ||
      verification?.unresolved_placeholders !== 0 || !same(verification?.legacy_validator_results, [
        {
          defect_id: 'F1', validator: ORIGINAL_AUTHORITY_VALIDATOR, executed: true,
          raw_result: 'FAIL', classification: 'KNOWN_PREEXISTING_BOOTSTRAP_DEFECT',
        },
        {
          defect_id: 'F2', validator: ORIGINAL_B001_VALIDATOR, executed: true,
          raw_result: 'FAIL', classification: 'KNOWN_PREEXISTING_BOOTSTRAP_DEFECT',
        },
      ])) {
    problems.push('closeout post-merge verification does not preserve exact PASS gates and raw F1/F2 classifications');
  }
  if (!same(record?.lifecycle_transition, { from: 'MERGED', through: 'POST_MERGE_VERIFIED', to: 'CLOSED' }) ||
      record?.owner_closeout_authorization?.authorized !== true ||
      record?.owner_closeout_authorization?.authorized_by !== 'Owner' ||
      /\b(?:TBD|TODO|FIXME|XXX)\b|<actual>|<sha>|<commit>|\{\{[^}]+\}\}/i.test(record?.owner_closeout_authorization?.directive ?? '')) {
    problems.push('closeout transition or separate Owner closeout authorization is invalid');
  }
  if (!same(record?.scope, {
    governance_only: true,
    business_code_changed: false,
    validator_repair_executed: false,
    b000_implementation_started: false,
  }) || !same(record?.bootstrap_permission, {
    use_count: 1, single_use: true, expired_after_this_transition: true,
  }) || !same(record?.open_findings, [])) {
    problems.push('closeout scope, single-use expiry or open-findings boundary drifted');
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

function syntheticF1Observation(expectedChangedPaths) {
  const executionContext = {
    github_actions: false, event_name: null, ref: null, head_ref: null,
  };
  const report = {
    schema: 'aipt.public.b001-validator-report/v1',
    name: 'p1-b000-authority',
    result: 'FAIL',
    task_id: AUTHORITY_TASK_ID,
    details: expectedF1Failures(expectedChangedPaths, executionContext),
    changed_paths: [...expectedChangedPaths],
    negative_probes: 'PASS',
    negative_probe_count: 39,
    real_model_calls: 0,
    real_playtest_executed: false,
    implementation_started: false,
    merge_authorized: false,
  };
  return {
    defect_id: 'F1', validator: ORIGINAL_AUTHORITY_VALIDATOR,
    sha256: ORIGINAL_AUTHORITY_VALIDATOR_SHA, executed: true, status: 1, signal: null,
    stdout: JSON.stringify(report), stderr: '', report, execution_context: executionContext,
  };
}

function syntheticF2Observation() {
  const stderr = [
    `file:///repo/${ORIGINAL_B001_VALIDATOR}:692`,
    "      ['merge authorization forged', (v) => { v.repositories.AIPT.pending_candidate.merge_authorized = true; }],",
    '                                                                                                     ^',
    '',
    "TypeError: Cannot set properties of undefined (setting 'merge_authorized')",
    `    at file:///repo/${ORIGINAL_B001_VALIDATOR}:692:102`,
    `    at file:///repo/${ORIGINAL_B001_VALIDATOR}:695:85`,
    '    at Array.map (<anonymous>)',
    `    at statusMutationChecks (file:///repo/${ORIGINAL_B001_VALIDATOR}:695:29)`,
    `    at run (file:///repo/${ORIGINAL_B001_VALIDATOR}:981:24)`,
    '    at runAsMain (file:///repo/scripts/ci/lib/cli.mjs:47:18)',
    `    at file:///repo/${ORIGINAL_B001_VALIDATOR}:999:1`,
    '    at ModuleJob.run (node:internal/modules/esm/module_job:439:25)',
    '    at async onImport.tracePromise.__proto__ (node:internal/modules/esm/loader:643:26)',
    '    at async asyncRunEntryPointWithESMLoader (node:internal/modules/run_main:101:5)',
    'Node.js v24.19.0',
    '',
  ].join('\n');
  return {
    defect_id: 'F2', validator: ORIGINAL_B001_VALIDATOR,
    sha256: ORIGINAL_B001_VALIDATOR_SHA, executed: true, status: 1, signal: null,
    stdout: '', stderr, report: null,
  };
}

function syntheticBootstrapTopology() {
  const candidate = 'c'.repeat(40);
  const candidateTree = 'd'.repeat(40);
  const merge = 'e'.repeat(40);
  return {
    taskId: REVISION_TASK_ID,
    lifecycleClass: 'BOOTSTRAP_CLOSEOUT_SUCCESSOR',
    closedBeforeCommit: false,
    candidate: {
      commit: candidate, tree: candidateTree, parent: AUTHORITY_MERGE,
      ordinaryCommitCount: 2, containsMerge: false, containsSupersededCandidate: false,
      priorAttemptCommit: PRIOR_R1_CANDIDATE, priorAttemptTree: PRIOR_R1_CANDIDATE_TREE,
      changedPaths: [...STAGE_PATHS],
    },
    merge: {
      commit: merge, parentCount: 2, firstParent: AUTHORITY_MERGE, secondParent: candidate,
      tree: candidateTree, candidateTree, candidateTreePreserved: true,
    },
    successor: {
      depth: 1, parentCount: 1, parent: merge, priorCloseoutRecordPresent: false,
      closeoutRecordCount: 1, duplicateCloseout: false, changedPaths: [CLOSEOUT_PATH],
      businessCodeChanged: false, validatorRepairExecuted: false, b000ImplementationStarted: false,
    },
  };
}

function syntheticCloseoutRecord(topology) {
  return {
    schema: 'aipt.public.authority-amendment-closeout/v1',
    closeout_id: `${TASK_ID}-CLOSEOUT-001`,
    amendment_id: TASK_ID,
    revision_task_id: REVISION_TASK_ID,
    accepted_identity: {
      candidate_commit: topology.candidate.commit,
      candidate_tree: topology.candidate.tree,
      merge_commit: topology.merge.commit,
      merge_tree: topology.merge.tree,
      merge_parents: [AUTHORITY_MERGE, topology.candidate.commit],
    },
    candidate_ci: {
      run_id: 101, head_sha: topology.candidate.commit, conclusion: 'success', jobs_failed: 0,
    },
    amendment_merge_ci: {
      run_id: 102, head_sha: topology.merge.commit, conclusion: 'success', jobs_failed: 0,
    },
    post_merge_verification: {
      amendment_validator: 'PASS', amendment_artifact_hashes: 'PASS', base_authority_immutability: 'PASS',
      effective_authority_resolution: 'PASS', amendment_ordering: 'PASS', amendment_provenance: 'PASS',
      lifecycle_transition: 'PASS', closeout_path_policy: 'PASS', b001_business_regression: 'PASS',
      go_test_all: 'PASS', negative_probes: 'PASS', unresolved_placeholders: 0,
      legacy_validator_results: [
        {
          defect_id: 'F1', validator: ORIGINAL_AUTHORITY_VALIDATOR, executed: true,
          raw_result: 'FAIL', classification: 'KNOWN_PREEXISTING_BOOTSTRAP_DEFECT',
        },
        {
          defect_id: 'F2', validator: ORIGINAL_B001_VALIDATOR, executed: true,
          raw_result: 'FAIL', classification: 'KNOWN_PREEXISTING_BOOTSTRAP_DEFECT',
        },
      ],
    },
    lifecycle_transition: { from: 'MERGED', through: 'POST_MERGE_VERIFIED', to: 'CLOSED' },
    owner_closeout_authorization: {
      authorized: true, authorized_by: 'Owner', directive: `${TASK_ID}-CLOSEOUT-AUTHORIZATION-001`,
    },
    scope: {
      governance_only: true, business_code_changed: false,
      validator_repair_executed: false, b000_implementation_started: false,
    },
    bootstrap_permission: { use_count: 1, single_use: true, expired_after_this_transition: true },
    open_findings: [],
  };
}

function revisionNegativeProbeResults(closeoutSchema) {
  const expectedChangedPaths = ['EXACT_GOVERNANCE_LIFECYCLE_DIFF'];
  const validInput = () => ({
    topology: syntheticBootstrapTopology(),
    observations: [syntheticF1Observation(expectedChangedPaths), syntheticF2Observation()],
    expectedChangedPaths,
    amendmentValidator: 'PASS',
    b001BusinessRegression: 'PASS',
    realCiUnrelatedFailure: false,
  });
  const results = [];
  const decisionProbe = (id, mutate, expectedAccepted = false) => {
    const value = validInput();
    mutate(value);
    results.push({ id, matched: classifyBootstrapDecision(value).accepted === expectedAccepted });
  };
  const defectProbe = (id, observation, expectedAccepted) => {
    results.push({
      id,
      matched: classifyLegacyDefect(observation, expectedChangedPaths).accepted === expectedAccepted,
    });
  };

  decisionProbe('R01', () => {}, true);
  const validTopology = syntheticBootstrapTopology();
  const closeoutLifecycle = {
    candidate: validTopology.candidate.commit,
    candidateTree: validTopology.candidate.tree,
    amendmentMerge: validTopology.merge.commit,
    amendmentMergeTree: validTopology.merge.tree,
  };
  results[0].matched = results[0].matched &&
    validateCloseoutRecord(syntheticCloseoutRecord(validTopology), closeoutSchema, closeoutLifecycle).length === 0;
  decisionProbe('R02', (v) => { v.topology.successor.changedPaths = [CLOSEOUT_PATH, ORIGINAL_AUTHORITY_VALIDATOR]; });
  decisionProbe('R03', (v) => { v.topology.successor.changedPaths = [CLOSEOUT_PATH, 'internal/run/core.go']; });
  decisionProbe('R04', (v) => { v.topology.successor.changedPaths = [CLOSEOUT_PATH, 'docs/authority/UNREGISTERED_AIPT_P1_B000_AUTHORITY.md']; });
  decisionProbe('R05', (v) => { v.topology.successor.changedPaths = [CLOSEOUT_PATH, AMENDMENT_PATH]; });
  decisionProbe('R06', (v) => { v.topology.successor.depth = 2; });
  decisionProbe('R07', (v) => { v.topology.lifecycleClass = 'UNRELATED_SUCCESSOR'; });
  defectProbe('R08', syntheticF1Observation(expectedChangedPaths), true);
  const wrongF1 = syntheticF1Observation(expectedChangedPaths);
  wrongF1.report.details.push('FAIL: new unrelated failure');
  defectProbe('R09', wrongF1, false);
  defectProbe('R10', syntheticF2Observation(), true);
  const wrongF2 = syntheticF2Observation();
  wrongF2.stderr = wrongF2.stderr.replace('merge_authorized', 'different_error');
  defectProbe('R11', wrongF2, false);
  decisionProbe('R12', (v) => { v.observations.push({ ...syntheticF2Observation(), defect_id: 'F3' }); });
  decisionProbe('R13', (v) => { v.observations[0].sha256 = '0'.repeat(64); });
  decisionProbe('R14', (v) => { v.amendmentValidator = 'FAIL'; });
  decisionProbe('R15', (v) => { v.b001BusinessRegression = 'FAIL'; });
  decisionProbe('R16', (v) => { v.realCiUnrelatedFailure = true; });
  decisionProbe('R17', (v) => { v.topology.successor.changedPaths = ['docs/authority/registry/unbounded.json']; });
  decisionProbe('R18', (v) => { v.topology.successor.duplicateCloseout = true; });
  decisionProbe('R19', (v) => { v.topology.closedBeforeCommit = true; });
  decisionProbe('R20', (v) => { v.topology.taskId = REPAIR_TASK_ID; });
  return results;
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
      manifest?.revision_task_id !== REVISION_TASK_ID ||
      manifest?.supersedes_candidate?.commit !== SUPERSEDED_CANDIDATE ||
      manifest?.supersedes_candidate?.tree !== SUPERSEDED_CANDIDATE_TREE ||
      manifest?.supersedes_candidate?.ci_run !== SUPERSEDED_CANDIDATE_CI ||
      manifest?.supersedes_candidate?.reason !== 'BOOTSTRAP_CLOSEOUT_MODEL_INCOMPLETE' ||
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
  const changed = changedPaths(repo);
  const legacyExpectedChangedPaths = changedPaths(repo, AUTHORITY_PARENTS[0]);
  const commitPaths = (base, target) => {
    const cp = git(repo, ['diff', '--name-only', '--no-renames', base, target], { check: false });
    return cp.status === 0 ? byteSort(cp.stdout.split('\n').filter(Boolean)) : [];
  };
  const parentsOf = (commit) => gitOut(repo, ['show', '-s', '--format=%P', commit])?.split(/\s+/).filter(Boolean) ?? [];
  const branchCandidate = (!github && branch === BRANCH) ||
    (github && event === 'push' && ref === `refs/heads/${BRANCH}`) ||
    (github && event === 'pull_request' && headRef === BRANCH);

  let phase = 'UNKNOWN_TOPOLOGY';
  let lifecycleClass = null;
  let bootstrapEligible = false;
  let candidate = null;
  let candidateTree = null;
  let amendmentMerge = null;
  let amendmentMergeTree = null;
  let topology = null;
  let closeoutRecordCount = 0;

  if (github && env.GITHUB_SHA && env.GITHUB_SHA !== head) problems.push('GITHUB_SHA is not the checked-out HEAD');

  if (branchCandidate) {
    phase = head === AUTHORITY_MERGE ? 'ACTIVE_WORKTREE' : 'CANDIDATE';
    candidate = head;
    if (github && event === 'pull_request') {
      if (/\/merge$/.test(ref || '')) {
        const syntheticParents = parentsOf(head);
        if (syntheticParents.length !== 2 || syntheticParents[0] !== AUTHORITY_MERGE) {
          problems.push('synthetic R1 PR merge is not an exact direct base/Candidate merge');
        }
        candidate = syntheticParents[1] ?? null;
        phase = 'CANDIDATE_PR_CHECK';
      } else if (!/\/head$/.test(ref || '')) {
        problems.push('R1 pull_request ref is neither a head nor synthetic merge ref');
      }
    }
    if (head === AUTHORITY_MERGE) {
      if (!same(changed, STAGE_PATHS)) problems.push(`active R1 worktree path set drifted: ${JSON.stringify(changed)}`);
    } else if (candidate) {
      candidateTree = gitOut(repo, ['rev-parse', `${candidate}^{tree}`]);
      const candidateCommitsOutput = gitOut(repo, ['rev-list', '--reverse', `${AUTHORITY_MERGE}..${candidate}`]);
      const candidateCommits = candidateCommitsOutput ? candidateCommitsOutput.split('\n').filter(Boolean) : [];
      const candidateCount = candidateCommits.length;
      const candidateRootParent = candidateCommits[0] ? parentsOf(candidateCommits[0])[0] : null;
      const candidateMerges = gitOut(repo, ['rev-list', '--merges', `${AUTHORITY_MERGE}..${candidate}`]);
      const containsSuperseded = git(repo, ['merge-base', '--is-ancestor', SUPERSEDED_CANDIDATE, candidate], { check: false }).status === 0;
      topology = {
        taskId: REVISION_TASK_ID,
        lifecycleClass: 'CANDIDATE',
        closedBeforeCommit: false,
        candidate: {
          commit: candidate, tree: candidateTree, parent: candidateRootParent,
          ordinaryCommitCount: candidateCount, containsMerge: Boolean(candidateMerges),
          containsSupersededCandidate: containsSuperseded,
          priorAttemptCommit: candidateCommits[0] ?? null,
          priorAttemptTree: candidateCommits[0] ? gitOut(repo, ['rev-parse', `${candidateCommits[0]}^{tree}`]) : null,
          changedPaths: commitPaths(AUTHORITY_MERGE, candidate),
        },
        merge: null,
        successor: null,
      };
      const classified = classifyBootstrapTopology(topology);
      for (const problem of classified.problems) problems.push(problem);
      lifecycleClass = classified.classification;
      bootstrapEligible = classified.accepted;
    }
  } else {
    const firstParentMergesOutput = gitOut(repo, ['rev-list', '--first-parent', '--merges', '--reverse', `${AUTHORITY_MERGE}..HEAD`]);
    const firstParentMerges = firstParentMergesOutput ? firstParentMergesOutput.split('\n').filter(Boolean) : [];
    amendmentMerge = firstParentMerges[0] ?? null;
    if (!amendmentMerge) {
      problems.push('checkout is neither the exact R1 branch nor a successor of its accepted merge');
    } else {
      const mergeParents = parentsOf(amendmentMerge);
      candidate = mergeParents[1] ?? null;
      candidateTree = candidate ? gitOut(repo, ['rev-parse', `${candidate}^{tree}`]) : null;
      amendmentMergeTree = gitOut(repo, ['rev-parse', `${amendmentMerge}^{tree}`]);
      const candidateCommitsOutput = candidate ? gitOut(repo, ['rev-list', '--reverse', `${AUTHORITY_MERGE}..${candidate}`]) : null;
      const candidateCommits = candidateCommitsOutput ? candidateCommitsOutput.split('\n').filter(Boolean) : [];
      const candidateCount = candidateCommits.length;
      const candidateRootParent = candidateCommits[0] ? parentsOf(candidateCommits[0])[0] : null;
      const candidateMerges = candidate ? gitOut(repo, ['rev-list', '--merges', `${AUTHORITY_MERGE}..${candidate}`]) : 'unknown';
      const containsSuperseded = candidate
        ? git(repo, ['merge-base', '--is-ancestor', SUPERSEDED_CANDIDATE, candidate], { check: false }).status === 0
        : true;
      const baseFacts = {
        taskId: REVISION_TASK_ID,
        closedBeforeCommit: false,
        candidate: {
          commit: candidate, tree: candidateTree, parent: candidateRootParent,
          ordinaryCommitCount: candidateCount, containsMerge: Boolean(candidateMerges),
          containsSupersededCandidate: containsSuperseded,
          priorAttemptCommit: candidateCommits[0] ?? null,
          priorAttemptTree: candidateCommits[0] ? gitOut(repo, ['rev-parse', `${candidateCommits[0]}^{tree}`]) : null,
          changedPaths: candidate ? commitPaths(AUTHORITY_MERGE, candidate) : [],
        },
        merge: {
          commit: amendmentMerge, parentCount: mergeParents.length,
          firstParent: mergeParents[0] ?? null, secondParent: mergeParents[1] ?? null,
          tree: amendmentMergeTree, candidateTree,
          candidateTreePreserved: amendmentMergeTree === candidateTree,
        },
      };

      if (head === amendmentMerge) {
        phase = 'LEGAL_MERGE';
        topology = { ...baseFacts, lifecycleClass: 'LEGAL_MERGE', successor: null };
        const classified = classifyBootstrapTopology(topology);
        for (const problem of classified.problems) problems.push(problem);
        lifecycleClass = classified.classification;
        bootstrapEligible = classified.accepted;
      } else {
        const successorsOutput = gitOut(repo, ['rev-list', '--first-parent', '--reverse', `${amendmentMerge}..HEAD`]);
        const successors = successorsOutput ? successorsOutput.split('\n').filter(Boolean) : [];
        const direct = successors[0] ?? null;
        const directParents = direct ? parentsOf(direct) : [];
        const directPaths = direct ? commitPaths(amendmentMerge, direct) : [];
        const priorCloseoutRecordPresent = gitBlob(repo, amendmentMerge, CLOSEOUT_PATH) != null;
        try {
          closeoutRecordCount = listRecordFiles(repo, CLOSEOUT_DIRECTORY).length;
        } catch (error) {
          problems.push(error.message);
        }
        const directIsCloseout = directParents.length === 1 && directParents[0] === amendmentMerge &&
          same(directPaths, [CLOSEOUT_PATH]) && gitBlob(repo, direct, CLOSEOUT_PATH) != null &&
          !priorCloseoutRecordPresent;
        if (successors.length === 1) {
          phase = 'BOOTSTRAP_CLOSEOUT_SUCCESSOR';
          topology = {
            ...baseFacts,
            lifecycleClass: 'BOOTSTRAP_CLOSEOUT_SUCCESSOR',
            successor: {
              depth: 1, parentCount: directParents.length, parent: directParents[0] ?? null,
              priorCloseoutRecordPresent, closeoutRecordCount,
              duplicateCloseout: closeoutRecordCount !== 1,
              changedPaths: directPaths,
              businessCodeChanged: directPaths.some((relative) => /^(?:internal|cmd|packages)\//.test(relative)),
              validatorRepairExecuted: directPaths.includes(ORIGINAL_AUTHORITY_VALIDATOR) || directPaths.includes(ORIGINAL_B001_VALIDATOR),
              b000ImplementationStarted: directPaths.some((relative) => /^(?:internal|cmd|packages)\//.test(relative)),
            },
          };
          const classified = classifyBootstrapTopology(topology);
          for (const problem of classified.problems) problems.push(problem);
          lifecycleClass = classified.classification;
          bootstrapEligible = classified.accepted;
        } else if (successors.length > 1 && directIsCloseout) {
          phase = 'BOOTSTRAP_EXPIRED';
          lifecycleClass = 'BOOTSTRAP_EXPIRED';
          bootstrapEligible = false;
        } else {
          problems.push('successor is unrelated, multi-hop before closeout, or has unknown topology');
        }
      }
    }
  }

  return {
    problems, phase, lifecycleClass, bootstrapEligible, topology,
    head, headTree, branch, changed, legacyExpectedChangedPaths,
    candidate, candidateTree, amendmentMerge, amendmentMergeTree,
    closeoutRecordCount,
  };
}

function executeLegacyValidator(repo, defectId, relative) {
  const cp = spawnSync(process.execPath, [relative], {
    cwd: repo,
    encoding: 'utf8',
    env: { ...process.env },
    maxBuffer: 16 * 1024 * 1024,
  });
  let report = null;
  if (defectId === 'F1' && (cp.stdout ?? '').trim() !== '') {
    try {
      report = JSON.parse(cp.stdout);
    } catch {
      report = null;
    }
  }
  return {
    defect_id: defectId,
    validator: relative,
    sha256: sha256(read(repo, relative)),
    executed: true,
    status: cp.status,
    signal: cp.signal,
    stdout: cp.stdout ?? '',
    stderr: cp.stderr ?? '',
    report,
    execution_context: {
      github_actions: process.env.GITHUB_ACTIONS === 'true',
      event_name: process.env.GITHUB_EVENT_NAME || null,
      ref: process.env.GITHUB_REF || null,
      head_ref: process.env.GITHUB_HEAD_REF || null,
    },
  };
}

function executeBootstrapLegacyValidators(repo) {
  return [
    executeLegacyValidator(repo, 'F1', ORIGINAL_AUTHORITY_VALIDATOR),
    executeLegacyValidator(repo, 'F2', ORIGINAL_B001_VALIDATOR),
  ];
}

export function run(ctx, args = {}) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push(`ok: ${message}`);
  const fail = (message) => { pass = false; details.push(`FAIL: ${message}`); };
  let amendment, artifactManifest, amendmentSchema, closeoutSchema, supersessionSchema, recoverySchema, baseManifestBytes;
  try {
    amendment = readJSON(ctx.repo, AMENDMENT_PATH);
    artifactManifest = readJSON(ctx.repo, ARTIFACT_PATH);
    amendmentSchema = readJSON(ctx.repo, AMENDMENT_SCHEMA_PATH);
    closeoutSchema = readJSON(ctx.repo, CLOSEOUT_SCHEMA_PATH);
    supersessionSchema = readJSON(ctx.repo, SUPERSESSION_SCHEMA_PATH);
    recoverySchema = readJSON(ctx.repo, RECOVERY_SCHEMA_PATH);
    baseManifestBytes = read(ctx.repo, BASE_MANIFEST_PATH);
  } catch (error) {
    return { result: 'FAIL', details: [`FAIL: Amendment input unreadable: ${error.message}`], negative_probes: 'NOT_RUN' };
  }

  for (const problem of schemaProblems(amendmentSchema, amendment, 'Amendment')) fail(problem);
  if (checkSchemaDocument(amendmentSchema).errors.length === 0) ok('Authority Amendment schema uses the supported fail-closed JSON Schema subset');
  for (const [label, schema] of [
    ['closeout evidence', closeoutSchema],
    ['supersession', supersessionSchema],
    ['recovery evidence', recoverySchema],
  ]) {
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
  let closeoutFiles = [];
  try {
    supersessionFiles = listRecordFiles(ctx.repo, SUPERSESSION_DIRECTORY);
    recoveryFiles = listRecordFiles(ctx.repo, RECOVERY_DIRECTORY);
    closeoutFiles = listRecordFiles(ctx.repo, CLOSEOUT_DIRECTORY);
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

  const closeoutExpected = ['BOOTSTRAP_CLOSEOUT_SUCCESSOR', 'BOOTSTRAP_EXPIRED'].includes(lifecycle.phase);
  if (closeoutExpected) {
    if (!same(closeoutFiles, [CLOSEOUT_PATH])) {
      fail('closeout record inventory is not the exact single frozen path');
    } else {
      let closeoutRecord = null;
      try {
        closeoutRecord = readJSON(ctx.repo, CLOSEOUT_PATH);
      } catch (error) {
        fail(`closeout record unreadable: ${error.message}`);
      }
      if (closeoutRecord) {
        const closeoutProblems = validateCloseoutRecord(closeoutRecord, closeoutSchema, lifecycle);
        for (const problem of closeoutProblems) fail(problem);
        if (closeoutProblems.length === 0) ok('single-use closeout record binds exact Candidate, merge, CI and CLOSED transition evidence');
      }
    }
  } else if (closeoutFiles.length !== 0) {
    fail('closeout record exists before the direct bootstrap closeout successor');
  } else {
    ok('no premature Amendment closeout record exists');
  }

  const placeholderTargets = [
    HUMAN_PATH, AMENDMENT_PATH, AMENDMENT_SCHEMA_PATH, CLOSEOUT_SCHEMA_PATH,
    SUPERSESSION_SCHEMA_PATH, RECOVERY_SCHEMA_PATH,
  ];
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
    ['candidate CI bootstrap classification', workflow.includes(`node ${VALIDATOR_PATH} --ci-bootstrap-classify --github-output "\${GITHUB_OUTPUT}"`)],
    ['legacy F1/F2 execution', text(ctx.repo, VALIDATOR_PATH).includes("executeLegacyValidator(repo, 'F1'") && text(ctx.repo, VALIDATOR_PATH).includes("executeLegacyValidator(repo, 'F2'")],
    ['authority index', index.includes('unregistered-aipt-p1-b000-authority-amendment-001.json') && index.includes('UNREGISTERED_AIPT_P1_B000_AUTHORITY_AMENDMENT_001.md')],
  ]) {
    if (condition) ok(`${label} wiring present`); else fail(`${label} wiring missing`);
  }
  const legacyCondition = "if: steps.authority_amendment_classify.outputs.applicable != 'true'";
  const routedLegacyCommands = [
    'pnpm run check:m0-development-pass',
    'pnpm run check:mvp-b001',
    'pnpm run check:mvp-bootstrap',
    'pnpm run check:p1-b000-authority',
    'pnpm run check',
  ];
  for (const command of routedLegacyCommands) {
    const escaped = command.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const pattern = new RegExp(`${legacyCondition.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\n\\s+run: ${escaped}`);
    if (!pattern.test(workflow)) fail(`candidate CI legacy-stage condition missing for ${command}`);
  }
  if (!workflow.includes("if: steps.authority_amendment_classify.outputs.applicable == 'true'\n        run: pnpm run check:p1-b000-authority-amendment") ||
      workflow.includes('continue-on-error:') || workflow.includes('if node scripts/ci/validate/p1-b000-authority-amendment.mjs')) {
    fail('candidate CI executed-fingerprint gate is missing, conditional binding drifted, or failure masking is present');
  } else ok('candidate CI executes raw F1/F2, verifies exact fingerprints and never masks failure');

  const probes = negativeProbeResults(amendment, supersessionSchema, recoverySchema, baseManifestBytes);
  for (let index = 0; index < probes.length; index += 1) {
    const [expectedID, label] = NEGATIVE_CASES[index];
    const probe = probes[index];
    if (probe.id !== expectedID || !probe.rejected) fail(`${expectedID} ${label} was not rejected`);
  }
  const rejectedCount = probes.filter((probe, index) => probe.id === NEGATIVE_CASES[index][0] && probe.rejected).length;
  if (rejectedCount === NEGATIVE_CASES.length) ok('all A01-A20 Amendment, supersession and recovery mutations reject');

  const revisionProbes = revisionNegativeProbeResults(closeoutSchema);
  for (let index = 0; index < revisionProbes.length; index += 1) {
    const [expectedID, label] = REVISION_NEGATIVE_CASES[index];
    const probe = revisionProbes[index];
    if (probe.id !== expectedID || !probe.matched) fail(`${expectedID} ${label} regression did not match`);
  }
  const revisionMatchedCount = revisionProbes.filter((probe, index) =>
    probe.id === REVISION_NEGATIVE_CASES[index][0] && probe.matched).length;
  if (revisionMatchedCount === REVISION_NEGATIVE_CASES.length) {
    ok('all R01-R20 closeout topology, fingerprint, scope, CI, expiry and repair-task probes matched');
  }

  const amendmentSpecificPass = pass;
  let bootstrapApplicable = false;
  let legacyObservations = [];
  let bootstrapDecision = null;
  if (args['ci-bootstrap-classify'] === true) {
    if (lifecycle.bootstrapEligible && lifecycle.topology) {
      legacyObservations = executeBootstrapLegacyValidators(ctx.repo);
      bootstrapDecision = classifyBootstrapDecision({
        topology: lifecycle.topology,
        observations: legacyObservations,
        expectedChangedPaths: lifecycle.legacyExpectedChangedPaths,
        amendmentValidator: amendmentSpecificPass ? 'PASS' : 'FAIL',
        b001BusinessRegression: b001Problems.length === 0 ? 'PASS' : 'FAIL',
        realCiUnrelatedFailure: false,
      });
      for (const problem of bootstrapDecision.problems) fail(`bootstrap classifier: ${problem}`);
      bootstrapApplicable = bootstrapDecision.accepted && amendmentSpecificPass;
      if (bootstrapApplicable) ok('raw F1/F2 executions match only the exact frozen known-defect fingerprints');
    } else if (lifecycle.phase === 'BOOTSTRAP_EXPIRED' && amendmentSpecificPass) {
      bootstrapApplicable = false;
      ok('Amendment is CLOSED; bootstrap permission expired and normal gates are required');
    } else {
      fail('checkout is not an exact validated R1 Candidate, legal merge or direct governance closeout successor');
    }
  }

  const candidateTopology = syntheticBootstrapTopology();
  candidateTopology.lifecycleClass = 'CANDIDATE';
  candidateTopology.merge = null;
  candidateTopology.successor = null;
  const legalMergeTopology = syntheticBootstrapTopology();
  legalMergeTopology.lifecycleClass = 'LEGAL_MERGE';
  legalMergeTopology.successor = null;
  const bootstrapModel = {
    candidate_classifier: classifyBootstrapTopology(candidateTopology).accepted ? 'PASS' : 'FAIL',
    legal_merge_classifier: classifyBootstrapTopology(legalMergeTopology).accepted ? 'PASS' : 'FAIL',
    governance_closeout_successor_classifier: classifyBootstrapTopology(syntheticBootstrapTopology()).accepted ? 'PASS' : 'FAIL',
    unrelated_successor: revisionProbes.find((probe) => probe.id === 'R07')?.matched ? 'REJECTED' : 'FAIL',
    multi_hop_successor: revisionProbes.find((probe) => probe.id === 'R06')?.matched ? 'REJECTED' : 'FAIL',
    repair_task_bootstrap_use: revisionProbes.find((probe) => probe.id === 'R20')?.matched ? 'REJECTED' : 'FAIL',
    expires_after_closeout: revisionProbes.find((probe) => probe.id === 'R19')?.matched === true,
  };

  if (args['github-output'] != null) {
    if (typeof args['github-output'] !== 'string' || args['github-output'] !== process.env.GITHUB_OUTPUT) {
      fail('--github-output must equal the exact GitHub-provided GITHUB_OUTPUT path');
    } else {
      fs.appendFileSync(args['github-output'], `applicable=${bootstrapApplicable ? 'true' : 'false'}\n`, { encoding: 'utf8' });
    }
  }
  return {
    result: pass ? 'PASS' : 'FAIL',
    details,
    task_id: TASK_ID,
    revision_task_id: REVISION_TASK_ID,
    authority_task_id: AUTHORITY_TASK_ID,
    authority_candidate_commit: AUTHORITY_CANDIDATE,
    authority_merge_commit: AUTHORITY_MERGE,
    authority_merge_tree: AUTHORITY_TREE,
    lifecycle_phase: lifecycle.phase,
    lifecycle_class: lifecycle.lifecycleClass,
    candidate_commit: ['CANDIDATE', 'CANDIDATE_PR_CHECK'].includes(lifecycle.phase) ? lifecycle.candidate : null,
    candidate_tree: ['CANDIDATE', 'CANDIDATE_PR_CHECK'].includes(lifecycle.phase) ? lifecycle.candidateTree : null,
    changed_paths: lifecycle.changed,
    amendment_validator: amendmentSpecificPass ? 'PASS' : 'FAIL',
    negative_probes: rejectedCount === NEGATIVE_CASES.length ? 'PASS' : 'FAIL',
    negative_probe_count: probes.length,
    revision_negative_probes: revisionMatchedCount === REVISION_NEGATIVE_CASES.length ? 'PASS' : 'FAIL',
    revision_negative_probe_count: revisionProbes.length,
    closeout_successor_bootstrap_classifier: revisionProbes.find((probe) => probe.id === 'R01')?.matched ? 'PASS' : 'FAIL',
    bootstrap_model: bootstrapModel,
    b001_regression: b001Problems.length === 0 ? 'PASS' : 'FAIL',
    original_validator_unchanged: sha256(read(ctx.repo, ORIGINAL_AUTHORITY_VALIDATOR)) === ORIGINAL_AUTHORITY_VALIDATOR_SHA,
    original_merge_check_run: 'ABSENT',
    historical_merge_ci_claimed_pass: false,
    supersession_record_count: supersessions.length,
    recovery_evidence_count: recoveryEvidence.length,
    closeout_record_count: closeoutFiles.length,
    unresolved_placeholders: placeholderTargets.filter((relative) => placeholder.test(text(ctx.repo, relative))).length,
    bootstrap_ci_applicable: bootstrapApplicable,
    legacy_validators: legacyObservations.map((observation, index) => ({
      defect_id: observation.defect_id,
      validator: observation.validator,
      sha256: observation.sha256,
      executed: observation.executed,
      raw_result: observation.status === 0 ? 'PASS' : 'FAIL',
      status: observation.status,
      signal: observation.signal,
      execution_context: observation.execution_context,
      classification: bootstrapDecision?.legacy?.[index]?.classification ?? 'NOT_CLASSIFIED',
      fingerprint_problems: bootstrapDecision?.legacy?.[index]?.problems ?? [],
      raw_stdout: observation.stdout,
      raw_stderr: observation.stderr,
    })),
    business_code_changed: false,
    repair_started: false,
    b000_implementation_started: false,
    merge_authorized: false,
  };
}

runAsMain(import.meta.url, 'p1-b000-authority-amendment', run);
