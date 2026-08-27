#!/usr/bin/env node
// UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-002 validator.
//
// Static mode validates the append-only Authority, schemas, inventory,
// evidence, lifecycle/scope and all mutation probes. With an exact detached
// predecessor checkout it additionally regenerates the inventory from Git and
// executes all four historical P0 gates. With a candidate checkout it also
// performs the preservation and controlled-delta comparison and executes the
// candidate P1 validator. Standard-library only; no network access.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { git, runAsMain } from '../lib/cli.mjs';
import { checkSchemaDocument, validateInstance } from '../lib/json-schema.mjs';
import { generateInventory } from '../generate/p1-b000-amendment-002-inventory.mjs';

const TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-002';
const AUTHORITY_TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-001';
const IMPLEMENTATION_TASK_ID = 'UNREGISTERED-AIPT-P1-B000';
const BRANCH = `task/${TASK_ID}`;
const BASE_COMMIT = '8d6a438d051fb635e769285215e70536958a8f42';
const BASE_TREE = '9ef6f121bd0d9a6484d7cc39a22450250e9ac489';
const PREDECESSOR_REPOSITORY = 'zyc14588/UNREGISTERED';
const PREDECESSOR_COMMIT = '358d6d9d08a86818e34fd0c0d9a62bfe66e73abe';
const PREDECESSOR_TREE = '5585271c78d1fe5cd8357c7b36a501bee34f0240';
const INVENTORY_PROJECTION_SHA = '55480de50eb218163db4d2bcb20b8c64ce0bc44858c6a4fa722e1a37ca6751ac';

const HUMAN_PATH = 'docs/authority/amendments/UNREGISTERED_AIPT_P1_B000_AUTHORITY_AMENDMENT_002.md';
const AMENDMENT_PATH = 'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-002.json';
const ARTIFACT_PATH = 'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-002-artifacts.json';
const INVENTORY_PATH = 'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-002-p0-inventory.json';
const PREDECESSOR_EVIDENCE_PATH = 'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-002-predecessor-evidence.json';
const AMENDMENT_SCHEMA_PATH = 'schemas/authority-amendment/v2/aipt-authority-acceptance-semantics-amendment.schema.json';
const ACCEPTANCE_EVIDENCE_SCHEMA_PATH = 'schemas/authority-amendment/v2/aipt-predecessor-successor-acceptance-evidence.schema.json';
const GENERATOR_PATH = 'scripts/ci/generate/p1-b000-amendment-002-inventory.mjs';
const VALIDATOR_PATH = 'scripts/ci/validate/p1-b000-authority-amendment-002.mjs';

const AUTHORITY_VALIDATOR_PATH = 'scripts/ci/validate/p1-b000-authority.mjs';
const AUTHORITY_VALIDATOR_SHA = 'c6f0c8e01397200ce15f48bf1fc2412d9db477dddc37d3f99e0478d26956dd0c';
const B001_VALIDATOR_PATH = 'scripts/ci/validate/mvp-b001.mjs';
const B001_VALIDATOR_SHA = '319c8d4a3466c20d14e2d5fc74cc246c9b796d36f884fcc39e2b0a25317351c4';
const REPAIR_VALIDATOR_PATH = 'scripts/ci/validate/p1-b000-authority-repair.mjs';
const REPAIR_VALIDATOR_SHA = '84110c276d92d509419c163a889183216e659dda14f9e55f4c343e6674676da0';
const CLOSEOUT_VALIDATOR_PATH = 'scripts/ci/validate/p1-b000-authority-closeout.mjs';
const CLOSEOUT_VALIDATOR_SHA = '081444ba84da6621f2586f2c8f539b16fea70d122cc5fcc414fdb4705739a8b0';
const STANDALONE_VALIDATOR_PATH = 'scripts/ci/validate/standalone-entrypoints.mjs';
const STANDALONE_VALIDATOR_SHA = '1e8def961e583ff0cd6ac2ff3bdfe8f034709972e5033b35b4e4a6b9cae8877d';
const POST_MERGE_REVERIFICATION_VALIDATOR_PATH = 'scripts/ci/validate/p1-b000-post-merge-reverification.mjs';
const POST_MERGE_REVERIFICATION_VALIDATOR_SHA = 'a021a7a30c0c45782e22fe96c59888ad227c66ab4ca855ee119400bbbdec2367';
const PACKAGE_SCHEMA_PATH = 'schemas/playtest-package/v1/aipt-playtest-package.schema.json';
const PACKAGE_SCHEMA_SHA = '88e55b63c8a6366c872edf0d886202a5c375e224c801433364332ddc4e4e7549';
const ADAPTER_SCHEMA_PATH = 'schemas/runtime-adapter-input/v1/aipt-runtime-adapter-input.schema.json';
const ADAPTER_SCHEMA_SHA = '935b88f2409e604d01a13657a7790dae16e19ebe0c4e96f054c580102ec17413';
const MIGRATION_PATH = 'internal/storage/postgres/migrations/000002_playtest_queue.sql';
const MIGRATION_SHA = '47f02a5a2129473caa0db5e359a0b294a01b2a96329d9f6fa08ac87cc429c997';

const P0_GATES = Object.freeze([
  Object.freeze({ gate_id: 'P0-B000', path: 'scripts/aipt/validate-p0-b000.mjs', sha256: 'bf27739727b86a4c174ea52da54fb17e741d7c7e95062ccbe1cf16da96ecb7d2', stdout_sha256: 'd9da5176b674e5692d1a58c1ce5a9da8b88f054a2174bcc861fd8a9b574053b5' }),
  Object.freeze({ gate_id: 'P0-B001', path: 'scripts/aipt/validate-p0-b001.mjs', sha256: 'd464034da401d1056b42d9910bd87d85adf6d9f6a39df44be81e6dc0b5b1bb71', stdout_sha256: '93f4207ade1cdff1d588221cabe91cc27d01624fc55b413cf1a538caf9e569c0' }),
  Object.freeze({ gate_id: 'P0-B002', path: 'scripts/aipt/validate-p0-b002.mjs', sha256: 'd1508d6449f4436064ac567dc9f58050837fab9e4f051512985f26358faa82b5', stdout_sha256: 'a33c4287d56dec764d965a8c3158a128c88f1f72bb0d65268192e51ce257630b' }),
  Object.freeze({ gate_id: 'P0-B003', path: 'scripts/aipt/validate-p0-b003.mjs', sha256: 'ef08ce52d27b33dfb00152c2d29dc9056a0b09fdadeafcc2dd9f1d1c59ddfe45', stdout_sha256: 'ef8122ad216d39389b5ce50c7451342cb7e9520fd0ec265dd01bad662adc9102' }),
]);
const EMPTY_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const CLOSED_GOVERNANCE_GATES = Object.freeze({
  repair: Object.freeze({
    name: 'p1-b000-authority-repair',
    path: REPAIR_VALIDATOR_PATH,
  }),
  closeout: Object.freeze({
    name: 'p1-b000-authority-closeout',
    path: CLOSEOUT_VALIDATOR_PATH,
  }),
  reverification: Object.freeze({
    name: 'p1-b000-post-merge-reverification',
    path: POST_MERGE_REVERIFICATION_VALIDATOR_PATH,
    sha256: POST_MERGE_REVERIFICATION_VALIDATOR_SHA,
    args: Object.freeze([
      '--target-sha',
      '169f9bd006dabb88eb653ab09a33b0eef5eadaed',
      '--expected-tree',
      '9cf551e7bc70d4354ca21d62a2bd456ed6f401bb',
    ]),
    report_schema: 'aipt.public.post-merge-reverification-candidate-run/v1',
    report_task_id: 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001',
  }),
});

const ALLOWED_ADDITIONS = Object.freeze([
  'aipt/p1-b000/compatibility-evidence.json',
  'aipt/p1-b000/playtest-package.json',
  'aipt/p1-b000/runtime-adapter-input.json',
  'scripts/aipt/validate-p1-b000.mjs',
]);
const ALLOWED_MODIFICATIONS = Object.freeze([
  '.github/workflows/aipt-content-gate.yml',
  'aipt/README.md',
  'aipt/status.json',
]);
const ALLOWED_CHANGED_PATHS = Object.freeze([
  ...ALLOWED_MODIFICATIONS,
  ...ALLOWED_ADDITIONS,
].sort(byteCompare));

const STAGE_PATHS = Object.freeze([
  '.github/workflows/ci.yml',
  'docs/authority/README.md',
  HUMAN_PATH,
  ARTIFACT_PATH,
  INVENTORY_PATH,
  PREDECESSOR_EVIDENCE_PATH,
  AMENDMENT_PATH,
  'package.json',
  AMENDMENT_SCHEMA_PATH,
  ACCEPTANCE_EVIDENCE_SCHEMA_PATH,
  GENERATOR_PATH,
  'scripts/ci/run-checks.mjs',
  VALIDATOR_PATH,
].sort(byteCompare));

const ARTIFACT_PATHS = Object.freeze([
  HUMAN_PATH,
  AMENDMENT_PATH,
  INVENTORY_PATH,
  PREDECESSOR_EVIDENCE_PATH,
  AMENDMENT_SCHEMA_PATH,
  ACCEPTANCE_EVIDENCE_SCHEMA_PATH,
  GENERATOR_PATH,
  VALIDATOR_PATH,
]);
const ARTIFACT_ROLES = Object.freeze([
  'HUMAN_READABLE_AUTHORITY_AMENDMENT',
  'MACHINE_EXECUTION_AUTHORITY_AMENDMENT',
  'P0_PREDECESSOR_PROTECTED_INVENTORY',
  'PREDECESSOR_VALIDATION_AND_CONTRADICTION_EVIDENCE',
  'ACCEPTANCE_SEMANTICS_AMENDMENT_SCHEMA',
  'PREDECESSOR_SUCCESSOR_ACCEPTANCE_EVIDENCE_SCHEMA',
  'P0_INVENTORY_GENERATOR',
  'AUTHORITY_AMENDMENT_002_VALIDATOR',
]);

const FROZEN_AIPT_HASHES = Object.freeze({
  'docs/authority/UNREGISTERED_AIPT_P1_B000_AUTHORITY.md': '787e1a1a278905d69cd9e000badec8c4143060dcb136e4b0da3d2fb7a12c3ede',
  'docs/authority/registry/unregistered-aipt-p1-b000-authority.json': 'a9845bb74dac409ee243b7024e23aae271ab13c75e18116ae2513853cc02eed6',
  'docs/authority/registry/unregistered-aipt-p1-b000-authority-artifacts.json': '3e7d5ee752ac01ae4034fdaf2ec71231bb4f58eca9174e99619d0a13b200cd4f',
  'docs/authority/amendments/UNREGISTERED_AIPT_P1_B000_AUTHORITY_AMENDMENT_001.md': 'd735eebb7bbd089a8c4910ce2fcaa79f2592e4137db92a119475c34cf7937afc',
  'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-001.json': 'dce73114f73e2e82cafd37519411116b6af739fc8ba9a862ebdb0691c8cc1130',
  'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-001-artifacts.json': '26bdcbaa09042f68221455924ba135226c9fdb0f765375cd60d0100e8d212a2e',
  [PACKAGE_SCHEMA_PATH]: PACKAGE_SCHEMA_SHA,
  [ADAPTER_SCHEMA_PATH]: ADAPTER_SCHEMA_SHA,
  [AUTHORITY_VALIDATOR_PATH]: AUTHORITY_VALIDATOR_SHA,
  [B001_VALIDATOR_PATH]: B001_VALIDATOR_SHA,
  [REPAIR_VALIDATOR_PATH]: REPAIR_VALIDATOR_SHA,
  [CLOSEOUT_VALIDATOR_PATH]: CLOSEOUT_VALIDATOR_SHA,
  [STANDALONE_VALIDATOR_PATH]: STANDALONE_VALIDATOR_SHA,
  [MIGRATION_PATH]: MIGRATION_SHA,
});

const REQUIRED_PROBES = Object.freeze([
  ['A2-N01', 'ACCEPT'], ['A2-N02', 'REJECT'], ['A2-N03', 'REJECT'], ['A2-N04', 'REJECT'],
  ['A2-N05', 'ACCEPT'], ['A2-N06', 'REJECT'], ['A2-N07', 'REJECT'], ['A2-N08', 'REJECT'],
  ['A2-N09', 'ACCEPT'], ['A2-N10', 'REJECT'], ['A2-N11', 'REJECT'], ['A2-N12', 'REJECT'],
  ['A2-N13', 'REJECT'], ['A2-N14', 'REJECT'], ['A2-N15', 'ACCEPT'], ['A2-N16', 'ACCEPT'],
  ['A2-N17', 'REJECT'], ['A2-N18', 'REJECT'], ['A2-N19', 'REJECT'], ['A2-N20', 'REJECT'],
  ['A2-N21', 'REJECT'], ['A2-N22', 'REJECT'], ['A2-N23', 'REJECT'], ['A2-N24', 'REJECT'],
  ['A2-N25', 'REJECT'], ['A2-N26', 'REJECT'], ['A2-N27', 'REJECT'], ['A2-N28', 'REJECT'],
  ['A2-N29', 'REJECT'], ['A2-N30', 'REJECT'],
]);
const SECURITY_PROBES = Object.freeze([
  ['A2-S01', 'REJECT'], ['A2-S02', 'REJECT'], ['A2-S03', 'REJECT'],
  ['A2-S04', 'REJECT'], ['A2-S05', 'REJECT'], ['A2-S06', 'REJECT'],
]);

function byteCompare(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

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

function same(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sorted(values) {
  return [...values].sort(byteCompare);
}

function sameSet(left, right) {
  return same(sorted(new Set(left)), sorted(new Set(right)));
}

function gitCall(repo, args, encoding = 'utf8') {
  const result = spawnSync('git', ['-C', repo, ...args], {
    encoding,
    maxBuffer: 64 * 1024 * 1024,
  });
  return result;
}

function gitOutput(repo, args) {
  const result = gitCall(repo, args);
  if (result.error || result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${result.error?.message ?? String(result.stderr ?? '').trim()}`);
  }
  return result.stdout.trim();
}

function schemaProblems(schema, instance, label) {
  const problems = [];
  for (const error of checkSchemaDocument(schema).errors) problems.push(`${label} schema: ${error}`);
  for (const error of validateInstance(schema, instance).errors) problems.push(`${label} instance: ${error.message}`);
  return problems;
}

function validateCanonicalPaths(entries) {
  const problems = [];
  const exact = new Set();
  const collision = new Map();
  for (const entry of entries) {
    const relative = entry?.path;
    if (typeof relative !== 'string' || relative.length === 0 || relative.startsWith('/') || relative.includes('\\') || relative.includes('\0')) {
      problems.push(`invalid repository-relative POSIX path: ${JSON.stringify(relative)}`);
      continue;
    }
    const segments = relative.split('/');
    if (segments.some((segment) => segment === '' || segment === '.' || segment === '..')) {
      problems.push(`non-canonical path segment: ${relative}`);
    }
    if (relative.normalize('NFC') !== relative) problems.push(`path is not Unicode NFC: ${relative}`);
    if (exact.has(relative)) problems.push(`duplicate canonical path: ${relative}`);
    exact.add(relative);
    const key = relative.normalize('NFC').toLocaleLowerCase('en-US');
    if (collision.has(key) && collision.get(key) !== relative) {
      problems.push(`case-folding or Unicode collision: ${collision.get(key)} vs ${relative}`);
    }
    collision.set(key, relative);
    if (entry.type !== 'blob' || !['100644', '100755'].includes(entry.mode)) {
      problems.push(`symlink, submodule, non-blob or unsupported mode: ${relative} (${entry.mode} ${entry.type})`);
    }
    if (!/^[0-9a-f]{40}$/u.test(entry.object ?? '')) problems.push(`invalid Git blob identity: ${relative}`);
  }
  return problems;
}

function inventoryAsTreeEntries(inventory) {
  return inventory.entries.map((entry) => ({
    path: entry.path,
    mode: entry.mode,
    type: 'blob',
    object: entry.git_blob_sha1,
  }));
}

export function analyzeCandidateDelta(inventory, candidateEntries) {
  const securityProblems = validateCanonicalPaths(candidateEntries);
  const candidate = new Map(candidateEntries.map((entry) => [entry.path, entry]));
  const predecessor = new Map(inventory.entries.map((entry) => [entry.path, entry]));
  const observedAdditions = [];
  const observedModifications = [];
  const observedDeletions = [];
  const unexpectedAdditions = [];
  const unexpectedModifications = [];
  const unexpectedDeletions = [];
  const protectedModifications = [];
  const protectedDeletions = [];
  const renames = [];
  const identityMismatches = [];

  for (const original of inventory.entries) {
    const current = candidate.get(original.path);
    if (!current) {
      observedDeletions.push(original.path);
      unexpectedDeletions.push(original.path);
      if (original.protection === 'PRESERVE_EXACT') protectedDeletions.push(original.path);
      continue;
    }
    if (current.type !== 'blob' || current.mode !== original.mode) {
      observedModifications.push(original.path);
      unexpectedModifications.push(original.path);
      identityMismatches.push(original.path);
      if (original.protection === 'PRESERVE_EXACT') protectedModifications.push(original.path);
      continue;
    }
    if (current.object === original.git_blob_sha1) continue;
    observedModifications.push(original.path);
    if (original.protection === 'PRESERVE_EXACT') {
      protectedModifications.push(original.path);
      unexpectedModifications.push(original.path);
      identityMismatches.push(original.path);
    } else if (!ALLOWED_MODIFICATIONS.includes(original.path)) {
      unexpectedModifications.push(original.path);
    }
  }

  for (const current of candidateEntries) {
    if (predecessor.has(current.path)) continue;
    observedAdditions.push(current.path);
    const validAddition = ALLOWED_ADDITIONS.includes(current.path) && current.type === 'blob' && current.mode === '100644';
    if (!validAddition) unexpectedAdditions.push(current.path);
  }

  for (const deletedPath of protectedDeletions) {
    const original = predecessor.get(deletedPath);
    for (const addedPath of observedAdditions) {
      if (candidate.get(addedPath)?.object === original.git_blob_sha1) renames.push(`${deletedPath} -> ${addedPath}`);
    }
  }

  const uniqSorted = (values) => sorted(new Set(values));
  const preservationProblems = uniqSorted([
    ...protectedModifications.map((item) => `protected modification: ${item}`),
    ...protectedDeletions.map((item) => `protected deletion: ${item}`),
    ...renames.map((item) => `protected rename: ${item}`),
    ...identityMismatches.map((item) => `identity mismatch: ${item}`),
    ...securityProblems.map((item) => `path security: ${item}`),
  ]);
  const deltaProblems = uniqSorted([
    ...unexpectedAdditions.map((item) => `unexpected addition: ${item}`),
    ...unexpectedModifications.map((item) => `unexpected modification: ${item}`),
    ...unexpectedDeletions.map((item) => `unexpected deletion: ${item}`),
    ...securityProblems.map((item) => `path security: ${item}`),
  ]);

  return {
    p0_preservation: {
      result: preservationProblems.length === 0 ? 'PASS' : 'FAIL',
      problems: preservationProblems,
      protected_modifications: uniqSorted(protectedModifications),
      protected_deletions: uniqSorted(protectedDeletions),
      renames: uniqSorted(renames),
      identity_mismatches: uniqSorted(identityMismatches),
    },
    p1_delta: {
      result: deltaProblems.length === 0 ? 'PASS' : 'FAIL',
      problems: deltaProblems,
      allowed_additions: [...ALLOWED_ADDITIONS],
      allowed_modifications: [...ALLOWED_MODIFICATIONS],
      observed_additions: uniqSorted(observedAdditions),
      observed_modifications: uniqSorted(observedModifications),
      observed_deletions: uniqSorted(observedDeletions),
      unexpected_additions: uniqSorted(unexpectedAdditions),
      unexpected_modifications: uniqSorted(unexpectedModifications),
      unexpected_deletions: uniqSorted(unexpectedDeletions),
    },
    security_problems: uniqSorted(securityProblems),
  };
}

function validatePredecessorModel(model) {
  const problems = [];
  if (model.repository !== PREDECESSOR_REPOSITORY) problems.push('wrong predecessor repository');
  if (model.commit !== PREDECESSOR_COMMIT) problems.push('wrong predecessor commit');
  if (model.tree !== PREDECESSOR_TREE) problems.push('wrong predecessor tree');
  if (model.identity_kind !== 'IMMUTABLE_GIT_COMMIT_AND_TREE' || model.mutable_ref_substitution_permitted !== false) {
    problems.push('mutable predecessor identity is forbidden');
  }
  if (model.detached !== true) problems.push('predecessor checkout is not detached');
  if (model.clean !== true) problems.push('predecessor checkout is not clean');
  if (model.candidate_overlay !== false) problems.push('candidate overlay is present in predecessor checkout');
  if (model.node_version !== 'v24.19.0') problems.push('wrong predecessor Node runtime');
  if (!same(model.validator_identities, P0_GATES.map(({ gate_id, path: gatePath, sha256: digest }) => ({ gate_id, path: gatePath, sha256: digest })))) {
    problems.push('historical validator identity mismatch');
  }
  if (model.inventory_projection_sha256 !== INVENTORY_PROJECTION_SHA) problems.push('P0 inventory identity mismatch');
  if (model.p0_supersession_authorized !== false) problems.push('unauthorized P0 supersession');
  return problems;
}

function evaluateAcceptance(model) {
  const predecessorProblems = validatePredecessorModel(model.predecessor);
  if (predecessorProblems.length > 0 || !same(model.p0_gate_results, ['PASS', 'PASS', 'PASS', 'PASS'])) {
    return { result: 'FAIL', failure_code: 'FAIL_PREDECESSOR_P0_VALIDATION', problems: predecessorProblems };
  }
  if (model.historical_p0_on_candidate_required === true || model.p0_gates_skipped === true) {
    return { result: 'FAIL', failure_code: 'FAIL_PREDECESSOR_P0_VALIDATION', problems: ['invalid P0 execution model'] };
  }
  if (model.p0_preservation !== 'PASS') return { result: 'FAIL', failure_code: 'FAIL_P0_PRESERVATION', problems: [] };
  if (model.p1_delta !== 'PASS') return { result: 'FAIL', failure_code: 'FAIL_P1_DELTA_POLICY', problems: [] };
  if (model.p1_validation !== 'PASS') return { result: 'FAIL', failure_code: 'FAIL_P1_B000_VALIDATION', problems: [] };
  if (model.b001_compatibility !== 'PASS') return { result: 'FAIL', failure_code: 'FAIL_B001_REGRESSION', problems: [] };
  return { result: 'PASS', failure_code: null, problems: [] };
}

function validPredecessorModel() {
  return {
    repository: PREDECESSOR_REPOSITORY,
    commit: PREDECESSOR_COMMIT,
    tree: PREDECESSOR_TREE,
    identity_kind: 'IMMUTABLE_GIT_COMMIT_AND_TREE',
    mutable_ref_substitution_permitted: false,
    detached: true,
    clean: true,
    candidate_overlay: false,
    node_version: 'v24.19.0',
    validator_identities: P0_GATES.map(({ gate_id, path: gatePath, sha256: digest }) => ({ gate_id, path: gatePath, sha256: digest })),
    inventory_projection_sha256: INVENTORY_PROJECTION_SHA,
    p0_supersession_authorized: false,
  };
}

function validAcceptanceModel() {
  return {
    predecessor: validPredecessorModel(),
    p0_gate_results: ['PASS', 'PASS', 'PASS', 'PASS'],
    historical_p0_on_candidate_required: false,
    p0_gates_skipped: false,
    p0_preservation: 'PASS',
    p1_delta: 'PASS',
    p1_validation: 'PASS',
    b001_compatibility: 'PASS',
  };
}

function replaceEntry(entries, relative, mutation) {
  const output = clone(entries);
  const index = output.findIndex((entry) => entry.path === relative);
  if (index < 0) throw new Error(`test entry missing: ${relative}`);
  mutation(output[index]);
  return output;
}

function removeEntry(entries, relative) {
  return clone(entries).filter((entry) => entry.path !== relative);
}

function addEntry(entries, relative, object = 'a'.repeat(40), mode = '100644', type = 'blob') {
  return [...clone(entries), { path: relative, mode, type, object }];
}

function probeResults(inventory) {
  const baseEntries = inventoryAsTreeEntries(inventory);
  const sourcePath = 'campaign/00-campaign.md';
  const validatorPath = 'scripts/aipt/validate-p0-b003.mjs';
  const manifestPath = 'aipt/input-manifest.json';
  const results = [];
  const accept = (id, accepted) => results.push({ id, matched: accepted === true, observed: accepted ? 'ACCEPT' : 'REJECT' });
  const reject = (id, rejected) => results.push({ id, matched: rejected === true, observed: rejected ? 'REJECT' : 'ACCEPT' });

  accept('A2-N01', validatePredecessorModel(validPredecessorModel()).length === 0);
  { const value = validPredecessorModel(); value.commit = '0'.repeat(40); reject('A2-N02', validatePredecessorModel(value).length > 0); }
  { const value = validPredecessorModel(); value.tree = '0'.repeat(40); reject('A2-N03', validatePredecessorModel(value).length > 0); }
  { const value = validPredecessorModel(); value.identity_kind = 'MUTABLE_BRANCH'; value.mutable_ref_substitution_permitted = true; reject('A2-N04', validatePredecessorModel(value).length > 0); }
  accept('A2-N05', evaluateAcceptance(validAcceptanceModel()).result === 'PASS');
  { const value = validAcceptanceModel(); value.p0_gate_results[2] = 'FAIL'; reject('A2-N06', evaluateAcceptance(value).failure_code === 'FAIL_PREDECESSOR_P0_VALIDATION'); }
  { const value = validAcceptanceModel(); value.predecessor.candidate_overlay = true; reject('A2-N07', evaluateAcceptance(value).result === 'FAIL'); }
  { const value = validAcceptanceModel(); value.predecessor.clean = false; reject('A2-N08', evaluateAcceptance(value).result === 'FAIL'); }
  accept('A2-N09', analyzeCandidateDelta(inventory, baseEntries).p0_preservation.result === 'PASS');
  { const entries = replaceEntry(baseEntries, sourcePath, (entry) => { entry.object = '1'.repeat(40); }); reject('A2-N10', analyzeCandidateDelta(inventory, entries).p0_preservation.result === 'FAIL'); }
  { const entries = removeEntry(baseEntries, sourcePath); reject('A2-N11', analyzeCandidateDelta(inventory, entries).p0_preservation.result === 'FAIL'); }
  {
    const original = baseEntries.find((entry) => entry.path === sourcePath);
    const entries = addEntry(removeEntry(baseEntries, sourcePath), 'campaign/renamed-campaign.md', original.object);
    reject('A2-N12', analyzeCandidateDelta(inventory, entries).p0_preservation.renames.length > 0);
  }
  { const entries = replaceEntry(baseEntries, validatorPath, (entry) => { entry.object = '2'.repeat(40); }); reject('A2-N13', analyzeCandidateDelta(inventory, entries).p0_preservation.result === 'FAIL'); }
  { const entries = replaceEntry(baseEntries, manifestPath, (entry) => { entry.object = '3'.repeat(40); }); reject('A2-N14', analyzeCandidateDelta(inventory, entries).p0_preservation.result === 'FAIL'); }
  accept('A2-N15', analyzeCandidateDelta(inventory, addEntry(baseEntries, 'aipt/p1-b000/playtest-package.json')).p1_delta.result === 'PASS');
  accept('A2-N16', analyzeCandidateDelta(inventory, addEntry(baseEntries, 'scripts/aipt/validate-p1-b000.mjs')).p1_delta.result === 'PASS');
  reject('A2-N17', analyzeCandidateDelta(inventory, addEntry(baseEntries, 'unapproved.json')).p1_delta.result === 'FAIL');
  reject('A2-N18', analyzeCandidateDelta(inventory, removeEntry(baseEntries, 'README.md')).p1_delta.result === 'FAIL');
  { const entries = replaceEntry(baseEntries, 'README.md', (entry) => { entry.object = '4'.repeat(40); }); reject('A2-N19', analyzeCandidateDelta(inventory, entries).p1_delta.result === 'FAIL'); }
  { const value = validAcceptanceModel(); value.p0_preservation = 'FAIL'; reject('A2-N20', evaluateAcceptance(value).failure_code === 'FAIL_P0_PRESERVATION'); }
  { const value = validAcceptanceModel(); value.p1_delta = 'FAIL'; reject('A2-N21', evaluateAcceptance(value).failure_code === 'FAIL_P1_DELTA_POLICY'); }
  { const value = validAcceptanceModel(); value.p1_validation = 'FAIL'; reject('A2-N22', evaluateAcceptance(value).failure_code === 'FAIL_P1_B000_VALIDATION'); }
  { const value = validAcceptanceModel(); value.historical_p0_on_candidate_required = true; reject('A2-N23', evaluateAcceptance(value).result === 'FAIL'); }
  { const value = validAcceptanceModel(); value.p0_gate_results = []; value.p0_gates_skipped = true; reject('A2-N24', evaluateAcceptance(value).result === 'FAIL'); }
  { const value = validAcceptanceModel(); value.predecessor.repository = 'fake/UNREGISTERED'; reject('A2-N25', evaluateAcceptance(value).result === 'FAIL'); }
  { const value = validAcceptanceModel(); value.predecessor.validator_identities[3].sha256 = '0'.repeat(64); reject('A2-N26', evaluateAcceptance(value).result === 'FAIL'); }
  { const value = validAcceptanceModel(); value.predecessor.detached = false; reject('A2-N27', evaluateAcceptance(value).result === 'FAIL'); }
  { const value = validAcceptanceModel(); value.predecessor.inventory_projection_sha256 = '0'.repeat(64); reject('A2-N28', evaluateAcceptance(value).result === 'FAIL'); }
  { const value = validAcceptanceModel(); value.predecessor.p0_supersession_authorized = true; reject('A2-N29', evaluateAcceptance(value).result === 'FAIL'); }
  { const value = validAcceptanceModel(); value.b001_compatibility = 'FAIL'; reject('A2-N30', evaluateAcceptance(value).failure_code === 'FAIL_B001_REGRESSION'); }

  reject('A2-S01', analyzeCandidateDelta(inventory, addEntry(baseEntries, 'aipt/p1-b000/playtest-package.json', '5'.repeat(40), '120000', 'blob')).security_problems.length > 0);
  reject('A2-S02', analyzeCandidateDelta(inventory, addEntry(baseEntries, 'AIPT/README.md')).security_problems.length > 0);
  reject('A2-S03', analyzeCandidateDelta(inventory, addEntry(baseEntries, 'aipt/p1-b000/compatibility-e\u0301vidence.json')).security_problems.length > 0);
  reject('A2-S04', analyzeCandidateDelta(inventory, [...clone(baseEntries), clone(baseEntries[0])]).security_problems.length > 0);
  reject('A2-S05', analyzeCandidateDelta(inventory, addEntry(baseEntries, 'aipt/p1-b000/playtest-package.json', '6'.repeat(40), '160000', 'commit')).security_problems.length > 0);
  { const entries = replaceEntry(baseEntries, sourcePath, (entry) => { entry.object = '7'.repeat(40); }); reject('A2-S06', analyzeCandidateDelta(inventory, entries).p0_preservation.identity_mismatches.includes(sourcePath)); }
  return results;
}

function validateInventoryDocument(inventory) {
  const problems = [];
  if (inventory.schema !== 'aipt.public.p0-predecessor-protected-inventory/v1' || inventory.authority_task_id !== TASK_ID ||
      inventory.repository !== PREDECESSOR_REPOSITORY || inventory.predecessor_commit !== PREDECESSOR_COMMIT ||
      inventory.predecessor_tree !== PREDECESSOR_TREE) problems.push('inventory root identity drifted');
  if (!Array.isArray(inventory.entries) || inventory.entries.length !== 136) problems.push('inventory must contain exactly 136 predecessor entries');
  const paths = inventory.entries?.map((entry) => entry.path) ?? [];
  if (!same(paths, sorted(paths))) problems.push('inventory paths are not UTF-8 byte sorted');
  const controlled = inventory.entries?.filter((entry) => entry.protection === 'CONTROLLED_SUCCESSOR_MODIFICATION') ?? [];
  const preserved = inventory.entries?.filter((entry) => entry.protection === 'PRESERVE_EXACT') ?? [];
  if (!same(controlled.map((entry) => entry.path), ALLOWED_MODIFICATIONS) || controlled.length !== 3 || preserved.length !== 133) {
    problems.push('inventory protection classes or counts drifted');
  }
  if (inventory.counts?.tracked_entries !== 136 || inventory.counts?.preserve_exact !== 133 ||
      inventory.counts?.controlled_successor_modification !== 3 ||
      !same(inventory.controlled_successor_surfaces, ALLOWED_MODIFICATIONS)) problems.push('inventory count/control summary drifted');
  for (const entry of inventory.entries ?? []) {
    if (!/^[0-9a-f]{64}$/u.test(entry.sha256 ?? '') || !/^[0-9a-f]{40}$/u.test(entry.git_blob_sha1 ?? '') ||
        typeof entry.role !== 'string' || entry.role.length === 0 || !['100644', '100755'].includes(entry.mode) ||
        !['PRESERVE_EXACT', 'CONTROLLED_SUCCESSOR_MODIFICATION'].includes(entry.protection)) {
      problems.push(`invalid inventory entry: ${entry.path ?? 'unknown'}`);
    }
  }
  const pathProblems = validateCanonicalPaths(inventoryAsTreeEntries(inventory));
  problems.push(...pathProblems.map((problem) => `inventory ${problem}`));
  const projection = {
    repository: inventory.repository,
    predecessor_commit: inventory.predecessor_commit,
    predecessor_tree: inventory.predecessor_tree,
    entries: inventory.entries,
  };
  const projectionSha = sha256(Buffer.from(JSON.stringify(projection), 'utf8'));
  if (projectionSha !== INVENTORY_PROJECTION_SHA || inventory.inventory_identity?.sha256 !== INVENTORY_PROJECTION_SHA) {
    problems.push('inventory projection identity mismatch');
  }
  if (inventory.generation_contract?.candidate_declared_inventory_permitted !== false ||
      inventory.generation_contract?.source !== 'IMMUTABLE_GIT_COMMIT_TREE_ONLY' ||
      inventory.generation_contract?.symlink_submodule_or_non_blob !== 'REJECT') {
    problems.push('inventory generation contract drifted');
  }
  return problems;
}

function validateMachineAuthority(repo, amendment, inventory, predecessorEvidence) {
  const problems = [];
  if (amendment.amendment_id !== TASK_ID || amendment.authority_task_id !== AUTHORITY_TASK_ID || amendment.amendment_sequence !== 2 ||
      amendment.authority_state !== 'CANDIDATE_FROZEN') problems.push('Amendment root identity or state drifted');
  if (amendment.authority_task?.branch !== BRANCH || amendment.authority_task?.base_commit !== BASE_COMMIT ||
      amendment.authority_task?.base_tree !== BASE_TREE || amendment.authority_task?.implementation_candidate !== false ||
      amendment.authority_task?.business_code_changed !== false || amendment.authority_task?.merge_authorized !== false) {
    problems.push('Amendment task identity/scope drifted');
  }
  const candidateEnvironment = amendment.authority_task?.candidate_validation_environment;
  if (candidateEnvironment?.dependency_install !== 'PNPM_11_4_0_FROZEN_LOCKFILE' ||
      candidateEnvironment?.generated_dependency_path !== 'node_modules/' ||
      candidateEnvironment?.candidate_tree_membership_permitted !== false ||
      candidateEnvironment?.checkout_local_git_info_exclude_required !== true ||
      candidateEnvironment?.non_dependency_untracked_paths_permitted !== false) {
    problems.push('candidate validation dependency-environment boundary drifted');
  }
  const basis = amendment.authority_basis;
  if (basis?.base_authority?.accepted_closeout !== BASE_COMMIT || basis?.base_authority?.status !== 'CLOSED' ||
      basis?.accepted_amendments?.[0]?.closeout !== '2619339e53113633e02f3aef14156a1ff08c13f8' ||
      basis?.accepted_repairs?.[0]?.merge !== 'df71476d4b8f271f3b444cace46a3d6fbd1eaea4' ||
      basis?.effective_validator_identities?.authority_validator?.sha256 !== AUTHORITY_VALIDATOR_SHA ||
      basis?.effective_validator_identities?.b001_validator?.sha256 !== B001_VALIDATOR_SHA ||
      basis?.effective_validator_identities?.superseded_validator_restore_permitted !== false) {
    problems.push('accepted governance chain or effective validator identities drifted');
  }
  const regressionTargets = basis?.governance_regression_targets;
  if (!same(regressionTargets?.amendment_candidate_target?.validators, [
    AUTHORITY_VALIDATOR_PATH,
    B001_VALIDATOR_PATH,
    'scripts/ci/validate/p1-b000-authority-amendment.mjs',
    VALIDATOR_PATH,
  ]) || regressionTargets?.closed_historical_target?.commit !== BASE_COMMIT ||
      regressionTargets?.closed_historical_target?.tree !== BASE_TREE ||
      regressionTargets?.closed_historical_target?.current_candidate_github_execution_identity_inherited !== false ||
      regressionTargets?.closed_historical_target?.target_identity_source !== 'EXACT_DETACHED_TARGET_GIT_COMMIT_AND_TREE' ||
      !same(regressionTargets?.closed_historical_target?.validators, [
        REPAIR_VALIDATOR_PATH,
        CLOSEOUT_VALIDATOR_PATH,
      ]) || regressionTargets?.composite_aggregate_target?.entrypoint !== 'scripts/ci/run-checks.mjs' ||
      regressionTargets?.composite_aggregate_target?.current_candidate_checks !== true ||
      regressionTargets?.composite_aggregate_target?.closed_repair_and_closeout_subchecks_target_exact_base !== true ||
      regressionTargets?.composite_aggregate_target?.standalone_entrypoints_subcheck_target_exact_base !== true ||
      regressionTargets?.composite_aggregate_target?.closed_target_dependency_setup !== 'PNPM_11_4_0_OFFLINE_FROZEN_LOCKFILE_IGNORE_SCRIPTS' ||
      regressionTargets?.composite_aggregate_target?.target_identity_reported_per_subcheck !== true) {
    problems.push('candidate/historical governance regression target separation drifted');
  }
  const predecessor = amendment.predecessor_identity;
  if (predecessor?.repository !== PREDECESSOR_REPOSITORY || predecessor?.commit !== PREDECESSOR_COMMIT ||
      predecessor?.tree !== PREDECESSOR_TREE || predecessor?.identity_kind !== 'IMMUTABLE_GIT_COMMIT_AND_TREE' ||
      predecessor?.mutable_ref_substitution_permitted !== false) problems.push('predecessor identity is not exact and immutable');
  const gateProjection = amendment.predecessor_validation_contract?.gates?.map((gate) => ({
    gate_id: gate.gate_id, path: gate.path, sha256: gate.sha256,
  }));
  if (!same(gateProjection, P0_GATES.map(({ gate_id, path: gatePath, sha256: digest }) => ({ gate_id, path: gatePath, sha256: digest }))) ||
      amendment.predecessor_validation_contract?.all_gates_required !== true ||
      amendment.predecessor_validation_contract?.historical_p0_closed_set_run_on_p1_candidate_is_required_gate !== false ||
      amendment.predecessor_validation_contract?.p0_gates_may_be_skipped !== false) {
    problems.push('historical P0 invocation/identity contract drifted');
  }
  const declaredInventory = amendment.p0_preservation_contract?.inventory;
  if (declaredInventory?.path !== INVENTORY_PATH || declaredInventory?.projection_sha256 !== INVENTORY_PROJECTION_SHA ||
      declaredInventory?.artifact_sha256 !== sha256(read(repo, INVENTORY_PATH)) || declaredInventory?.preserve_exact_count !== 133 ||
      declaredInventory?.controlled_successor_surface_count !== 3 || declaredInventory?.candidate_declared_inventory_permitted !== false) {
    problems.push('P0 preservation inventory binding drifted');
  }
  if (amendment.p0_preservation_contract?.p0_validator_modification !== 'REJECT' ||
      amendment.p0_preservation_contract?.p0_manifest_modification !== 'REJECT' ||
      amendment.p0_preservation_contract?.protected_rename !== 'REJECT') problems.push('P0 preservation failure semantics drifted');
  const delta = amendment.p1_delta_contract;
  if (!same(delta?.allowed_additions, ALLOWED_ADDITIONS) || !same(delta?.allowed_controlled_modifications, ALLOWED_MODIFICATIONS) ||
      !same(delta?.allowed_changed_paths, ALLOWED_CHANGED_PATHS) || !same(delta?.allowed_deletions, []) ||
      delta?.default_policy !== 'DENY' || delta?.path_policy?.exact_paths_only !== true ||
      delta?.path_policy?.unbounded_aipt_glob !== false || delta?.path_policy?.unbounded_scripts_aipt_glob !== false ||
      delta?.path_policy?.symlink !== 'REJECT' || delta?.path_policy?.submodule !== 'REJECT') {
    problems.push('controlled P1 delta policy drifted');
  }
  const p1 = amendment.p1_candidate_validation_contract;
  if (p1?.validator_path !== 'scripts/aipt/validate-p1-b000.mjs' || p1?.playtest_package_schema?.sha256 !== PACKAGE_SCHEMA_SHA ||
      p1?.runtime_adapter_schema?.sha256 !== ADAPTER_SCHEMA_SHA || p1?.b001_protected_baseline?.migration_sha256 !== MIGRATION_SHA ||
      p1?.runtime_boundary?.run_core_implemented !== false || p1?.runtime_boundary?.agent_orchestration_implemented !== false ||
      p1?.runtime_boundary?.real_model_gateway_implemented !== false || p1?.runtime_boundary?.real_model_calls !== 0 ||
      p1?.runtime_boundary?.real_playtest_executed !== false) problems.push('P1/B001 contract or runtime boundary drifted');
  const formula = amendment.acceptance_formula;
  if (formula?.operator !== 'AND' || !same(formula?.ordered_gates?.map((item) => item.gate), [
    'P0_PREDECESSOR_IDENTITY', 'P0_GATES', 'P0_PRESERVATION', 'P1_ALLOWED_DELTA', 'P1_B000_VALIDATION', 'AIPT_B001_COMPATIBILITY',
  ]) || formula?.p0_validation_target_field !== 'predecessor_validation_target' ||
      formula?.p1_validation_target_field !== 'candidate_validation_target' || formula?.ambiguous_validation_target_field_permitted !== false) {
    problems.push('acceptance formula or distinct target binding drifted');
  }
  if (!same(amendment.negative_probes?.map((probe) => [probe.id, probe.expectation]), REQUIRED_PROBES) ||
      !same(amendment.additional_security_probes?.map((probe) => [probe.id, probe.expectation]), SECURITY_PROBES)) {
    problems.push('required negative/security probe inventory drifted');
  }
  if (amendment.acceptance_evidence_contract?.schema_path !== ACCEPTANCE_EVIDENCE_SCHEMA_PATH ||
      !same(amendment.acceptance_evidence_contract?.required_distinct_targets, ['predecessor_validation_target', 'candidate_validation_target'])) {
    problems.push('acceptance evidence target contract drifted');
  }
  const resolution = amendment.effective_authority_resolution;
  if (resolution?.current_effective_authority_unchanged_by_unaccepted_candidate !== true ||
      resolution?.prospective_change !== 'ACCEPTANCE_EXECUTION_SEMANTICS_ONLY' || resolution?.business_semantics_changed !== false ||
      resolution?.latest_file_wins !== false || resolution?.unaccepted_record_effective !== false || resolution?.conflict_policy !== 'FAIL_CLOSED') {
    problems.push('effective Authority resolution drifted');
  }
  const lifecycle = amendment.lifecycle;
  if (lifecycle?.accepted !== false || lifecycle?.merge_authorized !== false || lifecycle?.closeout_authorized !== false ||
      lifecycle?.b000_implementation_started !== false || lifecycle?.b000_candidate_created !== false ||
      lifecycle?.b000_merge_authorized !== false || lifecycle?.next_task_authorized !== false) problems.push('lifecycle stop boundary drifted');
  if (!same(amendment.scope?.allowed_paths, STAGE_PATHS) || amendment.scope?.historical_unregistered_p0_validator_changed !== false ||
      amendment.scope?.b000_business_code_changed !== false || amendment.scope?.b000_implementation_started !== false) {
    problems.push('Amendment stage scope drifted');
  }
  if (amendment.provenance?.append_only !== true || amendment.provenance?.base_authority_modified !== false ||
      amendment.provenance?.amendment_001_modified !== false || amendment.provenance?.historical_p0_validator_modified !== false ||
      amendment.provenance?.contradiction_reproduced !== true || amendment.provenance?.exact_predecessor_p0_gates_result !== 'PASS' ||
      amendment.provenance?.inventory_generated_from_candidate !== false || amendment.provenance?.automatic_merge_permitted !== false) {
    problems.push('Amendment provenance drifted');
  }
  if (amendment.reason?.minimal_reproduction?.evidence_path !== PREDECESSOR_EVIDENCE_PATH ||
      amendment.reason?.minimal_reproduction?.evidence_sha256 !== sha256(read(repo, PREDECESSOR_EVIDENCE_PATH)) ||
      amendment.reason?.minimal_reproduction?.contradiction_reproduced !== true ||
      amendment.reason?.owner_decision !== 'DO_NOT_MODIFY_HISTORICAL_P0_VALIDATORS') {
    problems.push('contradiction evidence/reason binding drifted');
  }
  problems.push(...validateInventoryDocument(inventory));
  problems.push(...validatePredecessorEvidence(predecessorEvidence));
  return problems;
}

function validatePredecessorEvidence(evidence) {
  const problems = [];
  const target = evidence?.predecessor_validation_target;
  if (evidence?.schema !== 'aipt.public.predecessor-validation-stage-evidence/v1' || evidence?.authority_task_id !== TASK_ID ||
      target?.repository !== PREDECESSOR_REPOSITORY || target?.commit !== PREDECESSOR_COMMIT || target?.tree !== PREDECESSOR_TREE ||
      target?.detached !== true || target?.clean !== true || target?.candidate_overlay !== false ||
      target?.modified_predecessor_files !== false || target?.node_version !== 'v24.19.0') problems.push('predecessor stage evidence target drifted');
  const gates = evidence?.p0_gate_results ?? [];
  if (gates.length !== 4) problems.push('predecessor evidence must record four P0 gates');
  for (let index = 0; index < P0_GATES.length; index += 1) {
    const expected = P0_GATES[index];
    const actual = gates[index];
    if (actual?.gate_id !== expected.gate_id || actual?.validator_path !== expected.path || actual?.validator_sha256 !== expected.sha256 ||
        actual?.exit_status !== 0 || actual?.stdout_sha256 !== expected.stdout_sha256 || actual?.stderr_sha256 !== EMPTY_SHA || actual?.result !== 'PASS') {
      problems.push(`predecessor evidence gate mismatch: ${expected.gate_id}`);
    }
  }
  const contradiction = evidence?.contradiction_reproduction;
  if (contradiction?.original_acceptance_contract_satisfiable !== false || contradiction?.historical_validator_modified !== false ||
      contradiction?.fixtures_derived_from_exact_predecessor !== true || contradiction?.real_source_repository_modified !== false ||
      contradiction?.probes?.[0]?.only_added_path !== 'aipt/p1-b000/playtest-package.json' ||
      contradiction?.probes?.[0]?.stderr_sha256 !== '2d18eb08a63e6334cb8a4d6337a384c5c9041fca603b71213b5fac4b8781f262' ||
      contradiction?.probes?.[1]?.only_added_path !== 'scripts/aipt/validate-p1-b000.mjs' ||
      contradiction?.probes?.[1]?.stderr_sha256 !== 'e8766ca9d754607cd7cb1608251aff8dce51baa54c6d745da85e5cd8f0c837f8' ||
      evidence?.result !== 'PASS') problems.push('contradiction reproduction evidence drifted');
  return problems;
}

function validateArtifactManifest(repo, manifest) {
  const problems = [];
  if (manifest?.schema !== 'aipt.public.authority-amendment-artifacts/v2' || manifest?.amendment_id !== TASK_ID ||
      manifest?.hash_algorithm !== 'SHA-256' || manifest?.self_hash_excluded !== true ||
      manifest?.candidate_git_identity_embedded !== false ||
      !same(manifest?.artifacts?.map((item) => item.path), ARTIFACT_PATHS) ||
      !same(manifest?.artifacts?.map((item) => item.role), ARTIFACT_ROLES)) {
    problems.push('Amendment-002 artifact manifest shape, order or roles drifted');
    return problems;
  }
  for (const item of manifest.artifacts) {
    try {
      if (sha256(read(repo, item.path)) !== item.sha256) problems.push(`artifact SHA-256 mismatch: ${item.path}`);
    } catch (error) {
      problems.push(`artifact unreadable: ${item.path}: ${error.message}`);
    }
  }
  return problems;
}

function validateFrozenAipt(repo) {
  const problems = [];
  for (const [relative, expected] of Object.entries(FROZEN_AIPT_HASHES)) {
    try {
      if (sha256(read(repo, relative)) !== expected) problems.push(`frozen AIPT artifact changed: ${relative}`);
    } catch (error) {
      problems.push(`frozen AIPT artifact unreadable: ${relative}: ${error.message}`);
    }
  }
  for (const commit of [
    '2619339e53113633e02f3aef14156a1ff08c13f8',
    'df71476d4b8f271f3b444cace46a3d6fbd1eaea4',
  ]) {
    const result = gitCall(repo, ['merge-base', '--is-ancestor', commit, BASE_COMMIT]);
    if (result.error || result.status !== 0) problems.push(`accepted governance identity is not in Base closeout ancestry: ${commit}`);
  }
  try {
    if (gitOutput(repo, ['rev-parse', `${BASE_COMMIT}^{tree}`]) !== BASE_TREE) problems.push('Base closeout tree drifted');
  } catch (error) {
    problems.push(error.message);
  }
  const status = readJSON(repo, 'docs/authority/registry/project-status.json');
  const standalone = status.tracks?.['AIPT-STANDALONE'];
  if (standalone?.current_batch !== 'NO_ACTIVE_BATCH' || standalone?.next_serial_batch !== IMPLEMENTATION_TASK_ID ||
      standalone?.next_batch_state !== 'NOT_AUTHORIZED' || standalone?.next_batch_authorized !== false ||
      standalone?.next_batch_started !== false || standalone?.batch_history?.[IMPLEMENTATION_TASK_ID] !== 'NOT_STARTED' ||
      standalone?.global_wip !== 0 || standalone?.external_serial_predecessor?.closeout_commit !== PREDECESSOR_COMMIT ||
      standalone?.external_serial_predecessor?.closeout_tree !== PREDECESSOR_TREE) problems.push('project status no-active-B000/predecessor baseline regressed');
  const graph = readJSON(repo, 'docs/authority/registry/batch-graph.json');
  const b000 = graph.serial_batches?.find((batch) => batch.id === IMPLEMENTATION_TASK_ID);
  if (graph.serial_batches?.length !== 13 || b000?.order !== 3 || b000?.repository !== 'UNREGISTERED') problems.push('13-item batch graph/B000 position regressed');
  return problems;
}

function changedPathsFromBase(repo, head) {
  const committed = gitCall(repo, ['diff', '--name-only', '-z', BASE_COMMIT, head], null);
  if (committed.error || committed.status !== 0) throw new Error('cannot enumerate committed Amendment scope');
  const working = gitCall(repo, ['diff', '--name-only', '-z', head], null);
  if (working.error || working.status !== 0) throw new Error('cannot enumerate working-tree Amendment scope');
  const staged = gitCall(repo, ['diff', '--cached', '--name-only', '-z', head], null);
  if (staged.error || staged.status !== 0) throw new Error('cannot enumerate staged Amendment scope');
  const untracked = gitCall(repo, ['ls-files', '--others', '--exclude-standard', '-z'], null);
  if (untracked.error || untracked.status !== 0) throw new Error('cannot enumerate untracked Amendment scope');
  const decode = (buffer) => buffer.toString('utf8').split('\0').filter(Boolean);
  return sorted(new Set([...decode(committed.stdout), ...decode(working.stdout), ...decode(staged.stdout), ...decode(untracked.stdout)]));
}

function classifyAiptLifecycle(repo) {
  const problems = [];
  let head = null;
  let tree = null;
  let changed = [];
  let phase = 'UNKNOWN';
  let candidate = null;
  try {
    head = gitOutput(repo, ['rev-parse', 'HEAD']);
    tree = gitOutput(repo, ['rev-parse', 'HEAD^{tree}']);
    changed = changedPathsFromBase(repo, head);
  } catch (error) {
    return { phase, head, tree, changed, candidate, problems: [error.message] };
  }
  if (!same(changed, STAGE_PATHS)) problems.push(`Amendment changed paths must equal exact stage scope; got ${JSON.stringify(changed)}`);
  const currentBranch = gitCall(repo, ['branch', '--show-current']);
  const branch = (process.env.GITHUB_HEAD_REF || currentBranch.stdout || '').trim();
  const status = gitOutput(repo, ['status', '--porcelain=v1', '--untracked-files=all']);
  if (head === BASE_COMMIT) {
    phase = 'WORKTREE_PREFLIGHT';
    if (tree !== BASE_TREE) problems.push('Base preflight tree mismatch');
    if (branch !== BRANCH) problems.push(`preflight branch must be ${BRANCH}`);
    if (status === '') problems.push('preflight cannot be clean at unchanged Base commit');
  } else {
    const parents = gitOutput(repo, ['show', '-s', '--format=%P', head]).split(' ').filter(Boolean);
    if (parents.length === 1) {
      phase = process.env.GITHUB_EVENT_NAME === 'pull_request' ? 'CANDIDATE_PR_CHECK' : 'CANDIDATE';
      candidate = head;
      if (parents[0] !== BASE_COMMIT || gitOutput(repo, ['rev-list', '--count', `${BASE_COMMIT}..${head}`]) !== '1') {
        problems.push('candidate must be one ordinary commit directly above the frozen Base closeout');
      }
      if (branch !== BRANCH) problems.push(`candidate branch must be ${BRANCH}`);
    } else if (parents.length === 2 && parents[0] === BASE_COMMIT) {
      phase = 'LEGAL_MERGE';
      candidate = parents[1];
      const candidateParents = gitOutput(repo, ['show', '-s', '--format=%P', candidate]).split(' ').filter(Boolean);
      if (!same(candidateParents, [BASE_COMMIT])) problems.push('merge second parent is not the direct candidate');
      if (gitOutput(repo, ['rev-parse', `${candidate}^{tree}`]) !== tree) problems.push('legal merge tree must equal candidate tree');
    } else {
      problems.push('checkout is neither exact candidate nor legal no-fast-forward merge');
    }
    if (status !== '') problems.push('frozen candidate/merge worktree is not clean');
  }
  return { phase, head, tree, changed, candidate, problems };
}

function parseGitTree(repo, revision) {
  const result = gitCall(repo, ['ls-tree', '-r', '-z', '--full-tree', revision], null);
  if (result.error || result.status !== 0) throw new Error(`cannot read candidate Git tree: ${result.error?.message ?? result.stderr?.toString('utf8')}`);
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const entries = [];
  let start = 0;
  for (let index = 0; index < result.stdout.length; index += 1) {
    if (result.stdout[index] !== 0) continue;
    const record = result.stdout.subarray(start, index);
    start = index + 1;
    const tab = record.indexOf(0x09);
    if (tab < 0) throw new Error('malformed git ls-tree record');
    const [mode, type, object] = record.subarray(0, tab).toString('ascii').split(' ');
    entries.push({ path: decoder.decode(record.subarray(tab + 1)), mode, type, object });
  }
  if (start !== result.stdout.length) throw new Error('candidate git ls-tree output is not NUL terminated');
  return entries.sort((left, right) => byteCompare(left.path, right.path));
}

function ensureRegularCheckoutFile(root, relative, expectedSha) {
  let current = root;
  for (const segment of relative.split('/')) {
    current = path.join(current, segment);
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) throw new Error(`symlink injection in predecessor checkout: ${relative}`);
  }
  const stat = fs.lstatSync(current);
  if (!stat.isFile()) throw new Error(`predecessor tracked path is not a regular file: ${relative}`);
  if (sha256(fs.readFileSync(current)) !== expectedSha) throw new Error(`predecessor checkout bytes drifted: ${relative}`);
}

function executeValidator(checkout, relative) {
  const result = spawnSync(process.execPath, [path.join(checkout, relative)], {
    cwd: checkout,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return {
    status: result.status,
    signal: result.signal,
    error: result.error?.message ?? null,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
}

function historicalReplayEnvironment() {
  return Object.fromEntries(Object.entries(process.env)
    .filter(([key]) => !key.startsWith('GITHUB_')));
}

function replayClosedGovernance(repo, gate) {
  const validator = CLOSED_GOVERNANCE_GATES[gate];
  const validationTarget = {
    mode: 'EXACT_ACCEPTED_AIPT_BASE_CLOSEOUT',
    commit: BASE_COMMIT,
    tree: BASE_TREE,
  };
  if (!validator) {
    return {
      result: 'FAIL',
      gate,
      validation_target: validationTarget,
      details: [`unknown closed governance gate: ${String(gate)}`],
    };
  }

  const target = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-a2-closed-gate-'));
  const details = [];
  try {
    const cloneResult = spawnSync('git', ['clone', '--no-local', '--no-checkout', repo, target], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
    });
    if (cloneResult.error || cloneResult.status !== 0) {
      throw new Error(`exact target clone failed: ${cloneResult.error?.message ?? cloneResult.stderr.trim()}`);
    }
    const checkoutResult = gitCall(target, ['checkout', '--detach', BASE_COMMIT]);
    if (checkoutResult.error || checkoutResult.status !== 0) {
      throw new Error(`exact target checkout failed: ${checkoutResult.error?.message ?? checkoutResult.stderr.trim()}`);
    }
    if (gitOutput(target, ['rev-parse', 'HEAD']) !== BASE_COMMIT ||
        gitOutput(target, ['rev-parse', 'HEAD^{tree}']) !== BASE_TREE ||
        gitOutput(target, ['status', '--porcelain=v1', '--untracked-files=all']) !== '') {
      throw new Error('exact accepted Base closeout commit/tree/clean identity mismatch');
    }

    const validatorAbsolute = path.join(target, validator.path);
    const stat = fs.lstatSync(validatorAbsolute);
    if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('closed governance validator is not a regular file');
    const validatorSha = sha256(fs.readFileSync(validatorAbsolute));
    if (validator.sha256 && validatorSha !== validator.sha256) {
      throw new Error(`closed governance ${gate} validator identity mismatch`);
    }
    const execution = spawnSync(process.execPath, [validatorAbsolute, '--repo', target, ...(validator.args ?? [])], {
      cwd: target,
      encoding: 'utf8',
      env: historicalReplayEnvironment(),
      maxBuffer: 64 * 1024 * 1024,
    });
    let report = null;
    try { report = JSON.parse(execution.stdout); } catch { report = null; }
    const reportIdentityMatches = validator.report_schema
      ? report?.schema === validator.report_schema && report?.task_id === validator.report_task_id
      : report?.name === validator.name;
    if (execution.error || execution.signal || execution.status !== 0 || report?.result !== 'PASS' || !reportIdentityMatches) {
      const reportedFailures = Array.isArray(report?.details)
        ? report.details.filter((item) => typeof item === 'string' && item.startsWith('FAIL:')).join('; ')
        : '';
      throw new Error(`closed governance ${gate} replay failed: ${(execution.error?.message ?? execution.stderr.trim()) || reportedFailures || 'invalid/non-PASS report'}`);
    }
    if (gitOutput(target, ['status', '--porcelain=v1', '--untracked-files=all']) !== '') {
      throw new Error(`closed governance ${gate} replay modified its exact target`);
    }
    details.push(`exact ${validator.name} entrypoint PASS on accepted Base closeout`);
    return {
      result: 'PASS',
      gate,
      validator_name: validator.name,
      validator_path: validator.path,
      validator_sha256: validatorSha,
      exit_status: execution.status,
      validation_target: validationTarget,
      details,
    };
  } catch (error) {
    return {
      result: 'FAIL',
      gate,
      validator_name: validator.name,
      validator_path: validator.path,
      validation_target: validationTarget,
      details: [error.message],
    };
  } finally {
    fs.rmSync(target, { recursive: true, force: true });
  }
}

function validateActualPredecessor(checkout, inventory) {
  const problems = [];
  const results = [];
  let root;
  try {
    root = path.resolve(checkout);
    const stat = fs.lstatSync(root);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('predecessor checkout root must be a real directory');
    if (fs.realpathSync(root) !== root) throw new Error('predecessor checkout root path must be canonical');
    if (gitOutput(root, ['rev-parse', 'HEAD']) !== PREDECESSOR_COMMIT) throw new Error('resolved predecessor commit mismatch');
    if (gitOutput(root, ['rev-parse', 'HEAD^{tree}']) !== PREDECESSOR_TREE) throw new Error('resolved predecessor tree mismatch');
    const symbolic = gitCall(root, ['symbolic-ref', '-q', 'HEAD']);
    if (symbolic.status === 0 || symbolic.error) throw new Error('predecessor checkout must have detached HEAD');
    if (gitOutput(root, ['status', '--porcelain=v1', '--untracked-files=all']) !== '') throw new Error('predecessor checkout is not clean');
    if (process.version !== 'v24.19.0') throw new Error(`predecessor gates require Node v24.19.0, got ${process.version}`);
    const regenerated = generateInventory(root);
    if (!same(regenerated, inventory)) throw new Error('inventory regeneration from exact predecessor does not match frozen inventory');
    for (const entry of inventory.entries) ensureRegularCheckoutFile(root, entry.path, entry.sha256);
  } catch (error) {
    problems.push(error.message);
    return { result: 'FAIL', problems, gate_results: results };
  }
  for (const gate of P0_GATES) {
    const execution = executeValidator(root, gate.path);
    const record = {
      gate_id: gate.gate_id,
      validator_path: gate.path,
      validator_sha256: sha256(fs.readFileSync(path.join(root, gate.path))),
      exit_status: execution.status,
      stdout_sha256: sha256(execution.stdout),
      stderr_sha256: sha256(execution.stderr),
      result: execution.status === 0 && !execution.error ? 'PASS' : 'FAIL',
    };
    results.push(record);
    if (record.validator_sha256 !== gate.sha256) problems.push(`${gate.gate_id} historical validator identity mismatch`);
    if (record.exit_status !== 0 || execution.error || execution.signal) problems.push(`${gate.gate_id} failed: ${execution.error ?? execution.stderr.trim()}`);
    if (record.stdout_sha256 !== gate.stdout_sha256 || record.stderr_sha256 !== EMPTY_SHA) problems.push(`${gate.gate_id} deterministic output fingerprint mismatch`);
  }
  return { result: problems.length === 0 ? 'PASS' : 'FAIL', problems, gate_results: results };
}

function validateActualCandidate(candidateCheckout, predecessorCheckout, inventory) {
  const problems = [];
  let commit = null;
  let tree = null;
  let delta = null;
  let p1 = { result: 'FAIL', validator_path: 'scripts/aipt/validate-p1-b000.mjs', validator_sha256: null, exit_status: null };
  let b001 = { result: 'FAIL', validator_path: 'scripts/aipt/validate-p1-b000.mjs', validator_sha256: null, exit_status: null };
  try {
    const root = path.resolve(candidateCheckout);
    const predecessorRoot = path.resolve(predecessorCheckout);
    if (fs.realpathSync(root) === fs.realpathSync(predecessorRoot)) throw new Error('candidate and predecessor checkouts must be distinct');
    const stat = fs.lstatSync(root);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error('candidate checkout root must be a real directory');
    commit = gitOutput(root, ['rev-parse', 'HEAD']);
    tree = gitOutput(root, ['rev-parse', 'HEAD^{tree}']);
    if (!/^[0-9a-f]{40}$/u.test(commit) || !/^[0-9a-f]{40}$/u.test(tree) || commit === PREDECESSOR_COMMIT) throw new Error('candidate commit/tree identity is invalid');
    const symbolic = gitCall(root, ['symbolic-ref', '-q', 'HEAD']);
    if (symbolic.status === 0 || symbolic.error) throw new Error('candidate evidence checkout must have detached HEAD');
    if (gitOutput(root, ['status', '--porcelain=v1', '--untracked-files=all']) !== '') throw new Error('candidate checkout is not clean');
    const ancestor = gitCall(root, ['merge-base', '--is-ancestor', PREDECESSOR_COMMIT, commit]);
    if (ancestor.error || ancestor.status !== 0) throw new Error('candidate does not descend from the exact predecessor');
    delta = analyzeCandidateDelta(inventory, parseGitTree(root, commit));
    const validatorRelative = 'scripts/aipt/validate-p1-b000.mjs';
    const validatorAbsolute = path.join(root, validatorRelative);
    const validatorStat = fs.lstatSync(validatorAbsolute);
    if (!validatorStat.isFile() || validatorStat.isSymbolicLink()) throw new Error('P1 validator is not a regular file');
    const execution = executeValidator(root, validatorRelative);
    const digest = sha256(fs.readFileSync(validatorAbsolute));
    let report = null;
    try { report = JSON.parse(execution.stdout); } catch { report = null; }
    p1 = {
      result: execution.status === 0 && !execution.error ? 'PASS' : 'FAIL',
      validator_path: validatorRelative,
      validator_sha256: digest,
      exit_status: execution.status,
    };
    b001 = {
      result: p1.result === 'PASS' && report?.b001_compatibility === 'PASS' ? 'PASS' : 'FAIL',
      validator_path: validatorRelative,
      validator_sha256: digest,
      exit_status: execution.status,
    };
    if (p1.result !== 'PASS') problems.push(`P1 B000 validator failed: ${execution.error ?? execution.stderr.trim()}`);
    if (b001.result !== 'PASS') problems.push('P1 validator did not emit structured b001_compatibility PASS');
  } catch (error) {
    problems.push(error.message);
  }
  return { result: problems.length === 0 && delta?.p0_preservation.result === 'PASS' && delta?.p1_delta.result === 'PASS' && p1.result === 'PASS' && b001.result === 'PASS' ? 'PASS' : 'FAIL', problems, commit, tree, delta, p1_validation: p1, b001_compatibility: b001 };
}

export function run(ctx, args = {}) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push(`ok: ${message}`);
  const fail = (message) => { pass = false; details.push(`FAIL: ${message}`); };
  let amendment;
  let inventory;
  let predecessorEvidence;
  let artifactManifest;
  let amendmentSchema;
  let acceptanceEvidenceSchema;
  try {
    amendment = readJSON(ctx.repo, AMENDMENT_PATH);
    inventory = readJSON(ctx.repo, INVENTORY_PATH);
    predecessorEvidence = readJSON(ctx.repo, PREDECESSOR_EVIDENCE_PATH);
    artifactManifest = readJSON(ctx.repo, ARTIFACT_PATH);
    amendmentSchema = readJSON(ctx.repo, AMENDMENT_SCHEMA_PATH);
    acceptanceEvidenceSchema = readJSON(ctx.repo, ACCEPTANCE_EVIDENCE_SCHEMA_PATH);
  } catch (error) {
    return { result: 'FAIL', task_id: TASK_ID, details: [`FAIL: Amendment-002 input unreadable: ${error.message}`], required_negative_probes: 'NOT_RUN' };
  }

  for (const problem of schemaProblems(amendmentSchema, amendment, 'Amendment-002')) fail(problem);
  if (checkSchemaDocument(amendmentSchema).errors.length === 0) ok('Amendment-002 schema is supported and machine authority conforms');
  const evidenceSchemaErrors = checkSchemaDocument(acceptanceEvidenceSchema).errors;
  for (const problem of evidenceSchemaErrors) fail(`acceptance evidence schema: ${problem}`);
  if (evidenceSchemaErrors.length === 0) ok('predecessor/successor acceptance evidence schema is fail-closed and supported');

  const machineProblems = validateMachineAuthority(ctx.repo, amendment, inventory, predecessorEvidence);
  for (const problem of machineProblems) fail(problem);
  if (machineProblems.length === 0) ok('machine Authority freezes exact predecessor, preservation, controlled delta, formula and failure semantics');

  const frozenProblems = validateFrozenAipt(ctx.repo);
  for (const problem of frozenProblems) fail(problem);
  if (frozenProblems.length === 0) ok('Base/A1/repair effective identities, schemas, migration, B001 semantics and no-active-B000 status are preserved');

  const artifactProblems = validateArtifactManifest(ctx.repo, artifactManifest);
  for (const problem of artifactProblems) fail(problem);
  if (artifactProblems.length === 0) ok(`all ${ARTIFACT_PATHS.length} Amendment-002 artifact SHA-256 identities verified`);

  const lifecycle = classifyAiptLifecycle(ctx.repo);
  for (const problem of lifecycle.problems) fail(`lifecycle: ${problem}`);
  if (lifecycle.problems.length === 0) ok(`${lifecycle.phase} lifecycle and exact governance-only stage scope verified`);

  const packageJSON = readJSON(ctx.repo, 'package.json');
  const aggregate = text(ctx.repo, 'scripts/ci/run-checks.mjs');
  const validatorSource = text(ctx.repo, VALIDATOR_PATH);
  const workflow = text(ctx.repo, '.github/workflows/ci.yml');
  const authorityIndex = text(ctx.repo, 'docs/authority/README.md');
  const dependencyExclude = "printf '%s\\n' '# CI-local generated dependency metadata' 'node_modules/' >> .git/info/exclude";
  const dependencyExcludeIndex = workflow.indexOf(dependencyExclude);
  const frozenInstallIndex = workflow.indexOf('run: pnpm install --frozen-lockfile');
  const wiring = [
    ['package command', packageJSON.scripts?.['check:p1-b000-authority-amendment-002'] === `node ${VALIDATOR_PATH}`],
    ['closed repair package routing', packageJSON.scripts?.['check:p1-b000-authority-repair'] === `node ${VALIDATOR_PATH} --closed-governance-gate repair`],
    ['closed closeout package routing', packageJSON.scripts?.['check:p1-b000-authority-closeout'] === `node ${VALIDATOR_PATH} --closed-governance-gate closeout`],
    ['closed reverification package routing', packageJSON.scripts?.['check:p1-b000-post-merge-reverification'] === `node ${VALIDATOR_PATH} --closed-governance-gate reverification`],
    ['aggregate import/call', aggregate.includes("runP1B000AuthorityAmendment002") && aggregate.includes('runP1B000AuthorityAmendment002(ctx)')],
    ['focused CI command', workflow.includes('pnpm run check:p1-b000-authority-amendment-002')],
    ['candidate dependency-environment boundary', dependencyExcludeIndex >= 0 && dependencyExcludeIndex < frozenInstallIndex && workflow.includes("git ls-files -- 'node_modules/**' ':(glob)**/node_modules/**'")],
    ['exact predecessor CI command', workflow.includes(`node ${VALIDATOR_PATH} --require-predecessor --predecessor-checkout "\${A2_PREDECESSOR_TARGET}"`)],
    ['exact external repository checkout', workflow.includes('git clone --no-checkout https://github.com/zyc14588/UNREGISTERED.git "${A2_PREDECESSOR_TARGET}"') && workflow.includes(`checkout --detach "${PREDECESSOR_COMMIT}"`) && workflow.includes(PREDECESSOR_TREE)],
    ['closed governance exact-target replay', aggregate.includes('exactClosedGovernanceContext') && aggregate.includes(`checkout', '--detach', '${BASE_COMMIT}'`) && aggregate.includes(BASE_TREE) && aggregate.includes('EXACT_ACCEPTED_AIPT_BASE_CLOSEOUT') && aggregate.includes("'--offline', '--frozen-lockfile', '--ignore-scripts'") && aggregate.includes("version.stdout.trim() !== '11.4.0'")],
    ['closed entrypoints exact-target replay', aggregate.includes('standaloneCheck') && aggregate.includes("runClosedEntrypoint(closedGovernance.ctx, 'standalone-entrypoints')") && aggregate.includes("runClosedEntrypoint(closedGovernance.ctx, 'p1-b000-authority-repair')") && aggregate.includes("runClosedEntrypoint(closedGovernance.ctx, 'p1-b000-authority-closeout')")],
    ['closed replay GitHub identity isolation', validatorSource.includes("!key.startsWith('GITHUB_')") && aggregate.includes("!key.startsWith('GITHUB_')") && aggregate.includes('bindGitHubExecutionIdentity: false')],
    ['closed validator successor routing', !workflow.includes(`hashFiles('${AMENDMENT_PATH}')`) && workflow.includes('run: pnpm run check:p1-b000-authority-repair\n') && workflow.includes('run: pnpm run check:p1-b000-authority-closeout\n') && workflow.includes('run: pnpm run check:p1-b000-post-merge-reverification\n') && workflow.includes('run: pnpm run check\n')],
    ['authority index', authorityIndex.includes('unregistered-aipt-p1-b000-authority-amendment-002.json') && authorityIndex.includes('UNREGISTERED_AIPT_P1_B000_AUTHORITY_AMENDMENT_002.md')],
  ];
  for (const [label, present] of wiring) present ? ok(`${label} wiring present`) : fail(`${label} wiring missing`);
  if (workflow.includes('continue-on-error:')) fail('CI failure masking is forbidden');

  const probes = probeResults(inventory);
  const required = probes.slice(0, REQUIRED_PROBES.length);
  const security = probes.slice(REQUIRED_PROBES.length);
  for (let index = 0; index < REQUIRED_PROBES.length; index += 1) {
    if (required[index]?.id !== REQUIRED_PROBES[index][0] || !required[index]?.matched) fail(`${REQUIRED_PROBES[index][0]} did not produce ${REQUIRED_PROBES[index][1]}`);
  }
  for (let index = 0; index < SECURITY_PROBES.length; index += 1) {
    if (security[index]?.id !== SECURITY_PROBES[index][0] || !security[index]?.matched) fail(`${SECURITY_PROBES[index][0]} did not produce REJECT`);
  }
  const requiredMatched = required.filter((probe) => probe.matched).length;
  const securityMatched = security.filter((probe) => probe.matched).length;
  if (requiredMatched === REQUIRED_PROBES.length) ok('all A2-N01 through A2-N30 predecessor/preservation/delta/acceptance/B001 probes matched');
  if (securityMatched === SECURITY_PROBES.length) ok('all A2-S01 through A2-S06 symlink/collision/submodule/masquerade probes rejected');

  const placeholder = /\b(?:TBD|TODO|FIXME|XXX)\b|<actual>|<sha>|<commit>|\{\{[^}]+\}\}/iu;
  const placeholderPaths = [HUMAN_PATH, AMENDMENT_PATH, PREDECESSOR_EVIDENCE_PATH, AMENDMENT_SCHEMA_PATH, ACCEPTANCE_EVIDENCE_SCHEMA_PATH];
  const unresolved = placeholderPaths.filter((relative) => placeholder.test(text(ctx.repo, relative)));
  for (const relative of unresolved) fail(`unresolved placeholder in ${relative}`);
  if (unresolved.length === 0) ok('Authority artifacts contain no unresolved placeholders');

  let actualPredecessor = { result: 'NOT_RUN', problems: [], gate_results: [] };
  if (typeof args['predecessor-checkout'] === 'string') {
    actualPredecessor = validateActualPredecessor(args['predecessor-checkout'], inventory);
    for (const problem of actualPredecessor.problems) fail(`exact predecessor: ${problem}`);
    if (actualPredecessor.result === 'PASS') ok('exact detached clean predecessor inventory and all four historical P0 gates PASS');
  } else if (args['require-predecessor'] === true) {
    fail('--require-predecessor requires --predecessor-checkout');
  }

  let actualCandidate = { result: 'NOT_RUN', problems: [], commit: null, tree: null, delta: null, p1_validation: null, b001_compatibility: null };
  if (typeof args['candidate-checkout'] === 'string') {
    if (typeof args['predecessor-checkout'] !== 'string' || actualPredecessor.result !== 'PASS') {
      fail('--candidate-checkout requires a passing exact --predecessor-checkout');
    } else {
      actualCandidate = validateActualCandidate(args['candidate-checkout'], args['predecessor-checkout'], inventory);
      for (const problem of actualCandidate.problems) fail(`candidate: ${problem}`);
      for (const problem of actualCandidate.delta?.p0_preservation.problems ?? []) fail(`candidate preservation: ${problem}`);
      for (const problem of actualCandidate.delta?.p1_delta.problems ?? []) fail(`candidate delta: ${problem}`);
      if (actualCandidate.result === 'PASS') ok('candidate P0 preservation, controlled P1 delta, P1 validator and B001 compatibility PASS');
    }
  }

  const amendmentStaticPass = pass;
  let closedGovernanceReplay = { result: 'NOT_RUN', gate: null, details: [] };
  if (Object.hasOwn(args, 'closed-governance-gate')) {
    closedGovernanceReplay = replayClosedGovernance(ctx.repo, args['closed-governance-gate']);
    if (closedGovernanceReplay.result === 'PASS') {
      ok(`closed governance ${closedGovernanceReplay.gate} replay PASS on exact accepted Base closeout`);
    } else {
      for (const problem of closedGovernanceReplay.details) fail(`closed governance replay: ${problem}`);
    }
  }

  return {
    result: pass ? 'PASS' : 'FAIL',
    task_id: TASK_ID,
    authority_task_id: AUTHORITY_TASK_ID,
    implementation_task_id: IMPLEMENTATION_TASK_ID,
    details,
    amendment_validator: amendmentStaticPass ? 'PASS' : 'FAIL',
    lifecycle_phase: lifecycle.phase,
    candidate_commit: lifecycle.candidate,
    candidate_tree: lifecycle.candidate ? lifecycle.tree : null,
    changed_paths: lifecycle.changed,
    predecessor: {
      repository: PREDECESSOR_REPOSITORY,
      commit: PREDECESSOR_COMMIT,
      tree: PREDECESSOR_TREE,
      inventory_projection_sha256: INVENTORY_PROJECTION_SHA,
      actual_validation: actualPredecessor.result,
      p0_gate_results: actualPredecessor.gate_results,
    },
    p0_preservation_contract: machineProblems.length === 0 ? 'FROZEN' : 'FAIL',
    controlled_p1_delta_contract: machineProblems.length === 0 ? 'FROZEN' : 'FAIL',
    required_negative_probes: requiredMatched === REQUIRED_PROBES.length ? 'PASS' : 'FAIL',
    required_negative_probe_count: required.length,
    security_negative_probes: securityMatched === SECURITY_PROBES.length ? 'PASS' : 'FAIL',
    security_negative_probe_count: security.length,
    unexpected_acceptances: probes.filter((probe, index) => {
      const expected = index < REQUIRED_PROBES.length ? REQUIRED_PROBES[index][1] : 'REJECT';
      return expected === 'REJECT' && probe.observed === 'ACCEPT';
    }).length,
    uncaught_validation_errors: 0,
    effective_authority_regression: frozenProblems.length === 0 ? 'PASS' : 'FAIL',
    b001_regression: frozenProblems.length === 0 ? 'PASS' : 'FAIL',
    candidate_validation: actualCandidate,
    closed_governance_replay: closedGovernanceReplay,
    historical_p0_validator_modified: false,
    business_code_changed: false,
    b000_implementation_started: false,
    merge_eligible: false,
    merge_authorized: false,
  };
}

runAsMain(import.meta.url, 'p1-b000-authority-amendment-002', run);
