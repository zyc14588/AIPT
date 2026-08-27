#!/usr/bin/env node
// UNREGISTERED-AIPT-P1-B000-AUTHORITY-001 governance-only validator.
// Node.js standard library only. No runtime, model, network or playtest call.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  B007_EXTERNAL_SERIAL_PREDECESSOR,
  MVP_B001,
} from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';
import { checkSchemaDocument, validateInstance } from '../lib/json-schema.mjs';
import { checkMigrationContract } from './mvp-b001.mjs';

const TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-001';
const IMPLEMENTATION_TASK = 'UNREGISTERED-AIPT-P1-B000';
const AUTHORITY_VERSION = '1.0.0';
const AUTHORITY_BRANCH = 'task/UNREGISTERED-AIPT-P1-B000-AUTHORITY-001';
const AIPT_BASE_COMMIT = 'eede815e818d87362605f55d5bfd2a0460e6e130';
const AIPT_BASE_TREE = 'd2668f0ea9d3b72969199c7cd8afc5edb94c2a6b';
const UNREGISTERED_COMMIT = '358d6d9d08a86818e34fd0c0d9a62bfe66e73abe';
const UNREGISTERED_TREE = '5585271c78d1fe5cd8357c7b36a501bee34f0240';
const MIGRATION_SHA256 = '47f02a5a2129473caa0db5e359a0b294a01b2a96329d9f6fa08ac87cc429c997';

const AUTHORITY_PATH = 'docs/authority/registry/unregistered-aipt-p1-b000-authority.json';
const ARTIFACT_PATH = 'docs/authority/registry/unregistered-aipt-p1-b000-authority-artifacts.json';
const HUMAN_PATH = 'docs/authority/UNREGISTERED_AIPT_P1_B000_AUTHORITY.md';
const PACKAGE_SCHEMA_PATH = 'schemas/playtest-package/v1/aipt-playtest-package.schema.json';
const ADAPTER_SCHEMA_PATH = 'schemas/runtime-adapter-input/v1/aipt-runtime-adapter-input.schema.json';
const TEST_PLAN_SCHEMA_PATH = 'schemas/testplan/v1/aipt-test-plan.schema.json';
const RUN_MANIFEST_SCHEMA_PATH = 'schemas/run-manifest/v1/aipt-run-manifest.schema.json';
const MIGRATION_PATH = 'internal/storage/postgres/migrations/000002_playtest_queue.sql';
const VALIDATOR_PATH = 'scripts/ci/validate/p1-b000-authority.mjs';
const AUTHORITY_CANDIDATE = 'c9f7729f666d11716c04d7682da16044ca965236';
const AUTHORITY_CANDIDATE_TREE = '9cf551e7bc70d4354ca21d62a2bd456ed6f401bb';
const AUTHORITY_MERGE = '169f9bd006dabb88eb653ab09a33b0eef5eadaed';
const AUTHORITY_MERGE_PARENTS = [AIPT_BASE_COMMIT, AUTHORITY_CANDIDATE];
const AUTHORITY_MERGE_SUBJECT = 'merge: accept UNREGISTERED P1 B000 Authority contract';
const ORIGINAL_VALIDATOR_SHA256 = 'f5ed47898ad13b193cd685ae9649c18cada3a6fb5893c1810867c91869ad8c7c';
const AMENDMENT_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-001';
const AMENDMENT_CANDIDATE = 'a1d614c7468f67d13bcbf32f65ade7613a85e202';
const AMENDMENT_CANDIDATE_TREE = 'c03ce80729cce470e35325fd4d4a35e221221c55';
const AMENDMENT_MERGE = '33a53d53c6db474f46a886dcbbba6d083eee4f27';
const AMENDMENT_CLOSEOUT = '2619339e53113633e02f3aef14156a1ff08c13f8';
const AMENDMENT_CLOSEOUT_PATH = 'docs/authority/registry/authority-amendment-closeouts/unregistered-aipt-p1-b000-authority-amendment-001-closeout.json';
const SUPERSESSION_DIRECTORY = 'docs/authority/registry/authority-validator-supersessions';
const REPAIR_TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001';

const CANDIDATE_LIFECYCLE_STATES = new Set([
  'CANDIDATE_FROZEN', 'CODEX_STAGE_PASS', 'MERGE_ELIGIBLE',
]);
const HISTORICAL_LIFECYCLE_STATES = new Set([
  'MERGED', 'POST_MERGE_VERIFIED', 'CLOSED',
]);

const AUTHORITY_ALLOWED_PATHS = [
  '.github/workflows/ci.yml',
  'docs/authority/README.md',
  HUMAN_PATH,
  ARTIFACT_PATH,
  AUTHORITY_PATH,
  'package.json',
  PACKAGE_SCHEMA_PATH,
  ADAPTER_SCHEMA_PATH,
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/mvp-b001.mjs',
  VALIDATOR_PATH,
  'scripts/ci/validate/standalone-entrypoints.mjs',
  'scripts/ci/validate/workflow.mjs',
];

const IMPLEMENTATION_ALLOWED_PATHS = [
  '.github/workflows/aipt-content-gate.yml',
  'aipt/README.md',
  'aipt/p1-b000/compatibility-evidence.json',
  'aipt/p1-b000/playtest-package.json',
  'aipt/p1-b000/runtime-adapter-input.json',
  'aipt/status.json',
  'scripts/aipt/validate-p1-b000.mjs',
];

const NON_GOALS = [
  'RUN_CORE_IMPLEMENTATION',
  'AGENT_ORCHESTRATION',
  'AI_PLAYER_RUNTIME',
  'AI_GM_RUNTIME',
  'REAL_MODEL_GATEWAY',
  'DEEPSEEK_OPENAI_RUNTIME_INTEGRATION',
  'REAL_MODEL_CALLS',
  'REAL_PLAYTEST_EXECUTION',
  'COMBAT_RULE_ENGINE_IMPLEMENTATION',
  'SCENARIO_LOGIC_EXECUTION',
  'NPC_AUTONOMOUS_BEHAVIOUR',
  'MEMORY_RAG_ORCHESTRATION',
  'PROMPT_GENERATION_SYSTEM',
  'VISUAL_GENERATION',
  'VOICE_GENERATION',
  'TRPG_PLATFORM_INTEGRATION',
  'UNREGISTERED_STORY_REWRITE',
  'UNREGISTERED_RULE_REWRITE',
  'GENERAL_CONTENT_AUTHORING',
  'B001_QUEUE_REDESIGN',
  'B001_MANIFEST_REDESIGN',
];

const LIFECYCLE_STATES = [
  'PLANNED', 'AUTHORIZED', 'ACTIVE', 'CANDIDATE_FROZEN', 'CODEX_STAGE_PASS',
  'MERGE_ELIGIBLE', 'MERGED', 'POST_MERGE_VERIFIED', 'CLOSED', 'BLOCKED', 'FAIL',
];

const NEGATIVE_NAMES = [
  'MALFORMED_PACKAGE_MANIFEST',
  'UNSUPPORTED_SCHEMA_VERSION',
  'MISSING_PACKAGE_ID',
  'DUPLICATE_PACKAGE_IDENTITY',
  'INVALID_PACKAGE_VERSION',
  'MISSING_SOURCE_COMMIT',
  'SOURCE_COMMIT_MISMATCH',
  'SOURCE_TREE_MISMATCH',
  'SOURCE_DIGEST_MISMATCH',
  'STALE_SOURCE_MANIFEST',
  'DUPLICATE_LOGICAL_MAPPING_ID',
  'UNKNOWN_SOURCE_KIND',
  'DANGLING_MAPPING_REFERENCE',
  'PATH_TRAVERSAL',
  'MAPPING_ESCAPES_PACKAGE_ROOT',
  'MISSING_MAPPED_FILE',
  'MAPPED_CONTENT_DIGEST_MISMATCH',
  'MISSING_VISIBILITY',
  'UNKNOWN_VISIBILITY',
  'PLAYER_VISIBLE_REFERENCE_TO_GM_ONLY',
  'PLAYER_VISIBLE_EVIDENCE_CONTAINS_GM_ONLY',
  'SYSTEM_INTERNAL_EXPOSED_TO_PLAYER',
  'SECRET_MATERIAL_DETECTED',
  'CONFLICTING_VISIBILITY_DECLARATIONS',
  'UNSUPPORTED_ADAPTER_CONTRACT_VERSION',
  'INVALID_ADAPTER_INPUT',
  'ADAPTER_REFERENCES_UNKNOWN_PACKAGE',
  'CROSS_PACKAGE_REFERENCE_WITHOUT_AUTHORIZATION',
  'MISSING_RUN_MANIFEST_SOURCE_BINDING',
  'SOURCE_BINDING_IDENTITY_MISMATCH',
  'MUTABLE_BRANCH_USED_AS_IMMUTABLE_IDENTITY',
  'EVIDENCE_PROVENANCE_INCOMPLETE',
  'B001_CAMPAIGN_SUITE_CASE_RUN_REGRESSION',
  'ATTEMPT_EXTERNALLY_ADDRESSABLE',
  'RUN_MANIFEST_MUTATION_REGRESSION',
  'POSTGRESQL_QUEUE_AUTHORITY_REGRESSION',
  'FORMAL_WIP_ONE_REGRESSION',
  'LEASE_RECOVERY_REGRESSION',
  'ATTEMPT_APPEND_ONLY_REGRESSION',
];

const EXPECTED_PROBE_CODES = [
  'FAIL_SCHEMA', 'FAIL_UNSUPPORTED_VERSION', 'FAIL_SCHEMA',
  'FAIL_DUPLICATE_PACKAGE_IDENTITY', 'FAIL_SCHEMA', 'FAIL_SCHEMA',
  'FAIL_SOURCE_IDENTITY', 'FAIL_SOURCE_IDENTITY', 'FAIL_SOURCE_DIGEST',
  'FAIL_SOURCE_DIGEST', 'FAIL_MAPPING', 'FAIL_SCHEMA', 'FAIL_MAPPING',
  'FAIL_PATH_POLICY', 'FAIL_PATH_POLICY', 'FAIL_REFERENCE_INTEGRITY',
  'FAIL_SOURCE_DIGEST', 'FAIL_VISIBILITY', 'FAIL_SCHEMA', 'FAIL_VISIBILITY',
  'FAIL_VISIBILITY', 'FAIL_VISIBILITY', 'FAIL_SECRET', 'FAIL_VISIBILITY',
  'FAIL_UNSUPPORTED_VERSION', 'FAIL_SCHEMA', 'FAIL_PACKAGE_BINDING',
  'FAIL_CROSS_PACKAGE_REFERENCE', 'FAIL_SCHEMA', 'FAIL_B001_COMPATIBILITY',
  'FAIL_SCHEMA', 'FAIL_SCHEMA', 'FAIL_B001_REGRESSION', 'FAIL_B001_REGRESSION',
  'FAIL_B001_REGRESSION', 'FAIL_B001_REGRESSION', 'FAIL_B001_REGRESSION',
  'FAIL_B001_REGRESSION', 'FAIL_B001_REGRESSION',
];

const VISIBILITY_SURFACES = Object.freeze({
  PLAYER_VISIBLE: [
    'PLAYER_AGENT_CONTEXT', 'PLAYER_VISIBLE_EVIDENCE',
    'GM_CONTEXT', 'AUTHORIZED_EVIDENCE',
  ],
  GM_ONLY: ['GM_CONTEXT', 'ADJUDICATION', 'AUTHORIZED_EVIDENCE'],
  SYSTEM_INTERNAL: ['HARNESS_CONTROL', 'TEST_CONTROL', 'BOOKKEEPING'],
});

const KIND_FIELDS = Object.freeze({
  scene_ids: 'SCENE',
  guide_ids: 'GUIDE',
  rule_ids: 'RULE',
  asset_ids: 'ASSET',
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

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function sortedUnique(values) {
  return [...new Set(values)].sort();
}

function sameSet(a, b) {
  return same(sortedUnique(a), sortedUnique(b));
}

function canonicalJSON(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(',')}]`;
  if (isObject(value)) {
    return `{${Object.keys(value).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(',')}}`;
  }
  if (typeof value === 'number' && !Number.isFinite(value)) throw new Error('non-finite JSON number');
  return JSON.stringify(value);
}

function bindPackage(pkg) {
  const value = clone(pkg);
  delete value.source_digest;
  return { ...value, source_digest: sha256(Buffer.from(canonicalJSON(value), 'utf8')) };
}

function bindAdapter(input) {
  const value = clone(input);
  delete value.canonical_sha256;
  return { ...value, canonical_sha256: sha256(Buffer.from(canonicalJSON(value), 'utf8')) };
}

function bindRunManifest(manifest) {
  const value = clone(manifest);
  delete value.canonical_sha256;
  return { ...value, canonical_sha256: sha256(Buffer.from(canonicalJSON(value), 'utf8')) };
}

function hasValidBoundDigest(value, member) {
  if (!isObject(value) || typeof value[member] !== 'string') return false;
  const projection = clone(value);
  const claimed = projection[member];
  delete projection[member];
  return sha256(Buffer.from(canonicalJSON(projection), 'utf8')) === claimed;
}

function byteSort(values) {
  return [...values].sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
}

function validSourcePath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\\') ||
      value.includes('\0') || value.startsWith('/') || value.endsWith('/')) return false;
  const segments = value.split('/');
  return segments.every((segment) => segment.length > 0 && segment !== '.' && segment !== '..');
}

function withinRoot(sourcePath, packageRoot) {
  if (packageRoot === '.') return validSourcePath(sourcePath);
  return validSourcePath(sourcePath) && sourcePath.startsWith(`${packageRoot}/`);
}

function secretDetected(value) {
  const source = Buffer.isBuffer(value) ? value.toString('utf8') : String(value);
  return /-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(source) ||
    /(?:^|[^A-Za-z0-9])(?:sk-|dsk-|ghp_)[A-Za-z0-9_-]{8,}/.test(source) ||
    /(?:api[_-]?key|password|credential|access[_-]?token)\s*[:=]\s*["']?[^\s"']{8,}/i.test(source) ||
    /https?:\/\/[^/\s:@]+:[^@\s/]+@/i.test(source);
}

function addCode(codes, code) {
  if (!codes.includes(code)) codes.push(code);
}

function schemaCodes(schema, value, codes) {
  if (validateInstance(schema, value).errors.length > 0) addCode(codes, 'FAIL_SCHEMA');
}

function validatePackage(schema, pkg, fileFacts, expectedSource, loadedPackages = [pkg]) {
  const codes = [];
  if (!isObject(pkg)) {
    addCode(codes, 'FAIL_SCHEMA');
    return codes;
  }
  if (pkg.schema !== 'aipt.playtest-package/v1' || pkg.schema_version !== '1.0.0' ||
      pkg.mapping_version !== '1.0.0' || pkg.adapter_contract_version !== '1.0.0') {
    addCode(codes, 'FAIL_UNSUPPORTED_VERSION');
  }
  schemaCodes(schema, pkg, codes);

  const stable = loadedPackages.filter((entry) => isObject(entry) &&
    entry.package_id === pkg.package_id && entry.package_version === pkg.package_version);
  if (stable.length !== 1) addCode(codes, 'FAIL_DUPLICATE_PACKAGE_IDENTITY');

  if (pkg.source_repository !== expectedSource.repository ||
      pkg.source_commit !== expectedSource.commit || pkg.source_tree !== expectedSource.tree) {
    addCode(codes, 'FAIL_SOURCE_IDENTITY');
  }
  if (!hasValidBoundDigest(pkg, 'source_digest')) addCode(codes, 'FAIL_SOURCE_DIGEST');

  const mappings = Array.isArray(pkg.mappings) ? pkg.mappings : [];
  const references = Array.isArray(pkg.references) ? pkg.references : [];
  const entries = Array.isArray(pkg.digest_scope?.entries) ? pkg.digest_scope.entries : [];
  const mappingIDs = mappings.map((mapping) => mapping?.logical_id);
  const referenceIDs = references.map((reference) => reference?.reference_id);
  const allIDs = [...mappingIDs, ...referenceIDs];
  if (allIDs.some((id) => typeof id !== 'string') || new Set(allIDs).size !== allIDs.length) {
    addCode(codes, 'FAIL_MAPPING');
  }
  const idSet = new Set(allIDs);
  for (const mapping of mappings) {
    for (const dependency of mapping?.depends_on ?? []) {
      if (!idSet.has(dependency)) addCode(codes, 'FAIL_MAPPING');
    }
  }
  for (const reference of references) {
    for (const requiredBy of reference?.required_by ?? []) {
      if (!idSet.has(requiredBy)) addCode(codes, 'FAIL_MAPPING');
    }
  }

  const sourcePaths = [...mappings.map((mapping) => mapping?.source_path),
    ...references.map((reference) => reference?.source_path)];
  for (const sourcePath of sourcePaths) {
    if (!validSourcePath(sourcePath) || !withinRoot(sourcePath, pkg.package_root)) {
      addCode(codes, 'FAIL_PATH_POLICY');
    }
  }
  const entryPaths = entries.map((entry) => entry?.source_path);
  if (new Set(entryPaths).size !== entryPaths.length || !same(entryPaths, byteSort(entryPaths))) {
    addCode(codes, 'FAIL_SOURCE_DIGEST');
  }
  if (!sameSet(entryPaths, sourcePaths)) addCode(codes, 'FAIL_REFERENCE_INTEGRITY');

  const entryByPath = new Map(entries.map((entry) => [entry?.source_path, entry]));
  for (const sourcePath of new Set(sourcePaths)) {
    if (!fileFacts.has(sourcePath)) {
      addCode(codes, 'FAIL_REFERENCE_INTEGRITY');
      continue;
    }
    const actual = sha256(fileFacts.get(sourcePath));
    if (entryByPath.get(sourcePath)?.content_sha256 !== actual) addCode(codes, 'FAIL_SOURCE_DIGEST');
  }
  for (const item of [...mappings, ...references]) {
    if (entryByPath.get(item?.source_path)?.content_sha256 !== item?.content_sha256) {
      addCode(codes, 'FAIL_SOURCE_DIGEST');
    }
  }

  const declarations = Array.isArray(pkg.visibility_declarations) ? pkg.visibility_declarations : [];
  const declarationsByID = new Map();
  for (const declaration of declarations) {
    if (declarationsByID.has(declaration?.logical_id)) addCode(codes, 'FAIL_VISIBILITY');
    declarationsByID.set(declaration?.logical_id, declaration);
  }
  if (!sameSet([...declarationsByID.keys()], allIDs)) addCode(codes, 'FAIL_VISIBILITY');
  for (const item of [...mappings, ...references]) {
    const id = item.logical_id ?? item.reference_id;
    const declaration = declarationsByID.get(id);
    if (!declaration || declaration.visibility_class !== item.visibility_class) {
      addCode(codes, 'FAIL_VISIBILITY');
      continue;
    }
    if (!sameSet(declaration.allowed_surfaces ?? [], VISIBILITY_SURFACES[item.visibility_class] ?? [])) {
      addCode(codes, 'FAIL_VISIBILITY');
    }
  }

  const itemByID = new Map([...mappings.map((item) => [item.logical_id, item]),
    ...references.map((item) => [item.reference_id, item])]);
  const capabilities = new Set(pkg.declared_capabilities ?? []);
  for (const entrypoint of pkg.entrypoints ?? []) {
    for (const [field, kind] of Object.entries(KIND_FIELDS)) {
      for (const id of entrypoint[field] ?? []) {
        if (itemByID.get(id)?.source_kind !== kind) addCode(codes, 'FAIL_MAPPING');
      }
    }
    for (const id of entrypoint.reference_ids ?? []) {
      if (!referenceIDs.includes(id)) addCode(codes, 'FAIL_MAPPING');
    }
    for (const capability of entrypoint.required_capabilities ?? []) {
      if (!capabilities.has(capability)) addCode(codes, 'FAIL_MAPPING');
    }
    const selected = [
      ...(entrypoint.scene_ids ?? []), ...(entrypoint.guide_ids ?? []),
      ...(entrypoint.rule_ids ?? []), ...(entrypoint.asset_ids ?? []),
      ...(entrypoint.reference_ids ?? []),
    ];
    const partition = [
      ...(entrypoint.player_visible_ids ?? []), ...(entrypoint.gm_only_ids ?? []),
      ...(entrypoint.system_internal_ids ?? []),
    ];
    if (!sameSet(selected, partition) || new Set(partition).size !== partition.length) {
      addCode(codes, 'FAIL_VISIBILITY');
    }
    for (const id of entrypoint.player_visible_ids ?? []) {
      if (itemByID.get(id)?.visibility_class !== 'PLAYER_VISIBLE') addCode(codes, 'FAIL_VISIBILITY');
    }
    for (const id of entrypoint.gm_only_ids ?? []) {
      if (itemByID.get(id)?.visibility_class !== 'GM_ONLY') addCode(codes, 'FAIL_VISIBILITY');
    }
    for (const id of entrypoint.system_internal_ids ?? []) {
      if (itemByID.get(id)?.visibility_class !== 'SYSTEM_INTERNAL') addCode(codes, 'FAIL_VISIBILITY');
    }
  }

  if (secretDetected(canonicalJSON(pkg)) || [...fileFacts.values()].some(secretDetected)) {
    addCode(codes, 'FAIL_SECRET');
  }
  return codes;
}

function validateAdapter(schema, input, pkg, packageBytes, manifest) {
  const codes = [];
  if (!isObject(input)) {
    addCode(codes, 'FAIL_SCHEMA');
    return codes;
  }
  if (input.adapter_contract_version !== '1.0.0' || input.schema_version !== '1.0.0' ||
      input.schema !== 'aipt.runtime-adapter-input/v1') addCode(codes, 'FAIL_UNSUPPORTED_VERSION');
  if (Object.hasOwn(input, 'cross_package_reference')) addCode(codes, 'FAIL_CROSS_PACKAGE_REFERENCE');
  schemaCodes(schema, input, codes);
  if (!pkg) {
    addCode(codes, 'FAIL_PACKAGE_BINDING');
    return codes;
  }

  const expectedBinding = {
    package_id: pkg.package_id,
    package_version: pkg.package_version,
    game_id: pkg.game_id,
    game_version: pkg.game_version,
    source_repository: pkg.source_repository,
    source_commit: pkg.source_commit,
    source_tree: pkg.source_tree,
    source_digest: pkg.source_digest,
    package_manifest_sha256: sha256(packageBytes),
  };
  if (!same(input.package_binding, expectedBinding)) addCode(codes, 'FAIL_PACKAGE_BINDING');

  const entrypoint = pkg.entrypoints.find((entry) => entry.test_unit_id === input.selected_test_unit);
  if (!entrypoint) {
    addCode(codes, 'FAIL_PACKAGE_BINDING');
    return codes;
  }
  const mappingIDs = [
    ...entrypoint.scene_ids, ...entrypoint.guide_ids, ...entrypoint.rule_ids, ...entrypoint.asset_ids,
  ];
  const allSelectedIDs = [...mappingIDs, ...entrypoint.reference_ids];
  const expectedMappings = pkg.mappings.filter((item) => mappingIDs.includes(item.logical_id))
    .map(({ logical_id, source_kind, source_path, content_sha256, visibility_class }) =>
      ({ logical_id, source_kind, source_path, content_sha256, visibility_class }))
    .sort((a, b) => a.logical_id.localeCompare(b.logical_id));
  const actualMappings = [...(input.resolved_mappings ?? [])].sort((a, b) =>
    String(a.logical_id).localeCompare(String(b.logical_id)));
  if (!same(actualMappings, expectedMappings)) addCode(codes, 'FAIL_PACKAGE_BINDING');

  const expectedVisibility = pkg.visibility_declarations.filter((item) =>
    allSelectedIDs.includes(item.logical_id)).sort((a, b) => a.logical_id.localeCompare(b.logical_id));
  const actualVisibility = [...(input.visibility_resolution ?? [])].sort((a, b) =>
    String(a.logical_id).localeCompare(String(b.logical_id)));
  if (!same(actualVisibility, expectedVisibility)) addCode(codes, 'FAIL_VISIBILITY');
  if (!sameSet(input.scenario_references ?? [], entrypoint.scene_ids) ||
      !sameSet(input.guide_references ?? [], entrypoint.guide_ids) ||
      !sameSet(input.rule_references ?? [], entrypoint.rule_ids) ||
      !sameSet(input.asset_references ?? [], entrypoint.asset_ids) ||
      !sameSet(input.declared_capabilities ?? [], pkg.declared_capabilities)) {
    addCode(codes, 'FAIL_PACKAGE_BINDING');
  }

  const boundary = input.evidence_boundary;
  if (!boundary || !sameSet(boundary.player_visible_source_ids ?? [], entrypoint.player_visible_ids) ||
      !sameSet(boundary.non_player_source_ids ?? [],
        [...entrypoint.gm_only_ids, ...entrypoint.system_internal_ids]) ||
      (boundary.player_visible_gm_only_source_ids ?? []).length !== 0) {
    addCode(codes, 'FAIL_VISIBILITY');
  }
  const visibilityByID = new Map(pkg.visibility_declarations.map((item) =>
    [item.logical_id, item.visibility_class]));
  for (const id of boundary?.player_visible_source_ids ?? []) {
    if (visibilityByID.get(id) !== 'PLAYER_VISIBLE') addCode(codes, 'FAIL_VISIBILITY');
  }

  const runBinding = input.provenance?.run_manifest;
  if (!runBinding || runBinding.manifest_id !== manifest.manifest_id ||
      runBinding.run_id !== manifest.run_id || runBinding.canonical_sha256 !== manifest.canonical_sha256) {
    addCode(codes, 'FAIL_B001_COMPATIBILITY');
  }
  const expectedGameSource = {
    repository: pkg.source_repository, commit: pkg.source_commit, tree: pkg.source_tree,
  };
  if (!same(runBinding?.game_source, expectedGameSource) ||
      !same(runBinding?.game_source, manifest.source.game) ||
      !same(runBinding?.aipt_source, manifest.source.aipt) ||
      runBinding?.ancestry?.run_id !== manifest.run_id) {
    addCode(codes, 'FAIL_B001_COMPATIBILITY');
  }
  const authority = input.provenance?.authority;
  if (!authority || authority.task_id !== pkg.compatibility.authority_task_id ||
      authority.authority_version !== pkg.compatibility.authority_version ||
      authority.commit !== pkg.compatibility.authority_commit ||
      authority.tree !== pkg.compatibility.authority_tree ||
      authority.registry_sha256 !== pkg.compatibility.authority_registry_sha256 ||
      authority.artifact_manifest_sha256 !== pkg.compatibility.authority_artifact_manifest_sha256) {
    addCode(codes, 'FAIL_PACKAGE_BINDING');
  }
  if (!sameSet(input.provenance?.mapping_logical_ids ?? [], allSelectedIDs)) {
    addCode(codes, 'FAIL_PACKAGE_BINDING');
  }
  const selectedPaths = [...pkg.mappings.filter((item) => mappingIDs.includes(item.logical_id)),
    ...pkg.references.filter((item) => entrypoint.reference_ids.includes(item.reference_id))]
    .map((item) => item.source_path);
  if (!sameSet(input.provenance?.source_paths ?? [], selectedPaths)) {
    addCode(codes, 'FAIL_PACKAGE_BINDING');
  }
  if (!hasValidBoundDigest(input, 'canonical_sha256')) addCode(codes, 'FAIL_PACKAGE_BINDING');
  if (secretDetected(canonicalJSON(input))) addCode(codes, 'FAIL_SECRET');
  return codes;
}

function genericFixtures() {
  const files = new Map([
    ['package/assets/control.json', Buffer.from('{"mode":"test"}\n')],
    ['package/guides/gm.md', Buffer.from('# GM guide\n')],
    ['package/references/safety.md', Buffer.from('# Safety reference\n')],
    ['package/rules/core.md', Buffer.from('# Rule reference\n')],
    ['package/scenes/start.md', Buffer.from('# Scene\n')],
  ]);
  const digest = (sourcePath) => sha256(files.get(sourcePath));
  let pkg = {
    schema: 'aipt.playtest-package/v1',
    schema_version: '1.0.0',
    mapping_version: '1.0.0',
    package_id: 'example/game-playtest',
    package_version: '1.0.0',
    game_id: 'example-game',
    game_version: '1.0.0',
    package_root: 'package',
    source_repository: 'example/game',
    source_commit: '3'.repeat(40),
    source_tree: '4'.repeat(40),
    source_digest: '0'.repeat(64),
    digest_scope: {
      algorithm: 'SHA-256',
      manifest_canonicalization: 'RFC8785-JCS',
      file_content_mode: 'GIT_BLOB_EXACT_BYTES_NO_NEWLINE_NORMALIZATION',
      path_order: 'UTF8_BYTE_LEX_ASC',
      symlink_policy: 'REJECT',
      unexpected_file_policy: 'UNREFERENCED_OUT_OF_SCOPE_REFERENCED_UNLISTED_REJECT',
      entries: byteSort([...files.keys()]).map((source_path) =>
        ({ source_path, content_sha256: digest(source_path) })),
    },
    adapter_contract_version: '1.0.0',
    entrypoints: [{
      test_unit_id: 'unit-1',
      scene_ids: ['scene-1'],
      guide_ids: ['guide-1'],
      rule_ids: ['rule-1'],
      asset_ids: ['control-1'],
      reference_ids: ['reference-1'],
      player_visible_ids: ['rule-1', 'scene-1'],
      gm_only_ids: ['guide-1', 'reference-1'],
      system_internal_ids: ['control-1'],
      required_capabilities: ['playtest.package/v1'],
    }],
    mappings: [
      { logical_id: 'control-1', source_kind: 'ASSET', source_path: 'package/assets/control.json', content_sha256: digest('package/assets/control.json'), visibility_class: 'SYSTEM_INTERNAL', depends_on: [] },
      { logical_id: 'guide-1', source_kind: 'GUIDE', source_path: 'package/guides/gm.md', content_sha256: digest('package/guides/gm.md'), visibility_class: 'GM_ONLY', depends_on: ['scene-1'] },
      { logical_id: 'rule-1', source_kind: 'RULE', source_path: 'package/rules/core.md', content_sha256: digest('package/rules/core.md'), visibility_class: 'PLAYER_VISIBLE', depends_on: [] },
      { logical_id: 'scene-1', source_kind: 'SCENE', source_path: 'package/scenes/start.md', content_sha256: digest('package/scenes/start.md'), visibility_class: 'PLAYER_VISIBLE', depends_on: ['rule-1'] },
    ],
    visibility_declarations: [
      { logical_id: 'control-1', visibility_class: 'SYSTEM_INTERNAL', allowed_surfaces: [...VISIBILITY_SURFACES.SYSTEM_INTERNAL] },
      { logical_id: 'guide-1', visibility_class: 'GM_ONLY', allowed_surfaces: [...VISIBILITY_SURFACES.GM_ONLY] },
      { logical_id: 'reference-1', visibility_class: 'GM_ONLY', allowed_surfaces: [...VISIBILITY_SURFACES.GM_ONLY] },
      { logical_id: 'rule-1', visibility_class: 'PLAYER_VISIBLE', allowed_surfaces: [...VISIBILITY_SURFACES.PLAYER_VISIBLE] },
      { logical_id: 'scene-1', visibility_class: 'PLAYER_VISIBLE', allowed_surfaces: [...VISIBILITY_SURFACES.PLAYER_VISIBLE] },
    ],
    declared_capabilities: ['playtest.package/v1'],
    references: [{
      reference_id: 'reference-1',
      source_path: 'package/references/safety.md',
      content_sha256: digest('package/references/safety.md'),
      visibility_class: 'GM_ONLY',
      media_type: 'text/markdown',
      required_by: ['guide-1'],
    }],
    compatibility: {
      test_plan_schema: 'aipt.test-plan/v1',
      run_manifest_schema: 'aipt.run-manifest/v1',
      campaign_hierarchy: 'CAMPAIGN_SUITE_CASE_RUN',
      attempt_internal_only: true,
      manifest_binding_model: 'B001_GAME_SOURCE_PLUS_ADAPTER_BINDING_V1',
      aipt_ancestry_commit: AIPT_BASE_COMMIT,
      aipt_ancestry_tree: AIPT_BASE_TREE,
      authority_task_id: TASK_ID,
      authority_version: AUTHORITY_VERSION,
      authority_commit: '5'.repeat(40),
      authority_tree: '6'.repeat(40),
      authority_registry_sha256: '7'.repeat(64),
      authority_artifact_manifest_sha256: '8'.repeat(64),
    },
  };
  pkg = bindPackage(pkg);
  const packageBytes = Buffer.from(`${JSON.stringify(pkg, null, 2)}\n`);

  const manifest = bindRunManifest({
    schema: 'aipt.run-manifest/v1', manifest_id: 'manifest-1', run_id: 'run-1',
    ancestry: { campaign_id: 'campaign-1', suite_id: 'suite-1', case_id: 'case-1' },
    run_type: 'RULE',
    source: {
      aipt: { repository: 'example/aipt', commit: '1'.repeat(40), tree: '2'.repeat(40) },
      game: { repository: pkg.source_repository, commit: pkg.source_commit, tree: pkg.source_tree },
    },
    model_assignments: [{ assignment_id: 'assignment-1', model_profile_id: 'profile-1' }],
    prompt_assets: [{ asset_id: 'prompt-1', sha256: '9'.repeat(64) }],
    seat_roster: [{ seat_id: 'gm', role_id: 'GM', model_assignment_id: 'assignment-1' }],
    budget: { policy_id: 'budget-1', limits_id: 'limits-1', max_input_tokens: 1000, max_output_tokens: 500, max_duration_seconds: 60 },
    evidence: { profile_id: 'evidence-1', config_id: 'evidence-config-1' },
    visibility_profile_id: 'AIPT_VISIBILITY_STANDARD_V1',
    safety_applicable: true,
    safety_profile_id: 'AIPT_SAFETY_STANDARD_V1',
    classification: 'QUALIFICATION',
    qualification_eligible: true,
  });
  const mappingIDs = ['control-1', 'guide-1', 'rule-1', 'scene-1'];
  const allIDs = [...mappingIDs, 'reference-1'];
  let adapter = {
    schema: 'aipt.runtime-adapter-input/v1',
    schema_version: '1.0.0',
    adapter_contract_version: '1.0.0',
    adapter_input_id: 'adapter-input-1',
    package_binding: {
      package_id: pkg.package_id, package_version: pkg.package_version,
      game_id: pkg.game_id, game_version: pkg.game_version,
      source_repository: pkg.source_repository, source_commit: pkg.source_commit,
      source_tree: pkg.source_tree, source_digest: pkg.source_digest,
      package_manifest_sha256: sha256(packageBytes),
    },
    selected_test_unit: 'unit-1',
    resolved_mappings: pkg.mappings.map(({ logical_id, source_kind, source_path, content_sha256, visibility_class }) =>
      ({ logical_id, source_kind, source_path, content_sha256, visibility_class }))
      .sort((a, b) => a.logical_id.localeCompare(b.logical_id)),
    visibility_resolution: pkg.visibility_declarations.map(clone)
      .sort((a, b) => a.logical_id.localeCompare(b.logical_id)),
    scenario_references: ['scene-1'],
    guide_references: ['guide-1'],
    rule_references: ['rule-1'],
    asset_references: ['control-1'],
    declared_capabilities: [...pkg.declared_capabilities],
    evidence_boundary: {
      player_visible_source_ids: ['rule-1', 'scene-1'],
      non_player_source_ids: ['control-1', 'guide-1', 'reference-1'],
      player_visible_gm_only_source_ids: [],
      visibility_proof: 'EXACT_CLASS_MEMBERSHIP_NO_GM_ONLY_LEAK',
    },
    provenance: {
      authority: {
        task_id: TASK_ID, authority_version: AUTHORITY_VERSION,
        commit: pkg.compatibility.authority_commit, tree: pkg.compatibility.authority_tree,
        registry_sha256: pkg.compatibility.authority_registry_sha256,
        artifact_manifest_sha256: pkg.compatibility.authority_artifact_manifest_sha256,
      },
      run_manifest: {
        schema: manifest.schema, manifest_id: manifest.manifest_id, run_id: manifest.run_id,
        canonical_sha256: manifest.canonical_sha256,
        ancestry: { ...manifest.ancestry, run_id: manifest.run_id },
        aipt_source: clone(manifest.source.aipt), game_source: clone(manifest.source.game),
      },
      mapping_logical_ids: allIDs,
      source_paths: byteSort([...files.keys()]),
    },
    canonical_sha256: '0'.repeat(64),
  };
  adapter = bindAdapter(adapter);
  return { files, pkg, packageBytes, manifest, adapter };
}

function testPlanFixture() {
  return {
    schema: 'aipt.test-plan/v1', plan_id: 'plan-1', campaigns: [{
      campaign_id: 'campaign-1', name: 'Campaign', suites: [{
        suite_id: 'suite-1', name: 'Suite', cases: [{
          case_id: 'case-1', name: 'Case', task_type: 'RULE', runs: [{
            run_id: 'run-1', run_type: 'RULE', manifest_id: 'manifest-1',
            attempt_policy: { scope: 'RUN_INTERNAL_ONLY', max_attempts: 3 },
          }],
        }],
      }],
    }],
  };
}

function mutationProbeResults(packageSchema, adapterSchema, testPlanSchema, runManifestSchema, migration) {
  const { files, pkg, packageBytes, manifest, adapter } = genericFixtures();
  const expectedSource = { repository: 'example/game', commit: '3'.repeat(40), tree: '4'.repeat(40) };
  const probes = [];
  const record = (id, codes) => probes.push({ id, codes });
  const packageProbe = (id, mutate, options = {}) => {
    let value = clone(pkg);
    const facts = new Map([...files].map(([key, data]) => [key, Buffer.from(data)]));
    mutate(value, facts);
    if (options.rebind) value = bindPackage(value);
    record(id, validatePackage(packageSchema, value, facts,
      options.expectedSource ?? expectedSource, options.loadedPackages ?? [value]));
  };
  const adapterProbe = (id, mutate, options = {}) => {
    let value = clone(adapter);
    mutate(value);
    if (options.rebind) value = bindAdapter(value);
    record(id, validateAdapter(adapterSchema, value,
      options.noPackage ? null : pkg, packageBytes, manifest));
  };

  record('N01', validatePackage(packageSchema, 'not-an-object', files, expectedSource));
  packageProbe('N02', (value) => { value.schema_version = '2.0.0'; }, { rebind: true });
  packageProbe('N03', (value) => { delete value.package_id; }, { rebind: true });
  packageProbe('N04', () => {}, { loadedPackages: [pkg, clone(pkg)] });
  packageProbe('N05', (value) => { value.package_version = 'v1'; }, { rebind: true });
  packageProbe('N06', (value) => { delete value.source_commit; }, { rebind: true });
  packageProbe('N07', () => {}, { expectedSource: { ...expectedSource, commit: 'a'.repeat(40) } });
  packageProbe('N08', () => {}, { expectedSource: { ...expectedSource, tree: 'b'.repeat(40) } });
  packageProbe('N09', (value) => { value.source_digest = 'f'.repeat(64); });
  packageProbe('N10', (_value, facts) => { facts.set('package/scenes/start.md', Buffer.from('# changed\n')); });
  packageProbe('N11', (value) => { value.mappings[1].logical_id = value.mappings[0].logical_id; }, { rebind: true });
  packageProbe('N12', (value) => { value.mappings[0].source_kind = 'UNKNOWN'; }, { rebind: true });
  packageProbe('N13', (value) => { value.mappings[0].depends_on = ['missing-id']; }, { rebind: true });
  packageProbe('N14', (value) => { value.mappings[0].source_path = '../escape'; }, { rebind: true });
  packageProbe('N15', (value) => { value.mappings[0].source_path = 'outside/control.json'; }, { rebind: true });
  packageProbe('N16', (_value, facts) => { facts.delete('package/scenes/start.md'); });
  packageProbe('N17', (value) => { value.mappings[0].content_sha256 = 'f'.repeat(64); }, { rebind: true });
  packageProbe('N18', (value) => { value.visibility_declarations = value.visibility_declarations.slice(1); }, { rebind: true });
  packageProbe('N19', (value) => { value.mappings[0].visibility_class = 'UNKNOWN'; }, { rebind: true });
  packageProbe('N20', (value) => {
    value.entrypoints[0].player_visible_ids = ['guide-1', 'rule-1', 'scene-1'];
    value.entrypoints[0].gm_only_ids = ['reference-1'];
  }, { rebind: true });
  adapterProbe('N21', (value) => { value.evidence_boundary.player_visible_source_ids.push('guide-1'); }, { rebind: true });
  packageProbe('N22', (value) => {
    value.entrypoints[0].player_visible_ids.push('control-1');
    value.entrypoints[0].system_internal_ids = [];
  }, { rebind: true });
  packageProbe('N23', (value, facts) => {
    const secretPath = 'package/assets/secret.env';
    const sensitiveName = ['api', 'key'].join('_');
    const syntheticValue = ['dsk', 'example-secret-value'].join('-');
    const content = Buffer.from(`${sensitiveName}=${syntheticValue}\n`);
    facts.set(secretPath, content);
    value.mappings[0].source_path = secretPath;
    value.mappings[0].content_sha256 = sha256(content);
    value.digest_scope.entries = value.digest_scope.entries.filter((entry) =>
      entry.source_path !== 'package/assets/control.json');
    value.digest_scope.entries.push({ source_path: secretPath, content_sha256: sha256(content) });
    value.digest_scope.entries.sort((a, b) => Buffer.compare(Buffer.from(a.source_path), Buffer.from(b.source_path)));
  }, { rebind: true });
  packageProbe('N24', (value) => { value.visibility_declarations[0].visibility_class = 'GM_ONLY'; }, { rebind: true });
  adapterProbe('N25', (value) => { value.adapter_contract_version = '2.0.0'; }, { rebind: true });
  adapterProbe('N26', (value) => { delete value.selected_test_unit; }, { rebind: true });
  adapterProbe('N27', () => {}, { noPackage: true });
  adapterProbe('N28', (value) => { value.cross_package_reference = { package_id: 'other/package' }; }, { rebind: true });
  adapterProbe('N29', (value) => { delete value.provenance.run_manifest; }, { rebind: true });
  adapterProbe('N30', (value) => { value.provenance.run_manifest.game_source.commit = 'a'.repeat(40); }, { rebind: true });
  packageProbe('N31', (value) => { value.source_commit = 'main'; }, { rebind: true });
  adapterProbe('N32', (value) => { delete value.provenance.source_paths; }, { rebind: true });

  const invalidHierarchy = testPlanFixture();
  delete invalidHierarchy.campaigns[0].suites;
  record('N33', validateInstance(testPlanSchema, invalidHierarchy).errors.length > 0
    ? ['FAIL_B001_REGRESSION'] : []);
  const externalAttempt = testPlanFixture();
  externalAttempt.campaigns[0].suites[0].cases[0].runs[0].attempts = [];
  record('N34', validateInstance(testPlanSchema, externalAttempt).errors.length > 0
    ? ['FAIL_B001_REGRESSION'] : []);
  const mutableManifest = clone(manifest);
  mutableManifest.source.game.commit = 'a'.repeat(40);
  record('N35', validateInstance(runManifestSchema, mutableManifest).errors.length === 0 &&
    !hasValidBoundDigest(mutableManifest, 'canonical_sha256') ? ['FAIL_B001_REGRESSION'] : []);

  const ledger = textFromMigrationSibling(migration, '000001_ledger.sql');
  const baseline = new Map([
    ['000001_ledger.sql', ledger],
    ['000002_playtest_queue.sql', migration],
  ]);
  const queueRegression = new Map([...baseline, ['000003_queue_other.sql', 'CREATE TABLE other_queue(id int);']]);
  record('N36', checkMigrationContract(queueRegression).length > 0 ? ['FAIL_B001_REGRESSION'] : []);
  const wipRegression = new Map(baseline);
  wipRegression.set('000002_playtest_queue.sql', migration.replace(
    'CREATE UNIQUE INDEX run_leases_one_active_formal_slot', 'CREATE INDEX run_leases_many_formal_slots'));
  record('N37', checkMigrationContract(wipRegression).length > 0 ? ['FAIL_B001_REGRESSION'] : []);
  const leaseRegression = new Map(baseline);
  leaseRegression.set('000002_playtest_queue.sql', migration.replaceAll('token_sha256', 'removed_token'));
  record('N38', checkMigrationContract(leaseRegression).length > 0 ? ['FAIL_B001_REGRESSION'] : []);
  const attemptRegression = new Map(baseline);
  attemptRegression.set('000002_playtest_queue.sql', migration.replace('AIPT_RUN_ATTEMPT_APPEND_ONLY', 'REMOVED'));
  record('N39', checkMigrationContract(attemptRegression).length > 0 ? ['FAIL_B001_REGRESSION'] : []);
  return probes;
}

let migrationRepoForProbe = null;
function textFromMigrationSibling(_migration, name) {
  return text(migrationRepoForProbe, `internal/storage/postgres/migrations/${name}`);
}

function changedPaths(repo, base = AIPT_BASE_COMMIT, target = 'HEAD') {
  const tracked = git(repo, ['diff', '--name-only', '--no-renames', base, target], { check: false });
  const untracked = target === 'HEAD'
    ? git(repo, ['ls-files', '--others', '--exclude-standard'], { check: false })
    : { status: 0, stdout: '' };
  const lines = (output) => output.status === 0 ? output.stdout.split('\n').filter(Boolean) : [];
  return sortedUnique([...lines(tracked), ...lines(untracked)]
    .filter((relative) => !relative.split('/').includes('node_modules')));
}

function commitFacts(repo, commit) {
  if (!/^[0-9a-f]{40}$/.test(commit ?? '')) return null;
  const parents = git(repo, ['show', '-s', '--format=%P', commit], { check: false });
  const tree = git(repo, ['rev-parse', `${commit}^{tree}`], { check: false });
  const subject = git(repo, ['show', '-s', '--format=%s', commit], { check: false });
  if (parents.status !== 0 || tree.status !== 0 || subject.status !== 0) return null;
  return {
    commit,
    parents: parents.stdout.trim().split(/\s+/).filter(Boolean),
    tree: tree.stdout.trim(),
    subject: subject.stdout.trim(),
  };
}

export function validateAuthorityLifecycleFacts(facts) {
  const problems = [];
  if (!LIFECYCLE_STATES.includes(facts.state)) problems.push('unknown Authority lifecycle state');
  if (facts.baseCommit !== AIPT_BASE_COMMIT || facts.baseTree !== AIPT_BASE_TREE) {
    problems.push('AIPT ancestry anchor commit/tree drifted');
  }
  if (facts.candidate?.commit !== AUTHORITY_CANDIDATE ||
      facts.candidate?.tree !== AUTHORITY_CANDIDATE_TREE ||
      !facts.candidateDescendsFromBase || !facts.candidateLinear ||
      facts.candidateMergeCount !== 0) {
    problems.push('approved Authority Candidate identity or zero-merge ancestry drifted');
  }
  if (!same(facts.candidateChangedPaths, [...AUTHORITY_ALLOWED_PATHS].sort())) {
    problems.push('Authority Candidate changed paths drifted from the frozen allowlist');
  }

  if (CANDIDATE_LIFECYCLE_STATES.has(facts.state)) {
    if (facts.branch !== AUTHORITY_BRANCH || facts.head !== AUTHORITY_CANDIDATE) {
      problems.push('Candidate lifecycle is not bound to the exact branch and approved Candidate identity');
    }
    if (facts.mergePresent || facts.postMergeVerified || facts.closed) {
      problems.push('Candidate lifecycle contains accepted merge, reverification or closeout state');
    }
    return problems;
  }

  if (HISTORICAL_LIFECYCLE_STATES.has(facts.state)) {
    if (!facts.mergePresent || facts.merge?.commit !== AUTHORITY_MERGE ||
        facts.merge?.tree !== AUTHORITY_CANDIDATE_TREE ||
        !same(facts.merge?.parents, AUTHORITY_MERGE_PARENTS) ||
        facts.merge?.subject !== AUTHORITY_MERGE_SUBJECT ||
        !facts.mergeTreeEqualsCandidate || !facts.mergeContainsOnlyCandidateTree ||
        !facts.headDescendsFromMerge) {
      problems.push('accepted Authority merge identity, parents, ancestry or tree preservation drifted');
    }
    if (facts.state === 'MERGED' && (facts.postMergeVerified || facts.closed)) {
      problems.push('MERGED state carries premature reverification or closeout');
    }
    if (facts.state === 'POST_MERGE_VERIFIED' && (!facts.postMergeVerified || facts.closed)) {
      problems.push('POST_MERGE_VERIFIED state lacks exact reverification or is prematurely closed');
    }
    if (facts.state === 'CLOSED' && (!facts.postMergeVerified || !facts.closed || !facts.closeoutValid)) {
      problems.push('CLOSED state lacks accepted reverification and closeout provenance');
    }
    return problems;
  }

  if (['PLANNED', 'AUTHORIZED', 'ACTIVE'].includes(facts.state) &&
      (facts.mergePresent || facts.postMergeVerified || facts.closed)) {
    problems.push('pre-Candidate lifecycle contains later-stage acceptance fields');
  }
  return problems;
}

function lifecycleRegressionChecks() {
  const base = {
    state: 'MERGED', baseCommit: AIPT_BASE_COMMIT, baseTree: AIPT_BASE_TREE,
    head: AUTHORITY_MERGE, branch: 'main',
    candidate: { commit: AUTHORITY_CANDIDATE, tree: AUTHORITY_CANDIDATE_TREE },
    candidateDescendsFromBase: true, candidateLinear: true, candidateMergeCount: 0,
    candidateChangedPaths: [...AUTHORITY_ALLOWED_PATHS].sort(),
    mergePresent: true,
    merge: {
      commit: AUTHORITY_MERGE, tree: AUTHORITY_CANDIDATE_TREE,
      parents: [...AUTHORITY_MERGE_PARENTS], subject: AUTHORITY_MERGE_SUBJECT,
    },
    mergeTreeEqualsCandidate: true, mergeContainsOnlyCandidateTree: true,
    headDescendsFromMerge: true, postMergeVerified: false, closed: false,
    closeoutValid: false,
  };
  const candidate = {
    ...clone(base), state: 'CANDIDATE_FROZEN', head: AUTHORITY_CANDIDATE,
    branch: AUTHORITY_BRANCH, mergePresent: false, merge: null,
    mergeTreeEqualsCandidate: false, mergeContainsOnlyCandidateTree: false,
    headDescendsFromMerge: false,
  };
  const postMerge = { ...clone(base), state: 'POST_MERGE_VERIFIED', postMergeVerified: true };
  const closed = { ...clone(postMerge), state: 'CLOSED', closed: true, closeoutValid: true };
  const cases = [
    ['F1-R01 valid Candidate branch', candidate, 'PASS'],
    ['F1-R02 valid no-ff Authority merge', base, 'PASS'],
    ['F1-R03 valid post-merge main', postMerge, 'PASS'],
    ['F1-R04 valid CLOSED historical Authority', closed, 'PASS'],
    ['F1-R05 wrong merge parent', { ...clone(base), merge: { ...clone(base.merge), parents: ['0'.repeat(40), AUTHORITY_CANDIDATE] } }, 'FAIL'],
    ['F1-R06 wrong Candidate identity', { ...clone(base), candidate: { ...clone(base.candidate), commit: '0'.repeat(40) } }, 'FAIL'],
    ['F1-R07 unauthorized extra content', { ...clone(base), mergeContainsOnlyCandidateTree: false }, 'FAIL'],
    ['F1-R08 Candidate tree drift', { ...clone(base), candidate: { ...clone(base.candidate), tree: '0'.repeat(40) } }, 'FAIL'],
    ['F1-R09 Authority artifact drift', { ...clone(base), candidateChangedPaths: [...base.candidateChangedPaths, 'internal/run/core.go'].sort() }, 'FAIL'],
    ['F1-R10 invalid lifecycle transition', { ...clone(base), state: 'MERGED', closed: true }, 'FAIL'],
    ['F1-R11 unrelated main merge', { ...clone(base), merge: { ...clone(base.merge), commit: '0'.repeat(40) } }, 'FAIL'],
    ['F1-R12 mutable/latest authority shortcut', { ...clone(base), candidate: { commit: 'f'.repeat(40), tree: AUTHORITY_CANDIDATE_TREE } }, 'FAIL'],
  ];
  return cases.map(([name, facts, expected]) => {
    const actual = validateAuthorityLifecycleFacts(facts).length === 0 ? 'PASS' : 'FAIL';
    return { name, expected, actual, matched: expected === actual };
  });
}

function collectAuthorityLifecycleFacts(repo, state = 'MERGED') {
  const baseTree = git(repo, ['rev-parse', `${AIPT_BASE_COMMIT}^{tree}`], { check: false });
  const head = git(repo, ['rev-parse', 'HEAD^{commit}'], { check: false }).stdout.trim();
  const branch = git(repo, ['symbolic-ref', '--short', 'HEAD'], { check: false });
  const candidate = commitFacts(repo, AUTHORITY_CANDIDATE);
  const merge = commitFacts(repo, AUTHORITY_MERGE);
  const candidateHistory = git(repo, ['rev-list', '--reverse', '--parents', `${AIPT_BASE_COMMIT}..${AUTHORITY_CANDIDATE}`], { check: false });
  let previous = AIPT_BASE_COMMIT;
  let candidateLinear = candidateHistory.status === 0 && candidateHistory.stdout.trim() !== '';
  for (const line of candidateHistory.stdout.split('\n').filter(Boolean)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length !== 2 || parts[1] !== previous) candidateLinear = false;
    previous = parts[0];
  }
  const candidateMerges = git(repo, ['rev-list', '--merges', `${AIPT_BASE_COMMIT}..${AUTHORITY_CANDIDATE}`], { check: false });
  const candidateDiff = git(repo, ['diff', '--name-only', '--no-renames', AIPT_BASE_COMMIT, AUTHORITY_CANDIDATE], { check: false });
  const mergeDiff = git(repo, ['diff', '--name-only', '--no-renames', `${AUTHORITY_MERGE}^1`, AUTHORITY_MERGE], { check: false });
  const headDescends = git(repo, ['merge-base', '--is-ancestor', AUTHORITY_MERGE, 'HEAD'], { check: false }).status === 0;
  const baseToCandidate = candidateDiff.status === 0 ? candidateDiff.stdout.split('\n').filter(Boolean).sort() : [];
  const firstParentToMerge = mergeDiff.status === 0 ? mergeDiff.stdout.split('\n').filter(Boolean).sort() : [];
  return {
    state,
    baseCommit: AIPT_BASE_COMMIT,
    baseTree: baseTree.status === 0 ? baseTree.stdout.trim() : null,
    head,
    branch: branch.status === 0 ? branch.stdout.trim() : null,
    candidate,
    candidateDescendsFromBase: git(repo, ['merge-base', '--is-ancestor', AIPT_BASE_COMMIT, AUTHORITY_CANDIDATE], { check: false }).status === 0,
    candidateLinear,
    candidateMergeCount: candidateMerges.status === 0 && candidateMerges.stdout.trim() !== ''
      ? candidateMerges.stdout.split('\n').filter(Boolean).length : 0,
    candidateChangedPaths: baseToCandidate,
    mergePresent: merge !== null,
    merge,
    mergeTreeEqualsCandidate: merge?.tree === candidate?.tree,
    mergeContainsOnlyCandidateTree: same(firstParentToMerge, baseToCandidate) && merge?.tree === candidate?.tree,
    headDescendsFromMerge: headDescends,
    postMergeVerified: state === 'POST_MERGE_VERIFIED' || state === 'CLOSED',
    closed: state === 'CLOSED',
    closeoutValid: state === 'CLOSED',
  };
}

function verifyGitLifecycle(repo, fail, ok, state = 'MERGED', bindGitHubExecutionIdentity = true) {
  const facts = collectAuthorityLifecycleFacts(repo, state);
  const problems = validateAuthorityLifecycleFacts(facts);
  for (const problem of problems) fail(problem);
  if (problems.length === 0) {
    ok(`${state} lifecycle verifies the immutable Candidate, accepted no-ff merge, ancestry and exact tree preservation`);
  }
  if (process.env.GITHUB_ACTIONS === 'true' && bindGitHubExecutionIdentity) {
    if (process.env.GITHUB_SHA !== facts.head) fail('GITHUB_SHA is not checked-out HEAD');
    else ok('GitHub execution identity is bound to checked-out HEAD');
  } else if (process.env.GITHUB_ACTIONS === 'true') {
    ok('GitHub execution identity is intentionally distinct from the exact detached verification target');
  }
  return facts;
}

function verifyB001Protection(repo, fail, ok) {
  const protectedPaths = [
    'schemas/testplan', 'schemas/run-manifest', 'internal/testplan',
    'internal/storage/postgres/migrations', 'internal/storage/postgres/queue.go',
    'internal/storage/postgres/queue_errors.go', 'internal/storage/postgres/queue_types.go',
    'internal/storage/postgres/queue_test.go', 'internal/storage/postgres/queue_integration_test.go',
  ];
  const diff = git(repo, ['diff', '--name-only', '--no-renames', AIPT_BASE_COMMIT, '--', ...protectedPaths], { check: false });
  if (diff.status !== 0 || diff.stdout.trim() !== '') fail('B001 protected schema/code/migration surface changed');
  else ok('B001 Test Plan, Run Manifest, queue/lease code and migrations are byte-identical to closeout');
  if (sha256(read(repo, MIGRATION_PATH)) !== MIGRATION_SHA256) fail('B001 queue migration SHA-256 drifted');
  else ok('B001 historical migration SHA-256 remains exact');
  const status = git(repo, ['diff', '--exit-code', AIPT_BASE_COMMIT, '--',
    'docs/authority/registry/project-status.json', 'docs/authority/registry/batch-graph.json'], { check: false });
  if (status.status !== 0) fail('B001 closeout status or batch graph changed');
  else ok('B001 closeout status remains NOT_STARTED/NOT_AUTHORIZED for implementation B000');
}

function verifyAuthorityShape(authority, fail, ok) {
  if (authority.schema !== 'aipt.public.batch-authority/v1' || authority.task_id !== TASK_ID ||
      authority.authority_version !== AUTHORITY_VERSION || authority.frozen_batch !== IMPLEMENTATION_TASK) {
    fail('machine authority identity/version is invalid');
  } else ok('machine authority identity/version is exact');
  if (authority.authority_task?.base_commit !== AIPT_BASE_COMMIT ||
      authority.authority_task?.base_tree !== AIPT_BASE_TREE ||
      authority.authority_task?.branch !== AUTHORITY_BRANCH ||
      authority.authority_task?.implementation_candidate !== false ||
      authority.authority_task?.merge_authorized !== false) {
    fail('authority task separation/base/merge boundary drifted');
  } else ok('authority task is distinct from the implementation task and merge remains unauthorized');
  if (authority.implementation_task?.task_id !== IMPLEMENTATION_TASK ||
      authority.implementation_task?.base_commit !== UNREGISTERED_COMMIT ||
      authority.implementation_task?.base_tree !== UNREGISTERED_TREE ||
      authority.implementation_task?.state !== 'PLANNED' ||
      authority.implementation_task?.authorized !== false ||
      authority.implementation_task?.started !== false) {
    fail('implementation task was started/authorized or its exact base drifted');
  } else ok('implementation task remains PLANNED, unauthorized and not started');
  if (B007_EXTERNAL_SERIAL_PREDECESSOR.closeout_commit !== UNREGISTERED_COMMIT ||
      B007_EXTERNAL_SERIAL_PREDECESSOR.closeout_tree !== UNREGISTERED_TREE ||
      authority.dependencies?.unregistered_source?.commit !== UNREGISTERED_COMMIT ||
      authority.dependencies?.unregistered_source?.tree !== UNREGISTERED_TREE) {
    fail('UNREGISTERED source identity is inconsistent with the immutable predecessor record');
  } else ok('UNREGISTERED source commit/tree agrees with immutable AIPT predecessor provenance');
  if (!same(authority.non_goals, NON_GOALS)) fail('non-goal inventory drifted');
  else ok(`all ${NON_GOALS.length} exact non-goals are frozen`);
  if (!same(authority.scope?.authority_task?.allowed_paths, AUTHORITY_ALLOWED_PATHS) ||
      !same(authority.scope?.implementation_task?.allowed_paths, IMPLEMENTATION_ALLOWED_PATHS) ||
      authority.scope?.authority_task?.default_write_policy !== 'DENY' ||
      authority.scope?.implementation_task?.default_write_policy !== 'DENY') {
    fail('authority or implementation closed write scope drifted');
  } else ok('authority and implementation path policies are exact default-deny allowlists');
  const paths = [...(authority.scope?.authority_task?.allowed_paths ?? []),
    ...(authority.scope?.implementation_task?.allowed_paths ?? [])];
  if (paths.some((item) => typeof item !== 'string' || item.includes('*'))) fail('allowed path contains wildcard authority');
  else ok('allowed paths contain no wildcard authority');

  const tests = authority.negative_tests ?? [];
  const expectedTests = NEGATIVE_NAMES.map((name, index) => ({
    id: `N${String(index + 1).padStart(2, '0')}`, name, expected: EXPECTED_PROBE_CODES[index],
  }));
  if (!same(tests, expectedTests)) fail('N01-N39 machine negative-test inventory drifted');
  else ok('exact N01-N39 negative-test inventory and expected results frozen');
  if (!same(authority.lifecycle?.states, LIFECYCLE_STATES)) fail('implementation lifecycle state inventory drifted');
  const transitions = authority.lifecycle?.transitions ?? [];
  const transitionKeys = transitions.map((entry) => `${entry.from}->${entry.to}`);
  if (new Set(transitionKeys).size !== transitionKeys.length || transitions.some((entry) =>
    !LIFECYCLE_STATES.includes(entry.from) || !LIFECYCLE_STATES.includes(entry.to) ||
    typeof entry.requires !== 'string' || entry.requires.length === 0) ||
    authority.lifecycle?.unlisted_transition !== 'REJECT' ||
    authority.lifecycle?.closed_state_terminal !== true || authority.lifecycle?.fail_state_terminal !== true) {
    fail('lifecycle transition graph is invalid or fail-open');
  } else ok(`lifecycle has ${transitions.length} unique valid transitions and rejects every unlisted transition`);
  if ((authority.deliverables ?? []).length !== 10 ||
      !same(authority.deliverables.map((item) => item.id),
        Array.from({ length: 10 }, (_, index) => `D${index + 1}`))) {
    fail('D1-D10 deliverable inventory drifted');
  } else ok('D1-D10 deliverable inventory frozen');
  if ((authority.gap_matrix ?? []).length !== 13 ||
      authority.gap_matrix.some((entry) => entry.sufficient !== false)) {
    fail('13-item recovered authority gap matrix is incomplete');
  } else ok('all 13 recovered authority gaps have explicit freeze actions');
  if (authority.runtime_boundaries?.run_core_implemented !== false ||
      authority.runtime_boundaries?.agent_orchestration_implemented !== false ||
      authority.runtime_boundaries?.real_model_gateway_implemented !== false ||
      authority.runtime_boundaries?.real_model_calls !== 0 ||
      authority.runtime_boundaries?.real_playtest_executed !== false ||
      authority.runtime_boundaries?.business_implementation_started !== false) {
    fail('runtime/business boundary was crossed');
  } else ok('zero runtime, orchestration, model-call, playtest and business implementation boundary preserved');
}

function verifyNoPlaceholders(repo, authority, fail, ok) {
  const targets = [AUTHORITY_PATH, HUMAN_PATH, PACKAGE_SCHEMA_PATH, ADAPTER_SCHEMA_PATH];
  const prohibited = /\b(?:TBD|TODO)\b|\blater\b|\bas needed\b|\betc\.\b|\bappropriate\b|\brelevant files\b|\breasonable validation\b/i;
  const hit = targets.find((relative) => prohibited.test(text(repo, relative)));
  if (hit) fail(`unresolved or ambiguous execution placeholder appears in ${hit}`);
  else ok('authority artifacts contain no unresolved execution placeholders');
  if (JSON.stringify(authority).includes('**')) fail('machine authority contains globstar ambiguity');
  else ok('machine authority contains no globstar expression');
}

function gitBlob(repo, commit, relative) {
  const cp = git(repo, ['show', `${commit}:${relative}`], { check: false });
  return cp.status === 0 ? Buffer.from(cp.stdout, 'utf8') : null;
}

function readSupersessionRecords(repo) {
  const directory = path.join(repo, SUPERSESSION_DIRECTORY);
  if (!fs.existsSync(directory)) return [];
  const entries = fs.readdirSync(directory)
    .filter((name) => name.endsWith('.json'))
    .sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  return entries.map((name) => readJSON(repo, `${SUPERSESSION_DIRECTORY}/${name}`));
}

function verifyAcceptedAmendment(repo, fail, ok) {
  let closeout;
  try {
    closeout = readJSON(repo, AMENDMENT_CLOSEOUT_PATH);
  } catch (error) {
    fail(`accepted Amendment closeout unreadable: ${error.message}`);
    return false;
  }
  const candidate = commitFacts(repo, AMENDMENT_CANDIDATE);
  const merge = commitFacts(repo, AMENDMENT_MERGE);
  const closeoutCommit = commitFacts(repo, AMENDMENT_CLOSEOUT);
  const valid = closeout?.amendment_id === AMENDMENT_ID &&
    closeout?.accepted_identity?.candidate_commit === AMENDMENT_CANDIDATE &&
    closeout?.accepted_identity?.candidate_tree === AMENDMENT_CANDIDATE_TREE &&
    closeout?.accepted_identity?.merge_commit === AMENDMENT_MERGE &&
    closeout?.accepted_identity?.merge_tree === AMENDMENT_CANDIDATE_TREE &&
    same(closeout?.accepted_identity?.merge_parents, [AUTHORITY_MERGE, AMENDMENT_CANDIDATE]) &&
    closeout?.post_merge_verification?.effective_authority_resolution === 'PASS' &&
    closeout?.bootstrap_permission?.expired_after_this_transition === true &&
    candidate?.tree === AMENDMENT_CANDIDATE_TREE &&
    merge?.tree === AMENDMENT_CANDIDATE_TREE &&
    same(merge?.parents, [AUTHORITY_MERGE, AMENDMENT_CANDIDATE]) &&
    closeoutCommit?.parents?.length === 1 && closeoutCommit.parents[0] === AMENDMENT_MERGE &&
    git(repo, ['merge-base', '--is-ancestor', AMENDMENT_CLOSEOUT, 'HEAD'], { check: false }).status === 0;
  if (!valid) fail('accepted Amendment R1 Candidate/merge/closeout provenance drifted');
  else ok('accepted Amendment R1 exact Candidate, merge, closeout and expired bootstrap provenance verified');
  return valid;
}

function resolveValidatorIdentity(repo, fail, ok) {
  const current = sha256(read(repo, VALIDATOR_PATH));
  const records = readSupersessionRecords(repo)
    .filter((record) => record.role === 'AUTHORITY_VALIDATOR_IDENTITY');
  if (current === ORIGINAL_VALIDATOR_SHA256 && records.length === 0) {
    ok('current Authority validator is the original frozen identity');
    return { current, records, superseded: false };
  }
  if (records.length !== 1) {
    fail(`Authority validator identity changed without one unambiguous supersession link (found ${records.length})`);
    return { current, records, superseded: true };
  }
  const record = records[0];
  const acceptance = record.amendment_acceptance;
  const repairCommit = commitFacts(repo, record.repair_candidate_commit);
  const requiredConstraints = [
    'SUPPORT_CANDIDATE_MERGED_POST_MERGE_CLOSED_TOPOLOGY',
    'PRESERVE_ARTIFACT_HASH_VALIDATION',
    'PRESERVE_ANCESTRY_VALIDATION',
    'PRESERVE_CANDIDATE_IDENTITY_VALIDATION',
    'PRESERVE_SCOPE_VALIDATION',
    'PRESERVE_NEGATIVE_LIFECYCLE_CHECKS',
    'REJECT_UNAUTHORIZED_COMMITS',
    'REJECT_ARTIFACT_DRIFT',
    'REJECT_ILLEGAL_LIFECYCLE_TRANSITIONS',
  ];
  const valid = record.schema === 'aipt.public.authority-validator-supersession/v1' &&
    record.chain_sequence === 1 && record.predecessor_record_id === null &&
    record.path === VALIDATOR_PATH && record.old_sha256 === ORIGINAL_VALIDATOR_SHA256 &&
    record.new_sha256 === current && record.amendment_id === AMENDMENT_ID &&
    record.repair_task_id === REPAIR_TASK_ID &&
    requiredConstraints.every((constraint) => record.semantic_constraints?.includes(constraint)) &&
    acceptance?.accepted === true && acceptance?.candidate_commit === AMENDMENT_CANDIDATE &&
    acceptance?.candidate_tree === AMENDMENT_CANDIDATE_TREE && acceptance?.merge_commit === AMENDMENT_MERGE &&
    acceptance?.merge_tree === AMENDMENT_CANDIDATE_TREE &&
    same(acceptance?.merge_parents, [AUTHORITY_MERGE, AMENDMENT_CANDIDATE]) &&
    ['CANDIDATE_FROZEN', 'ACCEPTED'].includes(record.repair_acceptance?.state) &&
    repairCommit !== null &&
    git(repo, ['merge-base', '--is-ancestor', AMENDMENT_CLOSEOUT, record.repair_candidate_commit], { check: false }).status === 0 &&
    git(repo, ['merge-base', '--is-ancestor', record.repair_candidate_commit, 'HEAD'], { check: false }).status === 0 &&
    sha256(gitBlob(repo, record.repair_candidate_commit, VALIDATOR_PATH) ?? Buffer.alloc(0)) === current &&
    record.provenance?.original_identity_preserved === true;
  if (!valid) fail('Authority validator supersession provenance, chain, hash or semantic constraints are invalid');
  else ok('original validator identity remains historical and one explicit staged/accepted supersession resolves current bytes');
  return { current, records, superseded: true };
}

function verifyArtifacts(repo, definitionRepo, manifest, validatorIdentity, fail, ok) {
  const expectedPaths = [HUMAN_PATH, AUTHORITY_PATH, PACKAGE_SCHEMA_PATH, ADAPTER_SCHEMA_PATH, VALIDATOR_PATH];
  if (manifest?.schema !== 'aipt.public.authority-artifacts/v1' || manifest?.task_id !== TASK_ID ||
      manifest?.authority_version !== AUTHORITY_VERSION || manifest?.hash_algorithm !== 'SHA-256' ||
      !same(manifest?.artifacts?.map((item) => item.path), expectedPaths) ||
      manifest?.self_hash_excluded !== true || manifest?.candidate_git_identity_embedded !== false) {
    fail('authority artifact hash manifest shape/inventory drifted');
    return;
  }
  let matched = 0;
  for (const artifact of manifest.artifacts) {
    const candidateBlob = gitBlob(repo, AUTHORITY_CANDIDATE, artifact.path);
    const mergeBlob = gitBlob(repo, AUTHORITY_MERGE, artifact.path);
    const historicalMatch = candidateBlob !== null && mergeBlob !== null &&
      artifact.sha256 === sha256(candidateBlob) && artifact.sha256 === sha256(mergeBlob);
    const currentMatch = artifact.path === VALIDATOR_PATH
      ? artifact.sha256 === ORIGINAL_VALIDATOR_SHA256 &&
        (validatorIdentity.current === ORIGINAL_VALIDATOR_SHA256 || validatorIdentity.superseded)
      : artifact.sha256 === sha256(read(definitionRepo, artifact.path));
    if (historicalMatch && currentMatch && typeof artifact.role === 'string' && artifact.role.length > 0) {
      matched += 1;
    } else fail(`historical/current artifact SHA-256 or role mismatch: ${artifact.path}`);
  }
  if (matched === expectedPaths.length) {
    ok(`all ${matched} immutable Authority artifacts reconstruct at Candidate and merge; superseded validator history is preserved`);
  }
}

function runImpl(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push(`ok: ${message}`);
  const fail = (message) => { pass = false; details.push(`FAIL: ${message}`); };
  const definitionRepo = ctx.definitionRepo ?? ctx.repo;
  const head = git(ctx.repo, ['rev-parse', 'HEAD^{commit}'], { check: false }).stdout.trim();
  const branch = git(ctx.repo, ['symbolic-ref', '--short', 'HEAD'], { check: false });
  const lifecycleState = head === AUTHORITY_CANDIDATE && branch.status === 0 &&
    branch.stdout.trim() === AUTHORITY_BRANCH ? 'CANDIDATE_FROZEN' : 'MERGED';
  let authority, artifactManifest, packageSchema, adapterSchema, testPlanSchema, runManifestSchema, migration;
  try {
    authority = readJSON(ctx.repo, AUTHORITY_PATH);
    artifactManifest = readJSON(ctx.repo, ARTIFACT_PATH);
    packageSchema = readJSON(ctx.repo, PACKAGE_SCHEMA_PATH);
    adapterSchema = readJSON(ctx.repo, ADAPTER_SCHEMA_PATH);
    testPlanSchema = readJSON(ctx.repo, TEST_PLAN_SCHEMA_PATH);
    runManifestSchema = readJSON(ctx.repo, RUN_MANIFEST_SCHEMA_PATH);
    migration = text(ctx.repo, MIGRATION_PATH);
  } catch (error) {
    fail(`authority input unreadable: ${error.message}`);
    return { result: 'FAIL', details, negative_probes: 'NOT_RUN' };
  }

  const lifecycleFacts = verifyGitLifecycle(
    ctx.repo, fail, ok, lifecycleState, ctx.bindGitHubExecutionIdentity !== false,
  );
  if (HISTORICAL_LIFECYCLE_STATES.has(lifecycleState)) verifyAcceptedAmendment(definitionRepo, fail, ok);
  const validatorIdentity = resolveValidatorIdentity(definitionRepo, fail, ok);
  verifyB001Protection(ctx.repo, fail, ok);
  verifyAuthorityShape(authority, fail, ok);
  verifyNoPlaceholders(ctx.repo, authority, fail, ok);

  const actualChanged = changedPaths(ctx.repo, AIPT_BASE_COMMIT, AUTHORITY_CANDIDATE);
  if (!same(actualChanged, [...AUTHORITY_ALLOWED_PATHS].sort())) {
    fail(`authority candidate path set drifted: ${JSON.stringify(actualChanged)}`);
  } else ok(`authority Candidate changes exactly ${actualChanged.length} frozen governance paths`);

  for (const [label, schema] of [['Playtest Package', packageSchema], ['Runtime Adapter Input', adapterSchema]]) {
    const errors = checkSchemaDocument(schema).errors;
    if (errors.length > 0) errors.forEach((error) => fail(`${label} schema: ${error}`));
    else ok(`${label} schema uses only the supported fail-closed JSON Schema subset`);
  }
  const schemaText = `${text(ctx.repo, PACKAGE_SCHEMA_PATH)}\n${text(ctx.repo, ADAPTER_SCHEMA_PATH)}`;
  if (/UNREGISTERED|zyc14588\/UNREGISTERED|if\s*\([^)]*game/i.test(schemaText)) {
    fail('AIPT-side contract schema contains a game-specific literal or branch');
  } else ok('AIPT-side schemas are general-purpose and contain no game-specific branch/literal');

  const fixtures = genericFixtures();
  const expectedSource = { repository: 'example/game', commit: '3'.repeat(40), tree: '4'.repeat(40) };
  const packageCodes = validatePackage(packageSchema, fixtures.pkg, fixtures.files, expectedSource);
  if (packageCodes.length !== 0) fail(`valid generic package rejected: ${packageCodes.join(',')}`);
  else ok('valid generic package passes schema, identity, digest, mapping, reference, visibility and secret checks');
  const adapterCodes = validateAdapter(adapterSchema, fixtures.adapter, fixtures.pkg,
    fixtures.packageBytes, fixtures.manifest);
  if (adapterCodes.length !== 0) fail(`valid generic adapter input rejected: ${adapterCodes.join(',')}`);
  else ok('valid generic adapter input binds package, visibility, provenance and immutable B001 Run Manifest source');
  if (validateInstance(testPlanSchema, testPlanFixture()).errors.length !== 0 ||
      validateInstance(runManifestSchema, fixtures.manifest).errors.length !== 0 ||
      !hasValidBoundDigest(fixtures.manifest, 'canonical_sha256')) {
    fail('valid B001 compatibility fixture rejected');
  } else ok('B001 Campaign/Suite/Case/Run and immutable Run Manifest compatibility fixture passes');

  const migrationFiles = new Map([
    ['000001_ledger.sql', text(ctx.repo, 'internal/storage/postgres/migrations/000001_ledger.sql')],
    ['000002_playtest_queue.sql', migration],
  ]);
  if (checkMigrationContract(migrationFiles).length !== 0 || sha256(Buffer.from(migration)) !== MIGRATION_SHA256) {
    fail('B001 migration/queue/lease/WIP1/Attempt baseline failed');
  } else ok('B001 PostgreSQL queue/lease/WIP1/append-only Attempt baseline passes');

  migrationRepoForProbe = ctx.repo;
  const probes = mutationProbeResults(packageSchema, adapterSchema, testPlanSchema, runManifestSchema, migration);
  migrationRepoForProbe = null;
  let probeMatches = 0;
  for (let index = 0; index < probes.length; index += 1) {
    const expectedID = `N${String(index + 1).padStart(2, '0')}`;
    const expectedCode = EXPECTED_PROBE_CODES[index];
    const probe = probes[index];
    if (probe.id === expectedID && probe.codes.includes(expectedCode)) probeMatches += 1;
    else fail(`${expectedID} expected ${expectedCode}, got ${JSON.stringify(probe.codes)}`);
  }
  if (probes.length === 39 && probeMatches === 39) ok('all N01-N39 generic contract and B001 regression probes reject with their frozen result class');
  else if (probes.length !== 39) fail(`negative probe implementation count is ${probes.length}, expected 39`);

  verifyArtifacts(ctx.repo, definitionRepo, artifactManifest, validatorIdentity, fail, ok);

  const lifecycleProbes = lifecycleRegressionChecks();
  for (const probe of lifecycleProbes) {
    if (!probe.matched) fail(`${probe.name} expected ${probe.expected}, got ${probe.actual}`);
  }
  if (lifecycleProbes.every((probe) => probe.matched)) {
    ok(`all ${lifecycleProbes.length} F1 lifecycle/topology/identity regression probes matched`);
  }

  const index = text(definitionRepo, 'docs/authority/README.md');
  const packageJSON = readJSON(definitionRepo, 'package.json');
  const aggregate = text(definitionRepo, 'scripts/ci/run-checks.mjs');
  const workflow = text(definitionRepo, '.github/workflows/ci.yml');
  for (const [label, condition] of [
    ['authority index', index.includes('unregistered-aipt-p1-b000-authority.json') && index.includes('UNREGISTERED_AIPT_P1_B000_AUTHORITY.md')],
    ['package command', packageJSON.scripts?.['check:p1-b000-authority'] === `node ${VALIDATOR_PATH}`],
    ['aggregate import/call', aggregate.includes("import { run as runP1B000Authority }") && aggregate.includes('runP1B000Authority(ctx)')],
    ['remote CI focused command', workflow.includes('run: pnpm run check:p1-b000-authority')],
  ]) {
    if (condition) ok(`${label} wiring present`); else fail(`${label} wiring missing`);
  }

  return {
    result: pass ? 'PASS' : 'FAIL',
    details,
    task_id: TASK_ID,
    authority_version: AUTHORITY_VERSION,
    frozen_batch: IMPLEMENTATION_TASK,
    aipt_base_commit: AIPT_BASE_COMMIT,
    aipt_base_tree: AIPT_BASE_TREE,
    unregistered_source_commit: UNREGISTERED_COMMIT,
    unregistered_source_tree: UNREGISTERED_TREE,
    lifecycle_phase: lifecycleState,
    authority_candidate_commit: lifecycleFacts.candidate?.commit ?? null,
    authority_merge_commit: lifecycleFacts.merge?.commit ?? null,
    changed_paths: actualChanged,
    negative_probes: probes.length === 39 && probeMatches === 39 ? 'PASS' : 'FAIL',
    negative_probe_count: probes.length,
    lifecycle_regression: lifecycleProbes.every((probe) => probe.matched) ? 'PASS' : 'FAIL',
    lifecycle_regression_count: lifecycleProbes.length,
    original_validator_sha256: ORIGINAL_VALIDATOR_SHA256,
    effective_validator_sha256: validatorIdentity.current,
    b001_regression: pass ? 'PASS' : 'FAIL',
    real_model_calls: 0,
    real_playtest_executed: false,
    implementation_started: false,
    merge_authorized: false,
  };
}

export function run(ctx) {
  try {
    return runImpl(ctx);
  } catch (error) {
    return {
      result: 'FAIL',
      details: [`FAIL: structured Authority validator error: ${error.message}`],
      task_id: TASK_ID,
      negative_probes: 'NOT_RUN',
      uncaught_validator_errors: 0,
      real_model_calls: 0,
      real_playtest_executed: false,
      implementation_started: false,
      merge_authorized: false,
    };
  }
}

runAsMain(import.meta.url, 'p1-b000-authority', run);
