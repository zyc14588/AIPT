#!/usr/bin/env node
// AIPT-MVP-B004 lifecycle-aware governed model/Harness gateway gate.
// Standard library only. Public CI executes only synthetic fixtures and makes
// zero provider/model calls. Candidate identity is derived from the exact
// authorized Base and topology; legal successors never impersonate the task
// branch.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { git, runAsMain } from '../lib/cli.mjs';
import { checkSchemaDocument, validateInstance } from '../lib/json-schema.mjs';
import { PUBLICATION_HYGIENE_POLICY, runPublicationHygiene } from '../lib/publication-hygiene.mjs';

const TASK_ID = 'AIPT-MVP-B004';
const BRANCH = `task/${TASK_ID}`;
const BASE_COMMIT = '98591311c4872cdc5f091e23fba1acb500ad4599';
const BASE_TREE = 'a02ffea60c59d7187975f175875fa108c78d3cac';
const B003_CANDIDATE = '4f2979f4495e3d78393e9f9ec1978308a7fb10b9';
const B003_MERGE = 'beb7c70738b1f876845d68bec8e20166ab3eac10';
const B003_MERGE_CI = 33264083089;
const B003_CLOSEOUT_CI = 33264649945;
const HARNESS_COMMIT = '141eb6fef83422698aef7a981029e843e8161534';
const HARNESS_RELEASE = 'dsh-v0.1.0-rc.8';
const HARNESS_SOURCE_SHA256 = 'fda21471d83772bbbf2019500fa4a23e6238d0cd304a409cc54630153ad07eba';
const HARNESS_CAPABILITY_SHA256 = 'c33bc33f7cc62c172897a6ea6ba96d56c422dfbea01ab135d0c41dd1c2d09940';
const HARNESS_RUNTIME_CLOSURE_SHA256 = 'e4cb5990bc7f42337cbc2a734c0afe12d3b9a2aeb0061f5dcb5c9dded8d343db';
const ISOLATION_IDENTITY = 'AIPT_LINUX_USER_NETNS_SUPERVISOR_V1';
const ISOLATION_HELPER_REFERENCE = 'aipt-runtime-isolator-go1.26.6-linux-amd64';
const ISOLATION_HELPER_SHA256 = '1bba082e39f213f85c213c7dcdadd85e610d2b64dcf39214d39d44b1c5e36d3d';
const GGUF_REFERENCE = 'GGUF-04';
const GGUF_SHA256 = '31756fca94beca71ea4b8706d6fdc896dab2a3c6376ab0c1863b98512a24f8d6';
const REMOTE_EVIDENCE = 'docs/model-certification/remote-deepseek-controlled-real-02.json';
const LOCAL_EVIDENCE = 'docs/model-certification/local-llamacpp-controlled-real-02.json';
const SUPERSEDED_REMOTE_EVIDENCE = 'docs/model-certification/remote-deepseek-controlled-real-01.json';
const SUPERSEDED_LOCAL_EVIDENCE = 'docs/model-certification/local-llamacpp-controlled-real-01.json';
const HARNESS_CAPABILITIES = 'docs/model-certification/harness-01-capabilities.json';
const GGUF_REGISTRATION = 'docs/model-certification/gguf-04-registration.json';
const LLAMACPP_REGISTRATION = 'docs/model-certification/llamacpp-01-registration.json';
const SECURITY_REPRODUCTIONS = 'docs/model-certification/b004-security-repair-reproductions.json';
const PUBLICATION_DETECTOR_IDENTITY = 'aipt.publication-hygiene-detectors/v1';
const REQUIRED_PUBLICATION_DETECTORS = Object.freeze([
  'credential_api_key_material',
  'bearer_token_material',
  'environment_secret_values',
  'private_prompt_material',
  'private_asset_locator_material',
  'forbidden_absolute_local_path',
  'resolved_credential_reference',
]);
const OBSERVED_OWNER_LOCAL_BRIDGE_COMMIT = 'cd5ef8148158c3a752a658978873241fdf8e2bbc';
const OBSERVED_OWNER_LOCAL_BRIDGE_RELEASE = '0.1.2-alpha.1';
const RECORD_ROOT = 'docs/authority/registry/authority-lifecycle/records/aipt-mvp-b004';
const RECORD_PATHS = Object.freeze([
  `${RECORD_ROOT}/001-merged.json`,
  `${RECORD_ROOT}/002-post-merge-verified.json`,
  `${RECORD_ROOT}/003-closed.json`,
]);
const RECORD_IDS = Object.freeze([
  `${TASK_ID}-LIFECYCLE-001-MERGED`,
  `${TASK_ID}-LIFECYCLE-002-POST-MERGE-VERIFIED`,
  `${TASK_ID}-LIFECYCLE-003-CLOSED`,
]);
const RECORD_EVENTS = Object.freeze(['MERGED', 'POST_MERGE_VERIFIED', 'CLOSED']);
const RECORD_SCHEMA = 'schemas/authority-lifecycle/v1/aipt-authority-lifecycle-record.schema.json';

const SCHEMA_PATHS = Object.freeze([
  'schemas/model/v1/aipt-sampling-profile.schema.json',
  'schemas/model/v1/aipt-model-profile.schema.json',
  'schemas/model/v1/aipt-model-execution-tuple.schema.json',
  'schemas/model/v1/aipt-model-certification.schema.json',
  'schemas/model/v1/aipt-model-manifest-binding.schema.json',
  'schemas/model/v1/aipt-harness-route.schema.json',
]);

const REQUIRED_GO = Object.freeze([
  'internal/modelgateway/adapter_process.go',
  'internal/modelgateway/audit.go',
  'internal/modelgateway/break_glass.go',
  'internal/modelgateway/certification.go',
  'internal/modelgateway/context.go',
  'internal/modelgateway/controlled_certification.go',
  'internal/modelgateway/credential.go',
  'internal/modelgateway/doc.go',
  'internal/modelgateway/errors.go',
  'internal/modelgateway/gateway.go',
  'internal/modelgateway/local.go',
  'internal/modelgateway/local_isolation.go',
  'internal/modelgateway/local_listener.go',
  'internal/modelgateway/registry.go',
  'internal/modelgateway/runtime.go',
  'internal/modelgateway/types.go',
  'internal/modelgateway/validation.go',
  'internal/modelgateway/verified_asset.go',
  'internal/modelgateway/context_capability_test.go',
  'internal/modelgateway/audit_postgres_integration_test.go',
  'internal/modelgateway/break_glass_test.go',
  'internal/modelgateway/controlled_certification_test.go',
  'internal/modelgateway/contracts_negative_test.go',
  'internal/modelgateway/credential_test.go',
  'internal/modelgateway/fixtures_test.go',
  'internal/modelgateway/gateway_negative_test.go',
  'internal/modelgateway/local_process_test.go',
  'internal/modelgateway/cmd/aipt-model-certify/main.go',
  'internal/modelgateway/cmd/aipt-runtime-isolator/main.go',
]);

const REQUIRED_EXACT = new Set([
  '.github/workflows/ci.yml',
  'cmd/aipt/command_test.go',
  'README.md',
  'docs/architecture/README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/milestones/MVP.md',
  'docs/runtime/README.md',
  'docs/security/README.md',
  'docs/test-model/README.md',
  HARNESS_CAPABILITIES,
  GGUF_REGISTRATION,
  LLAMACPP_REGISTRATION,
  REMOTE_EVIDENCE,
  LOCAL_EVIDENCE,
  SUPERSEDED_REMOTE_EVIDENCE,
  SUPERSEDED_LOCAL_EVIDENCE,
  SECURITY_REPRODUCTIONS,
  'internal/launcher/dependencies.go',
  'internal/launcher/doc.go',
  'internal/launcher/gates.go',
  'internal/launcher/launcher.go',
  'internal/launcher/launcher_integration_test.go',
  'internal/launcher/launcher_test.go',
  'internal/evidence/export_test.go',
	'internal/evidence/export.go',
	'internal/evidence/postgres.go',
	'internal/evidence/postgres_test.go',
	'internal/evidence/verify.go',
	'internal/storage/postgres/verify_bounded.go',
	'internal/storage/postgres/verify_bounded_test.go',
  'package.json',
  'packages/adapter-sdk/src/canonical-json.ts',
  'packages/adapter-sdk/src/codec.ts',
  'packages/adapter-sdk/src/constants.ts',
  'packages/adapter-sdk/src/fixture.ts',
  'packages/adapter-sdk/src/index.ts',
  'packages/adapter-sdk/src/json-schema.ts',
  'packages/adapter-sdk/src/json-value.ts',
  'packages/adapter-sdk/src/projection.ts',
  'packages/adapter-sdk/src/resource-limits.ts',
  'packages/adapter-sdk/src/safe-pattern.ts',
  'packages/adapter-sdk/test/drift.test.ts',
  'packages/adapter-sdk/test/fixture.test.ts',
  'packages/adapter-sdk/test/security-repair.test.ts',
	'packages/harness-adapter/src/framing.ts',
	'packages/harness-adapter/src/runtime.ts',
	'packages/harness-adapter/test/stdio-smoke.test.ts',
  'packages/model-harness-gateway/package.json',
  'packages/model-harness-gateway/src/index.ts',
  'packages/model-harness-gateway/src/model-process-worker.ts',
  'packages/model-harness-gateway/src/protocol.ts',
  'packages/model-harness-gateway/test/fixture-acp-worker.ts',
  'packages/model-harness-gateway/test/model-process-worker.test.ts',
  'pnpm-lock.yaml',
  'pnpm-workspace.yaml',
  'scripts/ci/sbom/generate-sbom.mjs',
  'scripts/ci/build-harness-runtime-closure.mjs',
  'scripts/ci/harness-runtime-closure.config.ts',
  'scripts/ci/harness-runtime-closure.ts',
  'scripts/ci/prepare-b004-controlled-certification.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/lib/publication-hygiene.mjs',
  'scripts/ci/lib/scan.mjs',
  'scripts/ci/lib/json-schema.mjs',
  'scripts/ci/lib/safe-regex.mjs',
  'scripts/ci/test/publication-hygiene.test.mjs',
  'scripts/ci/test/json-schema-security.test.mjs',
  'scripts/ci/validate/mvp-b002.mjs',
  'scripts/ci/validate/mvp-b003.mjs',
  'scripts/ci/validate/mvp-b004.mjs',
  'scripts/ci/validate/b000-retro.mjs',
  'scripts/ci/validate/evidence.mjs',
  'scripts/ci/validate/adapter-sdk.mjs',
  'scripts/ci/validate/protocol-assets.mjs',
  'scripts/ci/validate/runtime-shell.mjs',
  'scripts/ci/validate/sbom.mjs',
  'scripts/ci/validate/supply-chain.mjs',
  'scripts/ci/validate/workflow.mjs',
  'tools/supply-chain/licenses.json',
  ...SCHEMA_PATHS,
]);

const GOVERNANCE_MUTABLE = new Set([
  'README.md',
  'docs/authority/BATCH_DEPENDENCY_GRAPH.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/milestones/MVP.md',
  'package.json',
  'scripts/ci/run-checks.mjs',
  ...RECORD_PATHS,
]);

const PROTECTED_PREFIXES = Object.freeze([
  'internal/orchestrator/',
  'internal/runcore/',
  'internal/testplan/',
  'packages/harness-adapter/',
  'schemas/orchestration/',
  'schemas/run-core/',
  'docs/authority/registry/authority-lifecycle/records/aipt-mvp-b001/',
  'docs/authority/registry/authority-lifecycle/records/aipt-mvp-b002/',
  'docs/authority/registry/authority-lifecycle/records/aipt-mvp-b003/',
]);

const PROTECTED_EXCEPTIONS = new Set([
	'packages/harness-adapter/src/framing.ts',
	'packages/harness-adapter/src/runtime.ts',
	'packages/harness-adapter/test/stdio-smoke.test.ts',
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

function nulPaths(result) {
  return result?.status === 0 ? result.stdout.split('\0').filter(Boolean) : [];
}

function publicationInventory(repo) {
  const tracked = gitResult(repo, ['ls-files', '-z']);
  const untracked = gitResult(repo, ['ls-files', '--others', '--exclude-standard', '-z']);
  const errors = [];
  if (tracked.status !== 0) errors.push('tracked publication inventory is unavailable');
  if (untracked.status !== 0) errors.push('untracked publication inventory is unavailable');
  return {
    files: [...new Set([...nulPaths(tracked), ...nulPaths(untracked)])].sort(),
    errors,
  };
}

function currentBranch(repo) {
  const branch = gitOut(repo, ['branch', '--show-current']);
  if (branch) return branch;
  return process.env.GITHUB_HEAD_REF ||
    (process.env.GITHUB_REF?.startsWith('refs/heads/')
      ? process.env.GITHUB_REF.slice('refs/heads/'.length) : 'DETACHED');
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
    .some((line) => !line.includes('node_modules/'));
}

function allowedPath(relative) {
  if (REQUIRED_EXACT.has(relative) || RECORD_PATHS.includes(relative)) return true;
  return relative.startsWith('internal/modelgateway/') ||
    relative.startsWith('packages/model-harness-gateway/') ||
    relative.startsWith('schemas/model/') ||
    relative.startsWith('docs/model-certification/');
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

function firstParentContains(repo, ancestor, descendant) {
  if (!ancestor || !descendant) return false;
  if (ancestor === descendant) return true;
  return lines(gitResult(repo, ['rev-list', '--first-parent', descendant])).includes(ancestor);
}

function committedChangedPaths(repo, from, to) {
  return lines(gitResult(repo, ['diff', '--name-only', '--no-renames', from, to])).sort();
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

function candidateScope(repo, candidate) {
  if (!candidate) return { paths: [], valid: false, required: false };
  const paths = committedChangedPaths(repo, BASE_COMMIT, candidate);
  return {
    paths,
    valid: paths.every(allowedPath) && !paths.some((relative) => relative.startsWith(`${RECORD_ROOT}/`)),
    required: requiredPresent(paths),
  };
}

function governanceOnlyRange(repo, from, to) {
  return Boolean(from && to) && committedChangedPaths(repo, from, to)
    .every((relative) => GOVERNANCE_MUTABLE.has(relative));
}

function businessArtifactPath(relative) {
  return relative.startsWith('internal/modelgateway/') ||
    relative.startsWith('packages/model-harness-gateway/src/') ||
    relative.startsWith('schemas/model/') ||
    ['internal/launcher/dependencies.go', 'internal/launcher/gates.go', 'internal/launcher/launcher.go'].includes(relative);
}

function blobText(repo, commit, relative) {
  const result = gitResult(repo, ['show', `${commit}:${relative}`]);
  return result.status === 0 ? result.stdout : null;
}

function acceptedArtifactProblems(repo, candidate, candidatePaths) {
  const problems = [];
  for (const relative of candidatePaths.filter(businessArtifactPath)) {
    const accepted = blobText(repo, candidate, relative);
    let current = null;
    try { current = read(repo, relative); } catch { current = null; }
    if (accepted === null || current === null || accepted !== current) {
      problems.push(`accepted B004 artifact differs from Candidate: ${relative}`);
    }
  }
  return problems;
}

function exactSet(left, right) {
  return Array.isArray(left) && Array.isArray(right) &&
    JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
}

function lifecycleInventory(repo) {
  const root = path.join(repo, 'docs/authority/registry/authority-lifecycle/records');
  if (!fs.existsSync(root)) return [];
  const found = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile() && entry.name.endsWith('.json')) {
        const relative = path.relative(repo, absolute).split(path.sep).join('/');
        try {
          const value = JSON.parse(fs.readFileSync(absolute, 'utf8'));
          if (value?.task_id === TASK_ID || relative.startsWith(`${RECORD_ROOT}/`)) found.push(relative);
        } catch {
          if (relative.startsWith(`${RECORD_ROOT}/`)) found.push(relative);
        }
      }
    }
  };
  visit(root);
  return found.sort();
}

function firstIntroduction(repo, merge, head, relative) {
  const commits = lines(gitResult(repo, [
    'log', '--first-parent', '--reverse', '--format=%H', '--diff-filter=A', `${merge}..${head}`, '--', relative,
  ]));
  return commits.length === 1 ? commits[0] : null;
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
    return facts.parentCount === 2 && facts.parent1 === BASE_COMMIT && facts.secondParentValid &&
      facts.parent2Tree === facts.headTree && !facts.lifecyclePresent ? 'LEGAL_MERGE' : 'REJECTED';
  }
  if (facts.kind === 'POST_MERGE') {
    return facts.parentCount === 1 && facts.mergeOnAncestry && facts.lifecycleValid &&
      facts.lifecycleState === 'POST_MERGE_VERIFIED' && facts.governanceOnly &&
      !facts.businessChanged && facts.acceptedArtifactsImmutable ? 'POST_MERGE_SUCCESSOR' : 'REJECTED';
  }
  if (facts.kind === 'CLOSEOUT') {
    return facts.parentCount === 1 && facts.mergeOnAncestry && facts.lifecycleValid &&
      facts.lifecycleState === 'CLOSED' && facts.governanceOnly && !facts.businessChanged &&
      facts.acceptedArtifactsImmutable ? 'CLOSEOUT_SUCCESSOR' : 'REJECTED';
  }
  if (facts.kind === 'CLOSED_HISTORICAL') {
    return facts.closedOnAncestry && facts.lifecycleValid && facts.lifecycleState === 'CLOSED' &&
      !facts.lifecycleFork && !facts.duplicateClosed && facts.acceptedArtifactsImmutable
      ? 'CLOSED_HISTORICAL_SUCCESSOR' : 'REJECTED';
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
    parentCount: 2, parent1: BASE_COMMIT, secondParentValid: true,
    parent2Tree: 'candidate-tree', headTree: 'candidate-tree', lifecyclePresent: false,
  };
  const successor = {
    baseExact: true, scopeValid: true, requiredPresent: true, parentCount: 1,
    mergeOnAncestry: true, lifecycleValid: true, governanceOnly: true,
    businessChanged: false, acceptedArtifactsImmutable: true,
  };
  const closeout = { ...successor, kind: 'CLOSEOUT', lifecycleState: 'CLOSED' };
  const closed = {
    kind: 'CLOSED_HISTORICAL', baseExact: true, scopeValid: true, requiredPresent: true,
    closedOnAncestry: true, lifecycleValid: true, lifecycleState: 'CLOSED', lifecycleFork: false,
    duplicateClosed: false, acceptedArtifactsImmutable: true,
  };
  const definitions = [
    ['L01', 'valid candidate', candidate, 'INITIAL_CANDIDATE'],
    ['L02', 'wrong Base', { ...candidate, baseExact: false }, 'REJECTED'],
    ['L03', 'wrong branch', { ...candidate, branch: 'main' }, 'REJECTED'],
    ['L04', 'scope drift', { ...candidate, scopeValid: false }, 'REJECTED'],
    ['L05', 'synthetic legal merge', merge, 'LEGAL_MERGE'],
    ['L06', 'wrong second parent', { ...merge, secondParentValid: false }, 'REJECTED'],
    ['L07', 'merge tree mismatch', { ...merge, headTree: 'different-tree' }, 'REJECTED'],
    ['L08', 'synthetic closeout successor', closeout, 'CLOSEOUT_SUCCESSOR'],
    ['L09', 'business-changing closeout', { ...closeout, businessChanged: true }, 'REJECTED'],
    ['L10', 'closed historical successor', closed, 'CLOSED_HISTORICAL_SUCCESSOR'],
    ['L11', 'accepted artifact mutation', { ...closed, acceptedArtifactsImmutable: false }, 'REJECTED'],
    ['L12', 'lifecycle fork', { ...closed, lifecycleFork: true }, 'REJECTED'],
    ['L13', 'duplicate CLOSED', { ...closed, duplicateClosed: true }, 'REJECTED'],
    ['L14', 'post-merge successor', { ...successor, kind: 'POST_MERGE', lifecycleState: 'POST_MERGE_VERIFIED' }, 'POST_MERGE_SUCCESSOR'],
  ];
  return definitions.map(([id, label, facts, expected]) => {
    let actual = 'REJECTED';
    let threw = false;
    try { actual = classifyTopology(facts); } catch { threw = true; }
    return { id, label, expected, actual, threw, matched: !threw && actual === expected };
  });
}

function validateLifecycle(repo, head) {
  const inventory = lifecycleInventory(repo);
  if (inventory.length === 0) {
    return { state: 'NONE', result: 'PASS', problems: [], inventory, lifecycleFork: false, duplicateClosed: false };
  }
  const problems = [];
  const expected = inventory.length >= 1 && inventory.length <= 3 ? RECORD_PATHS.slice(0, inventory.length) : [];
  if (!exactSet(inventory, expected)) problems.push('B004 lifecycle inventory is partial, forked, duplicated or outside canonical paths');
  let records = [];
  try { records = expected.map((relative) => readJSON(repo, relative)); }
  catch (error) {
    return { state: 'INVALID', result: 'FAIL', problems: [...problems, error.message], inventory, lifecycleFork: true, duplicateClosed: false };
  }
  const schema = readJSON(repo, RECORD_SCHEMA);
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    problems.push(...validateInstance(schema, record).errors.map((error) => `${expected[index]}: ${error.message}`));
    if (record?.record_id !== RECORD_IDS[index] || record?.task_id !== TASK_ID ||
        record?.event !== RECORD_EVENTS[index] || record?.event_sequence !== index + 1 ||
        record?.record_identity?.path !== RECORD_PATHS[index] ||
        record?.authority_basis?.model_id !== 'IMMUTABLE_SEMANTICS_APPEND_ONLY_LIFECYCLE_V1' ||
        record?.authority_basis?.authorized_by_task !== TASK_ID || record?.created_by_task !== TASK_ID) {
      problems.push(`${expected[index]} canonical lifecycle identity is not exact`);
    }
  }
  const duplicateClosed = records.filter((record) => record?.event === 'CLOSED').length > 1;
  const identity = records[0]?.semantic_artifact_identity;
  if (identity?.task_id !== TASK_ID || identity?.artifact_id !== TASK_ID ||
      identity?.artifact_path !== 'internal/modelgateway/gateway.go' ||
      identity?.semantic_snapshot_state !== 'CANDIDATE_FROZEN' || identity?.semantic_snapshot_accepted !== false) {
    problems.push('B004 semantic artifact identity is not the exact frozen gateway identity');
  }
  for (const record of records.slice(1)) {
    if (JSON.stringify(record?.semantic_artifact_identity) !== JSON.stringify(identity)) {
      problems.push('B004 lifecycle semantic identity changed across append-only records');
    }
  }
  const candidate = commitFacts(repo, identity?.candidate_commit);
  const scope = candidateScope(repo, candidate?.commit);
  if (!candidate || candidate.tree !== identity?.candidate_tree || !candidateLinearity(repo, candidate.commit) ||
      !scope.valid || !scope.required || sha256(blobText(repo, candidate.commit, identity?.artifact_path) ?? '') !== identity?.artifact_sha256) {
    problems.push('B004 lifecycle Candidate commit/tree/lineage/scope/artifact binding is invalid');
  }
  const mergeIdentity = records[0]?.event_evidence?.merge_identity;
  const merge = commitFacts(repo, mergeIdentity?.commit);
  if (!merge || merge.parents.length !== 2 || merge.parents[0] !== BASE_COMMIT ||
      merge.parents[1] !== candidate?.commit || merge.tree !== candidate?.tree ||
      mergeIdentity?.tree !== merge.tree || JSON.stringify(mergeIdentity?.parents) !== JSON.stringify(merge.parents)) {
    problems.push('B004 MERGED evidence is not the legal Base/Candidate merge');
  }
  if (!merge || !firstParentContains(repo, merge.commit, head)) problems.push('HEAD is outside accepted B004 first-parent ancestry');

  const introductions = [];
  for (let index = 0; index < expected.length; index += 1) {
    const introduction = merge ? firstIntroduction(repo, merge.commit, head, expected[index]) : null;
    introductions.push(introduction);
    if (!introduction) {
      problems.push(`${expected[index]} lacks one accepted first-parent introduction`);
      continue;
    }
    const introduced = blobText(repo, introduction, expected[index]);
    if (introduced === null || introduced !== read(repo, expected[index])) {
      problems.push(`accepted lifecycle record was rewritten: ${expected[index]}`);
    }
  }
  const artifactProblems = candidate ? acceptedArtifactProblems(repo, candidate.commit, scope.paths) : ['Candidate unavailable'];
  problems.push(...artifactProblems);
  const state = records.length === 3 ? 'CLOSED' : records.length === 2 ? 'POST_MERGE_VERIFIED' : 'MERGED';
  return {
    state: problems.length === 0 ? state : 'INVALID', result: problems.length === 0 ? 'PASS' : 'FAIL',
    problems, inventory, records, lifecycleFork: !exactSet(inventory, expected), duplicateClosed,
    candidate: candidate?.commit ?? null, candidateTree: candidate?.tree ?? null, candidatePaths: scope.paths,
    acceptedMerge: merge?.commit ?? null, acceptedMergeTree: merge?.tree ?? null,
    postMergeCommit: introductions[1] ?? null, closeoutCommit: introductions[2] ?? null,
    businessChanged: artifactProblems.length !== 0, acceptedArtifactsImmutable: artifactProblems.length === 0,
  };
}

function actualTopology(repo, paths) {
  const head = gitOut(repo, ['rev-parse', 'HEAD^{commit}']);
  const headFacts = commitFacts(repo, head);
  const branch = currentBranch(repo);
  const baseExact = commitFacts(repo, BASE_COMMIT)?.tree === BASE_TREE;
  const lifecyclePresent = lifecycleInventory(repo).length > 0;
  // Once the append-only B004 lifecycle exists, classify against its accepted
  // Candidate and immutable business artifacts before looking at a later
  // successor's dirty worktree. Otherwise an authorized B005 construction
  // payload is incorrectly reinterpreted as an in-progress B004 Candidate.
  const lifecycle = validateLifecycle(repo, head);
  if (lifecycle.state !== 'NONE') {
    const scopePaths = lifecycle.candidatePaths ?? [];
    const common = {
      baseExact, scopeValid: scopePaths.every(allowedPath), requiredPresent: requiredPresent(scopePaths),
      lifecycleValid: lifecycle.result === 'PASS', lifecycleState: lifecycle.state,
      businessChanged: lifecycle.businessChanged, acceptedArtifactsImmutable: lifecycle.acceptedArtifactsImmutable,
      mergeOnAncestry: firstParentContains(repo, lifecycle.acceptedMerge, head),
    };
    if (lifecycle.state === 'POST_MERGE_VERIFIED') {
      const facts = {
        ...common, kind: 'POST_MERGE', parentCount: headFacts?.parents.length ?? 0,
        governanceOnly: governanceOnlyRange(repo, lifecycle.acceptedMerge, head),
      };
      return { phase: classifyTopology(facts), head, headFacts, branch, scopePaths, lifecycle };
    }
    if (lifecycle.state === 'CLOSED') {
      if (head === lifecycle.closeoutCommit) {
        const facts = {
          ...common, kind: 'CLOSEOUT', parentCount: headFacts?.parents.length ?? 0,
          governanceOnly: governanceOnlyRange(repo, headFacts?.parents[0], head),
        };
        return { phase: classifyTopology(facts), head, headFacts, branch, scopePaths, lifecycle };
      }
      const facts = {
        ...common, kind: 'CLOSED_HISTORICAL',
        closedOnAncestry: firstParentContains(repo, lifecycle.closeoutCommit, head),
        lifecycleFork: lifecycle.lifecycleFork, duplicateClosed: lifecycle.duplicateClosed,
      };
      return { phase: classifyTopology(facts), head, headFacts, branch, scopePaths, lifecycle };
    }
    return { phase: 'REJECTED', head, headFacts, branch, scopePaths, lifecycle };
  }

  if (worktreeDirty(repo)) {
    const facts = {
      kind: 'CONSTRUCTION', baseExact, scopeValid: paths.every(allowedPath), requiredPresent: requiredPresent(paths),
      branch, descendsBase: isAncestor(repo, BASE_COMMIT, head),
      linear: head === BASE_COMMIT || candidateLinearity(repo, head), lifecyclePresent,
    };
    return { phase: classifyTopology(facts), head, headFacts, branch, scopePaths: paths, lifecycle: { state: 'NONE', problems: [] } };
  }

  if (headFacts?.parents.length === 2) {
    const parent2 = commitFacts(repo, headFacts.parents[1]);
    const scope = candidateScope(repo, headFacts.parents[1]);
    const secondParentValid = headFacts.parents[0] === BASE_COMMIT &&
      isAncestor(repo, BASE_COMMIT, headFacts.parents[1]) && candidateLinearity(repo, headFacts.parents[1]) &&
      scope.valid && scope.required;
    const facts = {
      kind: 'MERGE', baseExact, scopeValid: scope.valid, requiredPresent: scope.required,
      parentCount: 2, parent1: headFacts.parents[0], secondParentValid,
      parent2Tree: parent2?.tree, headTree: headFacts.tree, lifecyclePresent: false,
    };
    return { phase: classifyTopology(facts), head, headFacts, branch, scopePaths: scope.paths, lifecycle };
  }
  const scope = candidateScope(repo, head);
  const facts = {
    kind: 'CANDIDATE', baseExact, scopeValid: scope.valid, requiredPresent: scope.required,
    branch, descendsBase: isAncestor(repo, BASE_COMMIT, head), linear: candidateLinearity(repo, head),
    parentCount: headFacts?.parents.length ?? 0, lifecyclePresent: false,
  };
  return { phase: classifyTopology(facts), head, headFacts, branch, scopePaths: scope.paths, lifecycle };
}

function localIdentity() {
  const digest = 'b'.repeat(64);
  return {
    executable_reference: 'llama-server-registered', binary_sha256: digest, version: '1.0.0', commit: '',
    gguf_reference: 'operator-model-registered', gguf_sha256: digest, gguf_model_identity: 'synthetic-contract-model',
    quantization_identity: 'Q4_K_M', template_identity: 'chat-template-v1', template_sha256: digest,
    isolation_identity: ISOLATION_IDENTITY,
    isolation_helper_reference: ISOLATION_HELPER_REFERENCE,
    isolation_helper_sha256: digest,
    launch_parameters: ['--host', '127.0.0.1', '--no-webui'],
    hardware: { architecture: 'x86_64', cpu_class: 'generic', gpu_backend: 'none', memory_class: 'synthetic' },
  };
}

function schemaFixtures() {
  const digest = 'a'.repeat(64);
  const harness = {
    implementation: 'deepseek-harness', version: '0.1.0', commit: HARNESS_COMMIT,
    package_sha256: digest, protocol_identity: 'agent-client-protocol', protocol_version: '1',
    capability_fingerprint: digest, runtime_closure_kind: 'VERIFIED_SINGLE_FILE_DATA_URL_V1',
    runtime_closure_sha256: digest,
  };
  const tuple = {
    schema: 'aipt.model-execution-tuple/v1', backend_kind: 'REMOTE_DEEPSEEK',
    provider_identity: 'deepseek-official', model_id: 'deepseek-v4-pro',
    model_profile_binding: 'remote-profile@1.0.0', sampling_profile_binding: 'sampling@1.0.0',
    requested_sampling_sha256: digest,
    effective_sampling_projection: {
      schema: 'aipt.effective-sampling-projection/v1',
      enforcement_identity: 'AIPT_ACP_CONSERVATIVE_UTF8_BYTE_BUDGET_V1',
      applied_parameters: ['max_context_tokens', 'max_output_tokens'],
      unsupported_parameters: ['temperature', 'top_p'],
      max_context_tokens: 8192, max_output_tokens: 512,
      context_utf8_byte_ceiling: 8192, output_utf8_byte_ceiling: 512,
    },
    unsupported_sampling_parameters: ['temperature', 'top_p'],
    backend_serialized_request_sha256: digest,
    harness_identity: `deepseek-harness@${HARNESS_RELEASE}+${HARNESS_COMMIT}`,
    harness_protocol_identity: 'agent-client-protocol', harness_protocol_version: '1',
    structured_output_mode: 'PROMPTED', tool_call_mode: 'DISABLED', request_contract_version: '1',
    capability_fingerprint: digest, environment_identity: 'synthetic-public-ci', sha256: digest,
  };
  const assignments = ['GM', 'PLAYER_1', 'PLAYER_2', 'PLAYER_3', 'PLAYER_4'].map((seat) => ({
    assignment_id: `assignment-${seat}`, seat_id: seat, role_id: seat === 'GM' ? 'GM' : 'PLAYER',
    profile_binding: `${seat.toLowerCase()}-profile@1.0.0`, sampling_binding: 'sampling@1.0.0',
    backend_kind: seat === 'GM' ? 'REMOTE_DEEPSEEK' : 'LOCAL_LLAMACPP', certification_identity: `cert-${seat}`,
  }));
  return {
    'aipt-sampling-profile.schema.json': {
      schema: 'aipt.sampling-profile/v1', sampling_id: 'sampling', sampling_version: '1.0.0',
      temperature: 0.2, top_p: 0.9, max_output_tokens: 512, max_context_tokens: 8192,
      applied_parameters: ['max_context_tokens', 'max_output_tokens'],
      unsupported_parameters: ['temperature', 'top_p'], sha256: digest,
    },
    'aipt-model-profile.schema.json': {
      schema: 'aipt.model-profile/v1', profile_id: 'remote-profile', profile_version: '1.0.0',
      backend_kind: 'REMOTE_DEEPSEEK', provider_identity: 'deepseek-official', model_id: 'deepseek-v4-pro',
      harness_identity: harness, sampling_profile_id: 'sampling@1.0.0', structured_output_mode: 'PROMPTED',
      tool_call_mode: 'DISABLED',
      context_policy: { policy_id: 'context-v1', policy_version: '1.0.0', max_request_bytes: 65536, max_context_bytes: 32768, reduction_policy_id: 'AIPT_CONTEXT_BUDGET_REDUCE_V1' },
      data_egress_policy: { policy_id: 'remote-egress-v1', policy_version: '1.0.0', allowed_classifications: ['PUBLIC'], break_glass_allowed: false },
      credential_reference: { reference_id: 'deepseek-production', kind: 'ENVIRONMENT_VARIABLE', locator: 'DEEPSEEK_API_KEY' },
      capability_requirements: ['basic_completion', 'structured_output_prompted'], certification_identity: 'remote-cert-1', sha256: digest,
    },
    'aipt-model-execution-tuple.schema.json': tuple,
    'aipt-model-certification.schema.json': {
      schema: 'aipt.model-certification/v1', certification_id: 'synthetic-cert', certification_version: '1.0.0',
      profile_binding: 'remote-profile@1.0.0', sampling_binding: 'sampling@1.0.0', result: 'PASS',
      kind: 'SYNTHETIC_PUBLIC_CI', minimum_certification: true, real_model_calls: 0,
      evidence_identity: 'synthetic-evidence', production_role_eligibility: 'NOT_CLAIMED',
      claims: [{ name: 'basic_completion', status: 'CERTIFIED' }], execution_tuple: tuple,
      observed_at: '2026-08-30T00:00:00Z', sha256: digest,
    },
    'aipt-model-manifest-binding.schema.json': {
      schema: 'aipt.model-manifest-binding/v1', manifest_id: 'manifest-1', run_id: 'run-1', manifest_sha256: digest,
      run_classification: 'QUALIFICATION', qualification_eligible: true,
      assignments, clean_baseline_eligible: false, sha256: digest,
    },
    'aipt-harness-route.schema.json': {
      schema: 'aipt.harness-route/v1', profile_binding: 'remote-profile@1.0.0', sampling_binding: 'sampling@1.0.0',
      backend_kind: 'REMOTE_DEEPSEEK', provider_identity: 'deepseek-official', model_id: 'deepseek-v4-pro',
      harness_identity: `deepseek-harness@${HARNESS_RELEASE}+${HARNESS_COMMIT}`,
      harness_protocol_identity: 'agent-client-protocol', harness_protocol_version: '1', capability_fingerprint: digest,
      structured_output_mode: 'PROMPTED', tool_call_mode: 'DISABLED', session_working_directory: '/tmp/aipt-synthetic',
      sampling_profile: {
        schema: 'aipt.sampling-profile/v1', sampling_id: 'sampling', sampling_version: '1.0.0',
        temperature: 0.2, top_p: 0.9, max_output_tokens: 512, max_context_tokens: 8192,
        applied_parameters: ['max_context_tokens', 'max_output_tokens'],
        unsupported_parameters: ['temperature', 'top_p'], sha256: digest,
      },
      child: { executable_path: '/tmp/node', executable_sha256: digest, arguments: ['worker', '/tmp/dsh.js'], argument_file_digests: [{ index: 1, sha256: digest }], runtime_closure: { schema: 'aipt.harness-runtime-closure/v1', kind: 'VERIFIED_SINGLE_FILE_DATA_URL_V1', entrypoint_argument_index: 1, sha256: digest }, working_directory: '/tmp/aipt-synthetic', environment_allowlist: ['DEEPSEEK_API_KEY'], startup_timeout_ms: 1000, request_timeout_ms: 2000, shutdown_timeout_ms: 500, output_budget: { schema: 'aipt.acp-output-budget/v1', max_stdout_protocol_bytes: 8388608, max_notification_bytes: 4194304, max_response_and_notification_bytes: 8388608, max_stderr_bytes: 1048576 } },
    },
  };
}

function strictObjectProblems(node, location = '#') {
  const problems = [];
  if (node === null || typeof node !== 'object' || Array.isArray(node)) return problems;
  if (node.type === 'object' && node.additionalProperties !== false) problems.push(`${location} object is not fail-closed`);
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
    problems.push(...validateInstance(schema, fixture).errors.map((error) => `${relative} fixture: ${error.message}`));
    const mutations = [
      ['unknown-property', (value) => { value.__unknown = true; }],
      ['missing-schema', (value) => { delete value.schema; }],
      ['unknown-version', (value) => { value.schema = 'aipt.unknown/v999'; }],
      ['unknown-enum', (value) => {
        if (filename.includes('sampling')) value.applied_parameters[0] = 'imaginary_parameter';
        else if (filename.includes('profile')) value.backend_kind = 'OLLAMA';
        else if (filename.includes('execution')) value.structured_output_mode = 'BEST_EFFORT';
        else if (filename.includes('certification')) value.claims[0].status = 'ASSUMED';
        else if (filename.includes('manifest')) value.assignments[0].seat_id = 'PLAYER_99';
        else value.backend_kind = 'OPENAI';
      }],
    ];
    for (const [name, mutate] of mutations) {
      const value = structuredClone(fixture);
      let threw = false;
      let rejected = false;
      try { mutate(value); rejected = validateInstance(schema, value).errors.length > 0; } catch { threw = true; }
      probes.push({ id: `S-${filename}-${name}`, expected: 'REJECT', actual: rejected ? 'REJECT' : 'ACCEPT', threw, matched: rejected && !threw });
    }
  }
  // Exercise the local execution-tuple branch too; public CI still performs zero model calls.
  const localTuple = structuredClone(fixtures['aipt-model-execution-tuple.schema.json']);
  localTuple.backend_kind = 'LOCAL_LLAMACPP';
  localTuple.provider_identity = 'llama.cpp';
  localTuple.model_id = 'synthetic-contract-model';
  localTuple.local_runtime_identity = localIdentity();
  const localErrors = validateInstance(readJSON(repo, 'schemas/model/v1/aipt-model-execution-tuple.schema.json'), localTuple).errors;
  problems.push(...localErrors.map((error) => `local execution tuple fixture: ${error.message}`));
  return { problems, probes };
}

function protectedArtifactProblems(repo) {
  const problems = [];
  const baselinePaths = lines(gitResult(repo, ['ls-tree', '-r', '--name-only', BASE_COMMIT]))
		.filter((relative) => PROTECTED_PREFIXES.some((prefix) => relative.startsWith(prefix)) &&
			!PROTECTED_EXCEPTIONS.has(relative));
  for (const relative of baselinePaths) {
    const baseline = blobText(repo, BASE_COMMIT, relative);
    let current = null;
    try { current = read(repo, relative); } catch { current = null; }
    if (baseline === null || current === null || baseline !== current) problems.push(`protected predecessor artifact changed: ${relative}`);
  }
  for (const [relative, expected] of Object.entries(MIGRATIONS)) {
    let actual = null;
    try { actual = sha256(fs.readFileSync(path.join(repo, relative))); } catch { actual = null; }
    if (actual !== expected) problems.push(`historical migration changed: ${relative}`);
  }
  return problems;
}

function boundObjectDigest(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null;
  const copy = structuredClone(value);
  copy.sha256 = '';
  return sha256(JSON.stringify(copy));
}

function privatePathPresent(value) {
  if (typeof value === 'string') return value.startsWith('/') || /^[A-Za-z]:[\\/]/u.test(value);
  if (Array.isArray(value)) return value.some(privatePathPresent);
  if (value !== null && typeof value === 'object') {
    return Object.entries(value).some(([key, item]) => privatePathPresent(key) || privatePathPresent(item));
  }
  return false;
}

function samplingEvidenceProblems(label, evidence) {
  const problems = [];
  const sampling = evidence?.sampling_profile;
  const tuple = evidence?.certification?.execution_tuple;
  const projection = tuple?.effective_sampling_projection;
  const harness = evidence?.model_profile?.harness_identity;
  const expectedApplied = ['max_context_tokens', 'max_output_tokens'];
  const expectedUnsupported = ['temperature', 'top_p'];
  if (sampling?.temperature !== 0 || sampling?.top_p !== 1 ||
      sampling?.max_output_tokens !== 1024 || sampling?.max_context_tokens !== 8192 ||
      !exactSet(sampling?.applied_parameters, expectedApplied) ||
      !exactSet(sampling?.unsupported_parameters, expectedUnsupported) ||
      tuple?.requested_sampling_sha256 !== sampling?.sha256 ||
      !exactSet(tuple?.unsupported_sampling_parameters, expectedUnsupported) ||
      projection?.schema !== 'aipt.effective-sampling-projection/v1' ||
      projection?.enforcement_identity !== 'AIPT_ACP_CONSERVATIVE_UTF8_BYTE_BUDGET_V1' ||
      !exactSet(projection?.applied_parameters, expectedApplied) ||
      !exactSet(projection?.unsupported_parameters, expectedUnsupported) ||
      projection?.max_context_tokens !== 8192 || projection?.max_output_tokens !== 1024 ||
      projection?.context_utf8_byte_ceiling !== 8192 || projection?.output_utf8_byte_ceiling !== 1024 ||
      !/^[0-9a-f]{64}$/u.test(tuple?.backend_serialized_request_sha256 ?? '') ||
      harness?.runtime_closure_kind !== 'VERIFIED_SINGLE_FILE_DATA_URL_V1' ||
      harness?.runtime_closure_sha256 !== HARNESS_RUNTIME_CLOSURE_SHA256) {
    problems.push(`${label} sampling propagation/runtime-closure evidence is incomplete or drifted`);
  }
  return problems;
}

function supersededEvidenceProblems(label, evidence, reason) {
  const problems = [];
  if (evidence?.schema !== 'aipt.public.controlled-model-certification-result/v1' ||
      evidence?.result !== 'PASS' || evidence?.evidence_status !== 'SUPERSEDED_NON_FINAL' ||
      evidence?.superseded_reason !== reason || evidence?.certification?.kind !== 'CONTROLLED_REAL' ||
      evidence?.certification?.real_model_calls !== 1 || evidence?.private_paths_recorded !== false ||
      evidence?.credential_values_recorded !== false || privatePathPresent(evidence)) {
    problems.push(`${label} historical evidence is not preserved as an exact superseded non-final record`);
  }
  return problems;
}

function controlledEvidenceProblems(repo) {
  const problems = [];
  let capability;
  let evidence;
  let localEvidence;
  let supersededRemote;
  let supersededLocal;
  let gguf;
  let llama;
  try {
    const capabilityRaw = fs.readFileSync(path.join(repo, HARNESS_CAPABILITIES));
    if (sha256(capabilityRaw) !== HARNESS_CAPABILITY_SHA256) {
      problems.push('HARNESS-01 capability registration digest drift');
    }
    capability = JSON.parse(capabilityRaw.toString('utf8'));
    evidence = readJSON(repo, REMOTE_EVIDENCE);
    localEvidence = readJSON(repo, LOCAL_EVIDENCE);
    supersededRemote = readJSON(repo, SUPERSEDED_REMOTE_EVIDENCE);
    supersededLocal = readJSON(repo, SUPERSEDED_LOCAL_EVIDENCE);
    gguf = readJSON(repo, GGUF_REGISTRATION);
    llama = readJSON(repo, LLAMACPP_REGISTRATION);
  } catch (error) {
    return [`controlled certification registration/evidence is unreadable: ${error.message}`];
  }
  if (capability?.schema !== 'aipt.public.harness-capability-registration/v1' ||
      capability?.registration_id !== 'HARNESS-01' || capability?.implementation !== 'deepseek-harness' ||
      capability?.version !== '0.1.0-rc.8' || capability?.commit !== HARNESS_COMMIT ||
      capability?.source_archive_sha256 !== HARNESS_SOURCE_SHA256 ||
      capability?.runtime_closure?.schema !== 'aipt.harness-runtime-closure/v1' ||
      capability?.runtime_closure?.kind !== 'VERIFIED_SINGLE_FILE_DATA_URL_V1' ||
      capability?.runtime_closure?.sha256 !== HARNESS_RUNTIME_CLOSURE_SHA256 ||
      capability?.runtime_closure?.dependency_resolution !== 'STATIC_BUNDLED' ||
      capability?.runtime_closure?.execution_source !== 'INHERITED_VERIFIED_FILE_DESCRIPTOR' ||
      capability?.protocol?.identity !== 'agent-client-protocol' || capability?.protocol?.version !== '1' ||
      capability?.protocol?.initialize_request_protocol_version !== 1 ||
      capability?.protocol?.required_prompt_capabilities?.audio !== false ||
      capability?.protocol?.required_prompt_capabilities?.embedded_context !== false ||
      capability?.aipt_route?.direct_provider_bypass_available !== false ||
      capability?.aipt_route?.structured_output_mode !== 'PROMPTED' ||
      capability?.aipt_route?.tool_call_mode !== 'DISABLED' ||
      !exactSet(capability?.aipt_route?.minimum_capabilities,
        ['basic_completion', 'structured_output_prompted', 'role_invocation'])) {
    problems.push('HARNESS-01 capability registration is not the exact frozen route');
  }
  problems.push(...supersededEvidenceProblems(
    'REMOTE_DEEPSEEK', supersededRemote, 'SAMPLING_CONTROLS_NOT_PROPAGATED',
  ));
  problems.push(...supersededEvidenceProblems(
    'LOCAL_LLAMACPP', supersededLocal, 'LOCAL_RUNTIME_SECURITY_BOUNDARY_REPLACED',
  ));

  const topLevel = [
    'schema', 'result', 'backend_kind', 'model_profile', 'sampling_profile', 'certification',
    'harness_probe', 'credential_validation', 'request_sha256', 'response_sha256',
    'response_protocol_version', 'route_recovery_occurred', 'credential_values_recorded',
    'private_paths_recorded',
  ];
  if (!exactSet(Object.keys(evidence ?? {}), topLevel) ||
      evidence?.schema !== 'aipt.public.controlled-model-certification-result/v1' ||
      evidence?.result !== 'PASS' || evidence?.backend_kind !== 'REMOTE_DEEPSEEK' ||
      evidence?.response_protocol_version !== 'v1' || evidence?.route_recovery_occurred !== false ||
      evidence?.credential_values_recorded !== false || evidence?.private_paths_recorded !== false ||
      privatePathPresent(evidence)) {
    problems.push('REMOTE_DEEPSEEK controlled result is not the exact path-free public envelope');
  }
  const profileSchema = readJSON(repo, 'schemas/model/v1/aipt-model-profile.schema.json');
  const samplingSchema = readJSON(repo, 'schemas/model/v1/aipt-sampling-profile.schema.json');
  const certificationSchema = readJSON(repo, 'schemas/model/v1/aipt-model-certification.schema.json');
  problems.push(...validateInstance(profileSchema, evidence?.model_profile).errors
    .map((error) => `${REMOTE_EVIDENCE} model_profile: ${error.message}`));
  problems.push(...validateInstance(samplingSchema, evidence?.sampling_profile).errors
    .map((error) => `${REMOTE_EVIDENCE} sampling_profile: ${error.message}`));
  problems.push(...validateInstance(certificationSchema, evidence?.certification).errors
    .map((error) => `${REMOTE_EVIDENCE} certification: ${error.message}`));
  problems.push(...samplingEvidenceProblems('REMOTE_DEEPSEEK', evidence));
  if (boundObjectDigest(evidence?.model_profile) !== evidence?.model_profile?.sha256 ||
      boundObjectDigest(evidence?.sampling_profile) !== evidence?.sampling_profile?.sha256 ||
      boundObjectDigest(evidence?.certification?.execution_tuple) !== evidence?.certification?.execution_tuple?.sha256 ||
      boundObjectDigest(evidence?.certification) !== evidence?.certification?.sha256) {
    problems.push('REMOTE_DEEPSEEK controlled result contains a bound-object digest mismatch');
  }
  const credential = evidence?.model_profile?.credential_reference;
  const validation = evidence?.credential_validation;
  const harness = evidence?.model_profile?.harness_identity;
  const probe = evidence?.harness_probe;
  const certification = evidence?.certification;
  if (credential?.kind !== 'ENVIRONMENT_VARIABLE' || credential?.locator !== 'DEEPSEEK_API_KEY' ||
      validation?.reference_id !== credential?.reference_id || validation?.kind !== credential?.kind ||
      validation?.state !== 'VALID' || !exactSet(Object.keys(validation?.metadata ?? {}), ['source', 'exposure']) ||
      validation?.metadata?.source !== 'environment' || validation?.metadata?.exposure !== 'write-only' ||
      harness?.version !== '0.1.0-rc.8' || harness?.commit !== HARNESS_COMMIT ||
      harness?.package_sha256 !== HARNESS_SOURCE_SHA256 || harness?.capability_fingerprint !== HARNESS_CAPABILITY_SHA256 ||
      probe?.harness_identity !== `deepseek-harness@0.1.0-rc.8+${HARNESS_COMMIT}` ||
      probe?.observed_model_id !== 'deepseek-v4-pro' || probe?.route_available !== true ||
      probe?.direct_provider_bypass_available !== false || probe?.capability_fingerprint !== HARNESS_CAPABILITY_SHA256 ||
      certification?.kind !== 'CONTROLLED_REAL' || certification?.minimum_certification !== true ||
      certification?.real_model_calls !== 1 || certification?.result !== 'PASS' ||
      certification?.evidence_identity !== 'AIPT-MVP-B004-REMOTE-DEEPSEEK-CONTROLLED-REAL-02' ||
      certification?.execution_tuple?.backend_kind !== 'REMOTE_DEEPSEEK' ||
      certification?.execution_tuple?.local_runtime_identity !== undefined ||
      !/^[0-9a-f]{64}$/u.test(evidence?.request_sha256 ?? '') ||
      !/^[0-9a-f]{64}$/u.test(evidence?.response_sha256 ?? '')) {
    problems.push('REMOTE_DEEPSEEK controlled result identity/credential/probe/call binding is invalid');
  }

  const localTopLevel = [
    'schema', 'result', 'backend_kind', 'model_profile', 'sampling_profile', 'certification',
    'harness_probe', 'request_sha256', 'response_sha256', 'response_protocol_version',
    'route_recovery_occurred', 'credential_values_recorded', 'private_paths_recorded',
  ];
  if (!exactSet(Object.keys(localEvidence ?? {}), localTopLevel) ||
      localEvidence?.schema !== 'aipt.public.controlled-model-certification-result/v1' ||
      localEvidence?.result !== 'PASS' || localEvidence?.backend_kind !== 'LOCAL_LLAMACPP' ||
      localEvidence?.response_protocol_version !== 'v1' || localEvidence?.route_recovery_occurred !== false ||
      localEvidence?.credential_values_recorded !== false || localEvidence?.private_paths_recorded !== false ||
      privatePathPresent(localEvidence)) {
    problems.push('LOCAL_LLAMACPP controlled result is not the exact path-free public envelope');
  }
  problems.push(...validateInstance(profileSchema, localEvidence?.model_profile).errors
    .map((error) => `${LOCAL_EVIDENCE} model_profile: ${error.message}`));
  problems.push(...validateInstance(samplingSchema, localEvidence?.sampling_profile).errors
    .map((error) => `${LOCAL_EVIDENCE} sampling_profile: ${error.message}`));
  problems.push(...validateInstance(certificationSchema, localEvidence?.certification).errors
    .map((error) => `${LOCAL_EVIDENCE} certification: ${error.message}`));
  problems.push(...samplingEvidenceProblems('LOCAL_LLAMACPP', localEvidence));
  if (boundObjectDigest(localEvidence?.model_profile) !== localEvidence?.model_profile?.sha256 ||
      boundObjectDigest(localEvidence?.sampling_profile) !== localEvidence?.sampling_profile?.sha256 ||
      boundObjectDigest(localEvidence?.certification?.execution_tuple) !== localEvidence?.certification?.execution_tuple?.sha256 ||
      boundObjectDigest(localEvidence?.certification) !== localEvidence?.certification?.sha256) {
    problems.push('LOCAL_LLAMACPP controlled result contains a bound-object digest mismatch');
  }
  const localProfile = localEvidence?.model_profile;
  const localRuntime = localProfile?.local_runtime_identity;
  const localCertification = localEvidence?.certification;
  const localTuple = localCertification?.execution_tuple;
  const localProbe = localEvidence?.harness_probe;
  const expectedLaunch = [
    '--ctx-size', '8192', '--n-predict', '1024', '--n-gpu-layers', '99',
    '--model', '{REGISTERED_GGUF}', '--host', '127.0.0.1',
    '--port', '{DYNAMIC_IPV4_LOOPBACK_PORT}', '--alias', '{REGISTERED_MODEL_ID}',
    '--no-webui', '--no-slots', '--jinja',
  ];
  if (localProfile?.backend_kind !== 'LOCAL_LLAMACPP' || localProfile?.provider_identity !== 'llama.cpp' ||
      localProfile?.model_id !== 'gguf-04' || localProfile?.credential_reference !== undefined ||
      localProfile?.harness_identity?.version !== '0.1.0-rc.8' ||
      localProfile?.harness_identity?.commit !== HARNESS_COMMIT ||
      localProfile?.harness_identity?.package_sha256 !== HARNESS_SOURCE_SHA256 ||
      localProfile?.harness_identity?.capability_fingerprint !== HARNESS_CAPABILITY_SHA256 ||
      localRuntime?.executable_reference !== 'llama-server-gfx1151-b10582' ||
      localRuntime?.binary_sha256 !== 'b3afdd9c155dd481aaff6f26204104a3f4967fa8bc4a94ec6da4e9a57e6acad2' ||
      localRuntime?.version !== '0.2.0-dev' || localRuntime?.commit !== 'e85caa81ea2b65797396018c179b87ad61fa38ab' ||
      localRuntime?.gguf_reference !== GGUF_REFERENCE || localRuntime?.gguf_sha256 !== GGUF_SHA256 ||
      localRuntime?.gguf_model_identity !== 'Qwen3.8-27B-Abliterated' ||
      localRuntime?.quantization_identity !== 'Q8_0' ||
      localRuntime?.template_identity !== 'GGUF-04-qwen35-jinja' ||
      localRuntime?.template_sha256 !== 'c3cf9e34abf4f9e36c2d72165aa9c132d3e2a725b6c2586aaa3a8af9d7a81041' ||
      localRuntime?.isolation_identity !== ISOLATION_IDENTITY ||
      localRuntime?.isolation_helper_reference !== ISOLATION_HELPER_REFERENCE ||
      localRuntime?.isolation_helper_sha256 !== ISOLATION_HELPER_SHA256 ||
      JSON.stringify(localRuntime?.launch_parameters) !== JSON.stringify(expectedLaunch) ||
      localRuntime?.hardware?.architecture !== 'x86_64' || localRuntime?.hardware?.gpu_backend !== 'ROCm-gfx1151' ||
      localCertification?.kind !== 'CONTROLLED_REAL' || localCertification?.minimum_certification !== true ||
      localCertification?.real_model_calls !== 1 || localCertification?.result !== 'PASS' ||
      localCertification?.evidence_identity !== 'AIPT-MVP-B004-LOCAL-LLAMACPP-CONTROLLED-REAL-02' ||
      localCertification?.production_role_eligibility !== 'NOT_GRANTED_DEFER_003' ||
      localTuple?.backend_kind !== 'LOCAL_LLAMACPP' ||
      JSON.stringify(localTuple?.local_runtime_identity) !== JSON.stringify(localRuntime) ||
      localProbe?.harness_identity !== `deepseek-harness@0.1.0-rc.8+${HARNESS_COMMIT}` ||
      localProbe?.observed_model_id !== 'gguf-04' || localProbe?.route_available !== true ||
      localProbe?.direct_provider_bypass_available !== false ||
      localProbe?.capability_fingerprint !== HARNESS_CAPABILITY_SHA256 ||
      !/^[0-9a-f]{64}$/u.test(localEvidence?.request_sha256 ?? '') ||
      !/^[0-9a-f]{64}$/u.test(localEvidence?.response_sha256 ?? '')) {
    problems.push('LOCAL_LLAMACPP controlled result identity/probe/call binding is invalid');
  }

  if (gguf?.schema !== 'aipt.public.gguf-registration/v1' || gguf?.registration_id !== GGUF_REFERENCE ||
      gguf?.sha256 !== GGUF_SHA256 || gguf?.identity_state !== 'FROZEN' ||
      gguf?.asset_locator_registered !== true || gguf?.asset_locator_exported !== false ||
      gguf?.asset_verification_state !== 'PASS' || gguf?.approved_root_containment !== 'PASS' ||
      gguf?.canonical_target_match !== 'PASS' || gguf?.full_file_sha256_recomputed !== true ||
      gguf?.model_identity_state !== 'VERIFIED_METADATA_MATCH' ||
      gguf?.quantization_identity_state !== 'VERIFIED_Q8_0' ||
      gguf?.template_identity_state !== 'VERIFIED_SHA256_MATCH' ||
      gguf?.metadata?.gguf_version !== 3 || gguf?.metadata?.tensor_count !== 866 ||
      gguf?.metadata?.architecture !== 'qwen35' ||
      gguf?.metadata?.model_identity !== 'Qwen3.8-27B-Abliterated' ||
      gguf?.metadata?.basename !== 'Qwen3.8' || gguf?.metadata?.size_label !== '27B' ||
      gguf?.metadata?.parameter_count !== 27320697856 ||
      gguf?.metadata?.quantization_identity !== 'Q8_0' ||
      gguf?.metadata?.chat_template_identity !== 'GGUF-04-qwen35-jinja' ||
      gguf?.metadata?.chat_template_bytes !== 8952 ||
      gguf?.metadata?.chat_template_sha256 !== 'c3cf9e34abf4f9e36c2d72165aa9c132d3e2a725b6c2586aaa3a8af9d7a81041' ||
      gguf?.download_allowed !== false || gguf?.substitution_allowed !== false ||
      gguf?.controlled_local_certification !== 'PASS' ||
      gguf?.private_paths_recorded !== false || privatePathPresent(gguf)) {
    problems.push('GGUF-04 public registration is not frozen, verified, and path-free exactly');
  }
  if (llama?.schema !== 'aipt.public.llamacpp-runtime-registration/v1' ||
      llama?.registration_id !== 'LLAMACPP-01' ||
      llama?.binary_sha256 !== 'b3afdd9c155dd481aaff6f26204104a3f4967fa8bc4a94ec6da4e9a57e6acad2' ||
      llama?.version !== '0.2.0-dev' || llama?.build !== 10582 ||
      llama?.commit !== 'e85caa81ea2b65797396018c179b87ad61fa38ab' ||
      llama?.source_worktree_clean !== true || llama?.gguf_binding !== GGUF_REFERENCE ||
      llama?.gguf_sha256 !== GGUF_SHA256 || llama?.asset_locator_registered !== true ||
      llama?.asset_locator_exported !== false || llama?.rocm_device_compatibility !== 'PASS' ||
      llama?.managed_startup_identity_probe !== 'PASS' ||
      llama?.verified_asset_execution !== 'HELD_FILE_OBJECT' ||
      llama?.isolation_identity !== ISOLATION_IDENTITY ||
      llama?.isolation_helper_reference !== ISOLATION_HELPER_REFERENCE ||
      llama?.isolation_helper_sha256 !== ISOLATION_HELPER_SHA256 ||
      llama?.endpoint_access_control !== 'PRIVATE_USER_NETWORK_NAMESPACE' ||
      llama?.host_direct_access !== 'REJECTED' || llama?.llama_api_key_added !== false ||
      llama?.harness_routed_minimum_role_invocation !== 'PASS' ||
      llama?.bounded_shutdown_and_failure_probes !== 'PASS' || llama?.local_real_model_calls !== 2 ||
      llama?.controlled_local_certification !== 'PASS' ||
      llama?.controlled_local_certification_evidence !== LOCAL_EVIDENCE ||
      llama?.private_paths_recorded !== false || privatePathPresent(llama)) {
    problems.push('LLAMACPP-01 public runtime registration is invalid');
  }
  return problems;
}

function sourceContractProblems(repo) {
  const problems = [];
  const productionGo = REQUIRED_GO.filter((relative) => !relative.endsWith('_test.go')).map((relative) => read(repo, relative)).join('\n');
  const tests = REQUIRED_GO.filter((relative) => relative.endsWith('_test.go')).map((relative) => read(repo, relative)).join('\n');
  const worker = read(repo, 'packages/model-harness-gateway/src/model-process-worker.ts');
  const workerTests = read(repo, 'packages/model-harness-gateway/test/model-process-worker.test.ts');
  const sdkSecurityTests = read(repo, 'packages/adapter-sdk/test/security-repair.test.ts');
  const publicationTests = read(repo, 'scripts/ci/test/publication-hygiene.test.mjs');
  const schemaSecurityTests = read(repo, 'scripts/ci/test/json-schema-security.test.mjs');
  const closureSource = read(repo, 'scripts/ci/harness-runtime-closure.ts');
  const closureBuilder = read(repo, 'scripts/ci/build-harness-runtime-closure.mjs');
  const nodeProduction = ['index.ts', 'protocol.ts', 'model-process-worker.ts']
    .map((name) => read(repo, `packages/model-harness-gateway/src/${name}`)).join('\n');
  const required = [
    'type ModelProfile struct', 'type SamplingProfile struct', 'type ExecutionTuple struct', 'type Certification struct',
    'type CredentialBroker interface', 'type Gateway struct', 'func (g *Gateway) Invoke',
    'type ManagedLlama struct', 'func NewManagedLlama', 'func (m *ManagedLlama) Recover',
    'func BindManifestModels', 'func ApplyExplicitReplacement', 'func PrepareContext', 'func ValidateEgress',
    'type RuntimeCoordinator struct', 'func (c *RuntimeCoordinator) StartModel', 'func (c *RuntimeCoordinator) StartHarness',
    'type ControlledCertificationSpec struct', 'func RunControlledCertification',
    'func openVerifiedAsset', 'func verifyProcessExecutableAsset', 'func bindManagedProcessIdentity',
    'PidFD: &pidfd', 'process.WithHandle', 'func (m *ManagedLlama) Retire',
    'func (m *ManagedLlama) startIsolatedLifecycle', 'func RunRuntimeIsolator',
    'func (m *ManagedLlama) abortIsolatedStart', 'func mountPrivateProc',
    'endpointUnreachableFromHost', 'CLONE_NEWUSER', 'CLONE_NEWNET', 'CLONE_NEWPID', 'CLONE_NEWNS',
    'aipt-model-run-audit-v1-',
    'RequestSHA256', 'trustedBreakGlassVerifier', 'authoritativeBreakGlassConsumption',
    'readRunAuditState', 'ExpectedSequence: expectedSequence', 'RunClassification',
    'type ed25519BreakGlassVerifier struct', 'type postgresqlAuditSink struct',
    'controlledHarnessVersion', 'controlledHarnessCommit', 'controlledGGUFReference', 'controlledGGUFSHA256',
    'REMOTE_DEEPSEEK', 'LOCAL_LLAMACPP', 'deepseek-v4-pro', 'agent-client-protocol',
  ];
  for (const token of required) if (!productionGo.includes(token)) problems.push(`model gateway source contract missing ${token}`);
  for (const id of Array.from({ length: 30 }, (_, index) => `M${String(index + 1).padStart(2, '0')}`)) {
    if (!tests.includes(id)) problems.push(`security negative matrix missing ${id}`);
  }
  for (const token of [
    'cancelledSessions', 'environment_allowlist', 'argument_file_digests', 'detached: true',
    'AIPT_MODEL_GATEWAY_IDENTITY_MISMATCH', 'metadata.protocol_version "v1"',
    'AIPT_MODEL_GATEWAY_HARNESS_BOOT_FAILED', 'AIPT_MODEL_GATEWAY_MODEL_REQUEST_FAILED',
    'AIPT_ACP_OUTPUT_BUDGET_SCHEMA', 'readAcpFrames', 'rawBytes',
    'max_stdout_protocol_bytes', 'max_notification_bytes',
    'max_response_and_notification_bytes', 'max_stderr_bytes', 'budgetedNotification',
    'sealChildLifetime', 'retireChild(true)', 'stderrTask',
    'openVerifiedChildAssets', 'runtime_closure', 'VERIFIED_SINGLE_FILE_DATA_URL_V1',
    'childExecutableIdentity',
    'requested_sampling_sha256', 'effective_sampling_projection', 'backend_serialized_request_sha256',
  ]) {
    if (!worker.includes(token)) problems.push(`Harness process boundary missing ${token}`);
  }
  for (const token of [
    'TestListenerOwnershipRaceIsRejected',
    'pidfd process-generation identity remained valid after child exit',
    'TestBreakGlassConcurrentDoubleConsumptionHasExactlyOneWinner',
    'TestEveryGatewayRequiresAuthoritativeRunAuditSink',
    'TestFormalInvocationAuditRejectsConcurrentRunDisqualificationAfterFinalRead',
    'modified request payload accepted',
    'different diagnostic identity remains run-disqualified',
    'TestPostgresIntegrationBreakGlassAtomicReplayAndRestart',
    'clean invocation committed after disqualification',
    'TestVerifiedAssetUsesWriteSealedSnapshotAfterInPlaceMutation',
    'TestVerifiedAssetPathReplacementCannotChangeExecutableOrGGUF',
    'TestRuntimeEnvironmentInjectionCannotBypassVerifiedExecutables',
    'TestPrepareContextRejectsOversizedElementInventoryBeforeHashing',
    'TestFailedSpawnCleanupIsBoundedAndNeverSignalsInvalidOrUnrelatedPID',
    'TestManagedLifecycleConcurrentStartStopIsLinearizableAndLeakFree',
    'TestOnlyIsolatedAdapterCanReachManagedLlamaLoopback',
  ]) {
    if (!tests.includes(token)) problems.push(`B004 security repair regression missing ${token}`);
  }
  for (const token of [
    'verified Harness runtime pathname replacement cannot change the launched closure',
    'probe and invocation traverse the additive adapter and ACP child',
    'partial Harness initialization failure is rejected and the spawned child is retired',
    'sampling profile drift and silently claimed ACP parameters fail closed',
    'many small valid ACP frames fail closed',
    'active session output is charged incrementally before accumulation',
    'id-bearing session/update cannot bypass notification category budgets',
    'notification byte boundary passes exactly and boundary plus one rejects',
    'total stdout protocol byte boundary passes exactly and boundary plus one rejects',
    'stdout budget charges raw BOM and unterminated bytes before parsing',
    'stderr has an independent exact byte budget',
    'outer success waits for the complete ACP child lifetime budget verdict',
    'trailing total stdout overflow REJECTS with no result',
    'trailing notification overflow REJECTS with no result',
    'trailing response plus notification overflow REJECTS with no result',
    'trailing stderr overflow REJECTS with no result',
    'oversized encoded outer response rejects without partial semantics',
  ]) {
    if (!workerTests.includes(token)) problems.push(`ACP aggregate output regression missing ${token}`);
  }
  for (const token of [
    'canonical JSON preserves own __proto__ without prototype mutation or digest collision',
    'versioned JSON depth, node, width, and byte limits fail closed without stack exhaustion',
    'schema enum and uniqueItems deep-comparison work is charged and bounded',
    'caller-controlled catastrophic schema patterns are rejected before execution',
    'a shallow document cannot hide an over-limit recursive $ref chain',
  ]) {
    if (!sdkSecurityTests.includes(token)) problems.push(`SDK security repair regression missing ${token}`);
  }
  for (const token of [
    'every synthetic leak class is detected and clean removal passes',
    'missing and unsupported coverage fail closed instead of reporting zero',
    'detector and finding budgets fail closed with bounded redacted output',
    'legacy hazard reports never retain or echo matched sensitive material',
  ]) {
    if (!publicationTests.includes(token)) problems.push(`publication hygiene sentinel regression missing ${token}`);
  }
  if (!schemaSecurityTests.includes('REJECT_SCHEMA_UNSAFE_PATTERN') ||
      !schemaSecurityTests.includes('bounds JSON resources')) {
    problems.push('shared CI JSON Schema security regression is incomplete');
  }
  for (const token of ['@deepseek-ai/cordis', '@deepseek-ai/dsh-acp', '@deepseek-ai/dsh-agent-spine-demo', '@deepseek-ai/dsh-llm-deepseek']) {
    if (!closureSource.includes(token)) problems.push(`verified Harness runtime closure source missing ${token}`);
  }
  for (const token of [HARNESS_COMMIT, 'writeFileSync', 'MAX_CLOSURE_BYTES']) {
    if (!closureBuilder.includes(token)) problems.push(`verified Harness runtime closure builder missing ${token}`);
  }
  for (const forbidden of ['fetch(', 'axios', 'curl ', 'huggingface.co']) {
    if (nodeProduction.toLowerCase().includes(forbidden.toLowerCase()) || productionGo.toLowerCase().includes(forbidden.toLowerCase())) {
      problems.push(`direct provider/model-download bypass surface present: ${forbidden}`);
    }
  }
  // Download-oriented llama arguments must be explicitly denied by the
  // managed launcher; their presence in the deny-list is a security control,
  // not a download implementation.
  for (const denied of ['--model-url', '--hf-repo', '--hf-file']) {
    if (!productionGo.includes(denied)) problems.push(`managed llama download-argument deny-list missing ${denied}`);
  }
  const gatewayPackage = readJSON(repo, 'packages/model-harness-gateway/package.json');
  if (JSON.stringify(gatewayPackage.dependencies) !== JSON.stringify({ '@aipt/harness-adapter': 'workspace:*' })) {
    problems.push('model Harness gateway dependency set is not exactly the frozen harness adapter');
  }
  return problems;
}

function securityReproductionProblems(repo) {
  const evidence = readJSON(repo, SECURITY_REPRODUCTIONS);
  const problems = [];
  const findings = new Map((evidence?.reproductions ?? []).map((item) => [item.finding_id, item]));
  const expected = [
    'F01_PROTO_CANONICAL_COLLISION',
    'F02_VERIFIED_PATH_REOPEN_TOCTOU',
    'F03_PUBLICATION_DETECTOR_FALSE_ZERO',
    'F04_SAMPLING_CONTROL_DROP',
    'F05_PROCESS_LIFECYCLE_RACE',
    'F06_FAILED_SPAWN_CLEANUP',
    'F07_RECURSION_STACK_DOS',
    'F08_LOCAL_LLAMA_UNAUTH_ACCESS',
    'F09_SCHEMA_REGEX_DOS',
  ];
  if (evidence?.schema !== 'aipt.public.b004-security-repair-reproductions/v1' ||
      evidence?.task_id !== TASK_ID || evidence?.authorization !== 'IN_BATCH_SECURITY_REPAIR' ||
      evidence?.base_commit !== BASE_COMMIT || evidence?.real_model_calls !== 0 ||
      evidence?.provider_network_calls !== 0 || evidence?.findings_tested !== 9 ||
      evidence?.remaining_reproducible !== 0 || evidence?.rejected_candidate?.commit !== 'abd684a4d858376866766d67653f212c26ca4215' ||
      evidence?.rejected_candidate?.tree !== '0141bb24f7c46cfcc3d0ce0a50b17a0adf631d93' ||
      evidence?.rejected_candidate?.status !== 'REJECTED_PRE_PUSH_SECURITY_RESCAN' ||
      !Array.isArray(evidence?.reproductions) || evidence.reproductions.length !== expected.length ||
      findings.size !== expected.length) {
    problems.push('B004 security-repair reproduction envelope is invalid');
  }
  for (const findingID of expected) {
    const finding = findings.get(findingID);
    if (finding?.status !== 'FIXED' || finding?.original_issue_confirmed !== true ||
        finding?.post_fix_test !== 'PASS' || finding?.original?.status !== 'CONFIRMED' ||
        finding?.post_fix?.status !== 'REJECTED_AFTER_FIX' ||
        typeof finding?.original?.command !== 'string' || finding.original.command.length === 0 ||
        !Array.isArray(finding?.post_fix?.commands) || finding.post_fix.commands.length === 0) {
      problems.push(`B004 security-repair reproduction is incomplete: ${findingID}`);
    }
  }
  if (evidence?.postgresql_atomicity?.local_status !== 'NOT_RUN_NO_LOOPBACK_DSN' ||
      evidence?.postgresql_atomicity?.public_ci_required !== true ||
      !evidence?.postgresql_atomicity?.normal_command?.includes('AIPT_REQUIRE_POSTGRES_INTEGRATION=1') ||
      !evidence?.postgresql_atomicity?.race_command?.includes('go test -race')) {
    problems.push('B004 PostgreSQL atomicity evidence overclaims local execution or omits required public CI');
  }
  return problems;
}

function statusProblems(repo, topology) {
  const problems = [];
  const status = readJSON(repo, 'docs/authority/registry/project-status.json');
  const standalone = status.tracks?.['AIPT-STANDALONE'];
  const b003 = status.repositories?.AIPT?.mvp_b003;
  if (b003?.candidate?.commit !== B003_CANDIDATE || b003?.implementation_merge?.commit !== B003_MERGE ||
      (b003?.post_merge_ci?.run ?? b003?.post_merge_ci?.run_id) !== B003_MERGE_CI ||
      !b003?.closed) {
    problems.push('B003 accepted Candidate/merge/CI/closeout projection changed');
  }
  const b004 = status.repositories?.AIPT?.mvp_b004;
  if (b004?.task_id !== TASK_ID || b004?.base?.commit !== BASE_COMMIT || b004?.base?.tree !== BASE_TREE ||
      b004?.scope !== 'VERSIONED_MODEL_PROFILES_AND_GOVERNED_REAL_HARNESS_GATEWAY' ||
      JSON.stringify(b004?.supported_backends) !== JSON.stringify(['REMOTE_DEEPSEEK', 'LOCAL_LLAMACPP']) ||
      b004?.primary_remote_model !== 'deepseek-v4-pro' || b004?.harness_identity?.release !== HARNESS_RELEASE ||
      b004?.harness_identity?.commit !== HARNESS_COMMIT || b004?.harness_identity?.protocol_version !== '1' ||
      b004?.harness_identity?.registration_id !== 'HARNESS-01' ||
      b004?.harness_identity?.source_archive_sha256 !== HARNESS_SOURCE_SHA256 ||
      b004?.harness_identity?.capability_fingerprint !== HARNESS_CAPABILITY_SHA256 ||
      b004?.harness_identity?.runtime_closure_kind !== 'VERIFIED_SINGLE_FILE_DATA_URL_V1' ||
      b004?.harness_identity?.runtime_closure_sha256 !== HARNESS_RUNTIME_CLOSURE_SHA256 ||
      b004?.real_model_gateway_implemented !== true || b004?.model_launcher_gate_implemented !== true ||
      b004?.harness_launcher_gate_implemented !== true || b004?.launcher_plan_first_unimplemented_gate !== 'IPC' ||
      b004?.real_playtest_executed !== false || b004?.qualification_runs_executed !== 0 || b004?.new_migration !== 'NONE' ||
      !Array.isArray(b004?.open_findings) || b004.open_findings.length !== 0) {
    problems.push('B004 authority/status boundary projection is invalid');
  }
  const preAcceptance = ['CONSTRUCTION_WORKTREE', 'INITIAL_CANDIDATE', 'LEGAL_MERGE'].includes(topology.phase);
  if (preAcceptance) {
    if (status.authority_snapshot_id !== 'AIPT-MVP-B004-CONSTRUCTION-001' ||
        standalone?.construction !== 'IN_PROGRESS' || standalone?.current_batch !== TASK_ID || standalone?.global_wip !== 1 ||
        standalone?.next_serial_batch !== 'INT-AIPT-UNREGISTERED-MVP-001' || standalone?.next_batch_authorized !== false ||
        standalone?.next_batch_started !== false || standalone?.batch_history?.[TASK_ID] !== 'IN_PROGRESS' ||
        standalone?.batch_history?.['INT-AIPT-UNREGISTERED-MVP-001'] !== 'NOT_STARTED' ||
        b004?.state !== 'IN_PROGRESS' || b004?.merged !== false || b004?.closed !== false) {
      problems.push('B004 construction/WIP/serial boundary is invalid');
    }
  }
  if (topology.phase === 'CONSTRUCTION_WORKTREE') {
    const certification = b004?.controlled_certification;
    const preflight = certification?.preflight;
    const observedBridge = preflight?.observed_owner_local_development_bridge;
    if (certification?.real_harness !== 'PASS' || certification?.remote_deepseek !== 'PASS' ||
        certification?.local_llamacpp !== 'PASS' ||
        certification?.remote_evidence !== REMOTE_EVIDENCE || certification?.local_evidence !== LOCAL_EVIDENCE ||
        !exactSet(certification?.superseded_non_final_evidence,
          [SUPERSEDED_REMOTE_EVIDENCE, SUPERSEDED_LOCAL_EVIDENCE]) ||
        certification?.public_ci_real_model_calls !== 0 ||
        preflight?.product_runtime_config_registered !== false ||
        preflight?.product_credential_reference_registered !== true ||
        preflight?.credential_reference_kind !== 'ENVIRONMENT_VARIABLE' ||
        preflight?.credential_reference_locator !== 'DEEPSEEK_API_KEY' ||
        preflight?.frozen_harness_route_registered !== true ||
        preflight?.frozen_harness_identity?.release !== HARNESS_RELEASE ||
        preflight?.frozen_harness_identity?.commit !== HARNESS_COMMIT ||
        preflight?.gguf_registration_id !== GGUF_REFERENCE || preflight?.gguf_sha256 !== GGUF_SHA256 ||
        preflight?.gguf_identity_registered !== true || preflight?.gguf_asset_locator_registered !== true ||
        preflight?.gguf_asset_locator_exported !== false || preflight?.gguf_full_sha256_recomputed !== true ||
        preflight?.gguf_metadata_identity_verified !== true ||
        preflight?.llamacpp_registration_id !== 'LLAMACPP-01' || preflight?.llamacpp_runtime_registered !== true ||
        preflight?.llamacpp_managed_startup_verified !== true ||
        preflight?.llamacpp_bounded_shutdown_verified !== true ||
        preflight?.verified_asset_execution !== 'HELD_FILE_OBJECT' ||
        preflight?.harness_runtime_closure_verified !== true ||
        preflight?.local_isolation_identity !== ISOLATION_IDENTITY ||
        preflight?.local_isolation_helper_sha256 !== ISOLATION_HELPER_SHA256 ||
        preflight?.host_direct_llama_access !== 'REJECTED' || preflight?.llama_api_key_added !== false ||
        observedBridge?.use_scope !== 'owner-local-development' ||
        observedBridge?.release !== OBSERVED_OWNER_LOCAL_BRIDGE_RELEASE ||
        observedBridge?.commit !== OBSERVED_OWNER_LOCAL_BRIDGE_COMMIT ||
        observedBridge?.frozen_identity_match !== false ||
        observedBridge?.accepted_as_product_certification !== false ||
        preflight?.real_calls_attempted !== 5 || preflight?.successful_certification_real_model_calls !== 4 ||
        preflight?.local_certification_attempts !== 3 || preflight?.local_pre_call_failures !== 1 ||
        preflight?.local_real_model_calls !== 2 ||
        preflight?.local_successful_certification_real_model_calls !== 2 ||
        preflight?.credential_values_recorded !== 0 || preflight?.private_paths_recorded !== 0 ||
        b004?.rejected_pre_push_candidate?.commit !== 'abd684a4d858376866766d67653f212c26ca4215' ||
        b004?.rejected_pre_push_candidate?.tree !== '0141bb24f7c46cfcc3d0ce0a50b17a0adf631d93' ||
        b004?.rejected_pre_push_candidate?.status !== 'REJECTED_PRE_PUSH_SECURITY_RESCAN' ||
        b004?.rejected_pre_push_candidate?.publicly_pushed !== false ||
        b004?.rejected_pre_push_candidate?.public_ci_started !== false ||
        b004?.security_repair?.authorization !== 'IN_BATCH_SECURITY_REPAIR' ||
        b004?.security_repair?.findings_tested !== 9 || b004?.security_repair?.findings_closed !== 9 ||
        b004?.security_repair?.remaining_reproducible !== 0 ||
        b004?.deferred_parameters?.['DEFER-002'] !== 'RESOLVED_BY_OWNER_GGUF-04_IDENTITY' ||
        b004?.real_model_calls !== 5 || b004?.network_model_calls !== 3) {
      problems.push('B004 controlled-real construction registration/certification projection is invalid');
    }
  }
  if (topology.phase === 'INITIAL_CANDIDATE' || topology.phase === 'LEGAL_MERGE') {
    if (b004?.controlled_certification?.real_harness !== 'PASS' ||
        b004?.controlled_certification?.remote_deepseek !== 'PASS' ||
        b004?.controlled_certification?.local_llamacpp !== 'PASS' ||
        b004?.controlled_certification?.remote_evidence !== REMOTE_EVIDENCE ||
        b004?.controlled_certification?.local_evidence !== LOCAL_EVIDENCE ||
        !(b004?.real_model_calls > 0) || !(b004?.network_model_calls > 0) ||
        b004?.controlled_certification?.public_ci_real_model_calls !== 0) {
      problems.push('B004 Candidate/merge lacks both controlled-real minimum certifications');
    }
  }
  return problems;
}

function wiringProblems(repo) {
  const problems = [];
  const manifest = readJSON(repo, 'package.json');
  const expected = {
    'check:mvp-b004': 'node scripts/ci/validate/mvp-b004.mjs',
    'test:model-gateway': 'go test ./internal/modelgateway -count=1',
    'test:model-harness-gateway': 'pnpm --filter @aipt/model-harness-gateway test',
    'test:publication-hygiene': 'node --test scripts/ci/test/publication-hygiene.test.mjs',
  };
  for (const [name, value] of Object.entries(expected)) if (manifest.scripts?.[name] !== value) problems.push(`package script ${name} missing`);
  const aggregate = read(repo, 'scripts/ci/run-checks.mjs');
  if (!aggregate.includes("import { run as runMvpB004 } from './validate/mvp-b004.mjs';") || !aggregate.includes('runMvpB004(ctx)')) {
    problems.push('aggregate B004 validator wiring missing');
  }
  const workflow = read(repo, '.github/workflows/ci.yml');
  for (const token of ['pnpm run check:mvp-b004', 'pnpm run test:publication-hygiene', 'pnpm run test:model-gateway', 'pnpm run test:model-harness-gateway', 'go test -race ./internal/modelgateway']) {
    if (!workflow.includes(token)) problems.push(`public CI B004 wiring missing ${token}`);
  }
  for (const forbidden of ['DEEPSEEK_API_KEY:', 'OPENAI_API_KEY:', 'AIPT_MODEL_RUNTIME_CONFIG:']) {
    if (workflow.includes(forbidden)) problems.push(`public CI requires forbidden private input ${forbidden}`);
  }
  const workflowValidator = read(repo, 'scripts/ci/validate/workflow.mjs');
  if (!workflowValidator.includes('check:mvp-b004') || !workflowValidator.includes('test:publication-hygiene') || !workflowValidator.includes('test:model-gateway') ||
      !workflowValidator.includes('test:model-harness-gateway')) problems.push('workflow validator does not pin B004 gates');
  const launcher = read(repo, 'internal/launcher/gates.go');
  if (!/case GateConfig, GatePostgreSQL, GateMigrations, GateModel, GateHarness, GateCore, GateWeb:\s*return Implemented/u.test(launcher) ||
      !/case GateIPC:\s*return NotImplemented/u.test(launcher) ||
      !launcher.includes('FirstBlockingGate: firstBlocking')) {
    problems.push('launcher plan no longer exposes IPC as the first remaining boundary');
  }
  return problems;
}

export function run(ctx) {
  const repo = ctx.repo;
  const paths = changedPaths(repo);
  const topology = actualTopology(repo, paths);
  const scopePaths = topology.scopePaths ?? paths;
  const problems = [];
  const acceptedPhases = ['CONSTRUCTION_WORKTREE', 'INITIAL_CANDIDATE', 'LEGAL_MERGE', 'POST_MERGE_SUCCESSOR', 'CLOSEOUT_SUCCESSOR', 'CLOSED_HISTORICAL_SUCCESSOR'];
  if (!acceptedPhases.includes(topology.phase)) problems.push(`actual B004 lifecycle topology rejected (${topology.phase})`);
  problems.push(...(topology.lifecycle?.problems ?? []));
  const lifecycleProbes = lifecycleRegressionProbes();
  for (const probe of lifecycleProbes) if (!probe.matched) problems.push(`${probe.id} expected ${probe.expected}, got ${probe.actual}`);
  const unauthorized = scopePaths.filter((relative) => !allowedPath(relative));
  if (unauthorized.length > 0) problems.push(`B004 scope drift: ${unauthorized.join(', ')}`);
  if (!requiredPresent(scopePaths)) problems.push('B004 required implementation/wiring artifacts are absent from candidate scope');
  problems.push(...protectedArtifactProblems(repo));
  const schemas = schemaValidation(repo);
  problems.push(...schemas.problems);
  for (const probe of schemas.probes) if (!probe.matched) problems.push(`${probe.id} unexpectedly accepted or threw`);
  problems.push(...sourceContractProblems(repo));
  problems.push(...securityReproductionProblems(repo));
  problems.push(...controlledEvidenceProblems(repo));
  problems.push(...statusProblems(repo, topology));
  problems.push(...wiringProblems(repo));
  if (PUBLICATION_HYGIENE_POLICY.detector_identity !== PUBLICATION_DETECTOR_IDENTITY ||
      JSON.stringify(PUBLICATION_HYGIENE_POLICY.required_detector_ids) !== JSON.stringify(REQUIRED_PUBLICATION_DETECTORS)) {
    problems.push('publication detector implementation does not match the independently required manifest');
  }
  const inventory = publicationInventory(repo);
  problems.push(...inventory.errors);
  const publication = runPublicationHygiene({
    repo,
    files: inventory.files,
  });
  if (publication.result !== 'PASS') {
    problems.push(`publication hygiene failed: detector_set=${publication.required_detectors_executed} coverage=${publication.coverage} findings=${publication.findings.length} errors=${publication.errors.length}`);
  }

  const details = problems.length === 0 ? [
    `ok: ${topology.phase} derives from exact B003 closeout Base ${BASE_COMMIT}/${BASE_TREE}`,
    `ok: all ${lifecycleProbes.length} candidate/merge/post-merge/closeout/closed topology probes matched`,
    `ok: all ${schemas.probes.length} schema mutations reject; remote and local execution tuple fixtures validate`,
    'ok: versioned profiles/sampling, complete tuple, independent certification and immutable per-role binding are fail-closed',
    'ok: B003 AgentInvoker routes only through the exact governed Harness process boundary; silent fallback is absent',
    'ok: credential write-only semantics, dual egress policy, deterministic context reduction and safe evidence are present',
    'ok: managed llama startup consumes held verified assets inside a private user/network namespace with pidfd-bound, linearized and bounded lifecycle control',
    'ok: M01-M30 are present; public CI uses only synthetic files/processes and zero real model/provider calls',
    `ok: publication hygiene ${publication.detector_identity} executed ${publication.detector_count} required detectors across ${publication.files_scanned} files/${publication.bytes_scanned} bytes with complete coverage`,
    'ok: B001/B002/B003 business artifacts and historical migrations are byte-identical to the authorized Base',
  ] : problems.map((problem) => `FAIL: ${problem}`);
  const unexpectedAcceptances = lifecycleProbes.filter((probe) => probe.expected === 'REJECTED' && probe.actual !== 'REJECTED').length +
    schemas.probes.filter((probe) => probe.actual === 'ACCEPT').length;
  const uncaught = lifecycleProbes.filter((probe) => probe.threw).length + schemas.probes.filter((probe) => probe.threw).length;
  return {
    result: problems.length === 0 ? 'PASS' : 'FAIL', task_id: TASK_ID, details,
    lifecycle_phase: topology.phase, base_commit: BASE_COMMIT, base_tree: BASE_TREE,
    head_commit: topology.head, head_tree: topology.headFacts?.tree ?? null, branch: topology.branch,
    changed_paths: scopePaths, lifecycle_regression_probes: lifecycleProbes, schema_negative_probes: schemas.probes,
    negative_probe_count: lifecycleProbes.length + schemas.probes.length + 30,
    unexpected_acceptances: unexpectedAcceptances, uncaught_validation_errors: uncaught,
    publication_hygiene: publication,
    credential_leaks: (publication.counts.credential_leaks ?? 0) + (publication.counts.environment_secret_leaks ?? 0) + (publication.counts.credential_reference_leaks ?? 0),
    hidden_information_leaks: (publication.counts.private_prompt_leaks ?? 0) + (publication.counts.private_asset_locator_leaks ?? 0) + (publication.counts.private_path_leaks ?? 0),
    public_ci_real_model_calls: 0,
    public_ci_provider_network_calls: 0, public_ci_secret_requirements: 0,
    real_playtest_executed: false, qualification_runs_executed: 0,
    historical_migrations_unchanged: !problems.some((problem) => problem.startsWith('historical migration changed')),
    predecessor_business_semantics_changed: problems.some((problem) => problem.startsWith('protected predecessor artifact changed')),
    runtime_ready: false, first_blocking_gate: 'IPC', merge_authorized: false,
    closeout_authorized: false, next_batch_authorized: false, next_batch_started: false,
  };
}

runAsMain(import.meta.url, 'mvp-b004', run);
