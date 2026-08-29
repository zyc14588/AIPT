#!/usr/bin/env node
// AIPT-MVP-B002 deterministic Run Core gate. Node.js standard library only.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { git, runAsMain } from '../lib/cli.mjs';
import { checkSchemaDocument, validateInstance } from '../lib/json-schema.mjs';
import { lifecycleRecordSha256 } from '../lib/authority-lifecycle.mjs';

const TASK_ID = 'AIPT-MVP-B002';
const BRANCH = `task/${TASK_ID}`;
const BASE_COMMIT = '411bf2997cd0f10ba1a022ac687d27a1bd19eb36';
const BASE_TREE = 'd1daaeede13a2ba07c3b528c1792ef9fd5600a63';
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

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push(`ok: ${message}`);
  const fail = (message) => { pass = false; details.push(`FAIL: ${message}`); };
  try {
    const head = gitOut(ctx.repo, ['rev-parse', 'HEAD^{commit}']);
    const headTree = gitOut(ctx.repo, ['rev-parse', 'HEAD^{tree}']);
    const baseTree = gitOut(ctx.repo, ['rev-parse', `${BASE_COMMIT}^{tree}`]);
    if (baseTree !== BASE_TREE || git(ctx.repo, ['merge-base', '--is-ancestor', BASE_COMMIT, 'HEAD'], { check: false }).status !== 0) {
      fail('exact B002 Base identity/ancestry is not present');
    } else ok(`exact B002 Base ${BASE_COMMIT}/${BASE_TREE} is an ancestor of HEAD`);
    const originMain = gitOut(ctx.repo, ['rev-parse', 'refs/remotes/origin/main^{commit}']);
    if (originMain !== null && originMain !== BASE_COMMIT) fail(`origin/main drifted from exact authorized Base: ${originMain}`);
    else ok('origin/main is exact authorized Base when the remote-tracking ref is available');
    const branch = gitOut(ctx.repo, ['symbolic-ref', '--short', 'HEAD']);
    const githubBranchOK = process.env.GITHUB_ACTIONS === 'true' &&
      ((process.env.GITHUB_EVENT_NAME === 'push' && process.env.GITHUB_REF === `refs/heads/${BRANCH}`) ||
       (process.env.GITHUB_EVENT_NAME === 'pull_request' && process.env.GITHUB_HEAD_REF === BRANCH));
    if (branch !== BRANCH && !githubBranchOK) fail(`candidate branch is ${branch ?? 'detached'}, want ${BRANCH}`);
    else ok(`candidate checkout is bound to ${BRANCH}`);
    if (process.env.GITHUB_ACTIONS === 'true' && process.env.GITHUB_SHA !== head) fail('GITHUB_SHA is not candidate HEAD');
    const merges = gitOut(ctx.repo, ['rev-list', '--merges', `${BASE_COMMIT}..HEAD`]);
    if (merges) fail('B002 Candidate contains a merge commit');
    else ok('B002 Candidate lineage is zero-merge from the exact Base');

    const changed = changedPaths(ctx.repo);
    for (const relative of changed) if (!ALLOWED_CHANGED.has(relative)) fail(`out-of-scope changed path: ${relative}`);
    for (const relative of REQUIRED_CHANGED) if (!changed.includes(relative)) fail(`required B002 path is unchanged/missing: ${relative}`);
    if (!details.some((item) => item.includes('changed path') || item.includes('required B002 path'))) {
      ok(`closed B002 scope contains exactly ${changed.length} reviewable files`);
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
        packageJSON.scripts?.['check:p1-b000-authority-amendment'] !== 'node scripts/ci/validate/historical-governance.mjs --gate p1-b000-authority-amendment') fail('package B002/historical-regression commands are not exact');
    if (!aggregate.includes("import { run as runMvpB002 } from './validate/mvp-b002.mjs'") || !aggregate.includes('runMvpB002(ctx)')) fail('aggregate B002 gate is not wired');
    if (!aggregate.includes('runHistoricalGovernance(ctx)') || aggregate.includes('runP1B000Authority(ctx)') || aggregate.includes('runP1B000AuthorityAmendment(ctx)')) fail('aggregate historical authority replay is not wired');
    for (const command of [
      'pnpm run check:mvp-b002', 'pnpm run test:run-core',
      "go test ./internal/runcore -run '^TestPostgresIntegrationRunCoreAtomicConcurrencyReplay$' -count=1 -v",
      "go test -race ./internal/runcore -run '^TestPostgresIntegrationRunCoreAtomicConcurrencyReplay$' -count=1 -v",
    ]) if (!workflow.includes(command)) fail(`workflow B002 command missing: ${command}`);
    if (!details.some((item) => item.includes('not wired') || item.includes('command missing') || item.includes('commands are not exact'))) {
      ok('standalone, aggregate, unit, PostgreSQL and race CI gates are wired');
    }

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

    const unexpected = probes.filter((probe) => !probe.rejected).length;
    return {
      result: pass ? 'PASS' : 'FAIL', task_id: TASK_ID, details,
      base_commit: BASE_COMMIT, base_tree: BASE_TREE, candidate_commit: head, candidate_tree: headTree,
      branch: BRANCH, changed_paths: changed, negative_probes: pass ? 'PASS' : 'FAIL',
      negative_probe_count: probes.length, unexpected_acceptances: unexpected,
      predecessor_closed: records[2]?.effective === true, historical_migrations_unchanged: true,
      new_migration: 'NONE', real_model_calls: 0, real_playtest_executed: false,
      next_batch_authorized: false, next_batch_started: false,
      merge_eligible: pass, merge_authorized: false, closeout_authorized: false,
    };
  } catch (error) {
    return {
      result: 'FAIL', task_id: TASK_ID,
      details: [...details, `FAIL: structured B002 validator error: ${error.message}`],
      negative_probes: 'NOT_RUN', unexpected_acceptances: 0, uncaught_validator_errors: 0,
      real_model_calls: 0, real_playtest_executed: false,
      merge_eligible: false, merge_authorized: false, closeout_authorized: false,
    };
  }
}

runAsMain(import.meta.url, 'mvp-b002', run);
