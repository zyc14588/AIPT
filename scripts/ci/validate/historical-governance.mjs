#!/usr/bin/env node
// Replays closed lifecycle validators against their exact immutable closeout
// commits. Later governance tasks must preserve those gates without asking a
// closed validator to interpret a new task branch as its own Candidate.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { git, runAsMain } from '../lib/cli.mjs';
import { validateInstance } from '../lib/json-schema.mjs';
import {
  AUTHORITY_LIFECYCLE_EVENTS,
  AUTHORITY_LIFECYCLE_MODEL,
  AUTHORITY_LIFECYCLE_ORDERING,
  lifecycleRecordSha256,
  resolveEffectiveAuthority,
  selfCloseoutBootstrapExpired,
  validateAppendOnlyRecordSet,
  validateImmutableSemanticIdentity,
} from '../lib/authority-lifecycle.mjs';

const A3_TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-003';
const A3_CLOSEOUT_COMMIT = 'd12218f69a31884382e78c7c168b4677b5de8d87';
const A3_CLOSEOUT_TREE = '21cd8d5d80b8c097e959ed2b88394c2f770607e8';
const A3_CANDIDATE = '6d5ce51f8d288a87e05dccf2aeaf88defa15cc04';
const A3_CANDIDATE_TREE = '3facea0f747ddc718bee7416ce3889031f309d9f';
const A3_MERGE = '8ea2eaba9f7785cd215c4db46652cf6cdec950fa';
const A3_MACHINE_PATH = 'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-003.json';
const A3_RECORD_SCHEMA_PATH = 'schemas/authority-lifecycle/v1/aipt-authority-lifecycle-record.schema.json';
const A3_RECORD_ROOT = 'docs/authority/registry/authority-lifecycle/records';
const A3_RECORD_PATHS = Object.freeze([
  `${A3_RECORD_ROOT}/unregistered-aipt-p1-b000-authority-amendment-003/001-merged.json`,
  `${A3_RECORD_ROOT}/unregistered-aipt-p1-b000-authority-amendment-003/002-post-merge-verified.json`,
  `${A3_RECORD_ROOT}/unregistered-aipt-p1-b000-authority-amendment-003/003-closed.json`,
]);
const A3_IMMUTABLE_PATHS = Object.freeze([
  'docs/authority/amendments/UNREGISTERED_AIPT_P1_B000_AUTHORITY_AMENDMENT_003.md',
  A3_MACHINE_PATH,
  'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-003-artifacts.json',
  'docs/authority/registry/authority-lifecycle/registry.json',
  'schemas/authority-amendment/v3/aipt-authority-lifecycle-amendment.schema.json',
  A3_RECORD_SCHEMA_PATH,
  'scripts/ci/lib/authority-lifecycle.mjs',
  'scripts/ci/validate/p1-b000-authority-amendment-003.mjs',
]);
const A3_POLICY = Object.freeze({
  model_id: AUTHORITY_LIFECYCLE_MODEL,
  events: AUTHORITY_LIFECYCLE_EVENTS,
  ordering: AUTHORITY_LIFECYCLE_ORDERING,
  canonical_truth_source: 'ACCEPTED_APPEND_ONLY_LIFECYCLE_RECORD_CHAIN',
  semantic_fields_are_snapshot_metadata: true,
  semantic_artifact_mutation_permitted: false,
  unlisted_transition: 'REJECT',
  closed_terminal: true,
});

const HISTORICAL_GATES = Object.freeze({
  'm0-development-pass': {
    commit: 'c617f3c6ab3e56ac88f228ed4825e751537fc1f0',
    tree: '95a8d2980c5a6aa44f3db67c66f07ff008ff3491',
    validators: [
      'scripts/ci/validate/m0-development-pass.mjs',
      'scripts/ci/validate/status-transition.mjs',
      'scripts/ci/validate/tree-integrity.mjs',
    ],
  },
  'mvp-bootstrap': {
    commit: '64b5692971bbe687884ec34bd6417fe803987ae9',
    tree: '1a6feabb1796af9f66fd78fc842f249ec03a5251',
    validators: ['scripts/ci/validate/mvp-bootstrap.mjs'],
  },
  'p1-b000-authority': {
    commit: '8d6a438d051fb635e769285215e70536958a8f42',
    tree: '9ef6f121bd0d9a6484d7cc39a22450250e9ac489',
    validators: ['scripts/ci/validate/p1-b000-authority.mjs'],
  },
  'p1-b000-authority-amendment': {
    commit: '8d6a438d051fb635e769285215e70536958a8f42',
    tree: '9ef6f121bd0d9a6484d7cc39a22450250e9ac489',
    validators: ['scripts/ci/validate/p1-b000-authority-amendment.mjs'],
  },
  'p1-b000-authority-amendment-003': {
    commit: A3_CLOSEOUT_COMMIT,
    tree: A3_CLOSEOUT_TREE,
    validators: ['scripts/ci/validate/p1-b000-authority-amendment-003.mjs'],
  },
});

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function gitBuffer(repo, args) {
  const result = spawnSync('git', ['-C', repo, ...args], {
    encoding: null,
    maxBuffer: 64 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${result.error?.message ?? result.stderr?.toString('utf8').trim()}`);
  }
  return result.stdout;
}

function commitFacts(repo, commit) {
  const line = git(repo, ['rev-list', '--parents', '-n', '1', commit], { check: false });
  if (line.status !== 0) return null;
  const [resolved, ...parents] = line.stdout.trim().split(/\s+/u);
  const tree = git(repo, ['rev-parse', `${commit}^{tree}`], { check: false });
  return tree.status === 0 ? { commit: resolved, tree: tree.stdout.trim(), parents } : null;
}

function walkJSON(root) {
  if (!fs.existsSync(root)) return [];
  const found = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile() && entry.name.endsWith('.json')) found.push(absolute);
    }
  };
  visit(root);
  return found;
}

function collectCurrentA3Snapshot(repo) {
  const closeout = commitFacts(repo, A3_CLOSEOUT_COMMIT);
  const head = git(repo, ['rev-parse', 'HEAD^{commit}'], { check: false }).stdout.trim();
  const closeoutAncestor = git(repo, ['merge-base', '--is-ancestor', A3_CLOSEOUT_COMMIT, 'HEAD'], { check: false }).status === 0;
  const baselineArtifacts = Object.fromEntries(A3_IMMUTABLE_PATHS.map((relative) => [
    relative,
    gitBuffer(repo, ['show', `${A3_CLOSEOUT_COMMIT}:${relative}`]).toString('utf8'),
  ]));
  const currentArtifacts = Object.fromEntries(A3_IMMUTABLE_PATHS.map((relative) => [
    relative,
    fs.readFileSync(path.join(repo, relative), 'utf8'),
  ]));
  const baselineRecords = A3_RECORD_PATHS.map((relative) => JSON.parse(
    gitBuffer(repo, ['show', `${A3_CLOSEOUT_COMMIT}:${relative}`]).toString('utf8'),
  ));
  const currentRecordText = A3_RECORD_PATHS.map((relative) => fs.readFileSync(path.join(repo, relative), 'utf8'));
  const records = currentRecordText.map((value) => JSON.parse(value));
  const inventory = [];
  for (const absolute of walkJSON(path.join(repo, A3_RECORD_ROOT))) {
    try {
      const record = JSON.parse(fs.readFileSync(absolute, 'utf8'));
      if (record?.task_id === A3_TASK_ID) inventory.push(path.relative(repo, absolute).split(path.sep).join('/'));
    } catch {
      // A malformed JSON file under the canonical A3 path is still included
      // by the exact path inventory below and rejected deterministically.
      const relative = path.relative(repo, absolute).split(path.sep).join('/');
      if (relative.includes('unregistered-aipt-p1-b000-authority-amendment-003')) inventory.push(relative);
    }
  }
  return {
    repo,
    head,
    closeout,
    closeoutAncestor,
    candidate: commitFacts(repo, A3_CANDIDATE),
    merge: commitFacts(repo, A3_MERGE),
    baselineArtifacts,
    currentArtifacts,
    baselineRecords,
    currentRecordText,
    records,
    inventory: inventory.sort(),
    recordSchema: JSON.parse(currentArtifacts[A3_RECORD_SCHEMA_PATH]),
    projectStatus: JSON.parse(fs.readFileSync(path.join(repo, 'docs/authority/registry/project-status.json'), 'utf8')),
  };
}

function validateCurrentA3Snapshot(snapshot) {
  const problems = [];
  try {
    if (snapshot.closeout?.commit !== A3_CLOSEOUT_COMMIT || snapshot.closeout?.tree !== A3_CLOSEOUT_TREE ||
        snapshot.closeout?.parents?.length !== 1 || snapshot.closeout.parents[0] !== A3_MERGE) {
      problems.push('accepted Amendment-003 closeout commit/tree/topology drifted');
    }
    if (!snapshot.closeoutAncestor) problems.push('current HEAD does not retain the accepted Amendment-003 closeout on its ancestry');
    if (snapshot.candidate?.commit !== A3_CANDIDATE || snapshot.candidate?.tree !== A3_CANDIDATE_TREE) {
      problems.push('accepted Amendment-003 candidate identity drifted');
    }
    if (snapshot.merge?.commit !== A3_MERGE || snapshot.merge?.tree !== A3_CANDIDATE_TREE ||
        JSON.stringify(snapshot.merge?.parents) !== JSON.stringify(['005ec002e7d8bcccd83d3f3994fddf9da30ff82a', A3_CANDIDATE])) {
      problems.push('accepted Amendment-003 merge identity drifted');
    }
    for (const relative of A3_IMMUTABLE_PATHS) {
      if (snapshot.currentArtifacts[relative] !== snapshot.baselineArtifacts[relative]) {
        problems.push(`immutable Amendment-003 artifact changed: ${relative}`);
      }
    }
    const expectedInventory = [...A3_RECORD_PATHS].sort();
    if (JSON.stringify(snapshot.inventory) !== JSON.stringify(expectedInventory)) {
      problems.push('Amendment-003 lifecycle inventory contains a missing, forked or duplicate record path');
    }
    for (let index = 0; index < snapshot.records.length; index += 1) {
      for (const error of validateInstance(snapshot.recordSchema, snapshot.records[index]).errors) {
        problems.push(`${A3_RECORD_PATHS[index]}: ${error.message}`);
      }
    }
    const identity = snapshot.baselineRecords[0]?.semantic_artifact_identity;
    const currentIdentity = snapshot.records[0]?.semantic_artifact_identity;
    problems.push(...validateImmutableSemanticIdentity(identity, currentIdentity).problems);
    if (identity?.task_id !== A3_TASK_ID || identity?.candidate_commit !== A3_CANDIDATE ||
        identity?.candidate_tree !== A3_CANDIDATE_TREE || identity?.artifact_path !== A3_MACHINE_PATH ||
        identity?.artifact_sha256 !== sha256(snapshot.currentArtifacts[A3_MACHINE_PATH])) {
      problems.push('Amendment-003 accepted semantic identity no longer binds the exact immutable machine artifact');
    }
    const appendOnly = validateAppendOnlyRecordSet(snapshot.baselineRecords, snapshot.records);
    problems.push(...appendOnly.problems);
    const ids = [
      `${A3_TASK_ID}-LIFECYCLE-001-MERGED`,
      `${A3_TASK_ID}-LIFECYCLE-002-POST-MERGE-VERIFIED`,
      `${A3_TASK_ID}-LIFECYCLE-003-CLOSED`,
    ];
    const recordAcceptance = Object.fromEntries(snapshot.records.map((record, index) => [record.record_id, {
      accepted: true,
      commit: A3_CLOSEOUT_COMMIT,
      commit_ordinal: 1,
      first_parent_ancestry: true,
      path: A3_RECORD_PATHS[index],
      introduced_sha256: sha256(snapshot.currentRecordText[index]),
      current_sha256: sha256(snapshot.currentRecordText[index]),
      canonical_record_sha256: lifecycleRecordSha256(record),
    }]));
    const post = snapshot.records[1]?.event_evidence?.post_merge_evidence;
    const resolution = resolveEffectiveAuthority({
      semantic_artifact_identity: identity,
      records: snapshot.records,
      policy: A3_POLICY,
      record_acceptance: recordAcceptance,
      authority_basis_acceptance: Object.fromEntries(ids.map((id) => [id, true])),
      evidence_catalogue: {
        merge_commits: { [A3_MERGE]: { tree: A3_CANDIDATE_TREE, parents: snapshot.merge?.parents, accepted_ancestry: true } },
        post_merge_runs: post ? { [String(post.run_id)]: post } : {},
        closeout_records: { [ids[2]]: { commit: A3_CLOSEOUT_COMMIT, governance_only: true, owner_authorized: true } },
      },
      expected_accepted_record_ids: ids,
      expected_lifecycle_state: 'CLOSED',
    });
    problems.push(...resolution.problems);
    if (!selfCloseoutBootstrapExpired(A3_TASK_ID, resolution)) {
      problems.push('Amendment-003 CLOSED chain is not effective/terminal');
    }
    const standalone = snapshot.projectStatus?.tracks?.['AIPT-STANDALONE'];
    const pending = snapshot.projectStatus?.repositories?.AIPT?.pending_candidate;
    if (standalone?.batch_history?.['UNREGISTERED-AIPT-P1-B000'] !== 'MERGED_CLOSED' ||
        standalone?.external_serial_predecessor?.status !== 'MERGED_CLOSED' ||
        standalone?.current_batch === A3_TASK_ID || pending?.task_id === A3_TASK_ID) {
      problems.push('project-status projection contradicts the canonical closed Amendment-003 lifecycle');
    }
    return {
      result: problems.length === 0 ? 'PASS' : 'FAIL',
      problems,
      resolution,
    };
  } catch (error) {
    return { result: 'FAIL', problems: [`structured current Amendment-003 lifecycle validation error: ${error.message}`] };
  }
}

function currentA3RegressionProbes(snapshot) {
  const probes = [];
  const run = (id, label, mutate, expected) => {
    const copy = structuredClone(snapshot);
    mutate(copy);
    let actual = 'FAIL';
    let threw = false;
    try { actual = validateCurrentA3Snapshot(copy).result; } catch { threw = true; }
    probes.push({ id, label, expected, actual, threw, matched: !threw && actual === expected });
  };
  run('R1-02', 'current B002 successor is lifecycle-preserving, not an A3 candidate', () => {}, 'PASS');
  run('R1-03', 'mutated A3 semantic artifact', (copy) => {
    copy.currentArtifacts[A3_MACHINE_PATH] += '\n';
  }, 'FAIL');
  run('R1-04', 'mutated A3 lifecycle record', (copy) => {
    copy.records[2].effective = false;
  }, 'FAIL');
  run('R1-05', 'A3 lifecycle fork', (copy) => {
    const fork = structuredClone(copy.records[1]);
    fork.record_id += '-FORK';
    copy.records.push(fork);
    copy.currentRecordText.push(JSON.stringify(fork));
    copy.inventory.push(`${A3_RECORD_ROOT}/unregistered-aipt-p1-b000-authority-amendment-003/002-post-merge-verified-fork.json`);
    copy.inventory.sort();
  }, 'FAIL');
  return probes;
}

function validateCurrentA3Lifecycle(repo) {
  try {
    const snapshot = collectCurrentA3Snapshot(repo);
    const validation = validateCurrentA3Snapshot(snapshot);
    const probes = currentA3RegressionProbes(snapshot);
    const probeFailures = probes.filter((probe) => !probe.matched);
    return {
      result: validation.result === 'PASS' && probeFailures.length === 0 ? 'PASS' : 'FAIL',
      details: [
        ...validation.problems.map((problem) => `FAIL: ${problem}`),
        ...probes.map((probe) => probe.matched
          ? `ok: ${probe.id} ${probe.label} -> ${probe.actual}`
          : `FAIL: ${probe.id} ${probe.label} expected ${probe.expected}, got ${probe.actual}${probe.threw ? ' (threw)' : ''}`),
      ],
      head: snapshot.head,
      lifecycle_state: validation.resolution?.lifecycle_state ?? 'INVALID',
      effective: validation.resolution?.effective === true,
      negative_probes: probes,
      unexpected_acceptances: probes.filter((probe) => probe.expected === 'FAIL' && probe.actual === 'PASS').length,
      uncaught_validation_errors: probes.filter((probe) => probe.threw).length,
    };
  } catch (error) {
    return {
      result: 'FAIL',
      details: [`FAIL: current Amendment-003 lifecycle input unreadable: ${error.message}`],
      lifecycle_state: 'INVALID', effective: false, negative_probes: [],
      unexpected_acceptances: 0, uncaught_validation_errors: 0,
    };
  }
}

function executeAtCloseout(repo, name, gate) {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), `aipt-${name}-historical-`));
  const historicalRepo = path.join(temporaryRoot, 'repo');
  const reports = [];
  try {
    const clone = spawnSync('git', ['clone', '--quiet', '--shared', '--no-checkout', repo, historicalRepo], {
      encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
    });
    if (clone.status !== 0) throw new Error(`cannot materialize ${name} closeout: ${(clone.stderr || '').trim()}`);
    const checkout = spawnSync('git', ['-C', historicalRepo, 'checkout', '--quiet', '--detach', gate.commit], {
      encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
    });
    if (checkout.status !== 0) throw new Error(`cannot checkout ${name} closeout: ${(checkout.stderr || '').trim()}`);
    const resolved = git(historicalRepo, ['rev-parse', 'HEAD^{commit}']).stdout.trim();
    const tree = git(historicalRepo, ['rev-parse', 'HEAD^{tree}']).stdout.trim();
    const status = git(historicalRepo, ['status', '--porcelain=v1', '--untracked-files=all'], { check: false });
    const symbolic = git(historicalRepo, ['symbolic-ref', '-q', 'HEAD'], { check: false });
    if (resolved !== gate.commit || tree !== gate.tree) {
      throw new Error(`${name} resolved identity ${resolved}/${tree} differs from ${gate.commit}/${gate.tree}`);
    }
    if (status.status !== 0 || status.stdout.trim() !== '' || symbolic.status === 0) {
      throw new Error(`${name} historical target is not a clean detached checkout`);
    }
    for (const relative of gate.validators) {
      const child = spawnSync(process.execPath, [path.join(historicalRepo, relative), '--repo', historicalRepo], {
        cwd: historicalRepo,
        encoding: 'utf8',
        maxBuffer: 32 * 1024 * 1024,
        env: {
          ...process.env,
          GITHUB_ACTIONS: 'true',
          GITHUB_EVENT_NAME: 'push',
          GITHUB_REF: 'refs/heads/main',
          GITHUB_SHA: gate.commit,
          GITHUB_HEAD_REF: '',
          GITHUB_BASE_REF: '',
        },
      });
      let report = null;
      try { report = JSON.parse((child.stdout || '').trim()); } catch { report = null; }
      reports.push({
        validator: relative,
        result: child.status === 0 && report?.result === 'PASS' ? 'PASS' : 'FAIL',
        exit_status: child.status,
        signal: child.signal,
        report,
        stderr: child.stderr || '',
      });
    }
    return { name, commit: resolved, tree, reports };
  } finally {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

export function runHistoricalGovernance(ctx, args = {}) {
  const requested = args.gate ?? 'all';
  const routeClosedAuthority = args['route-closed-authority'] === true;
  const historicalOnly = args['historical-only'] === true;
  const currentOnly = args['current-only'] === true;
  const names = requested === 'all' ? Object.keys(HISTORICAL_GATES) : [requested];
  const details = [];
  const executions = [];
  let currentLifecycle = null;
  let pass = true;
  if (names.some((name) => !Object.hasOwn(HISTORICAL_GATES, name))) {
    return {
      result: 'FAIL',
      details: [`FAIL: unknown historical governance gate ${requested}`],
      executions,
      external_model_calls: 0,
      real_playtest_executed: false,
    };
  }
  if (routeClosedAuthority && requested !== 'p1-b000-authority-amendment') {
    return {
      result: 'FAIL',
      details: ['FAIL: closed Authority routing is restricted to the exact p1-b000-authority-amendment replay'],
      executions,
      external_model_calls: 0,
      real_playtest_executed: false,
    };
  }
  if ((historicalOnly || currentOnly) && requested !== 'p1-b000-authority-amendment-003') {
    return {
      result: 'FAIL',
      details: ['FAIL: --historical-only/--current-only are restricted to Amendment-003 lifecycle routing'],
      executions,
      external_model_calls: 0,
      real_playtest_executed: false,
    };
  }
  if (historicalOnly && currentOnly) {
    return {
      result: 'FAIL',
      details: ['FAIL: --historical-only and --current-only are mutually exclusive'],
      executions,
      external_model_calls: 0,
      real_playtest_executed: false,
    };
  }
  if (!currentOnly) {
    for (const name of names) {
      try {
        const execution = executeAtCloseout(ctx.repo, name, HISTORICAL_GATES[name]);
        executions.push(execution);
        for (const report of execution.reports) {
          if (report.result !== 'PASS') {
            pass = false;
            details.push(`FAIL: ${report.validator} did not PASS at exact ${name} closeout`);
          } else {
            const probe = name === 'p1-b000-authority-amendment-003' ? 'R1-01 ' : '';
            details.push(`ok: ${probe}${report.validator} PASS at ${execution.commit}/${execution.tree}`);
          }
        }
      } catch (error) {
        pass = false;
        details.push(`FAIL: structured historical replay error: ${error.message}`);
      }
    }
  }
  if (!historicalOnly && names.includes('p1-b000-authority-amendment-003')) {
    currentLifecycle = validateCurrentA3Lifecycle(ctx.repo);
    if (currentLifecycle.result !== 'PASS') pass = false;
    details.push(...currentLifecycle.details);
    if (currentLifecycle.result === 'PASS') {
      details.push(`ok: current canonical Amendment-003 lifecycle is ${currentLifecycle.lifecycle_state}/effective on successor ${currentLifecycle.head}`);
    }
  }
  let closedAuthorityRouted = false;
  if (routeClosedAuthority && pass) {
    const githubOutput = args['github-output'];
    if (typeof githubOutput !== 'string' || githubOutput.length === 0 || githubOutput !== process.env.GITHUB_OUTPUT) {
      pass = false;
      details.push('FAIL: --github-output must equal the exact GitHub-provided GITHUB_OUTPUT path');
    } else {
      fs.appendFileSync(githubOutput, 'applicable=false\n', { encoding: 'utf8' });
      closedAuthorityRouted = true;
      details.push('ok: closed Amendment replay PASS; bootstrap permission remains expired and normal gates are routed');
    }
  }
  return {
    result: pass ? 'PASS' : 'FAIL',
    details,
    execution_mode: 'IMMUTABLE_CLOSEOUT_REPLAY',
    executions,
    current_lifecycle_integrity: currentLifecycle,
    historical_replay_only: historicalOnly,
    current_lifecycle_only: currentOnly,
    closed_authority_routed: closedAuthorityRouted,
    external_model_calls: 0,
    real_playtest_executed: false,
  };
}

runAsMain(import.meta.url, 'historical-governance', runHistoricalGovernance);
