#!/usr/bin/env node
// Exact-target Base Authority reverification runner. The validator definitions
// come from the repair checkout; the target is a separate clean detached tree.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { git, parseArgs } from '../lib/cli.mjs';
import { run as runAuthority } from './p1-b000-authority.mjs';
import { run as runB001 } from './mvp-b001.mjs';
import { run as runRepair } from './p1-b000-authority-repair.mjs';

const TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001';
const AUTHORITY_TASK_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-001';
const AMENDMENT_ID = 'UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-001';
const TARGET_COMMIT = '169f9bd006dabb88eb653ab09a33b0eef5eadaed';
const TARGET_TREE = '9cf551e7bc70d4354ca21d62a2bd456ed6f401bb';
const CANDIDATE_COMMIT = 'c9f7729f666d11716c04d7682da16044ca965236';
const CANDIDATE_TREE = TARGET_TREE;
const ACCEPTED_REPAIR_CANDIDATE = '17f09e7cd766b39651101a1cacb896b296b821c8';
const ACCEPTED_REPAIR_TREE = 'c3a8f4f1e73a0ee60b6d29491d6981f0a01159d8';
const SUPERSESSION_ACCEPTANCE_COMMIT = 'c5cb2354af72df18c9323b6a1401e3cc874c7581';
const TARGET_PARENTS = [
  'eede815e818d87362605f55d5bfd2a0460e6e130',
  CANDIDATE_COMMIT,
];
const WORKFLOW_PATH = '.github/workflows/p1-b000-post-merge-reverification.yml';
const VALIDATORS = Object.freeze([
  { role: 'AUTHORITY_VALIDATOR_IDENTITY', path: 'scripts/ci/validate/p1-b000-authority.mjs' },
  { role: 'B001_HISTORICAL_VALIDATOR_IDENTITY', path: 'scripts/ci/validate/mvp-b001.mjs' },
]);

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function read(repo, relative) {
  return fs.readFileSync(path.join(repo, relative));
}

function commitBlob(repo, commit, relative) {
  const cp = git(repo, ['show', `${commit}:${relative}`], { check: false });
  return cp.status === 0 ? Buffer.from(cp.stdout, 'utf8') : null;
}

function runGoTests(targetRepo) {
  const child = spawnSync('go', ['test', './...'], {
    cwd: targetRepo,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env },
  });
  return {
    result: !child.error && child.status === 0 ? 'PASS' : 'FAIL',
    status: child.status,
    signal: child.signal,
    error: child.error?.message ?? null,
    stdout: child.stdout ?? '',
    stderr: child.stderr ?? '',
  };
}

function materializeTarget(definitionRepo, targetSha, expectedTree) {
  const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-p1-b000-reverify-'));
  const targetRepo = path.join(temporaryRoot, 'target');
  const clone = spawnSync('git', ['clone', '--quiet', '--shared', '--no-checkout', definitionRepo, targetRepo], {
    encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
  });
  if (clone.error || clone.status !== 0) {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
    throw new Error(`cannot materialize verification target: ${clone.error?.message ?? (clone.stderr || '').trim()}`);
  }
  const checkout = spawnSync('git', ['-C', targetRepo, 'checkout', '--quiet', '--detach', targetSha], {
    encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
  });
  if (checkout.error || checkout.status !== 0) {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
    throw new Error(`cannot checkout verification target: ${checkout.error?.message ?? (checkout.stderr || '').trim()}`);
  }
  const resolved = git(targetRepo, ['rev-parse', 'HEAD^{commit}']).stdout.trim();
  const tree = git(targetRepo, ['rev-parse', 'HEAD^{tree}']).stdout.trim();
  const status = git(targetRepo, ['status', '--porcelain=v1', '--untracked-files=all']).stdout;
  if (resolved !== targetSha || tree !== expectedTree || status !== '') {
    fs.rmSync(temporaryRoot, { recursive: true, force: true });
    throw new Error(`target identity/cleanliness mismatch: ${resolved}/${tree}/dirty=${status !== ''}`);
  }
  return { temporaryRoot, targetRepo, resolved, tree };
}

function formalEvidence(report, args, definition) {
  const runId = Number(args['workflow-run-id']);
  const acceptedCommit = args['accepted-repair-candidate'];
  const acceptedTree = git(definition.repo, ['rev-parse', `${acceptedCommit}^{tree}`], { check: false }).stdout.trim();
  return {
    schema: 'aipt.public.post-merge-reverification-evidence/v1',
    evidence_id: `${AUTHORITY_TASK_ID}-POST-MERGE-REVERIFICATION-001`,
    authority_task_id: AUTHORITY_TASK_ID,
    amendment_id: AMENDMENT_ID,
    original_merge_ci: {
      check_run: 'ABSENT', conclusion: null, historical_merge_ci_claim: 'NOT_CLAIMED_PASS',
    },
    candidate_identity: { commit: CANDIDATE_COMMIT, tree: CANDIDATE_TREE, verified: true },
    merge_identity: {
      commit: TARGET_COMMIT, tree: TARGET_TREE, parents: [...TARGET_PARENTS],
      ancestry_verified: true, tree_equals_candidate: true, no_unauthorized_content: true,
    },
    workflow_execution: {
      workflow_run_id: runId,
      event: 'workflow_dispatch',
      run_head_sha: args['run-head-sha'],
      workflow_definition_identity: {
        path: WORKFLOW_PATH, commit: acceptedCommit, tree: acceptedTree,
        sha256: definition.sourceWorkflowSha256, source_repair_task_id: TASK_ID,
      },
    },
    verification_target: {
      requested_target_sha: TARGET_COMMIT, resolved_target_sha: report.resolved_target_sha,
      target_tree: report.target_tree, checkout_mode: 'DETACHED_EXACT_COMMIT',
      clean_checkout: true, modified_worktree_used: false,
    },
    validator_identities: definition.validators.map((validator) => ({
      ...validator, source_repair_candidate_commit: acceptedCommit,
    })),
    jobs: report.jobs.map((job) => ({ name: job.name, conclusion: 'success' })),
    b001_regression: 'PASS',
    effective_authority_identities: 'PASS',
    repair_authority: {
      repair_task_id: TASK_ID,
      accepted_repair_candidate_commit: acceptedCommit,
      accepted_repair_candidate_tree: acceptedTree,
      independent_acceptance: 'PASS',
    },
    result: 'PASS',
    provenance: {
      execution_identity_distinct_from_verification_target: definition.commit !== TARGET_COMMIT,
      append_only: true,
      recovery_not_historical_ci: true,
    },
  };
}

export function run(ctx, args = {}) {
  const details = [];
  let target = null;
  try {
    const requested = args['target-sha'] ?? TARGET_COMMIT;
    const expectedTree = args['expected-tree'] ?? TARGET_TREE;
    if (requested !== TARGET_COMMIT || expectedTree !== TARGET_TREE) {
      throw new Error('requested target SHA/tree differs from exact authorized Base Authority merge');
    }
    const definitionCommit = git(ctx.repo, ['rev-parse', 'HEAD^{commit}']).stdout.trim();
    const definitionTree = git(ctx.repo, ['rev-parse', 'HEAD^{tree}']).stdout.trim();
    if (git(ctx.repo, ['status', '--porcelain=v1', '--untracked-files=no']).stdout !== '') {
      throw new Error('verification definition checkout has modified tracked content');
    }
    const validatorIdentities = VALIDATORS.map((validator) => {
      const working = read(ctx.repo, validator.path);
      const committed = commitBlob(ctx.repo, definitionCommit, validator.path);
      if (!committed || !working.equals(committed)) throw new Error(`validator definition is not committed: ${validator.path}`);
      return { ...validator, sha256: sha256(working) };
    });
    const workflowBytes = read(ctx.repo, WORKFLOW_PATH);
    const committedWorkflow = commitBlob(ctx.repo, definitionCommit, WORKFLOW_PATH);
    if (!committedWorkflow || !workflowBytes.equals(committedWorkflow)) throw new Error('workflow definition is not committed');

    target = materializeTarget(ctx.repo, requested, expectedTree);
    const parents = git(target.targetRepo, ['show', '-s', '--format=%P', requested]).stdout.trim().split(/\s+/);
    const candidateTree = git(target.targetRepo, ['rev-parse', `${CANDIDATE_COMMIT}^{tree}`]).stdout.trim();
    if (JSON.stringify(parents) !== JSON.stringify(TARGET_PARENTS) || candidateTree !== CANDIDATE_TREE) {
      throw new Error('verification target merge parents or approved Candidate tree drifted');
    }

    const authority = runAuthority({
      repo: target.targetRepo,
      definitionRepo: ctx.repo,
      bindGitHubExecutionIdentity: false,
    });
    const b001 = runB001({ repo: target.targetRepo, bindGitHubExecutionIdentity: false });
    const repair = runRepair({ repo: ctx.repo });
    const goTests = runGoTests(target.targetRepo);
    const jobs = [
      { name: 'exact-target-identity', conclusion: 'success', passed: true },
      { name: 'authority-validator', conclusion: authority.result === 'PASS' ? 'success' : 'failure', passed: authority.result === 'PASS' },
      { name: 'b001-historical-validator', conclusion: b001.result === 'PASS' ? 'success' : 'failure', passed: b001.result === 'PASS' },
      { name: 'effective-authority-resolution', conclusion: repair.result === 'PASS' ? 'success' : 'failure', passed: repair.result === 'PASS' },
      { name: 'go-test-all-at-target', conclusion: goTests.result === 'PASS' ? 'success' : 'failure', passed: goTests.result === 'PASS' },
    ];
    const pass = jobs.every((job) => job.passed);
    for (const job of jobs) details.push(`${job.passed ? 'ok' : 'FAIL'}: ${job.name} ${job.conclusion}`);
    const report = {
      schema: 'aipt.public.post-merge-reverification-candidate-run/v1',
      result: pass ? 'PASS' : 'FAIL',
      details,
      task_id: TASK_ID,
      requested_target_sha: requested,
      resolved_target_sha: target.resolved,
      target_tree: target.tree,
      target_checkout: 'DETACHED_EXACT_COMMIT',
      target_clean: true,
      modified_target_worktree_used: false,
      original_merge_ci: 'ABSENT',
      historical_merge_ci_claimed_pass: false,
      definition_commit: definitionCommit,
      definition_tree: definitionTree,
      workflow_definition_sha256: sha256(workflowBytes),
      validator_identities: validatorIdentities,
      jobs,
      b001_regression: b001.result === 'PASS' ? 'PASS' : 'FAIL',
      effective_authority_identities: repair.result === 'PASS' ? 'PASS' : 'FAIL',
      go_test_all: goTests.result,
      go_test_diagnostics: goTests.result === 'PASS' ? null : goTests,
      formal_evidence_eligible: false,
      formal_evidence_blocker: 'REPAIR_CANDIDATE_INDEPENDENT_ACCEPTANCE_PENDING',
      recovery_not_historical_ci: true,
      real_model_calls: 0,
      real_playtest_executed: false,
    };
    const formalRequested = args['emit-formal-evidence'] === true;
    if (formalRequested) {
      const runId = Number(args['workflow-run-id']);
      const acceptedCommit = args['accepted-repair-candidate'];
      const acceptancePass = args['independent-acceptance'] === 'PASS';
      const acceptedTree = /^[0-9a-f]{40}$/.test(acceptedCommit ?? '')
        ? git(ctx.repo, ['rev-parse', `${acceptedCommit}^{tree}`], { check: false }).stdout.trim()
        : '';
      const sourceWorkflowBytes = /^[0-9a-f]{40}$/.test(acceptedCommit ?? '')
        ? commitBlob(ctx.repo, acceptedCommit, WORKFLOW_PATH)
        : null;
      const validatorsFromCandidate = sourceWorkflowBytes !== null && validatorIdentities.every((identity) => {
        const source = commitBlob(ctx.repo, acceptedCommit, identity.path);
        return source !== null && sha256(source) === identity.sha256;
      });
      const acceptedAncestor = acceptedCommit === ACCEPTED_REPAIR_CANDIDATE &&
        git(ctx.repo, ['merge-base', '--is-ancestor', acceptedCommit, definitionCommit], { check: false }).status === 0;
      const acceptanceAncestor =
        git(ctx.repo, ['merge-base', '--is-ancestor', SUPERSESSION_ACCEPTANCE_COMMIT, definitionCommit], { check: false }).status === 0;
      const dispatchBound = process.env.GITHUB_ACTIONS === 'true' &&
        process.env.GITHUB_EVENT_NAME === 'workflow_dispatch' &&
        Number.isInteger(runId) && runId > 0 && String(runId) === process.env.GITHUB_RUN_ID &&
        acceptedAncestor && acceptedTree === ACCEPTED_REPAIR_TREE && acceptanceAncestor && validatorsFromCandidate &&
        /^[0-9a-f]{40}$/.test(args['run-head-sha'] ?? '') &&
        args['run-head-sha'] === process.env.GITHUB_SHA &&
        definitionCommit === args['run-head-sha'] && acceptancePass && pass;
      if (!dispatchBound) {
        report.result = 'FAIL';
        report.details.push('FAIL: formal evidence requires a successful workflow_dispatch bound to an independently accepted repair Candidate');
      } else {
        return formalEvidence(report, args, {
          repo: ctx.repo, commit: definitionCommit, tree: definitionTree,
          sourceWorkflowSha256: sha256(sourceWorkflowBytes), validators: validatorIdentities,
        });
      }
    }
    return report;
  } catch (error) {
    return {
      schema: 'aipt.public.post-merge-reverification-candidate-run/v1',
      result: 'FAIL', details: [`FAIL: structured reverification error: ${error.message}`],
      task_id: TASK_ID, requested_target_sha: args['target-sha'] ?? TARGET_COMMIT,
      resolved_target_sha: null, target_tree: null,
      original_merge_ci: 'ABSENT', historical_merge_ci_claimed_pass: false,
      formal_evidence_eligible: false,
      recovery_not_historical_ci: true,
      real_model_calls: 0, real_playtest_executed: false,
    };
  } finally {
    if (target?.temporaryRoot) fs.rmSync(target.temporaryRoot, { recursive: true, force: true });
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const args = parseArgs(process.argv.slice(2));
  const report = run({ repo: path.resolve(args.repo || process.cwd()) }, args);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  process.exitCode = report.result === 'PASS' ? 0 : 1;
}
