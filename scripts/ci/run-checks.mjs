#!/usr/bin/env node
// INT-AIPT-UNREGISTERED-MVP-001 closeout-authority Candidate suite entry
// (`pnpm run check`).
//
// Runs every validator with the repository root as context and prints a
// single machine-readable report. Exit code 0 only when every check is PASS.
// The report preserves every historical M0 gate and adds the exact MVP
// bootstrap authority/lifecycle gate, every closed MVP regression gate, the
// immutable read-only integration closeout, and the active B005 evidence
// closure gate. Historical semantics remain immutable.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { run as runDefer } from './validate/defer-016.mjs';
import { run as runToolchain } from './validate/toolchain-lock.mjs';
import { run as runWorkflow } from './validate/workflow.mjs';
import { run as runRetro } from './validate/b000-retro.mjs';
import { run as runSupplyChain } from './validate/supply-chain.mjs';
import { run as runSbom } from './validate/sbom.mjs';
import { run as runStorage } from './validate/storage.mjs';
import { run as runRuntimeShell } from './validate/runtime-shell.mjs';
import { run as runStandalone } from './validate/standalone-entrypoints.mjs';
import { run as runProtocol } from './validate/protocol-assets.mjs';
import { run as runAdapterSdk } from './validate/adapter-sdk.mjs';
import { run as runHarnessAdapter } from './validate/harness-adapter.mjs';
import { run as runEvidence } from './validate/evidence.mjs';
import { runHistoricalWeb } from './validate/mvp-b001.mjs';
import { run as runMvpB001 } from './validate/mvp-b001-regression.mjs';
import { run as runMvpB002 } from './validate/mvp-b002.mjs';
import { run as runMvpB003 } from './validate/mvp-b003.mjs';
import { run as runMvpB004 } from './validate/mvp-b004.mjs';
import { run as runMvpB005 } from './validate/mvp-b005.mjs';
import { run as runInt001CloseoutAuthority } from './validate/int001-closeout-authority.mjs';
import { runHistoricalGovernance } from './validate/historical-governance.mjs';
import { run as runP1B000AuthorityRepair } from './validate/p1-b000-authority-repair.mjs';
import { run as runP1B000AuthorityCloseout } from './validate/p1-b000-authority-closeout.mjs';

const ctx = { repo: path.resolve(process.cwd()) };
const amendment002Present = fs.existsSync(path.join(
  ctx.repo,
  'docs/authority/registry/unregistered-aipt-p1-b000-authority-amendment-002.json',
));

function historicalReplayEnvironment() {
  return Object.fromEntries(Object.entries(process.env)
    .filter(([key]) => !key.startsWith('GITHUB_')));
}

function runClosedEntrypoint(targetCtx, name) {
  const validator = path.join(targetCtx.repo, `scripts/ci/validate/${name}.mjs`);
  const execution = spawnSync(process.execPath, [validator, '--repo', targetCtx.repo], {
    cwd: targetCtx.repo,
    encoding: 'utf8',
    env: historicalReplayEnvironment(),
    maxBuffer: 64 * 1024 * 1024,
  });
  let report = null;
  try { report = JSON.parse(execution.stdout); } catch { report = null; }
  if (execution.error || execution.signal || execution.status !== 0 || report?.result !== 'PASS' || report?.name !== name) {
    const reportedFailures = Array.isArray(report?.details)
      ? report.details.filter((item) => typeof item === 'string' && item.startsWith('FAIL:'))
      : [];
    return {
      result: 'FAIL',
      details: [`FAIL: exact closed-governance ${name} replay failed: ${(execution.error?.message ?? execution.stderr.trim()) || reportedFailures.join('; ') || 'invalid/non-PASS report'}`],
    };
  }
  return report;
}

function exactClosedGovernanceContext() {
  if (!amendment002Present) return { ctx, cleanup: () => {}, problem: null };
  const target = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-a2-closed-governance-'));
  const runGit = (args) => spawnSync('git', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  const clone = runGit(['clone', '--no-local', '--no-checkout', ctx.repo, target]);
  if (clone.error || clone.status !== 0) {
    return { ctx: { repo: target }, cleanup: () => fs.rmSync(target, { recursive: true, force: true }), problem: `exact closed-governance clone failed: ${clone.error?.message ?? clone.stderr.trim()}` };
  }
  const checkout = runGit(['-C', target, 'checkout', '--detach', '8d6a438d051fb635e769285215e70536958a8f42']);
  const head = runGit(['-C', target, 'rev-parse', 'HEAD']);
  const tree = runGit(['-C', target, 'rev-parse', 'HEAD^{tree}']);
  const status = runGit(['-C', target, 'status', '--porcelain=v1', '--untracked-files=all']);
  let problem = checkout.error || checkout.status !== 0 || head.status !== 0 || tree.status !== 0 || status.status !== 0 ||
    head.stdout.trim() !== '8d6a438d051fb635e769285215e70536958a8f42' ||
    tree.stdout.trim() !== '9ef6f121bd0d9a6484d7cc39a22450250e9ac489' || status.stdout.trim() !== ''
    ? `exact closed-governance target verification failed: ${checkout.error?.message ?? checkout.stderr.trim()}`
    : null;
  if (!problem) {
    const packageManager = process.env.npm_execpath;
    if (!packageManager || !fs.existsSync(packageManager)) {
      problem = 'exact closed-governance target requires invocation through pinned pnpm';
    } else {
      const version = spawnSync(process.execPath, [packageManager, '--version'], { encoding: 'utf8' });
      if (version.error || version.status !== 0 || version.stdout.trim() !== '11.4.0') {
        problem = `exact closed-governance target requires pnpm 11.4.0: ${version.error?.message ?? version.stderr.trim()}`;
      } else {
        const excludePath = path.join(target, '.git', 'info', 'exclude');
        fs.appendFileSync(excludePath, '\n# Generated only for exact closed-governance replay\nnode_modules/\n', 'utf8');
        const install = spawnSync(process.execPath, [packageManager, 'install', '--offline', '--frozen-lockfile', '--ignore-scripts'], {
          cwd: target,
          encoding: 'utf8',
          maxBuffer: 64 * 1024 * 1024,
        });
        if (install.error || install.status !== 0) {
          problem = `exact closed-governance offline frozen dependency setup failed: ${install.error?.message ?? install.stderr.trim()}`;
        } else {
          const afterInstallStatus = runGit(['-C', target, 'status', '--porcelain=v1', '--untracked-files=all']);
          if (afterInstallStatus.error || afterInstallStatus.status !== 0 || afterInstallStatus.stdout.trim() !== '') {
            problem = `exact closed-governance dependency setup changed tracked target state: ${afterInstallStatus.error?.message ?? afterInstallStatus.stderr.trim()}`;
          }
        }
      }
    }
  }
  return {
    ctx: { repo: target, bindGitHubExecutionIdentity: false },
    cleanup: () => fs.rmSync(target, { recursive: true, force: true }),
    problem,
  };
}

const closedGovernance = exactClosedGovernanceContext();
const targetFailure = (name) => ({
  result: 'FAIL',
  details: [`FAIL: ${name}: ${closedGovernance.problem}`],
  validation_target: {
    mode: 'EXACT_ACCEPTED_AIPT_BASE_CLOSEOUT',
    commit: '8d6a438d051fb635e769285215e70536958a8f42',
    tree: '9ef6f121bd0d9a6484d7cc39a22450250e9ac489',
  },
});
const bindClosedTarget = (report) => ({
  ...report,
  validation_target: {
    mode: 'EXACT_ACCEPTED_AIPT_BASE_CLOSEOUT',
    commit: '8d6a438d051fb635e769285215e70536958a8f42',
    tree: '9ef6f121bd0d9a6484d7cc39a22450250e9ac489',
  },
});
const repairCheck = closedGovernance.problem
  ? targetFailure('repair validator was not executed')
  : amendment002Present
    ? bindClosedTarget(runClosedEntrypoint(closedGovernance.ctx, 'p1-b000-authority-repair'))
    : runP1B000AuthorityRepair(closedGovernance.ctx);
const closeoutCheck = closedGovernance.problem
  ? targetFailure('closeout validator was not executed')
  : amendment002Present
    ? bindClosedTarget(runClosedEntrypoint(closedGovernance.ctx, 'p1-b000-authority-closeout'))
    : runP1B000AuthorityCloseout(closedGovernance.ctx);
const standaloneCheck = closedGovernance.problem
  ? targetFailure('standalone-entrypoints validator was not executed')
  : amendment002Present
    ? bindClosedTarget(runClosedEntrypoint(closedGovernance.ctx, 'standalone-entrypoints'))
    : runStandalone(closedGovernance.ctx);
const checks = await Promise.all([
  runHistoricalGovernance(ctx),
  runProtocol(ctx),
  runDefer(ctx),
  runToolchain(ctx),
  runWorkflow(ctx),
  runRetro(ctx),
  runSupplyChain(ctx),
  runSbom(ctx),
  runStorage(ctx),
  runRuntimeShell(ctx),
  standaloneCheck,
  runAdapterSdk(ctx),
  runHarnessAdapter(ctx),
  runEvidence(ctx),
  runHistoricalWeb(ctx),
  runMvpB001(ctx),
  runMvpB002(ctx),
  runMvpB003(ctx),
  runMvpB004(ctx),
  runMvpB005(ctx),
  runInt001CloseoutAuthority(ctx),
  repairCheck,
  closeoutCheck,
]);
closedGovernance.cleanup();

const result = checks.every((c) => c.result === 'PASS') ? 'PASS' : 'FAIL';
const status = JSON.parse(fs.readFileSync(
  path.join(ctx.repo, 'docs/authority/registry/project-status.json'), 'utf8',
));
const standalone = status.tracks?.['AIPT-STANDALONE'];
const note = `INT-AIPT-UNREGISTERED-MVP-001 remains immutably closed without rerun; B001-B004 semantics remain immutable; ${standalone?.current_batch ?? 'UNKNOWN'} is the sole active batch at GLOBAL_WIP ${standalone?.global_wip ?? 'UNKNOWN'} and ${standalone?.next_serial_batch ?? 'UNKNOWN'} remains ${standalone?.next_batch_state ?? 'UNKNOWN'}; B005 public CI paths use zero real model/provider calls and no secret input; qualification remains unexecuted`;
const report = {
  schema: 'aipt.public.int001-closeout-authority-validator-run/v1',
  task_id: 'INT-AIPT-UNREGISTERED-MVP-001-CLOSEOUT-AUTHORITY-001',
  integration_task: 'INT-AIPT-UNREGISTERED-MVP-001',
  note,
  repo: ctx.repo,
  result,
  checks,
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = result === 'PASS' ? 0 : 1;
