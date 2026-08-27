#!/usr/bin/env node
// Replays closed lifecycle validators against their exact immutable closeout
// commits. Later governance tasks must preserve those gates without asking a
// closed validator to interpret a new task branch as its own Candidate.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { git, runAsMain } from '../lib/cli.mjs';

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
});

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
    if (resolved !== gate.commit || tree !== gate.tree) {
      throw new Error(`${name} resolved identity ${resolved}/${tree} differs from ${gate.commit}/${gate.tree}`);
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
  const names = requested === 'all' ? Object.keys(HISTORICAL_GATES) : [requested];
  const details = [];
  const executions = [];
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
  for (const name of names) {
    try {
      const execution = executeAtCloseout(ctx.repo, name, HISTORICAL_GATES[name]);
      executions.push(execution);
      for (const report of execution.reports) {
        if (report.result !== 'PASS') {
          pass = false;
          details.push(`FAIL: ${report.validator} did not PASS at exact ${name} closeout`);
        } else {
          details.push(`ok: ${report.validator} PASS at ${execution.commit}/${execution.tree}`);
        }
      }
    } catch (error) {
      pass = false;
      details.push(`FAIL: structured historical replay error: ${error.message}`);
    }
  }
  return {
    result: pass ? 'PASS' : 'FAIL',
    details,
    execution_mode: 'IMMUTABLE_CLOSEOUT_REPLAY',
    executions,
    external_model_calls: 0,
    real_playtest_executed: false,
  };
}

runAsMain(import.meta.url, 'historical-governance', runHistoricalGovernance);
