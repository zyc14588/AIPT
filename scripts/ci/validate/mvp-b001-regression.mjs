#!/usr/bin/env node
// Replays the immutable MVP-B001 acceptance gate on the exact B002 Base.
// The historical validator itself is protected byte-for-byte by the accepted
// P1 authority lifecycle; successor implementation paths must never weaken it.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { runAsMain } from '../lib/cli.mjs';
import { run as runHistoricalB001 } from './mvp-b001.mjs';

const B002_BASE_COMMIT = '411bf2997cd0f10ba1a022ac687d27a1bd19eb36';
const B002_BASE_TREE = 'd1daaeede13a2ba07c3b528c1792ef9fd5600a63';

export function run(ctx) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-b001-regression-'));
  try {
    const clone = spawnSync('git', ['clone', '--quiet', '--shared', '--no-checkout', ctx.repo, root], {
      encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
    });
    if (clone.error || clone.status !== 0) {
      return { result: 'FAIL', details: [`FAIL: cannot materialize exact B002 Base: ${clone.error?.message ?? clone.stderr.trim()}`] };
    }
    const checkout = spawnSync('git', ['-C', root, 'checkout', '--quiet', '--detach', B002_BASE_COMMIT], {
      encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
    });
    const head = spawnSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' });
    const tree = spawnSync('git', ['-C', root, 'rev-parse', 'HEAD^{tree}'], { encoding: 'utf8' });
    const status = spawnSync('git', ['-C', root, 'status', '--porcelain=v1', '--untracked-files=all'], { encoding: 'utf8' });
    if (checkout.error || checkout.status !== 0 || head.status !== 0 || tree.status !== 0 || status.status !== 0 ||
        head.stdout.trim() !== B002_BASE_COMMIT || tree.stdout.trim() !== B002_BASE_TREE || status.stdout.trim() !== '') {
      return { result: 'FAIL', details: ['FAIL: exact B002 Base identity is not clean and reproducible'] };
    }
    const report = runHistoricalB001({ repo: root, bindGitHubExecutionIdentity: false });
    return {
      ...report,
      details: [
        `ok: immutable B001 gate replayed on exact B002 Base ${B002_BASE_COMMIT}/${B002_BASE_TREE}`,
        ...(report.details ?? []),
      ],
      validation_target: { mode: 'EXACT_B002_BASE', commit: B002_BASE_COMMIT, tree: B002_BASE_TREE },
    };
  } catch (error) {
    return { result: 'FAIL', details: [`FAIL: B001 historical regression replay error: ${error.message}`] };
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

runAsMain(import.meta.url, 'mvp-b001-regression', run);
