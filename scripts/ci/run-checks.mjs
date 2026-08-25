#!/usr/bin/env node
// AIPT-MVP-B000 validator suite entry (`pnpm run check`).
//
// Runs every validator with the repository root as context and prints a
// single machine-readable report. Exit code 0 only when every check is PASS.
// The report preserves every historical M0 gate and adds the exact MVP
// bootstrap authority/lifecycle gate. M0 stays effective while B000 is either
// the sole active governance batch or its exact closeout; B001 remains
// unauthorized/not started in both phases.
import fs from 'node:fs';
import path from 'node:path';
import { run as runStatus } from './validate/status-transition.mjs';
import { run as runDefer } from './validate/defer-016.mjs';
import { run as runToolchain } from './validate/toolchain-lock.mjs';
import { run as runWorkflow } from './validate/workflow.mjs';
import { run as runTree } from './validate/tree-integrity.mjs';
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
import { run as runWeb } from './validate/web-ui.mjs';
import { run as runM0DevelopmentPass } from './validate/m0-development-pass.mjs';
import { run as runMvpBootstrap } from './validate/mvp-bootstrap.mjs';
import { CURRENT_BATCH } from './lib/constants.mjs';

const ctx = { repo: path.resolve(process.cwd()) };
const checks = await Promise.all([
  runStatus(ctx),
  runProtocol(ctx),
  runDefer(ctx),
  runToolchain(ctx),
  runWorkflow(ctx),
  runTree(ctx),
  runRetro(ctx),
  runSupplyChain(ctx),
  runSbom(ctx),
  runStorage(ctx),
  runRuntimeShell(ctx),
  runStandalone(ctx),
  runAdapterSdk(ctx),
  runHarnessAdapter(ctx),
  runEvidence(ctx),
  runWeb(ctx),
  runM0DevelopmentPass(ctx),
  runMvpBootstrap(ctx),
]);

const result = checks.every((c) => c.result === 'PASS') ? 'PASS' : 'FAIL';
const status = JSON.parse(fs.readFileSync(
  path.join(ctx.repo, 'docs/authority/registry/project-status.json'), 'utf8',
));
const standalone = status.tracks?.['AIPT-STANDALONE'];
const b000Closed = standalone?.batch_history?.[CURRENT_BATCH] === 'MERGED_CLOSED' &&
  standalone?.construction === 'IDLE_WAITING_NEXT_BATCH' &&
  standalone?.current_batch === 'NO_ACTIVE_BATCH' && standalone?.global_wip === 0;
const note = b000Closed
  ? 'AIPT-MVP-B000 MERGED_CLOSED / GLOBAL_WIP 0; AIPT-MVP-B001 is named but NOT_AUTHORIZED/NOT_STARTED; M0 Development Pass remains effective; production/release/MVP qualifications remain NOT_GRANTED, human equivalence remains NOT_CLAIMED, and platform integration remains FROZEN_WAITING_M1_ENGINE'
  : 'AIPT-MVP-B000 IN_PROGRESS / GLOBAL_WIP 1; AIPT-MVP-B001 is named but NOT_AUTHORIZED/NOT_STARTED; M0 Development Pass remains effective; production/release/MVP qualifications remain NOT_GRANTED, human equivalence remains NOT_CLAIMED, and platform integration remains FROZEN_WAITING_M1_ENGINE';
const report = {
  schema: 'aipt.public.mvp-b000-validator-run/v1',
  task_id: CURRENT_BATCH,
  note,
  repo: ctx.repo,
  result,
  checks,
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = result === 'PASS' ? 0 : 1;
