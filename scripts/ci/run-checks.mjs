#!/usr/bin/env node
// B006 validator suite entry (`pnpm run check`).
//
// Runs every validator with the repository root as context and prints a
// single machine-readable report. Exit code 0 only when every check is PASS.
// The report schema and task_id are B006 (AIPT-M0-B006 construction
// IN_PROGRESS): the report is an under-construction validator run, never a
// merge/closeout claim. Every B000-B005 validator is retained alongside the
// B006 Evidence gate.
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
]);

const result = checks.every((c) => c.result === 'PASS') ? 'PASS' : 'FAIL';
const report = {
  schema: 'aipt.public.b006-validator-run/v1',
  task_id: CURRENT_BATCH,
  // AIPT-M0-B006 is under construction (IN_PROGRESS, GLOBAL_WIP = 1). This
  // report carries B006 task metadata but is explicitly NOT a closeout: the
  // batch is not accepted or merged until the controller closes it.
  note: 'AIPT-M0-B006 construction IN_PROGRESS — validator-run report, not a merge/closeout claim; UNREGISTERED-AIPT-P0-B002 NOT_AUTHORIZED',
  repo: ctx.repo,
  result,
  checks,
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = result === 'PASS' ? 0 : 1;
