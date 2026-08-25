#!/usr/bin/env node
// B008 validator suite entry (`pnpm run check`).
//
// Runs every validator with the repository root as context and prints a
// single machine-readable report. Exit code 0 only when every check is PASS.
// The report schema and task_id are B008 Candidate metadata: the report is an
// under-construction validator run, never an effective Development Pass,
// merge or closeout claim. Every historical gate is retained alongside the
// B008 milestone gate.
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
]);

const result = checks.every((c) => c.result === 'PASS') ? 'PASS' : 'FAIL';
const report = {
  schema: 'aipt.public.b008-validator-run/v1',
  task_id: CURRENT_BATCH,
  note: 'AIPT-M0-B008 Candidate construction IN_PROGRESS — proposed M0 Development Pass remains NOT_YET_GRANTED until B008 is MERGED_CLOSED; no merge, closeout or next batch is authorized',
  repo: ctx.repo,
  result,
  checks,
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = result === 'PASS' ? 0 : 1;
