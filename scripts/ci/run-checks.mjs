#!/usr/bin/env node
// AIPT-MVP-B001 validator suite entry (`pnpm run check`).
//
// Runs every validator with the repository root as context and prints a
// single machine-readable report. Exit code 0 only when every check is PASS.
// The report preserves every historical M0 gate and adds the exact MVP
// bootstrap authority/lifecycle gate plus the exact B001 acceptance gate.
// M0, B000 and B001 remain immutable; no batch is active and every later batch
// remains unauthorized/not started.
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
import { runHistoricalWeb } from './validate/mvp-b001.mjs';
import { run as runM0DevelopmentPass } from './validate/m0-development-pass.mjs';
import { run as runMvpBootstrap } from './validate/mvp-bootstrap.mjs';
import { run as runMvpB001 } from './validate/mvp-b001.mjs';
import { ACTIVE_BATCH } from './lib/constants.mjs';

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
  runHistoricalWeb(ctx),
  runM0DevelopmentPass(ctx),
  runMvpBootstrap(ctx),
  runMvpB001(ctx),
]);

const result = checks.every((c) => c.result === 'PASS') ? 'PASS' : 'FAIL';
const status = JSON.parse(fs.readFileSync(
  path.join(ctx.repo, 'docs/authority/registry/project-status.json'), 'utf8',
));
const standalone = status.tracks?.['AIPT-STANDALONE'];
const note = 'AIPT-MVP-B001 MERGED_CLOSED / GLOBAL_WIP 0 under AIPT-MVP-B001-CLOSEOUT-001; exact Candidate, merge and post-merge CI identities are frozen; Run Core, Agent orchestration, product-model calls and real playtest remain unimplemented; UNREGISTERED-AIPT-P1-B000 remains NOT_STARTED / NOT_AUTHORIZED; M0 Development Pass remains effective, MVP qualification remains NOT_GRANTED, and platform integration remains FROZEN_WAITING_M1_ENGINE';
const report = {
  schema: 'aipt.public.mvp-b001-validator-run/v1',
  task_id: ACTIVE_BATCH,
  note,
  repo: ctx.repo,
  result,
  checks,
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = result === 'PASS' ? 0 : 1;
