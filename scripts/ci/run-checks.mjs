#!/usr/bin/env node
// B001 validator suite entry (`pnpm run check`).
//
// Runs every B001 validator with the repository root as context and prints a
// single machine-readable report. Exit code 0 only when every check is PASS.
import path from 'node:path';
import { run as runStatus } from './validate/status-transition.mjs';
import { run as runDefer } from './validate/defer-016.mjs';
import { run as runToolchain } from './validate/toolchain-lock.mjs';
import { run as runWorkflow } from './validate/workflow.mjs';
import { run as runTree } from './validate/tree-integrity.mjs';
import { run as runRetro } from './validate/b000-retro.mjs';
import { run as runSupplyChain } from './validate/supply-chain.mjs';
import { run as runSbom } from './validate/sbom.mjs';
import { TASK_ID } from './lib/constants.mjs';

const ctx = { repo: path.resolve(process.cwd()) };
const checks = [
  runStatus(ctx),
  runDefer(ctx),
  runToolchain(ctx),
  runWorkflow(ctx),
  runTree(ctx),
  runRetro(ctx),
  runSupplyChain(ctx),
  runSbom(ctx),
];

const result = checks.every((c) => c.result === 'PASS') ? 'PASS' : 'FAIL';
const report = {
  schema: 'aipt.public.b001-validator-run/v1',
  task_id: TASK_ID,
  repo: ctx.repo,
  result,
  checks,
};
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
process.exitCode = result === 'PASS' ? 0 : 1;
