#!/usr/bin/env node
// B001 source-provenance metadata emitter (CI step, output not committed).
//
// Records where a CI build came from: repository, commit, workflow run
// identity, runner environment, SBOM SHA-256 and pinned toolchain versions.
// Local runs (no GITHUB_RUN_ID) only print the record.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { buildSbom } from './sbom/generate-sbom.mjs';

function gitOut(args) {
  const cp = spawnSync('git', args, { encoding: 'utf8' });
  if (cp.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${cp.stderr}`);
  return cp.stdout.trim();
}

const repo = process.cwd();
const toolchain = JSON.parse(fs.readFileSync(path.join(repo, 'tools/toolchain.lock.json'), 'utf8'));
const sbom = buildSbom(repo);
const sbomSha256 = crypto.createHash('sha256').update(sbom).digest('hex');

const record = {
  schema: 'aipt.public.source-provenance/v1',
  generated_at: new Date().toISOString(),
  repository: process.env.GITHUB_REPOSITORY || 'github.com/zyc14588/AIPT',
  commit: gitOut(['rev-parse', 'HEAD']),
  branch_or_ref: process.env.GITHUB_REF || gitOut(['rev-parse', '--abbrev-ref', 'HEAD']),
  workflow: process.env.GITHUB_WORKFLOW || 'local',
  workflow_ref: process.env.GITHUB_WORKFLOW_REF || 'n/a (local run)',
  run_id: process.env.GITHUB_RUN_ID || null,
  run_attempt: process.env.GITHUB_RUN_ATTEMPT || null,
  event_name: process.env.GITHUB_EVENT_NAME || null,
  runner: {
    os: process.env.RUNNER_OS || `${os.type()} ${os.release()}`,
    arch: process.env.RUNNER_ARCH || os.arch(),
    image_os: process.env.ImageOS || null,
    image_version: process.env.ImageVersion || null,
  },
  sbom: {
    format: 'SPDX-2.3 (JSON)',
    sha256: sbomSha256,
    deterministic: true,
  },
  toolchain: {
    go: toolchain.toolchains.go.version,
    node: toolchain.toolchains.node.version,
    pnpm: toolchain.toolchains.pnpm.version,
    postgresql: toolchain.toolchains.postgresql.version,
    govulncheck: toolchain.tooling.govulncheck.version,
  },
};

const out = `${JSON.stringify(record, null, 2)}\n`;
if (process.env.GITHUB_RUN_ID) {
  const dest = process.env.RUNNER_TEMP || os.tmpdir();
  const file = path.join(dest, 'aipt-b001-provenance.json');
  fs.writeFileSync(file, out);
  process.stdout.write(`provenance record written: ${file}\n`);
}
process.stdout.write(out);
