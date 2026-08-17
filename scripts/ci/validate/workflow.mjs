// B002 workflow validator: the public .github/workflows/ci.yml must be the
// durable `AIPT M0 CI` workflow — secret-free, full-SHA action pins agreed
// with the frozen action lock, digest-pinned containers, Linux-only, the
// three required jobs, and the toolchain matrix (ubuntu-24.04 +
// ubuntu-26.04, fail-fast false) running the three explicit B002 contract
// gates plus the aggregate `pnpm run check` alongside every retained
// B000/B001 command and gate. Every required needle is fail-closed: a
// recorded missing needle fails the validator, never an unconditional ok.
import fs from 'node:fs';
import path from 'node:path';
import {
  B000,
  CI_ACTION_PINS,
  PG_MULTI_ARCH_DIGEST,
  TOOLCHAIN,
  GOVULNCHECK,
} from '../lib/constants.mjs';
import { runAsMain } from '../lib/cli.mjs';

const WORKFLOW = '.github/workflows/ci.yml';
const DURABLE_WORKFLOW_NAME = 'AIPT M0 CI';
const STALE_WORKFLOW_NAME = 'AIPT M0 B001 CI';
const CONCURRENCY_GROUP = 'aipt-m0-${{ github.workflow }}-${{ github.ref }}';
const MATRIX_RUNNERS = ['ubuntu-24.04', 'ubuntu-26.04'];

// The three explicit B002 contract gates plus the retained aggregate
// `pnpm run check`, each of which must be a `run:` step of the toolchain job.
const FOCUSED_COMMANDS = [
  'pnpm run check:protocol-assets',
  'pnpm run test:adapter-sdk',
  'pnpm run test:protocol-go',
  'pnpm run check',
];

// Step-name tokens the toolchain job must carry so the B002 coverage
// (schema / JSON-RPC / shared fixture, Adapter SDK, Go fixture, hidden-leak
// mutant rejection, replay determinism) stays auditable.
const STEP_NAME_NEEDLES = [
  'schema',
  'json-rpc',
  'shared fixture',
  'adapter sdk',
  'go fixture',
  'mutant',
  'replay',
];

// Retained B000/B001 gates that must stay in the workflow verbatim (checked
// against the whole file; the B002 focused commands are checked inside the
// toolchain job separately and strictly).
const RETAINED_GATES = [
  `go-version: ${TOOLCHAIN.go}`,
  `node-version: ${TOOLCHAIN.node}`,
  `pnpm@${TOOLCHAIN.pnpm}`,
  `@${GOVULNCHECK.version}`,
  'gofmt',
  'go vet ./...',
  'go test ./...',
  'pnpm install --frozen-lockfile',
  'pnpm audit',
  'go mod tidy',
  'git diff --exit-code -- go.mod go.sum',
  'postgres (PostgreSQL) 18.4',
  'node scripts/ci/validate/b000-retro.mjs',
  `--commit ${B000.commit}`,
  `--expected-tree ${B000.tree}`,
  'node scripts/ci/validate/supply-chain.mjs',
  'node scripts/ci/validate/sbom.mjs',
  'node scripts/ci/provenance.mjs',
];

// Extract one top-level job block (2-space indented job key until the next
// 2-space indented job key). Job content keys live at >=4 spaces, so they
// cannot collide with the boundary pattern.
function jobBlock(text, jobName) {
  const re = new RegExp(`^  ${jobName}:\\s*$([\\s\\S]*?)(?=^  [a-z0-9-]+:\\s*$)`, 'm');
  return re.exec(text)?.[1] ?? null;
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const text = fs.readFileSync(path.join(ctx.repo, WORKFLOW), 'utf8');

  // ---- durable workflow identity ----
  if (/^name:\s*AIPT M0 CI\s*$/m.test(text)) ok(`durable workflow name: ${DURABLE_WORKFLOW_NAME}`);
  else fail(`workflow name must be exactly ${JSON.stringify(DURABLE_WORKFLOW_NAME)}`);
  if (text.includes(STALE_WORKFLOW_NAME)) fail(`stale workflow name ${STALE_WORKFLOW_NAME} still present`);
  else ok('no stale B001 workflow name');

  // ---- concurrency prefix consistency ----
  const groupMatch = /^  group:\s*(.+?)\s*$/m.exec(text);
  if (groupMatch?.[1] === CONCURRENCY_GROUP) ok(`concurrency group uses the durable ${CONCURRENCY_GROUP} prefix`);
  else fail(`concurrency group must be exactly ${JSON.stringify(CONCURRENCY_GROUP)}`);
  if (text.includes('cancel-in-progress: false')) ok('concurrency cancel-in-progress: false retained');
  else fail('concurrency cancel-in-progress: false removed');

  // ---- permissions ----
  const permBlock = /^permissions:\s*$([\s\S]*?)(?=^\S)/m.exec(text);
  if (!permBlock) {
    fail('missing top-level permissions block');
  } else {
    const block = permBlock[1];
    if (!/^\s*contents:\s*read\s*$/m.test(block)) fail('permissions must be exactly contents: read');
    else ok('permissions: contents: read');
    if (/write/.test(block)) fail('permissions block must grant no write access');
    else ok('no write permission granted');
  }
  const permCount = (text.match(/^permissions:\s*$/gm) ?? []).length;
  if (permCount !== 1) fail(`expected exactly one top-level permissions block, found ${permCount}`);
  else ok('single top-level permissions block (no job-level overrides)');

  // ---- secret references ----
  if (text.includes('secrets.')) fail('workflow must not reference secrets.*');
  else ok('no secrets.* reference anywhere in the workflow');
  if (text.includes('id-token')) fail('workflow must not request OIDC id-token');
  else ok('no OIDC id-token requested');

  // ---- action pins ----
  const uses = [...text.matchAll(/^\s*uses:\s*([^\s#]+)\s*(#\s*(\S+))?\s*$/gm)].map((m) => ({
    raw: m[1],
    tagComment: m[3] ?? null,
  }));
  if (uses.length === 0) fail('no uses: entries found');
  const lock = JSON.parse(fs.readFileSync(path.join(ctx.repo, 'tools/ci-actions.lock.json'), 'utf8'));
  const lockByRepo = new Map(lock.actions.map((a) => [a.repository, a]));
  const usedRepos = new Set();
  for (const use of uses) {
    const at = use.raw.lastIndexOf('@');
    const repo = use.raw.slice(0, at);
    const ref = use.raw.slice(at + 1);
    usedRepos.add(repo);
    if (!/^[0-9a-f]{40}$/.test(ref)) {
      fail(`uses: ${use.raw} is not a full 40-hex commit SHA pin`);
      continue;
    }
    const entry = lockByRepo.get(repo);
    if (!entry) {
      fail(`uses: ${repo} has no entry in tools/ci-actions.lock.json`);
      continue;
    }
    if (entry.resolved_commit_sha !== ref) {
      fail(`${repo}: workflow SHA ${ref} != lock resolved_commit_sha ${entry.resolved_commit_sha}`);
    }
    if (use.tagComment && use.tagComment !== entry.stable_release_tag) {
      fail(`${repo}: trailing tag comment ${use.tagComment} != lock stable tag ${entry.stable_release_tag}`);
    }
  }
  if (uses.every((u) => /^[0-9a-f]{40}$/.test(u.raw.slice(u.raw.lastIndexOf('@') + 1)))) {
    ok(`all ${uses.length} uses: entries are full-SHA pinned`);
  }
  const lockedRepos = new Set(lock.actions.map((a) => a.repository));
  const expectedRepos = new Set(Object.keys(CI_ACTION_PINS));
  if (JSON.stringify([...usedRepos].sort()) !== JSON.stringify([...lockedRepos].sort())) {
    fail(`workflow/lock repository set mismatch: workflow=${[...usedRepos].sort().join(',')} lock=${[...lockedRepos].sort().join(',')}`);
  } else ok('workflow uses: set matches tools/ci-actions.lock.json exactly');
  if (JSON.stringify([...lockedRepos].sort()) !== JSON.stringify([...expectedRepos].sort())) {
    fail('ci-actions.lock.json contains unexpected action repositories');
  } else ok('ci-actions.lock.json covers exactly the three expected actions');
  for (const [repo, pin] of Object.entries(CI_ACTION_PINS)) {
    const entry = lockByRepo.get(repo);
    if (entry?.stable_release_tag !== pin.tag || entry?.resolved_commit_sha !== pin.sha) {
      fail(`${repo}: lock tag/sha mismatch vs fixed qualification (${pin.tag} / ${pin.sha})`);
    }
  }
  if (!/@(main|master|v\d)/.test(uses.map((u) => u.raw).join('\n'))) ok('no @main/@master/@vN floating refs on uses: lines');
  else fail('floating action refs present');

  // ---- jobs & runners ----
  const jobNames = [...text.matchAll(/^\s{2}([a-z0-9-]+):\s*$/gm)].map((m) => m[1]);
  for (const required of ['b000-retro', 'toolchain', 'supply-chain']) {
    if (!jobNames.includes(required)) fail(`required job missing: ${required}`);
    else ok(`required job present: ${required}`);
  }
  if (text.includes('ubuntu-24.04') && text.includes('ubuntu-26.04')) {
    ok('runner coverage includes ubuntu-24.04 (GA) and ubuntu-26.04 (reference)');
  } else fail('runner coverage must include ubuntu-24.04 and ubuntu-26.04');
  if (/runs-on:\s*(macos|windows)/.test(text)) fail('CI must be GitHub-hosted Linux only');
  else ok('GitHub-hosted Linux only');

  // ---- toolchain job: matrix, B002 focused commands, auditable step names ----
  const toolchain = jobBlock(text, 'toolchain');
  if (!toolchain) {
    fail('toolchain job block not found');
  } else {
    const strategy = /^    strategy:([\s\S]*?)(?=^    (?:steps|runs-on|name):)/m.exec(toolchain)?.[1] ?? '';
    if (!strategy) fail('toolchain strategy block not found');
    else {
      if (!/^\s{6}fail-fast:\s*false\s*$/m.test(strategy)) fail('toolchain matrix must keep fail-fast: false');
      else ok('toolchain matrix fail-fast: false');
      const missingRunners = MATRIX_RUNNERS.filter((r) => !strategy.includes(r));
      if (missingRunners.length > 0) fail(`toolchain matrix missing runner(s): ${missingRunners.join(', ')}`);
      else ok(`toolchain matrix runs on ${MATRIX_RUNNERS.join(' + ')}`);
    }

    // B002 focused commands must be real `run:` steps of the toolchain job —
    // not arbitrary text or comments elsewhere in the workflow.
    const runLines = [...toolchain.matchAll(/^\s{8}run:\s*(.+?)\s*$/gm)].map((m) => m[1].trim());
    for (const cmd of FOCUSED_COMMANDS) {
      if (runLines.includes(cmd)) ok(`toolchain job runs: ${cmd}`);
      else fail(`toolchain job must run ${cmd} as an explicit step`);
    }

    // Step names must keep the B002 coverage auditable.
    const stepNames = [...toolchain.matchAll(/^\s{6}-\s+name:\s*(.+?)\s*$/gm)].map((m) => m[1]);
    for (const needle of STEP_NAME_NEEDLES) {
      const hit = stepNames.some((n) => n.toLowerCase().includes(needle));
      if (hit) ok(`toolchain step names make ${needle} coverage auditable`);
      else fail(`toolchain step names must make ${needle} coverage auditable`);
    }
  }

  // ---- triggers ----
  const onBlock = /^on:\s*$([\s\S]*?)(?=^\S)/m.exec(text)?.[1] ?? '';
  if (onBlock.includes('push') && onBlock.includes('main') && onBlock.includes('task/**') && onBlock.includes('repair/**')) {
    ok('push triggers: main, task/**, repair/**');
  } else fail('push triggers must include main, task/** and repair/**');
  if (onBlock.includes('pull_request')) ok('pull_request trigger present');
  else fail('pull_request trigger missing');

  // ---- container digest pin ----
  const pgPinned = text.includes(`postgres@${PG_MULTI_ARCH_DIGEST}`);
  if (pgPinned) ok('PostgreSQL image pinned by multi-arch digest');
  else fail(`PostgreSQL pull must use digest ${PG_MULTI_ARCH_DIGEST}`);
  if (/postgres:18\.4/.test(text)) fail('PostgreSQL must not be referenced by bare tag (postgres:18.4)');
  else ok('no bare postgres:18.4 tag reference');

  // ---- retained B000/B001 gates (fail-closed: every missing needle fails) ----
  const missingGates = RETAINED_GATES.filter((needle) => !text.includes(needle));
  if (missingGates.length > 0) {
    fail(`workflow missing retained B000/B001 gate content: ${missingGates.join(', ')}`);
  } else ok('workflow retains exact toolchain pins, B000 retro, and every B001 command/gate');

  // ---- no model network config ----
  const modelHosts = ['deepseek', 'openai', 'anthropic', 'moonshot', 'openrouter', 'googleapis'];
  const hit = modelHosts.find((h) => text.toLowerCase().includes(h));
  if (hit) fail(`workflow contains model-endpoint material (${hit})`);
  else ok('workflow contains no remote-model network configuration');

  return { name: 'workflow', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'workflow', run);
