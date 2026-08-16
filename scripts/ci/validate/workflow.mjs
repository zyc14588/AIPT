// B001 workflow validator: secret-free, full-SHA action pins, digest-pinned
// containers, correct runner coverage, and the three required jobs.
import fs from 'node:fs';
import path from 'node:path';
import { CI_ACTION_PINS, PG_MULTI_ARCH_DIGEST, TOOLCHAIN, GOVULNCHECK } from '../lib/constants.mjs';
import { runAsMain } from '../lib/cli.mjs';

const WORKFLOW = '.github/workflows/ci.yml';

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const text = fs.readFileSync(path.join(ctx.repo, WORKFLOW), 'utf8');

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

  // ---- pinned versions inside the workflow ----
  for (const needle of [
    `go-version: ${TOOLCHAIN.go}`,
    `node-version: ${TOOLCHAIN.node}`,
    `pnpm@${TOOLCHAIN.pnpm}`,
    `@${GOVULNCHECK.version}`,
    'gofmt',
    'go vet ./...',
    'go test ./...',
    'pnpm install --frozen-lockfile',
    'pnpm audit',
  ]) {
    if (!text.includes(needle)) fail(`workflow missing expected step content: ${needle}`);
  }
  ok('workflow pins exact toolchain versions and expected commands');

  // ---- no model network config ----
  const modelHosts = ['deepseek', 'openai', 'anthropic', 'moonshot', 'openrouter', 'googleapis'];
  const hit = modelHosts.find((h) => text.toLowerCase().includes(h));
  if (hit) fail(`workflow contains model-endpoint material (${hit})`);
  else ok('workflow contains no remote-model network configuration');

  return { name: 'workflow', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain('workflow', run);
