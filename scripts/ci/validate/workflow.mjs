// B002 workflow validator: the public .github/workflows/ci.yml must be the
// durable `AIPT M0 CI` workflow — secret-free, full-SHA action pins agreed
// with the frozen action lock, digest-pinned containers, Linux-only, the
// three required jobs, and the toolchain matrix (ubuntu-24.04 +
// ubuntu-26.04, fail-fast false) running the three explicit B002 contract
// gates plus the aggregate `pnpm run check` alongside every retained
// B000/B001 command and gate. Every required needle is fail-closed: a
// recorded missing needle fails the validator, never an unconditional ok.
//
// This fixed workflow subset is parsed with small explicit indentation
// helpers (no YAML dependency): block structure comes from real key lines at
// fixed indents, so commented-out or relocated strings can never satisfy the
// permissions, fail-fast, or matrix checks. Step `name:` scalars are checked
// lexically: an unquoted `: ` inside a plain scalar makes the whole file
// invalid YAML, so restoring the exact unsafe focused step name fails here.
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

// ---- small explicit indentation helpers for this fixed workflow subset ----

// Leading-space count of one line.
function indent(line) {
  let n = 0;
  while (n < line.length && line[n] === ' ') n += 1;
  return n;
}

// True for blank and comment-only lines (they never start or end a block).
function isBlankOrComment(line) {
  const t = line.trimStart();
  return t === '' || t.startsWith('#');
}

// Index of a block-style `key:` line at exactly `keyIndent` spaces,
// searching from `from` (inclusive), or -1.
function findKeyLine(lines, key, keyIndent, from = 0) {
  const re = new RegExp(`^ {${keyIndent}}${key}:$`);
  for (let i = from; i < lines.length; i += 1) {
    if (re.test(lines[i])) return i;
  }
  return -1;
}

// Body lines of the block-style mapping entry whose key line is at
// `keyLineIdx`: everything after the key line until the first non-blank,
// non-comment line indented at `keyIndent` spaces or fewer.
function bodyLines(lines, keyLineIdx, keyIndent) {
  let end = lines.length;
  for (let i = keyLineIdx + 1; i < lines.length; i += 1) {
    if (isBlankOrComment(lines[i])) continue;
    if (indent(lines[i]) <= keyIndent) {
      end = i;
      break;
    }
  }
  return lines.slice(keyLineIdx + 1, end);
}

// Narrow scalar cleanup for this subset: strip a trailing ` #` comment and
// one pair of surrounding quotes.
function scalarValue(raw) {
  let v = raw;
  const hash = v.indexOf(' #');
  if (hash >= 0) v = v.slice(0, hash);
  v = v.trim();
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    v = v.slice(1, -1);
  }
  return v;
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
  const lines = text.split('\n');

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

  // ---- YAML syntax guard for step name: scalars (narrow, dependency-free) ----
  // In this fixed subset every step name is a plain or quoted scalar on a
  // 6-space `- name:` line. An unquoted plain scalar containing `: ` (the
  // YAML mapping indicator) makes the entire file invalid YAML, so the exact
  // unsafe unquoted focused step name must fail here lexically.
  const unsafeNames = [];
  for (let i = 0; i < lines.length; i += 1) {
    const m = /^ {6}- name:\s*(.+?)\s*$/.exec(lines[i]);
    if (!m) continue;
    const value = m[1];
    if (value.startsWith('"') || value.startsWith("'")) continue;
    if (/:\s/.test(value)) unsafeNames.push({ line: i + 1, value });
  }
  if (unsafeNames.length === 0) ok('every step name: scalar is YAML-safe (no unquoted `: `)');
  else {
    for (const u of unsafeNames) {
      fail(`step name at line ${u.line} is an unsafe unquoted scalar (YAML mapping indicator): ${u.value}`);
    }
  }

  // ---- permissions: exactly one top-level mapping, { contents: read } ----
  const permMappings = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (isBlankOrComment(lines[i])) continue;
    if (/^ *permissions:/.test(lines[i])) permMappings.push({ idx: i, indent: indent(lines[i]) });
  }
  if (permMappings.length === 1 && permMappings[0].indent === 0) {
    ok('exactly one permissions: mapping and it is top-level (no job-level/nested overrides)');
  } else {
    const desc = permMappings.length
      ? permMappings.map((p) => `line ${p.idx + 1}@indent ${p.indent}`).join(', ')
      : 'none';
    fail(`expected exactly one top-level permissions: mapping; found ${desc}`);
  }
  const permKeyIdx = findKeyLine(lines, 'permissions', 0);
  if (permKeyIdx < 0) {
    fail('missing top-level permissions block (`permissions:` with exactly `contents: read` beneath)');
  } else {
    const body = bodyLines(lines, permKeyIdx, 0);
    const entries = body.filter(
      (l) => !isBlankOrComment(l) && indent(l) === 2 && /^[A-Za-z0-9_-]+:/.test(l.trimStart()),
    );
    const exactlyContentsRead =
      entries.length === 1 && /^contents:\s*read\s*(?:#.*)?$/.test(entries[0].trimStart());
    if (exactlyContentsRead) ok('top-level permissions mapping is exactly { contents: read }');
    else {
      fail(`top-level permissions mapping must contain exactly one entry, \`contents: read\`; parsed ${JSON.stringify(entries.map((l) => l.trim()))}`);
    }
    if (/write/.test(body.join('\n'))) fail('permissions mapping must grant no write access');
    else ok('no write permission granted');
  }

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
  const jobsKeyIdx = findKeyLine(lines, 'jobs', 0);
  const jobsBody = jobsKeyIdx >= 0 ? bodyLines(lines, jobsKeyIdx, 0) : [];
  const jobNames = jobsBody
    .filter((l) => indent(l) === 2 && /^[a-z0-9-]+:$/.test(l.trimStart()))
    .map((l) => l.trim().slice(0, -1));
  for (const required of ['b000-retro', 'toolchain', 'supply-chain']) {
    if (jobNames.includes(required)) ok(`required job present: ${required}`);
    else fail(`required job missing: ${required}`);
  }
  if (/runs-on:\s*(macos|windows)/.test(text)) fail('CI must be GitHub-hosted Linux only');
  else ok('GitHub-hosted Linux only');

  // ---- toolchain job: matrix, B002 focused commands, auditable step names ----
  const toolchainIdx = findKeyLine(jobsBody, 'toolchain', 2);
  const toolchainBody = toolchainIdx >= 0 ? bodyLines(jobsBody, toolchainIdx, 2) : null;
  let matrixRunners = null;
  if (!toolchainBody) {
    fail('toolchain job block not found');
  } else {
    const strategyIdx = findKeyLine(toolchainBody, 'strategy', 4);
    const strategyBody = strategyIdx >= 0 ? bodyLines(toolchainBody, strategyIdx, 4) : null;
    if (!strategyBody) {
      fail('toolchain strategy block not found');
    } else {
      const failFastLines = strategyBody.filter(
        (l) => indent(l) === 6 && /^fail-fast:/.test(l.trimStart()),
      );
      if (failFastLines.length === 1 && /^fail-fast:\s*false\s*(?:#.*)?$/.test(failFastLines[0].trimStart())) {
        ok('toolchain matrix fail-fast: false (real entry at matrix indentation)');
      } else {
        fail('toolchain matrix must keep exactly one real fail-fast: false entry');
      }

      const matrixIdx = findKeyLine(strategyBody, 'matrix', 6);
      const matrixBody = matrixIdx >= 0 ? bodyLines(strategyBody, matrixIdx, 6) : null;
      if (!matrixBody) {
        fail('toolchain strategy.matrix block not found');
      } else {
        const osIdx = findKeyLine(matrixBody, 'os', 8);
        const osBody = osIdx >= 0 ? bodyLines(matrixBody, osIdx, 8) : null;
        if (!osBody) {
          fail('toolchain strategy.matrix.os block not found');
        } else {
          // Only real non-comment list entries count; runner strings in
          // comments or in other jobs can never satisfy this check.
          matrixRunners = osBody
            .filter((l) => /^ {10}- /.test(l))
            .map((l) => scalarValue(l.trim().slice(2)));
          const expected = [...MATRIX_RUNNERS].sort();
          const actual = [...matrixRunners].sort();
          if (matrixRunners.length === MATRIX_RUNNERS.length && actual.every((r, i) => r === expected[i])) {
            ok(`toolchain strategy.matrix.os parses to exactly ${MATRIX_RUNNERS.join(' + ')} (each once)`);
          } else {
            fail(`toolchain strategy.matrix.os must parse to exactly [${MATRIX_RUNNERS.join(', ')}]; parsed ${JSON.stringify(matrixRunners)}`);
          }
        }
      }
    }

    // Runner coverage is derived from the parsed matrix entries, never from
    // raw substring presence, so comments/other jobs cannot satisfy it.
    const covered =
      matrixRunners !== null &&
      matrixRunners.length === MATRIX_RUNNERS.length &&
      MATRIX_RUNNERS.every((r) => matrixRunners.includes(r));
    if (covered) ok('runner coverage includes ubuntu-24.04 (GA) and ubuntu-26.04 (reference)');
    else fail('runner coverage must include ubuntu-24.04 and ubuntu-26.04 (parsed matrix entries)');

    // B002 focused commands must be real `run:` steps of the toolchain job —
    // not arbitrary text or comments elsewhere in the workflow.
    const runLines = toolchainBody
      .map((l) => /^ {8}run:\s*(.+?)\s*$/.exec(l)?.[1]?.trim())
      .filter((v) => typeof v === 'string');
    for (const cmd of FOCUSED_COMMANDS) {
      if (runLines.includes(cmd)) ok(`toolchain job runs: ${cmd}`);
      else fail(`toolchain job must run ${cmd} as an explicit step`);
    }

    // Step names must keep the B002 coverage auditable.
    const stepsIdx = findKeyLine(toolchainBody, 'steps', 4);
    const stepsBody = stepsIdx >= 0 ? bodyLines(toolchainBody, stepsIdx, 4) : [];
    const stepNames = stepsBody
      .map((l) => /^ {6}- name:\s*(.+?)\s*$/.exec(l)?.[1])
      .filter(Boolean)
      .map((v) => scalarValue(v));
    for (const needle of STEP_NAME_NEEDLES) {
      const hit = stepNames.some((n) => n.toLowerCase().includes(needle));
      if (hit) ok(`toolchain step names make ${needle} coverage auditable`);
      else fail(`toolchain step names must make ${needle} coverage auditable`);
    }
  }

  // ---- triggers ----
  const onIdx = findKeyLine(lines, 'on', 0);
  const onBody = (onIdx >= 0 ? bodyLines(lines, onIdx, 0) : []).join('\n');
  if (onBody.includes('push') && onBody.includes('main') && onBody.includes('task/**') && onBody.includes('repair/**')) {
    ok('push triggers: main, task/**, repair/**');
  } else fail('push triggers must include main, task/** and repair/**');
  if (onBody.includes('pull_request')) ok('pull_request trigger present');
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
