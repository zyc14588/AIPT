// B002 workflow validator: the public .github/workflows/ci.yml must be the
// durable `AIPT M0 CI` workflow — secret-free, full-SHA action pins agreed
// with the frozen action lock, digest-pinned containers, Linux-only, the
// three required jobs, and the toolchain matrix (ubuntu-24.04 +
// ubuntu-26.04, fail-fast false) running the three explicit B002 contract
// gates plus the aggregate `pnpm run check` alongside every retained
// B000/B001 command and gate. Every required needle is fail-closed: a
// recorded missing needle fails the validator, never an unconditional ok.
//
// 6B2 hardening: executable evidence is bound to the exact required job and
// step that must run it — never to whole-file substring matches. The fixed
// workflow subset is parsed with small explicit indentation helpers (no YAML
// dependency): every required job body is extracted from the real `jobs:`
// mapping (the final job parses exactly like a job followed by another job),
// a step starts at the real six-space `- name:` line and ends before the
// next six-space step, step names are read with the narrow scalar helper,
// disguised control keys normalize through a small mapping-key helper (`if`,
// `continue-on-error`, `shell` on every step of those jobs; `if`,
// `continue-on-error`, `defaults`, `shell` on every required job;
// `permissions` at any scope) and every step must start with the canonical
// six-space `- name:` form, and run evidence comes
// only from inline `run:` lines (exact command equality, so `|| true`, echo
// wrappers or extra shell text can never masquerade as a gate) or
// literal/folded block run bodies that equal the accepted run block's exact
// ordered non-blank/non-comment command lines in exactly one real step.
// Every block gate carries a unique anchor command that must occur exactly
// once across every run form of its job, and every gate command's total
// executable occurrences across inline and block run forms are counted, so a
// mutated or extra block can never hide beside one valid block. Focused and
// aggregate commands must each run exactly once, unconditionally, after the
// single frozen-install step, under their auditable step name, exactly once
// total in the toolchain job and never in b000-retro/supply-chain; retained
// single-line gate commands must run exactly once in their intended job.
// Triggers and the top-level concurrency block are parsed as real blocks too:
// on.push/on.pull_request branches must be exactly the accepted non-comment
// list entries and concurrency exactly the two real indent-2 entries, while
// every action step keeps its own real `uses:` value and `with:` inputs, so
// the required jobs must carry the exact pinned action-step inventory in
// order with exact inputs (a version input under checkout can never satisfy
// setup-go/setup-node, and extra uses: steps always fail).
// Permission success details are emitted only when every permissions
// mapping/body validated cleanly and no mapping anywhere grants write.
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
const REQUIRED_JOBS = ['b000-retro', 'toolchain', 'supply-chain'];

// The three explicit B002 contract gates plus the retained aggregate
// `pnpm run check`. Each must be exactly one real unconditional inline
// `run:` step of the toolchain job, positioned after the single frozen
// install step, with the auditable coverage tokens on that same step's name.
const FOCUSED_COMMANDS = [
  {
    command: 'pnpm run check:protocol-assets',
    nameTokens: ['schema', 'json-rpc', 'shared fixture', 'mutant', 'replay'],
  },
  { command: 'pnpm run test:adapter-sdk', nameTokens: ['adapter sdk'] },
  {
    command: 'pnpm run test:protocol-go',
    nameTokens: ['go fixture', 'shared fixture', 'replay'],
  },
  { command: 'pnpm run check', nameTokens: ['b001+b002', 'aggregate'] },
];

// Retained single-line gate commands: each must be exactly one real inline
// `run:` step of its intended job. A comment, a step name, another job, or a
// duplicate can never satisfy them.
const RETAINED_INLINE_GATES = {
  toolchain: ['go vet ./...', 'go test ./...', 'pnpm install --frozen-lockfile'],
  'supply-chain': [
    'pnpm install --frozen-lockfile',
    'node scripts/ci/validate/supply-chain.mjs',
    'pnpm audit',
    'node scripts/ci/validate/sbom.mjs',
    'node scripts/ci/provenance.mjs',
  ],
};

// Exact action-step inventory per required job: every action step (a step
// carrying a real `uses:` value) must appear exactly once, in this order,
// with the pinned action SHA (from CI_ACTION_PINS) and exactly these `with:`
// inputs — a version input on any other step (e.g. checkout) can never
// satisfy setup-go/setup-node, and extra uses: steps always fail.
const ACTION_STEPS = {
  'b000-retro': [
    { repo: 'actions/checkout', with: { 'fetch-depth': '0' } },
    { repo: 'actions/setup-node', with: { 'node-version': TOOLCHAIN.node } },
  ],
  toolchain: [
    { repo: 'actions/checkout', with: { 'fetch-depth': '0' } },
    { repo: 'actions/setup-go', with: { 'go-version': TOOLCHAIN.go, cache: 'false' } },
    { repo: 'actions/setup-node', with: { 'node-version': TOOLCHAIN.node } },
  ],
  'supply-chain': [
    { repo: 'actions/checkout', with: { 'fetch-depth': '0' } },
    { repo: 'actions/setup-go', with: { 'go-version': TOOLCHAIN.go, cache: 'false' } },
    { repo: 'actions/setup-node', with: { 'node-version': TOOLCHAIN.node } },
  ],
};

// Exact block evidence: every gate is the accepted run block's exact ordered
// non-blank, non-comment command lines — a matching block must equal them
// element for element, in order, inside exactly one real run step of the
// given job (echo wrappers, `|| true` suffixes, extra, missing or reordered
// lines never satisfy it). `anchor` is a command unique to that gate which
// must occur exactly once across every run form of the job (inline or
// block), so an additional mutated/extra gate block can never hide beside
// one valid block. The PostgreSQL gate carries both failure arms and the
// surrounding case/esac, echo, pull and inspect lines; the pnpm gates keep
// their real final `pnpm --version` line only where the accepted block has
// one; the non-gate environment-recording `grep ... || true` lines stay
// ungated.
const BLOCK_GATES = {
  'b000-retro': [
    {
      label: 'the fixed B000 validator invocation',
      anchor: 'node scripts/ci/validate/b000-retro.mjs',
      lines: [
        'node scripts/ci/validate/b000-retro.mjs',
        '--repo .',
        `--commit ${B000.commit}`,
        `--expected-tree ${B000.tree}`,
      ],
    },
    {
      label: 'the exact Node.js version verification',
      anchor: `test "$(node --version)" = "v${TOOLCHAIN.node}"`,
      lines: [`test "$(node --version)" = "v${TOOLCHAIN.node}"`, 'node --version'],
    },
  ],
  toolchain: [
    {
      label: 'the exact Node.js version verification',
      anchor: `test "$(node --version)" = "v${TOOLCHAIN.node}"`,
      lines: [`test "$(node --version)" = "v${TOOLCHAIN.node}"`, 'node --version'],
    },
    {
      label: 'the exact Go version verification',
      anchor: `test "$(go version)" = "go version go${TOOLCHAIN.go} linux/amd64"`,
      lines: [
        `test "$(go version)" = "go version go${TOOLCHAIN.go} linux/amd64"`,
        'go version',
      ],
    },
    {
      label: 'the exact pnpm installation and version verification',
      anchor: `test "$(pnpm --version)" = "${TOOLCHAIN.pnpm}"`,
      lines: [
        `npm install --global --no-audit --no-fund pnpm@${TOOLCHAIN.pnpm}`,
        `test "$(pnpm --version)" = "${TOOLCHAIN.pnpm}"`,
        'pnpm --version',
      ],
    },
    {
      label: 'the gofmt check',
      anchor: 'test -z "$(gofmt -l .)"',
      lines: ['test -z "$(gofmt -l .)"', 'echo "gofmt clean"'],
    },
    {
      label: 'the PostgreSQL digest pull / version / repository-digest checks',
      anchor: `docker pull "postgres@${PG_MULTI_ARCH_DIGEST}"`,
      lines: [
        `docker pull "postgres@${PG_MULTI_ARCH_DIGEST}"`,
        `PG_VERSION="$(docker run --rm "postgres@${PG_MULTI_ARCH_DIGEST}" postgres --version)"`,
        'echo "postgres --version => ${PG_VERSION}"',
        'case "${PG_VERSION}" in',
        `"postgres (PostgreSQL) ${TOOLCHAIN.postgresql}"*) ;;`,
        '*) echo "unexpected postgres version: ${PG_VERSION}"; exit 1 ;;',
        'esac',
        `REPO_DIGESTS="$(docker image inspect "postgres@${PG_MULTI_ARCH_DIGEST}" --format '{{join .RepoDigests ","}}')"`,
        'echo "RepoDigests: ${REPO_DIGESTS}"',
        'case "${REPO_DIGESTS}" in',
        `*"${PG_MULTI_ARCH_DIGEST}"*) ;;`,
        '*) echo "pinned multi-arch digest not reported in RepoDigests"; exit 1 ;;',
        'esac',
      ],
    },
  ],
  'supply-chain': [
    {
      label: 'the exact pnpm installation and version verification',
      anchor: `test "$(pnpm --version)" = "${TOOLCHAIN.pnpm}"`,
      lines: [
        `npm install --global --no-audit --no-fund pnpm@${TOOLCHAIN.pnpm}`,
        `test "$(pnpm --version)" = "${TOOLCHAIN.pnpm}"`,
      ],
    },
    {
      label: 'the go mod tidy + go.mod/go.sum diff gate',
      anchor: 'go mod tidy',
      lines: [
        'go mod tidy',
        'git diff --exit-code -- go.mod go.sum',
        'echo "go.mod / go.sum tidy-clean"',
      ],
    },
    {
      label: 'the pinned govulncheck install and execution',
      anchor: `GOBIN="\${RUNNER_TEMP}/bin" go install ${GOVULNCHECK.module}/cmd/govulncheck@${GOVULNCHECK.version}`,
      lines: [
        `GOBIN="\${RUNNER_TEMP}/bin" go install ${GOVULNCHECK.module}/cmd/govulncheck@${GOVULNCHECK.version}`,
        `"\${RUNNER_TEMP}/bin/govulncheck" -version`,
        `"\${RUNNER_TEMP}/bin/govulncheck" ./...`,
      ],
    },
  ],
};

// ---- small explicit indentation helpers for this fixed workflow subset ----

// Leading-space count of one line.
function indent(line) {
  let n = 0;
  while (n < line.length && line[n] === ' ') n += 1;
  return n;
}

// True for blank and comment-only lines (they never start or end a block and
// are never executable evidence).
function isBlankOrComment(line) {
  const t = line.trimStart();
  return t === '' || t.startsWith('#');
}

// Index of a block-style `key:` line at exactly `keyIndent` spaces, searching
// `lines` in [from, to), or -1.
function findKeyLineIn(lines, key, keyIndent, from = 0, to = lines.length) {
  const re = new RegExp(`^ {${keyIndent}}${key}:$`);
  for (let i = from; i < to; i += 1) {
    if (re.test(lines[i])) return i;
  }
  return -1;
}

// Body of the block-style mapping entry whose key line is at `keyLineIdx`:
// everything after the key line until the first non-blank, non-comment line
// indented at `keyIndent` spaces or fewer (or the end of the array). Works
// identically for a final mapping at end-of-file and for a mapping followed
// by another mapping at the same indentation.
function blockAt(lines, keyLineIdx, keyIndent) {
  let end = lines.length;
  for (let i = keyLineIdx + 1; i < lines.length; i += 1) {
    if (isBlankOrComment(lines[i])) continue;
    if (indent(lines[i]) <= keyIndent) {
      end = i;
      break;
    }
  }
  return { start: keyLineIdx + 1, end, lines: lines.slice(keyLineIdx + 1, end) };
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

// Normalized mapping key of a line whose key starts at exactly `keyIndent`
// leading spaces: a plain key token (no whitespace, quote or colon) or a
// single/double-quoted key token, followed by `:` with optional whitespace
// before it and an optional value after it. `if:`, `if :`, `'if':` and
// `"if":` all normalize to `if`. Returns the unquoted key, or null when the
// line is not such a mapping entry at that exact indentation.
function mappingKey(line, keyIndent) {
  if (indent(line) !== keyIndent) return null;
  const m = /^(?:'([^']*)'|"([^"]*)"|([^\s:'"]+))\s*:/.exec(line.slice(keyIndent));
  if (!m) return null;
  return m[1] ?? m[2] ?? m[3];
}

// Extract one required job's body from the parsed jobs block. `bodyStart` is
// the absolute index of the first body line, so every body line can be
// reported with its real 1-based file line number.
function jobBlock(jobsBlock, name) {
  if (!jobsBlock) return null;
  const keyIdx = findKeyLineIn(jobsBlock.lines, name, 2, 0, jobsBlock.lines.length);
  if (keyIdx < 0) return null;
  const body = blockAt(jobsBlock.lines, keyIdx, 2);
  return {
    name,
    body: body.lines,
    bodyStart: jobsBlock.start + body.start,
    keyLineNo: jobsBlock.start + keyIdx + 1,
  };
}

// Split a job body into steps and record every noncanonical step start. A
// step starts at the real six-space `- name:` line — the canonical form this
// workflow subset uses — and ends before the next six-space step. Any other
// six-space `- ` item (`- run:`, `- uses:`, ...) is a disguised shorthand
// step: it is recorded in `badStarts` (and never analyzed as an empty step)
// so the validator fails on it explicitly instead of silently passing it.
function stepsOf(job) {
  if (!job) return { steps: [], badStarts: [] };
  const stepsIdx = findKeyLineIn(job.body, 'steps', 4, 0, job.body.length);
  if (stepsIdx < 0) return { steps: [], badStarts: [] };
  const body = blockAt(job.body, stepsIdx, 4);
  const steps = [];
  const badStarts = [];
  let current = null;
  for (let i = 0; i < body.lines.length; i += 1) {
    const line = body.lines[i];
    if (/^ {6}- /.test(line)) {
      if (current) steps.push(current);
      const m = /^ {6}- name:\s*(.+?)\s*$/.exec(line);
      if (m) {
        current = {
          name: scalarValue(m[1]),
          lines: [line],
          lineNo: job.bodyStart + body.start + i + 1,
        };
      } else {
        badStarts.push({ raw: line.trim(), lineNo: job.bodyStart + body.start + i + 1 });
        current = null;
      }
    } else if (current) {
      current.lines.push(line);
    }
  }
  if (current) steps.push(current);
  return { steps, badStarts };
}

// Analyze one step: collect inline `run:` commands (exact command equality is
// the caller's job), literal/folded block run bodies (trimmed non-blank,
// non-comment command lines), real eight-space control metadata (`if:`,
// `continue-on-error:`, `shell:` — plain or quoted keys, optional whitespace
// before the colon), the step's real `uses:` value, and its real `with:`
// mapping entries (simple quoted/plain scalar values normalized via the
// narrow scalar helper; comments ignored). This is not a general YAML parser
// and never claims to be one.
function analyzeStep(step) {
  const runs = [];
  const conditions = { if: [], continueOnError: [], shell: [] };
  const uses = [];
  const withEntries = [];
  let inWith = false;
  for (let i = 0; i < step.lines.length; i += 1) {
    const line = step.lines[i];
    const lineNo = step.lineNo + i;
    const blockRun = /^ {8}run:\s*[|>][-+]?\s*(?:#.*)?$/.exec(line);
    if (blockRun) {
      const body = [];
      let j = i + 1;
      for (; j < step.lines.length; j += 1) {
        const l = step.lines[j];
        if (isBlankOrComment(l)) continue;
        if (indent(l) <= 8) break;
        body.push(l.trim());
      }
      runs.push({ kind: 'block', lines: body, lineNo });
      i = j - 1;
      continue;
    }
    const inlineRun = /^ {8}run:\s*(.+?)\s*$/.exec(line);
    if (inlineRun) {
      runs.push({ kind: 'inline', command: inlineRun[1].trim(), lineNo });
      continue;
    }
    const key = mappingKey(line, 8);
    if (key === 'uses') {
      const um = /^ {8}uses:\s*(.+?)\s*$/.exec(line);
      if (um) uses.push({ value: scalarValue(um[1]), lineNo });
      continue;
    }
    if (key === 'with') {
      inWith = true;
      continue;
    }
    if (inWith && indent(line) === 10) {
      const wk = mappingKey(line, 10);
      if (wk) {
        const vm = /^ {10}(?:'[^']*'|"[^"]*"|[^\s:'"]+)\s*:\s*(.*)$/.exec(line);
        withEntries.push({ key: wk, value: scalarValue(vm?.[1] ?? ''), lineNo });
      }
      continue;
    }
    if (key === 'if' || key === 'continue-on-error' || key === 'shell') {
      const vm = /^ {8}(?:'[^']*'|"[^"]*"|[^\s:'"]+)\s*:\s*(.*)$/.exec(line);
      const value = (vm?.[1] ?? '').trim();
      if (key === 'if') conditions.if.push({ value, lineNo });
      else if (key === 'continue-on-error') conditions.continueOnError.push({ value, lineNo });
      else conditions.shell.push({ value, lineNo });
    }
  }
  return { ...step, runs, conditions, uses, withEntries };
}

// Steps (in order) whose runs contain an inline command exactly equal to cmd.
function inlineHits(steps, cmd) {
  const hits = [];
  steps.forEach((s, i) => {
    for (const r of s.runs) {
      if (r.kind === 'inline' && r.command === cmd) hits.push({ stepIndex: i, step: s });
    }
  });
  return hits;
}

// True when two command-line arrays are element-for-element identical.
function arraysEqual(a, b) {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

// Every step (in order) whose runs contain a block whose trimmed non-blank,
// non-comment command lines equal `requiredLines` exactly, in order.
function exactBlockGateHits(analyzed, requiredLines) {
  const hits = [];
  analyzed.forEach((s, stepIndex) => {
    for (const r of s.runs) {
      if (r.kind === 'block' && arraysEqual(r.lines, requiredLines)) {
        hits.push({ stepIndex, step: s });
      }
    }
  });
  return hits;
}

// Total executable occurrences of `cmd` across every run form (inline `run:`
// commands and block command lines) of the analyzed steps. Comments, step
// names, `with:` entries and any other YAML text never count.
function totalOccurrences(analyzed, cmd) {
  let n = 0;
  for (const s of analyzed) {
    for (const r of s.runs) {
      if (r.kind === 'inline') {
        if (r.command === cmd) n += 1;
      } else {
        for (const l of r.lines) if (l === cmd) n += 1;
      }
    }
  }
  return n;
}

// Real non-comment branch list entries of the canonical
// `on.<trigger>.branches` block, or null when that block (or any part of it)
// is missing. Entries living in comments, in another trigger, or at another
// indentation never count.
function triggerBranches(onBlock, trigger) {
  if (!onBlock) return null;
  const trigIdx = findKeyLineIn(onBlock.lines, trigger, 2, 0, onBlock.lines.length);
  if (trigIdx < 0) return null;
  const trigBody = blockAt(onBlock.lines, trigIdx, 2);
  const branchesIdx = findKeyLineIn(trigBody.lines, 'branches', 4, 0, trigBody.lines.length);
  if (branchesIdx < 0) return null;
  const branchesBody = blockAt(trigBody.lines, branchesIdx, 4);
  return branchesBody.lines
    .filter((l) => /^ {6}- /.test(l))
    .map((l) => scalarValue(l.trim().slice(2)));
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

  // ---- concurrency: exactly the real top-level block ----
  // The top-level `concurrency:` mapping must carry exactly two real indent-2
  // entries: the durable group and cancel-in-progress: false. Comment-only or
  // nested lookalikes, duplicates, and extra entries all fail.
  const concurrencyIdx = findKeyLineIn(lines, 'concurrency', 0, 0, lines.length);
  const concurrencyBlock = concurrencyIdx >= 0 ? blockAt(lines, concurrencyIdx, 0) : null;
  const concurrencyEntries = [];
  for (const l of concurrencyBlock?.lines ?? []) {
    if (isBlankOrComment(l)) continue;
    if (indent(l) !== 2) continue; // nested lookalikes never count
    const ck = mappingKey(l, 2);
    if (!ck) continue;
    const cm = /^ {2}(?:'[^']*'|"[^"]*"|[^\s:'"]+)\s*:\s*(.*)$/.exec(l);
    concurrencyEntries.push([ck, scalarValue(cm?.[1] ?? '')]);
  }
  const expectedConcurrency = [
    ['group', CONCURRENCY_GROUP],
    ['cancel-in-progress', 'false'],
  ];
  if (
    concurrencyEntries.length === expectedConcurrency.length &&
    concurrencyEntries.every((e, i) => e[0] === expectedConcurrency[i][0] && e[1] === expectedConcurrency[i][1])
  ) {
    ok(`top-level concurrency block is exactly group: ${CONCURRENCY_GROUP} and cancel-in-progress: false`);
  } else {
    fail(`top-level concurrency block must contain exactly the two real entries group: ${JSON.stringify(CONCURRENCY_GROUP)} and cancel-in-progress: false; parsed ${JSON.stringify(concurrencyEntries)}`);
  }

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
  // Disguised keys count too: `permissions :`, `'permissions':` and
  // `"permissions":` at job/nested scope are detected as extra overrides.
  const permMappings = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (isBlankOrComment(lines[i])) continue;
    if (mappingKey(lines[i], indent(lines[i])) === 'permissions') {
      permMappings.push({ idx: i, indent: indent(lines[i]) });
    }
  }
  const permMappingValid = permMappings.length === 1 && permMappings[0].indent === 0;
  if (permMappingValid) {
    ok('exactly one permissions: mapping and it is top-level (no job-level/nested overrides)');
  } else {
    const desc = permMappings.length
      ? permMappings.map((p) => `line ${p.idx + 1}@indent ${p.indent}`).join(', ')
      : 'none';
    fail(`expected exactly one top-level permissions: mapping; found ${desc}`);
  }
  const permKeyIdx = findKeyLineIn(lines, 'permissions', 0, 0, lines.length);
  let topLevelPermValid = false;
  if (permKeyIdx < 0) {
    fail('missing top-level permissions block (`permissions:` with exactly `contents: read` beneath)');
  } else {
    const body = blockAt(lines, permKeyIdx, 0);
    const entries = body.lines.filter(
      (l) => !isBlankOrComment(l) && indent(l) === 2 && /^[A-Za-z0-9_-]+:/.test(l.trimStart()),
    );
    const exactlyContentsRead =
      entries.length === 1 && /^contents:\s*read\s*(?:#.*)?$/.test(entries[0].trimStart());
    if (exactlyContentsRead) ok('top-level permissions mapping is exactly { contents: read }');
    else {
      fail(`top-level permissions mapping must contain exactly one entry, \`contents: read\`; parsed ${JSON.stringify(entries.map((l) => l.trim()))}`);
    }
    if (/write/.test(body.lines.join('\n'))) fail('permissions mapping must grant no write access');
    topLevelPermValid = exactlyContentsRead && !/write/.test(body.lines.join('\n'));
  }
  // Any permissions mapping or body anywhere that grants write vetoes the
  // success detail: a rejected nested write must never report "no write
  // permission granted".
  const writeGranters = permMappings.filter((p) => {
    const scope = [lines[p.idx], ...blockAt(lines, p.idx, p.indent).lines].join('\n');
    return /write/.test(scope);
  });
  for (const p of writeGranters) {
    fail(`permissions mapping at line ${p.idx + 1} grants write access`);
  }
  if (permMappingValid && topLevelPermValid && writeGranters.length === 0) {
    ok('no write permission granted');
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
  const jobsKeyIdx = findKeyLineIn(lines, 'jobs', 0, 0, lines.length);
  const jobsBlock = jobsKeyIdx >= 0 ? blockAt(lines, jobsKeyIdx, 0) : null;
  const jobNames = (jobsBlock?.lines ?? [])
    .filter((l) => indent(l) === 2 && /^[a-z0-9-]+:$/.test(l.trimStart()))
    .map((l) => l.trim().slice(0, -1));
  for (const required of REQUIRED_JOBS) {
    if (jobNames.includes(required)) ok(`required job present: ${required}`);
    else fail(`required job missing: ${required}`);
  }
  if (/runs-on:\s*(macos|windows)/.test(text)) fail('CI must be GitHub-hosted Linux only');
  else ok('GitHub-hosted Linux only');

  // ---- required jobs are unconditional and failure-visible ----
  const jobs = {};
  const analyzedJobs = {};
  for (const required of REQUIRED_JOBS) {
    const job = jobBlock(jobsBlock, required);
    jobs[required] = job;
    if (!job) continue;
    let clean = true;
    for (let i = 0; i < job.body.length; i += 1) {
      const lineNo = job.bodyStart + i + 1;
      // Normalized keys: `if :`, `'if':` and `"if":` are rejected too.
      const key = mappingKey(job.body[i], 4);
      if (key === 'if') {
        clean = false;
        fail(`${required} job must not be conditionally skipped (job-level if: at line ${lineNo})`);
      } else if (key === 'continue-on-error') {
        clean = false;
        fail(`${required} job must not mask failures (job-level continue-on-error: at line ${lineNo})`);
      } else if (key === 'defaults') {
        clean = false;
        fail(`${required} job must not carry job-level defaults: (line ${lineNo})`);
      } else if (key === 'shell') {
        clean = false;
        fail(`${required} job must not carry job-level shell: (line ${lineNo})`);
      }
    }
    const { steps: jobSteps, badStarts } = stepsOf(job);
    const analyzed = jobSteps.map(analyzeStep);
    analyzedJobs[required] = analyzed;
    for (const b of badStarts) {
      clean = false;
      fail(`${required} job must start every step with the canonical "      - name: ..." form; noncanonical step start ${JSON.stringify(b.raw)} at line ${b.lineNo}`);
    }
    for (const s of analyzed) {
      const label = s.name ? JSON.stringify(s.name) : '(unnamed step)';
      for (const c of s.conditions.if) {
        clean = false;
        fail(`${required} step ${label} must not be conditionally skipped (if: ${c.value} at line ${c.lineNo})`);
      }
      for (const c of s.conditions.continueOnError) {
        clean = false;
        fail(`${required} step ${label} must not mask failures (continue-on-error: ${c.value} at line ${c.lineNo})`);
      }
      for (const c of s.conditions.shell) {
        clean = false;
        fail(`${required} step ${label} must not set a custom shell (shell: ${c.value} at line ${c.lineNo})`);
      }
    }
    if (clean) ok(`${required} job and every step are unconditional and failure-visible`);
  }

  // ---- toolchain job: matrix, B002 focused commands, auditable step names ----
  const toolchainJob = jobs.toolchain;
  let matrixRunners = null;
  if (!toolchainJob) {
    fail('toolchain job block not found');
  } else {
    const strategyIdx = findKeyLineIn(toolchainJob.body, 'strategy', 4, 0, toolchainJob.body.length);
    const strategyBlock = strategyIdx >= 0 ? blockAt(toolchainJob.body, strategyIdx, 4) : null;
    if (!strategyBlock) {
      fail('toolchain strategy block not found');
    } else {
      const failFastLines = strategyBlock.lines.filter(
        (l) => indent(l) === 6 && /^fail-fast:/.test(l.trimStart()),
      );
      if (failFastLines.length === 1 && /^fail-fast:\s*false\s*(?:#.*)?$/.test(failFastLines[0].trimStart())) {
        ok('toolchain matrix fail-fast: false (real entry at matrix indentation)');
      } else {
        fail('toolchain matrix must keep exactly one real fail-fast: false entry');
      }

      const matrixIdx = findKeyLineIn(strategyBlock.lines, 'matrix', 6, 0, strategyBlock.lines.length);
      const matrixBlock = matrixIdx >= 0 ? blockAt(strategyBlock.lines, matrixIdx, 6) : null;
      if (!matrixBlock) {
        fail('toolchain strategy.matrix block not found');
      } else {
        const osIdx = findKeyLineIn(matrixBlock.lines, 'os', 8, 0, matrixBlock.lines.length);
        const osBlock = osIdx >= 0 ? blockAt(matrixBlock.lines, osIdx, 8) : null;
        if (!osBlock) {
          fail('toolchain strategy.matrix.os block not found');
        } else {
          // Only real non-comment list entries count; runner strings in
          // comments or in other jobs can never satisfy this check.
          matrixRunners = osBlock.lines
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
  }

  // ---- per-job executable gates (bound to real steps of the right job) ----
  for (const required of REQUIRED_JOBS) {
    const job = jobs[required];
    const analyzed = analyzedJobs[required] ?? [];
    if (!job) continue;

    // Exact action-step inventory: every uses: step must be one of the
    // expected action steps, exactly once, in the expected order, with the
    // pinned action SHA and exactly the expected with: inputs. A version
    // input on any other step (e.g. checkout) can never satisfy
    // setup-go/setup-node, and extra uses: steps always fail.
    const expectedActions = ACTION_STEPS[required] ?? [];
    const actionSteps = analyzed
      .map((s, i) => ({ step: s, index: i }))
      .filter(({ step }) => step.uses.length > 0);
    if (actionSteps.length !== expectedActions.length) {
      fail(`${required} job must have exactly ${expectedActions.length} uses: step(s) in order ${expectedActions.map((a) => a.repo).join(', ')}; found ${actionSteps.length} action step(s)`);
    } else {
      let inventoryOk = true;
      for (let k = 0; k < expectedActions.length; k += 1) {
        const expected = expectedActions[k];
        const { step } = actionSteps[k];
        const expectedUses = `${expected.repo}@${CI_ACTION_PINS[expected.repo].sha}`;
        const usesValues = step.uses.map((u) => u.value);
        const actualWith = {};
        let withDup = false;
        for (const e of step.withEntries) {
          if (e.key in actualWith) withDup = true;
          actualWith[e.key] = e.value;
        }
        const expectedKeys = Object.keys(expected.with).sort();
        const actualKeys = Object.keys(actualWith).sort();
        const usesOk = usesValues.length === 1 && usesValues[0] === expectedUses;
        const inputsOk =
          !withDup &&
          expectedKeys.length === actualKeys.length &&
          expectedKeys.every((k2) => actualWith[k2] === expected.with[k2]);
        if (!usesOk || !inputsOk) {
          inventoryOk = false;
          const label = step.name ? JSON.stringify(step.name) : `step ${actionSteps[k].index + 1}`;
          fail(`${required} job action step ${k + 1} (${label}) must use ${expectedUses} with exactly ${JSON.stringify(expected.with)}; found uses ${JSON.stringify(usesValues)} with inputs ${JSON.stringify(actualWith)}`);
        }
      }
      if (inventoryOk) {
        ok(`${required} job action-step inventory matches exactly: ${expectedActions.map((a) => `${a.repo}@${CI_ACTION_PINS[a.repo].sha}`).join(' + ')} with exact with: inputs`);
      }
    }

    // Exact block gates: the accepted run block's exact ordered non-blank,
    // non-comment command lines must sit in exactly one real run step of this
    // job, and the gate's unique anchor command must occur exactly once
    // across every run form — so an extra or mutated gate block can never
    // hide beside one valid block (echo wrappers, `|| true` suffixes, comment
    // placements or reordered lines never satisfy it).
    for (const gate of BLOCK_GATES[required] ?? []) {
      const hits = exactBlockGateHits(analyzed, gate.lines);
      const anchorCount = totalOccurrences(analyzed, gate.anchor);
      if (hits.length === 1 && anchorCount === 1) {
        ok(`${required} job keeps ${gate.label} as exactly one exact run block (anchor \`${gate.anchor}\` unique in the job)`);
      } else {
        if (hits.length !== 1) {
          fail(`${required} job must keep ${gate.label} as exactly one run block whose exact ordered command lines are: ${gate.lines.join(' | ')}; found ${hits.length}`);
        }
        if (anchorCount !== 1) {
          fail(`${required} job anchor \`${gate.anchor}\` (${gate.label}) must occur exactly once across all run forms of the job; found ${anchorCount}`);
        }
      }
    }

    // Retained single-line gates: exactly one real inline run step each, and
    // exactly one executable occurrence total across inline and block run
    // forms (a block-run duplicate of the same command can never satisfy it).
    for (const cmd of RETAINED_INLINE_GATES[required] ?? []) {
      const hits = inlineHits(analyzed, cmd);
      const total = totalOccurrences(analyzed, cmd);
      if (hits.length === 1 && total === 1) {
        ok(`${required} job runs \`${cmd}\` exactly once (single real inline run step, no block duplicate)`);
      } else {
        fail(`${required} job must run \`${cmd}\` exactly once as a real inline run step and exactly once total across all run forms (comments, step names, other jobs, block duplicates and inline duplicates never count): inline ${hits.length}, total ${total}`);
      }
    }
  }

  // Focused + aggregate B002 commands: exactly once in toolchain, after the
  // single frozen-install step, under their own auditable step name, and
  // exactly once total across inline and block run forms — a block-run
  // duplicate can never satisfy them. They must not appear in the other
  // required jobs at all.
  const toolchainAnalyzed = analyzedJobs.toolchain ?? [];
  const frozenHits = inlineHits(toolchainAnalyzed, 'pnpm install --frozen-lockfile');
  const frozenIndex = frozenHits.length === 1 ? frozenHits[0].stepIndex : -1;
  for (const focused of FOCUSED_COMMANDS) {
    const hits = inlineHits(toolchainAnalyzed, focused.command);
    const total = totalOccurrences(toolchainAnalyzed, focused.command);
    for (const other of ['b000-retro', 'supply-chain']) {
      const otherTotal = totalOccurrences(analyzedJobs[other] ?? [], focused.command);
      if (otherTotal > 0) {
        fail(`${other} job must not run \`${focused.command}\` (focused/aggregate commands belong only to the toolchain job): found ${otherTotal} executable occurrence(s)`);
      }
    }
    if (hits.length !== 1) {
      fail(`toolchain job must run \`${focused.command}\` exactly once as a real inline run step (comments, step names, other jobs and duplicates never count): found ${hits.length}`);
      continue;
    }
    if (total !== 1) {
      fail(`toolchain job must run \`${focused.command}\` exactly once total across all run forms (a block-run duplicate can never satisfy it): found ${total}`);
    }
    const { stepIndex, step } = hits[0];
    const name = (step.name ?? '').toLowerCase();
    const missing = focused.nameTokens.filter((t) => !name.includes(t));
    if (missing.length > 0) {
      fail(`toolchain step running \`${focused.command}\` must keep the auditable name tokens ${focused.nameTokens.join(' / ')}; name ${JSON.stringify(step.name)} lacks: ${missing.join(', ')}`);
    }
    if (frozenIndex < 0 || stepIndex <= frozenIndex) {
      const where = frozenIndex < 0 ? 'frozen install missing' : `frozen install at step ${frozenIndex + 1}`;
      fail(`toolchain job must run \`${focused.command}\` after the single pnpm install --frozen-lockfile step (command at step ${stepIndex + 1}, ${where})`);
    }
    if (missing.length === 0 && frozenIndex >= 0 && stepIndex > frozenIndex && total === 1) {
      ok(`toolchain job runs \`${focused.command}\` exactly once, unconditionally, after the frozen install, under its auditable step name`);
    }
  }

  // ---- triggers: exact on.push / on.pull_request branches ----
  const onIdx = findKeyLineIn(lines, 'on', 0, 0, lines.length);
  const onBlock = onIdx >= 0 ? blockAt(lines, onIdx, 0) : null;
  const pushBranches = triggerBranches(onBlock, 'push');
  const expectedPush = ['main', 'task/**', 'repair/**'];
  if (
    pushBranches !== null &&
    pushBranches.length === expectedPush.length &&
    [...pushBranches].sort().every((b, i) => b === [...expectedPush].sort()[i])
  ) {
    ok('on.push.branches is exactly main, task/**, repair/** (each once)');
  } else {
    fail(`on.push.branches must contain exactly main, task/** and repair/** as real non-comment list entries; parsed ${JSON.stringify(pushBranches)}`);
  }
  const prBranches = triggerBranches(onBlock, 'pull_request');
  if (prBranches !== null && prBranches.length === 1 && prBranches[0] === 'main') {
    ok('on.pull_request.branches is exactly main (once)');
  } else {
    fail(`on.pull_request.branches must contain exactly main as a real non-comment list entry; parsed ${JSON.stringify(prBranches)}`);
  }

  // ---- container digest pin ----
  const pgPinned = text.includes(`postgres@${PG_MULTI_ARCH_DIGEST}`);
  if (pgPinned) ok('PostgreSQL image pinned by multi-arch digest');
  else fail(`PostgreSQL pull must use digest ${PG_MULTI_ARCH_DIGEST}`);
  if (/postgres:18\.4/.test(text)) fail('PostgreSQL must not be referenced by bare tag (postgres:18.4)');
  else ok('no bare postgres:18.4 tag reference');

  // ---- no model network config ----
  const modelHosts = ['deepseek', 'openai', 'anthropic', 'moonshot', 'openrouter', 'googleapis'];
  const hit = modelHosts.find((h) => text.toLowerCase().includes(h));
  if (hit) fail(`workflow contains model-endpoint material (${hit})`);
  else ok('workflow contains no remote-model network configuration');

  return { name: 'workflow', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'workflow', run);
