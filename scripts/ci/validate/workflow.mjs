// B002 workflow validator: the public .github/workflows/ci.yml must be the
// durable `AIPT M0 CI` workflow — secret-free, full-SHA action pins agreed
// with the frozen action lock, digest-pinned containers, Linux-only, the
// four required jobs, and the toolchain matrix (ubuntu-24.04 +
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
// total in the toolchain job and never in the other required jobs; retained
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
//
// 6B (AIPT-M0-B003 iteration 6b): the independent `storage-postgres` job is
// required alongside the three retained baseline jobs — the jobs mapping must
// contain EXACTLY those four jobs (exhaustive NORMALIZED key enumeration:
// plain, quoted and spaced job-key spellings all count, so a quoted-key extra
// job or a duplicate key can never hide), each unconditional and
// failure-visible. The storage-postgres contract is bound to the real job and
// its real steps: exact runner (ubuntu-26.04 via a normalized exact-one
// runs-on check), zero needs: dependencies (normalized keys), exact action
// inventory (checkout + setup-go with exact with: inputs, no new action
// repository, normalized quoted/plain uses parsing in both the global
// pin/lock checks and the per-step inventories), the ephemeral PostgreSQL
// 18.4 container started from the exact multi-arch digest by EXACTLY ONE
// approved docker run and published ONLY on the loopback interface
// (comprehensive -p / -p= / --publish / --publish= rejection), the 18.4
// readiness/server-version verification, the test-only loopback DSN with
// dbname=postgres (no credentials, no production endpoint) and the
// required-integration flag hard-enabled exactly once per integration
// command — both variables confined by exact raw occurrence to their two
// approved shell export lines, rejecting env: mappings, shadow/alternate
// assignments and production values anywhere in the workflow — the exact full
// `^TestPostgresIntegration` command, the exact race command for the
// concurrent-runner/same-stream pair, and the CI-only container cleanup —
// all as exact run blocks with unique anchors, plus distinct fail-closed
// checks for independence, runner, loopback-only publication, DSN boundary
// and flag count. The whole check is a pure in-memory function
// (checkWorkflowText), and run() re-runs it against focused source mutations
// to prove missing job, runner/digest/tag drift, non-loopback publication,
// missing required flag, DSN/production-boundary drift, removed/altered
// full/race commands, `|| true`/if:/continue-on-error masking, baseline
// job/gate drift, unauthorized action/input, quoted-key job/needs/runs-on/
// uses bypasses, duplicate runs-on, alternate publication syntaxes,
// env:-shadowed integration variables and alternate DSN assignments are all
// rejected while the exact candidate passes.
//
// 6B closed-world (second Codex review): storage-postgres is a COMPLETE
// fixed subset, not a needle list — the job mapping must be exactly one
// normalized name:, runs-on: and steps: (no extra/shadow/duplicate job-level
// key), the job must be exactly the nine ordered named steps below with
// step names parsed NORMALIZED (plain, quoted and spaced `- name:` spellings
// all start a real step, so a quoted-name shadow or duplicate step can never
// hide beside the canonical nine), every step must carry exactly the expected
// NORMALIZED per-step key multiset (name+run for run steps, name+uses+with
// for action steps — no env:, no extra/second run:, no missing uses/with),
// run parsing/counting is NORMALIZED (`run:`, `'run':`, `"run":` and `run :`
// all count as run forms, inline and block), the evidence-recording and
// Go-version verification run blocks are bound as exact gates like every
// other run block so EVERY run step is bound to exactly one exact block gate
// (no unbound run step can ride along), psql and postgres:// connection URIs
// appear only in the approved forms (one psql probe inside the verification
// block; URIs only inside the two approved test-only DSN export lines), and
// appended production psql, quoted duplicate run keys, quoted-name duplicate
// steps, extra job-level keys and step-level env: mappings are all proven
// rejected by focused mutation probes below.
//
// 6B root closed-world (third Codex review): the document root is a closed
// world too — the complete indent-0 mapping key multiset must be exactly one
// each of name, on, permissions, concurrency and jobs (NORMALIZED keys, so a
// quoted duplicate top-level key can never hide from the raw `^key:$` block
// regexes), with no extras, duplicates, missing keys or quoted shadows.
// Focused probes prove duplicate quoted top-level jobs/on/concurrency/name
// are all rejected for that root closed-world reason while the exact
// candidate passes.
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
const REQUIRED_JOBS = ['b000-retro', 'toolchain', 'supply-chain', 'storage-postgres'];

// ---- AIPT-M0-B003 iteration 6b: the ephemeral storage-postgres contract ----
// The independent storage-postgres job must run on exactly ubuntu-26.04, use
// only the frozen checkout/setup-go actions, start a fresh ephemeral
// PostgreSQL 18.4 container from the exact multi-arch digest published ONLY
// on the loopback interface, verify the server reports 18.4, feed the tests
// the exact loopback test-only DSN with dbname=postgres (no credentials, no
// production endpoint), hard-enable AIPT_REQUIRE_POSTGRES_INTEGRATION=1 on
// exactly the two integration commands, run the exact full
// ^TestPostgresIntegration suite and the exact race pair, and remove the
// container afterwards. Every needle is bound to the real job/steps (exact
// run blocks + anchors), never to whole-file substrings.
const STORAGE_POSTGRES_RUNNER = 'ubuntu-26.04';
const STORAGE_POSTGRES_CONTAINER = 'aipt-pg-18.4';
const STORAGE_POSTGRES_PORT_PUB = '127.0.0.1:5432:5432';
const STORAGE_TEST_DSN = 'postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable';
const STORAGE_REQUIRE_FLAG = 'export AIPT_REQUIRE_POSTGRES_INTEGRATION=1';
const STORAGE_FULL_TEST = "go test ./internal/storage/postgres -run '^TestPostgresIntegration' -count=1 -v";
const STORAGE_RACE_TEST = "go test -race ./internal/storage/postgres -run '^TestPostgresIntegration(MigrationConcurrentRunners|LedgerConcurrentSameStreamAppends)$' -count=1 -v";

// The closed-world storage-postgres job is exactly these nine ordered named
// steps. Step names are parsed NORMALIZED (`- name:`, `- 'name':`,
// `- "name":` and `- name :` all start a real step with that name), so a
// quoted-name shadow or duplicate step can never hide beside the canonical
// nine.
const STORAGE_POSTGRES_STEPS = [
  'Record runner environment (evidence)',
  'Checkout candidate (full history for integration sources)',
  'Setup exact Go 1.26.6',
  'Verify exact Go version',
  'Start ephemeral PostgreSQL 18.4 container (digest-pinned, loopback-only)',
  'Verify PostgreSQL 18.4 readiness and server version',
  'PostgreSQL integration tests (full ^TestPostgresIntegration suite, test-only DSN)',
  'PostgreSQL integration race coverage (MigrationConcurrentRunners | LedgerConcurrentSameStreamAppends)',
  'Remove ephemeral PostgreSQL container (CI-only cleanup, never production)',
];

// The exact NORMALIZED per-step key multiset for each of the nine steps
// (index-aligned with STORAGE_POSTGRES_STEPS): run steps are exactly
// { name, run }, action steps exactly { name, uses, with }. Any extra key
// (env:, if:, continue-on-error:, shell:, a second run:, ...) or any missing
// key fails the closed world.
const STORAGE_STEP_KEYS = [
  ['name', 'run'],
  ['name', 'uses', 'with'],
  ['name', 'uses', 'with'],
  ['name', 'run'],
  ['name', 'run'],
  ['name', 'run'],
  ['name', 'run'],
  ['name', 'run'],
  ['name', 'run'],
];

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
  'storage-postgres': [
    { repo: 'actions/checkout', with: { 'fetch-depth': '0' } },
    { repo: 'actions/setup-go', with: { 'go-version': TOOLCHAIN.go, cache: 'false' } },
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
  'storage-postgres': [
    {
      label: 'the runner environment evidence recording',
      anchor: 'echo "GITHUB_WORKFLOW=$GITHUB_WORKFLOW"',
      lines: [
        'echo "GITHUB_WORKFLOW=$GITHUB_WORKFLOW"',
        'echo "GITHUB_RUN_ID=$GITHUB_RUN_ID GITHUB_RUN_ATTEMPT=$GITHUB_RUN_ATTEMPT"',
        'echo "GITHUB_REF=$GITHUB_REF GITHUB_SHA=$GITHUB_SHA"',
        'echo "RUNNER_OS=$RUNNER_OS RUNNER_ARCH=$RUNNER_ARCH"',
        'echo "ImageOS=$ImageOS ImageVersion=$ImageVersion"',
        "grep -E '^(NAME|PRETTY_NAME|VERSION|VERSION_ID|ID)=' /etc/os-release || true",
        'uname -a',
      ],
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
      label: 'the ephemeral PostgreSQL 18.4 container start (digest-pinned, loopback-only)',
      anchor: `docker pull "postgres@${PG_MULTI_ARCH_DIGEST}"`,
      lines: [
        `docker pull "postgres@${PG_MULTI_ARCH_DIGEST}"`,
        `docker run --rm --name ${STORAGE_POSTGRES_CONTAINER} -e POSTGRES_HOST_AUTH_METHOD=trust -p ${STORAGE_POSTGRES_PORT_PUB} -d "postgres@${PG_MULTI_ARCH_DIGEST}"`,
      ],
    },
    {
      label: 'the PostgreSQL 18.4 readiness and server-version verification',
      anchor: `docker exec ${STORAGE_POSTGRES_CONTAINER} pg_isready -U postgres -d postgres`,
      lines: [
        'for i in $(seq 1 60); do',
        `if docker exec ${STORAGE_POSTGRES_CONTAINER} pg_isready -U postgres -d postgres >/dev/null 2>&1; then`,
        'break',
        'fi',
        'sleep 1',
        'done',
        `docker exec ${STORAGE_POSTGRES_CONTAINER} pg_isready -U postgres -d postgres`,
        `PG_VERSION="$(docker exec ${STORAGE_POSTGRES_CONTAINER} postgres --version)"`,
        'echo "postgres --version => ${PG_VERSION}"',
        'case "${PG_VERSION}" in',
        `"postgres (PostgreSQL) ${TOOLCHAIN.postgresql}"*) ;;`,
        '*) echo "unexpected postgres version: ${PG_VERSION}"; exit 1 ;;',
        'esac',
        `SERVER_VERSION="$(docker exec ${STORAGE_POSTGRES_CONTAINER} psql -U postgres -d postgres -tAc 'SHOW server_version')"`,
        'echo "server_version => ${SERVER_VERSION}"',
        'case "${SERVER_VERSION}" in',
        `"${TOOLCHAIN.postgresql}"*) ;;`,
        '*) echo "unexpected server_version: ${SERVER_VERSION}"; exit 1 ;;',
        'esac',
      ],
    },
    {
      label: 'the full PostgreSQL integration suite command (test-only DSN, required flag)',
      anchor: STORAGE_FULL_TEST,
      lines: [
        `export AIPT_POSTGRES_DSN="${STORAGE_TEST_DSN}"`,
        STORAGE_REQUIRE_FLAG,
        STORAGE_FULL_TEST,
      ],
    },
    {
      label: 'the PostgreSQL integration race coverage command (concurrent runners + same-stream appends)',
      anchor: STORAGE_RACE_TEST,
      lines: [
        `export AIPT_POSTGRES_DSN="${STORAGE_TEST_DSN}"`,
        STORAGE_REQUIRE_FLAG,
        STORAGE_RACE_TEST,
      ],
    },
    {
      label: 'the ephemeral container cleanup (CI-only, never production)',
      anchor: `docker rm -f ${STORAGE_POSTGRES_CONTAINER}`,
      lines: [
        `if docker inspect ${STORAGE_POSTGRES_CONTAINER} >/dev/null 2>&1; then`,
        `docker rm -f ${STORAGE_POSTGRES_CONTAINER}`,
        'fi',
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

// Normalized mapping entry at exactly `keyIndent`: returns the normalized
// (unquoted) key plus the raw value part after the colon (trailing comment
// and surrounding quotes NOT stripped — scalarValue does that per use), or
// null when the line is not such an entry. `uses:`, `'uses':`, `"uses":`
// and `uses :` all normalize to the same entry.
function mappingEntry(line, keyIndent) {
  const key = mappingKey(line, keyIndent);
  if (key === null) return null;
  const m = new RegExp(`^ {${keyIndent}}(?:'[^']*'|"[^"]*"|[^\\s:'"]+)\\s*:\\s*(.*)$`).exec(line);
  return { key, rawValue: m ? m[1].trim() : '' };
}

// Split a uses: value into the pinned ref token and the trailing tag-comment
// token (`actions/checkout@<sha> # v7.0.1` -> { raw, tagComment: 'v7.0.1' }).
// One pair of surrounding quotes is stripped before the split.
function parseUsesValue(v) {
  let s = v.trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    s = s.slice(1, -1).trim();
  }
  const hash = s.indexOf(' #');
  const core = (hash >= 0 ? s.slice(0, hash) : s).trim();
  const tag = hash >= 0 ? s.slice(hash + 2).trim().split(/\s+/)[0] : '';
  if (!core) return null;
  return { raw: core, tagComment: tag || null };
}

// Every docker port-publication syntax a run line may carry: `-p X`, `-pX`,
// `-p=X`, `--publish X` and `--publish=X`. The loopback-only publication
// check rejects anything besides the exact approved bind.
function publicationValues(line) {
  const pubs = [];
  const re = /(?:^|\s)(--publish|-p)(?:=|\s+)?(\S+)/g;
  let m;
  while ((m = re.exec(line)) !== null) pubs.push(m[2]);
  return pubs;
}

// Index of a block-style `key:` line at exactly `keyIndent` spaces whose
// NORMALIZED key equals `name` (plain, quoted or spaced spellings all
// match), searching `lines` in [from, to), or -1.
function findNormalizedKeyLineIn(lines, name, keyIndent, from = 0, to = lines.length) {
  for (let i = from; i < to; i += 1) {
    if (mappingKey(lines[i], keyIndent) === name) return i;
  }
  return -1;
}

// Extract one required job's body from the parsed jobs block. `bodyStart` is
// the absolute index of the first body line, so every body line can be
// reported with its real 1-based file line number. The key lookup is
// normalized (quoted/plain), matching the exhaustive job-key enumeration.
function jobBlock(jobsBlock, name) {
  if (!jobsBlock) return null;
  const keyIdx = findNormalizedKeyLineIn(jobsBlock.lines, name, 2, 0, jobsBlock.lines.length);
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
// step starts at a real six-space `- ` line whose first mapping key is the
// NORMALIZED `name` key (`- name:`, `- 'name':`, `- "name":` and `- name :`
// all start a real step with that name) and ends before the next six-space
// step. Any other six-space `- ` item (`- run:`, `- uses:`, `- env:`, ...)
// is a disguised shorthand step: it is recorded in `badStarts` (and never
// analyzed as an empty step) so the validator fails on it explicitly instead
// of silently passing it. Quoted-name steps are REAL steps here — they can
// never hide beside the canonical nine; the closed-world exact-name checks
// reject them when they are not the exact ordered nine.
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
      const m = /^ {6}-\s*(?:'([^']*)'|"([^"]*)"|([^\s:'"]+))\s*:\s*(.*)$/.exec(line);
      if (m && (m[1] ?? m[2] ?? m[3]) === 'name') {
        current = {
          name: scalarValue(m[4]),
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
// narrow scalar helper; comments ignored). A `with:` collection ends at the
// first subsequent real non-comment line at indent <= 8, so a sibling
// `env:`/`run:`/`uses:`/`if:`/other step-level mapping can never contribute
// indent-10 entries to withEntries, and the number of real step-level `with:`
// mappings is tracked so split/duplicate `with:` blocks fail even when their
// union equals the expected inputs. Run parsing is NORMALIZED: `run:`,
// `'run':`, `"run":` and `run :` all count as real run forms (inline and
// block), so a quoted or spaced run-key spelling can never hide a run from
// the exact block gates, anchor counting or the closed-world per-step key
// multiset. `stepKeys` is the NORMALIZED multiset of every real step-level
// key, starting with the step's own start-line key. This is not a general
// YAML parser and never claims to be one.
function analyzeStep(step) {
  const runs = [];
  const conditions = { if: [], continueOnError: [], shell: [] };
  const uses = [];
  const withEntries = [];
  const stepKeys = [];
  let inWith = false;
  let withMappings = 0;
  const startKey = /^ {6}-\s*(?:'([^']*)'|"([^"]*)"|([^\s:'"]+))\s*:/.exec(step.lines[0]);
  if (startKey) stepKeys.push(startKey[1] ?? startKey[2] ?? startKey[3]);
  for (let i = 0; i < step.lines.length; i += 1) {
    const line = step.lines[i];
    const lineNo = step.lineNo + i;
    // The active `with:` mapping ends at the first subsequent real
    // non-comment line at indent <= 8 (comments/blanks never end it).
    if (inWith && !isBlankOrComment(line) && indent(line) <= 8) {
      inWith = false;
    }
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
      stepKeys.push('run');
      i = j - 1;
      continue;
    }
    const inlineRun = /^ {8}run:\s*(.+?)\s*$/.exec(line);
    if (inlineRun) {
      runs.push({ kind: 'inline', command: inlineRun[1].trim(), lineNo });
      stepKeys.push('run');
      continue;
    }
    const key = mappingKey(line, 8);
    if (key === 'run') {
      // NORMALIZED run-key spelling (`'run':`, `"run":`, `run :`): a real
      // run form — parsed (inline or block) and counted like any other run,
      // so a quoted duplicate run can never hide from the exact block gates,
      // anchor counting or the per-step key multiset.
      const e = mappingEntry(line, 8);
      const raw = (e?.rawValue ?? '').trim();
      if (/^[|>][-+]?\s*(?:#.*)?$/.test(raw)) {
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
      } else if (raw) {
        runs.push({ kind: 'inline', command: scalarValue(raw), lineNo });
      }
      stepKeys.push('run');
      continue;
    }
    if (key === 'uses') {
      // Normalized: `uses:`, `'uses':`, `"uses":` and `uses :` all parse, so
      // a quoted-key uses: step can never hide from the per-step inventory.
      const e = mappingEntry(line, 8);
      if (e) uses.push({ value: scalarValue(e.rawValue), lineNo });
      stepKeys.push('uses');
      continue;
    }
    if (key === 'with') {
      inWith = true;
      withMappings += 1;
      stepKeys.push('with');
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
      stepKeys.push(key);
      if (key === 'if') conditions.if.push({ value, lineNo });
      else if (key === 'continue-on-error') conditions.continueOnError.push({ value, lineNo });
      else conditions.shell.push({ value, lineNo });
    } else if (key) {
      // Any other real step-level key (`env:`, `timeout-minutes:`, ...) is
      // collected into the normalized key multiset too, so the closed-world
      // per-step key multiset rejects mappings no needle check ever looked
      // at (a step-level env: can never ride unnoticed beside name+run).
      stepKeys.push(key);
    }
  }
  return { ...step, runs, conditions, uses, withEntries, withMappings, stepKeys };
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

// Pure fail-closed check over in-memory workflow text plus the frozen action
// lock. Everything the live candidate must satisfy lives here; the 6b
// mutation regressions in run() exercise exactly this function, so a drifted
// or mutated workflow is proven rejected through the same code path the real
// file is checked with.
function checkWorkflowText(text, lock) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const lines = text.split('\n');

  // ---- durable workflow identity ----
  if (/^name:\s*AIPT M0 CI\s*$/m.test(text)) ok(`durable workflow name: ${DURABLE_WORKFLOW_NAME}`);
  else fail(`workflow name must be exactly ${JSON.stringify(DURABLE_WORKFLOW_NAME)}`);
  if (text.includes(STALE_WORKFLOW_NAME)) fail(`stale workflow name ${STALE_WORKFLOW_NAME} still present`);
  else ok('no stale B001 workflow name');

  // ---- closed-world root mapping: exactly one each of name, on,
  // permissions, concurrency and jobs at indent 0 ----
  // The complete indent-0 mapping key multiset of the document (NORMALIZED:
  // plain, quoted and spaced spellings all count) must be exactly one each of
  // `name`, `on`, `permissions`, `concurrency` and `jobs` — no extras,
  // duplicates, missing keys or quoted shadows can hide a second top-level
  // mapping that the raw `^key:$` block regexes would never see.
  const rootKeys = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (isBlankOrComment(lines[i])) continue;
    const rk = mappingKey(lines[i], 0);
    if (rk) rootKeys.push({ key: rk, lineNo: i + 1 });
  }
  const rootCounts = {};
  for (const e of rootKeys) rootCounts[e.key] = (rootCounts[e.key] ?? 0) + 1;
  const expectedRoot = ['name', 'on', 'permissions', 'concurrency', 'jobs'];
  const rootClosed =
    rootKeys.length === expectedRoot.length &&
    expectedRoot.every((k) => rootCounts[k] === 1);
  if (rootClosed) {
    ok(`closed-world root mapping is exactly one each of ${expectedRoot.join(', ')} (no extras, duplicates, missing keys or quoted shadows)`);
  } else {
    const unexpected = Object.keys(rootCounts).filter((k) => !expectedRoot.includes(k));
    const wrongCounts = expectedRoot.filter((k) => rootCounts[k] !== 1);
    fail(`closed-world root mapping must contain exactly one each of name, on, permissions, concurrency and jobs (normalized indent-0 keys, no extras/duplicates/missing/quoted shadows); parsed ${JSON.stringify(rootKeys.map((e) => e.key))}${unexpected.length ? `; unexpected top-level key(s): ${unexpected.join(', ')}` : ''}${wrongCounts.length ? `; wrong count(s): ${wrongCounts.map((k) => `${k}=${rootCounts[k] ?? 0}`).join(', ')}` : ''}`);
  }

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
  // Normalized line-by-line extraction: `uses:`, `'uses':`, `"uses":` and
  // `uses :` all count, so a quoted-key uses: line can never bypass the
  // global pin/lock checks by hiding outside the raw `uses:` regex.
  const uses = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (isBlankOrComment(lines[i])) continue;
    const e = mappingEntry(lines[i], indent(lines[i]));
    if (!e || e.key !== 'uses') continue;
    const parsed = parseUsesValue(e.rawValue);
    if (parsed) uses.push({ raw: parsed.raw, tagComment: parsed.tagComment, lineNo: i + 1 });
  }
  if (uses.length === 0) fail('no uses: entries found');
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
  // Exhaustive normalized job-key enumeration: every indent-2 mapping key of
  // the real jobs block counts (plain, quoted or spaced spellings), so a
  // quoted-key extra job can never hide from the exactly-four check and a
  // duplicate key (plain + quoted) is still enumerated twice.
  const jobNames = [];
  for (const l of jobsBlock?.lines ?? []) {
    if (isBlankOrComment(l)) continue;
    if (indent(l) !== 2) continue;
    const jk = mappingKey(l, 2);
    if (jk) jobNames.push(jk);
  }
  for (const required of REQUIRED_JOBS) {
    if (jobNames.includes(required)) ok(`required job present: ${required}`);
    else fail(`required job missing: ${required}`);
  }
  // 6b: the jobs mapping must contain EXACTLY the four required jobs — no
  // extra job can ride along beside the three retained baseline jobs and the
  // new storage-postgres job.
  const expectedJobSet = [...REQUIRED_JOBS].sort();
  const actualJobSet = [...jobNames].sort();
  if (jobNames.length === REQUIRED_JOBS.length && actualJobSet.every((j, i) => j === expectedJobSet[i])) {
    ok(`jobs mapping contains exactly the four required jobs: ${REQUIRED_JOBS.join(', ')}`);
  } else {
    fail(`jobs mapping must contain exactly the four required jobs ${REQUIRED_JOBS.join(', ')}; parsed ${JSON.stringify(jobNames)}`);
  }
  // GitHub-hosted Linux only: every runs-on value (plain or quoted key) must
  // be a Linux runner, never macos/windows.
  const nonLinuxRunners = [];
  for (let i = 0; i < lines.length; i += 1) {
    if (isBlankOrComment(lines[i])) continue;
    const e = mappingEntry(lines[i], indent(lines[i]));
    if (!e || e.key !== 'runs-on') continue;
    const v = scalarValue(e.rawValue).toLowerCase();
    if (v.startsWith('macos') || v.startsWith('windows')) {
      nonLinuxRunners.push({ lineNo: i + 1, value: v });
    }
  }
  if (nonLinuxRunners.length === 0) ok('GitHub-hosted Linux only');
  else fail(`CI must be GitHub-hosted Linux only (non-Linux runs-on at line ${nonLinuxRunners[0].lineNo}: ${nonLinuxRunners[0].value})`);

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
          step.withMappings === 1 &&
          !withDup &&
          expectedKeys.length === actualKeys.length &&
          expectedKeys.every((k2) => actualWith[k2] === expected.with[k2]);
        if (!usesOk || !inputsOk) {
          inventoryOk = false;
          const label = step.name ? JSON.stringify(step.name) : `step ${actionSteps[k].index + 1}`;
          const withDesc =
            step.withMappings !== 1 ? ` across ${step.withMappings} with: mapping(s)` : '';
          fail(`${required} job action step ${k + 1} (${label}) must use ${expectedUses} with exactly ${JSON.stringify(expected.with)}; found uses ${JSON.stringify(usesValues)} with inputs ${JSON.stringify(actualWith)}${withDesc}`);
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

  // ---- storage-postgres job: ephemeral PostgreSQL 18.4 integration
  // contract ----
  // The job must be independent, run on exactly ubuntu-26.04, publish the
  // container only on the loopback interface, use only the loopback test-only
  // DSN with dbname=postgres (no credentials, no production endpoint), and
  // hard-enable AIPT_REQUIRE_POSTGRES_INTEGRATION=1 exactly once per
  // integration command. The exact container/version/full/race/cleanup run
  // blocks are bound by BLOCK_GATES above; these additional checks bind the
  // runner, independence, loopback-only publication, DSN boundary and
  // required-flag evidence to the real job with distinct fail-closed
  // messages.
  const storageJob = jobs['storage-postgres'];
  if (!storageJob) {
    fail('storage-postgres job block not found');
  } else {
    const storageAnalyzed = analyzedJobs['storage-postgres'] ?? [];

    // Independence: zero `needs:` entries with a NORMALIZED key — `needs:`,
    // `'needs':`, `"needs":` and `needs :` all count, so a quoted-key
    // dependency can never hide from the check.
    const needsEntries = [];
    for (let i = 0; i < storageJob.body.length; i += 1) {
      if (isBlankOrComment(storageJob.body[i])) continue;
      if (mappingKey(storageJob.body[i], 4) === 'needs') {
        needsEntries.push({ lineNo: storageJob.bodyStart + i + 1, raw: storageJob.body[i].trim() });
      }
    }
    if (needsEntries.length === 0) {
      ok('storage-postgres job is independent (no needs: dependency, plain or quoted key)');
    } else {
      fail(`storage-postgres job must be independent (no needs: dependency on other jobs); found ${needsEntries.length} needs: entr${needsEntries.length === 1 ? 'y' : 'ies'} ${needsEntries.map((n) => `line ${n.lineNo}: ${JSON.stringify(n.raw)}`).join(', ')}`);
    }

    // Exact-one runs-on: exactly one real `runs-on:` entry with a NORMALIZED
    // key, whose value (plain or quoted) is exactly ubuntu-26.04. A quoted
    // key, a duplicate entry and a drifted runner all fail.
    const runsOnEntries = [];
    for (let i = 0; i < storageJob.body.length; i += 1) {
      if (isBlankOrComment(storageJob.body[i])) continue;
      const re2 = mappingEntry(storageJob.body[i], 4);
      if (re2 && re2.key === 'runs-on') {
        runsOnEntries.push({
          value: scalarValue(re2.rawValue),
          lineNo: storageJob.bodyStart + i + 1,
          raw: storageJob.body[i].trim(),
        });
      }
    }
    if (runsOnEntries.length !== 1) {
      fail(`storage-postgres job must carry exactly one real runs-on: entry (plain or quoted key) with value ${STORAGE_POSTGRES_RUNNER}; found ${runsOnEntries.length}: ${JSON.stringify(runsOnEntries.map((r) => r.raw))}`);
    } else if (runsOnEntries[0].value !== STORAGE_POSTGRES_RUNNER) {
      fail(`storage-postgres job must run on exactly ${STORAGE_POSTGRES_RUNNER}; parsed ${JSON.stringify(runsOnEntries.map((r) => r.value))}`);
    } else {
      ok(`storage-postgres job runs on exactly ${STORAGE_POSTGRES_RUNNER}`);
    }

    // Exactly one approved docker run, and loopback-only publication: every
    // publication the job carries — `-p X`, `-pX`, `-p=X`, `--publish X` or
    // `--publish=X` — must be exactly the loopback bind (127.0.0.1:5432:5432),
    // so a second docker run or a 0.0.0.0 / bare-port publication in any
    // alternate syntax is rejected.
    const dockerRuns = [];
    const publications = [];
    for (const s of storageAnalyzed) {
      for (const r of s.runs) {
        const runLines = r.kind === 'inline' ? [r.command] : r.lines;
        for (const l of runLines) {
          if (/\bdocker run\b/.test(l)) dockerRuns.push(l);
          publications.push(...publicationValues(l));
        }
      }
    }
    if (dockerRuns.length === 1) {
      ok('storage-postgres runs exactly one docker run (the approved digest-pinned ephemeral container start)');
    } else {
      fail(`storage-postgres must run exactly one docker run (the approved digest-pinned ephemeral container start); found ${dockerRuns.length} docker run occurrence(s) across run forms`);
    }
    if (publications.length === 1 && publications[0] === STORAGE_POSTGRES_PORT_PUB) {
      ok(`storage-postgres publishes the PostgreSQL container only on the loopback interface (${STORAGE_POSTGRES_PORT_PUB})`);
    } else {
      fail(`storage-postgres must publish the PostgreSQL container only on the loopback interface (${STORAGE_POSTGRES_PORT_PUB}); parsed ${JSON.stringify(publications)}`);
    }

    // Exact raw occurrence / assignment confinement: AIPT_POSTGRES_DSN and
    // AIPT_REQUIRE_POSTGRES_INTEGRATION may appear ONLY inside the approved
    // export lines, each exactly twice (once per integration command). env:
    // mappings (job- or step-level), shadow/alternate assignments and
    // production values anywhere in the workflow — including other jobs —
    // are rejected. Comments are inert and never satisfy the boundary.
    const dsnExportLine = `export AIPT_POSTGRES_DSN="${STORAGE_TEST_DSN}"`;
    let dsnExact = 0;
    let flagExact = 0;
    const dsnOther = [];
    const flagOther = [];
    for (let i = 0; i < lines.length; i += 1) {
      if (isBlankOrComment(lines[i])) continue;
      const t = lines[i].trim();
      if (t === dsnExportLine) dsnExact += 1;
      else if (t.includes('AIPT_POSTGRES_DSN')) dsnOther.push({ lineNo: i + 1, line: t });
      if (t === STORAGE_REQUIRE_FLAG) flagExact += 1;
      else if (t.includes('AIPT_REQUIRE_POSTGRES_INTEGRATION')) flagOther.push({ lineNo: i + 1, line: t });
    }
    if (dsnOther.length === 0 && dsnExact === 2) {
      ok(`storage-postgres confines AIPT_POSTGRES_DSN to exactly the two approved test-only DSN export lines (${JSON.stringify(STORAGE_TEST_DSN)}: dbname=postgres, loopback, no credentials, no production endpoint)`);
    } else {
      fail(`storage-postgres must confine AIPT_POSTGRES_DSN to exactly two occurrences of the approved test-only DSN export line ${JSON.stringify(dsnExportLine)} (dbname=postgres, no credentials, no production endpoint); found ${dsnExact} approved + ${dsnOther.length} other occurrence(s)${dsnOther.length ? ` (e.g. line ${dsnOther[0].lineNo}: ${dsnOther[0].line})` : ''}`);
    }
    if (flagOther.length === 0 && flagExact === 2) {
      ok('storage-postgres hard-enables AIPT_REQUIRE_POSTGRES_INTEGRATION=1 exactly twice via the approved export lines (once per integration command)');
    } else {
      fail(`storage-postgres must hard-enable AIPT_REQUIRE_POSTGRES_INTEGRATION=1 exactly twice via the approved export line ${JSON.stringify(STORAGE_REQUIRE_FLAG)}; found ${flagExact} approved + ${flagOther.length} other occurrence(s)${flagOther.length ? ` (e.g. line ${flagOther[0].lineNo}: ${flagOther[0].line})` : ''}`);
    }

    // ---- closed world: the job mapping is exactly one normalized name:,
    // runs-on: and steps: (no extra/shadow/duplicate job-level key) ----
    // Every real indent-4 mapping key of the job body counts with a
    // NORMALIZED key (plain, quoted and spaced spellings), so a quoted or
    // duplicate name/runs-on/steps, an extra timeout-minutes:/env:/strategy:/
    // needs:/defaults:/if: job-level key, or any other shadow mapping fails.
    const jobLevelKeys = [];
    for (let i = 0; i < storageJob.body.length; i += 1) {
      if (isBlankOrComment(storageJob.body[i])) continue;
      const jk = mappingKey(storageJob.body[i], 4);
      if (jk) jobLevelKeys.push({ key: jk, lineNo: storageJob.bodyStart + i + 1 });
    }
    const jobLevelCounts = {};
    for (const e of jobLevelKeys) jobLevelCounts[e.key] = (jobLevelCounts[e.key] ?? 0) + 1;
    const jobLevelClosed =
      jobLevelKeys.length === 3 &&
      jobLevelCounts.name === 1 &&
      jobLevelCounts['runs-on'] === 1 &&
      jobLevelCounts.steps === 1;
    if (jobLevelClosed) {
      ok('storage-postgres job mapping is exactly name: + runs-on: + steps: (one each, normalized, no extra/shadow/duplicate job-level key)');
    } else {
      fail(`storage-postgres job mapping must contain exactly one name:, one runs-on: and one steps: (normalized keys) and no other job-level key; parsed ${JSON.stringify(jobLevelKeys.map((e) => e.key))}`);
    }

    // ---- closed world: exactly the nine ordered named steps ----
    // Step names are parsed NORMALIZED (`- name:`, `- 'name':`, `- "name":`,
    // `- name :` all start a real step), so a quoted-name shadow or a
    // duplicate step can never hide beside the canonical nine: the job must
    // be exactly this ordered list, no more, no less.
    const storageStepNames = storageAnalyzed.map((s) => s.name);
    const nineOrdered =
      storageAnalyzed.length === STORAGE_POSTGRES_STEPS.length &&
      storageStepNames.every((n, i) => n === STORAGE_POSTGRES_STEPS[i]);
    if (nineOrdered) {
      ok(`storage-postgres job contains exactly the nine ordered named steps (${STORAGE_POSTGRES_STEPS.length}): ${STORAGE_POSTGRES_STEPS.join(' | ')}`);
    } else {
      fail(`storage-postgres job must contain exactly the nine ordered named steps ${JSON.stringify(STORAGE_POSTGRES_STEPS)}; parsed ${JSON.stringify(storageStepNames)}`);
    }

    // ---- closed world: exact normalized per-step key multisets ----
    // Every one of the nine fixed steps must carry exactly its expected
    // normalized step-level key multiset (name+run for run steps,
    // name+uses+with for action steps). An env: mapping, a second run: key
    // (plain or quoted), a missing uses:/with:, an if:/continue-on-error:/
    // shell: override or any other extra/missing step key fails.
    let stepKeysClosed = true;
    const stepKeysCheckCount = Math.min(storageAnalyzed.length, STORAGE_POSTGRES_STEPS.length);
    for (let i = 0; i < stepKeysCheckCount; i += 1) {
      const actual = [...storageAnalyzed[i].stepKeys].sort();
      const expected = [...STORAGE_STEP_KEYS[i]].sort();
      if (JSON.stringify(actual) !== JSON.stringify(expected)) {
        stepKeysClosed = false;
        fail(`storage-postgres step ${i + 1} (${JSON.stringify(storageAnalyzed[i].name)}) must carry exactly the expected step key multiset ${JSON.stringify(STORAGE_STEP_KEYS[i])}; parsed ${JSON.stringify(actual)}`);
      }
    }
    if (stepKeysClosed && storageAnalyzed.length === STORAGE_POSTGRES_STEPS.length) {
      ok('every storage-postgres step carries exactly its expected normalized key multiset (no env:, extra run:, missing uses/with or shadow keys)');
    }

    // ---- closed world: production boundary — psql and connection URIs ----
    // psql may appear only once (the SHOW server_version probe inside the
    // approved readiness/version block) and every postgres:// URI must be
    // exactly the approved test-only DSN export line — an appended
    // production psql step or a credential-bearing connection string is
    // rejected.
    const psqlLines = [];
    const uriLines = [];
    for (const s of storageAnalyzed) {
      for (const r of s.runs) {
        const runLines = r.kind === 'inline' ? [r.command] : r.lines;
        for (const l of runLines) {
          if (/\bpsql\b/.test(l)) psqlLines.push(l);
          if (l.includes('postgres://')) uriLines.push(l);
        }
      }
    }
    if (psqlLines.length === 1) {
      ok('storage-postgres runs psql only once (the SHOW server_version probe inside the approved readiness/server-version block)');
    } else {
      fail(`storage-postgres must run psql only inside the approved readiness/server-version verification block (exactly one occurrence); found ${psqlLines.length} psql occurrence(s)`);
    }
    const badUriLines = uriLines.filter((l) => l !== dsnExportLine);
    if (badUriLines.length === 0) {
      ok('storage-postgres connection URIs appear only inside the approved test-only DSN export lines (no production/credential-bearing URI)');
    } else {
      fail(`storage-postgres must not carry connection URIs outside the approved test-only DSN export line ${JSON.stringify(dsnExportLine)}; found ${JSON.stringify(badUriLines)}`);
    }

    // ---- closed world: every run step is bound to exactly one exact block
    // gate ----
    // The union of steps covered by the exact block gates must equal the set
    // of steps carrying any run form, and each covered step must carry
    // exactly one run form (its block). A new or mutated run step can never
    // ride unbound beside the nine fixed steps.
    let gateCoverFailures = 0;
    const gateCoveredSteps = new Set();
    for (const gate of BLOCK_GATES['storage-postgres'] ?? []) {
      const hits = exactBlockGateHits(storageAnalyzed, gate.lines);
      if (hits.length === 1) gateCoveredSteps.add(hits[0].stepIndex);
      else gateCoverFailures += 1;
    }
    if (gateCoverFailures === 0) {
      const runStepIndices = [];
      for (let i = 0; i < storageAnalyzed.length; i += 1) {
        if (storageAnalyzed[i].runs.length > 0) runStepIndices.push(i);
      }
      const bound = [...gateCoveredSteps].sort((a, b) => a - b);
      const allBoundSingleRun =
        JSON.stringify(bound) === JSON.stringify(runStepIndices) &&
        runStepIndices.every((i) => storageAnalyzed[i].runs.length === 1);
      if (allBoundSingleRun) {
        ok('every storage-postgres run step is bound to exactly one exact block gate (evidence, Go version, container start, version check, full/race tests, cleanup — no unbound or shadowed run evidence)');
      } else {
        const unbound = runStepIndices.filter((i) => !gateCoveredSteps.has(i));
        const extraBound = [...gateCoveredSteps].filter((i) => !runStepIndices.includes(i));
        fail(`every storage-postgres run step must be bound to exactly one exact block gate and carry exactly one run form; unbound run steps: ${JSON.stringify(unbound)}${extraBound.length ? `, gate-covered steps without a run: ${JSON.stringify(extraBound)}` : ''}`);
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
    for (const other of ['b000-retro', 'supply-chain', 'storage-postgres']) {
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

  return { result: pass ? 'PASS' : 'FAIL', details };
}

// ---- 6b focused mutation regressions (in-memory, same architecture) ----
// Every probe mutates the real workflow text and re-runs the exact same
// checkWorkflowText the live file is checked with, proving the
// storage-postgres contract and every retained B000/B001/B002 invariant are
// enforced fail-closed: missing job, runner drift, digest/tag drift,
// non-loopback publication, missing required-integration flag, DSN/
// production-boundary drift, removed/altered full or race command, `|| true`
// / if: / continue-on-error masking, baseline job/gate drift, unauthorized
// action/input, and — from the 6b review — quoted-key job/needs/runs-on/
// uses bypasses, duplicate runs-on, alternate -p= / --publish= publication
// syntaxes, env:-shadowed integration variables and alternate DSN
// assignments are all rejected while the exact candidate passes. From the
// second 6b review, the closed-world regressions prove appended production
// psql, a quoted duplicate run key, a quoted-name duplicate step, an extra
// job-level key and a step-level env: mapping are all rejected too.

// Remove one whole job (key line + body) from the workflow text.
function removeJobBlock(text, name) {
  const lines = text.split('\n');
  const keyIdx = findKeyLineIn(lines, name, 2, 0, lines.length);
  if (keyIdx < 0) return text;
  const body = blockAt(lines, keyIdx, 2);
  return [...lines.slice(0, keyIdx), ...lines.slice(body.end)].join('\n');
}

// Apply `mutate` to exactly one job's text (key line through body end) and
// reassemble the workflow, so a mutation can never bleed into another job.
function mutateJobText(text, name, mutate) {
  const lines = text.split('\n');
  const keyIdx = findKeyLineIn(lines, name, 2, 0, lines.length);
  if (keyIdx < 0) return text;
  const body = blockAt(lines, keyIdx, 2);
  const jobLines = lines.slice(keyIdx, body.end);
  const mutated = mutate(jobLines.join('\n'));
  return [...lines.slice(0, keyIdx), ...mutated.split('\n'), ...lines.slice(body.end)].join('\n');
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
  const lock = JSON.parse(fs.readFileSync(path.join(ctx.repo, 'tools/ci-actions.lock.json'), 'utf8'));

  // The exact candidate must PASS the same pure check the probes are run
  // against.
  const main = checkWorkflowText(text, lock);
  details.push(...main.details);
  if (main.result !== 'PASS') pass = false;

  const fullTestStepName =
    '      - name: PostgreSQL integration tests (full ^TestPostgresIntegration suite, test-only DSN)';
  const probes = [
    {
      label: 'storage-postgres job removed',
      reason: /required job missing: storage-postgres/,
      run: () => checkWorkflowText(removeJobBlock(text, 'storage-postgres'), lock),
    },
    {
      label: 'storage-postgres runner drifted (ubuntu-26.04 -> ubuntu-24.04)',
      reason: /storage-postgres job must run on exactly ubuntu-26\.04/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) => t.replace('runs-on: ubuntu-26.04', 'runs-on: ubuntu-24.04')),
          lock,
        ),
    },
    {
      label: 'storage-postgres container digest drifted',
      reason: /must keep the ephemeral PostgreSQL 18\.4 container start/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) => t.replace(PG_MULTI_ARCH_DIGEST, `sha256:${'0'.repeat(64)}`)),
          lock,
        ),
    },
    {
      label: 'storage-postgres container referenced by bare tag (postgres:18.4)',
      reason: /must keep the ephemeral PostgreSQL 18\.4 container start|must not be referenced by bare tag/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) => t.replaceAll(`"postgres@${PG_MULTI_ARCH_DIGEST}"`, 'postgres:18.4')),
          lock,
        ),
    },
    {
      label: 'storage-postgres container published on non-loopback (0.0.0.0)',
      reason: /must publish the PostgreSQL container only on the loopback interface/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) => t.replace(`-p ${STORAGE_POSTGRES_PORT_PUB}`, '-p 0.0.0.0:5432:5432')),
          lock,
        ),
    },
    {
      label: 'storage-postgres missing AIPT_REQUIRE_POSTGRES_INTEGRATION=1 flag',
      reason: /AIPT_REQUIRE_POSTGRES_INTEGRATION=1/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) => t.replaceAll(`${STORAGE_REQUIRE_FLAG}\n`, '')),
          lock,
        ),
    },
    {
      label: 'storage-postgres DSN drifted to a non-loopback production-style endpoint',
      reason: /test-only DSN/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            t.replaceAll(STORAGE_TEST_DSN, 'postgres://postgres@db.prod.internal:5432/ledger?sslmode=require'),
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres full integration command removed',
      reason: /must keep the full PostgreSQL integration suite command/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            t.replace(STORAGE_FULL_TEST, "go test ./internal/storage/postgres -run '^TestPostgresIntegration$' -count=1"),
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres full integration command altered (dropped -count=1)',
      reason: /must keep the full PostgreSQL integration suite command/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            t.replace(STORAGE_FULL_TEST, "go test ./internal/storage/postgres -run '^TestPostgresIntegration' -v"),
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres race coverage command removed',
      reason: /must keep the PostgreSQL integration race coverage command/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) => t.replace(STORAGE_RACE_TEST, 'go test -race ./internal/storage/postgres')),
          lock,
        ),
    },
    {
      label: 'storage-postgres full command masked with || true',
      reason: /must keep the full PostgreSQL integration suite command/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) => t.replace(STORAGE_FULL_TEST, `${STORAGE_FULL_TEST} || true`)),
          lock,
        ),
    },
    {
      label: 'storage-postgres integration step conditionally skipped (if: always())',
      reason: /must not be conditionally skipped/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) => t.replace(fullTestStepName, `${fullTestStepName}\n        if: always()`)),
          lock,
        ),
    },
    {
      label: 'storage-postgres integration step masks failures (continue-on-error: true)',
      reason: /must not mask failures/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            t.replace(fullTestStepName, `${fullTestStepName}\n        continue-on-error: true`),
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres integration step overrides the shell (shell: bash)',
      reason: /must not set a custom shell/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            t.replace(fullTestStepName, `${fullTestStepName}\n        shell: bash`),
          ),
          lock,
        ),
    },
    {
      label: 'baseline job removed (toolchain)',
      reason: /required job missing: toolchain/,
      run: () => checkWorkflowText(removeJobBlock(text, 'toolchain'), lock),
    },
    {
      label: 'baseline aggregate gate removed (pnpm run check from toolchain)',
      reason: /must run `pnpm run check` exactly once/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'toolchain', (t) => t.replace('        run: pnpm run check\n', '        run: echo pnpm run check\n')),
          lock,
        ),
    },
    {
      label: 'baseline retained gate removed (go vet from toolchain)',
      reason: /must run `go vet \.\/\.\.\.` exactly once/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'toolchain', (t) => t.replace('        run: go vet ./...', '        run: echo go vet ./...')),
          lock,
        ),
    },
    {
      label: 'unauthorized action added to storage-postgres',
      reason: /must have exactly 2 uses: step\(s\)/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            `${t}\n      - name: Upload artifact\n        uses: actions/upload-artifact@1234567890123456789012345678901234567890`,
          ),
          lock,
        ),
    },
    {
      label: 'unauthorized with: input on storage-postgres setup-go',
      reason: /action step 2/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            t.replace(
              '          go-version: 1.26.6\n          cache: false',
              '          go-version: 1.26.6\n          cache: false\n          go-version-file: go.mod',
            ),
          ),
          lock,
        ),
    },
    // ---- AIPT-M0-B003 iteration 6b review: the five demonstrated passing
    // bypasses plus quoted/duplicate runs-on and alternate publication
    // syntaxes must each FAIL for their specific reason ----
    {
      label: 'storage-postgres hidden extra job with quoted key',
      reason: /must contain exactly the four required jobs/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            `${t}\n  "sneak-job":\n    runs-on: ubuntu-26.04\n    steps:\n      - name: Sneak step\n        run: echo sneaky`,
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres hidden needs: dependency (quoted key)',
      reason: /storage-postgres job must be independent/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            t.replace('    runs-on: ubuntu-26.04', "    runs-on: ubuntu-26.04\n    'needs': toolchain"),
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres duplicate runs-on (plain + quoted key, drifted value)',
      reason: /must carry exactly one real runs-on/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            t.replace('    runs-on: ubuntu-26.04', "    runs-on: ubuntu-26.04\n    'runs-on': ubuntu-24.04"),
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres quoted runs-on key with drifted runner',
      reason: /storage-postgres job must run on exactly ubuntu-26\.04/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            t.replace('    runs-on: ubuntu-26.04', "    'runs-on': ubuntu-24.04"),
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres quoted uses: step (invisible action bypass)',
      reason: /must have exactly 2 uses: step\(s\)|has no entry in tools\/ci-actions\.lock\.json/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            `${t}\n      - name: Sneak upload\n        "uses": actions/upload-artifact@1234567890123456789012345678901234567890`,
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres second docker run with --publish=0.0.0.0 (alternate publication syntax)',
      reason: /exactly one docker run|only on the loopback interface/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            `${t}\n      - name: Sneak publish\n        run: docker run --rm -d --publish=0.0.0.0:5432:5432 "postgres@${PG_MULTI_ARCH_DIGEST}"`,
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres second docker run with -p=0.0.0.0 (alternate publication syntax)',
      reason: /exactly one docker run|only on the loopback interface/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            `${t}\n      - name: Sneak publish\n        run: docker run --rm -d -p=0.0.0.0:5432:5432 "postgres@${PG_MULTI_ARCH_DIGEST}"`,
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres step-level env: shadows AIPT_REQUIRE_POSTGRES_INTEGRATION',
      reason: /AIPT_REQUIRE_POSTGRES_INTEGRATION=1/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            t.replace(fullTestStepName, `${fullTestStepName}\n        env:\n          AIPT_REQUIRE_POSTGRES_INTEGRATION: 0`),
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres job-level env: sets production AIPT_POSTGRES_DSN',
      reason: /test-only DSN/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            t.replace(
              '    runs-on: ubuntu-26.04',
              '    runs-on: ubuntu-26.04\n    env:\n      AIPT_POSTGRES_DSN: postgres://postgres@db.prod.internal:5432/ledger?sslmode=require',
            ),
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres alternate DSN assignment (non-export, single-quoted)',
      reason: /test-only DSN/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            t.replace(
              `export AIPT_POSTGRES_DSN="${STORAGE_TEST_DSN}"\n`,
              `AIPT_POSTGRES_DSN='${STORAGE_TEST_DSN}'\n`,
            ),
          ),
          lock,
        ),
    },
    // ---- AIPT-M0-B003 iteration 6b second Codex review: closed-world
    // regressions — appended production psql, quoted duplicate run key,
    // quoted-name duplicate step, extra job-level key and step-level env:
    // must each FAIL for the closed-world reasons ----
    {
      label: 'storage-postgres appended production psql step',
      reason: /must run psql only inside the approved/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            `${t}\n      - name: Sneak production psql\n        run: psql "postgres://admin:secret@db.prod.internal:5432/ledger" -c "DROP TABLE production.ledger"`,
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres quoted duplicate run key on the full-test step',
      reason: /must carry exactly the expected step key multiset/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            t.replace(fullTestStepName, `${fullTestStepName}\n        'run': ${STORAGE_FULL_TEST}`),
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres quoted-name duplicate step (bypass of the exact nine ordered steps)',
      reason: /must contain exactly the nine ordered named steps/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            `${t}\n      - "name": Verify exact Go version\n        run: |\n          test "$(go version)" = "go version go1.26.6 linux/amd64"\n          go version`,
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres extra job-level key (timeout-minutes)',
      reason: /must contain exactly one name:, one runs-on: and one steps:/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            t.replace('    runs-on: ubuntu-26.04', '    runs-on: ubuntu-26.04\n    timeout-minutes: 30'),
          ),
          lock,
        ),
    },
    {
      label: 'storage-postgres step-level env: mapping on the full-test step',
      reason: /must carry exactly the expected step key multiset/,
      run: () =>
        checkWorkflowText(
          mutateJobText(text, 'storage-postgres', (t) =>
            t.replace(fullTestStepName, `${fullTestStepName}\n        env:\n          AIPT_CI_EVIDENCE: 1`),
          ),
          lock,
        ),
    },
    // ---- AIPT-M0-B003 iteration 6b third Codex review: closed-world root
    // mapping regressions — a quoted duplicate of a top-level key is
    // invisible to the raw `^key:$` block regexes but must still be rejected
    // by the normalized closed-world root check ----
    {
      label: 'duplicate quoted top-level jobs key',
      reason: /closed-world root mapping must contain exactly one each/,
      run: () => checkWorkflowText(text.replace('jobs:', "'jobs':\njobs:"), lock),
    },
    {
      label: 'duplicate quoted top-level on key',
      reason: /closed-world root mapping must contain exactly one each/,
      run: () => checkWorkflowText(text.replace('on:', '"on":\non:'), lock),
    },
    {
      label: 'duplicate quoted top-level concurrency key',
      reason: /closed-world root mapping must contain exactly one each/,
      run: () => checkWorkflowText(text.replace('concurrency:', "'concurrency':\nconcurrency:"), lock),
    },
    {
      label: 'duplicate quoted top-level name key',
      reason: /closed-world root mapping must contain exactly one each/,
      run: () => checkWorkflowText(text.replace('name:', '"name": AIPT M0 CI\nname:'), lock),
    },
  ];
  let probesOk = true;
  for (const probe of probes) {
    let result;
    try {
      result = probe.run();
    } catch (err) {
      fail(`negative workflow probe (${probe.label}) crashed: ${err.message}`);
      probesOk = false;
      continue;
    }
    if (result.result !== 'FAIL') {
      fail(`negative workflow probe (${probe.label}) was NOT rejected`);
      probesOk = false;
    } else {
      const rightReason = result.details.filter((d) => d.startsWith('FAIL')).some((d) => probe.reason.test(d));
      if (!rightReason) fail(`negative workflow probe (${probe.label}) failed for an unexpected reason`);
      else ok(`negative-probe PASS: ${probe.label} rejected`);
    }
  }
  if (probesOk) ok(`all ${probes.length} in-memory workflow mutation probes rejected as expected`);

  return { name: 'workflow', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'workflow', run);
