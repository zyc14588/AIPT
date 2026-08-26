#!/usr/bin/env node
// AIPT-M0-B003 iteration 6a: PostgreSQL storage layer machine gate.
//
// Node.js standard library only (fs, path, crypto, os). Fail-closed checks:
//   1. the exact pgx v5.10.0 runtime closure in go.mod/go.sum — the single
//      direct module github.com/jackc/pgx/v5 v5.10.0 plus the five indirect
//      modules, with exact versions, exact direct/indirect markers, NO
//      replace/exclude/retract dependency-graph override, and exact zip +
//      /go.mod h1 pins (the pinned SHA-256 values, decoded from the go.sum
//      base64 payloads);
//   2. the shared full required-file / source-tree contract over the
//      dynamically enumerated storage tree (every file under
//      internal/storage/postgres): all required files present, the migration
//      contract (migrations/000001_ledger.sql with the exact `<6 digits>_
//      <lowercase name>.sql` filename form, the pinned schema_test SHA-256,
//      and the complete forward-only append-only SQL contract), the ledger
//      contract surface (Append, VerifyStream, MigrateUp, HashDomain
//      AIPT_LEDGER_V1, the ten typed error sentinels), and the integration-
//      test contract (AIPT_POSTGRES_DSN fail-closed gating, ephemeral
//      aipt_it_* databases only, exact cleanup, concurrency + five-tamper
//      coverage);
//   3. a runtime integrity bypass scan over EVERY non-test *.go file under
//      internal/storage/postgres — dynamically enumerated, never a fixed
//      allowlist — with case-insensitive / whitespace-tolerant matching (a
//      lowercase `disable trigger`, extra whitespace/newlines, or Go token
//      spacing like `time . Now ( )` cannot hide a bypass);
//   4. meaningful in-memory and temporary-fixture negative mutation probes
//      proving every contract above is enforced — the temporary fixtures
//      exercise the SHARED full required-file/source-tree check and prove a
//      missing verify.go and an added bypass-bearing non-test Go file fail.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runAsMain } from '../lib/cli.mjs';
import { checkMigrationContract as checkB001MigrationContract } from './mvp-b001.mjs';

// The exact approved pgx v5.10.0 Go runtime closure (AIPT-M0-B003 iteration
// 6a). h1hex is the frozen SHA-256 (64 lowercase hex) that the go.sum zip
// `h1:` base64 payload must decode to; gomodhex is the frozen SHA-256 that
// the `<module> <version>/go.mod h1:` base64 payload must decode to.
const GO_RUNTIME_MODULES = [
  { module: 'github.com/jackc/pgx/v5', version: 'v5.10.0', direct: true, license: 'MIT', h1hex: '5614af814da34a58bca3702a20439326beeb670004515a381385e147de197ebd', gomodhex: '99a975b4118015f2c7bd9cda621efb612fde0ba217f4e59b455d50208334267e' },
  { module: 'github.com/jackc/pgpassfile', version: 'v1.0.0', direct: false, license: 'MIT', h1hex: 'ffa1e6ab2d774acdb30aaeb655d346f2d335c1c867f338d218e049ea2729b083', gomodhex: '084c74892e5a99b34575c46dc4f8f9261133fb107ab91932e5ec95bbf5b61c48' },
  { module: 'github.com/jackc/pgservicefile', version: 'v0.0.0-20240606120523-5a60cdf6a761', direct: false, license: 'MIT', h1hex: '882127a287bb525c0e418a4a16105a6cf322e1a3407e83833c414d8809c2971a', gomodhex: 'e5325958a1169e23ef7b7def956612a0661e7e7de02d04738df0e585227d64a3' },
  { module: 'github.com/jackc/puddle/v2', version: 'v2.2.2', direct: false, license: 'MIT', h1hex: '3d1f27c3e13fd70d062ee4454a68a2a18e94a28329e8a26fd3feb59c1ee2707a', gomodhex: 'beb8a21171ef104eb9e1a60a5d78cebd9337f6a274abe6b391916b7c439cdc7e' },
  { module: 'golang.org/x/sync', version: 'v0.21.0', direct: false, license: 'BSD-3-Clause', h1hex: '1cb208e314514ed091931629e0734517426cfce83aab68bef8a5db8348070b03', gomodhex: 'f71acdc1d2dfc788e429b36f6bd1692fabc437b7af9c4e3734d3494362c5dfed' },
  { module: 'golang.org/x/text', version: 'v0.39.0', direct: false, license: 'BSD-3-Clause', h1hex: '51b673e292cebe7eb4d03e8e87a186108e950269ddac404bbfcffa0445f3caeb', gomodhex: 'dd4c117259c2da0d1353dc7c3d98b27ce6a309dd7369434717d72fa9c419f993' },
];

// The pinned SHA-256 of the exact bytes of migrations/000001_ledger.sql as
// recorded by the storage package's own schema_test (ledgerMigrationChecksumHex).
const MIGRATION_CHECKSUM_HEX = 'cbab234c8d6a265397dcc553bd9bdb17006712f77ec482b0ef8332f050c9f591';
const QUEUE_MIGRATION_CHECKSUM_HEX = '47f02a5a2129473caa0db5e359a0b294a01b2a96329d9f6fa08ac87cc429c997';

const MIGRATION_FILENAME_RE = /^\d{6}_[a-z0-9_]+\.sql$/;

// The full required storage-file contract (relative to internal/storage/postgres).
const REQUIRED_STORAGE_FILES = [
  'migrate.go',
  'ledger.go',
  'verify.go',
  'errors.go',
  'hash.go',
  'schema.go',
  'migrations/000001_ledger.sql',
  'migrations/000002_playtest_queue.sql',
  'queue.go',
  'queue_errors.go',
  'queue_types.go',
  'queue_test.go',
  'queue_integration_test.go',
  'migrate_test.go',
  'ledger_test.go',
  'hash_test.go',
  'schema_test.go',
  'migration_integration_test.go',
  'ledger_integration_test.go',
];

// Runtime integrity bypass API patterns. These must NEVER appear in non-test
// Go sources: they would let production code rewrite or bypass the append-only
// hash-chain authority (the migration SQL trigger is the only place the
// append-only rejection is defined, and the tamper tests use them ONLY in
// *_test.go on ephemeral databases). Matching is case-insensitive and
// whitespace-tolerant: each pattern is normalized to uppercase with all
// whitespace removed, so a lowercase SQL form, extra whitespace/newlines, or
// Go token spacing (`time . Now ( )`) cannot hide a bypass.
const BYPASS_PATTERNS = [
  { label: 'DISABLE TRIGGER', canonical: 'DISABLETRIGGER' },
  { label: 'DROP CONSTRAINT', canonical: 'DROPCONSTRAINT' },
  { label: 'ALTER TABLE aipt.ledger_events', canonical: 'ALTERTABLEAIPT.LEDGER_EVENTS' },
  { label: 'TRUNCATE aipt.ledger_events', canonical: 'TRUNCATEAIPT.LEDGER_EVENTS' },
  { label: 'DROP TABLE aipt.ledger_events', canonical: 'DROPTABLEAIPT.LEDGER_EVENTS' },
  { label: 'DROP FUNCTION aipt.', canonical: 'DROPFUNCTIONAIPT.' },
  { label: 'DELETE FROM aipt.ledger_events', canonical: 'DELETEFROMAIPT.LEDGER_EVENTS' },
  { label: 'UPDATE aipt.ledger_events', canonical: 'UPDATEAIPT.LEDGER_EVENTS' },
  { label: 'time.Now(', canonical: 'TIME.NOW(' },
];

function normalizeBypassText(text) {
  return text.toUpperCase().replace(/\s+/g, '');
}

// The ten typed error sentinels of the storage contract (stable codes).
const ERROR_SENTINELS = [
  'AIPT_MIGRATION_CHECKSUM_DRIFT',
  'AIPT_LEDGER_CURSOR_MISMATCH',
  'AIPT_LEDGER_SEQUENCE_EXHAUSTED',
  'AIPT_LEDGER_STREAM_NOT_FOUND',
  'AIPT_LEDGER_SEQUENCE_GAP',
  'AIPT_LEDGER_PREV_HASH_MISMATCH',
  'AIPT_LEDGER_PAYLOAD_HASH_MISMATCH',
  'AIPT_LEDGER_EVENT_HASH_MISMATCH',
  'AIPT_LEDGER_MALFORMED_HASH',
  'AIPT_INVALID_LEDGER_HASH_INPUT',
];

const QUEUE_ERROR_SENTINELS = [
  'AIPT_QUEUE_INVALID_INPUT',
  'AIPT_QUEUE_RUN_EXISTS',
  'AIPT_QUEUE_RUN_NOT_FOUND',
  'AIPT_QUEUE_STATE_CONFLICT',
  'AIPT_QUEUE_PAUSED',
  'AIPT_QUEUE_NO_ELIGIBLE_RUN',
  'AIPT_LEASE_STALE',
  'AIPT_LEASE_EXPIRED',
  'AIPT_LEASE_TOKEN_SOURCE_FAILURE',
  'AIPT_ATTEMPT_CONFLICT',
  'AIPT_QUEUE_STORAGE_FAILURE',
];

// ---- pure go.mod/go.sum closure check (independent copy) ----
// Parse the require directives of a go.mod text into {module, version,
// indirect}. Both the single-line form (`require m v`) and the block form
// (`require (...)` with `// indirect` markers) are supported, with the
// optional leading horizontal whitespace accepted by Go honored before the
// `require` keyword and inside blocks.
//
// The parser is a FAIL-CLOSED line-state scanner, never a regex over block
// bodies: a block is opened by a line whose code portion (everything before a
// `//` comment, trimmed) is `require (` and is closed ONLY by a line whose
// code portion, trimmed, is exactly `)`. A `)` inside a `//` comment can
// therefore never close a block, and a block that is never closed is a parse
// error. Every non-comment line inside a block must parse as
// `<module> <version>`, with an arbitrary trailing `//` comment allowed: the
// comment is stripped before module/version parsing, and indirectness is read
// from the Go `// indirect` marker on the original line. Any top-level
// `require` directive (single-line form) or non-comment block entry that
// cannot be parsed is a parse error: the function THROWS instead of silently
// omitting lines, and every caller treats a parser error as a hard failure.
// Multiple blocks, the single-line form, exact count/version/directness, and
// the replace/exclude/retract override rejection are all preserved.
function parseGoModRequires(text) {
  const requires = [];
  const errors = [];
  const stripComment = (line) => {
    // Go line comments start at the first `//` outside code; module paths,
    // versions, and pseudo-versions never contain `//`, so the first `//` is
    // always the comment delimiter.
    const idx = line.indexOf('//');
    return idx === -1 ? line : line.slice(0, idx);
  };
  const isIndirect = (line) => /\/\/\s*indirect(\s|$)/.test(line);
  const parseEntry = (raw, where) => {
    const code = stripComment(raw).trim();
    if (code === '') return null; // blank or comment-only line
    const m = /^([^\s]+)\s+(v[\w.+\-]+)\s*$/.exec(code);
    if (!m) {
      errors.push(`${where}: cannot parse require entry ${JSON.stringify(raw.trim())}`);
      return null;
    }
    return { module: m[1], version: m[2], indirect: isIndirect(raw) };
  };
  const lines = text.split('\n');
  let inBlock = false;
  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i];
    const code = stripComment(raw).trim();
    if (inBlock) {
      if (code === ')') {
        inBlock = false;
        continue;
      }
      const entry = parseEntry(raw, `line ${i + 1} (require block)`);
      if (entry) requires.push(entry);
      continue;
    }
    if (/^require\s*\($/.test(code)) {
      inBlock = true;
      continue;
    }
    if (/^require\b/.test(code)) {
      const m = /^require\s+([^\s]+)\s+(v[\w.+\-]+)\s*$/.exec(code);
      if (!m) {
        errors.push(`line ${i + 1}: cannot parse single-line require directive ${JSON.stringify(raw.trim())}`);
      } else {
        requires.push({ module: m[1], version: m[2], indirect: isIndirect(raw) });
      }
    }
  }
  if (inBlock) errors.push('unterminated require ( block: no closing line whose code portion is exactly ")"');
  if (errors.length > 0) throw new Error(`go.mod require parse error(s): ${errors.join('; ')}`);
  return requires;
}

// A dependency-graph override directive (replace/exclude/retract) is present
// in either its single-line form (`replace a => b v1.0.0`) or its block form
// (`replace (` ... `)`), both with the optional leading horizontal whitespace
// accepted by Go. The keyword must start the line (after whitespace), so a
// comment or an unrelated line can never be misdetected as an override.
function hasOverrideDirective(text, keyword) {
  return new RegExp(`^[ \\t]*${keyword}\\s*(?:\\(|\\S)`, 'm').test(text);
}

function parseGoSumH1(text) {
  const zip = new Map();
  const gomod = new Map();
  for (const m of text.matchAll(/^([^\s]+)\s+(v[\w.+\-]+)\s+h1:([A-Za-z0-9+/=]+)$/gm)) zip.set(`${m[1]} ${m[2]}`, m[3]);
  for (const m of text.matchAll(/^([^\s]+)\s+(v[\w.+\-]+)\/go\.mod\s+h1:([A-Za-z0-9+/=]+)$/gm)) gomod.set(`${m[1]} ${m[2]}`, m[3]);
  return { zip, gomod };
}

function checkGoClosureText({ goMod, goSum }) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  // Parser errors are fail-closed: an unparseable top-level require directive
  // or non-comment block entry makes the whole closure check FAIL rather than
  // silently dropping the offending line.
  let requires;
  try {
    requires = parseGoModRequires(goMod);
  } catch (err) {
    fail(`go.mod require parse error (fail-closed): ${err.message}`);
    requires = [];
  }
  const byModule = new Map(requires.map((r) => [r.module, r]));
  if (requires.length !== GO_RUNTIME_MODULES.length) fail(`go.mod require count must be exactly ${GO_RUNTIME_MODULES.length}, got ${requires.length}`);
  let moduleOk = true;
  for (const m of GO_RUNTIME_MODULES) {
    const r = byModule.get(m.module);
    if (!r) {
      fail(`go.mod missing required module ${m.module}`);
      moduleOk = false;
      continue;
    }
    if (r.version !== m.version) {
      fail(`go.mod ${m.module} version must be ${m.version}, got ${JSON.stringify(r.version)}`);
      moduleOk = false;
    }
    if (Boolean(r.indirect) !== !m.direct) {
      fail(`go.mod ${m.module} directness drifted: expected ${m.direct ? 'direct' : 'indirect'}`);
      moduleOk = false;
    }
  }
  const unknown = requires.filter((r) => !GO_RUNTIME_MODULES.some((m) => m.module === r.module));
  if (unknown.length > 0) {
    fail(`unknown go.mod dependency: ${unknown.map((r) => r.module).join(', ')}`);
    moduleOk = false;
  }
  if (moduleOk) ok('go.mod carries exactly the six approved pgx v5.10.0 runtime-closure modules (pgx direct + five indirect)');
  // Dependency-graph override directives are fail-closed: a replace/exclude/
  // retract directive re-routes or hides modules of the approved closure.
  // Both single-line and block forms with optional leading whitespace are
  // detected.
  const graphOverride = [];
  if (hasOverrideDirective(goMod, 'replace')) graphOverride.push('replace');
  if (hasOverrideDirective(goMod, 'exclude')) graphOverride.push('exclude');
  if (hasOverrideDirective(goMod, 'retract')) graphOverride.push('retract');
  if (graphOverride.length > 0) {
    fail(`go.mod carries dependency-graph override directive(s): ${graphOverride.join(', ')} (replace/exclude/retract are forbidden for the approved closure)`);
  } else ok('go.mod carries no replace/exclude/retract dependency-graph override directive');
  const { zip, gomod } = parseGoSumH1(goSum);
  let h1Ok = true;
  for (const m of GO_RUNTIME_MODULES) {
    const key = `${m.module} ${m.version}`;
    const z = zip.get(key);
    const g = gomod.get(key);
    if (!z) {
      fail(`go.sum missing zip h1 for ${key}`);
      h1Ok = false;
      continue;
    }
    if (!g) {
      fail(`go.sum missing /go.mod h1 for ${key}`);
      h1Ok = false;
      continue;
    }
    const zBytes = Buffer.from(z, 'base64');
    const zHex = zBytes.length === 32 ? zBytes.toString('hex') : null;
    if (zHex !== m.h1hex) {
      fail(`go.sum ${key} zip h1 decodes to ${zHex ?? `<${zBytes.length} bytes>`}, expected pinned SHA-256 ${m.h1hex}`);
      h1Ok = false;
    }
    const gBytes = Buffer.from(g, 'base64');
    const gHex = gBytes.length === 32 ? gBytes.toString('hex') : null;
    if (gHex !== m.gomodhex) {
      fail(`go.sum ${key} /go.mod h1 decodes to ${gHex ?? `<${gBytes.length} bytes>`}, expected pinned SHA-256 ${m.gomodhex}`);
      h1Ok = false;
    }
  }
  if (h1Ok) ok(`go.sum carries zip + /go.mod h1 for all ${GO_RUNTIME_MODULES.length} modules, decoding to the pinned h1 SHA-256 values`);
  return { result: pass ? 'PASS' : 'FAIL', details };
}

// ---- pure migration SQL contract check ----
// The migration must define the forward-only append-only ledger authority:
// the versioned hash function over the literal AIPT_LEDGER_V1 domain, the
// stream cursor invariant, the event chain invariant, the payload/event hash
// check constraints, the UNIQUE event_id key, the RESTRICT foreign key, and
// the statement-level BEFORE UPDATE|DELETE|TRUNCATE append-only trigger with
// the stable code and SQLSTATE 55000.
function checkMigrationSql(sql) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const requireText = (label, needle) => {
    if (sql.includes(needle)) ok(label);
    else fail(label);
  };
  requireText('versioned hash function aipt.ledger_event_hash_v1 defined', 'CREATE FUNCTION aipt.ledger_event_hash_v1');
  requireText('literal hash domain AIPT_LEDGER_V1 bound into the SQL preimage', "'AIPT_LEDGER_V1'");
  requireText('aipt.ledger_streams table defined', 'CREATE TABLE aipt.ledger_streams');
  requireText('aipt.ledger_events table defined', 'CREATE TABLE aipt.ledger_events');
  requireText('stream cursor invariant enforced', 'ledger_streams_cursor_invariant');
  requireText('event chain invariant enforced (genesis NULL prev, later non-NULL)', 'ledger_events_chain_invariant');
  requireText('payload digest check constraint enforced', 'ledger_events_payload_sha256_check');
  requireText('payload digest binds to canonical payload bytes', 'payload_sha256 = sha256(convert_to(payload_canonical, \'UTF8\'))');
  requireText('event hash check constraint enforced', 'ledger_events_event_hash_check');
  requireText('event hash binds to the versioned SQL hash function', 'event_hash = aipt.ledger_event_hash_v1(');
  requireText('event id uniqueness enforced', 'ledger_events_event_id_key UNIQUE (event_id)');
  requireText('event rows RESTRICT stream deletion', 'ON DELETE RESTRICT');
  requireText('append-only trigger function defined', 'ledger_events_append_only');
  requireText('append-only trigger is a statement-level BEFORE UPDATE|DELETE|TRUNCATE trigger', 'BEFORE UPDATE OR DELETE OR TRUNCATE ON aipt.ledger_events');
  requireText('append-only trigger fires FOR EACH STATEMENT (never a row trigger)', 'FOR EACH STATEMENT');
  requireText('append-only trigger raises the stable code AIPT_LEDGER_APPEND_ONLY', 'AIPT_LEDGER_APPEND_ONLY');
  requireText('append-only trigger uses SQLSTATE 55000 (object_not_in_prerequisite_state)', "'55000'");
  return { result: pass ? 'PASS' : 'FAIL', details };
}

// ---- pure migration file set check ----
// Exactly the frozen B003 ledger migration followed by the single B001 queue
// migration. Both byte identities and both SQL contracts are fail-closed.
function checkMigrationFiles(files) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const names = files.map((f) => f.filename);
  const expectedNames = ['000001_ledger.sql', '000002_playtest_queue.sql'];
  if (JSON.stringify([...names].sort()) !== JSON.stringify(expectedNames)) {
    fail(`migrations/ must contain exactly ${expectedNames.join(' + ')}, got ${JSON.stringify(names)}`);
  } else ok(`migrations/ contains exactly ${expectedNames.join(' + ')}`);
  for (const f of files) {
    if (!MIGRATION_FILENAME_RE.test(f.filename)) {
      fail(`migration filename ${JSON.stringify(f.filename)} must match ^\\d{6}_[a-z0-9_]+\\.sql$`);
    }
  }
  if (files.every((f) => MIGRATION_FILENAME_RE.test(f.filename))) {
    ok('every migration filename matches the exact <6 digits>_<lowercase name>.sql form');
  }
  const ledger = files.find((f) => f.filename === '000001_ledger.sql');
  if (ledger) {
    const sum = crypto.createHash('sha256').update(ledger.content, 'utf8').digest('hex');
    if (sum !== MIGRATION_CHECKSUM_HEX) {
      fail(`migrations/000001_ledger.sql SHA-256 must equal the pinned schema_test value ${MIGRATION_CHECKSUM_HEX}, got ${sum}`);
    } else ok(`migrations/000001_ledger.sql SHA-256 == pinned ${MIGRATION_CHECKSUM_HEX}`);
    const sqlCheck = checkMigrationSql(ledger.content);
    details.push(...sqlCheck.details);
    if (sqlCheck.result !== 'PASS') fail('migration SQL contract FAIL');
    else ok('migration SQL carries the complete forward-only append-only ledger contract');
  } else {
    fail('migrations/000001_ledger.sql missing (the SQL contract cannot be checked)');
  }
  const queue = files.find((f) => f.filename === '000002_playtest_queue.sql');
  if (queue) {
    const sum = crypto.createHash('sha256').update(queue.content, 'utf8').digest('hex');
    if (sum !== QUEUE_MIGRATION_CHECKSUM_HEX) {
      fail(`migrations/000002_playtest_queue.sql SHA-256 must equal the pinned B001 value ${QUEUE_MIGRATION_CHECKSUM_HEX}, got ${sum}`);
    } else ok(`migrations/000002_playtest_queue.sql SHA-256 == pinned ${QUEUE_MIGRATION_CHECKSUM_HEX}`);
  } else {
    fail('migrations/000002_playtest_queue.sql missing (the queue contract cannot be checked)');
  }
  const b001Files = new Map(files.map((f) => [f.filename, f.content]));
  const b001Problems = checkB001MigrationContract(b001Files);
  for (const problem of b001Problems) fail(`B001 migration contract: ${problem}`);
  if (b001Problems.length === 0) ok('B001 migration contract preserves 000001 and enforces immutable Manifest, append-only Attempt, deterministic priority, lease ownership and formal WIP=1');
  return { result: pass ? 'PASS' : 'FAIL', details };
}

// ---- pure runtime integrity bypass scan ----
// Case-insensitive / whitespace-tolerant: the source is normalized to
// uppercase with all whitespace removed and each canonical pattern is matched
// against the normalized text, so `disable trigger`, `DISABLE\n TRIGGER`,
// `time . Now ( )` etc. are all caught.
function checkStorageSourceBypass(text) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const normalized = normalizeBypassText(typeof text === 'string' ? text : '');
  const hits = BYPASS_PATTERNS.filter((p) => normalized.includes(p.canonical));
  if (hits.length > 0) {
    for (const hit of hits) {
      fail(`runtime integrity bypass API present in non-test storage source: ${JSON.stringify(hit.label)} (case/whitespace-tolerant match)`);
    }
  } else ok('no runtime integrity bypass API in non-test storage sources (append-only authority intact)');
  return { result: pass ? 'PASS' : 'FAIL', details };
}

// ---- pure contract-surface check over a file map ----
function checkContractSurface(tree) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const text = (name) => tree.get(name) ?? '';
  const sourceText = ['ledger.go', 'verify.go', 'schema.go', 'hash.go', 'errors.go', 'migrate.go', 'queue.go', 'queue_types.go', 'queue_errors.go']
    .map((name) => text(name)).join('\n');
  const requireSurface = (label, needle) => {
    if (sourceText.includes(needle)) {
      ok(label);
    } else fail(label);
  };
  requireSurface('exported Append API present', 'func Append(ctx context.Context, pool *pgxpool.Pool, in AppendInput) (LedgerEvent, error)');
  requireSurface('exported VerifyStream API present', 'func VerifyStream(ctx context.Context, pool *pgxpool.Pool, in VerifyInput) (VerifiedStream, error)');
  requireSurface('exported MigrateUp API present', 'func MigrateUp(ctx context.Context, pool *pgxpool.Pool) error');
  if (text('hash.go').includes('const HashDomain = "AIPT_LEDGER_V1"')) ok('hash domain literal bound: HashDomain = "AIPT_LEDGER_V1"');
  else fail('hash domain literal HashDomain = "AIPT_LEDGER_V1" missing from hash.go');
  let sentinelsOk = true;
  for (const code of ERROR_SENTINELS) {
    if (!text('errors.go').includes(`errors.New("${code}")`) && !text('hash.go').includes(`errors.New("${code}")`)) {
      fail(`typed error sentinel ${code} missing`);
      sentinelsOk = false;
    }
  }
  if (sentinelsOk) ok(`all ${ERROR_SENTINELS.length} typed error sentinels present`);
  for (const [label, needle] of [
    ['exported EnqueueRun API present', 'func (s *QueueStore) EnqueueRun('],
    ['exported deterministic eligibility API present', 'func (s *QueueStore) ListEligibleRuns('],
    ['exported lease acquire API present', 'func (s *QueueStore) AcquireLease('],
    ['exported lease heartbeat API present', 'func (s *QueueStore) RenewLease('],
    ['exported lease release API present', 'func (s *QueueStore) ReleaseLease('],
    ['exported lease expiry recovery API present', 'func (s *QueueStore) RecoverExpiredLeases('],
    ['exported append-only Attempt API present', 'func (s *QueueStore) AppendAttempt('],
    ['injectable lease TokenSource present', 'type TokenSource interface'],
  ]) requireSurface(label, needle);
  let queueSentinelsOk = true;
  for (const code of QUEUE_ERROR_SENTINELS) {
    if (!text('queue_errors.go').includes(`errors.New("${code}")`)) {
      fail(`typed queue error sentinel ${code} missing`);
      queueSentinelsOk = false;
    }
  }
  if (queueSentinelsOk) ok(`all ${QUEUE_ERROR_SENTINELS.length} typed queue/lease/Attempt error sentinels present`);
  return { result: pass ? 'PASS' : 'FAIL', details };
}

// ---- pure integration-test contract check ----
function checkIntegrationContract(testTexts) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const migration = testTexts['migration_integration_test.go'] ?? '';
  const ledger = testTexts['ledger_integration_test.go'] ?? '';
  const queue = testTexts['queue_integration_test.go'] ?? '';
  const requireBoth = (label, needle) => {
    if (migration.includes(needle) && ledger.includes(needle)) ok(label);
    else fail(label);
  };
  requireBoth('integration tests gate on AIPT_POSTGRES_DSN', 'AIPT_POSTGRES_DSN');
  requireBoth('integration tests hard-fail on AIPT_REQUIRE_POSTGRES_INTEGRATION=1', 'AIPT_REQUIRE_POSTGRES_INTEGRATION');
  if (migration.includes('t.Skip("AIPT_POSTGRES_DSN is not set')) ok('missing DSN skips normally (fail-open only when not required)');
  else fail('migration integration test must skip when AIPT_POSTGRES_DSN is missing');
  if (migration.includes('t.Fatalf("AIPT_POSTGRES_DSN is required when AIPT_REQUIRE_POSTGRES_INTEGRATION=1')) ok('AIPT_REQUIRE_POSTGRES_INTEGRATION=1 turns the skip into a hard failure');
  else fail('migration integration test must hard-fail when AIPT_REQUIRE_POSTGRES_INTEGRATION=1 without a DSN');
  if (migration.includes('AIPT_POSTGRES_DSN must name a database')) ok('DSN fail-closed: a DSN without dbname is rejected');
  else fail('DSN without a dbname must be rejected');
  if (migration.includes('aipt_it_')) ok('fixtures create only ephemeral aipt_it_* databases');
  else fail('integration fixtures must create only ephemeral aipt_it_* databases');
  if (migration.includes('pg_terminate_backend') && migration.includes('DROP DATABASE IF EXISTS')) ok('cleanup terminates connections and drops exactly the ephemeral database');
  else fail('cleanup must terminate connections and drop exactly the ephemeral database');
  if (migration.includes("left(datname, 5) = 'aipt_'")) ok('cleanup verifies no aipt_* database remains (production data prohibition)');
  else fail('cleanup must verify no aipt_* database remains');
  if (migration.includes('TestPostgresIntegrationMigrationConcurrentRunners') && migration.includes('pg_advisory')) ok('migration concurrency coverage present (advisory-lock serialization proof)');
  else fail('migration concurrency coverage missing');
  if (ledger.includes('TestPostgresIntegrationLedgerConcurrentSameStreamAppends')) ok('ledger concurrency coverage present (16 concurrent same-stream appends)');
  else fail('ledger concurrency coverage missing');
  const tamperSentinels = ['ErrLedgerPayloadHashMismatch', 'ErrLedgerPrevHashMismatch', 'ErrLedgerEventHashMismatch', 'ErrLedgerCursorMismatch', 'ErrLedgerSequenceGap'];
  let tamperOk = true;
  for (const sentinel of tamperSentinels) {
    if (!ledger.includes(sentinel)) {
      fail(`ledger tamper coverage missing typed failure ${sentinel}`);
      tamperOk = false;
    }
  }
  if (tamperOk) ok('ledger tamper coverage exercises all five typed integrity failures');
  if (ledger.includes('DISABLE TRIGGER ledger_events_append_only')) ok('tamper tests disable the append-only trigger only inside ephemeral test databases');
  else fail('tamper tests must disable the append-only trigger (ephemeral only)');
  const queueCoverage = [
    'TestPostgresIntegrationQueueUpgradeFromB003',
    'TestPostgresIntegrationQueueManifestImmutableEnqueueCancelNewRunAndRollback',
    'TestPostgresIntegrationQueueDeterministicEligibilityPauseAndDependencies',
    'TestPostgresIntegrationQueueConcurrentFormalClaimsWIP1',
    'TestPostgresIntegrationQueueLeaseHeartbeatExpiryRecoveryAndStaleHolder',
    'TestPostgresIntegrationQueueAttemptAppendHistory',
  ];
  const missingQueueCoverage = queueCoverage.filter((name) => !queue.includes(name));
  if (missingQueueCoverage.length === 0 && queue.includes('16')) {
    ok('B001 PostgreSQL integration coverage includes B003-only upgrade, immutable Manifest, rollback/cancel/new-Run, deterministic eligibility, 16-claimer WIP=1, lease heartbeat/expiry/recovery/stale ownership and append-only Attempt history');
  } else {
    fail(`B001 PostgreSQL queue integration coverage missing: ${missingQueueCoverage.join(', ') || 'literal 16-claimer proof'}`);
  }
  return { result: pass ? 'PASS' : 'FAIL', details };
}

// ---- dynamic source-tree enumeration ----
// Recursively collect every file under the storage directory into a Map of
// relative path (e.g. 'migrate.go', 'migrations/000001_ledger.sql') -> UTF-8
// content. Future/additional files are picked up automatically — the bypass
// scan is never a fixed allowlist.
function collectStorageTree(storageDir) {
  const files = new Map();
  const walk = (dir, rel) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const childRel = rel === '' ? entry.name : `${rel}/${entry.name}`;
      const childPath = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(childPath, childRel);
      else if (entry.isFile()) files.set(childRel, fs.readFileSync(childPath, 'utf8'));
    }
  };
  walk(storageDir, '');
  return files;
}

// ---- shared full required-file / source-tree check ----
// Pure over the collected tree Map. Covers, in one pass: every required
// storage file present, the migration file contract, the ledger contract
// surface, the runtime integrity bypass scan over EVERY non-test *.go file in
// the tree (dynamically enumerated, case/whitespace-tolerant), and the
// integration-test contract. Temporary fixtures exercise exactly this
// function, so a missing verify.go and an added bypass-bearing non-test Go
// file are proven to fail through the same path the real tree is checked.
function checkStorageTree(tree) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };

  let requiredOk = true;
  for (const name of REQUIRED_STORAGE_FILES) {
    if (!tree.has(name)) {
      fail(`required storage file missing: internal/storage/postgres/${name}`);
      requiredOk = false;
    }
  }
  if (requiredOk) ok(`all ${REQUIRED_STORAGE_FILES.length} required storage files present`);

  const migrationFiles = [...tree.entries()]
    .filter(([name]) => name.startsWith('migrations/'))
    .map(([name, content]) => ({ filename: path.basename(name), content }));
  const migrationCheck = checkMigrationFiles(migrationFiles);
  details.push(...migrationCheck.details);
  if (migrationCheck.result !== 'PASS') fail('migration contract FAIL');
  else ok('migration contract PASS: exact file set, pinned checksum, complete append-only ledger SQL');

  const surfaceCheck = checkContractSurface(tree);
  details.push(...surfaceCheck.details);
  if (surfaceCheck.result !== 'PASS') fail('storage contract surface FAIL');
  else ok('storage contract surface PASS: Append/VerifyStream/MigrateUp, hash domain, typed sentinels');

  const nonTestGo = [...tree.entries()]
    .filter(([name]) => name.endsWith('.go') && !name.endsWith('_test.go') && !name.startsWith('testdata/'))
    .sort((a, b) => (a[0] < b[0] ? -1 : 1));
  let bypassOk = true;
  for (const [name, content] of nonTestGo) {
    const bypassCheck = checkStorageSourceBypass(content);
    details.push(...bypassCheck.details);
    if (bypassCheck.result !== 'PASS') bypassOk = false;
  }
  if (bypassOk) ok(`no runtime integrity bypass API in any of the ${nonTestGo.length} non-test storage Go sources (dynamically enumerated, case/whitespace-tolerant)`);
  else fail('runtime integrity bypass API present in non-test storage Go sources (append-only authority violated)');

  const integrationCheck = checkIntegrationContract({
    'migration_integration_test.go': tree.get('migration_integration_test.go') ?? '',
    'ledger_integration_test.go': tree.get('ledger_integration_test.go') ?? '',
    'queue_integration_test.go': tree.get('queue_integration_test.go') ?? '',
  });
  details.push(...integrationCheck.details);
  if (integrationCheck.result !== 'PASS') fail('integration-test contract FAIL');
  else ok('integration-test contract PASS: DSN fail-closed gating, ephemeral-only databases, exact cleanup, concurrency + five-tamper coverage');

  return { result: pass ? 'PASS' : 'FAIL', details };
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const read = (rel) => fs.readFileSync(path.join(ctx.repo, rel), 'utf8');

  // ---- 1. exact pgx v5.10.0 runtime closure ----
  const closure = checkGoClosureText({ goMod: read('go.mod'), goSum: read('go.sum') });
  details.push(...closure.details);
  if (closure.result !== 'PASS') fail('pgx runtime closure FAIL');
  else ok('storage runtime closure: exactly the six approved pgx v5.10.0 modules (pgx direct + five indirect, no graph override, exact zip + /go.mod h1 pins)');

  // ---- 2. shared full required-file / source-tree contract over the
  // dynamically enumerated storage tree ----
  const storageDir = path.join(ctx.repo, 'internal', 'storage', 'postgres');
  let storageTree;
  try {
    storageTree = collectStorageTree(storageDir);
  } catch (err) {
    fail(`cannot enumerate internal/storage/postgres: ${err.message}`);
    return { name: 'storage', result: 'FAIL', details };
  }
  const treeCheck = checkStorageTree(storageTree);
  details.push(...treeCheck.details);
  if (treeCheck.result !== 'PASS') fail('storage source-tree contract FAIL');
  else ok('storage source-tree contract PASS: required files, migration contract, contract surface, dynamic non-test bypass scan, integration-test contract');

  // ---- 3. negative mutation probes (in-memory) ----
  const goModText = read('go.mod');
  const goSumText = read('go.sum');
  const ledgerSqlText = storageTree.get('migrations/000001_ledger.sql') ?? '';
  const queueSqlText = storageTree.get('migrations/000002_playtest_queue.sql') ?? '';
  const probes = [
    {
      label: 'go.mod unknown dependency injected',
      reason: /unknown go.mod dependency/,
      run: () => checkGoClosureText({ goMod: `${goModText}\nrequire example.com/rogue v1.0.0\n`, goSum: goSumText }),
    },
    {
      label: 'go.mod pgx version drifted',
      reason: /github.com\/jackc\/pgx\/v5 version must be v5\.10\.0/,
      run: () => checkGoClosureText({
        goMod: goModText.replace('github.com/jackc/pgx/v5 v5.10.0', 'github.com/jackc/pgx/v5 v5.9.0'),
        goSum: goSumText,
      }),
    },
    {
      label: 'go.mod x/text vulnerable v0.29.0 rejected',
      reason: /golang.org\/x\/text version must be v0\.39\.0/,
      run: () => checkGoClosureText({
        goMod: goModText.replace('golang.org/x/text v0.39.0', 'golang.org/x/text v0.29.0'),
        goSum: goSumText,
      }),
    },
    {
      label: 'go.mod x/text unapproved newer v0.40.0 rejected',
      reason: /golang.org\/x\/text version must be v0\.39\.0/,
      run: () => checkGoClosureText({
        goMod: goModText.replace('golang.org/x/text v0.39.0', 'golang.org/x/text v0.40.0'),
        goSum: goSumText,
      }),
    },
    {
      label: 'go.sum x/text zip h1 removed',
      reason: /go.sum missing zip h1 for golang.org\/x\/text v0\.39\.0/,
      run: () => checkGoClosureText({
        goMod: goModText,
        goSum: goSumText.replace(/^golang\.org\/x\/text v0\.39\.0 h1:[^\n]+\n/m, ''),
      }),
    },
    {
      label: 'go.mod pgx direct module deleted',
      reason: /go.mod missing required module github.com\/jackc\/pgx\/v5/,
      run: () => checkGoClosureText({ goMod: goModText.replace('require github.com/jackc/pgx/v5 v5.10.0\n\n', ''), goSum: goSumText }),
    },
    {
      label: 'go.mod pgx directness flipped',
      reason: /directness drifted/,
      run: () => checkGoClosureText({
        goMod: goModText.replace('require github.com/jackc/pgx/v5 v5.10.0', 'require github.com/jackc/pgx/v5 v5.10.0 // indirect'),
        goSum: goSumText,
      }),
    },
    {
      label: 'go.mod replace directive injected (graph override)',
      reason: /replace\/exclude\/retract/,
      run: () => checkGoClosureText({
        goMod: `${goModText}\nreplace github.com/jackc/pgx/v5 => github.com/jackc/pgx/v5 v5.9.0\n`,
        goSum: goSumText,
      }),
    },
    {
      label: 'seventh dependency hidden in a second require block',
      reason: /go.mod require count must be exactly 6|unknown go.mod dependency/,
      run: () => checkGoClosureText({
        goMod: `${goModText}\nrequire (\n\texample.com/rogue v1.0.0\n)\n`,
        goSum: goSumText,
      }),
    },
    {
      label: 'seventh dependency hidden after a comment-paren "// )" line in a second require block',
      reason: /go.mod require count must be exactly 6|unknown go.mod dependency/,
      run: () => checkGoClosureText({
        goMod: `${goModText}\nrequire (\n\t// )\n\texample.com/rogue v1.0.0\n)\n`,
        goSum: goSumText,
      }),
    },
    {
      label: 'rogue single-line require with an ordinary trailing comment',
      reason: /go.mod require count must be exactly 6|unknown go.mod dependency/,
      run: () => checkGoClosureText({
        goMod: `${goModText}\nrequire example.com/rogue v1.0.0 // ordinary comment\n`,
        goSum: goSumText,
      }),
    },
    {
      label: 'go.mod replace directive with leading whitespace (graph override)',
      reason: /replace\/exclude\/retract/,
      run: () => checkGoClosureText({
        goMod: `${goModText}\n\treplace github.com/jackc/pgx/v5 => github.com/jackc/pgx/v5 v5.9.0\n`,
        goSum: goSumText,
      }),
    },
    {
      label: 'go.sum pgx zip h1 removed',
      reason: /go.sum missing zip h1 for github.com\/jackc\/pgx\/v5 v5\.10\.0/,
      run: () => checkGoClosureText({
        goMod: goModText,
        goSum: goSumText.replace(/^github\.com\/jackc\/pgx\/v5 v5\.10\.0 h1:[^\n]+\n/m, ''),
      }),
    },
    {
      label: 'go.sum pgx h1 tampered',
      reason: /zip h1 decodes to/,
      run: () => checkGoClosureText({
        goMod: goModText,
        goSum: goSumText.replace('github.com/jackc/pgx/v5 v5.10.0 h1:VhSvgU2jSli8o3AqIEOTJr7rZwAEUVo4E4XhR94Zfr0=', 'github.com/jackc/pgx/v5 v5.10.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
      }),
    },
    {
      label: 'go.sum pgx /go.mod h1 removed',
      reason: /missing \/go\.mod h1 for github.com\/jackc\/pgx\/v5 v5\.10\.0/,
      run: () => checkGoClosureText({
        goMod: goModText,
        goSum: goSumText.replace(/^github\.com\/jackc\/pgx\/v5 v5\.10\.0\/go\.mod h1:[^\n]+\n/m, ''),
      }),
    },
    {
      label: 'go.sum pgx /go.mod h1 tampered',
      reason: /\/go\.mod h1 decodes to/,
      run: () => checkGoClosureText({
        goMod: goModText,
        goSum: goSumText.replace('github.com/jackc/pgx/v5 v5.10.0/go.mod h1:mal1tBGAFfLHvZzaYh77YS/eC6IX9OWbRV1QIIM0Jn4=', 'github.com/jackc/pgx/v5 v5.10.0/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
      }),
    },
    {
      label: 'migration SQL append-only trigger removed',
      reason: /append-only trigger function defined|append-only trigger is a statement-level/,
      run: () => checkMigrationSql(ledgerSqlText.replace(/CREATE FUNCTION aipt\.ledger_events_append_only[\s\S]*?EXECUTE FUNCTION aipt\.ledger_events_append_only\(\);\n?/, '')),
    },
    {
      label: 'migration SQL payload digest check removed',
      reason: /payload digest check constraint enforced/,
      run: () => checkMigrationSql(ledgerSqlText.replace(/CONSTRAINT ledger_events_payload_sha256_check[\s\S]*?\n/, '')),
    },
    {
      label: 'migration SQL hash domain removed',
      reason: /literal hash domain AIPT_LEDGER_V1/,
      run: () => checkMigrationSql(ledgerSqlText.replace(/'AIPT_LEDGER_V1'/g, "'AIPT_LEDGER_V0'")),
    },
    {
      label: 'migration file bytes mutated (checksum drift)',
      reason: /SHA-256 must equal the pinned schema_test value/,
      run: () => checkMigrationFiles([
        { filename: '000001_ledger.sql', content: `${ledgerSqlText}\n-- drift\n` },
        { filename: '000002_playtest_queue.sql', content: queueSqlText },
      ]),
    },
    {
      label: 'B001 queue migration bytes mutated (checksum drift)',
      reason: /000002_playtest_queue\.sql SHA-256 must equal the pinned B001 value|000002 queue bytes\/checksum drifted/,
      run: () => checkMigrationFiles([
        { filename: '000001_ledger.sql', content: ledgerSqlText },
        { filename: '000002_playtest_queue.sql', content: `${queueSqlText}\n-- drift\n` },
      ]),
    },
    {
      label: 'B001 formal WIP=1 unique authority removed',
      reason: /B001 migration contract: 000002 misses CREATE UNIQUE INDEX run_leases_one_active_formal_slot|000002_playtest_queue\.sql SHA-256/,
      run: () => checkMigrationFiles([
        { filename: '000001_ledger.sql', content: ledgerSqlText },
        { filename: '000002_playtest_queue.sql', content: queueSqlText.replace('CREATE UNIQUE INDEX run_leases_one_active_formal_slot', 'CREATE INDEX run_leases_removed_formal_slot') },
      ]),
    },
    {
      label: 'migration filename malformed',
      reason: /must match \^\\d\{6\}/,
      run: () => checkMigrationFiles([
        { filename: '0001_bad.sql', content: 'SELECT 1;\n' },
        { filename: '000001_ledger.sql', content: ledgerSqlText },
        { filename: '000002_playtest_queue.sql', content: queueSqlText },
      ]),
    },
    {
      label: 'runtime integrity bypass API injected into non-test source',
      reason: /runtime integrity bypass API present/,
      run: () => checkStorageSourceBypass(`${storageTree.get('migrate.go') ?? ''}\n// probe\nif _, err := conn.Exec(ctx, "DISABLE TRIGGER ledger_events_append_only"); err != nil {}\n`),
    },
    {
      label: 'lowercase bypass variant (disable trigger) rejected by case-insensitive scan',
      reason: /DISABLE TRIGGER/,
      run: () => checkStorageSourceBypass('package postgres\n\n// probe\n_ = "disable trigger ledger_events_append_only"\n'),
    },
    {
      label: 'whitespace/newline bypass variant (ALTER TABLE with newlines) rejected',
      reason: /ALTER TABLE aipt\.ledger_events/,
      run: () => checkStorageSourceBypass('package postgres\n\n// probe\n_ = "ALTER\n  TABLE aipt.ledger_events\n  ALTER COLUMN payload DROP NOT NULL"\n'),
    },
    {
      label: 'whitespace-tolerant time.Now variant rejected',
      reason: /time\.Now\(/,
      run: () => checkStorageSourceBypass('package postgres\n\n// probe\ncommittedAt := time . Now ( )\n'),
    },
  ];
  let probesOk = true;
  for (const probe of probes) {
    let result;
    try {
      result = probe.run();
    } catch (err) {
      fail(`negative storage probe (${probe.label}) crashed: ${err.message}`);
      probesOk = false;
      continue;
    }
    if (result.result !== 'FAIL') {
      fail(`negative storage probe (${probe.label}) was NOT rejected`);
      probesOk = false;
    } else {
      const rightReason = result.details.filter((d) => d.startsWith('FAIL')).some((d) => probe.reason.test(d));
      if (!rightReason) fail(`negative storage probe (${probe.label}) failed for an unexpected reason`);
      else ok(`negative-probe PASS: ${probe.label} rejected`);
    }
  }
  if (probesOk) ok(`all ${probes.length} in-memory negative probes rejected as expected`);

  // ---- 4. temporary-fixture probes (filesystem-level fail-closed) ----
  // Every fixture is a real directory tree exercised through the SAME shared
  // collectStorageTree + checkStorageTree path the real repository uses.
  const probeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-storage-probe-'));
  try {
    let fixtureOk = true;
    // Fixture A: a full clean copy of the real storage tree must PASS the
    // shared full required-file/source-tree check.
    const treeA = path.join(probeDir, 'treeA');
    fs.cpSync(storageDir, treeA, { recursive: true });
    const checkA = checkStorageTree(collectStorageTree(treeA));
    if (checkA.result !== 'PASS') {
      fail('temporary fixture A (full clean storage tree) failed the shared source-tree check unexpectedly');
      fixtureOk = false;
    } else ok('temporary-fixture PASS: full clean storage tree passes the shared required-file/source-tree check');
    // Fixture B: the same full tree with the contract file verify.go removed
    // must FAIL through the shared required-file check.
    const treeB = path.join(probeDir, 'treeB');
    fs.cpSync(storageDir, treeB, { recursive: true });
    fs.rmSync(path.join(treeB, 'verify.go'));
    const checkB = checkStorageTree(collectStorageTree(treeB));
    const missingVerify = checkB.details.some(
      (d) => d.startsWith('FAIL') && d.includes('required storage file missing') && d.includes('verify.go'),
    );
    if (checkB.result !== 'FAIL' || !missingVerify) {
      fail('temporary-fixture probe: a storage tree missing verify.go was NOT rejected by the shared required-file check');
      fixtureOk = false;
    } else ok('temporary-fixture PASS: missing verify.go rejected by the shared required-file check');
    // Fixture C: the full tree PLUS an added non-test Go file carrying a
    // whitespace-tolerant bypass must FAIL through the dynamic bypass scan
    // (the added file is enumerated, never ignored by a fixed allowlist).
    const treeC = path.join(probeDir, 'treeC');
    fs.cpSync(storageDir, treeC, { recursive: true });
    fs.writeFileSync(
      path.join(treeC, 'probe_bypass.go'),
      'package postgres\n\n// temporary negative probe: added non-test source\nfunc probeBypass() string {\n\treturn "disable   trigger ledger_events_append_only"\n}\n',
    );
    const checkC = checkStorageTree(collectStorageTree(treeC));
    const bypassRejected = checkC.details.some(
      (d) => d.startsWith('FAIL') && d.includes('runtime integrity bypass API present'),
    );
    if (checkC.result !== 'FAIL' || !bypassRejected) {
      fail('temporary-fixture probe: an added bypass-bearing non-test Go file was NOT rejected by the dynamic source-tree scan');
      fixtureOk = false;
    } else ok('temporary-fixture PASS: added bypass-bearing non-test Go file rejected by the dynamic source-tree scan');
    // Fixture D: a migrations directory with an out-of-contract SQL mutation
    // (tampered trigger) must be rejected by the migration contract.
    const tamperedSql = ledgerSqlText.replace(/RAISE EXCEPTION 'AIPT_LEDGER_APPEND_ONLY'/, "RAISE EXCEPTION 'AIPT_LEDGER_TAMPERED'");
    const fixtureD = checkMigrationFiles([
      { filename: '000001_ledger.sql', content: tamperedSql },
      { filename: '000002_playtest_queue.sql', content: queueSqlText },
    ]);
    if (fixtureD.result !== 'FAIL') {
      fail('temporary-fixture probe: tampered append-only trigger was NOT rejected');
      fixtureOk = false;
    } else if (!fixtureD.details.some((d) => d.startsWith('FAIL') && (d.includes('SHA-256') || d.includes('AIPT_LEDGER_APPEND_ONLY')))) {
      fail('temporary-fixture probe: tampered trigger rejected for an unexpected reason');
      fixtureOk = false;
    } else {
      ok('temporary-fixture PASS: tampered append-only trigger in a temp migration rejected (checksum + contract)');
    }
    if (fixtureOk) ok('temporary-fixture probes all behaved fail-closed (clean copy PASS, missing verify.go FAIL, added bypass file FAIL, tampered migration FAIL)');
  } finally {
    fs.rmSync(probeDir, { recursive: true, force: true });
  }

  return { name: 'storage', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'storage', run);
