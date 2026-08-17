#!/usr/bin/env node
// B002 protocol-assets validator (iteration 3): proves the canonical protocol
// schema, the minimal deterministic fixture (including the persisted wire
// envelopes), and the required negative cases with a dependency-free JSON
// Schema 2020-12 subset validator.
//
// Gates (all fail closed):
//   1. Canonical schema document: parses, uses ONLY the explicit subset
//      supported by scripts/ci/lib/json-schema.mjs (any unsupported
//      functional keyword is rejected, never ignored), carries the frozen
//      version/method/visibility constants, resolves local $refs without
//      cycles, and has an EXECUTABLE root: a oneOf that accepts exactly the
//      registered wire envelopes (jsonrpc_request | jsonrpc_response |
//      jsonrpc_notification), never arbitrary JSON.
//   2. Fixture manifest (hardened BEFORE any asset read): schema-valid
//      against #/$defs/fixture_manifest; every entry path is safe
//      (relative, normalized, no absolute path, no dot segment, no
//      backslash) so no manifest entry can ever cause a read outside the
//      fixture dir; no duplicate asset/mutant paths; every kind maps to its
//      exact canonical schema_ref (the manifest-supplied $ref is never
//      trusted); the asset inventory is EXACT (every JSON file under the
//      fixture dir is listed and every listed file exists); every asset's
//      lowercase SHA-256 digest over canonical JSON matches, so unexpected
//      drift fails closed.
//   3. Every positive fixture asset validates against its declared $ref, and
//      every asset's protocol_version/schema_version/fixture_id equals the
//      frozen 1.0.0 / 1.0.0 / minimal-v1-arithmetic identity.
//   4. Semantics: exactly two seats (seat-a, seat-b); one PUBLIC field
//      visible to both and one TABLE_HIDDEN_REMOTE_ALLOWED field authorized
//      only to seat-a; the full-state projection contract (unique field ids
//      in state and projections, value equality with the source state,
//      authorization compared as a mathematical set, known seats only, and
//      no omitted authorized field); one generic action intent; one
//      deterministic versioned arithmetic check with fixed input/output;
//      one state transition and one event; the expected final state; a
//      SHA-256 replay assertion proving two replays yield the same final
//      state/hash.
//   5. Persisted wire envelopes under requests/ / responses/ /
//      notifications/: a valid applyAction request, its result response with
//      the same id VALUE AND JSON TYPE, a valid protocol error response for
//      the known request id using the documented implementation-choice
//      -32000 code with a stable AIPT_* data.error_code, and a valid
//      aipt.protocol.event notification embedding the exact existing
//      event.json. Request params cross-link to action-intent.json and the
//      result response cross-links to transition.json / final-state.json.
//   6. The hidden-leak mutant is validated against the schema FIRST (it must
//      be schema-valid), then semantically rejected for exactly
//      AIPT_VISIBILITY_UNAUTHORIZED_FIELD — never for unrelated JSON/schema
//      syntax reasons.
//   7. Negative probes, each rejected for the correct contract reason: the
//      nine frozen iteration-2 probes (jsonrpc != 2.0, unknown protocol
//      version, unknown schema version, missing request params,
//      result+error together, unknown method, missing visibility, unknown
//      visibility label, hidden-leak mutant) plus the iteration-3 root,
//      projection, manifest, and schema-helper probes.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { runAsMain } from '../lib/cli.mjs';
import { checkSchemaDocument, deepEqual, validateInstance, META_SCHEMA_URI } from '../lib/json-schema.mjs';
import { relOf, walkFiles } from '../lib/scan.mjs';

const SCHEMA_PATH = 'schemas/protocol/v1/aipt-protocol.schema.json';
const SCHEMA_URI = 'https://github.com/zyc14588/AIPT/schemas/protocol/v1/aipt-protocol.schema.json';
const FIXTURE_DIR = 'testdata/protocol/v1/minimal-fixture';
const PROTOCOL_VERSION = '1.0.0';
const SCHEMA_VERSION = '1.0.0';
const FIXTURE_ID = 'minimal-v1-arithmetic';
const METHOD_REQUEST = 'aipt.protocol.applyAction';
const METHOD_NOTIFICATION = 'aipt.protocol.event';
const VISIBILITY_UNAUTHORIZED_FIELD = 'AIPT_VISIBILITY_UNAUTHORIZED_FIELD';
const FROZEN_VISIBILITY_LABELS = [
  'PUBLIC',
  'UNRELEASED_REMOTE_ALLOWED',
  'TABLE_HIDDEN_REMOTE_ALLOWED',
  'LOCAL_ONLY_SECRET',
  'HUMAN_PRIVATE_DATA',
  'CREDENTIAL_SECRET',
];
const PUBLIC_FIELD_ID = 'turn-count';
const HIDDEN_FIELD_ID = 'table-note';
const HIDDEN_LABEL = 'TABLE_HIDDEN_REMOTE_ALLOWED';
const SEAT_A = 'seat-a';
const SEAT_B = 'seat-b';
const FINAL_STATE_REF = 'final-state.json';
const REPLAY_ASSERTION_REF = 'replay-assertion.json';
const WIRE_REQUEST_PATH = 'requests/apply-action-request.json';
const WIRE_RESULT_RESPONSE_PATH = 'responses/apply-action-result-response.json';
const WIRE_ERROR_RESPONSE_PATH = 'responses/apply-action-protocol-error-response.json';
const WIRE_NOTIFICATION_PATH = 'notifications/state-event-notification.json';
// B002_IMPLEMENTATION_CHOICE-009: the single documented, deterministic AIPT
// protocol error example. The schema leaves JSON-RPC `code` an unconstrained
// integer (it does NOT enforce a reserved range); the persisted example uses
// the conventional implementation-choice server/application code -32000 with
// the stable AIPT_* semantic namespace in data.error_code.
const PROTOCOL_ERROR_CODE = -32000;
const PROTOCOL_ERROR_CODE_NAME = VISIBILITY_UNAUTHORIZED_FIELD;

// Canonical JSON: arrays in order, object keys sorted recursively, minimal
// separators. Independent copy of the serializer used elsewhere so a shared
// defect cannot validate itself into PASS.
function canonicalJson(value) {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = canonicalJson(value[key]);
    return out;
  }
  return value;
}

function sha256Canonical(value) {
  return crypto.createHash('sha256').update(JSON.stringify(canonicalJson(value))).digest('hex');
}

// ---------------------------------------------------------------------------
// Manifest hardening (pure checks; no file access). These run BEFORE any
// manifest-listed file is resolved or read, and the negative probes exercise
// them self-contained (in-memory entries only).
// ---------------------------------------------------------------------------

// Exact kind -> canonical schema_ref mapping. The manifest-supplied $ref is
// never trusted: only this table decides which subschema validates a kind.
const KIND_SCHEMA_REF = {
  seat_set: '#/$defs/seat_set',
  state: '#/$defs/state',
  projection: '#/$defs/projection',
  action_intent: '#/$defs/action_intent',
  deterministic_check: '#/$defs/deterministic_check',
  state_transition: '#/$defs/state_transition',
  state_event: '#/$defs/state_event',
  replay_assertion: '#/$defs/replay_assertion',
  mutant_specimen: '#/$defs/mutant_specimen',
  jsonrpc_request: '#/$defs/jsonrpc_request',
  jsonrpc_response: '#/$defs/jsonrpc_response',
  jsonrpc_notification: '#/$defs/jsonrpc_notification',
};

// A manifest entry path must be relative, normalized, and free of absolute
// forms, dot segments, backslashes, or NULs — before it is ever resolved or
// read. Returns a problem string, or null when the path is safe.
function manifestPathProblem(p) {
  if (typeof p !== 'string' || p.length === 0) return 'unsafe manifest path: path must be a non-empty string';
  if (p.includes('\u0000')) return `unsafe manifest path: NUL byte in ${JSON.stringify(p)}`;
  if (path.isAbsolute(p)) return `unsafe manifest path: absolute path ${JSON.stringify(p)}`;
  if (p.includes('\\')) return `unsafe manifest path: backslash separator in ${JSON.stringify(p)}`;
  const segments = p.split('/');
  if (segments.some((seg) => seg === '..' || seg === '.')) {
    return `unsafe manifest path: dot segment in ${JSON.stringify(p)}`;
  }
  if (path.posix.normalize(p) !== p) return `unsafe manifest path: non-normalized path ${JSON.stringify(p)}`;
  return null;
}

function checkManifestPaths(entries) {
  const problems = [];
  for (const entry of entries) {
    const problem = manifestPathProblem(entry?.path);
    if (problem) problems.push(problem);
  }
  return problems;
}

function checkManifestDuplicates(entries) {
  const problems = [];
  const first = new Map();
  entries.forEach((entry, index) => {
    const p = entry?.path;
    if (typeof p !== 'string') return; // surfaced by checkManifestPaths
    if (first.has(p)) problems.push(`duplicate manifest path ${JSON.stringify(p)} (entry ${first.get(p) + 1} and entry ${index + 1})`);
    else first.set(p, index);
  });
  return problems;
}

function checkManifestKindRefs(entries) {
  const problems = [];
  for (const entry of entries) {
    const canonical = KIND_SCHEMA_REF[entry?.kind];
    if (canonical === undefined) problems.push(`manifest kind ${JSON.stringify(entry?.kind)} has no canonical schema_ref mapping`);
    else if (entry?.schema_ref !== canonical) {
      problems.push(`manifest kind ${JSON.stringify(entry.kind)} must map to exactly ${canonical}, got ${JSON.stringify(entry.schema_ref)}`);
    }
  }
  return problems;
}

// ---------------------------------------------------------------------------
// Projection / visibility semantics (schema validity alone is intentionally
// insufficient; all rejections use stable AIPT_* reasons).
// ---------------------------------------------------------------------------

// State field identity + authorization metadata: duplicate field_id values
// and visibility entries authorizing unknown seats are rejected.
function checkStateMetadata(state, knownSeats) {
  const reasons = [];
  if (!state || !Array.isArray(state.fields)) return ['AIPT_STATE_MISSING_FIELDS'];
  const seen = new Set();
  for (const field of state.fields) {
    if (seen.has(field.field_id)) reasons.push('AIPT_STATE_DUPLICATE_FIELD_ID');
    else seen.add(field.field_id);
    for (const seat of field?.visibility?.authorized_seat_ids ?? []) {
      if (!knownSeats.has(seat)) reasons.push('AIPT_VISIBILITY_UNKNOWN_SEAT');
    }
  }
  return reasons;
}

// Semantic gate for a projection over a state. Returns the list of stable
// AIPT_* rejection reasons; a valid projection returns [].
// Full-state projection contract:
//   - the projection seat must be a known seat (AIPT_PROJECTION_UNKNOWN_SEAT);
//   - no duplicate field_id in the projection (AIPT_PROJECTION_DUPLICATE_FIELD_ID);
//   - every projected field must exist in the state (AIPT_PROJECTION_UNKNOWN_FIELD);
//   - every projected field value must deep-equal the source value
//     (AIPT_PROJECTION_VALUE_DRIFT);
//   - the visibility label must not be reclassified (AIPT_VISIBILITY_RECLASSIFIED);
//   - authorized_seat_ids is compared as a mathematical SET, so ordering
//     alone is not authorization drift (AIPT_VISIBILITY_AUTHORIZATION_DRIFT);
//   - the projection seat must be authorized for the field
//     (AIPT_VISIBILITY_UNAUTHORIZED_FIELD);
//   - no field authorized to the projection seat may be omitted
//     (AIPT_PROJECTION_MISSING_AUTHORIZED_FIELD).
function checkProjection(state, projection, knownSeats) {
  const reasons = [];
  if (!projection || typeof projection !== 'object') return ['AIPT_PROJECTION_INVALID'];
  if (!knownSeats.has(projection.seat_id)) reasons.push('AIPT_PROJECTION_UNKNOWN_SEAT');
  const stateById = new Map();
  for (const field of state?.fields ?? []) {
    if (!stateById.has(field.field_id)) stateById.set(field.field_id, field);
  }
  const seen = new Set();
  for (const field of projection.fields ?? []) {
    if (seen.has(field.field_id)) reasons.push('AIPT_PROJECTION_DUPLICATE_FIELD_ID');
    else seen.add(field.field_id);
    const src = stateById.get(field.field_id);
    if (!src) {
      reasons.push('AIPT_PROJECTION_UNKNOWN_FIELD');
      continue;
    }
    if (!deepEqual(src.value, field.value)) reasons.push('AIPT_PROJECTION_VALUE_DRIFT');
    if (!deepEqual(src.visibility.label, field.visibility.label)) reasons.push('AIPT_VISIBILITY_RECLASSIFIED');
    const srcSet = [...(src.visibility.authorized_seat_ids ?? [])].sort();
    const projSet = [...(field.visibility.authorized_seat_ids ?? [])].sort();
    if (!deepEqual(srcSet, projSet)) reasons.push('AIPT_VISIBILITY_AUTHORIZATION_DRIFT');
    if (!(field.visibility?.authorized_seat_ids ?? []).includes(projection.seat_id)) {
      reasons.push(VISIBILITY_UNAUTHORIZED_FIELD);
    }
  }
  for (const field of state?.fields ?? []) {
    if ((field.visibility?.authorized_seat_ids ?? []).includes(projection.seat_id) && !seen.has(field.field_id)) {
      reasons.push('AIPT_PROJECTION_MISSING_AUTHORIZED_FIELD');
    }
  }
  return reasons;
}

// Deterministic transition application: a transition's result fields
// replace the matching state fields by field_id, and the state moves to the
// transition's to_state_id.
function applyTransition(state, transition) {
  const next = JSON.parse(JSON.stringify(state));
  next.state_id = transition.to_state_id;
  for (const patch of transition.result) {
    const idx = next.fields.findIndex((f) => f.field_id === patch.field_id);
    if (idx === -1) next.fields.push(JSON.parse(JSON.stringify(patch)));
    else next.fields[idx] = JSON.parse(JSON.stringify(patch));
  }
  return next;
}

function constOf(schemaDoc, defPath) {
  let node = schemaDoc;
  for (const part of defPath) {
    if (node === null || typeof node !== 'object') return undefined;
    node = node[part];
  }
  return node;
}

export function run(ctx) {
  const details = [];
  const negativeProbes = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const read = (rel) => fs.readFileSync(path.join(ctx.repo, rel), 'utf8');

  try {
    // ---------------------------------------------------------------
    // 1. Canonical schema document: subset conformance, frozen constants,
    //    and the executable (non-vacuous) root.
    // ---------------------------------------------------------------
    let schemaDoc;
    try {
      schemaDoc = JSON.parse(read(SCHEMA_PATH));
    } catch (err) {
      fail(`canonical schema unparseable: ${err.message}`);
      return { name: 'protocol-assets', result: 'FAIL', details, negative_probes: negativeProbes };
    }
    const meta = checkSchemaDocument(schemaDoc);
    if (!meta.valid) {
      for (const err of meta.errors) fail(`schema document subset violation: ${err}`);
    } else {
      ok('canonical schema document parses and uses ONLY the explicit dependency-free 2020-12 subset (no unsupported keyword, no bad local $ref, no ref cycle)');
    }
    if (schemaDoc.$id !== SCHEMA_URI) {
      fail(`canonical schema $id must be ${SCHEMA_URI}, got ${JSON.stringify(schemaDoc.$id)}`);
    } else ok('canonical schema $id is the single authoritative root URI');
    if (schemaDoc.$defs && typeof schemaDoc.$defs === 'object' && !Array.isArray(schemaDoc.$defs)) {
      ok(`${Object.keys(schemaDoc.$defs).length} local $defs carry all wire truth (no duplicated schemas)`);
    } else fail('canonical schema must carry local $defs at the root');
    const rootOneOf = constOf(schemaDoc, ['oneOf']);
    const expectedRootRefs = ['#/$defs/jsonrpc_request', '#/$defs/jsonrpc_response', '#/$defs/jsonrpc_notification'];
    if (
      Array.isArray(rootOneOf) &&
      rootOneOf.length === 3 &&
      deepEqual(rootOneOf.map((s) => s?.$ref).sort(), [...expectedRootRefs].sort())
    ) {
      ok('root is executable, not vacuous: oneOf accepts exactly jsonrpc_request | jsonrpc_response | jsonrpc_notification (local refs only)');
    } else {
      fail(`root must carry a oneOf over exactly ${expectedRootRefs.join(' | ')}, got ${JSON.stringify(rootOneOf?.map((s) => s?.$ref))}`);
    }
    for (const def of ['jsonrpc_request', 'jsonrpc_response', 'jsonrpc_notification']) {
      const req = constOf(schemaDoc, ['$defs', def, 'required']) ?? [];
      if (['protocol_version', 'schema_version', 'fixture_id'].every((k) => req.includes(k))) {
        ok(`${def} requires protocol_version + schema_version + fixture_id (persisted envelope identity)`);
      } else fail(`${def} must require protocol_version, schema_version, and fixture_id, got ${JSON.stringify(req)}`);
    }
    const frozenConsts = [
      [['$defs', 'protocol_version', 'const'], PROTOCOL_VERSION, 'protocol_version'],
      [['$defs', 'schema_version', 'const'], SCHEMA_VERSION, 'schema_version'],
      [['$defs', 'jsonrpc_version', 'const'], '2.0', 'jsonrpc'],
      [['$defs', 'jsonrpc_request', 'properties', 'method', 'const'], METHOD_REQUEST, 'request method registry'],
      [['$defs', 'jsonrpc_notification', 'properties', 'method', 'const'], METHOD_NOTIFICATION, 'notification method registry'],
    ];
    for (const [defPath, expected, label] of frozenConsts) {
      const actual = constOf(schemaDoc, defPath);
      if (actual !== expected) fail(`schema ${label} constant drifted: ${JSON.stringify(actual)} != ${JSON.stringify(expected)}`);
      else ok(`schema ${label} constant = ${JSON.stringify(expected)}`);
    }
    const labelsDef = constOf(schemaDoc, ['$defs', 'visibility_label', 'enum']);
    if (!Array.isArray(labelsDef) || !deepEqual(labelsDef, FROZEN_VISIBILITY_LABELS)) {
      fail(`visibility_label enum must be exactly the six frozen R4-F002 labels, got ${JSON.stringify(labelsDef)}`);
    } else ok('visibility_label enum = exactly the six frozen R4-F002 labels');
    const stateFieldRequired = constOf(schemaDoc, ['$defs', 'state_field', 'required']) ?? [];
    if (!stateFieldRequired.includes('visibility')) fail('state_field must require visibility (mandatory classification)');
    else ok('state_field requires visibility: classification is mandatory, never an optional ordinary field');
    const projectionRequired = constOf(schemaDoc, ['$defs', 'projection', 'required']) ?? [];
    if (!projectionRequired.includes('seat_id') || !projectionRequired.includes('fields')) {
      fail('projection must require seat_id and fields');
    } else ok('projection requires seat_id and fields (authorized projection metadata)');
    if (!Array.isArray(constOf(schemaDoc, ['$defs', 'jsonrpc_response', 'oneOf']))) {
      fail('jsonrpc_response must enforce result/error mutual exclusion via oneOf');
    } else ok('jsonrpc_response oneOf: result and error are mutually exclusive');
    if (!Array.isArray(constOf(schemaDoc, ['$defs', 'request_id', 'oneOf']))) {
      fail('request_id must be string or integer via oneOf');
    } else ok('request_id oneOf: string or integer only');
    const errorCodeSchema = constOf(schemaDoc, ['$defs', 'error_object', 'properties', 'code']);
    if (!errorCodeSchema || errorCodeSchema.type !== 'integer') {
      fail('error_object.code must be a plain integer (schema does NOT enforce a reserved range)');
    } else ok('error_object.code stays an unconstrained JSON-RPC integer; the documented deterministic example uses -32000 (CHOICE-009)');

    // ---------------------------------------------------------------
    // 2. Manifest: schema-valid; hardened paths/duplicates/kind->ref checks
    //    BEFORE any asset read; exact inventory; digests; identity.
    // ---------------------------------------------------------------
    const fixtureDir = path.join(ctx.repo, FIXTURE_DIR);
    let manifest;
    try {
      manifest = JSON.parse(read(`${FIXTURE_DIR}/manifest.json`));
    } catch (err) {
      fail(`fixture manifest unparseable: ${err.message}`);
      return { name: 'protocol-assets', result: 'FAIL', details, negative_probes: negativeProbes };
    }
    const manifestCheck = validateInstance(schemaDoc, manifest, { ref: '#/$defs/fixture_manifest' });
    if (!manifestCheck.valid) {
      for (const err of manifestCheck.errors.slice(0, 8)) fail(`manifest schema violation: ${err.message}`);
    } else ok('fixture manifest is schema-valid against #/$defs/fixture_manifest');
    if (manifest.protocol_version !== PROTOCOL_VERSION || manifest.schema_version !== SCHEMA_VERSION || manifest.fixture_id !== FIXTURE_ID) {
      fail(`manifest identity drifted: ${manifest.protocol_version} / ${manifest.schema_version} / ${manifest.fixture_id}`);
    } else ok(`manifest identity = ${PROTOCOL_VERSION} / ${SCHEMA_VERSION} / ${FIXTURE_ID}`);
    if (manifest.expected_final_state !== FINAL_STATE_REF || manifest.replay_assertion !== REPLAY_ASSERTION_REF) {
      fail('manifest must point at final-state.json / replay-assertion.json');
    } else ok('manifest names the expected final state and the replay assertion');

    const manifestEntries = [...(manifest.assets ?? []), ...(manifest.mutants ?? [])];
    // Path safety, duplicate paths, and exact kind -> schema_ref mapping are
    // enforced BEFORE any listed file is resolved or read.
    const pathProblems = checkManifestPaths(manifestEntries);
    if (pathProblems.length > 0) {
      for (const problem of pathProblems) fail(problem);
    } else ok('every manifest entry path is relative, normalized, and free of absolute/dot-segment/backslash forms (checked before any read)');
    const dupProblems = checkManifestDuplicates(manifestEntries);
    if (dupProblems.length > 0) {
      for (const problem of dupProblems) fail(problem);
    } else ok('no duplicate asset/mutant paths in the manifest');
    const kindRefProblems = checkManifestKindRefs(manifestEntries);
    if (kindRefProblems.length > 0) {
      for (const problem of kindRefProblems) fail(problem);
    } else ok('every manifest kind maps to its exact canonical schema_ref (the manifest-supplied $ref is not trusted)');

    // Exact inventory: every JSON file under the fixture dir must be listed
    // (assets + mutants + the manifest itself), and every listed file must
    // exist inside the fixture dir.
    const onDisk = walkFiles(fixtureDir, (f) => f.endsWith('.json')).map((f) => relOf(fixtureDir, f)).sort();
    const listed = [
      ...(manifest.assets ?? []).map((a) => a.path),
      ...(manifest.mutants ?? []).map((m) => m.path),
      'manifest.json',
    ].sort();
    const diskSet = new Set(onDisk);
    const listedSet = new Set(listed);
    const unlisted = onDisk.filter((p) => !listedSet.has(p));
    const missing = listed.filter((p) => !diskSet.has(p));
    if (unlisted.length > 0) fail(`fixture inventory has UNLISTED files (drift fails closed): ${unlisted.join(', ')}`);
    if (missing.length > 0) fail(`fixture inventory has MISSING files: ${missing.join(', ')}`);
    if (unlisted.length === 0 && missing.length === 0) {
      ok(`exact fixture inventory: ${onDisk.length} JSON files on disk == ${listed.length} listed (assets + mutants + manifest)`);
    }

    // Per-asset digest + schema validation + identity consistency.
    const assetDocs = new Map();
    for (const entry of manifestEntries) {
      // Defense-in-depth: even after the pre-read path checks, the resolved
      // path must stay inside the fixture dir before any read happens.
      const resolvedPath = path.resolve(fixtureDir, ...entry.path.split('/'));
      if (!resolvedPath.startsWith(fixtureDir + path.sep)) {
        fail(`manifest entry ${entry.path} resolves outside the fixture dir (read refused)`);
        continue;
      }
      if (!fs.existsSync(resolvedPath)) {
        fail(`listed fixture asset does not exist: ${entry.path}`);
        continue;
      }
      let doc;
      try {
        doc = JSON.parse(fs.readFileSync(resolvedPath, 'utf8'));
      } catch (err) {
        fail(`fixture asset ${entry.path} is not valid JSON: ${err.message}`);
        continue;
      }
      const digest = sha256Canonical(doc);
      if (digest !== entry.sha256) {
        fail(`fixture asset ${entry.path} digest drifted: got ${digest}, manifest says ${entry.sha256} (drift fails closed)`);
      } else ok(`fixture asset ${entry.path} digest matches manifest (${digest.slice(0, 12)}…)`);
      assetDocs.set(entry.path, doc);
      const inst = validateInstance(schemaDoc, doc, { ref: entry.schema_ref });
      if (!inst.valid) {
        for (const err of inst.errors.slice(0, 6)) fail(`fixture asset ${entry.path} violates ${entry.schema_ref}: ${err.message}`);
      } else if (entry.kind === 'mutant_specimen') {
        ok(`mutant ${entry.path} is schema-valid against ${entry.schema_ref} (schema-first gate, before semantic rejection)`);
      } else {
        ok(`fixture asset ${entry.path} is schema-valid against ${entry.schema_ref}`);
      }
      if (entry.kind !== 'mutant_specimen' && doc && typeof doc === 'object') {
        if (doc.protocol_version !== PROTOCOL_VERSION || doc.schema_version !== SCHEMA_VERSION || doc.fixture_id !== FIXTURE_ID) {
          fail(`fixture asset ${entry.path} identity drifted: ${JSON.stringify(doc.protocol_version)} / ${JSON.stringify(doc.schema_version)} / ${JSON.stringify(doc.fixture_id)}`);
        }
      }
    }
    const identityOk = [...assetDocs.entries()].every(([p, doc]) => {
      if (p.startsWith('mutants/')) {
        const inner = doc?.projection;
        return inner && inner.protocol_version === PROTOCOL_VERSION && inner.schema_version === SCHEMA_VERSION && inner.fixture_id === FIXTURE_ID;
      }
      return doc && doc.protocol_version === PROTOCOL_VERSION && doc.schema_version === SCHEMA_VERSION && doc.fixture_id === FIXTURE_ID;
    });
    if (identityOk) ok(`every fixture asset (and the mutant's inner projection) carries identity ${PROTOCOL_VERSION} / ${SCHEMA_VERSION} / ${FIXTURE_ID}`);

    // ---------------------------------------------------------------
    // 3. Fixture semantics.
    // ---------------------------------------------------------------
    const seats = assetDocs.get('seats.json');
    let knownSeats = new Set();
    if (seats && Array.isArray(seats.seats) && seats.seats.length === 2) {
      const ids = seats.seats.map((s) => s.seat_id).sort();
      if (ids[0] !== SEAT_A || ids[1] !== SEAT_B) fail(`seats must be exactly seat-a and seat-b, got ${JSON.stringify(ids)}`);
      else ok('exactly two seats: seat-a, seat-b');
      knownSeats = new Set(ids);
    } else fail('seats.json must carry exactly two seats');

    const state = assetDocs.get('state.json');
    const stateFields = state?.fields ?? [];
    const fieldIds = stateFields.map((f) => f.field_id).sort();
    if (fieldIds.length !== 2 || fieldIds[0] !== HIDDEN_FIELD_ID || fieldIds[1] !== PUBLIC_FIELD_ID) {
      fail(`initial state must have exactly the fields ${HIDDEN_FIELD_ID} and ${PUBLIC_FIELD_ID}, got ${JSON.stringify(fieldIds)}`);
    } else ok('initial state has exactly two fields (turn-count, table-note)');
    const publicField = stateFields.find((f) => f.field_id === PUBLIC_FIELD_ID);
    const hiddenField = stateFields.find((f) => f.field_id === HIDDEN_FIELD_ID);
    const seatSet = (f) => [...f.visibility.authorized_seat_ids].sort().join(',');
    if (publicField?.visibility?.label === 'PUBLIC' && seatSet(publicField) === `${SEAT_A},${SEAT_B}`) {
      ok('one PUBLIC state field (turn-count) visible to both seats');
    } else fail('turn-count must be PUBLIC with authorized_seat_ids = [seat-a, seat-b]');
    if (hiddenField?.visibility?.label === HIDDEN_LABEL && seatSet(hiddenField) === SEAT_A) {
      ok(`one ${HIDDEN_LABEL} field (table-note) authorized only to seat-a`);
    } else fail(`table-note must be ${HIDDEN_LABEL} with authorized_seat_ids = [seat-a]`);
    const allClassified = stateFields.every(
      (f) => f.visibility && FROZEN_VISIBILITY_LABELS.includes(f.visibility.label) && Array.isArray(f.visibility.authorized_seat_ids) && f.visibility.authorized_seat_ids.length > 0,
    );
    if (allClassified) ok('every state field carries an explicit frozen visibility label and a non-empty authorized_seat_ids');
    const stateMetaReasons = checkStateMetadata(state, knownSeats);
    if (stateMetaReasons.length > 0) fail(`initial state violates field/visibility metadata: ${stateMetaReasons.join(', ')}`);
    else ok('initial state has unique field_ids and authorizes only known seats');

    for (const [projPath, expectedSeat, expectedFields] of [
      ['projection-seat-a.json', SEAT_A, [PUBLIC_FIELD_ID, HIDDEN_FIELD_ID]],
      ['projection-seat-b.json', SEAT_B, [PUBLIC_FIELD_ID]],
    ]) {
      const proj = assetDocs.get(projPath);
      if (!proj) continue;
      if (proj.seat_id !== expectedSeat) fail(`${projPath} seat_id must be ${expectedSeat}`);
      else ok(`${projPath} declares seat ${expectedSeat}`);
      const projFieldIds = proj.fields.map((f) => f.field_id).sort();
      if (!deepEqual(projFieldIds, [...expectedFields].sort())) {
        fail(`${projPath} must project exactly [${expectedFields.join(', ')}], got [${projFieldIds.join(', ')}]`);
      } else ok(`${projPath} projects exactly [${expectedFields.join(', ')}]`);
      const reasons = checkProjection(state, proj, knownSeats);
      if (reasons.length > 0) fail(`${projPath} violates the full-state projection gate: ${reasons.join(', ')}`);
      else ok(`${projPath} passes the full-state projection gate (known seat, unique ids, value equality, set-compared authorization, no omitted authorized field)`);
    }
    // Set semantics proof: reordering authorized_seat_ids alone is NOT
    // authorization drift.
    const projA = assetDocs.get('projection-seat-a.json');
    if (state && projA && projA.fields?.[0]?.visibility?.authorized_seat_ids) {
      const reordered = JSON.parse(JSON.stringify(projA));
      reordered.fields[0].visibility.authorized_seat_ids.reverse();
      const reorderedReasons = checkProjection(state, reordered, knownSeats);
      if (reorderedReasons.includes('AIPT_VISIBILITY_AUTHORIZATION_DRIFT')) {
        fail('authorized_seat_ids reordering must NOT be authorization drift (mathematical set semantics)');
      } else ok('authorized_seat_ids compared as a mathematical set: ordering alone is not authorization drift');
    }

    const intent = assetDocs.get('action-intent.json');
    if (intent?.method !== METHOD_REQUEST) fail(`action intent method must be ${METHOD_REQUEST}`);
    else ok(`one generic action intent with method ${METHOD_REQUEST}`);
    if (intent?.params?.action !== 'advance-turn' || intent?.params?.seat_id !== SEAT_A) {
      fail('action intent must propose advance-turn from seat-a');
    } else ok('action intent proposes advance-turn from seat-a (with proposal payload)');

    const check = assetDocs.get('check-turn-increment.json');
    if (check?.kind !== 'arithmetic' || check?.operator !== 'add' || check?.check_version !== '1.0.0') {
      fail('deterministic check must be the versioned arithmetic add check');
    } else ok('one deterministic versioned arithmetic check (check_version 1.0.0, operator add)');
    if (!deepEqual(check?.inputs, [0, 1]) || check?.output !== 1) {
      fail(`deterministic check must carry fixed inputs [0, 1] and output 1, got ${JSON.stringify(check?.inputs)} / ${JSON.stringify(check?.output)}`);
    } else ok('deterministic check has fixed input [0, 1] and fixed output 1');
    if (check && Array.isArray(check.inputs) && check.inputs.reduce((acc, n) => acc + n, 0) === check.output) {
      ok('check output recomputes deterministically from its inputs (0 + 1 = 1)');
    } else fail('check output does not recompute from its inputs');

    const transition = assetDocs.get('transition.json');
    const finalState = assetDocs.get('final-state.json');
    if (transition?.from_state_id === state?.state_id && transition?.to_state_id === finalState?.state_id) {
      ok(`one state transition initial -> final (${transition.transition_id})`);
    } else fail('transition must move initial -> final');
    if (transition?.applied_action?.action === intent?.params?.action && transition?.applied_action?.seat_id === SEAT_A) {
      ok('transition applies the action intent (advance-turn, seat-a)');
    } else fail('transition applied_action must match the action intent');
    if (state && transition && finalState) {
      const next = applyTransition(state, transition);
      if (deepEqual(next.fields, finalState.fields)) {
        ok('transition result applied to the initial state yields the expected final state exactly');
      } else fail('transition result applied to the initial state does NOT yield final-state.json');
      if (transition.result.length === 1 && transition.result[0].field_id === PUBLIC_FIELD_ID && transition.result[0].value === 1) {
        ok('transition result updates exactly turn-count to 1');
      } else fail('transition result must update exactly turn-count to 1');
      const finalMetaReasons = checkStateMetadata(finalState, knownSeats);
      if (finalMetaReasons.length > 0) fail(`final state violates field/visibility metadata: ${finalMetaReasons.join(', ')}`);
      else ok('final state has unique field_ids and authorizes only known seats');
    }

    const event = assetDocs.get('event.json');
    if (event?.transition_id === transition?.transition_id && event?.event_type === 'state_transition_applied') {
      ok(`one state event (${event.event_id}) tied to the transition`);
    } else fail('event must reference the transition with event_type state_transition_applied');
    if (event?.payload?.from_state_id === 'initial' && event?.payload?.to_state_id === 'final') {
      ok('event payload records initial -> final');
    } else fail('event payload must record initial -> final');

    // Replay assertion + determinism.
    const assertion = assetDocs.get('replay-assertion.json');
    if (assertion?.hash_algorithm !== 'sha256' || assertion?.final_state_ref !== FINAL_STATE_REF) {
      fail('replay assertion must use sha256 over final-state.json');
    } else ok('replay assertion uses SHA-256 over canonical JSON of final-state.json');
    if (finalState && assertion) {
      const computed = sha256Canonical(finalState);
      if (computed !== assertion.final_state_hash) {
        fail(`replay assertion final_state_hash drifted: computed ${computed}, asserted ${assertion.final_state_hash}`);
      } else ok(`replay assertion final_state_hash matches the recomputed canonical-JSON SHA-256 (${computed.slice(0, 12)}…)`);
      const replays = assertion.replays ?? [];
      if (replays.length !== 2) fail('replay assertion must carry exactly two replay records');
      else if (replays.every((r) => r.final_state_hash === computed)) {
        ok('both replay records carry the same final state hash');
      } else fail('replay records must all equal the recomputed final state hash');
      if (state && transition) {
        const r1 = applyTransition(state, transition);
        const r2 = applyTransition(state, transition);
        const h1 = sha256Canonical(r1);
        const h2 = sha256Canonical(r2);
        if (deepEqual(r1.fields, r2.fields) && h1 === h2 && h1 === computed) {
          ok(`two independent in-memory replays yield the same final state/hash (${h1.slice(0, 12)}…) — determinism proven`);
        } else fail('two in-memory replays diverged (determinism violated)');
      }
    }

    // ---------------------------------------------------------------
    // 4. Persisted wire envelopes: loaded from disk (never recreated
    //    in memory), schema-valid against their declared refs (done in the
    //    per-asset loop), and cross-linked into one coherent contract.
    // ---------------------------------------------------------------
    const wireRequest = assetDocs.get(WIRE_REQUEST_PATH);
    const resultResponse = assetDocs.get(WIRE_RESULT_RESPONSE_PATH);
    const errorResponse = assetDocs.get(WIRE_ERROR_RESPONSE_PATH);
    const wireNotification = assetDocs.get(WIRE_NOTIFICATION_PATH);

    if (!wireRequest) fail(`persisted wire request missing: ${WIRE_REQUEST_PATH}`);
    else {
      if (wireRequest.method !== METHOD_REQUEST) fail(`persisted wire request method must be ${METHOD_REQUEST}`);
      else ok(`persisted request ${WIRE_REQUEST_PATH} is a valid ${METHOD_REQUEST} envelope`);
      if (intent && deepEqual(wireRequest.params, intent.params)) {
        ok('persisted request params deep-equal action-intent.json params (cross-linked coherent contract)');
      } else fail('persisted request params must deep-equal action-intent.json params');
      if (intent && wireRequest.method === intent.method) {
        ok('persisted request method matches action-intent.json method');
      } else fail('persisted request method must match action-intent.json method');
      const rootOk = validateInstance(schemaDoc, wireRequest, { ref: '#' });
      if (rootOk.valid) ok(`persisted request also validates against the executable root "#" (${rootOk.errors.length} errors)`);
      else fail(`persisted request must validate against the executable root "#": ${rootOk.errors[0]?.message}`);
    }

    if (!resultResponse) fail(`persisted result response missing: ${WIRE_RESULT_RESPONSE_PATH}`);
    else if (!wireRequest) fail('cannot prove result-response round-trip: persisted request missing');
    else {
      const sameId = deepEqual(resultResponse.id, wireRequest.id) && typeof resultResponse.id === typeof wireRequest.id;
      if (sameId) {
        ok(`persisted result response id round-trips the request id VALUE and JSON TYPE (${JSON.stringify(wireRequest.id)} as ${typeof wireRequest.id})`);
      } else fail(`persisted result response id ${JSON.stringify(resultResponse.id)} (${typeof resultResponse.id}) must equal the request id ${JSON.stringify(wireRequest.id)} (${typeof wireRequest.id}) in value and type`);
      if (resultResponse.result?.accepted === true) ok('persisted result response carries accepted = true');
      else fail('persisted result response result.accepted must be true');
      if (transition && resultResponse.result?.transition_id === transition.transition_id) {
        ok(`persisted result response transition_id cross-links to transition.json (${transition.transition_id})`);
      } else fail('persisted result response transition_id must equal transition.json transition_id');
      if (transition && deepEqual(resultResponse.result?.applied_fields, transition.result)) {
        ok('persisted result response applied_fields deep-equal transition.json result');
      } else fail('persisted result response applied_fields must deep-equal transition.json result');
      if (finalState && Array.isArray(resultResponse.result?.applied_fields)) {
        const finalById = new Map(finalState.fields.map((f) => [f.field_id, f]));
        const allLinked = resultResponse.result.applied_fields.every((af) => {
          const ff = finalById.get(af.field_id);
          return ff && deepEqual(ff.value, af.value) && deepEqual(ff.visibility, af.visibility);
        });
        if (allLinked) ok('persisted result response applied_fields match final-state.json values and visibility (cross-linked)');
        else fail('persisted result response applied_fields must match final-state.json values and visibility');
      }
      const rootOk = validateInstance(schemaDoc, resultResponse, { ref: '#' });
      if (rootOk.valid) ok('persisted result response also validates against the executable root "#"');
      else fail(`persisted result response must validate against the executable root "#": ${rootOk.errors[0]?.message}`);
    }

    if (!errorResponse) fail(`persisted protocol error response missing: ${WIRE_ERROR_RESPONSE_PATH}`);
    else if (!wireRequest) fail('cannot prove error-response identity: persisted request missing');
    else {
      const sameId = deepEqual(errorResponse.id, wireRequest.id) && typeof errorResponse.id === typeof wireRequest.id;
      if (sameId) ok('persisted error response carries the known request id (value and JSON type)');
      else fail(`persisted error response id must equal the known request id ${JSON.stringify(wireRequest.id)} (value and type)`);
      if (errorResponse.error?.code === PROTOCOL_ERROR_CODE) {
        ok(`persisted AIPT semantic error uses the documented implementation-choice code ${PROTOCOL_ERROR_CODE} (CHOICE-009)`);
      } else fail(`persisted AIPT semantic error code must be ${PROTOCOL_ERROR_CODE}, got ${JSON.stringify(errorResponse.error?.code)}`);
      if (errorResponse.error?.data?.error_code === PROTOCOL_ERROR_CODE_NAME) {
        ok(`persisted AIPT semantic error carries the stable ${PROTOCOL_ERROR_CODE_NAME} in data.error_code`);
      } else fail(`persisted AIPT semantic error data.error_code must be ${PROTOCOL_ERROR_CODE_NAME}, got ${JSON.stringify(errorResponse.error?.data?.error_code)}`);
      if (typeof errorResponse.error?.message === 'string' && errorResponse.error.message.length > 0) {
        ok('persisted AIPT semantic error carries a deterministic human-readable message');
      } else fail('persisted AIPT semantic error must carry a non-empty message');
      const rootOk = validateInstance(schemaDoc, errorResponse, { ref: '#' });
      if (rootOk.valid) ok('persisted protocol error response also validates against the executable root "#"');
      else fail(`persisted protocol error response must validate against the executable root "#": ${rootOk.errors[0]?.message}`);
    }

    if (!wireNotification) fail(`persisted wire notification missing: ${WIRE_NOTIFICATION_PATH}`);
    else {
      if (wireNotification.method !== METHOD_NOTIFICATION) fail(`persisted notification method must be ${METHOD_NOTIFICATION}`);
      else ok(`persisted notification ${WIRE_NOTIFICATION_PATH} is a valid ${METHOD_NOTIFICATION} envelope`);
      if (event && deepEqual(wireNotification.params?.event, event)) {
        ok('persisted notification embeds the EXACT existing event.json (deep-equal, loaded from disk)');
      } else fail('persisted notification params.event must deep-equal the existing event.json');
      const rootOk = validateInstance(schemaDoc, wireNotification, { ref: '#' });
      if (rootOk.valid) ok('persisted notification also validates against the executable root "#"');
      else fail(`persisted notification must validate against the executable root "#": ${rootOk.errors[0]?.message}`);
    }

    // ---------------------------------------------------------------
    // 5. Hidden-leak mutant: schema first, then semantic rejection.
    // ---------------------------------------------------------------
    const mutantEntry = (manifest.mutants ?? [])[0];
    const mutant = mutantEntry ? assetDocs.get(mutantEntry.path) : undefined;
    if (!mutantEntry || !mutant) {
      fail('hidden-leak mutant missing from manifest or disk');
    } else {
      if (!mutantEntry.path.startsWith('mutants/')) fail('mutant must live only under mutants/');
      else ok('mutant exists only under mutants/');
      if (mutantEntry.expected_semantic_rejection !== VISIBILITY_UNAUTHORIZED_FIELD) {
        fail(`mutant expected_semantic_rejection must be ${VISIBILITY_UNAUTHORIZED_FIELD}`);
      } else ok(`mutant manifest entry declares expected_semantic_rejection = ${VISIBILITY_UNAUTHORIZED_FIELD}`);
      if (!deepEqual(mutant.markers, ['NON_CANON', 'MUTANT']) || mutant.kind !== 'hidden-leak') {
        fail('mutant must carry the exact NON_CANON / MUTANT markers and kind hidden-leak');
      } else ok('mutant carries explicit NON_CANON and MUTANT markers (kind hidden-leak)');
      const inner = mutant.projection;
      if (inner?.seat_id !== SEAT_B || mutant.seat_id !== SEAT_B) {
        fail('hidden-leak mutant must be a seat-b projection');
      } else ok('hidden-leak mutant is a seat-b projection');
      if (mutant.leaked_field_id !== HIDDEN_FIELD_ID) {
        fail(`mutant leaked_field_id must be ${HIDDEN_FIELD_ID}`);
      } else ok(`mutant identifies the leaked field ${HIDDEN_FIELD_ID}`);
      const leakPresent = inner?.fields?.some((f) => f.field_id === HIDDEN_FIELD_ID) === true;
      if (!leakPresent) fail(`mutant must actually place ${HIDDEN_FIELD_ID} in the seat-b projection`);
      else ok(`mutant places seat-a's hidden field ${HIDDEN_FIELD_ID} in the seat-b projection`);
      const reasons = state && inner ? checkProjection(state, inner, knownSeats) : ['fixture-missing'];
      if (reasons.length !== 1 || reasons[0] !== VISIBILITY_UNAUTHORIZED_FIELD) {
        fail(`mutant must be rejected specifically with exactly one reason ${VISIBILITY_UNAUTHORIZED_FIELD}, got ${JSON.stringify(reasons)}`);
        negativeProbes.push({ label: 'hidden-leak mutant (mutants/hidden-leak.json)', result: 'FAIL', schema_valid: true, reason: JSON.stringify(reasons) });
      } else {
        ok(`mutant rejected specifically with exactly one reason ${VISIBILITY_UNAUTHORIZED_FIELD} (schema-valid, semantically unauthorized)`);
        negativeProbes.push({ label: 'hidden-leak mutant (mutants/hidden-leak.json)', result: 'PASS', schema_valid: true, reason: VISIBILITY_UNAUTHORIZED_FIELD });
      }
    }

    // ---------------------------------------------------------------
    // 6. Request/response identity: id round-trip and method registry.
    // ---------------------------------------------------------------
    const baseParams = { action: 'advance-turn', seat_id: SEAT_A };
    const makeRequest = (id) => ({
      jsonrpc: '2.0',
      id,
      method: METHOD_REQUEST,
      params: baseParams,
      protocol_version: PROTOCOL_VERSION,
      schema_version: SCHEMA_VERSION,
      fixture_id: FIXTURE_ID,
    });
    const makeResult = () => ({
      accepted: true,
      transition_id: 'transition-turn-increment',
      applied_fields: [
        {
          field_id: PUBLIC_FIELD_ID,
          value: 1,
          visibility: { label: 'PUBLIC', authorized_seat_ids: [SEAT_A, SEAT_B] },
        },
      ],
    });
    const makeResponse = (id, { result, error } = {}) => ({
      jsonrpc: '2.0',
      id,
      protocol_version: PROTOCOL_VERSION,
      schema_version: SCHEMA_VERSION,
      fixture_id: FIXTURE_ID,
      ...(result !== undefined ? { result } : {}),
      ...(error !== undefined ? { error } : {}),
    });
    let roundTripOk = true;
    for (const id of ['minimal-v1-arithmetic-request-1', 42]) {
      const req = makeRequest(id);
      const reqCheck = validateInstance(schemaDoc, req, { ref: '#/$defs/jsonrpc_request' });
      const res = makeResponse(id, { result: makeResult() });
      const resCheck = validateInstance(schemaDoc, res, { ref: '#/$defs/jsonrpc_response' });
      const roundTripped = reqCheck.valid && resCheck.valid && deepEqual(res.id, req.id) && typeof res.id === typeof req.id;
      if (!roundTripped) {
        roundTripOk = false;
        fail(`request/response id round-trip failed for id ${JSON.stringify(id)} (request valid=${reqCheck.valid}, response valid=${resCheck.valid})`);
      } else ok(`request/response id ${JSON.stringify(id)} (${typeof id}) validates and round-trips verbatim`);
    }
    if (roundTripOk) ok('request/response ids are string or integer and round-trip');
    const eventFixture = assetDocs.get('event.json');
    const notification = {
      jsonrpc: '2.0',
      method: METHOD_NOTIFICATION,
      params: { event: eventFixture },
      protocol_version: PROTOCOL_VERSION,
      schema_version: SCHEMA_VERSION,
      fixture_id: FIXTURE_ID,
    };
    const notificationCheck = validateInstance(schemaDoc, notification, { ref: '#/$defs/jsonrpc_notification' });
    if (!notificationCheck.valid) fail(`registered notification (${METHOD_NOTIFICATION}) must validate: ${notificationCheck.errors[0]?.message}`);
    else ok(`registered notification method ${METHOD_NOTIFICATION} validates with the fixture event`);
    const errResponse = makeResponse('minimal-v1-arithmetic-request-1', {
      error: { code: -32602, message: 'invalid params', data: { error_code: VISIBILITY_UNAUTHORIZED_FIELD } },
    });
    const errCheck = validateInstance(schemaDoc, errResponse, { ref: '#/$defs/jsonrpc_response' });
    if (!errCheck.valid) fail(`error response must validate: ${errCheck.errors[0]?.message}`);
    else ok(`error response validates with AIPT_* error namespace in data.error_code`);

    // ---------------------------------------------------------------
    // 7. Negative probes: each must be rejected for the correct reason.
    //    The first eight are the frozen iteration-2 probes; the mutant probe
    //    was recorded above; the remainder are the iteration-3 root,
    //    projection, manifest, and schema-helper probes.
    // ---------------------------------------------------------------
    const schemaProbe = (ref) => (instance) => {
      const res = validateInstance(schemaDoc, instance, { ref });
      return { valid: res.valid, messages: res.errors.map((e) => e.message) };
    };
    const semanticProbe = (reasonsFn) => {
      const reasons = reasonsFn();
      return reasons.length === 0 ? { valid: true, messages: [] } : { valid: false, messages: reasons };
    };
    const metaProbe = (doc) => {
      const res = checkSchemaDocument(doc);
      return { valid: res.valid, messages: res.errors };
    };
    const probeEntry = (over = {}) => ({
      path: 'probe.json',
      kind: 'state',
      schema_ref: '#/$defs/state',
      sha256: '0'.repeat(64),
      ...over,
    });
    const probeField = (over = {}) => ({
      field_id: PUBLIC_FIELD_ID,
      value: 0,
      visibility: { label: 'PUBLIC', authorized_seat_ids: [SEAT_A, SEAT_B] },
      ...over,
    });
    const hiddenFieldProbe = {
      field_id: HIDDEN_FIELD_ID,
      value: 'alpha',
      visibility: { label: HIDDEN_LABEL, authorized_seat_ids: [SEAT_A] },
    };
    const makeProbeState = (fields) => ({
      protocol_version: PROTOCOL_VERSION,
      schema_version: SCHEMA_VERSION,
      fixture_id: FIXTURE_ID,
      state_id: 'probe-state',
      fields,
    });
    const makeProbeProjection = (seatId, fields) => ({
      protocol_version: PROTOCOL_VERSION,
      schema_version: SCHEMA_VERSION,
      fixture_id: FIXTURE_ID,
      projection_id: 'probe-projection',
      seat_id: seatId,
      fields,
    });

    const probes = [
      {
        label: 'jsonrpc != 2.0',
        reason: /\/jsonrpc/,
        run: () => schemaProbe('#/$defs/jsonrpc_request')({ ...makeRequest('probe-jsonrpc'), jsonrpc: '1.0' }),
      },
      {
        label: 'unknown protocol version',
        reason: /\/protocol_version/,
        run: () => schemaProbe('#/$defs/jsonrpc_request')({ ...makeRequest('probe-protocol'), protocol_version: '9.9.9' }),
      },
      {
        label: 'unknown schema version',
        reason: /\/schema_version/,
        run: () => schemaProbe('#/$defs/jsonrpc_request')({ ...makeRequest('probe-schema'), schema_version: '9.9.9' }),
      },
      {
        label: 'request missing required params',
        reason: /params/,
        run: () => {
          const req = makeRequest('probe-no-params');
          delete req.params;
          return schemaProbe('#/$defs/jsonrpc_request')(req);
        },
      },
      {
        label: 'response carrying result and error together',
        reason: /oneOf/,
        run: () => schemaProbe('#/$defs/jsonrpc_response')(
          makeResponse('probe-both', { result: makeResult(), error: { code: -32603, message: 'internal error' } }),
        ),
      },
      {
        label: 'unknown method',
        reason: /\/method/,
        run: () => schemaProbe('#/$defs/jsonrpc_request')({ ...makeRequest('probe-method'), method: 'aipt.protocol.workerLifecycle' }),
      },
      {
        label: 'missing visibility information',
        reason: /visibility/,
        run: () => schemaProbe('#/$defs/state')(
          makeProbeState([{ field_id: 'x-field', value: 1 }]),
        ),
      },
      {
        label: 'unknown visibility label',
        reason: /label/,
        run: () => schemaProbe('#/$defs/state')(
          makeProbeState([{ field_id: 'x-field', value: 1, visibility: { label: 'TEAM_ONLY', authorized_seat_ids: [SEAT_A] } }]),
        ),
      },
      {
        label: 'arbitrary/malformed object against the executable schema root (#)',
        reason: /oneOf/,
        run: () => schemaProbe('#')({ hello: 'world', jsonrpc: '2.0' }),
      },
      {
        label: 'duplicate field_id values in the source state',
        reason: /AIPT_STATE_DUPLICATE_FIELD_ID/,
        run: () => semanticProbe(() => checkStateMetadata(makeProbeState([probeField(), probeField()]), knownSeats)),
      },
      {
        label: 'duplicate field_id values in a projection',
        reason: /AIPT_PROJECTION_DUPLICATE_FIELD_ID/,
        run: () => semanticProbe(() =>
          checkProjection(state, makeProbeProjection(SEAT_A, [probeField(), hiddenFieldProbe, probeField()]), knownSeats)),
      },
      {
        label: 'projection value drift (value != source state value)',
        reason: /AIPT_PROJECTION_VALUE_DRIFT/,
        run: () => semanticProbe(() =>
          checkProjection(state, makeProbeProjection(SEAT_A, [probeField({ value: 5 }), hiddenFieldProbe]), knownSeats)),
      },
      {
        label: 'unknown projection seat',
        reason: /AIPT_PROJECTION_UNKNOWN_SEAT/,
        run: () => semanticProbe(() =>
          checkProjection(state, makeProbeProjection('seat-ghost', [probeField()]), knownSeats)),
      },
      {
        label: 'state visibility authorizes an unknown seat',
        reason: /AIPT_VISIBILITY_UNKNOWN_SEAT/,
        run: () => semanticProbe(() =>
          checkStateMetadata(makeProbeState([probeField({ visibility: { label: 'PUBLIC', authorized_seat_ids: ['seat-ghost'] } })]), knownSeats)),
      },
      {
        label: 'projection omits a field authorized to the projection seat',
        reason: /AIPT_PROJECTION_MISSING_AUTHORIZED_FIELD/,
        run: () => semanticProbe(() =>
          checkProjection(state, makeProbeProjection(SEAT_A, [probeField()]), knownSeats)),
      },
      {
        label: 'manifest entry with an unsafe path (dot segment)',
        reason: /unsafe manifest path/,
        run: () => {
          const problems = checkManifestPaths([probeEntry({ path: '../escape.json' }), probeEntry()]);
          return { valid: problems.length === 0, messages: problems };
        },
      },
      {
        label: 'manifest entry with an absolute path',
        reason: /unsafe manifest path/,
        run: () => {
          const problems = checkManifestPaths([probeEntry({ path: '/etc/passwd.json' })]);
          return { valid: problems.length === 0, messages: problems };
        },
      },
      {
        label: 'manifest with a duplicate asset path',
        reason: /duplicate manifest path/,
        run: () => {
          const problems = checkManifestDuplicates([probeEntry({ path: 'a.json' }), probeEntry({ path: 'a.json' })]);
          return { valid: problems.length === 0, messages: problems };
        },
      },
      {
        label: 'manifest kind/schema_ref mismatch',
        reason: /must map to exactly/,
        run: () => {
          const problems = checkManifestKindRefs([probeEntry({ kind: 'state', schema_ref: '#/$defs/projection' })]);
          return { valid: problems.length === 0, messages: problems };
        },
      },
      {
        label: 'schema helper rejects an unsupported functional keyword',
        reason: /unsupported functional schema keyword/,
        run: () => metaProbe({ $schema: META_SCHEMA_URI, type: 'object', format: 'uri' }),
      },
      {
        label: 'schema helper rejects an external/unresolved $ref',
        reason: /external/,
        run: () => metaProbe({
          $schema: META_SCHEMA_URI,
          $defs: { x: { type: 'object', properties: { a: { $ref: 'https://example.com/schema.json' } } } },
        }),
      },
      {
        label: 'schema helper rejects a local $ref cycle',
        reason: /cycle/,
        run: () => metaProbe({
          $schema: META_SCHEMA_URI,
          $defs: { a: { $ref: '#/$defs/b' }, b: { $ref: '#/$defs/a' } },
        }),
      },
    ];
    for (const probe of probes) {
      let outcome;
      try {
        outcome = probe.run();
      } catch (err) {
        fail(`negative probe (${probe.label}) could not build: ${err.message}`);
        negativeProbes.push({ label: probe.label, result: 'FAIL', reason: `build error: ${err.message}` });
        continue;
      }
      if (outcome.valid) {
        fail(`negative probe (${probe.label}) was NOT rejected`);
        negativeProbes.push({ label: probe.label, result: 'FAIL', reason: 'accepted' });
      } else {
        const matched = outcome.messages.filter((m) => probe.reason.test(m));
        if (matched.length === 0) {
          fail(`negative probe (${probe.label}) failed for an unexpected reason: ${outcome.messages[0]}`);
          negativeProbes.push({ label: probe.label, result: 'FAIL', reason: outcome.messages[0] });
        } else {
          ok(`negative-probe PASS: ${probe.label} rejected for the correct contract reason (${matched.length} matching reason(s))`);
          negativeProbes.push({ label: probe.label, result: 'PASS', reason: matched.join(' | ') });
        }
      }
    }
    const probeFailures = negativeProbes.filter((p) => p.result !== 'PASS');
    if (probeFailures.length === 0) {
      ok(`all ${negativeProbes.length} negative probes rejected as expected`);
    } else {
      fail(`${probeFailures.length} negative probe(s) did not reject as expected`);
    }
  } catch (err) {
    fail(`protocol-assets validator crashed: ${err.message}`);
  }

  return {
    name: 'protocol-assets',
    result: pass ? 'PASS' : 'FAIL',
    details,
    negative_probes: negativeProbes,
    summary: {
      schema: {
        root: SCHEMA_PATH,
        dialect: 'JSON Schema 2020-12',
        root_executable: 'oneOf over jsonrpc_request | jsonrpc_response | jsonrpc_notification',
        protocol_version: PROTOCOL_VERSION,
        schema_version: SCHEMA_VERSION,
        methods: [METHOD_REQUEST, METHOD_NOTIFICATION],
        visibility_labels: FROZEN_VISIBILITY_LABELS,
        subset: 'dependency-free explicit subset (scripts/ci/lib/json-schema.mjs); unsupported keywords rejected',
      },
      fixture: {
        root: FIXTURE_DIR,
        fixture_id: FIXTURE_ID,
        seats: [SEAT_A, SEAT_B],
        public_field: PUBLIC_FIELD_ID,
        hidden_field: HIDDEN_FIELD_ID,
        wire_envelopes: [WIRE_REQUEST_PATH, WIRE_RESULT_RESPONSE_PATH, WIRE_ERROR_RESPONSE_PATH, WIRE_NOTIFICATION_PATH],
        error_example: `code ${PROTOCOL_ERROR_CODE} + data.error_code ${PROTOCOL_ERROR_CODE_NAME}`,
        mutant: 'mutants/hidden-leak.json -> AIPT_VISIBILITY_UNAUTHORIZED_FIELD',
        replay_hash_algorithm: 'sha256 (canonical JSON)',
      },
    },
  };
}

runAsMain(import.meta.url, 'protocol-assets', run);
