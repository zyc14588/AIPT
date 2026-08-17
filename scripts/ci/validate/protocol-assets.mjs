#!/usr/bin/env node
// B002 protocol-assets validator: proves the canonical protocol schema, the
// minimal deterministic fixture, and the required negative cases with a
// dependency-free JSON Schema 2020-12 subset validator.
//
// Gates (all fail closed):
//   1. Canonical schema document: parses, uses ONLY the explicit subset
//      supported by scripts/ci/lib/json-schema.mjs (any unsupported
//      functional keyword is rejected, never ignored), carries the frozen
//      version/method/visibility constants, and resolves local $refs without
//      cycles.
//   2. Fixture manifest: schema-valid against #/$defs/fixture_manifest; the
//      asset inventory is EXACT (every JSON file under the fixture dir is
//      listed and every listed file exists); every asset's lowercase SHA-256
//      digest over canonical JSON matches, so unexpected drift fails closed.
//   3. Every positive fixture asset validates against its declared $ref, and
//      every asset's protocol_version/schema_version/fixture_id equals the
//      frozen 1.0.0 / 1.0.0 / minimal-v1-arithmetic identity.
//   4. Semantics: exactly two seats (seat-a, seat-b); one PUBLIC field
//      visible to both and one TABLE_HIDDEN_REMOTE_ALLOWED field authorized
//      only to seat-a; separate valid seat-a / seat-b projections; one
//      generic action intent; one deterministic versioned arithmetic check
//      with fixed input/output; one state transition and one event; the
//      expected final state; a SHA-256 replay assertion proving two replays
//      yield the same final state/hash.
//   5. The hidden-leak mutant is validated against the schema FIRST (it must
//      be schema-valid), then semantically rejected for exactly
//      AIPT_VISIBILITY_UNAUTHORIZED_FIELD — never for unrelated JSON/schema
//      syntax reasons.
//   6. Nine in-memory/on-disk negative probes must each be rejected for the
//      correct contract reason (jsonrpc != 2.0, unknown protocol version,
//      unknown schema version, missing request params, result+error
//      together, unknown method, missing visibility, unknown visibility
//      label, hidden-leak mutant).
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { runAsMain } from '../lib/cli.mjs';
import { checkSchemaDocument, deepEqual, validateInstance } from '../lib/json-schema.mjs';
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

// Semantic visibility gate for a projection over a state. Returns the list
// of stable AIPT_* rejection reasons; a valid projection returns [].
function checkProjection(state, projection) {
  const reasons = [];
  const stateById = new Map(state.fields.map((f) => [f.field_id, f]));
  for (const field of projection.fields) {
    const src = stateById.get(field.field_id);
    if (!src) {
      reasons.push('AIPT_PROJECTION_UNKNOWN_FIELD');
      continue;
    }
    if (!deepEqual(src.visibility.label, field.visibility.label)) {
      reasons.push('AIPT_VISIBILITY_RECLASSIFIED');
    }
    if (!deepEqual(src.visibility.authorized_seat_ids, field.visibility.authorized_seat_ids)) {
      reasons.push('AIPT_VISIBILITY_AUTHORIZATION_DRIFT');
    }
    if (!field.visibility.authorized_seat_ids.includes(projection.seat_id)) {
      reasons.push(VISIBILITY_UNAUTHORIZED_FIELD);
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
  const readJson = (rel) => JSON.parse(read(rel));

  try {
    // ---------------------------------------------------------------
    // 1. Canonical schema document: subset conformance + frozen constants.
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

    // ---------------------------------------------------------------
    // 2. Manifest: schema-valid, exact inventory, digests, identity.
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
    const escaping = listed.filter((p) => p.includes('..') || path.isAbsolute(p) || p.split('/').includes('..'));
    if (escaping.length > 0) fail(`manifest paths must stay inside the fixture dir: ${escaping.join(', ')}`);
    if (unlisted.length === 0 && missing.length === 0 && escaping.length === 0) {
      ok(`exact fixture inventory: ${onDisk.length} JSON files on disk == ${listed.length} listed (assets + mutants + manifest)`);
    }

    // Per-asset digest + schema validation + identity consistency.
    const assetDocs = new Map();
    for (const entry of [...(manifest.assets ?? []), ...(manifest.mutants ?? [])]) {
      const filePath = path.join(fixtureDir, ...entry.path.split('/'));
      if (!fs.existsSync(filePath)) {
        fail(`listed fixture asset does not exist: ${entry.path}`);
        continue;
      }
      let doc;
      try {
        doc = JSON.parse(fs.readFileSync(filePath, 'utf8'));
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
    if (seats && Array.isArray(seats.seats) && seats.seats.length === 2) {
      const ids = seats.seats.map((s) => s.seat_id).sort();
      if (ids[0] !== SEAT_A || ids[1] !== SEAT_B) fail(`seats must be exactly seat-a and seat-b, got ${JSON.stringify(ids)}`);
      else ok('exactly two seats: seat-a, seat-b');
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
      const reasons = checkProjection(state, proj);
      if (reasons.length > 0) fail(`${projPath} violates the visibility gate: ${reasons.join(', ')}`);
      else ok(`${projPath} passes the visibility gate (labels, authorization, seat membership)`);
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
    // 4. Hidden-leak mutant: schema first, then semantic rejection.
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
      const reasons = state && inner ? checkProjection(state, inner) : ['fixture-missing'];
      if (reasons.length !== 1 || reasons[0] !== VISIBILITY_UNAUTHORIZED_FIELD) {
        fail(`mutant must be rejected specifically with ${VISIBILITY_UNAUTHORIZED_FIELD}, got ${JSON.stringify(reasons)}`);
        negativeProbes.push({ label: 'hidden-leak mutant (mutants/hidden-leak.json)', result: 'FAIL', schema_valid: true, reason: JSON.stringify(reasons) });
      } else {
        ok(`mutant rejected specifically with ${VISIBILITY_UNAUTHORIZED_FIELD} (schema-valid, semantically unauthorized)`);
        negativeProbes.push({ label: 'hidden-leak mutant (mutants/hidden-leak.json)', result: 'PASS', schema_valid: true, reason: VISIBILITY_UNAUTHORIZED_FIELD });
      }
    }

    // ---------------------------------------------------------------
    // 5. Request/response identity: id round-trip and method registry.
    // ---------------------------------------------------------------
    const baseParams = { action: 'advance-turn', seat_id: SEAT_A };
    const makeRequest = (id) => ({
      jsonrpc: '2.0',
      id,
      method: METHOD_REQUEST,
      params: baseParams,
      protocol_version: PROTOCOL_VERSION,
      schema_version: SCHEMA_VERSION,
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
    // 6. Negative probes: each must be rejected for the correct reason.
    // ---------------------------------------------------------------
    const probes = [
      {
        label: 'jsonrpc != 2.0',
        ref: '#/$defs/jsonrpc_request',
        reason: /\/jsonrpc/,
        build: () => ({ ...makeRequest('probe-jsonrpc'), jsonrpc: '1.0' }),
      },
      {
        label: 'unknown protocol version',
        ref: '#/$defs/jsonrpc_request',
        reason: /\/protocol_version/,
        build: () => ({ ...makeRequest('probe-protocol'), protocol_version: '9.9.9' }),
      },
      {
        label: 'unknown schema version',
        ref: '#/$defs/jsonrpc_request',
        reason: /\/schema_version/,
        build: () => ({ ...makeRequest('probe-schema'), schema_version: '9.9.9' }),
      },
      {
        label: 'request missing required params',
        ref: '#/$defs/jsonrpc_request',
        reason: /params/,
        build: () => {
          const req = makeRequest('probe-no-params');
          delete req.params;
          return req;
        },
      },
      {
        label: 'response carrying result and error together',
        ref: '#/$defs/jsonrpc_response',
        reason: /oneOf/,
        build: () => makeResponse('probe-both', { result: makeResult(), error: { code: -32603, message: 'internal error' } }),
      },
      {
        label: 'unknown method',
        ref: '#/$defs/jsonrpc_request',
        reason: /\/method/,
        build: () => ({ ...makeRequest('probe-method'), method: 'aipt.protocol.workerLifecycle' }),
      },
      {
        label: 'missing visibility information',
        ref: '#/$defs/state',
        reason: /visibility/,
        build: () => ({
          protocol_version: PROTOCOL_VERSION,
          schema_version: SCHEMA_VERSION,
          fixture_id: FIXTURE_ID,
          state_id: 'probe-state',
          fields: [{ field_id: 'x-field', value: 1 }],
        }),
      },
      {
        label: 'unknown visibility label',
        ref: '#/$defs/state',
        reason: /label/,
        build: () => ({
          protocol_version: PROTOCOL_VERSION,
          schema_version: SCHEMA_VERSION,
          fixture_id: FIXTURE_ID,
          state_id: 'probe-state',
          fields: [
            {
              field_id: 'x-field',
              value: 1,
              visibility: { label: 'TEAM_ONLY', authorized_seat_ids: [SEAT_A] },
            },
          ],
        }),
      },
    ];
    for (const probe of probes) {
      let instance;
      try {
        instance = probe.build();
      } catch (err) {
        fail(`negative probe (${probe.label}) could not build: ${err.message}`);
        negativeProbes.push({ label: probe.label, result: 'FAIL', reason: 'build error' });
        continue;
      }
      const res = validateInstance(schemaDoc, instance, { ref: probe.ref });
      if (res.valid) {
        fail(`negative probe (${probe.label}) was NOT rejected`);
        negativeProbes.push({ label: probe.label, result: 'FAIL', reason: 'accepted' });
      } else {
        const rightReason = res.errors.some((e) => probe.reason.test(e.message));
        if (!rightReason) {
          fail(`negative probe (${probe.label}) failed for an unexpected reason: ${res.errors[0]?.message}`);
          negativeProbes.push({ label: probe.label, result: 'FAIL', reason: res.errors[0]?.message });
        } else {
          ok(`negative-probe PASS: ${probe.label} rejected for the correct contract reason (${res.errors.filter((e) => probe.reason.test(e.message)).length} matching error(s))`);
          negativeProbes.push({ label: probe.label, result: 'PASS', reason: res.errors.filter((e) => probe.reason.test(e.message)).map((e) => e.message).join(' | ') });
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
        mutant: 'mutants/hidden-leak.json -> AIPT_VISIBILITY_UNAUTHORIZED_FIELD',
        replay_hash_algorithm: 'sha256 (canonical JSON)',
      },
    },
  };
}

runAsMain(import.meta.url, 'protocol-assets', run);
