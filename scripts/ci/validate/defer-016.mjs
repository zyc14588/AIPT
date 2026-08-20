// B002 deferred-parameter freeze validator, evolved by the AIPT-M0-B003
// security requalification.
//
// Rules (AIPT-M0-B002 iteration 1 + B003 security requalification):
//   - decisions.json / supersessions.json remain fully frozen: byte-identical
//     to the accepted B002 closeout/base (BASE_COMMIT — the AIPT-M0-B002
//     closeout commit on main, never the B001 merge);
//   - deferred-parameters.json is under EXACT CONTROLLED evolution:
//     DEFER-001..DEFER-015 must be byte-semantically identical to the accepted
//     base (each record JSON-identical, so a tampered record can never hide),
//     and DEFER-016 must match the exact controlled RESOLVED shape — an exact
//     top-level key set (the 9-key B002 base shape plus the single added
//     security_requalification key, nothing else), status RESOLVED,
//     resolved_by_batch = AIPT-M0-B001 (immutable historical fact), resolution
//     tools/toolchain.lock.json, value carrying the exact current toolchain
//     versions (go 1.26.6 / node 24.19.0 / pnpm 11.4.0 / postgresql 18.4),
//     blocks empty, and the exact 7-key B003 security requalification
//     provenance object: batch AIPT-M0-B003, previous_go_version 1.26.5,
//     current_go_version 1.26.6, verified_at 2026-08-20T04:16:01Z (UTC),
//     reason 'reachable standard-library vulnerabilities', officially_fixed_in
//     1.26.6 and the exact trigger advisory set GO-2026-6090 / GO-2026-6088 /
//     GO-2026-5972, each officially fixed in Go 1.26.6 — an extra key at
//     either level and the ambiguous go_version key are rejected;
//   - the other 15 parameters stay open;
//   - in-memory mutation probes prove drift is rejected for its specific
//     reason: Go reverted to 1.26.5, arbitrary 1.26.7, missing requalification
//     provenance, drifted previous/current go version, drifted verified_at,
//     the ambiguous go_version key, an extra top-level/nested key, drifted
//     resolution, wrong advisory set, resolved_by_batch drift, and any change
//     to DEFER-001..DEFER-015;
//   - decisions.json / supersessions.json / deferred-parameters.json registry
//     protection is never disabled: the fully frozen registries stay
//     byte-identical, and the controlled DEFER-016 evolution is validated
//     against the exact fixed closed shape.
import fs from 'node:fs';
import path from 'node:path';
import { BASE_COMMIT, FROZEN_REGISTRY_PATHS, TOOLCHAIN } from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const DEFERRED_PATH = 'docs/authority/registry/deferred-parameters.json';

// The exact controlled DEFER-016 record shape. The base record is the exact
// 9-key B002 shape (no security_requalification); the current record is the
// exact 10-key controlled shape whose security_requalification nested object
// is itself an exact 7-key closed shape. Any extra/missing key at either
// level fails — the controlled evolution is a closed shape, never an open
// extension.
const DEFER_016_VALUE = 'go 1.26.6, node 24.19.0, pnpm 11.4.0, postgresql 18.4';
const DEFER_016_SECURITY_BATCH = 'AIPT-M0-B003';
const DEFER_016_PREVIOUS_GO = '1.26.5';
const DEFER_016_CURRENT_GO = '1.26.6';
const DEFER_016_VERIFIED_AT = '2026-08-20T04:16:01Z';
const DEFER_016_SECURITY_REASON = 'reachable standard-library vulnerabilities';
const DEFER_016_SECURITY_FIXED_IN = '1.26.6';
const DEFER_016_ADVISORY_IDS = ['GO-2026-6090', 'GO-2026-6088', 'GO-2026-5972'];
const DEFER_016_RESOLUTION = 'tools/toolchain.lock.json';
const DEFER_016_TOP_KEYS = ['parameter_id', 'name', 'status', 'value', 'reason', 'resolved_by_batch', 'security_requalification', 'resolution', 'blocks', 'does_not_block'];
const DEFER_016_BASE_KEYS = ['parameter_id', 'name', 'status', 'value', 'reason', 'resolved_by_batch', 'resolution', 'blocks', 'does_not_block'];
const DEFER_016_SECURITY_KEYS = ['batch', 'previous_go_version', 'current_go_version', 'verified_at', 'reason', 'officially_fixed_in', 'advisory_ids'];
const sortedKeys = (obj) => Object.keys(obj).sort().join(',');

function loadDeferred(text) {
  const doc = JSON.parse(text);
  const params = doc.parameters;
  if (!Array.isArray(params)) throw new Error('parameters is not an array');
  const map = new Map();
  for (const p of params) {
    if (map.has(p.parameter_id)) throw new Error(`duplicate parameter_id ${p.parameter_id}`);
    map.set(p.parameter_id, p);
  }
  return { doc, map };
}

// Pure machine check of the exact controlled DEFER-016 evolution. Returns
// problem strings (empty when clean). Every exact fact is compared against
// the fixed constants above, so a drifted or missing field — including any
// extra key at either level and the ambiguous go_version key — fails
// path-specifically. Missing-state control flow: a missing DEFER-016 record
// or a missing security_requalification object reports its own exact problem
// instead of crashing.
export function defer016Problems(base, current) {
  const problems = [];
  const b16 = base?.map?.get('DEFER-016');
  const c16 = current?.map?.get('DEFER-016');
  if (!b16 || !c16) {
    problems.push('DEFER-016 missing');
    return problems;
  }
  if (typeof b16 !== 'object' || typeof c16 !== 'object') {
    problems.push('DEFER-016 record is not an object');
    return problems;
  }
  // Exact closed-shape key sets: base = the 9-key B002 shape, current = the
  // 10-key controlled shape. An extra key (a parallel field) or a missing key
  // fails.
  if (sortedKeys(b16) !== [...DEFER_016_BASE_KEYS].sort().join(',')) {
    problems.push(`DEFER-016 base key set drifted at the B002 base: ${JSON.stringify(Object.keys(b16))}`);
  }
  if (sortedKeys(c16) !== [...DEFER_016_TOP_KEYS].sort().join(',')) {
    problems.push(`DEFER-016 top-level key set must be exactly ${DEFER_016_TOP_KEYS.join(', ')} (closed controlled shape): ${JSON.stringify(Object.keys(c16))}`);
  }
  if (b16.status !== 'RESOLVED') problems.push(`DEFER-016 base status drifted at the B002 base: ${JSON.stringify(b16.status)}`);
  if (c16.status !== 'RESOLVED') problems.push(`DEFER-016 status must stay RESOLVED: ${JSON.stringify(c16.status)}`);
  if (c16.name !== b16.name) problems.push(`DEFER-016 name drifted: ${b16.name} -> ${c16.name}`);
  // Exact historical fields: resolved_by_batch and resolution are immutable
  // B001 facts carried into the controlled evolution.
  if (c16.resolved_by_batch !== 'AIPT-M0-B001') problems.push(`DEFER-016 resolved_by_batch drifted: ${JSON.stringify(c16.resolved_by_batch)}`);
  if (c16.resolution !== DEFER_016_RESOLUTION) problems.push(`DEFER-016 resolution must be ${DEFER_016_RESOLUTION}: ${JSON.stringify(c16.resolution)}`);
  // Exact current fields.
  const value = String(c16.value ?? '');
  if (value !== DEFER_016_VALUE) {
    problems.push(`DEFER-016 value must be exactly ${JSON.stringify(DEFER_016_VALUE)} (current Go 1.26.6 security requalification), got ${JSON.stringify(value)}`);
  }
  if (value.includes('go 1.26.5')) problems.push('DEFER-016 value must not carry the historical B001 Go 1.26.5 as the current value (explicit B001 historical statements live in the reason/provenance only)');
  const missingVersions = Object.values(TOOLCHAIN).filter((v) => !value.includes(v));
  if (missingVersions.length > 0) problems.push(`DEFER-016 value missing exact versions: ${missingVersions.join(', ')}`);
  if (JSON.stringify(c16.blocks) !== '[]') problems.push(`DEFER-016 blocks must be empty: ${JSON.stringify(c16.blocks)}`);
  if (JSON.stringify(c16.does_not_block) !== JSON.stringify(b16.does_not_block)) {
    problems.push(`DEFER-016 does_not_block drifted: ${JSON.stringify(c16.does_not_block)} != ${JSON.stringify(b16.does_not_block)}`);
  }
  const sec = c16.security_requalification;
  if (!sec || typeof sec !== 'object') {
    problems.push(`DEFER-016 must carry the exact B003 security requalification provenance (batch ${DEFER_016_SECURITY_BATCH}, previous Go ${DEFER_016_PREVIOUS_GO} -> current Go ${DEFER_016_CURRENT_GO}, verified_at ${DEFER_016_VERIFIED_AT} (UTC), reason '${DEFER_016_SECURITY_REASON}', advisory set ${DEFER_016_ADVISORY_IDS.join(', ')}): missing`);
  } else {
    if (sortedKeys(sec) !== [...DEFER_016_SECURITY_KEYS].sort().join(',')) {
      problems.push(`DEFER-016 security requalification key set must be exactly ${DEFER_016_SECURITY_KEYS.join(', ')} (closed controlled shape): ${JSON.stringify(Object.keys(sec))}`);
    }
    if (sec.batch !== DEFER_016_SECURITY_BATCH) problems.push(`DEFER-016 security requalification batch must be ${DEFER_016_SECURITY_BATCH}: ${JSON.stringify(sec.batch)}`);
    if (sec.previous_go_version !== DEFER_016_PREVIOUS_GO) problems.push(`DEFER-016 security requalification previous_go_version must be ${DEFER_016_PREVIOUS_GO} (the B001-qualified Go): ${JSON.stringify(sec.previous_go_version)}`);
    if (sec.current_go_version !== DEFER_016_CURRENT_GO) problems.push(`DEFER-016 security requalification current_go_version must be ${DEFER_016_CURRENT_GO}: ${JSON.stringify(sec.current_go_version)}`);
    if (sec.verified_at !== DEFER_016_VERIFIED_AT) problems.push(`DEFER-016 security requalification verified_at must be ${DEFER_016_VERIFIED_AT} (UTC): ${JSON.stringify(sec.verified_at)}`);
    if (Object.prototype.hasOwnProperty.call(sec, 'go_version')) problems.push('DEFER-016 security requalification must not carry the ambiguous go_version key (use previous_go_version / current_go_version)');
    if (sec.reason !== DEFER_016_SECURITY_REASON) problems.push(`DEFER-016 security requalification reason must be ${JSON.stringify(DEFER_016_SECURITY_REASON)}: ${JSON.stringify(sec.reason)}`);
    if (sec.officially_fixed_in !== DEFER_016_SECURITY_FIXED_IN) problems.push(`DEFER-016 security requalification officially_fixed_in must be ${DEFER_016_SECURITY_FIXED_IN}`);
    const actual = [...(sec.advisory_ids ?? [])].sort();
    const expected = [...DEFER_016_ADVISORY_IDS].sort();
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      problems.push(`DEFER-016 security requalification advisory set must be exactly ${expected.join(', ')} (each officially fixed in Go 1.26.6): ${JSON.stringify(sec.advisory_ids)}`);
    }
  }
  const reason = String(c16.reason ?? '');
  if (!reason.includes(DEFER_016_SECURITY_BATCH) || !reason.includes(DEFER_016_SECURITY_REASON)) {
    problems.push('DEFER-016 reason must document the B003 security requalification (reason: reachable standard-library vulnerabilities)');
  }
  if (!reason.includes(DEFER_016_ADVISORY_IDS[0]) || !reason.includes(DEFER_016_ADVISORY_IDS[1]) || !reason.includes(DEFER_016_ADVISORY_IDS[2])) {
    problems.push('DEFER-016 reason must name the exact trigger advisory set (GO-2026-6090 / GO-2026-6088 / GO-2026-5972)');
  }
  return problems;
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };

  // Fully frozen registries must not change relative to the accepted B002
  // base. deferred-parameters.json is NOT in FROZEN_REGISTRY_PATHS anymore:
  // its DEFER-016 record is under exact controlled evolution below, while the
  // registry protection for decisions.json / supersessions.json stays on.
  const frozenDiff = git(ctx.repo, ['diff', '--name-only', BASE_COMMIT, '--', ...FROZEN_REGISTRY_PATHS]);
  const frozenChanged = frozenDiff.stdout.split('\n').filter(Boolean);
  if (frozenChanged.length > 0) {
    fail(`frozen registries modified: ${frozenChanged.join(', ')}`);
  } else ok('decisions.json / supersessions.json unchanged vs base (fully frozen)');

  const baseText = git(ctx.repo, ['show', `${BASE_COMMIT}:${DEFERRED_PATH}`]).stdout;
  const currentPath = path.join(ctx.repo, DEFERRED_PATH);
  let base, current;
  try {
    base = loadDeferred(baseText);
    current = loadDeferred(fs.readFileSync(currentPath, 'utf8'));
  } catch (err) {
    fail(`${DEFERRED_PATH} unparseable: ${err.message}`);
    return { name: 'defer-016', result: 'FAIL', details };
  }

  const baseIds = [...base.map.keys()].sort();
  const curIds = [...current.map.keys()].sort();
  if (baseIds.length !== 16 || curIds.length !== 16) {
    fail(`parameter count must remain 16 (base=${baseIds.length}, current=${curIds.length})`);
  } else ok('parameter count stays 16');
  if (JSON.stringify(baseIds) !== JSON.stringify(curIds)) {
    fail(`parameter ID set drifted: base=${baseIds.join(',')} current=${curIds.join(',')}`);
  } else ok('parameter ID set unchanged (DEFER-001..DEFER-016)');

  // DEFER-001..DEFER-015 must be byte-semantically unchanged from the
  // accepted B002 base; only DEFER-016 may evolve, and only into the exact
  // controlled RESOLVED shape.
  let unchangedCount = 0;
  let controlledOk = true;
  for (const id of baseIds) {
    const b = base.map.get(id);
    const c = current.map.get(id);
    if (!b || !c) {
      fail(`${id} missing in base or current`);
      // A missing DEFER-016 record (in either the accepted base or the current
      // registry) is not a valid controlled evolution: the controlled-shape
      // success line must never be emitted for a missing record.
      if (id === 'DEFER-016') controlledOk = false;
      continue;
    }
    if (id === 'DEFER-016') {
      const problems = defer016Problems(base, current);
      for (const problem of problems) {
        fail(`DEFER-016 controlled evolution: ${problem}`);
        controlledOk = false;
      }
      continue;
    }
    if (JSON.stringify(b) !== JSON.stringify(c)) {
      fail(`${id} changed vs the accepted B002 base (only DEFER-016 may evolve):\n  base=${JSON.stringify(b)}\n  curr=${JSON.stringify(c)}`);
    } else {
      unchangedCount += 1;
    }
  }
  if (unchangedCount === 15) {
    ok('DEFER-001..DEFER-015 byte-semantically unchanged from the accepted B002 base');
  }
  if (controlledOk) {
    ok('DEFER-016 matches the exact controlled RESOLVED evolution (closed 10-key shape; Go 1.26.6 + Node 24.19.0 + pnpm 11.4.0 + PostgreSQL 18.4; resolved_by_batch = AIPT-M0-B001; resolution tools/toolchain.lock.json; exact B003 security requalification provenance: batch AIPT-M0-B003, previous Go 1.26.5 -> current Go 1.26.6, verified_at 2026-08-20T04:16:01Z, advisory set GO-2026-6090 / GO-2026-6088 / GO-2026-5972)');
  }

  // No other parameter may be RESOLVED/CLOSED.
  const othersResolved = [...current.map.entries()]
    .filter(([id, p]) => id !== 'DEFER-016' && ['RESOLVED', 'CLOSED', 'FROZEN', 'IMPLEMENTED'].includes(p.status))
    .map(([id]) => id);
  if (othersResolved.length > 0) {
    fail(`other parameters illegally presented as closed: ${othersResolved.join(', ')}`);
  } else ok('only DEFER-016 is RESOLVED; the other 15 stay open');

  // ---- in-memory controlled-evolution probes (the live registry is never
  // mutated; each probe clones the parsed current registry document, mutates
  // exactly one field, and must be rejected for its specific reason) ----
  const cloneDoc = () => JSON.parse(JSON.stringify(current.doc));
  const mutateDefer016 = (doc, mutate) => {
    mutate(doc.parameters.find((p) => p.parameter_id === 'DEFER-016'));
    return doc;
  };
  const probes = [
    {
      label: 'DEFER-016 value reverted to Go 1.26.5 FAIL',
      reason: /value must be exactly|must not carry the historical B001 Go 1\.26\.5/,
      run: () => defer016Problems(base, loadDeferred(JSON.stringify(mutateDefer016(cloneDoc(), (c) => { c.value = 'go 1.26.5, node 24.19.0, pnpm 11.4.0, postgresql 18.4'; })))),
    },
    {
      label: 'DEFER-016 value drifted to arbitrary Go 1.26.7 FAIL',
      reason: /value must be exactly/,
      run: () => defer016Problems(base, loadDeferred(JSON.stringify(mutateDefer016(cloneDoc(), (c) => { c.value = 'go 1.26.7, node 24.19.0, pnpm 11.4.0, postgresql 18.4'; })))),
    },
    {
      label: 'DEFER-016 security requalification provenance removed FAIL',
      reason: /must carry the exact B003 security requalification provenance/,
      run: () => defer016Problems(base, loadDeferred(JSON.stringify(mutateDefer016(cloneDoc(), (c) => { delete c.security_requalification; })))),
    },
    {
      label: 'DEFER-016 security requalification previous_go_version drifted FAIL',
      reason: /previous_go_version must be 1\.26\.5/,
      run: () => defer016Problems(base, loadDeferred(JSON.stringify(mutateDefer016(cloneDoc(), (c) => { c.security_requalification.previous_go_version = '1.26.4'; })))),
    },
    {
      label: 'DEFER-016 security requalification current_go_version drifted FAIL',
      reason: /current_go_version must be 1\.26\.6/,
      run: () => defer016Problems(base, loadDeferred(JSON.stringify(mutateDefer016(cloneDoc(), (c) => { c.security_requalification.current_go_version = '1.26.7'; })))),
    },
    {
      label: 'DEFER-016 security requalification verified_at drifted FAIL',
      reason: /verified_at must be 2026-08-20T04:16:01Z/,
      run: () => defer016Problems(base, loadDeferred(JSON.stringify(mutateDefer016(cloneDoc(), (c) => { c.security_requalification.verified_at = '2026-08-19T00:00:00Z'; })))),
    },
    {
      label: 'DEFER-016 security requalification retains the ambiguous go_version key FAIL',
      reason: /ambiguous go_version key/,
      run: () => defer016Problems(base, loadDeferred(JSON.stringify(mutateDefer016(cloneDoc(), (c) => { c.security_requalification.go_version = '1.26.6'; })))),
    },
    {
      label: 'DEFER-016 extra top-level key FAIL (closed 10-key shape)',
      reason: /top-level key set must be exactly/,
      run: () => defer016Problems(base, loadDeferred(JSON.stringify(mutateDefer016(cloneDoc(), (c) => { c.extra_field = 'x'; })))),
    },
    {
      label: 'DEFER-016 extra nested security_requalification key FAIL (closed 7-key shape)',
      reason: /security requalification key set must be exactly/,
      run: () => defer016Problems(base, loadDeferred(JSON.stringify(mutateDefer016(cloneDoc(), (c) => { c.security_requalification.extra_field = 'x'; })))),
    },
    {
      label: 'DEFER-016 resolution drifted FAIL',
      reason: /resolution must be tools\/toolchain\.lock\.json/,
      run: () => defer016Problems(base, loadDeferred(JSON.stringify(mutateDefer016(cloneDoc(), (c) => { c.resolution = 'other.json'; })))),
    },
    {
      label: 'DEFER-016 advisory set wrong FAIL',
      reason: /advisory set must be exactly/,
      run: () => defer016Problems(base, loadDeferred(JSON.stringify(mutateDefer016(cloneDoc(), (c) => { c.security_requalification.advisory_ids = ['GO-2026-6090', 'GO-2026-6088', 'GO-2026-9999']; })))),
    },
    {
      label: 'DEFER-016 security reason drifted FAIL',
      reason: /reason must be/,
      run: () => defer016Problems(base, loadDeferred(JSON.stringify(mutateDefer016(cloneDoc(), (c) => { c.security_requalification.reason = 'arbitrary bump'; })))),
    },
    {
      label: 'DEFER-016 resolved_by_batch drifted FAIL',
      reason: /resolved_by_batch drifted/,
      run: () => defer016Problems(base, loadDeferred(JSON.stringify(mutateDefer016(cloneDoc(), (c) => { c.resolved_by_batch = 'AIPT-M0-B003'; })))),
    },
    {
      label: 'DEFER-016 blocks no longer empty FAIL',
      reason: /blocks must be empty/,
      run: () => defer016Problems(base, loadDeferred(JSON.stringify(mutateDefer016(cloneDoc(), (c) => { c.blocks = ['something']; })))),
    },
    {
      label: 'DEFER-001 tampered FAIL (byte-identical protection for the other 15)',
      reason: /DEFER-001 changed vs the accepted B002 base/,
      run: () => {
        const mutated = cloneDoc();
        mutated.parameters.find((p) => p.parameter_id === 'DEFER-001').reason = 'tampered';
        const { map: m1 } = loadDeferred(baseText);
        const { map: m2 } = loadDeferred(JSON.stringify(mutated));
        const problems = [];
        for (const id of [...m1.keys()].sort()) {
          if (id === 'DEFER-016') continue;
          if (JSON.stringify(m1.get(id)) !== JSON.stringify(m2.get(id))) {
            problems.push(`${id} changed vs the accepted B002 base (only DEFER-016 may evolve)`);
          }
        }
        return problems;
      },
    },
  ];
  let probesOk = true;
  for (const probe of probes) {
    let problems;
    try {
      problems = probe.run();
    } catch (err) {
      fail(`in-memory defer-016 probe (${probe.label}) crashed: ${err.message}`);
      probesOk = false;
      continue;
    }
    if (!Array.isArray(problems) || problems.length === 0) {
      fail(`in-memory defer-016 probe (${probe.label}) was NOT rejected`);
      probesOk = false;
    } else if (!problems.some((p) => probe.reason.test(p))) {
      fail(`in-memory defer-016 probe (${probe.label}) failed for an unexpected reason: ${JSON.stringify(problems)}`);
      probesOk = false;
    } else {
      ok(`in-memory defer-016 probe PASS: ${probe.label} rejected`);
    }
  }
  if (probesOk) ok(`all ${probes.length} in-memory defer-016 controlled-evolution probes behaved as expected`);

  return { name: 'defer-016', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'defer-016', run);
