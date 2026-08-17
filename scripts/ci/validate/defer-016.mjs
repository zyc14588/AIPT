// B002 deferred-parameter freeze validator.
//
// Rules (AIPT-M0-B002, iteration 1):
//   - the deferred-parameters registry is frozen: all 16 DEFER-001..DEFER-016
//     records must be byte/semantically unchanged from the accepted B002 base
//     (the AIPT-M0-B001 merge commit), where DEFER-016 was already RESOLVED;
//   - exactly DEFER-016 remains RESOLVED and still carries the four exact
//     frozen toolchain values (Go 1.26.5 / Node 24.19.0 / pnpm 11.4.0 /
//     PostgreSQL 18.4) with empty blocks;
//   - the other 15 parameters stay open;
//   - decisions.json / supersessions.json / deferred-parameters.json are not
//     modified by the candidate (the historical B000/B001 facts inside them
//     are never rewritten).
import fs from 'node:fs';
import path from 'node:path';
import { BASE_COMMIT, FROZEN_REGISTRY_PATHS, TOOLCHAIN } from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const DEFERRED_PATH = 'docs/authority/registry/deferred-parameters.json';

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

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };

  // Frozen registries must not change relative to the accepted B002 base.
  const frozenDiff = git(ctx.repo, ['diff', '--name-only', BASE_COMMIT, '--', ...FROZEN_REGISTRY_PATHS]);
  const frozenChanged = frozenDiff.stdout.split('\n').filter(Boolean);
  if (frozenChanged.length > 0) {
    fail(`frozen registries modified: ${frozenChanged.join(', ')}`);
  } else ok('decisions.json / supersessions.json / deferred-parameters.json unchanged vs base');

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

  // All 16 records must be byte-semantically unchanged from the accepted
  // B002 base (the AIPT-M0-B001 merge commit).
  let unchangedCount = 0;
  for (const id of baseIds) {
    const b = base.map.get(id);
    const c = current.map.get(id);
    if (!b || !c) {
      fail(`${id} missing in base or current`);
      continue;
    }
    if (JSON.stringify(b) !== JSON.stringify(c)) {
      fail(`${id} changed vs the accepted B002 base:\n  base=${JSON.stringify(b)}\n  curr=${JSON.stringify(c)}`);
    } else {
      unchangedCount += 1;
    }
  }
  if (unchangedCount === 16) {
    ok('all 16 deferred parameter records byte-semantically unchanged from the accepted B002 base');
  }

  // Only DEFER-016 may be RESOLVED — with the exact frozen toolchain values.
  const b16 = base.map.get('DEFER-016');
  const c16 = current.map.get('DEFER-016');
  if (!b16 || !c16) {
    fail('DEFER-016 missing');
    return { name: 'defer-016', result: 'FAIL', details };
  }
  if (b16.status !== 'RESOLVED') {
    fail(`DEFER-016 base status drifted at the B002 base: ${JSON.stringify(b16.status)}`);
  } else ok('DEFER-016 was already RESOLVED at the accepted B002 base');
  if (c16.status !== 'RESOLVED') {
    fail(`DEFER-016 status must stay RESOLVED: ${JSON.stringify(c16.status)}`);
  } else ok('DEFER-016 remains RESOLVED');
  const value = String(c16.value ?? '');
  const missingVersions = Object.values(TOOLCHAIN).filter((v) => !value.includes(v));
  if (missingVersions.length > 0) {
    fail(`DEFER-016 value missing exact versions: ${missingVersions.join(', ')} (value=${JSON.stringify(c16.value)})`);
  } else ok(`DEFER-016 value carries the four exact frozen toolchain versions (${Object.values(TOOLCHAIN).join(' / ')})`);
  if (JSON.stringify(c16.blocks) !== '[]') {
    fail(`DEFER-016 blocks must be empty: ${JSON.stringify(c16.blocks)}`);
  } else ok('DEFER-016 blocks cleared');
  if (c16.resolved_by_batch !== 'AIPT-M0-B001') {
    fail(`DEFER-016 resolved_by_batch drifted: ${JSON.stringify(c16.resolved_by_batch)}`);
  } else ok('DEFER-016 resolved_by_batch = AIPT-M0-B001 (immutable historical fact)');
  if (c16.name !== b16.name) {
    fail(`DEFER-016 name drifted: ${b16.name} -> ${c16.name}`);
  } else ok('DEFER-016 name unchanged');

  // No other parameter may be RESOLVED/CLOSED.
  const othersResolved = [...current.map.entries()]
    .filter(([id, p]) => id !== 'DEFER-016' && ['RESOLVED', 'CLOSED', 'FROZEN', 'IMPLEMENTED'].includes(p.status))
    .map(([id]) => id);
  if (othersResolved.length > 0) {
    fail(`other parameters illegally presented as closed: ${othersResolved.join(', ')}`);
  } else ok('only DEFER-016 is RESOLVED; the other 15 stay open');

  return { name: 'defer-016', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'defer-016', run);
