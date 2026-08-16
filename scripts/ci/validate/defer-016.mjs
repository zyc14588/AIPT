// B001 deferred-parameter transition validator.
//
// Rules (AIPT-M0-B001):
//   - total parameter count stays 16;
//   - exactly DEFER-016 transitions DEFERRED_TO_AIPT-M0-B001 -> RESOLVED with
//     the four exact toolchain versions;
//   - the other 15 parameters remain byte/semantically unchanged;
//   - decisions.json / supersessions.json are not modified by the candidate.
import fs from 'node:fs';
import path from 'node:path';
import { BASE_COMMIT, FROZEN_REGISTRY_PATHS, TOOLCHAIN } from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

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

  // Frozen registries must not change relative to the accepted base.
  const frozenDiff = git(ctx.repo, ['diff', '--name-only', BASE_COMMIT, '--', ...FROZEN_REGISTRY_PATHS]);
  const frozenChanged = frozenDiff.stdout.split('\n').filter(Boolean);
  if (frozenChanged.length > 0) {
    fail(`frozen registries modified: ${frozenChanged.join(', ')}`);
  } else ok('decisions.json / supersessions.json unchanged vs base');

  const baseText = git(ctx.repo, ['show', `${BASE_COMMIT}:docs/authority/registry/deferred-parameters.json`]).stdout;
  const currentPath = path.join(ctx.repo, 'docs/authority/registry/deferred-parameters.json');
  let base, current;
  try {
    base = loadDeferred(baseText);
    current = loadDeferred(fs.readFileSync(currentPath, 'utf8'));
  } catch (err) {
    fail(`deferred-parameters.json unparseable: ${err.message}`);
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

  // DEFER-001..DEFER-015 must be byte-semantically identical to base.
  for (let i = 1; i <= 15; i += 1) {
    const id = `DEFER-${String(i).padStart(3, '0')}`;
    const b = base.map.get(id);
    const c = current.map.get(id);
    if (!b || !c) {
      fail(`${id} missing`);
      continue;
    }
    if (JSON.stringify(b) !== JSON.stringify(c)) {
      fail(`${id} changed:\n  base=${JSON.stringify(b)}\n  curr=${JSON.stringify(c)}`);
    }
  }
  if (baseIds.filter((id) => id !== 'DEFER-016').every((id) => JSON.stringify(base.map.get(id)) === JSON.stringify(current.map.get(id)))) {
    ok('DEFER-001..DEFER-015 byte-semantically unchanged');
  }

  // DEFER-016 transition.
  const b16 = base.map.get('DEFER-016');
  const c16 = current.map.get('DEFER-016');
  if (!b16 || !c16) {
    fail('DEFER-016 missing');
    return { name: 'defer-016', result: 'FAIL', details };
  }
  if (b16.status !== 'DEFERRED_TO_AIPT-M0-B001') {
    fail(`DEFER-016 base status drifted: ${JSON.stringify(b16.status)}`);
  } else ok('DEFER-016 base status was DEFERRED_TO_AIPT-M0-B001 (historical)');
  if (c16.status !== 'RESOLVED') {
    fail(`DEFER-016 status must be RESOLVED: ${JSON.stringify(c16.status)}`);
  } else ok('DEFER-016 status = RESOLVED');
  const value = String(c16.value ?? '');
  const missingVersions = Object.values(TOOLCHAIN).filter((v) => !value.includes(v));
  if (missingVersions.length > 0) {
    fail(`DEFER-016 value missing exact versions: ${missingVersions.join(', ')} (value=${JSON.stringify(c16.value)})`);
  } else ok(`DEFER-016 value carries the four exact versions (${Object.values(TOOLCHAIN).join(' / ')})`);
  if (JSON.stringify(c16.blocks) !== '[]') {
    fail(`DEFER-016 blocks must be empty: ${JSON.stringify(c16.blocks)}`);
  } else ok('DEFER-016 blocks cleared');
  const reason = String(c16.reason ?? '');
  if (!reason.includes('B001') || !(reason.includes('资格') || reason.includes('qualification')) || !reason.includes('CI')) {
    fail(`DEFER-016 reason must explain B001 qualification + CI freeze: ${JSON.stringify(c16.reason)}`);
  } else ok('DEFER-016 reason explains B001 qualification + CI freeze');
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

runAsMain('defer-016', run);
