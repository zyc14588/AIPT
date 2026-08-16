// B001 supply-chain foundation validator (R5): lock presence/integrity,
// action SHA pins, container digest pin, dependency inventory/license
// coverage (with the machine license values checked against the expected
// B001 SPDX short identifiers), deterministic SBOM inputs, and the
// secret-free / no-real-model-config rules.
import fs from 'node:fs';
import path from 'node:path';
import {
  CI_ACTION_PINS,
  PG_MULTI_ARCH_DIGEST,
  REQUIRED_SUPPLY_CHAIN_RULES,
  TASK_ID,
} from '../lib/constants.mjs';
import { scanTreeForHazards } from '../lib/scan.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

// Expected SPDX short identifiers for the machine `license` values of the
// current B001 license inventory. PostgreSQL carries the SPDX identifier
// `PostgreSQL`; the human full name "PostgreSQL License" may only appear in
// the human-readable evidence text, never as the machine license value.
const EXPECTED_SPDX_LICENSES = {
  AIPT: 'MIT',
  'actions/checkout': 'MIT',
  'actions/setup-go': 'MIT',
  'actions/setup-node': 'MIT',
  go: 'BSD-3-Clause',
  node: 'MIT',
  pnpm: 'MIT',
  postgresql: 'PostgreSQL',
  'golang.org/x/vuln': 'BSD-3-Clause',
};

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const read = (rel) => fs.readFileSync(path.join(ctx.repo, rel), 'utf8');

  // ---- policy.json: exactly the frozen rule set ----
  let policy;
  try {
    policy = JSON.parse(read('tools/supply-chain/policy.json'));
  } catch (err) {
    fail(`policy.json unparseable: ${err.message}`);
    return { name: 'supply-chain', result: 'FAIL', details };
  }
  const ruleKeys = Object.keys(policy.rules ?? {}).sort();
  const expectedRules = [...REQUIRED_SUPPLY_CHAIN_RULES].sort();
  if (JSON.stringify(ruleKeys) !== JSON.stringify(expectedRules)) {
    fail(`policy rules drifted: got ${ruleKeys.join(',')}, want ${expectedRules.join(',')}`);
  } else ok('policy.json carries exactly the frozen R4-Q023 rule set');
  for (const key of expectedRules) {
    if (policy.rules[key] !== true) fail(`policy rule ${key} must be true`);
  }
  if (policy.selected_by_batch !== TASK_ID) fail(`policy.json selected_by_batch must be ${TASK_ID}`);
  else ok('policy.json selected_by_batch = AIPT-M0-B001');
  if (policy.license_policy?.current_third_party_application_runtime_dependencies !== 0) {
    fail('policy.json must record zero third-party application runtime dependencies');
  } else ok('policy.json records zero third-party application runtime dependencies');

  // ---- licenses.json: inventory coverage, nothing unknown ----
  let licenses;
  try {
    licenses = JSON.parse(read('tools/supply-chain/licenses.json'));
  } catch (err) {
    fail(`licenses.json unparseable: ${err.message}`);
    return { name: 'supply-chain', result: 'FAIL', details };
  }
  const records = licenses.records ?? [];
  if (!Array.isArray(records) || records.length === 0) fail('licenses.json must carry records');
  for (const rec of records) {
    if (!rec.id || !rec.license || rec.license === 'UNKNOWN' || rec.license === '') {
      fail(`license record incomplete/unknown: ${JSON.stringify(rec)}`);
    }
    if (!rec.verified_at) fail(`license record ${rec.id} missing verified_at`);
  }
  if (records.every((r) => r.id && r.license && r.license !== 'UNKNOWN')) {
    ok(`${records.length} license records, none UNKNOWN`);
  }
  const aiptRec = records.find((r) => r.id === 'AIPT');
  if (aiptRec?.license !== 'MIT') fail('AIPT license record must be MIT');
  else ok('AIPT = MIT (root LICENSE)');
  // Machine-check every current B001 inventory record against its expected
  // SPDX short identifier (postgresql must be `PostgreSQL`, not the full
  // human name).
  let spdxLicenseOk = true;
  for (const [id, expected] of Object.entries(EXPECTED_SPDX_LICENSES)) {
    const rec = records.find((r) => r.id === id);
    if (!rec) {
      fail(`licenses.json missing record ${id}`);
      spdxLicenseOk = false;
      continue;
    }
    if (rec.license !== expected) {
      fail(`licenses.json record ${id} machine license must be the SPDX short identifier ${JSON.stringify(expected)}, got ${JSON.stringify(rec.license)}`);
      spdxLicenseOk = false;
    }
  }
  if (spdxLicenseOk) {
    ok(`${Object.keys(EXPECTED_SPDX_LICENSES).length} B001 license records carry the expected SPDX short identifiers (postgresql = PostgreSQL)`);
  }
  if (licenses.application_dependencies?.go_runtime_third_party_modules !== 0 || licenses.application_dependencies?.pnpm_runtime_third_party_packages !== 0) {
    fail('licenses.json application_dependencies must both be 0 at B001');
  } else ok('licenses.json application dependency inventory = 0 / 0');

  // ---- ci-actions.lock.json ----
  let actionsLock;
  try {
    actionsLock = JSON.parse(read('tools/ci-actions.lock.json'));
  } catch (err) {
    fail(`ci-actions.lock.json unparseable: ${err.message}`);
    return { name: 'supply-chain', result: 'FAIL', details };
  }
  const lockByRepo = new Map((actionsLock.actions ?? []).map((a) => [a.repository, a]));
  const expectedRepos = Object.keys(CI_ACTION_PINS);
  if (JSON.stringify([...lockByRepo.keys()].sort()) !== JSON.stringify([...expectedRepos].sort())) {
    fail('ci-actions.lock.json repository set drifted');
  }
  for (const [repo, pin] of Object.entries(CI_ACTION_PINS)) {
    const entry = lockByRepo.get(repo);
    if (!entry) {
      fail(`ci-actions.lock.json missing ${repo}`);
      continue;
    }
    for (const field of ['repository', 'stable_release_tag', 'resolved_commit_sha', 'license', 'source_verified_at', 'purpose']) {
      if (!entry[field]) fail(`${repo} lock entry missing ${field}`);
    }
    if (entry.resolved_commit_sha !== pin.sha) fail(`${repo} resolved SHA drifted vs fixed qualification`);
    if (entry.stable_release_tag !== pin.tag) fail(`${repo} stable tag drifted vs fixed qualification`);
    const licRec = records.find((r) => r.id === repo);
    if (!licRec || licRec.license !== entry.license) fail(`${repo} license coverage mismatch between licenses.json and ci-actions.lock.json`);
  }
  if (expectedRepos.every((repo) => {
    const entry = lockByRepo.get(repo);
    const licRec = records.find((r) => r.id === repo);
    return entry && licRec && licRec.license === entry.license && entry.resolved_commit_sha === CI_ACTION_PINS[repo].sha;
  })) {
    ok('every CI action is SHA-pinned in the lock, license-covered, and verified');
  }

  // ---- lock file presence/integrity ----
  for (const rel of ['tools/toolchain.lock.json', 'tools/ci-actions.lock.json', 'tools/supply-chain/policy.json', 'tools/supply-chain/licenses.json', 'pnpm-lock.yaml', 'go.mod']) {
    if (!fs.existsSync(path.join(ctx.repo, rel))) fail(`required lock file missing: ${rel}`);
  }
  const toolchainLock = JSON.parse(read('tools/toolchain.lock.json'));
  if (toolchainLock.selected_by_batch !== TASK_ID) fail('toolchain.lock.json selected_by_batch drifted');
  for (const [key, digest] of Object.entries({ multi_arch_digest: PG_MULTI_ARCH_DIGEST })) {
    if (toolchainLock.toolchains?.postgresql?.docker_official_image?.[key] !== digest) {
      fail(`toolchain.lock.json postgresql ${key} drifted`);
    }
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(toolchainLock.toolchains?.postgresql?.docker_official_image?.multi_arch_digest ?? '')) {
    fail('postgresql multi-arch digest malformed');
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(toolchainLock.toolchains?.postgresql?.docker_official_image?.linux_amd64_platform_digest ?? '')) {
    fail('postgresql linux/amd64 platform digest malformed');
  }
  ok('lock files present and structurally sound');

  // ---- workflow consistency (action pins + container digest) ----
  const workflow = read('.github/workflows/ci.yml');
  const uses = [...workflow.matchAll(/^\s*uses:\s*([^\s#]+)/gm)].map((m) => m[1]);
  for (const use of uses) {
    const ref = use.slice(use.lastIndexOf('@') + 1);
    if (!/^[0-9a-f]{40}$/.test(ref)) fail(`workflow uses: not full-SHA: ${use}`);
    const repo = use.slice(0, use.lastIndexOf('@'));
    if (lockByRepo.get(repo)?.resolved_commit_sha !== ref) fail(`workflow uses: ${use} not in lock`);
  }
  if (uses.length > 0 && uses.every((u) => {
    const repo = u.slice(0, u.lastIndexOf('@'));
    const ref = u.slice(u.lastIndexOf('@') + 1);
    return /^[0-9a-f]{40}$/.test(ref) && lockByRepo.get(repo)?.resolved_commit_sha === ref;
  })) {
    ok(`workflow uses: entries (${uses.length}) all full-SHA and lock-consistent`);
  }
  if (!workflow.includes(`postgres@${PG_MULTI_ARCH_DIGEST}`)) fail('workflow container pull is not digest-pinned');
  else ok('workflow PostgreSQL pull pinned by multi-arch digest');

  // ---- dependency inventory: zero third-party runtime deps ----
  const goMod = read('go.mod');
  if (/^require\b/m.test(goMod)) fail('go.mod has runtime requires (forbidden at B001)');
  else ok('go.mod: zero module requirements (no third-party runtime dependency)');
  const pnpmLock = read('pnpm-lock.yaml');
  if (/^packages:\s*$/m.test(pnpmLock)) fail('pnpm-lock.yaml carries third-party packages');
  else ok('pnpm-lock.yaml: zero third-party packages (root importer only)');
  if (!pnpmLock.includes('lockfileVersion')) fail('pnpm-lock.yaml missing lockfileVersion');
  const importers = /^importers:\s*\n((?:(?!^\S)[\s\S])*)/m.exec(pnpmLock)?.[1] ?? '';
  const importerKeys = [...importers.matchAll(/^\s{2}['"]?([^'"\s:]+)['"]?:/gm)].map((m) => m[1]);
  if (importerKeys.length !== 1 || importerKeys[0] !== '.') {
    fail(`pnpm-lock importers must be exactly the root package: ${JSON.stringify(importerKeys)}`);
  } else ok('pnpm-lock importers = root package only');
  if (importers.includes('specifiers:')) {
    fail('pnpm-lock root importer carries specifiers (unexpected dependencies)');
  } else ok('pnpm-lock root importer has no dependency specifiers');

  // ---- provenance inputs ----
  const head = git(ctx.repo, ['rev-parse', 'HEAD']).stdout.trim();
  if (!/^[0-9a-f]{40}$/.test(head)) fail('provenance input unavailable: git HEAD not resolvable');
  else ok(`provenance input available (HEAD ${head.slice(0, 12)})`);
  const lockTimestamps = ['go', 'node', 'pnpm', 'postgresql'].every(
    (k) => toolchainLock.toolchains?.[k]?.source_verification?.verified_at,
  );
  if (!lockTimestamps) fail('toolchain.lock.json missing source verification timestamps');
  else ok('toolchain.lock.json records source verification times');
  const actionTimestamps = [...lockByRepo.values()].every((a) => a.source_verified_at);
  if (!actionTimestamps) fail('ci-actions.lock.json missing source verification timestamps');
  else ok('ci-actions.lock.json records source verification times');

  // ---- secret / real-model-config hygiene on tracked config AND executable
  // scripts (no blanket scripts/ci skip; the scanner sources are self-safe
  // because every hazard literal is assembled from fragments) ----
  const hazards = scanTreeForHazards(ctx.repo);
  if (hazards.length > 0) {
    for (const h of hazards.slice(0, 20)) fail(`hazard ${h.hazard} in ${h.file}: ${JSON.stringify(h.sample)}`);
  } else ok('no secrets, private paths, model endpoints or prompt bodies in tracked config or executable scripts');
  if (workflow.includes('secrets.')) fail('workflow references secrets.*');
  else ok('workflow secret-free');

  return { name: 'supply-chain', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'supply-chain', run);
