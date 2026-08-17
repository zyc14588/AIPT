// B001 supply-chain foundation validator (R6): lock presence/integrity,
// action SHA pins, container digest pin, dependency inventory/license
// coverage (with the machine license values checked against the expected
// B001 SPDX license values — the three-layer PostgreSQL model: main
// software = PostgreSQL, docker-library/postgres packaging source = MIT,
// composite Docker Official Image = NOASSERTION, with both frozen digests
// on the image record), a hardened licenses.json baseline (records must be
// a non-empty array with unique ids and all 11 expected identities present;
// duplicate ids fail; future explicit records with new ids remain allowed),
// negative license-inventory regressions on mutated in-memory copies (a
// missing key identity never crashes a probe — the probe records an
// explicit FAIL and is safely skipped), deterministic SBOM inputs, and the
// secret-free / no-real-model-config rules.
import fs from 'node:fs';
import path from 'node:path';
import {
  CI_ACTION_PINS,
  PG_LINUX_AMD64_PLATFORM_DIGEST,
  PG_MULTI_ARCH_DIGEST,
  REQUIRED_SUPPLY_CHAIN_RULES,
  SUPPLY_CHAIN_BASELINE_BATCH,
} from '../lib/constants.mjs';
import { scanTreeForHazards } from '../lib/scan.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

// Expected SPDX license values for the machine `license` fields of the
// current B001 license inventory. Three-layer PostgreSQL model (R6):
//   - postgresql (18.4 main software): SPDX short identifier PostgreSQL —
//     the human full name "PostgreSQL License" may only appear in the
//     human-readable evidence text, never as the machine license value;
//   - docker-library/postgres (packaging source): MIT;
//   - postgresql-docker-official-image (composite container of multiple
//     sources/components): NOASSERTION — PostgreSQL or MIT for the whole
//     image is rejected.
const EXPECTED_SPDX_LICENSES = {
  AIPT: 'MIT',
  'actions/checkout': 'MIT',
  'actions/setup-go': 'MIT',
  'actions/setup-node': 'MIT',
  go: 'BSD-3-Clause',
  node: 'MIT',
  pnpm: 'MIT',
  postgresql: 'PostgreSQL',
  'docker-library/postgres': 'MIT',
  'postgresql-docker-official-image': 'NOASSERTION',
  'golang.org/x/vuln': 'BSD-3-Clause',
};

// Pure machine check over a parsed licenses.json inventory: record sanity
// (records must be a non-empty array with unique ids), the exact expected
// SPDX license value for every current B001 identity (all 11), the frozen
// PostgreSQL digests on the composite-image record, and the zero
// third-party dependency invariant. Future explicit records with new ids
// are allowed; duplicate ids fail. Negative probes feed mutated in-memory
// inventories; the on-disk file is never modified.
function checkLicenseInventory(licenses) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };

  const src = licenses && typeof licenses === 'object' ? licenses : {};
  const records = Array.isArray(src.records) ? src.records : [];
  if (!Array.isArray(src.records) || src.records.length === 0) {
    fail(`licenses.json records must be a non-empty array, got ${Array.isArray(src.records) ? 'an empty array' : typeof src.records}`);
  }
  for (const rec of records) {
    if (!rec?.id || !rec?.license || rec.license === 'UNKNOWN' || rec.license === '') {
      fail(`license record incomplete/unknown: ${JSON.stringify(rec)}`);
    }
    if (!rec?.verified_at) fail(`license record ${rec?.id ?? '?'} missing verified_at`);
  }
  if (records.length > 0 && records.every((r) => r?.id && r.license && r.license !== 'UNKNOWN')) {
    ok(`${records.length} license records, none UNKNOWN`);
  }
  // Id uniqueness: duplicate ids fail now; future explicit records with new
  // ids are allowed.
  const seenIds = new Set();
  const duplicateIds = new Set();
  for (const rec of records) {
    if (typeof rec?.id === 'string' && rec.id !== '') {
      if (seenIds.has(rec.id)) duplicateIds.add(rec.id);
      else seenIds.add(rec.id);
    }
  }
  if (duplicateIds.size > 0) fail(`duplicate license record ids: ${[...duplicateIds].join(', ')}`);
  else if (records.length > 0) ok(`${records.length} license record ids unique`);
  const aiptRec = records.find((r) => r?.id === 'AIPT');
  if (aiptRec?.license !== 'MIT') fail('AIPT license record must be MIT');
  else ok('AIPT = MIT (root LICENSE)');
  // Machine-check every current B001 inventory record against its expected
  // SPDX license value — all 11 expected identities must exist and match
  // exactly (postgresql = PostgreSQL; docker-library/postgres = MIT;
  // composite image = NOASSERTION).
  let spdxLicenseOk = true;
  for (const [id, expected] of Object.entries(EXPECTED_SPDX_LICENSES)) {
    const rec = records.find((r) => r?.id === id);
    if (!rec) {
      fail(`licenses.json missing record ${id}`);
      spdxLicenseOk = false;
      continue;
    }
    if (rec.license !== expected) {
      fail(`licenses.json record ${id} machine license must be ${JSON.stringify(expected)}, got ${JSON.stringify(rec.license)}`);
      spdxLicenseOk = false;
    }
  }
  if (spdxLicenseOk) {
    ok(`${Object.keys(EXPECTED_SPDX_LICENSES).length} B001 license records carry the expected SPDX license values (postgresql = PostgreSQL; docker-library/postgres = MIT; composite image = NOASSERTION)`);
  }
  // The composite-image record must pin both frozen digests exactly.
  const imageRec = records.find((r) => r?.id === 'postgresql-docker-official-image');
  if (!imageRec) {
    fail('licenses.json missing composite image record postgresql-docker-official-image');
  } else {
    if (imageRec.image_multi_arch_digest !== PG_MULTI_ARCH_DIGEST) {
      fail(`composite image record image_multi_arch_digest must be exactly ${PG_MULTI_ARCH_DIGEST}, got ${JSON.stringify(imageRec.image_multi_arch_digest)}`);
    }
    if (imageRec.linux_amd64_platform_digest !== PG_LINUX_AMD64_PLATFORM_DIGEST) {
      fail(`composite image record linux_amd64_platform_digest must be exactly ${PG_LINUX_AMD64_PLATFORM_DIGEST}, got ${JSON.stringify(imageRec.linux_amd64_platform_digest)}`);
    }
    if (imageRec.image_multi_arch_digest === PG_MULTI_ARCH_DIGEST && imageRec.linux_amd64_platform_digest === PG_LINUX_AMD64_PLATFORM_DIGEST) {
      ok('composite image license record pins the exact multi-arch and linux/amd64 platform digests');
    }
  }
  const appDeps = src.application_dependencies && typeof src.application_dependencies === 'object' ? src.application_dependencies : {};
  if (appDeps.go_runtime_third_party_modules !== 0 || appDeps.pnpm_runtime_third_party_packages !== 0) {
    fail('licenses.json application_dependencies must both be 0 at B001');
  } else ok('licenses.json application dependency inventory = 0 / 0');

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
  if (policy.selected_by_batch !== SUPPLY_CHAIN_BASELINE_BATCH) fail(`policy.json selected_by_batch must be ${SUPPLY_CHAIN_BASELINE_BATCH}`);
  else ok('policy.json selected_by_batch = AIPT-M0-B001');
  if (policy.license_policy?.current_third_party_application_runtime_dependencies !== 0) {
    fail('policy.json must record zero third-party application runtime dependencies');
  } else ok('policy.json records zero third-party application runtime dependencies');

  // ---- licenses.json: machine-checked three-layer inventory + negative
  // regressions over mutated in-memory copies (the file is never written) --
  let licenses;
  try {
    licenses = JSON.parse(read('tools/supply-chain/licenses.json'));
  } catch (err) {
    fail(`licenses.json unparseable: ${err.message}`);
    return { name: 'supply-chain', result: 'FAIL', details };
  }
  const records = Array.isArray(licenses?.records) ? licenses.records : [];
  const licSem = checkLicenseInventory(licenses);
  details.push(...licSem.details);
  if (licSem.result !== 'PASS') {
    fail('licenses.json machine license inventory FAIL');
  } else ok('licenses.json machine license inventory PASS');
  const licenseProbes = [
    {
      label: 'composite image record mislabeled PostgreSQL',
      targetId: 'postgresql-docker-official-image',
      reason: /NOASSERTION/,
      mutate: (recs) => {
        recs.find((r) => r.id === 'postgresql-docker-official-image').license = 'PostgreSQL';
      },
    },
    {
      label: 'composite image record mislabeled MIT',
      targetId: 'postgresql-docker-official-image',
      reason: /NOASSERTION/,
      mutate: (recs) => {
        recs.find((r) => r.id === 'postgresql-docker-official-image').license = 'MIT';
      },
    },
    {
      label: 'main software record moved away from PostgreSQL',
      targetId: 'postgresql',
      reason: /PostgreSQL/,
      mutate: (recs) => {
        recs.find((r) => r.id === 'postgresql').license = 'MIT';
      },
    },
    {
      label: 'packaging source record moved away from MIT',
      targetId: 'docker-library/postgres',
      reason: /MIT/,
      mutate: (recs) => {
        recs.find((r) => r.id === 'docker-library/postgres').license = 'BSD-3-Clause';
      },
    },
    {
      label: 'composite image record digest deleted',
      targetId: 'postgresql-docker-official-image',
      reason: /digest/,
      mutate: (recs) => {
        delete recs.find((r) => r.id === 'postgresql-docker-official-image').image_multi_arch_digest;
      },
    },
    {
      label: 'composite image record digest modified',
      targetId: 'postgresql-docker-official-image',
      reason: /digest/,
      mutate: (recs) => {
        const rec = recs.find((r) => r.id === 'postgresql-docker-official-image');
        rec.image_multi_arch_digest = PG_MULTI_ARCH_DIGEST.slice(0, -1) + (PG_MULTI_ARCH_DIGEST.endsWith('6') ? '7' : '6');
      },
    },
    {
      label: 'duplicate record id',
      targetId: 'AIPT',
      reason: /duplicate license record ids/,
      mutate: (recs) => {
        recs.push(JSON.parse(JSON.stringify(recs.find((r) => r.id === 'AIPT'))));
      },
    },
    {
      label: 'key identity record deleted',
      targetId: 'postgresql',
      reason: /missing record postgresql/,
      mutate: (recs) => {
        recs.splice(recs.findIndex((r) => r.id === 'postgresql'), 1);
      },
    },
  ];
  let licenseProbesOk = true;
  for (const probe of licenseProbes) {
    const mutated = JSON.parse(JSON.stringify(licenses));
    const mutatedRecords = Array.isArray(mutated?.records) ? mutated.records : [];
    // Robustness: a missing key identity must never crash a probe through
    // `find` returning undefined. Record an explicit FAIL and safely skip
    // probes that cannot be executed; the baseline check above already
    // reports the missing identity.
    const target = mutatedRecords.find((r) => r?.id === probe.targetId);
    if (!target) {
      fail(`negative license-inventory probe (${probe.label}) could not run: key identity ${JSON.stringify(probe.targetId)} missing from licenses.json records`);
      licenseProbesOk = false;
      continue;
    }
    try {
      probe.mutate(mutatedRecords);
    } catch (err) {
      fail(`negative license-inventory probe (${probe.label}) crashed: ${err.message}`);
      licenseProbesOk = false;
      continue;
    }
    const result = checkLicenseInventory(mutated);
    if (result.result !== 'FAIL') {
      fail(`negative license-inventory probe (${probe.label}) was NOT rejected`);
      licenseProbesOk = false;
    } else {
      const rightReason = result.details.filter((d) => d.startsWith('FAIL')).some((d) => probe.reason.test(d));
      if (!rightReason) {
        fail(`negative license-inventory probe (${probe.label}) failed for an unexpected reason`);
        licenseProbesOk = false;
      } else ok(`negative-probe PASS: licenses.json ${probe.label} rejected by the machine license inventory`);
    }
  }
  if (licenseProbesOk) ok(`all ${licenseProbes.length} license-inventory negative probes rejected as expected`);

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
    const licRec = records.find((r) => r?.id === repo);
    if (!licRec || licRec.license !== entry.license) fail(`${repo} license coverage mismatch between licenses.json and ci-actions.lock.json`);
  }
  if (expectedRepos.every((repo) => {
    const entry = lockByRepo.get(repo);
    const licRec = records.find((r) => r?.id === repo);
    return entry && licRec && licRec.license === entry.license && entry.resolved_commit_sha === CI_ACTION_PINS[repo].sha;
  })) {
    ok('every CI action is SHA-pinned in the lock, license-covered, and verified');
  }

  // ---- lock file presence/integrity ----
  for (const rel of ['tools/toolchain.lock.json', 'tools/ci-actions.lock.json', 'tools/supply-chain/policy.json', 'tools/supply-chain/licenses.json', 'pnpm-lock.yaml', 'go.mod']) {
    if (!fs.existsSync(path.join(ctx.repo, rel))) fail(`required lock file missing: ${rel}`);
  }
  const toolchainLock = JSON.parse(read('tools/toolchain.lock.json'));
  if (toolchainLock.selected_by_batch !== SUPPLY_CHAIN_BASELINE_BATCH) fail('toolchain.lock.json selected_by_batch drifted');
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
