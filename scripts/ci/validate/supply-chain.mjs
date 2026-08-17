// AIPT supply-chain validator (B001 foundation, evolved by B002 iteration 4).
//
// Gates: lock presence/integrity, action SHA pins, container digest pin,
// dependency inventory/license coverage (machine SPDX license values —
// three-layer PostgreSQL model: main software = PostgreSQL, packaging source
// = MIT, composite Docker Official Image = NOASSERTION with both frozen
// digests), a hardened licenses.json baseline, the first-party pnpm workspace
// model (exact importer set {root, packages/adapter-sdk}, zero dependency
// specifiers, zero third-party packages), negative regressions on mutated
// in-memory copies, deterministic SBOM inputs, and the secret-free /
// no-real-model-config rules.
//
// B002 iteration 4 evolution (explicit model):
//   - exact expected first-party set = {AIPT root, @aipt/adapter-sdk} (both
//     kind first_party, MIT, with the SDK record carrying its own truthful
//     B002 metadata — never claimed as B001-verified);
//   - exact approved tooling/CI/infrastructure set preserved from B001
//     (actions/*, go, node, pnpm, postgresql, docker-library/postgres,
//     postgresql-docker-official-image, golang.org/x/vuln) with their exact
//     SPDX license values and frozen pins;
//   - zero unrecorded third-party Go/pnpm packages: go.mod has no requires,
//     pnpm-lock.yaml has no `packages:` section, and any license record id
//     outside the exact 12-identity set is rejected.
// The B001 "root importer only" snapshot is superseded by the exact two-
// importer workspace model; the exact-set validation is kept and extended,
// never deleted.
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
// license inventory. Three-layer PostgreSQL model (R6):
//   - postgresql (18.4 main software): SPDX short identifier PostgreSQL —
//     the human full name "PostgreSQL License" may only appear in the
//     human-readable evidence text, never as the machine license value;
//   - docker-library/postgres (packaging source): MIT;
//   - postgresql-docker-official-image (composite container of multiple
//     sources/components): NOASSERTION — PostgreSQL or MIT for the whole
//     image is rejected.
// B002 iteration 4 adds the first-party @aipt/adapter-sdk record (MIT).
const EXPECTED_SPDX_LICENSES = {
  AIPT: 'MIT',
  '@aipt/adapter-sdk': 'MIT',
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

// Exact expected record kinds for the current inventory: the exact
// first-party set {AIPT, @aipt/adapter-sdk} plus the exact approved
// tooling/CI/infrastructure set preserved from B001.
const EXPECTED_RECORD_KINDS = {
  AIPT: 'first_party',
  '@aipt/adapter-sdk': 'first_party',
  'actions/checkout': 'ci_action',
  'actions/setup-go': 'ci_action',
  'actions/setup-node': 'ci_action',
  go: 'toolchain',
  node: 'toolchain',
  pnpm: 'toolchain',
  postgresql: 'infrastructure_image_component',
  'docker-library/postgres': 'infrastructure_image_component',
  'postgresql-docker-official-image': 'infrastructure_image',
  'golang.org/x/vuln': 'supply_chain_tooling',
};

const EXPECTED_FIRST_PARTY_IDS = ['AIPT', '@aipt/adapter-sdk'];

// Truthful B002 metadata the SDK inventory record must carry: the SDK was
// verified in AIPT-M0-B002 iteration 4, never in B001.
const SDK_RECORD = {
  id: '@aipt/adapter-sdk',
  version: '1.0.0',
  selected_by_batch: 'AIPT-M0-B002',
  verified_at: '2026-08-17T07:15:00Z',
};

// Pure machine check over a parsed licenses.json inventory: record sanity
// (records must be a non-empty array with unique ids), the exact 12-identity
// record set (exact first-party set + exact B001 tooling/CI/infrastructure
// set), exact SPDX license values, exact record kinds, the truthful SDK
// record metadata, the frozen PostgreSQL digests on the composite-image
// record, and the zero third-party dependency invariant. Negative probes
// feed mutated in-memory inventories; the on-disk file is never modified.
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
  // Id uniqueness: duplicate ids fail now and forever.
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
  // Machine-check every expected inventory record against its expected SPDX
  // license value and kind — all 12 expected identities must exist and match
  // exactly.
  let identityOk = true;
  for (const [id, expected] of Object.entries(EXPECTED_SPDX_LICENSES)) {
    const rec = records.find((r) => r?.id === id);
    if (!rec) {
      fail(`licenses.json missing record ${id}`);
      identityOk = false;
      continue;
    }
    if (rec.license !== expected) {
      fail(`licenses.json record ${id} machine license must be ${JSON.stringify(expected)}, got ${JSON.stringify(rec.license)}`);
      identityOk = false;
    }
    const kind = EXPECTED_RECORD_KINDS[id];
    if (rec.kind !== kind) {
      fail(`licenses.json record ${id} kind must be ${JSON.stringify(kind)}, got ${JSON.stringify(rec.kind)}`);
      identityOk = false;
    }
  }
  if (identityOk) {
    ok(`${Object.keys(EXPECTED_SPDX_LICENSES).length} license records carry the expected SPDX license values and kinds (exact first-party set + exact B001 tooling/CI/infrastructure set)`);
  }
  // Exact-set model: no unrecorded third-party identity may exist.
  const known = new Set(Object.keys(EXPECTED_SPDX_LICENSES));
  const unrecorded = records.filter((r) => typeof r?.id === 'string' && r.id !== '' && !known.has(r.id));
  if (unrecorded.length > 0) {
    fail(`unrecorded license record ids (zero unrecorded third-party Go/pnpm packages): ${unrecorded.map((r) => r.id).join(', ')}`);
  } else if (records.length > 0 && records.length === known.size) {
    ok(`license record set is exactly the ${known.size} expected identities (zero unrecorded third-party packages)`);
  }
  // Exact first-party set: exactly AIPT + @aipt/adapter-sdk.
  const firstParty = records.filter((r) => r?.kind === 'first_party').map((r) => r?.id).sort();
  if (JSON.stringify(firstParty) !== JSON.stringify([...EXPECTED_FIRST_PARTY_IDS].sort())) {
    fail(`first-party set must be exactly ${EXPECTED_FIRST_PARTY_IDS.join(' + ')}, got ${JSON.stringify(firstParty)}`);
  } else ok(`exact first-party set: ${EXPECTED_FIRST_PARTY_IDS.join(' + ')}`);
  // Truthful SDK record metadata (B002-verified, never B001).
  const sdkRec = records.find((r) => r?.id === SDK_RECORD.id);
  if (sdkRec) {
    if (sdkRec.version !== SDK_RECORD.version) fail(`@aipt/adapter-sdk license record version must be ${SDK_RECORD.version}, got ${JSON.stringify(sdkRec.version)}`);
    if (sdkRec.selected_by_batch !== SDK_RECORD.selected_by_batch) fail(`@aipt/adapter-sdk license record selected_by_batch must be ${SDK_RECORD.selected_by_batch} (truthful B002 metadata)`);
    if (sdkRec.verified_at !== SDK_RECORD.verified_at) fail(`@aipt/adapter-sdk license record verified_at must be ${SDK_RECORD.verified_at} (verified in B002, never B001)`);
    if (typeof sdkRec.evidence !== 'string' || !sdkRec.evidence.includes('packages/adapter-sdk') || !sdkRec.evidence.includes('LICENSE')) {
      fail('@aipt/adapter-sdk license record evidence must reference packages/adapter-sdk and the root LICENSE');
    } else ok('@aipt/adapter-sdk license record carries truthful B002 metadata (version 1.0.0, B002 selection, B002 verification, root LICENSE evidence)');
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
    fail('licenses.json application_dependencies must both be 0');
  } else ok('licenses.json application dependency inventory = 0 / 0');

  return { result: pass ? 'PASS' : 'FAIL', details };
}

// Pure machine check of the first-party pnpm workspace model.
//   - exact importer set: '.' plus exactly the registered workspace package
//     directories (B002 iteration 4: packages/adapter-sdk);
//   - every importer carries zero dependency specifiers;
//   - zero third-party packages (no `packages:` section);
//   - pnpm-workspace.yaml declares packages/* and its prose names the SDK.
function checkPnpmWorkspaceModel({ lockText, importerDirs, workspaceYaml }) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const text = typeof lockText === 'string' ? lockText : '';
  if (!text.includes('lockfileVersion')) fail('pnpm-lock.yaml missing lockfileVersion');
  if (/^packages:\s*$/m.test(text)) fail('pnpm-lock.yaml carries third-party packages (zero unrecorded third-party Go/pnpm packages required)');
  else ok('pnpm-lock.yaml: zero third-party packages section');

  const allLines = text.split('\n');
  const importerStart = allLines.findIndex((line) => line.trim() === 'importers:');
  const section = [];
  if (importerStart !== -1) {
    for (let index = importerStart + 1; index < allLines.length; index += 1) {
      if (/^\S/.test(allLines[index])) break; // next top-level key ends the section
      section.push(allLines[index]);
    }
  }
  const importers = new Map(); // key -> { inline: string, content: string[] }
  let current = null;
  for (const line of section) {
    const keyMatch = /^  ([^\s:]+):(.*)$/.exec(line);
    if (keyMatch) {
      current = { key: keyMatch[1], inline: keyMatch[2].trim(), content: [] };
      importers.set(current.key, current);
    } else if (current && line.trim() !== '') {
      current.content.push(line);
    }
  }
  const expectedKeys = ['.', ...importerDirs].sort();
  const actualKeys = [...importers.keys()].sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
    fail(`pnpm-lock importers must be exactly the registered workspace importers [${expectedKeys.join(', ')}], got [${actualKeys.join(', ')}] (unregistered workspace importer/package rejected)`);
  } else ok(`pnpm-lock importers = exactly [${expectedKeys.join(', ')}]`);
  let specifierFree = true;
  for (const [key, importer] of importers) {
    if (!(importer.inline === '{}' && importer.content.length === 0)) {
      fail(`pnpm-lock importer ${JSON.stringify(key)} carries dependency specifiers (importer entry must be exactly <key>: {})`);
      specifierFree = false;
    }
  }
  if (specifierFree) ok('every pnpm-lock importer carries zero dependency specifiers');
  if (typeof workspaceYaml === 'string') {
    if (!workspaceYaml.includes('"packages/*"')) fail('pnpm-workspace.yaml must keep the packages/* workspace glob');
    else if (!workspaceYaml.includes('packages/adapter-sdk')) fail('pnpm-workspace.yaml prose must name the registered first-party package packages/adapter-sdk');
    else ok('pnpm-workspace.yaml declares packages/* and names packages/adapter-sdk');
  }
  return { result: pass ? 'PASS' : 'FAIL', details };
}

// Pure machine check that every registered workspace package directory has a
// matching first-party license record (id == package name, version ==
// package version, MIT == package license) and zero dependency specifiers.
function checkWorkspaceFirstParty(packageEntries, licenses) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const records = Array.isArray(licenses?.records) ? licenses.records : [];
  for (const entry of packageEntries) {
    const record = records.find((r) => r?.id === entry.name);
    if (!record) {
      fail(`workspace package ${JSON.stringify(entry.dir)} (${entry.name}) has no first-party license record`);
      continue;
    }
    if (record.kind !== 'first_party') fail(`workspace package ${entry.name} license record must be kind first_party`);
    if (record.license !== entry.license || entry.license !== 'MIT') fail(`workspace package ${entry.name} license record must be MIT (package says ${JSON.stringify(entry.license)})`);
    if (record.version !== entry.version) fail(`workspace package ${entry.name} license record version ${JSON.stringify(record.version)} must equal package.json version ${JSON.stringify(entry.version)}`);
    if (entry.hasDeps) fail(`workspace package ${entry.name} carries dependency specifiers (first-party packages must stay dependency-free)`);
    else ok(`workspace package ${entry.name}@${entry.version}: first-party, MIT, dependency-free, license-covered`);
  }
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
  else ok('policy.json selected_by_batch = AIPT-M0-B001 (historical baseline selector, unchanged)');
  if (policy.license_policy?.current_third_party_application_runtime_dependencies !== 0) {
    fail('policy.json must record zero third-party application runtime dependencies');
  } else ok('policy.json records zero third-party application runtime dependencies');

  // ---- licenses.json: machine-checked inventory + negative regressions over
  // mutated in-memory copies (the file is never written) ----
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
    {
      label: 'adapter SDK inventory record deleted',
      targetId: SDK_RECORD.id,
      reason: /missing record @aipt\/adapter-sdk/,
      mutate: (recs) => {
        recs.splice(recs.findIndex((r) => r.id === SDK_RECORD.id), 1);
      },
    },
    {
      label: 'adapter SDK inventory record wrongly licensed',
      targetId: SDK_RECORD.id,
      reason: /MIT/,
      mutate: (recs) => {
        recs.find((r) => r.id === SDK_RECORD.id).license = 'Apache-2.0';
      },
    },
    {
      label: 'adapter SDK inventory record kind not first-party',
      targetId: SDK_RECORD.id,
      reason: /first_party/,
      mutate: (recs) => {
        recs.find((r) => r.id === SDK_RECORD.id).kind = 'dev_tool';
      },
    },
    {
      label: 'adapter SDK inventory record pretends B001 verification',
      targetId: SDK_RECORD.id,
      reason: /selected_by_batch|verified_at/,
      mutate: (recs) => {
        const rec = recs.find((r) => r.id === SDK_RECORD.id);
        rec.selected_by_batch = 'AIPT-M0-B001';
        rec.verified_at = '2026-08-16T06:51:41Z';
      },
    },
    {
      label: 'unrecorded third-party license identity injected',
      targetId: 'AIPT',
      reason: /unrecorded license record ids/,
      mutate: (recs) => {
        recs.push({
          id: 'rogue-third-party-lib',
          kind: 'third_party',
          license: 'MIT',
          version: '1.2.3',
          evidence: 'probe',
          verified_at: '2026-08-17T00:00:00Z',
        });
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

  // ---- first-party pnpm workspace model (B002 iteration 4) ----
  const workspaceYaml = read('pnpm-workspace.yaml');
  const pnpmLockText = read('pnpm-lock.yaml');
  const packagesRoot = path.join(ctx.repo, 'packages');
  const importerDirs = [];
  const packageEntries = [];
  for (const entry of fs.readdirSync(packagesRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const pkgPath = path.join(packagesRoot, entry.name, 'package.json');
    if (!fs.existsSync(pkgPath)) continue;
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    importerDirs.push(`packages/${entry.name}`);
    packageEntries.push({
      dir: `packages/${entry.name}`,
      name: pkg.name,
      version: pkg.version,
      license: pkg.license,
      hasDeps: Boolean(pkg.dependencies || pkg.devDependencies || pkg.peerDependencies || pkg.optionalDependencies),
    });
  }
  if (importerDirs.length === 0) fail('no workspace packages found under packages/ (packages/adapter-sdk missing)');
  const workspaceModel = checkPnpmWorkspaceModel({ lockText: pnpmLockText, importerDirs, workspaceYaml });
  details.push(...workspaceModel.details);
  if (workspaceModel.result !== 'PASS') fail('first-party pnpm workspace model FAIL');
  else ok('first-party pnpm workspace model PASS: exact importer set, zero specifiers, zero third-party packages');
  const workspaceFirstParty = checkWorkspaceFirstParty(packageEntries, licenses);
  details.push(...workspaceFirstParty.details);
  if (workspaceFirstParty.result !== 'PASS') fail('workspace first-party license coverage FAIL');
  else ok('every workspace package is license-covered as first-party');
  // Negative workspace probes over mutated in-memory inputs.
  const workspaceProbes = [
    {
      label: 'unregistered workspace importer injected into the lock',
      reason: /unregistered workspace importer|importers must be exactly/,
      mutate: () => checkPnpmWorkspaceModel({
        lockText: pnpmLockText.replace('  packages/adapter-sdk: {}', '  packages/adapter-sdk: {}\n\n  packages/rogue-pkg: {}'),
        importerDirs,
        workspaceYaml,
      }),
    },
    {
      label: 'registered SDK importer missing from the lock',
      reason: /importers must be exactly/,
      mutate: () => checkPnpmWorkspaceModel({
        lockText: pnpmLockText.replace(/  packages\/adapter-sdk: \{\}\n/, ''),
        importerDirs,
        workspaceYaml,
      }),
    },
    {
      label: 'dependency specifier smuggled into an importer',
      reason: /dependency specifiers/,
      mutate: () => checkPnpmWorkspaceModel({
        lockText: pnpmLockText.replace('  packages/adapter-sdk: {}', '  packages/adapter-sdk:\n    dependencies:\n      is-odd:\n        specifier: ^3.0.0\n        version: 3.0.2'),
        importerDirs,
        workspaceYaml,
      }),
    },
    {
      label: 'third-party package smuggled into the packages section',
      reason: /third-party packages/,
      mutate: () => checkPnpmWorkspaceModel({
        lockText: `${pnpmLockText}\npackages:\n\n  is-odd@3.0.2:\n    resolution: {integrity: sha512-probe}\n`,
        importerDirs,
        workspaceYaml,
      }),
    },
  ];
  let workspaceProbesOk = true;
  for (const probe of workspaceProbes) {
    let result;
    try {
      result = probe.mutate();
    } catch (err) {
      fail(`negative workspace probe (${probe.label}) crashed: ${err.message}`);
      workspaceProbesOk = false;
      continue;
    }
    if (result.result !== 'FAIL') {
      fail(`negative workspace probe (${probe.label}) was NOT rejected`);
      workspaceProbesOk = false;
    } else {
      const rightReason = result.details.filter((d) => d.startsWith('FAIL')).some((d) => probe.reason.test(d));
      if (!rightReason) fail(`negative workspace probe (${probe.label}) failed for an unexpected reason`);
      else ok(`negative-probe PASS: workspace model rejects ${probe.label}`);
    }
  }
  if (workspaceProbesOk) ok(`all ${workspaceProbes.length} workspace-model negative probes rejected as expected`);

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
  if (/^require\b/m.test(goMod)) fail('go.mod has runtime requires (forbidden)');
  else ok('go.mod: zero module requirements (no third-party runtime dependency)');
  ok('pnpm-lock.yaml: zero third-party packages (exact workspace importer set checked above)');

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
