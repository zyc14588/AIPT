// AIPT supply-chain validator (B001 foundation, evolved by B002 iteration 4
// and AIPT-M0-B003 iteration 6a).
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
// AIPT-M0-B003 iteration 6a evolution (explicit model):
//   - the exact approved six-module pgx v5.10.0 Go runtime closure in
//     go.mod/go.sum (direct github.com/jackc/pgx/v5 v5.10.0 plus five indirect
//     modules), cross-checked against go.sum zip + /go.mod h1 availability and
//     the pinned h1 SHA-256 hex values;
//   - six third-party Go runtime license records (kind
//     third_party_go_runtime, role runtime_dependency) with exact versions,
//     SPDX licenses (MIT for jackc modules, BSD-3-Clause for golang.org/x
//     modules), directness, and truthful B003 selection/verification metadata;
//     the exact inventory set grows from 12 to 18 identities;
//   - application dependency inventory go=6 / pnpm=0 in licenses.json, while
//     the frozen B001 policy.json baseline keeps its immutable
//     current_third_party_application_runtime_dependencies = 0;
//   - the go toolchain license record (id go) carries the current Go 1.26.6
//     identity with its top-level verified_at bumped to the exact B003
//     security requalification UTC verification time 2026-08-20T04:16:01Z
//     (the ONLY record whose verified_at the security requalification
//     touches — every other record's verified_at stays unchanged) and a
//     closed-shape security_requalification object whose exact key set is
//     {batch, previous_go_version, current_go_version, verified_at, reason,
//     officially_fixed_in, advisory_ids} with the exact B003 values;
//   - focused negative probes reject mutated go.mod/go.sum (unknown dependency,
//     version drift, directness flip, missing/tampered h1) and mutated
//     inventory records (Go runtime record deleted / wrongly licensed / wrong
//     version / directness flipped / pretending B001 verification, go
//     toolchain record version reverted to 1.26.5, missing/wrong
//     security_requalification metadata, wrong advisory set, drifted previous/
//     current go version, wrong verified_at, top-level verified_at not the
//     B003 time, extra key in security_requalification, ambiguous go_version
//     key).
// The B001 "root importer only" snapshot is superseded by the exact two-
// importer workspace model; the exact-set validation is kept and extended,
// never deleted. The frozen policy.json remains an immutable B001 baseline and
// is never rewritten.
import fs from 'node:fs';
import path from 'node:path';
import {
  CI_ACTION_PINS,
  PG_LINUX_AMD64_PLATFORM_DIGEST,
  PG_MULTI_ARCH_DIGEST,
  REQUIRED_SUPPLY_CHAIN_RULES,
  SUPPLY_CHAIN_BASELINE_BATCH,
  TOOLCHAIN,
} from '../lib/constants.mjs';
import { scanTreeForHazards } from '../lib/scan.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

// The exact approved pgx v5.10.0 Go runtime closure (AIPT-M0-B003 iteration
// 6a): github.com/jackc/pgx/v5 v5.10.0 is the single direct module required
// by internal/storage/postgres; the five indirect modules are its transitive
// runtime dependencies as recorded by go.mod. h1hex is the pinned SHA-256
// (64 lowercase hex) that the go.sum zip `h1:` base64 payload must decode to;
// gomodhex is the pinned SHA-256 that the `<module> <version>/go.mod h1:`
// base64 payload must decode to — both go.sum values are derived and
// compared, so a tampered-but-still-base64 h1 cannot pass.
const GO_RUNTIME_MODULES = [
  { module: 'github.com/jackc/pgx/v5', version: 'v5.10.0', direct: true, license: 'MIT', h1hex: '5614af814da34a58bca3702a20439326beeb670004515a381385e147de197ebd', gomodhex: '99a975b4118015f2c7bd9cda621efb612fde0ba217f4e59b455d50208334267e' },
  { module: 'github.com/jackc/pgpassfile', version: 'v1.0.0', direct: false, license: 'MIT', h1hex: 'ffa1e6ab2d774acdb30aaeb655d346f2d335c1c867f338d218e049ea2729b083', gomodhex: '084c74892e5a99b34575c46dc4f8f9261133fb107ab91932e5ec95bbf5b61c48' },
  { module: 'github.com/jackc/pgservicefile', version: 'v0.0.0-20240606120523-5a60cdf6a761', direct: false, license: 'MIT', h1hex: '882127a287bb525c0e418a4a16105a6cf322e1a3407e83833c414d8809c2971a', gomodhex: 'e5325958a1169e23ef7b7def956612a0661e7e7de02d04738df0e585227d64a3' },
  { module: 'github.com/jackc/puddle/v2', version: 'v2.2.2', direct: false, license: 'MIT', h1hex: '3d1f27c3e13fd70d062ee4454a68a2a18e94a28329e8a26fd3feb59c1ee2707a', gomodhex: 'beb8a21171ef104eb9e1a60a5d78cebd9337f6a274abe6b391916b7c439cdc7e' },
  { module: 'golang.org/x/sync', version: 'v0.17.0', direct: false, license: 'BSD-3-Clause', h1hex: '97ad2738d323f65e5daeac3a8e584810b36ff48d00e0e16046c1bd936a13f548', gomodhex: 'f4a4c75e64a7a06aee2e9c058d5497d2534d03be42ca488c1026e8bcd4d9a862' },
  { module: 'golang.org/x/text', version: 'v0.29.0', direct: false, license: 'BSD-3-Clause', h1hex: 'd6778db3dd30f58cc9f41a1cc5fb103472ae013e299208725dce27859eac26f9', gomodhex: 'ecc849380f420f6a99c8e2986b3c5d60c17ce4ec0f744afd8d3b41a4eef2747e' },
];

// Expected SPDX license values for the machine `license` fields of the
// license inventory. Three-layer PostgreSQL model (R6):
//   - postgresql (18.4 main software): SPDX short identifier PostgreSQL —
//     the human full name "PostgreSQL License" may only appear in the
//     human-readable evidence text, never as the machine license value;
//   - docker-library/postgres (packaging source): MIT;
//   - postgresql-docker-official-image (composite container of multiple
//     sources/components): NOASSERTION — PostgreSQL or MIT for the whole
//     image is rejected.
// B002 iteration 4 adds the first-party @aipt/adapter-sdk record (MIT);
// AIPT-M0-B003 iteration 6a adds the six third-party Go runtime records
// (MIT for the four jackc modules, BSD-3-Clause for the two golang.org/x
// modules).
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
  'github.com/jackc/pgx/v5': 'MIT',
  'github.com/jackc/pgpassfile': 'MIT',
  'github.com/jackc/pgservicefile': 'MIT',
  'github.com/jackc/puddle/v2': 'MIT',
  'golang.org/x/sync': 'BSD-3-Clause',
  'golang.org/x/text': 'BSD-3-Clause',
};

// Exact expected record kinds for the current inventory: the exact
// first-party set {AIPT, @aipt/adapter-sdk} plus the exact approved
// tooling/CI/infrastructure set preserved from B001 plus the six approved
// third-party Go runtime modules.
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
  'github.com/jackc/pgx/v5': 'third_party_go_runtime',
  'github.com/jackc/pgpassfile': 'third_party_go_runtime',
  'github.com/jackc/pgservicefile': 'third_party_go_runtime',
  'github.com/jackc/puddle/v2': 'third_party_go_runtime',
  'golang.org/x/sync': 'third_party_go_runtime',
  'golang.org/x/text': 'third_party_go_runtime',
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
// (records must be a non-empty array with unique ids), the exact 18-identity
// record set (exact first-party set + exact B001 tooling/CI/infrastructure
// set + exact B003 six-module Go runtime closure), exact SPDX license values,
// exact record kinds, the truthful SDK record metadata, the truthful B003 Go
// runtime record metadata (version/directness/role/selection), the frozen
// PostgreSQL digests on the composite-image record, and the exact
// go=6/pnpm=0 application dependency inventory. Negative probes feed mutated
// in-memory inventories; the on-disk file is never modified.
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
  // Top-level baseline lock: licenses.json's own selected_by_batch must be
  // the immutable historical SUPPLY_CHAIN_BASELINE_BATCH (AIPT-M0-B001). The
  // B003 Go runtime records inside carry their own truthful
  // selected_by_batch = AIPT-M0-B003, but the FILE-level baseline selector is
  // a B001 fact and is never rewritten to B003.
  if (src.selected_by_batch !== SUPPLY_CHAIN_BASELINE_BATCH) {
    fail(`licenses.json top-level selected_by_batch must be ${SUPPLY_CHAIN_BASELINE_BATCH} (immutable B001 baseline selector, never rewritten), got ${JSON.stringify(src.selected_by_batch)}`);
  } else ok(`licenses.json top-level selected_by_batch = ${SUPPLY_CHAIN_BASELINE_BATCH} (historical B001 baseline selector preserved)`);
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
  // The go toolchain record must carry the exact current Go identity (B003
  // security requalification: 1.26.6) with the truthful closed-shape B003
  // security requalification metadata — never the historical B001 1.26.5 as
  // the current version, and never the ambiguous go_version key.
  const goRec = records.find((r) => r?.id === 'go');
  if (goRec?.version !== TOOLCHAIN.go) {
    fail(`go toolchain license record version must be the current ${TOOLCHAIN.go} (B003 security requalification), got ${JSON.stringify(goRec?.version)}`);
  } else ok(`go toolchain license record version = ${TOOLCHAIN.go} (current B003 security requalification)`);
  const goSec = goRec?.security_requalification;
  // The go record's top-level verified_at must be the exact B003 security
  // requalification UTC verification time (this is the ONLY record whose
  // verified_at was bumped by the security requalification; every other
  // record's verified_at is untouched).
  if (goRec?.verified_at !== '2026-08-20T04:16:01Z') {
    fail(`go toolchain license record top-level verified_at must be 2026-08-20T04:16:01Z (B003 security requalification verification time): ${JSON.stringify(goRec?.verified_at)}`);
  } else ok(`go toolchain license record top-level verified_at = 2026-08-20T04:16:01Z (B003 security requalification verification time)`);
  if (!goSec || typeof goSec !== 'object') {
    fail('go toolchain license record must carry the truthful B003 security requalification metadata (batch AIPT-M0-B003, previous Go 1.26.5 -> current Go 1.26.6, verified_at 2026-08-20T04:16:01Z)');
  } else {
    // Exact closed key set: the nested security_requalification object is
    // exactly {batch, previous_go_version, current_go_version, verified_at,
    // reason, officially_fixed_in, advisory_ids} — an extra or missing key
    // fails.
    const goSecKeys = Object.keys(goSec).sort().join(',');
    const expectedGoSecKeys = ['advisory_ids', 'batch', 'current_go_version', 'officially_fixed_in', 'previous_go_version', 'reason', 'verified_at'].sort().join(',');
    if (goSecKeys !== expectedGoSecKeys) {
      fail(`go toolchain license record security requalification key set must be exactly batch, previous_go_version, current_go_version, verified_at, reason, officially_fixed_in, advisory_ids (closed shape): ${JSON.stringify(Object.keys(goSec))}`);
    }
    if (goSec.batch !== 'AIPT-M0-B003') fail(`go toolchain license record security requalification batch must be AIPT-M0-B003: ${JSON.stringify(goSec.batch)}`);
    if (goSec.previous_go_version !== '1.26.5') fail(`go toolchain license record security requalification previous_go_version must be 1.26.5 (the B001-qualified Go): ${JSON.stringify(goSec.previous_go_version)}`);
    if (goSec.current_go_version !== TOOLCHAIN.go) fail(`go toolchain license record security requalification current_go_version must be ${TOOLCHAIN.go}: ${JSON.stringify(goSec.current_go_version)}`);
    if (goSec.verified_at !== '2026-08-20T04:16:01Z') fail(`go toolchain license record security requalification verified_at must be 2026-08-20T04:16:01Z (UTC): ${JSON.stringify(goSec.verified_at)}`);
    if (Object.prototype.hasOwnProperty.call(goSec, 'go_version')) fail('go toolchain license record security requalification must not carry the ambiguous go_version key (use previous_go_version / current_go_version)');
    if (goSec.reason !== 'reachable standard-library vulnerabilities') fail('go toolchain license record security requalification reason must be "reachable standard-library vulnerabilities"');
    if (goSec.officially_fixed_in !== '1.26.6') fail('go toolchain license record security requalification officially_fixed_in must be 1.26.6');
  }
  const goAdvisoryIds = [...(goRec?.security_requalification?.advisory_ids ?? [])].sort();
  const expectedGoAdvisoryIds = ['GO-2026-6090', 'GO-2026-6088', 'GO-2026-5972'].sort();
  if (JSON.stringify(goAdvisoryIds) !== JSON.stringify(expectedGoAdvisoryIds)) {
    fail('go toolchain license record security requalification advisory set must be exactly GO-2026-6090 / GO-2026-6088 / GO-2026-5972');
  }
  if (goRec?.selected_by_batch !== SUPPLY_CHAIN_BASELINE_BATCH) {
    fail(`go toolchain license record selected_by_batch must be ${SUPPLY_CHAIN_BASELINE_BATCH} (historical B001 initial qualification, never rewritten)`);
  }
  // Machine-check every expected inventory record against its expected SPDX
  // license value and kind — all 18 expected identities (12 prior + six B003
  // Go runtime modules) must exist and match exactly.
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
    ok(`${Object.keys(EXPECTED_SPDX_LICENSES).length} license records carry the expected SPDX license values and kinds (exact first-party set + exact B001 tooling/CI/infrastructure set + exact B003 Go runtime closure)`);
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
  // Truthful B003 Go runtime record metadata (AIPT-M0-B003 iteration 6a): the
  // six approved modules must carry exact versions, SPDX licenses, kind
  // third_party_go_runtime, role runtime_dependency, the exact go.mod
  // directness, and truthful B003 selection/verification evidence — never
  // claimed as B001/B002-verified.
  let goRuntimeOk = true;
  for (const m of GO_RUNTIME_MODULES) {
    const rec = records.find((r) => r?.id === m.module);
    if (!rec) {
      fail(`licenses.json missing Go runtime record ${m.module}`);
      goRuntimeOk = false;
      continue;
    }
    if (rec.version !== m.version) {
      fail(`licenses.json record ${m.module} version must be ${m.version}, got ${JSON.stringify(rec.version)}`);
      goRuntimeOk = false;
    }
    if (rec.kind !== 'third_party_go_runtime') {
      fail(`licenses.json record ${m.module} kind must be third_party_go_runtime, got ${JSON.stringify(rec.kind)}`);
      goRuntimeOk = false;
    }
    if (rec.role !== 'runtime_dependency') {
      fail(`licenses.json record ${m.module} role must be runtime_dependency, got ${JSON.stringify(rec.role)}`);
      goRuntimeOk = false;
    }
    if (rec.direct !== m.direct) {
      fail(`licenses.json record ${m.module} direct must be ${m.direct} (go.mod directness), got ${JSON.stringify(rec.direct)}`);
      goRuntimeOk = false;
    }
    if (rec.selected_by_batch !== 'AIPT-M0-B003') {
      fail(`licenses.json record ${m.module} selected_by_batch must be AIPT-M0-B003 (truthful B003 metadata, never B001/B002)`);
      goRuntimeOk = false;
    }
    if (typeof rec.evidence !== 'string' || !rec.evidence.includes('AIPT-M0-B003')) {
      fail(`licenses.json record ${m.module} evidence must reference the AIPT-M0-B003 selection/verification`);
      goRuntimeOk = false;
    }
    if (!rec.verified_at) fail(`licenses.json record ${m.module} missing verified_at`);
  }
  if (goRuntimeOk) {
    ok(`${GO_RUNTIME_MODULES.length} Go runtime license records carry exact versions, SPDX licenses, kind/role, go.mod directness, and truthful B003 selection/verification evidence`);
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
  if (appDeps.go_runtime_third_party_modules !== GO_RUNTIME_MODULES.length || appDeps.pnpm_runtime_third_party_packages !== 0) {
    fail(`licenses.json application_dependencies must be go=${GO_RUNTIME_MODULES.length}/pnpm=0, got go=${JSON.stringify(appDeps.go_runtime_third_party_modules)}/pnpm=${JSON.stringify(appDeps.pnpm_runtime_third_party_packages)}`);
  } else ok(`licenses.json application dependency inventory = ${GO_RUNTIME_MODULES.length} / 0 (six approved pgx runtime modules, zero pnpm third-party packages)`);

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

// Parse the h1 lines of a go.sum text: zip hashes (`<module> <version>
// h1:...`) and go.mod hashes (`<module> <version>/go.mod h1:...`), keyed by
// `<module> <version>`.
function parseGoSumH1(text) {
  const zip = new Map();
  const gomod = new Map();
  for (const m of text.matchAll(/^([^\s]+)\s+(v[\w.+\-]+)\s+h1:([A-Za-z0-9+/=]+)$/gm)) {
    zip.set(`${m[1]} ${m[2]}`, m[3]);
  }
  for (const m of text.matchAll(/^([^\s]+)\s+(v[\w.+\-]+)\/go\.mod\s+h1:([A-Za-z0-9+/=]+)$/gm)) {
    gomod.set(`${m[1]} ${m[2]}`, m[3]);
  }
  return { zip, gomod };
}

// Pure machine check of the go.mod/go.sum pair against the exact approved
// six-module pgx v5.10.0 runtime closure (AIPT-M0-B003 iteration 6a):
//   - go.mod require set must be EXACTLY the six modules with exact versions
//     and the exact direct/indirect markers (pgx direct, five transitive);
//     any unknown module, version drift, or directness flip is rejected;
//   - go.mod must carry NO replace/exclude/retract dependency-graph override
//     directive (a graph override would re-route or hide modules of the
//     approved closure);
//   - go.sum must carry BOTH the zip `h1:` and the `/go.mod h1:` line for
//     every one of the six modules, and every base64 payload must decode to
//     32 bytes whose lowercase hex equals the pinned h1 SHA-256 value — so a
//     tampered (but still base64-valid) h1 cannot pass.
// Pure over the supplied texts: negative probes mutate in-memory strings and
// the on-disk files are never modified.
function checkGoModuleClosure({ goMod, goSum }) {
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
  if (requires.length !== GO_RUNTIME_MODULES.length) {
    fail(`go.mod require count must be exactly ${GO_RUNTIME_MODULES.length}, got ${requires.length}`);
  }
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
      fail(`go.mod ${m.module} directness drifted: ${r.indirect ? 'indirect' : 'direct'} in go.mod, expected ${m.direct ? 'direct' : 'indirect'}`);
      moduleOk = false;
    }
  }
  const unknown = requires.filter((r) => !GO_RUNTIME_MODULES.some((m) => m.module === r.module));
  if (unknown.length > 0) {
    fail(`unknown go.mod dependency (outside the approved six-module closure): ${unknown.map((r) => r.module).join(', ')}`);
    moduleOk = false;
  }
  if (moduleOk) {
    ok('go.mod require set is exactly the six approved pgx v5.10.0 runtime-closure modules (1 direct + 5 transitive, exact versions, exact directness, no unknown dependency)');
  }

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
  } else {
    ok('go.mod carries no replace/exclude/retract dependency-graph override directive');
  }

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
  if (h1Ok) {
    ok(`go.sum carries zip + /go.mod h1 for all ${GO_RUNTIME_MODULES.length} modules; every payload decodes to the pinned SHA-256 value`);
  }

  return { result: pass ? 'PASS' : 'FAIL', details };
}

// Pure machine check of a tools/toolchain.lock.json object: the historical
// B001 selected_by_batch fact, the exact frozen multi-arch digest, and the
// exact frozen linux/amd64 platform digest (exact equality — a mere format
// match is never enough). Returns {result, details}; in-memory probes mutate
// copies of the object so the on-disk lock is never modified.
function checkToolchainLockObject(toolchainLock) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  if (toolchainLock.selected_by_batch !== SUPPLY_CHAIN_BASELINE_BATCH) {
    fail(`toolchain.lock.json selected_by_batch must be ${SUPPLY_CHAIN_BASELINE_BATCH} (historical B001 baseline selector, never rewritten), got ${JSON.stringify(toolchainLock.selected_by_batch)}`);
  } else ok('toolchain.lock.json selected_by_batch = AIPT-M0-B001 (historical B001 baseline selector)');
  for (const [key, digest] of Object.entries({ multi_arch_digest: PG_MULTI_ARCH_DIGEST })) {
    if (toolchainLock.toolchains?.postgresql?.docker_official_image?.[key] !== digest) {
      fail(`toolchain.lock.json postgresql ${key} drifted from the frozen value`);
    } else ok(`toolchain.lock.json postgresql ${key} == frozen value`);
  }
  const pg = toolchainLock.toolchains?.postgresql?.docker_official_image;
  if (pg?.linux_amd64_platform_digest !== PG_LINUX_AMD64_PLATFORM_DIGEST) {
    fail(`toolchain.lock.json postgresql linux/amd64 platform digest must equal the frozen value ${PG_LINUX_AMD64_PLATFORM_DIGEST}, got ${JSON.stringify(pg?.linux_amd64_platform_digest)}`);
  } else ok('toolchain.lock.json postgresql linux/amd64 platform digest == frozen value');
  if (!/^sha256:[0-9a-f]{64}$/.test(pg?.multi_arch_digest ?? '')) fail('postgresql multi-arch digest malformed');
  if (!/^sha256:[0-9a-f]{64}$/.test(pg?.linux_amd64_platform_digest ?? '')) fail('postgresql linux/amd64 platform digest malformed');
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
    fail('policy.json current_third_party_application_runtime_dependencies must stay 0 (frozen immutable B001 baseline; the current B003 count lives in licenses.json application_dependencies)');
  } else ok('policy.json keeps the frozen B001 baseline of zero third-party application runtime dependencies (immutable historical fact, never rewritten; the current go=6/pnpm=0 count is recorded in licenses.json)');

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
    {
      label: 'pgx Go runtime license record deleted',
      targetId: 'github.com/jackc/pgx/v5',
      reason: /missing Go runtime record github.com\/jackc\/pgx\/v5/,
      mutate: (recs) => {
        recs.splice(recs.findIndex((r) => r.id === 'github.com/jackc/pgx/v5'), 1);
      },
    },
    {
      label: 'pgx Go runtime license record wrongly licensed',
      targetId: 'github.com/jackc/pgx/v5',
      reason: /MIT/,
      mutate: (recs) => {
        recs.find((r) => r.id === 'github.com/jackc/pgx/v5').license = 'Apache-2.0';
      },
    },
    {
      label: 'pgx Go runtime license record version drifted',
      targetId: 'github.com/jackc/pgx/v5',
      reason: /version must be v5\.10\.0/,
      mutate: (recs) => {
        recs.find((r) => r.id === 'github.com/jackc/pgx/v5').version = 'v5.9.0';
      },
    },
    {
      label: 'pgx Go runtime license record directness flipped',
      targetId: 'github.com/jackc/pgx/v5',
      reason: /direct must be true/,
      mutate: (recs) => {
        recs.find((r) => r.id === 'github.com/jackc/pgx/v5').direct = false;
      },
    },
    {
      label: 'pgx Go runtime license record pretends B001 verification',
      targetId: 'github.com/jackc/pgx/v5',
      reason: /selected_by_batch must be AIPT-M0-B003/,
      mutate: (recs) => {
        const rec = recs.find((r) => r.id === 'github.com/jackc/pgx/v5');
        rec.selected_by_batch = 'AIPT-M0-B001';
        rec.verified_at = '2026-08-16T06:51:41Z';
      },
    },
    {
      label: 'golang.org/x/text Go runtime license record mislicensed BSD-3-Clause -> MIT',
      targetId: 'golang.org/x/text',
      reason: /BSD-3-Clause/,
      mutate: (recs) => {
        recs.find((r) => r.id === 'golang.org/x/text').license = 'MIT';
      },
    },
    {
      label: 'licenses.json top-level selected_by_batch drifted to AIPT-M0-B003 (baseline probe)',
      targetId: 'AIPT',
      reason: /top-level selected_by_batch must be AIPT-M0-B001/,
      mutate: (recs, whole) => {
        whole.selected_by_batch = 'AIPT-M0-B003';
      },
    },
    {
      label: 'go toolchain license record version drifted back to the historical 1.26.5',
      targetId: 'go',
      reason: /version must be the current 1\.26\.6/,
      mutate: (recs) => {
        recs.find((r) => r.id === 'go').version = '1.26.5';
      },
    },
    {
      label: 'go toolchain license record security requalification provenance removed',
      targetId: 'go',
      reason: /truthful B003 security requalification metadata/,
      mutate: (recs) => {
        delete recs.find((r) => r.id === 'go').security_requalification;
      },
    },
    {
      label: 'go toolchain license record advisory set wrong',
      targetId: 'go',
      reason: /advisory set must be exactly/,
      mutate: (recs) => {
        recs.find((r) => r.id === 'go').security_requalification.advisory_ids = ['GO-2026-6090', 'GO-2026-6088', 'GO-2026-9999'];
      },
    },
    {
      label: 'go toolchain license record security requalification previous_go_version wrong',
      targetId: 'go',
      reason: /previous_go_version must be 1\.26\.5/,
      mutate: (recs) => {
        recs.find((r) => r.id === 'go').security_requalification.previous_go_version = '1.26.4';
      },
    },
    {
      label: 'go toolchain license record security requalification current_go_version wrong',
      targetId: 'go',
      reason: /current_go_version must be 1\.26\.6/,
      mutate: (recs) => {
        recs.find((r) => r.id === 'go').security_requalification.current_go_version = '1.26.7';
      },
    },
    {
      label: 'go toolchain license record security requalification verified_at wrong',
      targetId: 'go',
      reason: /verified_at must be 2026-08-20T04:16:01Z/,
      mutate: (recs) => {
        recs.find((r) => r.id === 'go').security_requalification.verified_at = '2026-08-19T00:00:00Z';
      },
    },
    {
      label: 'go toolchain license record security requalification retains the ambiguous go_version key',
      targetId: 'go',
      reason: /ambiguous go_version key/,
      mutate: (recs) => {
        recs.find((r) => r.id === 'go').security_requalification.go_version = '1.26.6';
      },
    },
    {
      label: 'go toolchain license record top-level verified_at not the B003 security requalification time',
      targetId: 'go',
      reason: /top-level verified_at must be 2026-08-20T04:16:01Z/,
      mutate: (recs) => {
        recs.find((r) => r.id === 'go').verified_at = '2026-08-16T06:51:41Z';
      },
    },
    {
      label: 'go toolchain license record security requalification extra key (closed key set)',
      targetId: 'go',
      reason: /security requalification key set must be exactly/,
      mutate: (recs) => {
        recs.find((r) => r.id === 'go').security_requalification.extra = 'x';
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
      probe.mutate(mutatedRecords, mutated);
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
  let lockFilesOk = true;
  for (const rel of ['tools/toolchain.lock.json', 'tools/ci-actions.lock.json', 'tools/supply-chain/policy.json', 'tools/supply-chain/licenses.json', 'pnpm-lock.yaml', 'go.mod', 'go.sum']) {
    if (!fs.existsSync(path.join(ctx.repo, rel))) {
      fail(`required lock file missing: ${rel}`);
      lockFilesOk = false;
    }
  }
  const toolchainLock = JSON.parse(read('tools/toolchain.lock.json'));
  // The lock object is checked by a pure function (exact B001 baseline
  // selector + exact frozen multi-arch and linux/amd64 platform digests —
  // never a mere format match), and negative probes run against mutated
  // in-memory copies below; the on-disk lock is never modified.
  const lockObjectCheck = checkToolchainLockObject(toolchainLock);
  details.push(...lockObjectCheck.details);
  if (lockObjectCheck.result !== 'PASS') {
    fail('toolchain.lock.json does not match the frozen B001 baseline/digest qualification');
    lockFilesOk = false;
  }
  // The success line is emitted ONLY when every lock-file check above passed
  // — a failed lock check never produces an unconditional success detail.
  if (lockFilesOk && lockObjectCheck.result === 'PASS') {
    ok('lock files present and structurally sound (exact B001 baseline selector and frozen PostgreSQL digests)');
  }

  // ---- toolchain.lock.json negative probes (baseline/digest drift) ----
  const lockProbes = [
    {
      label: 'toolchain.lock.json selected_by_batch drifted to AIPT-M0-B003',
      reason: /selected_by_batch must be AIPT-M0-B001/,
      mutate: (copy) => {
        copy.selected_by_batch = 'AIPT-M0-B003';
      },
    },
    {
      label: 'toolchain.lock.json postgresql multi-arch digest drifted',
      reason: /multi_arch_digest drifted from the frozen value/,
      mutate: (copy) => {
        copy.toolchains.postgresql.docker_official_image.multi_arch_digest = `${PG_MULTI_ARCH_DIGEST.slice(0, -1)}7`;
      },
    },
    {
      label: 'toolchain.lock.json postgresql linux/amd64 platform digest drifted',
      reason: /linux\/amd64 platform digest must equal the frozen value/,
      mutate: (copy) => {
        copy.toolchains.postgresql.docker_official_image.linux_amd64_platform_digest = `${PG_LINUX_AMD64_PLATFORM_DIGEST.slice(0, -1)}7`;
      },
    },
  ];
  let lockProbesOk = true;
  for (const probe of lockProbes) {
    const copy = JSON.parse(JSON.stringify(toolchainLock));
    probe.mutate(copy);
    const result = checkToolchainLockObject(copy);
    if (result.result !== 'FAIL') {
      fail(`negative toolchain.lock probe (${probe.label}) was NOT rejected`);
      lockProbesOk = false;
    } else {
      const rightReason = result.details.filter((d) => d.startsWith('FAIL')).some((d) => probe.reason.test(d));
      if (!rightReason) fail(`negative toolchain.lock probe (${probe.label}) failed for an unexpected reason`);
      else ok(`negative-probe PASS: toolchain.lock.json rejects ${probe.label}`);
    }
  }
  if (lockProbesOk) ok(`all ${lockProbes.length} toolchain.lock.json baseline/digest negative probes rejected as expected`);

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

  // ---- dependency inventory: exact approved pgx v5.10.0 runtime closure ----
  // go.mod/go.sum are cross-checked against the exact six-module closure and
  // negative probes run over mutated in-memory copies (the on-disk manifests
  // are never written).
  const goMod = read('go.mod');
  const goSum = read('go.sum');
  const closure = checkGoModuleClosure({ goMod, goSum });
  details.push(...closure.details);
  if (closure.result !== 'PASS') fail('go.mod/go.sum runtime closure FAIL');
  else ok('go.mod/go.sum carry exactly the approved pgx v5.10.0 runtime closure (1 direct + 5 transitive modules, no graph override, exact zip + /go.mod h1 pins)');
  if (workspaceModel.result === 'PASS') {
    ok('pnpm-lock.yaml: zero third-party packages (exact workspace importer set checked above)');
  }

  const manifestProbes = [
    {
      label: 'unknown dependency injected into go.mod',
      reason: /unknown go.mod dependency/,
      mutate: () => checkGoModuleClosure({
        goMod: `${goMod}\nrequire example.com/rogue v1.0.0\n`,
        goSum,
      }),
    },
    {
      label: 'pgx version drifted in go.mod',
      reason: /github.com\/jackc\/pgx\/v5 version must be v5\.10\.0/,
      mutate: () => checkGoModuleClosure({
        goMod: goMod.replace('github.com/jackc/pgx/v5 v5.10.0', 'github.com/jackc/pgx/v5 v5.9.0'),
        goSum,
      }),
    },
    {
      label: 'pgx direct module deleted from go.mod',
      reason: /go.mod missing required module github.com\/jackc\/pgx\/v5/,
      mutate: () => checkGoModuleClosure({
        goMod: goMod.replace('require github.com/jackc/pgx/v5 v5.10.0\n\n', ''),
        goSum,
      }),
    },
    {
      label: 'pgx directness flipped in go.mod (direct -> indirect)',
      reason: /github.com\/jackc\/pgx\/v5 directness drifted/,
      mutate: () => checkGoModuleClosure({
        goMod: goMod.replace('require github.com/jackc/pgx/v5 v5.10.0', 'require github.com/jackc/pgx/v5 v5.10.0 // indirect'),
        goSum,
      }),
    },
    {
      label: 'pgx zip h1 removed from go.sum',
      reason: /go.sum missing zip h1 for github.com\/jackc\/pgx\/v5 v5\.10\.0/,
      mutate: () => checkGoModuleClosure({
        goMod,
        goSum: goSum.replace(/^github\.com\/jackc\/pgx\/v5 v5\.10\.0 h1:[^\n]+\n/m, ''),
      }),
    },
    {
      label: 'pgx /go.mod h1 removed from go.sum',
      reason: /go.sum missing \/go\.mod h1 for github.com\/jackc\/pgx\/v5 v5\.10\.0/,
      mutate: () => checkGoModuleClosure({
        goMod,
        goSum: goSum.replace(/^github\.com\/jackc\/pgx\/v5 v5\.10\.0\/go\.mod h1:[^\n]+\n/m, ''),
      }),
    },
    {
      label: 'pgx zip h1 tampered in go.sum',
      reason: /decodes to/,
      mutate: () => checkGoModuleClosure({
        goMod,
        goSum: goSum.replace('github.com/jackc/pgx/v5 v5.10.0 h1:VhSvgU2jSli8o3AqIEOTJr7rZwAEUVo4E4XhR94Zfr0=', 'github.com/jackc/pgx/v5 v5.10.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
      }),
    },
    {
      label: 'go.mod replace directive injected (graph override)',
      reason: /replace\/exclude\/retract/,
      mutate: () => checkGoModuleClosure({
        goMod: `${goMod}\nreplace github.com/jackc/pgx/v5 => github.com/jackc/pgx/v5 v5.9.0\n`,
        goSum,
      }),
    },
    {
      label: 'seventh dependency hidden in a second require block',
      reason: /go.mod require count must be exactly 6|unknown go.mod dependency/,
      mutate: () => checkGoModuleClosure({
        goMod: `${goMod}\nrequire (\n\texample.com/rogue v1.0.0\n)\n`,
        goSum,
      }),
    },
    {
      label: 'seventh dependency hidden after a comment-paren "// )" line in a second require block',
      reason: /go.mod require count must be exactly 6|unknown go.mod dependency/,
      mutate: () => checkGoModuleClosure({
        goMod: `${goMod}\nrequire (\n\t// )\n\texample.com/rogue v1.0.0\n)\n`,
        goSum,
      }),
    },
    {
      label: 'rogue single-line require with an ordinary trailing comment',
      reason: /go.mod require count must be exactly 6|unknown go.mod dependency/,
      mutate: () => checkGoModuleClosure({
        goMod: `${goMod}\nrequire example.com/rogue v1.0.0 // ordinary comment\n`,
        goSum,
      }),
    },
    {
      label: 'go.mod replace directive with leading whitespace (graph override)',
      reason: /replace\/exclude\/retract/,
      mutate: () => checkGoModuleClosure({
        goMod: `${goMod}\n\treplace github.com/jackc/pgx/v5 => github.com/jackc/pgx/v5 v5.9.0\n`,
        goSum,
      }),
    },
    {
      label: 'pgx /go.mod h1 tampered in go.sum',
      reason: /\/go\.mod h1 decodes to/,
      mutate: () => checkGoModuleClosure({
        goMod,
        goSum: goSum.replace('github.com/jackc/pgx/v5 v5.10.0/go.mod h1:mal1tBGAFfLHvZzaYh77YS/eC6IX9OWbRV1QIIM0Jn4=', 'github.com/jackc/pgx/v5 v5.10.0/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
      }),
    },
  ];
  let manifestProbesOk = true;
  for (const probe of manifestProbes) {
    let result;
    try {
      result = probe.mutate();
    } catch (err) {
      fail(`negative go.mod/go.sum probe (${probe.label}) crashed: ${err.message}`);
      manifestProbesOk = false;
      continue;
    }
    if (result.result !== 'FAIL') {
      fail(`negative go.mod/go.sum probe (${probe.label}) was NOT rejected`);
      manifestProbesOk = false;
    } else {
      const rightReason = result.details.filter((d) => d.startsWith('FAIL')).some((d) => probe.reason.test(d));
      if (!rightReason) fail(`negative go.mod/go.sum probe (${probe.label}) failed for an unexpected reason`);
      else ok(`negative-probe PASS: go.mod/go.sum rejects ${probe.label}`);
    }
  }
  if (manifestProbesOk) ok(`all ${manifestProbes.length} go.mod/go.sum negative probes rejected as expected`);

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
