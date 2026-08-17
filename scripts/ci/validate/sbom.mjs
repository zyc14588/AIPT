// SBOM validator (AIPT-M0-B001-REPAIR-R6 foundation, evolved by B002
// iteration 4): the gate enforces deterministic output AND SPDX 2.3 /
// component semantics — including the three-layer PostgreSQL license model,
// the first-party @aipt/adapter-sdk package model (own SPDX 2.3 package,
// MIT, version 1.0.0, npm purl, PACKAGE_OF AIPT — never DEV_TOOL_OF) — plus
// negative probes proving invalid documents are rejected:
//   - an invalid SRI-style checksum;
//   - the human full license name "PostgreSQL License" in place of the SPDX
//     short identifier PostgreSQL (on the main-software package);
//   - a version-defining mutation that retains the original namespace
//     (content-addressed namespace binding);
//   - the legacy static pre-R5 B001 documentNamespace;
//   - the composite image mislabeled as PostgreSQL or as MIT;
//   - the PostgreSQL main software moved away from PostgreSQL;
//   - the docker-library/postgres packaging source moved away from MIT;
//   - the pinned multi-arch digest deleted from or modified in the image
//     versionInfo / purl / comment;
//   - the image CONTAINS PostgreSQL main software composition relationship
//     deleted or retyped;
//   - the image GENERATED_FROM docker-library/postgres packaging source
//     composition relationship deleted or retyped (treating the packaging
//     source as image content — e.g. CONTAINS — is rejected);
//   - B002 iteration 4: the @aipt/adapter-sdk package deleted from or
//     wrongly licensed in the SBOM, its npm purl missing/drifted, its
//     PACKAGE_OF first-party relationship deleted or retyped to DEV_TOOL_OF
//     (each rejected by its own semantic check, never merely by the
//     content-addressed namespace mismatch).
//
// `node scripts/ci/validate/sbom.mjs` reports PASS only when:
//   1. semantic validation passes (SPDX-2.3, CC0-1.0, version-unique
//      content-addressed documentNamespace — SHA-256 of the canonical
//      version-defining payload — with the legacy static B001 namespace
//      explicitly rejected, unique package SPDXIDs, the exact B002 required
//      package set (all 11 B001 identities preserved plus the first-party
//      @aipt/adapter-sdk package), SPDX license values for every current
//      package (the three-layer PostgreSQL model: main software =
//      PostgreSQL, packaging source = MIT, composite image = NOASSERTION),
//      the exact composition relationships (image CONTAINS main software,
//      image GENERATED_FROM packaging source — never CONTAINS the packaging
//      source; adapter-sdk PACKAGE_OF AIPT — never DEV_TOOL_OF),
//      toolchain/action versions matching the lock files, resolvable
//      relationships with SPDX 2.3-valid types, lowercase-hex checksums of
//      algorithm-appropriate length, pnpm SHA512 hex decoded from the pinned
//      SRI payload, the exact PostgreSQL multi-arch digest in the image
//      versionInfo + purl + comment and the linux/amd64 platform digest in
//      the comment, zero third-party deps);
//   2. two independent generations are byte-identical;
//   3. every negative probe above is rejected for the right reason
//      (relationship-drift probes must be rejected by the composition
//      relationship check itself, not merely by the content-addressed
//      namespace mismatch that any mutation causes).
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { buildSbom } from '../sbom/generate-sbom.mjs';
import { runAsMain } from '../lib/cli.mjs';
import {
  CI_ACTION_PINS,
  PG_LINUX_AMD64_PLATFORM_DIGEST,
  PG_MULTI_ARCH_DIGEST,
  PNPM_REGISTRY_INTEGRITY,
} from '../lib/constants.mjs';

const SPDX_VERSION = 'SPDX-2.3';
const DATA_LICENSE = 'CC0-1.0';
const DOCUMENT_SPDXID = 'SPDXRef-DOCUMENT';
const AIPT_SPDXID = 'SPDXRef-AIPT';
const SDK_SPDXID = 'SPDXRef-adapter-sdk';
const NAMESPACE_BASE = 'https://github.com/zyc14588/AIPT/spdx/aipt-m0-b002';
// The static pre-R5 B001 namespace reused by distinct R3/R4 documents; still
// forbidden — a B002 document must never fall back to it.
const LEGACY_NAMESPACE = 'https://github.com/zyc14588/AIPT/spdx/aipt-m0-b001';

// SPDX 2.3 specification relationship types.
const SPDX23_RELATIONSHIP_TYPES = new Set([
  'AMENDS', 'ANCESTOR_OF', 'BUILD_DEPENDENCY_OF', 'BUILD_TOOL_OF',
  'CONTAINED_BY', 'CONTAINS', 'COPY_OF', 'DATA_FILE_OF',
  'DEPENDENCY_MANIFEST_OF', 'DEPENDENCY_OF', 'DEPENDS_ON', 'DESCENDANT_OF',
  'DESCRIBED_BY', 'DESCRIBES', 'DEV_DEPENDENCY_OF', 'DEV_TOOL_OF',
  'DISTRIBUTION_ARTIFACT', 'DOCUMENTATION_OF', 'DYNAMIC_LINK', 'EXAMPLE_OF',
  'EXPANDED_FROM_ARCHIVE', 'FILE_ADDED', 'FILE_DELETED', 'FILE_MODIFIED',
  'GENERATED_FROM', 'GENERATES', 'HAS_PREREQUISITE', 'METAFILE_OF',
  'OPTIONAL_COMPONENT_OF', 'OPTIONAL_DEPENDENCY_OF', 'OTHER', 'PACKAGE_OF',
  'PATCH_APPLIED', 'PATCH_FOR', 'PREREQUISITE_FOR', 'PROVIDED_DEPENDENCY_OF',
  'REQUIREMENT_DESCRIPTION_FOR', 'RUNTIME_DEPENDENCY_OF', 'SPECIFICATION_FOR',
  'STATIC_LINK', 'TEST_CASE_OF', 'TEST_DEPENDENCY_OF', 'TEST_OF',
  'TEST_TOOL_OF', 'VARIANT_OF',
]);

// The exact required package identities (B001's 11 identities preserved,
// plus the first-party B002 workspace package @aipt/adapter-sdk). B002 has
// zero third-party application runtime dependencies, so the SBOM package set
// must be exactly this set — no GoDep/PnpmDep packages.
const REQUIRED_PACKAGES = [
  { name: 'AIPT', spdxId: AIPT_SPDXID },
  { name: '@aipt/adapter-sdk', spdxId: SDK_SPDXID },
  { name: 'Go toolchain', spdxId: 'SPDXRef-Toolchain-Go' },
  { name: 'Node.js', spdxId: 'SPDXRef-Toolchain-Node' },
  { name: 'pnpm', spdxId: 'SPDXRef-Toolchain-pnpm' },
  { name: 'PostgreSQL', spdxId: 'SPDXRef-PostgreSQL' },
  { name: 'docker-library/postgres', spdxId: 'SPDXRef-docker-library-postgres' },
  { name: 'PostgreSQL Docker Official Image', spdxId: 'SPDXRef-PostgreSQL-Image' },
  { name: 'govulncheck', spdxId: 'SPDXRef-Tool-govulncheck' },
  { name: 'actions/checkout', spdxId: 'SPDXRef-Action-actions-checkout' },
  { name: 'actions/setup-go', spdxId: 'SPDXRef-Action-actions-setup-go' },
  { name: 'actions/setup-node', spdxId: 'SPDXRef-Action-actions-setup-node' },
];

const CHECKSUM_HEX_LENGTHS = { SHA1: 40, SHA256: 64, SHA512: 128 };

// Expected SPDX license values for every current SBOM package (keyed by
// package name). Three-layer PostgreSQL model:
//   - PostgreSQL (18.4 main software) carries the SPDX identifier
//     `PostgreSQL`; the human full name "PostgreSQL License" is NOT accepted;
//   - docker-library/postgres (packaging source) carries `MIT`;
//   - PostgreSQL Docker Official Image (composite container of multiple
//     sources/components) carries `NOASSERTION` for BOTH fields — asserting
//     `PostgreSQL` or `MIT` for the whole image is rejected.
// B002 iteration 4 adds the first-party @aipt/adapter-sdk package: MIT.
const EXPECTED_PACKAGE_LICENSES = {
  AIPT: 'MIT',
  '@aipt/adapter-sdk': 'MIT',
  'Go toolchain': 'BSD-3-Clause',
  'Node.js': 'MIT',
  pnpm: 'MIT',
  PostgreSQL: 'PostgreSQL',
  'docker-library/postgres': 'MIT',
  'PostgreSQL Docker Official Image': 'NOASSERTION',
  govulncheck: 'BSD-3-Clause',
  'actions/checkout': 'MIT',
  'actions/setup-go': 'MIT',
  'actions/setup-node': 'MIT',
};

// The exact npm purl of the first-party SDK package (percent-encoded scope).
const SDK_NPM_PURL = 'pkg:npm/%40aipt/adapter-sdk@1.0.0';

// Canonical JSON: arrays in order, object keys sorted recursively. Mirrors
// the generator's serializer (independent copy, so a generator defect cannot
// validate itself into PASS).
function canonicalJson(value) {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (value && typeof value === 'object') {
    const sorted = {};
    for (const key of Object.keys(value).sort()) sorted[key] = canonicalJson(value[key]);
    return sorted;
  }
  return value;
}

// Independently recompute the expected content-addressed namespace from the
// document's version-defining payload (the whole document minus
// documentNamespace): SHA-256, 64 lowercase hex.
function computeExpectedNamespace(doc) {
  const withoutNamespace = { ...doc };
  delete withoutNamespace.documentNamespace;
  const hash = crypto.createHash('sha256').update(JSON.stringify(canonicalJson(withoutNamespace))).digest('hex');
  return `${NAMESPACE_BASE}/${hash}`;
}

function readJson(repo, rel) {
  return JSON.parse(fs.readFileSync(path.join(repo, rel), 'utf8'));
}

// Independent re-derivation of the pinned pnpm SHA-512 hex digest from the
// npm-registry SRI base64 payload (shared shape with generate-sbom.mjs but
// computed here so a generator defect cannot validate itself into PASS).
function pinnedPnpmSha512Hex(toolchainLock) {
  const sri = toolchainLock.toolchains.pnpm.registry.integrity_sha512;
  const bytes = Buffer.from(sri, 'base64');
  if (bytes.length !== 64) return null;
  const hex = bytes.toString('hex');
  return /^[0-9a-f]{128}$/.test(hex) ? hex : null;
}

export function validateSbomSemantics(doc, { repo, toolchainLock, actionsLock }) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const find = (spdxId) => doc.packages.find((p) => p.SPDXID === spdxId);

  // ---- document header ----
  if (doc.spdxVersion !== SPDX_VERSION) fail(`spdxVersion must be ${SPDX_VERSION}: ${JSON.stringify(doc.spdxVersion)}`);
  else ok(`spdxVersion = ${SPDX_VERSION}`);
  if (doc.dataLicense !== DATA_LICENSE) fail(`dataLicense must be ${DATA_LICENSE}: ${JSON.stringify(doc.dataLicense)}`);
  else ok(`dataLicense = ${DATA_LICENSE}`);
  let namespaceOk = false;
  try {
    const u = new URL(doc.documentNamespace);
    namespaceOk = u.protocol === 'https:' || u.protocol === 'http:';
  } catch {
    namespaceOk = false;
  }
  if (!namespaceOk) fail(`documentNamespace is not a valid absolute URI: ${JSON.stringify(doc.documentNamespace)}`);
  else ok('documentNamespace is a valid absolute URI');
  if (doc.documentNamespace === LEGACY_NAMESPACE) {
    fail(`documentNamespace is the legacy static pre-R5 namespace ${JSON.stringify(LEGACY_NAMESPACE)} (already reused by distinct R3/R4 documents); a version-unique hash suffix is required`);
  }
  const expectedNamespace = computeExpectedNamespace(doc);
  if (doc.documentNamespace !== expectedNamespace) {
    fail(`documentNamespace must equal the content-addressed version namespace ${expectedNamespace} (SHA-256 of the canonical version-defining payload), got ${JSON.stringify(doc.documentNamespace)}`);
  } else {
    ok('documentNamespace is the version-unique content-addressed namespace (SHA-256 of the canonical version-defining payload)');
  }
  if (doc.SPDXID !== DOCUMENT_SPDXID) fail(`document SPDXID must be ${DOCUMENT_SPDXID}`);
  else ok(`document SPDXID = ${DOCUMENT_SPDXID}`);

  // ---- packages: unique, well-formed SPDXIDs ----
  if (!Array.isArray(doc.packages) || doc.packages.length === 0) {
    fail('SBOM carries no packages');
    return { result: 'FAIL', details };
  }
  const ids = doc.packages.map((p) => p.SPDXID);
  if (new Set(ids).size !== ids.length) fail('package SPDXIDs are not unique');
  else ok(`${ids.length} packages, all SPDXIDs unique`);
  const badIds = doc.packages.filter((p) => typeof p.SPDXID !== 'string' || !/^SPDXRef-[A-Za-z0-9.-]+$/.test(p.SPDXID));
  if (badIds.length > 0) fail(`malformed SPDXIDs: ${badIds.map((p) => p.SPDXID).join(', ')}`);
  else ok('all package SPDXIDs match the SPDXRef- form');
  if (ids.includes(DOCUMENT_SPDXID)) fail('a package reuses the document SPDXID');
  else ok('no package reuses the document SPDXID');

  // ---- exact required package set (zero third-party deps) ----
  const byName = new Map(doc.packages.map((p) => [p.name, p]));
  let requiredOk = true;
  for (const req of REQUIRED_PACKAGES) {
    const p = byName.get(req.name);
    if (!p) {
      fail(`required package missing: ${req.name}`);
      requiredOk = false;
    } else if (p.SPDXID !== req.spdxId) {
      fail(`package ${req.name} has SPDXID ${p.SPDXID}, expected ${req.spdxId}`);
      requiredOk = false;
    }
  }
  if (requiredOk) ok(`all ${REQUIRED_PACKAGES.length} required package identities present with expected SPDXIDs (11 B001 identities preserved + @aipt/adapter-sdk)`);
  const unknown = doc.packages.filter((p) => !byName.has(p.name) || !REQUIRED_PACKAGES.some((r) => r.name === p.name));
  if (doc.packages.length !== REQUIRED_PACKAGES.length || unknown.length > 0) {
    fail(`SBOM package set must be exactly the ${REQUIRED_PACKAGES.length} required packages (third-party dependency count must remain 0), got ${doc.packages.length}`);
  } else ok('SBOM package set is exactly the required set: third-party application dependency count = 0');
  const depIds = ids.filter((id) => id.startsWith('SPDXRef-GoDep-') || id.startsWith('SPDXRef-PnpmDep-'));
  if (depIds.length > 0) fail(`SBOM carries dependency packages: ${depIds.join(', ')}`);
  else ok('no GoDep/PnpmDep dependency packages in the SBOM');

  // ---- first-party @aipt/adapter-sdk package model (B002 iteration 4) ----
  const sdkPkg = byName.get('@aipt/adapter-sdk');
  if (sdkPkg) {
    if (sdkPkg.versionInfo !== '1.0.0') {
      fail(`@aipt/adapter-sdk versionInfo must be 1.0.0, got ${JSON.stringify(sdkPkg.versionInfo)}`);
    } else ok('@aipt/adapter-sdk versionInfo = 1.0.0');
    const sdkPurl = (sdkPkg.externalRefs ?? []).find((r) => r?.referenceType === 'purl');
    if (!sdkPurl || sdkPurl.referenceLocator !== SDK_NPM_PURL) {
      fail(`@aipt/adapter-sdk npm purl referenceLocator must be exactly ${SDK_NPM_PURL}, got ${JSON.stringify(sdkPurl?.referenceLocator)}`);
    } else ok('@aipt/adapter-sdk carries the exact npm purl (pkg:npm/%40aipt/adapter-sdk@1.0.0)');
    if ((sdkPkg.comment ?? '').includes('classified as a DEV_TOOL_OF dependency')) {
      fail('@aipt/adapter-sdk comment must not classify the package as a DEV_TOOL_OF dependency');
    } else if (!(sdkPkg.comment ?? '').includes('PACKAGE_OF')) {
      fail('@aipt/adapter-sdk comment must document its first-party PACKAGE_OF relationship to AIPT');
    } else ok('@aipt/adapter-sdk comment documents the first-party PACKAGE_OF model (never DEV_TOOL_OF)');
  }
  const sdkFirstPartyRel = doc.relationships.some(
    (r) => r.spdxElementId === SDK_SPDXID && r.relationshipType === 'PACKAGE_OF' && r.relatedSpdxElement === AIPT_SPDXID,
  );
  if (!sdkFirstPartyRel) {
    fail(`missing first-party relationship: ${SDK_SPDXID} PACKAGE_OF ${AIPT_SPDXID} (the SDK is part of the AIPT repository, never a dev tool)`);
  } else ok('first-party relationship present: SPDXRef-adapter-sdk PACKAGE_OF SPDXRef-AIPT');
  const sdkDevToolRel = doc.relationships.some(
    (r) => r.spdxElementId === SDK_SPDXID && r.relationshipType === 'DEV_TOOL_OF' && r.relatedSpdxElement === AIPT_SPDXID,
  );
  if (sdkDevToolRel) {
    fail(`${SDK_SPDXID} must NOT be classified as a DEV_TOOL_OF dependency of AIPT (it is a first-party workspace package)`);
  } else ok('@aipt/adapter-sdk is never classified as DEV_TOOL_OF');

  // ---- SPDX license values for every current package ----
  // Exact-match against the expected B001 SPDX license value; arbitrary
  // strings (including the human full name "PostgreSQL License" on the main
  // software, or PostgreSQL/MIT on the composite image) fail.
  let licenseOk = true;
  for (const pkg of doc.packages) {
    const expected = EXPECTED_PACKAGE_LICENSES[pkg.name];
    if (expected === undefined) {
      fail(`${pkg.SPDXID}: package ${JSON.stringify(pkg.name)} has no expected B001 SPDX license value`);
      licenseOk = false;
      continue;
    }
    for (const field of ['licenseConcluded', 'licenseDeclared']) {
      if (pkg[field] !== expected) {
        fail(`${pkg.SPDXID}: ${field} must be the SPDX license value ${JSON.stringify(expected)}, got ${JSON.stringify(pkg[field])}`);
        licenseOk = false;
      }
    }
  }
  if (licenseOk) ok('every package licenseConcluded/licenseDeclared matches the expected SPDX license value (PostgreSQL main software = PostgreSQL, docker-library/postgres = MIT, composite image = NOASSERTION, @aipt/adapter-sdk = MIT)');

  // ---- app-level zero-dependency invariants (go.mod / pnpm-lock) ----
  const goMod = fs.readFileSync(path.join(repo, 'go.mod'), 'utf8');
  if (/^require\b/m.test(goMod)) fail('go.mod declares runtime requires (third-party dependency count != 0)');
  else ok('go.mod: zero module requirements (third-party dependency count = 0)');
  const pnpmLock = fs.readFileSync(path.join(repo, 'pnpm-lock.yaml'), 'utf8');
  if (/^packages:\s*$/m.test(pnpmLock)) fail('pnpm-lock.yaml carries third-party packages (dependency count != 0)');
  else ok('pnpm-lock.yaml: zero third-party packages (dependency count = 0)');

  // ---- toolchain versions match lock files ----
  const tc = toolchainLock.toolchains;
  const expectVersion = (pkg, expected) => {
    if (!pkg || pkg.versionInfo !== expected) {
      fail(`${pkg?.name ?? '?'} versionInfo must be ${JSON.stringify(expected)}, got ${JSON.stringify(pkg?.versionInfo)}`);
      return false;
    }
    ok(`${pkg.name} versionInfo matches toolchain lock (${expected})`);
    return true;
  };
  expectVersion(find('SPDXRef-Toolchain-Go'), tc.go.version);
  expectVersion(find('SPDXRef-Toolchain-Node'), `${tc.node.version} (LTS ${tc.node.release_codename})`);
  expectVersion(find('SPDXRef-Toolchain-pnpm'), tc.pnpm.version);
  const pg = tc.postgresql.docker_official_image;
  expectVersion(find('SPDXRef-PostgreSQL'), tc.postgresql.version);
  expectVersion(find('SPDXRef-docker-library-postgres'), `${tc.postgresql.version} packaging source`);
  expectVersion(find('SPDXRef-PostgreSQL-Image'), `library/postgres:${tc.postgresql.version} @ ${pg.multi_arch_digest}`);
  expectVersion(find('SPDXRef-Tool-govulncheck'), toolchainLock.tooling.govulncheck.version);

  // ---- CI action versions match ci-actions.lock.json (and frozen pins) ----
  const lockByRepo = new Map((actionsLock.actions ?? []).map((a) => [a.repository, a]));
  let actionsOk = true;
  for (const [repo, pin] of Object.entries(CI_ACTION_PINS)) {
    const lockEntry = lockByRepo.get(repo);
    const pkg = byName.get(repo);
    if (!lockEntry) {
      fail(`ci-actions.lock.json missing ${repo}`);
      actionsOk = false;
      continue;
    }
    if (lockEntry.resolved_commit_sha !== pin.sha || lockEntry.stable_release_tag !== pin.tag) {
      fail(`ci-actions.lock.json entry for ${repo} drifted from frozen pins`);
      actionsOk = false;
    }
    if (!pkg) {
      fail(`SBOM missing action package ${repo}`);
      actionsOk = false;
      continue;
    }
    const expectedVersion = `${lockEntry.stable_release_tag} @ ${lockEntry.resolved_commit_sha}`;
    if (pkg.versionInfo !== expectedVersion) {
      fail(`SBOM ${repo} versionInfo must be ${JSON.stringify(expectedVersion)}, got ${JSON.stringify(pkg.versionInfo)}`);
      actionsOk = false;
    }
    if (pkg.downloadLocation !== `https://github.com/${repo}`) {
      fail(`SBOM ${repo} downloadLocation drifted: ${JSON.stringify(pkg.downloadLocation)}`);
      actionsOk = false;
    }
    if (!(pkg.sourceInfo ?? '').includes(lockEntry.resolved_commit_sha)) {
      fail(`SBOM ${repo} sourceInfo must carry the pinned commit SHA`);
      actionsOk = false;
    }
  }
  if (actionsOk) ok('all CI action packages match ci-actions.lock.json and frozen pins');

  // ---- checksums: lowercase hex, algorithm-appropriate length ----
  let checksumOk = true;
  for (const pkg of doc.packages) {
    for (const cs of pkg.checksums ?? []) {
      const want = CHECKSUM_HEX_LENGTHS[cs.algorithm];
      if (want === undefined) {
        fail(`${pkg.SPDXID}: unknown checksum algorithm ${JSON.stringify(cs.algorithm)}`);
        checksumOk = false;
        continue;
      }
      if (typeof cs.checksumValue !== 'string' || !new RegExp(`^[0-9a-f]{${want}}$`).test(cs.checksumValue)) {
        fail(`${pkg.SPDXID}: ${cs.algorithm} checksumValue must be ${want} lowercase hex chars, got ${JSON.stringify(cs.checksumValue)}`);
        checksumOk = false;
      }
    }
  }
  if (checksumOk) ok('all checksumValues are lowercase hex of algorithm-appropriate length');

  // ---- toolchain archive checksums tie back to the lock ----
  const goPkg = find('SPDXRef-Toolchain-Go');
  const nodePkg = find('SPDXRef-Toolchain-Node');
  if (goPkg?.checksums?.length !== 1 || goPkg.checksums[0].algorithm !== 'SHA256' || goPkg.checksums[0].checksumValue !== tc.go.linux_amd64_archive.sha256) {
    fail('Go toolchain SHA256 checksum does not match the lock linux/amd64 archive sha256');
  } else ok('Go toolchain SHA256 == toolchain lock linux/amd64 archive sha256');
  if (nodePkg?.checksums?.length !== 1 || nodePkg.checksums[0].algorithm !== 'SHA256' || nodePkg.checksums[0].checksumValue !== tc.node.linux_x64_archive.sha256) {
    fail('Node.js SHA256 checksum does not match the lock linux-x64 archive sha256');
  } else ok('Node.js SHA256 == toolchain lock linux-x64 archive sha256');
  if (goPkg?.downloadLocation !== tc.go.linux_amd64_archive.url) fail('Go toolchain downloadLocation drifted from lock');
  else ok('Go toolchain downloadLocation matches lock');
  if (nodePkg?.downloadLocation !== tc.node.linux_x64_archive.url) fail('Node.js downloadLocation drifted from lock');
  else ok('Node.js downloadLocation matches lock');
  if (find('SPDXRef-Toolchain-pnpm')?.downloadLocation !== tc.pnpm.registry.tarball) fail('pnpm downloadLocation drifted from lock');
  else ok('pnpm downloadLocation matches lock');

  // ---- pnpm SHA512: hex decodes from the exact pinned SRI payload ----
  const pnpmPkg = find('SPDXRef-Toolchain-pnpm');
  const frozenPayload = PNPM_REGISTRY_INTEGRITY.replace(/^sha512-/, '');
  if (tc.pnpm.registry.integrity_sha512 !== frozenPayload) {
    fail('toolchain lock pnpm integrity_sha512 drifted from the frozen qualified SRI payload');
  } else ok('toolchain lock pnpm integrity_sha512 == frozen qualified SRI payload');
  const pinnedHex = pinnedPnpmSha512Hex(toolchainLock);
  const pnpmCs = pnpmPkg?.checksums;
  if (!pinnedHex) {
    fail('frozen pnpm SRI payload does not decode to 64 bytes / 128 hex chars');
  } else if (pnpmCs?.length !== 1 || pnpmCs[0].algorithm !== 'SHA512' || pnpmCs[0].checksumValue !== pinnedHex) {
    fail(`pnpm SHA512 checksumValue must be the 128-char lowercase hex decode of the pinned SRI payload, got ${JSON.stringify(pnpmCs?.[0])}`);
  } else ok('pnpm SHA512 checksumValue decodes from the exact pinned SRI payload (no sha512- prefix)');

  // ---- PostgreSQL digest identity: the exact multi-arch digest must be
  // carried in the image versionInfo AND purl AND comment, and the exact
  // linux/amd64 platform digest in the comment ----
  const pgPkg = find('SPDXRef-PostgreSQL-Image');
  if (pg.multi_arch_digest !== PG_MULTI_ARCH_DIGEST) fail('toolchain lock postgresql multi-arch digest drifted from frozen value');
  else ok('toolchain lock postgresql multi-arch digest == frozen value');
  if (pg.linux_amd64_platform_digest !== PG_LINUX_AMD64_PLATFORM_DIGEST) fail('toolchain lock postgresql linux/amd64 platform digest drifted from frozen value');
  else ok('toolchain lock postgresql linux/amd64 platform digest == frozen value');
  if (!pgPkg) {
    fail('PostgreSQL Docker Official Image package missing from SBOM');
  } else {
    const imgVersion = pgPkg.versionInfo ?? '';
    if (!imgVersion.includes(PG_MULTI_ARCH_DIGEST)) {
      fail(`image versionInfo must carry the exact multi-arch digest ${PG_MULTI_ARCH_DIGEST}`);
    } else ok('image versionInfo carries the exact multi-arch digest');
    const expectedPurl = `pkg:docker/library/postgres@${PG_MULTI_ARCH_DIGEST}`;
    const purlRef = (pgPkg.externalRefs ?? []).find((r) => r?.referenceType === 'purl');
    if (!purlRef || purlRef.referenceLocator !== expectedPurl) {
      fail(`image purl referenceLocator must be exactly ${expectedPurl}, got ${JSON.stringify(purlRef?.referenceLocator)}`);
    } else ok('image purl referenceLocator == exact multi-arch digest purl');
    const imgComment = pgPkg.comment ?? '';
    if (!imgComment.includes(PG_MULTI_ARCH_DIGEST)) {
      fail(`image comment must carry the exact multi-arch digest ${PG_MULTI_ARCH_DIGEST}`);
    } else ok('image comment carries the exact multi-arch digest');
    if (!imgComment.includes(PG_LINUX_AMD64_PLATFORM_DIGEST)) {
      fail(`image comment must carry the exact linux/amd64 platform digest ${PG_LINUX_AMD64_PLATFORM_DIGEST}`);
    } else ok('image comment carries the exact linux/amd64 platform digest');
  }

  // ---- govulncheck identity ----
  const gvPkg = find('SPDXRef-Tool-govulncheck');
  const gv = toolchainLock.tooling.govulncheck;
  if (gvPkg?.downloadLocation !== gv.source) fail('govulncheck downloadLocation drifted from lock');
  else ok('govulncheck downloadLocation matches lock');
  const gvText = `${JSON.stringify(gvPkg?.externalRefs ?? [])} ${gvPkg?.comment ?? ''}`;
  if (!gvText.includes(gv.module) || !gvText.includes(gv.version)) fail('govulncheck module/version identity missing from SBOM');
  else ok('govulncheck module/version identity represented in the SBOM');

  // ---- relationships: resolvable ids + SPDX 2.3-valid types ----
  if (!Array.isArray(doc.relationships) || doc.relationships.length === 0) {
    fail('SBOM carries no relationships');
    return { result: 'FAIL', details };
  }
  const knownIds = new Set([DOCUMENT_SPDXID, ...ids]);
  let relOk = true;
  for (const rel of doc.relationships) {
    if (typeof rel?.spdxElementId !== 'string' || typeof rel?.relationshipType !== 'string' || typeof rel?.relatedSpdxElement !== 'string') {
      fail(`malformed relationship entry: ${JSON.stringify(rel)}`);
      relOk = false;
      continue;
    }
    if (!knownIds.has(rel.spdxElementId)) {
      fail(`relationship source SPDXID does not resolve: ${rel.spdxElementId}`);
      relOk = false;
    }
    if (!knownIds.has(rel.relatedSpdxElement)) {
      fail(`relationship target SPDXID does not resolve: ${rel.relatedSpdxElement}`);
      relOk = false;
    }
    if (!SPDX23_RELATIONSHIP_TYPES.has(rel.relationshipType)) {
      fail(`relationship type not valid in SPDX 2.3: ${rel.relationshipType}`);
      relOk = false;
    }
  }
  if (relOk) ok(`${doc.relationships.length} relationships: all source/target SPDXIDs resolve, all types valid for SPDX 2.3`);
  const describes = doc.relationships.some(
    (r) => r.spdxElementId === DOCUMENT_SPDXID && r.relationshipType === 'DESCRIBES' && r.relatedSpdxElement === AIPT_SPDXID,
  );
  if (!describes) fail(`missing ${DOCUMENT_SPDXID} DESCRIBES ${AIPT_SPDXID} relationship`);
  else ok(`document DESCRIBES ${AIPT_SPDXID}`);
  const nonAipt = doc.packages.filter((p) => p.SPDXID !== AIPT_SPDXID && p.SPDXID !== SDK_SPDXID);
  const missingDevTool = nonAipt.filter(
    (p) => !doc.relationships.some((r) => r.spdxElementId === p.SPDXID && r.relationshipType === 'DEV_TOOL_OF' && r.relatedSpdxElement === AIPT_SPDXID),
  );
  if (missingDevTool.length > 0) fail(`packages missing DEV_TOOL_OF relationship to AIPT: ${missingDevTool.map((p) => p.SPDXID).join(', ')}`);
  else ok('every tooling/CI/infrastructure package has a DEV_TOOL_OF relationship to AIPT (the first-party SDK is excluded: it is PACKAGE_OF AIPT)');

  // ---- three-layer PostgreSQL composition: the composite image CONTAINS
  // the main software (a component inside the container) and GENERATED_FROM
  // the packaging source (the image's build input, never its content) ----
  const composition = [
    ['SPDXRef-PostgreSQL-Image', 'CONTAINS', 'SPDXRef-PostgreSQL', 'PostgreSQL main software'],
    ['SPDXRef-PostgreSQL-Image', 'GENERATED_FROM', 'SPDXRef-docker-library-postgres', 'docker-library/postgres packaging source (build input, not image content)'],
  ];
  let compositionOk = true;
  for (const [src, type, tgt, label] of composition) {
    const found = doc.relationships.some(
      (r) => r.spdxElementId === src && r.relationshipType === type && r.relatedSpdxElement === tgt,
    );
    if (!found) {
      fail(`missing composition relationship: ${src} ${type} ${tgt} (${label})`);
      compositionOk = false;
    }
  }
  if (compositionOk) ok('three-layer PostgreSQL composition: composite image CONTAINS main software + GENERATED_FROM packaging source (never CONTAINS the packaging source)');

  // ---- documentDescribes ----
  if (!Array.isArray(doc.documentDescribes) || doc.documentDescribes.length === 0) {
    fail('documentDescribes missing');
  } else if (!doc.documentDescribes.includes(AIPT_SPDXID)) {
    fail('documentDescribes must include SPDXRef-AIPT');
  } else if (!doc.documentDescribes.includes(SDK_SPDXID)) {
    fail(`documentDescribes must include the first-party ${SDK_SPDXID}`);
  } else if (doc.documentDescribes.some((id) => !knownIds.has(id))) {
    fail('documentDescribes references an unresolved SPDXID');
  } else ok('documentDescribes resolves and includes SPDXRef-AIPT and SPDXRef-adapter-sdk');

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

  let toolchainLock;
  let actionsLock;
  try {
    toolchainLock = readJson(ctx.repo, 'tools/toolchain.lock.json');
    actionsLock = readJson(ctx.repo, 'tools/ci-actions.lock.json');
  } catch (err) {
    fail(`cannot read lock inputs: ${err.message}`);
    return { name: 'sbom', result: 'FAIL', details };
  }

  // 1. Determinism: two independent generations must be byte-identical.
  let first;
  let second;
  try {
    first = buildSbom(ctx.repo);
    second = buildSbom(ctx.repo);
  } catch (err) {
    fail(`SBOM generation failed: ${err.message}`);
    return { name: 'sbom', result: 'FAIL', details };
  }
  if (!first.equals(second)) {
    fail('SBOM generation is not deterministic (two runs differ byte-wise)');
  } else {
    ok(`deterministic PASS: two independent generations are byte-identical (${first.length} bytes)`);
  }
  details.push(`ok: sbom sha256 = ${crypto.createHash('sha256').update(first).digest('hex')}`);

  // 2. SPDX 2.3 + component semantics.
  let doc;
  try {
    doc = JSON.parse(first.toString('utf8'));
  } catch (err) {
    fail(`generated SBOM is not valid JSON: ${err.message}`);
    return { name: 'sbom', result: 'FAIL', details };
  }
  let sem;
  try {
    sem = validateSbomSemantics(doc, { repo: ctx.repo, toolchainLock, actionsLock });
  } catch (err) {
    fail(`semantic validation crashed: ${err.message}`);
    return { name: 'sbom', result: 'FAIL', details };
  }
  details.push(...sem.details);
  if (sem.result !== 'PASS') {
    fail('semantic validation FAIL: SPDX-2.3/component semantics not satisfied');
  } else {
    ok('semantic PASS: SPDX-2.3 + component semantics all green');
  }

  // 3. Negative probe: rewrite the pnpm SHA512 checksumValue into SRI/base64
  // form; the semantic validator must reject the mutated document.
  const mutated = JSON.parse(JSON.stringify(doc));
  const mutatedPnpm = mutated.packages.find((p) => p.SPDXID === 'SPDXRef-Toolchain-pnpm');
  if (!mutatedPnpm) {
    fail('negative invalid-checksum probe could not run: pnpm package missing from SBOM');
    return { name: 'sbom', result: 'FAIL', details };
  }
  mutatedPnpm.checksums = [
    {
      algorithm: 'SHA512',
      checksumValue: `sha512-${toolchainLock.toolchains.pnpm.registry.integrity_sha512}`,
    },
  ];
  const probe = validateSbomSemantics(mutated, { repo: ctx.repo, toolchainLock, actionsLock });
  if (probe.result !== 'FAIL') {
    fail('negative invalid-checksum probe was NOT rejected (SRI/base64 checksumValue accepted)');
  } else {
    const rightReason = probe.details.some((d) => d.includes('pnpm') || d.includes('SHA512') || d.includes('hex'));
    if (!rightReason) fail('negative probe failed for an unexpected reason');
    else ok('negative-probe PASS: SRI/base64 pnpm checksumValue rejected by the semantic validator');
  }

  // 4. Negative probe: the human full license name "PostgreSQL License" in
  // place of the SPDX short identifier on the MAIN SOFTWARE package must be
  // rejected.
  const licenseProbe = JSON.parse(JSON.stringify(doc));
  const licenseProbePg = licenseProbe.packages.find((p) => p.SPDXID === 'SPDXRef-PostgreSQL');
  if (!licenseProbePg) {
    fail('negative full-name license probe could not run: PostgreSQL main-software package missing from SBOM');
    return { name: 'sbom', result: 'FAIL', details };
  }
  licenseProbePg.licenseConcluded = 'PostgreSQL License';
  licenseProbePg.licenseDeclared = 'PostgreSQL License';
  const licenseProbeResult = validateSbomSemantics(licenseProbe, { repo: ctx.repo, toolchainLock, actionsLock });
  if (licenseProbeResult.result !== 'FAIL') {
    fail('negative full-name license probe was NOT rejected ("PostgreSQL License" accepted as a license expression)');
  } else {
    const rightReason = licenseProbeResult.details.some((d) => d.includes('license'));
    if (!rightReason) fail('full-name license probe failed for an unexpected reason');
    else ok('negative-probe PASS: full human license name "PostgreSQL License" rejected on the main software; SPDX short identifier PostgreSQL required');
  }

  // 5. Negative probe: a version-defining mutation must invalidate the
  // retained namespace (content-addressed binding).
  const versionProbe = JSON.parse(JSON.stringify(doc));
  const versionProbeAipt = versionProbe.packages.find((p) => p.SPDXID === AIPT_SPDXID);
  if (!versionProbeAipt) {
    fail('negative version-binding probe could not run: AIPT package missing from SBOM');
    return { name: 'sbom', result: 'FAIL', details };
  }
  versionProbeAipt.comment += ' [version-defining mutation probe]';
  const versionProbeResult = validateSbomSemantics(versionProbe, { repo: ctx.repo, toolchainLock, actionsLock });
  if (versionProbeResult.result !== 'FAIL') {
    fail('negative version-binding probe was NOT rejected (mutated version-defining content kept the original namespace)');
  } else {
    const rightReason = versionProbeResult.details.some((d) => d.includes('documentNamespace'));
    if (!rightReason) fail('version-binding probe failed for an unexpected reason');
    else ok('negative-probe PASS: version-defining mutation invalidates the retained namespace (content-addressed namespace binding enforced)');
  }

  // 6. Negative probe: the legacy static pre-R5 namespace must be rejected
  // explicitly, even though it is a valid absolute URI.
  const legacyProbe = JSON.parse(JSON.stringify(doc));
  legacyProbe.documentNamespace = LEGACY_NAMESPACE;
  const legacyProbeResult = validateSbomSemantics(legacyProbe, { repo: ctx.repo, toolchainLock, actionsLock });
  if (legacyProbeResult.result !== 'FAIL') {
    fail('negative legacy-namespace probe was NOT rejected (stale static namespace accepted)');
  } else {
    const rightReason = legacyProbeResult.details.some((d) => d.includes('legacy') || d.includes('documentNamespace'));
    if (!rightReason) fail('legacy-namespace probe failed for an unexpected reason');
    else ok(`negative-probe PASS: legacy static namespace ${JSON.stringify(LEGACY_NAMESPACE)} explicitly rejected (stale/reused namespace forbidden)`);
  }

  // 7-10. Negative probes (B001-GPT-003 regressions): the three-layer
  // license model and the exact digest identity must each be enforced.
  const threeLayerProbes = [
    {
      label: 'composite image mislabeled PostgreSQL',
      reason: /NOASSERTION/,
      mutate: (probeDoc) => {
        const p = probeDoc.packages.find((x) => x.SPDXID === 'SPDXRef-PostgreSQL-Image');
        p.licenseConcluded = 'PostgreSQL';
        p.licenseDeclared = 'PostgreSQL';
      },
    },
    {
      label: 'composite image mislabeled MIT',
      reason: /NOASSERTION/,
      mutate: (probeDoc) => {
        const p = probeDoc.packages.find((x) => x.SPDXID === 'SPDXRef-PostgreSQL-Image');
        p.licenseConcluded = 'MIT';
        p.licenseDeclared = 'MIT';
      },
    },
    {
      label: 'PostgreSQL main software moved away from PostgreSQL',
      reason: /PostgreSQL/,
      mutate: (probeDoc) => {
        const p = probeDoc.packages.find((x) => x.SPDXID === 'SPDXRef-PostgreSQL');
        p.licenseConcluded = 'MIT';
        p.licenseDeclared = 'MIT';
      },
    },
    {
      label: 'docker-library/postgres packaging source moved away from MIT',
      reason: /MIT/,
      mutate: (probeDoc) => {
        const p = probeDoc.packages.find((x) => x.SPDXID === 'SPDXRef-docker-library-postgres');
        p.licenseConcluded = 'BSD-3-Clause';
        p.licenseDeclared = 'BSD-3-Clause';
      },
    },
    {
      label: 'multi-arch digest deleted from image versionInfo/purl/comment',
      reason: /digest|purl|versionInfo/,
      mutate: (probeDoc) => {
        const p = probeDoc.packages.find((x) => x.SPDXID === 'SPDXRef-PostgreSQL-Image');
        p.versionInfo = p.versionInfo.replace(` @ ${PG_MULTI_ARCH_DIGEST}`, '');
        p.externalRefs = [];
        p.comment = p.comment.split(PG_MULTI_ARCH_DIGEST).join('').split(PG_LINUX_AMD64_PLATFORM_DIGEST).join('');
      },
    },
    {
      label: 'multi-arch digest modified in image versionInfo/purl/comment',
      reason: /digest/,
      mutate: (probeDoc) => {
        const p = probeDoc.packages.find((x) => x.SPDXID === 'SPDXRef-PostgreSQL-Image');
        const tampered = PG_MULTI_ARCH_DIGEST.slice(0, -1) + (PG_MULTI_ARCH_DIGEST.endsWith('6') ? '7' : '6');
        p.versionInfo = p.versionInfo.split(PG_MULTI_ARCH_DIGEST).join(tampered);
        p.comment = p.comment.split(PG_MULTI_ARCH_DIGEST).join(tampered);
        for (const ref of p.externalRefs ?? []) {
          if (ref.referenceType === 'purl') ref.referenceLocator = ref.referenceLocator.split(PG_MULTI_ARCH_DIGEST).join(tampered);
        }
      },
    },
  ];
  for (const def of threeLayerProbes) {
    const probeDoc = JSON.parse(JSON.stringify(doc));
    const probeImage = probeDoc.packages.find((x) => x.SPDXID === 'SPDXRef-PostgreSQL-Image');
    if (!probeImage || !probeDoc.packages.some((x) => x.SPDXID === 'SPDXRef-PostgreSQL') || !probeDoc.packages.some((x) => x.SPDXID === 'SPDXRef-docker-library-postgres')) {
      fail(`negative ${def.label} probe could not run: three-layer PostgreSQL packages missing from SBOM`);
      continue;
    }
    def.mutate(probeDoc);
    const probeResult = validateSbomSemantics(probeDoc, { repo: ctx.repo, toolchainLock, actionsLock });
    if (probeResult.result !== 'FAIL') {
      fail(`negative ${def.label} probe was NOT rejected`);
    } else {
      const rightReason = probeResult.details.filter((d) => d.startsWith('FAIL')).some((d) => def.reason.test(d));
      if (!rightReason) fail(`negative ${def.label} probe failed for an unexpected reason`);
      else ok(`negative-probe PASS: ${def.label} rejected by the semantic validator`);
    }
  }

  // 11-14. Negative probes (B001-GPT-003 relationship drift): deleting or
  // changing the image CONTAINS PostgreSQL main software composition
  // relationship, or the image GENERATED_FROM docker-library/postgres
  // packaging source composition relationship, must be rejected — and each
  // rejection must come from the composition relationship check itself, not
  // merely from the content-addressed namespace mismatch that any mutation
  // of the document causes.
  const relContains = (r) =>
    r.spdxElementId === 'SPDXRef-PostgreSQL-Image' &&
    r.relationshipType === 'CONTAINS' &&
    r.relatedSpdxElement === 'SPDXRef-PostgreSQL';
  const relGeneratedFrom = (r) =>
    r.spdxElementId === 'SPDXRef-PostgreSQL-Image' &&
    r.relationshipType === 'GENERATED_FROM' &&
    r.relatedSpdxElement === 'SPDXRef-docker-library-postgres';
  const relationshipProbes = [
    {
      label: 'composition relationship deleted: image CONTAINS PostgreSQL main software',
      reason: /composition relationship: SPDXRef-PostgreSQL-Image CONTAINS SPDXRef-PostgreSQL/,
      predicate: relContains,
      mutate: (probeDoc) => {
        probeDoc.relationships = probeDoc.relationships.filter((r) => !relContains(r));
      },
    },
    {
      label: 'composition relationship changed: image CONTAINS PostgreSQL main software retyped to DEPENDS_ON',
      reason: /composition relationship: SPDXRef-PostgreSQL-Image CONTAINS SPDXRef-PostgreSQL/,
      predicate: relContains,
      mutate: (probeDoc) => {
        probeDoc.relationships.find(relContains).relationshipType = 'DEPENDS_ON';
      },
    },
    {
      label: 'composition relationship deleted: image GENERATED_FROM docker-library/postgres packaging source',
      reason: /composition relationship: SPDXRef-PostgreSQL-Image GENERATED_FROM SPDXRef-docker-library-postgres/,
      predicate: relGeneratedFrom,
      mutate: (probeDoc) => {
        probeDoc.relationships = probeDoc.relationships.filter((r) => !relGeneratedFrom(r));
      },
    },
    {
      label: 'composition relationship changed: image GENERATED_FROM packaging source retyped to CONTAINS',
      reason: /composition relationship: SPDXRef-PostgreSQL-Image GENERATED_FROM SPDXRef-docker-library-postgres/,
      predicate: relGeneratedFrom,
      mutate: (probeDoc) => {
        probeDoc.relationships.find(relGeneratedFrom).relationshipType = 'CONTAINS';
      },
    },
  ];
  for (const def of relationshipProbes) {
    const probeDoc = JSON.parse(JSON.stringify(doc));
    if (!probeDoc.relationships.some(def.predicate)) {
      fail(`negative ${def.label} probe could not run: expected composition relationship missing from generated SBOM`);
      continue;
    }
    def.mutate(probeDoc);
    const probeResult = validateSbomSemantics(probeDoc, { repo: ctx.repo, toolchainLock, actionsLock });
    if (probeResult.result !== 'FAIL') {
      fail(`negative ${def.label} probe was NOT rejected`);
    } else {
      const rightReason = probeResult.details.filter((d) => d.startsWith('FAIL')).some((d) => def.reason.test(d));
      if (!rightReason) {
        fail(`negative ${def.label} probe failed for an unexpected reason (composition relationship check did not fire)`);
      } else ok(`negative-probe PASS: ${def.label} rejected by the composition relationship check`);
    }
  }

  // 15-19. Negative probes (B002 iteration 4): the first-party adapter-sdk
  // package model must be enforced — each rejection must come from the
  // package/relationship checks themselves, not merely from the
  // content-addressed namespace mismatch that any mutation causes.
  const sdkPackageProbes = [
    {
      label: 'adapter-sdk package deleted from the SBOM',
      reason: /required package missing: @aipt\/adapter-sdk/,
      mutate: (probeDoc) => {
        probeDoc.packages = probeDoc.packages.filter((p) => p.SPDXID !== SDK_SPDXID);
      },
    },
    {
      label: 'adapter-sdk package wrongly licensed',
      reason: /MIT/,
      mutate: (probeDoc) => {
        const p = probeDoc.packages.find((x) => x.SPDXID === SDK_SPDXID);
        p.licenseConcluded = 'Apache-2.0';
        p.licenseDeclared = 'Apache-2.0';
      },
    },
    {
      label: 'adapter-sdk npm purl deleted/drifted',
      reason: /npm purl/,
      mutate: (probeDoc) => {
        const p = probeDoc.packages.find((x) => x.SPDXID === SDK_SPDXID);
        p.externalRefs = (p.externalRefs ?? []).filter((r) => r.referenceType !== 'purl');
      },
    },
    {
      label: 'adapter-sdk PACKAGE_OF relationship deleted',
      reason: /first-party relationship: SPDXRef-adapter-sdk PACKAGE_OF SPDXRef-AIPT/,
      mutate: (probeDoc) => {
        probeDoc.relationships = probeDoc.relationships.filter(
          (r) => !(r.spdxElementId === SDK_SPDXID && r.relationshipType === 'PACKAGE_OF' && r.relatedSpdxElement === AIPT_SPDXID),
        );
      },
    },
    {
      label: 'adapter-sdk PACKAGE_OF relationship retyped to DEV_TOOL_OF',
      reason: /first-party relationship: SPDXRef-adapter-sdk PACKAGE_OF SPDXRef-AIPT|DEV_TOOL_OF/,
      mutate: (probeDoc) => {
        const rel = probeDoc.relationships.find(
          (r) => r.spdxElementId === SDK_SPDXID && r.relationshipType === 'PACKAGE_OF' && r.relatedSpdxElement === AIPT_SPDXID,
        );
        rel.relationshipType = 'DEV_TOOL_OF';
      },
    },
  ];
  for (const def of sdkPackageProbes) {
    const probeDoc = JSON.parse(JSON.stringify(doc));
    const probeSdk = probeDoc.packages.find((x) => x.SPDXID === SDK_SPDXID);
    if (!probeSdk) {
      fail(`negative ${def.label} probe could not run: adapter-sdk package missing from generated SBOM`);
      continue;
    }
    def.mutate(probeDoc);
    const probeResult = validateSbomSemantics(probeDoc, { repo: ctx.repo, toolchainLock, actionsLock });
    if (probeResult.result !== 'FAIL') {
      fail(`negative ${def.label} probe was NOT rejected`);
    } else {
      const rightReason = probeResult.details.filter((d) => d.startsWith('FAIL')).some((d) => def.reason.test(d));
      if (!rightReason) fail(`negative ${def.label} probe failed for an unexpected reason`);
      else ok(`negative-probe PASS: ${def.label} rejected by the first-party package model checks`);
    }
  }

  return { name: 'sbom', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'sbom', run);
