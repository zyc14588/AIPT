// SBOM validator (AIPT-M0-B001-REPAIR-R4, finding B001-GPT-002): the gate now
// enforces deterministic output AND SPDX 2.3 / component semantics, plus a
// negative probe proving an invalid SRI-style checksum is rejected.
//
// `node scripts/ci/validate/sbom.mjs` reports PASS only when:
//   1. semantic validation passes (SPDX-2.3, CC0-1.0, absolute document
//      namespace, unique package SPDXIDs, the exact B001 required package
//      set, toolchain/action versions matching the lock files, resolvable
//      relationships with SPDX 2.3-valid types, lowercase-hex checksums of
//      algorithm-appropriate length, pnpm SHA512 hex decoded from the pinned
//      SRI payload, PostgreSQL digest identity, zero third-party deps);
//   2. two independent generations are byte-identical;
//   3. a negative probe that rewrites the pnpm SHA512 checksumValue into
//      SRI/base64 form is rejected (semantic validator returns FAIL).
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

// The exact B001 required package identities (B001 has zero third-party
// application runtime dependencies, so the SBOM package set must be exactly
// this set — no GoDep/PnpmDep packages).
const REQUIRED_PACKAGES = [
  { name: 'AIPT', spdxId: AIPT_SPDXID },
  { name: 'Go toolchain', spdxId: 'SPDXRef-Toolchain-Go' },
  { name: 'Node.js', spdxId: 'SPDXRef-Toolchain-Node' },
  { name: 'pnpm', spdxId: 'SPDXRef-Toolchain-pnpm' },
  { name: 'PostgreSQL Docker Official Image', spdxId: 'SPDXRef-PostgreSQL-Image' },
  { name: 'govulncheck', spdxId: 'SPDXRef-Tool-govulncheck' },
  { name: 'actions/checkout', spdxId: 'SPDXRef-Action-actions-checkout' },
  { name: 'actions/setup-go', spdxId: 'SPDXRef-Action-actions-setup-go' },
  { name: 'actions/setup-node', spdxId: 'SPDXRef-Action-actions-setup-node' },
];

const CHECKSUM_HEX_LENGTHS = { SHA1: 40, SHA256: 64, SHA512: 128 };

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

  // ---- exact required B001 package set (zero third-party deps) ----
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
  if (requiredOk) ok(`all ${REQUIRED_PACKAGES.length} required B001 package identities present with expected SPDXIDs`);
  const unknown = doc.packages.filter((p) => !byName.has(p.name) || !REQUIRED_PACKAGES.some((r) => r.name === p.name));
  if (doc.packages.length !== REQUIRED_PACKAGES.length || unknown.length > 0) {
    fail(`SBOM package set must be exactly the ${REQUIRED_PACKAGES.length} required B001 packages (third-party dependency count must remain 0), got ${doc.packages.length}`);
  } else ok('SBOM package set is exactly the required B001 set: third-party application dependency count = 0');
  const depIds = ids.filter((id) => id.startsWith('SPDXRef-GoDep-') || id.startsWith('SPDXRef-PnpmDep-'));
  if (depIds.length > 0) fail(`SBOM carries dependency packages: ${depIds.join(', ')}`);
  else ok('no GoDep/PnpmDep dependency packages in the SBOM');

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

  // ---- PostgreSQL digest identity remains represented ----
  const pgPkg = find('SPDXRef-PostgreSQL-Image');
  const pgText = `${JSON.stringify(pgPkg?.externalRefs ?? [])} ${pgPkg?.comment ?? ''} ${pgPkg?.versionInfo ?? ''}`;
  if (pg.multi_arch_digest !== PG_MULTI_ARCH_DIGEST) fail('toolchain lock postgresql multi-arch digest drifted from frozen value');
  else ok('toolchain lock postgresql multi-arch digest == frozen value');
  if (pg.linux_amd64_platform_digest !== PG_LINUX_AMD64_PLATFORM_DIGEST) fail('toolchain lock postgresql linux/amd64 platform digest drifted from frozen value');
  else ok('toolchain lock postgresql linux/amd64 platform digest == frozen value');
  if (!pgText.includes(PG_MULTI_ARCH_DIGEST) || !pgText.includes(PG_LINUX_AMD64_PLATFORM_DIGEST)) {
    fail('PostgreSQL package must represent both pinned digests (multi-arch + linux/amd64 platform)');
  } else ok('PostgreSQL digest identity (multi-arch + linux/amd64) represented in the SBOM');

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
  const nonAipt = doc.packages.filter((p) => p.SPDXID !== AIPT_SPDXID);
  const missingDevTool = nonAipt.filter(
    (p) => !doc.relationships.some((r) => r.spdxElementId === p.SPDXID && r.relationshipType === 'DEV_TOOL_OF' && r.relatedSpdxElement === AIPT_SPDXID),
  );
  if (missingDevTool.length > 0) fail(`packages missing DEV_TOOL_OF relationship to AIPT: ${missingDevTool.map((p) => p.SPDXID).join(', ')}`);
  else ok('every non-AIPT package has a DEV_TOOL_OF relationship to AIPT');

  // ---- documentDescribes ----
  if (!Array.isArray(doc.documentDescribes) || doc.documentDescribes.length === 0) {
    fail('documentDescribes missing');
  } else if (!doc.documentDescribes.includes(AIPT_SPDXID)) {
    fail('documentDescribes must include SPDXRef-AIPT');
  } else if (doc.documentDescribes.some((id) => !knownIds.has(id))) {
    fail('documentDescribes references an unresolved SPDXID');
  } else ok('documentDescribes resolves and includes SPDXRef-AIPT');

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

  return { name: 'sbom', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'sbom', run);
