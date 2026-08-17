#!/usr/bin/env node
// Deterministic SPDX 2.3 JSON SBOM generator for AIPT-M0-B002.
//
// Node.js standard library only (no third-party dependency). The same inputs
// produce byte-identical output: fixed timestamps, sorted arrays, no
// environment- or time-dependent content. Dynamic provenance is emitted
// separately by scripts/ci/provenance.mjs.
//
// The SPDX documentNamespace is content-addressed: the version-defining
// payload (the whole document minus documentNamespace) is canonically
// serialized (sorted object keys) and SHA-256 hashed, and the 64 lowercase
// hex characters become the namespace suffix under
// https://github.com/zyc14588/AIPT/spdx/aipt-m0-b002/. Any change to a
// version-defining field therefore yields a different, version-unique
// namespace; the historical static pre-R5 B001 namespace is never reused.
//
// Coverage: AIPT root package, the first-party workspace package
// @aipt/adapter-sdk (B002 iteration 4, PACKAGE_OF AIPT — never a
// DEV_TOOL_OF dependency), Go module direct/transitive deps, pnpm
// direct/transitive deps, CI action fixed commits, supply-chain ephemeral
// scanner/tool identities, toolchain versions, and the three-layer
// PostgreSQL model (AIPT-M0-B001-R6):
//   1. PostgreSQL 18.4 main software — its own package identity with
//      licenseConcluded/licenseDeclared = SPDX short identifier PostgreSQL;
//   2. docker-library/postgres packaging source — its own package identity
//      with licenseConcluded/licenseDeclared = MIT;
//   3. PostgreSQL Docker Official Image — a composite container of multiple
//      sources/components; its licenseConcluded/licenseDeclared are BOTH
//      NOASSERTION (never PostgreSQL, never MIT). The image package's
//      versionInfo, purl and comment each carry the exact pinned multi-arch
//      digest, and its comment also carries the linux/amd64 platform digest.
//
// Composition (precise three-layer relationship model): the image CONTAINS
// the main software (a component actually present inside the container),
// and the docker-library/postgres packaging source is the image's build
// INPUT rather than its content — so the image GENERATED_FROM the packaging
// source. An image never CONTAINS its own packaging sources.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const CREATED = '2026-08-17T00:00:00Z';
const NAMESPACE_BASE = 'https://github.com/zyc14588/AIPT/spdx/aipt-m0-b002';
const SDK_SPDXID = 'SPDXRef-adapter-sdk';

// Canonical JSON: arrays in order, object keys sorted recursively, so the
// serialized version-defining payload is independent of insertion order.
function canonicalJson(value) {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (value && typeof value === 'object') {
    const sorted = {};
    for (const key of Object.keys(value).sort()) sorted[key] = canonicalJson(value[key]);
    return sorted;
  }
  return value;
}

// SHA-256 (64 lowercase hex) over the canonical serialization of a document
// payload that must NOT contain a documentNamespace property.
function documentVersionHash(docWithoutNamespace) {
  return crypto.createHash('sha256').update(JSON.stringify(canonicalJson(docWithoutNamespace))).digest('hex');
}

function readJson(repo, rel) {
  return JSON.parse(fs.readFileSync(path.join(repo, rel), 'utf8'));
}

function parseGoRequires(repo) {
  const text = fs.readFileSync(path.join(repo, 'go.mod'), 'utf8');
  const requires = [];
  const block = /^require\s*\(([\s\S]*?)^\)/m.exec(text);
  if (block) {
    for (const line of block[1].split('\n')) {
      const m = /^\s*([\w./\-]+)\s+(v[\w.+\-]+)/.exec(line);
      if (m) requires.push({ path: m[1], version: m[2] });
    }
  }
  for (const m of text.matchAll(/^require\s+([\w./\-]+)\s+(v[\w.+\-]+)\s*$/gm)) {
    requires.push({ path: m[1], version: m[2] });
  }
  return requires;
}

function parsePnpmPackages(repo) {
  const text = fs.readFileSync(path.join(repo, 'pnpm-lock.yaml'), 'utf8');
  const packages = [];
  const section = /^packages:\s*$([\s\S]*?)(?=^\S)/m.exec(text);
  if (!section) return packages;
  for (const m of section[1].matchAll(/^\s{2}['"]?([^'"]+)['"]?:\s*$/gm)) {
    const key = m[1];
    const at = key.lastIndexOf('@');
    const name = key.slice(0, at).replace(/^\/+/, '');
    const version = key.slice(at + 1);
    packages.push({ name, version });
  }
  return packages;
}

function purl(type, locator) {
  return { referenceCategory: 'PACKAGE-MANAGER', referenceType: 'purl', referenceLocator: `pkg:${type}/${locator}` };
}

// The pnpm lock stores the npm registry SHA-512 SRI value as a base64
// payload. SPDX 2.3 requires checksumValue to be the digest encoded as
// lowercase hexadecimal digits (128 chars for SHA512), never an `sha512-`
// SRI string. Decode and re-encode deterministically, failing loudly when
// the pinned payload is not a 64-byte SHA-512 digest.
function sriSha512ToHex(sri) {
  const bytes = Buffer.from(sri, 'base64');
  if (bytes.length !== 64) {
    throw new Error(`pnpm registry integrity_sha512 must decode to 64 bytes, got ${bytes.length}`);
  }
  const hex = bytes.toString('hex');
  if (!/^[0-9a-f]{128}$/.test(hex)) {
    throw new Error(`pnpm registry integrity_sha512 must encode to 128 lowercase hex chars, got ${hex.length}`);
  }
  return hex;
}

export function buildSbom(repoRoot) {
  const repo = path.resolve(repoRoot);
  const toolchain = readJson(repo, 'tools/toolchain.lock.json');
  const actions = readJson(repo, 'tools/ci-actions.lock.json').actions;
  const goRequires = parseGoRequires(repo);
  const pnpmPackages = parsePnpmPackages(repo);
  const govulncheck = toolchain.tooling.govulncheck;
  const pg = toolchain.toolchains.postgresql;

  const packages = [
    {
      name: 'AIPT',
      SPDXID: 'SPDXRef-AIPT',
      downloadLocation: 'https://github.com/zyc14588/AIPT',
      versionInfo: 'M0-B002',
      licenseConcluded: 'MIT',
      licenseDeclared: 'MIT',
      copyrightText: 'Copyright (c) 2026 AIPT contributors',
      filesAnalyzed: false,
      comment:
        'Go module github.com/zyc14588/AIPT (go 1.26.x, toolchain go1.26.5), private npm root package aipt@0.0.0, ' +
        `and the first-party workspace package @aipt/adapter-sdk@1.0.0 (packages/adapter-sdk, PACKAGE_OF AIPT). ` +
        `B002 third-party runtime dependencies: go=${goRequires.length}, pnpm=${pnpmPackages.length} ` +
        '(both expected to be 0; any future dependency must first enter tools/supply-chain/licenses.json).',
      externalRefs: [
        purl('golang', 'github.com/zyc14588/AIPT'),
        purl('npm', 'aipt@0.0.0'),
      ],
    },
    {
      name: '@aipt/adapter-sdk',
      SPDXID: SDK_SPDXID,
      downloadLocation: 'NOASSERTION',
      versionInfo: '1.0.0',
      licenseConcluded: 'MIT',
      licenseDeclared: 'MIT',
      copyrightText: 'Copyright (c) 2026 AIPT contributors',
      filesAnalyzed: false,
      comment:
        'First-party dependency-free TypeScript adapter contract SDK (packages/adapter-sdk, zero dependency ' +
        'specifiers; Node 24 native erasable TypeScript). Part of the AIPT repository: SPDXRef-adapter-sdk ' +
        'PACKAGE_OF SPDXRef-AIPT — first-party, never a DEV_TOOL_OF dependency. MIT, covered by the root LICENSE ' +
        '(recorded in the B002 license inventory).',
      externalRefs: [purl('npm', '%40aipt/adapter-sdk@1.0.0')],
    },
    {
      name: 'Go toolchain',
      SPDXID: 'SPDXRef-Toolchain-Go',
      downloadLocation: toolchain.toolchains.go.linux_amd64_archive.url,
      versionInfo: toolchain.toolchains.go.version,
      licenseConcluded: 'BSD-3-Clause',
      licenseDeclared: 'BSD-3-Clause',
      copyrightText: 'Copyright 2009 The Go Authors',
      filesAnalyzed: false,
      checksums: [
        {
          algorithm: 'SHA256',
          checksumValue: toolchain.toolchains.go.linux_amd64_archive.sha256,
        },
      ],
    },
    {
      name: 'Node.js',
      SPDXID: 'SPDXRef-Toolchain-Node',
      downloadLocation: toolchain.toolchains.node.linux_x64_archive.url,
      versionInfo: `${toolchain.toolchains.node.version} (LTS ${toolchain.toolchains.node.release_codename})`,
      licenseConcluded: 'MIT',
      licenseDeclared: 'MIT',
      copyrightText: 'Node.js contributors',
      filesAnalyzed: false,
      checksums: [
        {
          algorithm: 'SHA256',
          checksumValue: toolchain.toolchains.node.linux_x64_archive.sha256,
        },
      ],
    },
    {
      name: 'pnpm',
      SPDXID: 'SPDXRef-Toolchain-pnpm',
      downloadLocation: toolchain.toolchains.pnpm.registry.tarball,
      versionInfo: toolchain.toolchains.pnpm.version,
      licenseConcluded: 'MIT',
      licenseDeclared: 'MIT',
      copyrightText: 'pnpm contributors',
      filesAnalyzed: false,
      checksums: [
        {
          algorithm: 'SHA512',
          checksumValue: sriSha512ToHex(toolchain.toolchains.pnpm.registry.integrity_sha512),
        },
      ],
    },
    {
      name: 'PostgreSQL',
      SPDXID: 'SPDXRef-PostgreSQL',
      downloadLocation: 'https://www.postgresql.org/download/',
      versionInfo: pg.version,
      licenseConcluded: 'PostgreSQL',
      licenseDeclared: 'PostgreSQL',
      copyrightText: 'PostgreSQL Global Development Group',
      filesAnalyzed: false,
      comment:
        `PostgreSQL ${pg.version} main software from postgresql.org; SPDX short identifier PostgreSQL ` +
        `(human-readable full name "PostgreSQL License" is recorded in the B001 license inventory).`,
    },
    {
      name: 'docker-library/postgres',
      SPDXID: 'SPDXRef-docker-library-postgres',
      downloadLocation: 'https://github.com/docker-library/postgres',
      versionInfo: `${pg.version} packaging source`,
      licenseConcluded: 'MIT',
      licenseDeclared: 'MIT',
      copyrightText: 'docker-library/postgres contributors',
      filesAnalyzed: false,
      comment:
        `docker-library/postgres packaging source for library/postgres:${pg.version} (the image is GENERATED_FROM ` +
        `this packaging source, never CONTAINS it); MIT (recorded in the B001 license inventory).`,
    },
    {
      name: 'PostgreSQL Docker Official Image',
      SPDXID: 'SPDXRef-PostgreSQL-Image',
      downloadLocation: `https://hub.docker.com/_/postgres`,
      versionInfo: `library/postgres:${pg.version} @ ${pg.docker_official_image.multi_arch_digest}`,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: 'NOASSERTION',
      copyrightText: 'NOASSERTION',
      filesAnalyzed: false,
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: `pkg:docker/library/postgres@${pg.docker_official_image.multi_arch_digest}`,
        },
      ],
      comment:
        `composite container: CONTAINS PostgreSQL ${pg.version} main software (PostgreSQL) and GENERATED_FROM the ` +
        `docker-library/postgres packaging source (MIT), plus base-image components; the whole image carries NOASSERTION ` +
        `for licenseConcluded/licenseDeclared (never PostgreSQL, never MIT). ` +
        `multi-arch digest ${pg.docker_official_image.multi_arch_digest}; ` +
        `linux/amd64 platform digest ${pg.docker_official_image.linux_amd64_platform_digest}`,
    },
    {
      name: 'govulncheck',
      SPDXID: 'SPDXRef-Tool-govulncheck',
      downloadLocation: govulncheck.source,
      versionInfo: govulncheck.version,
      licenseConcluded: 'BSD-3-Clause',
      licenseDeclared: 'BSD-3-Clause',
      copyrightText: 'Copyright 2009 The Go Authors',
      filesAnalyzed: false,
      comment: `module ${govulncheck.module}; supply-chain ephemeral scanner identity (vulnerability scan tooling)`,
      externalRefs: [purl('golang', `${govulncheck.module}@${govulncheck.version}`)],
    },
  ];

  for (const action of actions) {
    packages.push({
      name: action.repository,
      SPDXID: `SPDXRef-Action-${action.repository.replace(/[^A-Za-z0-9-]/g, '-')}`,
      downloadLocation: `https://github.com/${action.repository}`,
      versionInfo: `${action.stable_release_tag} @ ${action.resolved_commit_sha}`,
      licenseConcluded: action.license,
      licenseDeclared: action.license,
      copyrightText: `${action.repository} contributors`,
      filesAnalyzed: false,
      sourceInfo: `CI action pinned at commit ${action.resolved_commit_sha}`,
    });
  }

  for (const dep of goRequires) {
    packages.push({
      name: dep.path,
      SPDXID: `SPDXRef-GoDep-${dep.path.replace(/[^A-Za-z0-9-]/g, '-')}`,
      downloadLocation: 'NOASSERTION',
      versionInfo: dep.version,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: 'NOASSERTION',
      copyrightText: 'NOASSERTION',
      filesAnalyzed: false,
    });
  }

  for (const dep of pnpmPackages) {
    packages.push({
      name: dep.name,
      SPDXID: `SPDXRef-PnpmDep-${dep.name.replace(/[^A-Za-z0-9-]/g, '-')}`,
      downloadLocation: 'NOASSERTION',
      versionInfo: dep.version,
      licenseConcluded: 'NOASSERTION',
      licenseDeclared: 'NOASSERTION',
      copyrightText: 'NOASSERTION',
      filesAnalyzed: false,
    });
  }

  packages.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  const relationships = [
    {
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: 'SPDXRef-AIPT',
    },
    {
      // First-party workspace package: part of the AIPT repository itself,
      // never a build/dev tool dependency of it.
      spdxElementId: SDK_SPDXID,
      relationshipType: 'PACKAGE_OF',
      relatedSpdxElement: 'SPDXRef-AIPT',
    },
    {
      spdxElementId: 'SPDXRef-PostgreSQL-Image',
      relationshipType: 'CONTAINS',
      relatedSpdxElement: 'SPDXRef-PostgreSQL',
    },
    {
      // The packaging source is the image's build input, not its content:
      // GENERATED_FROM, never CONTAINS.
      spdxElementId: 'SPDXRef-PostgreSQL-Image',
      relationshipType: 'GENERATED_FROM',
      relatedSpdxElement: 'SPDXRef-docker-library-postgres',
    },
    ...packages
      .filter((p) => p.SPDXID !== 'SPDXRef-AIPT' && p.SPDXID !== SDK_SPDXID)
      .map((p) => ({
        spdxElementId: p.SPDXID,
        relationshipType: 'DEV_TOOL_OF',
        relatedSpdxElement: 'SPDXRef-AIPT',
      })),
  ];

  const doc = {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'AIPT-M0-B002-supply-chain-sbom',
    creationInfo: {
      created: CREATED,
      creators: ['Tool: AIPT-M0-B002 scripts/ci/sbom/generate-sbom.mjs (Node.js standard library only)'],
      comment:
        'Deterministic SBOM: identical inputs produce byte-identical output (CI generates twice and compares). ' +
        'The first-party workspace package @aipt/adapter-sdk is modeled as PACKAGE_OF AIPT (never DEV_TOOL_OF). ' +
        'Dynamic source provenance is attached separately via scripts/ci/provenance.mjs.',
    },
    packages,
    relationships,
    documentDescribes: ['SPDXRef-AIPT', SDK_SPDXID],
  };

  // Version-unique, content-addressed namespace: the hash is computed over
  // the full document payload WITHOUT documentNamespace, so the namespace is
  // a deterministic function of the document's version-defining content.
  doc.documentNamespace = `${NAMESPACE_BASE}/${documentVersionHash(doc)}`;

  return Buffer.from(`${JSON.stringify(doc, null, 2)}\n`, 'utf8');
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const args = {};
  for (let i = 2; i < process.argv.length; i += 1) {
    if (process.argv[i] === '--repo' && process.argv[i + 1]) {
      args.repo = process.argv[i + 1];
      i += 1;
    } else if (process.argv[i] === '--out' && process.argv[i + 1]) {
      args.out = process.argv[i + 1];
      i += 1;
    }
  }
  const out = buildSbom(args.repo || process.cwd());
  if (args.out) {
    fs.writeFileSync(args.out, out);
    process.stdout.write(`SBOM written: ${args.out} (${out.length} bytes)\n`);
  } else {
    process.stdout.write(out);
  }
}
