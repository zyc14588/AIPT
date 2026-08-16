#!/usr/bin/env node
// Deterministic SPDX 2.3 JSON SBOM generator for AIPT-M0-B001.
//
// Node.js standard library only (no third-party dependency). The same inputs
// produce byte-identical output: fixed timestamps, sorted arrays, no
// environment- or time-dependent content. Dynamic provenance is emitted
// separately by scripts/ci/provenance.mjs.
//
// Coverage: AIPT root package, Go module direct/transitive deps, pnpm
// direct/transitive deps, CI action fixed commits, supply-chain ephemeral
// scanner/tool identities, PostgreSQL image digest, and toolchain versions.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const CREATED = '2026-08-16T00:00:00Z';
const DOC_NAMESPACE = 'https://github.com/zyc14588/AIPT/spdx/aipt-m0-b001';

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
      versionInfo: 'M0-B001',
      licenseConcluded: 'MIT',
      licenseDeclared: 'MIT',
      copyrightText: 'Copyright (c) 2026 AIPT contributors',
      filesAnalyzed: false,
      comment:
        'Go module github.com/zyc14588/AIPT (go 1.26.x, toolchain go1.26.5) and private npm root package aipt@0.0.0. ' +
        `B001 third-party runtime dependencies: go=${goRequires.length}, pnpm=${pnpmPackages.length} ` +
        '(both expected to be 0; any future dependency must first enter tools/supply-chain/licenses.json).',
      externalRefs: [
        purl('golang', 'github.com/zyc14588/AIPT'),
        purl('npm', 'aipt@0.0.0'),
      ],
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
          checksumValue: `sha512-${toolchain.toolchains.pnpm.registry.integrity_sha512}`,
        },
      ],
    },
    {
      name: 'PostgreSQL Docker Official Image',
      SPDXID: 'SPDXRef-PostgreSQL-Image',
      downloadLocation: `https://hub.docker.com/_/postgres`,
      versionInfo: `library/postgres:${pg.version} @ ${pg.docker_official_image.multi_arch_digest}`,
      licenseConcluded: 'PostgreSQL License',
      licenseDeclared: 'PostgreSQL License',
      copyrightText: 'PostgreSQL Global Development Group',
      filesAnalyzed: false,
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: `pkg:docker/library/postgres@${pg.docker_official_image.multi_arch_digest}`,
        },
      ],
      comment: `multi-arch digest ${pg.docker_official_image.multi_arch_digest}; linux/amd64 platform digest ${pg.docker_official_image.linux_amd64_platform_digest}`,
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
    ...packages
      .filter((p) => p.SPDXID !== 'SPDXRef-AIPT')
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
    name: 'AIPT-M0-B001-supply-chain-sbom',
    documentNamespace: DOC_NAMESPACE,
    creationInfo: {
      created: CREATED,
      creators: ['Tool: AIPT-M0-B001 scripts/ci/sbom/generate-sbom.mjs (Node.js standard library only)'],
      comment:
        'Deterministic SBOM: identical inputs produce byte-identical output (CI generates twice and compares). ' +
        'Dynamic source provenance is attached separately via scripts/ci/provenance.mjs.',
    },
    packages,
    relationships,
    documentDescribes: ['SPDXRef-AIPT'],
  };

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
