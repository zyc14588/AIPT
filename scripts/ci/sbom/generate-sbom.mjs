#!/usr/bin/env node
// Deterministic SPDX 2.3 JSON SBOM generator for AIPT-M0-B005.
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
// https://github.com/zyc14588/AIPT/spdx/aipt-m0-b005/. Any change to a
// version-defining field therefore yields a different, version-unique
// namespace; the historical static pre-R5 B001 namespace is never reused.
//
// Coverage: AIPT root package, the first-party workspace package
// @aipt/adapter-sdk (B002 iteration 4, PACKAGE_OF AIPT — never a
// DEV_TOOL_OF dependency), the six approved third-party Go runtime modules of
// the pgx v5.10.0 closure (AIPT-M0-B003 iteration 6a), CI action fixed
// commits, supply-chain ephemeral scanner/tool identities, toolchain
// versions, and the three-layer PostgreSQL model (AIPT-M0-B001-R6):
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
//
// Go runtime dependency model (AIPT-M0-B003 iteration 6a): the six modules
// are APPLICATION RUNTIME dependencies, never DEV_TOOL_OF packages. AIPT
// DEPENDS_ON github.com/jackc/pgx/v5 (the single direct go.mod require), and
// pgx DEPENDS_ON each of the five indirect modules. Every module carries its
// exact known SPDX license (MIT for the jackc modules, BSD-3-Clause for the
// golang.org/x modules), its golang purl, and a SHA-256 checksumValue that is
// the lowercase-hex decode of the go.sum zip `h1:` base64 payload (the Go
// dirhash H1 value is itself a 32-byte SHA-256 digest, so SPDX 2.3 requires
// the decoded lowercase hex, never the base64 `h1:` string).
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const CREATED = '2026-08-22T00:00:00Z';
const NAMESPACE_BASE = 'https://github.com/zyc14588/AIPT/spdx/aipt-m0-b005';
const SDK_SPDXID = 'SPDXRef-adapter-sdk';
const HARNESS_ADAPTER_SPDXID = 'SPDXRef-harness-adapter';

// The exact approved pgx v5.10.0 Go runtime closure (AIPT-M0-B003 iteration
// 6a), pinned in the generator and cross-checked against go.mod/go.sum so a
// manifest drift fails generation instead of silently changing the SBOM.
// gomodhex is the frozen SHA-256 (64 lowercase hex) that the go.sum
// `<module> <version>/go.mod h1:` base64 payload must decode to (the zip h1
// is derived separately at build time).
const GO_RUNTIME_MODULES = [
  { module: 'github.com/jackc/pgx/v5', version: 'v5.10.0', direct: true, license: 'MIT', copyright: 'Copyright (c) Jack Christensen', h1hex: '5614af814da34a58bca3702a20439326beeb670004515a381385e147de197ebd', gomodhex: '99a975b4118015f2c7bd9cda621efb612fde0ba217f4e59b455d50208334267e' },
  { module: 'github.com/jackc/pgpassfile', version: 'v1.0.0', direct: false, license: 'MIT', copyright: 'Copyright (c) Jack Christensen', h1hex: 'ffa1e6ab2d774acdb30aaeb655d346f2d335c1c867f338d218e049ea2729b083', gomodhex: '084c74892e5a99b34575c46dc4f8f9261133fb107ab91932e5ec95bbf5b61c48' },
  { module: 'github.com/jackc/pgservicefile', version: 'v0.0.0-20240606120523-5a60cdf6a761', direct: false, license: 'MIT', copyright: 'Copyright (c) Jack Christensen', h1hex: '882127a287bb525c0e418a4a16105a6cf322e1a3407e83833c414d8809c2971a', gomodhex: 'e5325958a1169e23ef7b7def956612a0661e7e7de02d04738df0e585227d64a3' },
  { module: 'github.com/jackc/puddle/v2', version: 'v2.2.2', direct: false, license: 'MIT', copyright: 'Copyright (c) Jack Christensen', h1hex: '3d1f27c3e13fd70d062ee4454a68a2a18e94a28329e8a26fd3feb59c1ee2707a', gomodhex: 'beb8a21171ef104eb9e1a60a5d78cebd9337f6a274abe6b391916b7c439cdc7e' },
  { module: 'golang.org/x/sync', version: 'v0.21.0', direct: false, license: 'BSD-3-Clause', copyright: 'Copyright 2009 The Go Authors', h1hex: '1cb208e314514ed091931629e0734517426cfce83aab68bef8a5db8348070b03', gomodhex: 'f71acdc1d2dfc788e429b36f6bd1692fabc437b7af9c4e3734d3494362c5dfed' },
  { module: 'golang.org/x/text', version: 'v0.39.0', direct: false, license: 'BSD-3-Clause', copyright: 'Copyright 2009 The Go Authors', h1hex: '51b673e292cebe7eb4d03e8e87a186108e950269ddac404bbfcffa0445f3caeb', gomodhex: 'dd4c117259c2da0d1353dc7c3d98b27ce6a309dd7369434717d72fa9c419f993' },
];

// x/text v0.39.0 also deterministically selects these two module-graph-only
// tooling modules under Go 1.26.6. They are represented in the SBOM but are
// never counted or modeled as AIPT application runtime dependencies.
const GO_MODULE_GRAPH_TOOLING = [
  { module: 'golang.org/x/mod', previousVersion: 'v0.27.0', version: 'v0.37.0', license: 'BSD-3-Clause', copyright: 'Copyright 2009 The Go Authors', h1hex: 'bc5d438e9544b21708aa811a6aeb8779b68b9353b57e8af18f105a567f3ce094', gomodhex: '9bc4bc55e33daf87730f08eb28ed1ad6c64fdd88de31a9914650fe7e647643fd' },
  { module: 'golang.org/x/tools', previousVersion: 'v0.36.0', version: 'v0.47.0', license: 'BSD-3-Clause', copyright: 'Copyright 2009 The Go Authors', h1hex: 'eca9f9c7f775b2fc7f3f3af24eca9ea193784d9c2a787e691968de7e12e2ff54', gomodhex: '7451e7c93bc5598db5d86fa1ed963856ca7f2b7538ffb5bd4f255a02e97cb820' },
];

function goModuleSpdxId(module) {
  return `SPDXRef-GoModule-${module.replace(/[^A-Za-z0-9-]/g, '-')}`;
}

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
function readGoModRequiresText(text) {
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

// Read the require directives of the repo's go.mod (disk wrapper).
function readGoModRequires(repo) {
  const text = fs.readFileSync(path.join(repo, 'go.mod'), 'utf8');
  return readGoModRequiresText(text);
}

// Read one go.sum h1 base64 payload for a module@version from a go.sum text
// and return its SHA-256 as 64 lowercase hex. kind is 'zip' (the module
// archive `h1:`) or 'gomod' (the module's go.mod `h1:`). The Go dirhash H1
// value is a 32-byte SHA-256 digest, so the SPDX 2.3 checksumValue is the
// decoded lowercase hex — never the base64 `h1:` string. Throws when the
// payload is missing or does not decode to 32 bytes.
function goModuleH1HexFromText(goSumText, module, version, kind) {
  const suffix = kind === 'gomod' ? '/go.mod' : '';
  const re = new RegExp(`^${module.replace(/[.\\+]/g, '\\$&')}\\s+${version.replace(/[.\\+]/g, '\\$&')}${suffix}\\s+h1:([A-Za-z0-9+/=]+)$`, 'm');
  const m = re.exec(goSumText);
  if (!m) throw new Error(`go.sum missing ${kind === 'gomod' ? '/go.mod ' : ''}h1 for ${module} ${version}`);
  const bytes = Buffer.from(m[1], 'base64');
  if (bytes.length !== 32) throw new Error(`go.sum ${kind === 'gomod' ? '/go.mod ' : ''}h1 for ${module} ${version} decodes to ${bytes.length} bytes, want 32`);
  const hex = bytes.toString('hex');
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error(`go.sum ${kind === 'gomod' ? '/go.mod ' : ''}h1 for ${module} ${version} is not 64 lowercase hex chars`);
  return hex;
}

// Read the go.sum zip `h1:` base64 payload for one module@version from the
// repo and return its SHA-256 as 64 lowercase hex characters.
function goModuleH1Hex(repo, module, version) {
  const text = fs.readFileSync(path.join(repo, 'go.sum'), 'utf8');
  return goModuleH1HexFromText(text, module, version, 'zip');
}

// Fail-closed cross-check over in-memory go.mod/go.sum texts: go.mod must
// require EXACTLY the six approved modules with exact versions and exact
// direct/indirect markers and carry NO replace/exclude/retract
// dependency-graph override directive; go.sum must carry the zip + /go.mod
// h1 for each module with both payloads decoding to the frozen pinned
// SHA-256 values. Any drift throws and aborts generation.
function verifyGoClosureText({ goMod, goSum }) {
  const requires = readGoModRequiresText(goMod);
  const byModule = new Map(requires.map((r) => [r.module, r]));
  if (requires.length !== GO_RUNTIME_MODULES.length) {
    throw new Error(`go.mod require count must be exactly ${GO_RUNTIME_MODULES.length}, got ${requires.length}`);
  }
  for (const m of GO_RUNTIME_MODULES) {
    const r = byModule.get(m.module);
    if (!r) throw new Error(`go.mod missing required module ${m.module}`);
    if (r.version !== m.version) throw new Error(`go.mod ${m.module} version drift: ${r.version} != ${m.version}`);
    if (Boolean(r.indirect) !== !m.direct) throw new Error(`go.mod ${m.module} directness drift: expected ${m.direct ? 'direct' : 'indirect'}`);
  }
  const unknown = requires.filter((r) => !GO_RUNTIME_MODULES.some((m) => m.module === r.module));
  if (unknown.length > 0) throw new Error(`go.mod unknown dependency outside the approved closure: ${unknown.map((r) => r.module).join(', ')}`);
  const graphOverride = [];
  if (hasOverrideDirective(goMod, 'replace')) graphOverride.push('replace');
  if (hasOverrideDirective(goMod, 'exclude')) graphOverride.push('exclude');
  if (hasOverrideDirective(goMod, 'retract')) graphOverride.push('retract');
  if (graphOverride.length > 0) throw new Error(`go.mod carries dependency-graph override directive(s): ${graphOverride.join(', ')} (replace/exclude/retract are forbidden for the approved closure)`);
  for (const m of GO_RUNTIME_MODULES) {
    const zipHex = goModuleH1HexFromText(goSum, m.module, m.version, 'zip');
    if (zipHex !== m.h1hex) throw new Error(`go.sum ${m.module} ${m.version} zip h1 decodes to ${zipHex}, expected pinned SHA-256 ${m.h1hex}`);
    const gomodHex = goModuleH1HexFromText(goSum, m.module, m.version, 'gomod');
    if (gomodHex !== m.gomodhex) throw new Error(`go.sum ${m.module} ${m.version} /go.mod h1 decodes to ${gomodHex}, expected pinned SHA-256 ${m.gomodhex}`);
  }
}

// Fail-closed cross-check of the repo's go.mod/go.sum (reads the on-disk
// files and delegates to the pure verifyGoClosureText).
function verifyGoClosure(repo) {
  const goMod = fs.readFileSync(path.join(repo, 'go.mod'), 'utf8');
  const goSum = fs.readFileSync(path.join(repo, 'go.sum'), 'utf8');
  verifyGoClosureText({ goMod, goSum });
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
  verifyGoClosure(repo);
  const goModules = GO_RUNTIME_MODULES.map((m) => ({ ...m, h1hex: goModuleH1Hex(repo, m.module, m.version) }));
  const goGraphTooling = GO_MODULE_GRAPH_TOOLING.map((m) => ({ ...m }));
  const pnpmPackages = parsePnpmPackages(repo);
  const govulncheck = toolchain.tooling.govulncheck;
  const pg = toolchain.toolchains.postgresql;

  const packages = [
    {
      name: 'AIPT',
      SPDXID: 'SPDXRef-AIPT',
      downloadLocation: 'https://github.com/zyc14588/AIPT',
      versionInfo: 'M0-B005',
      licenseConcluded: 'MIT',
      licenseDeclared: 'MIT',
      copyrightText: 'Copyright (c) 2026 AIPT contributors',
      filesAnalyzed: false,
      comment:
        'AIPT-M0-B005 fail-closed Harness Adapter stdio runtime; no new third-party dependency identity was introduced. ' +
        'Go module github.com/zyc14588/AIPT (go 1.26.x, toolchain go1.26.6 — B003 security requalification), private npm root package aipt@0.0.0, ' +
        `and first-party workspace packages @aipt/adapter-sdk@1.0.0 and @aipt/harness-adapter@0.1.0 (both PACKAGE_OF AIPT). ` +
        `B004 security-requalifies the B003 runtime closure: go=${goModules.length}, selected-module-graph tooling=${goGraphTooling.length}, pnpm=${pnpmPackages.length} ` +
        `(six approved Go runtime modules: pgx v5.10.0 direct + five transitive, recorded in ` +
        `tools/supply-chain/licenses.json with exact versions/licenses/directness; x/text v0.29.0 -> v0.39.0 resolves GO-2026-5970, ` +
        `and MVS selects x/sync v0.21.0 plus graph-only x/mod v0.37.0 and x/tools v0.47.0). ` +
        `SPDXRef-AIPT DEPENDS_ON ${goModuleSpdxId('github.com/jackc/pgx/v5')} — the pgx closure is an application ` +
        'runtime dependency, never a DEV_TOOL_OF package.',
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
      name: '@aipt/harness-adapter',
      SPDXID: HARNESS_ADAPTER_SPDXID,
      downloadLocation: 'NOASSERTION',
      versionInfo: '0.1.0',
      licenseConcluded: 'MIT',
      licenseDeclared: 'MIT',
      copyrightText: 'Copyright (c) 2026 AIPT contributors',
      filesAnalyzed: false,
      comment:
        'First-party B005 thin stdio Harness Adapter runtime (packages/harness-adapter). ' +
        'SPDXRef-harness-adapter PACKAGE_OF SPDXRef-AIPT and SPDXRef-harness-adapter DEPENDS_ON ' +
        'SPDXRef-adapter-sdk through the exact workspace:* -> link:../adapter-sdk edge. ' +
        'No npm registry or other third-party package; never classified as DEV_TOOL_OF.',
      externalRefs: [purl('npm', '%40aipt/harness-adapter@0.1.0')],
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

  // The six approved third-party Go runtime modules of the pgx v5.10.0
  // closure: exact known SPDX licenses (never NOASSERTION), golang purls,
  // and SHA-256 checksumValues decoded from the go.sum zip h1 base64 payload.
  for (const m of goModules) {
    const spdxId = goModuleSpdxId(m.module);
    const role = m.direct ? 'direct' : 'transitive';
    packages.push({
      name: m.module,
      SPDXID: spdxId,
      downloadLocation: 'NOASSERTION',
      versionInfo: m.version,
      licenseConcluded: m.license,
      licenseDeclared: m.license,
      copyrightText: m.copyright,
      filesAnalyzed: false,
      checksums: [
        {
          algorithm: 'SHA256',
          checksumValue: m.h1hex,
        },
      ],
      externalRefs: [purl('golang', `${m.module}@${m.version}`)],
      comment:
        `third-party Go application runtime dependency (${role}; go.mod ${m.direct ? 'require' : 'require // indirect'} ` +
        `${m.module} ${m.version}); SPDX license ${m.license}; go.sum zip h1 SHA-256 checksum ` +
        `(SPDX 2.3 lowercase hex decode of the h1 base64 payload); ` +
        `${m.direct ? `SPDXRef-AIPT DEPENDS_ON ${spdxId}` : `SPDXRef-GoModule-github-com-jackc-pgx-v5 DEPENDS_ON ${spdxId}`} — ` +
        'never classified as DEV_TOOL_OF.',
    });
  }

  for (const m of goGraphTooling) {
    const spdxId = goModuleSpdxId(m.module);
    packages.push({
      name: m.module,
      SPDXID: spdxId,
      downloadLocation: 'NOASSERTION',
      versionInfo: m.version,
      licenseConcluded: m.license,
      licenseDeclared: m.license,
      copyrightText: m.copyright,
      filesAnalyzed: false,
      checksums: [{ algorithm: 'SHA256', checksumValue: m.h1hex }],
      externalRefs: [purl('golang', `${m.module}@${m.version}`)],
      sourceInfo:
        `Go 1.26.6 selected-module graph; deterministic x/text v0.39.0 consequence; ` +
        `sumdb zip h1 SHA-256 ${m.h1hex}; go.mod h1 SHA-256 ${m.gomodhex}`,
      comment:
        `third-party Go selected module-graph tooling (module-graph-tooling; indirect; not an AIPT runtime dependency); ` +
        `${m.module} ${m.previousVersion} -> ${m.version} under AIPT-M0-B004-DEPENDENCY-SECURITY-REQUAL-001; ` +
        `SPDX license ${m.license}; ${goModuleSpdxId('golang.org/x/text')} DEPENDS_ON ${spdxId}; ` +
        `${spdxId} BUILD_TOOL_OF SPDXRef-AIPT; never classified as an application runtime dependency or DEV_TOOL_OF.`,
    });
  }

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

  const pgxSpdxId = goModuleSpdxId('github.com/jackc/pgx/v5');
  // Runtime dependency packages (the first-party SDK and the six Go runtime
  // modules) never receive a DEV_TOOL_OF relationship to AIPT.
  const nonDevTool = new Set([
    'SPDXRef-AIPT',
    SDK_SPDXID,
    HARNESS_ADAPTER_SPDXID,
    ...GO_RUNTIME_MODULES.map((m) => goModuleSpdxId(m.module)),
    ...GO_MODULE_GRAPH_TOOLING.map((m) => goModuleSpdxId(m.module)),
  ]);

  const relationships = [
    {
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: 'SPDXRef-AIPT',
    },
    {
      spdxElementId: HARNESS_ADAPTER_SPDXID,
      relationshipType: 'PACKAGE_OF',
      relatedSpdxElement: 'SPDXRef-AIPT',
    },
    {
      spdxElementId: HARNESS_ADAPTER_SPDXID,
      relationshipType: 'DEPENDS_ON',
      relatedSpdxElement: SDK_SPDXID,
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
    {
      // Application runtime dependency: AIPT DEPENDS_ON the direct pgx module.
      spdxElementId: 'SPDXRef-AIPT',
      relationshipType: 'DEPENDS_ON',
      relatedSpdxElement: pgxSpdxId,
    },
    // pgx DEPENDS_ON each of the five indirect modules of its closure.
    ...GO_RUNTIME_MODULES
      .filter((m) => !m.direct)
      .map((m) => ({
        spdxElementId: pgxSpdxId,
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: goModuleSpdxId(m.module),
      })),
    // x/text v0.39.0's selected module-graph consequences. x/sync is already
    // a runtime identity through pgx; x/mod and x/tools remain tooling-only.
    ...['golang.org/x/sync', ...GO_MODULE_GRAPH_TOOLING.map((m) => m.module)]
      .map((module) => ({
        spdxElementId: goModuleSpdxId('golang.org/x/text'),
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: goModuleSpdxId(module),
      })),
    ...GO_MODULE_GRAPH_TOOLING.map((m) => ({
      spdxElementId: goModuleSpdxId(m.module),
      relationshipType: 'BUILD_TOOL_OF',
      relatedSpdxElement: 'SPDXRef-AIPT',
    })),
    ...packages
      .filter((p) => !nonDevTool.has(p.SPDXID))
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
    name: 'AIPT-M0-B005-supply-chain-sbom',
    creationInfo: {
      created: CREATED,
      creators: ['Tool: AIPT-M0-B005 scripts/ci/sbom/generate-sbom.mjs (Node.js standard library only)'],
      comment:
        'Deterministic SBOM: identical inputs produce byte-identical output (CI generates twice and compares). ' +
        'AIPT-M0-B005 adds the first-party Harness Adapter and zero third-party package identity while preserving the exact B004 security-requalified pgx closure. ' +
        'The first-party workspace packages @aipt/adapter-sdk and @aipt/harness-adapter are modeled as PACKAGE_OF AIPT (never DEV_TOOL_OF); Harness Adapter DEPENDS_ON Adapter SDK. ' +
        'The six approved pgx v5.10.0 Go runtime modules are modeled as application runtime dependencies: ' +
        'AIPT DEPENDS_ON github.com/jackc/pgx/v5 and pgx DEPENDS_ON the five indirect modules (never DEV_TOOL_OF). ' +
        'x/text v0.39.0 DEPENDS_ON x/sync v0.21.0 plus graph-only x/mod v0.37.0 and x/tools v0.47.0; the two graph-only modules are BUILD_TOOL_OF AIPT, never runtime dependencies. ' +
        'Go module checksumValues are the SPDX 2.3 lowercase-hex decodes of the go.sum zip h1 base64 payloads. ' +
        'Dynamic source provenance is attached separately via scripts/ci/provenance.mjs.',
    },
    packages,
    relationships,
    documentDescribes: ['SPDXRef-AIPT', SDK_SPDXID, HARNESS_ADAPTER_SPDXID],
  };

  // Version-unique, content-addressed namespace: the hash is computed over
  // the full document payload WITHOUT documentNamespace, so the namespace is
  // a deterministic function of the document's version-defining content.
  doc.documentNamespace = `${NAMESPACE_BASE}/${documentVersionHash(doc)}`;

  return Buffer.from(`${JSON.stringify(doc, null, 2)}\n`, 'utf8');
}

// In-memory closure self-check: proves the generator's own fail-closed
// go.mod/go.sum cross-check rejects every enumerated drift on mutated copies
// of the real manifests (the on-disk files are never modified). Runs only in
// main mode, immediately before generation.
function runClosureSelfCheck(repo) {
  const goMod = fs.readFileSync(path.join(repo, 'go.mod'), 'utf8');
  const goSum = fs.readFileSync(path.join(repo, 'go.sum'), 'utf8');
  const cases = [
    {
      label: 'exact pgx v5.10.0 closure PASS',
      expectRejected: false,
      run: () => verifyGoClosureText({ goMod, goSum }),
    },
    {
      label: 'pgx missing FAIL',
      expectRejected: true,
      run: () => verifyGoClosureText({ goMod: goMod.replace('require github.com/jackc/pgx/v5 v5.10.0\n\n', ''), goSum }),
    },
    {
      label: 'pgx wrong version FAIL',
      expectRejected: true,
      run: () => verifyGoClosureText({ goMod: goMod.replace('github.com/jackc/pgx/v5 v5.10.0', 'github.com/jackc/pgx/v5 v5.9.0'), goSum }),
    },
    {
      label: 'extra direct dependency FAIL',
      expectRejected: true,
      run: () => verifyGoClosureText({ goMod: `${goMod}\nrequire example.com/rogue v1.0.0\n`, goSum }),
    },
    {
      label: 'replace graph override FAIL',
      expectRejected: true,
      run: () => verifyGoClosureText({ goMod: `${goMod}\nreplace github.com/jackc/pgx/v5 => github.com/jackc/pgx/v5 v5.9.0\n`, goSum }),
    },
    {
      label: 'seventh dependency hidden in a second require block FAIL',
      expectRejected: true,
      run: () => verifyGoClosureText({ goMod: `${goMod}\nrequire (\n\texample.com/rogue v1.0.0\n)\n`, goSum }),
    },
    {
      label: 'seventh dependency hidden after a comment-paren "// )" line in a second require block FAIL',
      expectRejected: true,
      run: () => verifyGoClosureText({ goMod: `${goMod}\nrequire (\n\t// )\n\texample.com/rogue v1.0.0\n)\n`, goSum }),
    },
    {
      label: 'rogue single-line require with an ordinary trailing comment FAIL',
      expectRejected: true,
      run: () => verifyGoClosureText({ goMod: `${goMod}\nrequire example.com/rogue v1.0.0 // ordinary comment\n`, goSum }),
    },
    {
      label: 'replace graph override with leading whitespace FAIL',
      expectRejected: true,
      run: () => verifyGoClosureText({ goMod: `${goMod}\n\treplace github.com/jackc/pgx/v5 => github.com/jackc/pgx/v5 v5.9.0\n`, goSum }),
    },
    {
      label: 'zip h1 tampered FAIL',
      expectRejected: true,
      run: () => verifyGoClosureText({
        goMod,
        goSum: goSum.replace('github.com/jackc/pgx/v5 v5.10.0 h1:VhSvgU2jSli8o3AqIEOTJr7rZwAEUVo4E4XhR94Zfr0=', 'github.com/jackc/pgx/v5 v5.10.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
      }),
    },
    {
      label: '/go.mod h1 removed FAIL',
      expectRejected: true,
      run: () => verifyGoClosureText({
        goMod,
        goSum: goSum.replace(/^github\.com\/jackc\/pgx\/v5 v5\.10\.0\/go\.mod h1:[^\n]+\n/m, ''),
      }),
    },
    {
      label: '/go.mod h1 tampered FAIL',
      expectRejected: true,
      run: () => verifyGoClosureText({
        goMod,
        goSum: goSum.replace('github.com/jackc/pgx/v5 v5.10.0/go.mod h1:mal1tBGAFfLHvZzaYh77YS/eC6IX9OWbRV1QIIM0Jn4=', 'github.com/jackc/pgx/v5 v5.10.0/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
      }),
    },
  ];
  const failures = [];
  for (const c of cases) {
    let rejected = false;
    try {
      c.run();
    } catch (err) {
      rejected = true;
    }
    const good = c.expectRejected ? rejected : !rejected;
    if (!good) failures.push(c.label);
  }
  if (failures.length > 0) {
    throw new Error(`generator closure self-check FAILED: ${failures.join('; ')}`);
  }
  process.stderr.write(`generator closure self-check PASS: ${cases.length} in-memory cases (1 exact closure + ${cases.length - 1} rejected drifts)\n`);
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
  const repo = args.repo || process.cwd();
  runClosureSelfCheck(repo);
  const out = buildSbom(repo);
  if (args.out) {
    fs.writeFileSync(args.out, out);
    process.stdout.write(`SBOM written: ${args.out} (${out.length} bytes)\n`);
  } else {
    process.stdout.write(out);
  }
}
