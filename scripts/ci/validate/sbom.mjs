// SBOM validator (AIPT-M0-B001-REPAIR-R6 foundation, evolved by B002
// iteration 4 and AIPT-M0-B003 iteration 6a): the gate enforces deterministic
// output AND SPDX 2.3 / component semantics — including the three-layer
// PostgreSQL license model, the first-party @aipt/adapter-sdk package model
// (own SPDX 2.3 package, MIT, version 1.0.0, npm purl, PACKAGE_OF AIPT —
// never DEV_TOOL_OF), and (AIPT-M0-B003 iteration 6a) the six approved
// third-party Go runtime modules of the pgx v5.10.0 closure with exact known
// licenses (MIT/BSD-3-Clause, never NOASSERTION), golang purls, SHA-256
// checksumValues decoded from the go.sum zip h1 base64 payloads, and the
// application runtime dependency graph AIPT DEPENDS_ON pgx / pgx DEPENDS_ON
// the five indirect modules (never DEV_TOOL_OF) — plus negative probes
// proving invalid documents are rejected:
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
//     content-addressed namespace mismatch);
//   - AIPT-M0-B003 iteration 6a: a Go runtime module package deleted,
//     version/license/checksum drifted, a runtime module misclassified as
//     DEV_TOOL_OF, the AIPT DEPENDS_ON pgx relationship deleted or retyped,
//     a pgx DEPENDS_ON indirect-module relationship deleted, and the
//     direct/transitive role of a runtime module drifted (each rejected by
//     its own semantic check).
//
// `node scripts/ci/validate/sbom.mjs` reports PASS only when:
//   1. semantic validation passes (SPDX-2.3, CC0-1.0, version-unique
//      content-addressed documentNamespace — SHA-256 of the canonical
//      version-defining payload — with the legacy static B001 namespace
//      explicitly rejected, unique package SPDXIDs, the exact B003 required
//      package set (all 11 B001 identities preserved plus the first-party
//      @aipt/adapter-sdk package plus the six approved Go runtime modules),
//      SPDX license values for every current package (the three-layer
//      PostgreSQL model: main software = PostgreSQL, packaging source = MIT,
//      composite image = NOASSERTION; adapter-sdk = MIT; pgx closure = exact
//      known MIT/BSD-3-Clause values),
//      the exact composition relationships (image CONTAINS main software,
//      image GENERATED_FROM packaging source — never CONTAINS the packaging
//      source; adapter-sdk PACKAGE_OF AIPT — never DEV_TOOL_OF; AIPT
//      DEPENDS_ON pgx; pgx DEPENDS_ON the five indirect modules — runtime
//      modules never DEV_TOOL_OF),
//      toolchain/action versions matching the lock files, resolvable
//      relationships with SPDX 2.3-valid types, lowercase-hex checksums of
//      algorithm-appropriate length, pnpm SHA512 hex decoded from the pinned
//      SRI payload, Go module SHA256 hex decoded from the go.sum zip h1
//      base64 payloads and pinned against the frozen h1 values, the exact
//      PostgreSQL multi-arch digest in the image versionInfo + purl + comment
//      and the linux/amd64 platform digest in the comment, zero pnpm
//      third-party deps, and the exact go.mod six-module closure);
//   2. two independent generations are byte-identical;
//   3. every negative probe above is rejected for the right reason
//      (relationship-drift probes must be rejected by the composition or
//      dependency relationship check itself, not merely by the
//      content-addressed namespace mismatch that any mutation causes).
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
const HARNESS_ADAPTER_SPDXID = 'SPDXRef-harness-adapter';
const NAMESPACE_BASE = 'https://github.com/zyc14588/AIPT/spdx/aipt-m0-b005';
// The static pre-R5 B001 namespace reused by distinct R3/R4 documents; still
// forbidden — a B004 document must never fall back to it.
const LEGACY_NAMESPACE = 'https://github.com/zyc14588/AIPT/spdx/aipt-m0-b001';
const PREVIOUS_NAMESPACE_BASE = 'https://github.com/zyc14588/AIPT/spdx/aipt-m0-b004';
const EXPECTED_DOCUMENT_NAME = 'AIPT-M0-B005-supply-chain-sbom';
const EXPECTED_AIPT_VERSION = 'M0-B005';
const EXPECTED_CREATED = '2026-08-22T00:00:00Z';
const EXPECTED_CREATOR = 'Tool: AIPT-M0-B005 scripts/ci/sbom/generate-sbom.mjs (Node.js standard library only)';

// The exact approved pgx v5.10.0 Go runtime closure (AIPT-M0-B003 iteration
// 6a). h1hex is the frozen SHA-256 (64 lowercase hex) that the go.sum zip
// `h1:` base64 payload must decode to; gomodhex is the frozen SHA-256 that
// the `<module> <version>/go.mod h1:` base64 payload must decode to. The
// validator independently derives both values from go.sum and compares, so a
// tampered h1 cannot pass.
const GO_RUNTIME_MODULES = [
  { module: 'github.com/jackc/pgx/v5', version: 'v5.10.0', direct: true, license: 'MIT', h1hex: '5614af814da34a58bca3702a20439326beeb670004515a381385e147de197ebd', gomodhex: '99a975b4118015f2c7bd9cda621efb612fde0ba217f4e59b455d50208334267e' },
  { module: 'github.com/jackc/pgpassfile', version: 'v1.0.0', direct: false, license: 'MIT', h1hex: 'ffa1e6ab2d774acdb30aaeb655d346f2d335c1c867f338d218e049ea2729b083', gomodhex: '084c74892e5a99b34575c46dc4f8f9261133fb107ab91932e5ec95bbf5b61c48' },
  { module: 'github.com/jackc/pgservicefile', version: 'v0.0.0-20240606120523-5a60cdf6a761', direct: false, license: 'MIT', h1hex: '882127a287bb525c0e418a4a16105a6cf322e1a3407e83833c414d8809c2971a', gomodhex: 'e5325958a1169e23ef7b7def956612a0661e7e7de02d04738df0e585227d64a3' },
  { module: 'github.com/jackc/puddle/v2', version: 'v2.2.2', direct: false, license: 'MIT', h1hex: '3d1f27c3e13fd70d062ee4454a68a2a18e94a28329e8a26fd3feb59c1ee2707a', gomodhex: 'beb8a21171ef104eb9e1a60a5d78cebd9337f6a274abe6b391916b7c439cdc7e' },
  { module: 'golang.org/x/sync', version: 'v0.21.0', direct: false, license: 'BSD-3-Clause', h1hex: '1cb208e314514ed091931629e0734517426cfce83aab68bef8a5db8348070b03', gomodhex: 'f71acdc1d2dfc788e429b36f6bd1692fabc437b7af9c4e3734d3494362c5dfed' },
  { module: 'golang.org/x/text', version: 'v0.39.0', direct: false, license: 'BSD-3-Clause', h1hex: '51b673e292cebe7eb4d03e8e87a186108e950269ddac404bbfcffa0445f3caeb', gomodhex: 'dd4c117259c2da0d1353dc7c3d98b27ce6a309dd7369434717d72fa9c419f993' },
];

const GO_MODULE_GRAPH_TOOLING = [
  { module: 'golang.org/x/mod', previousVersion: 'v0.27.0', version: 'v0.37.0', license: 'BSD-3-Clause', h1hex: 'bc5d438e9544b21708aa811a6aeb8779b68b9353b57e8af18f105a567f3ce094', gomodhex: '9bc4bc55e33daf87730f08eb28ed1ad6c64fdd88de31a9914650fe7e647643fd' },
  { module: 'golang.org/x/tools', previousVersion: 'v0.36.0', version: 'v0.47.0', license: 'BSD-3-Clause', h1hex: 'eca9f9c7f775b2fc7f3f3af24eca9ea193784d9c2a787e691968de7e12e2ff54', gomodhex: '7451e7c93bc5598db5d86fa1ed963856ca7f2b7538ffb5bd4f255a02e97cb820' },
];

function goModuleSpdxId(module) {
  return `SPDXRef-GoModule-${module.replace(/[^A-Za-z0-9-]/g, '-')}`;
}

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
// plus the first-party B002 workspace package @aipt/adapter-sdk, the six
// approved third-party Go runtime modules of the pgx v5.10.0 closure, and
// the two B004-qualified selected-module-graph tooling identities). The SBOM
// package set is exactly these 20 identities — no PnpmDep package and no Go
// identity outside the approved runtime/graph closure.
const REQUIRED_PACKAGES = [
  { name: 'AIPT', spdxId: AIPT_SPDXID },
  { name: '@aipt/adapter-sdk', spdxId: SDK_SPDXID },
  { name: '@aipt/harness-adapter', spdxId: HARNESS_ADAPTER_SPDXID },
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
  ...GO_RUNTIME_MODULES.map((m) => ({ name: m.module, spdxId: goModuleSpdxId(m.module) })),
  ...GO_MODULE_GRAPH_TOOLING.map((m) => ({ name: m.module, spdxId: goModuleSpdxId(m.module) })),
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
// AIPT-M0-B003 iteration 6a adds the six approved Go runtime modules with
// their exact known SPDX licenses (MIT for the jackc modules, BSD-3-Clause
// for the golang.org/x modules) — never NOASSERTION.
const EXPECTED_PACKAGE_LICENSES = {
  AIPT: 'MIT',
  '@aipt/adapter-sdk': 'MIT',
  '@aipt/harness-adapter': 'MIT',
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
  'github.com/jackc/pgx/v5': 'MIT',
  'github.com/jackc/pgpassfile': 'MIT',
  'github.com/jackc/pgservicefile': 'MIT',
  'github.com/jackc/puddle/v2': 'MIT',
  'golang.org/x/sync': 'BSD-3-Clause',
  'golang.org/x/text': 'BSD-3-Clause',
  'golang.org/x/mod': 'BSD-3-Clause',
  'golang.org/x/tools': 'BSD-3-Clause',
};

// The exact npm purl of the first-party SDK package (percent-encoded scope).
const SDK_NPM_PURL = 'pkg:npm/%40aipt/adapter-sdk@1.0.0';
const HARNESS_ADAPTER_NPM_PURL = 'pkg:npm/%40aipt/harness-adapter@0.1.0';

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

// Independent parse of go.mod require directives (single-line and block
// forms, `// indirect` markers). A separate copy from the generator's, so a
// generator parser defect cannot validate itself into PASS. The optional
// leading horizontal whitespace accepted by Go is honored before the
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

// Independent derivation of one go.sum zip h1 value as 64 lowercase hex; null
// when the line is missing or does not decode to 32 bytes. The Go dirhash H1
// value is a 32-byte SHA-256 digest, so the SPDX 2.3 checksumValue is the
// decoded lowercase hex.
function goSumZipH1Hex(goSumText, module, version) {
  const re = new RegExp(`^${module.replace(/[.\\+]/g, '\\$&')}\\s+${version.replace(/[.\\+]/g, '\\$&')}\\s+h1:([A-Za-z0-9+/=]+)$`, 'm');
  const m = re.exec(goSumText);
  if (!m) return null;
  const bytes = Buffer.from(m[1], 'base64');
  if (bytes.length !== 32) return null;
  const hex = bytes.toString('hex');
  return /^[0-9a-f]{64}$/.test(hex) ? hex : null;
}

// Independent fail-closed check that go.mod requires EXACTLY the six approved
// Go runtime modules with exact versions and exact direct/indirect markers,
// and carries NO replace/exclude/retract dependency-graph override directive.
// Returns a list of problem strings (empty when clean).
function goModClosureProblems(goModText) {
  const problems = [];
  // Parser errors are fail-closed: an unparseable top-level require directive
  // or non-comment block entry is reported as a problem instead of silently
  // dropping the offending line.
  let requires;
  try {
    requires = parseGoModRequires(goModText);
  } catch (err) {
    problems.push(`go.mod require parse error (fail-closed): ${err.message}`);
    return problems;
  }
  const byModule = new Map(requires.map((r) => [r.module, r]));
  if (requires.length !== GO_RUNTIME_MODULES.length) {
    problems.push(`go.mod require count must be exactly ${GO_RUNTIME_MODULES.length}, got ${requires.length}`);
  }
  for (const m of GO_RUNTIME_MODULES) {
    const r = byModule.get(m.module);
    if (!r) {
      problems.push(`go.mod missing required module ${m.module}`);
      continue;
    }
    if (r.version !== m.version) problems.push(`go.mod ${m.module} version must be ${m.version}, got ${r.version}`);
    if (Boolean(r.indirect) !== !m.direct) problems.push(`go.mod ${m.module} directness drifted: expected ${m.direct ? 'direct' : 'indirect'}`);
  }
  for (const r of requires) {
    if (!GO_RUNTIME_MODULES.some((m) => m.module === r.module)) problems.push(`unknown go.mod dependency: ${r.module}`);
  }
  const graphOverride = [];
  if (hasOverrideDirective(goModText, 'replace')) graphOverride.push('replace');
  if (hasOverrideDirective(goModText, 'exclude')) graphOverride.push('exclude');
  if (hasOverrideDirective(goModText, 'retract')) graphOverride.push('retract');
  if (graphOverride.length > 0) {
    problems.push(`go.mod carries dependency-graph override directive(s): ${graphOverride.join(', ')} (replace/exclude/retract are forbidden for the approved closure)`);
  }
  return problems;
}

// Independent fail-closed check of the go.sum h1 pins for all six approved
// modules: BOTH the zip `h1:` and the `/go.mod h1:` line must be present, and
// every base64 payload must decode to 32 bytes whose lowercase hex equals the
// frozen h1 SHA-256 value. Returns a list of problem strings (empty when
// clean).
function goSumH1Problems(goSumText) {
  const problems = [];
  const { zip, gomod } = (() => {
    const zip = new Map();
    const gomod = new Map();
    for (const m of goSumText.matchAll(/^([^\s]+)\s+(v[\w.+\-]+)\s+h1:([A-Za-z0-9+/=]+)$/gm)) zip.set(`${m[1]} ${m[2]}`, m[3]);
    for (const m of goSumText.matchAll(/^([^\s]+)\s+(v[\w.+\-]+)\/go\.mod\s+h1:([A-Za-z0-9+/=]+)$/gm)) gomod.set(`${m[1]} ${m[2]}`, m[3]);
    return { zip, gomod };
  })();
  for (const m of GO_RUNTIME_MODULES) {
    const key = `${m.module} ${m.version}`;
    const z = zip.get(key);
    const g = gomod.get(key);
    if (!z) {
      problems.push(`go.sum missing zip h1 for ${key}`);
      continue;
    }
    if (!g) {
      problems.push(`go.sum missing /go.mod h1 for ${key}`);
      continue;
    }
    const zBytes = Buffer.from(z, 'base64');
    const zHex = zBytes.length === 32 ? zBytes.toString('hex') : null;
    if (zHex !== m.h1hex) problems.push(`go.sum ${key} zip h1 decodes to ${zHex ?? `<${zBytes.length} bytes>`}, expected pinned SHA-256 ${m.h1hex}`);
    const gBytes = Buffer.from(g, 'base64');
    const gHex = gBytes.length === 32 ? gBytes.toString('hex') : null;
    if (gHex !== m.gomodhex) problems.push(`go.sum ${key} /go.mod h1 decodes to ${gHex ?? `<${gBytes.length} bytes>`}, expected pinned SHA-256 ${m.gomodhex}`);
  }
  return problems;
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
  if (typeof doc.documentNamespace === 'string' && doc.documentNamespace.startsWith(PREVIOUS_NAMESPACE_BASE + '/')) {
    fail('documentNamespace reuses the prior B004 namespace family; B005 requires its own content-addressed namespace family');
  }
  const expectedNamespace = computeExpectedNamespace(doc);
  if (doc.documentNamespace !== expectedNamespace) {
    fail(`documentNamespace must equal the content-addressed version namespace ${expectedNamespace} (SHA-256 of the canonical version-defining payload), got ${JSON.stringify(doc.documentNamespace)}`);
  } else {
    ok('documentNamespace is the version-unique content-addressed namespace (SHA-256 of the canonical version-defining payload)');
  }
  if (doc.SPDXID !== DOCUMENT_SPDXID) fail(`document SPDXID must be ${DOCUMENT_SPDXID}`);
  else ok(`document SPDXID = ${DOCUMENT_SPDXID}`);
  if (doc.name !== EXPECTED_DOCUMENT_NAME) {
    fail(`document name must be ${EXPECTED_DOCUMENT_NAME}, got ${JSON.stringify(doc.name)}`);
  } else ok(`document name = ${EXPECTED_DOCUMENT_NAME}`);
  if (doc.creationInfo?.created !== EXPECTED_CREATED) {
    fail(`creationInfo.created must be deterministic B005 time ${EXPECTED_CREATED}, got ${JSON.stringify(doc.creationInfo?.created)}`);
  } else ok(`creationInfo.created = ${EXPECTED_CREATED}`);
  if (!Array.isArray(doc.creationInfo?.creators) || !doc.creationInfo.creators.includes(EXPECTED_CREATOR)) {
    fail('creationInfo.creators must carry the exact B005 generator identity');
  } else ok('creationInfo.creators carries the exact B005 generator identity');

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
  const aiptPackage = find(AIPT_SPDXID);
  if (!aiptPackage || aiptPackage.versionInfo !== EXPECTED_AIPT_VERSION) {
    fail(`AIPT versionInfo must be ${EXPECTED_AIPT_VERSION}, got ${JSON.stringify(aiptPackage?.versionInfo)}`);
  } else ok(`AIPT versionInfo = ${EXPECTED_AIPT_VERSION}`);
  if (!aiptPackage || typeof aiptPackage.comment !== 'string' ||
      !aiptPackage.comment.includes('AIPT-M0-B005 fail-closed Harness Adapter stdio runtime') ||
      !aiptPackage.comment.includes('no new third-party dependency')) {
    fail('AIPT package comment must describe B005 Harness Adapter scope and zero new third-party dependencies');
  } else ok('AIPT package comment records B005 Harness Adapter scope and zero new third-party dependencies');

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
  if (requiredOk) ok(`all ${REQUIRED_PACKAGES.length} required package identities present with expected SPDXIDs (retained identities + two first-party workspace packages + Go closure)`);
  const unknown = doc.packages.filter((p) => !byName.has(p.name) || !REQUIRED_PACKAGES.some((r) => r.name === p.name));
  if (doc.packages.length !== REQUIRED_PACKAGES.length || unknown.length > 0) {
    fail(`SBOM package set must be exactly the ${REQUIRED_PACKAGES.length} required packages (no package outside the approved identities), got ${doc.packages.length}`);
  } else ok(`SBOM package set is exactly the ${REQUIRED_PACKAGES.length} required identities, including the B005 Harness Adapter and zero registry package`);
  const depIds = ids.filter((id) => id.startsWith('SPDXRef-GoDep-') || id.startsWith('SPDXRef-PnpmDep-'));
  if (depIds.length > 0) fail(`SBOM carries legacy GoDep/PnpmDep dependency packages: ${depIds.join(', ')}`);
  else ok('no legacy GoDep/PnpmDep dependency packages in the SBOM');

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

  // ---- first-party @aipt/harness-adapter package model (B005) ----
  const harnessPkg = byName.get('@aipt/harness-adapter');
  if (harnessPkg) {
    if (harnessPkg.versionInfo !== '0.1.0') {
      fail(`@aipt/harness-adapter versionInfo must be 0.1.0, got ${JSON.stringify(harnessPkg.versionInfo)}`);
    } else ok('@aipt/harness-adapter versionInfo = 0.1.0');
    const harnessPurl = (harnessPkg.externalRefs ?? []).find((r) => r?.referenceType === 'purl');
    if (!harnessPurl || harnessPurl.referenceLocator !== HARNESS_ADAPTER_NPM_PURL) {
      fail(`@aipt/harness-adapter npm purl must be exactly ${HARNESS_ADAPTER_NPM_PURL}`);
    } else ok('@aipt/harness-adapter carries the exact npm purl');
    const comment = harnessPkg.comment ?? '';
    if (!comment.includes('PACKAGE_OF') || !comment.includes('DEPENDS_ON') ||
        !comment.includes('workspace:*') || !comment.includes('link:../adapter-sdk') ||
        !comment.includes('never classified as DEV_TOOL_OF')) {
      fail('@aipt/harness-adapter comment must document first-party PACKAGE_OF, exact workspace DEPENDS_ON SDK, and never DEV_TOOL_OF');
    } else ok('@aipt/harness-adapter comment records the exact first-party workspace dependency model');
  }
  const harnessPackageOf = doc.relationships.some(
    (r) => r.spdxElementId === HARNESS_ADAPTER_SPDXID && r.relationshipType === 'PACKAGE_OF' && r.relatedSpdxElement === AIPT_SPDXID,
  );
  if (!harnessPackageOf) fail(`missing first-party relationship: ${HARNESS_ADAPTER_SPDXID} PACKAGE_OF ${AIPT_SPDXID}`);
  else ok('first-party relationship present: SPDXRef-harness-adapter PACKAGE_OF SPDXRef-AIPT');
  const harnessDependsOnSdk = doc.relationships.some(
    (r) => r.spdxElementId === HARNESS_ADAPTER_SPDXID && r.relationshipType === 'DEPENDS_ON' && r.relatedSpdxElement === SDK_SPDXID,
  );
  if (!harnessDependsOnSdk) fail(`missing dependency relationship: ${HARNESS_ADAPTER_SPDXID} DEPENDS_ON ${SDK_SPDXID}`);
  else ok('first-party dependency present: Harness Adapter DEPENDS_ON Adapter SDK');
  if (doc.relationships.some(
    (r) => r.spdxElementId === HARNESS_ADAPTER_SPDXID && r.relationshipType === 'DEV_TOOL_OF' && r.relatedSpdxElement === AIPT_SPDXID,
  )) fail(`${HARNESS_ADAPTER_SPDXID} must never be DEV_TOOL_OF AIPT`);
  else ok('@aipt/harness-adapter is never classified as DEV_TOOL_OF');

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
  if (licenseOk) ok('every package license matches its exact SPDX value, including both MIT first-party workspace packages');

  // ---- app-level dependency invariants (go.mod closure / pnpm-lock) ----
  // go.mod must carry EXACTLY the six approved Go runtime modules (1 direct +
  // 5 transitive) with exact versions and directness; pnpm-lock must carry
  // zero third-party packages.
  const goMod = fs.readFileSync(path.join(repo, 'go.mod'), 'utf8');
  const goModProblems = goModClosureProblems(goMod);
  if (goModProblems.length > 0) {
    for (const problem of goModProblems) fail(`go.mod closure: ${problem}`);
  } else ok('go.mod requires exactly the six approved pgx v5.10.0 runtime-closure modules (1 direct + 5 transitive, exact versions/directness, no replace/exclude/retract override)');
  const goSumH1Text = fs.readFileSync(path.join(repo, 'go.sum'), 'utf8');
  const goSumProblems = goSumH1Problems(goSumH1Text);
  if (goSumProblems.length > 0) {
    for (const problem of goSumProblems) fail(`go.sum h1 pins: ${problem}`);
  } else ok('go.sum carries exact zip + /go.mod h1 pins for all six approved modules (payloads decode to the frozen SHA-256 values)');
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

  // ---- Go runtime module packages (AIPT-M0-B003 iteration 6a): exact
  // versions, exact known SPDX licenses, golang purls, SHA-256 checksumValues
  // decoded from the go.sum zip h1 base64 payloads (independently derived
  // here and pinned against the frozen h1 values), and the direct/transitive
  // role in the comment ----
  const goSumText = fs.readFileSync(path.join(repo, 'go.sum'), 'utf8');
  let goModulesOk = true;
  for (const m of GO_RUNTIME_MODULES) {
    const pkg = byName.get(m.module);
    if (!pkg) {
      fail(`Go runtime module package missing from SBOM: ${m.module}`);
      goModulesOk = false;
      continue;
    }
    if (pkg.versionInfo !== m.version) {
      fail(`${m.module} versionInfo must be ${m.version}, got ${JSON.stringify(pkg.versionInfo)}`);
      goModulesOk = false;
    }
    const expectedPurl = `pkg:golang/${m.module}@${m.version}`;
    const purlRef = (pkg.externalRefs ?? []).find((r) => r?.referenceType === 'purl');
    if (!purlRef || purlRef.referenceLocator !== expectedPurl) {
      fail(`${m.module} purl referenceLocator must be exactly ${expectedPurl}, got ${JSON.stringify(purlRef?.referenceLocator)}`);
      goModulesOk = false;
    }
    const derived = goSumZipH1Hex(goSumText, m.module, m.version);
    if (derived !== m.h1hex) {
      fail(`go.sum zip h1 for ${m.module} ${m.version} must decode to the frozen SHA-256 ${m.h1hex}, got ${JSON.stringify(derived)}`);
      goModulesOk = false;
    }
    const cs = pkg.checksums ?? [];
    if (cs.length !== 1 || cs[0].algorithm !== 'SHA256' || cs[0].checksumValue !== m.h1hex) {
      fail(`${m.module} SHA256 checksumValue must be the frozen lowercase hex ${m.h1hex} (go.sum zip h1 decode), got ${JSON.stringify(cs)}`);
      goModulesOk = false;
    }
    const roleWord = m.direct ? 'direct' : 'transitive';
    const roleToken = m.direct ? '(direct;' : '(transitive;';
    const comment = pkg.comment ?? '';
    // Exact structured role token: the generator emits `(direct;` or
    // `(transitive;` as the role marker, and the validator requires that
    // exact token. A bare substring check would accept 'indirect' for the
    // direct role (because 'indirect' CONTAINS 'direct'); the structured
    // token closes that fail-open gap.
    if (!comment.includes(roleToken)) {
      fail(`${m.module} comment must classify the module as ${roleWord} via the exact structured role token ${JSON.stringify(roleToken)} (so an "indirect" marker can never satisfy the direct role), got ${JSON.stringify(comment)}`);
      goModulesOk = false;
    }
    if (!comment.includes('DEV_TOOL_OF') || !/never (?:classified as |a )?DEV_TOOL_OF/.test(comment)) {
      fail(`${m.module} comment must state the module is never classified as DEV_TOOL_OF`);
      goModulesOk = false;
    }
  }
  if (goModulesOk) ok('all six Go runtime module packages carry exact versions, known SPDX licenses, golang purls, frozen h1 SHA-256 checksums, and truthful direct/transitive roles');

  let graphToolingOk = true;
  for (const m of GO_MODULE_GRAPH_TOOLING) {
    const pkg = byName.get(m.module);
    if (!pkg) {
      fail(`Go selected module-graph tooling package missing from SBOM: ${m.module}`);
      graphToolingOk = false;
      continue;
    }
    if (pkg.versionInfo !== m.version) {
      fail(`${m.module} graph-tooling versionInfo must be ${m.version}, got ${JSON.stringify(pkg.versionInfo)}`);
      graphToolingOk = false;
    }
    const expectedPurl = `pkg:golang/${m.module}@${m.version}`;
    const purlRef = (pkg.externalRefs ?? []).find((r) => r?.referenceType === 'purl');
    if (!purlRef || purlRef.referenceLocator !== expectedPurl) {
      fail(`${m.module} graph-tooling purl must be exactly ${expectedPurl}`);
      graphToolingOk = false;
    }
    const cs = pkg.checksums ?? [];
    if (cs.length !== 1 || cs[0].algorithm !== 'SHA256' || cs[0].checksumValue !== m.h1hex) {
      fail(`${m.module} graph-tooling SHA256 checksumValue must be frozen sumdb h1 hex ${m.h1hex}`);
      graphToolingOk = false;
    }
    const comment = pkg.comment ?? '';
    if (
      !comment.includes('(module-graph-tooling;') ||
      !comment.includes(`${m.previousVersion} -> ${m.version}`) ||
      !comment.includes('not an AIPT runtime dependency')
    ) {
      fail(`${m.module} comment must preserve previous/current MVS history and exact module-graph-tooling non-runtime role`);
      graphToolingOk = false;
    }
  }
  if (graphToolingOk) ok('x/mod and x/tools SBOM packages carry exact MVS versions, BSD-3-Clause licenses, purls, checksums, and non-runtime tooling roles');

  // ---- Go runtime dependency graph: AIPT DEPENDS_ON pgx (the single direct
  // module) and pgx DEPENDS_ON each of the five indirect modules; runtime
  // modules are never DEV_TOOL_OF packages ----
  const pgxSpdxId = goModuleSpdxId('github.com/jackc/pgx/v5');
  const aiptDependsOnPgx = doc.relationships.some(
    (r) => r.spdxElementId === AIPT_SPDXID && r.relationshipType === 'DEPENDS_ON' && r.relatedSpdxElement === pgxSpdxId,
  );
  if (!aiptDependsOnPgx) {
    fail(`missing dependency relationship: ${AIPT_SPDXID} DEPENDS_ON ${pgxSpdxId} (pgx v5.10.0 is the direct application runtime dependency)`);
  } else ok(`application runtime dependency present: ${AIPT_SPDXID} DEPENDS_ON ${pgxSpdxId}`);
  let pgxDepsOk = true;
  for (const m of GO_RUNTIME_MODULES.filter((x) => !x.direct)) {
    const rel = doc.relationships.some(
      (r) => r.spdxElementId === pgxSpdxId && r.relationshipType === 'DEPENDS_ON' && r.relatedSpdxElement === goModuleSpdxId(m.module),
    );
    if (!rel) {
      fail(`missing dependency relationship: ${pgxSpdxId} DEPENDS_ON ${goModuleSpdxId(m.module)} (transitive runtime module of pgx)`);
      pgxDepsOk = false;
    }
  }
  if (pgxDepsOk) ok(`pgx DEPENDS_ON all five indirect modules of the closure (${GO_RUNTIME_MODULES.filter((x) => !x.direct).length} transitive runtime relationships)`);
  const xtextSpdxId = goModuleSpdxId('golang.org/x/text');
  let xtextGraphOk = true;
  for (const module of ['golang.org/x/sync', ...GO_MODULE_GRAPH_TOOLING.map((m) => m.module)]) {
    const target = goModuleSpdxId(module);
    if (!doc.relationships.some(
      (r) => r.spdxElementId === xtextSpdxId && r.relationshipType === 'DEPENDS_ON' && r.relatedSpdxElement === target,
    )) {
      fail(`missing selected-module relationship: ${xtextSpdxId} DEPENDS_ON ${target}`);
      xtextGraphOk = false;
    }
  }
  for (const m of GO_MODULE_GRAPH_TOOLING) {
    const source = goModuleSpdxId(m.module);
    if (!doc.relationships.some(
      (r) => r.spdxElementId === source && r.relationshipType === 'BUILD_TOOL_OF' && r.relatedSpdxElement === AIPT_SPDXID,
    )) {
      fail(`missing graph-tooling relationship: ${source} BUILD_TOOL_OF ${AIPT_SPDXID}`);
      xtextGraphOk = false;
    }
  }
  if (xtextGraphOk) ok('x/text selected graph edges and x/mod/x/tools BUILD_TOOL_OF roles are exact');
  const goDevTool = doc.relationships.filter(
    (r) => r.relationshipType === 'DEV_TOOL_OF' && r.relatedSpdxElement === AIPT_SPDXID && r.spdxElementId.startsWith('SPDXRef-GoModule-'),
  );
  if (goDevTool.length > 0) {
    fail(`Go runtime module(s) wrongly classified as DEV_TOOL_OF of AIPT: ${goDevTool.map((r) => r.spdxElementId).join(', ')} (runtime modules are DEPENDS_ON, never DEV_TOOL_OF)`);
  } else ok('no Go runtime module is classified as DEV_TOOL_OF (the pgx closure is an application runtime dependency)');

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
  // Every package that is neither AIPT nor the first-party SDK nor a Go
  // runtime module (the runtime closure is modeled as DEPENDS_ON, never
  // DEV_TOOL_OF) must have a DEV_TOOL_OF relationship to AIPT.
  const nonDevTool = new Set([
    AIPT_SPDXID,
    SDK_SPDXID,
    HARNESS_ADAPTER_SPDXID,
    ...GO_RUNTIME_MODULES.map((m) => goModuleSpdxId(m.module)),
    ...GO_MODULE_GRAPH_TOOLING.map((m) => goModuleSpdxId(m.module)),
  ]);
  const nonAipt = doc.packages.filter((p) => !nonDevTool.has(p.SPDXID));
  const missingDevTool = nonAipt.filter(
    (p) => !doc.relationships.some((r) => r.spdxElementId === p.SPDXID && r.relationshipType === 'DEV_TOOL_OF' && r.relatedSpdxElement === AIPT_SPDXID),
  );
  if (missingDevTool.length > 0) fail(`packages missing DEV_TOOL_OF relationship to AIPT: ${missingDevTool.map((p) => p.SPDXID).join(', ')}`);
  else ok('every generic tooling/CI/infrastructure package has DEV_TOOL_OF AIPT; SDK, runtime modules, and explicit graph-tooling BUILD_TOOL_OF packages are correctly excluded');

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
  } else if (!doc.documentDescribes.includes(HARNESS_ADAPTER_SPDXID)) {
    fail(`documentDescribes must include the first-party ${HARNESS_ADAPTER_SPDXID}`);
  } else if (doc.documentDescribes.some((id) => !knownIds.has(id))) {
    fail('documentDescribes references an unresolved SPDXID');
  } else ok('documentDescribes resolves and includes AIPT plus both first-party workspace packages');

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

  // B005 identity must be enforced independently of the namespace binding.
  const batchIdentityProbe = JSON.parse(JSON.stringify(doc));
  const batchIdentityAipt = batchIdentityProbe.packages.find((p) => p.SPDXID === AIPT_SPDXID);
  if (!batchIdentityAipt) {
    fail('negative B005 identity probe could not run: AIPT package missing from SBOM');
    return { name: 'sbom', result: 'FAIL', details };
  }
  batchIdentityAipt.versionInfo = 'M0-B004';
  batchIdentityProbe.documentNamespace = computeExpectedNamespace(batchIdentityProbe);
  const batchIdentityResult = validateSbomSemantics(batchIdentityProbe, { repo: ctx.repo, toolchainLock, actionsLock });
  if (batchIdentityResult.result !== 'FAIL') {
    fail('negative B005 identity probe was NOT rejected (M0-B004 root version accepted)');
  } else if (!batchIdentityResult.details.some((d) => d.includes('AIPT versionInfo must be M0-B005'))) {
    fail('B005 identity probe failed for an unexpected reason');
  } else {
    ok('negative-probe PASS: AIPT M0-B004 root version rejected even with a recomputed content-addressed namespace');
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

  const previousNamespaceProbe = JSON.parse(JSON.stringify(doc));
  const suffix = computeExpectedNamespace(previousNamespaceProbe).slice(NAMESPACE_BASE.length + 1);
  previousNamespaceProbe.documentNamespace = PREVIOUS_NAMESPACE_BASE + '/' + suffix;
  const previousNamespaceResult = validateSbomSemantics(previousNamespaceProbe, { repo: ctx.repo, toolchainLock, actionsLock });
  if (previousNamespaceResult.result !== 'FAIL') {
    fail('negative prior-B004 namespace probe was NOT rejected');
  } else if (!previousNamespaceResult.details.some((d) => d.includes('prior B004 namespace family'))) {
    fail('prior-B004 namespace probe failed for an unexpected reason');
  } else {
    ok('negative-probe PASS: prior B004 namespace family explicitly rejected for the B005 document');
  }

  // 5-10. Negative probes (B001-GPT-003 regressions): the three-layer
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

  const harnessPackageProbes = [
    {
      label: 'Harness Adapter package deleted from the SBOM',
      reason: /required package missing: @aipt\/harness-adapter/,
      mutate: (probeDoc) => {
        probeDoc.packages = probeDoc.packages.filter((p) => p.SPDXID !== HARNESS_ADAPTER_SPDXID);
      },
    },
    {
      label: 'Harness Adapter package wrongly licensed',
      reason: /MIT/,
      mutate: (probeDoc) => {
        const p = probeDoc.packages.find((x) => x.SPDXID === HARNESS_ADAPTER_SPDXID);
        p.licenseConcluded = 'Apache-2.0';
        p.licenseDeclared = 'Apache-2.0';
      },
    },
    {
      label: 'Harness Adapter npm purl drifted',
      reason: /harness-adapter npm purl/,
      mutate: (probeDoc) => {
        const p = probeDoc.packages.find((x) => x.SPDXID === HARNESS_ADAPTER_SPDXID);
        p.externalRefs[0].referenceLocator = 'pkg:npm/%40aipt/harness-adapter@9.9.9';
      },
    },
    {
      label: 'Harness Adapter PACKAGE_OF relationship deleted',
      reason: /missing first-party relationship: SPDXRef-harness-adapter PACKAGE_OF SPDXRef-AIPT/,
      mutate: (probeDoc) => {
        probeDoc.relationships = probeDoc.relationships.filter(
          (r) => !(r.spdxElementId === HARNESS_ADAPTER_SPDXID && r.relationshipType === 'PACKAGE_OF'),
        );
      },
    },
    {
      label: 'Harness Adapter DEPENDS_ON SDK relationship deleted',
      reason: /missing dependency relationship: SPDXRef-harness-adapter DEPENDS_ON SPDXRef-adapter-sdk/,
      mutate: (probeDoc) => {
        probeDoc.relationships = probeDoc.relationships.filter(
          (r) => !(r.spdxElementId === HARNESS_ADAPTER_SPDXID && r.relationshipType === 'DEPENDS_ON' && r.relatedSpdxElement === SDK_SPDXID),
        );
      },
    },
    {
      label: 'Harness Adapter DEPENDS_ON SDK retyped to DEV_TOOL_OF',
      reason: /missing dependency relationship: SPDXRef-harness-adapter DEPENDS_ON SPDXRef-adapter-sdk|must never be DEV_TOOL_OF/,
      mutate: (probeDoc) => {
        const rel = probeDoc.relationships.find(
          (r) => r.spdxElementId === HARNESS_ADAPTER_SPDXID && r.relationshipType === 'DEPENDS_ON' && r.relatedSpdxElement === SDK_SPDXID,
        );
        rel.relationshipType = 'DEV_TOOL_OF';
        rel.relatedSpdxElement = AIPT_SPDXID;
      },
    },
  ];
  for (const def of harnessPackageProbes) {
    const probeDoc = JSON.parse(JSON.stringify(doc));
    if (!probeDoc.packages.some((x) => x.SPDXID === HARNESS_ADAPTER_SPDXID)) {
      fail(`negative ${def.label} probe could not run: Harness Adapter package missing`);
      continue;
    }
    def.mutate(probeDoc);
    const probeResult = validateSbomSemantics(probeDoc, { repo: ctx.repo, toolchainLock, actionsLock });
    if (probeResult.result !== 'FAIL') fail(`negative ${def.label} probe was NOT rejected`);
    else if (!probeResult.details.filter((d) => d.startsWith('FAIL')).some((d) => def.reason.test(d))) {
      fail(`negative ${def.label} probe failed for an unexpected reason`);
    } else ok(`negative-probe PASS: ${def.label} rejected by the B005 first-party dependency model`);
  }

  // 20-30. Negative probes (AIPT-M0-B003 iteration 6a): the six Go runtime
  // module packages and the DEPENDS_ON dependency graph must be enforced —
  // each rejection must come from the package/relationship checks themselves,
  // not merely from the content-addressed namespace mismatch.
  const pgxSpdxId = goModuleSpdxId('github.com/jackc/pgx/v5');
  const goDepProbes = [
    {
      label: 'Go runtime module package deleted from the SBOM',
      reason: /Go runtime module package missing from SBOM: github.com\/jackc\/pgx\/v5|required package missing: github.com\/jackc\/pgx\/v5/,
      mutate: (probeDoc) => {
        probeDoc.packages = probeDoc.packages.filter((p) => p.SPDXID !== pgxSpdxId);
      },
    },
    {
      label: 'Go runtime module version drifted',
      reason: /versionInfo must be v5\.10\.0/,
      mutate: (probeDoc) => {
        probeDoc.packages.find((x) => x.SPDXID === pgxSpdxId).versionInfo = 'v5.9.0';
      },
    },
    {
      label: 'Go runtime module license drifted',
      reason: /github\.com\/jackc\/pgx\/v5: licenseConcluded|SPDXRef-GoModule-github-com-jackc-pgx-v5: licenseConcluded/,
      mutate: (probeDoc) => {
        const p = probeDoc.packages.find((x) => x.SPDXID === pgxSpdxId);
        p.licenseConcluded = 'Apache-2.0';
        p.licenseDeclared = 'Apache-2.0';
      },
    },
    {
      label: 'Go runtime module checksum drifted',
      reason: /SHA256 checksumValue must be the frozen lowercase hex/,
      mutate: (probeDoc) => {
        const p = probeDoc.packages.find((x) => x.SPDXID === pgxSpdxId);
        p.checksums = [{ algorithm: 'SHA256', checksumValue: '0'.repeat(64) }];
      },
    },
    {
      label: 'Go runtime module purl drifted',
      reason: /purl referenceLocator must be exactly pkg:golang\/github.com\/jackc\/pgx\/v5@v5\.10\.0/,
      mutate: (probeDoc) => {
        const p = probeDoc.packages.find((x) => x.SPDXID === pgxSpdxId);
        p.externalRefs = (p.externalRefs ?? []).filter((r) => r.referenceType !== 'purl');
      },
    },
    {
      label: 'AIPT DEPENDS_ON pgx relationship deleted',
      reason: /missing dependency relationship: SPDXRef-AIPT DEPENDS_ON SPDXRef-GoModule-github-com-jackc-pgx-v5/,
      mutate: (probeDoc) => {
        probeDoc.relationships = probeDoc.relationships.filter(
          (r) => !(r.spdxElementId === AIPT_SPDXID && r.relationshipType === 'DEPENDS_ON' && r.relatedSpdxElement === pgxSpdxId),
        );
      },
    },
    {
      label: 'AIPT DEPENDS_ON pgx relationship retyped to DEV_TOOL_OF',
      reason: /missing dependency relationship: SPDXRef-AIPT DEPENDS_ON SPDXRef-GoModule-github-com-jackc-pgx-v5|wrongly classified as DEV_TOOL_OF/,
      mutate: (probeDoc) => {
        const rel = probeDoc.relationships.find(
          (r) => r.spdxElementId === AIPT_SPDXID && r.relationshipType === 'DEPENDS_ON' && r.relatedSpdxElement === pgxSpdxId,
        );
        rel.relationshipType = 'DEV_TOOL_OF';
      },
    },
    {
      label: 'pgx DEPENDS_ON indirect module relationship deleted',
      reason: /missing dependency relationship: SPDXRef-GoModule-github-com-jackc-pgx-v5 DEPENDS_ON SPDXRef-GoModule-golang-org-x-text/,
      mutate: (probeDoc) => {
        probeDoc.relationships = probeDoc.relationships.filter(
          (r) => !(r.spdxElementId === pgxSpdxId && r.relationshipType === 'DEPENDS_ON' && r.relatedSpdxElement === goModuleSpdxId('golang.org/x/text')),
        );
      },
    },
    {
      label: 'Go runtime module direct/transitive role drifted in comment',
      reason: /comment must classify the module as direct/,
      mutate: (probeDoc) => {
        const p = probeDoc.packages.find((x) => x.SPDXID === pgxSpdxId);
        p.comment = p.comment.replace('(direct;', '(transitive;');
      },
    },
    {
      label: 'direct Go runtime module comment retyped to indirect (structured role token regression)',
      reason: /structured role token/,
      mutate: (probeDoc) => {
        const p = probeDoc.packages.find((x) => x.SPDXID === pgxSpdxId);
        p.comment = p.comment.replace('(direct;', '(indirect;');
      },
    },
    {
      label: 'transitive Go runtime module wrongly marked direct',
      reason: /comment must classify the module as transitive/,
      mutate: (probeDoc) => {
        const p = probeDoc.packages.find((x) => x.SPDXID === goModuleSpdxId('golang.org/x/text'));
        p.comment = p.comment.replace('(transitive;', '(direct;');
      },
    },
    {
      label: 'x/text vulnerable v0.29.0 package version rejected',
      reason: /golang\.org\/x\/text versionInfo must be v0\.39\.0/,
      mutate: (probeDoc) => {
        probeDoc.packages.find((x) => x.SPDXID === goModuleSpdxId('golang.org/x/text')).versionInfo = 'v0.29.0';
      },
    },
    {
      label: 'x/mod selected graph-tooling package deleted',
      reason: /Go selected module-graph tooling package missing from SBOM: golang\.org\/x\/mod|required package missing: golang\.org\/x\/mod/,
      mutate: (probeDoc) => {
        probeDoc.packages = probeDoc.packages.filter((p) => p.SPDXID !== goModuleSpdxId('golang.org/x/mod'));
      },
    },
    {
      label: 'x/tools selected graph-tooling checksum removed',
      reason: /x\/tools graph-tooling SHA256 checksumValue must be frozen sumdb h1 hex/,
      mutate: (probeDoc) => {
        probeDoc.packages.find((x) => x.SPDXID === goModuleSpdxId('golang.org/x/tools')).checksums = [];
      },
    },
    {
      label: 'x/text DEPENDS_ON x/mod selected graph edge deleted',
      reason: /missing selected-module relationship:.*x-text DEPENDS_ON.*x-mod/,
      mutate: (probeDoc) => {
        probeDoc.relationships = probeDoc.relationships.filter(
          (r) => !(
            r.spdxElementId === goModuleSpdxId('golang.org/x/text') &&
            r.relationshipType === 'DEPENDS_ON' &&
            r.relatedSpdxElement === goModuleSpdxId('golang.org/x/mod')
          ),
        );
      },
    },
    {
      label: 'x/mod BUILD_TOOL_OF role retyped to runtime dependency',
      reason: /missing graph-tooling relationship:.*x-mod BUILD_TOOL_OF/,
      mutate: (probeDoc) => {
        const rel = probeDoc.relationships.find(
          (r) => r.spdxElementId === goModuleSpdxId('golang.org/x/mod') && r.relationshipType === 'BUILD_TOOL_OF',
        );
        rel.relationshipType = 'RUNTIME_DEPENDENCY_OF';
      },
    },
  ];
  for (const def of goDepProbes) {
    const probeDoc = JSON.parse(JSON.stringify(doc));
    if (!probeDoc.packages.some((x) => x.SPDXID === pgxSpdxId)) {
      fail(`negative ${def.label} probe could not run: pgx Go runtime module package missing from generated SBOM`);
      continue;
    }
    def.mutate(probeDoc);
    const probeResult = validateSbomSemantics(probeDoc, { repo: ctx.repo, toolchainLock, actionsLock });
    if (probeResult.result !== 'FAIL') {
      fail(`negative ${def.label} probe was NOT rejected`);
    } else {
      const rightReason = probeResult.details.filter((d) => d.startsWith('FAIL')).some((d) => def.reason.test(d));
      if (!rightReason) fail(`negative ${def.label} probe failed for an unexpected reason (dependency package/graph check did not fire)`);
      else ok(`negative-probe PASS: ${def.label} rejected by the Go runtime module/graph checks`);
    }
  }

  // 31-37. Negative probes (AIPT-M0-B003 iteration 6a): the go.mod/go.sum
  // closure manifest checks themselves are probed in memory — a
  // replace/exclude/retract graph override (including a leading-whitespace
  // form), a seventh dependency hidden in a second require block (including
  // one hidden after a comment-paren `// )` line, which must not close the
  // block), a rogue single-line require with an ordinary trailing comment, a
  // missing /go.mod h1, and a tampered /go.mod h1 must each be rejected by
  // the independent manifest checks (the on-disk go.mod/go.sum are never
  // modified).
  const realGoMod = fs.readFileSync(path.join(ctx.repo, 'go.mod'), 'utf8');
  const realGoSum = fs.readFileSync(path.join(ctx.repo, 'go.sum'), 'utf8');
  const manifestProbes = [
    {
      label: 'go.mod x/text vulnerable v0.29.0',
      reason: /golang.org\/x\/text version must be v0\.39\.0/,
      run: () => goModClosureProblems(realGoMod.replace('golang.org/x/text v0.39.0', 'golang.org/x/text v0.29.0')),
    },
    {
      label: 'go.mod x/text below-fixed v0.38.0',
      reason: /golang.org\/x\/text version must be v0\.39\.0/,
      run: () => goModClosureProblems(realGoMod.replace('golang.org/x/text v0.39.0', 'golang.org/x/text v0.38.0')),
    },
    {
      label: 'go.mod x/text unapproved newer v0.40.0',
      reason: /golang.org\/x\/text version must be v0\.39\.0/,
      run: () => goModClosureProblems(realGoMod.replace('golang.org/x/text v0.39.0', 'golang.org/x/text v0.40.0')),
    },
    {
      label: 'go.sum x/text zip h1 removed',
      reason: /missing zip h1 for golang.org\/x\/text v0\.39\.0/,
      run: () => goSumH1Problems(realGoSum.replace(/^golang\.org\/x\/text v0\.39\.0 h1:[^\n]+\n/m, '')),
    },
    {
      label: 'go.mod replace directive injected (graph override)',
      reason: /replace\/exclude\/retract/,
      run: () => goModClosureProblems(`${realGoMod}\nreplace github.com/jackc/pgx/v5 => github.com/jackc/pgx/v5 v5.9.0\n`),
    },
    {
      label: 'seventh dependency hidden in a second require block',
      reason: /require count must be exactly 6|unknown go.mod dependency/,
      run: () => goModClosureProblems(`${realGoMod}\nrequire (\n\texample.com/rogue v1.0.0\n)\n`),
    },
    {
      label: 'seventh dependency hidden after a comment-paren "// )" line in a second require block',
      reason: /require count must be exactly 6|unknown go.mod dependency/,
      run: () => goModClosureProblems(`${realGoMod}\nrequire (\n\t// )\n\texample.com/rogue v1.0.0\n)\n`),
    },
    {
      label: 'rogue single-line require with an ordinary trailing comment',
      reason: /require count must be exactly 6|unknown go.mod dependency/,
      run: () => goModClosureProblems(`${realGoMod}\nrequire example.com/rogue v1.0.0 // ordinary comment\n`),
    },
    {
      label: 'go.mod replace directive with leading whitespace (graph override)',
      reason: /replace\/exclude\/retract/,
      run: () => goModClosureProblems(`${realGoMod}\n\treplace github.com/jackc/pgx/v5 => github.com/jackc/pgx/v5 v5.9.0\n`),
    },
    {
      label: 'go.sum pgx /go.mod h1 removed',
      reason: /missing \/go\.mod h1 for github.com\/jackc\/pgx\/v5 v5\.10\.0/,
      run: () => goSumH1Problems(realGoSum.replace(/^github\.com\/jackc\/pgx\/v5 v5\.10\.0\/go\.mod h1:[^\n]+\n/m, '')),
    },
    {
      label: 'go.sum pgx /go.mod h1 tampered',
      reason: /\/go\.mod h1 decodes to/,
      run: () => goSumH1Problems(realGoSum.replace('github.com/jackc/pgx/v5 v5.10.0/go.mod h1:mal1tBGAFfLHvZzaYh77YS/eC6IX9OWbRV1QIIM0Jn4=', 'github.com/jackc/pgx/v5 v5.10.0/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=')),
    },
  ];
  let manifestProbesOk = true;
  for (const probe of manifestProbes) {
    let problems;
    try {
      problems = probe.run();
    } catch (err) {
      fail(`negative go.mod/go.sum probe (${probe.label}) crashed: ${err.message}`);
      manifestProbesOk = false;
      continue;
    }
    if (!Array.isArray(problems) || problems.length === 0) {
      fail(`negative go.mod/go.sum probe (${probe.label}) was NOT rejected`);
      manifestProbesOk = false;
    } else if (!problems.some((p) => probe.reason.test(p))) {
      fail(`negative go.mod/go.sum probe (${probe.label}) failed for an unexpected reason`);
      manifestProbesOk = false;
    } else {
      ok(`negative-probe PASS: go.mod/go.sum manifest checks reject ${probe.label}`);
    }
  }
  if (manifestProbesOk) ok(`all ${manifestProbes.length} go.mod/go.sum manifest negative probes rejected as expected`);

  return { name: 'sbom', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'sbom', run);
