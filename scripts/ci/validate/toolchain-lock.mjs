// B001 exact-toolchain lock validator, evolved by AIPT-M0-B003-SCOPE-
// EXPANSION-001 for iteration 6a.
//
// The candidate must freeze, in tools/toolchain.lock.json and the repo pins,
// exactly: Go 1.26.5, Node.js 24.19.0 LTS, pnpm 11.4.0, PostgreSQL 18.4, plus
// the pinned Go vulnerability tooling (govulncheck). All integrity material
// must match the values qualified from official sources.
//
// AIPT-M0-B003 iteration 6a evolution: the historical B001 bootstrap rule
// "go.mod must declare no third-party runtime dependency (no require
// directives)" is REPLACED by the fail-closed validation of the exact
// approved B003 Go runtime closure — the direct github.com/jackc/pgx/v5
// v5.10.0 module plus exactly five pinned indirect modules, no additional
// direct or indirect module, no replace/exclude/retract dependency-graph
// override, and exact go.sum zip + /go.mod h1 coverage/pins for all six
// modules. Every B001 toolchain pin, the historical
// selected_by_batch=AIPT-M0-B001 fact (SUPPLY_CHAIN_BASELINE_BATCH stays
// AIPT-M0-B001), and the zero-pnpm-dependency policy are preserved unchanged.
//
// The gate runs meaningful in-memory regressions: PASS for the exact closure
// and the exact lock, and FAIL for pgx missing, wrong version, extra direct
// dependency, a seventh dependency hidden in a second require block (including
// one hidden after a comment-paren `// )` line, which must not close the
// block), a rogue single-line require with an ordinary trailing comment,
// graph override (replace, including a leading-whitespace form), go.mod module
// path rewritten behind a misleading comment, a second module directive with a
// different path, a second/different go directive, a second/different toolchain
// directive, Go/toolchain version drift, PostgreSQL digest drift,
// SUPPLY_CHAIN_BASELINE_BATCH drift to B003, toolchain.lock selected_by_batch
// drift to B003, and peer/bundled dependency declarations in package.json.
import fs from 'node:fs';
import path from 'node:path';
import {
  GO_LINUX_AMD64_SHA256,
  GOVULNCHECK,
  NODE_LINUX_X64_SHA256,
  PG_LINUX_AMD64_PLATFORM_DIGEST,
  PG_MULTI_ARCH_DIGEST,
  PNPM_REGISTRY_INTEGRITY,
  SUPPLY_CHAIN_BASELINE_BATCH,
  TOOLCHAIN,
} from '../lib/constants.mjs';
import { runAsMain } from '../lib/cli.mjs';

// The exact approved pgx v5.10.0 Go runtime closure (AIPT-M0-B003 iteration
// 6a). h1hex is the frozen SHA-256 (64 lowercase hex) that the go.sum zip
// `h1:` base64 payload must decode to; gomodhex is the frozen SHA-256 that the
// `<module> <version>/go.mod h1:` base64 payload must decode to. The go.sum
// values are derived and compared, so a tampered-but-still-base64 h1 cannot
// pass.
const GO_RUNTIME_MODULES = [
  { module: 'github.com/jackc/pgx/v5', version: 'v5.10.0', direct: true, h1hex: '5614af814da34a58bca3702a20439326beeb670004515a381385e147de197ebd', gomodhex: '99a975b4118015f2c7bd9cda621efb612fde0ba217f4e59b455d50208334267e' },
  { module: 'github.com/jackc/pgpassfile', version: 'v1.0.0', direct: false, h1hex: 'ffa1e6ab2d774acdb30aaeb655d346f2d335c1c867f338d218e049ea2729b083', gomodhex: '084c74892e5a99b34575c46dc4f8f9261133fb107ab91932e5ec95bbf5b61c48' },
  { module: 'github.com/jackc/pgservicefile', version: 'v0.0.0-20240606120523-5a60cdf6a761', direct: false, h1hex: '882127a287bb525c0e418a4a16105a6cf322e1a3407e83833c414d8809c2971a', gomodhex: 'e5325958a1169e23ef7b7def956612a0661e7e7de02d04738df0e585227d64a3' },
  { module: 'github.com/jackc/puddle/v2', version: 'v2.2.2', direct: false, h1hex: '3d1f27c3e13fd70d062ee4454a68a2a18e94a28329e8a26fd3feb59c1ee2707a', gomodhex: 'beb8a21171ef104eb9e1a60a5d78cebd9337f6a274abe6b391916b7c439cdc7e' },
  { module: 'golang.org/x/sync', version: 'v0.17.0', direct: false, h1hex: '97ad2738d323f65e5daeac3a8e584810b36ff48d00e0e16046c1bd936a13f548', gomodhex: 'f4a4c75e64a7a06aee2e9c058d5497d2534d03be42ca488c1026e8bcd4d9a862' },
  { module: 'golang.org/x/text', version: 'v0.29.0', direct: false, h1hex: 'd6778db3dd30f58cc9f41a1cc5fb103472ae013e299208725dce27859eac26f9', gomodhex: 'ecc849380f420f6a99c8e2986b3c5d60c17ce4ec0f744afd8d3b41a4eef2747e' },
];

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
//   - go.mod must carry NO dependency-graph override directive (replace,
//     exclude, retract) — a graph override would let the candidate
//     re-route/ignore the approved closure;
//   - go.sum must carry BOTH the zip `h1:` and the `/go.mod h1:` line for
//     every one of the six modules, and every base64 payload must decode to
//     32 bytes whose lowercase hex equals the pinned h1 SHA-256 values — so
//     a tampered (but still base64-valid) h1 cannot pass.
// Pure over the supplied texts: in-memory regressions mutate copies and the
// on-disk files are never modified.
function checkGoClosure({ goMod, goSum }) {
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
  // retract block or line re-routes or hides modules of the approved closure
  // and is never accepted, even when the require set itself is exact. Both
  // single-line and block forms with optional leading whitespace are detected.
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

// Pure machine check of tools/toolchain.lock.json against the frozen B001
// toolchain qualification: selected_by_batch must be the historical
// SUPPLY_CHAIN_BASELINE_BATCH (AIPT-M0-B001 — never rewritten to B003), the
// exact Go 1.26.5 / Node 24.19.0 LTS / pnpm 11.4.0 / PostgreSQL 18.4 versions
// with channels and source/CI verification records, the official archive and
// registry integrity values, the exact PostgreSQL Docker Official Image
// multi-arch and linux/amd64 platform digests, and the govulncheck v1.7.0
// module/source identity.
function checkToolchainObject(lock, baseline = SUPPLY_CHAIN_BASELINE_BATCH) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };

  if (lock.selected_by_batch !== baseline) {
    fail(`selected_by_batch must be ${baseline}: ${JSON.stringify(lock.selected_by_batch)}`);
  } else ok(`selected_by_batch = ${baseline}`);

  const tc = lock.toolchains ?? {};
  const expect = (section, version, channel) => {
    if (tc[section]?.version !== version) fail(`${section} version must be ${version}: ${JSON.stringify(tc[section]?.version)}`);
    else ok(`${section} = ${version}`);
    if (channel && tc[section]?.channel !== channel) fail(`${section} channel must be ${channel}: ${JSON.stringify(tc[section]?.channel)}`);
    if (!tc[section]?.source_verification?.verified_at) fail(`${section} missing source/release verification time`);
    else ok(`${section} source verification recorded (${tc[section].source_verification.verified_at})`);
    if (!tc[section]?.expected_version_output) fail(`${section} missing CI expected version output`);
    else ok(`${section} CI expected version output recorded`);
  };
  expect('go', TOOLCHAIN.go, 'stable');
  expect('node', TOOLCHAIN.node, 'LTS');
  expect('pnpm', TOOLCHAIN.pnpm, 'stable');
  expect('postgresql', TOOLCHAIN.postgresql, 'stable');

  if (tc.go?.linux_amd64_archive?.sha256 !== GO_LINUX_AMD64_SHA256) {
    fail(`go linux/amd64 archive sha256 must match official value (${GO_LINUX_AMD64_SHA256})`);
  } else ok('go linux/amd64 archive sha256 == official go.dev value');

  if (tc.node?.linux_x64_archive?.sha256 !== NODE_LINUX_X64_SHA256) {
    fail('node linux-x64 archive sha256 must match official SHASUMS256.txt value');
  } else ok('node linux-x64 sha256 == official SHASUMS256.txt value');
  if (tc.node?.release_codename !== 'Krypton') fail('node LTS codename must be Krypton');
  else ok('node LTS codename Krypton recorded');

  if (tc.pnpm?.registry?.integrity_sha512 !== PNPM_REGISTRY_INTEGRITY.replace(/^sha512-/, '')) {
    fail('pnpm registry integrity must match the qualified registry value');
  } else ok('pnpm registry integrity recorded (sha512)');
  if (tc.pnpm?.git_release?.tag !== 'v11.4.0' || !/^[0-9a-f]{40}$/.test(tc.pnpm?.git_release?.commit ?? '')) {
    fail('pnpm upstream git release tag/commit must be recorded');
  } else ok('pnpm upstream git tag v11.4.0 -> commit recorded');

  const pg = tc.postgresql?.docker_official_image;
  if (pg?.multi_arch_digest !== PG_MULTI_ARCH_DIGEST) {
    fail(`postgresql multi-arch digest must equal ${PG_MULTI_ARCH_DIGEST}`);
  } else ok('postgresql Docker Official Image multi-arch digest recorded');
  if (pg?.linux_amd64_platform_digest !== PG_LINUX_AMD64_PLATFORM_DIGEST) {
    fail(`postgresql linux/amd64 platform digest must equal ${PG_LINUX_AMD64_PLATFORM_DIGEST}`);
  } else ok('postgresql linux/amd64 platform digest recorded');

  const gv = lock.tooling?.govulncheck;
  if (gv?.version !== GOVULNCHECK.version) fail(`govulncheck tooling version must be ${GOVULNCHECK.version}`);
  else ok(`govulncheck tooling pinned at ${GOVULNCHECK.version}`);
  if (gv?.module !== GOVULNCHECK.module) fail('govulncheck module identity must be golang.org/x/vuln');
  if (gv?.source_commit !== GOVULNCHECK.source_commit) fail('govulncheck source commit must be recorded');
  if (!gv?.install_command?.includes(`@${GOVULNCHECK.version}`)) fail('govulncheck install command must pin the exact version');
  else ok('govulncheck install command pins the exact version');
  if (!gv?.purpose?.includes('fresh')) fail('tooling record must state advisory data is fetched fresh (not pinned)');
  else ok('advisory data freshness rule documented (no stale-DB bypass)');

  return { result: pass ? 'PASS' : 'FAIL', details };
}

// Pure machine check of the repo pin files against the frozen toolchain:
// .go-version / .node-version contents, the go.mod module/go/toolchain
// directives plus the exact approved Go runtime closure (delegated to
// checkGoClosure), the package.json packageManager/Node engine range/private/
// zero-dependency facts, and the pnpm-lock lockfileVersion / zero third-party
// packages section (zero-pnpm-dependency policy preserved from B001).
function checkRepoPins({ goVersion, nodeVersion, goMod, goSum, pkgJson, pnpmLockText }) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };

  if (goVersion !== TOOLCHAIN.go) fail(`.go-version must be ${TOOLCHAIN.go}`);
  else ok(`.go-version = ${TOOLCHAIN.go}`);
  if (nodeVersion !== TOOLCHAIN.node) fail(`.node-version must be ${TOOLCHAIN.node}`);
  else ok(`.node-version = ${TOOLCHAIN.node}`);

  // go.mod must carry EXACTLY ONE `module` directive, and it must be exactly
  // `module github.com/zyc14588/AIPT`. EVERY anchored module directive line is
  // collected and counted regardless of its path, so a second/different module
  // directive (or a rewritten path hidden behind a misleading comment, or a
  // removed directive) is rejected — a substring match on the expected path
  // alone would silently accept those drifts.
  const moduleDirectives = (goMod.match(/^[ \t]*module\b[^\n]*$/gm) ?? []).map((line) => line.trim());
  if (moduleDirectives.length !== 1 || moduleDirectives[0] !== 'module github.com/zyc14588/AIPT') {
    fail(`go.mod must carry exactly one module directive for github.com/zyc14588/AIPT, got ${moduleDirectives.length}: ${moduleDirectives.join(' | ') || 'none'}`);
  } else ok('go.mod module path correct (exactly one anchored module directive)');
  // go.mod must carry EXACTLY ONE anchored `go` directive, and its value must
  // be 1.26.x. EVERY anchored go directive line is collected and counted
  // regardless of its value, so a second/different go directive (or a removed
  // one) is rejected — a substring match on a single matching line would
  // silently accept those drifts.
  const goDirectives = (goMod.match(/^[ \t]*go\b[^\n]*$/gm) ?? []).map((line) => line.trim());
  if (goDirectives.length !== 1) {
    fail(`go.mod must carry exactly one anchored go directive, got ${goDirectives.length}: ${goDirectives.join(' | ') || 'none'}`);
  } else if (!/^go 1\.26(\.\d+)?$/.test(goDirectives[0])) {
    fail(`go.mod go directive must pin 1.26.x, got ${JSON.stringify(goDirectives[0])}`);
  } else {
    ok('go.mod pins the go directive to 1.26.x (exactly one anchored go directive)');
  }
  // go.mod must carry EXACTLY ONE anchored `toolchain` directive, and it must
  // be exactly `toolchain go1.26.5`. EVERY anchored toolchain directive line
  // is collected and counted regardless of its value, so a second/different
  // toolchain directive (or a removed one) is rejected.
  const toolchainDirectives = (goMod.match(/^[ \t]*toolchain\b[^\n]*$/gm) ?? []).map((line) => line.trim());
  if (toolchainDirectives.length !== 1) {
    fail(`go.mod must carry exactly one anchored toolchain directive, got ${toolchainDirectives.length}: ${toolchainDirectives.join(' | ') || 'none'}`);
  } else if (toolchainDirectives[0] !== 'toolchain go1.26.5') {
    fail(`go.mod toolchain directive must be exactly "toolchain go1.26.5", got ${JSON.stringify(toolchainDirectives[0])}`);
  } else {
    ok('go.mod pins toolchain go1.26.5 (exactly one anchored toolchain directive)');
  }
  const closure = checkGoClosure({ goMod, goSum });
  details.push(...closure.details);
  if (closure.result !== 'PASS') fail('go.mod/go.sum do not carry the exact approved pgx v5.10.0 runtime closure');
  else ok('go.mod/go.sum carry exactly the approved pgx v5.10.0 runtime closure (six modules, no graph override, exact zip + /go.mod h1 pins)');

  if (pkgJson.packageManager !== `pnpm@${TOOLCHAIN.pnpm}`) fail(`package.json packageManager must be pnpm@${TOOLCHAIN.pnpm}`);
  else ok('package.json packageManager = pnpm@11.4.0');
  if (pkgJson.engines?.node !== '>=24.19.0 <25') fail('package.json engines.node must declare the Node 24 LTS range (>=24.19.0 <25)');
  else ok('package.json declares the Node 24 LTS range');
  if (pkgJson.private !== true) fail('package.json must be private');
  else ok('package.json private');
  // Zero-pnpm-dependency policy (preserved from B001): no runtime, development,
  // peer, or bundled package dependency may be declared — dependencies,
  // devDependencies, optionalDependencies, peerDependencies,
  // bundledDependencies, and bundleDependencies are all rejected.
  const zeroDepFields = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies', 'bundledDependencies', 'bundleDependencies'];
  const declaredDeps = zeroDepFields.filter((f) => pkgJson[f]);
  if (declaredDeps.length > 0) {
    fail(`package.json must carry no runtime/development/peer/bundled package dependency declarations (zero-pnpm-dependency policy): ${declaredDeps.join(', ')}`);
  } else ok('package.json has no runtime/development/peer/bundled dependency declarations');

  if (!pnpmLockText.includes('lockfileVersion')) fail('pnpm-lock.yaml must be present with a lockfileVersion');
  else ok('pnpm-lock.yaml present with lockfileVersion');
  if (/^packages:\s*$/m.test(pnpmLockText)) fail('pnpm-lock.yaml must contain no third-party packages section (zero runtime deps)');
  else ok('pnpm-lock.yaml records zero third-party packages');

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

  let lock;
  try {
    lock = JSON.parse(read('tools/toolchain.lock.json'));
  } catch (err) {
    fail(`tools/toolchain.lock.json unparseable: ${err.message}`);
    return { name: 'toolchain-lock', result: 'FAIL', details };
  }

  const toolchainCheck = checkToolchainObject(lock);
  details.push(...toolchainCheck.details);
  if (toolchainCheck.result !== 'PASS') fail('tools/toolchain.lock.json does not match the frozen B001 toolchain qualification');
  else ok('tools/toolchain.lock.json matches the frozen B001 toolchain qualification (versions, archives, digests, govulncheck identity, B001 selection)');

  const repoPins = checkRepoPins({
    goVersion: read('.go-version').trim(),
    nodeVersion: read('.node-version').trim(),
    goMod: read('go.mod'),
    goSum: read('go.sum'),
    pkgJson: JSON.parse(read('package.json')),
    pnpmLockText: read('pnpm-lock.yaml'),
  });
  details.push(...repoPins.details);
  if (repoPins.result !== 'PASS') fail('repo pin files do not match the frozen toolchain / approved B003 closure');
  else ok('repo pin files match the frozen toolchain and the approved B003 pgx v5.10.0 closure');

  // ---- in-memory regressions ----
  // Every regression runs pure functions over in-memory copies of the real
  // inputs; the on-disk lock/manifest files are never modified. PASS for the
  // exact closure/lock, FAIL for every enumerated drift case.
  const goModText = read('go.mod');
  const goSumText = read('go.sum');
  const mutatedLock = (mutate) => {
    const copy = JSON.parse(JSON.stringify(lock));
    mutate(copy);
    return copy;
  };
  const regressions = [
    {
      label: 'exact pgx v5.10.0 closure PASS',
      expect: 'PASS',
      reason: null,
      run: () => checkGoClosure({ goMod: goModText, goSum: goSumText }),
    },
    {
      label: 'pgx direct module missing from go.mod FAIL',
      expect: 'FAIL',
      reason: /go\.mod missing required module github\.com\/jackc\/pgx\/v5/,
      run: () => checkGoClosure({
        goMod: goModText.replace('require github.com/jackc/pgx/v5 v5.10.0\n\n', ''),
        goSum: goSumText,
      }),
    },
    {
      label: 'pgx version drifted in go.mod FAIL',
      expect: 'FAIL',
      reason: /github\.com\/jackc\/pgx\/v5 version must be v5\.10\.0/,
      run: () => checkGoClosure({
        goMod: goModText.replace('github.com/jackc/pgx/v5 v5.10.0', 'github.com/jackc/pgx/v5 v5.9.0'),
        goSum: goSumText,
      }),
    },
    {
      label: 'extra direct dependency injected into go.mod FAIL',
      expect: 'FAIL',
      reason: /unknown go\.mod dependency/,
      run: () => checkGoClosure({
        goMod: `${goModText}\nrequire example.com/rogue v1.0.0\n`,
        goSum: goSumText,
      }),
    },
    {
      label: 'graph override: replace directive injected into go.mod FAIL',
      expect: 'FAIL',
      reason: /replace\/exclude\/retract/,
      run: () => checkGoClosure({
        goMod: `${goModText}\nreplace github.com/jackc/pgx/v5 => github.com/jackc/pgx/v5 v5.9.0\n`,
        goSum: goSumText,
      }),
    },
    {
      label: 'go.sum pgx zip h1 tampered FAIL',
      expect: 'FAIL',
      reason: /zip h1 decodes to/,
      run: () => checkGoClosure({
        goMod: goModText,
        goSum: goSumText.replace('github.com/jackc/pgx/v5 v5.10.0 h1:VhSvgU2jSli8o3AqIEOTJr7rZwAEUVo4E4XhR94Zfr0=', 'github.com/jackc/pgx/v5 v5.10.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
      }),
    },
    {
      label: 'go.sum pgx /go.mod h1 removed FAIL',
      expect: 'FAIL',
      reason: /missing \/go\.mod h1/,
      run: () => checkGoClosure({
        goMod: goModText,
        goSum: goSumText.replace(/^github\.com\/jackc\/pgx\/v5 v5\.10\.0\/go\.mod h1:[^\n]+\n/m, ''),
      }),
    },
    {
      label: 'go.sum pgx /go.mod h1 tampered FAIL',
      expect: 'FAIL',
      reason: /\/go\.mod h1 decodes to/,
      run: () => checkGoClosure({
        goMod: goModText,
        goSum: goSumText.replace('github.com/jackc/pgx/v5 v5.10.0/go.mod h1:mal1tBGAFfLHvZzaYh77YS/eC6IX9OWbRV1QIIM0Jn4=', 'github.com/jackc/pgx/v5 v5.10.0/go.mod h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='),
      }),
    },
    {
      label: 'Go/toolchain version drift in toolchain.lock.json FAIL',
      expect: 'FAIL',
      reason: /go version must be 1\.26\.5/,
      run: () => checkToolchainObject(mutatedLock((copy) => { copy.toolchains.go.version = '1.26.6'; })),
    },
    {
      label: 'PostgreSQL multi-arch digest drift in toolchain.lock.json FAIL',
      expect: 'FAIL',
      reason: /postgresql multi-arch digest must equal/,
      run: () => checkToolchainObject(mutatedLock((copy) => {
        copy.toolchains.postgresql.docker_official_image.multi_arch_digest = `${PG_MULTI_ARCH_DIGEST.slice(0, -1)}7`;
      })),
    },
    {
      label: 'SUPPLY_CHAIN_BASELINE_BATCH drift to B003 FAIL (historical B001 baseline selector is load-bearing)',
      expect: 'FAIL',
      reason: /selected_by_batch must be AIPT-M0-B003/,
      run: () => checkToolchainObject(lock, 'AIPT-M0-B003'),
    },
    {
      label: 'toolchain.lock selected_by_batch drift to AIPT-M0-B003 FAIL',
      expect: 'FAIL',
      reason: /selected_by_batch must be AIPT-M0-B001/,
      run: () => checkToolchainObject(mutatedLock((copy) => { copy.selected_by_batch = 'AIPT-M0-B003'; })),
    },
    {
      label: 'seventh dependency hidden in a second require block FAIL',
      expect: 'FAIL',
      reason: /require count must be exactly 6|unknown go\.mod dependency/,
      run: () => checkGoClosure({
        goMod: `${goModText}\nrequire (\n\texample.com/rogue v1.0.0\n)\n`,
        goSum: goSumText,
      }),
    },
    {
      label: 'seventh dependency hidden after a comment-paren "// )" line in a second require block FAIL',
      expect: 'FAIL',
      reason: /require count must be exactly 6|unknown go\.mod dependency/,
      run: () => checkGoClosure({
        goMod: `${goModText}\nrequire (\n\t// )\n\texample.com/rogue v1.0.0\n)\n`,
        goSum: goSumText,
      }),
    },
    {
      label: 'rogue single-line require with an ordinary trailing comment FAIL',
      expect: 'FAIL',
      reason: /require count must be exactly 6|unknown go\.mod dependency/,
      run: () => checkGoClosure({
        goMod: `${goModText}\nrequire example.com/rogue v1.0.0 // ordinary comment\n`,
        goSum: goSumText,
      }),
    },
    {
      label: 'replace graph override with leading whitespace FAIL',
      expect: 'FAIL',
      reason: /replace\/exclude\/retract/,
      run: () => checkGoClosure({
        goMod: `${goModText}\n\treplace github.com/jackc/pgx/v5 => github.com/jackc/pgx/v5 v5.9.0\n`,
        goSum: goSumText,
      }),
    },
    {
      label: 'go.mod module path rewritten with misleading comment FAIL',
      expect: 'FAIL',
      reason: /exactly one module directive/,
      run: () => checkRepoPins({
        goVersion: read('.go-version').trim(),
        nodeVersion: read('.node-version').trim(),
        goMod: goModText.replace('module github.com/zyc14588/AIPT', 'module example.com/other // github.com/zyc14588/AIPT'),
        goSum: goSumText,
        pkgJson: JSON.parse(read('package.json')),
        pnpmLockText: read('pnpm-lock.yaml'),
      }),
    },
    {
      label: 'second module directive with a different path FAIL',
      expect: 'FAIL',
      reason: /exactly one module directive/,
      run: () => checkRepoPins({
        goVersion: read('.go-version').trim(),
        nodeVersion: read('.node-version').trim(),
        goMod: `${goModText}\nmodule example.com/other\n`,
        goSum: goSumText,
        pkgJson: JSON.parse(read('package.json')),
        pnpmLockText: read('pnpm-lock.yaml'),
      }),
    },
    {
      label: 'second/different go directive injected into go.mod FAIL',
      expect: 'FAIL',
      reason: /exactly one anchored go directive/,
      run: () => checkRepoPins({
        goVersion: read('.go-version').trim(),
        nodeVersion: read('.node-version').trim(),
        goMod: `${goModText}\ngo 1.27.0\n`,
        goSum: goSumText,
        pkgJson: JSON.parse(read('package.json')),
        pnpmLockText: read('pnpm-lock.yaml'),
      }),
    },
    {
      label: 'second/different toolchain directive injected into go.mod FAIL',
      expect: 'FAIL',
      reason: /exactly one anchored toolchain directive/,
      run: () => checkRepoPins({
        goVersion: read('.go-version').trim(),
        nodeVersion: read('.node-version').trim(),
        goMod: `${goModText}\ntoolchain go1.26.6\n`,
        goSum: goSumText,
        pkgJson: JSON.parse(read('package.json')),
        pnpmLockText: read('pnpm-lock.yaml'),
      }),
    },
    {
      label: 'package.json peerDependencies declared FAIL',
      expect: 'FAIL',
      reason: /peerDependencies/,
      run: () => checkRepoPins({
        goVersion: read('.go-version').trim(),
        nodeVersion: read('.node-version').trim(),
        goMod: goModText,
        goSum: goSumText,
        pkgJson: { ...JSON.parse(read('package.json')), peerDependencies: { 'is-odd': '^3.0.0' } },
        pnpmLockText: read('pnpm-lock.yaml'),
      }),
    },
    {
      label: 'package.json bundledDependencies declared FAIL',
      expect: 'FAIL',
      reason: /bundledDependencies/,
      run: () => checkRepoPins({
        goVersion: read('.go-version').trim(),
        nodeVersion: read('.node-version').trim(),
        goMod: goModText,
        goSum: goSumText,
        pkgJson: { ...JSON.parse(read('package.json')), bundledDependencies: ['is-odd'] },
        pnpmLockText: read('pnpm-lock.yaml'),
      }),
    },
    {
      label: 'package.json bundleDependencies declared FAIL',
      expect: 'FAIL',
      reason: /bundleDependencies/,
      run: () => checkRepoPins({
        goVersion: read('.go-version').trim(),
        nodeVersion: read('.node-version').trim(),
        goMod: goModText,
        goSum: goSumText,
        pkgJson: { ...JSON.parse(read('package.json')), bundleDependencies: ['is-odd'] },
        pnpmLockText: read('pnpm-lock.yaml'),
      }),
    },
  ];
  let regressionsOk = true;
  for (const reg of regressions) {
    let result;
    try {
      result = reg.run();
    } catch (err) {
      fail(`in-memory regression (${reg.label}) crashed: ${err.message}`);
      regressionsOk = false;
      continue;
    }
    if (reg.expect === 'PASS') {
      if (result.result !== 'PASS') {
        fail(`in-memory regression (${reg.label}) unexpectedly FAILED`);
        regressionsOk = false;
      } else ok(`in-memory regression PASS: ${reg.label}`);
      continue;
    }
    if (result.result !== 'FAIL') {
      fail(`in-memory regression (${reg.label}) was NOT rejected`);
      regressionsOk = false;
    } else {
      const rightReason = result.details.filter((d) => d.startsWith('FAIL')).some((d) => reg.reason.test(d));
      if (!rightReason) fail(`in-memory regression (${reg.label}) failed for an unexpected reason`);
      else ok(`in-memory regression PASS: ${reg.label} rejected`);
    }
  }
  if (regressionsOk) ok(`all ${regressions.length} in-memory toolchain regressions behaved as expected (1 PASS closure + ${regressions.filter((r) => r.expect === 'FAIL').length} FAIL drifts)`);

  return { name: 'toolchain-lock', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'toolchain-lock', run);
