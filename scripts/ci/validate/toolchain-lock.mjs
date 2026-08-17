// B001 exact-toolchain lock validator.
//
// The candidate must freeze, in tools/toolchain.lock.json and the repo pins,
// exactly: Go 1.26.5, Node.js 24.19.0 LTS, pnpm 11.4.0, PostgreSQL 18.4, plus
// the pinned Go vulnerability tooling (govulncheck). All integrity material
// must match the values qualified from official sources.
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
  if (lock.selected_by_batch !== SUPPLY_CHAIN_BASELINE_BATCH) {
    fail(`selected_by_batch must be ${SUPPLY_CHAIN_BASELINE_BATCH}: ${JSON.stringify(lock.selected_by_batch)}`);
  } else ok('selected_by_batch = AIPT-M0-B001');

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

  // Repo pins.
  if (read('.go-version').trim() !== TOOLCHAIN.go) fail(`.go-version must be ${TOOLCHAIN.go}`);
  else ok(`.go-version = ${TOOLCHAIN.go}`);
  if (read('.node-version').trim() !== TOOLCHAIN.node) fail(`.node-version must be ${TOOLCHAIN.node}`);
  else ok(`.node-version = ${TOOLCHAIN.node}`);

  const goMod = read('go.mod');
  if (!goMod.includes('module github.com/zyc14588/AIPT')) fail('go.mod module path must be github.com/zyc14588/AIPT');
  else ok('go.mod module path correct');
  if (!/^go 1\.26(\.\d+)?\s*$/m.test(goMod)) fail('go.mod must pin the go directive to 1.26.x');
  else ok('go.mod pins the go directive to 1.26.x');
  if (!/^toolchain go1\.26\.5\s*$/m.test(goMod)) fail('go.mod must pin toolchain go1.26.5');
  else ok('go.mod pins toolchain go1.26.5');
  if (/^require\b/m.test(goMod)) fail('go.mod must declare no third-party runtime dependency (no require directives)');
  else ok('go.mod declares zero runtime dependencies');

  const pkg = JSON.parse(read('package.json'));
  if (pkg.packageManager !== `pnpm@${TOOLCHAIN.pnpm}`) fail(`package.json packageManager must be pnpm@${TOOLCHAIN.pnpm}`);
  else ok('package.json packageManager = pnpm@11.4.0');
  if (pkg.engines?.node !== '>=24.19.0 <25') fail('package.json engines.node must declare the Node 24 LTS range (>=24.19.0 <25)');
  else ok('package.json declares the Node 24 LTS range');
  if (pkg.private !== true) fail('package.json must be private');
  else ok('package.json private');
  if (pkg.dependencies || pkg.devDependencies || pkg.optionalDependencies) {
    fail('package.json must carry no runtime/development package dependencies at B001');
  } else ok('package.json has no runtime/development dependencies');

  const lockText = read('pnpm-lock.yaml');
  if (!lockText.includes('lockfileVersion')) fail('pnpm-lock.yaml must be present with a lockfileVersion');
  else ok('pnpm-lock.yaml present with lockfileVersion');
  if (/^packages:\s*$/m.test(lockText)) fail('pnpm-lock.yaml must contain no third-party packages section (zero runtime deps)');
  else ok('pnpm-lock.yaml records zero third-party packages');

  return { name: 'toolchain-lock', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'toolchain-lock', run);
