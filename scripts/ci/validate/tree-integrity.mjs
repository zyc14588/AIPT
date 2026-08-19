// B003 tree-integrity validator: self-anchored scope (accepted base identity
// plus the registered B003 per-iteration allowed set), Markdown links, JSON
// parse, and secret / private-path / prompt-body hygiene for the candidate
// tree (including the executable scripts/ci sources themselves), plus a
// temporary-fixture regression proving the hygiene scan really covers .mjs
// files under a scripts/ci-shaped path.
//
// Markdown rules for B003: no brittle fixed total document count (later
// approved documents of the accepted base must not be rejected by a count) —
// instead every Markdown document of the accepted base must still be present
// and every current relative link must resolve.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  ALLOWED_PATHS,
  BASE_COMMIT,
  BASE_TREE,
  EXPECTED_MIT_LICENSE,
  FORBIDDEN_PREFIXES,
  FROZEN_REGISTRY_PATHS,
  normalizeText,
  pathMatchesAllowed,
} from '../lib/constants.mjs';
import { collectMarkdownLinkIssues, scanTreeForHazards, walkFiles } from '../lib/scan.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

// Independent literal self-anchors for the B003 per-iteration scope: the
// exact ordered 20-path B003 allowlist and the exact ordered 18-entry
// forbidden-prefix list, hard-coded here and compared against the imported
// constants BEFORE any candidate scope is evaluated. Drifting constants.mjs
// together with the candidate can therefore never make a scope change pass
// silently.
const ALLOWED_PATHS_LITERAL = [
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/storage/**',
  'package.json',
  'go.mod',
  'go.sum',
  'internal/storage/postgres/**',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
  'scripts/ci/validate/workflow.mjs',
  'scripts/ci/validate/storage.mjs',
  'scripts/ci/validate/supply-chain.mjs',
  'scripts/ci/validate/sbom.mjs',
  'scripts/ci/sbom/generate-sbom.mjs',
  'tools/supply-chain/licenses.json',
  'docs/supply-chain/README.md',
  '.github/workflows/ci.yml',
];

const FORBIDDEN_PREFIXES_LITERAL = [
  'api/',
  'cmd/',
  'migrations/',
  'deploy/',
  'runtime/',
  'packages/',
  'schemas/protocol/',
  'testdata/protocol/',
  'docs/architecture/',
  'docs/integration/',
  'docs/test-model/',
  'docs/security/',
  'docs/evidence/',
  'internal/protocol/',
  'LICENSE',
  'tools/supply-chain/policy.json',
  'tools/toolchain.lock.json',
  'tools/ci-actions.lock.json',
];

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };

  // ---- independent literal self-anchors (before candidate scope) ----
  // Every identity the candidate scope depends on is hard-coded in this gate
  // and compared against the imported constants BEFORE any Git/history or
  // candidate-scope validation runs. Drifting constants.mjs together with the
  // candidate can therefore never make the accepted base or the registered
  // scope change pass silently: each imported field/list must equal its fixed
  // literal (ordered equality for the scope lists).
  const verifyAnchor = (label, actual, expected) => {
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      fail(`${label} drifted from its independent literal self-anchor: ${JSON.stringify(actual)} != ${JSON.stringify(expected)}`);
      return false;
    }
    ok(`${label} anchored to literal ${JSON.stringify(expected)}`);
    return true;
  };
  verifyAnchor('BASE_COMMIT', BASE_COMMIT, '45a96087d75a61f2910cb5ce99134e3ca777bca8');
  verifyAnchor('BASE_TREE', BASE_TREE, '8b16b599c261879406f0435e80c878e092683a50');
  verifyAnchor('ALLOWED_PATHS', ALLOWED_PATHS, ALLOWED_PATHS_LITERAL);
  verifyAnchor('FORBIDDEN_PREFIXES', FORBIDDEN_PREFIXES, FORBIDDEN_PREFIXES_LITERAL);

  // ---- accepted base identity: resolves, fixed tree, ancestor of HEAD ----
  const resolveCommit = (label, commit) => {
    const probe = git(ctx.repo, ['rev-parse', `${commit}^{commit}`], { check: false });
    const resolved = probe.stdout.trim();
    if (probe.status !== 0 || resolved !== commit) {
      fail(`${label} does not resolve to fixed commit ${commit}: ${JSON.stringify(resolved)}`);
      return false;
    }
    ok(`${label} resolves to fixed commit ${commit}`);
    return true;
  };
  const verifyTree = (label, commit, expectedTree) => {
    const probe = git(ctx.repo, ['rev-parse', `${commit}^{tree}`], { check: false });
    const resolved = probe.stdout.trim();
    if (probe.status !== 0 || resolved !== expectedTree) {
      fail(`${label} tree drifted: ${JSON.stringify(resolved)} != ${expectedTree}`);
      return false;
    }
    ok(`${label} tree = ${expectedTree}`);
    return true;
  };
  resolveCommit('accepted base', BASE_COMMIT);
  verifyTree('accepted base', BASE_COMMIT, BASE_TREE);
  const headProbe = git(ctx.repo, ['rev-parse', 'HEAD^{commit}'], { check: false });
  const ancestryProbe = git(ctx.repo, ['merge-base', '--is-ancestor', BASE_COMMIT, 'HEAD'], { check: false });
  if (headProbe.status !== 0 || ancestryProbe.status !== 0) {
    fail(`current HEAD ${JSON.stringify(headProbe.stdout.trim())} does not descend from accepted base ${BASE_COMMIT}`);
  } else ok(`current HEAD descends from accepted base ${BASE_COMMIT}`);

  // ---- scope (changed paths vs the registered B003 per-iteration allowed set) ----
  // --no-renames keeps both sides of a rename in the changed-path set.
  const diff = git(ctx.repo, ['diff', '--name-only', '--no-renames', BASE_COMMIT]).stdout.split('\n').filter(Boolean);
  // Regenerable package-manager install output is not candidate source: the
  // repository carries no .gitignore (adding one is outside the B003 allowed
  // path set), so filter the generated node_modules tree here.
  const untracked = git(ctx.repo, ['ls-files', '--others', '--exclude-standard'])
    .stdout.split('\n')
    .filter((p) => p && p !== 'node_modules' && !p.startsWith('node_modules/'));
  const changed = [...new Set([...diff, ...untracked])].sort();
  if (changed.length === 0) fail('no changed paths found vs base');
  else ok(`${changed.length} changed paths vs base`);
  for (const p of changed) {
    if (!pathMatchesAllowed(p)) fail(`path outside AIPT-M0-B003 allowed set: ${p}`);
    for (const prefix of FORBIDDEN_PREFIXES) {
      if (p.startsWith(prefix)) fail(`forbidden prefix changed: ${p}`);
    }
    if (FROZEN_REGISTRY_PATHS.includes(p)) fail(`frozen registry modified: ${p}`);
  }
  if (changed.every((p) => pathMatchesAllowed(p) && !FORBIDDEN_PREFIXES.some((x) => p.startsWith(x)) && !FROZEN_REGISTRY_PATHS.includes(p))) {
    ok('all changed paths within the registered B003 per-iteration scope');
  }

  // LICENSE untouched vs base.
  const licDiff = git(ctx.repo, ['diff', BASE_COMMIT, '--', 'LICENSE']).stdout;
  if (licDiff.trim() !== '') fail('LICENSE modified by candidate');
  else {
    const lic = fs.readFileSync(path.join(ctx.repo, 'LICENSE'), 'utf8');
    if (normalizeText(lic) !== normalizeText(EXPECTED_MIT_LICENSE)) fail('LICENSE does not carry the exact MIT text');
    else ok('LICENSE untouched, exact MIT text');
  }

  // ---- Markdown links (no blanket scripts/ci skip: every Markdown document
  // in the tree participates). No fixed total count: instead, every base
  // Markdown document must remain present, and every current relative link
  // must resolve — a later approved protocol document of the accepted base
  // must not be rejected by a brittle count. ----
  const baseFiles = git(ctx.repo, ['ls-tree', '-r', '--name-only', BASE_COMMIT]).stdout.split('\n').filter(Boolean);
  const baseMd = baseFiles.filter((f) => f.endsWith('.md'));
  const missingBaseMd = baseMd.filter((f) => !fs.existsSync(path.join(ctx.repo, f)));
  if (missingBaseMd.length > 0) {
    for (const f of missingBaseMd) fail(`base Markdown document no longer present: ${f}`);
  } else ok(`every base Markdown document remains (${baseMd.length} documents from the accepted base)`);
  const { mdCount, issues: linkIssues } = collectMarkdownLinkIssues(ctx.repo);
  if (linkIssues.length > 0) {
    for (const issue of linkIssues.slice(0, 20)) {
      fail(`broken relative link: ${issue.file} -> ${issue.target} (${issue.reason})`);
    }
  } else ok(`${mdCount} Markdown documents in the tree, all relative links resolve`);

  // ---- JSON parse ----
  let jsonCount = 0;
  let jsonFailures = [];
  for (const file of walkFiles(ctx.repo, (f) => f.endsWith('.json'))) {
    jsonCount += 1;
    try {
      JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (err) {
      jsonFailures.push(`${path.relative(ctx.repo, file)}: ${err.message}`);
    }
  }
  if (jsonFailures.length > 0) {
    for (const f of jsonFailures) fail(`invalid JSON: ${f}`);
  } else ok(`${jsonCount} JSON files parse`);

  // ---- secret / private-path / prompt-body hygiene ----
  // No blanket skip for scripts/ci: the executable public scripts are scanned
  // too. This is safe because every hazard literal in lib/scan.mjs is
  // assembled from fragments, so the scanner cannot flag its own source.
  const hazards = scanTreeForHazards(ctx.repo);
  if (hazards.length > 0) {
    for (const h of hazards.slice(0, 20)) {
      fail(`hazard ${h.hazard} in ${h.file}: ${JSON.stringify(h.sample)}`);
    }
  } else ok('no credential material, private absolute paths, model endpoints or prompt bodies (scripts/ci included)');

  // ---- hygiene regression (B001-GPT-001): a forbidden hazard inside a
  // temporary .mjs file under a scripts/ci-shaped path MUST be detected ----
  const probeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-hygiene-probe-'));
  try {
    const probeRel = path.join('scripts', 'ci', 'probe.mjs');
    const probeFile = path.join(probeDir, probeRel);
    fs.mkdirSync(path.dirname(probeFile), { recursive: true });
    // The forbidden endpoint is assembled from fragments at runtime, so this
    // validator source never contains the literal hazard string.
    fs.writeFileSync(
      probeFile,
      `// temporary hygiene negative probe\nexport const probeEndpoint = 'https://${['api', 'deepseek', 'com'].join('.')}/v1';\n`,
    );
    const probeFindings = scanTreeForHazards(probeDir);
    const detected = probeFindings.some(
      (f) => f.file === 'scripts/ci/probe.mjs' && f.hazard === 'DEEPSEEK_ENDPOINT',
    );
    if (!detected) {
      fail('hygiene regression: runtime-assembled forbidden endpoint in temp scripts/ci/probe.mjs was NOT detected (.mjs support or script-tree coverage regressed)');
    } else ok('hygiene regression: .mjs negative probe under scripts/ci/ detected (script-tree coverage intact)');
  } finally {
    fs.rmSync(probeDir, { recursive: true, force: true });
  }

  // ---- index mode scan (fail-closed) ----
  // Every tracked index entry must be a regular file (or executable): mode
  // 120000 (symlink) and mode 160000 (gitlink) are rejected. Metadata is
  // parsed only up to the first TAB; the entire remainder is the path, so
  // ordinary spaces in paths are preserved. Malformed output is a failure,
  // and a nonzero git exit status is a failure.
  const indexProbe = git(ctx.repo, ['ls-files', '--stage'], { check: false });
  let entryCount = 0;
  let parseErrors = 0;
  const unsafeEntries = [];
  if (indexProbe.status !== 0) {
    fail(`git ls-files --stage failed with status ${indexProbe.status}: ${(indexProbe.stderr || '').trim()}`);
  } else {
    for (const line of indexProbe.stdout.split('\n')) {
      if (line === '') continue;
      entryCount += 1;
      const tab = line.indexOf('\t');
      if (tab === -1) {
        parseErrors += 1;
        fail(`malformed index entry (no tab separating metadata from path): ${JSON.stringify(line)}`);
        continue;
      }
      const metadata = line.slice(0, tab);
      const filePath = line.slice(tab + 1);
      if (filePath === '') {
        parseErrors += 1;
        fail(`malformed index entry (empty path after metadata): ${JSON.stringify(line)}`);
        continue;
      }
      // Metadata must be exactly '<mode> <object> <stage>' with six octal
      // mode digits, an object id of exactly 40 or 64 lowercase hex digits,
      // and a stage of exactly one digit 0..3.
      const metaMatch = /^([0-7]{6}) ([0-9a-f]{40}|[0-9a-f]{64}) ([0-3])$/.exec(metadata);
      if (!metaMatch) {
        parseErrors += 1;
        fail(`malformed index entry metadata (expected six octal mode digits, 40/64 lowercase hex object id, one stage digit 0..3): ${JSON.stringify(metadata)}`);
        continue;
      }
      const [, mode] = metaMatch;
      if (mode === '120000' || mode === '160000') {
        unsafeEntries.push({ mode, filePath });
        fail(`unsafe index entry: mode ${mode} (${mode === '120000' ? 'symlink' : 'gitlink'}) at ${filePath}`);
      }
    }
  }
  if (indexProbe.status === 0 && parseErrors === 0 && unsafeEntries.length === 0) {
    ok(`all ${entryCount} tracked index entries are regular files (no 120000 symlink / 160000 gitlink modes)`);
  }

  return { name: 'tree-integrity', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'tree-integrity', run);
