// B002 tree-integrity validator: scope, Markdown links, JSON parse, and
// secret / private-path / prompt-body hygiene for the candidate tree
// (including the executable scripts/ci sources themselves), plus a
// temporary-fixture regression proving the hygiene scan really covers .mjs
// files under a scripts/ci-shaped path.
//
// Markdown rules for B002: no brittle fixed total document count (later
// approved B002 contract documents must not be rejected by a count) — instead
// every Markdown document of the accepted base must still be present and
// every current relative link must resolve.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  BASE_COMMIT,
  EXPECTED_MIT_LICENSE,
  FROZEN_REGISTRY_PATHS,
  FORBIDDEN_PREFIXES,
  normalizeText,
  pathMatchesAllowed,
} from '../lib/constants.mjs';
import { collectMarkdownLinkIssues, scanTreeForHazards, walkFiles } from '../lib/scan.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };

  // ---- scope (changed paths vs the B002 iteration-1 allowed set) ----
  const diff = git(ctx.repo, ['diff', '--name-only', BASE_COMMIT]).stdout.split('\n').filter(Boolean);
  // Regenerable package-manager install output is not candidate source: the
  // repository carries no .gitignore (adding one is outside the B002 allowed
  // path set), so filter the generated node_modules tree here.
  const untracked = git(ctx.repo, ['ls-files', '--others', '--exclude-standard'])
    .stdout.split('\n')
    .filter((p) => p && p !== 'node_modules' && !p.startsWith('node_modules/'));
  const changed = [...new Set([...diff, ...untracked])].sort();
  if (changed.length === 0) fail('no changed paths found vs base');
  else ok(`${changed.length} changed paths vs base`);
  for (const p of changed) {
    if (!pathMatchesAllowed(p)) fail(`path outside AIPT-M0-B002 allowed set: ${p}`);
    for (const prefix of FORBIDDEN_PREFIXES) {
      if (p.startsWith(prefix)) fail(`forbidden prefix changed: ${p}`);
    }
    if (FROZEN_REGISTRY_PATHS.includes(p)) fail(`frozen registry modified: ${p}`);
  }
  if (changed.every((p) => pathMatchesAllowed(p) && !FORBIDDEN_PREFIXES.some((x) => p.startsWith(x)) && !FROZEN_REGISTRY_PATHS.includes(p))) {
    ok('all changed paths within the registered B002 iteration-1 scope');
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
  // must resolve — a later approved B002 protocol document must not be
  // rejected by a brittle count. ----
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

  return { name: 'tree-integrity', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'tree-integrity', run);
