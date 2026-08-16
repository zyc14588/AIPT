// B001 tree-integrity validator: scope, Markdown links, JSON parse, and
// secret / private-path / prompt-body hygiene for the candidate tree.
import fs from 'node:fs';
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

  // ---- scope (changed paths vs private task manifest) ----
  const diff = git(ctx.repo, ['diff', '--name-only', BASE_COMMIT]).stdout.split('\n').filter(Boolean);
  // Regenerable package-manager install output is not candidate source: the
  // repository carries no .gitignore (adding one is outside the B001 allowed
  // path set), so filter the generated node_modules tree here.
  const untracked = git(ctx.repo, ['ls-files', '--others', '--exclude-standard'])
    .stdout.split('\n')
    .filter((p) => p && p !== 'node_modules' && !p.startsWith('node_modules/'));
  const changed = [...new Set([...diff, ...untracked])].sort();
  if (changed.length === 0) fail('no changed paths found vs base');
  else ok(`${changed.length} changed paths vs base`);
  for (const p of changed) {
    if (!pathMatchesAllowed(p)) fail(`path outside AIPT-M0-B001 allowed set: ${p}`);
    for (const prefix of FORBIDDEN_PREFIXES) {
      if (p.startsWith(prefix)) fail(`forbidden prefix changed: ${p}`);
    }
    if (FROZEN_REGISTRY_PATHS.includes(p)) fail(`frozen registry modified: ${p}`);
  }
  if (changed.every((p) => pathMatchesAllowed(p) && !FORBIDDEN_PREFIXES.some((x) => p.startsWith(x)) && !FROZEN_REGISTRY_PATHS.includes(p))) {
    ok('all changed paths within the registered B001 scope');
  }

  // LICENSE untouched vs base.
  const licDiff = git(ctx.repo, ['diff', BASE_COMMIT, '--', 'LICENSE']).stdout;
  if (licDiff.trim() !== '') fail('LICENSE modified by candidate');
  else {
    const lic = fs.readFileSync(path.join(ctx.repo, 'LICENSE'), 'utf8');
    if (normalizeText(lic) !== normalizeText(EXPECTED_MIT_LICENSE)) fail('LICENSE does not carry the exact MIT text');
    else ok('LICENSE untouched, exact MIT text');
  }

  // ---- Markdown links ----
  const { mdCount, issues: linkIssues } = collectMarkdownLinkIssues(ctx.repo, {
    skipPrefixes: ['scripts/ci/'],
  });
  if (linkIssues.length > 0) {
    for (const issue of linkIssues.slice(0, 20)) {
      fail(`broken relative link: ${issue.file} -> ${issue.target} (${issue.reason})`);
    }
  } else ok(`${mdCount} Markdown documents, all relative links resolve`);
  if (mdCount !== 18) fail(`expected 18 Markdown documents in the B001 tree (17 B000 + docs/supply-chain/README.md), found ${mdCount}`);
  else ok('18 Markdown documents (B000 17 + supply-chain README)');

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
  const hazards = scanTreeForHazards(ctx.repo, {
    skipPrefixes: ['scripts/ci/'],
  });
  if (hazards.length > 0) {
    for (const h of hazards.slice(0, 20)) {
      fail(`hazard ${h.hazard} in ${h.file}: ${JSON.stringify(h.sample)}`);
    }
  } else ok('no credential material, private absolute paths, model endpoints or prompt bodies');

  return { name: 'tree-integrity', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain('tree-integrity', run);
