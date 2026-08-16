// B000 retro validator (AIPT-M0-B001 edition).
//
// Uses B001's own validators to re-validate the FIXED historical B000 merge
// commit 777a3f39ba78c1ef3168597890c61abf7a55d962 from the current B001
// checkout. The B000 tree is expanded into a temporary read-only directory.
//
// Historical expectations are constants in lib/constants.mjs (B000 block) and
// are NEVER updated by later batches — B001 resolving DEFER-016 must not
// change the B000 expectations.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  B000,
  EXPECTED_MIT_LICENSE,
  normalizeText,
} from '../lib/constants.mjs';
import {
  chmodTreeReadOnly,
  collectMarkdownLinkIssues,
  scanTreeForHazards,
  verifyTreeReadOnly,
  walkFiles,
} from '../lib/scan.mjs';
import { expandCommitTree, git, gitOut, runAsMain } from '../lib/cli.mjs';

function checkFileCounts(root, details, ok, fail) {
  const files = walkFiles(root);
  const md = files.filter((f) => f.endsWith('.md'));
  const json = files.filter((f) => f.endsWith('.json'));
  if (files.length !== B000.tracked_file_count) {
    fail(`B000 tree file count drifted: ${files.length} != ${B000.tracked_file_count}`);
  } else ok(`B000 tree has exactly ${B000.tracked_file_count} tracked files`);
  if (md.length !== B000.markdown_documents) {
    fail(`B000 markdown document count drifted: ${md.length} != ${B000.markdown_documents}`);
  } else ok(`${B000.markdown_documents} Markdown documents`);
  if (json.length !== 4) fail(`B000 registry JSON count drifted: ${json.length} != 4`);
  else ok('4 registry JSON files');
}

export function run(ctx, args = {}) {
  const details = [];
  let pass = true;
  const ok = (msg) => details.push(`ok: ${msg}`);
  const fail = (msg) => {
    pass = false;
    details.push(`FAIL: ${msg}`);
  };
  const commit = args.commit || B000.commit;
  const expectedTree = args['expected-tree'] || args.expectedTree || B000.tree;

  // 1. Fixed commit identity in this checkout.
  const resolvedCommit = gitOut(ctx.repo, ['rev-parse', `${commit}^{commit}`]);
  if (resolvedCommit !== B000.commit) {
    fail(`commit resolution drifted: ${resolvedCommit} != ${B000.commit}`);
  } else ok(`fixed B000 commit resolves: ${B000.commit}`);
  const tree = gitOut(ctx.repo, ['rev-parse', `${commit}^{tree}`]);
  if (tree !== expectedTree) {
    fail(`merge tree mismatch: ${tree} != ${expectedTree}`);
  } else ok(`merge tree == ${expectedTree}`);

  // 2. Read-only expansion.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-b000-retro-'));
  try {
    expandCommitTree(ctx.repo, commit, tmp);
    chmodTreeReadOnly(tmp);
    const writable = verifyTreeReadOnly(tmp);
    if (writable.length > 0) fail(`expanded tree not read-only: ${writable.slice(0, 5).join(', ')}`);
    else ok('expanded B000 tree is read-only');

    // 3. Content checks.
    checkFileCounts(tmp, details, ok, fail);

    const licPath = path.join(tmp, 'LICENSE');
    if (!fs.existsSync(licPath)) fail('LICENSE missing in B000 tree');
    else if (normalizeText(fs.readFileSync(licPath, 'utf8')) !== normalizeText(EXPECTED_MIT_LICENSE)) {
      fail('B000 LICENSE is not the exact root MIT License');
    } else ok('root MIT License exact');

    const { issues: linkIssues } = collectMarkdownLinkIssues(tmp);
    if (linkIssues.length > 0) {
      for (const issue of linkIssues.slice(0, 20)) {
        fail(`B000 broken relative link: ${issue.file} -> ${issue.target} (${issue.reason})`);
      }
    } else ok(`all relative links across the ${B000.markdown_documents} B000 Markdown documents resolve`);

    // Decisions: 454 unique.
    const decisions = JSON.parse(fs.readFileSync(path.join(tmp, 'docs/authority/registry/decisions.json'), 'utf8'));
    const ids = decisions.records.map((r) => r.decision_id);
    if (ids.length !== B000.decisions || new Set(ids).size !== B000.decisions) {
      fail(`decisions: ${ids.length} records, ${new Set(ids).size} unique, expected ${B000.decisions} unique`);
    } else ok(`${B000.decisions} unique decisions`);

    // Supersessions: 35.
    const supersessions = JSON.parse(fs.readFileSync(path.join(tmp, 'docs/authority/registry/supersessions.json'), 'utf8'));
    if ((supersessions.relationships ?? []).length !== B000.supersessions) {
      fail(`supersessions: ${(supersessions.relationships ?? []).length} != ${B000.supersessions}`);
    } else ok(`${B000.supersessions} supersessions`);

    // Deferred: 16, judged by B000's own historical state.
    const deferred = JSON.parse(fs.readFileSync(path.join(tmp, 'docs/authority/registry/deferred-parameters.json'), 'utf8'));
    const params = deferred.parameters ?? [];
    if (params.length !== B000.deferred_parameters) {
      fail(`deferred parameters: ${params.length} != ${B000.deferred_parameters}`);
    } else ok(`${B000.deferred_parameters} deferred parameters (B000 historical state)`);
    const d16 = params.find((p) => p.parameter_id === 'DEFER-016');
    if (!d16) fail('DEFER-016 missing from B000 registry');
    else if (d16.status !== B000.deferred_016_historical_status) {
      fail(`DEFER-016 historical status drifted: ${d16.status} != ${B000.deferred_016_historical_status}`);
    } else ok('DEFER-016 holds its historical B000 status (DEFERRED_TO_AIPT-M0-B001) — later batches do not rewrite history');
    if (params.some((p) => p.status === 'RESOLVED')) fail('B000 tree must contain no RESOLVED deferred parameter');
    else ok('no deferred parameter is RESOLVED in the historical B000 tree');

    // Project status (B000 historical state).
    const status = JSON.parse(fs.readFileSync(path.join(tmp, 'docs/authority/registry/project-status.json'), 'utf8'));
    const platform = status.tracks?.['AIPT-PLATFORM-INTEGRATION'];
    if (platform?.status !== 'FROZEN_WAITING_M1_ENGINE') fail('B000 project status lost the platform freeze');
    else ok('B000 project status keeps platform integration frozen');

    // JSON parse for all registry docs.
    let jsonOk = true;
    for (const file of walkFiles(tmp, (f) => f.endsWith('.json'))) {
      try {
        JSON.parse(fs.readFileSync(file, 'utf8'));
      } catch (err) {
        jsonOk = false;
        fail(`JSON parse failure in B000 tree: ${path.relative(tmp, file)}: ${err.message}`);
      }
    }
    if (jsonOk) ok('all B000 JSON parses');

    // Hygiene: no credentials, private paths, model endpoints or prompt bodies.
    const hazards = scanTreeForHazards(tmp);
    if (hazards.length > 0) {
      for (const h of hazards.slice(0, 20)) fail(`B000 hazard ${h.hazard} in ${h.file}: ${JSON.stringify(h.sample)}`);
    } else ok('B000 tree: no credentials, no private absolute paths, no model endpoints, no public prompt body');

    // B000 bootstrap scope: no runtime/code/CI paths may exist in the tree.
    const forbidden = [
      '.github', 'cmd', 'internal', 'packages', 'api', 'migrations', 'deploy', 'testdata',
      'go.mod', 'go.sum', 'package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml',
    ];
    const present = forbidden.filter((p) => fs.existsSync(path.join(tmp, p)));
    if (present.length > 0) fail(`B000 tree contains forbidden runtime paths: ${present.join(', ')}`);
    else ok('B000 tree contains no runtime/code/CI paths (bootstrap scope)');
  } catch (err) {
    fail(`B000 retro expansion/validation crashed: ${err.message}`);
  } finally {
    try {
      // Restore write bits (children first) so cleanup can remove the tree.
      const restore = (dir) => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
          const full = path.join(dir, entry.name);
          if (entry.isDirectory()) restore(full);
          fs.chmodSync(full, fs.statSync(full).mode | 0o222);
        }
      };
      restore(tmp);
      fs.rmSync(tmp, { recursive: true, force: true });
    } catch {
      // best-effort cleanup
    }
  }

  return { name: 'b000-retro', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain('b000-retro', run);
