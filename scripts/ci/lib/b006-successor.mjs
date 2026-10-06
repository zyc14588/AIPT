// The Owner-approved B002 repair is an exact exception, never a generic bypass.
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { isDeepStrictEqual as equal } from 'node:util';
import { acceptedGovernanceProblems, resolveB005R1Topology, b005R1StatusProblems } from './b005-r1-lifecycle.mjs';

export const BASE = '08a5aa175edae712cdaacc7a84ff94673fa13552';
export const BASE_TREE = '31bdfac01b3810f49e7099ca86e8270a4bdd65ae';
export const TASK = 'AIPT-MVP-B006';
export const ENGINE = 'internal/runcore/engine.go';
export const REPAIR = 'docs/authority/registry/b006-b002-successor-repair.json';
export const START = 'docs/authority/registry/b006-start.json';
export const REGRESSION = 'internal/runcore/b006_zero_rng_replay_test.go';
export const ORIGINAL_SHA = '297f32b8a18ae69bd5d38c81cb0a014c2ae5918f84588b4a68ea178db3d9bfbb';
export const REPAIRED_SHA = '3bf7974874969664b6940bc7ac1ee013f2a7a5c945382a19ace962921377f9c3';
export const REPAIR_SHA = '3b6520b34b2e602bdbaf5a14f405968439174a693c4f19d436cd610a5a8305f5';
export const STATUS = 'docs/authority/registry/project-status.json';
export const GATE_AUTHORITY = 'docs/authority/registry/b006-predecessor-gates-successor.json';
export const GATE_AUTHORITY_SHA = '8f1f8566a498a24def6e62b74505d2a4aadb4cac420cbca4587a70c78499fde8';
export const GATE_DECISION = 'B006-PREDECESSOR-GATES-SUCCESSOR-Q001=A';
const EXCEPTIONS = new Set([ENGINE, STATUS, 'docs/authority/PROJECT_STATUS.md', 'docs/milestones/MVP.md', 'package.json', 'scripts/ci/run-checks.mjs', 'packages/model-harness-gateway/test/fixture-acp-worker.ts']);
export const EXACT_NEW = new Map([
  [GATE_AUTHORITY, GATE_AUTHORITY_SHA], [REPAIR, REPAIR_SHA], [START, '649bb0f3f465784e7406188f799990faecb27249c915ab675fec30dc2957c0d6'],
  [REGRESSION, 'f768f372b1c64faced7d237476a356fbacb64b1052669a5a5986c336ea8b06b5'],
]);
export function sha(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
export function git(repo, args, binary = false) {
  const r = spawnSync('git', ['-C', repo, ...args], { encoding: binary ? undefined : 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (r.error || r.status !== 0) return null;
  return r.stdout;
}
export function out(repo, args) { return git(repo, args)?.trim() ?? null; }
export function rows(repo, args) { return git(repo, args)?.split('\n').filter(Boolean) ?? []; }
export function blob(repo, revision, relative) { return git(repo, ['show', revision + ':' + relative], true); }
export function read(repo, relative) { return fs.readFileSync(path.join(repo, relative)); }
export function facts(repo, revision) {
  const row = out(repo, ['rev-list', '--parents', '-n', '1', revision]);
  if (!row) return null;
  const [commit, ...parents] = row.split(/\s+/u);
  const tree = out(repo, ['rev-parse', commit + '^{tree}']);
  return tree ? { commit, parents, tree } : null;
}
export function firstParentContains(repo, revision, ancestor) { return rows(repo, ['rev-list', '--first-parent', revision]).includes(ancestor); }
export function inventory(repo, revision) {
  const text = git(repo, ['ls-tree', '-r', '-z', revision]);
  if (text === null) throw new Error('Git inventory unavailable');
  return new Map(text.split('\0').filter(Boolean).map((row) => {
    const match = /^(\d+) blob ([a-f0-9]{40})\t(.+)$/u.exec(row);
    if (!match) throw new Error('unexpected tree entry');
    return [match[3], { mode: match[1], oid: match[2] }];
  }));
}
function workingOID(repo, relative) {
  const full = path.join(repo, relative); const stat = fs.lstatSync(full);
  if (!stat.isFile()) throw new Error('protected artifact is not a regular file');
  const bytes = fs.readFileSync(full);
  return { mode: stat.mode & 0o111 ? '100755' : '100644', oid: crypto.createHash('sha1').update('blob ' + bytes.length + '\0').update(bytes).digest('hex') };
}
function historicalTouched(repo, revision) {
  return new Set(rows(repo, ['log', '--first-parent', '--full-history', '--format=', '--name-only', BASE + '..' + revision]));
}
function invariantAuthority(repo, revision, relative, digest, problems) {
  const text = blob(repo, revision, relative);
  const additions = rows(repo, ['log', '--first-parent', '--format=%H', '--diff-filter=A', BASE + '..' + revision, '--', relative]);
  if (additions.length === 0) {
    if (text !== null) problems.push('unintroduced successor authority on ' + revision + ': ' + relative);
    return;
  }
  if (additions.length !== 1 || text === null || sha(text) !== digest ||
      rows(repo, ['log', '--first-parent', '--full-history', '--format=%H', additions[0] + '..' + revision, '--', relative]).length !== 0) {
    problems.push('successor authority/test was rewritten on ' + revision + ': ' + relative);
  }
}
function exactB006Candidate(repo, head) {
  const f=facts(repo,head);
  if (equal(f?.parents,[BASE])) return head;
  const pairs=rows(repo,['rev-list','--first-parent',BASE+'..'+head]).map((id)=>facts(repo,id)).filter((m)=>m?.parents?.length===2&&m.parents[0]===BASE&&equal(facts(repo,m.parents[1])?.parents,[BASE]));
  return pairs.length===1?pairs[0].parents[1]:null;
}
function exceptionHistoryProblems(repo, head, main) {
  const p=[];const candidate=exactB006Candidate(repo,head);
  if (!candidate) return ['B006 exception versions have no exact Candidate/Base lineage'];
  // These are bounded authorization exceptions, not mutable history exemptions.
  for (const relative of ['package.json','scripts/ci/run-checks.mjs','packages/model-harness-gateway/test/fixture-acp-worker.ts']) {
    const original=blob(repo,BASE,relative);const successor=blob(repo,candidate,relative);
    if (!original||!successor) {p.push('approved B006 exception version unavailable: '+relative);continue;}
    if (!successor.equals(read(repo,relative))) p.push('B006 working exception differs from its exact committed Candidate: '+relative);
    for (const revision of new Set([head,main])) {
      if (!revision) continue;
      const merges=rows(repo,['rev-list','--first-parent',BASE+'..'+revision]).map((id)=>facts(repo,id)).filter((m)=>equal(m?.parents,[BASE,candidate])&&m.tree===facts(repo,candidate)?.tree);
      if (merges.length>1) p.push('B006 exception history has ambiguous merge identity on '+revision);
      const merge=merges[0];
      const versions=[revision,...rows(repo,['log','--first-parent','--full-history','--format=%H',BASE+'..'+revision,'--',relative])];
      for (const id of new Set(versions)) {
        const bytes=blob(repo,id,relative);
        const afterMerge=merge&&firstParentContains(repo,id,merge.commit);
        // BASE is an admissible predecessor only BEFORE the exact B006 merge.
        // Restoring BASE later would silently remove the accepted successor guard.
        if (!bytes||(afterMerge?!bytes.equals(successor):(!bytes.equals(original)&&!bytes.equals(successor)))) p.push('approved B006 exception bytes/history changed on '+revision+': '+relative);
      }
    }
  }
  return p;
}
function predecessorStatusProblems(baseStatus,status) {
  const p=[];
    for (const [key, value] of Object.entries(baseStatus)) {
      if (['as_of', 'authority_snapshot_id', 'tracks', 'repositories', 'runtime'].includes(key)) continue;
      if (!equal(status[key], value)) p.push('accepted status projection changed: ' + key);
    }
    for (const [key, value] of Object.entries(baseStatus.repositories)) {
      if (key !== 'AIPT' && !equal(status.repositories?.[key], value)) p.push('external repository authority changed: ' + key);
    }
    for (const [key, value] of Object.entries(baseStatus.repositories.AIPT)) {
      if (!equal(status.repositories?.AIPT?.[key], value)) p.push('accepted AIPT predecessor status changed: ' + key);
    }
    for (const [key, value] of Object.entries(baseStatus.runtime)) if (key !== 'status' && !equal(status.runtime?.[key], value)) p.push('runtime predecessor registration changed: ' + key);
    if (!equal(status.tracks?.['AIPT-PLATFORM-INTEGRATION'], baseStatus.tracks['AIPT-PLATFORM-INTEGRATION'])) p.push('platform integration freeze changed');
    const track = status.tracks?.['AIPT-STANDALONE'];
    for (const [key, value] of Object.entries(baseStatus.tracks['AIPT-STANDALONE'].batch_history)) {
      if (key !== TASK && !equal(track?.batch_history?.[key], value)) p.push('accepted batch history changed: ' + key);
    }
    const trackMutable=new Set(['construction','current_batch','next_serial_batch','next_batch_state','next_batch_authorized','next_batch_started','batch_history','global_wip']);
    for (const [key,value] of Object.entries(baseStatus.tracks['AIPT-STANDALONE'])) if (!trackMutable.has(key)&&!equal(track?.[key],value)) p.push('accepted standalone predecessor projection changed: '+key);
  return p;
}
export function successorProblems(repo) {
  const problems = [];
  try {
    if (facts(repo, BASE)?.tree !== BASE_TREE) problems.push('exact accepted B005 base/tree unavailable');
    const head = out(repo, ['rev-parse', 'HEAD^{commit}']);
    const main = out(repo, ['rev-parse', 'refs/remotes/origin/main^{commit}']);
    if (!head || !main || !firstParentContains(repo, head, BASE) || !firstParentContains(repo, main, BASE)) problems.push('checkout and accepted main must contain exact B005 closeout on their first-parent histories');
    problems.push(...exceptionHistoryProblems(repo,head,main));
    const accepted = inventory(repo, BASE);
    for (const revision of new Set([head, main])) {
      if (!revision) continue;
      const current = inventory(repo, revision); const touched = historicalTouched(repo, revision);
      for (const [relative, expected] of accepted) {
        if (EXCEPTIONS.has(relative)) continue;
        if (!equal(current.get(relative), expected) || touched.has(relative)) problems.push('accepted predecessor bytes/history changed on ' + revision + ': ' + relative);
      }
      // A rewrite-and-restore cannot hide behind a clean older checkout.
      for (const changed of rows(repo, ['log', '--first-parent', '--full-history', '--format=%H', BASE + '..' + revision, '--', ENGINE])) {
        const bytes = blob(repo, changed, ENGINE);
        if (bytes === null || sha(bytes) !== REPAIRED_SHA) problems.push('B002 repair history admits an unauthorized engine version on ' + revision);
      }
      for (const [relative, digest] of EXACT_NEW) invariantAuthority(repo, revision, relative, digest, problems);
    }
    for (const [relative, expected] of accepted) {
      if (!EXCEPTIONS.has(relative) && !equal(workingOID(repo, relative), expected)) problems.push('accepted predecessor working artifact changed: ' + relative);
    }
    if (sha(blob(repo, BASE, ENGINE) ?? '') !== ORIGINAL_SHA || sha(read(repo, ENGINE)) !== REPAIRED_SHA) problems.push('B002 engine is not the exact approved nil/empty clone successor');
    for (const [relative, digest] of EXACT_NEW) if (sha(read(repo, relative)) !== digest) problems.push('exact Owner authority/regression changed: ' + relative);
    if (sha(read(repo, 'packages/model-harness-gateway/test/fixture-acp-worker.ts')) !== '6f8b14ec211714bda702775ac984fc52528bcb28a14d4f55d1385bdce213f38e') problems.push('ACP fixture is not the bounded synchronization-only change');
    const baseStatus = JSON.parse(blob(repo, BASE, STATUS)); const status = JSON.parse(read(repo, STATUS));
    problems.push(...predecessorStatusProblems(baseStatus,status));
    if (!read(repo,STATUS).equals(Buffer.from(JSON.stringify(status,null,2)+'\n'))) problems.push('working predecessor status is not exact canonical JSON');
    for (const revision of new Set([head,main])) {
      if (!revision) continue;
      const versions=[revision,...rows(repo,['log','--first-parent','--full-history','--format=%H',BASE+'..'+revision,'--',STATUS])];
      for (const id of new Set(versions)) {
        const bytes=blob(repo,id,STATUS);
        try {
          const projection=JSON.parse(bytes);
          if (!bytes?.equals(Buffer.from(JSON.stringify(projection,null,2)+'\n'))) problems.push('predecessor status history is not exact canonical JSON on '+revision+' at '+id);
          problems.push(...predecessorStatusProblems(baseStatus,projection).map((p)=>'frozen predecessor status/history on '+revision+' at '+id+': '+p));
        } catch { problems.push('predecessor status history missing or unreadable on '+revision+' at '+id); }
      }
    }
    const track=status.tracks?.['AIPT-STANDALONE'];
    const b006=status.repositories?.AIPT?.mvp_b006;
    if (b006?.state==='IN_PROGRESS'&&(track?.construction!=='IN_PROGRESS'||track.current_batch!==TASK||track.global_wip!==1||track.batch_history?.[TASK]!=='IN_PROGRESS'||track.next_serial_batch!=='AIPT-MVP-B007'||track.next_batch_state!=='NOT_AUTHORIZED'||track.next_batch_authorized!==false||track.next_batch_started!==false)) problems.push('B006 authorized construction/current/next/WIP tuple changed');
    if (!['IN_PROGRESS','MERGED_CLOSED'].includes(b006?.state)) problems.push('B006 state is neither authorized construction nor closed projection');
    const b005=resolveB005R1Topology(repo);
    problems.push(...acceptedGovernanceProblems(repo),...b005.problems,...b005R1StatusProblems(repo,status,b005));
    if (b005.phase!=='CLOSED_HISTORICAL_REPLAY') problems.push('accepted B005 current lifecycle no longer resolves to its immutable closeout');
    const oldPackage = JSON.parse(blob(repo, BASE, 'package.json')); const pkg = JSON.parse(read(repo, 'package.json'));
    for (const [key, value] of Object.entries(oldPackage)) if (!['description', 'scripts'].includes(key) && !equal(pkg[key], value)) problems.push('package dependency/toolchain metadata changed: ' + key);
    for (const [key, value] of Object.entries(oldPackage.scripts)) {
      const gate = ['check:mvp-b002', 'check:mvp-b003', 'check:mvp-b004', 'check:mvp-b005', 'check:int001-closeout-authority'].includes(key);
      const expected = gate ? 'node scripts/ci/validate/b006-approved-predecessors.mjs --gate ' + key.slice(6) : value;
      if (pkg.scripts?.[key] !== expected) problems.push('required predecessor script changed: ' + key);
    }
  } catch (error) { problems.push('successor guard failed closed: ' + error.message); }
  return problems;
}

// Replay the unchanged legacy gates at their exact previously accepted state,
// only AFTER separately checking the current checkout/main/history exception.
const snapshots = new Map();
function snapshot(repo) {
  if (snapshots.has(repo)) return snapshots.get(repo);
  const target = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-b006-accepted-predecessors-'));
  const clone = spawnSync('git', ['clone', '--no-local', '--no-checkout', repo, target], { encoding: 'utf8' });
  if (clone.status !== 0) { fs.rmSync(target, { recursive: true, force: true }); throw new Error('local immutable predecessor expansion failed'); }
  if (git(target, ['checkout', '--detach', BASE]) === null || git(target, ['update-ref', 'refs/remotes/origin/main', BASE]) === null ||
      facts(target, 'HEAD')?.tree !== BASE_TREE || out(target, ['status', '--porcelain=v1', '--untracked-files=all']) !== '') {
    fs.rmSync(target, { recursive: true, force: true }); throw new Error('predecessor expansion identity/cleanliness failed');
  }
  snapshots.set(repo, target); return target;
}
export function cleanupSnapshots() { for (const p of snapshots.values()) fs.rmSync(p, { recursive: true, force: true }); snapshots.clear(); }
export function runApprovedPredecessor(ctx, args = {}) {
  const gate = args.gate;
  const valid = ['mvp-b002', 'mvp-b003', 'mvp-b004', 'mvp-b005', 'int001-closeout-authority'];
  const problems = valid.includes(gate) ? successorProblems(ctx.repo) : ['unknown predecessor gate'];
  let report = null;
  if (problems.length === 0) {
    try {
      const target = snapshot(ctx.repo);
      const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GITHUB_')));
      // Validator/lib bytes were checked against BASE by successorProblems.
      const r = spawnSync(process.execPath, [path.join(ctx.repo, 'scripts/ci/validate/' + gate + '.mjs'), '--repo', target], { cwd: target, env, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
      try { report = JSON.parse(r.stdout); } catch { /* fail closed */ }
      if (r.error || r.signal || r.status !== 0 || report?.result !== 'PASS' || report?.name !== gate) problems.push('exact accepted predecessor replay failed: ' + gate + ': ' + (report?.details?.filter((x) => x.startsWith('FAIL:')).join('; ') || 'invalid result'));
    } catch (error) { problems.push(error.message); }
  }
  return {
    result: problems.length ? 'FAIL' : 'PASS', task_id: gate === 'int001-closeout-authority' ? 'INT-AIPT-UNREGISTERED-MVP-001-CLOSEOUT-AUTHORITY-001' : gate?.toUpperCase().replace('MVP-', 'AIPT-MVP-') ?? 'UNKNOWN',
    details: problems.length ? problems.map((p) => 'FAIL: ' + p) : ['ok: exact historical gate PASS at accepted B005 closeout', 'ok: current checkout, accepted main and their complete first-parent histories preserve every other predecessor byte', 'ok: only the exact Owner-approved B002 repair and separately authorized predecessor gate successors are admitted'],
    historical_gate: report, validation_target: { commit: BASE, tree: BASE_TREE, mode: 'EXACT_ACCEPTED_PREDECESSOR_WITH_EXPLICIT_CURRENT_SUCCESSOR_GUARD' },
    predecessor_gate_authority: { path: GATE_AUTHORITY, sha256: GATE_AUTHORITY_SHA, decision_id: GATE_DECISION },
    repair_authority: { path: REPAIR, sha256: REPAIR_SHA, engine_sha256: REPAIRED_SHA }, external_github_requests: 0, real_model_calls: 0,
  };
}
