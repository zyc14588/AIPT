#!/usr/bin/env node
// AIPT-MVP-B000 exact Candidate status transition validator.
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {
  B008_IMPLEMENTATION_MERGE,
  CURRENT_BATCH,
  MVP_B000_BASE_COMMIT,
  MVP_B000_NEXT_BATCH,
  MVP_B000_SNAPSHOT,
  STATUS_DATE,
} from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';
import { EXPECTED_BATCHES, validateStatus } from './mvp-bootstrap.mjs';

const STATUS_PATH = 'docs/authority/registry/project-status.json';
const GRAPH_PATH = 'docs/authority/registry/batch-graph.json';
const PLATFORM = 'FROZEN_WAITING_M1_ENGINE';
const B008_BASE_STATUS_SHA256 = '12cc7cb32f330512410a3070d0d03278066c48e58f1b69e0399b5efe9c845ec8';

function readJson(repo, relative) {
  return JSON.parse(fs.readFileSync(path.join(repo, relative), 'utf8'));
}

function readBaseStatus(repo) {
  const probe = git(repo, ['show', `${MVP_B000_BASE_COMMIT}:${STATUS_PATH}`], { check: false });
  if (probe.status !== 0) throw new Error('M0 closeout status is unavailable');
  return JSON.parse(probe.stdout);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

// Keep the complete B008 closeout state independently anchored instead of
// trusting it merely because B000 derives its expected state from Base. The
// content hash closes every field/key/order value, while the explicit checks
// keep the critical lifecycle and cross-repository invariants reviewable.
export function validateHistoricalB008Status(status) {
  const problems = [];
  const canonical = `${JSON.stringify(status, null, 2)}\n`;
  if (createHash('sha256').update(canonical).digest('hex') !== B008_BASE_STATUS_SHA256) {
    problems.push('historical B008 closeout status bytes drifted');
  }
  const standalone = status?.tracks?.['AIPT-STANDALONE'];
  const platform = status?.tracks?.['AIPT-PLATFORM-INTEGRATION'];
  const aipt = status?.repositories?.AIPT;
  const unregistered = status?.repositories?.UNREGISTERED;
  const m0Ids = Array.from({ length: 9 }, (_, index) =>
    `AIPT-M0-B${String(index).padStart(3, '0')}`);
  if (status?.schema !== 'aipt.public.project-status/v1' ||
      status?.as_of !== '2026-08-25' ||
      status?.authority_snapshot_id !== 'AIPT-M0-B008-CLOSEOUT-001') {
    problems.push('historical B008 root identity drifted');
  }
  if (standalone?.construction !== 'IDLE_WAITING_NEXT_BATCH' ||
      standalone?.current_batch !== 'NO_ACTIVE_BATCH' ||
      standalone?.global_wip !== 0 || standalone?.next_serial_batch !== 'NONE' ||
      standalone?.next_batch_state !== 'NOT_AUTHORIZED' ||
      standalone?.next_batch_authorized !== false || standalone?.next_batch_started !== false ||
      JSON.stringify(Object.keys(standalone?.batch_history ?? {})) !== JSON.stringify(m0Ids) ||
      m0Ids.some((id) => standalone?.batch_history?.[id] !== 'MERGED_CLOSED')) {
    problems.push('historical B008 WIP0/MERGED_CLOSED/no-next lifecycle drifted');
  }
  if (platform?.status !== PLATFORM || platform?.unfreeze_authorized !== false) {
    problems.push('historical B008 platform freeze drifted');
  }
  if (aipt?.verified_head !== B008_IMPLEMENTATION_MERGE.commit ||
      aipt?.verified_tree !== B008_IMPLEMENTATION_MERGE.tree ||
      Object.hasOwn(aipt ?? {}, 'pending_candidate') ||
      aipt?.verified_state?.state !== 'MERGED_CLOSED' ||
      aipt?.verified_state?.m0_development_pass?.result !== 'GRANTED' ||
      aipt?.verified_state?.gpt_hard_gate?.result !== 'PASS' ||
      (aipt?.verified_state?.gpt_hard_gate?.open_findings?.length ?? -1) !== 0 ||
      aipt?.verified_state?.boundaries?.mvp_development_pass !== 'NOT_GRANTED') {
    problems.push('historical B008 implementation/audit/Development Pass boundary drifted');
  }
  if (unregistered?.verified_head !== '5d25dad0dbcb648de565ea723027f999ec5b3a37' ||
      unregistered?.verified_tree !== 'aa86d842c82d2a7f33eb3e6c44378cbe5ab338cc' ||
      unregistered?.verified_closeout !== '358d6d9d08a86818e34fd0c0d9a62bfe66e73abe' ||
      unregistered?.verified_closeout_tree !== '5585271c78d1fe5cd8357c7b36a501bee34f0240') {
    problems.push('historical B008 UNREGISTERED binding drifted');
  }
  return problems;
}

function historicalNegativeProbes(baseStatus) {
  const probes = [
    ['construction reopened', (copy) => { copy.tracks['AIPT-STANDALONE'].construction = 'IN_PROGRESS'; }],
    ['active batch added', (copy) => { copy.tracks['AIPT-STANDALONE'].current_batch = 'AIPT-M0-B008'; }],
    ['GLOBAL_WIP raised', (copy) => { copy.tracks['AIPT-STANDALONE'].global_wip = 1; }],
    ['next batch added', (copy) => { copy.tracks['AIPT-STANDALONE'].next_serial_batch = 'AIPT-M1-B000'; }],
    ['next batch authorized', (copy) => { copy.tracks['AIPT-STANDALONE'].next_batch_authorized = true; }],
    ['next batch started', (copy) => { copy.tracks['AIPT-STANDALONE'].next_batch_started = true; }],
    ['B008 reopened', (copy) => { copy.tracks['AIPT-STANDALONE'].batch_history['AIPT-M0-B008'] = 'IN_PROGRESS'; }],
    ['B007 reopened', (copy) => { copy.tracks['AIPT-STANDALONE'].batch_history['AIPT-M0-B007'] = 'IN_PROGRESS'; }],
    ['external predecessor drift', (copy) => { copy.tracks['AIPT-STANDALONE'].external_serial_predecessor.candidate_tree = 'wrong'; }],
    ['external history removed', (copy) => { copy.tracks['AIPT-STANDALONE'].external_batch_history.pop(); }],
    ['platform unfrozen', (copy) => { copy.tracks['AIPT-PLATFORM-INTEGRATION'].unfreeze_authorized = true; }],
    ['verified head changed to Base', (copy) => { copy.repositories.AIPT.verified_head = MVP_B000_BASE_COMMIT; }],
    ['verified tree changed', (copy) => { copy.repositories.AIPT.verified_tree = '0'.repeat(40); }],
    ['verified state reopened', (copy) => { copy.repositories.AIPT.verified_state.state = 'IN_PROGRESS'; }],
    ['Development Pass revoked', (copy) => { copy.repositories.AIPT.verified_state.m0_development_pass.result = 'NOT_GRANTED'; }],
    ['production boundary elevated', (copy) => { copy.repositories.AIPT.verified_state.boundaries.production_qualification = 'GRANTED'; }],
    ['audit root drift', (copy) => { copy.repositories.AIPT.verified_state.gpt_hard_gate.audit_ready_root_sha256 = '0'.repeat(64); }],
    ['lifecycle repair reopened', (copy) => { copy.repositories.AIPT.verified_state.lifecycle_repair.status = 'OPEN'; }],
    ['pending Candidate reintroduced', (copy) => { copy.repositories.AIPT.pending_candidate = {}; }],
    ['Harness identity drift', (copy) => { copy.runtime.deepseek_harness_commit = '0'.repeat(40); }],
    ['UNREGISTERED implementation drift', (copy) => { copy.repositories.UNREGISTERED.verified_head = 'wrong'; }],
    ['unknown root field', (copy) => { copy.m0_development_pass_effective = true; }],
  ];
  return probes.map(([label, mutate]) => {
    const copy = clone(baseStatus);
    mutate(copy);
    return [label, validateHistoricalB008Status(copy).length > 0];
  });
}

function negativeProbes(status, baseStatus) {
  const probes = [
    ['wrong snapshot', (copy) => { copy.authority_snapshot_id = 'AIPT-MVP-B001-CANDIDATE-001'; }],
    ['wrong status date', (copy) => { copy.as_of = '2026-08-27'; }],
    ['GLOBAL_WIP zero', (copy) => { copy.tracks['AIPT-STANDALONE'].global_wip = 0; }],
    ['GLOBAL_WIP above one', (copy) => { copy.tracks['AIPT-STANDALONE'].global_wip = 2; }],
    ['foreign active batch', (copy) => { copy.tracks['AIPT-STANDALONE'].current_batch = 'AIPT-MVP-B001'; }],
    ['B001 authorized', (copy) => { copy.tracks['AIPT-STANDALONE'].next_batch_authorized = true; }],
    ['B001 started', (copy) => { copy.tracks['AIPT-STANDALONE'].next_batch_started = true; }],
    ['later MVP batch started', (copy) => { copy.tracks['AIPT-STANDALONE'].batch_history['AIPT-MVP-B006'] = 'IN_PROGRESS'; }],
    ['M0 history reopened', (copy) => { copy.tracks['AIPT-STANDALONE'].batch_history['AIPT-M0-B008'] = 'IN_PROGRESS'; }],
    ['B008 implementation head replaced', (copy) => { copy.repositories.AIPT.verified_head = MVP_B000_BASE_COMMIT; }],
    ['pending Candidate removed', (copy) => { delete copy.repositories.AIPT.pending_candidate; }],
    ['pending Candidate merge authorized', (copy) => { copy.repositories.AIPT.pending_candidate.merge_authorized = true; }],
    ['platform unfreeze', (copy) => { copy.tracks['AIPT-PLATFORM-INTEGRATION'].unfreeze_authorized = true; }],
    ['UNREGISTERED drift', (copy) => { copy.repositories.UNREGISTERED.verified_tree = '0'.repeat(40); }],
    ['MVP pass inflation', (copy) => { copy.repositories.AIPT.verified_state.boundaries.mvp_development_pass = 'GRANTED'; }],
  ];
  return probes.map(([label, mutate]) => {
    const copy = clone(status);
    mutate(copy);
    return [label, validateStatus(copy, baseStatus).length > 0];
  });
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => { pass = false; details.push('FAIL: ' + message); };
  let status;
  let baseStatus;
  let graph;
  try {
    status = readJson(ctx.repo, STATUS_PATH);
    baseStatus = readBaseStatus(ctx.repo);
    graph = readJson(ctx.repo, GRAPH_PATH);
  } catch (error) {
    fail('status authority is unreadable: ' + error.message);
    return { result: 'FAIL', details, negative_probes: 'NOT_RUN' };
  }

  const problems = validateStatus(status, baseStatus);
  for (const problem of problems) fail(problem);
  if (problems.length === 0) ok('machine status is the exact AIPT-MVP-B000 Candidate transition');

  const historicalProblems = validateHistoricalB008Status(baseStatus);
  for (const problem of historicalProblems) fail(problem);
  if (historicalProblems.length === 0) {
    ok('B008 final closeout status retains its exact independent hash and lifecycle boundaries');
  }

  const standalone = status.tracks?.['AIPT-STANDALONE'];
  const graphIds = graph?.serial_batches?.map((batch) => batch.id) ?? [];
  const statusIds = Object.keys(standalone?.batch_history ?? {}).filter((id) =>
    !id.startsWith('AIPT-M0-'));
  if (JSON.stringify(graphIds) !== JSON.stringify(statusIds) ||
      JSON.stringify(graphIds) !== JSON.stringify(EXPECTED_BATCHES.map((batch) => batch.id))) {
    fail('status MVP batch order does not exactly mirror the machine graph');
  } else ok('status carries the exact ordered 13-item MVP graph');

  if (status.as_of !== STATUS_DATE || status.authority_snapshot_id !== MVP_B000_SNAPSHOT ||
      standalone.current_batch !== CURRENT_BATCH || standalone.global_wip !== 1 ||
      standalone.next_serial_batch !== MVP_B000_NEXT_BATCH ||
      standalone.next_batch_authorized !== false || standalone.next_batch_started !== false) {
    fail('current/next/WIP lifecycle tuple drifted');
  } else ok('B000 is sole active batch; B001 is named but unauthorized and not started');

  if (status.repositories?.AIPT?.verified_head !== B008_IMPLEMENTATION_MERGE.commit ||
      status.repositories?.AIPT?.verified_tree !== B008_IMPLEMENTATION_MERGE.tree ||
      status.repositories?.AIPT?.verified_state?.m0_development_pass?.result !== 'GRANTED') {
    fail('accepted M0 implementation identity or Development Pass drifted');
  } else ok('accepted M0 implementation identity and effective Development Pass are preserved');

  if (status.tracks?.['AIPT-PLATFORM-INTEGRATION']?.status !== PLATFORM ||
      status.tracks?.['AIPT-PLATFORM-INTEGRATION']?.unfreeze_authorized !== false) {
    fail('platform integration is not frozen');
  } else ok('platform integration remains frozen without unfreeze authority');

  const docs = [
    ['README.md', [MVP_B000_SNAPSHOT, CURRENT_BATCH, 'GLOBAL_WIP = 1', MVP_B000_NEXT_BATCH]],
    ['docs/authority/PROJECT_STATUS.md', [MVP_B000_SNAPSHOT, CURRENT_BATCH,
      'GLOBAL_WIP = 1', MVP_B000_NEXT_BATCH, 'NOT_AUTHORIZED']],
  ];
  for (const [relative, needles] of docs) {
    const text = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
    const missing = needles.filter((needle) => !text.includes(needle));
    if (missing.length) fail(`${relative} misses Candidate lifecycle tokens: ${missing.join(', ')}`);
    else ok(`${relative} carries the exact Candidate lifecycle boundary`);
  }

  const probes = negativeProbes(status, baseStatus);
  for (const [label, rejected] of probes) if (!rejected) fail('negative status probe was accepted: ' + label);
  const rejected = probes.filter(([, value]) => value).length;
  if (rejected === probes.length) ok(`all ${rejected} status-transition mutations reject`);

  const historicalProbes = historicalNegativeProbes(baseStatus);
  for (const [label, rejectedHistorical] of historicalProbes) {
    if (!rejectedHistorical) fail('historical B008 status probe was accepted: ' + label);
  }
  const historicalRejected = historicalProbes.filter(([, value]) => value).length;
  if (historicalRejected === historicalProbes.length) {
    ok(`all ${historicalRejected} historical B008 final-status mutations reject`);
  }

  return {
    result: pass ? 'PASS' : 'FAIL',
    details,
    negative_probes: rejected === probes.length && historicalRejected === historicalProbes.length
      ? 'PASS' : 'FAIL',
    negative_probe_count: probes.length + historicalProbes.length,
    historical_b008_status_protection: historicalProblems.length === 0 &&
      historicalRejected === historicalProbes.length ? 'PASS' : 'FAIL',
  };
}

runAsMain(import.meta.url, 'status-transition', run);
