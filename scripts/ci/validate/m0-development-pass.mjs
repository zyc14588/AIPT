#!/usr/bin/env node
// AIPT-M0-B008 fail-closed M0 Development Pass Candidate validator.
// Node.js standard library only.
import fs from 'node:fs';
import path from 'node:path';
import {
  ALLOWED_PATHS, BASE_COMMIT, BASE_TREE, B007_CLOSEOUT,
  B007_EXTERNAL_SERIAL_PREDECESSOR, B007_IMPLEMENTATION_MERGE,
  CURRENT_BATCH, FROZEN_REGISTRY_PATHS, pathMatchesAllowed,
} from '../lib/constants.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const RECORD_PATH = 'docs/milestones/m0-development-pass.json';
const DOCUMENT_PATH = 'docs/milestones/M0_DEVELOPMENT_PASS.md';
const STATUS_PATH = 'docs/authority/registry/project-status.json';
const AUDIT_ARCHIVE_SHA256 = '0eb777d62c8045acc29b0a80216951b4aeb36f856bf690d2cd394019a1f7119d';
const AUDIT_ROOT_SHA256 = '33becf9c765902442ec7d7445c50d3ac00737c50bccfc33b5bb4f56e2bdaa90b';
const GPT_AUDIT_SHA256 = 'd35fca102f28387c0e4c7045d65da8418ffc947189500bf639d4edb11bbba207';
const INTEGRATION_ROOT_SHA256 = '329c98d00600ede1e9bdd7830b30f7968cc3de4d458b57bb3f6730a0bfedac91';
const LEDGER_SHA256 = 'e294002e426e157c4eb765b4944568d853bdd4cd4a34afc763073ae21c85a88e';
const CLOSED_FINDINGS = [
  'AIPT-B008-AUDIT-EVIDENCE-SELF-CONTAINMENT-001',
  'AIPT-B008-SOURCE-TREE-DIGEST-001',
  'AIPT-B008-SOURCE-TREE-SUMMARY-FACT-001',
];
const CLOSED_BATCH_IDS = [
  'AIPT-M0-B000', 'AIPT-M0-B001', 'AIPT-M0-B002', 'AIPT-M0-B003',
  'AIPT-M0-B004', 'AIPT-M0-B005', 'AIPT-M0-B006', 'AIPT-M0-B007',
];
const REQUIRED_CHANGED_PATHS = [
  '.github/workflows/ci.yml',
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/milestones/M0.md',
  DOCUMENT_PATH,
  RECORD_PATH,
  'package.json',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/m0-development-pass.mjs',
  'scripts/ci/validate/standalone-entrypoints.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
  'scripts/ci/validate/workflow.mjs',
];
const TASK_BRANCH = 'task/AIPT-M0-B008';
const MAIN_BRANCH = 'main';
const IMPLEMENTATION_MERGE_SUBJECT = 'merge: integrate AIPT-M0-B008';
const PR_REF_PATTERN = /^refs\/pull\/[1-9][0-9]*\/(?:head|merge)$/;
const GITHUB_LIFECYCLE_KEYS = [
  'GITHUB_ACTIONS', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'GITHUB_HEAD_REF',
  'GITHUB_BASE_REF', 'GITHUB_SHA',
];
const FROZEN_FILES = [
  '.go-version', 'go.mod', 'go.sum', 'pnpm-lock.yaml', 'pnpm-workspace.yaml',
  'tools/toolchain.lock.json', 'tools/ci-actions.lock.json',
  'tools/supply-chain/policy.json', 'tools/supply-chain/licenses.json',
  ...FROZEN_REGISTRY_PATHS,
];

const EXPECTED_RECORD = {
  schema: 'aipt.m0.development-pass/v1',
  task_id: 'AIPT-M0-B008',
  record_state: 'CANDIDATE_PROPOSAL',
  authority: {
    directive_id: 'AIPT-M0-B008-GPT-PASS-AND-FINALIZE-001',
    authorization_scope: 'IMPLEMENT_AND_FREEZE_CANDIDATE_ONLY',
    branch: 'task/AIPT-M0-B008',
    merge_authorized: false,
  },
  lifecycle: {
    construction: 'IN_PROGRESS',
    current_batch: 'AIPT-M0-B008',
    global_wip: 1,
    batch_history: Object.fromEntries([
      ...CLOSED_BATCH_IDS.map((id) => [id, 'MERGED_CLOSED']),
      ['AIPT-M0-B008', 'IN_PROGRESS'],
    ]),
    next_serial_batch: 'NONE',
    next_batch_state: 'NOT_AUTHORIZED',
    next_batch_authorized: false,
    next_batch_started: false,
  },
  milestone_state: {
    gpt_audit: 'PASS',
    m0_development_pass: 'PROPOSED_PENDING_B008_MERGED_CLOSED',
  },
  proposal: {
    proposed_result: 'M0_DEVELOPMENT_PASS',
    current_effective_status: 'NOT_YET_GRANTED',
    effective_after: 'AIPT-M0-B008_MERGED_CLOSED',
  },
  source_bindings: {
    aipt: {
      source_b007_closeout: { commit: B007_CLOSEOUT.commit, tree: B007_CLOSEOUT.tree },
      accepted_m0_implementation: {
        commit: B007_IMPLEMENTATION_MERGE.commit,
        tree: B007_IMPLEMENTATION_MERGE.tree,
      },
    },
    unregistered: {
      closeout: {
        commit: B007_EXTERNAL_SERIAL_PREDECESSOR.closeout_commit,
        tree: B007_EXTERNAL_SERIAL_PREDECESSOR.closeout_tree,
      },
      accepted_implementation: {
        commit: B007_EXTERNAL_SERIAL_PREDECESSOR.merge_commit,
        tree: B007_EXTERNAL_SERIAL_PREDECESSOR.candidate_tree,
      },
    },
    integration: {
      id: 'INT-AIPT-UNREGISTERED-001',
      result: 'PASS',
      state: 'CLOSED',
      root_sha256: INTEGRATION_ROOT_SHA256,
    },
  },
  audit_binding: {
    audit_ready_archive_sha256: AUDIT_ARCHIVE_SHA256,
    audit_ready_root_sha256: AUDIT_ROOT_SHA256,
    gpt_audit_result_sha256: GPT_AUDIT_SHA256,
    gpt_result: 'PASS',
    gpt_open_findings: [],
    closed_stage_a_r1_findings: CLOSED_FINDINGS,
  },
  batch_identity_ledger: {
    archive_member: 'AUDIT_READY/BATCH_IDENTITY_LEDGER.json',
    schema: 'aipt.m0.batch-identity-ledger/v1',
    sha256: LEDGER_SHA256,
    bound_by_audit_ready_root_sha256: AUDIT_ROOT_SHA256,
  },
  boundaries: {
    production_qualification: 'NOT_GRANTED',
    release_qualification: 'NOT_GRANTED',
    mvp_development_pass: 'NOT_GRANTED',
    human_equivalence: 'NOT_CLAIMED',
    real_playtest_completion: 'NOT_CLAIMED',
    platform_integration: 'FROZEN_WAITING_M1_ENGINE',
    automatic_next_batch: 'NONE',
  },
};

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function compareExact(actual, expected, at = '$') {
  const problems = [];
  if (Array.isArray(expected)) {
    if (!Array.isArray(actual)) return [`${at} must be an array`];
    if (actual.length !== expected.length) problems.push(`${at} array length drifted`);
    for (let i = 0; i < Math.min(actual.length, expected.length); i += 1) {
      problems.push(...compareExact(actual[i], expected[i], `${at}[${i}]`));
    }
    return problems;
  }
  if (isPlainObject(expected)) {
    if (!isPlainObject(actual)) return [`${at} must be an object`];
    const actualKeys = Object.keys(actual).sort();
    const expectedKeys = Object.keys(expected).sort();
    if (JSON.stringify(actualKeys) !== JSON.stringify(expectedKeys)) {
      problems.push(`${at} key set drifted`);
    }
    for (const key of expectedKeys) {
      if (Object.hasOwn(actual, key)) {
        problems.push(...compareExact(actual[key], expected[key], `${at}.${key}`));
      }
    }
    return problems;
  }
  if (!Object.is(actual, expected)) problems.push(`${at} drifted`);
  return problems;
}

export function validateRecord(record) {
  return compareExact(record, EXPECTED_RECORD);
}

function validateChangedPaths(changed) {
  const problems = [];
  for (const relative of changed) {
    if (!pathMatchesAllowed(relative)) problems.push('path outside B008 scope: ' + relative);
    if (/^(?:internal|schemas|packages|cmd|testdata|tools)\//.test(relative)) {
      problems.push('runtime/product/dependency path changed: ' + relative);
    }
    if (relative === 'go.mod' || relative === 'go.sum' || relative === 'pnpm-lock.yaml' ||
        relative === 'pnpm-workspace.yaml' || relative === '.go-version') {
      problems.push('dependency/lock/toolchain path changed: ' + relative);
    }
  }
  return problems;
}

// `pnpm install --frozen-lockfile` creates untracked workspace metadata and
// first-party links below node_modules before this CI gate runs. Those
// disposable install artifacts are not Candidate source changes; tracked
// node_modules content would still be present in the Base..HEAD diff and fail
// the exact allowlist below.
function isGeneratedWorktreeArtifact(relative) {
  return relative.split('/').includes('node_modules');
}

function linesFrom(probe) {
  return probe?.status === 0 ? probe.stdout.split('\n').filter(Boolean) : null;
}

function normalizedEnv(value) {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : null;
}

function exactStringSet(actual, expected) {
  return Array.isArray(actual) && actual.length === expected.length &&
    new Set(actual).size === actual.length &&
    JSON.stringify([...actual].sort()) === JSON.stringify([...expected].sort());
}

function isGitObjectId(value) {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

function readCommit(repo, commit) {
  if (!commit) return null;
  const parentProbe = git(repo, ['rev-list', '--parents', '-n', '1', commit], { check: false });
  const parts = parentProbe.status === 0
    ? parentProbe.stdout.trim().split(/\s+/).filter(Boolean) : [];
  if (parts[0] !== commit) return null;
  const treeProbe = git(repo, ['rev-parse', commit + '^{tree}'], { check: false });
  const subjectProbe = git(repo, ['show', '-s', '--format=%s', commit], { check: false });
  return {
    commit,
    parents: parts.slice(1),
    tree: treeProbe.status === 0 ? treeProbe.stdout.trim() : null,
    subject: subjectProbe.status === 0 ? subjectProbe.stdout.trim() : null,
  };
}

// Git facts are collected once and then passed to a pure, fail-closed
// classifier/validator. In particular, a pull_request synthetic merge and an
// authorized main implementation merge may have the same graph shape, so the
// GitHub event/ref binding participates in classification instead of being
// treated as optional decoration.
export function collectLifecycleFacts(repo, env = process.env) {
  const baseCommitProbe = git(repo, ['rev-parse', BASE_COMMIT + '^{commit}'], { check: false });
  const baseTreeProbe = git(repo, ['rev-parse', BASE_COMMIT + '^{tree}'], { check: false });
  const headProbe = git(repo, ['rev-parse', 'HEAD^{commit}'], { check: false });
  const head = headProbe.status === 0 ? headProbe.stdout.trim() : null;
  const headCommit = readCommit(repo, head);
  const branchProbe = git(repo, ['symbolic-ref', '--short', 'HEAD'], { check: false });
  const ancestryProbe = git(repo, ['merge-base', '--is-ancestor', BASE_COMMIT, 'HEAD'], {
    check: false,
  });
  const mergeProbe = git(repo, [
    'rev-list', '--merges', '--reverse', BASE_COMMIT + '..HEAD',
  ], { check: false });
  const mergeCommits = linesFrom(mergeProbe);
  const soleMerge = Array.isArray(mergeCommits) && mergeCommits.length === 1
    ? readCommit(repo, mergeCommits[0]) : null;
  const candidateTip = soleMerge?.parents?.length === 2 ? soleMerge.parents[1] : head;
  const candidateCommit = readCommit(repo, candidateTip);
  const candidateAncestry = candidateTip
    ? git(repo, ['merge-base', '--is-ancestor', BASE_COMMIT, candidateTip], { check: false })
    : { status: 2 };
  const candidateMergeProbe = candidateTip
    ? git(repo, ['rev-list', '--merges', BASE_COMMIT + '..' + candidateTip], { check: false })
    : { status: 2, stdout: '' };
  const candidatePathsProbe = candidateTip
    ? git(repo, ['diff', '--name-only', '--no-renames', BASE_COMMIT, candidateTip], { check: false })
    : { status: 2, stdout: '' };
  const githubPresent = GITHUB_LIFECYCLE_KEYS.some((key) => Object.hasOwn(env, key));
  return {
    baseCommit: baseCommitProbe.status === 0 ? baseCommitProbe.stdout.trim() : null,
    baseTree: baseTreeProbe.status === 0 ? baseTreeProbe.stdout.trim() : null,
    head,
    headTree: headCommit?.tree ?? null,
    ancestryKnown: ancestryProbe.status === 0 || ancestryProbe.status === 1,
    baseIsAncestor: ancestryProbe.status === 0,
    branch: branchProbe.status === 0 ? branchProbe.stdout.trim() : null,
    github: {
      present: githubPresent,
      eventName: normalizedEnv(env.GITHUB_EVENT_NAME),
      ref: normalizedEnv(env.GITHUB_REF),
      headRef: normalizedEnv(env.GITHUB_HEAD_REF),
      baseRef: normalizedEnv(env.GITHUB_BASE_REF),
    },
    mergeCommits,
    merge: soleMerge ? {
      ...soleMerge,
      treeDiffQuiet: candidateTip
        ? git(repo, ['diff', '--quiet', candidateTip, soleMerge.commit], { check: false }).status === 0
        : false,
    } : null,
    candidateTip,
    candidateTree: candidateCommit?.tree ?? null,
    candidateDescendsFromBase: candidateAncestry.status === 0,
    candidateMergeCommits: linesFrom(candidateMergeProbe),
    candidateChangedPaths: linesFrom(candidatePathsProbe)?.sort() ?? null,
  };
}

export function classifyLifecycle(facts) {
  const problems = [];
  const github = facts?.github;
  let phase = 'UNKNOWN';
  if (!isPlainObject(github) || typeof github.present !== 'boolean') {
    problems.push('GitHub lifecycle environment is unreadable');
    return { result: 'FAIL', phase, problems };
  }

  if (github.present) {
    if (github.eventName === 'pull_request') {
      phase = 'PULL_REQUEST_CHECK';
      if (github.headRef !== TASK_BRANCH) problems.push('pull_request head ref is not the B008 task branch');
      if (!PR_REF_PATTERN.test(github.ref ?? '')) problems.push('pull_request GITHUB_REF is not an exact PR head/merge ref');
      if (github.baseRef !== MAIN_BRANCH) problems.push('pull_request base ref is not main');
      if (facts.branch !== null && facts.branch !== TASK_BRANCH) {
        problems.push('pull_request symbolic branch is foreign');
      }
    } else if (github.eventName === 'push') {
      if (github.headRef !== null || github.baseRef !== null) {
        problems.push('push event unexpectedly carries PR head/base refs');
      }
      if (github.ref === 'refs/heads/' + TASK_BRANCH) {
        phase = 'CANDIDATE_PUSH';
        if (facts.branch !== null && facts.branch !== TASK_BRANCH) {
          problems.push('Candidate push symbolic branch is foreign');
        }
      } else if (github.ref === 'refs/heads/' + MAIN_BRANCH) {
        phase = 'POST_MERGE_MAIN';
        if (facts.branch !== null && facts.branch !== MAIN_BRANCH) {
          problems.push('main push symbolic branch is foreign');
        }
      } else {
        problems.push('push GITHUB_REF is not the B008 task branch or main');
      }
    } else {
      problems.push('GitHub event is not an authorized push or pull_request lifecycle event');
    }
  } else if (facts.branch === TASK_BRANCH) {
    phase = 'CANDIDATE_PUSH';
  } else if (facts.branch === MAIN_BRANCH) {
    phase = 'POST_MERGE_MAIN';
  } else if (facts.branch === null) {
    if (Array.isArray(facts.mergeCommits) && facts.mergeCommits.length === 0) {
      phase = 'CANDIDATE_PUSH';
    } else if (Array.isArray(facts.mergeCommits) && facts.mergeCommits.length === 1 &&
        facts.merge?.commit === facts.head && facts.merge?.subject === IMPLEMENTATION_MERGE_SUBJECT) {
      phase = 'POST_MERGE_MAIN';
    } else {
      problems.push('detached local checkout cannot be classified uniquely from exact topology');
    }
  } else {
    problems.push('local symbolic branch is not the B008 task branch or main');
  }
  return { result: problems.length === 0 ? 'PASS' : 'FAIL', phase, problems };
}

export function validateLifecycle(facts) {
  const classification = classifyLifecycle(facts);
  const problems = [...classification.problems];
  const phase = classification.phase;
  let checkoutKind = 'UNKNOWN';
  let implementationMergeRecognized = false;
  const mergeCommits = facts?.mergeCommits;

  if (facts?.baseCommit !== BASE_COMMIT) problems.push('fixed Base commit does not resolve exactly');
  if (facts?.baseTree !== BASE_TREE) problems.push('fixed Base tree does not resolve exactly');
  if (!isGitObjectId(facts?.head)) problems.push('HEAD commit identity is unreadable');
  if (!isGitObjectId(facts?.headTree)) problems.push('HEAD tree identity is unreadable');
  if (facts?.ancestryKnown !== true) problems.push('HEAD ancestry is unreadable');
  if (facts?.baseIsAncestor !== true) problems.push('HEAD does not descend from fixed Base');

  const validateCandidate = () => {
    if (!isGitObjectId(facts.candidateTip)) problems.push('Candidate tip identity is unreadable');
    if (!isGitObjectId(facts.candidateTree)) problems.push('Candidate tree identity is unreadable');
    if (facts.candidateTip !== facts.head) problems.push('Candidate tip is not HEAD');
    if (facts.candidateDescendsFromBase !== true) problems.push('Candidate lineage does not descend from fixed Base');
    if (!Array.isArray(facts.candidateMergeCommits)) {
      problems.push('Candidate merge list is unreadable');
    } else if (facts.candidateMergeCommits.length !== 0) {
      problems.push('Candidate lineage contains a merge commit');
    }
    if (facts.candidateTree !== facts.headTree) problems.push('Candidate tree is not the checked-out HEAD tree');
  };
  const validateCandidateContract = () => {
    if (!exactStringSet(facts.candidateChangedPaths, REQUIRED_CHANGED_PATHS)) {
      problems.push('Base-to-Candidate changed-path contract is not the exact 15-path B008 surface');
    }
  };
  const validateTwoParentMerge = ({ requireSubject }) => {
    const merge = facts.merge;
    if (!merge || typeof merge !== 'object') {
      problems.push('lifecycle merge facts are missing');
      return;
    }
    if (!isGitObjectId(merge.commit)) problems.push('lifecycle merge identity is unreadable');
    if (!isGitObjectId(merge.tree)) problems.push('lifecycle merge tree identity is unreadable');
    if (!isGitObjectId(facts.candidateTip)) problems.push('Candidate parent identity is unreadable');
    if (!isGitObjectId(facts.candidateTree)) problems.push('Candidate parent tree identity is unreadable');
    if (merge.commit !== facts.head) problems.push('lifecycle merge is not current HEAD');
    if (!Array.isArray(merge.parents) || merge.parents.length !== 2) {
      problems.push('lifecycle merge does not have exactly two parents');
      return;
    }
    if (merge.parents[0] !== BASE_COMMIT) problems.push('lifecycle merge first parent is not fixed Base/main');
    if (merge.parents[1] !== facts.candidateTip) problems.push('lifecycle merge second parent is not Candidate tip');
    if (facts.candidateDescendsFromBase !== true) problems.push('Candidate parent does not descend from fixed Base');
    if (!Array.isArray(facts.candidateMergeCommits)) {
      problems.push('Candidate parent merge list is unreadable');
    } else if (facts.candidateMergeCommits.length !== 0) {
      problems.push('Candidate parent contains a merge commit');
    }
    if (merge.tree !== facts.candidateTree) problems.push('lifecycle merge tree does not equal Candidate tree');
    if (merge.treeDiffQuiet !== true) problems.push('lifecycle merge introduces a tree delta from Candidate');
    if (facts.headTree !== merge.tree) problems.push('checked-out HEAD tree does not equal lifecycle merge tree');
    if (requireSubject && merge.subject !== IMPLEMENTATION_MERGE_SUBJECT) {
      problems.push('implementation merge subject is not exact');
    }
  };

  if (phase === 'CANDIDATE_PUSH') {
    checkoutKind = 'CANDIDATE_HEAD';
    if (!Array.isArray(mergeCommits)) problems.push('post-base merge list is unreadable');
    else if (mergeCommits.length !== 0) problems.push('Candidate history must contain zero post-base merges');
    validateCandidate();
    validateCandidateContract();
  } else if (phase === 'PULL_REQUEST_CHECK') {
    if (!Array.isArray(mergeCommits)) {
      problems.push('post-base merge list is unreadable');
    } else if (mergeCommits.length === 0) {
      checkoutKind = 'PR_HEAD';
      validateCandidate();
      validateCandidateContract();
    } else if (mergeCommits.length === 1) {
      checkoutKind = 'PR_SYNTHETIC_MERGE';
      if (facts.branch !== null) problems.push('PR synthetic merge checkout must be detached');
      if (mergeCommits[0] !== facts.head) problems.push('PR synthetic merge must be current HEAD');
      validateTwoParentMerge({ requireSubject: false });
      validateCandidateContract();
    } else {
      problems.push('PR checkout contains more than one post-base merge');
    }
  } else if (phase === 'POST_MERGE_MAIN') {
    checkoutKind = 'IMPLEMENTATION_MERGE';
    if (!Array.isArray(mergeCommits)) {
      problems.push('post-base merge list is unreadable');
    } else if (mergeCommits.length !== 1) {
      problems.push('post-merge main must contain exactly one implementation merge');
    } else {
      if (mergeCommits[0] !== facts.head) problems.push('implementation merge must be current HEAD');
      validateTwoParentMerge({ requireSubject: true });
      validateCandidateContract();
      implementationMergeRecognized = problems.length === 0;
    }
  } else {
    problems.push('lifecycle phase is not uniquely classified');
  }

  return {
    result: problems.length === 0 ? 'PASS' : 'FAIL',
    phase,
    checkoutKind,
    implementationMergeRecognized,
    problems,
  };
}

function lifecycleRegressionProbes() {
  const candidateId = 'c'.repeat(40);
  const candidateTree = 'd'.repeat(40);
  const syntheticId = 'e'.repeat(40);
  const implementationId = 'f'.repeat(40);
  const githubLocal = {
    present: false, eventName: null, ref: null, headRef: null, baseRef: null,
  };
  const candidate = {
    baseCommit: BASE_COMMIT,
    baseTree: BASE_TREE,
    head: candidateId,
    headTree: candidateTree,
    ancestryKnown: true,
    baseIsAncestor: true,
    branch: TASK_BRANCH,
    github: githubLocal,
    mergeCommits: [],
    merge: null,
    candidateTip: candidateId,
    candidateTree,
    candidateDescendsFromBase: true,
    candidateMergeCommits: [],
    candidateChangedPaths: [...REQUIRED_CHANGED_PATHS],
  };
  const syntheticMerge = {
    ...clone(candidate),
    head: syntheticId,
    headTree: candidateTree,
    branch: null,
    github: {
      present: true,
      eventName: 'pull_request',
      ref: 'refs/pull/8/merge',
      headRef: TASK_BRANCH,
      baseRef: MAIN_BRANCH,
    },
    mergeCommits: [syntheticId],
    merge: {
      commit: syntheticId,
      parents: [BASE_COMMIT, candidateId],
      tree: candidateTree,
      subject: 'Merge candidate-tip into main',
      treeDiffQuiet: true,
    },
  };
  const implementationMerge = {
    ...clone(syntheticMerge),
    head: implementationId,
    branch: MAIN_BRANCH,
    github: githubLocal,
    mergeCommits: [implementationId],
    merge: {
      ...syntheticMerge.merge,
      commit: implementationId,
      subject: IMPLEMENTATION_MERGE_SUBJECT,
    },
  };
  const prHead = {
    ...clone(candidate),
    branch: null,
    github: {
      present: true,
      eventName: 'pull_request',
      ref: 'refs/pull/8/merge',
      headRef: TASK_BRANCH,
      baseRef: MAIN_BRANCH,
    },
  };
  const probes = [
    ['task branch + zero merge Candidate', candidate, 'PASS', 'CANDIDATE_PUSH', false],
    ['exact Candidate GitHub push', {
      ...clone(candidate), branch: null, github: {
        present: true, eventName: 'push', ref: 'refs/heads/' + TASK_BRANCH,
        headRef: null, baseRef: null,
      },
    }, 'PASS', 'CANDIDATE_PUSH', false],
    ['exact PR head Candidate', prHead, 'PASS', 'PULL_REQUEST_CHECK', false],
    ['valid detached PR synthetic merge', syntheticMerge, 'PASS', 'PULL_REQUEST_CHECK', false],
    ['PR synthetic merge with implementation subject stays non-authoritative', {
      ...clone(syntheticMerge),
      merge: { ...syntheticMerge.merge, subject: IMPLEMENTATION_MERGE_SUBJECT },
    }, 'PASS', 'PULL_REQUEST_CHECK', false],
    ['valid main post-merge', implementationMerge, 'PASS', 'POST_MERGE_MAIN', true],
    ['valid detached GitHub main push', {
      ...clone(implementationMerge), branch: null, github: {
        present: true, eventName: 'push', ref: 'refs/heads/' + MAIN_BRANCH,
        headRef: null, baseRef: null,
      },
    }, 'PASS', 'POST_MERGE_MAIN', true],
    ['wrong Candidate branch', { ...clone(candidate), branch: 'task/foreign' }, 'FAIL'],
    ['task branch with merge', {
      ...clone(candidate), mergeCommits: ['internal-merge'], candidateMergeCommits: ['internal-merge'],
    }, 'FAIL'],
    ['wrong PR head', {
      ...clone(prHead), github: { ...prHead.github, headRef: 'task/foreign' },
    }, 'FAIL'],
    ['main with zero merge', { ...clone(candidate), branch: MAIN_BRANCH }, 'FAIL'],
    ['wrong merge first parent', {
      ...clone(implementationMerge),
      merge: { ...implementationMerge.merge, parents: ['a'.repeat(40), candidateId] },
    }, 'FAIL'],
    ['missing merge second parent', {
      ...clone(implementationMerge),
      merge: { ...implementationMerge.merge, parents: [BASE_COMMIT] },
    }, 'FAIL'],
    ['wrong implementation merge subject', {
      ...clone(implementationMerge),
      merge: { ...implementationMerge.merge, subject: 'merge: wrong' },
    }, 'FAIL'],
    ['merge tree mismatch', {
      ...clone(implementationMerge), headTree: '0'.repeat(40),
      merge: { ...implementationMerge.merge, tree: '0'.repeat(40) },
    }, 'FAIL'],
    ['merge introduces Candidate tree delta', {
      ...clone(implementationMerge),
      merge: { ...implementationMerge.merge, treeDiffQuiet: false },
    }, 'FAIL'],
    ['Candidate parent contains merge', {
      ...clone(implementationMerge), candidateMergeCommits: ['candidate-internal-merge'],
    }, 'FAIL'],
    ['second merge', {
      ...clone(implementationMerge), mergeCommits: [implementationId, '1'.repeat(40)],
    }, 'FAIL'],
  ];
  return probes.map(([label, facts, expected, expectedPhase, expectedRecognized]) => {
    const actual = validateLifecycle(facts);
    const matched = actual.result === expected &&
      (expectedPhase === undefined || actual.phase === expectedPhase) &&
      (expectedRecognized === undefined ||
        actual.implementationMergeRecognized === expectedRecognized);
    return { label, expected, actual: actual.result, phase: actual.phase, matched };
  });
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function runNegativeProbes(record) {
  const probes = [
    ['AUDIT_READY root drift', (r) => { r.audit_binding.audit_ready_root_sha256 = '0'.repeat(64); }],
    ['audit archive digest drift', (r) => { r.audit_binding.audit_ready_archive_sha256 = '0'.repeat(64); }],
    ['GPT audit digest drift', (r) => { r.audit_binding.gpt_audit_result_sha256 = '0'.repeat(64); }],
    ['Integration root drift', (r) => { r.source_bindings.integration.root_sha256 = '0'.repeat(64); }],
    ['missing closed finding', (r) => { r.audit_binding.closed_stage_a_r1_findings.pop(); }],
    ['GPT result changed from PASS', (r) => { r.audit_binding.gpt_result = 'FAIL'; }],
    ['production qualification granted', (r) => { r.boundaries.production_qualification = 'GRANTED'; }],
    ['release qualification granted', (r) => { r.boundaries.release_qualification = 'GRANTED'; }],
    ['MVP Development Pass granted', (r) => { r.boundaries.mvp_development_pass = 'GRANTED'; }],
    ['human equivalence claimed', (r) => { r.boundaries.human_equivalence = 'CLAIMED'; }],
    ['real playtest claimed', (r) => { r.boundaries.real_playtest_completion = 'CLAIMED'; }],
    ['platform integration unfrozen', (r) => { r.boundaries.platform_integration = 'UNFROZEN'; }],
    ['B008 Candidate claims MERGED_CLOSED', (r) => { r.lifecycle.batch_history['AIPT-M0-B008'] = 'MERGED_CLOSED'; }],
    ['effective M0 pass set before merge/closeout', (r) => { r.proposal.current_effective_status = 'GRANTED'; }],
    ['automatic next batch added', (r) => { r.boundaries.automatic_next_batch = 'AIPT-M1-B000'; }],
  ];
  const results = [];
  for (const [label, mutate] of probes) {
    const copy = clone(record);
    mutate(copy);
    results.push([label, validateRecord(copy).length > 0]);
  }
  results.push([
    'forbidden runtime path modified',
    validateChangedPaths(['internal/model/runtime.go']).length > 0,
  ]);
  return results;
}

function readJson(repo, relative) {
  return JSON.parse(fs.readFileSync(path.join(repo, relative), 'utf8'));
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => { pass = false; details.push('FAIL: ' + message); };
  let record;
  let status;
  try {
    record = readJson(ctx.repo, RECORD_PATH);
    status = readJson(ctx.repo, STATUS_PATH);
  } catch (error) {
    fail('Candidate record or project status is unreadable: ' + error.message);
    return { result: 'FAIL', details, negative_probes: 'NOT_RUN' };
  }

  const recordProblems = validateRecord(record);
  for (const problem of recordProblems) fail('record: ' + problem);
  if (recordProblems.length === 0) ok('record schema, key sets, identities and Candidate boundaries are exact');

  const standalone = status?.tracks?.['AIPT-STANDALONE'];
  const platform = status?.tracks?.['AIPT-PLATFORM-INTEGRATION'];
  const repoStatus = status?.repositories?.AIPT;
  const pending = repoStatus?.pending_candidate;
  if (standalone?.construction !== record.lifecycle.construction ||
      standalone?.current_batch !== record.lifecycle.current_batch ||
      standalone?.global_wip !== record.lifecycle.global_wip ||
      JSON.stringify(standalone?.batch_history) !== JSON.stringify(record.lifecycle.batch_history) ||
      standalone?.next_serial_batch !== record.lifecycle.next_serial_batch ||
      standalone?.next_batch_state !== record.lifecycle.next_batch_state ||
      standalone?.next_batch_authorized !== record.lifecycle.next_batch_authorized ||
      standalone?.next_batch_started !== record.lifecycle.next_batch_started) {
    fail('public project status disagrees with the Candidate lifecycle');
  } else ok('public project status matches the IN_PROGRESS/WIP1/no-next-batch lifecycle');
  if (repoStatus?.verified_head !== B007_IMPLEMENTATION_MERGE.commit ||
      repoStatus?.verified_tree !== B007_IMPLEMENTATION_MERGE.tree ||
      pending?.task_id !== CURRENT_BATCH || pending?.base_commit !== BASE_COMMIT ||
      pending?.base_tree !== BASE_TREE || pending?.state !== 'IN_PROGRESS' ||
      pending?.current_effective_status !== 'NOT_YET_GRANTED') {
    fail('accepted implementation or pending Candidate status drifted');
  } else ok('accepted implementation remains B007 while B008 is explicit and pending');
  if (platform?.status !== record.boundaries.platform_integration ||
      platform?.unfreeze_authorized !== false) {
    fail('platform integration is not frozen');
  } else ok('platform integration remains frozen without unfreeze authority');

  const document = fs.readFileSync(path.join(ctx.repo, DOCUMENT_PATH), 'utf8');
  const docNeedles = [
    'GPT M0 development audit is `PASS`',
    'only the B008 Candidate',
    '`NOT_YET_GRANTED`',
    'did not execute a real TRPG playtest',
    'not MVP Development Pass',
    'Production and release qualification are not granted',
    'No human-equivalence claim is made',
    'second-auditor production gate remains pending',
    'MODEL, HARNESS and IPC production gates remain unimplemented',
    '`FROZEN_WAITING_M1_ENGINE`',
    'No automatic M1, MVP, platform-integration or other next-batch authorization follows',
  ];
  const missingDocNeedles = docNeedles.filter((needle) => !document.includes(needle));
  if (missingDocNeedles.length > 0) {
    fail('human milestone document misses: ' + missingDocNeedles.join(', '));
  } else ok('human milestone document states every required non-inflation boundary');

  const lifecycleFacts = collectLifecycleFacts(ctx.repo);
  if (lifecycleFacts.baseCommit !== BASE_COMMIT || lifecycleFacts.baseTree !== BASE_TREE) {
    fail('fixed B008 base commit/tree does not resolve exactly');
  } else ok('fixed B008 base commit/tree resolves exactly');
  const lifecycle = validateLifecycle(lifecycleFacts);
  if (lifecycle.result === 'FAIL') {
    for (const problem of lifecycle.problems) fail('lifecycle: ' + problem);
  } else if (lifecycle.phase === 'CANDIDATE_PUSH') {
    ok('CANDIDATE_PUSH = PASS: exact task/ref binding, fixed-Base ancestry, zero merges and 15-path Candidate surface');
  } else if (lifecycle.phase === 'PULL_REQUEST_CHECK') {
    ok('PULL_REQUEST_CHECK = PASS: exact B008 PR head and ' + lifecycle.checkoutKind +
      ' topology; no implementation merge is recognized');
  } else {
    ok('POST_MERGE_MAIN = PASS: exact one-merge main topology, subject and Candidate tree');
  }

  const tracked = git(ctx.repo, ['diff', '--name-only', '--no-renames', BASE_COMMIT], { check: false });
  const untracked = git(ctx.repo, ['ls-files', '--others', '--exclude-standard'], { check: false });
  const changed = [...new Set([
    ...tracked.stdout.split('\n'),
    ...untracked.stdout.split('\n').filter((relative) => !isGeneratedWorktreeArtifact(relative)),
  ].filter(Boolean))].sort();
  for (const problem of validateChangedPaths(changed)) fail(problem);
  for (const relative of REQUIRED_CHANGED_PATHS) {
    if (!changed.includes(relative)) fail('required B008 Candidate path is absent: ' + relative);
  }
  if (changed.length === REQUIRED_CHANGED_PATHS.length &&
      changed.every((relative) => REQUIRED_CHANGED_PATHS.includes(relative))) {
    ok('changed-path set is the exact 15-path B008 Candidate surface');
  }

  for (const relative of FROZEN_FILES) {
    const base = git(ctx.repo, ['show', BASE_COMMIT + ':' + relative], { check: false });
    let current;
    try {
      current = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
    } catch (error) {
      fail('frozen file unreadable: ' + relative + ': ' + error.message);
      continue;
    }
    if (base.status !== 0 || base.stdout !== current) fail('frozen file changed: ' + relative);
  }
  if (!details.some((line) => line.startsWith('FAIL: frozen file'))) {
    ok('dependency, lock, toolchain and frozen authority files are byte-identical to Base');
  }

  const rawRecord = fs.readFileSync(path.join(ctx.repo, RECORD_PATH), 'utf8');
  const disclosurePatterns = [
    [/\/home\//, 'absolute local path'],
    [/file:\/\//i, 'local URI'],
    [/PRIVATE_REASONING/i, 'private reasoning marker'],
    [/\bsk-[A-Za-z0-9_-]{8,}\b/, 'credential-like marker'],
  ];
  for (const [pattern, label] of disclosurePatterns) {
    if (pattern.test(rawRecord)) fail('milestone record contains ' + label);
  }
  if (disclosurePatterns.every(([pattern]) => !pattern.test(rawRecord))) {
    ok('milestone record contains no local path, prompt/reasoning body or credential marker');
  }

  const probes = runNegativeProbes(record);
  const rejected = probes.filter(([, good]) => good).length;
  for (const [label, good] of probes) {
    if (!good) fail('negative probe was accepted: ' + label);
  }
  if (rejected === probes.length) ok('all ' + rejected + ' required negative probes reject');

  const lifecycleProbes = lifecycleRegressionProbes();
  const lifecycleProbeMatches = lifecycleProbes.filter((probe) => probe.matched).length;
  for (const probe of lifecycleProbes) {
    if (!probe.matched) {
      fail('lifecycle regression probe mismatched: ' + probe.label +
        ' (expected ' + probe.expected + ', got ' + probe.actual + '/' + probe.phase + ')');
    }
  }
  if (lifecycleProbeMatches === lifecycleProbes.length) {
    ok('all ' + lifecycleProbes.length + ' lifecycle topology/event/ref regression probes matched');
  }

  return {
    result: pass ? 'PASS' : 'FAIL',
    details,
    negative_probes: rejected === probes.length ? 'PASS' : 'FAIL',
    negative_probe_count: probes.length,
    lifecycle_phase: lifecycle.phase,
    lifecycle_checkout: lifecycle.checkoutKind,
    implementation_merge_recognized: lifecycle.implementationMergeRecognized,
    lifecycle_regression: lifecycleProbeMatches === lifecycleProbes.length ? 'PASS' : 'FAIL',
    lifecycle_probe_count: lifecycleProbes.length,
    changed_paths: changed,
  };
}

runAsMain(import.meta.url, 'm0-development-pass', run);
