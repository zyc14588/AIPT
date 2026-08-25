#!/usr/bin/env node
// AIPT-M0-B008 fail-closed M0 Development Pass final lifecycle validator.
// Node.js standard library only.
import fs from 'node:fs';
import path from 'node:path';
import {
  ALLOWED_PATHS, BASE_COMMIT, BASE_TREE, B007_CLOSEOUT,
  B007_EXTERNAL_SERIAL_PREDECESSOR, B007_IMPLEMENTATION_MERGE,
  B008_CANDIDATE_HISTORY, B008_FINAL_CANDIDATE, B008_IMPLEMENTATION_MERGE,
  B008_INITIAL_CANDIDATE, B008_LIFECYCLE_REPAIR,
  CLOSEOUT_ALLOWED_PATHS, FROZEN_REGISTRY_PATHS,
  CURRENT_BATCH, M0_CLOSEOUT, M0_HISTORICAL_PATHS,
  MVP_B000_ALLOWED_PATHS, MVP_B000_BASE_COMMIT, MVP_B000_BASE_TREE,
  MVP_B000_BRANCH, MVP_B000_NEXT_BATCH, MVP_B000_SNAPSHOT, STATUS_DATE,
  pathMatchesAllowed, pathMatchesCloseoutAllowed,
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
  'AIPT-M0-B008',
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
const CLOSEOUT_SUBJECT = 'closeout: complete AIPT-M0-B008';
const REQUIRED_CLOSEOUT_PATHS = [
  '.github/workflows/ci.yml',
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/milestones/M0.md',
  DOCUMENT_PATH,
  RECORD_PATH,
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/m0-development-pass.mjs',
  'scripts/ci/validate/standalone-entrypoints.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
  'scripts/ci/validate/workflow.mjs',
];
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
  record_state: 'M0_DEVELOPMENT_PASS_EFFECTIVE',
  authority: {
    gpt_stage_b_directive: 'AIPT-M0-B008-GPT-PASS-AND-FINALIZE-001',
    merge_directive: 'AIPT-M0-B008-MERGE-001',
    closeout_directive: 'AIPT-M0-B008-CLOSEOUT-001',
    authorization_scope: 'FINALIZE_M0_DEVELOPMENT_PASS',
    branch: 'main',
  },
  lifecycle: {
    construction: 'IDLE_WAITING_NEXT_BATCH',
    current_batch: 'NO_ACTIVE_BATCH',
    global_wip: 0,
    batch_history: Object.fromEntries(CLOSED_BATCH_IDS.map((id) => [id, 'MERGED_CLOSED'])),
    next_serial_batch: 'NONE',
    next_batch_state: 'NOT_AUTHORIZED',
    next_batch_authorized: false,
    next_batch_started: false,
  },
  milestone_state: {
    gpt_audit: 'PASS',
    m0_development_pass: 'GRANTED',
  },
  result: {
    result: 'M0_DEVELOPMENT_PASS',
    effective_status: 'GRANTED',
    effective_condition: 'AIPT-M0-B008_MERGED_CLOSED',
    effective_condition_satisfied: true,
  },
  source_bindings: {
    aipt: {
      audited_product_implementation: {
        commit: B007_IMPLEMENTATION_MERGE.commit,
        tree: B007_IMPLEMENTATION_MERGE.tree,
      },
      source_b007_closeout: { commit: B007_CLOSEOUT.commit, tree: B007_CLOSEOUT.tree },
      b008_initial_candidate: { commit: B008_INITIAL_CANDIDATE.commit },
      b008_final_candidate: {
        commit: B008_FINAL_CANDIDATE.commit,
        tree: B008_FINAL_CANDIDATE.tree,
        ci_run: B008_FINAL_CANDIDATE.ci_run,
        ci_conclusion: B008_FINAL_CANDIDATE.ci_conclusion,
      },
      b008_lifecycle_repair: {
        finding: B008_LIFECYCLE_REPAIR.finding,
        status: B008_LIFECYCLE_REPAIR.status,
        commit: B008_LIFECYCLE_REPAIR.commit,
        parent: B008_LIFECYCLE_REPAIR.parent,
        changed_paths: B008_LIFECYCLE_REPAIR.changed_paths,
      },
      b008_milestone_implementation: {
        commit: B008_IMPLEMENTATION_MERGE.commit,
        tree: B008_IMPLEMENTATION_MERGE.tree,
        parents: [B008_IMPLEMENTATION_MERGE.parent1, B008_IMPLEMENTATION_MERGE.parent2],
        subject: B008_IMPLEMENTATION_MERGE.subject,
        post_merge_ci_run: B008_IMPLEMENTATION_MERGE.post_merge_ci_run,
        post_merge_ci_conclusion: B008_IMPLEMENTATION_MERGE.post_merge_ci_conclusion,
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
    closed_lifecycle_findings: [B008_LIFECYCLE_REPAIR.finding],
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

function validateCloseoutPaths(changed) {
  const problems = [];
  if (!exactStringSet(changed, REQUIRED_CLOSEOUT_PATHS)) {
    problems.push('implementation-merge-to-closeout changed paths are not the exact 14-path surface');
  }
  if (!exactStringSet(CLOSEOUT_ALLOWED_PATHS, REQUIRED_CLOSEOUT_PATHS)) {
    problems.push('shared closeout allowlist is not the exact 14-path surface');
  }
  for (const relative of changed ?? []) {
    if (!pathMatchesCloseoutAllowed(relative)) problems.push('path outside B008 closeout scope: ' + relative);
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
  const descendantProbe = soleMerge
    ? git(repo, [
        'rev-list', '--reverse', '--ancestry-path', '--parents', soleMerge.commit + '..HEAD',
      ], { check: false })
    : { status: 0, stdout: '' };
  const ordinaryDescendants = descendantProbe.status === 0
    ? descendantProbe.stdout.split('\n').filter(Boolean).map((line) => {
        const parts = line.trim().split(/\s+/);
        return readCommit(repo, parts[0]);
      })
    : null;
  const closeoutPathsProbe = soleMerge && head && head !== soleMerge.commit
    ? git(repo, ['diff', '--name-only', '--no-renames', soleMerge.commit, head], { check: false })
    : { status: 0, stdout: '' };
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
    headCommit,
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
      sha: normalizedEnv(env.GITHUB_SHA),
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
    ordinaryDescendants,
    closeoutChangedPaths: linesFrom(closeoutPathsProbe)?.sort() ?? null,
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
    if (github.sha !== facts.head) problems.push('GITHUB_SHA is not the checked-out HEAD');
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
        phase = Array.isArray(facts.mergeCommits) && facts.mergeCommits.length === 1 &&
          facts.merge?.commit !== facts.head ? 'CLOSEOUT_MAIN' : 'POST_MERGE_MAIN';
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
    if (Array.isArray(facts.mergeCommits) && facts.mergeCommits.length === 1 &&
        facts.merge?.commit === facts.head) {
      phase = 'POST_MERGE_MAIN';
    } else {
      problems.push('local main is not the exact post-merge implementation commit');
    }
  } else if (facts.branch === null) {
    if (Array.isArray(facts.mergeCommits) && facts.mergeCommits.length === 0 &&
        facts.head === B008_FINAL_CANDIDATE.commit) {
      phase = 'CANDIDATE_PUSH';
    } else if (Array.isArray(facts.mergeCommits) && facts.mergeCommits.length === 1 &&
        facts.merge?.commit === facts.head &&
        facts.merge?.commit === B008_IMPLEMENTATION_MERGE.commit) {
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
  let m0DevelopmentPassEffective = false;
  const mergeCommits = facts?.mergeCommits;

  if (facts?.baseCommit !== BASE_COMMIT) problems.push('fixed Base commit does not resolve exactly');
  if (facts?.baseTree !== BASE_TREE) problems.push('fixed Base tree does not resolve exactly');
  if (!isGitObjectId(facts?.head)) problems.push('HEAD commit identity is unreadable');
  if (!isGitObjectId(facts?.headTree)) problems.push('HEAD tree identity is unreadable');
  if (facts?.ancestryKnown !== true) problems.push('HEAD ancestry is unreadable');
  if (facts?.baseIsAncestor !== true) problems.push('HEAD does not descend from fixed Base');

  const validateCandidateLineage = ({ mustBeHead = false } = {}) => {
    if (!isGitObjectId(facts.candidateTip)) problems.push('Candidate tip identity is unreadable');
    if (!isGitObjectId(facts.candidateTree)) problems.push('Candidate tree identity is unreadable');
    if (facts.candidateTip !== B008_FINAL_CANDIDATE.commit) {
      problems.push('Candidate tip is not the frozen B008 final Candidate');
    }
    if (facts.candidateTree !== B008_FINAL_CANDIDATE.tree) {
      problems.push('Candidate tree is not the frozen B008 final Candidate tree');
    }
    if (mustBeHead && facts.candidateTip !== facts.head) problems.push('Candidate tip is not HEAD');
    if (facts.candidateDescendsFromBase !== true) problems.push('Candidate lineage does not descend from fixed Base');
    if (!Array.isArray(facts.candidateMergeCommits)) {
      problems.push('Candidate merge list is unreadable');
    } else if (facts.candidateMergeCommits.length !== 0) {
      problems.push('Candidate lineage contains a merge commit');
    }
    if (mustBeHead && facts.candidateTree !== facts.headTree) {
      problems.push('Candidate tree is not the checked-out HEAD tree');
    }
  };
  const validateCandidateContract = () => {
    if (!exactStringSet(facts.candidateChangedPaths, REQUIRED_CHANGED_PATHS)) {
      problems.push('Base-to-Candidate changed-path contract is not the exact 15-path B008 surface');
    }
  };
  const validateSyntheticPrMerge = () => {
    const merge = facts.merge;
    if (!merge || typeof merge !== 'object') {
      problems.push('lifecycle merge facts are missing');
      return;
    }
    if (!isGitObjectId(merge.commit)) problems.push('lifecycle merge identity is unreadable');
    if (!isGitObjectId(merge.tree)) problems.push('lifecycle merge tree identity is unreadable');
    if (!isGitObjectId(facts.candidateTip)) problems.push('Candidate parent identity is unreadable');
    if (!isGitObjectId(facts.candidateTree)) problems.push('Candidate parent tree identity is unreadable');
    if (merge.commit !== facts.head) problems.push('PR synthetic merge is not current HEAD');
    if (!Array.isArray(merge.parents) || merge.parents.length !== 2) {
      problems.push('lifecycle merge does not have exactly two parents');
      return;
    }
    if (merge.parents[0] !== BASE_COMMIT) problems.push('PR synthetic merge first parent is not fixed Base/main');
    if (merge.parents[1] !== facts.candidateTip) problems.push('PR synthetic merge second parent is not Candidate tip');
    validateCandidateLineage();
    if (merge.tree !== facts.candidateTree) problems.push('PR synthetic merge tree does not equal Candidate tree');
    if (merge.treeDiffQuiet !== true) problems.push('PR synthetic merge introduces a tree delta from Candidate');
    if (facts.headTree !== merge.tree) problems.push('PR synthetic checkout tree does not equal merge tree');
  };
  const validateImplementationMerge = () => {
    const merge = facts.merge;
    if (!merge || typeof merge !== 'object') {
      problems.push('implementation merge facts are missing');
      return;
    }
    if (merge.commit !== B008_IMPLEMENTATION_MERGE.commit) {
      problems.push('implementation merge identity is not exact');
    }
    if (!Array.isArray(merge.parents) || merge.parents.length !== 2) {
      problems.push('implementation merge does not have exactly two parents');
      return;
    }
    if (merge.parents[0] !== B008_IMPLEMENTATION_MERGE.parent1) {
      problems.push('implementation merge first parent is not fixed Base');
    }
    if (merge.parents[1] !== B008_IMPLEMENTATION_MERGE.parent2) {
      problems.push('implementation merge second parent is not frozen Candidate');
    }
    if (merge.tree !== B008_IMPLEMENTATION_MERGE.tree) {
      problems.push('implementation merge tree is not exact');
    }
    if (merge.subject !== B008_IMPLEMENTATION_MERGE.subject) {
      problems.push('implementation merge subject is not exact');
    }
    validateCandidateLineage();
    if (merge.tree !== facts.candidateTree) {
      problems.push('implementation merge tree does not equal Candidate tree');
    }
    if (merge.treeDiffQuiet !== true) {
      problems.push('implementation merge introduces a tree delta from Candidate');
    }
  };

  if (phase === 'CANDIDATE_PUSH') {
    checkoutKind = 'CANDIDATE_HEAD';
    if (!Array.isArray(mergeCommits)) problems.push('post-base merge list is unreadable');
    else if (mergeCommits.length !== 0) problems.push('Candidate history must contain zero post-base merges');
    validateCandidateLineage({ mustBeHead: true });
    validateCandidateContract();
  } else if (phase === 'PULL_REQUEST_CHECK') {
    if (!Array.isArray(mergeCommits)) {
      problems.push('post-base merge list is unreadable');
    } else if (mergeCommits.length === 0) {
      checkoutKind = 'PR_HEAD';
      validateCandidateLineage({ mustBeHead: true });
      validateCandidateContract();
    } else if (mergeCommits.length === 1) {
      checkoutKind = 'PR_SYNTHETIC_MERGE';
      if (facts.branch !== null) problems.push('PR synthetic merge checkout must be detached');
      if (mergeCommits[0] !== facts.head) problems.push('PR synthetic merge must be current HEAD');
      validateSyntheticPrMerge();
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
      if (mergeCommits[0] !== B008_IMPLEMENTATION_MERGE.commit) {
        problems.push('post-base merge is not the frozen implementation merge');
      }
      if (facts.head !== B008_IMPLEMENTATION_MERGE.commit) {
        problems.push('implementation merge must be current HEAD');
      }
      if (!Array.isArray(facts.ordinaryDescendants) || facts.ordinaryDescendants.length !== 0) {
        problems.push('post-merge main must have no ordinary descendant');
      }
      validateImplementationMerge();
      validateCandidateContract();
      implementationMergeRecognized = problems.length === 0;
    }
  } else if (phase === 'CLOSEOUT_MAIN') {
    checkoutKind = 'FINAL_CLOSEOUT';
    if (!facts.github?.present || facts.github.eventName !== 'push' ||
        facts.github.ref !== 'refs/heads/' + MAIN_BRANCH) {
      problems.push('closeout requires an exact GitHub main push binding');
    }
    if (!Array.isArray(mergeCommits)) {
      problems.push('post-base merge list is unreadable');
    } else if (mergeCommits.length !== 1) {
      problems.push('closeout main must contain exactly one implementation merge');
    } else {
      if (mergeCommits[0] !== B008_IMPLEMENTATION_MERGE.commit) {
        problems.push('closeout history does not contain the exact implementation merge');
      }
      validateImplementationMerge();
      validateCandidateContract();
    }
    if (!Array.isArray(facts.ordinaryDescendants) || facts.ordinaryDescendants.length !== 1) {
      problems.push('closeout main must contain exactly one ordinary descendant of the implementation merge');
    }
    const closeout = facts.headCommit;
    if (!closeout || closeout.commit !== facts.head) {
      problems.push('closeout HEAD commit facts are unreadable');
    } else {
      if (!Array.isArray(closeout.parents) || closeout.parents.length !== 1) {
        problems.push('closeout must be an ordinary single-parent commit');
      } else if (closeout.parents[0] !== B008_IMPLEMENTATION_MERGE.commit) {
        problems.push('closeout parent is not the exact implementation merge');
      }
      if (closeout.subject !== CLOSEOUT_SUBJECT) problems.push('closeout subject is not exact');
    }
    if (Array.isArray(facts.ordinaryDescendants) && facts.ordinaryDescendants.length === 1 &&
        facts.ordinaryDescendants[0]?.commit !== facts.head) {
      problems.push('sole ordinary descendant is not current closeout HEAD');
    }
    for (const problem of validateCloseoutPaths(facts.closeoutChangedPaths)) problems.push(problem);
    implementationMergeRecognized = problems.length === 0;
    m0DevelopmentPassEffective = problems.length === 0;
  } else {
    problems.push('lifecycle phase is not uniquely classified');
  }

  return {
    result: problems.length === 0 ? 'PASS' : 'FAIL',
    phase,
    checkoutKind,
    implementationMergeRecognized,
    m0DevelopmentPassEffective,
    problems,
  };
}

function lifecycleRegressionProbes() {
  const candidateId = B008_FINAL_CANDIDATE.commit;
  const candidateTree = B008_FINAL_CANDIDATE.tree;
  const syntheticId = 'e'.repeat(40);
  const implementationId = B008_IMPLEMENTATION_MERGE.commit;
  const closeoutId = 'f'.repeat(40);
  const githubLocal = {
    present: false, eventName: null, ref: null, headRef: null, baseRef: null, sha: null,
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
    headCommit: {
      commit: candidateId,
      parents: [B008_LIFECYCLE_REPAIR.parent],
      tree: candidateTree,
      subject: 'fix(ci): support B008 milestone validator lifecycle',
    },
    mergeCommits: [],
    merge: null,
    candidateTip: candidateId,
    candidateTree,
    candidateDescendsFromBase: true,
    candidateMergeCommits: [],
    candidateChangedPaths: [...REQUIRED_CHANGED_PATHS],
    ordinaryDescendants: [],
    closeoutChangedPaths: [],
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
      sha: syntheticId,
    },
    headCommit: {
      commit: syntheticId,
      parents: [BASE_COMMIT, candidateId],
      tree: candidateTree,
      subject: 'Merge candidate-tip into main',
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
    headCommit: {
      commit: implementationId,
      parents: [B008_IMPLEMENTATION_MERGE.parent1, B008_IMPLEMENTATION_MERGE.parent2],
      tree: B008_IMPLEMENTATION_MERGE.tree,
      subject: B008_IMPLEMENTATION_MERGE.subject,
    },
    mergeCommits: [implementationId],
    merge: {
      ...syntheticMerge.merge,
      commit: implementationId,
      parents: [B008_IMPLEMENTATION_MERGE.parent1, B008_IMPLEMENTATION_MERGE.parent2],
      tree: B008_IMPLEMENTATION_MERGE.tree,
      subject: B008_IMPLEMENTATION_MERGE.subject,
    },
    ordinaryDescendants: [],
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
      sha: candidateId,
    },
  };
  const closeoutCommit = {
    commit: closeoutId,
    parents: [implementationId],
    tree: '1'.repeat(40),
    subject: CLOSEOUT_SUBJECT,
  };
  const closeout = {
    ...clone(implementationMerge),
    head: closeoutId,
    headTree: closeoutCommit.tree,
    headCommit: closeoutCommit,
    branch: null,
    github: {
      present: true,
      eventName: 'push',
      ref: 'refs/heads/' + MAIN_BRANCH,
      headRef: null,
      baseRef: null,
      sha: closeoutId,
    },
    ordinaryDescendants: [closeoutCommit],
    closeoutChangedPaths: [...REQUIRED_CLOSEOUT_PATHS],
  };
  const probes = [
    ['task branch + zero merge Candidate', candidate, 'PASS', 'CANDIDATE_PUSH', false],
    ['exact Candidate GitHub push', {
      ...clone(candidate), branch: null, github: {
        present: true, eventName: 'push', ref: 'refs/heads/' + TASK_BRANCH,
        headRef: null, baseRef: null, sha: candidateId,
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
        headRef: null, baseRef: null, sha: implementationId,
      },
    }, 'PASS', 'POST_MERGE_MAIN', true],
    ['valid exact closeout main', closeout, 'PASS', 'CLOSEOUT_MAIN', true, true],
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
    ['wrong closeout parent', {
      ...clone(closeout),
      headCommit: { ...closeout.headCommit, parents: ['a'.repeat(40)] },
      ordinaryDescendants: [{ ...closeout.headCommit, parents: ['a'.repeat(40)] }],
    }, 'FAIL'],
    ['closeout has two parents', {
      ...clone(closeout),
      headCommit: { ...closeout.headCommit, parents: [implementationId, candidateId] },
      ordinaryDescendants: [
        { ...closeout.headCommit, parents: [implementationId, candidateId] },
      ],
    }, 'FAIL'],
    ['wrong closeout subject', {
      ...clone(closeout),
      headCommit: { ...closeout.headCommit, subject: 'closeout: wrong' },
      ordinaryDescendants: [{ ...closeout.headCommit, subject: 'closeout: wrong' }],
    }, 'FAIL'],
    ['second ordinary descendant', {
      ...clone(closeout),
      head: '2'.repeat(40),
      headTree: '3'.repeat(40),
      headCommit: {
        commit: '2'.repeat(40), parents: [closeoutId], tree: '3'.repeat(40),
        subject: 'docs: unauthorized descendant',
      },
      github: { ...closeout.github, sha: '2'.repeat(40) },
      ordinaryDescendants: [
        closeoutCommit,
        {
          commit: '2'.repeat(40), parents: [closeoutId], tree: '3'.repeat(40),
          subject: 'docs: unauthorized descendant',
        },
      ],
    }, 'FAIL'],
    ['closeout path outside exact allowlist', {
      ...clone(closeout), closeoutChangedPaths: [...REQUIRED_CLOSEOUT_PATHS, 'package.json'],
    }, 'FAIL'],
  ];
  return probes.map(([label, facts, expected, expectedPhase, expectedRecognized,
    expectedEffective]) => {
    const actual = validateLifecycle(facts);
    const matched = actual.result === expected &&
      (expectedPhase === undefined || actual.phase === expectedPhase) &&
      (expectedRecognized === undefined ||
        actual.implementationMergeRecognized === expectedRecognized) &&
      (expectedEffective === undefined ||
        actual.m0DevelopmentPassEffective === expectedEffective);
    return { label, expected, actual: actual.result, phase: actual.phase, matched };
  });
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function lifecycleSemanticsFromRecord(record) {
  return {
    recordState: record?.record_state,
    effectiveStatus: record?.result?.effective_status,
    developmentPass: record?.milestone_state?.m0_development_pass,
    b008: record?.lifecycle?.batch_history?.['AIPT-M0-B008'],
    globalWip: record?.lifecycle?.global_wip,
    nextSerialBatch: record?.lifecycle?.next_serial_batch,
    nextBatchAuthorized: record?.lifecycle?.next_batch_authorized,
    nextBatchStarted: record?.lifecycle?.next_batch_started,
    boundaries: record?.boundaries,
  };
}

function validateLifecycleSemantics(state, phase) {
  const problems = [];
  const closeout = phase === 'CLOSEOUT_MAIN';
  if (closeout) {
    if (state.recordState !== 'M0_DEVELOPMENT_PASS_EFFECTIVE') {
      problems.push('closeout record is not effective');
    }
    if (state.effectiveStatus !== 'GRANTED' || state.developmentPass !== 'GRANTED') {
      problems.push('closeout M0 Development Pass is not granted');
    }
    if (state.b008 !== 'MERGED_CLOSED' || state.globalWip !== 0) {
      problems.push('closeout batch lifecycle is not closed/WIP0');
    }
  } else {
    if (state.recordState !== 'CANDIDATE_PROPOSAL') {
      problems.push('pre-closeout record is not a Candidate proposal');
    }
    if (state.effectiveStatus !== 'NOT_YET_GRANTED' ||
        state.developmentPass !== 'PROPOSED_PENDING_B008_MERGED_CLOSED') {
      problems.push('pre-closeout M0 Development Pass became effective early');
    }
    if (state.b008 !== 'IN_PROGRESS' || state.globalWip !== 1) {
      problems.push('pre-closeout B008 lifecycle is not IN_PROGRESS/WIP1');
    }
  }
  if (state.nextSerialBatch !== 'NONE' || state.nextBatchAuthorized !== false ||
      state.nextBatchStarted !== false) {
    problems.push('next batch was introduced or authorized');
  }
  const boundaries = state.boundaries ?? {};
  if (boundaries.production_qualification !== 'NOT_GRANTED' ||
      boundaries.release_qualification !== 'NOT_GRANTED' ||
      boundaries.mvp_development_pass !== 'NOT_GRANTED' ||
      boundaries.human_equivalence !== 'NOT_CLAIMED' ||
      boundaries.real_playtest_completion !== 'NOT_CLAIMED') {
    problems.push('non-inflation qualification boundary was elevated');
  }
  if (boundaries.platform_integration !== 'FROZEN_WAITING_M1_ENGINE') {
    problems.push('platform integration was unfrozen');
  }
  if (boundaries.automatic_next_batch !== 'NONE') {
    problems.push('automatic next batch is not NONE');
  }
  return problems;
}

function lifecycleSemanticsRegressionProbes(record) {
  const finalState = lifecycleSemanticsFromRecord(record);
  const preCloseout = {
    ...clone(finalState),
    recordState: 'CANDIDATE_PROPOSAL',
    effectiveStatus: 'NOT_YET_GRANTED',
    developmentPass: 'PROPOSED_PENDING_B008_MERGED_CLOSED',
    b008: 'IN_PROGRESS',
    globalWip: 1,
  };
  const probes = [
    ['Candidate proposal stays not effective', preCloseout, 'CANDIDATE_PUSH', true],
    ['PR proposal stays not effective', preCloseout, 'PULL_REQUEST_CHECK', true],
    ['post-merge proposal stays not effective', preCloseout, 'POST_MERGE_MAIN', true],
    ['exact closeout becomes effective', finalState, 'CLOSEOUT_MAIN', true],
    ['Candidate phase prematurely GRANTED', {
      ...clone(preCloseout), effectiveStatus: 'GRANTED', developmentPass: 'GRANTED',
    }, 'CANDIDATE_PUSH', false],
    ['closeout remains NOT_YET_GRANTED', {
      ...clone(finalState), effectiveStatus: 'NOT_YET_GRANTED',
    }, 'CLOSEOUT_MAIN', false],
    ['next batch added', {
      ...clone(finalState), nextSerialBatch: 'AIPT-M1-B000', nextBatchAuthorized: true,
    }, 'CLOSEOUT_MAIN', false],
    ['production boundary elevated', {
      ...clone(finalState), boundaries: {
        ...finalState.boundaries, production_qualification: 'GRANTED',
      },
    }, 'CLOSEOUT_MAIN', false],
    ['release boundary elevated', {
      ...clone(finalState), boundaries: {
        ...finalState.boundaries, release_qualification: 'GRANTED',
      },
    }, 'CLOSEOUT_MAIN', false],
    ['MVP boundary elevated', {
      ...clone(finalState), boundaries: {
        ...finalState.boundaries, mvp_development_pass: 'GRANTED',
      },
    }, 'CLOSEOUT_MAIN', false],
    ['human equivalence claimed', {
      ...clone(finalState), boundaries: {
        ...finalState.boundaries, human_equivalence: 'CLAIMED',
      },
    }, 'CLOSEOUT_MAIN', false],
    ['platform integration unfrozen', {
      ...clone(finalState), boundaries: {
        ...finalState.boundaries, platform_integration: 'UNFROZEN',
      },
    }, 'CLOSEOUT_MAIN', false],
  ];
  return probes.map(([label, state, phase, shouldPass]) => {
    const passed = validateLifecycleSemantics(state, phase).length === 0;
    return { label, matched: passed === shouldPass };
  });
}

function runNegativeProbes(record) {
  const probes = [
    ['AUDIT_READY root drift', (r) => { r.audit_binding.audit_ready_root_sha256 = '0'.repeat(64); }],
    ['audit archive digest drift', (r) => { r.audit_binding.audit_ready_archive_sha256 = '0'.repeat(64); }],
    ['GPT audit digest drift', (r) => { r.audit_binding.gpt_audit_result_sha256 = '0'.repeat(64); }],
    ['Integration root drift', (r) => { r.source_bindings.integration.root_sha256 = '0'.repeat(64); }],
    ['missing closed finding', (r) => { r.audit_binding.closed_stage_a_r1_findings.pop(); }],
    ['missing closed lifecycle finding', (r) => { r.audit_binding.closed_lifecycle_findings.pop(); }],
    ['GPT result changed from PASS', (r) => { r.audit_binding.gpt_result = 'FAIL'; }],
    ['production qualification granted', (r) => { r.boundaries.production_qualification = 'GRANTED'; }],
    ['release qualification granted', (r) => { r.boundaries.release_qualification = 'GRANTED'; }],
    ['MVP Development Pass granted', (r) => { r.boundaries.mvp_development_pass = 'GRANTED'; }],
    ['human equivalence claimed', (r) => { r.boundaries.human_equivalence = 'CLAIMED'; }],
    ['real playtest claimed', (r) => { r.boundaries.real_playtest_completion = 'CLAIMED'; }],
    ['platform integration unfrozen', (r) => { r.boundaries.platform_integration = 'UNFROZEN'; }],
    ['B008 closeout reopened', (r) => { r.lifecycle.batch_history['AIPT-M0-B008'] = 'IN_PROGRESS'; }],
    ['effective M0 pass revoked after closeout', (r) => { r.result.effective_status = 'NOT_YET_GRANTED'; }],
    ['record reverted to Candidate proposal', (r) => { r.record_state = 'CANDIDATE_PROPOSAL'; }],
    ['GLOBAL_WIP restored', (r) => { r.lifecycle.global_wip = 1; }],
    ['next batch authorized', (r) => { r.lifecycle.next_batch_authorized = true; }],
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

function normalizedSuccessorEnv(value) {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : null;
}

function isExactMvpB000Checkout(repo) {
  const branch = git(repo, ['symbolic-ref', '--short', 'HEAD'], { check: false });
  return branch.stdout.trim() === MVP_B000_BRANCH ||
    normalizedSuccessorEnv(process.env.GITHUB_REF) === `refs/heads/${MVP_B000_BRANCH}`;
}

function expectedMvpHistory() {
  const future = [
    'AIPT-MVP-B000', 'AIPT-MVP-B001', 'UNREGISTERED-AIPT-P1-B000',
    'AIPT-MVP-B002', 'AIPT-MVP-B003', 'AIPT-MVP-B004',
    'INT-AIPT-UNREGISTERED-MVP-001', 'AIPT-MVP-B005', 'AIPT-MVP-B006',
    'AIPT-MVP-B007', 'AIPT-MVP-B008', 'AIPT-MVP-B009', 'AIPT-MVP-B010',
  ];
  return Object.fromEntries([
    ...CLOSED_BATCH_IDS.map((id) => [id, 'MERGED_CLOSED']),
    ...future.map((id, index) => [id, index === 0 ? 'IN_PROGRESS' : 'NOT_STARTED']),
  ]);
}

function validatePostM0SuccessorStatus(status, baseStatus) {
  const expected = {
    ...baseStatus,
    as_of: STATUS_DATE,
    authority_snapshot_id: MVP_B000_SNAPSHOT,
    tracks: {
      'AIPT-STANDALONE': {
        ...baseStatus.tracks['AIPT-STANDALONE'],
        construction: 'IN_PROGRESS',
        current_batch: CURRENT_BATCH,
        next_serial_batch: MVP_B000_NEXT_BATCH,
        next_batch_state: 'NOT_AUTHORIZED',
        next_batch_authorized: false,
        next_batch_started: false,
        batch_history: expectedMvpHistory(),
        global_wip: 1,
      },
      'AIPT-PLATFORM-INTEGRATION': baseStatus.tracks['AIPT-PLATFORM-INTEGRATION'],
    },
    repositories: {
      AIPT: {
        ...baseStatus.repositories.AIPT,
        pending_candidate: {
          milestone: 'MVP',
          task_id: CURRENT_BATCH,
          authority: 'AIPT-MVP-B000-START-001',
          branch: MVP_B000_BRANCH,
          base_commit: MVP_B000_BASE_COMMIT,
          base_tree: MVP_B000_BASE_TREE,
          state: 'IN_PROGRESS',
          scope: 'GOVERNANCE_BOOTSTRAP_ONLY',
          merge_authorized: false,
          closeout_authorized: false,
        },
      },
      UNREGISTERED: baseStatus.repositories.UNREGISTERED,
    },
  };
  return compareExact(status, expected, '$status');
}

function collectPostM0ChangedPaths(repo) {
  const tracked = git(repo, [
    'diff', '--name-only', '--no-renames', MVP_B000_BASE_COMMIT,
  ], { check: false });
  const untracked = git(repo, ['ls-files', '--others', '--exclude-standard'], { check: false });
  if (tracked.status !== 0 || untracked.status !== 0) return null;
  return [...new Set([
    ...tracked.stdout.split('\n'),
    ...untracked.stdout.split('\n').filter((relative) =>
      relative && !isGeneratedWorktreeArtifact(relative)),
  ].filter(Boolean))].sort();
}

function runPostM0Successor(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => { pass = false; details.push('FAIL: ' + message); };
  let record;
  let status;
  let baseStatus;
  try {
    record = readJson(ctx.repo, RECORD_PATH);
    status = readJson(ctx.repo, STATUS_PATH);
    const baseStatusProbe = git(ctx.repo, [
      'show', `${MVP_B000_BASE_COMMIT}:${STATUS_PATH}`,
    ], { check: false });
    if (baseStatusProbe.status !== 0) throw new Error('M0 closeout project status is unavailable');
    baseStatus = JSON.parse(baseStatusProbe.stdout);
  } catch (error) {
    fail('M0 record or post-M0 status is unreadable: ' + error.message);
    return { result: 'FAIL', details, negative_probes: 'NOT_RUN' };
  }

  const recordProblems = validateRecord(record);
  for (const problem of recordProblems) fail('record: ' + problem);
  if (recordProblems.length === 0) {
    ok('immutable M0 Development Pass record, audit and integration bindings remain exact');
  }

  const statusProblems = validatePostM0SuccessorStatus(status, baseStatus);
  for (const problem of statusProblems) fail('post-M0 successor status: ' + problem);
  if (statusProblems.length === 0) {
    ok('exact AIPT-MVP-B000 successor preserves M0 and rejects every arbitrary future batch name');
  }

  const baseCommit = git(ctx.repo, ['rev-parse', `${MVP_B000_BASE_COMMIT}^{commit}`], { check: false });
  const baseTree = git(ctx.repo, ['rev-parse', `${MVP_B000_BASE_COMMIT}^{tree}`], { check: false });
  const head = git(ctx.repo, ['rev-parse', 'HEAD^{commit}'], { check: false });
  const branch = git(ctx.repo, ['symbolic-ref', '--short', 'HEAD'], { check: false });
  const ancestry = git(ctx.repo, [
    'merge-base', '--is-ancestor', MVP_B000_BASE_COMMIT, 'HEAD',
  ], { check: false });
  const merges = git(ctx.repo, [
    'rev-list', '--merges', `${MVP_B000_BASE_COMMIT}..HEAD`,
  ], { check: false });
  const subjects = git(ctx.repo, [
    'log', '--format=%s', `${MVP_B000_BASE_COMMIT}..HEAD`,
  ], { check: false }).stdout.split('\n').filter(Boolean);
  const githubPresent = ['GITHUB_ACTIONS', 'GITHUB_EVENT_NAME', 'GITHUB_REF', 'GITHUB_SHA']
    .some((key) => Object.hasOwn(process.env, key));
  const exactLocal = !githubPresent && branch.stdout.trim() === MVP_B000_BRANCH;
  const exactPush = githubPresent &&
    normalizedSuccessorEnv(process.env.GITHUB_EVENT_NAME) === 'push' &&
    normalizedSuccessorEnv(process.env.GITHUB_REF) === `refs/heads/${MVP_B000_BRANCH}` &&
    normalizedSuccessorEnv(process.env.GITHUB_SHA) === head.stdout.trim() &&
    normalizedSuccessorEnv(process.env.GITHUB_HEAD_REF) === null &&
    normalizedSuccessorEnv(process.env.GITHUB_BASE_REF) === null &&
    (branch.status !== 0 || branch.stdout.trim() === MVP_B000_BRANCH);
  if (baseCommit.stdout.trim() !== MVP_B000_BASE_COMMIT ||
      baseTree.stdout.trim() !== MVP_B000_BASE_TREE || ancestry.status !== 0 ||
      merges.status !== 0 || merges.stdout.trim() !== '' ||
      subjects.some((subject) => /^(?:merge|closeout):/i.test(subject)) ||
      (!exactLocal && !exactPush)) {
    fail('successor lifecycle is not the exact zero-merge task/AIPT-MVP-B000 Candidate');
  } else ok('post-M0 successor lifecycle is exact task branch, zero merge and no closeout claim');

  const closeoutParents = git(ctx.repo, [
    'rev-list', '--parents', '-n', '1', M0_CLOSEOUT.commit,
  ], { check: false });
  const closeoutTree = git(ctx.repo, ['rev-parse', `${M0_CLOSEOUT.commit}^{tree}`], { check: false });
  const closeoutSubject = git(ctx.repo, [
    'show', '-s', '--format=%s', M0_CLOSEOUT.commit,
  ], { check: false });
  const b008Parents = git(ctx.repo, [
    'rev-list', '--parents', '-n', '1', B008_IMPLEMENTATION_MERGE.commit,
  ], { check: false });
  const b008Tree = git(ctx.repo, [
    'rev-parse', `${B008_IMPLEMENTATION_MERGE.commit}^{tree}`,
  ], { check: false });
  const b008Subject = git(ctx.repo, [
    'show', '-s', '--format=%s', B008_IMPLEMENTATION_MERGE.commit,
  ], { check: false });
  const b008History = git(ctx.repo, [
    'rev-list', '--reverse', BASE_COMMIT + '..' + B008_FINAL_CANDIDATE.commit,
  ], { check: false });
  const b008RepairPaths = git(ctx.repo, [
    'diff', '--name-only', '--no-renames', B008_LIFECYCLE_REPAIR.parent,
    B008_LIFECYCLE_REPAIR.commit,
  ], { check: false });
  if (closeoutParents.stdout.trim() !== `${M0_CLOSEOUT.commit} ${M0_CLOSEOUT.parent}` ||
      closeoutTree.stdout.trim() !== M0_CLOSEOUT.tree ||
      closeoutSubject.stdout.trim() !== M0_CLOSEOUT.subject ||
      b008Parents.stdout.trim() !== `${B008_IMPLEMENTATION_MERGE.commit} ${B008_IMPLEMENTATION_MERGE.parent1} ${B008_IMPLEMENTATION_MERGE.parent2}` ||
      b008Tree.stdout.trim() !== B008_IMPLEMENTATION_MERGE.tree ||
      b008Subject.stdout.trim() !== B008_IMPLEMENTATION_MERGE.subject ||
      JSON.stringify(b008History.stdout.split('\n').filter(Boolean)) !== JSON.stringify(B008_CANDIDATE_HISTORY) ||
      !exactStringSet(b008RepairPaths.stdout.split('\n').filter(Boolean), B008_LIFECYCLE_REPAIR.changed_paths)) {
    fail('B008 final Candidate/merge/repair or M0 closeout topology drifted');
  } else ok('B008 final Candidate/merge/repair and M0 closeout identities remain immutable');

  const changed = collectPostM0ChangedPaths(ctx.repo);
  if (!changed || !exactStringSet(changed, MVP_B000_ALLOWED_PATHS)) {
    fail('post-M0 successor changed paths are not the exact 17-path B000 surface');
  } else ok('post-M0 successor changed paths are the exact governance/CI-only surface');

  for (const relative of [...FROZEN_FILES, ...M0_HISTORICAL_PATHS]) {
    const base = git(ctx.repo, ['show', `${MVP_B000_BASE_COMMIT}:${relative}`], { check: false });
    let current;
    try {
      current = fs.readFileSync(path.join(ctx.repo, relative), 'utf8');
    } catch (error) {
      fail(`frozen successor file unreadable: ${relative}: ${error.message}`);
      continue;
    }
    if (base.status !== 0 || base.stdout !== current) fail('frozen successor file changed: ' + relative);
  }
  if (!details.some((line) => line.startsWith('FAIL: frozen successor file'))) {
    ok('M0 milestone, dependency, toolchain and frozen registry files remain byte-identical');
  }

  const semanticProblems = validateLifecycleSemantics(
    lifecycleSemanticsFromRecord(record), 'CLOSEOUT_MAIN',
  );
  for (const problem of semanticProblems) fail('effective M0 semantics: ' + problem);
  if (semanticProblems.length === 0) ok('M0 pass remains effective without qualification inflation');

  const recordProbes = runNegativeProbes(record);
  const statusProbeMutations = [
    ['B001 authorization', (copy) => { copy.tracks['AIPT-STANDALONE'].next_batch_authorized = true; }],
    ['arbitrary future batch', (copy) => { copy.tracks['AIPT-STANDALONE'].current_batch = 'AIPT-MVP-B002'; }],
    ['M0 pass revocation', (copy) => { copy.repositories.AIPT.verified_state.m0_development_pass.result = 'REVOKED'; }],
    ['platform unfreeze', (copy) => { copy.tracks['AIPT-PLATFORM-INTEGRATION'].status = 'UNFROZEN'; }],
    ['UNREGISTERED drift', (copy) => { copy.repositories.UNREGISTERED.verified_head = '0'.repeat(40); }],
  ];
  const statusProbes = statusProbeMutations.map(([label, mutate]) => {
    const copy = clone(status);
    mutate(copy);
    return [label, validatePostM0SuccessorStatus(copy, baseStatus).length > 0];
  });
  const negativeProbes = [...recordProbes, ...statusProbes];
  for (const [label, rejected] of negativeProbes) if (!rejected) fail('negative probe accepted: ' + label);
  const rejected = negativeProbes.filter(([, value]) => value).length;
  if (rejected === negativeProbes.length) ok(`all ${rejected} M0 preservation mutations reject`);

  const lifecycleProbes = lifecycleRegressionProbes();
  const lifecycleProbeMatches = lifecycleProbes.filter((probe) => probe.matched).length;
  for (const probe of lifecycleProbes) {
    if (!probe.matched) fail('B008 lifecycle regression probe mismatched: ' + probe.label);
  }
  if (lifecycleProbeMatches === lifecycleProbes.length) {
    ok(`all ${lifecycleProbes.length} historical B008 lifecycle topology/event/ref probes matched`);
  }
  const semanticsProbes = lifecycleSemanticsRegressionProbes(record);
  const semanticsMatches = semanticsProbes.filter((probe) => probe.matched).length;
  for (const probe of semanticsProbes) {
    if (!probe.matched) fail('B008 lifecycle semantics probe mismatched: ' + probe.label);
  }
  if (semanticsMatches === semanticsProbes.length) {
    ok(`all ${semanticsProbes.length} historical effectiveness/boundary probes matched`);
  }

  return {
    result: pass ? 'PASS' : 'FAIL',
    details,
    negative_probes: rejected === negativeProbes.length ? 'PASS' : 'FAIL',
    negative_probe_count: negativeProbes.length,
    lifecycle_phase: 'POST_M0_SUCCESSOR_CANDIDATE',
    lifecycle_checkout: 'MVP_B000_CANDIDATE_HEAD',
    implementation_merge_recognized: true,
    m0_development_pass_effective: semanticProblems.length === 0,
    lifecycle_regression: lifecycleProbeMatches === lifecycleProbes.length ? 'PASS' : 'FAIL',
    lifecycle_probe_count: lifecycleProbes.length,
    lifecycle_semantics_regression: semanticsMatches === semanticsProbes.length ? 'PASS' : 'FAIL',
    lifecycle_semantics_probe_count: semanticsProbes.length,
    changed_paths: changed ?? [],
  };
}

export function run(ctx) {
  // Preserve the complete B008 Candidate/merge/closeout gate below. The only
  // added acceptance path is the exact Owner-authorized post-M0 B000 branch.
  if (isExactMvpB000Checkout(ctx.repo)) return runPostM0Successor(ctx);
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
    fail('final milestone record or project status is unreadable: ' + error.message);
    return { result: 'FAIL', details, negative_probes: 'NOT_RUN' };
  }

  const recordProblems = validateRecord(record);
  for (const problem of recordProblems) fail('record: ' + problem);
  if (recordProblems.length === 0) {
    ok('record schema, key sets, immutable identities and final boundaries are exact');
  }

  const standalone = status?.tracks?.['AIPT-STANDALONE'];
  const platform = status?.tracks?.['AIPT-PLATFORM-INTEGRATION'];
  const repoStatus = status?.repositories?.AIPT;
  if (standalone?.construction !== record.lifecycle.construction ||
      standalone?.current_batch !== record.lifecycle.current_batch ||
      standalone?.global_wip !== record.lifecycle.global_wip ||
      JSON.stringify(standalone?.batch_history) !== JSON.stringify(record.lifecycle.batch_history) ||
      standalone?.next_serial_batch !== record.lifecycle.next_serial_batch ||
      standalone?.next_batch_state !== record.lifecycle.next_batch_state ||
      standalone?.next_batch_authorized !== record.lifecycle.next_batch_authorized ||
      standalone?.next_batch_started !== record.lifecycle.next_batch_started) {
    fail('public project status disagrees with the final closeout lifecycle');
  } else ok('public project status matches MERGED_CLOSED/WIP0/no-next-batch lifecycle');
  if (status?.authority_snapshot_id !== 'AIPT-M0-B008-CLOSEOUT-001' ||
      repoStatus?.verified_head !== B008_IMPLEMENTATION_MERGE.commit ||
      repoStatus?.verified_tree !== B008_IMPLEMENTATION_MERGE.tree ||
      Object.hasOwn(repoStatus ?? {}, 'pending_candidate')) {
    fail('final authority snapshot, verified implementation merge, or pending-Candidate removal drifted');
  } else ok('project status binds the exact B008 implementation merge and has no pending Candidate');
  if (platform?.status !== record.boundaries.platform_integration ||
      platform?.unfreeze_authorized !== false) {
    fail('platform integration is not frozen');
  } else ok('platform integration remains frozen without unfreeze authority');

  const document = fs.readFileSync(path.join(ctx.repo, DOCUMENT_PATH), 'utf8');
  const docNeedles = [
    'GPT Hard Gate = `PASS`',
    'AIPT-M0-B008 = `MERGED_CLOSED`',
    'M0 Development Pass = `GRANTED`',
    'buildable and verifiable engineering foundation',
    'did not execute a real TRPG playtest',
    'not MVP Development Pass',
    'Production qualification = `NOT_GRANTED`',
    'Release qualification = `NOT_GRANTED`',
    'No human-equivalence claim is made',
    'second-auditor production gate remains pending',
    'MODEL, HARNESS and IPC production gates remain unimplemented',
    '`FROZEN_WAITING_M1_ENGINE`',
    'No automatic next batch is authorized',
    'new Owner Authority',
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
  } else if (lifecycle.phase === 'POST_MERGE_MAIN') {
    ok('POST_MERGE_MAIN = PASS: exact one-merge main topology, subject and Candidate tree');
  } else if (lifecycle.phase === 'CLOSEOUT_MAIN') {
    ok('CLOSEOUT_MAIN = PASS: exact implementation merge plus one exact 14-path final closeout');
  }

  const semanticProblems = validateLifecycleSemantics(
    lifecycleSemanticsFromRecord(record), lifecycle.phase,
  );
  for (const problem of semanticProblems) fail('lifecycle semantics: ' + problem);
  if (semanticProblems.length === 0) {
    ok('lifecycle phase and milestone effectiveness state are aligned without boundary inflation');
  }

  const tracked = git(ctx.repo, ['diff', '--name-only', '--no-renames', BASE_COMMIT], { check: false });
  const untracked = git(ctx.repo, ['ls-files', '--others', '--exclude-standard'], { check: false });
  const changed = [...new Set([
    ...tracked.stdout.split('\n'),
    ...untracked.stdout.split('\n').filter((relative) => !isGeneratedWorktreeArtifact(relative)),
  ].filter(Boolean))].sort();
  for (const problem of validateChangedPaths(changed)) fail(problem);
  for (const relative of REQUIRED_CHANGED_PATHS) {
    if (!changed.includes(relative)) fail('required total B008 surface path is absent: ' + relative);
  }
  if (changed.length === REQUIRED_CHANGED_PATHS.length &&
      changed.every((relative) => REQUIRED_CHANGED_PATHS.includes(relative))) {
    ok('Base-to-closeout changed-path set preserves the exact 15-path B008 surface');
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

  const semanticsProbes = lifecycleSemanticsRegressionProbes(record);
  const semanticsProbeMatches = semanticsProbes.filter((probe) => probe.matched).length;
  for (const probe of semanticsProbes) {
    if (!probe.matched) fail('lifecycle semantics regression probe mismatched: ' + probe.label);
  }
  if (semanticsProbeMatches === semanticsProbes.length) {
    ok('all ' + semanticsProbes.length + ' lifecycle effectiveness/boundary probes matched');
  }

  return {
    result: pass ? 'PASS' : 'FAIL',
    details,
    negative_probes: rejected === probes.length ? 'PASS' : 'FAIL',
    negative_probe_count: probes.length,
    lifecycle_phase: lifecycle.phase,
    lifecycle_checkout: lifecycle.checkoutKind,
    implementation_merge_recognized: lifecycle.implementationMergeRecognized,
    m0_development_pass_effective: lifecycle.m0DevelopmentPassEffective &&
      semanticProblems.length === 0,
    lifecycle_regression: lifecycleProbeMatches === lifecycleProbes.length ? 'PASS' : 'FAIL',
    lifecycle_probe_count: lifecycleProbes.length,
    lifecycle_semantics_regression: semanticsProbeMatches === semanticsProbes.length
      ? 'PASS' : 'FAIL',
    lifecycle_semantics_probe_count: semanticsProbes.length,
    changed_paths: changed,
  };
}

runAsMain(import.meta.url, 'm0-development-pass', run);
