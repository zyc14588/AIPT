// Shared B002 validator constants.
//
// Every fixed identity below is an immutable historical fact installed by the
// closed AIPT-M0-B000 / AIPT-M0-B001 acceptances. Nothing is computed at
// runtime from the candidate itself, so the candidate cannot validate itself
// into acceptance.
//
// BASE_* is the accepted main base the B002 candidate must diff against: the
// AIPT-M0-B001 merge commit and its tree. B000 and B001 keep their own
// original commit/tree identities instead of aliasing the current base.

// The batch under construction for this iteration (public status, runner
// report, and the status-transition validator all target this batch).
export const CURRENT_BATCH = 'AIPT-M0-B002';

// The historical batch that selected the frozen toolchain / supply-chain
// policy. tools/*.lock.json `selected_by_batch` is an immutable B001 fact,
// and the frozen toolchain-lock / supply-chain validators keep comparing it
// against this constant — it must never be bumped to a later batch. The name
// describes the role (the supply-chain baseline selector), never the current
// task, so it cannot be confused with CURRENT_BATCH.
export const SUPPLY_CHAIN_BASELINE_BATCH = 'AIPT-M0-B001';

// Public status date of this B002 iteration (machine + human docs).
export const STATUS_DATE = '2026-08-17';

// Immutable closed-batch identities — historical state, never updated by
// later batches and never aliased to the current base.
export const B000 = {
  commit: '777a3f39ba78c1ef3168597890c61abf7a55d962',
  tree: 'f5f845b860ba0944ef104b4679fa074ad6efecbb',
  decisions: 454,
  supersessions: 35,
  deferred_parameters: 16,
  markdown_documents: 17,
  tracked_file_count: 22,
  deferred_016_historical_status: 'DEFERRED_TO_AIPT-M0-B001',
};

// Immutable B001 acceptance identity: the merged candidate, the merge commit
// on main (== the accepted main base for B002), its tree, and the post-merge
// public CI run that verified the merged tree.
export const B001 = {
  candidate: '2e904ddc2d4f1313a99e19f6751a991d589f8336',
  merge_commit: '8bcadc9669e7d04f589f883daa6d4f593875fc9e',
  tree: 'fefc25f1acb523d013c2a7d8db9801ccdab37d2d',
  post_merge_ci_run: 31951440133,
};

// Accepted main base for the current B002 iteration: the AIPT-M0-B001 merge
// commit / tree. `verified_head` may only point here, never at a candidate.
export const BASE_COMMIT = B001.merge_commit;
export const BASE_TREE = B001.tree;

export const TOOLCHAIN = {
  go: '1.26.5',
  node: '24.19.0',
  pnpm: '11.4.0',
  postgresql: '18.4',
};

export const GO_LINUX_AMD64_SHA256 =
  '5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053';
export const NODE_LINUX_X64_SHA256 =
  '14b342e71204f811bde6153be8e04b62aef63c236fef92b55f9c83154b409647';
export const PNPM_REGISTRY_INTEGRITY =
  'sha512-8P68fjdVKrSFSUqRQkGzOOCzWAuT1UzjHwCTMBWICGMSkDihtK5OQUoO5jrDW/IRl+mQFyxKaCVkULVjYxCWjw==';

export const PG_MULTI_ARCH_DIGEST =
  'sha256:a02db8cac496f15b094798a38254f14d6e00741f709360e5e00bb6668ea31636';
export const PG_LINUX_AMD64_PLATFORM_DIGEST =
  'sha256:4cc13dede823cab4e05290c7fb3350fb4e599ecabd9b07e6706b5d5e8f5bc929';

export const GOVULNCHECK = {
  module: 'golang.org/x/vuln',
  version: 'v1.7.0',
  source_commit: '617f44b718537dccdea1915395650e0529e3b72e',
};

export const CI_ACTION_PINS = {
  'actions/checkout': {
    tag: 'v7.0.1',
    sha: '3d3c42e5aac5ba805825da76410c181273ba90b1',
  },
  'actions/setup-go': {
    tag: 'v7.0.0',
    sha: 'b7ad1dad31e06c5925ef5d2fc7ad053ef454303e',
  },
  'actions/setup-node': {
    tag: 'v7.0.0',
    sha: '820762786026740c76f36085b0efc47a31fe5020',
  },
};

export const REQUIRED_SUPPLY_CHAIN_RULES = [
  'exact_toolchain_versions_required',
  'frozen_pnpm_lock_required',
  'go_module_tidy_clean_required',
  'action_full_sha_pin_required',
  'container_digest_pin_required',
  'dependency_license_record_required',
  'unknown_license_blocks',
  'sbom_required',
  'vulnerability_scan_required',
  'source_provenance_required',
  'public_ci_secret_reference_forbidden',
  'remote_model_call_forbidden',
];

// AIPT-M0-B002 allowed paths. The tree-integrity gate diffs the candidate
// against the accepted batch base (the B001 merge commit), so this list is
// the CUMULATIVE union of every B002 iteration's approved paths: the
// iteration-1 status-transition/validator-baseline set, the iteration-2
// protocol-schema/fixture/validator set, and this iteration-3 bounded repair
// set. Path admission is PER-ITERATION: each B002 iteration registers only
// the paths its own accepted scope may change, and the scope gate is never
// disabled.
export const ALLOWED_PATHS = [
  // iteration 1 (public status transition + validator baseline)
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'package.json',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/defer-016.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
  // iteration 2 (canonical protocol schema, minimal fixture, validators)
  'docs/protocol/README.md',
  'schemas/protocol/v1/**',
  'testdata/protocol/v1/minimal-fixture/**',
  'scripts/ci/lib/json-schema.mjs',
  'scripts/ci/validate/protocol-assets.mjs',
  'scripts/ci/validate/toolchain-lock.mjs',
  'scripts/ci/validate/supply-chain.mjs',
];

// Forbidden prefixes for the CURRENT B002 repair iteration (B001 historical
// forbidden prefixes retained). The prefixes below are mechanically blocked
// in this iteration, but they are NOT a permanent B002 verdict: the B002
// master contract explicitly requires a later B002 iteration to build
// packages/adapter-sdk and internal/protocol (the Adapter SDK and the Go
// protocol consumer). When a later B002 iteration is scoped to those
// deliverables, its own accepted per-iteration path admission will register
// them; runtime/, tools/, .github/, architecture/runtime implementation,
// frozen documents, and dependency manifests remain forbidden.
export const FORBIDDEN_PREFIXES = [
  'api/',
  'cmd/',
  'migrations/',
  'deploy/',
  'packages/',
  'internal/protocol/',
  'runtime/',
  'tools/',
  '.github/',
  'docs/architecture/',
  'docs/integration/',
  'docs/test-model/',
  'docs/security/',
  'docs/evidence/',
  'LICENSE',
  'go.mod',
  'go.sum',
  'pnpm-lock.yaml',
  'pnpm-workspace.yaml',
];

// Frozen authority registries: byte-for-byte immutability is enforced
// against the accepted main base. Deferred parameters are frozen for the
// B002 iteration as well (DEFER-016 stays RESOLVED with the exact B001
// toolchain qualification; the other 15 stay open).
export const FROZEN_REGISTRY_PATHS = [
  'docs/authority/registry/decisions.json',
  'docs/authority/registry/supersessions.json',
  'docs/authority/registry/deferred-parameters.json',
];

export const FROZEN_DECISION_PATHS = [
  'docs/authority/registry/decisions.json',
  'docs/authority/registry/supersessions.json',
  'docs/authority/SUPERSEDED_DECISIONS.md',
];

export const EXPECTED_MIT_LICENSE = `MIT License

Copyright (c) 2026 AIPT contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`;

export function normalizeText(text) {
  return (
    text
      .replace(/\r\n/g, '\n')
      .replace(/\r/g, '\n')
      .split('\n')
      .map((line) => line.replace(/[ \t]+$/, ''))
      .join('\n')
      .replace(/^\n+/, '')
      .replace(/\n+$/, '') + '\n'
  );
}

export function pathMatchesAllowed(p) {
  for (const pattern of ALLOWED_PATHS) {
    if (pattern.endsWith('/**')) {
      if (p.startsWith(pattern.slice(0, -3))) return true;
    } else if (p === pattern) {
      return true;
    }
  }
  return false;
}
