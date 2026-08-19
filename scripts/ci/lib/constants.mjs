// Shared B003 validator constants.
//
// Every fixed identity below is an immutable historical fact installed by the
// closed AIPT-M0-B000 / AIPT-M0-B001 / AIPT-M0-B002 acceptances. Nothing is
// computed at runtime from the candidate itself, so the candidate cannot
// validate itself into acceptance.
//
// BASE_* is the accepted main base the B003 candidate must diff against: the
// AIPT-M0-B002 closeout commit and its tree. B000, B001, and B002 keep their
// own original commit/tree identities instead of aliasing the current base.

// The batch under construction for this iteration (public status, runner
// report, and the status-transition validator all target this batch).
export const CURRENT_BATCH = 'AIPT-M0-B003';

// The historical batch that selected the frozen toolchain / supply-chain
// policy. tools/*.lock.json `selected_by_batch` is an immutable B001 fact,
// and the frozen toolchain-lock / supply-chain validators keep comparing it
// against this constant — it must never be bumped to a later batch. The name
// describes the role (the supply-chain baseline selector), never the current
// task, so it cannot be confused with CURRENT_BATCH.
export const SUPPLY_CHAIN_BASELINE_BATCH = 'AIPT-M0-B001';

// Public status date of this B003 iteration (machine + human docs).
export const STATUS_DATE = '2026-08-19';

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
// on main, its tree, and the post-merge public CI run that verified the
// merged tree. B001 was the accepted main base for the closed B002 batch.
export const B001 = {
  candidate: '2e904ddc2d4f1313a99e19f6751a991d589f8336',
  merge_commit: '8bcadc9669e7d04f589f883daa6d4f593875fc9e',
  tree: 'fefc25f1acb523d013c2a7d8db9801ccdab37d2d',
  post_merge_ci_run: 31951440133,
};

// Immutable B002 acceptance identity: the merged candidate, the merge commit
// on main, its tree, and the post-merge public CI run that verified the
// merged tree. B002 is the accepted predecessor of the current B003 batch.
export const B002 = {
  candidate: '9968cbc89c09640e3fc2feb8d851220eae98b9b9',
  merge_commit: 'fccfb595c23feab38397506505a3e996fe7b9e9c',
  tree: 'f99570bc3c4307244ca926cec62e82a07ef5aee8',
  post_merge_ci_run: 31985644832,
  post_merge_ci_conclusion: 'success',
};

// Immutable B002 closeout: the fixup commit on main that closed AIPT-M0-B002
// after its implementation merge. Its tree is the accepted B003 base tree and
// its single parent is the B002 merge commit.
export const B002_CLOSEOUT = {
  commit: '45a96087d75a61f2910cb5ce99134e3ca777bca8',
  tree: '8b16b599c261879406f0435e80c878e092683a50',
  parent: 'fccfb595c23feab38397506505a3e996fe7b9e9c',
};

// External serial predecessor of the current batch: the unregistered serial
// batch that ran and merged/closed before B003 construction began. Its
// closeout commit and post-closeout public CI run are immutable facts.
export const EXTERNAL_SERIAL_PREDECESSOR = {
  batch: 'UNREGISTERED-AIPT-P0-B001',
  status: 'MERGED_CLOSED',
  closeout_commit: 'a37b284bf5ec35895f436abe71d22599edb6da53',
  closeout_ci_run: 32194224161,
  closeout_ci_conclusion: 'success',
};

// Accepted main base for the current B003 iteration: the AIPT-M0-B002
// closeout commit / tree. `verified_head` may only point here, never at a
// candidate.
export const BASE_COMMIT = B002_CLOSEOUT.commit;
export const BASE_TREE = B002_CLOSEOUT.tree;

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

// AIPT-M0-B003 allowed paths. The tree-integrity gate diffs the candidate
// against the accepted batch base (the AIPT-M0-B002 closeout commit), so this
// list is exactly the full approved B003 scope: the storage iteration admits
// the PostgreSQL storage implementation and its docs, the dependency
// manifests (go.mod/go.sum) that the new storage module requires, and the
// retained public-status / validator / supply-chain / SBOM / CI-workflow
// paths that B003 iterations may evolve. Path admission is PER-ITERATION:
// each B003 iteration registers only the paths its own accepted scope may
// change, and the scope gate is never disabled.
export const ALLOWED_PATHS = [
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

// Forbidden prefixes for the CURRENT B003 iteration (non-conflicting
// historical frozen paths retained). B003 admits go.mod/go.sum and the
// storage paths via the exact allowed-path list above, so go.mod/go.sum are
// NOT forbidden; the frozen B001 supply-chain artifacts (policy.json,
// toolchain/action locks) stay mechanically blocked. The B002-era
// adapter/protocol paths are read-only for B003 and are blocked by exact
// prefix: packages/, schemas/protocol/, testdata/protocol/, internal/
// protocol/, plus the prohibited cmd/, runtime/, api/ implementations and
// the frozen docs/architecture|security|evidence|integration/ documents.
export const FORBIDDEN_PREFIXES = [
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

// Frozen authority registries: byte-for-byte immutability is enforced
// against the accepted main base. Deferred parameters are frozen for the
// B003 iteration as well (DEFER-016 stays RESOLVED with the exact B001
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
      if (p.startsWith(pattern.slice(0, -2))) return true;
    } else if (p === pattern) {
      return true;
    }
  }
  return false;
}
