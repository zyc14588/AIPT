// Shared B004 validator constants and construction identities.
//
// Every fixed identity below is an immutable historical fact installed by the
// closed AIPT-M0-B000 / AIPT-M0-B001 / AIPT-M0-B002 / AIPT-M0-B003
// acceptances. Nothing is computed at runtime from the candidate itself, so
// the candidate cannot validate itself into acceptance.
//
// BASE_* is the accepted main base the B004 candidate must diff against: the
// AIPT-M0-B003 closeout commit and its tree, held as independent literal
// anchors. B000, B001, B002, and B003 keep their own original commit/tree
// identities instead of aliasing the current base.

// The batch whose implementation and closeout are validated by this suite.
// This is AIPT-M0-B004 while B004 construction is in progress, so B004
// reports and identities cannot masquerade as B003 or B005 work.
export const CURRENT_BATCH = 'AIPT-M0-B004';

// The machine authority has exactly one active construction batch:
// AIPT-M0-B004. B005 is not authorized and is explicitly not started.
export const ACTIVE_BATCH = 'AIPT-M0-B004';

// The historical batch that selected the frozen toolchain / supply-chain
// policy. tools/*.lock.json `selected_by_batch` is an immutable B001 fact,
// and the frozen toolchain-lock / supply-chain validators keep comparing it
// against this constant — it must never be bumped to a later batch. The name
// describes the role (the supply-chain baseline selector), never the current
// task, so it cannot be confused with CURRENT_BATCH.
export const SUPPLY_CHAIN_BASELINE_BATCH = 'AIPT-M0-B001';

// Public status date of the B004 construction snapshot (machine + human docs).
export const STATUS_DATE = '2026-08-20';

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

// Immutable B003 implementation acceptance identity. The implementation
// merge is a two-parent merge commit whose first parent is the B002 closeout
// base and whose second parent is the frozen B003 Candidate. Candidate and
// implementation merge intentionally share the exact accepted tree.
export const B003 = {
  candidate: 'fbe1363acd977759c4effa2687483c0b78b63ab6',
  tree: '60bcdd0df2c29391c2564bfeae17013c07723cd3',
  candidate_ci_run: 32334341279,
  candidate_ci_conclusion: 'success',
  merge_commit: '725fc005185412d115307b594aa64e84acfabf67',
  post_merge_ci_run: 32336615560,
  post_merge_ci_conclusion: 'success',
  security_toolchain_requalification: 'AIPT-M0-B003-SECURITY-TOOLCHAIN-QUAL-001',
};

// Immutable B003 closeout: the fixup commit on main that closed AIPT-M0-B003
// after its implementation merge. Its tree is the accepted B004 base tree and
// its single parent is the B003 implementation merge.
export const B003_CLOSEOUT = {
  commit: '6d7225828b45b69ecc44d5bb51a04c40f0865aba',
  tree: 'f557a9f54cbac11474f2d56f78e2d983a7d6a7be',
  parent: '725fc005185412d115307b594aa64e84acfabf67',
};

// External serial predecessor of B003: the unregistered serial batch that ran
// and merged/closed before B003 construction began. Its
// closeout commit and post-closeout public CI run are immutable facts.
export const EXTERNAL_SERIAL_PREDECESSOR = {
  batch: 'UNREGISTERED-AIPT-P0-B001',
  status: 'MERGED_CLOSED',
  closeout_commit: 'a37b284bf5ec35895f436abe71d22599edb6da53',
  closeout_ci_run: 32194224161,
  closeout_ci_conclusion: 'success',
};

// B004 accepted implementation-diff base: the AIPT-M0-B003 closeout commit /
// tree, supplied by the controller and held as independent literal anchors —
// never aliased to B002_CLOSEOUT and never derived from any candidate. The
// registry `verified_head` for the in-progress B004 construction points at
// this accepted base, never at the B003 Candidate or implementation merge.
export const B004_BASE_COMMIT = '6d7225828b45b69ecc44d5bb51a04c40f0865aba';
export const B004_BASE_TREE = 'f557a9f54cbac11474f2d56f78e2d983a7d6a7be';

export const BASE_COMMIT = B004_BASE_COMMIT;
export const BASE_TREE = B004_BASE_TREE;

export const TOOLCHAIN = {
  go: '1.26.6',
  node: '24.19.0',
  pnpm: '11.4.0',
  postgresql: '18.4',
};

export const GO_LINUX_AMD64_SHA256 =
  '708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89';

// Exact official Go 1.26.6 security-requalification identity (AIPT-M0-B003
// security toolchain requalification, leaf B003): official stable release
// go1.26.6 dated 2026-08-13, official release index, linux/amd64 archive and
// SHA-256 (independently recomputed), official upstream tag go1.26.6 commit,
// official release history and security announcement.
export const GO_SECURITY_REQUALIFICATION = {
  version: '1.26.6',
  // The B001-qualified Go this B003 security requalification supersedes as
  // the CURRENT identity (equals GO_INITIAL_QUALIFICATION.go_version — an
  // explicit historical B001 fact, never rewritten).
  previous_go_version: '1.26.5',
  // Mandated UTC verification time for the B003 security requalification.
  verified_at: '2026-08-20T04:16:01Z',
  // The exact frozen Go source_verification method recorded in
  // tools/toolchain.lock.json (official go.dev release index + locally
  // compared and independently recomputed linux/amd64 archive sha256, the
  // official stable release date, the official upstream tag commit, and the
  // cross-referenced official release history + security announcement). The
  // toolchain-lock validator requires this exact method string and the exact
  // {method, verified_at} key set, never a looser match.
  source_verification_method:
    'official go.dev release index (stable=true) + linux/amd64 archive sha256 compared locally and independently recomputed; official release go1.26.6 stable dated 2026-08-13; official upstream tag go1.26.6 commit 1ea5a71ad8ceb7b9f16b4b6f8ea4739a4327dd6e; official release history + security announcement cross-referenced',
  channel: 'stable',
  release_index: 'https://go.dev/dl/?mode=json&include=all',
  release_status: 'stable',
  release_date: '2026-08-13',
  release_history: 'https://go.dev/doc/devel/release#go1.26.6',
  security_announcement: 'https://groups.google.com/g/golang-announce/c/94pEornpRlI',
  upstream_tag: 'go1.26.6',
  upstream_commit: '1ea5a71ad8ceb7b9f16b4b6f8ea4739a4327dd6e',
  archive_filename: 'go1.26.6.linux-amd64.tar.gz',
  archive_url: 'https://go.dev/dl/go1.26.6.linux-amd64.tar.gz',
  archive_sha256: GO_LINUX_AMD64_SHA256,
  expected_version_output: 'go version go1.26.6 linux/amd64',
  reason: 'reachable standard-library vulnerabilities',
  officially_fixed_in: '1.26.6',
};

// Exact trigger advisory set, each officially fixed in Go 1.26.6.
export const GO_SECURITY_ADVISORIES = [
  { id: 'GO-2026-6090', package: 'crypto/tls' },
  { id: 'GO-2026-6088', package: 'encoding/xml' },
  { id: 'GO-2026-5972', package: 'encoding/asn1' },
];

// The historical B001 initial qualification (Go 1.26.5) that this B003
// security requalification supersedes as the CURRENT Go identity. Explicit
// B001 historical facts are retained and never rewritten.
export const GO_INITIAL_QUALIFICATION = {
  batch: 'AIPT-M0-B001',
  go_version: '1.26.5',
  reason: 'B001 exact-toolchain supply-chain qualification (froze DEFER-016)',
  archive_sha256: '5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053',
};
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

// AIPT-M0-B004 allowed paths. The tree-integrity gate diffs the candidate
// against the accepted batch base (the AIPT-M0-B003 closeout commit), so this
// list is exactly the full approved B004 scope from the master contract: the
// Go Launcher shell (cmd/aipt), the shared config service/schema foundation
// (internal/config + schemas/config/v1), the Core lifecycle shell
// (internal/core), the launcher gate machine (internal/launcher), the runtime
// documentation (docs/runtime), and the retained authority / status /
// validator / supply-chain / SBOM / CI-workflow paths that B004 iterations may
// evolve — including the storage validator gate. B003 storage/protocol code
// and docs stay read-only; dependency and toolchain registries stay frozen.
// Path admission is PER-ITERATION: each B004 iteration registers only the
// paths its own accepted scope may change, and the scope gate is never
// disabled.
export const ALLOWED_PATHS = [
  // Major new B004 areas from the master contract.
  'cmd/aipt/**',
  'internal/config/**',
  'internal/core/**',
  'internal/launcher/**',
  'schemas/config/v1/**',
  'docs/runtime/**',
  // Retained authority / status / validator / CI paths B004 may evolve.
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'package.json',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
  'scripts/ci/validate/workflow.mjs',
  'scripts/ci/validate/storage.mjs',
  'scripts/ci/validate/supply-chain.mjs',
  'scripts/ci/validate/sbom.mjs',
  // New B004 fail-closed runtime-shell gate.
  'scripts/ci/validate/runtime-shell.mjs',
  'scripts/ci/sbom/generate-sbom.mjs',
  'tools/supply-chain/licenses.json',
  'docs/supply-chain/README.md',
  '.github/workflows/ci.yml',
];

// Exact first-leaf authority/status surface. It is retained separately from
// the full construction allowlist so the transition validator can prove that
// the status mutation itself remained bounded.
export const STATUS_TRANSITION_PATHS = [
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
];

// Forbidden prefixes/files for the CURRENT B004 iteration (non-conflicting
// historical frozen paths retained). cmd/ is NOT a blanket forbidden prefix:
// the master-contract B004 scope admits cmd/aipt/** by exact wildcard, and
// non-aipt cmd paths remain outside the exact allowlist (the allowlist alone
// rejects them). The frozen B001 supply-chain artifacts (policy.json) stay
// mechanically blocked, the B002-era adapter/protocol paths are read-only for
// B004 and are blocked by exact prefix, and B005 / runtime / platform
// implementation paths remain fail-closed.
export const FORBIDDEN_PREFIXES = [
  'api/',
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
  'internal/storage/postgres/',
  'internal/harness/',
  'internal/model/',
  'internal/web/',
  'internal/ipc/',
  'internal/campaign/',
  '.go-version',
  'go.mod',
  'go.sum',
  'pnpm-lock.yaml',
  'LICENSE',
  'tools/toolchain.lock.json',
  'tools/ci-actions.lock.json',
  'tools/supply-chain/policy.json',
];

// Frozen authority registries: byte-for-byte immutability is enforced
// against the accepted main base. decisions.json, supersessions.json, and
// deferred-parameters.json are all fully frozen for B004 (the B003
// security-requalification controlled evolution of deferred-parameters.json
// is closed; B004 performs no deferred-parameters work).
export const FROZEN_REGISTRY_PATHS = [
  'docs/authority/registry/decisions.json',
  'docs/authority/registry/supersessions.json',
  'docs/authority/registry/deferred-parameters.json',
];

export const FROZEN_DECISION_PATHS = [
  'docs/authority/registry/decisions.json',
  'docs/authority/registry/supersessions.json',
  'docs/authority/registry/deferred-parameters.json',
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

export function pathMatchesStatusTransition(p) {
  return STATUS_TRANSITION_PATHS.includes(p);
}
