// Shared B001 validator constants.
//
// All fixed identities are derived from the closed AIPT-M0-B000 acceptance and
// the AIPT-M0-B001 private task package (v1.0.0). Nothing here is computed at
// runtime from the candidate itself, so the candidate cannot validate itself
// into acceptance.

export const TASK_ID = 'AIPT-M0-B001';

export const BASE_COMMIT = '777a3f39ba78c1ef3168597890c61abf7a55d962';
export const BASE_TREE = 'f5f845b860ba0944ef104b4679fa074ad6efecbb';

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

// Fixed B000 expectations — historical state, never updated by later batches.
export const B000 = {
  commit: BASE_COMMIT,
  tree: BASE_TREE,
  decisions: 454,
  supersessions: 35,
  deferred_parameters: 16,
  markdown_documents: 17,
  tracked_file_count: 22,
  deferred_016_historical_status: 'DEFERRED_TO_AIPT-M0-B001',
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

// AIPT-M0-B001 private task package v1.0.0 allowed_paths / forbidden_prefixes.
export const ALLOWED_PATHS = [
  'README.md',
  'docs/authority/README.md',
  'docs/authority/DECISION_MATRIX.md',
  'docs/authority/DEFERRED_PARAMETERS.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/deferred-parameters.json',
  'docs/authority/registry/project-status.json',
  'docs/supply-chain/README.md',
  '.github/workflows/ci.yml',
  '.github/dependabot.yml',
  '.go-version',
  '.node-version',
  'go.mod',
  'package.json',
  'pnpm-lock.yaml',
  'pnpm-workspace.yaml',
  'internal/toolchainsmoke/doc.go',
  'internal/toolchainsmoke/toolchainsmoke_test.go',
  'scripts/ci/**',
  'tools/toolchain.lock.json',
  'tools/ci-actions.lock.json',
  'tools/supply-chain/policy.json',
  'tools/supply-chain/licenses.json',
];

export const FORBIDDEN_PREFIXES = [
  'api/',
  'cmd/',
  'migrations/',
  'deploy/',
  'packages/',
  'testdata/',
  'docs/integration/',
  'docs/test-model/',
  'docs/security/',
  'docs/evidence/',
];

export const FROZEN_REGISTRY_PATHS = [
  'docs/authority/registry/decisions.json',
  'docs/authority/registry/supersessions.json',
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
