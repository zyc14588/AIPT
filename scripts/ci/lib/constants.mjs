// Shared MVP bootstrap validator constants and immutable predecessor identities.
//
// Every fixed identity below is an immutable historical fact installed by the
// closed AIPT-M0-B000 through AIPT-M0-B007 acceptances. Nothing in the
// milestone record may rewrite those accepted identities. B008 closeout makes
// the independently audited M0 Development Pass effective without changing
// any product/runtime identity or granting a later batch.
//
// BASE_* is the accepted main base the B008 Candidate must diff against: the
// AIPT-M0-B007 closeout commit and its tree, held as independent literal
// anchors. Every predecessor keeps its own original identity.

export const CURRENT_BATCH = 'AIPT-MVP-B000';

// The new Owner Authority opens exactly one post-M0 governance batch while
// every later MVP batch remains unauthorized and not started.
export const ACTIVE_BATCH = CURRENT_BATCH;

// The historical batch that selected the frozen toolchain / supply-chain
// policy. tools/*.lock.json `selected_by_batch` is an immutable B001 fact,
// and the frozen toolchain-lock / supply-chain validators keep comparing it
// against this constant — it must never be bumped to a later batch. The name
// describes the role (the supply-chain baseline selector), never the current
// task, so it cannot be confused with CURRENT_BATCH.
export const SUPPLY_CHAIN_BASELINE_BATCH = 'AIPT-M0-B001';

// Public status date of the B008 Candidate snapshot (machine + human docs).
export const STATUS_DATE = '2026-08-26';

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

// Immutable append-only construction checkpoint. Dependency security repair
// commits must descend from this exact commit/tree; it is never amended or
// rewritten by the B004 requalification.
export const B004_CONSTRUCTION_CHECKPOINT = {
  commit: '59230daae0113d35896f192a255633ba2cc1dec7',
  tree: 'bab4289817a26a07553da4bfcccaac82dbb04319',
};

// Immutable B004 Candidate identity accepted by the Owner light gate. The
// Candidate and its public push CI remain distinct from the later main merge
// and from all validator-repair / closeout commits.
export const B004_CANDIDATE = {
  commit: '4810d2cfec6146db7c161506ba7f37ab0a4ce69c',
  tree: 'f35365d0ad47fdd513fbecb84a03b1559026637e',
  ci_run: 32392886647,
};

// Exact two-parent merge authorized by AIPT-M0-B004-MERGE-001. This identity
// is the sole merge commit permitted after the immutable B004 base. Later
// validator-repair and closeout commits must remain ordinary single-parent
// descendants and must never replace this verified implementation identity.
export const B004_IMPLEMENTATION_MERGE = {
  directive: 'AIPT-M0-B004-MERGE-001',
  commit: 'd07c0c3817620ada47b3ae7344d8ee423ace3b12',
  tree: 'f35365d0ad47fdd513fbecb84a03b1559026637e',
  parent1: '6d7225828b45b69ecc44d5bb51a04c40f0865aba',
  parent2: '4810d2cfec6146db7c161506ba7f37ab0a4ce69c',
};

// Immutable post-merge validator repair. The initial failed CI remains
// immutable failure evidence; this ordinary single-parent commit repaired the
// lifecycle gate without changing the accepted B004 implementation tree.
export const B004_POST_MERGE_REPAIR = {
  directive: 'AIPT-M0-B004-POSTMERGE-TREE-INTEGRITY-REPAIR-001',
  initial_ci_run: 32557930038,
  initial_ci_conclusion: 'failure',
  failure: 'AIPT-B004-TREE-INTEGRITY-LIFECYCLE-001',
  commit: 'bd0c06867da58f89e82a35d82ce1d798c1ec9cae',
  tree: '02e53e65ea194236e0b34a96768f9a848ecfd3a7',
  parent: 'd07c0c3817620ada47b3ae7344d8ee423ace3b12',
  ci_run: 32558813381,
  ci_conclusion: 'success',
};

// Immutable B004 closeout. This ordinary single-parent authority commit is
// the independently supplied B005 implementation base; it never masquerades
// as the B004 implementation merge or Candidate identity.
export const B004_CLOSEOUT = {
  commit: '8005dd3bec8b367a6d97dcd9397158f1d8618f3e',
  tree: 'd0f32b7ac1c3f6e5ddb258aaa2ee030844b1eb2b',
  parent: 'bd0c06867da58f89e82a35d82ce1d798c1ec9cae',
};

export const B005_BASE_COMMIT = '8005dd3bec8b367a6d97dcd9397158f1d8618f3e';
export const B005_BASE_TREE = 'd0f32b7ac1c3f6e5ddb258aaa2ee030844b1eb2b';

export const B005_MERGE_SUBJECT = 'merge: integrate AIPT-M0-B005';
export const B005_CLOSEOUT_SUBJECT = 'closeout: complete AIPT-M0-B005';

export const B005_CANDIDATE_HISTORY = [
  'cae7c38a57da0b52e9a19e713ca8abeb9074698c',
  'ca8951529adb179c7e5f9e5a407aabb2ffa791f9',
  'd9e24cbac30a1472c41cc8719848acbbc2426fa5',
];

// Immutable B005 Candidate accepted by the Owner light gate. The Candidate
// and its public push CI remain distinct from the implementation merge and
// the later closeout authority commit.
export const B005_CANDIDATE = {
  commit: 'd9e24cbac30a1472c41cc8719848acbbc2426fa5',
  tree: 'c1b0b3e3c5218a46c4f3d9501b52a2618cfe20f5',
  ci_run: 32565305803,
  ci_conclusion: 'success',
};

// Exact two-parent implementation merge authorized by
// AIPT-M0-B005-MERGE-001. The verified implementation identity remains this
// commit/tree after closeout; the closeout commit must never replace it.
export const B005_IMPLEMENTATION_MERGE = {
  directive: 'AIPT-M0-B005-MERGE-001',
  commit: '8652a92c51b86a3bf66aee725c0f1b7be4c60654',
  tree: 'c1b0b3e3c5218a46c4f3d9501b52a2618cfe20f5',
  parent1: '8005dd3bec8b367a6d97dcd9397158f1d8618f3e',
  parent2: 'd9e24cbac30a1472c41cc8719848acbbc2426fa5',
  subject: B005_MERGE_SUBJECT,
  post_merge_ci_run: 32569995492,
  post_merge_ci_conclusion: 'success',
};

// Immutable B005 closeout is the independently supplied B006 base. It is a
// single-parent authority commit after the accepted B005 implementation merge
// and must never replace that merge as the verified B005 implementation.
export const B005_CLOSEOUT = {
  commit: '10d0232bd2e3e42601bbb00cedc753f842e219db',
  tree: '922115b9a75a7eca8dd97475f3f228bc7d3d2c10',
  parent: '8652a92c51b86a3bf66aee725c0f1b7be4c60654',
  ci_run: 32571092786,
  ci_conclusion: 'success',
};

export const B006_BASE_COMMIT = B005_CLOSEOUT.commit;
export const B006_BASE_TREE = B005_CLOSEOUT.tree;
export const B006_MERGE_SUBJECT = 'merge: integrate AIPT-M0-B006';
export const B006_CLOSEOUT_SUBJECT = 'closeout: complete AIPT-M0-B006';

export const B006_CANDIDATE_HISTORY = [
  '3987b8d4c26ac079d01c214ba90e113eeffd5713',
];

// Immutable B006 Candidate accepted by the Owner light gate. Its exact tree
// and successful public push CI remain distinct from the implementation merge
// and from the later single-parent closeout authority commit.
export const B006_CANDIDATE = {
  commit: '3987b8d4c26ac079d01c214ba90e113eeffd5713',
  tree: '4271a3fb71236a8b003b4d9ddc84727c6fec8d46',
  ci_run: 32577246851,
  ci_conclusion: 'success',
};

// Exact two-parent implementation merge authorized by
// AIPT-M0-B006-MERGE-001. This commit/tree remains the verified B006
// implementation identity after closeout.
export const B006_IMPLEMENTATION_MERGE = {
  directive: 'AIPT-M0-B006-MERGE-001',
  commit: '35acba9fb629f50087def3b720df304fadfd2158',
  tree: '4271a3fb71236a8b003b4d9ddc84727c6fec8d46',
  parent1: '10d0232bd2e3e42601bbb00cedc753f842e219db',
  parent2: '3987b8d4c26ac079d01c214ba90e113eeffd5713',
  subject: B006_MERGE_SUBJECT,
  post_merge_ci_run: 32578143923,
  post_merge_ci_conclusion: 'success',
};

// Immutable B006 closeout: the independently supplied B007 base. It is a
// single-parent authority commit after the accepted B006 implementation
// merge and its exact public CI result is historical evidence.
export const B006_CLOSEOUT = {
  commit: 'e1e1a6315ef2308922105dd30fd4bbcf4e3f91c8',
  tree: '326def92334a43f6d63cd77b40f0eae9af31b375',
  parent: '35acba9fb629f50087def3b720df304fadfd2158',
  ci_run: 32579049539,
  ci_conclusion: 'success',
};

export const B007_BASE_COMMIT = B006_CLOSEOUT.commit;
export const B007_BASE_TREE = B006_CLOSEOUT.tree;
export const B007_MERGE_SUBJECT = 'merge: integrate AIPT-M0-B007';
export const B007_CLOSEOUT_SUBJECT = 'closeout: complete AIPT-M0-B007';

// Exact linear Candidate history from the immutable B006 closeout base. No
// commit in this history is a merge; the final entry is the approved repair.
export const B007_CANDIDATE_HISTORY = [
  '61a3675d0675a09c9c299a787fdffa51a448bb54',
  '41c4396471da775659f68d43c5dae49301606b0a',
  'd6a4308288c17360fcc41e37b26b764518bbe9e8',
  'e92428300afcbe7c8d21f83724eb9d9d89bb4cf3',
  '0d8dca82daf93ce83512146c9741653ae6ed628e',
  '9577adeb3484ada1f7c0af2a2f74e57e1b59edb1',
  '2e3d08a1609d725f00985f6ab2f1ac8eb8748b1a',
  '5f78ca91170521ac2acc6ec6eeef4a20e1fdbf92',
  '561e43f9bc646c43da0b48c8485f820f73941df9',
];

// Immutable original Candidate before the documentation-only supply-chain
// repair. Its commit and tree remain separately auditable facts.
export const B007_ORIGINAL_CANDIDATE = {
  commit: '5f78ca91170521ac2acc6ec6eeef4a20e1fdbf92',
  tree: 'd4cc34e8fcbec8ea4f864f22aa7503cc1dcdffcd',
};

// Owner-accepted repair: a single-parent child of the original Candidate,
// touching only two validator comments/diagnostics with no semantic change.
export const B007_REPAIR = {
  finding: 'AIPT-B007-SUPPLY-CHAIN-DOC-CONSISTENCY-001',
  status: 'CLOSED',
  commit: '561e43f9bc646c43da0b48c8485f820f73941df9',
  parent: B007_ORIGINAL_CANDIDATE.commit,
  changed_paths: [
    'scripts/ci/validate/sbom.mjs',
    'scripts/ci/validate/supply-chain.mjs',
  ],
  semantic_code_changes: false,
};

// Approved final Candidate and its exact successful remote CI identity.
export const B007_CANDIDATE = {
  commit: B007_REPAIR.commit,
  tree: '35a5cc261fef75df8d25102015670bcb1d6fbd92',
  ci_run: 32634972911,
  ci_conclusion: 'success',
};

// Exact two-parent implementation merge authorized by
// AIPT-M0-B007-MERGE-001. Closeout must retain this commit/tree as the
// verified implementation identity and may add only one ordinary descendant.
export const B007_IMPLEMENTATION_MERGE = {
  directive: 'AIPT-M0-B007-MERGE-001',
  commit: 'e05179a223f9dd0ff1b317e78c0e466e1146f6bb',
  tree: B007_CANDIDATE.tree,
  parent1: B007_BASE_COMMIT,
  parent2: B007_CANDIDATE.commit,
  subject: B007_MERGE_SUBJECT,
  post_merge_ci_run: 32636449574,
  post_merge_ci_conclusion: 'success',
};

// Immutable B007 closeout and exact B008 source base. This ordinary
// single-parent authority commit does not replace the accepted B007
// implementation identity above.
export const B007_CLOSEOUT = {
  commit: '656154ff37f8cff0daff46d6f4b7dfe68254853c',
  tree: '4781236e62a112132e00c21bd5f5b407d73178ab',
  parent: B007_IMPLEMENTATION_MERGE.commit,
  ci_run: 32637552873,
  ci_conclusion: 'success',
};

export const B008_BASE_COMMIT = B007_CLOSEOUT.commit;
export const B008_BASE_TREE = B007_CLOSEOUT.tree;
export const B008_MERGE_SUBJECT = 'merge: integrate AIPT-M0-B008';
export const B008_CLOSEOUT_SUBJECT = 'closeout: complete AIPT-M0-B008';

// Exact linear Candidate history from the immutable B007 closeout base. All
// three commits are ordinary single-parent commits and the final entry is the
// lifecycle validator repair accepted by the Owner.
export const B008_CANDIDATE_HISTORY = [
  '6534edd8c721c7807db2fca1f20fe6f68aac08ce',
  '6647cd97cc46aeda981a6615ca6bd0a729cab38d',
  'e5659082f9a0ec657d5c33cc8063d8a410c335aa',
];

export const B008_INITIAL_CANDIDATE = {
  commit: '6647cd97cc46aeda981a6615ca6bd0a729cab38d',
};

export const B008_FINAL_CANDIDATE = {
  commit: 'e5659082f9a0ec657d5c33cc8063d8a410c335aa',
  tree: '9ad4341317e977d455e98ced20f3880d9e50c691',
  ci_run: 32808838664,
  ci_conclusion: 'success',
};

export const B008_LIFECYCLE_REPAIR = {
  finding: 'AIPT-B008-MILESTONE-VALIDATOR-LIFECYCLE-001',
  status: 'CLOSED',
  commit: 'e5659082f9a0ec657d5c33cc8063d8a410c335aa',
  parent: '6647cd97cc46aeda981a6615ca6bd0a729cab38d',
  changed_paths: ['scripts/ci/validate/m0-development-pass.mjs'],
};

// Exact two-parent implementation merge authorized by
// AIPT-M0-B008-MERGE-001. The closeout is one ordinary child of this commit;
// verified_head intentionally remains this implementation identity.
export const B008_IMPLEMENTATION_MERGE = {
  directive: 'AIPT-M0-B008-MERGE-001',
  commit: '8927a2779f3f123dabd472623d76d8e910152133',
  tree: '9ad4341317e977d455e98ced20f3880d9e50c691',
  parent1: '656154ff37f8cff0daff46d6f4b7dfe68254853c',
  parent2: 'e5659082f9a0ec657d5c33cc8063d8a410c335aa',
  subject: B008_MERGE_SUBJECT,
  post_merge_ci_run: 32819203218,
  post_merge_ci_conclusion: 'success',
};

// Immutable M0 closeout and exact AIPT-MVP-B000 source base. This ordinary
// single-parent authority commit made the M0 Development Pass effective; it
// does not replace the accepted B008 implementation identity above.
export const M0_CLOSEOUT = {
  commit: 'c617f3c6ab3e56ac88f228ed4825e751537fc1f0',
  tree: '95a8d2980c5a6aa44f3db67c66f07ff008ff3491',
  parent: B008_IMPLEMENTATION_MERGE.commit,
  subject: 'closeout: complete AIPT-M0-B008',
  ci_run: 32828913767,
  ci_conclusion: 'success',
};

export const MVP_B000_BASE_COMMIT = M0_CLOSEOUT.commit;
export const MVP_B000_BASE_TREE = M0_CLOSEOUT.tree;
export const MVP_B000_BRANCH = 'task/AIPT-MVP-B000';
export const MVP_B000_AUTHORITY = 'AIPT-MVP-B000-START-001';
export const MVP_B000_SNAPSHOT = 'AIPT-MVP-B000-CANDIDATE-001';
export const MVP_B000_NEXT_BATCH = 'AIPT-MVP-B001';

// Current cross-repository serial predecessor required by B007. Candidate,
// merge and closeout identities remain separately auditable facts.
export const B007_EXTERNAL_SERIAL_PREDECESSOR = {
  batch: 'UNREGISTERED-AIPT-P0-B003',
  status: 'MERGED_CLOSED',
  candidate: 'a304070b2a31c8717b6bacbb2a2c3b7aa5e49ad4',
  candidate_tree: 'aa86d842c82d2a7f33eb3e6c44378cbe5ab338cc',
  candidate_ci_run: 32619196472,
  candidate_ci_conclusion: 'success',
  merge_commit: '5d25dad0dbcb648de565ea723027f999ec5b3a37',
  merge_ci_run: 32621232115,
  merge_ci_conclusion: 'success',
  closeout_commit: '358d6d9d08a86818e34fd0c0d9a62bfe66e73abe',
  closeout_tree: '5585271c78d1fe5cd8357c7b36a501bee34f0240',
  closeout_ci_run: 32621464543,
  closeout_ci_conclusion: 'success',
};

export const EXTERNAL_SERIAL_HISTORY = [
  EXTERNAL_SERIAL_PREDECESSOR,
  {
    batch: 'UNREGISTERED-AIPT-P0-B002',
    status: 'MERGED_CLOSED',
    candidate: '284c50eeab65c0713a6776198004245895724cba',
    candidate_tree: '781220f10f7c2f72e58ba2d6d214b58833045a13',
    merge_commit: '5c12c0b5a126e8dfa891eae6d13f7d472781e87a',
    closeout_commit: '7ae44d12b3637e49f0883049a09423dd4f385341',
    closeout_tree: '84c5abd8ca74fca7c00ccf77b798481de8f3d7f7',
    closeout_ci_run: 32589300293,
    closeout_ci_conclusion: 'success',
  },
];

// B007 construction qualification telemetry. The installed Bridge exact
// identity did not match the reusable baseline and the fresh Q1 provider
// synchronization failed before any model call, so policy selected Codex-only.
export const B007_CONSTRUCTION_HARNESS = {
  bridge_version: '0.6.5',
  bridge_hotfix: 'security-audit-repair-r1',
  harness_source_commit: '141eb6fef83422698aef7a981029e843e8161534',
  baseline_identity_match: false,
  qualification_evidence_reused: false,
  qualification_result: 'UNQUALIFIED_OR_WITHDRAWN',
  qualification_failure: 'BRIDGE_PROGRESSIVE_TOOL_SYNCHRONIZATION',
  api_calls: 0,
  patch_produced: false,
  final_route: 'CODEX_ONLY',
  maximum_workers: 2,
  observed_peak_workers: 0,
  split_memory_manual_edit: false,
};

// Construction-routing telemetry is provenance, not a product runtime
// failure. The Bridge-owned split-memory profile remains outside repository
// authority and was not manually edited.
export const B006_CONSTRUCTION_HARNESS = {
  initial_route: 'CODEX_HARNESS',
  failure: 'HARNESS_INPUT_TOKEN_BUDGET',
  observed_input_tokens: 190183,
  input_token_limit: 180000,
  patch_produced: false,
  final_route: 'CODEX_ONLY',
  split_memory_manual_edit: false,
};

// The Owner-authorized 2026-08-22 DSH deployment upgrade. The previous
// frozen commit remains explicit historical provenance; B005 qualifies only
// the currently clean source checkout/tag as its external compatibility seam.
export const HARNESS_SOURCE = {
  installation: 'source',
  previous_commit: '47f943859bef60e4160492346772ded9b24f765a',
  commit: '141eb6fef83422698aef7a981029e843e8161534',
  release: 'dsh-v0.1.0-rc.8',
  upgrade_authority: 'AIPT-M0-B005-EXTERNAL-HARNESS-UPGRADE-001',
};

// Owner-gate ratification records the disposition known at closeout without
// inventing an independently verified pre-construction timing fact.
export const HARNESS_UPGRADE_RATIFICATION = {
  directive: 'AIPT-M0-B005-EXTERNAL-HARNESS-UPGRADE-001',
  disposition: 'OWNER_GATE_RATIFIED',
  ratified_on: '2026-08-22',
  prior_authorization_timing_independently_verified: false,
};

// Exact B004 dependency-security requalification. The B003-selected runtime
// identities remain historical facts; this records the current selected
// versions and every deterministic MVS consequence under Go 1.26.6.
export const B004_DEPENDENCY_SECURITY_REQUALIFICATION = {
  directive: 'AIPT-M0-B004-DEPENDENCY-SECURITY-REQUAL-001',
  batch: 'AIPT-M0-B004',
  advisory: 'GO-2026-5970',
  cve: 'CVE-2026-56852',
  module: 'golang.org/x/text',
  previous_version: 'v0.29.0',
  current_version: 'v0.39.0',
  fixed_in: 'v0.39.0',
  reason: 'reachable vulnerability',
  verified_at: '2026-08-20T16:00:40Z',
  vulnerability_authority: 'https://vuln.go.dev/ID/GO-2026-5970.json',
  upstream: 'https://go.googlesource.com/text',
  upstream_tag: 'v0.39.0',
  upstream_commit: 'b326f3d3c814ab79b3c516f4ac03c2314d8df65f',
  fix_commit: '5ae8e578e495731553eddba11b2d0e86c91a00ce',
  module_h1: 'h1:UbZz4pLOvn600D6Oh6GGEI6VAmndrEBLv8/6BEXzyus=',
  go_mod_h1: 'h1:3UwRclnC2g0TU9x8PZiyfOajCd1zaUNHF9cvqcQZ+ZM=',
  module_h1_sha256: '51b673e292cebe7eb4d03e8e87a186108e950269ddac404bbfcffa0445f3caeb',
  go_mod_h1_sha256: 'dd4c117259c2da0d1353dc7c3d98b27ce6a309dd7369434717d72fa9c419f993',
  raw_module_zip_sha256: 'cbfa33111dfa6cbafef63103b82c544d35df425824ac94ea19629a12bdbf0523',
  raw_go_mod_sha256: '40e9425e17dcc56faf496619fde6908631d57b2cce0f766c4dca6bea8fc93838',
  license: 'BSD-3-Clause',
  license_file_sha256: '911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad',
  go_version: '1.26.6',
  pgx_version: 'v5.10.0',
  vulnerability_database: 'https://vuln.go.dev',
  vulnerability_module_index: 'https://vuln.go.dev/index/modules.json',
  vulnerability_checked_at: '2026-08-20T16:16:58Z',
  vulnerability_module_index_sha256: '8b4159bf3e73d78c9246c49a6ccf576a27bb2f3871a4cf0046d94d128e068dca',
  vulnerability_qualifications: {
    'golang.org/x/text': {
      status: 'FIXED_AT_SELECTED_VERSION',
      known_advisory_ids: ['GO-2020-0015', 'GO-2021-0113', 'GO-2022-1059', 'GO-2026-5970'],
      affected_advisory_ids_at_selected_version: [],
      affected_package_graph_evidence: 'golang.org/x/text/unicode/norm is imported; GO-2026-5970 is fixed at selected v0.39.0',
      reachable_vulnerability: false,
    },
    'golang.org/x/sync': {
      status: 'NO_KNOWN_MODULE_ADVISORY',
      known_advisory_ids: [],
      affected_advisory_ids_at_selected_version: [],
      affected_package_graph_evidence: 'golang.org/x/sync/semaphore is imported; the fresh official module index contains no x/sync advisory',
      reachable_vulnerability: false,
    },
    'golang.org/x/mod': {
      status: 'AFFECTED_VERSION_GRAPH_ONLY_NO_IMPORTED_PACKAGE',
      known_advisory_ids: ['GO-2026-6179', 'GO-2026-6180'],
      affected_advisory_ids_at_selected_version: ['GO-2026-6179', 'GO-2026-6180'],
      affected_package_graph_evidence: 'go list -deps -test ./... imports no golang.org/x/mod package; Go 1.26.6 cmd/go is fixed',
      reachable_vulnerability: false,
    },
    'golang.org/x/tools': {
      status: 'NO_KNOWN_MODULE_ADVISORY',
      known_advisory_ids: [],
      affected_advisory_ids_at_selected_version: [],
      affected_package_graph_evidence: 'go list -deps -test ./... imports no golang.org/x/tools package; the fresh official module index contains no x/tools advisory',
      reachable_vulnerability: false,
    },
  },
  mvs_induced_changes: [
    {
      module: 'golang.org/x/sync',
      previous_version: 'v0.17.0',
      current_version: 'v0.21.0',
      role: 'runtime_dependency',
      direct: false,
      upstream_commit: '5071ed6a9f1617117556b66384f765c934de3698',
      module_h1: 'h1:HLII4xRRTtCRkxYp4HNFF0Js/Og6q2i++KXbg0gHCwM=',
      go_mod_h1: 'h1:9xrNwdLfx4jkKbNva9FpL6vEN7evnE43NNNJQ2LF3+0=',
      module_h1_sha256: '1cb208e314514ed091931629e0734517426cfce83aab68bef8a5db8348070b03',
      go_mod_h1_sha256: 'f71acdc1d2dfc788e429b36f6bd1692fabc437b7af9c4e3734d3494362c5dfed',
      raw_module_zip_sha256: 'ee65459023de7f24836f6e2123144b5329bd0a4d05a87c3c448509378e2e6be7',
      raw_go_mod_sha256: 'a3e29e76060bd561060454b1fa2bdcd66674f60c9ca93833b8106355e34c603c',
    },
    {
      module: 'golang.org/x/mod',
      previous_version: 'v0.27.0',
      current_version: 'v0.37.0',
      role: 'module_graph_tooling',
      direct: false,
      upstream_commit: 'deb1dfcdb7c7fd98fb5afddc3e95dd36d5880874',
      module_h1: 'h1:vF1DjpVEshcIqoEaauuHebaLk1O1forxjxBaVn884JQ=',
      go_mod_h1: 'h1:m8S8VeM9r4dzDwjrKO0a1sZP3YjeMamRRlD+fmR2Q/0=',
      module_h1_sha256: 'bc5d438e9544b21708aa811a6aeb8779b68b9353b57e8af18f105a567f3ce094',
      go_mod_h1_sha256: '9bc4bc55e33daf87730f08eb28ed1ad6c64fdd88de31a9914650fe7e647643fd',
      raw_module_zip_sha256: '91e8e4e9b74a8706dae808b66538d4ab22befd00c11f34134eb97ff572d52e85',
      raw_go_mod_sha256: '538472fdf094dd5e49dc40e70468fa931a93c241eba07fb946a98747c94ab4df',
    },
    {
      module: 'golang.org/x/tools',
      previous_version: 'v0.36.0',
      current_version: 'v0.47.0',
      role: 'module_graph_tooling',
      direct: false,
      upstream_commit: 'fbf9f2e2c8124fbe1877f5ed2857111038d9fe12',
      module_h1: 'h1:7Kn5x/d1svx/PzryTsqeoZN4TZwqeH5pGWjefhLi/1Q=',
      go_mod_h1: 'h1:dFHnyTvFWY212G+h7ZY4Vsp/K3U4/7W9TyVaAul8uCA=',
      module_h1_sha256: 'eca9f9c7f775b2fc7f3f3af24eca9ea193784d9c2a787e691968de7e12e2ff54',
      go_mod_h1_sha256: '7451e7c93bc5598db5d86fa1ed963856ca7f2b7538ffb5bd4f255a02e97cb820',
      raw_module_zip_sha256: '143d132b519da1454db967febb65241796805d7c9d4752034341c1376fd3d7f1',
      raw_go_mod_sha256: 'eb46e44850fb4dca48f7b680cac5177682cb0e302b307d4d3dbd7ed9df05fc0f',
    },
  ],
};

export const BASE_COMMIT = B008_BASE_COMMIT;
export const BASE_TREE = B008_BASE_TREE;

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

// Exact cumulative AIPT-M0-B008 surface from Base through final closeout.
// Runtime/product implementation, schemas, dependencies, lockfiles,
// toolchains, SBOM and supply-chain sources remain frozen. package.json is a
// historical Candidate change and is not part of the closeout allowlist.
export const ALLOWED_PATHS = [
  '.github/workflows/ci.yml',
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/milestones/M0.md',
  'docs/milestones/M0_DEVELOPMENT_PASS.md',
  'docs/milestones/m0-development-pass.json',
  'package.json',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/m0-development-pass.mjs',
  'scripts/ci/validate/standalone-entrypoints.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
  'scripts/ci/validate/workflow.mjs',
];

// Exact Owner-authorized B008 closeout surface. It contains governance state,
// milestone metadata, and only the CI labels/validators needed to enforce the
// final lifecycle. package.json and every product/runtime path remain frozen.
export const CLOSEOUT_ALLOWED_PATHS = [
  '.github/workflows/ci.yml',
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'docs/milestones/M0.md',
  'docs/milestones/M0_DEVELOPMENT_PASS.md',
  'docs/milestones/m0-development-pass.json',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/m0-development-pass.mjs',
  'scripts/ci/validate/standalone-entrypoints.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
  'scripts/ci/validate/workflow.mjs',
];

// Exact machine/human status transition subset used by the final closeout.
// Milestone record validation is owned by its dedicated gate.
export const STATUS_TRANSITION_PATHS = [
  'README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/project-status.json',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/validate/status-transition.mjs',
];

// Frozen predecessor implementation, dependency and future-product areas.
export const FORBIDDEN_PREFIXES = [
  'cmd/',
  'internal/',
  'packages/',
  'schemas/',
  'testdata/',
  'tools/',
  'scripts/ci/sbom/',
  'scripts/ci/validate/sbom.mjs',
  'scripts/ci/validate/supply-chain.mjs',
  'docs/architecture/',
  'docs/integration/',
  'docs/test-model/',
  '.go-version',
  'go.mod',
  'go.sum',
  'LICENSE',
  'pnpm-lock.yaml',
  'pnpm-workspace.yaml',
  'tools/toolchain.lock.json',
  'tools/ci-actions.lock.json',
  'tools/supply-chain/policy.json',
  'tools/supply-chain/licenses.json',
];

// Frozen authority registries: byte-for-byte immutability is enforced
// against the accepted main base. decisions.json, supersessions.json, and
// deferred-parameters.json are all fully frozen for B007 (the B003
// security-requalification controlled evolution of deferred-parameters.json
// is closed; B007 performs no deferred-parameters work).
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

// Exact governance/CI-only surface authorized for AIPT-MVP-B000. The older
// B008 allowlists above remain frozen historical inputs to the M0 final gate;
// current lifecycle validators use this separate successor surface.
export const MVP_B000_ALLOWED_PATHS = [
  '.github/workflows/ci.yml',
  'README.md',
  'docs/authority/README.md',
  'docs/authority/BATCH_DEPENDENCY_GRAPH.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/registry/batch-graph.json',
  'docs/authority/registry/project-status.json',
  'docs/milestones/MVP.md',
  'package.json',
  'scripts/ci/lib/constants.mjs',
  'scripts/ci/run-checks.mjs',
  'scripts/ci/validate/m0-development-pass.mjs',
  'scripts/ci/validate/mvp-bootstrap.mjs',
  'scripts/ci/validate/standalone-entrypoints.mjs',
  'scripts/ci/validate/status-transition.mjs',
  'scripts/ci/validate/tree-integrity.mjs',
  'scripts/ci/validate/workflow.mjs',
];

export const M0_HISTORICAL_PATHS = [
  'docs/milestones/M0.md',
  'docs/milestones/M0_DEVELOPMENT_PASS.md',
  'docs/milestones/m0-development-pass.json',
];

export const MVP_B000_FORBIDDEN_PREFIXES = [
  'cmd/',
  'internal/',
  'packages/',
  'schemas/',
  'testdata/',
  'tools/',
  'scripts/ci/sbom/',
  'scripts/ci/validate/sbom.mjs',
  'scripts/ci/validate/supply-chain.mjs',
  'docs/architecture/',
  'docs/harness/',
  'docs/evidence/',
  'docs/integration/',
  'docs/licensing/',
  'docs/runtime/',
  'docs/supply-chain/',
  '.go-version',
  'go.mod',
  'go.sum',
  'LICENSE',
  'pnpm-lock.yaml',
  'pnpm-workspace.yaml',
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

export function pathMatchesCloseoutAllowed(p) {
  return CLOSEOUT_ALLOWED_PATHS.includes(p);
}

export function pathMatchesStatusTransition(p) {
  return STATUS_TRANSITION_PATHS.includes(p);
}

export function pathMatchesMvpB000Allowed(p) {
  return MVP_B000_ALLOWED_PATHS.includes(p);
}
