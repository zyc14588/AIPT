# UNREGISTERED P1 B000 Authority Amendment 001

Task: `UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-001`

Machine execution authority: [`../registry/unregistered-aipt-p1-b000-authority-amendment-001.json`](../registry/unregistered-aipt-p1-b000-authority-amendment-001.json)

This document explains the machine record. If they conflict, the machine record controls. This Amendment is append-only: it does not edit, re-hash, replace, revert, squash or rewrite the original Authority or its merge history.

This file is the replacement revision produced by task `UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-001-R1`. Candidate `00c9a25ea3df7436339a104de4c412d6d6f39322` (tree `f308f1885112e0826dc6be4b70b0d7713d1a8dba`, CI run `32987673859`) is `SUPERSEDED_BEFORE_MERGE` because its bootstrap model could not legally accept the Amendment's own closeout successor. That commit, tree, branch and CI provenance remain preserved and must not be merged, deleted, rewritten or force-updated. R1 keeps every original Amendment authorization and changes only bootstrap closeout-successor acceptance plus the directly necessary CI classifier semantics.

## 1. Exact base Authority

The immutable base is `UNREGISTERED-AIPT-P1-B000-AUTHORITY-001`:

- approved Candidate commit `c9f7729f666d11716c04d7682da16044ca965236`;
- approved Candidate tree `9cf551e7bc70d4354ca21d62a2bd456ed6f401bb`;
- lawful GitHub PR #6 merge commit `169f9bd006dabb88eb653ab09a33b0eef5eadaed`;
- merge tree `9cf551e7bc70d4354ca21d62a2bd456ed6f401bb`;
- merge parents `eede815e818d87362605f55d5bfd2a0460e6e130` and `c9f7729f666d11716c04d7682da16044ca965236`;
- merge mechanism `github_pr_merge_commit`.

The Candidate is preserved, ancestry is verified, the merge tree equals the Candidate tree, the Authority artifacts are preserved, and the merge introduces no unauthorized content. The Authority is merged, is not post-merge verified, and is not closed.

The base artifact manifest remains exactly `docs/authority/registry/unregistered-aipt-p1-b000-authority-artifacts.json` with SHA-256 `3e7d5ee752ac01ae4034fdaf2ec71231bb4f58eca9174e99619d0a13b200cd4f`. Its historical entries are never edited to make a superseding validator look original.

## 2. Why an Amendment is necessary

Three independently observed defects create the narrow need for this record:

1. `scripts/ci/validate/p1-b000-authority.mjs` applies Candidate-only zero-merge and exact-task-branch rules to legitimate merged and post-merge main states.
2. `scripts/ci/validate/mvp-b001.mjs` treats immutable historical CLOSED state as an active Candidate and dereferences an absent `pending_candidate`, causing an uncaught `TypeError` instead of a structured failure result.
3. The lawful Authority merge has no GitHub check run. The immutable historical fact is `original_merge_check_run = ABSENT`; it is not and must never be described as a historical CI pass.

This task creates authorization and verification infrastructure only. It does not repair either validator, close the Authority, start the recovery run, or start `UNREGISTERED-AIPT-P1-B000` implementation.

## 3. Original frozen validator identity

The original frozen identity permanently remains:

- role: `ORIGINAL_FROZEN_AUTHORITY_VALIDATOR_IDENTITY`;
- artifact role: `AUTHORITY_VALIDATOR_IDENTITY`;
- path: `scripts/ci/validate/p1-b000-authority.mjs`;
- SHA-256: `f5ed47898ad13b193cd685ae9649c18cada3a6fb5893c1810867c91869ad8c7c`.

A repair does not retroactively change what the Authority froze. It may only add a `SUPERSEDING_AUTHORITY_VALIDATOR_IDENTITY` through a record conforming to `schemas/authority-amendment/v1/aipt-authority-validator-supersession.schema.json`.

Every supersession record carries `role`, `path`, `old_sha256`, `new_sha256`, `amendment_id`, `repair_task_id`, `repair_candidate_commit`, `reason`, `semantic_constraints`, and `regression_evidence`. The first Authority-validator link must use the exact old SHA-256 above. The first B001 historical-validator link must use `ba29c75b68c282484cbdceeb7ae035c010b51181ce8e2b5f5b54b9c11a241aaf`.

Because a Git commit cannot contain its own object ID, a supersession record is appended in a governance/provenance commit that descends from, and names, the earlier repair artifact commit. It must never claim that the record itself was present in the `repair_candidate_commit` it names. The record can become effective only through the independently accepted repair history; this ordering avoids placeholders and self-referential hashes without rewriting the repair artifact commit.

Records are ordered by role and integer chain sequence. Link one starts at the frozen hash. Every following link names its predecessor and must use the previous accepted `new_sha256` as its own `old_sha256`. Two changes to one role that do not form that explicit contiguous chain fail closed.

## 4. Narrow repair authority

After this Amendment is independently accepted, one separate repair task may propose the following behavior changes:

- make the Authority validator distinguish Candidate, merged, post-merge and closed topology;
- make the B001 validator derive CLOSED state from immutable accepted/closeout identity;
- require `pending_candidate` only in ACTIVE/CANDIDATE phases;
- return a structured FAIL for invalid lifecycle combinations rather than throw an uncaught exception;
- add an exact-target post-merge reverification definition and append-only evidence surface.

That authority does not permit weaker validation. A repair must retain artifact hashes, ancestry, Candidate identity, scope, negative lifecycle checks, rejection of unauthorized commits, rejection of artifact drift and rejection of illegal transitions.

It also cannot change the Playtest Package Contract, Runtime Adapter Input Contract, B000 objective or non-goals, or any protected B001 business semantics. Campaign → Suite → Case → Run, internal-only Attempt, immutable Run Manifest, PostgreSQL queue authority, WIP=1, deterministic selection, lease, heartbeat, expiry, recovery and append-only attempt history remain protected. Migration `internal/storage/postgres/migrations/000002_playtest_queue.sql` remains SHA-256 `47f02a5a2129473caa0db5e359a0b294a01b2a96329d9f6fa08ac87cc429c997`.

## 5. Effective Authority resolution

Effective Authority is resolved as:

1. the exact immutable base Authority and base artifact manifest;
2. accepted Amendments ordered by their unique integer sequence and accepted merge first-parent ancestry;
3. accepted supersession links ordered by role and explicit chain sequence.

An Amendment is accepted only when a separately Owner-approved no-fast-forward merge preserves its Candidate tree and occurs in the accepted first-parent history. A supersession is effective only when its Amendment is accepted and its own repair Candidate has independent acceptance evidence.

File modification time, directory enumeration order, “latest file wins,” and “the current main hash is the Authority” are prohibited resolution rules. An effective-resolution report must retain the base Authority identity, Amendment identity, old hash, new hash, reason, repair Candidate and independent acceptance evidence.

## 6. Post-merge reverification

The missing historical check may be addressed only by evidence conforming to `schemas/authority-amendment/v1/aipt-post-merge-reverification-evidence.schema.json` and only when every eligibility condition in the machine Amendment holds.

The recovery execution must:

- retain `original_merge_check_run = ABSENT` and `historical_merge_ci = NOT_CLAIMED_PASS`;
- target commit `169f9bd006dabb88eb653ab09a33b0eef5eadaed` and tree `9cf551e7bc70d4354ca21d62a2bd456ed6f401bb` exactly;
- independently prove Candidate identity, merge ancestry, tree equality and absence of unauthorized merge content;
- check out the requested target as an exact, clean detached tree in a separate target directory;
- run a required-CI-equivalent suite with validator and workflow definitions from the accepted repair Candidate;
- record workflow run ID, workflow definition identity, requested and resolved target SHAs, target tree, validator identities, result and individual jobs;
- distinguish the workflow execution identity, including `run.head_sha`, from the old commit being verified;
- pass the B001 regression and effective Authority identity gates.

Recovery is unavailable when a required real CI run exists and failed, when merge contents are unknown, when tree or scope drifts, when an unauthorized commit exists, when a validator fails, or when a modified working tree is presented as the old target. A recovery PASS is new reverification evidence; it is never a retroactive GitHub check run and never rewrites the missing historical run into PASS.

The recovery workflow is deliberately not implemented by this Amendment Candidate. The machine policy requires both that workflow definition and the repaired validator identities to come from the separately accepted repair Candidate.

## 7. Single-use bootstrap closeout successor

The bootstrap permission recognizes exactly three lifecycle classes: the R1 Candidate, its legal no-fast-forward merge, and one `BOOTSTRAP_CLOSEOUT_SUCCESSOR`. It is not authority for arbitrary later commits.

The replacement Candidate is the single ordinary commit on branch `task/UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-001-R1` whose parent is the exact base merge. The legal Amendment merge must have that base merge as first parent, the approved replacement Candidate as second parent, and a tree equal to the Candidate tree. The closeout successor must then be the direct, single-parent child of that accepted Amendment merge. A second-generation or unrelated successor is not eligible.

The closeout successor has one exact allowed path:

- `docs/authority/registry/authority-amendment-closeouts/unregistered-aipt-p1-b000-authority-amendment-001-closeout.json`

That record must conform to `schemas/authority-amendment/v1/aipt-authority-amendment-closeout.schema.json`. It records the accepted Candidate and merge identities, their real CI, post-merge verification, the separately issued Owner closeout authorization, the transition `MERGED` through `POST_MERGE_VERIFIED` to `CLOSED`, and the facts that business code, both frozen validators and B000 implementation remain unchanged. Git topology supplies the closeout commit identity so the record does not need a self-referential commit hash.

Every other path is denied. In particular, the successor cannot modify either frozen validator, any `internal/`, `cmd/` or `packages/` path, either B000 business schema, the base Authority, or any frozen Amendment semantic artifact. The permission is single-use and expires automatically when the Amendment reaches `CLOSED`. It is unavailable to `UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001`, whose purpose is to fix F1 and F2 rather than classify them.

## 8. Executed legacy-defect classifier

Bootstrap never means that the two legacy validators are skipped. Candidate, legal-merge and closeout CI execute both frozen files and preserve raw stdout and stderr:

- F1 binds `scripts/ci/validate/p1-b000-authority.mjs` to SHA-256 `f5ed47898ad13b193cd685ae9649c18cada3a6fb5893c1810867c91869ad8c7c`, structured result `FAIL`, and exactly the three stable candidate-only topology/scope failures caused by the post-base governance lifecycle. Its reported path inventory must equal the exact Git lifecycle diff; any additional `FAIL` rejects.
- F2 binds `scripts/ci/validate/mvp-b001.mjs` to SHA-256 `ba29c75b68c282484cbdceeb7ae035c010b51181ce8e2b5f5b54b9c11a241aaf`, exit status 1, the exact `TypeError` message for absent `pending_candidate.merge_authorized`, and the frozen application failure sites. A different TypeError, stack site, stdout result or extra error rejects.

Only these two exact observations receive `KNOWN_PREEXISTING_BOOTSTRAP_DEFECT`; they are never reported as PASS. A hash change, third failure, new failure class, Amendment-specific failure, artifact/ancestry/scope drift, B001 business regression or unrelated real CI failure fails the job. The classifier pipeline is run → capture raw result → verify frozen identity and exact fingerprint → fail unless only F1/F2 match.

Candidate CI, Amendment-merge CI and closeout-successor CI must each be real runs bound to their own head SHA. A real failed CI conclusion is never recoverable. The already-closed M0-development-pass and MVP-bootstrap task-branch stages, plus the aggregate that repeats the same two broken validators, are inapplicable during this three-state bootstrap window; all unaffected business gates, the Amendment validator, `go test ./...`, artifact/provenance/lifecycle checks, A01–A20 and R01–R20 probes remain mandatory.

## 9. Acceptance and stop boundary

This Amendment Candidate may become merge-eligible only after its schemas, validator, A01–A20 negative probes, B001 protected baseline, local suite and Candidate-bound remote CI all pass, its Git commit/tree are frozen, its worktree is clean, and open findings are empty.

The R1 Candidate must also pass all R01–R20 topology, fingerprint, CI, scope, duplicate-use, expiry and repair-task exclusion probes. The classifier is fail closed before Amendment closeout and automatically routes to normal gates after the closeout record is present in the exact direct successor. It never turns a legacy FAIL into PASS: it reports the raw failure and its exact authorized classification.

Even then:

- `merge_authorized = false`;
- repair remains unauthorized and not started;
- closeout remains unauthorized;
- B000 implementation remains unauthorized and not started.

Only a separate Owner action may merge the Amendment. Only after that acceptance may the distinct task `UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001` be authorized.
