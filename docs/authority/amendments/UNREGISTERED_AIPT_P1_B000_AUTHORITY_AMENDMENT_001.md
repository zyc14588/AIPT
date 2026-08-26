# UNREGISTERED P1 B000 Authority Amendment 001

Task: `UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-001`

Machine execution authority: [`../registry/unregistered-aipt-p1-b000-authority-amendment-001.json`](../registry/unregistered-aipt-p1-b000-authority-amendment-001.json)

This document explains the machine record. If they conflict, the machine record controls. This Amendment is append-only: it does not edit, re-hash, replace, revert, squash or rewrite the original Authority or its merge history.

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

## 7. Acceptance and stop boundary

This Amendment Candidate may become merge-eligible only after its schemas, validator, A01–A20 negative probes, B001 protected baseline, local suite and Candidate-bound remote CI all pass, its Git commit/tree are frozen, its worktree is clean, and open findings are empty.

The existing aggregate and lifecycle gates are also executed locally and their pre-existing stage-classification failures are recorded, but they are not called PASS. Candidate and exact Amendment-merge CI use a fail-closed bootstrap classifier: only a complete PASS from this Amendment validator over the exact eleven-path scope may suppress the five legacy stage-bound commands (`check:m0-development-pass`, `check:mvp-b001`, `check:mvp-bootstrap`, `check:p1-b000-authority`, and the aggregate `check`). Every unclassified checkout runs those legacy commands normally. The Amendment focused gate, `go test ./...`, and all unaffected business contract gates remain mandatory. This narrow bootstrap behavior is needed so the frozen validators being governed cannot veto the Owner-authorized mechanism solely because they do not recognize its lifecycle; it never converts their skipped or known-failing result into PASS.

Even then:

- `merge_authorized = false`;
- repair remains unauthorized and not started;
- closeout remains unauthorized;
- B000 implementation remains unauthorized and not started.

Only a separate Owner action may merge the Amendment. Only after that acceptance may the distinct task `UNREGISTERED-AIPT-P1-B000-AUTHORITY-POSTMERGE-REPAIR-001` be authorized.
