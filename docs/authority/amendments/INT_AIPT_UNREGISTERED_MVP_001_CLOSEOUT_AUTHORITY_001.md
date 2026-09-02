# INT-AIPT-UNREGISTERED-MVP-001 Closeout Authority Amendment 001

Authority task: `INT-AIPT-UNREGISTERED-MVP-001-CLOSEOUT-AUTHORITY-001`

Owner directive: `FORMAL_CLOSEOUT_REGISTRATION_001`

## Purpose

This governance-only amendment closes the gap
`READ_ONLY_INTEGRATION_CLOSEOUT_NOT_PERSISTED_IN_MACHINE_AUTHORITY`. The
integration stage and local closeout already passed. This amendment does not
execute the integration again and does not change either fixed source.

The existing `MERGED → POST_MERGE_VERIFIED → CLOSED` Authority lifecycle is a
Git implementation lifecycle. It cannot truthfully represent a read-only
integration that has no Candidate, no repository merge, no merge parents, and
no merge CI. Those identities must not be fabricated.

## Machine contract

The game-neutral schema is
[`aipt-read-only-integration-closeout.schema.json`](../../../schemas/integration-lifecycle/v1/aipt-read-only-integration-closeout.schema.json).
The canonical record is
[`int-aipt-unregistered-mvp-001-closeout.json`](../registry/integration-closeouts/int-aipt-unregistered-mvp-001-closeout.json).

The record binds only stable IDs, Git commit/tree identities, SHA-256 values,
PASS/FAIL results, counters, classifications, authorization, record identity,
and provenance. It contains no game prose, guide or handout text, private
prompt, credential value, private asset locator, or local absolute path.

## Frozen identity and lifecycle meaning

- AIPT source remains `c65075691e0b9503a8e3bd9da1220bf319354a26` / `bd2fa7d7374f1bbff44c1f5aa4746a86f68d41eb`.
- The external package remains `fe0965977447caf8cd7b6e58252bc1b991b7cc6f` / `34597e79c586fb034256daa32d67640692ec589d`.
- Its nested source remains `358d6d9d08a86818e34fd0c0d9a62bfe66e73abe` / `5585271c78d1fe5cd8357c7b36a501bee34f0240`.
- `repository_merge_performed = false` and `closeout_kind = READ_ONLY_INTEGRATION` disambiguate the `MERGED_CLOSED` project-status projection. The projection means formally closed in the serial batch registry; it does not claim a Git merge for the integration.
- The governance Candidate that carries this amendment is a later AIPT governance commit. It does not replace the fixed AIPT source used by the completed integration.

## Successor boundary

After this amendment Candidate is published, passes public CI, is merged, is
post-merge verified, and is itself formally closed, `AIPT-MVP-B005` may be
considered for a separate Owner authorization. This amendment does not grant
that authorization: B005 remains `NOT_AUTHORIZED` and `NOT_STARTED`.

## Scope

This amendment changes governance records, the integration-lifecycle schema,
and CI validators only. B001, B002, B003, and B004 semantics remain unchanged;
no runtime, business implementation, Run Manifest business schema,
qualification rule, source package, or game content is modified.
