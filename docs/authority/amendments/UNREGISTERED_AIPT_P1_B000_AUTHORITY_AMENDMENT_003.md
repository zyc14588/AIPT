# UNREGISTERED AIPT P1 B000 Authority Amendment 003

Task: `UNREGISTERED-AIPT-P1-B000-AUTHORITY-AMENDMENT-003`

State in this immutable semantic snapshot: `CANDIDATE_FROZEN`

Accepted in this immutable semantic snapshot: `false`

This Amendment is governance infrastructure only. It neither starts nor
implements `UNREGISTERED-AIPT-P1-B000`, and it does not authorize its own
merge, its own closeout, Amendment-002 closeout, or any runtime/model work.

## Decision

Authority semantics and Authority lifecycle are separate objects:

```text
immutable semantic artifact
        │ exact task / candidate / tree / artifact hashes
        ▼
accepted append-only lifecycle record chain
        │ MERGED → POST_MERGE_VERIFIED → CLOSED
        ▼
deterministic effective-Authority resolution
```

`state = CANDIDATE_FROZEN` and `accepted = false` inside a frozen semantic
artifact are freeze-time snapshot metadata. They are not mutable current
lifecycle truth. No lifecycle transition may edit a frozen artifact.

The only canonical current lifecycle source introduced here is the accepted
append-only lifecycle record chain. `project-status.json`, prose status and
other displays are derived projections; disagreement with the chain is a
validation failure.

## Existing authority facts preserved

- Base Authority is CLOSED at `8d6a438d051fb635e769285215e70536958a8f42`.
- Amendment-001-R1 is CLOSED at
  `2619339e53113633e02f3aef14156a1ff08c13f8` after candidate
  `a1d614c7468f67d13bcbf32f65ade7613a85e202` and merge
  `33a53d53c6db474f46a886dcbbba6d083eee4f27`.
- Post-Merge Repair-001 is CLOSED with accepted merge
  `df71476d4b8f271f3b444cace46a3d6fbd1eaea4`.
- Amendment-002 candidate `45067db875b7bc3ee657ef117ae13ce55ce2af85`
  and tree `1b173e129ccb3df1e1a9bc80385f9dc4f530b6ca` were legally merged as
  `005ec002e7d8bcccd83d3f3994fddf9da30ff82a`. GitHub Actions run
  `33131896928` succeeded with five jobs. Amendment-002 is MERGED and
  POST_MERGE_VERIFIED, but it is not CLOSED.

No Amendment-002 semantic artifact is changed by this Amendment.

## Root-cause matrix

| Source | Old interpretation | Unsatisfied constraint | This Amendment |
| --- | --- | --- | --- |
| Frozen semantic record | `accepted=false` is current truth | Frozen bytes cannot advance | Treat as snapshot metadata |
| Effective resolver | Artifact must mutate to accepted | Immutable artifact can never become effective | Require exact identity plus lifecycle chain |
| Amendment-002 validator | Current HEAD must be candidate/legal merge | Any lawful successor fails topology | Replay semantic gate at exact merge |
| Amendment-001 closeout | Task-specific closed world | Future authorities cannot reuse it | Generic record/schema/resolver |

Semantic validation therefore targets an exact frozen candidate or its exact
legal merge tree. Lifecycle validation targets the current accepted record
chain. A later main descendant is neither semantic acceptance nor lifecycle
acceptance by itself.

## Canonical lifecycle record

The machine schema is
`schemas/authority-lifecycle/v1/aipt-authority-lifecycle-record.schema.json`.
Every record binds:

- a unique record and task ID;
- exact semantic artifact path, SHA-256, candidate commit and candidate tree;
- one event and contiguous sequence;
- the prior record ID and canonical record digest;
- the authority basis;
- merge, post-merge CI, or closeout evidence;
- the immutable containing Git commit/path identity;
- creator and historical provenance; and
- an effective assertion that is true only for the CLOSED record.

Record files are accepted only when their containing commit is on the accepted
first-parent governance ancestry and their introduction/current blob identity
is unchanged. File presence, current branch contents, mtime, lexical filename
order and directory enumeration order are never sufficient.

The deterministic order is:

1. `event_sequence` ascending;
2. explicit predecessor record ID plus SHA-256 chain;
3. accepted commit ordinal ascending.

Once accepted, a record cannot be edited, deleted, reordered or overwritten.
The only legal state advance is another record. Deletion/rewrite is checked
against the previous accepted record set as well as predecessor digests.

## Transitions and effective state

The default transition chain is exact:

```text
SEMANTIC_ONLY → MERGED → POST_MERGE_VERIFIED → CLOSED
```

Skipping an event, duplicate events, forks, gaps, unrelated tasks, wrong
semantic identity, wrong candidate/tree, false evidence, or any successor of
CLOSED is rejected. CLOSED is terminal.

An Amendment is effective only when all three accepted records bind its exact
semantic identity. Consequently:

- frozen `accepted=false` plus a valid CLOSED chain is effective;
- frozen `accepted=true` without the chain is not effective; and
- a main descendant without records is not accepted.

The CLOSED lifecycle record is the sole closeout state record. No second
closeout schema or mutable closeout flag is introduced.

## Historical migration anchors

The generic registry is
`docs/authority/registry/authority-lifecycle/registry.json`. Existing Base,
Amendment-001-R1 and Repair-001 closeout evidence is adapted as immutable
migration roots using exact paths, SHA-256 values and accepted commits. This
does not fabricate historical events and cannot be extended with new legacy
anchors after activation. All new lifecycle events use v1 records.

## Amendment-002 recovery

After, and only after, Amendment-003 itself is CLOSED, a separately authorized
governance task may add exactly these records:

```text
docs/authority/registry/authority-lifecycle/records/
  unregistered-aipt-p1-b000-authority-amendment-002/
    001-merged.json
    002-post-merge-verified.json
    003-closed.json
```

MERGED and POST_MERGE_VERIFIED may be backfilled only from the real candidate,
merge and run `33131896928`. CLOSED requires a new real owner-authorized
governance-only closeout commit; this Amendment does not claim it already
exists. The semantic artifact SHA-256 remains
`1ecce52415f4c1fff93383250d2e4df88d8aa381d93e81711681534d59df72e5`.
The recovery uses the accepted general mechanism, never the Amendment-003
self-closeout bootstrap.

## One-time Amendment-003 self-closeout bootstrap

The bootstrap recognizes only:

```text
VALID_CANDIDATE
VALID_LEGAL_MERGE
VALID_DIRECT_SELF_CLOSEOUT
```

The candidate is one ordinary commit directly above
`005ec002e7d8bcccd83d3f3994fddf9da30ff82a`. The legal merge is an
owner-approved two-parent merge whose tree equals the candidate tree. The
self-closeout is exactly one ordinary governance-only child of that merge,
after successful post-merge verification.

The self-closeout child may add only:

```text
docs/authority/registry/authority-lifecycle/records/
  unregistered-aipt-p1-b000-authority-amendment-003/
    001-merged.json
    002-post-merge-verified.json
    003-closed.json
```

It cannot modify Amendment-003 semantics, Amendment-002, Base Authority,
business code, the two protected validators, Playtest Package or Runtime
Adapter schemas, migrations, or UNREGISTERED content. It is single-use and
expires permanently as soon as the resolved Amendment-003 state is CLOSED.
An unrelated successor, multi-hop successor, business successor, semantic
mutation or other-task record is rejected by the bootstrap classifier.

## Protected baselines

The Authority validator remains
`c6f0c8e01397200ce15f48bf1fc2412d9db477dddc37d3f99e0478d26956dd0c`.
The B001 validator remains
`319c8d4a3466c20d14e2d5fc74cc246c9b796d36f884fcc39e2b0a25317351c4`.
Migration `000002_playtest_queue.sql` remains
`47f02a5a2129473caa0db5e359a0b294a01b2a96329d9f6fa08ac87cc429c997`.

Campaign → Suite → Case → Run, internal-only Attempt, immutable Run Manifest,
PostgreSQL queue authority, WIP=1, deterministic selection, lease, heartbeat,
expiry, recovery and append-only attempt history remain unchanged. Run Core,
agent orchestration and a real model gateway remain unimplemented; real model
calls and real playtests remain zero.

## Stop boundary

Candidate success means only that this Amendment is merge-eligible. It does
not authorize merge or closeout. On successful candidate CI the next task is
`MERGE_AND_CLOSEOUT_AMENDMENT_003`, still unauthorized and not started.
Amendment-002 remains open, and `UNREGISTERED-AIPT-P1-B000` remains
unauthorized and not started.
