# UNREGISTERED-AIPT-P1-B000 Authority Contract

> Authority task: `UNREGISTERED-AIPT-P1-B000-AUTHORITY-001`
> Authority version: `1.0.0`
> Frozen implementation batch: `UNREGISTERED-AIPT-P1-B000`
> Machine authority: [registry/unregistered-aipt-p1-b000-authority.json](registry/unregistered-aipt-p1-b000-authority.json)

## 1. Result and precedence

This authority task freezes the executable contract for the future UNREGISTERED P1 package batch. It is governance work, not the implementation batch. The implementation task remains `PLANNED`, `authorized = false`, `started = false`, and `merge_authorized = false`.

The existing precedence in [README.md](README.md) remains controlling. An `ACTIVE` decision or the terminal `ACTIVE` member of a `REFINED` chain outranks this task-scoped machine contract. When no higher active decision conflicts, the machine contract outranks this page, milestone prose, and roadmap prose. This page explains the machine contract and creates no second authority.

The AIPT authority candidate cannot embed its own Git commit or tree without changing that identity. The final structured stage review records the candidate commit/tree and artifact-manifest SHA-256. A future Owner start directive for `UNREGISTERED-AIPT-P1-B000` must copy those exact values. A reference to “latest authority” is invalid.

## 2. Verified fixed ancestry

The AIPT construction base is exactly:

```text
commit eede815e818d87362605f55d5bfd2a0460e6e130
tree   d2668f0ea9d3b72969199c7cd8afc5edb94c2a6b
task   AIPT-MVP-B001 / MERGED_CLOSED
```

The fixed game-source snapshot is exactly:

```text
repository zyc14588/UNREGISTERED
commit     358d6d9d08a86818e34fd0c0d9a62bfe66e73abe
tree       5585271c78d1fe5cd8357c7b36a501bee34f0240
readiness  PLAYTESTABLE_DRAFT
```

The existing `aipt/input-manifest.json` is a P0-B001 inventory and `aipt/p0-b003/game-adapter.json` is a predecessor asset. Neither is P1 authority. The actual source material remains at the fixed UNREGISTERED snapshot; the future P1 manifest is metadata in the P1 candidate and therefore binds the historical source commit/tree rather than attempting a self-referential containing-commit binding.

## 3. Objective

Establish and validate the UNREGISTERED P1 Playtest Package Contract so a package with fixed source identity can be accepted by AIPT through versioned, deterministic, auditable and hidden-information-isolated input contracts and can bind lawfully to the AIPT-MVP-B001 `Campaign → Suite → Case → Run` hierarchy and immutable Run Manifest. The implementation batch is limited to package data, source mapping, visibility, adapter input, provenance and compatibility. It does not implement a run core, agent orchestration, a real model gateway or a real playtest.

The data flow is:

```text
fixed game source commit/tree
  → exact file digests + logical mappings + visibility declarations
  → aipt.playtest-package/v1
  → aipt.runtime-adapter-input/v1
  → existing B001 Run Manifest source.game binding
  → immutable manifest canonical SHA-256
```

## 4. Ownership boundary

AIPT owns the Playtest Package Contract, Runtime Adapter Input Contract, source identity requirements, mapping semantics, visibility semantics, compatibility checks, validator semantics and evidence/provenance semantics. The game repository owns only the concrete source material, concrete package instance, concrete mappings, concrete visibility declarations, concrete digests and game-specific data.

The two AIPT schemas are game-neutral. They contain no UNREGISTERED literal, game-specific queue state, game-specific lifecycle, game-specific Run Manifest field, game-only evidence class or validator bypass. Game-specific values may exist only in package metadata, mapping data, declared capabilities, versioned extension data and game-repository assets.

## 5. Authority gap closure

Repository recovery found only a roadmap objective, B001 indirect compatibility, and P0 predecessor assets. None was sufficient as a P1 executable contract. This authority freezes all thirteen missing surfaces:

| Surface | Recovered source | Frozen result |
|---|---|---|
| Objective | MVP roadmap one-line summary | Exact objective above |
| Deliverables | No P1 inventory | D1–D10 inventory |
| Non-goals | Partial milestone prose | Exact closed list |
| Package contract | None | `aipt.playtest-package/v1` |
| Adapter input | P0 predecessor only | `aipt.runtime-adapter-input/v1` |
| Mapping | P0 assets, no P1 semantics | Five source kinds and closed integrity rules |
| Visibility | Game-local P0 taxonomy | P1 role/surface taxonomy below |
| Source identity | P0 external binding only | Commit/tree/file/source-digest contract |
| B001 compatibility | Indirect | Exact binding chain below |
| Acceptance | None | Local/candidate/remote gates |
| Negative probes | None for P1 | N01–N39 |
| Candidate/CI | Generic governance only | Exact branch/head/job contract |
| Lifecycle/stop | Generic only | Exact state graph and stop codes |

## 6. Frozen deliverables

The future implementation must deliver all ten items:

1. D1 — conforming use of [the Playtest Package schema](../../schemas/playtest-package/v1/aipt-playtest-package.schema.json).
2. D2 — conforming use of [the Runtime Adapter Input schema](../../schemas/runtime-adapter-input/v1/aipt-runtime-adapter-input.schema.json).
3. D3 — `aipt/p1-b000/playtest-package.json` in UNREGISTERED.
4. D4 — scene, guide and rule mappings inside that package manifest.
5. D5 — a visibility declaration for every mapped logical ID.
6. D6 — repository/commit/tree/source-digest binding.
7. D7 — `scripts/aipt/validate-p1-b000.mjs` with schema, identity, digest, mapping, visibility, reference and compatibility checks.
8. D8 — the N01–N39 negative probes in the same validator.
9. D9 — `aipt/p1-b000/compatibility-evidence.json` proving the B001 binding chain.
10. D10 — immutable candidate Git identity, GitHub Actions run and structured stage review evidence.

## 7. Closed implementation write scope

`UNREGISTERED-AIPT-P1-B000` is a single-repository batch. Writes are denied unless the path is one of these seven exact paths:

```text
.github/workflows/aipt-content-gate.yml
aipt/README.md
aipt/p1-b000/compatibility-evidence.json
aipt/p1-b000/playtest-package.json
aipt/p1-b000/runtime-adapter-input.json
aipt/status.json
scripts/aipt/validate-p1-b000.mjs
```

The future batch may read `LICENSES/`, `campaign/`, and `aipt/p0-b000/` through `aipt/p0-b003/` as pinned source. It may not modify those paths. It may not write AIPT or TRPG_PLATFORM. The default-deny rule also blocks every unlisted refactor.

The following capabilities are explicit non-goals; any unapproved occurrence is `FAIL_SCOPE_DRIFT`:

```text
run core implementation
agent orchestration
AI player runtime
AI GM runtime
real model gateway
DeepSeek/OpenAI runtime integration
real model calls
real playtest execution
combat/rule engine implementation
scenario logic execution
NPC autonomous behaviour
memory/RAG orchestration
prompt generation system
visual generation
voice generation
TRPG_PLATFORM integration
UNREGISTERED story rewrite
UNREGISTERED rule rewrite
general content authoring
B001 queue redesign
B001 manifest redesign
```

## 8. Package identity and source identity

The stable package key is `(package_id, package_version)`. The immutable instance tuple adds `schema_version`, `source_repository`, `source_commit`, `source_tree`, `source_digest`, and `adapter_contract_version`. Comparison is byte-exact after schema validation. A duplicate stable key is rejected, including an identical duplicate entry. Filename, directory, mutable branch and human title are never identity.

`source_commit` and `source_tree` are lowercase full 40-hex Git object IDs. Validation must prove the commit exists and resolves to the declared tree. A branch name cannot satisfy either field. Every mapped file must exist as a regular non-symlink file at that commit. A changed source requires a new package version and a new immutable source tuple; a stale manifest is rejected.

## 9. Digest algorithm and closed scope

The package `source_digest` is SHA-256 over RFC 8785 JCS UTF-8 bytes of the entire package object after removing only the `source_digest` member. The package therefore binds identity, entrypoints, mappings, visibility, capability declarations, compatibility metadata and the closed digest inventory.

Each digest inventory entry binds a repository-relative POSIX path to SHA-256 of the exact Git blob bytes at `source_commit`. No newline conversion, Unicode normalization or content rewriting occurs. Entry paths are ordered by lexicographic UTF-8 bytes. Empty segments, `.` segments other than the declared root sentinel, `..`, backslashes, absolute paths, NUL, a symlink component, a symlink target, directory and non-regular target are rejected.

The digest path set must equal the set union of all mapping and reference source paths. A referenced path absent from the inventory and an inventory path with no mapping/reference are both rejected. Repository files outside that exact set are out of package scope; they do not silently enter the digest. Duplicate digest paths and duplicate logical mapping IDs are rejected.

## 10. Mapping semantics

The mapping version is `1.0.0`. Every mapping has `logical_id`, `source_kind`, `source_path`, `content_sha256`, `visibility_class`, and `depends_on`.

- `SCENE` is a data unit for playtest progression, encounter or situation input. B000 does not execute it.
- `GUIDE` is GM/Keeper/system adjudication or scenario-operation material. It supports `GM_ONLY` classification.
- `RULE` is a declared test target or runtime reference source. B000 does not implement a rule engine.
- `ASSET` and `REFERENCE` bind supporting source material without adding execution semantics.

File paths are locators, not semantic identity. Duplicate logical IDs, dangling dependencies, unknown kinds, missing targets, traversal, package-root escape, digest mismatch and an unsupported mapping version reject the package. Cross-package references are forbidden in v1.

## 11. Visibility and hidden information

P1 has three valid content classes:

- `PLAYER_VISIBLE` may enter player agent context, player-visible evidence, GM context and authorized evidence.
- `GM_ONLY` may enter GM context, adjudication and authorized evidence. It may not enter player agent context or player-visible evidence.
- `SYSTEM_INTERNAL` may enter harness control, test control and bookkeeping. It may not be exposed to a game role.

`SECRET` means credentials, keys, passwords, tokens and private infrastructure secrets. It is not TRPG hidden information and is not a valid package class. Discovery of a PEM private-key header, a known provider-secret prefix with at least eight payload characters, a sensitive assignment name with a nonempty value, or URI userinfo containing a password rejects the candidate. A validator may detect more credential signatures, but cannot waive these four signatures.

Every logical ID has exactly one visibility declaration matching its mapping/reference. Missing or unknown visibility, conflicting declarations, a player reference to `GM_ONLY`, player evidence containing `GM_ONLY`, a player surface containing `SYSTEM_INTERNAL`, and any secret are fail-closed errors.

## 12. Runtime adapter input boundary

The adapter input is a normalized immutable data object. It carries package identity, source identity, one selected test unit, resolved mappings, visibility resolution, scenario/guide/rule/asset references, declared capabilities, evidence boundary and provenance.

It cannot represent a live model connection, model invocation, agent loop, tool-call loop, runtime scheduler or memory execution. Schema `additionalProperties: false` blocks such fields. Semantic validation additionally requires exact equality with the referenced package and rejects an unknown package, unsupported adapter version or cross-package reference.

## 13. B001 compatibility without redesign

The B001 user hierarchy remains exactly `Campaign → Suite → Case → Run`; Attempt stays Run-internal and is not externally addressable. The existing Run Manifest schema and PostgreSQL queue migration remain byte-identical.

No second manifest is introduced. The audit chain is:

```text
Run
→ existing immutable Run Manifest ID + canonical_sha256
→ existing source.game repository/commit/tree
→ adapter input run_manifest binding with the same repository/commit/tree
→ package binding with the same repository/commit/tree
→ package source_digest
→ exact mapping IDs, source paths and file SHA-256 values
```

The adapter input also binds the Run Manifest ancestry IDs (`campaign_id`, `suite_id`, `case_id`, `run_id`) and the exact authority task commit/tree/hash values supplied by the future Owner start directive.

Protected B001 behavior is:

```text
Campaign/Suite/Case/Run
Attempt internal-only
Run Manifest immutability
PostgreSQL queue authority
formal WIP=1
deterministic selection
lease / heartbeat / expiry / recovery
append-only Attempt history
```

The protected migration is `internal/storage/postgres/migrations/000002_playtest_queue.sql`, SHA-256 `47f02a5a2129473caa0db5e359a0b294a01b2a96329d9f6fa08ac87cc429c997`.

## 14. Evidence provenance

Evidence must answer which package and version, which source repository/commit/tree/digest, which logical mapping, which scene/rule/guide path and file digest, and which Run Manifest ID/canonical SHA-256 produced the evidence. Player-visible evidence must additionally prove that its source-ID set has an empty intersection with the `GM_ONLY` source-ID set. Incomplete provenance is rejected.

## 15. Negative acceptance

The machine contract freezes exactly N01–N39. They cover malformed/version/identity inputs (N01–N10), mapping/path/content integrity (N11–N17), visibility and secret isolation (N18–N24), adapter/package isolation (N25–N28), Run Manifest/provenance binding (N29–N32), and every protected B001 hierarchy/immutability/queue/lease/Attempt invariant (N33–N39). The AIPT authority validator proves the complete inventory and generic contract semantics. The future UNREGISTERED validator must implement the same IDs against its concrete package.

## 16. Candidate and remote CI acceptance

`CODEX_STAGE_PASS` and `merge_eligible = true` require every item below:

```text
authority contract present
objective satisfied
all deliverables present
scope compliant
forbidden paths unchanged
source identity verified
source digest verified
mapping validation PASS
visibility validation PASS
adapter validation PASS
B001 compatibility PASS
N01–N39 PASS
B001 regression PASS
all required local tests PASS
remote CI PASS
candidate frozen
worktree clean
open findings empty
```

The future candidate branch is exactly `task/UNREGISTERED-AIPT-P1-B000`, based on the fixed UNREGISTERED commit/tree. GitHub Actions workflow `AIPT Content Gate`, required job `aipt-content-gate`, must run with `head_sha == candidate_commit` and conclude `success`. The job cannot use an external model, real API key or provider availability. A fixture containing GM leakage or a secret is forbidden.

## 17. Lifecycle and stop behavior

The normal lifecycle is:

```text
PLANNED → AUTHORIZED → ACTIVE → CANDIDATE_FROZEN
→ CODEX_STAGE_PASS → MERGE_ELIGIBLE → MERGED
→ POST_MERGE_VERIFIED → CLOSED
```

The machine registry lists every permitted transition to `BLOCKED` or `FAIL` and its required evidence. An unlisted transition is rejected. `FAIL` and `CLOSED` are terminal. Returning from `BLOCKED` requires a new Owner authority that resolves the exact blocker.

Construction stops on a missing ancestry anchor, authority conflict, source identity drift, unrepresentable authority, required B001 change, scope drift, required business implementation, secret exposure, validator failure, remote CI failure or candidate identity drift. The stable result codes are recorded in the machine registry.

## 18. Freeze and handoff

The authority artifact manifest records SHA-256 for this page, the machine registry, both schemas and the authority validator. The authority candidate stage review records the artifact-manifest SHA-256 plus the Git candidate commit/tree/branch and remote CI identity. It does not merge, close the implementation batch, authorize the next batch or begin B000 implementation.
