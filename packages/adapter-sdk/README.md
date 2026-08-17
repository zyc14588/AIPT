# @aipt/adapter-sdk

AIPT-M0-B002 TypeScript adapter **contract SDK** — not the later B005 Harness
Adapter runtime.

- **Zero dependencies**: Node.js 24 standard library only (`node:crypto`,
  `node:test`); erasable TypeScript syntax executed natively by Node 24
  (no compiler, no framework, no code generator, no network-fetched artifact).
- **Single wire authority**: `schemas/protocol/v1/aipt-protocol.schema.json`
  remains the only wire-contract truth. This package embeds a fail-closed
  contract drift manifest (`src/contract/descriptor.ts`) that projects the
  schema's frozen constants/requirements plus a **full-content canonical
  schema fingerprint**; the machine gate
  `scripts/ci/validate/adapter-sdk.mjs` re-derives that descriptor from the
  canonical schema at gate time and fails on drift, so every schema/type edit
  — even one outside the projected fields — forces explicit SDK review. The
  gate additionally audits the ACTUAL declared interface surface of
  `src/types.ts` — required/optional/discriminant members AND declared member
  **type expressions** (91 schema-derived expressions including nested object
  shapes and descriptor-derived const/discriminant literals) for all 25
  public wire and fixture types. A hand edit such as
  `StateField.value: JsonValue -> string`, a nested member type drift, or
  widening `ManifestMutant.expected_semantic_rejection` back to
  `AiptErrorCode` is detected by in-memory negative probes. The canonical
  schema is never copied into the package; the package never imports
  scripts/ci internals.
- **Public surface**: canonical constants (protocol/schema/JSON-RPC
  versions, registered methods, safe-integer id bounds, the six frozen
  visibility labels, the finite stable `AIPT_*` validation-issue code
  union), public JSON value/identity/request/response/result/error/
  notification/state/projection/seat/seat-set/deterministic-check/
  state-transition/replay-assertion/replay-record/mutant-specimen/
  fixture-manifest/bundle types (literal unions derived from the exported
  readonly constants/descriptor; `ManifestMutant.expected_semantic_rejection`
  is the exact descriptor-derived literal, never the broad union; no `any`
  is exported; the open wire error namespace is the separate branded
  `AiptWireErrorCode` type, runtime-enforced by `isAiptWireErrorCode`;
  regex/numeric constraints TypeScript cannot express — `Identifier`,
  safe-integer ids, the `AIPT_*` pattern — are enforced at runtime),
  deterministic canonical JSON + SHA-256 helpers, a pure path-preserving
  **lossless JSON-value gate** (`validateJsonValue` / `requireJsonValue`)
  that inspects OWN PROPERTY DESCRIPTORS ONLY and never invokes a getter or
  setter — array symbol keys, non-enumerable extras, accessor indices,
  sparse holes, and invalid index descriptors included — and runs as a
  whole-value gate at every public trust boundary (wire/state/projection/
  request-id/manifest validators, `validateSchemaInstance`'s schema/document
  inputs, `checkFixtureIdentity`, projection known seats, and the bundle
  wrapper/documents collection), typed JSON-RPC parse/decode/encode helpers
  and builders, fail-closed semantic projection validation (projection
  identity bound to the source state, validated known seats, lossless
  values), a package-local dependency-free **canonical JSON Schema 2020-12
  subset evaluator** (`validateSchemaInstance`) with a deterministic
  recursive schema-grammar preflight that runs FRESH on every call — a
  caller-supplied mutable schema object is a trust boundary, so a PASS is
  never reused across calls by object identity and a later mutation of the
  same object is observed (no cache; the input is never copied, frozen, or
  mutated). The preflight walks the complete local-$ref graph with
  visiting/done state, so every local `$ref` cycle fails with
  `AIPT_FIXTURE_INVALID_SCHEMA` before instance evaluation — cycles inside
  unused `$defs` children included — while acyclic shared-target refs and
  repeated non-ancestral JS object aliases stay valid. The declared grammar
  is enforced exactly: `required` is an array of unique strings (an empty
  array is valid JSON Schema 2020-12); `type` arrays are non-empty,
  supported, and duplicate-free; `enum` is non-empty and JSON-semantically
  unique; `title`/`description`/`$comment` are strings, `examples` is an
  array, `deprecated` is a boolean, `default` may be any lossless JSON
  value; `$schema`/`$id`/`$defs` are structural ROOT-ONLY keywords
  (`$schema`, when present, must be exactly the JSON Schema 2020-12
  meta-schema URI; synthetic package-local schemas need no `$schema`).
  Schema nodes are objects only (`items`/`properties`/combinator branches
  included; boolean and array-form schemas stay outside the supported
  dialect). Decimal `multipleOf` uses the deterministic tolerance of the
  repository's independent standard-library oracle (q = value / multipleOf;
  a multiple iff abs(q - round(q)) <= 1e-9), so 0.3 is a multiple of 0.1
  while nearby non-multiples (0.35) still fail. Malformed keyword
  shapes/ranges, unsupported type names, unsupported keywords hidden in
  anyOf/oneOf/not branches, unreferenced `$defs` children, and
  external/unresolvable refs all fail with `AIPT_FIXTURE_INVALID_SCHEMA`;
  own-member `const` presence), and pure
  fixture compatibility validation over supplied documents: manifest
  preflight (canonical consts/path form/duplicate paths/exact kind→schema_ref
  map) that stops before any supplied document is read, hashed, traversed, or
  invoked; the **canonical schema SHA-256 fingerprint binding**
  (`AIPT_FIXTURE_INVALID_SCHEMA` on any missing/lossy/drifted schema, before
  any asset processing); per-document lossless+digest+schema+identity gates;
  the **ordinary projection semantic gate** (every clean projection must
  pass `validateProjectionSemantics` against a compatible supplied state
  with the supplied known seats — hidden data never passes as an ordinary
  projection); the mutant semantic proof with **wrapper metadata binding**
  (`seat_id` = `projection.seat_id`, `leaked_field_id` = the single field
  producing the declared rejection; drift fails with
  `AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT`); and **exact inventory** with no
  `manifest.json` exemption.
- **No ambient work**: importing the package performs no network, process,
  socket, database, service, worker, or environment access. See
  `test/side-effects.test.ts`.

## Usage

```ts
import { buildRequest, buildResultResponse, encodeResponse, decodeResponse } from '@aipt/adapter-sdk';

const request = buildRequest('req-1', { action: 'advance-turn', seat_id: 'seat-a' }, 'minimal-v1-arithmetic');
const response = buildResultResponse('req-1', {
  accepted: true,
  transition_id: 'transition-turn-increment',
  applied_fields: [/* ... */],
}, 'minimal-v1-arithmetic');

const wire = encodeResponse(response);          // deterministic canonical JSON
const decoded = decodeResponse(wire);           // typed, validated

// Fixture bundle validation: the canonical schema document is an explicit
// caller-supplied validation boundary (the SDK never reads the filesystem).
import { validateFixtureBundle } from '@aipt/adapter-sdk';
const result = validateFixtureBundle({ manifest, documents }, canonicalSchema);
```

## Tests

```sh
pnpm --filter @aipt/adapter-sdk test   # node --test test/ (hermetic, node:test/assert only; 122 tests)
pnpm run check:adapter-sdk             # machine gate: descriptor + fingerprint drift, type-shape AND
                                       # type-expression audits (91 expressions), fixture behavior,
                                       # 103 probes (80 behavior + 11 drift + 6 zero-invocation/
                                       # no-document-touch + mutant + future wire code +
                                       # 4 positive grammar)
```

Tests consume the repository's public canonical schema/fixture under
`testdata/protocol/v1/minimal-fixture/` and pass the single repository schema
in as the bundle-validation boundary; the package hard-codes no
fixture-specific seat ids, field ids, action names, transition ids, or game
content.
