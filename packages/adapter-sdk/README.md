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
  `src/types.ts` (required/optional/discriminant members for all 25 public
  wire and fixture types) against schema-derived shape expectations. The
  canonical schema is never copied into the package.
- **Public surface**: canonical constants (protocol/schema/JSON-RPC
  versions, registered methods, safe-integer id bounds, the six frozen
  visibility labels, the finite stable `AIPT_*` validation-issue code
  union), public JSON value/identity/request/response/result/error/
  notification/state/projection/seat/seat-set/deterministic-check/
  state-transition/replay-assertion/replay-record/mutant-specimen/
  fixture-manifest/bundle types (literal unions derived from the exported
  readonly constants/descriptor; no `any` is exported; the open wire error
  namespace is the separate branded `AiptWireErrorCode` type, runtime-enforced
  by `isAiptWireErrorCode`), deterministic canonical JSON + SHA-256 helpers,
  a pure path-preserving **lossless JSON-value gate** (`validateJsonValue` /
  `requireJsonValue`) applied at every trust boundary where the schema
  accepts any JSON value (`state_field.value`, `proposal`, nested JSON
  values, generic parse output), typed JSON-RPC parse/decode/encode helpers
  and builders, fail-closed semantic projection validation (projection
  identity bound to the source state, validated known seats, lossless
  values), a package-local dependency-free **canonical JSON Schema 2020-12
  subset evaluator** (`validateSchemaInstance`), and pure fixture
  compatibility validation over supplied documents (manifest preflight with
  canonical consts/path form/duplicate paths/exact kind→schema_ref map;
  per-document lossless+digest+schema+identity gates; exact inventory; and a
  semantic proof that the manifest mutant actually produces exactly its
  declared `AIPT_VISIBILITY_UNAUTHORIZED_FIELD` rejection against
  bundle-supplied seat/state documents).
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
pnpm --filter @aipt/adapter-sdk test   # node --test test/ (hermetic, node:test/assert only; 90 tests)
pnpm run check:adapter-sdk             # machine gate: descriptor + fingerprint drift, type-shape audit,
                                       # fixture behavior, 53 negative probes (43 behavior + 8 drift + mutant + wire-code)
```

Tests consume the repository's public canonical schema/fixture under
`testdata/protocol/v1/minimal-fixture/` and pass the single repository schema
in as the bundle-validation boundary; the package hard-codes no
fixture-specific seat ids, field ids, action names, transition ids, or game
content.
