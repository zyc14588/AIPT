# @aipt/adapter-sdk

AIPT-M0-B002 TypeScript adapter **contract SDK** — not the later B005 Harness
Adapter runtime.

- **Zero dependencies**: Node.js 24 standard library only (`node:crypto`,
  `node:test`); erasable TypeScript syntax executed natively by Node 24
  (no compiler, no framework, no code generator, no network-fetched artifact).
- **Single wire authority**: `schemas/protocol/v1/aipt-protocol.schema.json`
  remains the only wire-contract truth. This package embeds a fail-closed
  contract drift manifest (`src/contract/descriptor.ts`) that projects the
  schema's frozen constants/requirements; the machine gate
  `scripts/ci/validate/adapter-sdk.mjs` re-derives that descriptor from the
  canonical schema at gate time and fails on drift, so a schema/type edit can
  never pass silently. The canonical schema is never copied into the package.
- **Public surface**: canonical constants (protocol/schema/JSON-RPC
  versions, registered methods, safe-integer id bounds, the six frozen
  visibility labels, stable `AIPT_*` error identifiers), public JSON
  value/identity/request/response/result/error/notification/state/projection/
  fixture-manifest/bundle types (literal unions derived from the exported
  readonly constants/descriptor; no `any` is exported), deterministic
  canonical JSON + SHA-256 helpers, typed JSON-RPC parse/decode/encode
  helpers and builders, fail-closed semantic projection validation, and pure
  fixture compatibility validation over supplied documents.
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
```

## Tests

```sh
pnpm --filter @aipt/adapter-sdk test   # node --test test/ (hermetic, node:test/assert only)
pnpm run check:adapter-sdk             # machine gate: descriptor drift + fixture behavior
```

Tests consume the repository's public canonical schema/fixture under
`testdata/protocol/v1/minimal-fixture/`; the package hard-codes no
fixture-specific seat ids, field ids, action names, transition ids, or game
content.
