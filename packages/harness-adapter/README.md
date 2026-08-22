# `@aipt/harness-adapter`

`@aipt/harness-adapter@0.1.0` is the B005 thin stdio runtime between an
explicitly supplied `HarnessBackend` and the frozen AIPT protocol contract.
It is an AIPT product runtime object. It is not the `$codex-harness`
construction worker and it does not select or call a model.

The input contract is one UTF-8 JSON-RPC request envelope per LF-terminated
line, capped at 1 MiB before the LF. Clean EOF is graceful. Invalid UTF-8,
invalid JSON/request envelopes, oversized frames, and unterminated EOF frames
fail closed. A backend result is fully encoded and identity-checked before any
bytes are emitted. The response is written first, followed by zero or more
notifications. Protocol output is stdout-only; stable redacted diagnostics are
stderr-only.

Production hosts implement `HarnessBackend` and invoke
`runProcessHarnessAdapter`. The adapter reads no ambient environment, forwards
no credentials, opens no network listener, and contains no game-specific
fixture literals. The deterministic fixture backend and executable child
worker live only under `test/`.

Run the focused gates from the repository root:

```sh
pnpm run check:harness-adapter
pnpm run test:harness-adapter
```
