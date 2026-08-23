# @aipt/web-ui

Dependency-free TypeScript source for the AIPT-M0-B007 local dashboard. It
fetches only `/api/v1/dashboard`, validates the complete snapshot at runtime,
and renders exactly six read-only panels with text-node APIs.

The UI is a derived view, not authority. Queue, Run, Status/Table, report UI
export, audit generators, signing, encryption, and chunking are visibly
`NOT_IMPLEMENTED`. No configuration editor, credential field, network model
call, browser persistence, analytics, or external asset is present.

Run its hermetic Node 24 tests with:

```sh
pnpm --filter @aipt/web-ui test
```
