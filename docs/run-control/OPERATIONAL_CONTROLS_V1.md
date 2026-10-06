# Operational controls v1

B006 adds `aipt-control plan` and `aipt-control run --config <private shared Config> --control-config <private control Config>`. CONFIG validates both inputs before PostgreSQL, migrations, MODEL, HARNESS, CORE, IPC and WEB start in the accepted order. The operational launcher shares one B001 PostgreSQL QueueStore and one run-control service between stdio and loopback HTTP. Queue state and immutable manifests remain B001 authority; gameplay state remains the B002 append-only ledger.

The six panels expose Config, Health, Queue, Run, Status/Table and Reports. Queue registration IDs refer to immutable server-owned inputs. Clients cannot supply a manifest, lease token, capability set, prompt, credential, executor or evidence path. Seats show their registered assignments. Pause blocks new claims; cancel applies only to queued Runs; expiry recovery follows the B001 database clock. A running attempt uses the service lifetime and frozen budget, preserves WIP1, renews its lease, joins cancellation, and records success only after matching verified completed report evidence and renewing current ownership.

HTTP binds only a random `127.0.0.1` port and reuses the accepted exact Host/Origin/CSRF/CSP policy. The in-memory CSRF token is returned by the same-origin session endpoint. No query parameters, CORS, public/private prompt bodies, DSNs, raw captures or hidden game state are exposed. GET `/api/v1/dashboard` reads bounded queue state without report verification or provider traffic. POST `/api/v1/control` and stdio both use the same envelope:

```json
{"jsonrpc":"2.0","protocol_version":1,"id":"request-a","method":"aipt.v1.queue.pause","params":{"paused":true}}
```

Requests are UTF-8 objects bounded to 1 MiB, with exact case-sensitive keys and duplicate/deep/trailing JSON rejected. Stdio uses one exact `Content-Length: <decimal>\r\n\r\n` header and bounded bodies; batches and notifications are rejected. The owning launcher closes and joins stdio streams on shutdown. Stdout carries framed responses only; redacted launcher diagnostics use stderr.

| Method | Exact parameters |
|---|---|
| `aipt.v1.queue.list` | `limit` (1–100) |
| `aipt.v1.queue.enqueue` | `registration_id` |
| `aipt.v1.queue.pause` | `paused` |
| `aipt.v1.queue.cancel` | `run_id` |
| `aipt.v1.queue.recover` | empty object |
| `aipt.v1.run.next` | empty object |
| `aipt.v1.run.get` | `run_id` |
| `aipt.v1.report.inspect` | `run_id` |
| `aipt.v1.report.export` | `run_id`, `format` (`json`, `md`, `csv`, `junit`, `html`) |

Explicit report inspection/export invokes B005's fixed anonymous online GitHub source verifier. Only authenticated PUBLIC report contracts/derivatives, at most 2 MiB each, can be exported. Export copies the bytes held by verification and rechecks the declared length/hash. HTML downloads use `application/octet-stream`. A whole bundle may remain PRIVATE_FULL; its hidden assets are never made public by the report export policy. The UI uses text nodes and checks downloaded bytes against SHA-256 before saving them.

Production game execution is not configured in B006: `run.next` returns `AIPT_RUN_CONTROL_EXECUTOR_NOT_CONFIGURED` before claiming a lease. The trusted Executor API and actual B002/PostgreSQL completion/replay wiring are tested with non-narrative diagnostic fixtures. The real Task 0 driver and pilot belong to B007. `plan` is declarative and reports `runtime_ready=false`, `STARTUP_NOT_VERIFIED`, `B007_CONFIGURATION_REQUIRED`; HTTP reports `NOT_ASSERTED`. Qualification enqueue/execution is denied even if a formal Run already exists in the database. There are no B006 real-model, real-playtest or qualification claims.

## Explicit B002 successor repair and acceptance

Owner decision `B006-B002-ZERO-RNG-REPAIR-Q001=A` allows only the exact `cloneProposal` change preserving nil versus empty RNG slices. Its accepted and successor SHA-256 values, regression bytes and authorization are fixed in `docs/authority/registry/b006-b002-successor-repair.json`. The original B002 closeout and failed `rng_requests=[]` replay evidence remain historical truth; no event is rewritten and replay digest checks stay strict.

Unchanged B002/B003/B004/B005 and integration-closeout validators replay at exact accepted B005 closeout `08a5aa175edae712cdaacc7a84ff94673fa13552`. The original B005 runtime/lifecycle resolver also checks current accepted state. A separate current guard runs first and binds the exact repair, all other accepted predecessor files, current checkout, accepted main and complete first-parent history, including rewrite-and-restore attacks. Public CI makes zero GitHub API/model calls. Existing PostgreSQL CI selectors include the two added B006 integration tests; the B006 PostgreSQL race checks are a separate local acceptance requirement.

The Candidate is a single-parent successor of that exact base. Its merge must have parents `[base, Candidate]` and the identical Candidate tree. Closing B006 requires the same authorized independent read-only Codex reviewer to PASS the exact Candidate, local PostgreSQL 18.4 race PASS, and all five jobs of the exact main merge CI to succeed. Local online Actions verification then supplies an immutable catalogue under the Owner-accepted main/local-verification trust model. These local attestations are not signed offline CI credentials. Three canonical append-only lifecycle records, independent review and CI evidence are introduced in one governance-only direct closeout successor. Partial/forked/rewritten records, wrong SHA/jobs, premature self-closeout and changes hidden behind an older checkout reject.

The separate Owner decision `B006-PREDECESSOR-GATES-SUCCESSOR-Q001=A` is immutable at `docs/authority/registry/b006-predecessor-gates-successor.json`. It authorizes the bounded B005/integration gate successor routes reviewed in the four-path proposal, while original validators and tests remain byte-identical. Every HEAD/main first-parent status version must preserve frozen predecessor projections; after exact B006 merge the exception files retain exact Candidate bytes. Introduced CI/review/records/status require canonical JSON and the catalogue digest binds the actual accepted CI blob. Final review must verify all six known local findings; intermediate rejected Candidates and synthetic test CI remain failures or test fixtures, never real acceptance.
