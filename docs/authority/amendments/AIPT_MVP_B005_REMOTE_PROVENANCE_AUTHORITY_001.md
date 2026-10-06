# AIPT-MVP-B005 Remote Provenance Authority 001

Authority work item: `AIPT-MVP-B005-REMOTE-PROVENANCE-AUTHORITY-001`

Parent formal batch: `AIPT-MVP-B005`

Owner decision: `B005-PROV-Q001 = A`

Decision name: `ONLINE_GITHUB_REMOTE_PROVENANCE_V1`

Execution class: `GOVERNANCE_SUBTASK`

Candidate state: `PRIVATE_GOVERNANCE_CANDIDATE_FROZEN`

Implementation state: `AUTHORITY_DEFINED_IMPLEMENTATION_PENDING_R1`

This is not a new serial implementation batch. `AIPT-MVP-B005` remains
`IN_PROGRESS` at `GLOBAL_WIP = 1`; `AIPT-MVP-B006` remains `NOT_AUTHORIZED`
and `NOT_STARTED`. This Amendment defines Authority only. It does not repair
or modify the B005 runtime implementation.

## Frozen blocked-merge facts

The exact main state on which this governance Candidate is based is:

| Fact | Value |
|---|---|
| merge commit | `c07e1aae94f681733ad73c1800423248bcc72376` |
| merge tree | `828defa8ea85a757b43d1a04ce05016ebeea9020` |
| merge CI | `33767358596` |
| merge CI conclusion | `success` |
| post-merge security | `FAIL` |
| lifecycle records created | `false` |
| accepted as final merge | `false` |

The merged implementation is therefore
`MERGED_POST_MERGE_SECURITY_BLOCKED`. Successful merge CI does not override
the failed post-merge security gate and does not close B005.

## Authority gap

The recorded gap is `REMOTE_PROVENANCE_VERIFICATION_UNDERSPECIFIED`.

The existing Authority already requires separate repositories to remain
authoritative and be bound by immutable Commit identities (`R0-Q004`), makes
the authoritative repositories publicly available for remote read-only audit
(`R0-Q012`), and permits formal audit only for immutable Commits pushed to the
authoritative remote (`R9-Q004`). It also limits Codex to read-only source and
input evidence while writing only a separate audit output (`R10-Q005`) and
defines a read-only source-mirror workspace (`R11-Q003`).

Those decisions do not specify how a source mirror proves that an object was
ever present at the authoritative remote. Consequently:

```text
LOCAL_OBJECT_PRESENT != VERIFIED_IMMUTABLE_REMOTE_COMMIT
```

A local bare repository is controlled by local state. A caller can create an
object, set a matching `remote.origin.url`, and make local ownership and object
checks pass without ever pushing that object. Mirror ownership, a matching
origin URL, and object presence are useful consistency facts, but none is
remote provenance.

## Owner resolution

For the Development MVP, the only production method authorized to mint
`VERIFIED_IMMUTABLE_REMOTE_COMMIT` is:

```text
policy:   ONLINE_GITHUB_REMOTE_PROVENANCE_V1
provider: GITHUB_PUBLIC_HTTPS_API_V1
mode:     direct read-only online HTTPS verification
```

The machine policy is
[remote-provenance-policy.json](../registry/remote-provenance-policy.json),
validated by
[aipt-remote-provenance-policy.schema.json](../../../schemas/remote-provenance/v1/aipt-remote-provenance-policy.schema.json).

This is an operational refinement of `R9-Q004` and `R10-Q005`, not a weakening
of remote Commit authority. It supplies the missing proof operation required
to establish that the exact immutable Commit is available from the exact
authoritative repository. It preserves `R0-Q004`, `R0-Q012`, `R9-Q004`,
`R10-Q005`, `R11-Q003`, and `R11-Q004`. No R0-R16 decision prohibits this
read-only GitHub access; `R0-Q012`, `R10-Q005`, and `R11-Q004` expressly allow
the relevant remote read-only boundary.

## Supported repository class

Version 1 supports only `PUBLIC_GITHUB_REPOSITORY`. A repository identity must
be the canonical public HTTPS form:

```text
https://github.com/<owner>/<repo>
```

The existing canonical `.git` suffix equivalent is also accepted. Parsing
must yield exactly `owner` and `repo`. The identity rejects userinfo,
passwords, credential material, query, fragment, control characters, any
non-HTTPS scheme, any host other than `github.com`, and extra path segments.

Private GitHub repositories and non-GitHub remotes are not supported by this
MVP profile. They return `REMOTE_PROVENANCE_PROVIDER_UNSUPPORTED`, or a stable
typed equivalent with the same fail-closed meaning. Neither case may fall back
to trusting a local mirror. Supporting either class requires separate Owner
Authority.

## Exact authoritative verification

The production verifier resolves the repository URL only into the exact
`owner` and `repo`, then queries the fixed authoritative API host using:

```text
GET https://api.github.com/repos/<owner>/<repo>/git/commits/<commit>
```

An equivalent stable GitHub REST route is permissible only when it preserves
the exact Commit-object semantics. The requested Commit is an exact 40-hex
identity. A successful verification requires both:

```text
remote commit SHA == SourceIdentity.Commit
remote tree SHA   == SourceIdentity.Tree
```

Only a successful exact-object response can pass. Branch lookup, tag lookup,
local object lookup, or remote URL string equality cannot substitute for this
operation. Branches are navigation, not provenance Authority.

The production endpoint is built in and fixed to `api.github.com`. A caller
cannot supply an API endpoint, base URL, proxy endpoint, or redirect target.
Redirects are not followed and fail closed. The source repository string is
never used as an arbitrary request destination, which keeps it outside an
SSRF routing boundary.

## Authentication and network security

`GITHUB_PUBLIC_HTTPS_API_V1` uses `NO_CREDENTIAL`. It must not require a GitHub
credential, OAuth grant, or credential-bearing URL, and must never include
credential material in a URL, receipt, manifest, stdout, or stderr. The
general read-only access mechanics in `R11-Q004` and `R11-F002` do not expand
this narrower anonymous public-repository profile into private repository
support.

The production request uses HTTPS with standard validated TLS, no
caller-controlled CA, no caller-controlled endpoint, and no environment-
derived HTTP proxy. Connection and read timeouts, response bytes, and JSON
decoding are bounded.

DNS failure, TLS failure, timeout, rate limiting, HTTP 403/404/429/5xx,
redirect, oversized response, malformed response, Commit mismatch, or Tree
mismatch all fail closed. Temporary inability to perform authoritative online
verification is `BLOCKED_REMOTE_PROVENANCE_UNAVAILABLE`; it is never a reason
to reuse stale trust or fall back to the mirror.

## Fresh verification at both AUDIT_READY operations

AUDIT_READY generation performs a real authoritative online provenance check.
Independent AUDIT_READY verification performs a new authoritative online
provenance check. Neither operation may trust only the claim or receipt already
inside a bundle, a prior successful verification, or a local cache.

Thus the current offline-only B005 provenance model is `NOT_ACCEPTED`. The
online policy is defined here, but its production implementation remains
pending in a separately authorized B005 R1 recovery after this Authority is
disclosed, verified, merged, and closed.

## Reserved claim and production trust boundary

`VERIFIED_IMMUTABLE_REMOTE_COMMIT` is a
`RESERVED_PROVENANCE_CLAIM`. Only the built-in, Authority-approved
`GITHUB_PUBLIC_HTTPS_API_V1` production verifier may mint it.

Future production `GenerateAuditReady(...)` and `VerifyAuditReady(...)` APIs
must not accept a caller implementation, callback, runtime flag, environment
variable, plugin registration, manifest field, or JSON input that can select
the verifier or mint the reserved claim. Tests may use only an unexported,
package-internal seam, such as an unexported helper or fake transport. That
seam cannot be part of the production API.

## Local source-mirror role

The read-only source mirror remains useful, but its role is exactly:

```text
SOURCE_CONTENT_CACHE
+ LOCAL_OBJECT_CONSISTENCY_CHECK
```

Its maximum internal result is `LOCAL_OBJECT_MATCH`, or an implementation-
equivalent state. It is not `REMOTE_PROVENANCE_AUTHORITY` and cannot mint the
reserved claim. Current-UID ownership, origin URL equality, and local object
presence remain local consistency facts only.

## Deterministic remote provenance receipt

The versioned receipt identity is `aipt.remote-provenance/v1`. Its exact
required fields are:

```text
schema
version
policy_id
provider
repository
commit
tree
status
```

`policy_id`, `provider`, and `status` are respectively
`ONLINE_GITHUB_REMOTE_PROVENANCE_V1`, `GITHUB_PUBLIC_HTTPS_API_V1`, and
`VERIFIED_IMMUTABLE_REMOTE_COMMIT`. The repository is the canonical public
GitHub HTTPS identity.

The receipt has no additional fields. It excludes verification time, HTTP
headers, request IDs, rate-limit state, ETag, IP, hostname, local path,
credential material, GitHub response bodies, and temporary endpoints. The
same repository/Commit/Tree/policy/provider facts therefore yield identical
canonical receipt bytes.

R1 must bind the receipt into the deterministic AUDIT_READY bundle and root.
`manifest.remote_verification` remains consistent with repository, Commit,
and status; the receipt adds Tree, policy ID, and provider. Verification is a
truth operation, not a time source for deterministic evidence. The legacy
RAW_CAPTURE v1 contract and bytes remain unchanged.

## Public CI boundary

Public CI must make zero external GitHub API requests and zero model-provider
requests. Tests use an unexported fake transport or a loopback synthetic
GitHub-compatible endpoint and prove that ordinary callers cannot alter the
production endpoint. The synthetic test seam does not grant production trust.

## Required B005 R1 security probes

| Probe | Required outcome |
|---|---|
| `P01` exact remote Commit and exact Tree | PASS |
| `P02` remote 404 | FAIL |
| `P03` remote Commit mismatch | FAIL |
| `P04` remote Tree mismatch | FAIL |
| `P05` redirect | FAIL |
| `P06` oversized response | FAIL before unbounded buffering |
| `P07` rate limit | FAIL |
| `P08` caller mirror, fake origin URL, and unpushed Commit | remote provenance FAIL |
| `P09` caller fake verifier | cannot reach production trust claim |
| `P10` userinfo/query/fragment source URL | reject |
| `P11` non-GitHub source | unsupported |
| `P12` network unavailable | BLOCKED with no mirror fallback |

CI tests for these semantics remain synthetic and offline. They do not perform
the production truth operation.

## Existing security findings

The HIGH finding `csf_a1972a15d20bffccad42fbdb` (caller-controlled mirrors
can fabricate verified remote provenance) remains open and must be eliminated
by the online proof in R1. The MEDIUM findings
`csf_4c0f54541fae325dd26494b0` (mirror-local signature helper) and
`csf_b28e7fb44b3e754d93704fa2` (unbounded Git output) also remain open for R1.
This Authority does not mark any of them fixed.

The previously fixed findings `csf_79ae442f21f33ad95cc698f3`,
`csf_2e89d096e9e5fc0fb26494b0`, and
`csf_1b9288ef93ab4e203b070db6` remain `FIXED`. R1 must preserve explicit
classification, credential-free repository identities, and no-lazy-fetch
behavior.

The separate `HISTORICAL_VALIDATOR_SUCCESSOR_ROUTING_DEFECT` remains outside
this Amendment. This task does not modify
`scripts/ci/validate/int001-closeout-authority.mjs`; that repair is reserved
for an authorized B005 R1 implementation recovery.

## Governance validation and scope

The Authority validator verifies the schema and exact policy semantics,
preserves `R9-Q004`, rejects any equivalence between local object presence and
remote proof, protects the reserved claim, holds the provider and repository
class closed, and verifies the no-credential, no-redirect, no-fallback, fresh-
online-generate, and fresh-online-independent-verification boundaries.

Its negative governance probes are A01 through A11: local-mirror minting,
caller-verifier minting, offline-only verification, unsupported provider,
private-repository acceptance, redirects, required credentials, network-
failure mirror fallback, timestamped receipts, B005 closure, and B006 start.
Every probe must reject and `unexpected_acceptances` must equal zero.

This governance-only task may change only the Authority policy/schema,
Authority/evidence human projections, its dedicated validator, and necessary
aggregate-check wiring. It changes no `internal`, `cmd`, `packages`, storage,
migration, UNREGISTERED, B005 verifier, Git verifier, bounded-I/O, or INT001
validator implementation.

## Publication and stop boundary

The Owner authorized formation of a local Candidate but did not authorize
public disclosure. This task does not push, run public CI, start B005 R1, or
start B006. Its successful result is
`PUBLIC_DISCLOSURE_REAUTHORIZATION_REQUIRED`.

The stop state is:

```text
AIPT-MVP-B005
IN_PROGRESS
GLOBAL_WIP=1

AIPT-MVP-B005-REMOTE-PROVENANCE-AUTHORITY-001
PRIVATE_GOVERNANCE_CANDIDATE_FROZEN

AIPT-MVP-B006
NOT_AUTHORIZED
NOT_STARTED
```
