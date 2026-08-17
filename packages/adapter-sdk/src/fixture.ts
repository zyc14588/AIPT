// Fixture compatibility helpers.
//
// Pure validation over SUPPLIED parsed documents/assets: this package never
// reads the repository filesystem, never copies the canonical fixture, and
// never creates a second fixture truth. The canonical schema document is
// accepted as an explicit validation boundary (second argument or
// bundle.schema) — never read from the ambient filesystem.
//
// Iteration 4B contract:
//  1. Manifest preflight (path form, duplicate paths, exact kind ->
//     schema_ref map from the contract descriptor, canonical consts
//     expected_final_state / replay_assertion, exact mutant cardinality).
//     If preflight fails, bundle validation STOPS before hashing or
//     interpreting any supplied asset document.
//  2. Every listed document must then pass, in order: the lossless
//     JSON-value gate, the canonical-JSON SHA-256 digest check, the
//     package-local canonical-schema instance evaluation against the
//     expected $defs target (including the full mutant wrapper), and the
//     protocol identity triple (mutant wrappers via their inner
//     projection). The manifest-supplied schema_ref is never trusted for
//     evaluation — only the kind-derived canonical target decides.
//  3. The manifest mutant must actually produce exactly its declared
//     semantic rejection (AIPT_VISIBILITY_UNAUTHORIZED_FIELD) when its
//     projection is evaluated against game-neutral seat/state documents
//     supplied in the same bundle; a digest-correct neutral/non-rejecting
//     mutant fails closed (AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT).
//  4. The exact inventory of supplied documents is enforced: every listed
//     asset must exist and every unlisted supplied document fails closed.
import { CONTRACT_DESCRIPTOR as D } from './contract/descriptor.ts';
import { sha256Hex } from './canonical-json.ts';
import { failResult, issue, okResult, type ValidationIssue, type ValidationResult } from './errors.ts';
import { validateJsonValue } from './json-value.ts';
import { validateSchemaInstance } from './json-schema.ts';
import { validateProjectionSemantics } from './projection.ts';
import type { FixtureManifest } from './types.ts';

const SHA256_RE = /^[0-9a-f]{64}$/u;
const IDENTIFIER_RE = new RegExp(D.identifier_pattern, 'u');

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasOwn(value: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

// Validate a supplied parsed document against the protocol identity triple:
// protocol_version/schema_version must equal the frozen constants, fixture_id
// must be a well-formed fixture identifier, and — when an expected fixture id
// is supplied — fixture_id must equal it (the canonical schema requires every
// asset fixture_id to equal the manifest fixture_id).
export function checkFixtureIdentity(document: unknown, path = '$', expectedFixtureId?: string): ValidationResult {
  const issues: ValidationIssue[] = [];
  if (!isRecord(document)) {
    issues.push(issue(path, 'AIPT_FIXTURE_IDENTITY_MISMATCH', 'document is not an object (identity triple unreadable)'));
    return failResult(issues);
  }
  if (document.protocol_version !== D.protocol_version) {
    issues.push(issue(`${path}/protocol_version`, 'AIPT_FIXTURE_IDENTITY_MISMATCH', `protocol_version drifted from ${JSON.stringify(D.protocol_version)}`));
  }
  if (document.schema_version !== D.schema_version) {
    issues.push(issue(`${path}/schema_version`, 'AIPT_FIXTURE_IDENTITY_MISMATCH', `schema_version drifted from ${JSON.stringify(D.schema_version)}`));
  }
  if (typeof document.fixture_id !== 'string' || !IDENTIFIER_RE.test(document.fixture_id)) {
    issues.push(issue(`${path}/fixture_id`, 'AIPT_FIXTURE_IDENTITY_MISMATCH', `fixture_id must match ${D.identifier_pattern}`));
  } else if (expectedFixtureId !== undefined && document.fixture_id !== expectedFixtureId) {
    issues.push(issue(`${path}/fixture_id`, 'AIPT_FIXTURE_IDENTITY_MISMATCH', `fixture_id must equal the manifest fixture_id ${JSON.stringify(expectedFixtureId)}, got ${JSON.stringify(document.fixture_id)}`));
  }
  return issues.length === 0 ? okResult() : failResult(issues);
}

// ---------------------------------------------------------------------------
// Manifest path preflight (pure; no file access).
// ---------------------------------------------------------------------------

// A manifest entry path must be a relative, normalized POSIX path: a
// non-empty string, no NUL, no absolute form (no leading separator), no
// backslash separator, no empty segment, no '.'/'..' segment, and no
// normalization drift. Returns a human-readable problem, or null when safe.
function manifestPathProblem(p: unknown): string | null {
  if (typeof p !== 'string' || p.length === 0) return 'manifest path must be a non-empty string';
  if (p.includes('\u0000')) return `manifest path contains a NUL byte: ${JSON.stringify(p)}`;
  if (p.startsWith('/')) return `manifest path must be relative, got absolute path ${JSON.stringify(p)}`;
  if (p.includes('\\')) return `manifest path must use POSIX separators only, got ${JSON.stringify(p)}`;
  const segments = p.split('/');
  if (segments.some((segment) => segment.length === 0)) return `manifest path contains an empty segment: ${JSON.stringify(p)}`;
  if (segments.some((segment) => segment === '.' || segment === '..')) return `manifest path contains a dot/dotdot segment: ${JSON.stringify(p)}`;
  if (segments.join('/') !== p) return `manifest path is not normalized: ${JSON.stringify(p)}`;
  return null;
}

function checkManifestPath(p: unknown, path: string, issues: ValidationIssue[]): void {
  const problem = manifestPathProblem(p);
  if (problem !== null) issues.push(issue(path, 'AIPT_FIXTURE_UNSAFE_PATH', problem));
}

function checkSha256Field(sha: unknown, path: string, issues: ValidationIssue[]): void {
  if (typeof sha !== 'string' || !SHA256_RE.test(sha)) {
    issues.push(issue(path, 'AIPT_INVALID_VALUE', 'manifest entry sha256 must be 64 lowercase hexadecimal characters'));
  }
}

// The canonical ref for a manifest kind comes ONLY from the descriptor map;
// the manifest-supplied schema_ref is never trusted.
function canonicalRefForKind(kind: unknown): string | undefined {
  if (typeof kind !== 'string') return undefined;
  return (D.manifest_kind_schema_refs as Record<string, string>)[kind];
}

function checkAssetEntry(entry: unknown, path: string, issues: ValidationIssue[]): void {
  if (!isRecord(entry)) {
    issues.push(issue(path, 'AIPT_INVALID_VALUE', 'manifest asset entry must be an object'));
    return;
  }
  for (const key of ['path', 'kind', 'schema_ref', 'sha256']) {
    if (!hasOwn(entry, key)) issues.push(issue(`${path}/${key}`, 'AIPT_MISSING_REQUIRED', `missing required manifest entry member ${JSON.stringify(key)}`));
  }
  const extra = Object.keys(entry).filter((key) => !['path', 'kind', 'schema_ref', 'sha256'].includes(key));
  for (const key of extra) issues.push(issue(`${path}/${key}`, 'AIPT_UNKNOWN_FIELD', `manifest entry member ${JSON.stringify(key)} is not allowed`));
  checkManifestPath(entry.path, `${path}/path`, issues);
  if (typeof entry.kind !== 'string' || !(D.manifest_kinds as readonly string[]).includes(entry.kind)) {
    issues.push(issue(`${path}/kind`, 'AIPT_INVALID_VALUE', `unknown manifest entry kind ${JSON.stringify(entry.kind)}`));
  } else {
    const canonicalRef = canonicalRefForKind(entry.kind);
    if (entry.schema_ref !== canonicalRef) {
      issues.push(issue(`${path}/schema_ref`, 'AIPT_FIXTURE_SCHEMA_REF_MISMATCH', `manifest kind ${JSON.stringify(entry.kind)} must map to exactly ${JSON.stringify(canonicalRef)}, got ${JSON.stringify(entry.schema_ref)} (the manifest-supplied $ref is never trusted)`));
    }
  }
  checkSha256Field(entry.sha256, `${path}/sha256`, issues);
}

function checkMutantEntry(entry: unknown, path: string, issues: ValidationIssue[]): void {
  if (!isRecord(entry)) {
    issues.push(issue(path, 'AIPT_INVALID_VALUE', 'manifest mutant entry must be an object'));
    return;
  }
  for (const key of ['path', 'kind', 'schema_ref', 'sha256', 'expected_semantic_rejection']) {
    if (!hasOwn(entry, key)) issues.push(issue(`${path}/${key}`, 'AIPT_MISSING_REQUIRED', `missing required mutant entry member ${JSON.stringify(key)}`));
  }
  const extra = Object.keys(entry).filter((key) => !['path', 'kind', 'schema_ref', 'sha256', 'expected_semantic_rejection'].includes(key));
  for (const key of extra) issues.push(issue(`${path}/${key}`, 'AIPT_UNKNOWN_FIELD', `mutant entry member ${JSON.stringify(key)} is not allowed`));
  checkManifestPath(entry.path, `${path}/path`, issues);
  if (entry.kind !== D.mutant_kind) {
    issues.push(issue(`${path}/kind`, 'AIPT_INVALID_VALUE', `mutant entry kind must be exactly ${JSON.stringify(D.mutant_kind)}`));
  } else {
    const canonicalRef = canonicalRefForKind(entry.kind);
    if (entry.schema_ref !== canonicalRef) {
      issues.push(issue(`${path}/schema_ref`, 'AIPT_FIXTURE_SCHEMA_REF_MISMATCH', `mutant kind ${JSON.stringify(entry.kind)} must map to exactly ${JSON.stringify(canonicalRef)}, got ${JSON.stringify(entry.schema_ref)}`));
    }
  }
  if (entry.expected_semantic_rejection !== D.mutant_expected_semantic_rejection) {
    issues.push(issue(`${path}/expected_semantic_rejection`, 'AIPT_INVALID_VALUE', `mutant expected_semantic_rejection must be exactly ${JSON.stringify(D.mutant_expected_semantic_rejection)}`));
  }
  checkSha256Field(entry.sha256, `${path}/sha256`, issues);
}

export function validateFixtureManifest(input: unknown): ValidationResult {
  const issues: ValidationIssue[] = [];
  if (!isRecord(input)) {
    return failResult([issue('$', 'AIPT_FIXTURE_INVALID_MANIFEST', 'fixture manifest must be a JSON object')]);
  }
  for (const key of D.fixture_manifest_required) {
    if (!hasOwn(input, key)) issues.push(issue(`$/${key}`, 'AIPT_MISSING_REQUIRED', `missing required manifest member ${JSON.stringify(key)}`));
  }
  const extra = Object.keys(input).filter((key) => !(D.fixture_manifest_required as readonly string[]).includes(key));
  for (const key of extra) issues.push(issue(`$/${key}`, 'AIPT_UNKNOWN_FIELD', `manifest member ${JSON.stringify(key)} is not allowed`));
  if (input.protocol_version !== D.protocol_version) issues.push(issue('$/protocol_version', 'AIPT_UNKNOWN_VERSION', `protocol_version must be exactly ${JSON.stringify(D.protocol_version)}`));
  if (input.schema_version !== D.schema_version) issues.push(issue('$/schema_version', 'AIPT_UNKNOWN_VERSION', `schema_version must be exactly ${JSON.stringify(D.schema_version)}`));
  if (typeof input.fixture_id !== 'string' || !IDENTIFIER_RE.test(input.fixture_id)) {
    issues.push(issue('$/fixture_id', 'AIPT_FIXTURE_IDENTITY_MISMATCH', `fixture_id must match ${D.identifier_pattern}`));
  }
  if (typeof input.fixture_name !== 'string' || input.fixture_name.length < 1) {
    issues.push(issue('$/fixture_name', 'AIPT_INVALID_VALUE', 'fixture_name must be a non-empty string'));
  }
  // Canonical consts: these manifest members are frozen by the schema and
  // must equal the exact canonical constants, never a caller-chosen path.
  if (input.expected_final_state !== D.fixture_manifest_expected_final_state) {
    issues.push(issue('$/expected_final_state', 'AIPT_INVALID_VALUE', `expected_final_state must be exactly ${JSON.stringify(D.fixture_manifest_expected_final_state)}`));
  }
  if (input.replay_assertion !== D.fixture_manifest_replay_assertion) {
    issues.push(issue('$/replay_assertion', 'AIPT_INVALID_VALUE', `replay_assertion must be exactly ${JSON.stringify(D.fixture_manifest_replay_assertion)}`));
  }
  const assets = input.assets;
  if (!Array.isArray(assets) || assets.length < 1) {
    issues.push(issue('$/assets', 'AIPT_INVALID_VALUE', 'assets must be a non-empty array'));
  } else {
    assets.forEach((entry, index) => checkAssetEntry(entry, `$/assets/${index}`, issues));
  }
  const mutants = input.mutants;
  if (!Array.isArray(mutants) || mutants.length !== 1) {
    issues.push(issue('$/mutants', 'AIPT_INVALID_VALUE', 'mutants must be an array with exactly one entry'));
  } else {
    mutants.forEach((entry, index) => checkMutantEntry(entry, `$/mutants/${index}`, issues));
  }
  // Uniqueness across assets AND mutants (deterministic: the later
  // occurrence is addressed).
  const firstPath = new Map<string, string>();
  const recordPath = (p: unknown, indexPath: string): void => {
    if (typeof p !== 'string') return;
    const first = firstPath.get(p);
    if (first !== undefined) {
      issues.push(issue(indexPath, 'AIPT_FIXTURE_DUPLICATE_PATH', `duplicate manifest path ${JSON.stringify(p)} (already listed at ${first})`));
    } else {
      firstPath.set(p, indexPath);
    }
  };
  if (Array.isArray(assets)) assets.forEach((entry, index) => recordPath((entry as { path?: unknown } | null)?.path, `$/assets/${index}/path`));
  if (Array.isArray(mutants)) mutants.forEach((entry, index) => recordPath((entry as { path?: unknown } | null)?.path, `$/mutants/${index}/path`));
  return issues.length === 0 ? okResult() : failResult(issues);
}

// ---------------------------------------------------------------------------
// Bundle validation.
// ---------------------------------------------------------------------------

// Build the trusted documents map from the caller-supplied bundle. Non-string
// keys and symbol-keyed object members fail closed (they could never be
// manifest paths and would otherwise be silently dropped).
function collectDocuments(input: unknown, issues: ValidationIssue[]): Map<string, unknown> | null {
  const documents = new Map<string, unknown>();
  if (input instanceof Map) {
    for (const [key, value] of input) {
      if (typeof key !== 'string') {
        issues.push(issue('$/documents', 'AIPT_FIXTURE_INVALID_MANIFEST', 'document map keys must be manifest path strings'));
        continue;
      }
      documents.set(key, value);
    }
    return documents;
  }
  if (isRecord(input)) {
    if (Object.getOwnPropertySymbols(input).length > 0) {
      issues.push(issue('$/documents', 'AIPT_FIXTURE_INVALID_MANIFEST', 'documents object must not carry symbol-keyed members'));
    }
    for (const key of Object.keys(input)) documents.set(key, input[key]);
    return documents;
  }
  issues.push(issue('$/documents', 'AIPT_FIXTURE_INVALID_MANIFEST', 'fixture documents must be a Map or an object keyed by manifest path'));
  return null;
}

// Validate a supplied fixture bundle against the caller-supplied canonical
// schema document (explicit second argument or bundle.schema member). Every
// listed asset must be present, lossless-JSON-representable, digest-exact,
// canonical-schema-valid against its kind-derived $defs target, and
// identity-consistent; the manifest mutant must produce exactly its declared
// semantic rejection against bundle-supplied seat/state documents; unlisted
// supplied documents fail closed. If the manifest preflight fails, bundle
// validation stops before hashing or interpreting any supplied asset
// document.
export function validateFixtureBundle(input: unknown, schema?: unknown): ValidationResult {
  if (!isRecord(input)) {
    return failResult([issue('$', 'AIPT_FIXTURE_INVALID_MANIFEST', 'fixture bundle must be an object with manifest and documents')]);
  }
  const schemaDoc = schema !== undefined ? schema : input.schema;
  if (!isRecord(schemaDoc)) {
    return failResult([issue('$/schema', 'AIPT_FIXTURE_INVALID_SCHEMA', 'bundle validation requires the caller-supplied canonical schema document (explicit argument or bundle.schema member); the SDK never reads the repository filesystem')]);
  }
  // 1. Manifest preflight first: on any failure, stop BEFORE hashing or
  //    interpreting supplied asset documents.
  const manifestCheck = validateFixtureManifest(input.manifest);
  if (!manifestCheck.valid) return manifestCheck;
  const manifest = input.manifest as unknown as FixtureManifest;

  // 2. Trusted documents map.
  const issues: ValidationIssue[] = [];
  const documents = collectDocuments(input.documents, issues);
  if (documents === null) return failResult(issues);

  // 3. Per-entry gates: lossless JSON value -> digest -> schema instance ->
  //    identity. The seat/state documents are collected for the mutant
  //    semantic proof.
  const entries = [...manifest.assets, ...manifest.mutants];
  const listed = new Set<string>();
  const knownSeats: string[] = [];
  const stateDocuments: unknown[] = [];
  let mutantEntry: FixtureManifest['mutants'][number] | undefined;
  let mutantDocument: unknown;
  let mutantDocumentClean = false;
  for (const entry of entries) {
    listed.add(entry.path);
    const docPath = `$/documents/${entry.path}`;
    const document = documents.get(entry.path);
    if (document === undefined) {
      issues.push(issue(docPath, 'AIPT_FIXTURE_MISSING_ASSET', `listed fixture asset ${JSON.stringify(entry.path)} is missing from the supplied documents`));
      continue;
    }
    const issuesBefore = issues.length;

    // Lossless JSON-value gate (cycles/undefined/unsafe integers/etc.).
    const lossless = validateJsonValue(document, docPath);
    issues.push(...lossless.issues);
    if (!lossless.valid) continue;

    // Canonical digest (fail closed on lossy documents: hashing only runs
    // after the lossless gate passed).
    const digest = sha256Hex(document);
    if (digest !== entry.sha256) {
      issues.push(issue(docPath, 'AIPT_FIXTURE_DIGEST_DRIFT', `canonical JSON SHA-256 of ${JSON.stringify(entry.path)} drifted: got ${digest}, manifest says ${entry.sha256}`));
    }

    // Canonical-schema instance validation against the kind-derived target.
    // The manifest-supplied schema_ref is ignored for evaluation.
    const expectedRef = (D.manifest_kind_schema_refs as Record<string, string>)[entry.kind];
    if (expectedRef !== undefined) {
      const schemaCheck = validateSchemaInstance(schemaDoc, document, expectedRef, docPath);
      issues.push(...schemaCheck.issues);
    } else {
      issues.push(issue(docPath, 'AIPT_FIXTURE_INVALID_SCHEMA', `manifest kind ${JSON.stringify(entry.kind)} has no canonical $defs target`));
    }

    // Identity (mutant wrappers are checked through their inner projection).
    if (entry.kind === D.mutant_kind) {
      const inner = isRecord(document) ? document.projection : undefined;
      issues.push(...checkFixtureIdentity(inner, `${docPath}/projection`, manifest.fixture_id).issues);
    } else {
      issues.push(...checkFixtureIdentity(document, docPath, manifest.fixture_id).issues);
    }

    // Game-neutral document collection for the mutant semantic proof.
    if (entry.kind === 'seat_set' && isRecord(document) && Array.isArray(document.seats)) {
      for (const seat of document.seats) {
        if (isRecord(seat) && typeof seat.seat_id === 'string') knownSeats.push(seat.seat_id);
      }
    } else if (entry.kind === 'state') {
      stateDocuments.push(document);
    }
    if (entry.kind === D.mutant_kind) {
      mutantEntry = entry;
      mutantDocument = document;
      mutantDocumentClean = issues.length === issuesBefore;
    }
  }

  // 4. Mutant semantic proof: the declared semantic rejection must ACTUALLY
  //    be produced — with exactly that one reason — when the mutant
  //    projection is evaluated against a game-neutral state document and the
  //    seat set supplied in this same bundle. A digest-correct neutral or
  //    non-rejecting mutant fails closed.
  if (mutantEntry !== undefined && mutantDocumentClean && isRecord(mutantDocument)) {
    const expected = D.mutant_expected_semantic_rejection;
    const projection = mutantDocument.projection;
    const produced = stateDocuments.some((stateDocument) => {
      const semantic = validateProjectionSemantics(stateDocument, projection, knownSeats);
      return !semantic.valid && semantic.issues.length === 1 && semantic.issues[0].code === expected;
    });
    if (!produced) {
      issues.push(issue('$/mutants/0', 'AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT', `mutant ${JSON.stringify(mutantEntry.path)} must produce exactly its declared semantic rejection ${JSON.stringify(expected)} when evaluated against a bundle-supplied state document (with bundle-supplied seats), but no supplied state produces it`));
    }
  }

  // 5. Exact inventory: every supplied document must be listed (the manifest
  //    document itself is exempt from the inventory check).
  for (const key of documents.keys()) {
    if (key !== 'manifest.json' && !listed.has(key)) {
      issues.push(issue(`$/documents/${key}`, 'AIPT_FIXTURE_UNLISTED_ASSET', `supplied document ${JSON.stringify(key)} is not listed in the fixture manifest`));
    }
  }
  return issues.length === 0 ? okResult() : failResult(issues);
}
