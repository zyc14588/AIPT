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
//
// Iteration 4C contract:
//  - The bundle wrapper and the documents collection are inspected through
//    OWN PROPERTY DESCRIPTORS ONLY (no getter/setter invocation, no
//    traversal) and the documents collection is never traversed before the
//    manifest preflight succeeds.
//  - After manifest preflight and BEFORE any asset document processing, the
//    caller-supplied schema must be a lossless JSON document whose canonical
//    SHA-256 equals CONTRACT_DESCRIPTOR.canonical_schema_sha256; a missing,
//    malformed, lossy, or fingerprint-drifted schema fails with
//    AIPT_FIXTURE_INVALID_SCHEMA.
//  - Every clean ordinary projection asset must pass
//    validateProjectionSemantics against at least one compatible supplied
//    state document using the supplied known seats (schema validity alone is
//    insufficient; hidden data never passes as an ordinary projection).
//  - The mutant wrapper seat_id is bound to projection.seat_id and
//    leaked_field_id to the single field producing the declared rejection;
//    metadata drift fails with AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT.
//  - Exact inventory means exact: a supplied documents entry named
//    manifest.json is unlisted and rejected like every other unlisted
//    document (no exemption).
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
// asset fixture_id to equal the manifest fixture_id). The whole document must
// first pass the lossless JSON-value gate (no getter/setter invocation).
export function checkFixtureIdentity(document: unknown, path = '$', expectedFixtureId?: string): ValidationResult {
  const lossy = validateJsonValue(document, path);
  if (!lossy.valid) return failResult([...lossy.issues]);
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
  const lossy = validateJsonValue(input, '$');
  if (!lossy.valid) return failResult([...lossy.issues]);
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
// Bundle wrapper / documents collection (descriptor-only, no accessors).
// ---------------------------------------------------------------------------

// Read the caller-supplied bundle wrapper through its OWN PROPERTY
// DESCRIPTORS only: symbol-keyed members, accessors, and non-enumerable
// members fail closed deterministically (AIPT_FIXTURE_INVALID_MANIFEST)
// without ever invoking a getter/setter. Accepted enumerable data members
// are read from their data descriptor (a descriptor read never invokes an
// accessor).
function readBundleWrapper(input: unknown, issues: ValidationIssue[]): Record<string, unknown> | null {
  if (!isRecord(input)) {
    issues.push(issue('$', 'AIPT_FIXTURE_INVALID_MANIFEST', 'fixture bundle must be an object with manifest and documents'));
    return null;
  }
  const members: Record<string, unknown> = {};
  if (Object.getOwnPropertySymbols(input).length > 0) {
    issues.push(issue('$', 'AIPT_FIXTURE_INVALID_MANIFEST', 'fixture bundle wrapper must not carry symbol-keyed members'));
  }
  for (const key of Object.getOwnPropertyNames(input)) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (descriptor === undefined) continue;
    if (descriptor.get !== undefined || descriptor.set !== undefined) {
      issues.push(issue(`$/${key}`, 'AIPT_FIXTURE_INVALID_MANIFEST', `bundle wrapper member ${JSON.stringify(key)} must be an ordinary data member, not an accessor`));
      continue;
    }
    if (!descriptor.enumerable) {
      issues.push(issue(`$/${key}`, 'AIPT_FIXTURE_INVALID_MANIFEST', `bundle wrapper member ${JSON.stringify(key)} must be an enumerable data member`));
      continue;
    }
    members[key] = descriptor.value;
  }
  return issues.length === 0 ? members : null;
}

// Build the trusted documents map from the caller-supplied bundle. Map keys
// must be strings; for the object form, every own member is inspected via
// its descriptor (symbol keys, accessors, and non-enumerable members fail
// closed without invocation) and read from its data descriptor. The document
// VALUES are collected by reference only — nothing is traversed here; the
// per-entry gates (after manifest preflight and the canonical schema binding)
// own all document interpretation.
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
    for (const key of Object.getOwnPropertyNames(input)) {
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (descriptor === undefined) continue;
      if (descriptor.get !== undefined || descriptor.set !== undefined) {
        issues.push(issue(`$/documents/${key}`, 'AIPT_FIXTURE_INVALID_MANIFEST', `documents member ${JSON.stringify(key)} must be an ordinary data member, not an accessor`));
        continue;
      }
      if (!descriptor.enumerable) {
        issues.push(issue(`$/documents/${key}`, 'AIPT_FIXTURE_INVALID_MANIFEST', `documents member ${JSON.stringify(key)} must be an enumerable data member`));
        continue;
      }
      documents.set(key, descriptor.value);
    }
    return documents;
  }
  issues.push(issue('$/documents', 'AIPT_FIXTURE_INVALID_MANIFEST', 'fixture documents must be a Map or an object keyed by manifest path'));
  return null;
}

// ---------------------------------------------------------------------------
// Bundle validation.
// ---------------------------------------------------------------------------

// Validate a supplied fixture bundle against the caller-supplied canonical
// schema document (explicit second argument or bundle.schema member). Order
// of gates (iteration 4C):
//  1. Bundle wrapper descriptor inspection (no accessor invocation).
//  2. Manifest preflight — on ANY failure, stop BEFORE hashing, reading,
//     traversing, or invoking anything in supplied asset documents.
//  3. Canonical schema binding: lossless JSON document + canonical SHA-256
//     equality with CONTRACT_DESCRIPTOR.canonical_schema_sha256
//     (AIPT_FIXTURE_INVALID_SCHEMA otherwise).
//  4. Documents collection via own property descriptors (no traversal yet).
//  5. Per listed entry: lossless gate -> digest -> canonical-schema instance
//     -> identity; clean seat/state/projection documents are collected.
//  6. Ordinary projection semantic gate: every clean projection asset must
//     pass validateProjectionSemantics against at least one compatible
//     supplied state document with the supplied known seats.
//  7. Mutant semantic proof (exact declared rejection; wrapper seat_id bound
//     to projection.seat_id; leaked_field_id bound to the single rejected
//     field).
//  8. Exact inventory: every supplied document must be listed — a supplied
//     manifest.json entry is unlisted and rejected like every other
//     unlisted document.
export function validateFixtureBundle(input: unknown, schema?: unknown): ValidationResult {
  const wrapperIssues: ValidationIssue[] = [];
  const wrapper = readBundleWrapper(input, wrapperIssues);
  if (wrapper === null) return failResult(wrapperIssues);

  // 1. Manifest preflight first: on any failure, stop BEFORE hashing or
  //    interpreting supplied asset documents (and before traversing the
  //    documents collection).
  const manifestCheck = validateFixtureManifest(wrapper.manifest);
  if (!manifestCheck.valid) return manifestCheck;
  const manifest = wrapper.manifest as unknown as FixtureManifest;

  // 2. Canonical schema binding: after manifest preflight but before any
  //    asset document processing, the supplied schema must be a lossless
  //    JSON document whose canonical SHA-256 equals the full-content
  //    fingerprint carried by the contract descriptor.
  const schemaDoc = schema !== undefined ? schema : wrapper.schema;
  if (schemaDoc === undefined) {
    return failResult([issue('$/schema', 'AIPT_FIXTURE_INVALID_SCHEMA', 'bundle validation requires the caller-supplied canonical schema document (explicit argument or bundle.schema member); the SDK never reads the repository filesystem')]);
  }
  const schemaLossy = validateJsonValue(schemaDoc, '$/schema');
  if (!schemaLossy.valid) {
    const first = schemaLossy.issues[0];
    return failResult([issue('$/schema', 'AIPT_FIXTURE_INVALID_SCHEMA', `the supplied canonical schema must be a lossless JSON document (rejected at ${first.path}: ${first.message})`)]);
  }
  if (!isRecord(schemaDoc)) {
    return failResult([issue('$/schema', 'AIPT_FIXTURE_INVALID_SCHEMA', 'the supplied canonical schema document must be a JSON object')]);
  }
  const schemaDigest = sha256Hex(schemaDoc);
  if (schemaDigest !== D.canonical_schema_sha256) {
    return failResult([issue('$/schema', 'AIPT_FIXTURE_INVALID_SCHEMA', `canonical schema fingerprint drifted: got ${schemaDigest}, the contract descriptor carries ${D.canonical_schema_sha256} (only the exact canonical schema document may validate a fixture bundle)`)]);
  }

  // 3. Trusted documents map (collected by reference; nothing traversed).
  const issues: ValidationIssue[] = [];
  const documents = collectDocuments(wrapper.documents, issues);
  if (documents === null || issues.length > 0) return failResult(issues);

  // 4. Per-entry gates: lossless JSON value -> digest -> schema instance ->
  //    identity. Clean seat/state/projection documents are collected for the
  //    semantic gates.
  const entries = [...manifest.assets, ...manifest.mutants];
  const listed = new Set<string>();
  const knownSeats: string[] = [];
  const stateDocuments: unknown[] = [];
  const projectionDocuments: Array<{ readonly entry: FixtureManifest['assets'][number]; readonly document: unknown; readonly docPath: string }> = [];
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

    // Lossless JSON-value gate (cycles/undefined/unsafe integers/accessors/
    // symbol keys/etc.; no getter/setter invocation).
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

    const entryClean = issues.length === issuesBefore;

    // Game-neutral document collection for the semantic gates — only
    // documents that passed every gate are trusted.
    if (entryClean) {
      if (entry.kind === 'seat_set' && isRecord(document) && Array.isArray(document.seats)) {
        for (const seat of document.seats) {
          if (isRecord(seat) && typeof seat.seat_id === 'string') knownSeats.push(seat.seat_id);
        }
      } else if (entry.kind === 'state') {
        stateDocuments.push(document);
      } else if (entry.kind === 'projection') {
        projectionDocuments.push({ entry, document, docPath });
      }
    }
    if (entry.kind === D.mutant_kind) {
      mutantEntry = entry;
      mutantDocument = document;
      mutantDocumentClean = entryClean;
    }
  }

  // 5. Ordinary projection semantic gate: schema validity is NOT enough for
  //    an ordinary projection — every clean projection asset must pass
  //    validateProjectionSemantics against at least one compatible supplied
  //    state document using the supplied known seats. Hidden data must never
  //    pass as an ordinary projection.
  for (const projectionDoc of projectionDocuments) {
    if (stateDocuments.length === 0) {
      issues.push(issue(projectionDoc.docPath, 'AIPT_PROJECTION_INVALID', `ordinary projection ${JSON.stringify(projectionDoc.entry.path)} requires at least one clean supplied state document to prove its semantics, but no clean state document was supplied`));
      continue;
    }
    let compatible = false;
    let firstFailure: ValidationIssue[] | null = null;
    for (const stateDocument of stateDocuments) {
      const semantic = validateProjectionSemantics(stateDocument, projectionDoc.document, knownSeats);
      if (semantic.valid) {
        compatible = true;
        break;
      }
      if (firstFailure === null) firstFailure = [...semantic.issues];
    }
    if (!compatible) {
      if (firstFailure !== null && firstFailure.length > 0) {
        for (const semanticIssue of firstFailure) {
          issues.push(issue(`${projectionDoc.docPath}${semanticIssue.path.slice(1)}`, semanticIssue.code, semanticIssue.message));
        }
      } else {
        issues.push(issue(projectionDoc.docPath, 'AIPT_PROJECTION_INVALID', `ordinary projection ${JSON.stringify(projectionDoc.entry.path)} does not pass the semantic projection contract against any compatible supplied state document`));
      }
    }
  }

  // 6. Mutant semantic proof: the declared semantic rejection must ACTUALLY
  //    be produced — with exactly that one reason — when the mutant
  //    projection is evaluated against a game-neutral state document and the
  //    seat set supplied in this same bundle. The wrapper seat_id is bound to
  //    projection.seat_id and leaked_field_id is bound to the single field
  //    that produces the declared rejection (metadata drift fails closed).
  if (mutantEntry !== undefined && mutantDocumentClean && isRecord(mutantDocument)) {
    const expected = D.mutant_expected_semantic_rejection;
    const projection = mutantDocument.projection;
    let produced: { readonly semantic: ValidationResult } | null = null;
    for (const stateDocument of stateDocuments) {
      const semantic = validateProjectionSemantics(stateDocument, projection, knownSeats);
      if (!semantic.valid && semantic.issues.length === 1 && semantic.issues[0].code === expected) {
        produced = { semantic };
        break;
      }
    }
    if (produced === null) {
      issues.push(issue('$/mutants/0', 'AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT', `mutant ${JSON.stringify(mutantEntry.path)} must produce exactly its declared semantic rejection ${JSON.stringify(expected)} when evaluated against a bundle-supplied state document (with bundle-supplied seats), but no supplied state produces it`));
    } else {
      const projectionSeatId = isRecord(projection) ? projection.seat_id : undefined;
      if (mutantDocument.seat_id !== projectionSeatId) {
        issues.push(issue('$/mutants/0/seat_id', 'AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT', `mutant wrapper seat_id ${JSON.stringify(mutantDocument.seat_id)} must equal the wrapped projection.seat_id ${JSON.stringify(projectionSeatId)}`));
      }
      const rejectionPath = produced.semantic.issues[0].path;
      const rejectedFieldId = rejectionPath.startsWith('$/fields/') ? rejectionPath.slice('$/fields/'.length) : null;
      if (mutantDocument.leaked_field_id !== rejectedFieldId) {
        issues.push(issue('$/mutants/0/leaked_field_id', 'AIPT_FIXTURE_MUTANT_SEMANTIC_DRIFT', `mutant wrapper leaked_field_id ${JSON.stringify(mutantDocument.leaked_field_id)} must equal the single field that produces ${JSON.stringify(expected)} (${JSON.stringify(rejectedFieldId)})`));
      }
    }
  }

  // 7. Exact inventory: every supplied document must be listed. There is NO
  //    exemption: a supplied documents entry named manifest.json is unlisted
  //    (the manifest is carried by the wrapper's manifest member, never as a
  //    listed document) and is rejected like every other unlisted document.
  for (const key of documents.keys()) {
    if (!listed.has(key)) {
      issues.push(issue(`$/documents/${key}`, 'AIPT_FIXTURE_UNLISTED_ASSET', `supplied document ${JSON.stringify(key)} is not listed in the fixture manifest`));
    }
  }
  return issues.length === 0 ? okResult() : failResult(issues);
}
