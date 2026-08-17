// Fixture compatibility helpers.
//
// Pure validation over SUPPLIED parsed documents/assets: this package never
// reads the repository filesystem, never copies the canonical fixture, and
// never creates a second fixture truth. The helpers validate the fixture
// manifest shape, the canonical-JSON SHA-256 digest of every supplied
// document against the manifest, the protocol identity triple of every
// document (mutant wrappers included, via their inner projection), and the
// exact inventory of supplied documents.
import { CONTRACT_DESCRIPTOR as D } from './contract/descriptor.ts';
import { sha256Hex } from './canonical-json.ts';
import { failResult, issue, okResult, type ValidationIssue, type ValidationResult } from './errors.ts';
import type { FixtureManifest } from './types.ts';

const SHA256_RE = /^[0-9a-f]{64}$/u;
const SCHEMA_REF_RE = /^#\/\$defs\/[A-Za-z0-9_-]+$/u;
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

function checkManifestEntry(entry: unknown, path: string, allowedKinds: readonly string[], issues: ValidationIssue[]): void {
  if (!isRecord(entry)) {
    issues.push(issue(path, 'AIPT_INVALID_VALUE', 'manifest entry must be an object'));
    return;
  }
  for (const key of ['path', 'kind', 'schema_ref', 'sha256']) {
    if (!hasOwn(entry, key)) issues.push(issue(`${path}/${key}`, 'AIPT_MISSING_REQUIRED', `missing required manifest entry member ${JSON.stringify(key)}`));
  }
  const extra = Object.keys(entry).filter((key) => !['path', 'kind', 'schema_ref', 'sha256', 'expected_semantic_rejection'].includes(key));
  for (const key of extra) issues.push(issue(`${path}/${key}`, 'AIPT_UNKNOWN_FIELD', `manifest entry member ${JSON.stringify(key)} is not allowed`));
  if (typeof entry.path !== 'string' || entry.path.length < 1) {
    issues.push(issue(`${path}/path`, 'AIPT_INVALID_VALUE', 'manifest entry path must be a non-empty string'));
  }
  if (typeof entry.kind !== 'string' || !allowedKinds.includes(entry.kind)) {
    issues.push(issue(`${path}/kind`, 'AIPT_INVALID_VALUE', `unknown manifest entry kind ${JSON.stringify(entry.kind)}`));
  }
  if (typeof entry.schema_ref !== 'string' || !SCHEMA_REF_RE.test(entry.schema_ref)) {
    issues.push(issue(`${path}/schema_ref`, 'AIPT_INVALID_VALUE', `schema_ref must match ^#/\\$defs/[A-Za-z0-9_-]+$, got ${JSON.stringify(entry.schema_ref)}`));
  }
  if (typeof entry.sha256 !== 'string' || !SHA256_RE.test(entry.sha256)) {
    issues.push(issue(`${path}/sha256`, 'AIPT_INVALID_VALUE', 'manifest entry sha256 must be 64 lowercase hexadecimal characters'));
  }
}

export function validateFixtureManifest(input: unknown): ValidationResult {
  const issues: ValidationIssue[] = [];
  if (!isRecord(input)) {
    return failResult([issue('$', 'AIPT_FIXTURE_INVALID_MANIFEST', 'fixture manifest must be a JSON object')]);
  }
  for (const key of D.fixture_manifest_required) {
    if (!hasOwn(input, key)) issues.push(issue(`$/${key}`, 'AIPT_MISSING_REQUIRED', `missing required manifest member ${JSON.stringify(key)}`));
  }
  const extra = Object.keys(input).filter((key) => !D.fixture_manifest_required.includes(key));
  for (const key of extra) issues.push(issue(`$/${key}`, 'AIPT_UNKNOWN_FIELD', `manifest member ${JSON.stringify(key)} is not allowed`));
  if (input.protocol_version !== D.protocol_version) issues.push(issue('$/protocol_version', 'AIPT_UNKNOWN_VERSION', `protocol_version must be exactly ${JSON.stringify(D.protocol_version)}`));
  if (input.schema_version !== D.schema_version) issues.push(issue('$/schema_version', 'AIPT_UNKNOWN_VERSION', `schema_version must be exactly ${JSON.stringify(D.schema_version)}`));
  if (typeof input.fixture_id !== 'string' || !IDENTIFIER_RE.test(input.fixture_id)) {
    issues.push(issue('$/fixture_id', 'AIPT_FIXTURE_IDENTITY_MISMATCH', `fixture_id must match ${D.identifier_pattern}`));
  }
  if (typeof input.fixture_name !== 'string' || input.fixture_name.length < 1) {
    issues.push(issue('$/fixture_name', 'AIPT_INVALID_VALUE', 'fixture_name must be a non-empty string'));
  }
  if (typeof input.expected_final_state !== 'string' || input.expected_final_state.length < 1) {
    issues.push(issue('$/expected_final_state', 'AIPT_INVALID_VALUE', 'expected_final_state must be a non-empty string'));
  }
  if (typeof input.replay_assertion !== 'string' || input.replay_assertion.length < 1) {
    issues.push(issue('$/replay_assertion', 'AIPT_INVALID_VALUE', 'replay_assertion must be a non-empty string'));
  }
  const assets = input.assets;
  if (!Array.isArray(assets) || assets.length < 1) {
    issues.push(issue('$/assets', 'AIPT_INVALID_VALUE', 'assets must be a non-empty array'));
  } else {
    assets.forEach((entry, index) => checkManifestEntry(entry, `$/assets/${index}`, D.manifest_kinds, issues));
  }
  const mutants = input.mutants;
  if (!Array.isArray(mutants) || mutants.length !== 1) {
    issues.push(issue('$/mutants', 'AIPT_INVALID_VALUE', 'mutants must be an array with exactly one entry'));
  } else {
    mutants.forEach((entry, index) => {
      const path = `$/mutants/${index}`;
      checkManifestEntry(entry, path, [D.mutant_kind], issues);
      if (isRecord(entry)) {
        if (entry.kind !== D.mutant_kind) {
          issues.push(issue(`${path}/kind`, 'AIPT_INVALID_VALUE', `mutant entry kind must be exactly ${JSON.stringify(D.mutant_kind)}`));
        }
        if (entry.expected_semantic_rejection !== D.mutant_expected_semantic_rejection) {
          issues.push(issue(`${path}/expected_semantic_rejection`, 'AIPT_INVALID_VALUE', `mutant expected_semantic_rejection must be exactly ${JSON.stringify(D.mutant_expected_semantic_rejection)}`));
        }
      }
    });
  }
  return issues.length === 0 ? okResult() : failResult(issues);
}

// Validate a supplied fixture bundle: manifest plus parsed documents keyed by
// manifest path. Every listed asset must be present with a matching canonical
// JSON SHA-256 digest and a matching protocol identity triple (mutant
// wrappers are checked through their inner projection); unlisted supplied
// documents fail closed. The manifest document itself ('manifest.json') is
// not an asset entry and is exempt from the inventory check.
export function validateFixtureBundle(input: unknown): ValidationResult {
  if (!isRecord(input)) {
    return failResult([issue('$', 'AIPT_FIXTURE_INVALID_MANIFEST', 'fixture bundle must be an object with manifest and documents')]);
  }
  const manifestCheck = validateFixtureManifest(input.manifest);
  if (!manifestCheck.valid) return manifestCheck;
  const manifest = input.manifest as unknown as FixtureManifest;

  const documents = new Map<string, unknown>();
  if (input.documents instanceof Map) {
    for (const [key, value] of input.documents) {
      if (typeof key === 'string') documents.set(key, value);
    }
  } else if (isRecord(input.documents)) {
    for (const key of Object.keys(input.documents)) documents.set(key, input.documents[key]);
  } else {
    return failResult([issue('$/documents', 'AIPT_FIXTURE_INVALID_MANIFEST', 'fixture documents must be a Map or an object keyed by manifest path')]);
  }

  const issues: ValidationIssue[] = [];
  const entries = [...manifest.assets, ...manifest.mutants];
  const listed = new Set<string>();
  for (const entry of entries) {
    if (typeof entry.path !== 'string') continue;
    listed.add(entry.path);
    const docPath = `$/documents/${entry.path}`;
    const document = documents.get(entry.path);
    if (document === undefined) {
      issues.push(issue(docPath, 'AIPT_FIXTURE_MISSING_ASSET', `listed fixture asset ${JSON.stringify(entry.path)} is missing from the supplied documents`));
      continue;
    }
    let digest: string;
    try {
      digest = sha256Hex(document);
    } catch {
      digest = '';
    }
    if (digest !== entry.sha256) {
      issues.push(issue(docPath, 'AIPT_FIXTURE_DIGEST_DRIFT', `canonical JSON SHA-256 of ${JSON.stringify(entry.path)} drifted: got ${digest || 'unserializable'}, manifest says ${entry.sha256}`));
    }
    if (entry.kind === D.mutant_kind && isRecord(document)) {
      const inner = document.projection;
      const innerCheck = checkFixtureIdentity(inner, `${docPath}/projection`, manifest.fixture_id);
      issues.push(...innerCheck.issues);
    } else {
      const identityCheck = checkFixtureIdentity(document, docPath, manifest.fixture_id);
      issues.push(...identityCheck.issues);
    }
  }
  for (const key of documents.keys()) {
    if (key !== 'manifest.json' && !listed.has(key)) {
      issues.push(issue(`$/documents/${key}`, 'AIPT_FIXTURE_UNLISTED_ASSET', `supplied document ${JSON.stringify(key)} is not listed in the fixture manifest`));
    }
  }
  return issues.length === 0 ? okResult() : failResult(issues);
}
