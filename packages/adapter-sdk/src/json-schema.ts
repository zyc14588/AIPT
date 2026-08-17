// Package-local, dependency-free evaluator for the exact supported canonical
// JSON Schema 2020-12 subset (B002, iterations 4B/4C/4D).
//
// The canonical schema schemas/protocol/v1/aipt-protocol.schema.json is the
// single wire authority; it is NEVER copied into this package. Fixture
// compatibility validation receives the caller-supplied canonical schema
// document as an explicit validation boundary and evaluates every supplied
// asset against its independently expected canonical $defs target before
// trusting it. The evaluator implements exactly the functional keywords the
// canonical schema uses — `$ref` (local `#/...` pointers only), `type`,
// `const`, `enum`, `properties`, `required`, `additionalProperties`,
// `items`, `minItems`, `maxItems`, `uniqueItems`, `minLength`, `maxLength`,
// `pattern`, `minimum`, `maximum`, `exclusiveMinimum`, `exclusiveMaximum`,
// `multipleOf`, `minProperties`, `maxProperties`, `oneOf`, `anyOf`,
// `allOf`, `not` — and enforces the declared grammar truthfully:
//
//   - Annotations: `title`, `description`, and `$comment` are strings;
//     `examples` is an array; `deprecated` is a boolean; `default` may be
//     any lossless JSON value (the whole-document lossless JSON-value gate
//     already rejects every non-JSON value, this member included).
//   - Structural keywords: `$schema`, `$id`, and `$defs` are ROOT-ONLY in
//     the declared repository subset — a nested occurrence is rejected, not
//     silently ignored. At the root, `$schema` (when present) must be
//     exactly the JSON Schema 2020-12 meta-schema URI, `$id` must be a
//     string, and `$defs` must be an object whose children are supported
//     schema nodes. Synthetic package-local schema documents need not carry
//     `$schema` and stay valid without it.
//   - `required` must be an array of UNIQUE strings (an empty array is
//     valid JSON Schema 2020-12 and is accepted). A `type` array must be
//     non-empty, contain only the supported type names, and contain no
//     duplicates. An `enum` must be non-empty and contain JSON-semantically
//     unique values (duplicate members are rejected deterministically).
//   - Schema nodes are OBJECTS ONLY in this package-local subset: `items`,
//     `properties`, `additionalProperties` (boolean allowed), and
//     combinator branches never accept boolean or array-form schema nodes.
//     This deliberate narrowness is not broadened here.
//
// Any OTHER keyword, an unresolvable local `$ref`, a circular local `$ref`
// chain, or a malformed schema node fails closed with
// AIPT_FIXTURE_INVALID_SCHEMA; instance violations are reported
// path-addressed with AIPT_FIXTURE_SCHEMA_VIOLATION. Nothing is silently
// ignored: an unsupported functional keyword is a rejection, never a pass.
//
// Iteration 4C contract: before ANY instance evaluation, a deterministic
// recursive schema-grammar preflight validates the whole supplied schema
// document — keyword value shapes and ranges (non-negative integer bounds
// keywords, string pattern constraints, boolean flags, object properties,
// unique required arrays, combination arrays), supported type names,
// schema-valued children (`properties`/`items`/`additionalProperties`/
// combinator branches/`not`/`$defs`), local refs, and annotation/structural
// keyword shapes. The preflight traverses the ENTIRE schema document (every
// $defs child, every combinator branch, even branches inside `not`), so an
// unsupported or malformed keyword hidden in a passing anyOf/oneOf branch or
// inside `not` is rejected BEFORE any instance is evaluated — and the
// evaluator additionally propagates invalid-schema issues out of combinator
// branches so they can never be converted into an ordinary branch mismatch.
// `const` uses own-member presence (null/false/0 all apply). External and
// unresolvable refs remain rejections. The schema document is never copied
// and never mutated.
//
// Iteration 4D contract:
//   - The preflight runs FRESH on every public validation call. A
//     caller-supplied mutable schema object is a trust boundary, so a PASS
//     is never reused across calls by object identity (there is no
//     preflight cache) and the caller's data is never copied, frozen, or
//     mutated — a later mutation of the same object is observed by the next
//     call. Each call only reads current content.
//   - The preflight walks the complete local-$ref graph with explicit
//     visiting/done state: every local `$ref` cycle is rejected with
//     AIPT_FIXTURE_INVALID_SCHEMA before instance evaluation, even when the
//     cycle lives in an unused `$defs` child that no requested ref reaches.
//     Valid acyclic DAG/shared-target references and repeated non-ancestral
//     JavaScript object aliases stay valid; ordinary containment traversal
//     is never mistaken for a ref cycle (the lossless JSON-value gate
//     already rejected cyclic container structures).
//   - Decimal `multipleOf` uses the deterministic tolerance of the
//     repository's independent standard-library oracle: with
//     q = instance / multipleOf, the instance is a multiple iff
//     abs(q - round(q)) <= 1e-9, so 0.3 is a multiple of 0.1 while nearby
//     non-multiples (0.35) still fail.
import { failResult, issue, okResult, type ValidationIssue, type ValidationResult } from './errors.ts';
import { validateJsonValue } from './json-value.ts';

const META_SCHEMA_URI = 'https://json-schema.org/draft/2020-12/schema';
const MULTIPLE_OF_TOLERANCE = 1e-9;
const ANNOTATION_KEYWORDS = new Set(['title', 'description', 'examples', 'default', 'deprecated', '$comment', '$schema', '$id', '$defs']);
const FUNCTIONAL_KEYWORDS = new Set([
  '$ref', 'type', 'const', 'enum', 'properties', 'required', 'additionalProperties', 'items',
  'minItems', 'maxItems', 'uniqueItems', 'minLength', 'maxLength', 'pattern',
  'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf',
  'minProperties', 'maxProperties', 'oneOf', 'anyOf', 'allOf', 'not',
]);
const SUPPORTED_TYPE_NAMES = new Set(['object', 'array', 'string', 'number', 'integer', 'boolean', 'null']);
const NON_NEGATIVE_INTEGER_KEYWORDS = new Set(['minItems', 'maxItems', 'minLength', 'maxLength', 'minProperties', 'maxProperties']);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasOwn(value: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function describe(value: unknown): string {
  if (value === undefined) return 'undefined';
  if (typeof value === 'function') return 'a function';
  if (typeof value === 'symbol') return 'a symbol';
  if (typeof value === 'bigint') return `${value}n`;
  try {
    const text = JSON.stringify(value);
    if (text !== undefined) return text;
  } catch {
    // fall through to String (cyclic structures cannot be stringified)
  }
  try {
    return String(value);
  } catch {
    return '<unrepresentable>';
  }
}

function deepJsonEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null || typeof a !== 'object') return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((item, index) => deepJsonEqual(item, b[index]));
  }
  const recordA = a as Record<string, unknown>;
  const recordB = b as Record<string, unknown>;
  const keysA = Object.keys(recordA);
  const keysB = Object.keys(recordB);
  if (keysA.length !== keysB.length) return false;
  return keysA.every((key) => hasOwn(recordB, key) && deepJsonEqual(recordA[key], recordB[key]));
}

function matchesType(expected: string, value: unknown): boolean {
  switch (expected) {
    case 'object': return isRecord(value);
    case 'array': return Array.isArray(value);
    case 'string': return typeof value === 'string';
    case 'number': return typeof value === 'number' && Number.isFinite(value);
    case 'integer': return typeof value === 'number' && Number.isInteger(value);
    case 'boolean': return typeof value === 'boolean';
    case 'null': return value === null;
    default: return false;
  }
}

// ---------------------------------------------------------------------------
// Deterministic recursive schema-grammar preflight (iterations 4C/4D).
// ---------------------------------------------------------------------------

interface PreflightContext {
  readonly root: Record<string, unknown>;
  readonly issues: ValidationIssue[];
  // Explicit three-state walk: 0 = visiting (on the current traversal
  // stack), 1 = done (fully grammar-checked). A $ref back into a visiting
  // node is a circular local-ref chain; re-encountering a done node is an
  // ordinary shared acyclic target/alias and is skipped.
  readonly state: Map<object, 0 | 1>;
}

function preflightInvalid(ctx: PreflightContext, message: string): void {
  ctx.issues.push(issue('$schema', 'AIPT_FIXTURE_INVALID_SCHEMA', message));
}

// Resolve a local JSON pointer against the schema root. Returns null when the
// pointer is unresolvable. External (non-`#/`) pointers never resolve here.
function resolvePointerNode(root: Record<string, unknown>, pointer: string): unknown | null {
  if (!pointer.startsWith('#/')) return null;
  const segments = pointer
    .slice(2)
    .split('/')
    .map((segment) => segment.replace(/~1/gu, '/').replace(/~0/gu, '~'));
  let node: unknown = root;
  for (const segment of segments) {
    if (isRecord(node) && hasOwn(node, segment)) {
      node = node[segment];
    } else {
      return null;
    }
  }
  return node;
}

function preflightNode(node: unknown, label: string, ctx: PreflightContext): void {
  if (!isRecord(node)) {
    preflightInvalid(ctx, `schema node at ${label} must be a JSON object (boolean schemas are outside the supported canonical subset)`);
    return;
  }
  const nodeState = ctx.state.get(node);
  if (nodeState === 1) return; // already fully checked via another path
  if (nodeState === 0) {
    // Re-entered through a local $ref while still on the traversal stack:
    // a circular ref chain. Ordinary containment can never re-enter an
    // ancestor here (the lossless JSON-value gate rejected cyclic container
    // structures before the preflight runs).
    preflightInvalid(ctx, `circular local $ref chain detected at ${label} (cyclic refs are rejected in this subset)`);
    return;
  }
  ctx.state.set(node, 0);
  const structural = node === ctx.root;
  for (const key of Object.keys(node).sort()) {
    const value = node[key];
    switch (key) {
      case '$ref': {
        if (typeof value !== 'string' || !value.startsWith('#/')) {
          preflightInvalid(ctx, `schema "$ref" at ${label} must be a local JSON pointer, got ${describe(value)}`);
          continue;
        }
        const target = resolvePointerNode(ctx.root, value);
        if (target === null) preflightInvalid(ctx, `unresolvable local $ref ${JSON.stringify(value)} at ${label}`);
        else preflightNode(target, value, ctx);
        continue;
      }
      case '$schema':
        if (!structural) {
          preflightInvalid(ctx, `schema "$schema" is structural and root-only in the supported canonical subset (nested occurrence at ${label} is rejected, never ignored)`);
        } else if (value !== META_SCHEMA_URI) {
          preflightInvalid(ctx, `schema "$schema" at ${label} must be exactly ${META_SCHEMA_URI} (JSON Schema 2020-12), got ${describe(value)}`);
        }
        continue;
      case '$id':
        if (!structural) {
          preflightInvalid(ctx, `schema "$id" is structural and root-only in the supported canonical subset (nested occurrence at ${label} is rejected, never ignored)`);
        } else if (typeof value !== 'string') {
          preflightInvalid(ctx, `schema "$id" at ${label} must be a string, got ${describe(value)}`);
        }
        continue;
      case '$defs':
        if (!structural) {
          preflightInvalid(ctx, `schema "$defs" is structural and root-only in the supported canonical subset (nested occurrence at ${label} is rejected, never ignored)`);
          continue;
        }
        if (!isRecord(value)) {
          preflightInvalid(ctx, `schema "$defs" at ${label} must be an object`);
          continue;
        }
        for (const name of Object.keys(value)) preflightNode(value[name], `${label}/$defs/${name}`, ctx);
        continue;
      case '$comment':
      case 'title':
      case 'description':
        if (typeof value !== 'string') {
          preflightInvalid(ctx, `schema annotation ${JSON.stringify(key)} at ${label} must be a string, got ${describe(value)}`);
        }
        continue;
      case 'examples':
        if (!Array.isArray(value)) {
          preflightInvalid(ctx, `schema annotation "examples" at ${label} must be an array, got ${describe(value)}`);
        }
        continue;
      case 'default':
        // Any lossless JSON value: the whole-document lossless JSON-value
        // gate already rejected every non-JSON value anywhere in the schema
        // document, this member included.
        continue;
      case 'deprecated':
        if (typeof value !== 'boolean') {
          preflightInvalid(ctx, `schema annotation "deprecated" at ${label} must be a boolean, got ${describe(value)}`);
        }
        continue;
      case 'type': {
        const types = Array.isArray(value) ? value : [value];
        if (Array.isArray(value) && types.length === 0) {
          preflightInvalid(ctx, `schema "type" at ${label} must be a non-empty array of supported type names`);
          continue;
        }
        for (const entry of types) {
          if (typeof entry !== 'string' || !SUPPORTED_TYPE_NAMES.has(entry)) {
            preflightInvalid(ctx, `schema "type" at ${label} contains unsupported type name ${describe(entry)} (supported: ${[...SUPPORTED_TYPE_NAMES].sort().join(', ')})`);
          }
        }
        if (Array.isArray(value) && new Set(types).size !== types.length) {
          preflightInvalid(ctx, `schema "type" at ${label} must not repeat type names`);
        }
        continue;
      }
      case 'const':
        // Any lossless JSON value (null/false/0 included). Presence during
        // instance evaluation is own-member based (hasOwn), never
        // undefined-based, so falsy const values still apply.
        continue;
      case 'enum':
        if (!Array.isArray(value) || value.length === 0) {
          preflightInvalid(ctx, `schema "enum" at ${label} must be a non-empty array`);
          continue;
        }
        for (let i = 0; i < value.length; i += 1) {
          for (let j = i + 1; j < value.length; j += 1) {
            if (deepJsonEqual(value[i], value[j])) {
              preflightInvalid(ctx, `schema "enum" at ${label} must not repeat JSON-equal values (entries ${i} and ${j} are duplicates)`);
            }
          }
        }
        continue;
      case 'properties': {
        if (!isRecord(value)) {
          preflightInvalid(ctx, `schema "properties" at ${label} must be an object`);
          continue;
        }
        for (const name of Object.keys(value)) preflightNode(value[name], `${label}/properties/${name}`, ctx);
        continue;
      }
      case 'required':
        // An empty array is valid JSON Schema 2020-12 and is accepted; the
        // entries must be unique strings.
        if (!Array.isArray(value) || !value.every((entry) => typeof entry === 'string')) {
          preflightInvalid(ctx, `schema "required" at ${label} must be an array of strings`);
          continue;
        }
        if (new Set(value).size !== value.length) {
          preflightInvalid(ctx, `schema "required" at ${label} must not repeat member names`);
        }
        continue;
      case 'additionalProperties':
        if (typeof value === 'boolean') continue;
        if (isRecord(value)) {
          preflightNode(value, `${label}/additionalProperties`, ctx);
          continue;
        }
        preflightInvalid(ctx, `schema "additionalProperties" at ${label} must be a boolean or a schema object, got ${describe(value)}`);
        continue;
      case 'items':
        if (!isRecord(value)) {
          preflightInvalid(ctx, `schema "items" at ${label} must be a schema object (array-form items are outside the supported canonical subset), got ${describe(value)}`);
          continue;
        }
        preflightNode(value, `${label}/items`, ctx);
        continue;
      case 'uniqueItems':
        if (typeof value !== 'boolean') preflightInvalid(ctx, `schema "uniqueItems" at ${label} must be a boolean`);
        continue;
      case 'pattern':
        if (typeof value !== 'string') {
          preflightInvalid(ctx, `schema "pattern" at ${label} must be a string, got ${describe(value)}`);
          continue;
        }
        try {
          new RegExp(value, 'u');
        } catch {
          preflightInvalid(ctx, `schema "pattern" at ${label} is not a valid regular expression: ${JSON.stringify(value)}`);
        }
        continue;
      case 'minimum':
      case 'maximum':
      case 'exclusiveMinimum':
      case 'exclusiveMaximum':
        if (typeof value !== 'number') preflightInvalid(ctx, `schema ${JSON.stringify(key)} at ${label} must be a number, got ${describe(value)}`);
        continue;
      case 'multipleOf':
        if (typeof value !== 'number' || !(value > 0)) preflightInvalid(ctx, `schema "multipleOf" at ${label} must be a number greater than 0, got ${describe(value)}`);
        continue;
      case 'oneOf':
      case 'anyOf':
      case 'allOf': {
        if (!Array.isArray(value) || value.length === 0) {
          preflightInvalid(ctx, `schema ${JSON.stringify(key)} at ${label} must be a non-empty array of schemas`);
          continue;
        }
        value.forEach((branch, index) => preflightNode(branch, `${label}/${key}/${index}`, ctx));
        continue;
      }
      case 'not':
        preflightNode(value, `${label}/not`, ctx);
        continue;
      default:
        if (NON_NEGATIVE_INTEGER_KEYWORDS.has(key)) {
          if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
            preflightInvalid(ctx, `schema ${JSON.stringify(key)} at ${label} must be a non-negative integer, got ${describe(value)}`);
          }
          continue;
        }
        preflightInvalid(ctx, `unsupported functional schema keyword ${JSON.stringify(key)} at ${label} (the canonical subset is explicit; nothing is silently ignored)`);
    }
  }
  ctx.state.set(node, 1);
}

// The preflight runs FRESH on every public validation call: a
// caller-supplied mutable schema document is a trust boundary, so a PASS is
// never reused across calls by object identity (there is deliberately no
// preflight cache), and the caller's data is never copied, frozen, or
// mutated. Each call observes the document's current content.
function preflightSchemaDocument(schemaDocument: Record<string, unknown>): ValidationResult {
  const issues: ValidationIssue[] = [];
  const ctx: PreflightContext = { root: schemaDocument, issues, state: new Map<object, 0 | 1>() };
  preflightNode(schemaDocument, '#', ctx);
  return issues.length === 0 ? okResult() : failResult(issues);
}

// ---------------------------------------------------------------------------
// Instance evaluation.
// ---------------------------------------------------------------------------

interface EvaluatorContext {
  readonly schemaRoot: Record<string, unknown>;
  readonly issues: ValidationIssue[];
  readonly refStack: readonly string[];
}

function invalidSchema(ctx: EvaluatorContext, message: string): void {
  ctx.issues.push(issue('$schema', 'AIPT_FIXTURE_INVALID_SCHEMA', message));
}

function violation(ctx: EvaluatorContext, path: string, message: string): void {
  ctx.issues.push(issue(path, 'AIPT_FIXTURE_SCHEMA_VIOLATION', message));
}

// Resolve a local JSON pointer ($ref). Only `#/...` pointers exist in the
// canonical schema; external refs, unresolvable refs, and ref cycles fail
// closed with AIPT_FIXTURE_INVALID_SCHEMA. (The grammar preflight already
// rejected every cycle in the whole document; this stack is defense in
// depth for the requested-ref descent.)
function resolveRef(ctx: EvaluatorContext, ref: unknown): unknown {
  if (typeof ref !== 'string' || !ref.startsWith('#/')) {
    invalidSchema(ctx, `only local JSON pointers are supported, got ${describe(ref)}`);
    return {};
  }
  if (ctx.refStack.includes(ref)) {
    invalidSchema(ctx, `circular local $ref chain ${JSON.stringify(ref)}`);
    return {};
  }
  const resolved = resolvePointerNode(ctx.schemaRoot, ref);
  if (resolved === null) {
    invalidSchema(ctx, `unresolvable local $ref ${JSON.stringify(ref)}`);
    return {};
  }
  return resolved;
}

// Propagate invalid-schema issues out of a combinator branch: a malformed or
// unsupported branch is a schema rejection, never an ordinary branch
// mismatch, and is never silently ignored — even inside a passing anyOf/oneOf
// branch or inside `not`.
function propagateInvalidSchema(branchCtx: EvaluatorContext, ctx: EvaluatorContext): void {
  for (const branchIssue of branchCtx.issues) {
    if (branchIssue.code === 'AIPT_FIXTURE_INVALID_SCHEMA') ctx.issues.push(branchIssue);
  }
}

function evalSchema(schema: unknown, value: unknown, path: string, ctx: EvaluatorContext): void {
  if (!isRecord(schema)) {
    invalidSchema(ctx, `schema at ${path} must be a JSON object`);
    return;
  }
  // Deterministic fail-closed keyword gate: every keyword outside the exact
  // supported subset (annotation keywords excepted) is a rejection. The
  // grammar preflight already enforced this over the whole document; this
  // gate is defense in depth for nodes evaluated directly.
  for (const key of Object.keys(schema).sort()) {
    if (!FUNCTIONAL_KEYWORDS.has(key) && !ANNOTATION_KEYWORDS.has(key)) {
      invalidSchema(ctx, `unsupported functional schema keyword ${JSON.stringify(key)} (the canonical subset is explicit; nothing is silently ignored)`);
      return;
    }
  }

  // type
  if (hasOwn(schema, 'type')) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (types.length === 0 || !types.every((entry) => typeof entry === 'string')) {
      invalidSchema(ctx, `schema "type" at ${path} must be a string or a non-empty array of strings`);
    } else if (!types.some((entry) => matchesType(entry as string, value))) {
      violation(ctx, path, `expected type ${JSON.stringify(schema.type)}, got ${describe(value)}`);
    }
  }

  // const / enum (deep equality over JSON semantics). const presence is
  // OWN-MEMBER based, so const null/false/0 all apply.
  if (hasOwn(schema, 'const') && !deepJsonEqual(schema.const, value)) {
    violation(ctx, path, `must equal the schema const ${describe(schema.const)}, got ${describe(value)}`);
  }
  if (hasOwn(schema, 'enum')) {
    if (!Array.isArray(schema.enum)) {
      invalidSchema(ctx, `schema "enum" at ${path} must be an array`);
    } else if (!schema.enum.some((candidate) => deepJsonEqual(candidate, value))) {
      violation(ctx, path, `must equal one of ${schema.enum.length} schema enum values, got ${describe(value)}`);
    }
  }

  // Numeric bounds
  if (typeof value === 'number') {
    if (typeof schema.minimum === 'number' && value < schema.minimum) violation(ctx, path, `must be >= ${schema.minimum}, got ${value}`);
    if (typeof schema.maximum === 'number' && value > schema.maximum) violation(ctx, path, `must be <= ${schema.maximum}, got ${value}`);
    if (typeof schema.exclusiveMinimum === 'number' && value <= schema.exclusiveMinimum) violation(ctx, path, `must be > ${schema.exclusiveMinimum}, got ${value}`);
    if (typeof schema.exclusiveMaximum === 'number' && value >= schema.exclusiveMaximum) violation(ctx, path, `must be < ${schema.exclusiveMaximum}, got ${value}`);
    // Decimal-safe deterministic tolerance, identical to the independent
    // standard-library oracle: q = value / multipleOf; the value is a
    // multiple iff abs(q - round(q)) <= 1e-9. Exact binary division alone
    // would reject 0.3 against multipleOf 0.1.
    if (typeof schema.multipleOf === 'number' && schema.multipleOf > 0) {
      const quotient = value / schema.multipleOf;
      if (Math.abs(quotient - Math.round(quotient)) > MULTIPLE_OF_TOLERANCE) {
        violation(ctx, path, `must be a multiple of ${schema.multipleOf}, got ${value}`);
      }
    }
  }

  // String constraints
  if (typeof value === 'string') {
    const length = [...value].length;
    if (typeof schema.minLength === 'number' && length < schema.minLength) violation(ctx, path, `string length ${length} is below minLength ${schema.minLength}`);
    if (typeof schema.maxLength === 'number' && length > schema.maxLength) violation(ctx, path, `string length ${length} is above maxLength ${schema.maxLength}`);
    if (typeof schema.pattern === 'string') {
      let regex: RegExp;
      try {
        regex = new RegExp(schema.pattern, 'u');
      } catch {
        invalidSchema(ctx, `schema "pattern" at ${path} is not a valid regular expression: ${JSON.stringify(schema.pattern)}`);
        regex = /(?!)/u;
      }
      if (!regex.test(value)) violation(ctx, path, `must match pattern ${JSON.stringify(schema.pattern)}, got ${describe(value)}`);
    }
  }

  // Array constraints
  if (Array.isArray(value)) {
    if (typeof schema.minItems === 'number' && value.length < schema.minItems) violation(ctx, path, `array length ${value.length} is below minItems ${schema.minItems}`);
    if (typeof schema.maxItems === 'number' && value.length > schema.maxItems) violation(ctx, path, `array length ${value.length} is above maxItems ${schema.maxItems}`);
    if (schema.uniqueItems === true) {
      for (let i = 0; i < value.length; i += 1) {
        for (let j = i + 1; j < value.length; j += 1) {
          if (deepJsonEqual(value[i], value[j])) {
            violation(ctx, `${path}/${j}`, `array items ${i} and ${j} are duplicates (uniqueItems = true)`);
          }
        }
      }
    }
    if (hasOwn(schema, 'items')) {
      if (Array.isArray(schema.items)) {
        invalidSchema(ctx, `array-form "items" at ${path} is outside the supported canonical subset (schema-form items only)`);
      } else {
        value.forEach((item, index) => evalSchema(schema.items, item, `${path}/${index}`, ctx));
      }
    }
  }

  // Object constraints
  if (isRecord(value)) {
    if (typeof schema.minProperties === 'number' && Object.keys(value).length < schema.minProperties) {
      violation(ctx, path, `object member count is below minProperties ${schema.minProperties}`);
    }
    if (typeof schema.maxProperties === 'number' && Object.keys(value).length > schema.maxProperties) {
      violation(ctx, path, `object member count is above maxProperties ${schema.maxProperties}`);
    }
    if (isRecord(schema.properties)) {
      for (const [key, subschema] of Object.entries(schema.properties)) {
        if (hasOwn(value, key)) evalSchema(subschema, value[key], `${path}/${key}`, ctx);
      }
    }
    if (hasOwn(schema, 'required')) {
      if (!Array.isArray(schema.required) || !schema.required.every((entry) => typeof entry === 'string')) {
        invalidSchema(ctx, `schema "required" at ${path} must be an array of strings`);
      } else {
        for (const key of schema.required) {
          if (!hasOwn(value, key as string)) violation(ctx, `${path}/${key}`, `missing required member ${JSON.stringify(key)}`);
        }
      }
    }
    const additional = schema.additionalProperties;
    if (additional === false || isRecord(additional)) {
      const declared = isRecord(schema.properties) ? Object.keys(schema.properties) : [];
      for (const key of Object.keys(value)) {
        if (!declared.includes(key)) {
          if (additional === false) {
            violation(ctx, `${path}/${key}`, `member ${JSON.stringify(key)} is not allowed (additionalProperties = false)`);
          } else {
            evalSchema(additional, value[key], `${path}/${key}`, ctx);
          }
        }
      }
    }
  }

  // Combinators (each branch is evaluated with an independent issue sink so
  // branch mismatch failures are invisible to the parent result — but
  // invalid-SCHEMA issues propagate: a malformed or unsupported branch is a
  // schema rejection, never an ordinary branch mismatch, even in a passing
  // anyOf/oneOf branch or inside `not`).
  const branchContext = (): EvaluatorContext => ({ schemaRoot: ctx.schemaRoot, issues: [], refStack: ctx.refStack });
  if (hasOwn(schema, 'allOf')) {
    if (!Array.isArray(schema.allOf)) {
      invalidSchema(ctx, `schema "allOf" at ${path} must be an array`);
    } else {
      for (const branch of schema.allOf) {
        const branchCtx = branchContext();
        evalSchema(branch, value, path, branchCtx);
        propagateInvalidSchema(branchCtx, ctx);
        ctx.issues.push(...branchCtx.issues);
      }
    }
  }
  if (hasOwn(schema, 'anyOf')) {
    if (!Array.isArray(schema.anyOf) || schema.anyOf.length === 0) {
      invalidSchema(ctx, `schema "anyOf" at ${path} must be a non-empty array`);
    } else {
      const passing = schema.anyOf.filter((branch) => {
        const branchCtx = branchContext();
        evalSchema(branch, value, path, branchCtx);
        propagateInvalidSchema(branchCtx, ctx);
        return branchCtx.issues.length === 0;
      }).length;
      if (passing === 0) violation(ctx, path, `anyOf requires at least one valid branch, ${passing} matched`);
    }
  }
  if (hasOwn(schema, 'oneOf')) {
    if (!Array.isArray(schema.oneOf) || schema.oneOf.length === 0) {
      invalidSchema(ctx, `schema "oneOf" at ${path} must be a non-empty array`);
    } else {
      const passing = schema.oneOf.filter((branch) => {
        const branchCtx = branchContext();
        evalSchema(branch, value, path, branchCtx);
        propagateInvalidSchema(branchCtx, ctx);
        return branchCtx.issues.length === 0;
      }).length;
      if (passing !== 1) violation(ctx, path, `oneOf requires exactly one valid branch, ${passing} matched`);
    }
  }
  if (hasOwn(schema, 'not')) {
    const branchCtx = branchContext();
    evalSchema(schema.not, value, path, branchCtx);
    propagateInvalidSchema(branchCtx, ctx);
    if (branchCtx.issues.length === 0) violation(ctx, path, 'the schema "not" branch must fail, but the instance satisfies it');
  }

  // $ref (evaluated with cycle detection on the active ref stack: the ref is
  // resolved against the ANCESTOR stack first, then pushed for the descent).
  if (hasOwn(schema, '$ref')) {
    const resolved = resolveRef(ctx, schema.$ref);
    const nextCtx: EvaluatorContext = { schemaRoot: ctx.schemaRoot, issues: ctx.issues, refStack: [...ctx.refStack, schema.$ref as string] };
    evalSchema(resolved, value, path, nextCtx);
  }
}

// Validate `document` against the canonical subschema targeted by the local
// JSON pointer `ref` (e.g. '#/$defs/state') of the caller-supplied canonical
// schema document. Issue paths are prefixed with `path` so bundle-level
// callers can address every violation under the asset's document path.
//
// Gate order (iterations 4C/4D): the schema document and the instance
// document must both be lossless JSON values (AIPT_LOSSY_JSON_VALUE), then
// the WHOLE schema document must pass the deterministic schema-grammar
// preflight (AIPT_FIXTURE_INVALID_SCHEMA) — including the complete
// local-$ref cycle check — before any instance is evaluated. The preflight
// runs fresh on every call (no cross-call cache), so a caller mutation of
// the same schema object is observed by the next call. This API remains the
// general package-local supported-subset evaluator: only bundle
// compatibility (validateFixtureBundle) additionally requires the exact
// canonical full-content fingerprint.
export function validateSchemaInstance(schemaDocument: unknown, document: unknown, ref: string, path = '$'): ValidationResult {
  if (!isRecord(schemaDocument)) {
    return failResult([issue(path, 'AIPT_FIXTURE_INVALID_SCHEMA', 'the canonical schema document must be a JSON object')]);
  }
  const schemaLossy = validateJsonValue(schemaDocument, '$schema');
  if (!schemaLossy.valid) return failResult([...schemaLossy.issues]);
  const documentLossy = validateJsonValue(document, path);
  if (!documentLossy.valid) return failResult([...documentLossy.issues]);
  const preflight = preflightSchemaDocument(schemaDocument);
  if (!preflight.valid) return preflight;
  const issues: ValidationIssue[] = [];
  const ctx: EvaluatorContext = { schemaRoot: schemaDocument, issues, refStack: [] };
  evalSchema(resolveRef(ctx, ref), document, path, ctx);
  return issues.length === 0 ? okResult() : failResult(issues);
}
