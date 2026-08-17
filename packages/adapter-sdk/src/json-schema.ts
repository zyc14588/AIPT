// Package-local, dependency-free evaluator for the exact supported canonical
// JSON Schema 2020-12 subset (B002, iteration 4B).
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
// `allOf`, `not` — and ignores only the annotation keywords `title`,
// `description`, `examples`, `default`, `deprecated`, `$comment`, `$schema`,
// `$id`, `$defs`. Any OTHER keyword, an unresolvable local `$ref`, a
// circular `$ref` chain, or a malformed schema node fails closed with
// AIPT_FIXTURE_INVALID_SCHEMA; instance violations are reported
// path-addressed with AIPT_FIXTURE_SCHEMA_VIOLATION. Nothing is silently
// ignored: an unsupported functional keyword is a rejection, never a pass.
import { failResult, issue, okResult, type ValidationIssue, type ValidationResult } from './errors.ts';

const ANNOTATION_KEYWORDS = new Set(['title', 'description', 'examples', 'default', 'deprecated', '$comment', '$schema', '$id', '$defs']);
const FUNCTIONAL_KEYWORDS = new Set([
  '$ref', 'type', 'const', 'enum', 'properties', 'required', 'additionalProperties', 'items',
  'minItems', 'maxItems', 'uniqueItems', 'minLength', 'maxLength', 'pattern',
  'minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf',
  'minProperties', 'maxProperties', 'oneOf', 'anyOf', 'allOf', 'not',
]);

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
// closed with AIPT_FIXTURE_INVALID_SCHEMA.
function resolveRef(ctx: EvaluatorContext, ref: unknown): unknown {
  if (typeof ref !== 'string' || !ref.startsWith('#/')) {
    invalidSchema(ctx, `only local JSON pointers are supported, got ${describe(ref)}`);
    return {};
  }
  if (ctx.refStack.includes(ref)) {
    invalidSchema(ctx, `circular local $ref chain ${JSON.stringify(ref)}`);
    return {};
  }
  const segments = ref
    .slice(2)
    .split('/')
    .map((segment) => segment.replace(/~1/gu, '/').replace(/~0/gu, '~'));
  let node: unknown = ctx.schemaRoot;
  for (const segment of segments) {
    if (isRecord(node) && hasOwn(node, segment)) {
      node = node[segment];
    } else {
      invalidSchema(ctx, `unresolvable local $ref ${JSON.stringify(ref)}`);
      return {};
    }
  }
  return node;
}

function evalSchema(schema: unknown, value: unknown, path: string, ctx: EvaluatorContext): void {
  if (!isRecord(schema)) {
    invalidSchema(ctx, `schema at ${path} must be a JSON object`);
    return;
  }
  // Deterministic fail-closed keyword gate: every keyword outside the exact
  // supported subset (annotation keywords excepted) is a rejection.
  for (const key of Object.keys(schema).sort()) {
    if (!FUNCTIONAL_KEYWORDS.has(key) && !ANNOTATION_KEYWORDS.has(key)) {
      invalidSchema(ctx, `unsupported functional schema keyword ${JSON.stringify(key)} (the canonical subset is explicit; nothing is silently ignored)`);
      return;
    }
  }

  // type
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (types.length === 0 || !types.every((entry) => typeof entry === 'string')) {
      invalidSchema(ctx, `schema "type" at ${path} must be a string or a non-empty array of strings`);
    } else if (!types.some((entry) => matchesType(entry as string, value))) {
      violation(ctx, path, `expected type ${JSON.stringify(schema.type)}, got ${describe(value)}`);
    }
  }

  // const / enum (deep equality over JSON semantics)
  if (schema.const !== undefined && !deepJsonEqual(schema.const, value)) {
    violation(ctx, path, `must equal the schema const ${describe(schema.const)}, got ${describe(value)}`);
  }
  if (schema.enum !== undefined) {
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
    if (typeof schema.multipleOf === 'number' && schema.multipleOf > 0 && value / schema.multipleOf !== Math.floor(value / schema.multipleOf)) {
      violation(ctx, path, `must be a multiple of ${schema.multipleOf}, got ${value}`);
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
    if (schema.items !== undefined) {
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
    if (schema.required !== undefined) {
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
  // branch failures are invisible to the parent result).
  const branchContext = (): EvaluatorContext => ({ schemaRoot: ctx.schemaRoot, issues: [], refStack: ctx.refStack });
  if (schema.allOf !== undefined) {
    if (!Array.isArray(schema.allOf)) {
      invalidSchema(ctx, `schema "allOf" at ${path} must be an array`);
    } else {
      for (const branch of schema.allOf) {
        const branchCtx = branchContext();
        evalSchema(branch, value, path, branchCtx);
        ctx.issues.push(...branchCtx.issues);
      }
    }
  }
  if (schema.anyOf !== undefined) {
    if (!Array.isArray(schema.anyOf) || schema.anyOf.length === 0) {
      invalidSchema(ctx, `schema "anyOf" at ${path} must be a non-empty array`);
    } else {
      const passing = schema.anyOf.filter((branch) => {
        const branchCtx = branchContext();
        evalSchema(branch, value, path, branchCtx);
        return branchCtx.issues.length === 0;
      }).length;
      if (passing === 0) violation(ctx, path, `anyOf requires at least one valid branch, ${passing} matched`);
    }
  }
  if (schema.oneOf !== undefined) {
    if (!Array.isArray(schema.oneOf) || schema.oneOf.length === 0) {
      invalidSchema(ctx, `schema "oneOf" at ${path} must be a non-empty array`);
    } else {
      const passing = schema.oneOf.filter((branch) => {
        const branchCtx = branchContext();
        evalSchema(branch, value, path, branchCtx);
        return branchCtx.issues.length === 0;
      }).length;
      if (passing !== 1) violation(ctx, path, `oneOf requires exactly one valid branch, ${passing} matched`);
    }
  }
  if (schema.not !== undefined) {
    const branchCtx = branchContext();
    evalSchema(schema.not, value, path, branchCtx);
    if (branchCtx.issues.length === 0) violation(ctx, path, 'the schema "not" branch must fail, but the instance satisfies it');
  }

  // $ref (evaluated with cycle detection on the active ref stack: the ref is
  // resolved against the ANCESTOR stack first, then pushed for the descent).
  if (schema.$ref !== undefined) {
    const resolved = resolveRef(ctx, schema.$ref);
    const nextCtx: EvaluatorContext = { schemaRoot: ctx.schemaRoot, issues: ctx.issues, refStack: [...ctx.refStack, schema.$ref as string] };
    evalSchema(resolved, value, path, nextCtx);
  }
}

// Validate `document` against the canonical subschema targeted by the local
// JSON pointer `ref` (e.g. '#/$defs/state') of the caller-supplied canonical
// schema document. Issue paths are prefixed with `path` so bundle-level
// callers can address every violation under the asset's document path.
export function validateSchemaInstance(schemaDocument: unknown, document: unknown, ref: string, path = '$'): ValidationResult {
  const issues: ValidationIssue[] = [];
  if (!isRecord(schemaDocument)) {
    issues.push(issue(path, 'AIPT_FIXTURE_INVALID_SCHEMA', 'the canonical schema document must be a JSON object'));
    return failResult(issues);
  }
  const ctx: EvaluatorContext = { schemaRoot: schemaDocument, issues, refStack: [] };
  evalSchema(resolveRef(ctx, ref), document, path, ctx);
  return issues.length === 0 ? okResult() : failResult(issues);
}
