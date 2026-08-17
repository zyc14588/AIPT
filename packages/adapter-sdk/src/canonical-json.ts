// Deterministic canonical JSON and SHA-256 helpers.
//
// Canonical form: object keys sorted recursively, arrays in order, minimal
// separators, no insignificant whitespace. The serializer FAILS CLOSED on
// every value JSON cannot faithfully represent — cycles, undefined,
// functions, symbols, bigint, non-finite numbers, integers outside the
// JavaScript safe-integer range, -0, non-plain objects, accessor properties,
// non-enumerable properties, and symbol-keyed properties — instead of
// silently coercing them. sha256Hex returns the 64-character lowercase
// hexadecimal SHA-256 digest of the canonical serialization.
import { createHash } from 'node:crypto';
import { ProtocolValidationError, issue, type ValidationIssue } from './errors.ts';
import type { JsonValue } from './types.ts';

function isPlainObject(value: object): boolean {
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function ownPropertyProblems(value: object, path: string, issues: ValidationIssue[]): void {
  if (Object.getOwnPropertySymbols(value).length > 0) {
    issues.push(issue(path, 'AIPT_LOSSY_JSON_VALUE', 'symbol-keyed property (JSON cannot represent symbol keys)'));
  }
  for (const key of Object.getOwnPropertyNames(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) continue;
    if (descriptor.get !== undefined || descriptor.set !== undefined) {
      issues.push(issue(`${path}/${key}`, 'AIPT_LOSSY_JSON_VALUE', 'accessor property (getter/setter) cannot be faithfully serialized'));
    }
    if (!descriptor.enumerable) {
      issues.push(issue(`${path}/${key}`, 'AIPT_LOSSY_JSON_VALUE', 'non-enumerable property would be silently dropped'));
    }
  }
}

export function canonicalJson(value: unknown): JsonValue {
  const issues: ValidationIssue[] = [];
  const walk = (current: unknown, path: string, ancestors: ReadonlySet<object>): JsonValue => {
    if (current === null) return null;
    switch (typeof current) {
      case 'boolean':
      case 'string':
        return current;
      case 'undefined':
        issues.push(issue(path, 'AIPT_LOSSY_JSON_VALUE', 'undefined is not a JSON value'));
        return null;
      case 'function':
        issues.push(issue(path, 'AIPT_LOSSY_JSON_VALUE', 'function is not a JSON value'));
        return null;
      case 'symbol':
        issues.push(issue(path, 'AIPT_LOSSY_JSON_VALUE', 'symbol is not a JSON value'));
        return null;
      case 'bigint':
        issues.push(issue(path, 'AIPT_LOSSY_JSON_VALUE', 'bigint is not a JSON value'));
        return null;
      case 'number':
        if (!Number.isFinite(current)) {
          issues.push(issue(path, 'AIPT_LOSSY_JSON_VALUE', 'non-finite number (NaN/Infinity) is not a JSON value'));
        }
        if (Number.isInteger(current) && !Number.isSafeInteger(current)) {
          issues.push(issue(path, 'AIPT_LOSSY_JSON_VALUE', 'integer outside the safe-integer range would round through IEEE-754'));
        }
        if (Object.is(current, -0)) {
          issues.push(issue(path, 'AIPT_LOSSY_JSON_VALUE', '-0 serializes as 0 and would lose its identity'));
        }
        return current;
      case 'object': {
        if (ancestors.has(current)) {
          issues.push(issue(path, 'AIPT_LOSSY_JSON_VALUE', 'cyclic reference cannot be serialized'));
          return null;
        }
        const next = new Set(ancestors);
        next.add(current);
        if (Array.isArray(current)) {
          return current.map((item, index) => walk(item, `${path}/${index}`, next));
        }
        if (!isPlainObject(current)) {
          issues.push(issue(path, 'AIPT_LOSSY_JSON_VALUE', 'non-plain object (foreign prototype) is not a JSON value'));
          return {};
        }
        ownPropertyProblems(current, path, issues);
        const out: Record<string, JsonValue> = {};
        for (const key of Object.keys(current).sort()) {
          out[key] = walk((current as Record<string, unknown>)[key], `${path}/${key}`, next);
        }
        return out;
      }
      default:
        issues.push(issue(path, 'AIPT_LOSSY_JSON_VALUE', `unrepresentable value of type ${typeof current}`));
        return null;
    }
  };
  const result = walk(value, '$', new Set());
  if (issues.length > 0) {
    throw new ProtocolValidationError('value cannot be faithfully represented as JSON', issues);
  }
  return result;
}

export function canonicalJsonString(value: unknown): string {
  const text = JSON.stringify(canonicalJson(value));
  return text as string;
}

export function sha256Hex(value: unknown): string {
  return createHash('sha256').update(canonicalJsonString(value), 'utf8').digest('hex');
}
