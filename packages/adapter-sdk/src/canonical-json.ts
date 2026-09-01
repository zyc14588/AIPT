// Deterministic canonical JSON and SHA-256 helpers.
//
// Canonical form: object keys sorted recursively, arrays in order, minimal
// separators, no insignificant whitespace. The serializer FAILS CLOSED on
// every value JSON cannot faithfully represent — cycles, undefined,
// functions, symbols, bigint, non-finite numbers, integers outside the
// JavaScript safe-integer range, -0, non-plain objects, accessor properties,
// non-enumerable properties, symbol-keyed properties, sparse-array holes,
// and non-index array properties — instead of silently coercing them.
// sha256Hex returns the 64-character lowercase hexadecimal SHA-256 digest
// of the canonical serialization.
import { createHash } from 'node:crypto';
import { requireJsonValue } from './json-value.ts';
import type { JsonValue } from './types.ts';

type JsonContainer = JsonValue[] | Record<string, JsonValue>;

interface CloneFrame {
  readonly source: unknown[] | Record<string, unknown>;
  readonly target: JsonContainer;
}

function isContainer(value: unknown): value is unknown[] | Record<string, unknown> {
  return value !== null && typeof value === 'object';
}

function makeContainer(value: unknown[] | Record<string, unknown>): JsonContainer {
  return Array.isArray(value) ? new Array<JsonValue>(value.length) : {};
}

// CreateDataProperty semantics are essential here.  In particular, assigning
// `target['__proto__'] = value` on an ordinary object would invoke the legacy
// inherited setter and silently drop a legal JSON member.  defineProperty
// preserves the normal Object prototype of this public return value while
// creating every untrusted key as an ordinary own data property.
function defineJsonMember(target: JsonContainer, key: string, value: JsonValue): void {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
}

// Iterative canonical clone.  validateJsonValue has already proved that all
// descriptors are enumerable data properties, that there are no cycles, and
// that the versioned resource budget is satisfied.
function buildCanonical(value: JsonValue): JsonValue {
  if (!isContainer(value)) return value;
  const root = makeContainer(value);
  const stack: CloneFrame[] = [{ source: value, target: root }];
  while (stack.length > 0) {
    const { source, target } = stack.pop() as CloneFrame;
    const keys = Array.isArray(source)
      ? Array.from({ length: source.length }, (_, index) => String(index))
      : Object.keys(source).sort();
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(source, key);
      if (descriptor === undefined || !('value' in descriptor)) {
        throw new TypeError('validated JSON data property disappeared during canonicalization');
      }
      const child = descriptor.value as JsonValue;
      if (isContainer(child)) {
        const childTarget = makeContainer(child);
        defineJsonMember(target, key, childTarget);
        stack.push({ source: child, target: childTarget });
      } else {
        defineJsonMember(target, key, child);
      }
    }
  }
  return root;
}

export function canonicalJson(value: unknown): JsonValue {
  return buildCanonical(requireJsonValue(value, '$'));
}

export function canonicalJsonString(value: unknown): string {
  const text = JSON.stringify(canonicalJson(value));
  return text as string;
}

export function sha256Hex(value: unknown): string {
  return createHash('sha256').update(canonicalJsonString(value), 'utf8').digest('hex');
}
