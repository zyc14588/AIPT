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

// Build the canonical output form. Only called after the lossless JSON-value
// gate passed, so the walk is safe: no cycles, no accessors, no coercion.
function buildCanonical(value: unknown): JsonValue {
  if (value === null) return null;
  switch (typeof value) {
    case 'boolean':
    case 'string':
    case 'number':
      return value;
    case 'object': {
      if (Array.isArray(value)) {
        return value.map((item) => buildCanonical(item));
      }
      const out: Record<string, JsonValue> = {};
      const record = value as Record<string, unknown>;
      for (const key of Object.keys(record).sort()) {
        out[key] = buildCanonical(record[key]);
      }
      return out;
    }
    default:
      // Unreachable after requireJsonValue; kept for exhaustiveness.
      throw new TypeError(`unrepresentable value of type ${typeof value}`);
  }
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
