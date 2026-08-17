// Pure, path-preserving lossless JSON-value validation.
//
// A value is trusted as JSON only when it round-trips through JSON
// serialization with no silent coercion and no information loss. This
// module is the single gate used at every trust boundary where the
// canonical schema intentionally accepts ANY JSON value (`state_field.value`,
// `action_intent_params.proposal`, any nested JSON value) and by the generic
// parser before a parsed document is returned as JsonValue.
//
// Rejected (AIPT_LOSSY_JSON_VALUE, path-addressed): cyclic references,
// undefined/function/symbol/bigint values, non-finite numbers, integers
// outside the JavaScript safe-integer range, -0, non-plain objects,
// accessor properties, non-enumerable properties, symbol-keyed properties,
// sparse-array holes, and non-index array properties. The walker is
// iterative, never mutates its input, and treats repeated (non-ancestral)
// shared references as ordinary values.
//
// Iteration 4C contract: the walker inspects OWN PROPERTY DESCRIPTORS ONLY
// and never reads a rejected property. No getter or setter is ever invoked
// while validating — not even once after a rejection is detected. Arrays
// are held to the same own-descriptor discipline: only the built-in `length`
// descriptor is exempt (and only as a data descriptor); symbol keys,
// accessor indices, non-enumerable/non-index own properties, sparse holes,
// and invalid index descriptors all fail closed.
import { failResult, issue, okResult, ProtocolValidationError, type ValidationIssue, type ValidationResult } from './errors.ts';
import type { JsonValue } from './types.ts';

function isPlainObject(value: object): boolean {
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

type Frame =
  | { readonly kind: 'value'; readonly value: unknown; readonly path: string }
  | { readonly kind: 'exit'; readonly value: object };

const ARRAY_INDEX_RE = /^(0|[1-9][0-9]*)$/u;

// Scan the OWN string-keyed property descriptors of a plain object WITHOUT
// reading any rejected property. Accessor and non-enumerable properties are
// reported from their descriptor alone; accepted enumerable data properties
// are returned so the caller can descend into descriptor.value — reading a
// DATA descriptor's value never invokes an accessor. Symbol-keyed properties
// are rejected up front (JSON cannot represent symbol keys).
function scanOwnStringDescriptors(
  value: object,
  path: string,
  issues: ValidationIssue[],
): Array<{ readonly key: string; readonly value: unknown }> {
  const accepted: Array<{ readonly key: string; readonly value: unknown }> = [];
  if (Object.getOwnPropertySymbols(value).length > 0) {
    issues.push(issue(path, 'AIPT_LOSSY_JSON_VALUE', 'symbol-keyed property (JSON cannot represent symbol keys)'));
  }
  for (const key of Object.getOwnPropertyNames(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) continue;
    if (descriptor.get !== undefined || descriptor.set !== undefined) {
      issues.push(issue(`${path}/${key}`, 'AIPT_LOSSY_JSON_VALUE', 'accessor property (getter/setter) cannot be faithfully serialized'));
      continue;
    }
    if (!descriptor.enumerable) {
      issues.push(issue(`${path}/${key}`, 'AIPT_LOSSY_JSON_VALUE', 'non-enumerable property would be silently dropped'));
      continue;
    }
    accepted.push({ key, value: descriptor.value });
  }
  return accepted;
}

// Scan the OWN property descriptors of an ARRAY. Only the built-in `length`
// descriptor is exempt from the enumerable/index rules, and only when it is
// an ordinary data descriptor (an accessor length fails closed). Every other
// own property must be an enumerable data property whose key is a canonical
// array index below `length`. Returns the accepted index entries plus the
// array length; rejected properties are reported without being read.
function scanArrayOwnDescriptors(
  value: unknown[],
  path: string,
  issues: ValidationIssue[],
): { readonly length: number; readonly entries: Array<{ readonly key: string; readonly value: unknown }> } {
  const entries: Array<{ readonly key: string; readonly value: unknown }> = [];
  let length = 0;
  let lengthSeen = false;
  if (Object.getOwnPropertySymbols(value).length > 0) {
    issues.push(issue(path, 'AIPT_LOSSY_JSON_VALUE', 'symbol-keyed property (JSON cannot represent symbol keys)'));
  }
  const names = Object.getOwnPropertyNames(value);
  // First pass: locate the built-in `length` descriptor (property-name order
  // lists integer indices before the string-keyed `length`, so the length
  // must be resolved before any index is range-checked against it).
  const lengthDescriptor = names.includes('length') ? Object.getOwnPropertyDescriptor(value, 'length') : undefined;
  if (lengthDescriptor !== undefined) {
    if (lengthDescriptor.get !== undefined || lengthDescriptor.set !== undefined) {
      issues.push(issue(`${path}/length`, 'AIPT_LOSSY_JSON_VALUE', 'the array length descriptor must be the built-in data descriptor, not an accessor'));
    } else {
      lengthSeen = true;
      length = Number(lengthDescriptor.value);
    }
  }
  for (const key of names) {
    if (key === 'length') continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) continue;
    if (descriptor.get !== undefined || descriptor.set !== undefined) {
      issues.push(issue(`${path}/${key}`, 'AIPT_LOSSY_JSON_VALUE', 'accessor property (getter/setter) cannot be faithfully serialized'));
      continue;
    }
    if (!descriptor.enumerable) {
      issues.push(issue(`${path}/${key}`, 'AIPT_LOSSY_JSON_VALUE', 'non-enumerable property would be silently dropped'));
      continue;
    }
    if (!ARRAY_INDEX_RE.test(key)) {
      issues.push(issue(`${path}/${key}`, 'AIPT_LOSSY_JSON_VALUE', 'non-index array property would be silently dropped'));
      continue;
    }
    const index = Number(key);
    if (index >= length) {
      issues.push(issue(`${path}/${key}`, 'AIPT_LOSSY_JSON_VALUE', `array index ${key} is outside the array length ${length} and would be silently dropped`));
      continue;
    }
    entries.push({ key, value: descriptor.value });
  }
  // The built-in length descriptor is always present on a real array; an
  // exotic hostile array without one is not faithfully serializable.
  if (!lengthSeen) {
    issues.push(issue(`${path}/length`, 'AIPT_LOSSY_JSON_VALUE', 'the array is missing the built-in length descriptor'));
  }
  return { length, entries };
}

// Validate that `value` is a lossless JSON value. Returns okResult() for
// ordinary JSON and an invalid result (valid=false, AIPT_LOSSY_JSON_VALUE
// issues) for anything JSON cannot faithfully represent. Never mutates the
// input, never invokes a getter/setter, and never returns a partially
// trusted value.
export function validateJsonValue(value: unknown, path = '$'): ValidationResult {
  const issues: ValidationIssue[] = [];
  const stack: Frame[] = [{ kind: 'value', value, path }];
  const ancestors = new Set<object>();
  while (stack.length > 0) {
    const frame = stack.pop() as Frame;
    if (frame.kind === 'exit') {
      ancestors.delete(frame.value);
      continue;
    }
    const current = frame.value;
    const currentPath = frame.path;
    if (current === null) continue;
    switch (typeof current) {
      case 'boolean':
      case 'string':
        continue;
      case 'number':
        if (!Number.isFinite(current)) {
          issues.push(issue(currentPath, 'AIPT_LOSSY_JSON_VALUE', 'non-finite number (NaN/Infinity) is not a JSON value'));
        }
        if (Number.isInteger(current) && !Number.isSafeInteger(current)) {
          issues.push(issue(currentPath, 'AIPT_LOSSY_JSON_VALUE', 'integer outside the safe-integer range would round through IEEE-754'));
        }
        if (Object.is(current, -0)) {
          issues.push(issue(currentPath, 'AIPT_LOSSY_JSON_VALUE', '-0 serializes as 0 and would lose its identity'));
        }
        continue;
      case 'undefined':
      case 'function':
      case 'symbol':
      case 'bigint':
        issues.push(issue(currentPath, 'AIPT_LOSSY_JSON_VALUE', `${typeof current} is not a JSON value`));
        continue;
      case 'object': {
        if (ancestors.has(current)) {
          issues.push(issue(currentPath, 'AIPT_LOSSY_JSON_VALUE', 'cyclic reference cannot be serialized'));
          continue;
        }
        ancestors.add(current);
        stack.push({ kind: 'exit', value: current });
        if (Array.isArray(current)) {
          const { length, entries } = scanArrayOwnDescriptors(current, currentPath, issues);
          const present = new Set<number>();
          for (const entry of entries) present.add(Number(entry.key));
          for (let index = 0; index < length; index += 1) {
            if (!present.has(index)) {
              issues.push(issue(`${currentPath}/${index}`, 'AIPT_LOSSY_JSON_VALUE', 'sparse-array hole would serialize as null'));
              break;
            }
          }
          for (const entry of entries) {
            stack.push({ kind: 'value', value: entry.value, path: `${currentPath}/${entry.key}` });
          }
          continue;
        }
        if (!isPlainObject(current)) {
          issues.push(issue(currentPath, 'AIPT_LOSSY_JSON_VALUE', 'non-plain object (foreign prototype) is not a JSON value'));
          continue;
        }
        for (const entry of scanOwnStringDescriptors(current, currentPath, issues)) {
          stack.push({ kind: 'value', value: entry.value, path: `${currentPath}/${entry.key}` });
        }
        continue;
      }
      default:
        issues.push(issue(currentPath, 'AIPT_LOSSY_JSON_VALUE', `unrepresentable value of type ${typeof current}`));
    }
  }
  return issues.length === 0 ? okResult() : failResult(issues);
}

// Throwing form of the lossless JSON-value gate, used by the
// parse/decode/to/build/encode helpers: a failed gate throws
// ProtocolValidationError carrying every path-addressed issue.
export function requireJsonValue(value: unknown, path = '$'): JsonValue {
  const check = validateJsonValue(value, path);
  if (!check.valid) {
    throw new ProtocolValidationError('value is not a lossless JSON value', check.issues);
  }
  return value as JsonValue;
}
