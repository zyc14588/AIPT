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

function ownObjectProblems(value: object, path: string, issues: ValidationIssue[]): void {
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

// Validate that `value` is a lossless JSON value. Returns okResult() for
// ordinary JSON and an invalid result (valid=false, AIPT_LOSSY_JSON_VALUE
// issues) for anything JSON cannot faithfully represent. Never mutates the
// input and never returns a partially trusted value.
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
          const length = current.length;
          for (let index = 0; index < length; index += 1) {
            if (!Object.prototype.hasOwnProperty.call(current, index)) {
              issues.push(issue(`${currentPath}/${index}`, 'AIPT_LOSSY_JSON_VALUE', 'sparse-array hole would serialize as null'));
            } else {
              stack.push({ kind: 'value', value: current[index], path: `${currentPath}/${index}` });
            }
          }
          for (const key of Object.keys(current)) {
            if (!ARRAY_INDEX_RE.test(key) || Number(key) >= length) {
              issues.push(issue(`${currentPath}/${key}`, 'AIPT_LOSSY_JSON_VALUE', 'non-index array property would be silently dropped'));
            }
          }
          continue;
        }
        if (!isPlainObject(current)) {
          issues.push(issue(currentPath, 'AIPT_LOSSY_JSON_VALUE', 'non-plain object (foreign prototype) is not a JSON value'));
          continue;
        }
        ownObjectProblems(current, currentPath, issues);
        for (const key of Object.keys(current)) {
          stack.push({ kind: 'value', value: (current as Record<string, unknown>)[key], path: `${currentPath}/${key}` });
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
