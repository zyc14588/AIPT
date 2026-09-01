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
import { SDK_JSON_RESOURCE_LIMITS_V1 as LIMITS } from './resource-limits.ts';
import type { JsonValue } from './types.ts';

function isPlainObject(value: object): boolean {
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

type Frame =
  | { readonly kind: 'value'; readonly value: unknown; readonly path: string; readonly depth: number }
  | { readonly kind: 'exit'; readonly value: object };

type IssueSink = (next: ValidationIssue) => void;

// Mutable aggregate accounting shared by the fixture validator's repeated
// JSON traversals.  It is intentionally not re-exported from the package
// index: ordinary SDK callers keep the stable validateJsonValue API, while
// the fixture boundary can enforce one budget across all of its internal
// validation passes.
export interface JsonAggregateBudget {
  nodes: number;
  bytes: number;
  readonly maxNodes: number;
  readonly maxBytes: number;
  exhausted: boolean;
}

export interface JsonResourceUsage {
  readonly nodes: number;
  readonly bytes: number;
}

export interface BudgetedJsonValidation {
  readonly result: ValidationResult;
  readonly usage: JsonResourceUsage;
}

export function createJsonAggregateBudget(maxNodes: number, maxBytes: number): JsonAggregateBudget {
  return { nodes: 0, bytes: 0, maxNodes, maxBytes, exhausted: false };
}

// Charge work performed by a sibling validator that traverses values already
// measured by validateJsonValueWithBudget.  No caller-controlled text is
// formatted here, and exhaustion is sticky so every later stage fails closed.
export function chargeJsonAggregateBudget(
  budget: JsonAggregateBudget,
  usage: JsonResourceUsage,
  multiplier = 1,
): boolean {
  if (budget.exhausted) return false;
  const nodes = usage.nodes * multiplier;
  const bytes = usage.bytes * multiplier;
  if (!Number.isSafeInteger(nodes) || !Number.isSafeInteger(bytes) || nodes < 0 || bytes < 0) {
    budget.exhausted = true;
    return false;
  }
  budget.nodes += nodes;
  budget.bytes += bytes;
  if (budget.nodes > budget.maxNodes || budget.bytes > budget.maxBytes) {
    budget.exhausted = true;
    return false;
  }
  return true;
}

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
  addIssue: IssueSink,
	maximumEntries: number,
): { readonly entries: Array<{ readonly key: string; readonly value: unknown }>; readonly overflow: boolean } {
  const accepted: Array<{ readonly key: string; readonly value: unknown }> = [];
  const names = Object.getOwnPropertyNames(value);
  if (names.length > maximumEntries || names.length > LIMITS.max_container_width) {
    return { entries: accepted, overflow: true };
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    addIssue(issue(path, 'AIPT_LOSSY_JSON_VALUE', 'symbol-keyed property (JSON cannot represent symbol keys)'));
  }
  for (const key of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined) continue;
    if (descriptor.get !== undefined || descriptor.set !== undefined) {
      addIssue(issue(`${path}/${key}`, 'AIPT_LOSSY_JSON_VALUE', 'accessor property (getter/setter) cannot be faithfully serialized'));
      continue;
    }
    if (!descriptor.enumerable) {
      addIssue(issue(`${path}/${key}`, 'AIPT_LOSSY_JSON_VALUE', 'non-enumerable property would be silently dropped'));
      continue;
    }
    accepted.push({ key, value: descriptor.value });
  }
  return { entries: accepted, overflow: false };
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
  addIssue: IssueSink,
	maximumEntries: number,
): { readonly length: number; readonly entries: Array<{ readonly key: string; readonly value: unknown }>; readonly overflow: boolean } {
  const entries: Array<{ readonly key: string; readonly value: unknown }> = [];
  let length = 0;
  let lengthSeen = false;
  if (Object.getOwnPropertySymbols(value).length > 0) {
    addIssue(issue(path, 'AIPT_LOSSY_JSON_VALUE', 'symbol-keyed property (JSON cannot represent symbol keys)'));
  }
  const names = Object.getOwnPropertyNames(value);
  const ownMembers = names.includes('length') ? names.length - 1 : names.length;
  if (ownMembers > maximumEntries || ownMembers > LIMITS.max_container_width) {
    const lengthDescriptor = names.includes('length') ? Object.getOwnPropertyDescriptor(value, 'length') : undefined;
    const declaredLength = typeof lengthDescriptor?.value === 'number' ? lengthDescriptor.value : 0;
    return { length: declaredLength, entries, overflow: true };
  }
  // First pass: locate the built-in `length` descriptor (property-name order
  // lists integer indices before the string-keyed `length`, so the length
  // must be resolved before any index is range-checked against it).
  const lengthDescriptor = names.includes('length') ? Object.getOwnPropertyDescriptor(value, 'length') : undefined;
  if (lengthDescriptor !== undefined) {
    if (lengthDescriptor.get !== undefined || lengthDescriptor.set !== undefined) {
      addIssue(issue(`${path}/length`, 'AIPT_LOSSY_JSON_VALUE', 'the array length descriptor must be the built-in data descriptor, not an accessor'));
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
      addIssue(issue(`${path}/${key}`, 'AIPT_LOSSY_JSON_VALUE', 'accessor property (getter/setter) cannot be faithfully serialized'));
      continue;
    }
    if (!descriptor.enumerable) {
      addIssue(issue(`${path}/${key}`, 'AIPT_LOSSY_JSON_VALUE', 'non-enumerable property would be silently dropped'));
      continue;
    }
    if (!ARRAY_INDEX_RE.test(key)) {
      addIssue(issue(`${path}/${key}`, 'AIPT_LOSSY_JSON_VALUE', 'non-index array property would be silently dropped'));
      continue;
    }
    const index = Number(key);
    if (index >= length) {
      addIssue(issue(`${path}/${key}`, 'AIPT_LOSSY_JSON_VALUE', `array index ${key} is outside the array length ${length} and would be silently dropped`));
      continue;
    }
    entries.push({ key, value: descriptor.value });
  }
  // The built-in length descriptor is always present on a real array; an
  // exotic hostile array without one is not faithfully serializable.
  if (!lengthSeen) {
    addIssue(issue(`${path}/length`, 'AIPT_LOSSY_JSON_VALUE', 'the array is missing the built-in length descriptor'));
  }
  return { length, entries, overflow: false };
}

// Validate that `value` is a lossless JSON value. Returns okResult() for
// ordinary JSON and an invalid result (valid=false, AIPT_LOSSY_JSON_VALUE
// issues) for anything JSON cannot faithfully represent. Never mutates the
// input, never invokes a getter/setter, and never returns a partially
// trusted value.
export function validateJsonValueWithBudget(
  value: unknown,
  path = '$',
  aggregateBudget?: JsonAggregateBudget,
  maximumIssues = LIMITS.max_issues,
): BudgetedJsonValidation {
  const issues: ValidationIssue[] = [];
  let nodes = 0;
  let aggregateBytes = 0;
  let issueOverflowed = false;
  let resourceExceeded = false;
  const issueLimit = Number.isFinite(maximumIssues)
    ? Math.max(1, Math.min(LIMITS.max_issues, Math.floor(maximumIssues)))
    : LIMITS.max_issues;
  const addIssue: IssueSink = (next) => {
    if (issues.length < issueLimit) {
      issues.push(next);
      return;
    }
    if (!issueOverflowed) {
      issueOverflowed = true;
      issues[issues.length - 1] = issue(path, 'AIPT_JSON_RESOURCE_LIMIT', `validation issue count exceeds ${issueLimit} (${LIMITS.identity})`);
    }
  };
  const resourceFailure = (at: string, message: string): void => {
    if (resourceExceeded) return;
    resourceExceeded = true;
    addIssue(issue(at, 'AIPT_JSON_RESOURCE_LIMIT', `${message} (${LIMITS.identity})`));
  };
  const addBytes = (text: string): boolean => {
    const byteLength = Buffer.byteLength(text, 'utf8');
    aggregateBytes += byteLength;
    if (aggregateBudget !== undefined) {
      aggregateBudget.bytes += byteLength;
      if (aggregateBudget.bytes > aggregateBudget.maxBytes) {
        aggregateBudget.exhausted = true;
        resourceFailure(path, `fixture aggregate JSON bytes exceed ${aggregateBudget.maxBytes}`);
        return false;
      }
    }
    return aggregateBytes <= LIMITS.max_aggregate_bytes;
  };
  const stack: Frame[] = [{ kind: 'value', value, path, depth: 0 }];
  const ancestors = new Set<object>();
  while (stack.length > 0) {
    if (resourceExceeded) break;
    const frame = stack.pop() as Frame;
    if (frame.kind === 'exit') {
      ancestors.delete(frame.value);
      continue;
    }
    const current = frame.value;
    const currentPath = frame.path;
    nodes += 1;
    if (aggregateBudget !== undefined) {
      aggregateBudget.nodes += 1;
      if (aggregateBudget.nodes > aggregateBudget.maxNodes) {
        aggregateBudget.exhausted = true;
        resourceFailure(currentPath, `fixture aggregate JSON node count exceeds ${aggregateBudget.maxNodes}`);
        break;
      }
    }
    if (nodes > LIMITS.max_nodes) {
      resourceFailure(currentPath, `JSON node count exceeds ${LIMITS.max_nodes}`);
      break;
    }
    if (frame.depth > LIMITS.max_depth) {
      resourceFailure(currentPath, `JSON depth ${frame.depth} exceeds ${LIMITS.max_depth}`);
      break;
    }
    if (current === null) {
      if (!addBytes('null')) resourceFailure(currentPath, `aggregate JSON bytes exceed ${LIMITS.max_aggregate_bytes}`);
      continue;
    }
    switch (typeof current) {
      case 'boolean':
        if (!addBytes(current ? 'true' : 'false')) resourceFailure(currentPath, `aggregate JSON bytes exceed ${LIMITS.max_aggregate_bytes}`);
        continue;
      case 'string':
        if (!addBytes(current)) resourceFailure(currentPath, `aggregate JSON bytes exceed ${LIMITS.max_aggregate_bytes}`);
        continue;
      case 'number':
        if (!addBytes(String(current))) resourceFailure(currentPath, `aggregate JSON bytes exceed ${LIMITS.max_aggregate_bytes}`);
        if (!Number.isFinite(current)) {
          addIssue(issue(currentPath, 'AIPT_LOSSY_JSON_VALUE', 'non-finite number (NaN/Infinity) is not a JSON value'));
        }
        if (Number.isInteger(current) && !Number.isSafeInteger(current)) {
          addIssue(issue(currentPath, 'AIPT_LOSSY_JSON_VALUE', 'integer outside the safe-integer range would round through IEEE-754'));
        }
        if (Object.is(current, -0)) {
          addIssue(issue(currentPath, 'AIPT_LOSSY_JSON_VALUE', '-0 serializes as 0 and would lose its identity'));
        }
        continue;
      case 'undefined':
      case 'function':
      case 'symbol':
      case 'bigint':
        addIssue(issue(currentPath, 'AIPT_LOSSY_JSON_VALUE', `${typeof current} is not a JSON value`));
        continue;
      case 'object': {
        if (ancestors.has(current)) {
          addIssue(issue(currentPath, 'AIPT_LOSSY_JSON_VALUE', 'cyclic reference cannot be serialized'));
          continue;
        }
        ancestors.add(current);
        stack.push({ kind: 'exit', value: current });
        if (Array.isArray(current)) {
          const lengthDescriptor = Object.getOwnPropertyDescriptor(current, 'length');
          const declaredLength = typeof lengthDescriptor?.value === 'number' ? lengthDescriptor.value : 0;
          if (declaredLength > LIMITS.max_nodes || nodes + declaredLength > LIMITS.max_nodes) {
            resourceFailure(currentPath, `array length ${declaredLength} exceeds the remaining ${LIMITS.max_nodes}-node budget`);
            continue;
          }
			const scanned = scanArrayOwnDescriptors(current, currentPath, addIssue, LIMITS.max_nodes - nodes);
			if (scanned.overflow) {
				resourceFailure(currentPath, `array width exceeds the remaining ${LIMITS.max_nodes}-node budget`);
				continue;
			}
			const { length, entries } = scanned;
          const present = new Set<number>();
          for (const entry of entries) present.add(Number(entry.key));
          for (let index = 0; index < length; index += 1) {
            if (!present.has(index)) {
              addIssue(issue(`${currentPath}/${index}`, 'AIPT_LOSSY_JSON_VALUE', 'sparse-array hole would serialize as null'));
              break;
            }
          }
          for (const entry of entries) {
            stack.push({ kind: 'value', value: entry.value, path: `${currentPath}/${entry.key}`, depth: frame.depth + 1 });
          }
          continue;
        }
        if (!isPlainObject(current)) {
          addIssue(issue(currentPath, 'AIPT_LOSSY_JSON_VALUE', 'non-plain object (foreign prototype) is not a JSON value'));
          continue;
        }
		const scanned = scanOwnStringDescriptors(current, currentPath, addIssue, LIMITS.max_nodes - nodes);
		if (scanned.overflow) {
			resourceFailure(currentPath, `object width exceeds the remaining ${LIMITS.max_nodes}-node budget`);
			continue;
		}
		const entries = scanned.entries;
        if (nodes + entries.length > LIMITS.max_nodes) {
          resourceFailure(currentPath, `object width exceeds the remaining ${LIMITS.max_nodes}-node budget`);
          continue;
        }
        let keysFit = true;
        for (const entry of entries) {
          if (!addBytes(entry.key)) {
            resourceFailure(currentPath, `aggregate JSON bytes exceed ${LIMITS.max_aggregate_bytes}`);
            keysFit = false;
            break;
          }
        }
        if (!keysFit) continue;
        for (const entry of entries) {
          stack.push({ kind: 'value', value: entry.value, path: `${currentPath}/${entry.key}`, depth: frame.depth + 1 });
        }
        continue;
      }
      default:
        addIssue(issue(currentPath, 'AIPT_LOSSY_JSON_VALUE', `unrepresentable value of type ${typeof current}`));
    }
  }
  return {
    result: issues.length === 0 ? okResult() : failResult(issues),
    usage: { nodes, bytes: aggregateBytes },
  };
}

export function validateJsonValue(value: unknown, path = '$'): ValidationResult {
  return validateJsonValueWithBudget(value, path).result;
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
