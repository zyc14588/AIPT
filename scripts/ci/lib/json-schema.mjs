// Dependency-free JSON Schema 2020-12 SUBSET validator/helper for the AIPT
// B002 protocol-assets gate. Node.js standard library only.
//
// Contract (B002_IMPLEMENTATION_CHOICE — explicitly supported subset):
//   - Only the keywords listed in SUPPORTED_VALIDATION_KEYWORDS are enforced.
//     Any other FUNCTIONAL keyword (format, if/then/else, dependentSchemas,
//     unevaluatedProperties, prefixItems, contains, $dynamicRef, $anchor,
//     $vocabulary, ...) is REJECTED with an error — never silently ignored.
//   - Annotation keywords (title/description/examples/default/deprecated/
//     $comment) are permitted and are not validated against.
//   - $ref resolves LOCAL root refs only: "#" and "#/..." JSON pointers into
//     the same schema document. Remote/external refs (http, file, relative)
//     are rejected. Invalid refs are errors, and cyclic $ref chains are
//     detected and rejected (defense-in-depth).
//   - $defs is supported at the schema root only; $id/$schema at the root
//     only. Boolean schemas (true/false) are supported.
//   - Every failure carries { path, keyword, message } so callers can assert
//     the REJECTION REASON, not merely that validation failed.
//
// The canonical schema (schemas/protocol/v1/aipt-protocol.schema.json) is
// written against exactly this subset; checkSchemaDocument proves it uses no
// unsupported keyword, and validateInstance proves fixture conformance.
export const META_SCHEMA_URI = 'https://json-schema.org/draft/2020-12/schema';

export const SUPPORTED_VALIDATION_KEYWORDS = new Set([
  '$ref',
  'type',
  'const',
  'enum',
  'properties',
  'required',
  'additionalProperties',
  'items',
  'minItems',
  'maxItems',
  'uniqueItems',
  'minLength',
  'maxLength',
  'pattern',
  'minimum',
  'maximum',
  'exclusiveMinimum',
  'exclusiveMaximum',
  'multipleOf',
  'minProperties',
  'maxProperties',
  'oneOf',
  'anyOf',
  'allOf',
  'not',
]);

// Non-validation keywords the subset permits (2020-12 annotations).
export const ANNOTATION_KEYWORDS = new Set([
  'title',
  'description',
  'examples',
  'default',
  'deprecated',
  '$comment',
]);

export const STRUCTURAL_KEYWORDS = new Set(['$schema', '$id', '$defs']);

const JSON_TYPES = new Set(['null', 'boolean', 'object', 'array', 'number', 'integer', 'string']);

const MAX_ERRORS = 50;
const MAX_REF_DEPTH = 64;

export function isSchemaNode(node) {
  return typeof node === 'boolean' || (node !== null && typeof node === 'object' && !Array.isArray(node));
}

// Deep value equality (JSON Schema value semantics: object key order does
// not matter).
export function deepEqual(a, b) {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return false;
    return a.length === b.length && a.every((x, i) => deepEqual(x, b[i]));
  }
  if (typeof a === 'object') {
    const ka = Object.keys(a);
    const kb = Object.keys(b);
    if (ka.length !== kb.length) return false;
    return ka.every((k) => Object.prototype.hasOwnProperty.call(b, k) && deepEqual(a[k], b[k]));
  }
  return false;
}

// Resolve a LOCAL $ref ("#", "#/...") inside the schema document. Returns
// the resolved node, or null when the ref is not a local pointer or does not
// resolve. External refs (anything not starting with "#") are always null.
export function resolveRef(schemaDoc, ref) {
  if (typeof ref !== 'string') return null;
  if (ref === '#') return schemaDoc;
  if (!ref.startsWith('#/')) return null;
  const parts = ref
    .slice(2)
    .split('/')
    .map((seg) => seg.replace(/~1/g, '/').replace(/~0/g, '~'));
  let node = schemaDoc;
  for (const part of parts) {
    if (node === null || typeof node !== 'object' || Array.isArray(node)) return null;
    if (!Object.prototype.hasOwnProperty.call(node, part)) return null;
    node = node[part];
  }
  return node;
}

function schemaError(errors, path, keyword, message) {
  if (errors.length < MAX_ERRORS) {
    errors.push({ path, keyword, message: `${path}: ${message}` });
  }
}

function checkShape(errors, node, isRoot) {
  if (typeof node === 'boolean') return;
  if (!isSchemaNode(node)) {
    errors.push('schema nodes must be objects or booleans');
    return;
  }
  for (const key of Object.keys(node)) {
    if (SUPPORTED_VALIDATION_KEYWORDS.has(key)) {
      checkKeywordShape(errors, key, node[key]);
      continue;
    }
    if (ANNOTATION_KEYWORDS.has(key)) continue;
    if (key === '$schema') {
      if (!isRoot) errors.push('$schema is only allowed at the schema root');
      else if (node[key] !== META_SCHEMA_URI) errors.push(`$schema must be exactly ${META_SCHEMA_URI}, got ${JSON.stringify(node[key])}`);
      continue;
    }
    if (key === '$id') {
      if (!isRoot) errors.push('$id is only allowed at the schema root in this subset');
      continue;
    }
    if (key === '$defs') {
      if (!isRoot) errors.push('$defs is only allowed at the schema root in this subset');
      else if (node[key] === null || typeof node[key] !== 'object' || Array.isArray(node[key])) {
        errors.push('$defs must be an object');
      } else {
        for (const [name, def] of Object.entries(node[key])) {
          checkShape(errors, def, false);
        }
      }
      continue;
    }
    // Any other keyword is unsupported FUNCTIONAL territory: fail closed.
    errors.push(`unsupported functional schema keyword ${JSON.stringify(key)} (not in the explicit B002 subset — rejected, never ignored)`);
  }
}

function checkKeywordShape(errors, keyword, value) {
  switch (keyword) {
    case '$ref':
      if (typeof value !== 'string' || !value.startsWith('#/')) {
        errors.push('$ref must be a local "#/..." pointer in this subset (remote/external refs are rejected)');
      }
      break;
    case 'type': {
      const list = Array.isArray(value) ? value : [value];
      if (list.length === 0 || !list.every((t) => JSON_TYPES.has(t))) {
        errors.push(`type must be one of ${[...JSON_TYPES].join(' | ')} (or an array of them)`);
      }
      break;
    }
    case 'enum':
      if (!Array.isArray(value) || value.length === 0) errors.push('enum must be a non-empty array');
      break;
    case 'const':
      // Any JSON value is a valid const target; nothing to shape-check.
      break;
    case 'properties':
      if (value === null || typeof value !== 'object' || Array.isArray(value)) errors.push('properties must be an object');
      else {
        for (const sub of Object.values(value)) {
          if (!isSchemaNode(sub)) errors.push('every properties entry must be a schema');
          else checkShape(errors, sub, false);
        }
      }
      break;
    case 'required':
      if (!Array.isArray(value) || !value.every((v) => typeof v === 'string') || new Set(value).size !== value.length) {
        errors.push('required must be an array of unique strings');
      }
      break;
    case 'additionalProperties':
      if (typeof value === 'boolean') break;
      if (isSchemaNode(value)) checkShape(errors, value, false);
      else errors.push('additionalProperties must be a boolean or a schema');
      break;
    case 'items':
      if (typeof value === 'boolean') break;
      if (Array.isArray(value)) errors.push('items must be a single schema in this subset (tuple form unsupported)');
      else if (isSchemaNode(value)) checkShape(errors, value, false);
      else errors.push('items must be a schema or boolean');
      break;
    case 'minItems':
    case 'maxItems':
    case 'minLength':
    case 'maxLength':
    case 'minProperties':
    case 'maxProperties':
      if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) errors.push(`${keyword} must be a non-negative integer`);
      break;
    case 'uniqueItems':
      if (typeof value !== 'boolean') errors.push('uniqueItems must be a boolean');
      break;
    case 'pattern':
      if (typeof value !== 'string') errors.push('pattern must be a string');
      else {
        try {
          new RegExp(value, 'u');
        } catch (err) {
          errors.push(`pattern does not compile: ${err.message}`);
        }
      }
      break;
    case 'minimum':
    case 'maximum':
    case 'exclusiveMinimum':
    case 'exclusiveMaximum':
      if (typeof value !== 'number') errors.push(`${keyword} must be a number`);
      break;
    case 'multipleOf':
      if (typeof value !== 'number' || !(value > 0)) errors.push('multipleOf must be a positive number');
      break;
    case 'oneOf':
    case 'anyOf':
    case 'allOf':
      if (!Array.isArray(value) || value.length === 0 || !value.every(isSchemaNode)) {
        errors.push(`${keyword} must be a non-empty array of schemas`);
      } else {
        for (const sub of value) checkShape(errors, sub, false);
      }
      break;
    case 'not':
      if (!isSchemaNode(value)) errors.push('not must be a schema');
      else checkShape(errors, value, false);
      break;
    default:
      errors.push(`keyword ${keyword} has no shape check (subset bookkeeping defect)`);
  }
}

// Ref-graph cycle detection over the schema document (defense-in-depth).
function detectRefCycles(schemaDoc, errors) {
  const edges = new Map(); // ref-holder node -> list of resolved target nodes
  // Traverse every nested plain object (schema nodes and keyword payloads
  // alike — harmless for non-schema payloads); only $ref keys create edges.
  const collect = (node) => {
    if (node === null || typeof node !== 'object' || Array.isArray(node)) return;
    for (const key of Object.keys(node)) {
      const value = node[key];
      if (key === '$ref') {
        const target = resolveRef(schemaDoc, value);
        if (target === null) {
          errors.push(`$ref ${JSON.stringify(value)} does not resolve locally`);
        } else {
          if (!edges.has(node)) edges.set(node, []);
          edges.get(node).push(target);
        }
      } else {
        collect(value);
      }
    }
  };
  collect(schemaDoc);
  const state = new Map(); // 0=visiting, 1=done
  const visit = (node) => {
    if (!edges.has(node)) return;
    if (state.get(node) === 1) return;
    if (state.get(node) === 0) {
      errors.push('$ref cycle detected in the schema document (cyclic refs are rejected in this subset)');
      return;
    }
    state.set(node, 0);
    for (const target of edges.get(node)) visit(target);
    state.set(node, 1);
  };
  for (const node of edges.keys()) visit(node);
}

// Meta-check a schema DOCUMENT: supported-keyword conformance, keyword shape,
// local-ref resolvability, and ref-cycle defense. Returns { valid, errors }.
export function checkSchemaDocument(doc) {
  const errors = [];
  if (!isSchemaNode(doc) || typeof doc === 'boolean') {
    errors.push('the schema document root must be an object');
    return { valid: false, errors };
  }
  if (doc.$schema !== META_SCHEMA_URI) {
    errors.push(`root $schema must be exactly ${META_SCHEMA_URI} (JSON Schema 2020-12), got ${JSON.stringify(doc.$schema)}`);
  }
  if (doc.$id !== undefined && typeof doc.$id !== 'string') {
    errors.push('root $id must be a string');
  }
  checkShape(errors, doc, true);
  detectRefCycles(doc, errors);
  return { valid: errors.length === 0, errors };
}

function valueTypeOf(instance) {
  if (instance === null) return 'null';
  if (Array.isArray(instance)) return 'array';
  if (typeof instance === 'number') return Number.isInteger(instance) ? 'integer' : 'number';
  return typeof instance;
}

function typeMatches(instance, types) {
  const got = valueTypeOf(instance);
  for (const t of types) {
    if (t === 'number') {
      if (got === 'number' || got === 'integer') return true;
    } else if (t === got) {
      return true;
    }
  }
  return false;
}

function evaluate(schemaDoc, schema, instance, path, stack, errors) {
  if (typeof schema === 'boolean') {
    if (!schema) schemaError(errors, path, 'false-schema', 'value rejected by a false schema');
    return;
  }
  if (!isSchemaNode(schema)) {
    schemaError(errors, path, 'schema', 'internal defect: schema node is not an object or boolean');
    return;
  }
  if (stack.length > MAX_REF_DEPTH) {
    schemaError(errors, path, '$ref', 'maximum $ref resolution depth exceeded');
    return;
  }

  // $ref: local resolution with cycle defense. Sibling validation keywords
  // continue to apply (2020-12 semantics).
  if (typeof schema.$ref === 'string') {
    if (!schema.$ref.startsWith('#/')) {
      schemaError(errors, path, '$ref', `external/remote $ref ${JSON.stringify(schema.$ref)} is not supported by this subset`);
      return;
    }
    const target = resolveRef(schemaDoc, schema.$ref);
    if (target === null) {
      schemaError(errors, path, '$ref', `$ref ${JSON.stringify(schema.$ref)} does not resolve inside the schema document`);
      return;
    }
    if (stack.includes(target)) {
      schemaError(errors, path, '$ref', `$ref cycle detected at ${schema.$ref}`);
      return;
    }
    evaluate(schemaDoc, target, instance, path, [...stack, target], errors);
  }

  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!typeMatches(instance, types)) {
      schemaError(errors, path, 'type', `expected type ${types.join('|')}, got ${valueTypeOf(instance)}`);
    }
  }

  if (schema.const !== undefined && !deepEqual(instance, schema.const)) {
    schemaError(errors, path, 'const', `value ${JSON.stringify(instance)} does not equal the required constant ${JSON.stringify(schema.const)}`);
  }

  if (schema.enum !== undefined && !schema.enum.some((v) => deepEqual(instance, v))) {
    schemaError(errors, path, 'enum', `value ${JSON.stringify(instance)} is not one of the allowed enum values`);
  }

  if (Array.isArray(schema.allOf)) {
    for (const sub of schema.allOf) evaluate(schemaDoc, sub, instance, path, stack, errors);
  }
  if (Array.isArray(schema.anyOf)) {
    if (!schema.anyOf.some((sub) => branchPasses(schemaDoc, sub, instance, path, stack))) {
      schemaError(errors, path, 'anyOf', `value must satisfy at least one of ${schema.anyOf.length} anyOf alternatives`);
    }
  }
  if (Array.isArray(schema.oneOf)) {
    const passed = schema.oneOf.filter((sub) => branchPasses(schemaDoc, sub, instance, path, stack)).length;
    if (passed !== 1) {
      schemaError(errors, path, 'oneOf', `value must satisfy exactly one of ${schema.oneOf.length} oneOf alternatives (satisfied ${passed})`);
    }
  }
  if (isSchemaNode(schema.not) && branchPasses(schemaDoc, schema.not, instance, path, stack)) {
    schemaError(errors, path, 'not', 'value must NOT satisfy the "not" schema');
  }

  if (typeof instance === 'object' && instance !== null && !Array.isArray(instance)) {
    evaluateObject(schemaDoc, schema, instance, path, stack, errors);
  }
  if (Array.isArray(instance)) {
    evaluateArray(schemaDoc, schema, instance, path, stack, errors);
  }
  if (typeof instance === 'string') {
    evaluateString(schema, instance, path, errors);
  }
  if (typeof instance === 'number') {
    evaluateNumber(schema, instance, path, errors);
  }
}

function branchPasses(schemaDoc, sub, instance, path, stack) {
  const subErrors = [];
  evaluate(schemaDoc, sub, instance, path, stack, subErrors);
  return subErrors.length === 0;
}

function evaluateObject(schemaDoc, schema, instance, path, stack, errors) {
  if (schema.minProperties !== undefined && Object.keys(instance).length < schema.minProperties) {
    schemaError(errors, path, 'minProperties', `object must have at least ${schema.minProperties} properties`);
  }
  if (schema.maxProperties !== undefined && Object.keys(instance).length > schema.maxProperties) {
    schemaError(errors, path, 'maxProperties', `object must have at most ${schema.maxProperties} properties`);
  }
  for (const requiredKey of schema.required ?? []) {
    if (!Object.prototype.hasOwnProperty.call(instance, requiredKey)) {
      schemaError(errors, path, 'required', `missing required property ${JSON.stringify(requiredKey)}`);
    }
  }
  if (schema.properties !== undefined) {
    for (const [key, sub] of Object.entries(schema.properties)) {
      if (Object.prototype.hasOwnProperty.call(instance, key)) {
        evaluate(schemaDoc, sub, instance[key], `${path}/${key}`, stack, errors);
      }
    }
  }
  if (schema.additionalProperties !== undefined) {
    const known = new Set(Object.keys(schema.properties ?? {}));
    for (const key of Object.keys(instance)) {
      if (known.has(key)) continue;
      if (schema.additionalProperties === false) {
        schemaError(errors, `${path}/${key}`, 'additionalProperties', `property ${JSON.stringify(key)} is not allowed (additionalProperties = false)`);
      } else if (isSchemaNode(schema.additionalProperties)) {
        evaluate(schemaDoc, schema.additionalProperties, instance[key], `${path}/${key}`, stack, errors);
      }
    }
  }
}

function evaluateArray(schemaDoc, schema, instance, path, stack, errors) {
  if (schema.minItems !== undefined && instance.length < schema.minItems) {
    schemaError(errors, path, 'minItems', `array must have at least ${schema.minItems} items (got ${instance.length})`);
  }
  if (schema.maxItems !== undefined && instance.length > schema.maxItems) {
    schemaError(errors, path, 'maxItems', `array must have at most ${schema.maxItems} items (got ${instance.length})`);
  }
  if (schema.uniqueItems === true) {
    for (let i = 0; i < instance.length; i += 1) {
      for (let j = i + 1; j < instance.length; j += 1) {
        if (deepEqual(instance[i], instance[j])) {
          schemaError(errors, path, 'uniqueItems', 'array items must be unique');
          break;
        }
      }
    }
  }
  if (isSchemaNode(schema.items)) {
    instance.forEach((item, i) => {
      evaluate(schemaDoc, schema.items, item, `${path}/${i}`, stack, errors);
    });
  }
}

function evaluateString(schema, instance, path, errors) {
  const len = [...instance].length;
  if (schema.minLength !== undefined && len < schema.minLength) {
    schemaError(errors, path, 'minLength', `string must be at least ${schema.minLength} characters long`);
  }
  if (schema.maxLength !== undefined && len > schema.maxLength) {
    schemaError(errors, path, 'maxLength', `string must be at most ${schema.maxLength} characters long`);
  }
  if (schema.pattern !== undefined) {
    const re = new RegExp(schema.pattern, 'u');
    if (!re.test(instance)) {
      schemaError(errors, path, 'pattern', `string does not match the required pattern ${JSON.stringify(schema.pattern)}`);
    }
  }
}

function evaluateNumber(schema, instance, path, errors) {
  if (schema.minimum !== undefined && instance < schema.minimum) {
    schemaError(errors, path, 'minimum', `number must be >= ${schema.minimum}`);
  }
  if (schema.maximum !== undefined && instance > schema.maximum) {
    schemaError(errors, path, 'maximum', `number must be <= ${schema.maximum}`);
  }
  if (schema.exclusiveMinimum !== undefined && instance <= schema.exclusiveMinimum) {
    schemaError(errors, path, 'exclusiveMinimum', `number must be > ${schema.exclusiveMinimum}`);
  }
  if (schema.exclusiveMaximum !== undefined && instance >= schema.exclusiveMaximum) {
    schemaError(errors, path, 'exclusiveMaximum', `number must be < ${schema.exclusiveMaximum}`);
  }
  if (schema.multipleOf !== undefined) {
    const q = instance / schema.multipleOf;
    if (Math.abs(q - Math.round(q)) > 1e-9) {
      schemaError(errors, path, 'multipleOf', `number must be a multiple of ${schema.multipleOf}`);
    }
  }
}

// Validate an instance against a subschema of the document addressed by a
// LOCAL ref (default "#": the root). Returns { valid, errors } where each
// error carries { path, keyword, message }.
export function validateInstance(schemaDoc, instance, { ref = '#', maxErrors = MAX_ERRORS } = {}) {
  const start = resolveRef(schemaDoc, ref);
  if (start === null) {
    return {
      valid: false,
      errors: [{ path: '#', keyword: '$ref', message: `#: cannot resolve starting ref ${JSON.stringify(ref)} locally` }],
    };
  }
  const errors = [];
  evaluate(schemaDoc, start, instance, '', [], errors);
  const report = errors.slice(0, maxErrors);
  return { valid: report.length === 0, errors: report };
}
