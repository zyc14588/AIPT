import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { test } from 'node:test';
import * as sdk from '../src/index.ts';

test('canonical JSON preserves own __proto__ without prototype mutation or digest collision', () => {
  const absent = JSON.parse('{"x":1}') as Record<string, unknown>;
  const present = JSON.parse('{"x":1,"__proto__":{"admin":true}}') as Record<string, unknown>;
  const nested = JSON.parse('{"items":[{"__proto__":{"nested":true},"constructor":1,"prototype":2}]}') as Record<string, unknown>;

  const canonical = sdk.canonicalJson(present) as Record<string, unknown>;
  assert.equal(Object.getPrototypeOf(canonical), Object.prototype);
  assert.equal(Object.hasOwn(canonical, '__proto__'), true);
  assert.deepEqual(Object.getOwnPropertyDescriptor(canonical, '__proto__')?.value, { admin: true });
  assert.equal((Object.prototype as Record<string, unknown>).admin, undefined);
  assert.equal(sdk.canonicalJsonString(absent), '{"x":1}');
  assert.equal(sdk.canonicalJsonString(present), '{"__proto__":{"admin":true},"x":1}');
  assert.notEqual(sdk.canonicalJsonString(absent), sdk.canonicalJsonString(present));
  assert.notEqual(sdk.sha256Hex(absent), sdk.sha256Hex(present));

  const nestedCanonical = sdk.canonicalJson(nested) as { items: Array<Record<string, unknown>> };
  assert.equal(Object.hasOwn(nestedCanonical.items[0] as object, '__proto__'), true);
  assert.equal(Object.hasOwn(nestedCanonical.items[0] as object, 'constructor'), true);
  assert.equal(Object.hasOwn(nestedCanonical.items[0] as object, 'prototype'), true);
  assert.equal((Object.prototype as Record<string, unknown>).nested, undefined);
});

function nestedValue(depth: number): unknown {
  let value: unknown = 0;
  for (let index = 0; index < depth; index += 1) value = { value };
  return value;
}

test('versioned JSON depth, node, width, and byte limits fail closed without stack exhaustion', () => {
  const limits = sdk.SDK_JSON_RESOURCE_LIMITS_V1;
  assert.equal(limits.identity, 'aipt.adapter-sdk.json-resource-limits/v1');
  assert.equal(sdk.validateJsonValue(nestedValue(limits.max_depth)).valid, true);
  const tooDeep = sdk.validateJsonValue(nestedValue(limits.max_depth + 1));
  assert.equal(tooDeep.valid, false);
  assert.ok(tooDeep.issues.some((entry) => entry.code === 'AIPT_JSON_RESOURCE_LIMIT'));
  assert.throws(() => sdk.canonicalJsonString(nestedValue(limits.max_depth + 1)), sdk.ProtocolValidationError);

  const exactNodes = Object.fromEntries(Array.from({ length: limits.max_nodes - 1 }, (_, index) => [`k${index}`, null]));
  assert.equal(sdk.validateJsonValue(exactNodes).valid, true);
  const tooWide = { ...exactNodes, overflow: null };
  const wideResult = sdk.validateJsonValue(tooWide);
  assert.equal(wideResult.valid, false);
  assert.ok(wideResult.issues.some((entry) => entry.code === 'AIPT_JSON_RESOURCE_LIMIT'));

  assert.equal(sdk.validateJsonValue('x'.repeat(limits.max_aggregate_bytes)).valid, true);
  const tooLarge = sdk.validateJsonValue('x'.repeat(limits.max_aggregate_bytes + 1));
  assert.equal(tooLarge.valid, false);
  assert.ok(tooLarge.issues.some((entry) => entry.code === 'AIPT_JSON_RESOURCE_LIMIT'));
	assert.throws(
		() => sdk.parseJson(JSON.stringify('x'.repeat(limits.max_aggregate_bytes + 1))),
		(error: unknown) => error instanceof sdk.ProtocolValidationError &&
			error.issues.some((entry) => entry.code === 'AIPT_JSON_RESOURCE_LIMIT'),
	);

  const nestedArrays = nestedValue(limits.max_depth + 1);
  assert.doesNotThrow(() => sdk.validateJsonValue(nestedArrays));
});

test('schema enum and uniqueItems deep-comparison work is charged and bounded', () => {
	const values = Array.from({ length: 500 }, (_, index) => ({ index, nested: [index] }));
	const unique = sdk.validateSchemaInstance(
		{ $defs: { value: { type: 'array', uniqueItems: true } } },
		values,
		'#/$defs/value',
	);
	assert.equal(unique.valid, false);
	assert.ok(unique.issues.some((entry) => entry.code === 'AIPT_JSON_RESOURCE_LIMIT'));

	const enumeration = sdk.validateSchemaInstance(
		{ $defs: { value: { enum: values } } },
		{ index: -1, nested: [-1] },
		'#/$defs/value',
	);
	assert.equal(enumeration.valid, false);
	assert.ok(enumeration.issues.some((entry) => entry.code === 'AIPT_JSON_RESOURCE_LIMIT'));
});

test('schema string work is cached for equivalent branches and bounded across distinct patterns', () => {
  const largeValue = 'a'.repeat(2 * 1024 * 1024);
  const repeated = sdk.validateSchemaInstance(
    {
      $defs: {
        value: {
          allOf: Array.from({ length: 1_000 }, () => ({ minLength: 1, pattern: '^a*$' })),
        },
      },
    },
    largeValue,
    '#/$defs/value',
  );
  assert.equal(repeated.valid, true, JSON.stringify(repeated.issues));

  const distinct = sdk.validateSchemaInstance(
    {
      $defs: {
        value: {
          allOf: ['^a*$', '^[a]*$', '^[aa]*$', '^[a-a]*$', '^[a\\x61]*$'].map((pattern) => ({ pattern })),
        },
      },
    },
    largeValue,
    '#/$defs/value',
  );
  assert.equal(distinct.valid, false);
  assert.ok(distinct.issues.some((entry) => entry.code === 'AIPT_JSON_RESOURCE_LIMIT'));
});

function patternSchema(pattern: string): Record<string, unknown> {
  return { $defs: { value: { type: 'string', pattern } } };
}

test('caller-controlled catastrophic schema patterns are rejected before execution', () => {
  const attacks = [
    '^(a+)+$',
    '^(a|aa)+$',
    '^(.*a){20}$',
    '^(a+)\\1$',
    '^(?=a)a+$',
	'^a*a{1024}b$',
    `^.*${'a'.repeat(200)}$`,
    `^${'a'.repeat(sdk.SDK_JSON_RESOURCE_LIMITS_V1.max_schema_pattern_code_units + 1)}$`,
  ];
  for (const pattern of attacks) {
    const started = performance.now();
    const result = sdk.validateSchemaInstance(patternSchema(pattern), `${'a'.repeat(40)}!`, '#/$defs/value');
    assert.equal(result.valid, false, pattern);
    assert.ok(result.issues.some((entry) => entry.code === 'AIPT_SCHEMA_UNSAFE_PATTERN' && entry.message.includes('REJECT_SCHEMA_UNSAFE_PATTERN')), pattern);
    assert.ok(performance.now() - started < 250, `${pattern} must be rejected before regex execution`);
  }

  const safe = sdk.validateSchemaInstance(patternSchema('^[a-z0-9][a-z0-9-]{0,63}$'), 'safe-id', '#/$defs/value');
  assert.equal(safe.valid, true, JSON.stringify(safe.issues));
});

test('a shallow document cannot hide an over-limit recursive $ref chain', () => {
  const defs: Record<string, unknown> = {};
  const count = sdk.SDK_JSON_RESOURCE_LIMITS_V1.max_schema_traversal_depth + 2;
  for (let index = 0; index < count; index += 1) {
    defs[`n${index}`] = index + 1 === count ? { type: 'string' } : { $ref: `#/$defs/n${index + 1}` };
  }
  const result = sdk.validateSchemaInstance({ $defs: defs }, 'x', '#/$defs/n0');
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((entry) => entry.code === 'AIPT_JSON_RESOURCE_LIMIT'));
});

test('schema branches share one issue budget and stop with a bounded terminal issue', () => {
  const branchCount = sdk.SDK_JSON_RESOURCE_LIMITS_V1.max_issues + 1;
  const schema = {
    $defs: {
      value: {
        allOf: Array.from({ length: branchCount }, () => ({ type: 'number' })),
      },
    },
  };
  const largeValue = `sentinel-${'x'.repeat(1024 * 1024)}`;
  const result = sdk.validateSchemaInstance(schema, largeValue, '#/$defs/value');
  assert.equal(result.valid, false);
  assert.ok(result.issues.some((entry) => entry.code === 'AIPT_JSON_RESOURCE_LIMIT'));
  assert.ok(result.issues.length <= sdk.SDK_JSON_RESOURCE_LIMITS_V1.max_issues);
  assert.ok(result.issues.every((entry) => entry.message.length < 512), 'diagnostics must describe values in constant-size text');
  assert.ok(result.issues.every((entry) => !entry.message.includes('sentinel-')), 'diagnostics must not embed caller-sized values');
});

test('schema preflight shares the same bounded issue sink across all branches', () => {
  const branchCount = sdk.SDK_JSON_RESOURCE_LIMITS_V1.max_issues + 1;
  const schema = {
    $defs: {
      value: {
        allOf: Array.from({ length: branchCount }, (_, index) => ({ [`unsupported_${index}`]: true })),
      },
    },
  };
  const result = sdk.validateSchemaInstance(schema, null, '#/$defs/value');
  assert.equal(result.valid, false);
  assert.deepEqual(result.issues.map((entry) => entry.code), ['AIPT_JSON_RESOURCE_LIMIT']);
});
