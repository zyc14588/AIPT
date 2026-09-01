import assert from 'node:assert/strict';
import test from 'node:test';

import {
  JSON_SCHEMA_RESOURCE_LIMITS_V1,
  checkSchemaDocument,
  validateInstance,
} from '../lib/json-schema.mjs';

const META = 'https://json-schema.org/draft/2020-12/schema';

function nestedObject(depth) {
  let value = null;
  for (let index = 0; index < depth; index += 1) value = { child: value };
  return value;
}

test('shared CI schema evaluator rejects unsafe regular expressions and bounds JSON resources', () => {
  const catastrophic = {
    $schema: META,
    type: 'string',
    pattern: '^(a+)+$',
  };
  const started = performance.now();
  const checked = checkSchemaDocument(catastrophic);
  assert.equal(checked.valid, false);
  assert.match(checked.errors.join('\n'), /REJECT_SCHEMA_UNSAFE_PATTERN/u);
  assert.ok(performance.now() - started < 500, 'unsafe-pattern rejection must remain bounded');
	const overlapping = checkSchemaDocument({
		$schema: META, type: 'string', pattern: '^a*a{1024}b$',
	});
	assert.equal(overlapping.valid, false);
	assert.match(overlapping.errors.join('\n'), /REJECT_SCHEMA_UNSAFE_PATTERN/u);
	const longSuffixBacktracking = checkSchemaDocument({
		$schema: META, type: 'string', pattern: `^.*${'a'.repeat(200)}$`,
	});
	assert.equal(longSuffixBacktracking.valid, false);
	assert.match(longSuffixBacktracking.errors.join('\n'), /REJECT_SCHEMA_UNSAFE_PATTERN/u);

  const safe = {
    $schema: META,
    type: 'string',
    pattern: '^[a-z]{1,32}$',
  };
  assert.deepEqual(checkSchemaDocument(safe), { valid: true, errors: [] });
  assert.equal(validateInstance(safe, 'bounded').valid, true);
  assert.equal(validateInstance(safe, `${'a'.repeat(31)}!`).valid, false);

  const unconstrainedObject = { $schema: META, type: 'object' };
  assert.equal(
    validateInstance(unconstrainedObject, nestedObject(JSON_SCHEMA_RESOURCE_LIMITS_V1.maxDepth)).valid,
    true,
  );
  const tooDeep = validateInstance(
    unconstrainedObject,
    nestedObject(JSON_SCHEMA_RESOURCE_LIMITS_V1.maxDepth + 1),
  );
  assert.equal(tooDeep.valid, false);
  assert.equal(tooDeep.errors[0]?.keyword, 'resourceLimit');

  const tooWide = Object.fromEntries(
    Array.from({ length: JSON_SCHEMA_RESOURCE_LIMITS_V1.maxNodes + 1 }, (_, index) => [`k${index}`, null]),
  );
  const wide = validateInstance(unconstrainedObject, tooWide);
  assert.equal(wide.valid, false);
  assert.equal(wide.errors[0]?.keyword, 'resourceLimit');

	const unique = validateInstance(
		{ $schema: META, type: 'array', uniqueItems: true },
		Array.from({ length: 500 }, (_, index) => ({ index, nested: [index] })),
	);
	assert.equal(unique.valid, false);
	assert.ok(unique.errors.some((entry) => entry.keyword === 'resourceLimit'));
});

test('shared CI schema string work caches repeats and bounds distinct full-input scans', () => {
	const repeatedValue = 'a'.repeat(2 * 1024 * 1024);
	const repeated = validateInstance(
		{
			$schema: META,
			allOf: Array.from({ length: 1_000 }, () => ({ minLength: 1, pattern: '^a*$' })),
		},
		repeatedValue,
	);
	assert.equal(repeated.valid, true, JSON.stringify(repeated.errors));

	const distinct = validateInstance(
		{
			$schema: META,
			allOf: ['^a*$', '^[a]*$', '^[aa]*$', '^[a-a]*$', '^[a\\x61]*$'].map((pattern) => ({ pattern })),
		},
		'a'.repeat(4 * 1024 * 1024),
	);
	assert.equal(distinct.valid, false);
	assert.ok(distinct.errors.some((entry) => entry.keyword === 'resourceLimit'));
});
