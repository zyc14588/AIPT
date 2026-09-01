// Fail-closed regular-expression boundary for repository JSON Schema gates.
// New caller-controlled patterns must fit the dependency-free linear-work
// subset below.  A small versioned compatibility registry preserves the
// exact, manually reviewed patterns already frozen in historical schemas;
// arbitrary variations of those patterns do not inherit that approval.

export const SAFE_REGEX_POLICY_ID = 'aipt.ci.schema-safe-regex/v1';
export const MAX_PATTERN_CODE_UNITS = 512;
export const MAX_PATTERN_REPETITION = 4096;

const REVIEWED_COMPATIBILITY_PATTERNS_V1 = new Set([
  String.raw`^#/\$defs/[A-Za-z0-9_-]+$`,
  String.raw`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`,
  String.raw`^(?!/)(?!.*(?:^|/)\.\.(?:/|$))(?!.*//)[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$`,
  String.raw`^(?!/)(?!.*(?:^|/)\.\.(?:/|$))(?!.*\\).+$`,
  String.raw`^(?:FAIL_PREDECESSOR_P0_VALIDATION|FAIL_P0_PRESERVATION|FAIL_P1_DELTA_POLICY|FAIL_P1_B000_VALIDATION|FAIL_B001_REGRESSION)$`,
  String.raw`^(?:[0-9a-f]{40})?$`,
  String.raw`^(?:\.|[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)$`,
  String.raw`^A2-(?:N|S)[0-9]{2}$`,
  String.raw`^AIPT_[A-Z0-9_]{1,63}$`,
  String.raw`^[0-9]+(?:\.[0-9]+){0,2}$`,
  String.raw`^[0-9]+(?:\.[0-9]+){0,2}(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?$`,
  String.raw`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$`,
  String.raw`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[^\s]+Z$`,
  String.raw`^[0-9a-f]{16}$`,
  String.raw`^[0-9a-f]{40}$`,
  String.raw`^[0-9a-f]{64}$`,
  String.raw`^[A-Z][A-Z0-9_]{0,127}$`,
  String.raw`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`,
  String.raw`^[A-Za-z0-9][A-Za-z0-9.+-]*/[A-Za-z0-9][A-Za-z0-9.+-]*$`,
  String.raw`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`,
  String.raw`^[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,127}$`,
  String.raw`^[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,159}$`,
  String.raw`^[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,179}$`,
  String.raw`^[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,199}$`,
  String.raw`^[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,239}$`,
  String.raw`^[A-Za-z0-9][A-Za-z0-9._:@+/\-]{0,127}$`,
  String.raw`^[A-Za-z0-9_@+.-]+(?:/[A-Za-z0-9_@+.-]+)*$`,
  String.raw`^[a-z0-9.+-]+/[a-z0-9.+-]+$`,
  String.raw`^[a-z0-9][a-z0-9-]{0,63}$`,
  String.raw`^[a-z][a-z0-9.-]*/v(0|[1-9][0-9]*)$`,
  String.raw`^[a-z][a-z0-9_]*([.-][a-z0-9_]+)*$`,
  String.raw`^[a-z_][a-z0-9_]{0,62}$`,
  String.raw`^https://\S+$`,
]);

function reject(reason) {
  const error = new Error(`REJECT_SCHEMA_UNSAFE_PATTERN: ${reason} (${SAFE_REGEX_POLICY_ID})`);
  error.code = 'REJECT_SCHEMA_UNSAFE_PATTERN';
  throw error;
}

function escapedAt(text, index) {
  let slashes = 0;
  for (let cursor = index - 1; cursor >= 0 && text[cursor] === '\\'; cursor -= 1) slashes += 1;
  return slashes % 2 === 1;
}

function assertLinearSubset(pattern) {
  if (pattern.length === 0) return;
  if (!(pattern.startsWith('^') && pattern.endsWith('$') && !escapedAt(pattern, pattern.length - 1))) {
    reject('every non-empty pattern requires both anchors');
  }
  let inClass = false;
  let classHasAtom = false;
  let atomAvailable = false;
  let variableRepetitions = 0;
	let quantifiedAtoms = 0;
  let variableRepetitionEnd = -1;
  for (let cursor = 0; cursor < pattern.length; cursor += 1) {
    const char = pattern[cursor];
    if (inClass) {
      if (char === ']' && classHasAtom && !escapedAt(pattern, cursor)) {
        inClass = false;
        atomAvailable = true;
      } else if (char === '\\') {
        if (cursor + 1 >= pattern.length) reject('dangling escape in character class');
        if (pattern[cursor + 1] === 'p' || pattern[cursor + 1] === 'P') reject('Unicode property escapes are outside the linear subset');
        classHasAtom = true;
        cursor += 1;
      } else {
        classHasAtom = true;
      }
      continue;
    }
    if (char === '[') {
      inClass = true;
      classHasAtom = false;
      atomAvailable = false;
      if (pattern[cursor + 1] === '^') cursor += 1;
      continue;
    }
    if (char === '\\') {
      const escaped = pattern[cursor + 1];
      if (escaped === undefined) reject('dangling escape');
      if (/[1-9]/u.test(escaped) || escaped === 'k') reject('backreferences are forbidden');
      if (escaped === 'p' || escaped === 'P') reject('Unicode property escapes are outside the linear subset');
      atomAvailable = true;
      cursor += 1;
      continue;
    }
    if (char === '(' || char === ')' || char === '|') reject('groups, lookaround, and alternation require an exact reviewed compatibility pattern');
    if (char === '^') {
      if (cursor !== 0) reject('^ is only allowed as the leading anchor');
      atomAvailable = false;
      continue;
    }
    if (char === '$') {
      if (cursor !== pattern.length - 1) reject('$ is only allowed as the trailing anchor');
      atomAvailable = false;
      continue;
    }
    if (char === '*' || char === '+' || char === '?') {
      if (!atomAvailable) reject('stacked or atomless quantifier');
      variableRepetitions += 1;
	  variableRepetitionEnd = cursor + 1;
	  quantifiedAtoms += 1;
      atomAvailable = false;
      continue;
    }
    if (char === '{') {
      if (!atomAvailable) reject('stacked or atomless repetition');
      const end = pattern.indexOf('}', cursor + 1);
      if (end < 0) reject('unterminated repetition');
      const body = pattern.slice(cursor + 1, end);
      const match = /^(0|[1-9][0-9]*)(?:,(0|[1-9][0-9]*)?)?$/u.exec(body);
      if (match === null) reject('malformed repetition');
      const lower = Number(match[1]);
      const comma = body.includes(',');
      const upper = comma ? (match[2] === undefined ? Number.POSITIVE_INFINITY : Number(match[2])) : lower;
      if (upper < lower || lower > MAX_PATTERN_REPETITION || upper > MAX_PATTERN_REPETITION) reject(`repetition exceeds ${MAX_PATTERN_REPETITION}`);
	  if (comma && upper !== lower) {
		variableRepetitions += 1;
		variableRepetitionEnd = end + 1;
	  }
	  quantifiedAtoms += 1;
      atomAvailable = false;
      cursor = end;
      continue;
    }
    if (char === '}') reject('unmatched repetition delimiter');
    atomAvailable = true;
  }
  if (inClass) reject('unterminated character class');
  if (variableRepetitions > 1) reject('more than one variable repetition is outside the linear subset');
	if (variableRepetitions === 1 && quantifiedAtoms !== 1) reject('a variable repetition cannot overlap another quantified atom');
  if (variableRepetitions === 1 && variableRepetitionEnd !== pattern.length - 1) {
    reject('a variable repetition must be the final consuming atom');
  }
}

const compiled = new Map();

export function compileSafeRegex(pattern) {
  if (typeof pattern !== 'string') reject('pattern must be a string');
  if (pattern.length > MAX_PATTERN_CODE_UNITS) reject(`pattern exceeds ${MAX_PATTERN_CODE_UNITS} code units`);
  const cached = compiled.get(pattern);
  if (cached !== undefined) return cached;
  if (!REVIEWED_COMPATIBILITY_PATTERNS_V1.has(pattern)) assertLinearSubset(pattern);
  let regex;
  try {
    regex = new RegExp(pattern, 'u');
  } catch (error) {
    reject(`pattern does not compile: ${error instanceof Error ? error.message : String(error)}`);
  }
  compiled.set(pattern, regex);
  return regex;
}

export function safeRegexPolicySummary() {
  return Object.freeze({
    identity: SAFE_REGEX_POLICY_ID,
    reviewed_compatibility_patterns: REVIEWED_COMPATIBILITY_PATTERNS_V1.size,
    max_pattern_code_units: MAX_PATTERN_CODE_UNITS,
    max_repetition: MAX_PATTERN_REPETITION,
  });
}
