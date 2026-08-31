import { SDK_JSON_RESOURCE_LIMITS_V1 as LIMITS } from './resource-limits.ts';

// Public JSON Schema patterns are deliberately restricted to a small regular
// dialect whose worst-case work is linear in the instance length.  It allows
// literals, escapes, character classes, anchors, exact repetition, and at
// most one variable repetition.  Groups, alternation, backreferences,
// lookaround, Unicode-property escapes, and stacked quantifiers are rejected.
// The frozen protocol schema uses only this dialect.
export class UnsafeSchemaPatternError extends Error {}

function isEscaped(text: string, index: number): boolean {
  let slashes = 0;
  for (let cursor = index - 1; cursor >= 0 && text[cursor] === '\\'; cursor -= 1) slashes += 1;
  return slashes % 2 === 1;
}

export function compileSafeSchemaPattern(pattern: string): RegExp {
  if (pattern.length > LIMITS.max_schema_pattern_code_units) {
    throw new UnsafeSchemaPatternError(`REJECT_SCHEMA_UNSAFE_PATTERN: pattern exceeds ${LIMITS.max_schema_pattern_code_units} code units`);
  }
  if (pattern.length === 0) return new RegExp(pattern, 'u');
  if (!(pattern.startsWith('^') && pattern.endsWith('$') && !isEscaped(pattern, pattern.length - 1))) {
    throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: every non-empty pattern requires both anchors');
  }

  let variableRepetitions = 0;
	let quantifiedAtoms = 0;
  let variableRepetitionEnd = -1;
  let atomAvailable = false;
  let inClass = false;
  let classHasAtom = false;
  let cursor = 0;

  while (cursor < pattern.length) {
    const char = pattern[cursor] as string;
    if (inClass) {
      if (char === ']' && classHasAtom && !isEscaped(pattern, cursor)) {
        inClass = false;
        atomAvailable = true;
        cursor += 1;
        continue;
      }
      if (char === '\\') {
        if (cursor + 1 >= pattern.length) throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: dangling escape in character class');
        if (pattern[cursor + 1] === 'p' || pattern[cursor + 1] === 'P') {
          throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: Unicode property escapes are outside the safe subset');
        }
        classHasAtom = true;
        cursor += 2;
        continue;
      }
      classHasAtom = true;
      cursor += 1;
      continue;
    }

    if (char === '[') {
      inClass = true;
      classHasAtom = false;
      atomAvailable = false;
      cursor += 1;
      if (pattern[cursor] === '^') cursor += 1;
      continue;
    }
    if (char === '\\') {
      const escaped = pattern[cursor + 1];
      if (escaped === undefined) throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: dangling escape');
      if (/[1-9]/u.test(escaped) || escaped === 'k') {
        throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: backreferences are forbidden');
      }
      if (escaped === 'p' || escaped === 'P') {
        throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: Unicode property escapes are outside the safe subset');
      }
      atomAvailable = true;
      cursor += 2;
      continue;
    }
    if (char === '(' || char === ')' || char === '|') {
      throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: groups, lookaround, and alternation are outside the safe subset');
    }
    if (char === '^') {
      if (cursor !== 0) throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: ^ is only allowed as the leading anchor');
      atomAvailable = false;
      cursor += 1;
      continue;
    }
    if (char === '$') {
      if (cursor !== pattern.length - 1) throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: $ is only allowed as the trailing anchor');
      atomAvailable = false;
      cursor += 1;
      continue;
    }
    if (char === '*' || char === '+' || char === '?') {
      if (!atomAvailable) throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: quantifier has no single safe atom');
      variableRepetitions += 1;
	  variableRepetitionEnd = cursor + 1;
	  quantifiedAtoms += 1;
      atomAvailable = false;
      cursor += 1;
      continue;
    }
    if (char === '{') {
      if (!atomAvailable) throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: repetition has no single safe atom');
      const end = pattern.indexOf('}', cursor + 1);
      if (end < 0) throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: unterminated repetition');
      const body = pattern.slice(cursor + 1, end);
      const match = /^(0|[1-9][0-9]*)(?:,(0|[1-9][0-9]*)?)?$/u.exec(body);
      if (match === null) throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: malformed repetition');
      const lower = Number(match[1]);
      const hasComma = body.includes(',');
      const upper = hasComma ? (match[2] === undefined ? Number.POSITIVE_INFINITY : Number(match[2])) : lower;
      if (upper < lower || lower > LIMITS.max_schema_pattern_repetition || upper > LIMITS.max_schema_pattern_repetition) {
        throw new UnsafeSchemaPatternError(`REJECT_SCHEMA_UNSAFE_PATTERN: repetition exceeds ${LIMITS.max_schema_pattern_repetition}`);
      }
	  if (hasComma && upper !== lower) {
		variableRepetitions += 1;
		variableRepetitionEnd = end + 1;
	  }
	  quantifiedAtoms += 1;
      atomAvailable = false;
      cursor = end + 1;
      continue;
    }
    if (char === '}') throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: unmatched repetition delimiter');
    atomAvailable = true;
    cursor += 1;
  }

  if (inClass) throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: unterminated character class');
  if (variableRepetitions > 1) {
    throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: more than one variable repetition is forbidden');
  }
	if (variableRepetitions === 1 && quantifiedAtoms !== 1) {
		throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: a variable repetition cannot overlap another quantified atom');
	}
	if (variableRepetitions === 1 && variableRepetitionEnd !== pattern.length - 1) {
		throw new UnsafeSchemaPatternError('REJECT_SCHEMA_UNSAFE_PATTERN: a variable repetition must be the final consuming atom');
	}
  try {
    return new RegExp(pattern, 'u');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new UnsafeSchemaPatternError(`REJECT_SCHEMA_UNSAFE_PATTERN: invalid regular expression (${message})`);
  }
}
