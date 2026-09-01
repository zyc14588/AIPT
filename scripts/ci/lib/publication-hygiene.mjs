import fs from 'node:fs';
import path from 'node:path';

export const PUBLICATION_HYGIENE_POLICY = Object.freeze({
  detector_identity: 'aipt.publication-hygiene-detectors/v1',
  detector_version: '1.0.0',
  required_detector_ids: Object.freeze([
    'credential_api_key_material',
    'bearer_token_material',
    'environment_secret_values',
    'private_prompt_material',
    'private_asset_locator_material',
    'forbidden_absolute_local_path',
    'resolved_credential_reference',
  ]),
  limits: Object.freeze({
    max_files: 10_000,
    max_file_bytes: 8 * 1024 * 1024,
    max_total_bytes: 64 * 1024 * 1024,
    max_matches_per_detector_file: 256,
    max_total_findings: 4096,
  }),
});

const secretName = /(?:API[_-]?KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)/iu;
const keyPrefix = ['s', 'k', '-'].join('');
const pemPrefix = ['-----', 'BEGIN', ' '].join('');
const bearerPrefix = ['Bear', 'er'].join('');
const homePrefix = ['/', 'ho', 'me', '/'].join('');
const usersPrefix = ['/', 'Us', 'ers', '/'].join('');
const rootPrefix = ['/', 'ro', 'ot', '/'].join('');
const privatePromptMarkers = [
  ['BEGIN', ' PRIVATE', ' PROMPT'].join(''),
  ['<private', '_prompt>'].join(''),
  ['SYSTEM', '_PROMPT', '_PRIVATE'].join(''),
];
const privateAssetMarker = ['PRIVATE', '_ASSET', '_LOCATOR:'].join('');

class PublicationBudgetError extends Error {}

function indexesForRegex(text, regex) {
  const indexes = [];
  regex.lastIndex = 0;
  for (;;) {
    const match = regex.exec(text);
    if (match === null) break;
    indexes.push(match.index);
    if (indexes.length > PUBLICATION_HYGIENE_POLICY.limits.max_matches_per_detector_file) {
      throw new PublicationBudgetError('detector match budget exceeded');
    }
    if (match[0].length === 0) regex.lastIndex += 1;
  }
  return indexes;
}

function literalIndexes(text, literal) {
  const indexes = [];
  if (literal.length === 0) return indexes;
  let cursor = 0;
  for (;;) {
    const index = text.indexOf(literal, cursor);
    if (index < 0) return indexes;
    indexes.push(index);
    if (indexes.length > PUBLICATION_HYGIENE_POLICY.limits.max_matches_per_detector_file) {
      throw new PublicationBudgetError('detector match budget exceeded');
    }
    cursor = index + literal.length;
  }
}

function boundedIndexes(...groups) {
  const indexes = [];
  for (const group of groups) {
    for (const index of group) {
      indexes.push(index);
      if (indexes.length > PUBLICATION_HYGIENE_POLICY.limits.max_matches_per_detector_file) {
        throw new PublicationBudgetError('detector match budget exceeded');
      }
    }
  }
  return indexes;
}

const detectors = Object.freeze([
  {
    id: 'credential_api_key_material', category: 'credential_leaks',
    scan(text, context) {
      const prefix = keyPrefix.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
      const pem = pemPrefix.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
      const keyLike = new RegExp(`(?:^|[^A-Za-z0-9])${prefix}[A-Za-z0-9_-]{8,}`, 'gu');
      const privateKey = new RegExp(`${pem}[A-Z0-9 ]*PRIVATE KEY-----`, 'gu');
      const assignment = /\b[A-Z][A-Z0-9_]*(?:API[_-]?KEY|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*\s*[:=]\s*(["']?)([A-Za-z0-9_+./=-]{8,})\1/gu;
      const assignments = [];
      for (const match of text.matchAll(assignment)) {
        const quoted = (match[1] ?? '').length > 0;
        const value = match[2] ?? '';
        const environmentLikeFile = /(?:^|\/)(?:\.env(?:\..*)?|[^/]+\.(?:properties|conf))$/u.test(context.relative);
        if (!environmentLikeFile && (!quoted || /^[A-Z][A-Z0-9_]{0,127}$/u.test(value))) continue;
        assignments.push(match.index ?? 0);
        if (assignments.length > PUBLICATION_HYGIENE_POLICY.limits.max_matches_per_detector_file) {
          throw new PublicationBudgetError('detector match budget exceeded');
        }
      }
      return boundedIndexes(indexesForRegex(text, keyLike), indexesForRegex(text, privateKey), assignments);
    },
  },
  {
    id: 'bearer_token_material', category: 'token_leaks',
    scan(text) {
      const escaped = bearerPrefix.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
      return indexesForRegex(text, new RegExp(`${escaped}\\s+[A-Za-z0-9._~+/-]{12,}`, 'giu'));
    },
  },
  {
    id: 'environment_secret_values', category: 'environment_secret_leaks',
    scan(text, context) {
      return boundedIndexes(...context.environmentSecrets.map((value) => literalIndexes(text, value)));
    },
  },
  {
    id: 'private_prompt_material', category: 'private_prompt_leaks',
    scan(text) { return boundedIndexes(...privatePromptMarkers.map((marker) => literalIndexes(text, marker))); },
  },
  {
    id: 'private_asset_locator_material', category: 'private_asset_locator_leaks',
    scan(text) {
      const markerMatches = literalIndexes(text, privateAssetMarker);
      const resolvedAsset = new RegExp(`(?:${homePrefix}|${usersPrefix})[^\\s"']+\\.(?:gguf|bin|safetensors)`, 'giu');
      return boundedIndexes(markerMatches, indexesForRegex(text, resolvedAsset));
    },
  },
  {
    id: 'forbidden_absolute_local_path', category: 'private_path_leaks',
    scan(text) {
      const unixHome = new RegExp(`(?:${homePrefix}|${usersPrefix})[A-Za-z0-9._-]+/[^\\s"'<>]+`, 'gu');
      const rootHome = new RegExp(`${rootPrefix}[^\\s"'<>]+`, 'gu');
      const windowsHome = new RegExp(String.raw`[A-Za-z]:\\Users\\[A-Za-z0-9._-]+\\[^\s"'<>]+`, 'gu');
      return boundedIndexes(indexesForRegex(text, unixHome), indexesForRegex(text, rootHome), indexesForRegex(text, windowsHome));
    },
  },
  {
    id: 'resolved_credential_reference', category: 'credential_reference_leaks',
    scan(text, context) {
      const indexes = [];
      const locator = /["']locator["']\s*:\s*["']([^"']+)["']/giu;
      for (const match of text.matchAll(locator)) {
        const value = match[1] ?? '';
        if (!/^[A-Z][A-Z0-9_]{0,127}$/u.test(value) || context.environmentSecrets.includes(value)) indexes.push(match.index ?? 0);
        if (indexes.length > PUBLICATION_HYGIENE_POLICY.limits.max_matches_per_detector_file) {
          throw new PublicationBudgetError('detector match budget exceeded');
        }
      }
      return indexes;
    },
  },
]);

function newlineIndexes(text) {
  const indexes = [];
  for (let cursor = 0; cursor < text.length; cursor += 1) {
    if (text.charCodeAt(cursor) === 10) indexes.push(cursor);
  }
  return indexes;
}

function lineAt(indexes, index) {
  let low = 0;
  let high = indexes.length;
  while (low < high) {
    const middle = low + Math.floor((high - low) / 2);
    if (indexes[middle] < index) low = middle + 1;
    else high = middle;
  }
  return low + 1;
}

function environmentSecretValues(environment) {
  const values = [];
  const seen = new Set();
  let overflow = false;
  for (const [name, value] of Object.entries(environment ?? {})) {
    if (secretName.test(name) && typeof value === 'string' && value.length >= 8 && !seen.has(value)) {
      seen.add(value);
      values.push(value);
      if (values.length > PUBLICATION_HYGIENE_POLICY.limits.max_matches_per_detector_file) {
        overflow = true;
        break;
      }
    }
  }
  return { values, overflow };
}

export function runPublicationHygiene({ repo, files, environment = process.env }) {
  const required = PUBLICATION_HYGIENE_POLICY.required_detector_ids;
  const active = detectors.map((detector) => detector.id);
  const detectorInventoryValid = JSON.stringify(active) === JSON.stringify(required) && new Set(active).size === active.length;
  const errors = [];
  const findings = [];
  let filesScanned = 0;
  let bytesScanned = 0;
  let findingBudgetExceeded = false;
  const provided = Array.isArray(files) ? files : [];
  const expected = [...new Set(provided)].sort();
  const environmentSecrets = environmentSecretValues(environment);
  const context = { environmentSecrets: environmentSecrets.values, relative: '' };
  const executions = Object.fromEntries(detectors.map((detector) => [detector.id, 0]));
  const limits = PUBLICATION_HYGIENE_POLICY.limits;
  const repoRoot = path.resolve(repo);
  if (!detectorInventoryValid) errors.push('required detector inventory is missing, duplicated, or unsupported');
  if (!Array.isArray(files) || expected.length === 0) errors.push('publication inventory is absent');
  if (provided.length !== expected.length) errors.push('publication inventory contains duplicate paths');
  if (expected.length > limits.max_files) errors.push('publication file inventory exceeds the bounded policy');
  if (environmentSecrets.overflow) errors.push('environment secret inventory exceeds the bounded policy');
  fileLoop: for (const relative of expected) {
    if (expected.length > limits.max_files) break;
    if (typeof relative !== 'string' || relative === '' || path.isAbsolute(relative) || relative.split(/[\\/]/u).includes('..')) {
      errors.push('publication inventory contains an unsafe relative path');
      continue;
    }
    const absolute = path.resolve(repoRoot, relative);
    const contained = path.relative(repoRoot, absolute);
    if (contained === '' || contained.startsWith(`..${path.sep}`) || path.isAbsolute(contained)) {
      errors.push('publication inventory resolves outside the repository');
      continue;
    }
    let info;
    let raw;
    let descriptor;
    try {
      descriptor = fs.openSync(absolute, fs.constants.O_RDONLY | fs.constants.O_CLOEXEC | fs.constants.O_NOFOLLOW);
      const opened = fs.realpathSync(`/proc/self/fd/${descriptor}`);
      const openedRelative = path.relative(repoRoot, opened);
      if (openedRelative.startsWith(`..${path.sep}`) || path.isAbsolute(openedRelative)) {
        throw new Error('candidate payload resolves outside the repository');
      }
      info = fs.fstatSync(descriptor);
      if (!info.isFile() || info.size < 0 || info.size > limits.max_file_bytes || info.size > limits.max_total_bytes - bytesScanned) {
        throw new PublicationBudgetError('candidate payload exceeds the bounded policy');
      }
      raw = fs.readFileSync(descriptor);
      const after = fs.fstatSync(descriptor);
      if (raw.byteLength !== info.size || after.size !== info.size || after.mtimeMs !== info.mtimeMs || after.ctimeMs !== info.ctimeMs) {
        throw new Error('candidate payload changed during scan');
      }
    } catch {
      errors.push(`${relative}: coverage read failed`);
      continue;
    } finally {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch { errors.push(`${relative}: coverage close failed`); }
      }
    }
    let text;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(raw); }
    catch {
      errors.push(`${relative}: unsupported non-UTF-8 candidate payload`);
      continue;
    }
    filesScanned += 1;
    bytesScanned += raw.byteLength;
    context.relative = relative;
    const lines = newlineIndexes(text);
    for (const detector of detectors) {
      let indexes;
      try {
        indexes = detector.scan(text, context);
        executions[detector.id] += 1;
      } catch (error) {
        const failure = error instanceof PublicationBudgetError ? 'exceeded its bounded policy' : 'crashed';
        errors.push(`${relative}: detector ${detector.id} ${failure}`);
        continue;
      }
      for (const index of indexes) {
        if (findings.length >= limits.max_total_findings) {
          if (!findingBudgetExceeded) errors.push('publication findings exceed the bounded policy');
          findingBudgetExceeded = true;
          break;
        }
        findings.push({ detector_id: detector.id, category: detector.category, file: relative, line: lineAt(lines, index) });
      }
      if (findingBudgetExceeded) break fileLoop;
    }
  }
  const detectorsExecuted = detectorInventoryValid && required.every((id) => executions[id] === expected.length);
  const coverageComplete = filesScanned === expected.length && detectorsExecuted && errors.length === 0;
  const counts = Object.fromEntries(detectors.map((detector) => [detector.category, findings.filter((finding) => finding.category === detector.category).length]));
  return Object.freeze({
    detector_identity: PUBLICATION_HYGIENE_POLICY.detector_identity,
    detector_version: PUBLICATION_HYGIENE_POLICY.detector_version,
    detector_count: detectors.length,
    required_detector_count: required.length,
    required_detectors_executed: detectorsExecuted,
    files_expected: expected.length,
    files_scanned: filesScanned,
    bytes_scanned: bytesScanned,
    limits,
    coverage: coverageComplete ? 'complete' : 'incomplete',
    result: detectorsExecuted && coverageComplete && findings.length === 0 ? 'PASS' : 'FAIL',
    counts,
    findings,
    errors,
  });
}
