// Q015 metadata-only successor. Entire original scan loop and limits retained.
// Findings bind the exact decoded buffer, never a later path read.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { walkFiles, relOf, SECRET_PATTERNS, MODEL_ENDPOINT_PATTERNS, PROMPT_BODY_PATTERNS } from './scan.mjs';

const TEXT_SUFFIXES = new Set([
  '.md', '.json', '.yaml', '.yml', '.txt', '.go',
  '.mjs', '.js', '.ts', '.sh',
]);

const SCAN_LIMITS = Object.freeze({
  max_entries: 50_000,
  max_files: 10_000,
  max_file_bytes: 8 * 1024 * 1024,
  max_total_bytes: 64 * 1024 * 1024,
  max_findings: 4096,
});

export function scanTreeForByteEvidence(root) {
  const skipPrefixes = [];
  const extraPatterns = [];
  const findings = [];
  let bytesScanned = 0;
  const patterns = [
    ...SECRET_PATTERNS,
    ...MODEL_ENDPOINT_PATTERNS,
    ...PROMPT_BODY_PATTERNS,
    ...extraPatterns,
  ];
  for (const file of walkFiles(root, (f) => TEXT_SUFFIXES.has(path.extname(f).toLowerCase()))) {
    const rel = relOf(root, file);
    if (skipPrefixes.some((p) => rel.startsWith(p))) continue;
    let descriptor;
    let text;
    let rawSHA;
    let rawBytes;
    try {
      descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_CLOEXEC | fs.constants.O_NOFOLLOW);
      const before = fs.fstatSync(descriptor);
      if (!before.isFile() || before.size < 0 || before.size > SCAN_LIMITS.max_file_bytes ||
          before.size > SCAN_LIMITS.max_total_bytes - bytesScanned) {
        throw new Error('hazard scan payload exceeds bounded byte policy');
      }
      const raw = fs.readFileSync(descriptor);
      const after = fs.fstatSync(descriptor);
      if (raw.byteLength !== before.size || after.size !== before.size ||
          after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) {
        throw new Error('hazard scan payload changed while open');
      }
      rawSHA = createHash('sha256').update(raw).digest('hex');
      rawBytes = raw.byteLength;
      text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
      bytesScanned += raw.byteLength;
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
    for (const [pattern, label] of patterns) {
      pattern.lastIndex = 0;
      const match = pattern.exec(text);
      if (match) {
        findings.push({ file: rel, hazard: label, bytes: rawBytes, sha256: rawSHA });
        if (findings.length > SCAN_LIMITS.max_findings) throw new Error('hazard scan exceeds bounded finding policy');
        break;
      }
    }
  }
  return { findings, bytes_scanned: bytesScanned, scan_complete: true };
}
