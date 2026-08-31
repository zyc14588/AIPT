// Shared scanning helpers for B001 validators (Node.js standard library only).
import fs from 'node:fs';
import path from 'node:path';

// Patterns are assembled from fragments so that the validator sources do not
// themselves contain the literal secret/endpoint strings they hunt for.
export const SECRET_PATTERNS = [
  [new RegExp('ghp_' + '[A-Za-z0-9]{20,}'), 'GITHUB_PERSONAL_TOKEN'],
  [new RegExp('github_pat_' + '[A-Za-z0-9_]{20,}'), 'GITHUB_FINE_GRAINED_TOKEN'],
  [new RegExp('sk-' + '[A-Za-z0-9_-]{20,}'), 'API_KEY_LIKE'],
  [new RegExp('AKIA' + '[0-9A-Z]{16}'), 'AWS_ACCESS_KEY'],
  [new RegExp('-----BEGIN ' + '(RSA |EC |OPENSSH )?' + 'PRIVATE KEY-----'), 'PRIVATE_KEY_BLOCK'],
  [new RegExp('/home/' + '[A-Za-z0-9_.-]+/'), 'LINUX_HOME_ABSOLUTE_PATH'],
  [new RegExp('/Users/' + '[A-Za-z0-9_.-]+/'), 'MAC_HOME_ABSOLUTE_PATH'],
  [new RegExp('C:\\\\Users\\\\' + '[^\\\\\\s]+'), 'WINDOWS_USER_ABSOLUTE_PATH'],
];

export const MODEL_ENDPOINT_PATTERNS = [
  [new RegExp('api[.]' + 'deepseek[.]' + 'com'), 'DEEPSEEK_ENDPOINT'],
  [new RegExp('api[.]' + 'openai[.]' + 'com'), 'OPENAI_ENDPOINT'],
  [new RegExp('api[.]' + 'anthropic[.]' + 'com'), 'ANTHROPIC_ENDPOINT'],
  [new RegExp('api[.]' + 'moonshot[.]' + 'cn'), 'MOONSHOT_ENDPOINT'],
  [new RegExp('openrouter[.]' + 'ai'), 'OPENROUTER_ENDPOINT'],
  [new RegExp('generativelanguage[.]' + 'googleapis[.]' + 'com'), 'GOOGLE_GENAI_ENDPOINT'],
  [new RegExp('gemini[.]' + 'googleapis[.]' + 'com'), 'GEMINI_ENDPOINT'],
];

// Markers of pasted conversational prompt transcripts (public prompt bodies
// are forbidden in the public repository).
export const PROMPT_BODY_PATTERNS = [
  // Assembled from fragments so the scanner source itself stays scan-safe.
  [new RegExp('<' + '<' + 'SYS' + '>' + '>'), 'LLAMA_SYS_PROMPT_MARKER'],
  [new RegExp('^\\s*(system|user|assistant)\\s*:\\s', 'mi'), 'CHAT_TRANSCRIPT_MARKER'],
  [new RegExp('^\\s*(System|User|Assistant)\\s*:\\s', 'm'), 'CHAT_TRANSCRIPT_MARKER_EN'],
];

// Public text and executable script suffixes covered by the hygiene scan.
// .mjs/.js/.ts/.sh cover the public CI scripts themselves so a credential-like
// value or model endpoint in an executable script cannot slip past the gate.
const TEXT_SUFFIXES = new Set([
  '.md', '.json', '.yaml', '.yml', '.txt', '.go',
  '.mjs', '.js', '.ts', '.sh',
]);

const SKIPPED_DIRS = new Set(['.git', 'node_modules', '.b001-toolcache']);
const SCAN_LIMITS = Object.freeze({
  max_entries: 50_000,
  max_files: 10_000,
  max_file_bytes: 8 * 1024 * 1024,
  max_total_bytes: 64 * 1024 * 1024,
  max_findings: 4096,
});

export function walkFiles(root, filter) {
  const out = [];
  const stack = [root];
  let entriesVisited = 0;
  while (stack.length > 0) {
    const dir = stack.pop();
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      entriesVisited += 1;
      if (entriesVisited > SCAN_LIMITS.max_entries) throw new Error('scan traversal exceeds bounded entry policy');
      const full = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error(`scan traversal rejects symbolic link: ${relOf(root, full)}`);
      } else if (entry.isDirectory()) {
        if (!SKIPPED_DIRS.has(entry.name)) stack.push(full);
      } else if (entry.isFile()) {
        if (!filter || filter(full)) {
          out.push(full);
          if (out.length > SCAN_LIMITS.max_files) throw new Error('scan traversal exceeds bounded file policy');
        }
      } else {
        throw new Error(`scan traversal rejects unsupported node: ${relOf(root, full)}`);
      }
    }
  }
  return out.sort();
}

export function relOf(root, file) {
  return path.relative(root, file).split(path.sep).join('/');
}

export function stripFencedCode(text) {
  return text.replace(/```[\s\S]*?```/g, '');
}

// Collect relative Markdown links and verify they resolve inside `root`.
export function collectMarkdownLinkIssues(root, { skipPrefixes = [] } = {}) {
  const issues = [];
  let mdCount = 0;
  for (const file of walkFiles(root, (f) => f.endsWith('.md'))) {
    const rel = relOf(root, file);
    if (skipPrefixes.some((p) => rel.startsWith(p))) continue;
    mdCount += 1;
    let text;
    try {
      text = stripFencedCode(fs.readFileSync(file, 'utf8'));
    } catch {
      issues.push({ file: rel, target: '<unreadable>', reason: 'UNREADABLE' });
      continue;
    }
    for (const m of text.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g)) {
      let target = m[1].trim();
      if (
        !target ||
        target.startsWith('#') ||
        target.startsWith('http://') ||
        target.startsWith('https://') ||
        target.startsWith('mailto:')
      ) {
        continue;
      }
      if (target.includes(' ') && !target.startsWith('<')) {
        target = target.split(' ', 1)[0];
      }
      target = target.replace(/^</, '').replace(/>$/, '');
      try {
        target = decodeURIComponent(target.split('#')[0].split('?')[0]);
      } catch {
        issues.push({ file: rel, target, reason: 'BAD_URI_ENCODING' });
        continue;
      }
      if (!target) continue;
      const resolved = target.startsWith('/')
        ? path.join(root, target.slice(1))
        : path.resolve(path.dirname(file), target);
      const relResolved = path.relative(root, resolved);
      if (relResolved.startsWith('..') || path.isAbsolute(relResolved)) {
        issues.push({ file: rel, target, reason: 'ESCAPES_REPOSITORY' });
        continue;
      }
      if (!fs.existsSync(resolved)) {
        issues.push({ file: rel, target, reason: 'MISSING' });
      }
    }
  }
  return { mdCount, issues };
}

// Scan text and executable script files under `root` for secret / endpoint /
// prompt-body hazards. Every pattern is assembled from fragments so the
// scanner sources can be scanned themselves without a blanket skip:
// callers must NOT exempt script directories (see the .mjs negative
// regression in tree-integrity.mjs).
export function scanTreeForHazards(root, { skipPrefixes = [], extraPatterns = [] } = {}) {
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
      text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
      bytesScanned += raw.byteLength;
    } finally {
      if (descriptor !== undefined) fs.closeSync(descriptor);
    }
    for (const [pattern, label] of patterns) {
      pattern.lastIndex = 0;
      const match = pattern.exec(text);
      if (match) {
        findings.push({ file: rel, hazard: label });
        if (findings.length > SCAN_LIMITS.max_findings) throw new Error('hazard scan exceeds bounded finding policy');
        break;
      }
    }
  }
  return findings;
}

export function chmodTreeReadOnly(root) {
  const all = [];
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      all.push(full);
      if (entry.isDirectory()) stack.push(full);
    }
  }
  // Children first so directories are traversable during the pass.
  for (const full of all.reverse()) {
    const st = fs.statSync(full);
    fs.chmodSync(full, st.mode & ~0o222);
  }
}

export function verifyTreeReadOnly(root) {
  const writable = [];
  const stack = [root];
  while (stack.length > 0) {
    const dir = stack.pop();
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if ((fs.statSync(full).mode & 0o222) !== 0) {
        writable.push(relOf(root, full));
      }
      if (entry.isDirectory()) stack.push(full);
    }
  }
  return writable;
}
