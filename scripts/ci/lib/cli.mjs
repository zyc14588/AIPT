// Shared CLI / runner helpers for B001 validators.
import { spawnSync, execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export function git(repo, args, { check = true } = {}) {
  const cp = spawnSync('git', ['-C', repo, ...args], { encoding: 'utf8' });
  if (check && cp.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${(cp.stderr || '').trim()}`);
  }
  return cp;
}

export function gitOut(repo, args) {
  return git(repo, args).stdout.trim();
}

export function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
        args[key] = argv[i + 1];
        i += 1;
      } else {
        args[key] = true;
      }
    }
  }
  return args;
}

// Run a validator as a standalone script when executed directly:
//   node scripts/ci/validate/<name>.mjs [--repo /path] [extra args]
//
// The caller must pass its own module identity explicitly so the comparison
// uses the CALLING validator's file URL, never this helper's import.meta.url:
//   runAsMain(import.meta.url, '<name>', run);
export function runAsMain(moduleUrl, name, runFn) {
  const isMain =
    process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(moduleUrl);
  if (!isMain) return;
  const args = parseArgs(process.argv.slice(2));
  const ctx = { repo: path.resolve(args.repo || process.cwd()) };
  const report = runFn(ctx, args);
  process.stdout.write(`${JSON.stringify({ schema: 'aipt.public.b001-validator-report/v1', name, ...report }, null, 2)}\n`);
  process.exitCode = report.result === 'PASS' ? 0 : 1;
}

// Expand a git commit tree into a brand-new directory (archive round-trip).
export function expandCommitTree(repo, commit, destDir) {
  execFileSync('bash', [
    '-c',
    'git -C "$1" archive "$2" | tar -x -C "$3"',
    'aipt-ci',
    repo,
    commit,
    destDir,
  ]);
}
