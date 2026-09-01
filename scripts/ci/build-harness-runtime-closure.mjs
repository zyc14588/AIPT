#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const HARNESS_VERSION = '0.1.0-rc.8'
const HARNESS_COMMIT = '141eb6fef83422698aef7a981029e843e8161534'
const EXACT_NODE_VERSION = 'v24.19.0'
const MAX_CLOSURE_BYTES = 64 * 1024 * 1024
const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url))

function fail(message) {
  process.stderr.write(`harness-runtime-closure: ${message}\n`)
  process.exit(1)
}

function argumentsOf(argv) {
  if (argv.length !== 4 || argv[0] !== '--harness-root' || argv[2] !== '--output' ||
      argv[1].length === 0 || argv[3].length === 0) {
    fail('usage: --harness-root <frozen checkout> --output <private artifact>')
  }
  return { harnessRoot: realpathSync(argv[1]), output: resolve(argv[3]) }
}

function command(executable, args, cwd) {
  return execFileSync(executable, args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      PATH: process.env.PATH ?? '/usr/bin:/bin',
      LANG: 'C.UTF-8',
      LC_ALL: 'C.UTF-8',
      TZ: 'UTC',
    },
  }).trim()
}

function validateFrozenHarness(harnessRoot) {
  const manifest = JSON.parse(readFileSync(join(harnessRoot, 'package.json'), 'utf8'))
  if (manifest.version !== HARNESS_VERSION) fail('frozen Harness version mismatch')
  if (command('git', ['rev-parse', 'HEAD'], harnessRoot) !== HARNESS_COMMIT) {
    fail('frozen Harness commit mismatch')
  }
  if (command('git', ['status', '--porcelain=v1'], harnessRoot) !== '') {
    fail('frozen Harness checkout is not clean')
  }
}

function linkPackage(stage, name, target) {
  symlinkSync(target, join(stage, 'node_modules', '@deepseek-ai', name), 'dir')
}

function validateClosure(raw, harnessRoot) {
  if (raw.length < 1 || raw.length > MAX_CLOSURE_BYTES) fail('closure size is outside the governed bound')
  const text = raw.toString('utf8')
  if (text.includes(harnessRoot) || text.includes('/home/') || text.includes('node_modules/.pnpm')) {
    fail('closure retained a private build path')
  }
  if (/\bimport\s*\(/u.test(text) || text.includes('import.meta.url')) {
    fail('closure retained a dynamic import or ambient module base')
  }
  const imports = [...text.matchAll(/\bfrom["']([^"']+)["']/gu)].map(match => match[1])
  if (imports.length === 0 || imports.some(specifier => !specifier.startsWith('node:'))) {
    fail('closure retained a non-builtin static import')
  }
  if (text.split('/proc/self/fd/4').length !== 2) {
    fail('closure does not bind exactly one CommonJS builtin base to its inherited descriptor')
  }
}

const { harnessRoot, output } = argumentsOf(process.argv.slice(2))
if (process.version !== EXACT_NODE_VERSION) fail(`exact Node ${EXACT_NODE_VERSION} is required`)
validateFrozenHarness(harnessRoot)
const stage = mkdtempSync(join(tmpdir(), 'aipt-harness-runtime-closure-'))
try {
  mkdirSync(join(stage, 'node_modules', '@deepseek-ai'), { recursive: true, mode: 0o700 })
  copyFileSync(join(SCRIPT_DIRECTORY, 'harness-runtime-closure.ts'), join(stage, 'entry.ts'))
  copyFileSync(join(SCRIPT_DIRECTORY, 'harness-runtime-closure.config.ts'), join(stage, 'tsdown.config.ts'))
  linkPackage(stage, 'cordis', join(harnessRoot, 'vendor', 'cordis'))
  linkPackage(stage, 'dsh-acp', join(harnessRoot, 'packages', 'acp', 'acp'))
  linkPackage(stage, 'dsh-agent-spine-demo', join(harnessRoot, 'packages', 'examples', 'agent-spine-demo'))
  linkPackage(stage, 'dsh-llm-deepseek', join(harnessRoot, 'packages', 'llm', 'llm-deepseek'))
  symlinkSync(join(harnessRoot, 'node_modules', 'tsdown'), join(stage, 'node_modules', 'tsdown'), 'dir')
  symlinkSync(join(harnessRoot, 'node_modules', 'typescript'), join(stage, 'node_modules', 'typescript'), 'dir')

  try {
    command(process.execPath, [join(harnessRoot, 'node_modules', 'tsdown', 'dist', 'run.mjs'),
      'entry.ts', '--config', 'tsdown.config.ts', '--format', 'esm', '--platform', 'node',
      '--target', 'node24', '--out-dir', 'closure', '--deps.always-bundle', '.*', '--minify',
      '--logLevel', 'warn',
    ], stage)
  } catch {
    fail('closure bundler failed')
  }

  const raw = readFileSync(join(stage, 'closure', 'entry.mjs'))
  validateClosure(raw, harnessRoot)
  mkdirSync(dirname(output), { recursive: true, mode: 0o700 })
  const temporaryOutput = `${output}.new`
  writeFileSync(temporaryOutput, raw, { mode: 0o600 })
  renameSync(temporaryOutput, output)
  process.stdout.write(`${JSON.stringify({
    schema: 'aipt.private.harness-runtime-closure-build/v1',
    kind: 'VERIFIED_SINGLE_FILE_DATA_URL_V1',
    sha256: createHash('sha256').update(raw).digest('hex'),
    bytes: raw.length,
  })}\n`)
} finally {
  rmSync(stage, { recursive: true, force: true })
}
