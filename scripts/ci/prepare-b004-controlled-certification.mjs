#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, realpathSync, renameSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url))
const REPOSITORY_ROOT = resolve(SCRIPT_DIRECTORY, '..', '..')
const CAPABILITY_REGISTRATION = join(REPOSITORY_ROOT, 'docs', 'model-certification', 'harness-01-capabilities.json')
const ISOLATION_IDENTITY = 'AIPT_LINUX_USER_NETNS_SUPERVISOR_V1'
const ISOLATION_REFERENCE = 'aipt-runtime-isolator-go1.26.6-linux-amd64'

function fail(message) {
  process.stderr.write(`prepare-b004-controlled-certification: ${message}\n`)
  process.exit(1)
}

function options(argv) {
  if (argv.length % 2 !== 0) fail('arguments must be key/value pairs')
  const result = new Map()
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index]
    const value = argv[index + 1]
    if (!key.startsWith('--') || value.length === 0 || result.has(key)) fail('invalid or duplicate argument')
    result.set(key, value)
  }
  const required = ['--mode', '--base-evidence', '--output', '--node', '--adapter', '--closure']
  for (const key of required) if (!result.has(key)) fail(`missing ${key}`)
  const mode = result.get('--mode')
  if (mode !== 'remote' && mode !== 'local') fail('--mode must be remote or local')
  for (const key of ['--llama', '--gguf', '--isolator']) {
    if ((mode === 'local') !== result.has(key)) fail(`${key} is required only for local mode`)
  }
  return { mode, get: key => result.get(key) }
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex')
}

function exactFile(path, expected, label) {
  const resolved = realpathSync(path)
  const observed = sha256(resolved)
  if (expected !== undefined && observed !== expected) fail(`${label} digest mismatch`)
  return { path: resolved, sha256: observed }
}

function writePrivateJSON(path, value) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  const temporary = `${path}.new`
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 })
  renameSync(temporary, path)
}

const { mode, get } = options(process.argv.slice(2))
const base = JSON.parse(readFileSync(get('--base-evidence'), 'utf8'))
const capability = JSON.parse(readFileSync(CAPABILITY_REGISTRATION, 'utf8'))
const capabilityFingerprint = sha256(CAPABILITY_REGISTRATION)
const node = exactFile(get('--node'), undefined, 'Node executable')
const adapter = exactFile(get('--adapter'), undefined, 'adapter worker')
const closure = exactFile(get('--closure'), capability.runtime_closure?.sha256, 'Harness runtime closure')
const output = resolve(get('--output'))
const privateRoot = dirname(output)
const sessionWorkingDirectory = join(privateRoot, `${mode}-session-workspace`)
mkdirSync(sessionWorkingDirectory, { recursive: true, mode: 0o700 })

const sampling = {
  ...base.sampling_profile,
  unsupported_parameters: ['temperature', 'top_p'],
  sha256: '',
}
const profile = {
  ...base.model_profile,
  harness_identity: {
    ...base.model_profile.harness_identity,
    capability_fingerprint: capabilityFingerprint,
    runtime_closure_kind: capability.runtime_closure.kind,
    runtime_closure_sha256: closure.sha256,
  },
  sha256: '',
}

let localRuntime
if (mode === 'local') {
  const llama = exactFile(get('--llama'), profile.local_runtime_identity.binary_sha256, 'llama executable')
  const gguf = realpathSync(get('--gguf'))
  const isolator = exactFile(get('--isolator'), undefined, 'runtime isolator')
  profile.local_runtime_identity = {
    ...profile.local_runtime_identity,
    isolation_identity: ISOLATION_IDENTITY,
    isolation_helper_reference: ISOLATION_REFERENCE,
    isolation_helper_sha256: isolator.sha256,
  }
  const localWorkingDirectory = join(privateRoot, 'local-runtime-workspace')
  mkdirSync(localWorkingDirectory, { recursive: true, mode: 0o700 })
  localRuntime = {
    profile_binding: `${profile.profile_id}@${profile.profile_version}`,
    executable_path: llama.path,
    gguf_path: gguf,
    additional_arguments: ['--ctx-size', '8192', '--n-predict', '1024', '--n-gpu-layers', '99'],
    environment: {},
    working_directory: localWorkingDirectory,
    startup_timeout_ms: 300000,
    shutdown_timeout_ms: 30000,
    isolation_executable_path: isolator.path,
    isolation_executable_sha256: isolator.sha256,
    isolation_arguments: [],
  }
}

const environmentAllowlist = mode === 'remote'
  ? ['AIPT_HARNESS_PERSISTENCE_ROOT', 'DEEPSEEK_API_KEY', 'DSH_HOME']
  : ['AIPT_HARNESS_PERSISTENCE_ROOT', 'AIPT_LOCAL_LLAMACPP_ENDPOINT', 'DSH_HOME']
const suffix = mode === 'remote' ? 'REMOTE-DEEPSEEK' : 'LOCAL-LLAMACPP'
const spec = {
  schema: 'aipt.controlled-model-certification-spec/v1',
  certification_id: base.certification.certification_id,
  certification_version: base.certification.certification_version,
  evidence_identity: `AIPT-MVP-B004-${suffix}-CONTROLLED-REAL-02`,
  environment_identity: 'aipt-b004-security-repair-host-20260901',
  sampling_profile: sampling,
  model_profile: profile,
  adapter_executable_path: node.path,
  adapter_executable_sha256: node.sha256,
  adapter_entrypoint_path: adapter.path,
  adapter_entrypoint_sha256: adapter.sha256,
  adapter_working_directory: REPOSITORY_ROOT,
  adapter_startup_timeout_ms: 30000,
  adapter_shutdown_timeout_ms: 10000,
  harness_child: {
    executable_path: node.path,
    executable_sha256: node.sha256,
    arguments: [closure.path],
    argument_file_digests: [{ index: 0, sha256: closure.sha256 }],
    runtime_closure: {
      schema: 'aipt.harness-runtime-closure/v1',
      kind: 'VERIFIED_SINGLE_FILE_DATA_URL_V1',
      entrypoint_argument_index: 0,
      sha256: closure.sha256,
    },
    working_directory: sessionWorkingDirectory,
    environment_allowlist: environmentAllowlist,
    startup_timeout_ms: 30000,
    request_timeout_ms: mode === 'remote' ? 300000 : 600000,
    shutdown_timeout_ms: 5000,
    output_budget: {
      schema: 'aipt.acp-output-budget/v1',
      max_stdout_protocol_bytes: 8388608,
      max_notification_bytes: 4194304,
      max_response_and_notification_bytes: 8388608,
      max_stderr_bytes: 1048576,
    },
  },
  ...(localRuntime === undefined ? {} : { local_runtime: localRuntime }),
}

writePrivateJSON(output, spec)
process.stdout.write(`${JSON.stringify({
  schema: 'aipt.private.controlled-certification-spec-preparation/v1',
  mode,
  capability_fingerprint: capabilityFingerprint,
  runtime_closure_sha256: closure.sha256,
  isolation_helper_sha256: localRuntime?.isolation_executable_sha256,
})}\n`)
