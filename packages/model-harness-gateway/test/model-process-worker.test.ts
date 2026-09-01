import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { closeSync, openSync } from 'node:fs';
import { mkdtemp, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { once } from 'node:events';
import { createInterface, type Interface } from 'node:readline';
import { afterEach, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const worker = join(packageRoot, 'src/model-process-worker.ts');
const fixture = join(packageRoot, 'test/fixture-acp-worker.ts');
const fingerprint = '1'.repeat(64);
const harnessIdentity = 'deepseek-harness@0.1.0-rc.8+141eb6fef83422698aef7a981029e843e8161534';
let root: string | undefined;
let child: ChildProcessWithoutNullStreams | undefined;
let lines: Interface | undefined;

async function shutdownCurrentWorker(): Promise<void> {
  const current = child;
  const currentLines = lines;
  lines = undefined;
  child = undefined;
  currentLines?.close();
  if (current === undefined) return;
  current.stdin.end();
  const settled = new Promise<void>((resolveExit) => {
    let done = false;
    const settle = (): void => {
      if (done) return;
      done = true;
      resolveExit();
    };
    current.once('exit', settle);
    current.once('close', settle);
    current.once('error', settle);
    if (current.exitCode !== null || current.signalCode !== null) settle();
  });
  const bounded = async (milliseconds: number): Promise<boolean> => {
    let timer: NodeJS.Timeout | undefined;
    const timedOut = new Promise<false>((resolveTimeout) => {
      timer = setTimeout(() => resolveTimeout(false), milliseconds);
    });
    const result = await Promise.race([settled.then(() => true), timedOut]);
    if (timer !== undefined) clearTimeout(timer);
    return result;
  };
  if (await bounded(1_500)) return;
  if (Number.isSafeInteger(current.pid) && (current.pid as number) > 1) current.kill('SIGTERM');
  if (await bounded(500)) return;
  if (Number.isSafeInteger(current.pid) && (current.pid as number) > 1) current.kill('SIGKILL');
  await bounded(500);
}

interface OutputBudget {
  schema: 'aipt.acp-output-budget/v1';
  max_stdout_protocol_bytes: number;
  max_notification_bytes: number;
  max_response_and_notification_bytes: number;
  max_stderr_bytes: number;
}

function governedSamplingProfile(): Record<string, unknown> {
  const value = {
    schema: 'aipt.sampling-profile/v1',
    sampling_id: 'sampling-remote',
    sampling_version: '1.0.0',
    temperature: 0,
    top_p: 1,
    max_output_tokens: 1024,
    max_context_tokens: 8192,
    applied_parameters: ['max_context_tokens', 'max_output_tokens'],
    unsupported_parameters: ['temperature', 'top_p'],
    sha256: '',
  };
  return {
    ...value,
    sha256: createHash('sha256').update(JSON.stringify(value), 'utf8').digest('hex'),
  };
}

const defaultOutputBudget: OutputBudget = {
  schema: 'aipt.acp-output-budget/v1',
  max_stdout_protocol_bytes: 8 * 1024 * 1024,
  max_notification_bytes: 4 * 1024 * 1024,
  max_response_and_notification_bytes: 8 * 1024 * 1024,
  max_stderr_bytes: 1024 * 1024,
};

async function digest(path: string): Promise<string> {
  return createHash('sha256').update(await readFile(path)).digest('hex');
}

async function boot(
  extraEnvironment: NodeJS.ProcessEnv = {},
  budget: Partial<OutputBudget> = {},
  requestTimeoutMs = 5_000,
): Promise<{ childEntrypoint: string; next: () => Promise<Record<string, unknown>> }> {
  // Several top-level cases contain sequential subtests. Retire the previous
  // worker before replacing the shared fixture handle so a passed subtest can
  // never leave a hidden child keeping the full suite alive.
  await shutdownCurrentWorker();
  root = await mkdtemp(join(tmpdir(), 'aipt-model-gateway-'));
  const childEntrypoint = join(root, 'verified-acp-runtime.ts');
  await writeFile(childEntrypoint, await readFile(fixture), { mode: 0o600 });
  const route = {
    schema: 'aipt.harness-route/v1',
    profile_binding: 'gm-remote@1.0.0',
    sampling_binding: 'sampling-remote@1.0.0',
    backend_kind: 'REMOTE_DEEPSEEK',
    provider_identity: 'deepseek-official',
    model_id: 'deepseek-v4-pro',
    harness_identity: harnessIdentity,
    harness_protocol_identity: 'agent-client-protocol',
    harness_protocol_version: '1',
    capability_fingerprint: fingerprint,
    structured_output_mode: 'PROMPTED',
    tool_call_mode: 'DISABLED',
    session_working_directory: root,
    sampling_profile: governedSamplingProfile(),
    child: {
      executable_path: process.execPath,
      executable_sha256: await digest(process.execPath),
      arguments: [childEntrypoint],
      argument_file_digests: [{ index: 0, sha256: await digest(childEntrypoint) }],
      runtime_closure: {
        schema: 'aipt.harness-runtime-closure/v1',
        kind: 'VERIFIED_SINGLE_FILE_DATA_URL_V1',
        entrypoint_argument_index: 0,
        sha256: await digest(childEntrypoint),
      },
      working_directory: root,
      environment_allowlist: [
        'LANG', 'TZ', 'AIPT_FIXTURE_HANG', 'AIPT_FIXTURE_NOISE_COUNT', 'AIPT_FIXTURE_NOISE_BYTES',
        'AIPT_FIXTURE_STARTUP_NOISE_BYTES', 'AIPT_FIXTURE_OVERSIZED_FRAME', 'AIPT_FIXTURE_STDERR_BYTES',
        'AIPT_FIXTURE_BOM_INITIALIZE', 'AIPT_FIXTURE_UNTERMINATED_BYTES',
        'AIPT_FIXTURE_RESPONSE_PADDING_BYTES', 'AIPT_FIXTURE_BOM_STARTUP_NOTIFICATION',
        'AIPT_FIXTURE_ID_BEARING_UPDATE', 'AIPT_FIXTURE_TRAILING_NOISE_COUNT',
        'AIPT_FIXTURE_TRAILING_NOISE_BYTES', 'AIPT_FIXTURE_TRAILING_STDERR_BYTES',
        'AIPT_FIXTURE_INVALID_INITIALIZE',
        'AIPT_FIXTURE_PROMPT_ERROR',
        'AIPT_FIXTURE_ACTIVE_OUTPUT_BYTES',
        'AIPT_FIXTURE_FRAGMENT_BYTES',
      ],
      startup_timeout_ms: 5_000,
      request_timeout_ms: requestTimeoutMs,
      shutdown_timeout_ms: 1_000,
      output_budget: { ...defaultOutputBudget, ...budget },
    },
  };
  const routePath = join(root, 'route.json');
  await writeFile(routePath, JSON.stringify(route));
  const routeFD = openSync(routePath, 'r');
  const executableFD = openSync(process.execPath, 'r');
  const childEntrypointFD = openSync(childEntrypoint, 'r');
  try {
    child = spawn(process.execPath, [worker], {
      cwd: packageRoot,
      env: { LANG: 'C.UTF-8', TZ: 'UTC', AIPT_HARNESS_ROUTE_FD: '3', ...extraEnvironment },
      stdio: ['pipe', 'pipe', 'pipe', routeFD, executableFD, childEntrypointFD],
    }) as ChildProcessWithoutNullStreams;
  } finally {
    closeSync(routeFD);
    closeSync(executableFD);
    closeSync(childEntrypointFD);
  }
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk: string) => {
    stderr += chunk;
  });
  child.on('exit', (code, signal) => {
    stderr += `[outer-worker-exit code=${String(code)} signal=${String(signal)}]`;
  });
  child.on('error', () => {
    stderr += '[outer-worker-spawn-error]';
  });
  lines = createInterface({ input: child.stdout });
  const queue: Record<string, unknown>[] = [];
  const waiters: ((value: Record<string, unknown>) => void)[] = [];
  lines.on('line', (line) => {
    const value = JSON.parse(line) as Record<string, unknown>;
    const waiter = waiters.shift();
    if (waiter) waiter(value); else queue.push(value);
  });
  return {
    childEntrypoint,
    next: () => {
      const value = queue.shift();
      if (value) return Promise.resolve(value);
      return new Promise<Record<string, unknown>>((resolveNext, reject) => {
        const timer = setTimeout(() => {
          reject(new Error(`worker response timeout; exit=${child?.exitCode ?? 'live'} stderr=${stderr}`));
        }, 8_000);
        waiters.push((response) => {
          clearTimeout(timer);
          resolveNext(response);
        });
      });
    },
  };
}

async function waitForHeldFile(pid: number, path: string): Promise<void> {
  const expected = await stat(path);
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    for (const name of await readdir(`/proc/${pid}/fd`)) {
      try {
        const observed = await stat(`/proc/${pid}/fd/${name}`);
        if (observed.dev === expected.dev && observed.ino === expected.ino) return;
      } catch {
        // Descriptor tables can change while they are inspected.
      }
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 10));
  }
  throw new Error('outer worker did not retain the verified Harness runtime file object');
}

async function waitForNoDirectChildren(pid: number): Promise<void> {
  const children = `/proc/${pid}/task/${pid}/children`;
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    try {
      if ((await readFile(children, 'utf8')).trim() === '') return;
    } catch {
      return;
    }
    await new Promise((resolveWait) => setTimeout(resolveWait, 10));
  }
  throw new Error('outer worker returned before its operation-scoped child was retired');
}

function send(value: unknown): void {
  child!.stdin.write(`${JSON.stringify(value)}\n`);
}

async function sendFragmented(value: unknown, fragmentBytes: number): Promise<void> {
  const frame = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  for (let offset = 0; offset < frame.length; offset += fragmentBytes) {
    if (!child!.stdin.write(frame.subarray(offset, Math.min(offset + fragmentBytes, frame.length)))) {
      await once(child!.stdin, 'drain');
    }
    await new Promise<void>((resolveTurn) => setImmediate(resolveTurn));
  }
}

function invocationRequest(id: string): Record<string, unknown> {
  const context = Buffer.from(JSON.stringify({ schema: 'aipt.prepared-context/v1' })).toString('base64');
  return {
    jsonrpc: '2.0', id, protocol_version: '1', method: 'aipt.model.invoke',
    params: {
      schema: 'aipt.harness-agent-request/v1', protocol_version: '1', request_id: id,
      profile_binding: 'gm-remote@1.0.0', sampling_binding: 'sampling-remote@1.0.0',
      expected_model_id: 'deepseek-v4-pro', harness_identity: harnessIdentity,
      backend_kind: 'REMOTE_DEEPSEEK', provider_identity: 'deepseek-official',
      structured_output_mode: 'PROMPTED', tool_call_mode: 'DISABLED', sampling_profile: governedSamplingProfile(),
      session: { session_id: `session-${id}` },
      invocation: {
        invocation_id: id, run_id: 'run-1', seat_id: 'GM',
        session_id: `session-${id}`, kind: 'ORIGINAL', attempt: 1,
      },
      prepared_context: context, context_reduction: {}, request_sha256: '4'.repeat(64),
    },
  };
}

function noiseNotificationBytes(contentBytes: number): number {
  return Buffer.byteLength(`${JSON.stringify({
    jsonrpc: '2.0', method: 'session/update',
    params: {
      sessionId: 'unrelated-0',
      update: {
        sessionUpdate: 'agent_message_chunk',
        content: { type: 'text', text: 'x'.repeat(contentBytes) },
      },
    },
  })}\n`, 'utf8');
}

function initializeResponseBytes(): number {
  return Buffer.byteLength(`${JSON.stringify({
    jsonrpc: '2.0', id: '1',
    result: {
      protocolVersion: 1,
      agentCapabilities: { promptCapabilities: { image: false, audio: false, embeddedContext: false } },
    },
  })}\n`, 'utf8');
}

afterEach(async () => {
  await shutdownCurrentWorker();
  if (root) await rm(root, { recursive: true, force: true });
  root = undefined;
});

test('verified Harness runtime pathname replacement cannot change the launched closure', async () => {
  const runtime = await boot();
  assert.ok(child?.pid && child.pid > 1);
  await waitForHeldFile(child.pid, runtime.childEntrypoint);
  await rename(runtime.childEntrypoint, `${runtime.childEntrypoint}.verified`);
  await writeFile(runtime.childEntrypoint, 'process.exit(97);\n', { mode: 0o600 });
  send({
    jsonrpc: '2.0', id: 'held-route-probe', protocol_version: '1', method: 'aipt.model.probe',
    params: {
      profile_binding: 'gm-remote@1.0.0', expected_model_id: 'deepseek-v4-pro',
      harness_identity: harnessIdentity, protocol_identity: 'agent-client-protocol',
      protocol_version: '1', capability_fingerprint: fingerprint,
    },
  });
  const probe = await runtime.next();
  assert.equal(probe.id, 'held-route-probe');
  assert.equal((probe.result as Record<string, unknown>).route_available, true, JSON.stringify(probe));
});

test('probe and invocation traverse the additive adapter and ACP child', async () => {
  const { next } = await boot();
  send({
    jsonrpc: '2.0', id: 'probe', protocol_version: '1', method: 'aipt.model.probe',
    params: {
      profile_binding: 'gm-remote@1.0.0', expected_model_id: 'deepseek-v4-pro',
      harness_identity: harnessIdentity, protocol_identity: 'agent-client-protocol',
      protocol_version: '1', capability_fingerprint: fingerprint,
    },
  });
  const probe = await next();
  assert.equal(probe.id, 'probe');
  assert.equal((probe.result as Record<string, unknown>).route_available, true);

  const context = Buffer.from(JSON.stringify({ schema: 'aipt.prepared-context/v1' })).toString('base64');
  send({
    jsonrpc: '2.0', id: 'invoke', protocol_version: '1', method: 'aipt.model.invoke',
    params: {
      schema: 'aipt.harness-agent-request/v1', protocol_version: '1', request_id: 'invocation-1',
      profile_binding: 'gm-remote@1.0.0', sampling_binding: 'sampling-remote@1.0.0',
      expected_model_id: 'deepseek-v4-pro', harness_identity: harnessIdentity,
      backend_kind: 'REMOTE_DEEPSEEK', provider_identity: 'deepseek-official',
      structured_output_mode: 'PROMPTED', tool_call_mode: 'DISABLED', sampling_profile: governedSamplingProfile(),
      session: { session_id: 'session-1' },
      invocation: {
        invocation_id: 'invocation-1', run_id: 'run-1', seat_id: 'GM', session_id: 'session-1',
        kind: 'ORIGINAL', attempt: 1,
      },
      prepared_context: context, context_reduction: {}, request_sha256: '2'.repeat(64),
    },
  });
  const invocation = await next();
  assert.equal(invocation.id, 'invoke');
  assert.ok(invocation.result, JSON.stringify(invocation));
  const result = invocation.result as Record<string, unknown>;
  const response = JSON.parse(Buffer.from(String(result.raw_response), 'base64').toString('utf8')) as Record<string, unknown>;
  const structured = JSON.parse(Buffer.from(String(result.structured_response), 'base64').toString('utf8')) as Record<string, unknown>;
  assert.deepEqual(structured, response);
  assert.equal(response.schema, 'aipt.agent-response/v1');
  assert.equal(response.invocation_id, 'invocation-1');
  assert.equal((response.metadata as Record<string, unknown>).protocol_version, 'v1');
  assert.equal(result.observed_model_id, 'deepseek-v4-pro');
  const sampling = governedSamplingProfile();
  assert.equal(result.requested_sampling_sha256, sampling.sha256);
  assert.deepEqual(result.unsupported_sampling_parameters, ['temperature', 'top_p']);
  assert.match(String(result.backend_serialized_request_sha256), /^[0-9a-f]{64}$/u);
  assert.deepEqual(result.effective_sampling_projection, {
    schema: 'aipt.effective-sampling-projection/v1',
    enforcement_identity: 'AIPT_ACP_CONSERVATIVE_UTF8_BYTE_BUDGET_V1',
    applied_parameters: ['max_context_tokens', 'max_output_tokens'],
    unsupported_parameters: ['temperature', 'top_p'],
    max_context_tokens: 8192,
    max_output_tokens: 1024,
    context_utf8_byte_ceiling: 8192,
    output_utf8_byte_ceiling: 1024,
  });
});

test('fragmented outer requests and ACP child frames preserve protocol semantics', async () => {
  const { next } = await boot({ AIPT_FIXTURE_FRAGMENT_BYTES: '7' });
  await sendFragmented({
    jsonrpc: '2.0', id: 'fragmented-probe', protocol_version: '1', method: 'aipt.model.probe',
    params: {
      profile_binding: 'gm-remote@1.0.0', expected_model_id: 'deepseek-v4-pro',
      harness_identity: harnessIdentity, protocol_identity: 'agent-client-protocol',
      protocol_version: '1', capability_fingerprint: fingerprint,
    },
  }, 5);
  const response = await next();
  assert.equal(response.id, 'fragmented-probe');
  assert.equal((response.result as Record<string, unknown>).route_available, true, JSON.stringify(response));
});

test('partial Harness initialization failure is rejected and the spawned child is retired', async () => {
  const { next } = await boot({ AIPT_FIXTURE_INVALID_INITIALIZE: '1' });
  send({
    jsonrpc: '2.0', id: 'invalid-initialize', protocol_version: '1', method: 'aipt.model.probe',
    params: {
      profile_binding: 'gm-remote@1.0.0', expected_model_id: 'deepseek-v4-pro',
      harness_identity: harnessIdentity, protocol_identity: 'agent-client-protocol',
      protocol_version: '1', capability_fingerprint: fingerprint,
    },
  });
  const response = await next();
  assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_IDENTITY_MISMATCH');
  assert.ok(child?.pid && child.pid > 1);
  await waitForNoDirectChildren(child.pid);
});

test('an inner ACP request timeout retires the operation-scoped child before returning the error', async () => {
  const { next } = await boot({ AIPT_FIXTURE_HANG: '1' }, {}, 50);
  send(invocationRequest('inner-timeout'));
  const response = await next();
  assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_TIMEOUT');
  assert.ok(child?.pid && child.pid > 1);
  await waitForNoDirectChildren(child.pid);
});

test('an inner ACP error retires the operation-scoped child before returning the error', async () => {
  const { next } = await boot({ AIPT_FIXTURE_PROMPT_ERROR: '1' });
  send(invocationRequest('inner-error'));
  const response = await next();
  assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_MODEL_REQUEST_FAILED');
  assert.ok(child?.pid && child.pid > 1);
  await waitForNoDirectChildren(child.pid);
});

test('sampling profile drift and silently claimed ACP parameters fail closed', async () => {
  const { next } = await boot();
  const drifted = invocationRequest('sampling-drift');
  const params = drifted.params as Record<string, unknown>;
  params.sampling_profile = { ...governedSamplingProfile(), temperature: 0.7 };
  send(drifted);
  const response = await next();
  assert.equal(response.id, 'sampling-drift');
  assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_IDENTITY_MISMATCH');
  assert.equal(response.result, undefined);
});

test('identity mismatch fails closed without starting an alternate model', async () => {
  const { next } = await boot();
  send({
    jsonrpc: '2.0', id: 'wrong-model', protocol_version: '1', method: 'aipt.model.probe',
    params: {
      profile_binding: 'gm-remote@1.0.0', expected_model_id: 'latest',
      harness_identity: harnessIdentity, protocol_identity: 'agent-client-protocol',
      protocol_version: '1', capability_fingerprint: fingerprint,
    },
  });
  const response = await next();
  assert.equal(response.id, 'wrong-model');
  assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_IDENTITY_MISMATCH');
});

test('timeout cancellation reaches ACP and no late invocation result is accepted', async () => {
  const { next } = await boot({ AIPT_FIXTURE_HANG: '1' });
  const context = Buffer.from(JSON.stringify({ schema: 'aipt.prepared-context/v1' })).toString('base64');
  send({
    jsonrpc: '2.0', id: 'invoke-hanging', protocol_version: '1', method: 'aipt.model.invoke',
    params: {
      schema: 'aipt.harness-agent-request/v1', protocol_version: '1', request_id: 'invocation-hanging',
      profile_binding: 'gm-remote@1.0.0', sampling_binding: 'sampling-remote@1.0.0',
      expected_model_id: 'deepseek-v4-pro', harness_identity: harnessIdentity,
      backend_kind: 'REMOTE_DEEPSEEK', provider_identity: 'deepseek-official',
      structured_output_mode: 'PROMPTED', tool_call_mode: 'DISABLED', sampling_profile: governedSamplingProfile(),
      session: { session_id: 'session-hanging' },
      invocation: {
        invocation_id: 'invocation-hanging', run_id: 'run-1', seat_id: 'GM',
        session_id: 'session-hanging', kind: 'ORIGINAL', attempt: 1,
      },
      prepared_context: context, context_reduction: {}, request_sha256: '3'.repeat(64),
    },
  });
  await new Promise((resolveWait) => setTimeout(resolveWait, 50));
  send({
    jsonrpc: '2.0', id: 'cancel-hanging', protocol_version: '1', method: 'aipt.model.cancel',
    params: { session_id: 'session-hanging' },
  });
  const responses = [await next(), await next()];
  const cancellation = responses.find((response) => response.id === 'cancel-hanging');
  const invocation = responses.find((response) => response.id === 'invoke-hanging');
  assert.ok(cancellation?.result);
  assert.equal((invocation?.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_CANCELLED');
});

test('malformed outer frame fails closed with a stable public diagnostic', async () => {
  const { next } = await boot();
  child!.stdin.write('{malformed}\n');
  const response = await next();
  assert.equal(response.id, 'unknown');
  assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_FRAME_INVALID');
});

test('many small valid ACP frames fail closed at the response-notification aggregate limit', async () => {
  const { next } = await boot({
    AIPT_FIXTURE_NOISE_COUNT: '256',
    AIPT_FIXTURE_NOISE_BYTES: '256',
  }, {
    max_notification_bytes: 8 * 1024 * 1024,
    max_response_and_notification_bytes: 16 * 1024,
  });
  send(invocationRequest('aggregate-reproduction'));
  const invocation = await next();
  assert.equal(invocation.id, 'aggregate-reproduction');
  assert.equal((invocation.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_OUTPUT_LIMIT');
  assert.equal(invocation.result, undefined);
});

test('active session output is charged incrementally before accumulation', async () => {
  const { next } = await boot({ AIPT_FIXTURE_ACTIVE_OUTPUT_BYTES: '1025' });
  send(invocationRequest('incremental-active-output-budget'));
  const invocation = await next();
  assert.equal(invocation.id, 'incremental-active-output-budget');
  assert.equal((invocation.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_OUTPUT_LIMIT');
  assert.equal(invocation.result, undefined);
});

test('id-bearing session/update cannot bypass notification category budgets', async (t) => {
  await t.test('the frame is charged to the notification budget before semantic handling', async () => {
    const { next } = await boot({ AIPT_FIXTURE_ID_BEARING_UPDATE: '1' }, {
      max_notification_bytes: 1,
    });
    send(invocationRequest('id-bearing-update-budget'));
    const invocation = await next();
    assert.equal(invocation.id, 'id-bearing-update-budget');
    assert.equal((invocation.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_OUTPUT_LIMIT');
    assert.equal(invocation.result, undefined);
  });
  await t.test('the invalid JSON-RPC request shape is rejected with no partial result', async () => {
    const { next } = await boot({ AIPT_FIXTURE_ID_BEARING_UPDATE: '1' });
    send(invocationRequest('id-bearing-update-shape'));
    const invocation = await next();
    assert.equal(invocation.id, 'id-bearing-update-shape');
    assert.equal((invocation.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_FRAME_INVALID');
    assert.equal(invocation.result, undefined);
  });
});

test('notification byte boundary passes exactly and boundary plus one rejects', async (t) => {
  const contentBytes = 256;
  const exactBoundary = noiseNotificationBytes(contentBytes);
  await t.test('exact boundary PASS', async () => {
    const { next } = await boot({
      AIPT_FIXTURE_STARTUP_NOISE_BYTES: String(contentBytes),
    }, { max_notification_bytes: exactBoundary });
    send({
      jsonrpc: '2.0', id: 'notification-boundary', protocol_version: '1', method: 'aipt.model.probe',
      params: {
        profile_binding: 'gm-remote@1.0.0', expected_model_id: 'deepseek-v4-pro',
        harness_identity: harnessIdentity, protocol_identity: 'agent-client-protocol',
        protocol_version: '1', capability_fingerprint: fingerprint,
      },
    });
    const response = await next();
    assert.ok(response.result);
  });
  await t.test('boundary plus one REJECT', async () => {
    const { next } = await boot({
      AIPT_FIXTURE_STARTUP_NOISE_BYTES: String(contentBytes + 1),
    }, { max_notification_bytes: exactBoundary });
    send({
      jsonrpc: '2.0', id: 'notification-boundary-plus-one', protocol_version: '1', method: 'aipt.model.probe',
      params: {
        profile_binding: 'gm-remote@1.0.0', expected_model_id: 'deepseek-v4-pro',
        harness_identity: harnessIdentity, protocol_identity: 'agent-client-protocol',
        protocol_version: '1', capability_fingerprint: fingerprint,
      },
    });
    const response = await next();
    assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_OUTPUT_LIMIT');
    assert.equal(response.result, undefined);
  });
});

test('total stdout protocol byte boundary passes exactly and boundary plus one rejects', async (t) => {
  const exactBoundary = initializeResponseBytes();
  const probe = {
    jsonrpc: '2.0', id: 'probe-boundary', protocol_version: '1', method: 'aipt.model.probe',
    params: {
      profile_binding: 'gm-remote@1.0.0', expected_model_id: 'deepseek-v4-pro',
      harness_identity: harnessIdentity, protocol_identity: 'agent-client-protocol',
      protocol_version: '1', capability_fingerprint: fingerprint,
    },
  };
  await t.test('exact boundary PASS', async () => {
    const { next } = await boot({}, { max_stdout_protocol_bytes: exactBoundary });
    send(probe);
    const response = await next();
    assert.ok(response.result);
  });
  await t.test('boundary plus one REJECT', async () => {
    const { next } = await boot({}, { max_stdout_protocol_bytes: exactBoundary - 1 });
    send({ ...probe, id: 'probe-boundary-plus-one' });
    const response = await next();
    assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_OUTPUT_LIMIT');
  });
});

test('stdout budget charges raw BOM and unterminated bytes before parsing', async (t) => {
  await t.test('UTF-8 BOM bytes are charged', async () => {
    const { next } = await boot({ AIPT_FIXTURE_BOM_INITIALIZE: '1' }, {
      max_stdout_protocol_bytes: initializeResponseBytes(),
    });
    send({
      jsonrpc: '2.0', id: 'bom-raw-budget', protocol_version: '1', method: 'aipt.model.probe',
      params: {
        profile_binding: 'gm-remote@1.0.0', expected_model_id: 'deepseek-v4-pro',
        harness_identity: harnessIdentity, protocol_identity: 'agent-client-protocol',
        protocol_version: '1', capability_fingerprint: fingerprint,
      },
    });
    const response = await next();
    assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_OUTPUT_LIMIT');
  });
  await t.test('response and notification budgets charge raw BOM bytes', async () => {
    const contentBytes = 256;
    const { next } = await boot({
      AIPT_FIXTURE_STARTUP_NOISE_BYTES: String(contentBytes),
      AIPT_FIXTURE_BOM_STARTUP_NOTIFICATION: '1',
    }, {
      max_notification_bytes: noiseNotificationBytes(contentBytes),
    });
    send({
      jsonrpc: '2.0', id: 'bom-notification-budget', protocol_version: '1', method: 'aipt.model.probe',
      params: {
        profile_binding: 'gm-remote@1.0.0', expected_model_id: 'deepseek-v4-pro',
        harness_identity: harnessIdentity, protocol_identity: 'agent-client-protocol',
        protocol_version: '1', capability_fingerprint: fingerprint,
      },
    });
    const response = await next();
    assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_OUTPUT_LIMIT');
  });
  await t.test('unterminated bytes are charged immediately', async () => {
    const { next } = await boot({ AIPT_FIXTURE_UNTERMINATED_BYTES: '257' }, {
      max_stdout_protocol_bytes: 256,
    });
    send({
      jsonrpc: '2.0', id: 'unterminated-raw-budget', protocol_version: '1', method: 'aipt.model.probe',
      params: {
        profile_binding: 'gm-remote@1.0.0', expected_model_id: 'deepseek-v4-pro',
        harness_identity: harnessIdentity, protocol_identity: 'agent-client-protocol',
        protocol_version: '1', capability_fingerprint: fingerprint,
      },
    });
    const response = await next();
    assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_OUTPUT_LIMIT');
  });
});

test('single oversized ACP frame rejects without partial semantics', async () => {
  const { next } = await boot({ AIPT_FIXTURE_OVERSIZED_FRAME: '1' });
  send(invocationRequest('single-oversized-frame'));
  const response = await next();
  assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_FRAME_INVALID');
  assert.equal(response.result, undefined);
});

test('stderr has an independent exact byte budget', async (t) => {
  await t.test('exact boundary PASS', async () => {
    const { next } = await boot({ AIPT_FIXTURE_STDERR_BYTES: '256' }, { max_stderr_bytes: 256 });
    send(invocationRequest('stderr-boundary'));
    const response = await next();
    assert.ok(response.result);
  });
  await t.test('boundary plus one REJECT', async () => {
    const { next } = await boot({ AIPT_FIXTURE_STDERR_BYTES: '257' }, { max_stderr_bytes: 256 });
    send(invocationRequest('stderr-boundary-plus-one'));
    const response = await next();
    assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_OUTPUT_LIMIT');
  });
});

test('outer success waits for the complete ACP child lifetime budget verdict', async (t) => {
  const trailing = {
    AIPT_FIXTURE_TRAILING_NOISE_COUNT: '1',
    AIPT_FIXTURE_TRAILING_NOISE_BYTES: '4096',
  };
  await t.test('trailing total stdout overflow REJECTS with no result', async () => {
    const { next } = await boot(trailing, { max_stdout_protocol_bytes: 4096 });
    send(invocationRequest('trailing-stdout'));
    const response = await next();
    assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_OUTPUT_LIMIT');
    assert.equal(response.result, undefined);
  });
  await t.test('trailing notification overflow REJECTS with no result', async () => {
    const { next } = await boot(trailing, { max_notification_bytes: 1024 });
    send(invocationRequest('trailing-notification'));
    const response = await next();
    assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_OUTPUT_LIMIT');
    assert.equal(response.result, undefined);
  });
  await t.test('trailing response plus notification overflow REJECTS with no result', async () => {
    const { next } = await boot(trailing, { max_response_and_notification_bytes: 1024 });
    send(invocationRequest('trailing-combined'));
    const response = await next();
    assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_OUTPUT_LIMIT');
    assert.equal(response.result, undefined);
  });
  await t.test('trailing stderr overflow REJECTS with no result', async () => {
    const { next } = await boot({ AIPT_FIXTURE_TRAILING_STDERR_BYTES: '257' }, { max_stderr_bytes: 256 });
    send(invocationRequest('trailing-stderr'));
    const response = await next();
    assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_OUTPUT_LIMIT');
    assert.equal(response.result, undefined);
  });
});

test('oversized encoded outer response rejects without partial semantics', async () => {
  const { next } = await boot({ AIPT_FIXTURE_RESPONSE_PADDING_BYTES: String(400 * 1024) });
  send(invocationRequest('outer-encoded-bound'));
  const response = await next();
  assert.equal(response.id, 'outer-encoded-bound');
  assert.equal((response.error as Record<string, unknown>).code, 'AIPT_MODEL_GATEWAY_OUTPUT_LIMIT');
  assert.equal(response.result, undefined);
});
