import assert from 'node:assert/strict';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { once } from 'node:events';
import { Readable, Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  decodeNotification,
  decodeRequest,
  decodeResponse,
  encodeNotification,
  encodeRequest,
  encodeResponse,
  type JsonRpcNotification,
  type JsonRpcRequest,
} from '@aipt/adapter-sdk';
import { HarnessAdapterError, MAX_FRAME_BYTES, serveHarnessAdapter } from '../src/index.ts';
import {
  chargeBackendOutputFrameBytes,
  MAX_BACKEND_ENCODED_OUTPUT_BYTES,
  MAX_BACKEND_NOTIFICATION_COUNT,
} from '../src/runtime.ts';
import { createFixtureBackend, type FixtureBackendMode } from './fixture-backend.ts';

const REPO_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const WORKER = fileURLToPath(new URL('./fixture-worker.ts', import.meta.url));
const FIXTURE = new URL('../../../testdata/protocol/v1/minimal-fixture/', import.meta.url);
const TEST_MARKER = 'TEST_CREDENTIAL_MARKER_DO_NOT_FORWARD';

async function text(relative: string): Promise<string> {
  return readFile(new URL(relative, FIXTURE), 'utf8');
}

function allowlistedEnvironment(source: Readonly<Record<string, string | undefined>>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const key of ['LANG', 'LC_ALL', 'TZ']) {
    const value = source[key];
    if (value !== undefined) result[key] = value;
  }
  return result;
}

interface ChildResult {
  readonly code: number | null;
  readonly signal: NodeJS.Signals | null;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
  readonly pid: number;
}

function collect(child: ChildProcessWithoutNullStreams): Promise<ChildResult> {
  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  child.stdout.on('data', (chunk) => stdout.push(Buffer.from(chunk)));
  child.stderr.on('data', (chunk) => stderr.push(Buffer.from(chunk)));
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({
      code, signal, stdout: Buffer.concat(stdout), stderr: Buffer.concat(stderr), pid: child.pid!,
    }));
  });
}

function startWorker(mode: FixtureBackendMode): ChildProcessWithoutNullStreams {
  const source = {
    LANG: 'C.UTF-8',
    TZ: 'UTC',
    AIPT_TEST_CREDENTIAL: TEST_MARKER,
  };
  return spawn(process.execPath, [WORKER, mode], {
    cwd: REPO_ROOT,
    env: allowlistedEnvironment(source),
    stdio: ['pipe', 'pipe', 'pipe'],
    windowsHide: true,
  });
}

async function runWorker(mode: FixtureBackendMode, input: string | Buffer): Promise<ChildResult> {
  const child = startWorker(mode);
  const result = collect(child);
  child.stdin.end(input);
  return result;
}

function diagnostic(result: ChildResult): Record<string, unknown> {
  const lines = result.stderr.toString('utf8').trim().split('\n').filter(Boolean);
  assert.equal(lines.length, 1);
  return JSON.parse(lines[0]);
}

const requestText = await text('requests/apply-action-request.json');
const request = decodeRequest(requestText);
const requestFrame = encodeRequest(request) + '\n';
const accepted = encodeResponse(await (async () => decodeResponse(
  await text('responses/apply-action-result-response.json'),
))());
const rejected = encodeResponse(await (async () => decodeResponse(
  await text('responses/apply-action-protocol-error-response.json'),
))());
const event = encodeNotification(await (async () => decodeNotification(
  await text('notifications/state-event-notification.json'),
))());

test('real child ACCEPT emits exact response then notification on stdout', async () => {
  const result = await runWorker('accept', requestFrame);
  assert.equal(result.code, 0);
  assert.equal(result.stderr.length, 0);
  assert.equal(result.stdout.toString('utf8'), accepted + '\n' + event + '\n');
});

test('real child REJECT emits only the exact canonical protocol error', async () => {
  const result = await runWorker('reject', requestFrame);
  assert.equal(result.code, 0);
  assert.equal(result.stderr.length, 0);
  assert.equal(result.stdout.toString('utf8'), rejected + '\n');
});

test('one input frame produces a response before all notifications', async () => {
  const result = await runWorker('accept', requestFrame);
  assert.deepEqual(result.stdout.toString('utf8').trim().split('\n'), [accepted, event]);
});

test('two request lines are processed sequentially without interleaving', async () => {
  const result = await runWorker('accept', requestFrame + requestFrame);
  assert.equal(result.code, 0);
  assert.deepEqual(result.stdout.toString('utf8').trim().split('\n'), [accepted, event, accepted, event]);
});

test('repeated real child runs have an identical SHA-256 transcript', async () => {
  const first = await runWorker('accept', requestFrame);
  const second = await runWorker('accept', requestFrame);
  const digest = (value: Buffer) => createHash('sha256').update(value).digest('hex');
  assert.equal(digest(first.stdout), digest(second.stdout));
});

test('clean EOF without a partial frame is graceful', async () => {
  const result = await runWorker('accept', Buffer.alloc(0));
  assert.equal(result.code, 0);
  assert.equal(result.stdout.length, 0);
  assert.equal(result.stderr.length, 0);
});

test('a frame split across writes is reconstructed exactly', async () => {
  const child = startWorker('accept');
  const result = collect(child);
  const midpoint = Math.floor(requestFrame.length / 2);
  child.stdin.write(requestFrame.slice(0, midpoint));
  child.stdin.end(requestFrame.slice(midpoint));
  const completed = await result;
  assert.equal(completed.stdout.toString('utf8'), accepted + '\n' + event + '\n');
});

test('a maximum-size frame fragmented into small chunks is reconstructed exactly', async () => {
  const outputChunks: Buffer[] = [];
  const diagnosticChunks: Buffer[] = [];
  const output = new Writable({
    write(chunk, _encoding, callback) { outputChunks.push(Buffer.from(chunk)); callback(); },
  });
  const diagnosticOutput = new Writable({
    write(chunk, _encoding, callback) { diagnosticChunks.push(Buffer.from(chunk)); callback(); },
  });
  const requestBytes = Buffer.from(requestFrame.slice(0, -1), 'utf8');
  const maximumFrame = Buffer.concat([
    requestBytes,
    Buffer.alloc(MAX_FRAME_BYTES - requestBytes.length, 0x20),
    Buffer.from('\n'),
  ]);
  const fragmented: Buffer[] = [];
  for (let offset = 0; offset < maximumFrame.length; offset += 256) {
    fragmented.push(maximumFrame.subarray(offset, Math.min(offset + 256, maximumFrame.length)));
  }
  await serveHarnessAdapter({
    backend: await createFixtureBackend('accept'),
    input: Readable.from(fragmented), output, diagnostic: diagnosticOutput,
  });
  assert.equal(Buffer.concat(outputChunks).toString('utf8'), accepted + '\n' + event + '\n');
  assert.equal(diagnosticChunks.length, 0);
});

test('malformed JSON fails closed without stdout payload echo', async () => {
  const marker = 'MALFORMED_PAYLOAD_MARKER';
  const result = await runWorker('accept', '{"' + marker + '":}\n');
  assert.equal(result.code, 1);
  assert.equal(result.stdout.length, 0);
  assert.equal(diagnostic(result).code, 'AIPT_HARNESS_INVALID_REQUEST');
  assert.equal(result.stderr.includes(marker), false);
});

test('a valid non-request JSON-RPC envelope is rejected', async () => {
  const result = await runWorker('accept', accepted + '\n');
  assert.equal(result.code, 1);
  assert.equal(result.stdout.length, 0);
  assert.equal(diagnostic(result).code, 'AIPT_HARNESS_INVALID_REQUEST');
});

test('an unsupported request method fails closed in the real child', async () => {
  const envelope = JSON.parse(requestText);
  envelope.method = 'aipt.protocol.unsupported';
  const result = await runWorker('accept', JSON.stringify(envelope) + '\n');
  assert.equal(result.code, 1);
  assert.equal(result.stdout.length, 0);
  assert.equal(diagnostic(result).code, 'AIPT_HARNESS_INVALID_REQUEST');
});

test('an unsupported protocol version fails closed in the real child', async () => {
  const envelope = JSON.parse(requestText);
  envelope.protocol_version = '9.9.9';
  const result = await runWorker('accept', JSON.stringify(envelope) + '\n');
  assert.equal(result.code, 1);
  assert.equal(result.stdout.length, 0);
  assert.equal(diagnostic(result).code, 'AIPT_HARNESS_INVALID_REQUEST');
});

test('invalid UTF-8 fails closed with a stable redacted code', async () => {
  const result = await runWorker('accept', Buffer.from([0xc3, 0x28, 0x0a]));
  assert.equal(result.code, 1);
  assert.equal(result.stdout.length, 0);
  assert.equal(diagnostic(result).code, 'AIPT_HARNESS_INVALID_UTF8');
});

test('a frame over 1 MiB is rejected before backend dispatch', async () => {
  const input = Buffer.concat([Buffer.alloc(MAX_FRAME_BYTES + 1, 0x20), Buffer.from('\n')]);
  const result = await runWorker('accept', input);
  assert.equal(result.code, 1);
  assert.equal(result.stdout.length, 0);
  assert.equal(diagnostic(result).code, 'AIPT_HARNESS_FRAME_TOO_LARGE');
});

test('EOF with a partial frame fails closed', async () => {
  const result = await runWorker('accept', requestFrame.slice(0, -1));
  assert.equal(result.code, 1);
  assert.equal(result.stdout.length, 0);
  assert.equal(diagnostic(result).code, 'AIPT_HARNESS_PARTIAL_FRAME');
});

test('child environment is an exact allowlist and excludes credential-like inputs', () => {
  const env = allowlistedEnvironment({
    LANG: 'C.UTF-8', TZ: 'UTC', AIPT_TEST_CREDENTIAL: TEST_MARKER, PATH: '/not-forwarded',
  });
  assert.deepEqual(env, { LANG: 'C.UTF-8', TZ: 'UTC' });
  assert.equal(JSON.stringify(env).includes(TEST_MARKER), false);
});

test('credential marker is absent from successful stdout and stderr', async () => {
  const result = await runWorker('accept', requestFrame);
  assert.equal(Buffer.concat([result.stdout, result.stderr]).includes(TEST_MARKER), false);
});

test('backend exception text is redacted from diagnostics', async () => {
  const result = await runWorker('fail', requestFrame);
  assert.equal(result.code, 1);
  assert.equal(result.stdout.length, 0);
  assert.equal(diagnostic(result).code, 'AIPT_HARNESS_BACKEND_FAILED');
  assert.equal(result.stderr.includes('TEST_MARKER_MUST_NEVER_REACH_DIAGNOSTICS'), false);
});

test('response identity drift emits no partial protocol output', async () => {
  const result = await runWorker('identity-drift', requestFrame);
  assert.equal(result.code, 1);
  assert.equal(result.stdout.length, 0);
  assert.equal(diagnostic(result).code, 'AIPT_HARNESS_RESPONSE_IDENTITY_MISMATCH');
});

test('backend result with an extra key fails closed before stdout', async () => {
  const result = await runWorker('invalid-output', requestFrame);
  assert.equal(result.code, 1);
  assert.equal(result.stdout.length, 0);
  assert.equal(diagnostic(result).code, 'AIPT_HARNESS_OUTPUT_INVALID');
});

test('an oversized backend frame fails closed before any stdout write', async () => {
  const result = await runWorker('oversized-output', requestFrame);
  assert.equal(result.code, 1);
  assert.equal(result.stdout.length, 0);
  assert.equal(diagnostic(result).code, 'AIPT_HARNESS_FRAME_TOO_LARGE');
});

test('backend notification count accepts the exact boundary', async () => {
  const outputChunks: Buffer[] = [];
  const notification = decodeNotification(event);
  await serveHarnessAdapter({
    backend: {
      applyAction() {
        return {
          response: decodeResponse(accepted),
          notifications: new Array<JsonRpcNotification>(MAX_BACKEND_NOTIFICATION_COUNT).fill(notification),
        };
      },
    },
    input: Readable.from([requestFrame]),
    output: new Writable({
      write(chunk, _encoding, callback) { outputChunks.push(Buffer.from(chunk)); callback(); },
    }),
    diagnostic: new Writable({ write(_chunk, _encoding, callback) { callback(); } }),
  });
  const frames = Buffer.concat(outputChunks).toString('utf8').trimEnd().split('\n');
  assert.equal(frames.length, MAX_BACKEND_NOTIFICATION_COUNT + 1);
  assert.equal(frames[0], accepted);
  assert.ok(frames.slice(1).every((frame) => frame === event));
});

test('backend notification count is rejected before any item is inspected or output written', async () => {
  const outputChunks: Buffer[] = [];
  const notifications = new Array<JsonRpcNotification>(MAX_BACKEND_NOTIFICATION_COUNT + 1);
  let inspected = false;
  Object.defineProperty(notifications, 0, {
    enumerable: true,
    get() {
      inspected = true;
      return decodeNotification(event);
    },
  });
  await assert.rejects(serveHarnessAdapter({
    backend: {
      applyAction() {
        return { response: decodeResponse(accepted), notifications };
      },
    },
    input: Readable.from([requestFrame]),
    output: new Writable({
      write(chunk, _encoding, callback) { outputChunks.push(Buffer.from(chunk)); callback(); },
    }),
    diagnostic: new Writable({ write(_chunk, _encoding, callback) { callback(); } }),
  }), (error: unknown) => {
    assert.ok(error instanceof HarnessAdapterError);
    assert.equal(error.code, 'AIPT_HARNESS_OUTPUT_INVALID');
    return true;
  });
  assert.equal(inspected, false);
  assert.equal(outputChunks.length, 0);
});

test('backend aggregate accounting includes LF and fixes the 4 MiB boundary', () => {
  const frame = 'x'.repeat(MAX_FRAME_BYTES - 1);
  let accumulated = 0;
  for (let index = 0; index < 4; index += 1) {
    accumulated = chargeBackendOutputFrameBytes(accumulated, frame);
  }
  assert.equal(accumulated, MAX_BACKEND_ENCODED_OUTPUT_BYTES);
  assert.throws(
    () => chargeBackendOutputFrameBytes(accumulated, ''),
    (error: unknown) => {
      assert.ok(error instanceof HarnessAdapterError);
      assert.equal(error.code, 'AIPT_HARNESS_FRAME_TOO_LARGE');
      return true;
    },
  );
});

test('runtime honors writable backpressure before completing', async () => {
  const outputChunks: Buffer[] = [];
  const diagnosticChunks: Buffer[] = [];
  const output = new Writable({
    highWaterMark: 1,
    write(chunk, _encoding, callback) {
      setTimeout(() => { outputChunks.push(Buffer.from(chunk)); callback(); }, 5);
    },
  });
  const diagnosticOutput = new Writable({
    write(chunk, _encoding, callback) { diagnosticChunks.push(Buffer.from(chunk)); callback(); },
  });
  await serveHarnessAdapter({
    backend: await createFixtureBackend('accept'),
    input: Readable.from([requestFrame]), output, diagnostic: diagnosticOutput,
  });
  assert.equal(Buffer.concat(outputChunks).toString('utf8'), accepted + '\n' + event + '\n');
  assert.equal(diagnosticChunks.length, 0);
});

test('SIGTERM cancellation is bounded and leaves no child process', async () => {
  const child = startWorker('hang');
  const resultPromise = collect(child);
  child.stdin.write(requestFrame);
  await new Promise((resolve) => setTimeout(resolve, 100));
  const started = Date.now();
  assert.equal(child.kill('SIGTERM'), true);
  const timeout = new Promise<never>((_resolve, reject) => {
    setTimeout(() => reject(new Error('cancellation timeout')), 2000);
  });
  const result = await Promise.race([resultPromise, timeout]);
  assert.ok(Date.now() - started < 2000);
  assert.equal(result.code, 143);
  assert.equal(result.stdout.length, 0);
  assert.equal(diagnostic(result).code, 'AIPT_HARNESS_CANCELLED');
  assert.throws(() => process.kill(result.pid, 0), { code: 'ESRCH' });
});

test('fixture request remains the canonical SDK-decoded request', () => {
  const again: JsonRpcRequest = decodeRequest(requestText);
  assert.equal(encodeRequest(again), encodeRequest(request));
});
