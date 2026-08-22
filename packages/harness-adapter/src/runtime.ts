import type { Readable, Writable } from 'node:stream';
import {
  decodeRequest, encodeNotification, encodeResponse,
  type JsonRpcNotification, type JsonRpcRequest, type JsonRpcResponse, type RequestId,
} from '@aipt/adapter-sdk';
import type { HarnessBackend, HarnessBackendResult } from './backend.ts';
import { asHarnessAdapterError, HarnessAdapterError, type HarnessAdapterErrorCode } from './errors.ts';
import { MAX_FRAME_BYTES, readLineFrames } from './framing.ts';

export interface HarnessAdapterStreams {
  readonly input: Readable;
  readonly output: Writable;
  readonly diagnostic: Writable;
}

export interface HarnessAdapterOptions extends HarnessAdapterStreams {
  readonly backend: HarnessBackend;
  readonly signal?: AbortSignal;
}

export interface HarnessAdapterRunResult {
  readonly ok: boolean;
  readonly code?: HarnessAdapterErrorCode;
}

function sameRequestId(left: RequestId, right: RequestId): boolean {
  return typeof left === typeof right && Object.is(left, right);
}

function assertIdentity(request: JsonRpcRequest, response: JsonRpcResponse): void {
  if (!sameRequestId(request.id, response.id) ||
      request.protocol_version !== response.protocol_version ||
      request.schema_version !== response.schema_version ||
      request.fixture_id !== response.fixture_id) {
    throw new HarnessAdapterError('AIPT_HARNESS_RESPONSE_IDENTITY_MISMATCH');
  }
}

function normalizeBackendResult(value: HarnessBackendResult): {
  response: JsonRpcResponse;
  notifications: readonly JsonRpcNotification[];
} {
  if (value === null || typeof value !== 'object' || Array.isArray(value) ||
      !Object.hasOwn(value, 'response')) {
    throw new HarnessAdapterError('AIPT_HARNESS_OUTPUT_INVALID');
  }
  const keys = Object.keys(value).sort();
  const allowed = Object.hasOwn(value, 'notifications')
    ? ['notifications', 'response'] : ['response'];
  if (JSON.stringify(keys) !== JSON.stringify(allowed)) {
    throw new HarnessAdapterError('AIPT_HARNESS_OUTPUT_INVALID');
  }
  const notifications = value.notifications ?? [];
  if (!Array.isArray(notifications)) {
    throw new HarnessAdapterError('AIPT_HARNESS_OUTPUT_INVALID');
  }
  return { response: value.response, notifications };
}

function prepareOutput(request: JsonRpcRequest, value: HarnessBackendResult): readonly string[] {
  const { response, notifications } = normalizeBackendResult(value);
  assertIdentity(request, response);
  let responseFrame: string;
  let notificationFrames: string[];
  try {
    responseFrame = encodeResponse(response);
    notificationFrames = notifications.map((notification) => {
      if (notification.protocol_version !== request.protocol_version ||
          notification.schema_version !== request.schema_version ||
          notification.fixture_id !== request.fixture_id ||
          notification.params.event.protocol_version !== request.protocol_version ||
          notification.params.event.schema_version !== request.schema_version ||
          notification.params.event.fixture_id !== request.fixture_id) {
        throw new HarnessAdapterError('AIPT_HARNESS_RESPONSE_IDENTITY_MISMATCH');
      }
      return encodeNotification(notification);
    });
  } catch (error) {
    if (error instanceof HarnessAdapterError) throw error;
    throw new HarnessAdapterError('AIPT_HARNESS_OUTPUT_INVALID');
  }
  if ('error' in response && notifications.length !== 0) {
    throw new HarnessAdapterError('AIPT_HARNESS_OUTPUT_INVALID');
  }
  if ('result' in response) {
    for (const notification of notifications) {
      if (notification.params.event.transition_id !== response.result.transition_id) {
        throw new HarnessAdapterError('AIPT_HARNESS_RESPONSE_IDENTITY_MISMATCH');
      }
    }
  }
  const frames = [responseFrame, ...notificationFrames];
  if (frames.some((frame) => Buffer.byteLength(frame, 'utf8') > MAX_FRAME_BYTES)) {
    throw new HarnessAdapterError('AIPT_HARNESS_FRAME_TOO_LARGE');
  }
  return frames;
}

async function invokeWithCancellation<T>(
  operation: () => Promise<T> | T,
  signal: AbortSignal,
): Promise<T> {
  if (signal.aborted) throw new HarnessAdapterError('AIPT_HARNESS_CANCELLED');
  let onAbort: (() => void) | undefined;
  const cancellation = new Promise<never>((_resolve, reject) => {
    onAbort = () => reject(new HarnessAdapterError('AIPT_HARNESS_CANCELLED'));
    signal.addEventListener('abort', onAbort, { once: true });
  });
  try {
    return await Promise.race([Promise.resolve().then(operation), cancellation]);
  } finally {
    if (onAbort) signal.removeEventListener('abort', onAbort);
  }
}

async function writeFrame(output: Writable, frame: string): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    output.write(frame + '\n', 'utf8', (error) => {
      if (error) reject(new HarnessAdapterError('AIPT_HARNESS_WRITE_FAILED'));
      else resolve();
    });
  });
}

async function writeDiagnostic(output: Writable, code: HarnessAdapterErrorCode): Promise<void> {
  const record = {
    schema: 'aipt.public.harness-adapter-diagnostic/v1',
    code,
    disposition: 'FAIL_CLOSED',
  };
  await new Promise<void>((resolve) => {
    output.write(JSON.stringify(record) + '\n', 'utf8', () => resolve());
  });
}

export async function serveHarnessAdapter(options: HarnessAdapterOptions): Promise<void> {
  const signal = options.signal ?? new AbortController().signal;
  let primaryError: unknown;
  try {
    for await (const frame of readLineFrames(options.input, signal)) {
      if (signal.aborted) throw new HarnessAdapterError('AIPT_HARNESS_CANCELLED');
      let request: JsonRpcRequest;
      try { request = decodeRequest(frame); }
      catch { throw new HarnessAdapterError('AIPT_HARNESS_INVALID_REQUEST'); }
      let result: HarnessBackendResult;
      try {
        result = await invokeWithCancellation(
          () => options.backend.applyAction(request, signal),
          signal,
        );
      }
      catch (error) {
        if (signal.aborted) throw new HarnessAdapterError('AIPT_HARNESS_CANCELLED');
        if (error instanceof HarnessAdapterError) throw error;
        throw new HarnessAdapterError('AIPT_HARNESS_BACKEND_FAILED');
      }
      const frames = prepareOutput(request, result);
      for (const outputFrame of frames) await writeFrame(options.output, outputFrame);
    }
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    if (options.backend.close) {
      try { await options.backend.close(signal); }
      catch {
        if (primaryError === undefined) {
          throw new HarnessAdapterError('AIPT_HARNESS_BACKEND_FAILED');
        }
      }
    }
  }
}

export async function runHarnessAdapter(options: HarnessAdapterOptions): Promise<HarnessAdapterRunResult> {
  try {
    await serveHarnessAdapter(options);
    return { ok: true };
  } catch (error) {
    const safe = asHarnessAdapterError(error);
    await writeDiagnostic(options.diagnostic, safe.code);
    return { ok: false, code: safe.code };
  }
}
