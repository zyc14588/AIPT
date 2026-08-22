import type { Readable } from 'node:stream';
import { HarnessAdapterError } from './errors.ts';

export const MAX_FRAME_BYTES = 1024 * 1024;

function appendBounded(pending: Buffer, segment: Buffer): Buffer {
  if (pending.length + segment.length > MAX_FRAME_BYTES) {
    throw new HarnessAdapterError('AIPT_HARNESS_FRAME_TOO_LARGE');
  }
  if (pending.length === 0) return Buffer.from(segment);
  if (segment.length === 0) return pending;
  return Buffer.concat([pending, segment], pending.length + segment.length);
}

function decodeFrame(frame: Buffer): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(frame);
  } catch {
    throw new HarnessAdapterError('AIPT_HARNESS_INVALID_UTF8');
  }
}

export async function* readLineFrames(
  input: Readable,
  signal: AbortSignal,
): AsyncGenerator<string> {
  let pending = Buffer.alloc(0);
  const abort = () => input.destroy(new HarnessAdapterError('AIPT_HARNESS_CANCELLED'));
  if (signal.aborted) abort();
  else signal.addEventListener('abort', abort, { once: true });
  try {
    for await (const rawChunk of input) {
      if (signal.aborted) throw new HarnessAdapterError('AIPT_HARNESS_CANCELLED');
      const chunk = Buffer.isBuffer(rawChunk) ? rawChunk : Buffer.from(rawChunk);
      let start = 0;
      for (let index = 0; index < chunk.length; index += 1) {
        if (chunk[index] !== 0x0a) continue;
        pending = appendBounded(pending, chunk.subarray(start, index));
        yield decodeFrame(pending);
        pending = Buffer.alloc(0);
        start = index + 1;
      }
      pending = appendBounded(pending, chunk.subarray(start));
    }
  } catch (error) {
    if (signal.aborted) throw new HarnessAdapterError('AIPT_HARNESS_CANCELLED');
    throw error;
  } finally {
    signal.removeEventListener('abort', abort);
  }
  if (pending.length !== 0) {
    throw new HarnessAdapterError('AIPT_HARNESS_PARTIAL_FRAME');
  }
}
