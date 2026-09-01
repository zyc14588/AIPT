import type { Readable } from 'node:stream';
import { HarnessAdapterError } from './errors.ts';

export const MAX_FRAME_BYTES = 1024 * 1024;

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
  const pending = Buffer.allocUnsafe(MAX_FRAME_BYTES);
  let pendingBytes = 0;
  const append = (segment: Buffer): void => {
    if (pendingBytes + segment.length > MAX_FRAME_BYTES) {
      throw new HarnessAdapterError('AIPT_HARNESS_FRAME_TOO_LARGE');
    }
    segment.copy(pending, pendingBytes);
    pendingBytes += segment.length;
  };
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
        append(chunk.subarray(start, index));
        yield decodeFrame(pending.subarray(0, pendingBytes));
        pendingBytes = 0;
        start = index + 1;
      }
      append(chunk.subarray(start));
    }
  } catch (error) {
    if (signal.aborted) throw new HarnessAdapterError('AIPT_HARNESS_CANCELLED');
    throw error;
  } finally {
    signal.removeEventListener('abort', abort);
  }
  if (pendingBytes !== 0) {
    throw new HarnessAdapterError('AIPT_HARNESS_PARTIAL_FRAME');
  }
}
