#!/usr/bin/env node
import { createInterface } from 'node:readline';
import process from 'node:process';

interface Frame {
  jsonrpc?: unknown;
  id?: unknown;
  method?: unknown;
  params?: unknown;
}

const prompts = new Map<string, string | number>();
let sessionSerial = 0;

const stderrBytes = Number(process.env.AIPT_FIXTURE_STDERR_BYTES ?? '0');
if (Number.isSafeInteger(stderrBytes) && stderrBytes > 0) {
  process.stderr.write('d'.repeat(stderrBytes));
}

function write(value: unknown): void {
  const frame = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  const fragmentBytes = Number(process.env.AIPT_FIXTURE_FRAGMENT_BYTES ?? '0');
  if (Number.isSafeInteger(fragmentBytes) && fragmentBytes > 0) {
    for (let offset = 0; offset < frame.length; offset += fragmentBytes) {
      process.stdout.write(frame.subarray(offset, Math.min(offset + fragmentBytes, frame.length)));
    }
    return;
  }
  process.stdout.write(frame);
}

function emitTrailingOutput(): void {
  const count = Number(process.env.AIPT_FIXTURE_TRAILING_NOISE_COUNT ?? '0');
  const contentBytes = Number(process.env.AIPT_FIXTURE_TRAILING_NOISE_BYTES ?? '0');
  if (Number.isSafeInteger(count) && count > 0 &&
      Number.isSafeInteger(contentBytes) && contentBytes > 0) {
    for (let index = 0; index < count; index += 1) {
      write({
        jsonrpc: '2.0', method: 'session/update',
        params: {
          sessionId: `trailing-${index}`,
          update: {
            sessionUpdate: 'agent_message_chunk',
            content: { type: 'text', text: 't'.repeat(contentBytes) },
          },
        },
      });
    }
  }
  const stderrBytes = Number(process.env.AIPT_FIXTURE_TRAILING_STDERR_BYTES ?? '0');
  if (Number.isSafeInteger(stderrBytes) && stderrBytes > 0) {
    process.stderr.write('e'.repeat(stderrBytes));
  }
}

function object(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown> : {};
}

const lines = createInterface({ input: process.stdin });
lines.on('line', (line) => {
  let frame: Frame;
  try { frame = JSON.parse(line) as Frame; } catch { process.exit(2); return; }
  const params = object(frame.params);
  if (frame.method === 'initialize' && frame.id !== undefined) {
    const unterminatedBytes = Number(process.env.AIPT_FIXTURE_UNTERMINATED_BYTES ?? '0');
    if (Number.isSafeInteger(unterminatedBytes) && unterminatedBytes > 0) {
      process.stdout.write('u'.repeat(unterminatedBytes));
      return;
    }
    const startupNoiseBytes = Number(process.env.AIPT_FIXTURE_STARTUP_NOISE_BYTES ?? '0');
    if (Number.isSafeInteger(startupNoiseBytes) && startupNoiseBytes > 0) {
      const notification = {
        jsonrpc: '2.0', method: 'session/update',
        params: {
          sessionId: 'unrelated-0',
          update: {
            sessionUpdate: 'agent_message_chunk',
            content: { type: 'text', text: 'x'.repeat(startupNoiseBytes) },
          },
        },
      };
      if (process.env.AIPT_FIXTURE_BOM_STARTUP_NOTIFICATION === '1') {
        process.stdout.write(`\uFEFF${JSON.stringify(notification)}\n`);
      } else {
        write(notification);
      }
    }
    const initialized = {
      jsonrpc: '2.0', id: frame.id,
      result: {
        protocolVersion: process.env.AIPT_FIXTURE_INVALID_INITIALIZE === '1' ? 2 : 1,
        agentCapabilities: { promptCapabilities: { image: false, audio: false, embeddedContext: false } },
      },
    };
    if (process.env.AIPT_FIXTURE_BOM_INITIALIZE === '1') {
      process.stdout.write(`\uFEFF${JSON.stringify(initialized)}\n`);
    } else {
      write(initialized);
    }
    return;
  }
  if (frame.method === 'session/new' && frame.id !== undefined) {
    write({ jsonrpc: '2.0', id: frame.id, result: { sessionId: `fixture-session-${++sessionSerial}` } });
    return;
  }
  if (frame.method === 'session/prompt' && frame.id !== undefined) {
    const sessionId = String(params.sessionId ?? '');
    prompts.set(sessionId, frame.id as string | number);
    if (process.env.AIPT_FIXTURE_HANG === '1') return;
    if (process.env.AIPT_FIXTURE_PROMPT_ERROR === '1') {
      write({ jsonrpc: '2.0', id: frame.id, error: { code: -32000, message: 'synthetic prompt failure' } });
      return;
    }
    if (process.env.AIPT_FIXTURE_OVERSIZED_FRAME === '1') {
      process.stdout.write(`${'x'.repeat((1024 * 1024) + 1)}\n`);
      return;
    }
    const prompt = Array.isArray(params.prompt) ? object(params.prompt[0]) : {};
    const text = String(prompt.text ?? '');
    const taskLine = text.split('\n').at(-1) ?? '{}';
    const task = object(JSON.parse(taskLine) as unknown);
    const invocation = object(task.invocation);
    const sampling = object(task.sampling);
    const effective = object(sampling.effective_sampling_projection);
    if (typeof sampling.requested_sampling_sha256 !== 'string' ||
        !Array.isArray(sampling.unsupported_parameters) ||
        JSON.stringify(sampling.unsupported_parameters) !== JSON.stringify(['temperature', 'top_p']) ||
        effective.schema !== 'aipt.effective-sampling-projection/v1' ||
        effective.enforcement_identity !== 'AIPT_ACP_CONSERVATIVE_UTF8_BYTE_BUDGET_V1' ||
        effective.max_context_tokens !== 8192 || effective.max_output_tokens !== 1024 ||
        effective.context_utf8_byte_ceiling !== 8192 || effective.output_utf8_byte_ceiling !== 1024) {
      process.exit(3);
      return;
    }
    const noiseCount = Number(process.env.AIPT_FIXTURE_NOISE_COUNT ?? '0');
    const noiseBytes = Number(process.env.AIPT_FIXTURE_NOISE_BYTES ?? '0');
    if (Number.isSafeInteger(noiseCount) && noiseCount > 0 &&
        Number.isSafeInteger(noiseBytes) && noiseBytes > 0) {
      for (let index = 0; index < noiseCount; index += 1) {
        write({
          jsonrpc: '2.0', method: 'session/update',
          params: {
            sessionId: `unrelated-${index}`,
            update: {
              sessionUpdate: 'agent_message_chunk',
              content: { type: 'text', text: 'x'.repeat(noiseBytes) },
            },
          },
        });
      }
    }
    const activeOutputBytes = Number(process.env.AIPT_FIXTURE_ACTIVE_OUTPUT_BYTES ?? '0');
    if (Number.isSafeInteger(activeOutputBytes) && activeOutputBytes > 0) {
      write({
        jsonrpc: '2.0', method: 'session/update',
        params: {
          sessionId,
          update: {
            sessionUpdate: 'agent_message_chunk',
            content: { type: 'text', text: 'o'.repeat(activeOutputBytes) },
          },
        },
      });
    }
    const responsePaddingBytes = Number(process.env.AIPT_FIXTURE_RESPONSE_PADDING_BYTES ?? '0');
    const response = JSON.stringify({
      schema: 'aipt.agent-response/v1',
      invocation_id: invocation.invocation_id,
      run_id: invocation.run_id,
      seat_id: invocation.seat_id,
      session_id: invocation.session_id,
      speech: Number.isSafeInteger(responsePaddingBytes) && responsePaddingBytes > 0
        ? 'p'.repeat(responsePaddingBytes) : 'fixture response',
      metadata: { protocol_version: 'v1' },
    });
    if (process.env.AIPT_FIXTURE_ID_BEARING_UPDATE === '1') {
      write({
        jsonrpc: '2.0', id: 'malicious-session-update', method: 'session/update',
        params: {
          sessionId,
          update: { sessionUpdate: 'agent_message_chunk', content: { type: 'text', text: response } },
        },
      });
      write({ jsonrpc: '2.0', id: frame.id, result: { stopReason: 'end_turn' } });
      prompts.delete(sessionId);
      return;
    }
    write({
      jsonrpc: '2.0', method: 'session/update',
      params: {
        sessionId,
        update: { sessionUpdate: 'agent_message_chunk', content: { type: 'text', text: response } },
      },
    });
    write({ jsonrpc: '2.0', id: frame.id, result: { stopReason: 'end_turn' } });
    emitTrailingOutput();
    prompts.delete(sessionId);
    return;
  }
  if (frame.method === 'session/cancel') {
    const sessionId = String(params.sessionId ?? '');
    const promptID = prompts.get(sessionId);
    if (promptID !== undefined) {
      write({ jsonrpc: '2.0', id: promptID, result: { stopReason: 'cancelled' } });
      prompts.delete(sessionId);
    }
    return;
  }
  if (frame.id !== undefined) write({ jsonrpc: '2.0', id: frame.id, error: { code: -32601, message: 'unknown' } });
});
