/**
 * Proposed B007 bounded diagnostic Harness runtime (NOT AUTHORIZED).
 *
 * This file is bundled with every dependency into one ESM artifact. The model
 * gateway verifies and inherits that artifact through an already-open file
 * descriptor, then imports it as a data URL. Keep this entrypoint free of
 * config loaders, dynamic imports, and runtime package resolution.
 */
import { Context } from '@deepseek-ai/cordis'
import * as acp from '@deepseek-ai/dsh-acp'
import * as agentSpine from '@deepseek-ai/dsh-agent-spine-demo'
import * as deepseek from '@deepseek-ai/dsh-llm-deepseek'

const REMOTE_MODEL = 'deepseek-v4-pro'
const LOCAL_MODEL = 'gguf-04'
const MAX_CONTEXT_TOKENS = 8192
const MAX_OUTPUT_TOKENS = 1024
const LOCAL_ENDPOINT_ENV = 'AIPT_LOCAL_LLAMACPP_ENDPOINT'

function controlledLocalEndpoint(): string | undefined {
  const raw = process.env[LOCAL_ENDPOINT_ENV]
  if (raw === undefined) return undefined
  const endpoint = new URL(raw)
  if (endpoint.protocol !== 'http:' || endpoint.hostname !== '127.0.0.1' ||
      endpoint.username !== '' || endpoint.password !== '' || endpoint.search !== '' ||
      endpoint.hash !== '' || endpoint.pathname !== '/') {
    throw new Error('controlled local endpoint is not an exact IPv4 loopback origin')
  }
  return endpoint.href.slice(0, -1)
}

const localEndpoint = controlledLocalEndpoint()
const model = localEndpoint === undefined ? REMOTE_MODEL : LOCAL_MODEL
const credentialEnvironment = localEndpoint === undefined ? 'DEEPSEEK_API_KEY' : LOCAL_ENDPOINT_ENV
// A versioned B007 successor, never a rewrite of the B004 closure.
// This process is retired after its single ACP operation. The outer launcher
// must durably reserve this attempt before spawning it, including certification.
const originalWireFetch = globalThis.fetch.bind(globalThis)
let wireAttemptUsed = false
const guardedWireFetch: typeof globalThis.fetch = async (input, init) => {
  // Construct the exact final request, with automatic redirects forbidden.
  const request = new Request(input, { ...init, redirect: 'error' })
  const endpoint = new URL(request.url)
  const expectedOrigin = localEndpoint === undefined ? 'https://api.deepseek.com' : localEndpoint
  if (endpoint.origin !== expectedOrigin || endpoint.username !== '' || endpoint.password !== '' ||
      endpoint.search !== '' || endpoint.hash !== '' ||
      !['/chat/completions', '/v1/chat/completions'].includes(endpoint.pathname) || request.method !== 'POST') {
    throw new Error('B007 upstream request identity rejected before send')
  }
  const body = await request.clone().text()
  // This byte bound covers all final wrappers, identity/persona and messages.
  // It is not itself an independently verified provider tokenizer proof.
  if (Buffer.byteLength(body, 'utf8') > MAX_CONTEXT_TOKENS) {
    throw new Error('B007 complete upstream input exceeds byte bound')
  }
  const payload = JSON.parse(body)
  const allowedKeys = ['model', 'messages', 'stream', 'stream_options', 'thinking', 'max_tokens', 'temperature', 'stop']
  const exactKeys = (value: unknown, keys: string[]): boolean =>
    value !== null && typeof value === 'object' && !Array.isArray(value) &&
    JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...keys].sort())
  if (JSON.stringify(payload) !== body || payload === null || typeof payload !== 'object' ||
      Array.isArray(payload) || Object.keys(payload).some((key) => !allowedKeys.includes(key)) ||
      payload.stream !== true || !exactKeys(payload.stream_options, ['include_usage']) ||
      payload.stream_options.include_usage !== true || !exactKeys(payload.thinking, ['type']) ||
      (payload.temperature !== undefined && (typeof payload.temperature !== 'number' ||
        !Number.isFinite(payload.temperature) || payload.temperature < 0 || payload.temperature > 2)) ||
      (payload.stop !== undefined && typeof payload.stop !== 'string' &&
        (!Array.isArray(payload.stop) || payload.stop.length > 16 || payload.stop.some((s: unknown) => typeof s !== 'string')))) {
    throw new Error('B007 ambiguous or unregistered upstream fields rejected before send')
  }
  if (payload.model !== model || payload.max_tokens !== MAX_OUTPUT_TOKENS ||
      payload.thinking?.type !== 'disabled' ||
      (payload.reasoning_effort !== undefined && payload.reasoning_effort !== 'none') ||
      (payload.n !== undefined && payload.n !== 1) ||
      (payload.tools !== undefined && (!Array.isArray(payload.tools) || payload.tools.length !== 0)) ||
      !Array.isArray(payload.messages) || payload.messages.length === 0 ||
      payload.messages.some((m: { role?: string; content?: unknown; tool_calls?: unknown; tool_call_id?: unknown }) =>
        !exactKeys(m, ['role', 'content']) || !['system', 'user', 'assistant'].includes(m.role ?? '') || typeof m.content !== 'string' ||
        m.tool_calls !== undefined || m.tool_call_id !== undefined)) {
    throw new Error('B007 upstream generation/input policy rejected before send')
  }
  // Check and consume immediately before dispatch, after every await. Concurrent
  // requests, unknown-tool continuations and recovery cannot receive two sends.
  if (wireAttemptUsed) throw new Error('B007 one upstream attempt per closure process exceeded')
  wireAttemptUsed = true
  return originalWireFetch(request)
}
Object.defineProperty(globalThis, 'fetch', { value: guardedWireFetch, writable: false, configurable: false })

const ctx = new Context()

await ctx.plugin(agentSpine, {
  workspaceContext: false,
  skills: { enabled: false },
  toolBash: false,
  toolJobs: false,
  goals: false,
  includeRuntimeContext: false,
  includeHarnessIdentity: true,
  persona: 'Follow the AIPT invocation JSON response schema and the assigned role instructions. Return exactly one JSON object. Do not call tools.',
})

await ctx.plugin(deepseek, {
  apiKeyEnv: credentialEnvironment,
  ...(localEndpoint === undefined ? {} : { baseURL: localEndpoint }),
  thinking: 'disabled',
  reasoningEffort: 'off',
  maxTokens: MAX_OUTPUT_TOKENS,
  defaultContextWindow: MAX_CONTEXT_TOKENS,
  models: [{
    id: model,
    contextWindow: MAX_CONTEXT_TOKENS,
    maxTokens: MAX_OUTPUT_TOKENS,
    inputModalities: ['text'],
  }],
  retryPolicy: { mode: 'normal', maxRetries: 0 },
})

await ctx.plugin(acp, { provider: 'deepseek-official', model })

process.stdin.once('end', () => {
  void ctx.fiber.dispose().then(() => process.exit(0))
})
