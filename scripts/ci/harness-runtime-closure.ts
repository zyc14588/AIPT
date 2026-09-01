/**
 * Frozen B004 controlled-certification Harness runtime.
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
const ctx = new Context()

await ctx.plugin(agentSpine, {
  workspaceContext: false,
  skills: { enabled: false },
  toolBash: false,
  toolJobs: false,
  goals: false,
  includeRuntimeContext: false,
  includeHarnessIdentity: true,
  persona: 'Return a brief speech-only response. Do not call tools.',
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
