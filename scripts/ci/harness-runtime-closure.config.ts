import { defineConfig } from 'tsdown'
import ts from 'typescript'

const DECORATOR_SYNTAX = /^\s*@[A-Za-z_$][\w$]*/m
const FROZEN_HARNESS_VERSION = '0.1.0-rc.8'
const ATTRIBUTION_SOURCE_SUFFIX = '/packages/llm/llm/src/attribution.ts'
const ATTRIBUTION_REQUIRE_IMPORT = "import { createRequire } from 'node:module'\n"
const ATTRIBUTION_VERSION_READ =
  "const { version } = createRequire(import.meta.url)('../package.json') as { version: string }"

/**
 * Lower the frozen Harness's standard decorators before the one-file bundle
 * is parsed by Node. The full Harness build plugin also emits workspace
 * metadata; controlled certification needs only its deterministic transform.
 */
const lowerHarnessDecorators = {
  name: 'aipt-lower-frozen-harness-decorators',
  transform(code: string, id: string) {
    const file = id.split('?', 1)[0] ?? id
    let transformed = code
    if (file.replaceAll('\\', '/').endsWith(ATTRIBUTION_SOURCE_SUFFIX)) {
      if (!transformed.includes(ATTRIBUTION_REQUIRE_IMPORT) ||
          !transformed.includes(ATTRIBUTION_VERSION_READ)) {
        throw new Error('frozen Harness attribution source no longer matches the reviewed closure transform')
      }
      transformed = transformed
        .replace(ATTRIBUTION_REQUIRE_IMPORT, '')
        .replace(ATTRIBUTION_VERSION_READ, `const version = '${FROZEN_HARNESS_VERSION}'`)
    }
    if (!/\.[cm]?tsx?$/.test(file) || !DECORATOR_SYNTAX.test(transformed)) {
      return transformed === code ? undefined : { code: transformed, map: undefined }
    }
    const result = ts.transpileModule(transformed, {
      fileName: file,
      compilerOptions: {
        target: ts.ScriptTarget.ES2024,
        module: ts.ModuleKind.ESNext,
        ...(file.endsWith('x') ? { jsx: ts.JsxEmit.ReactJSX } : {}),
        sourceMap: true,
      },
    })
    return {
      code: result.outputText.replace(/\n?\/\/# sourceMappingURL=.*$/u, '\n'),
      map: result.sourceMapText,
    }
  },
  generateBundle(_options: unknown, bundle: Record<string, { type: string; code?: string }>) {
    const chunks = Object.values(bundle).filter(item => item.type === 'chunk' && item.code !== undefined)
    if (chunks.length !== 1) throw new Error('controlled Harness closure must emit exactly one chunk')
    const chunk = chunks[0]!
    const matches = chunk.code!.match(/import\.meta\.url/g) ?? []
    if (matches.length !== 1) {
      throw new Error(`controlled Harness closure expected one bundler createRequire base, found ${matches.length}`)
    }
    chunk.code = chunk.code!.replace('import.meta.url', "'/proc/self/fd/4'")
  },
}

export default defineConfig({ plugins: [lowerHarnessDecorators] })
