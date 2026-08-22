import type { HarnessBackend } from './backend.ts';
import { runHarnessAdapter, type HarnessAdapterRunResult } from './runtime.ts';

export interface ProcessWorkerOptions {
  readonly signal?: AbortSignal;
}

// Composition root for a DSH-managed subprocess. The host supplies the
// backend; no model, endpoint, credential, or ambient environment is selected
// by the adapter itself.
export function runProcessHarnessAdapter(
  backend: HarnessBackend,
  options: ProcessWorkerOptions = {},
): Promise<HarnessAdapterRunResult> {
  return runHarnessAdapter({
    backend,
    input: process.stdin,
    output: process.stdout,
    diagnostic: process.stderr,
    signal: options.signal,
  });
}
