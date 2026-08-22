import { runProcessHarnessAdapter } from '../src/process-worker.ts';
import { createFixtureBackend, type FixtureBackendMode } from './fixture-backend.ts';

const rawMode = process.argv[2];
const modes = new Set([
  'accept', 'reject', 'fail', 'hang', 'identity-drift', 'invalid-output', 'oversized-output',
]);
if (!rawMode || !modes.has(rawMode)) {
  process.exitCode = 64;
} else {
  const controller = new AbortController();
  let terminationCode: number | undefined;
  const terminate = (code: number) => {
    terminationCode = code;
    controller.abort();
  };
  const onInterrupt = () => terminate(130);
  const onTerminate = () => terminate(143);
  process.once('SIGINT', onInterrupt);
  process.once('SIGTERM', onTerminate);
  try {
    const backend = await createFixtureBackend(rawMode as FixtureBackendMode);
    const result = await runProcessHarnessAdapter(backend, { signal: controller.signal });
    process.exitCode = terminationCode ?? (result.ok ? 0 : 1);
  } finally {
    process.removeListener('SIGINT', onInterrupt);
    process.removeListener('SIGTERM', onTerminate);
  }
}
