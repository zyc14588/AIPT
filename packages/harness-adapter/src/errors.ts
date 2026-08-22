export const HARNESS_ADAPTER_ERROR_CODES = [
  'AIPT_HARNESS_BACKEND_FAILED',
  'AIPT_HARNESS_CANCELLED',
  'AIPT_HARNESS_FRAME_TOO_LARGE',
  'AIPT_HARNESS_INVALID_REQUEST',
  'AIPT_HARNESS_INVALID_UTF8',
  'AIPT_HARNESS_OUTPUT_INVALID',
  'AIPT_HARNESS_PARTIAL_FRAME',
  'AIPT_HARNESS_RESPONSE_IDENTITY_MISMATCH',
  'AIPT_HARNESS_WRITE_FAILED',
] as const;

export type HarnessAdapterErrorCode = (typeof HARNESS_ADAPTER_ERROR_CODES)[number];

export class HarnessAdapterError extends Error {
  readonly code: HarnessAdapterErrorCode;

  constructor(code: HarnessAdapterErrorCode) {
    super(code);
    this.name = 'HarnessAdapterError';
    this.code = code;
  }
}

export function asHarnessAdapterError(error: unknown): HarnessAdapterError {
  if (error instanceof HarnessAdapterError) return error;
  return new HarnessAdapterError('AIPT_HARNESS_BACKEND_FAILED');
}
