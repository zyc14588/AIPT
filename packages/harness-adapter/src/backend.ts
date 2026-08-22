import type { JsonRpcNotification, JsonRpcRequest, JsonRpcResponse } from '@aipt/adapter-sdk';

export interface HarnessBackendResult {
  readonly response: JsonRpcResponse;
  readonly notifications?: readonly JsonRpcNotification[];
}

// Harness-neutral seam. A production host supplies the implementation; this
// package owns only protocol framing, validation, ordering, and cancellation.
export interface HarnessBackend {
  applyAction(
    request: JsonRpcRequest,
    signal: AbortSignal,
  ): Promise<HarnessBackendResult> | HarnessBackendResult;
  close?(signal: AbortSignal): Promise<void> | void;
}
