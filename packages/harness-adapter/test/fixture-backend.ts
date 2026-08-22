import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import {
  decodeNotification,
  decodeRequest,
  decodeResponse,
  encodeRequest,
  type JsonRpcNotification,
  type JsonRpcRequest,
  type JsonRpcResponse,
} from '@aipt/adapter-sdk';
import {
  HarnessAdapterError,
  type HarnessBackend,
  type HarnessBackendResult,
} from '../src/index.ts';

export type FixtureBackendMode =
  | 'accept'
  | 'reject'
  | 'fail'
  | 'hang'
  | 'identity-drift'
  | 'invalid-output'
  | 'oversized-output';

const FIXTURE_ROOT = fileURLToPath(new URL(
  '../../../testdata/protocol/v1/minimal-fixture/',
  import.meta.url,
));

async function fixtureText(relative: string): Promise<string> {
  return readFile(new URL(relative, new URL(
    '../../../testdata/protocol/v1/minimal-fixture/',
    import.meta.url,
  )), 'utf8');
}

export async function createFixtureBackend(mode: FixtureBackendMode): Promise<HarnessBackend> {
  if (!FIXTURE_ROOT.endsWith('testdata/protocol/v1/minimal-fixture/')) {
    throw new HarnessAdapterError('AIPT_HARNESS_BACKEND_FAILED');
  }
  const canonicalRequest = decodeRequest(await fixtureText('requests/apply-action-request.json'));
  const acceptedResponse = decodeResponse(
    await fixtureText('responses/apply-action-result-response.json'),
  );
  const rejectedResponse = decodeResponse(
    await fixtureText('responses/apply-action-protocol-error-response.json'),
  );
  const notification = decodeNotification(
    await fixtureText('notifications/state-event-notification.json'),
  );

  return {
    applyAction(request: JsonRpcRequest): Promise<HarnessBackendResult> | HarnessBackendResult {
      if (encodeRequest(request) !== encodeRequest(canonicalRequest)) {
        throw new HarnessAdapterError('AIPT_HARNESS_BACKEND_FAILED');
      }
      if (mode === 'hang') return new Promise(() => {});
      if (mode === 'fail') {
        throw new Error('TEST_MARKER_MUST_NEVER_REACH_DIAGNOSTICS');
      }
      if (mode === 'identity-drift') {
        return {
          response: {
            ...acceptedResponse,
            fixture_id: 'different-fixture',
          } as JsonRpcResponse,
        };
      }
      if (mode === 'invalid-output') {
        return {
          response: acceptedResponse,
          unexpected: true,
        } as unknown as HarnessBackendResult;
      }
      if (mode === 'oversized-output') {
        if (!('result' in acceptedResponse)) {
          throw new HarnessAdapterError('AIPT_HARNESS_BACKEND_FAILED');
        }
        return {
          response: {
            ...acceptedResponse,
            result: {
              ...acceptedResponse.result,
              applied_fields: acceptedResponse.result.applied_fields.map((field, index) =>
                index === 0 ? { ...field, value: 'x'.repeat(1024 * 1024) } : field),
            },
          },
        };
      }
      if (mode === 'reject') return { response: rejectedResponse };
      return {
        response: acceptedResponse,
        notifications: [notification as JsonRpcNotification],
      };
    },
  };
}
