import test from 'node:test';
import assert from 'node:assert/strict';
import { envelope, readDashboard, readResponse, readDownload } from '../src/controls.ts';
function dashboard() {
 return { schema: 'aipt.web-operational/v1', config: { schema: 'aipt.config/v1', profile: 'development', database_identity: 'test', database_namespace: 'test', evidence_namespace: 'test' }, health: { serving_status: 'SERVING', runtime_readiness: 'NOT_ASSERTED' }, control: { schema: 'aipt.run-control/v1', queue_authority: 'POSTGRESQL_B001_QUEUESTORE', gameplay_authority: 'B002_APPEND_ONLY_POSTGRESQL_LEDGER', paused: false, truncated: false, items: [], registrations: [], executor_configured: false, qualification_execution_authorized: false, worker_run_id: null, worker_last_error: null } };
}
test('dashboard rejects authority drift, private fields and premature readiness', () => {
 assert.deepEqual(readDashboard(dashboard()), dashboard());
 for (const mutate of [
  (value: any) => { value.config.dsn = 'private'; },
  (value: any) => { value.health.runtime_readiness = 'READY'; },
  (value: any) => { value.control.qualification_execution_authorized = true; },
  (value: any) => { value.control.queue_authority = 'IN_MEMORY'; },
  (value: any) => { value.control.items = [{ run_id: 'run-a', lease_token: 'private' }]; },
  (value: any) => { value.control.schema = 'aipt.run-control/v2'; },
 ]) { const value = dashboard(); mutate(value); assert.throws(() => readDashboard(value)); }
});
test('versioned responses bind request ID and reject ambiguous or private errors', () => {
 assert.deepEqual(envelope('a', 'aipt.v1.queue.pause', { paused: true }), { jsonrpc: '2.0', protocol_version: 1, id: 'a', method: 'aipt.v1.queue.pause', params: { paused: true } });
 assert.equal(readResponse({ jsonrpc: '2.0', protocol_version: 1, id: 'a', result: 'ok' }, 'a'), 'ok');
 for (const value of [ { jsonrpc: '2.0', protocol_version: 1, id: 'other', result: 'ok' }, { jsonrpc: '2.0', protocol_version: 1, id: 'a', result: 'ok', error: { code: -32000, message: 'private/path' } }, { jsonrpc: '2.0', protocol_version: 1, id: 'a', error: { code: -32000, message: 'postgresql://private' } }, { jsonrpc: '2.0', protocol_version: 2, id: 'a', result: 'ok' } ]) assert.throws(() => readResponse(value, 'a'));
 assert.throws(() => envelope('bad\n', 'aipt.v1.queue.pause', {}));
});
test('report download rejects raw/private names and active HTML media type', () => {
 const valid = { filename: 'run-report.html', media_type: 'application/octet-stream', sha256: 'a'.repeat(64), data_base64: Buffer.from('public report').toString('base64') };
 assert.equal(new TextDecoder().decode(readDownload(valid).bytes), 'public report');
 for (const change of [ { filename: '../../credential' }, { filename: 'raw-capture-events.ndjson' }, { media_type: 'text/html' }, { sha256: 'invalid' }, { data_base64: '***' }, { data_base64: 'AAAA'.repeat(700000) } ]) assert.throws(() => readDownload({ ...valid, ...change }));
});
