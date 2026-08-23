import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  DashboardShapeError,
  parseDashboard,
  renderDashboard,
  startDashboard,
  type DashboardSnapshot,
} from '../src/dashboard.ts';

const VALID = {
  schema: 'aipt.web-dashboard/v1',
  config: {
    schema: 'aipt.config/v1',
    profile: 'development',
    database_identity: 'aipt_development',
    database_namespace: 'aipt_dev',
    evidence_namespace: 'aipt.evidence.development',
  },
  health: { serving_status: 'SERVING', runtime_readiness: 'NOT_ASSERTED' },
  queue: { backend_authority: 'POSTGRESQL', implementation_status: 'NOT_IMPLEMENTED', items: [] },
  run: { implementation_status: 'NOT_IMPLEMENTED', active_run: null },
  status_table: { implementation_status: 'NOT_IMPLEMENTED', seats: [] },
  report: {
    raw_capture: 'IMPLEMENTED_LIBRARY_ONLY',
    ui_export_action: 'NOT_IMPLEMENTED',
    audit_ready_generator: 'NOT_IMPLEMENTED',
    audit_result_generator: 'NOT_IMPLEMENTED',
    signing: 'NOT_IMPLEMENTED',
    encryption: 'NOT_IMPLEMENTED',
    chunking: 'NOT_IMPLEMENTED',
  },
};

class FakeElement {
  className = '';
  textContent: string | null = '';
  readonly children: FakeElement[] = [];
  readonly tagName: string;

  constructor(tagName: string) {
    this.tagName = tagName;
  }

  append(...nodes: FakeElement[]): void {
    this.children.push(...nodes);
  }

  replaceChildren(...nodes: FakeElement[]): void {
    this.children.splice(0, this.children.length, ...nodes);
  }
}

const fakeDocument = {
  createElement(tagName: string): FakeElement {
    return new FakeElement(tagName);
  },
};

function clone(): Record<string, any> {
  return structuredClone(VALID);
}

function allText(node: FakeElement): string[] {
  return [node.textContent ?? '', ...node.children.flatMap(allText)];
}

test('strict parser accepts the exact six-panel snapshot', () => {
  const parsed = parseDashboard(clone());
  assert.deepEqual(Object.keys(parsed), ['schema', 'config', 'health', 'queue', 'run', 'status_table', 'report']);
  assert.equal(parsed.queue.items.length, 0);
  assert.equal(parsed.run.active_run, null);
  assert.equal(parsed.status_table.seats.length, 0);
});

test('strict parser rejects malformed, unknown, and synthetic live state', () => {
  const cases = [
    null,
    {},
    { ...clone(), extra: true },
    { ...clone(), schema: 'aipt.web-dashboard/v2' },
    { ...clone(), health: { serving_status: 'READY', runtime_readiness: 'READY' } },
    { ...clone(), queue: { backend_authority: 'POSTGRESQL', implementation_status: 'READY', items: [] } },
    { ...clone(), queue: { backend_authority: 'POSTGRESQL', implementation_status: 'NOT_IMPLEMENTED', items: [{}] } },
    { ...clone(), run: { implementation_status: 'NOT_IMPLEMENTED', active_run: { id: 'fake' } } },
    { ...clone(), status_table: { implementation_status: 'NOT_IMPLEMENTED', seats: [{ id: 'fake' }] } },
    { ...clone(), report: { ...clone().report, signing: 'IMPLEMENTED' } },
  ];
  for (const candidate of cases) {
    assert.throws(() => parseDashboard(candidate), DashboardShapeError);
  }
});

test('renderer creates exactly six panels and exposes capability truth', () => {
  const root = new FakeElement('main');
  renderDashboard(root, parseDashboard(clone()), fakeDocument);
  assert.equal(root.children.length, 6);
  const text = allText(root);
  for (const title of ['Config', 'Health', 'Queue', 'Run', 'Status / Table', 'Reports']) {
    assert.ok(text.includes(title), `missing ${title}`);
  }
  assert.ok(text.filter((value) => value === 'NOT_IMPLEMENTED').length >= 9);
  assert.ok(text.includes('IMPLEMENTED_LIBRARY_ONLY'));
  assert.ok(text.includes('NOT_ASSERTED'));
});

test('renderer assigns an untrusted-looking value only as text', () => {
  const root = new FakeElement('main');
  const snapshot = parseDashboard(clone()) as DashboardSnapshot;
  const marker = '<img src=x onerror=alert(1)>';
  const mutated = structuredClone(snapshot);
  mutated.config.database_identity = marker;
  renderDashboard(root, mutated, fakeDocument);
  assert.ok(allText(root).includes(marker));
  assert.equal(root.children.filter((node) => node.tagName === 'img').length, 0);
});

test('loader fetches only the fixed same-origin endpoint and fails safely', async () => {
  const root = new FakeElement('main');
  const calls: unknown[][] = [];
  await startDashboard(root, fakeDocument, async (...args: unknown[]) => {
    calls.push(args);
    return {
      ok: true,
      headers: { get: () => 'application/json; charset=utf-8' },
      json: async () => clone(),
    };
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], '/api/v1/dashboard');
  assert.deepEqual(calls[0][1], {
    method: 'GET',
    headers: { Accept: 'application/json' },
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
  });
  assert.equal(root.children.length, 6);

  await startDashboard(root, fakeDocument, async () => ({
    ok: true,
    headers: { get: () => 'application/json' },
    json: async () => ({ leaked: '<script>untrusted</script>' }),
  }));
  assert.equal(root.children.length, 1);
  assert.equal(root.children[0].textContent, 'Dashboard unavailable: strict response validation failed.');
});

test('production source contains no active-content or persistence primitives', async () => {
  const source = await readFile(new URL('../src/dashboard.ts', import.meta.url), 'utf8');
  for (const forbidden of [
    'local' + 'Storage',
    'session' + 'Storage',
    'indexed' + 'DB',
    'inner' + 'HTML',
    'new ' + 'Function',
    'eval' + '(',
    'https' + '://',
    'http' + '://',
  ]) {
    assert.equal(source.includes(forbidden), false, `forbidden source primitive ${forbidden}`);
  }
});
