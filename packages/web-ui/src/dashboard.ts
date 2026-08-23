export const DASHBOARD_ENDPOINT = '/api/v1/dashboard';
export const DASHBOARD_SCHEMA = 'aipt.web-dashboard/v1';
export const NOT_IMPLEMENTED = 'NOT_IMPLEMENTED';

export interface ConfigPanel {
  schema: 'aipt.config/v1';
  profile: 'development' | 'production';
  database_identity: string;
  database_namespace: string;
  evidence_namespace: string;
}

export interface HealthPanel {
  serving_status: 'SERVING';
  runtime_readiness: 'NOT_ASSERTED';
}

export interface QueuePanel {
  backend_authority: 'POSTGRESQL';
  implementation_status: 'NOT_IMPLEMENTED';
  items: [];
}

export interface RunPanel {
  implementation_status: 'NOT_IMPLEMENTED';
  active_run: null;
}

export interface StatusTablePanel {
  implementation_status: 'NOT_IMPLEMENTED';
  seats: [];
}

export interface ReportPanel {
  raw_capture: 'IMPLEMENTED_LIBRARY_ONLY';
  ui_export_action: 'NOT_IMPLEMENTED';
  audit_ready_generator: 'NOT_IMPLEMENTED';
  audit_result_generator: 'NOT_IMPLEMENTED';
  signing: 'NOT_IMPLEMENTED';
  encryption: 'NOT_IMPLEMENTED';
  chunking: 'NOT_IMPLEMENTED';
}

export interface DashboardSnapshot {
  schema: 'aipt.web-dashboard/v1';
  config: ConfigPanel;
  health: HealthPanel;
  queue: QueuePanel;
  run: RunPanel;
  status_table: StatusTablePanel;
  report: ReportPanel;
}

interface ElementLike {
  className: string;
  textContent: string | null;
  append(...nodes: ElementLike[]): void;
  replaceChildren(...nodes: ElementLike[]): void;
}

interface DocumentLike {
  createElement(tagName: string): ElementLike;
}

interface FetchResponseLike {
  ok: boolean;
  headers: { get(name: string): string | null };
  json(): Promise<unknown>;
}

type FetchLike = (input: string, init: Record<string, unknown>) => Promise<FetchResponseLike>;
type JsonRecord = Record<string, unknown>;

const ROOT_KEYS = ['schema', 'config', 'health', 'queue', 'run', 'status_table', 'report'];
const CONFIG_KEYS = ['schema', 'profile', 'database_identity', 'database_namespace', 'evidence_namespace'];
const HEALTH_KEYS = ['serving_status', 'runtime_readiness'];
const QUEUE_KEYS = ['backend_authority', 'implementation_status', 'items'];
const RUN_KEYS = ['implementation_status', 'active_run'];
const STATUS_TABLE_KEYS = ['implementation_status', 'seats'];
const REPORT_KEYS = [
  'raw_capture',
  'ui_export_action',
  'audit_ready_generator',
  'audit_result_generator',
  'signing',
  'encryption',
  'chunking',
];
const POSTGRES_IDENTIFIER = /^[a-z_][a-z0-9_]{0,62}$/u;
const EVIDENCE_NAMESPACE = /^[a-z][a-z0-9_]*([.-][a-z0-9_]+)*$/u;

export class DashboardShapeError extends Error {
  readonly code = 'AIPT_WEB_INVALID_DASHBOARD';

  constructor() {
    super('dashboard response failed its strict contract');
    this.name = 'DashboardShapeError';
  }
}

function fail(): never {
  throw new DashboardShapeError();
}

function exactObject(value: unknown, keys: readonly string[]): JsonRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) fail();
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail();
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== 'string')) fail();
  const actual = (ownKeys as string[]).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of actual) {
    const descriptor = descriptors[key];
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) fail();
  }
  return value as JsonRecord;
}

function exactString(record: JsonRecord, key: string, expected: string): string {
  const value = record[key];
  if (value !== expected) fail();
  return value;
}

function boundedString(record: JsonRecord, key: string, maximum: number, pattern: RegExp): string {
  const value = record[key];
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum || !pattern.test(value)) fail();
  return value;
}

function exactEmptyArray(record: JsonRecord, key: string): [] {
  const value = record[key];
  if (!Array.isArray(value) || value.length !== 0) fail();
  return [];
}

function parseConfig(value: unknown): ConfigPanel {
  const record = exactObject(value, CONFIG_KEYS);
  const profile = record.profile;
  if (profile !== 'development' && profile !== 'production') fail();
  return {
    schema: exactString(record, 'schema', 'aipt.config/v1') as 'aipt.config/v1',
    profile,
    database_identity: boundedString(record, 'database_identity', 63, POSTGRES_IDENTIFIER),
    database_namespace: boundedString(record, 'database_namespace', 63, POSTGRES_IDENTIFIER),
    evidence_namespace: boundedString(record, 'evidence_namespace', 128, EVIDENCE_NAMESPACE),
  };
}

function parseHealth(value: unknown): HealthPanel {
  const record = exactObject(value, HEALTH_KEYS);
  return {
    serving_status: exactString(record, 'serving_status', 'SERVING') as 'SERVING',
    runtime_readiness: exactString(record, 'runtime_readiness', 'NOT_ASSERTED') as 'NOT_ASSERTED',
  };
}

function parseQueue(value: unknown): QueuePanel {
  const record = exactObject(value, QUEUE_KEYS);
  return {
    backend_authority: exactString(record, 'backend_authority', 'POSTGRESQL') as 'POSTGRESQL',
    implementation_status: exactString(record, 'implementation_status', NOT_IMPLEMENTED) as 'NOT_IMPLEMENTED',
    items: exactEmptyArray(record, 'items'),
  };
}

function parseRun(value: unknown): RunPanel {
  const record = exactObject(value, RUN_KEYS);
  if (record.active_run !== null) fail();
  return {
    implementation_status: exactString(record, 'implementation_status', NOT_IMPLEMENTED) as 'NOT_IMPLEMENTED',
    active_run: null,
  };
}

function parseStatusTable(value: unknown): StatusTablePanel {
  const record = exactObject(value, STATUS_TABLE_KEYS);
  return {
    implementation_status: exactString(record, 'implementation_status', NOT_IMPLEMENTED) as 'NOT_IMPLEMENTED',
    seats: exactEmptyArray(record, 'seats'),
  };
}

function parseReport(value: unknown): ReportPanel {
  const record = exactObject(value, REPORT_KEYS);
  return {
    raw_capture: exactString(record, 'raw_capture', 'IMPLEMENTED_LIBRARY_ONLY') as 'IMPLEMENTED_LIBRARY_ONLY',
    ui_export_action: exactString(record, 'ui_export_action', NOT_IMPLEMENTED) as 'NOT_IMPLEMENTED',
    audit_ready_generator: exactString(record, 'audit_ready_generator', NOT_IMPLEMENTED) as 'NOT_IMPLEMENTED',
    audit_result_generator: exactString(record, 'audit_result_generator', NOT_IMPLEMENTED) as 'NOT_IMPLEMENTED',
    signing: exactString(record, 'signing', NOT_IMPLEMENTED) as 'NOT_IMPLEMENTED',
    encryption: exactString(record, 'encryption', NOT_IMPLEMENTED) as 'NOT_IMPLEMENTED',
    chunking: exactString(record, 'chunking', NOT_IMPLEMENTED) as 'NOT_IMPLEMENTED',
  };
}

// parseDashboard validates every member and returns a fresh, inert snapshot.
// Unknown members, schemas, statuses, fake rows, and fake active runs fail.
export function parseDashboard(value: unknown): DashboardSnapshot {
  const root = exactObject(value, ROOT_KEYS);
  return {
    schema: exactString(root, 'schema', DASHBOARD_SCHEMA) as 'aipt.web-dashboard/v1',
    config: parseConfig(root.config),
    health: parseHealth(root.health),
    queue: parseQueue(root.queue),
    run: parseRun(root.run),
    status_table: parseStatusTable(root.status_table),
    report: parseReport(root.report),
  };
}

function element(documentLike: DocumentLike, tagName: string, className: string, text: string): ElementLike {
  const node = documentLike.createElement(tagName);
  node.className = className;
  node.textContent = text;
  return node;
}

function row(documentLike: DocumentLike, label: string, value: string): ElementLike {
  const item = element(documentLike, 'div', 'fact', '');
  item.append(
    element(documentLike, 'span', 'fact-label', label),
    element(documentLike, 'span', value === NOT_IMPLEMENTED ? 'status not-implemented' : 'status', value),
  );
  return item;
}

function panel(documentLike: DocumentLike, title: string, variant: string, rows: readonly [string, string][]): ElementLike {
  const article = element(documentLike, 'article', `panel panel-${variant}`, '');
  article.append(element(documentLike, 'h2', 'panel-title', title));
  const body = element(documentLike, 'div', 'panel-body', '');
  for (const [label, value] of rows) body.append(row(documentLike, label, value));
  article.append(body);
  return article;
}

// renderDashboard creates only trusted elements and assigns textContent for
// every value. It never interprets snapshot strings as markup.
export function renderDashboard(root: ElementLike, snapshot: DashboardSnapshot, documentLike: DocumentLike): void {
  root.replaceChildren(
    panel(documentLike, 'Config', 'config', [
      ['Schema', snapshot.config.schema],
      ['Profile', snapshot.config.profile],
      ['Database', snapshot.config.database_identity],
      ['Namespace', snapshot.config.database_namespace],
      ['Evidence', snapshot.config.evidence_namespace],
    ]),
    panel(documentLike, 'Health', 'health', [
      ['Serving', snapshot.health.serving_status],
      ['Runtime readiness', snapshot.health.runtime_readiness],
    ]),
    panel(documentLike, 'Queue', 'queue', [
      ['Authority', snapshot.queue.backend_authority],
      ['Implementation', snapshot.queue.implementation_status],
      ['Items', String(snapshot.queue.items.length)],
    ]),
    panel(documentLike, 'Run', 'run', [
      ['Implementation', snapshot.run.implementation_status],
      ['Active run', 'None'],
    ]),
    panel(documentLike, 'Status / Table', 'status-table', [
      ['Implementation', snapshot.status_table.implementation_status],
      ['Seats', String(snapshot.status_table.seats.length)],
    ]),
    panel(documentLike, 'Reports', 'reports', [
      ['RAW_CAPTURE', snapshot.report.raw_capture],
      ['UI export action', snapshot.report.ui_export_action],
      ['AUDIT_READY generator', snapshot.report.audit_ready_generator],
      ['AUDIT_RESULT generator', snapshot.report.audit_result_generator],
      ['Signing', snapshot.report.signing],
      ['Encryption', snapshot.report.encryption],
      ['Chunking', snapshot.report.chunking],
    ]),
  );
}

function renderFailure(root: ElementLike, documentLike: DocumentLike): void {
  root.replaceChildren(element(documentLike, 'p', 'dashboard-error', 'Dashboard unavailable: strict response validation failed.'));
}

export async function startDashboard(root: ElementLike, documentLike: DocumentLike, fetcher: FetchLike): Promise<void> {
  try {
    const response = await fetcher(DASHBOARD_ENDPOINT, {
      method: 'GET',
      headers: { Accept: 'application/json' },
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
    });
    const contentType = response.headers.get('content-type') ?? '';
    if (!response.ok || !contentType.toLowerCase().startsWith('application/json')) fail();
    renderDashboard(root, parseDashboard(await response.json()), documentLike);
  } catch {
    renderFailure(root, documentLike);
  }
}

declare const document: {
  getElementById(id: string): ElementLike | null;
  createElement(tagName: string): ElementLike;
};
declare const fetch: FetchLike;

if (typeof document !== 'undefined') {
  const root = document.getElementById('aipt-dashboard');
  if (root !== null) void startDashboard(root, document, fetch);
}
