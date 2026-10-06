// Generated from packages/web-ui/src/controls.ts with exact Node 24.19.0 type stripping.
// Dependency-free operational UI. All authority remains in the Go service.
                                                  
function object(value         )                       {
 return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function string(value         )                  { return typeof value === 'string'; }
function strings(value         )                    { return Array.isArray(value) && value.every(string); }
function exact(value             , keys          )          {
 return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
export function envelope(id        , method        , params             )              {
 if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(id) || !method.startsWith('aipt.v1.')) throw new Error('INVALID_REQUEST');
 return { jsonrpc: '2.0', protocol_version: 1, id, method, params };
}
export function readDashboard(value         )              {
 if (!object(value) || !exact(value, ['schema', 'config', 'health', 'control']) || value.schema !== 'aipt.web-operational/v1') throw new Error('INVALID_DASHBOARD');
 const config = value.config;
 if (!object(config) || !exact(config, ['schema', 'profile', 'database_identity', 'database_namespace', 'evidence_namespace']) || config.schema !== 'aipt.config/v1' || !Object.values(config).every(string)) throw new Error('INVALID_CONFIG_VIEW');
 const health = value.health;
 if (!object(health) || !exact(health, ['serving_status', 'runtime_readiness']) || health.serving_status !== 'SERVING' || health.runtime_readiness !== 'NOT_ASSERTED') throw new Error('INVALID_HEALTH_VIEW');
 const c = value.control;
 if (!object(c) || !exact(c, ['schema', 'queue_authority', 'gameplay_authority', 'paused', 'truncated', 'items', 'registrations', 'executor_configured', 'qualification_execution_authorized', 'worker_run_id', 'worker_last_error']) || c.schema !== 'aipt.run-control/v1' || c.queue_authority !== 'POSTGRESQL_B001_QUEUESTORE' || c.gameplay_authority !== 'B002_APPEND_ONLY_POSTGRESQL_LEDGER' || typeof c.paused !== 'boolean' || typeof c.truncated !== 'boolean' || typeof c.executor_configured !== 'boolean' || c.qualification_execution_authorized !== false || !(c.worker_run_id === null || string(c.worker_run_id)) || !(c.worker_last_error === null || string(c.worker_last_error))) throw new Error('INVALID_CONTROL_VIEW');
 if (!Array.isArray(c.items) || c.items.length > 100 || !c.items.every(item => object(item) && exact(item, ['run_id', 'manifest_id', 'manifest_sha256', 'case_id', 'run_type', 'classification', 'qualification_eligible', 'priority', 'status', 'queued_at', 'eligible_after']) && ['run_id', 'manifest_id', 'manifest_sha256', 'case_id', 'run_type', 'classification', 'priority', 'status', 'queued_at', 'eligible_after'].every(key => string(item[key])) && ['QUEUED', 'LEASED', 'COMPLETED', 'CANCELED'].includes(item.status          ) && typeof item.qualification_eligible === 'boolean')) throw new Error('INVALID_QUEUE_VIEW');
 if (!Array.isArray(c.registrations) || c.registrations.length > 64 || !c.registrations.every(item => object(item) && exact(item, ['registration_id', 'run_id', 'manifest_id', 'manifest_sha256', 'classification']) && Object.values(item).every(string))) throw new Error('INVALID_REGISTRATIONS');
 return value;
}
export function readResponse(value         , expectedID        )          {
 if (!object(value) || value.jsonrpc !== '2.0' || value.protocol_version !== 1 || value.id !== expectedID) throw new Error('INVALID_RESPONSE');
 if (Object.hasOwn(value, 'error')) {
  if (!exact(value, ['jsonrpc', 'protocol_version', 'id', 'error']) || !object(value.error) || !exact(value.error, ['code', 'message']) || !Number.isInteger(value.error.code) || !string(value.error.message) || !/^AIPT_RUN_CONTROL_[A-Z_]+$/.test(value.error.message)) throw new Error('INVALID_ERROR');
  throw new Error(value.error.message);
 }
 if (!exact(value, ['jsonrpc', 'protocol_version', 'id', 'result'])) throw new Error('INVALID_RESPONSE');
 return value.result;
}
export function readDownload(value         )                                                                             {
 const files                         = { 'run-report.json': 'application/json', 'run-report.md': 'text/markdown; charset=utf-8', 'run-report.csv': 'text/csv; charset=utf-8', 'run-report.junit.xml': 'application/xml', 'run-report.html': 'application/octet-stream' };
 if (!object(value) || !exact(value, ['filename', 'media_type', 'sha256', 'data_base64']) || !string(value.filename) || files[value.filename] !== value.media_type || !string(value.sha256) || !/^[0-9a-f]{64}$/.test(value.sha256) || !string(value.data_base64) || value.data_base64.length > 2796204 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value.data_base64)) throw new Error('INVALID_DOWNLOAD');
 const decoded = atob(value.data_base64);
 if (decoded.length > 2097152) throw new Error('INVALID_DOWNLOAD');
 return { filename: value.filename, mediaType: value.media_type          , sha256: value.sha256, bytes: Uint8Array.from(decoded, char => char.charCodeAt(0)) };
}

if (typeof document !== 'undefined') {
 let csrf = '';
 let sequence = 0;
 let busy = false;
 let paused = false;
 let selected                = null;
 const element = (id        )              => {
  const value = document.getElementById(id);
  if (!value) throw new Error('UI_UNAVAILABLE');
  return value;
 };
 const button = (id        )                    => element(id)                     ;
 const notice = (message        )       => { element('notice').textContent = message; };
 const label = (parent             , key        , value         )       => {
  const term = document.createElement('dt'); term.textContent = key;
  const detail = document.createElement('dd'); detail.textContent = String(value);
  parent.append(term, detail);
 };
 const call = async (method        , params             )                   => {
  const id = `web-${++sequence}`;
  const response = await fetch('/api/v1/control', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json', 'X-AIPT-CSRF': csrf }, body: JSON.stringify(envelope(id, method, params)) });
  return readResponse(await response.json(), id);
 };
 const action = async (work                     )                => {
  if (busy) return;
  busy = true;
  try { await work(); } catch (error) { notice(error instanceof Error ? error.message : '请求未完成'); }
  finally { busy = false; }
 };
 const showRun = async (id        )                => {
  const detail = await call('aipt.v1.run.get', { run_id: id });
  if (!object(detail) || !object(detail.run) || !Array.isArray(detail.seats) || !Array.isArray(detail.attempts)) throw new Error('INVALID_RUN_VIEW');
  selected = id;
  element('run-summary').textContent = `${id} · ${String(detail.run.status)} · ${String(detail.run.manifest_sha256)}`;
  element('attempts').replaceChildren();
  for (const item of detail.attempts) {
   if (!object(item)) throw new Error('INVALID_ATTEMPT_VIEW');
   const row = document.createElement('li'); row.textContent = `${String(item.number)} · ${String(item.kind)} · ${String(item.outcome)}`; element('attempts').append(row);
  }
  element('seats').replaceChildren();
  for (const seat of detail.seats) {
   if (!object(seat)) throw new Error('INVALID_SEAT_VIEW');
   const row = document.createElement('li'); row.textContent = `${String(seat.seat_id)} · ${String(seat.role_id)} · ${String(seat.model_assignment_id)} · ${String(seat.assignment_status)}`; element('seats').append(row);
  }
  element('report-formats').replaceChildren();
  element('report-summary').textContent = '此 Run 的报告尚未核验。';
  button('inspect-report').disabled = false;
 };
 const refresh = async ()                => {
  const response = await fetch('/api/v1/dashboard', { credentials: 'same-origin' });
  if (!response.ok) throw new Error('读取队列失败');
  const data = readDashboard(await response.json());
  const control = data.control               ;
  paused = control.paused           ;
  element('connection').textContent = '已连接 · 本机';
  element('config').replaceChildren();
  const config = data.config               ;
  label(element('config'), 'Profile', config.profile); label(element('config'), '数据库', config.database_identity); label(element('config'), '数据库 namespace', config.database_namespace); label(element('config'), '证据 namespace', config.evidence_namespace);
  element('health').replaceChildren();
  label(element('health'), 'Web', 'SERVING'); label(element('health'), '完整 Runtime', '尚未验收'); label(element('health'), 'Run 执行器', control.executor_configured ? '已配置' : '待配置'); label(element('health'), '资格执行授权', '尚未开放');
  if (control.worker_run_id) label(element('health'), '当前 Worker Run', control.worker_run_id);
  if (control.worker_last_error) label(element('health'), '最近运行结果', control.worker_last_error);
  button('pause').disabled = false; button('pause').textContent = paused ? '恢复新领取' : '暂停新领取'; button('recover').disabled = false;
  button('run-next').disabled = !control.executor_configured || paused || control.worker_run_id !== null;
  element('queue-note').textContent = `${paused ? '已暂停新领取；当前 Run 不受影响。' : '允许新领取。'}${control.executor_configured ? '' : ' 真实任务执行器尚未配置。'}${control.truncated ? ' 仅显示前 100 项。' : ''}`;
  const select = element('registration')                     ;
  const previous = select.value; select.replaceChildren();
  const registrations = control.registrations                 ;
  for (const item of registrations) {
   if (item.classification !== 'DIAGNOSTIC') continue;
   const option = document.createElement('option'); option.value = item.registration_id          ; option.textContent = item.run_id          ; select.append(option);
  }
  if (select.options.length === 0) { const option = document.createElement('option'); option.value = ''; option.textContent = '暂无登记'; select.append(option); }
  if ([...select.options].some(option => option.value === previous)) select.value = previous;
  button('enqueue').disabled = select.value === '';
  element('queue-items').replaceChildren();
  for (const item of control.items                 ) {
   const row = document.createElement('tr');
   for (const field of ['run_id', 'classification', 'priority', 'status']) { const cell = document.createElement('td'); cell.textContent = String(item[field]); row.append(cell); }
   const actions = document.createElement('td');
   const view = document.createElement('button'); view.type = 'button'; view.textContent = '查看'; view.addEventListener('click', () => { void action(() => showRun(item.run_id          )); }); actions.append(view);
   if (item.status === 'QUEUED') { const cancel = document.createElement('button'); cancel.type = 'button'; cancel.textContent = '取消'; cancel.addEventListener('click', () => { void action(async () => { await call('aipt.v1.queue.cancel', { run_id: item.run_id }); notice('排队 Run 已取消，记录保留。'); await refresh(); }); }); actions.append(cancel); }
   row.append(actions); element('queue-items').append(row);
  }
 };
 button('refresh').addEventListener('click', () => { void action(refresh); });
 button('enqueue').addEventListener('click', () => { void action(async () => { await call('aipt.v1.queue.enqueue', { registration_id: (element('registration')                     ).value }); notice('Run 已加入数据库队列。'); await refresh(); }); });
 button('pause').addEventListener('click', () => { void action(async () => { await call('aipt.v1.queue.pause', { paused: !paused }); notice('队列领取状态已更新。'); await refresh(); }); });
 button('recover').addEventListener('click', () => { void action(async () => { await call('aipt.v1.queue.recover', {}); notice('过期租约恢复已执行。'); await refresh(); }); });
 button('run-next').addEventListener('click', () => { void action(async () => { await call('aipt.v1.run.next', {}); notice('数据库选中的下一场已开始。'); await refresh(); }); });
 button('inspect-report').addEventListener('click', () => { void action(async () => {
  const id = selected; if (id === null) return;
  const report = await call('aipt.v1.report.inspect', { run_id: id });
  if (!object(report) || report.run_id !== id || !string(report.root) || !strings(report.formats)) throw new Error('INVALID_REPORT_VIEW');
  element('report-summary').textContent = `${String(report.report_id)} · ${String(report.execution_status)} · ${report.root}`;
  element('report-formats').replaceChildren();
  for (const format of report.formats) {
   if (!['json', 'md', 'csv', 'junit', 'html'].includes(format)) throw new Error('INVALID_REPORT_FORMAT');
   const exportButton = document.createElement('button'); exportButton.type = 'button'; exportButton.textContent = `导出 ${format.toUpperCase()}`;
   exportButton.addEventListener('click', () => { void action(async () => {
    const download = readDownload(await call('aipt.v1.report.export', { run_id: id, format }));
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', download.bytes));
    const actual = Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
    if (actual !== download.sha256) throw new Error('DOWNLOAD_DIGEST_MISMATCH');
    const url = URL.createObjectURL(new Blob([download.bytes], { type: download.mediaType }));
    try { const link = document.createElement('a'); link.href = url; link.download = download.filename; link.click(); notice(`已导出 ${download.filename} · SHA-256 ${actual}`); }
    finally { URL.revokeObjectURL(url); }
   }); }); element('report-formats').append(exportButton);
  }
 }); });
 void action(async () => {
  const response = await fetch('/api/v1/session', { credentials: 'same-origin' }); const session = await response.json();
  if (!object(session) || !exact(session, ['schema', 'csrf_token']) || session.schema !== 'aipt.web-session/v1' || !string(session.csrf_token) || !/^[A-Za-z0-9_-]{43}$/.test(session.csrf_token)) throw new Error('INVALID_SESSION');
  csrf = session.csrf_token; await refresh();
 });
}
