#!/usr/bin/env node
// AIPT-M0-B007 strict local Web/UI validator. Node standard library only.
import fs from 'node:fs';
import path from 'node:path';
import { stripTypeScriptTypes } from 'node:module';

import { checkSchemaDocument, validateInstance } from '../lib/json-schema.mjs';
import { git, runAsMain } from '../lib/cli.mjs';

const BASE_COMMIT = 'e1e1a6315ef2308922105dd30fd4bbcf4e3f91c8';
const EXACT_NODE = '24.19.0';
const WEB_SCHEMA_PATH = 'schemas/web/v1/aipt-web.schema.json';
const UI_PACKAGE_PATH = 'packages/web-ui/package.json';
const TS_PATH = 'packages/web-ui/src/dashboard.ts';
const ARTIFACT_PATH = 'internal/web/static/app.js';
const MIGRATION_PATH = 'internal/storage/postgres/migrations/000001_ledger.sql';

const SOURCE_PATHS = [
  'internal/web/contracts.go',
  'internal/web/security.go',
  'internal/web/server.go',
  'internal/web/config_health.go',
  'internal/web/capabilities.go',
  'internal/web/routes.go',
  'internal/web/static.go',
  'internal/web/contracts_test.go',
  'internal/web/security_test.go',
  'internal/web/config_health_test.go',
  'internal/web/capabilities_test.go',
  'internal/web/routes_test.go',
  'internal/web/smoke_test.go',
  'internal/web/static/index.html',
  'internal/web/static/styles.css',
  ARTIFACT_PATH,
  TS_PATH,
  'packages/web-ui/test/dashboard.test.ts',
  'packages/web-ui/scripts/build.mjs',
  'internal/launcher/dependencies.go',
  'internal/launcher/gates.go',
  'internal/launcher/launcher.go',
  'internal/launcher/launcher_test.go',
  'pnpm-lock.yaml',
];

const PRODUCTION_WEB_PATHS = [
  'internal/web/contracts.go',
  'internal/web/security.go',
  'internal/web/server.go',
  'internal/web/config_health.go',
  'internal/web/capabilities.go',
  'internal/web/routes.go',
  'internal/web/static.go',
];

const FROZEN_SURFACES = [
  'schemas/config',
  'internal/config',
  'schemas/protocol',
  'internal/protocol',
  'packages/adapter-sdk',
  'internal/storage/postgres/migrations',
  'internal/storage/postgres/ledger.go',
  'internal/storage/postgres/verify.go',
  'schemas/evidence',
  'internal/evidence',
  'packages/harness-adapter',
  'internal/core',
  'go.mod',
  'go.sum',
  'pnpm-workspace.yaml',
  'tools',
];

const ROOT_KEYS = ['schema', 'config', 'health', 'queue', 'run', 'status_table', 'report'];
const PANEL_KEYS = ['config', 'health', 'queue', 'run', 'status_table', 'report'];
const PANEL_TITLES = ['Config', 'Health', 'Queue', 'Run', 'Status / Table', 'Reports'];
const GATE_ORDER = ['GateConfig', 'GatePostgreSQL', 'GateMigrations', 'GateModel', 'GateHarness', 'GateCore', 'GateIPC', 'GateWeb'];

function canonicalSnapshot() {
  return {
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
}

function same(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function objectSchemaNodes(root) {
  const nodes = [];
  const visit = (node) => {
    if (!node || typeof node !== 'object' || Array.isArray(node)) return;
    if (node.type === 'object' || node.properties) nodes.push(node);
    for (const containerName of ['properties', '$defs']) {
      const container = node[containerName];
      if (!container || typeof container !== 'object' || Array.isArray(container)) continue;
      for (const child of Object.values(container)) visit(child);
    }
  };
  visit(root);
  return nodes;
}

function expectedArtifact(source) {
  const stripped = stripTypeScriptTypes(source, { mode: 'strip', sourceMap: false });
  return [
    '// Generated deterministically from packages/web-ui/src/dashboard.ts.',
    '// Exact generator: Node 24.19.0 node:module.stripTypeScriptTypes mode=strip.',
    '// Do not edit this served artifact directly.',
    stripped,
  ].join('\n');
}

function parseGateOrder(source) {
  const match = /var fixedGateOrder = \[\.\.\.\]Gate\{([\s\S]*?)\n\}/.exec(source);
  return match ? [...match[1].matchAll(/\bGate[A-Za-z]+\b/g)].map((item) => item[0]) : [];
}

function workspaceImporters(lock) {
  const lines = lock.split('\n');
  const start = lines.indexOf('importers:');
  if (start < 0) return [];
  const importers = [];
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (line.length > 0 && !line.startsWith(' ')) break;
    const match = /^  ([^\s][^:]*):(?:\s*\{\})?$/.exec(line);
    if (match) importers.push(match[1]);
  }
  return importers;
}

function evaluate(input) {
  const problems = [];
  const requireText = (text, pattern, message) => {
    if (!pattern.test(text)) problems.push(message);
  };
  const forbidText = (text, pattern, message) => {
    if (pattern.test(text)) problems.push(message);
  };
  const files = input.files;
  for (const required of SOURCE_PATHS) {
    if (typeof files[required] !== 'string') problems.push(`required Web source missing: ${required}`);
  }
  if (problems.length) return problems;

  const schema = input.schema;
  const meta = checkSchemaDocument(schema);
  if (!meta.valid) problems.push(`Web schema subset invalid: ${meta.errors.join('; ')}`);
  const schemaProperties = schema?.properties && typeof schema.properties === 'object'
    ? Object.keys(schema.properties) : [];
  const schemaRequired = Array.isArray(schema?.required) ? schema.required : [];
  if (!same(schemaProperties, ROOT_KEYS) || !same(schemaRequired, ROOT_KEYS)) {
    problems.push('Web schema root is not schema plus the exact six ordered panels');
  }
  if (schema?.properties?.schema?.const !== 'aipt.web-dashboard/v1') {
    problems.push('Web schema marker drifted');
  }
  const openObjects = objectSchemaNodes(schema).filter((node) => node.additionalProperties !== false);
  if (openObjects.length) problems.push(`${openObjects.length} Web object schema(s) allow unknown fields`);
  const valid = validateInstance(schema, canonicalSnapshot());
  if (!valid.valid) problems.push('canonical six-panel snapshot is rejected by Web schema');
  const unknownStatus = canonicalSnapshot();
  unknownStatus.queue.implementation_status = 'READY';
  if (validateInstance(schema, unknownStatus).valid) problems.push('Web schema accepts unknown/false queue status');

  const security = files['internal/web/security.go'];
  const server = files['internal/web/server.go'];
  const routes = files['internal/web/routes.go'];
  const configHealth = files['internal/web/config_health.go'];
  const capabilities = files['internal/web/capabilities.go'];
  const staticGo = files['internal/web/static.go'];
  const hostTests = files['internal/web/security_test.go'];
  const routeTests = files['internal/web/routes_test.go'];
  const smokeTests = files['internal/web/smoke_test.go'];
  const productionGo = PRODUCTION_WEB_PATHS.map((relative) => files[relative]).join('\n');

  requireText(server, /loopbackListenAddress\s*= "127\.0\.0\.1:0"/, 'listener is not hardcoded to 127.0.0.1:0');
  requireText(server, /net\.Listen\("tcp4", loopbackListenAddress\)/, 'listener is not forced to tcp4 dynamic loopback');
  requireText(server, /tcpAddress\.IP\.To4\(\) == nil/, 'selected listener is not checked as IPv4');
  requireText(server, /tcpAddress\.IP\.Equal\(net\.IPv4\(127, 0, 0, 1\)\)/, 'selected listener is not checked as exact loopback');
  forbidText(productionGo, /0\.0\.0\.0|\[::\]|"::"|localhost/, 'production Web source contains a non-exact bind alias');

  requireText(security, /if r\.Host != expectedHost \{/, 'exact Host guard missing');
  const originComparisons = security.match(/origins\[0\] != expectedOrigin/g) ?? [];
  if (originComparisons.length < 2) problems.push('safe and mutation Origin guards are not exact same-origin');
  requireText(security, /len\(origins\) != 1/, 'duplicate/missing mutation Origin is not rejected');
  requireText(security, /case http\.MethodPost, http\.MethodPut, http\.MethodPatch, http\.MethodDelete:/,
    'mutation method inventory drifted');
  requireText(security, /if isMutationMethod\(r\.Method\) \{/, 'mutation guard is not invoked');
  requireText(security, /tokens := r\.Header\.Values\("X-AIPT-CSRF"\)/, 'CSRF header guard missing');
  requireText(security, /subtle\.ConstantTimeCompare/, 'CSRF comparison is not constant-time');
  requireText(server, /tokenBytes := make\(\[\]byte, 32\)/, 'CSRF token entropy length drifted');
  requireText(server, /rand\.Read\(tokenBytes\)/, 'CSRF token is not cryptographically random');
  requireText(server, /base64\.RawURLEncoding\.EncodeToString\(tokenBytes\)/, 'CSRF token is not ephemeral encoded random bytes');
  requireText(server, /ErrorLog:\s+log\.New\(io\.Discard, "", 0\)/, 'HTTP error logging is not closed over discard');
  forbidText(server + security, /(?:Print|Printf|Sprintf|WriteString)[^\n]*(?:csrf|token)/i, 'CSRF token can enter a log/string sink');

  for (const [header, value] of [
    ['Content-Security-Policy', 'contentSecurityPolicy'],
    ['X-Content-Type-Options', '"nosniff"'],
    ['Referrer-Policy', '"no-referrer"'],
    ['X-Frame-Options', '"DENY"'],
    ['Cross-Origin-Resource-Policy', '"same-origin"'],
    ['Cache-Control', '"no-store"'],
  ]) {
    if (!security.includes(`header.Set("${header}", ${value})`)) problems.push(`security header ${header} drifted`);
  }
  for (const directive of [
    "default-src 'self'", "script-src 'self'", "style-src 'self'", "object-src 'none'",
    "base-uri 'none'", "frame-ancestors 'none'", "form-action 'none'", "connect-src 'self'",
  ]) {
    if (!security.includes(directive)) problems.push(`CSP directive missing: ${directive}`);
  }
  forbidText(productionGo, /Access-Control-Allow-Origin|cors/i, 'CORS surface exists');

  requireText(staticGo, /go:embed static\/index\.html static\/app\.js static\/styles\.css/,
    'static assets are not a fixed embed set');
  forbidText(staticGo + routes, /os\.|filepath\.|http\.FileServer|http\.Dir|ServeFile/,
    'static serving depends on runtime filesystem/path traversal');
  const routeCases = [...routes.matchAll(/case "([^"]+)":/g)].map((item) => item[1]);
  const expectedRoutes = ['/', '/assets/app.js', '/assets/styles.css', '/healthz', '/api/v1/dashboard'];
  if (!same(routeCases, expectedRoutes)) problems.push(`route set drifted: ${JSON.stringify(routeCases)}`);
  requireText(routes, /r\.Method != http\.MethodGet && r\.Method != http\.MethodHead/,
    'router does not restrict every endpoint to GET/HEAD');
  requireText(routes, /http\.StatusMethodNotAllowed/, 'router lacks explicit 405');
  requireText(routes, /ConfigHealth\(validated\)/, 'dashboard does not reuse shared validated Config service');
  requireText(routes, /Capabilities\(\)/, 'dashboard does not use truthful capability provider');
  forbidText(routes, /"\/(?:queue|run|report|status|mutation|export)"/, 'forbidden backend/mutation route exists');

  for (const accessor of [
    /validated\.Schema\(\)/,
    /validated\.Profile\(\)\.String\(\)/,
    /database\.Identity\(\)/,
    /database\.Namespace\(\)/,
    /evidence\.Namespace\(\)/,
  ]) requireText(configHealth, accessor, `authorized Config accessor missing: ${accessor}`);
  forbidText(productionGo, /\.DSN\s*\(/, 'internal/web reads raw Config DSN');
  forbidText(productionGo, /json:"(?:dsn|password|credential|secret|token)"/i,
    'credential-bearing Web JSON member exists');

  requireText(capabilities, /BackendAuthority:\s+AuthorityPostgreSQL/, 'Queue authority is not PostgreSQL');
  requireText(capabilities, /queue := QueuePanel\{\s*BackendAuthority:\s+AuthorityPostgreSQL,\s*ImplementationStatus:\s+StatusNotImplemented,/,
    'Queue implementation status is not NOT_IMPLEMENTED');
  requireText(capabilities, /Items:\s+make\(\[\]QueueItem, 0\)/, 'Queue items are not a truthful empty array');
  requireText(capabilities, /run := RunPanel\{\s*ImplementationStatus:\s+StatusNotImplemented,\s*ActiveRun:\s+nil,/,
    'Run implementation status is not NOT_IMPLEMENTED');
  requireText(capabilities, /ActiveRun:\s+nil/, 'Run active state is not null');
  requireText(capabilities, /Seats:\s+make\(\[\]Seat, 0\)/, 'Status/Table seats are not a truthful empty array');
  requireText(capabilities, /RawCapture:\s+StatusLibraryOnly/, 'RAW_CAPTURE is not library-only');
  for (const field of ['UIExportAction', 'AuditReadyGenerator', 'AuditResultGenerator', 'Signing', 'Encryption', 'Chunking']) {
    requireText(capabilities, new RegExp(`${field}:\\s+StatusNotImplemented`), `${field} is not NOT_IMPLEMENTED`);
  }
  forbidText(productionGo, /database\/sql|pgx|\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^\n]*(?:queue|run)/i,
    'Web source contains queue/run SQL or database access');
  forbidText(productionGo, /WebSocket|EventSource|text\/event-stream|\bUpgrade\b/, 'WebSocket/SSE surface exists');
  forbidText(productionGo, /AIPT-M0-B008|INT-AIPT-UNREGISTERED|"\/integration|"\/b008/i,
    'future Integration/B008 surface exists');

  for (const [name, source, pattern] of [
    ['loopback/dynamic port', hostTests, /TestHostBindsDynamicIPv4Loopback/],
    ['Host and Origin', hostTests, /TestHostAndOriginGuards/],
    ['CSRF and router reachability', hostTests + routeTests, /TestMutationRequiresExactOriginAndCSRF[\s\S]*TestRealRouterValidGuardedMutationReachesMethodNotAllowed/],
    ['security headers', hostTests, /TestSecurityHeadersAndNoCORSWildcard/],
    ['context cancellation/port release', hostTests, /TestContextCancellationStopsAndReleasesPort/],
    ['live loopback smoke', smokeTests, /TestLiveLoopbackSmoke/],
  ]) requireText(source, pattern, `required ${name} test missing`);
  for (const token of ['foreign.example', '"null"', 'host.csrfToken', 'http.StatusMethodNotAllowed']) {
    if (!(hostTests + routeTests + smokeTests).includes(token)) problems.push(`host negative test token missing: ${token}`);
  }

  const packageJson = input.packageJson;
  if (packageJson?.name !== '@aipt/web-ui' || packageJson?.version !== '0.1.0' || packageJson?.private !== true ||
      packageJson?.license !== 'MIT' || packageJson?.engines?.node !== '>=24.19.0 <25') {
    problems.push('@aipt/web-ui identity/toolchain drifted');
  }
  if (Object.hasOwn(packageJson ?? {}, 'dependencies') || Object.hasOwn(packageJson ?? {}, 'devDependencies') ||
      Object.hasOwn(packageJson ?? {}, 'peerDependencies') || Object.hasOwn(packageJson ?? {}, 'optionalDependencies')) {
    problems.push('@aipt/web-ui has a dependency surface');
  }
  const importers = workspaceImporters(files['pnpm-lock.yaml']);
  if (!same(importers, ['.', 'packages/adapter-sdk', 'packages/harness-adapter', 'packages/web-ui'])) {
    problems.push(`pnpm importer set drifted: ${JSON.stringify(importers)}`);
  }
  if (/^(packages|snapshots):/m.test(files['pnpm-lock.yaml'])) problems.push('pnpm lock contains third-party package records');

  const sourceTS = files[TS_PATH];
  const html = files['internal/web/static/index.html'];
  const css = files['internal/web/static/styles.css'];
  const titles = [...sourceTS.matchAll(/panel\(documentLike, '([^']+)', '[^']+', \[/g)].map((item) => item[1]);
  if (!same(titles, PANEL_TITLES)) problems.push(`frontend panel titles drifted: ${JSON.stringify(titles)}`);
  requireText(sourceTS, /const ROOT_KEYS = \['schema', 'config', 'health', 'queue', 'run', 'status_table', 'report'\]/,
    'frontend root shape is not exact');
  requireText(sourceTS, /export const DASHBOARD_ENDPOINT = '\/api\/v1\/dashboard'/,
    'frontend fetch endpoint is not fixed same-origin');
  requireText(sourceTS, /credentials: 'same-origin'/, 'frontend fetch credentials mode is not same-origin');
  requireText(sourceTS, /redirect: 'error'/, 'frontend does not fail redirects closed');
  requireText(sourceTS, /node\.textContent = text/, 'frontend does not render values through textContent');
  requireText(sourceTS, /root\.replaceChildren\(/, 'frontend does not replace with trusted nodes');
  requireText(sourceTS, /NOT_IMPLEMENTED/, 'frontend does not display NOT_IMPLEMENTED truth');
  const browserSources = sourceTS + '\n' + html + '\n' + css;
  forbidText(browserSources, /https?:\/\//i, 'frontend contains an external URL/fetch/asset');
  forbidText(browserSources, /\b(?:localStorage|sessionStorage|indexedDB)\b/, 'frontend uses persistent browser storage');
  forbidText(browserSources, /\binnerHTML\b|\bouterHTML\b|insertAdjacentHTML/, 'frontend interprets untrusted markup');
  forbidText(browserSources, /\beval\s*\(|new\s+Function\b/, 'frontend uses dynamic code execution');
  forbidText(browserSources, /analytics|telemetry|beacon|track(?:ing)?\s*\(/i, 'frontend contains telemetry/analytics');
  forbidText(html, /\son[a-z]+\s*=|<script(?![^>]*\bsrc=)/i, 'HTML contains an inline event/script');
  forbidText(css, /url\s*\(/i, 'CSS contains an external/data asset reference');

  if (process.versions.node !== EXACT_NODE) problems.push(`Web artifact check requires exact Node ${EXACT_NODE}`);
  else if (files[ARTIFACT_PATH] !== expectedArtifact(sourceTS)) {
    problems.push('served app.js is not the deterministic strip of authoritative TypeScript');
  }

  const gates = files['internal/launcher/gates.go'];
  const dependencies = files['internal/launcher/dependencies.go'];
  const launcher = files['internal/launcher/launcher.go'];
  const launcherTests = files['internal/launcher/launcher_test.go'];
  const order = parseGateOrder(gates);
  if (!same(order, GATE_ORDER)) problems.push(`Launcher gate order drifted: ${JSON.stringify(order)}`);
  requireText(gates, /case GateConfig, GatePostgreSQL, GateMigrations, GateCore, GateWeb:\s*return Implemented/,
    'WEB is not marked implemented with the existing implemented gates');
  requireText(gates, /case GateModel, GateHarness, GateIPC:\s*return NotImplemented/,
    'MODEL/HARNESS/IPC no longer fail closed');
  requireText(gates, /firstBlocking == "" && implementation == NotImplemented/,
    'first blocking mandatory gate is no longer derived');
  requireText(dependencies, /type WebStartState struct \{[\s\S]*Config\s+\*config\.Config[\s\S]*PriorStartedGates \[\]Gate/,
    'state-aware WEB dependency contract missing');
  requireText(dependencies, /StartWeb:\s+webComponent\(\)/, 'DefaultDependencies does not wire real WEB');
  requireText(dependencies, /host, err := web\.Start\(ctx, state\.Config\)/, 'real WEB does not start the local Host');
  requireText(dependencies, /StartModel:\s+unimplementedComponent\(GateModel\)/, 'MODEL placeholder was bypassed');
  requireText(dependencies, /StartHarness:\s+unimplementedComponent\(GateHarness\)/, 'HARNESS placeholder was bypassed');
  requireText(dependencies, /StartIPC:\s+unimplementedComponent\(GateIPC\)/, 'IPC placeholder was bypassed');
  requireText(launcher, /completed = append\(completed, gate\)/, 'Launcher does not record every successful prior gate');
  requireText(launcher, /prior := append\(\[\]Gate\(nil\), completed\.\.\.\)/, 'WEB prior snapshot is not defensive');
  requireText(launcher, /return l\.dependencies\.StartWeb\(ctx, WebStartState\{/, 'Launcher does not pass state to WEB');
  requireText(launcher, /for _, gate := range fixedGateOrder \{/, 'Launcher bypasses fixed order');
  for (const testName of ['TestFixedGateOrderAndPlanAreImmutable', 'TestRunExactOrderAndReverseShutdown', 'TestProductionModelGateFailsClosed']) {
    requireText(launcherTests, new RegExp(`func ${testName}\\(`), `Launcher test missing: ${testName}`);
  }
  requireText(launcherTests, /"start:IPC",\s*"start:WEB",\s*"stop:WEB",\s*"stop:IPC"/,
    'injected success does not prove WEB last and first stopped');
  requireText(launcherTests, /wantPrior := \[\]Gate\{GateConfig, GatePostgreSQL, GateMigrations, GateModel, GateHarness, GateCore, GateIPC\}/,
    'Launcher test does not prove complete WEB prior gate snapshot');

  if (!same(input.migrationFiles, [MIGRATION_PATH])) {
    problems.push(`migration inventory drifted: ${JSON.stringify(input.migrationFiles)}`);
  }
  return problems;
}

function replaceOnce(text, before, after) {
  if (!text.includes(before)) throw new Error(`mutation precondition missing: ${before}`);
  return text.replace(before, after);
}

function cloneInput(input) {
  return {
    files: { ...input.files },
    schema: structuredClone(input.schema),
    packageJson: structuredClone(input.packageJson),
    migrationFiles: [...input.migrationFiles],
  };
}

function mutationProbes(input) {
  const source = (relative, mutate) => (candidate) => {
    candidate.files[relative] = mutate(candidate.files[relative]);
  };
  return [
    ['bind 0.0.0.0', source('internal/web/server.go', (text) => replaceOnce(text, '"127.0.0.1:0"', '"0.0.0.0:0"'))],
    ['bind ::', source('internal/web/server.go', (text) => replaceOnce(text, '"127.0.0.1:0"', '"[::]:0"'))],
    ['remove Host guard', source('internal/web/security.go', (text) => replaceOnce(text, 'if r.Host != expectedHost {', 'if false {'))],
    ['foreign Host test removed', (candidate) => {
      candidate.files['internal/web/security_test.go'] = candidate.files['internal/web/security_test.go'].replaceAll('foreign.example', 'removed.example');
      candidate.files['internal/web/smoke_test.go'] = candidate.files['internal/web/smoke_test.go'].replaceAll('foreign.example', 'removed.example');
    }],
    ['Origin wildcard', source('internal/web/security.go', (text) => text.replaceAll('origins[0] != expectedOrigin', 'origins[0] != "*"'))],
    ['null Origin test removed', source('internal/web/security_test.go', (text) => text.replaceAll('"null"', '"removed-null"'))],
    ['remove CSRF', source('internal/web/security.go', (text) => replaceOnce(text, 'if isMutationMethod(r.Method) {', 'if false {'))],
    ['hardcoded CSRF token', source('internal/web/server.go', (text) => replaceOnce(text, 'if _, err := rand.Read(tokenBytes); err != nil {', 'if false {'))],
    ['log CSRF token', source('internal/web/server.go', (text) => text + '\nfunc leakCSRF(csrfToken string) { log.Print(csrfToken) }\n')],
    ['CORS wildcard', source('internal/web/security.go', (text) => text + '\nfunc cors(w http.ResponseWriter) { w.Header().Set("Access-Control-Allow-Origin", "*") }\n')],
    ['remove CSP', source('internal/web/security.go', (text) => replaceOnce(text, '"Content-Security-Policy"', '"Removed-CSP"'))],
    ['allow frame', source('internal/web/security.go', (text) => replaceOnce(text, '"DENY"', '"SAMEORIGIN"'))],
    ['external CDN', source('internal/web/static/index.html', (text) => text + '<script src="https://cdn.example/app.js"></script>\n')],
    ['analytics', source(TS_PATH, (text) => text + '\nanalytics.track("dashboard");\n')],
    ['localStorage', source(TS_PATH, (text) => text + '\nlocalStorage.setItem("x", "y");\n')],
    ['untrusted markup sink', source(TS_PATH, (text) => text + '\ndocument.body.innerHTML = "x";\n')],
    ['external fetch', source(TS_PATH, (text) => replaceOnce(text, "'/api/v1/dashboard'", "'https://foreign.example/dashboard'"))],
    ['config DSN', source('internal/web/config_health.go', (text) => text + '\nfunc leak(c *config.Config) string { return c.Database().DSN() }\n')],
    ['credential API', source('internal/web/contracts.go', (text) => text + '\ntype Leak struct { Credential string `json:"credential"` }\n')],
    ['queue READY', source('internal/web/capabilities.go', (text) => replaceOnce(text, 'ImplementationStatus: StatusNotImplemented,', 'ImplementationStatus: "READY",'))],
    ['fake queue item', source('internal/web/capabilities.go', (text) => replaceOnce(text, 'make([]QueueItem, 0)', '[]QueueItem{{}}'))],
    ['run ACTIVE', source('internal/web/capabilities.go', (text) => {
      const first = text.indexOf('ImplementationStatus: StatusNotImplemented,');
      const second = text.indexOf('ImplementationStatus: StatusNotImplemented,', first + 1);
      if (second < 0) throw new Error('run status mutation precondition missing');
      return text.slice(0, second) + text.slice(second).replace('ImplementationStatus: StatusNotImplemented,', 'ImplementationStatus: "ACTIVE",');
    })],
    ['fake seat/table', source('internal/web/capabilities.go', (text) => replaceOnce(text, 'make([]Seat, 0)', '[]Seat{{}}'))],
    ['AUDIT_READY PASS', source('internal/web/capabilities.go', (text) => replaceOnce(text, 'AuditReadyGenerator:  StatusNotImplemented,', 'AuditReadyGenerator:  "PASS",'))],
    ['signing IMPLEMENTED', source('internal/web/capabilities.go', (text) => replaceOnce(text, 'Signing:              StatusNotImplemented,', 'Signing:              "IMPLEMENTED",'))],
    ['queue migration', (candidate) => candidate.migrationFiles.push('internal/storage/postgres/migrations/000002_queue.sql')],
    ['Web before IPC', source('internal/launcher/gates.go', (text) => replaceOnce(text, '\tGateIPC,\n\tGateWeb,', '\tGateWeb,\n\tGateIPC,'))],
    ['skip IPC', source('internal/launcher/gates.go', (text) => replaceOnce(text, '\tGateIPC,\n\tGateWeb,', '\tGateWeb,'))],
    ['unknown dashboard field', (candidate) => {
      candidate.schema.properties.extra = { type: 'string' };
      candidate.schema.required.push('extra');
    }],
    ['schema empty', (candidate) => { candidate.schema = {}; }],
    ['missing panel', (candidate) => {
      delete candidate.schema.properties.report;
      candidate.schema.required = candidate.schema.required.filter((key) => key !== 'report');
    }],
    ['third-party package', (candidate) => { candidate.packageJson.dependencies = { leftpad: '1.0.0' }; }],
    ['WebSocket', source('internal/web/routes.go', (text) => text + '\nconst futureSocket = "WebSocket"\n')],
    ['SSE', source('internal/web/routes.go', (text) => text + '\nconst futureEvents = "text/event-stream"\n')],
    ['future INT/B008 surface', source('internal/web/routes.go', (text) => text + '\nconst futureRoute = "/integration/AIPT-M0-B008"\n')],
  ];
}

function loadInputs(repo) {
  const files = {};
  for (const relative of SOURCE_PATHS) {
    const absolute = path.join(repo, relative);
    if (fs.existsSync(absolute)) files[relative] = fs.readFileSync(absolute, 'utf8');
  }
  let schema = null;
  let packageJson = null;
  try {
    schema = JSON.parse(fs.readFileSync(path.join(repo, WEB_SCHEMA_PATH), 'utf8'));
    packageJson = JSON.parse(fs.readFileSync(path.join(repo, UI_PACKAGE_PATH), 'utf8'));
  } catch {
    // evaluate reports missing/invalid identities without reflecting file data.
  }
  const migrationRoot = path.join(repo, 'internal/storage/postgres/migrations');
  const migrationFiles = fs.existsSync(migrationRoot)
    ? fs.readdirSync(migrationRoot).filter((name) => name.endsWith('.sql')).sort()
      .map((name) => `internal/storage/postgres/migrations/${name}`)
    : [];
  return { files, schema, packageJson, migrationFiles };
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push(`ok: ${message}`);
  const fail = (message) => {
    pass = false;
    details.push(`FAIL: ${message}`);
  };

  const input = loadInputs(ctx.repo);
  const problems = evaluate(input);
  for (const problem of problems) fail(problem);
  if (problems.length === 0) {
    ok('strict Web schema, loopback Host, six-panel UI, artifact, Launcher, and non-goal contracts PASS');
  }

  let mutationFailures = 0;
  const probes = mutationProbes(input);
  for (const [label, mutate] of probes) {
    const candidate = cloneInput(input);
    try {
      mutate(candidate);
      const candidateProblems = evaluate(candidate);
      if (candidateProblems.length === 0) {
        mutationFailures += 1;
        fail(`mutation accepted: ${label}`);
      }
    } catch (error) {
      mutationFailures += 1;
      fail(`mutation probe defect (${label}): ${error.message}`);
    }
  }
  if (mutationFailures === 0) ok(`all ${probes.length} Web security/truth mutation probes rejected`);

  for (const relative of FROZEN_SURFACES) {
    const probe = git(ctx.repo, ['diff', '--quiet', BASE_COMMIT, '--', relative], { check: false });
    if (probe.status !== 0) fail(`historical frozen surface changed: ${relative}`);
  }
  if (!details.some((detail) => detail.includes('historical frozen surface changed'))) {
    ok(`all ${FROZEN_SURFACES.length} config/protocol/storage/adapter/evidence/Core/tool surfaces remain frozen`);
  }

  return { name: 'web-ui', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'web-ui', run);
