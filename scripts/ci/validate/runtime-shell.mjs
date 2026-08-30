// AIPT-M0-B007 runtime-shell validator.
//
// This is a dependency-free, fail-closed source/contract gate. It binds the
// immutable launch order, real CONFIG/PostgreSQL/B003 migration wiring, first
// mandatory unimplemented IPC failure after governed MODEL/HARNESS, reverse cleanup, redacted errors,
// Core lifecycle shell, final state-aware Web gate, signal-aware CLI, strict shared config schema, and
// required unit/integration test inventory. Focused in-memory mutations prove
// each critical check rejects drift without editing the working tree.
import fs from 'node:fs';
import path from 'node:path';
import { checkSchemaDocument, validateInstance } from '../lib/json-schema.mjs';
import { runAsMain } from '../lib/cli.mjs';

const EXPECTED_GATES = [
  'GateConfig',
  'GatePostgreSQL',
  'GateMigrations',
  'GateModel',
  'GateHarness',
  'GateCore',
  'GateIPC',
  'GateWeb',
];

const SOURCE_PATHS = [
  'internal/config/load.go',
  'internal/config/redact.go',
  'internal/config/strictjson.go',
  'internal/config/types.go',
  'internal/config/config_test.go',
  'internal/config/redact_test.go',
  'internal/config/schema_contract_test.go',
  'internal/core/core.go',
  'internal/core/errors.go',
  'internal/core/core_test.go',
  'internal/launcher/dependencies.go',
  'internal/launcher/errors.go',
  'internal/launcher/gates.go',
  'internal/launcher/launcher.go',
  'internal/launcher/launcher_test.go',
  'internal/launcher/launcher_integration_test.go',
  'internal/web/security.go',
  'internal/web/server.go',
  'internal/web/routes.go',
  'internal/web/smoke_test.go',
  'cmd/aipt/command.go',
  'cmd/aipt/command_test.go',
  'cmd/aipt/main.go',
];

const SCHEMA_PATH = 'schemas/config/v1/aipt-config.schema.json';

const ERROR_CODES = [
  'AIPT_LAUNCH_INVALID_OPTIONS',
  'AIPT_LAUNCH_CANCELLED',
  'AIPT_LAUNCH_GATE_FAILED',
  'AIPT_LAUNCH_GATE_NOT_IMPLEMENTED',
  'AIPT_LAUNCH_SHUTDOWN_FAILED',
  'AIPT_LAUNCH_SHUTDOWN_TIMEOUT',
];

const REQUIRED_TESTS = [
  'TestLoadValidDevelopment',
  'TestLoadValidProduction',
  'TestLoadRejectsUnknownField',
  'TestLoadRejectsMissingRequiredField',
  'TestValidateIsolation',
  'TestRedactionNegative',
  'TestProductionDoesNotInheritDevelopmentDefaults',
  'TestStartRunningStopReverseAndDoubleStop',
  'TestStartFailureStopsEarlierAndNeverStartsLater',
  'TestBoundedShutdownAndDependencyErrorPropagation',
  'TestFixedGateOrderAndPlanAreImmutable',
  'TestRunExactOrderAndReverseShutdown',
  'TestRunFailFastAtEveryImplementedBoundary',
  'TestProductionModelGateFailsClosedWithoutPrivateRuntimeConfiguration',
  'TestLiveLoopbackSmoke',
  'TestStartupRootErrorPrecedesAndSurvivesCleanupError',
  'TestCoreGateUsesRealCoreShellThroughDependencyInjection',
  'TestPostgresIntegrationLauncherConnectionMigrationAndNoOp',
  'TestPostgresIntegrationLauncherDatabaseUnavailableFailsBeforeMigrations',
  'TestPlanIsDeterministicAndDoesNotStartRuntime',
  'TestProcessContextReceivesSIGTERM',
];

function sameArray(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function schemaNodes(root) {
  const nodes = [];
  const visit = (node) => {
    if (!node || typeof node !== 'object' || Array.isArray(node)) return;
    nodes.push(node);
    for (const containerName of ['properties', '$defs']) {
      const container = node[containerName];
      if (!container || typeof container !== 'object' || Array.isArray(container)) continue;
      for (const child of Object.values(container)) visit(child);
    }
  };
  visit(root);
  return nodes;
}

function validConfig(profile) {
  const development = profile === 'development';
  const identity = development ? 'aipt_development' : 'aipt_production';
  return {
    schema: 'aipt.config/v1',
    profile,
    database: {
      dsn: 'postgres://localhost/' + identity,
      identity,
      namespace: development ? 'aipt_dev' : 'aipt_prod',
      ping_timeout_ms: development ? 5000 : 1000,
    },
    evidence: {
      namespace: development ? 'aipt.evidence.development' : 'aipt.evidence.production',
    },
  };
}

export function checkRuntimeSources(files, schema) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => {
    pass = false;
    details.push('FAIL: ' + message);
  };
  const expectText = (text, pattern, label) => {
    if (pattern.test(text)) ok(label);
    else fail(label);
  };

  for (const required of SOURCE_PATHS) {
    if (typeof files[required] !== 'string') fail('required runtime-shell source missing: ' + required);
  }
  if (!pass) return { name: 'runtime-shell', result: 'FAIL', details };
  ok('all required B007 runtime-shell sources and tests are present');

  const gates = files['internal/launcher/gates.go'];
  const orderMatch = /var fixedGateOrder = \[\.\.\.\]Gate\{([\s\S]*?)\n\}/.exec(gates);
  const parsedOrder = orderMatch ? [...orderMatch[1].matchAll(/\bGate[A-Za-z]+\b/g)].map((match) => match[0]) : [];
  if (sameArray(parsedOrder, EXPECTED_GATES)) {
    ok('fixed gate order is exactly CONFIG -> POSTGRESQL -> MIGRATIONS -> MODEL -> HARNESS -> CORE -> IPC -> WEB');
  } else {
    fail('fixed gate order drifted: ' + JSON.stringify(parsedOrder));
  }
  expectText(gates, /case GateConfig, GatePostgreSQL, GateMigrations, GateModel, GateHarness, GateCore, GateWeb:\s*return Implemented/,
    'production implementation map marks CONFIG/PostgreSQL/MIGRATIONS/MODEL/HARNESS/Core/WEB implemented');
  expectText(gates, /case GateIPC:\s*return NotImplemented/,
    'production implementation map keeps exactly IPC unimplemented');
  expectText(gates, /RuntimeReady:\s+false/, 'runtime plan is explicitly not ready');
  expectText(gates, /FirstBlockingGate:\s+firstBlocking/, 'runtime plan exposes its first blocking gate');
  expectText(gates, /firstBlocking == "" && implementation == NotImplemented/,
    'first mandatory unimplemented gate is derived in fixed order');

  const dependencies = files['internal/launcher/dependencies.go'];
  expectText(dependencies, /LoadConfig:\s+config\.LoadFile/, 'CONFIG gate uses the shared config.LoadFile service');
  expectText(dependencies, /return pgxpool\.New\(ctx, dsn\)/, 'PostgreSQL gate opens the configured pgx pool');
  expectText(dependencies, /return postgres\.MigrateUp\(ctx, pgxPool\)/, 'MIGRATIONS gate reuses B003 postgres.MigrateUp');
  expectText(dependencies, /modelgateway\.NewRuntimeCoordinator\(/,
    'MODEL/HARNESS production gates share the governed B004 runtime coordinator');
  expectText(dependencies, /StartModel:\s+func\(ctx context\.Context\)[\s\S]*runtime\.StartModel\(ctx\)/,
    'MODEL production gate starts the governed model runtime');
  expectText(dependencies, /StartHarness:\s+func\(ctx context\.Context\)[\s\S]*runtime\.StartHarness\(ctx\)/,
    'HARNESS production gate starts the exact governed adapter routes');
  expectText(dependencies, /StartIPC:\s+unimplementedComponent\(GateIPC\)/,
    'IPC production gate remains fail-closed as unimplemented');
  expectText(dependencies, /StartCore:\s+coreComponent\(shutdownTimeout\)/,
    'Core production dependency uses the B004 lifecycle shell');
  expectText(dependencies, /StartWeb:\s+webComponent\(\)/,
    'WEB production dependency uses the real B007 secure loopback component');
  expectText(dependencies, /type WebStartState struct \{[\s\S]*Config\s+\*config\.Config[\s\S]*PriorStartedGates \[\]Gate/,
    'WEB receives only validated config and a defensive prior-gate snapshot');
  expectText(dependencies, /expected := fixedGateOrder\[:len\(fixedGateOrder\)-1\]/,
    'WEB verifies every mandatory predecessor in immutable order');
  expectText(dependencies, /host, err := web\.Start\(ctx, state\.Config\)/,
    'WEB starts through the secure internal/web host boundary');

  const launcher = files['internal/launcher/launcher.go'];
  expectText(launcher, /for _, gate := range fixedGateOrder \{/, 'Run walks only the immutable fixed gate order');
  expectText(launcher, /for index := len\(started\) - 1; index >= 0; index-- \{/,
    'cleanup walks every started component in reverse order');
  expectText(launcher, /return errors\.Join\(root, cleanupError\)/,
    'startup root error precedes joined cleanup errors');
  expectText(launcher, /context\.WithTimeout\(context\.Background\(\), l\.shutdownTimeout\)/,
    'reverse cleanup uses an independent bounded context');
  expectText(launcher, /context\.WithTimeout\(ctx, timeout\)/,
    'PostgreSQL Ping uses the configured bounded timeout');

  const launcherErrors = files['internal/launcher/errors.go'];
  for (const code of ERROR_CODES) {
    if (!launcherErrors.includes('"' + code + '"')) fail('stable launcher error code missing: ' + code);
  }
  if (ERROR_CODES.every((code) => launcherErrors.includes('"' + code + '"'))) {
    ok('all stable AIPT_LAUNCH error codes are present');
  }
  if (/Cause\.Error\(\)/.test(launcherErrors)) {
    fail('launcher error rendering includes provider cause text and can leak a DSN');
  } else {
    ok('launcher error rendering never includes provider cause text');
  }

  const configLoad = files['internal/config/load.go'];
  expectText(configLoad, /func ValidateIsolation\(development, production \*Config\) error/,
    'shared config exposes explicit development/production isolation validation');
  expectText(configLoad, /development\.profile != ProfileDevelopment \|\| production\.profile != ProfileProduction/,
    'profile isolation validates development and production roles');
  if (/configuration file: %s/.test(configLoad)) fail('config I/O error reflects the caller-supplied path');
  else ok('config I/O errors do not reflect caller-supplied paths');

  const redaction = files['internal/config/redact.go'];
  expectText(redaction, /func \(c Config\) Format\(state fmt\.State, _ rune\)/,
    'Config implements value-safe fmt redaction for every verb');
  expectText(redaction, /func \(d Database\) Format\(state fmt\.State, _ rune\)/,
    'Database implements fmt redaction for every verb');
  expectText(redaction, /func \(c Config\) MarshalJSON\(\) \(\[\]byte, error\)/,
    'Config value and pointer JSON renderings are redacted');

  const strictJSON = files['internal/config/strictjson.go'];
  expectText(strictJSON, /func hex4\(b \[\]byte\) \(rune, bool\)/,
    'strict JSON parser rejects non-hex Unicode escape digits');
  expectText(strictJSON, /ReasonJSONDuplicateKey/, 'strict JSON parser rejects duplicate object keys');
  expectText(strictJSON, /configJSONPath\(parent, key string\)/,
    'strict JSON error paths sanitize attacker-controlled member names');

  const meta = checkSchemaDocument(schema);
  if (meta.valid) ok('canonical config schema uses only the dependency-free JSON Schema 2020-12 subset');
  else fail('canonical config schema subset violation: ' + meta.errors.join('; '));
  const profileEnum = schema && schema.properties && schema.properties.profile && schema.properties.profile.enum;
  if (Array.isArray(profileEnum) && sameArray(profileEnum, ['development', 'production'])) {
    ok('canonical config profile enum is exactly development|production');
  } else {
    fail('canonical config profile enum drifted: ' + JSON.stringify(profileEnum));
  }
  const openObjectSchemas = schemaNodes(schema).filter((node) =>
    node.properties && node.additionalProperties !== false);
  if (openObjectSchemas.length === 0) ok('canonical config schema rejects unknown fields recursively');
  else fail('canonical config schema permits unknown fields in ' + openObjectSchemas.length + ' object schema(s)');
  for (const profile of ['development', 'production']) {
    const result = validateInstance(schema, validConfig(profile), { ref: '#' });
    if (result.valid) ok('canonical config schema accepts valid ' + profile);
    else fail('canonical config schema rejects valid ' + profile);
  }
  const unknown = validConfig('development');
  unknown.extra = true;
  if (!validateInstance(schema, unknown, { ref: '#' }).valid) ok('canonical config schema rejects an unknown root field');
  else fail('canonical config schema accepted an unknown root field');
  const missing = validConfig('production');
  delete missing.database;
  if (!validateInstance(schema, missing, { ref: '#' }).valid) ok('canonical config schema rejects a missing required field');
  else fail('canonical config schema accepted a missing required field');

  const core = files['internal/core/core.go'];
  const stateMatch = /const \(([\s\S]*?)\n\)/.exec(core);
  const stateTokens = stateMatch ? [...stateMatch[1].matchAll(/State(?:New|Starting|Running|Stopping|Stopped|Failed)/g)].map((m) => m[0]) : [];
  const expectedStates = ['StateNew', 'StateStarting', 'StateRunning', 'StateStopping', 'StateStopped', 'StateFailed'];
  if (sameArray(stateTokens, expectedStates)) ok('Core lifecycle states are exactly NEW/STARTING/RUNNING/STOPPING/STOPPED/FAILED');
  else fail('Core lifecycle state set/order drifted: ' + JSON.stringify(stateTokens));
  expectText(core, /c\.state = StateRunning\s+c\.ready = true/, 'Core becomes ready only after its owned checks complete');
  expectText(core, /context\.WithTimeout\(context\.Background\(\), c\.shutdownTimeout\)/,
    'Core failed-start cleanup is independently bounded');

  const command = files['cmd/aipt/command.go'];
  expectText(command, /signal\.NotifyContext\([\s\S]*os\.Interrupt,[\s\S]*syscall\.SIGTERM/,
    'CLI handles SIGINT and SIGTERM through process context');
  expectText(command, /defer stop\(\)/, 'CLI always releases signal notification resources');
  expectText(command, /launcher\.Plan\(\)/, 'CLI plan uses the deterministic launcher plan');
  if (/err\.Error\(\)/.test(command) || /fmt\.(?:Print|Fprint)/.test(command)) {
    fail('CLI renders raw runtime error text instead of stable code/gate output');
  } else {
    ok('CLI emits stable code/gate output without raw runtime causes');
  }

  const productionGo = [
    files['internal/config/load.go'],
    files['internal/config/redact.go'],
    files['internal/config/strictjson.go'],
    files['internal/config/types.go'],
    files['internal/core/core.go'],
    files['internal/core/errors.go'],
    files['internal/launcher/dependencies.go'],
    files['internal/launcher/errors.go'],
    files['internal/launcher/gates.go'],
    files['internal/launcher/launcher.go'],
    files['cmd/aipt/command.go'],
    files['cmd/aipt/main.go'],
  ].join('\n');
  const forbiddenRuntimeCalls = [
    /net\.Listen\s*\(/,
    /http\.ListenAndServe\s*\(/,
    /grpc\.NewServer\s*\(/,
    /exec\.Command\s*\(/,
  ];
  if (forbiddenRuntimeCalls.some((pattern) => pattern.test(productionGo))) {
    fail('non-Web production shell starts an unauthorized network listener or external process');
  } else {
    ok('non-Web production shell starts no additional network listener or external process');
  }

  const allTests = SOURCE_PATHS.filter((file) => file.endsWith('_test.go')).map((file) => files[file]).join('\n');
  const missingTests = REQUIRED_TESTS.filter((name) => !allTests.includes('func ' + name + '('));
  if (missingTests.length === 0) ok('required config/Core/Launcher/CLI/integration test inventory is present');
  else fail('required runtime-shell tests missing: ' + missingTests.join(', '));
  const integration = files['internal/launcher/launcher_integration_test.go'];
  expectText(integration, /versionNumber != 180004/, 'launcher integration enforces PostgreSQL 18.4');
  expectText(integration, /AIPT_REQUIRE_POSTGRES_INTEGRATION/, 'launcher integration fails rather than skips when CI requires PostgreSQL');
  expectText(integration, /CodeGateFailed, GateMigrations/, 'launcher integration proves migration failure stops at MIGRATIONS');
  expectText(integration, /CodeGateFailed, GatePostgreSQL/, 'launcher integration proves database unavailability stops at POSTGRESQL');

  return { name: 'runtime-shell', result: pass ? 'PASS' : 'FAIL', details };
}

function loadInputs(repo) {
  const files = {};
  for (const relative of SOURCE_PATHS) {
    const absolute = path.join(repo, relative);
    if (fs.existsSync(absolute)) files[relative] = fs.readFileSync(absolute, 'utf8');
  }
  let schema = null;
  const schemaFile = path.join(repo, SCHEMA_PATH);
  if (fs.existsSync(schemaFile)) {
    try {
      schema = JSON.parse(fs.readFileSync(schemaFile, 'utf8'));
    } catch {
      schema = null;
    }
  }
  return { files, schema };
}

function replaceOnce(text, before, after) {
  if (!text.includes(before)) throw new Error('probe precondition missing: ' + before);
  return text.replace(before, after);
}

export function run(ctx) {
  const input = loadInputs(ctx.repo);
  const main = checkRuntimeSources(input.files, input.schema);
  const details = [...main.details];
  let pass = main.result === 'PASS';
  const fail = (message) => {
    pass = false;
    details.push('FAIL: ' + message);
  };
  const ok = (message) => details.push('ok: ' + message);

  const probes = [
    {
      label: 'fixed gate order swap',
      reason: /fixed gate order drifted/,
      mutate(files) {
        files['internal/launcher/gates.go'] = replaceOnce(
          files['internal/launcher/gates.go'],
          '\tGateMigrations,\n\tGateModel,',
          '\tGateModel,\n\tGateMigrations,',
        );
      },
    },
    {
      label: 'IPC falsely marked implemented',
      reason: /keeps exactly IPC unimplemented/,
      mutate(files) {
        files['internal/launcher/gates.go'] = replaceOnce(
          files['internal/launcher/gates.go'],
          'case GateIPC:',
          'case GateModel:',
        );
      },
    },
    {
      label: 'plan falsely marked runtime ready',
      reason: /runtime plan is explicitly not ready/,
      mutate(files) {
        files['internal/launcher/gates.go'] = replaceOnce(
          files['internal/launcher/gates.go'],
          'RuntimeReady:      false',
          'RuntimeReady:      true',
        );
      },
    },
    {
      label: 'B003 migration wiring removed',
      reason: /MIGRATIONS gate reuses B003/,
      mutate(files) {
        files['internal/launcher/dependencies.go'] = replaceOnce(
          files['internal/launcher/dependencies.go'],
          'return postgres.MigrateUp(ctx, pgxPool)',
          'return nil',
        );
      },
    },
    {
      label: 'shared config service bypassed',
      reason: /CONFIG gate uses the shared/,
      mutate(files) {
        files['internal/launcher/dependencies.go'] = replaceOnce(
          files['internal/launcher/dependencies.go'],
          'LoadConfig: config.LoadFile',
          'LoadConfig: nil',
        );
      },
    },
    {
      label: 'reverse cleanup direction broken',
      reason: /cleanup walks every started component in reverse/,
      mutate(files) {
        files['internal/launcher/launcher.go'] = replaceOnce(
          files['internal/launcher/launcher.go'],
          'for index := len(started) - 1; index >= 0; index-- {',
          'for index := 0; index < len(started); index++ {',
        );
      },
    },
    {
      label: 'provider cause text leaked',
      reason: /error rendering includes provider cause text/,
      mutate(files) {
        files['internal/launcher/errors.go'] = replaceOnce(
          files['internal/launcher/errors.go'],
          '\treturn message\n',
          '\treturn e.Cause.Error()\n',
        );
      },
    },
    {
      label: 'SIGTERM handling removed',
      reason: /CLI handles SIGINT and SIGTERM/,
      mutate(files) {
        files['cmd/aipt/command.go'] = replaceOnce(
          files['cmd/aipt/command.go'],
          '\t\tsyscall.SIGTERM,\n',
          '',
        );
      },
    },
    {
      label: 'network listener added',
      reason: /unauthorized network listener or external process/,
      mutate(files) {
        files['cmd/aipt/main.go'] += '\nfunc forbiddenProbe() { net.Listen("tcp", ":0") }\n';
      },
    },
  ];

  for (const probe of probes) {
    const files = { ...input.files };
    let schema = JSON.parse(JSON.stringify(input.schema));
    try {
      probe.mutate(files, schema);
    } catch (error) {
      fail('negative probe could not run (' + probe.label + '): ' + error.message);
      continue;
    }
    const result = checkRuntimeSources(files, schema);
    if (result.result !== 'FAIL') {
      fail('negative probe was accepted: ' + probe.label);
    } else if (!result.details.some((detail) => probe.reason.test(detail))) {
      fail('negative probe failed for the wrong reason: ' + probe.label);
    } else {
      ok('negative-probe PASS: ' + probe.label);
    }
  }

  const schemaProbes = [
    {
      label: 'root unknown fields enabled',
      reason: /schema permits unknown fields/,
      mutate(schema) {
        schema.additionalProperties = true;
      },
    },
    {
      label: 'staging profile injected',
      reason: /profile enum drifted/,
      mutate(schema) {
        schema.properties.profile.enum.push('staging');
      },
    },
  ];
  for (const probe of schemaProbes) {
    const schema = JSON.parse(JSON.stringify(input.schema));
    probe.mutate(schema);
    const result = checkRuntimeSources({ ...input.files }, schema);
    if (result.result !== 'FAIL') {
      fail('negative probe was accepted: ' + probe.label);
    } else if (!result.details.some((detail) => probe.reason.test(detail))) {
      fail('negative probe failed for the wrong reason: ' + probe.label);
    } else {
      ok('negative-probe PASS: ' + probe.label);
    }
  }

  return { name: 'runtime-shell', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'runtime-shell', run);
