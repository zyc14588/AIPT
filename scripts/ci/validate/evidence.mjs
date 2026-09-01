#!/usr/bin/env node
// AIPT-M0-B006 Evidence/Audit schema + minimal RAW_CAPTURE machine gate.
// Node standard library only; all JSON Schema evaluation reuses the frozen
// dependency-free 2020-12 subset in scripts/ci/lib/json-schema.mjs.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { runAsMain } from '../lib/cli.mjs';
import { checkSchemaDocument, validateInstance } from '../lib/json-schema.mjs';
import { walkFiles } from '../lib/scan.mjs';

const SCHEMA_PATH = 'schemas/evidence/v1/aipt-evidence.schema.json';
const FIXTURE_ROOT = 'testdata/evidence/v1/minimal-raw-capture';
const FIXTURE_README = 'testdata/evidence/v1/README.md';
const EXPECTED_SCHEMA_ID = 'https://github.com/zyc14588/AIPT/schemas/evidence/v1/aipt-evidence.schema.json';
const EXPECTED_FILES = ['ROOT.sha256', 'events.ndjson', 'manifest.json'];
const EXPECTED_DEFS = [
  'asset', 'asset_path', 'audit_ready_manifest', 'audit_result_manifest', 'auditor',
  'disclosure', 'disclosure_external_published', 'disclosure_external_unpublished',
  'disclosure_private', 'disclosure_public', 'encrypted', 'finding', 'git_object_id',
  'identifier', 'ledger_text', 'normalization_version', 'raw_capture_manifest',
  'raw_event', 'raw_events_asset', 'remote_immutable_verification', 'schema_id',
  'schema_version', 'sha256_hex', 'source_identity', 'unencrypted',
];
const EXPECTED_PRODUCTION_FILES = ['export.go', 'postgres.go', 'types.go', 'verify.go'];
const EXPECTED_TEST_FILES = ['export_test.go', 'postgres_integration_test.go', 'postgres_test.go'];
const BOUNDED_VERIFY_PATH = 'internal/storage/postgres/verify_bounded.go';
const EXPECTED_EVENTS_SHA = 'fb45425367a0f0d56efd983c31dc0c6f6b21b426202b6858757d764d6a0ad5c0';
const EXPECTED_MANIFEST_SHA = '106ba6686d0f47304921266824c5832916867931869c45424d894410eed241a2';

function same(a, b) {
  return JSON.stringify(a) === JSON.stringify(b);
}

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function schemaContractProblems(schema) {
  const problems = [];
  const meta = checkSchemaDocument(schema);
  if (!meta.valid) problems.push(...meta.errors.map((error) => 'schema meta: ' + error));
  if (schema?.$id !== EXPECTED_SCHEMA_ID) problems.push('schema $id drifted');
  if (!same(Object.keys(schema ?? {}).sort(), ['$defs', '$id', '$schema', 'description', 'oneOf', 'title'].sort())) {
    problems.push('schema root keys are not exact');
  }
  const stageRefs = schema?.oneOf?.map((entry) => entry?.$ref);
  const expectedRefs = [
    '#/$defs/raw_capture_manifest',
    '#/$defs/audit_ready_manifest',
    '#/$defs/audit_result_manifest',
  ];
  if (!same(stageRefs, expectedRefs)) problems.push('root is not the exact ordered three-stage oneOf');
  if (!same(Object.keys(schema?.$defs ?? {}).sort(), [...EXPECTED_DEFS].sort())) {
    problems.push('$defs inventory drifted');
  }
  const defs = schema?.$defs ?? {};
  if (defs.schema_id?.const !== 'aipt.evidence/v1' || defs.schema_version?.const !== '1.0.0') {
    problems.push('schema identity/version constants drifted');
  }
  if (defs.raw_capture_manifest?.properties?.stage?.const !== 'RAW_CAPTURE' ||
      defs.audit_ready_manifest?.properties?.stage?.const !== 'AUDIT_READY' ||
      defs.audit_result_manifest?.properties?.stage?.const !== 'AUDIT_RESULT') {
    problems.push('stage constants drifted');
  }
  if (defs.raw_capture_manifest?.properties?.capture_kind?.const !== 'LEDGER_STREAM' ||
      defs.raw_events_asset?.properties?.path?.const !== 'events.ndjson' ||
      defs.raw_events_asset?.properties?.media_type?.const !== 'application/x-ndjson') {
    problems.push('minimal RAW_CAPTURE kind/asset contract drifted');
  }
  if (defs.disclosure_private?.properties?.encryption?.$ref !== '#/$defs/encrypted' ||
      defs.disclosure_external_unpublished?.properties?.encryption?.$ref !== '#/$defs/encrypted' ||
      defs.disclosure_external_unpublished?.properties?.contains_unpublished_content?.const !== true ||
      defs.disclosure_public?.properties?.contains_unpublished_content?.const !== false) {
    problems.push('disclosure/encryption invariants drifted');
  }
  if (!defs.auditor?.required?.includes('profile') ||
      !same(defs.audit_result_manifest?.properties?.verdict?.enum, ['PASS', 'FAIL', 'BLOCKED'])) {
    problems.push('auditor profile or result verdict contract drifted');
  }
  const visit = (node, location) => {
    if (node === null || typeof node !== 'object') return;
    if (!Array.isArray(node) && node.type === 'object' && node.additionalProperties !== false) {
      problems.push(location + ' object is not additionalProperties:false');
    }
    if (Array.isArray(node)) {
      node.forEach((entry, index) => visit(entry, location + '/' + index));
    } else {
      for (const [key, value] of Object.entries(node)) visit(value, location + '/' + key);
    }
  };
  visit(schema, '#');
  return problems;
}

function schemaExamples(schema, rawManifest) {
  const encrypted = { status: 'ENCRYPTED', scheme: 'synthetic-scheme-v1', key_reference: 'synthetic-key-v1' };
  const source = rawManifest.source;
  const commonReady = {
    schema: 'aipt.evidence/v1', version: '1.0.0', stage: 'AUDIT_READY',
    raw_capture_root: EXPECTED_MANIFEST_SHA, source,
    remote_verification: {
      remote: source.repository, commit: source.commit,
      status: 'VERIFIED_IMMUTABLE_REMOTE_COMMIT',
    },
    normalization_version: 'synthetic-audit-ready/v1',
    normalized_assets: [{
      path: 'normalized/events.json', media_type: 'application/json', bytes: 2,
      sha256: sha256('{}'),
    }],
  };
  const readyPublic = {
    ...commonReady,
    disclosure: { profile: 'PUBLIC', contains_unpublished_content: false, encryption: { status: 'UNENCRYPTED' } },
  };
  const readyExternal = {
    ...commonReady,
    disclosure: { profile: 'EXTERNAL_AUDITOR', contains_unpublished_content: true, encryption: encrypted },
  };
  const readyPrivate = {
    ...commonReady,
    disclosure: { profile: 'PRIVATE_FULL', contains_unpublished_content: true, encryption: encrypted },
  };
  const resultPass = {
    schema: 'aipt.evidence/v1', version: '1.0.0', stage: 'AUDIT_RESULT',
    audit_ready_root: '3'.repeat(64),
    auditor: { id: 'synthetic-auditor', kind: 'MODEL', profile: 'synthetic-profile', version: 'v1' },
    verdict: 'PASS', findings: [],
  };
  const resultFail = {
    ...resultPass,
    verdict: 'FAIL',
    findings: [{
      id: 'SYNTHETIC-F001', severity: 'LOW', category: 'fixture',
      summary: 'Synthetic finding used only to exercise the public schema.',
      evidence_refs: ['normalized/events.json'],
    }],
  };
  return { readyPublic, readyExternal, readyPrivate, resultPass, resultFail };
}

function validateSchemaBehavior(schema, rawManifest) {
  const problems = [];
  const expect = (label, instance, valid, options = {}) => {
    const report = validateInstance(schema, instance, options);
    if (report.valid !== valid) {
      problems.push(label + ': expected valid=' + valid + ', got ' + report.valid + ' ' + JSON.stringify(report.errors));
    }
  };
  const examples = schemaExamples(schema, rawManifest);
  expect('RAW_CAPTURE', rawManifest, true);
  for (const [label, instance] of Object.entries(examples)) expect(label, instance, true);
  expect('empty document', {}, false);
  const missingStage = clone(rawManifest); delete missingStage.stage;
  expect('missing stage', missingStage, false);
  expect('unknown stage', { ...rawManifest, stage: 'RAW_CAPTURE_V2' }, false);
  expect('unknown version', { ...rawManifest, version: '2.0.0' }, false);
  expect('unknown field', { ...rawManifest, exported_at: '2026-01-01T00:00:00Z' }, false);
  expect('wrong source SHA', { ...rawManifest, source: { ...rawManifest.source, commit: 'short' } }, false);
  const unsafeReady = clone(examples.readyPublic);
  unsafeReady.normalized_assets[0].path = '../events.json';
  expect('unsafe ../ asset', unsafeReady, false);
  const absoluteReady = clone(examples.readyPublic);
  absoluteReady.normalized_assets[0].path = '/events.json';
  expect('absolute asset', absoluteReady, false);
  const privatePlain = clone(examples.readyPrivate);
  privatePlain.disclosure.encryption = { status: 'UNENCRYPTED' };
  expect('PRIVATE_FULL unencrypted', privatePlain, false);
  const externalPlain = clone(examples.readyExternal);
  externalPlain.disclosure.encryption = { status: 'UNENCRYPTED' };
  expect('unpublished EXTERNAL_AUDITOR unencrypted', externalPlain, false);
  expect('PASS with findings', { ...examples.resultFail, verdict: 'PASS' }, false);
  expect('FAIL without findings', { ...examples.resultPass, verdict: 'FAIL' }, false);
  return problems;
}

function goldenProblems(repo, schema) {
  const problems = [];
  const root = path.join(repo, FIXTURE_ROOT);
  let names;
  try {
    names = fs.readdirSync(root).sort();
  } catch (error) {
    return ['golden directory unreadable: ' + error.message];
  }
  if (!same(names, EXPECTED_FILES)) problems.push('golden inventory is not exact: ' + JSON.stringify(names));
  for (const name of names) {
    const stat = fs.lstatSync(path.join(root, name));
    if (stat.isSymbolicLink() || !stat.isFile()) problems.push('golden member is not a regular file: ' + name);
  }
  const readme = fs.readFileSync(path.join(repo, FIXTURE_README), 'utf8');
  if (!readme.includes('NON_CANON_TEST_FIXTURE') || !readme.includes('synthetic') ||
      !/do\s+not\s+contain\s+real\s+database\s+content/.test(readme)) {
    problems.push('golden is not explicitly labeled synthetic NON_CANON_TEST_FIXTURE');
  }
  const manifestBytes = fs.readFileSync(path.join(root, 'manifest.json'));
  const eventsBytes = fs.readFileSync(path.join(root, 'events.ndjson'));
  const rootBytes = fs.readFileSync(path.join(root, 'ROOT.sha256'));
  if (sha256(manifestBytes) !== EXPECTED_MANIFEST_SHA) problems.push('golden manifest exact digest drifted');
  if (sha256(eventsBytes) !== EXPECTED_EVENTS_SHA) problems.push('golden events exact digest drifted');
  if (rootBytes.toString('utf8') !== EXPECTED_MANIFEST_SHA + '\n') problems.push('golden ROOT.sha256 drifted');
  if (!manifestBytes.subarray(-1).equals(Buffer.from('\n')) || manifestBytes.subarray(0, -1).includes(0x0a) || manifestBytes.includes(0x0d)) {
    problems.push('golden manifest is not one JSON document plus LF');
  }
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch (error) {
    problems.push('golden manifest JSON parse failed: ' + error.message);
    return problems;
  }
  if (JSON.stringify(manifest) + '\n' !== manifestBytes.toString('utf8')) problems.push('golden manifest is not canonical compact persisted order');
  const report = validateInstance(schema, manifest);
  if (!report.valid) problems.push('golden manifest fails schema: ' + JSON.stringify(report.errors));
  if (manifest.source?.commit !== '1'.repeat(40) || manifest.source?.tree !== '2'.repeat(40) ||
      manifest.source?.repository !== 'https://example.invalid/aipt-synthetic') {
    problems.push('golden source identity is not the frozen clearly synthetic identity');
  }
  if (manifest.assets?.length !== 1 || manifest.assets[0].path !== 'events.ndjson' ||
      manifest.assets[0].bytes !== eventsBytes.length || manifest.assets[0].sha256 !== EXPECTED_EVENTS_SHA) {
    problems.push('golden manifest asset identity drifted');
  }
  if (!eventsBytes.subarray(-1).equals(Buffer.from('\n')) || eventsBytes.includes(0x0d)) {
    problems.push('golden events must be LF-terminated with no CR');
  }
  const text = eventsBytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(eventsBytes)) problems.push('golden events are not valid UTF-8');
  const lines = text.endsWith('\n') ? text.slice(0, -1).split('\n') : [];
  if (lines.length !== 3 || lines.some((line) => line.length === 0)) problems.push('golden must contain exactly three nonblank events');
  let previous = null;
  let tail = null;
  for (let index = 0; index < lines.length; index += 1) {
    let event;
    try {
      event = JSON.parse(lines[index]);
    } catch (error) {
      problems.push('golden event line ' + (index + 1) + ' parse failed: ' + error.message);
      continue;
    }
    if (JSON.stringify(event) !== lines[index]) problems.push('golden event line ' + (index + 1) + ' is not canonical compact persisted order');
    const eventReport = validateInstance(schema, event, { ref: '#/$defs/raw_event' });
    if (!eventReport.valid) problems.push('golden event line ' + (index + 1) + ' fails schema: ' + JSON.stringify(eventReport.errors));
    if (event.stream_id !== manifest.stream_id || event.sequence !== index + 1 || event.prev_event_hash !== previous) {
      problems.push('golden event line ' + (index + 1) + ' stream/sequence/prev linkage drifted');
    }
    try {
      const payload = JSON.parse(event.payload_canonical);
      if (JSON.stringify(payload) !== event.payload_canonical) problems.push('golden payload line ' + (index + 1) + ' is not canonical');
    } catch (error) {
      problems.push('golden payload line ' + (index + 1) + ' parse failed: ' + error.message);
    }
    if (sha256(event.payload_canonical) !== event.payload_sha256) problems.push('golden payload SHA drifted at line ' + (index + 1));
    previous = event.event_hash;
    tail = event.event_hash;
  }
  if (manifest.event_count !== lines.length || manifest.tail_sequence !== lines.length || manifest.tail_event_hash !== tail) {
    problems.push('golden manifest count/tail does not bind its events');
  }
  return problems;
}

function evidenceSourceMap(repo) {
  const sourceRoot = path.join(repo, 'internal', 'evidence');
  const sources = new Map();
  for (const file of walkFiles(sourceRoot, (candidate) => candidate.endsWith('.go'))) {
    sources.set(path.relative(repo, file).split(path.sep).join('/'), fs.readFileSync(file, 'utf8'));
  }
  return sources;
}

function sourceContractProblems(sources, boundedVerifier) {
  const problems = [];
  const keys = [...sources.keys()].sort();
  const productionKeys = keys.filter((key) => !key.endsWith('_test.go'));
  const testKeys = keys.filter((key) => key.endsWith('_test.go'));
  if (!same(productionKeys.map((key) => path.posix.basename(key)).sort(), [...EXPECTED_PRODUCTION_FILES].sort())) {
    problems.push('production evidence Go inventory drifted: ' + JSON.stringify(productionKeys));
  }
  if (!same(testKeys.map((key) => path.posix.basename(key)).sort(), [...EXPECTED_TEST_FILES].sort())) {
    problems.push('evidence test inventory drifted: ' + JSON.stringify(testKeys));
  }
  for (const key of keys) {
    if (!key.startsWith('internal/evidence/')) problems.push('evidence implementation escaped internal/evidence: ' + key);
    if (key.includes('UNREGISTERED-AIPT-P0-B002') || key.startsWith('internal/web/')) {
      problems.push('unauthorized next-batch/Web path entered evidence source: ' + key);
    }
  }
  const production = productionKeys.map((key) => sources.get(key)).join('\n');
  const postgres = sources.get('internal/evidence/postgres.go') ?? '';
  const exporter = sources.get('internal/evidence/export.go') ?? '';
  const verifier = sources.get('internal/evidence/verify.go') ?? '';
  const canonicalCalls = production.match(/protocol\.CanonicalJSON\s*\(/g) ?? [];
  if (!production.includes('github.com/zyc14588/AIPT/internal/protocol') || canonicalCalls.length < 3) {
    problems.push('internal/protocol.CanonicalJSON is not reused at every canonical trust boundary');
  }
  if (/func\s+(?:canonicalJSON|canonicalizeJSON|sortJSON)\s*\(/i.test(production)) {
    problems.push('a second JSON canonicalizer was introduced');
  }
  for (const token of ['verify: storagepostgres.VerifyStreamBounded', 'source.verify(', 'MaxEvents: maxRawCaptureEventCount',
    'MaxEventPayloadBytes: int64(maxRawCaptureEventLineBytes)', 'MaxTotalPayloadBytes: maxRawCaptureEventsBytes',
    'pgx.ReadOnly', 'pgx.ReadCommitted', 'sequence <= $2', 'ORDER BY sequence ASC', 'LIMIT $3',
    'octet_length(payload_canonical)', 'encodeEventLine(event)', 'SELECT last_sequence, last_event_hash']) {
    if (!postgres.includes(token)) problems.push('PostgreSQL source misses required read-only/verification token: ' + token);
  }
  if (/\b(?:INSERT|UPDATE|DELETE|ALTER|TRUNCATE|CREATE|DROP)\b/.test(postgres)) {
    problems.push('production PostgreSQL evidence adapter contains DML/DDL');
  }
  for (const token of [
    'func VerifyStreamBounded(', 'pgx.RepeatableRead', 'pgx.ReadOnly',
    'cursorSequence > in.MaxEvents', 'octet_length(payload_canonical)',
    'MAX(payload_bytes)', 'SUM(payload_bytes)',
    'maxPayloadBytes > in.MaxEventPayloadBytes', 'totalPayloadBytes > in.MaxTotalPayloadBytes',
    'verifyStreamTx(ctx, boundedVerifyTx{',
    'tx.maxEvents + 1', 'boundedVerifyRows',
  ]) {
    if (!boundedVerifier.includes(token)) problems.push('bounded frozen-ledger verifier misses token: ' + token);
  }
  if ((boundedVerifier.match(/LIMIT \$2/g) ?? []).length < 2) {
    problems.push('bounded frozen-ledger verifier must limit both payload preflight and full event query');
  }
  if (/\b(?:INSERT|UPDATE|DELETE|ALTER|TRUNCATE|CREATE|DROP)\b/.test(boundedVerifier)) {
    problems.push('bounded frozen-ledger verifier contains DML/DDL');
  }
  for (const token of [
    'openPrivateExportParent(', 'createPrivateStagingDirectory(', 'writePrivateFileAt(',
    'verifyHeldRawCapture(tempDirectory, tempState)', 'renameat2NoReplace(', 'samePrivateBundleDirectory(',
    'pathMatchesHeldDirectory(', 'os.RemoveAll(', '0o700', '0o600',
  ]) {
    if (!exporter.includes(token)) problems.push('atomic/private exporter contract misses token: ' + token);
  }
  for (const token of [
    'syscall.Open(', 'syscall.Openat(', 'syscall.O_NOFOLLOW', 'directoryFile.ReadDir(4)',
    'io.LimitReader(', 'sameFileState(', 'protocol.CanonicalJSON(', 'sha256.Sum256(',
    'payload SHA-256 mismatch',
  ]) {
    if (!verifier.includes(token)) problems.push('independent verifier contract misses token: ' + token);
  }
  const forbidden = [
    ['wall-clock root input', /time\s*\.\s*Now\s*\(/],
    ['hostname', /os\s*\.\s*Hostname\s*\(/],
    ['PID', /os\s*\.\s*Getpid\s*\(/],
    ['user identity', /os\s*\.\s*(?:Getuid|UserHomeDir)\s*\(/],
    ['ambient environment read/dump', /os\s*\.\s*(?:Getenv|LookupEnv|Environ)\s*\(/],
    ['network package/API', /["'](?:net|net\/http)["']|http\s*\.\s*(?:Get|Post|Do)\s*\(/],
    ['subprocess/network escape', /exec\s*\.\s*Command(?:Context)?\s*\(/],
    ['payload logging', /(?:fmt\s*\.\s*Print|log\s*\.|slog\s*\.).{0,120}(?:Payload|payload_canonical)/s],
    ['silent max-events truncation', /\bevents\s*\[:/i],
    ['Web implementation', /internal\/web|\bWeb(?:Server|Handler|Runtime)\b/],
    ['next batch implementation', /UNREGISTERED-AIPT-P0-B002/],
    ['Harness/model runtime', /codex-harness|HarnessBackend|deepseek|model\s*\.\s*(?:Call|Generate)/i],
    ['secret locator in manifest', /json:"(?:dsn|credential|password|hostname|pid|username|absolute_path|exported_at)"/i],
  ];
  for (const [label, pattern] of forbidden) {
    if (pattern.test(production)) problems.push('forbidden production evidence capability: ' + label);
  }
  if (/func\s+\w*(?:AuditReady|AuditResult)\w*\s*\(/i.test(production)) {
    problems.push('AUDIT_READY/AUDIT_RESULT runtime generator entered internal/evidence');
  }
  return problems;
}

function mutationProblems(schema, sources, boundedVerifier, rawManifest) {
  const problems = [];
  const probes = [];
  probes.push(['empty schema', schemaContractProblems({}).length > 0]);
  const missingStage = clone(schema);
  missingStage.oneOf.splice(1, 1);
  probes.push(['deleted stage', schemaContractProblems(missingStage).length > 0]);
  const privatePlain = clone(schema);
  privatePlain.$defs.disclosure_private.properties.encryption.$ref = '#/$defs/unencrypted';
  probes.push(['PRIVATE_FULL allows unencrypted', schemaContractProblems(privatePlain).length > 0]);
  const unsafeReady = schemaExamples(schema, rawManifest).readyPublic;
  unsafeReady.normalized_assets[0].path = '../asset.json';
  probes.push(['asset ../', !validateInstance(schema, unsafeReady).valid]);

  const mutateSources = (mutate) => {
    const copy = new Map(sources);
    mutate(copy);
    return sourceContractProblems(copy, boundedVerifier).length > 0;
  };
  probes.push(['CanonicalJSON reuse removed', mutateSources((copy) => {
    for (const [key, text] of copy) if (!key.endsWith('_test.go')) copy.set(key, text.replaceAll('protocol.CanonicalJSON', 'removedCanonicalJSON'));
  })]);
  probes.push(['held descriptor verification removed', mutateSources((copy) => {
    const verifier = copy.get('internal/evidence/verify.go') ?? '';
    copy.set('internal/evidence/verify.go', verifier.replace('syscall.Openat(', 'removedOpenat('));
  })]);
  probes.push(['no-replace publication removed', mutateSources((copy) => {
    const exporter = copy.get('internal/evidence/export.go') ?? '';
    copy.set('internal/evidence/export.go', exporter.replaceAll('renameat2NoReplace(', 'removedNoReplace('));
  })]);
  probes.push(['pre-materialization event bound removed', mutateSources((copy) => {
    const postgres = copy.get('internal/evidence/postgres.go') ?? '';
    copy.set('internal/evidence/postgres.go', postgres.replace('MaxEvents: maxRawCaptureEventCount', 'MaxEvents: 0'));
  })]);
  probes.push(['same-snapshot bounded verifier limit removed',
    sourceContractProblems(sources, boundedVerifier.replace('LIMIT $2', 'removedLimit')).length > 0]);
  probes.push(['time/hostname/PID root pollution', mutateSources((copy) => {
    copy.set('internal/evidence/export.go', (copy.get('internal/evidence/export.go') ?? '') + '\nfunc polluted(){ _,_=time.Now(),os.Hostname(); _=os.Getpid() }\n');
  })]);
  probes.push(['network', mutateSources((copy) => {
    copy.set('internal/evidence/export.go', (copy.get('internal/evidence/export.go') ?? '') + '\n// mutation import "net/http"; http.Get("https://example.invalid")\n');
  })]);
  probes.push(['payload log', mutateSources((copy) => {
    copy.set('internal/evidence/export.go', (copy.get('internal/evidence/export.go') ?? '') + '\n// mutation fmt.Printf("%s", event.PayloadCanonical)\n');
  })]);
  probes.push(['max-events truncation success', mutateSources((copy) => {
    copy.set('internal/evidence/export.go', (copy.get('internal/evidence/export.go') ?? '') + '\n// mutation maxEvents := 10; events = events[:maxEvents]\n');
  })]);
  probes.push(['Web', mutateSources((copy) => {
    copy.set('internal/web/evidence.go', 'package web\n');
  })]);
  probes.push(['UNREGISTERED path', mutateSources((copy) => {
    copy.set('UNREGISTERED-AIPT-P0-B002/evidence.go', 'package unregistered\n');
  })]);
  for (const [label, rejected] of probes) if (!rejected) problems.push('mutation probe failed open: ' + label);
  return { problems, count: probes.length };
}

export function run(ctx) {
  const details = [];
  let pass = true;
  const ok = (message) => details.push('ok: ' + message);
  const fail = (message) => { pass = false; details.push('FAIL: ' + message); };
  let schema;
  let rawManifest;
  try {
    schema = JSON.parse(fs.readFileSync(path.join(ctx.repo, SCHEMA_PATH), 'utf8'));
    rawManifest = JSON.parse(fs.readFileSync(path.join(ctx.repo, FIXTURE_ROOT, 'manifest.json'), 'utf8'));
  } catch (error) {
    fail('read schema/golden manifest: ' + error.message);
    return { result: 'FAIL', details };
  }
  const schemaProblems = schemaContractProblems(schema);
  for (const problem of schemaProblems) fail(problem);
  if (schemaProblems.length === 0) ok('Evidence/Audit root is the exact non-vacuous three-stage Draft 2020-12 schema');
  const behaviorProblems = validateSchemaBehavior(schema, rawManifest);
  for (const problem of behaviorProblems) fail(problem);
  if (behaviorProblems.length === 0) ok('positive and negative stage/disclosure/schema examples behave fail-closed');
  const fixtureProblems = goldenProblems(ctx.repo, schema);
  for (const problem of fixtureProblems) fail(problem);
  if (fixtureProblems.length === 0) ok('synthetic NON_CANON_TEST_FIXTURE has exact canonical bytes, hashes, root, and chain');
  const sources = evidenceSourceMap(ctx.repo);
  const boundedVerifier = fs.readFileSync(path.join(ctx.repo, BOUNDED_VERIFY_PATH), 'utf8');
  const sourceProblems = sourceContractProblems(sources, boundedVerifier);
  for (const problem of sourceProblems) fail(problem);
  if (sourceProblems.length === 0) ok('RAW_CAPTURE runtime is atomic, read-only, complete, CanonicalJSON-reusing, and capability-confined');
  const mutations = mutationProblems(schema, sources, boundedVerifier, rawManifest);
  for (const problem of mutations.problems) fail(problem);
  if (mutations.problems.length === 0) ok('all ' + mutations.count + ' evidence/schema mutation probes fail closed');
  return { result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain(import.meta.url, 'evidence', run);
