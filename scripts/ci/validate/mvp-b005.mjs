#!/usr/bin/env node
// AIPT-MVP-B005 lifecycle-aware AUDIT_READY evidence-closure gate.
// This validator is standard-library-only and performs no model, provider,
// source fetch, integration rerun, or qualification execution.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { git, runAsMain } from '../lib/cli.mjs';
import { checkSchemaDocument, validateInstance } from '../lib/json-schema.mjs';
import { runPublicationHygiene } from '../lib/publication-hygiene.mjs';

const TASK_ID = 'AIPT-MVP-B005';
const BRANCH = `task/${TASK_ID}`;
const BASE_COMMIT = '176f33d8f20f94a77ab688f4869e944b6ffe97c6';
const BASE_TREE = '210320957a35633bcf766a3d88ea50a3493bd0fc';
const PREVIOUS_PUBLIC_CANDIDATE = '7ca1f9679c42c502e4b56103f66fff5e6798c184';
const PREVIOUS_PUBLIC_TREE = '127b17486d66df0a21e3e4048a89eda2ce8e1e04';
const PREVIOUS_PUBLIC_CI = 33738314143;
const PREDECESSOR = 'INT-AIPT-UNREGISTERED-MVP-001';
const PREDECESSOR_RECORD = 'docs/authority/registry/integration-closeouts/int-aipt-unregistered-mvp-001-closeout.json';
const PREDECESSOR_SHA256 = '1f22028561c90619755314eedb50869bb40e78b4ef55458e35eb654bf8d9ebc2';
const LEGACY_SCHEMA = 'schemas/evidence/v1/aipt-evidence.schema.json';
const LEGACY_SCHEMA_SHA256 = 'bf93b4d60db652e59c83f2f89b6763150ec01a8549a9f87a7e6daa189a0e4d85';
const LEGACY_GOLDEN = 'testdata/evidence/v1/minimal-raw-capture/manifest.json';
const LEGACY_GOLDEN_SHA256 = '106ba6686d0f47304921266824c5832916867931869c45424d894410eed241a2';
const STATUS_PATH = 'docs/authority/registry/project-status.json';
const MATRIX_PATH = 'testdata/evidence/v1/b005-negative-matrix.json';
const NEGATIVE_PROBE_COUNT = 50;

const SCHEMAS = Object.freeze({
  closure: 'schemas/evidence/v1/aipt-run-evidence-closure.schema.json',
  defects: 'schemas/evidence/v1/aipt-defect-contracts.schema.json',
  report: 'schemas/evidence/v1/aipt-run-report.schema.json',
  index: 'schemas/evidence/v1/aipt-audit-ready-bundle-index.schema.json',
});

const REQUIRED_PATHS = Object.freeze([
  'cmd/aipt-audit-ready/main.go',
  'cmd/aipt-audit-ready/main_test.go',
  'docs/evidence/B005_AUTHORITY_MATRIX.md',
  'docs/evidence/README.md',
  'docs/authority/PROJECT_STATUS.md',
  'docs/authority/BATCH_DEPENDENCY_GRAPH.md',
  STATUS_PATH,
  'internal/evidence/audit_ready.go',
  'internal/evidence/audit_ready_test.go',
  'internal/evidence/closure_types.go',
  'internal/evidence/closure_validate.go',
  'internal/evidence/raw_material.go',
  'internal/evidence/report_render.go',
  'internal/evidence/source_verify.go',
  'internal/evidence/types.go',
  'internal/evidence/postgres_integration_test.go',
  ...Object.values(SCHEMAS),
  MATRIX_PATH,
  'scripts/ci/validate/mvp-b005.mjs',
  'scripts/ci/validate/evidence.mjs',
  'scripts/ci/validate/int001-closeout-authority.mjs',
  'scripts/ci/validate/mvp-b004.mjs',
  'scripts/ci/validate/workflow.mjs',
  'scripts/ci/run-checks.mjs',
  'package.json',
  '.github/workflows/ci.yml',
]);

function read(repo, relative) { return fs.readFileSync(path.join(repo, relative), 'utf8'); }
function readJSON(repo, relative) { return JSON.parse(read(repo, relative)); }
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function gitResult(repo, args) { return git(repo, args, { check: false }); }
function gitOut(repo, args) { const result = gitResult(repo, args); return result.status === 0 ? result.stdout.trim() : null; }
function lines(result) { return result?.status === 0 ? result.stdout.split('\n').filter(Boolean) : []; }
function nulPaths(result) { return result?.status === 0 ? result.stdout.split('\0').filter(Boolean) : []; }
function isAncestor(repo, ancestor, descendant) { return gitResult(repo, ['merge-base', '--is-ancestor', ancestor, descendant]).status === 0; }
function currentBranch(repo) {
  return gitOut(repo, ['branch', '--show-current']) || process.env.GITHUB_HEAD_REF ||
    (process.env.GITHUB_REF?.startsWith('refs/heads/') ? process.env.GITHUB_REF.slice('refs/heads/'.length) : 'DETACHED');
}
function commitFacts(repo, commit) {
  const row = gitOut(repo, ['rev-list', '--parents', '-n', '1', commit]);
  if (!row) return null;
  const [resolved, ...parents] = row.split(/\s+/u);
  const tree = gitOut(repo, ['rev-parse', `${resolved}^{tree}`]);
  return tree ? { commit: resolved, tree, parents } : null;
}
function changedPaths(repo, from, to) {
  return lines(gitResult(repo, ['diff', '--name-only', '--no-renames', from, to])).sort();
}
function candidateInventory(repo) {
  const committed = changedPaths(repo, BASE_COMMIT, 'HEAD');
  const tracked = lines(gitResult(repo, ['diff', '--name-only', '--no-renames']));
  const staged = lines(gitResult(repo, ['diff', '--cached', '--name-only', '--no-renames']));
  const untracked = lines(gitResult(repo, ['ls-files', '--others', '--exclude-standard']));
  return [...new Set([...committed, ...tracked, ...staged, ...untracked]
    .filter((relative) => relative && !relative.split('/').includes('node_modules')))].sort();
}
function dirty(repo) {
  return lines(gitResult(repo, ['status', '--porcelain=v1', '--untracked-files=all']))
    .some((line) => !line.includes('node_modules/'));
}
function allowedPath(relative) {
  return relative.startsWith('internal/evidence/') || relative.startsWith('schemas/evidence/') ||
    relative.startsWith('cmd/aipt-audit-ready/') || relative.startsWith('docs/evidence/') ||
    relative === MATRIX_PATH || relative === STATUS_PATH || relative === 'docs/authority/PROJECT_STATUS.md' ||
    relative === 'docs/authority/BATCH_DEPENDENCY_GRAPH.md' || relative === 'docs/authority/README.md' ||
    relative === 'scripts/ci/validate/mvp-b005.mjs' || relative === 'scripts/ci/validate/evidence.mjs' ||
    relative === 'scripts/ci/validate/int001-closeout-authority.mjs' || relative === 'scripts/ci/validate/mvp-b004.mjs' ||
    relative === 'scripts/ci/run-checks.mjs' ||
    relative === 'scripts/ci/validate/workflow.mjs' ||
    relative === 'package.json' || relative === '.github/workflows/ci.yml';
}
function linearCandidate(repo, candidate) {
  const rows = lines(gitResult(repo, ['rev-list', '--reverse', '--parents', `${BASE_COMMIT}..${candidate}`]));
  let previous = BASE_COMMIT;
  for (const row of rows) {
    const [commit, ...parents] = row.split(/\s+/u);
    if (parents.length !== 1 || parents[0] !== previous) return false;
    previous = commit;
  }
  return rows.length > 0 && previous === candidate;
}

function resolveTopology(repo) {
  const head = gitOut(repo, ['rev-parse', 'HEAD^{commit}']);
  const headFacts = commitFacts(repo, head);
  const branch = currentBranch(repo);
  const baseExact = commitFacts(repo, BASE_COMMIT)?.tree === BASE_TREE;
  const previousExact = commitFacts(repo, PREVIOUS_PUBLIC_CANDIDATE)?.tree === PREVIOUS_PUBLIC_TREE &&
    linearCandidate(repo, PREVIOUS_PUBLIC_CANDIDATE);
  if (!baseExact || !previousExact || !head || !isAncestor(repo, BASE_COMMIT, head)) {
    return { phase: 'REJECTED', head, headFacts, branch, candidate: null, paths: candidateInventory(repo) };
  }
  if (dirty(repo)) {
    const paths = candidateInventory(repo);
    const repairHead = head === PREVIOUS_PUBLIC_CANDIDATE && headFacts?.tree === PREVIOUS_PUBLIC_TREE;
    const valid = (head === BASE_COMMIT || repairHead) && branch === BRANCH && paths.every(allowedPath);
    return { phase: valid ? 'CONSTRUCTION' : 'REJECTED', head, headFacts, branch, candidate: null, paths };
  }
  if (branch === BRANCH && head !== PREVIOUS_PUBLIC_CANDIDATE && headFacts?.parents.length === 1 &&
      linearCandidate(repo, head) && isAncestor(repo, PREVIOUS_PUBLIC_CANDIDATE, head)) {
    const paths = changedPaths(repo, BASE_COMMIT, head);
    return { phase: paths.every(allowedPath) ? 'CANDIDATE' : 'REJECTED', head, headFacts, branch, candidate: head, paths };
  }
  const firstParent = lines(gitResult(repo, ['rev-list', '--first-parent', '--reverse', `${BASE_COMMIT}..${head}`]));
  for (const commit of firstParent) {
    const facts = commitFacts(repo, commit);
    if (facts?.parents.length !== 2 || facts.parents[0] !== BASE_COMMIT || !linearCandidate(repo, facts.parents[1])) continue;
    const candidateFacts = commitFacts(repo, facts.parents[1]);
    const paths = changedPaths(repo, BASE_COMMIT, facts.parents[1]);
    const immutable = paths.every((relative) => {
      if (!relative.startsWith('internal/evidence/') && !relative.startsWith('schemas/evidence/') && !relative.startsWith('cmd/aipt-audit-ready/')) return true;
      const accepted = gitResult(repo, ['show', `${facts.parents[1]}:${relative}`]);
      const current = gitResult(repo, ['show', `${head}:${relative}`]);
      return accepted.status === 0 && current.status === 0 && accepted.stdout === current.stdout;
    });
    if (candidateFacts?.tree === facts.tree && paths.every(allowedPath) && immutable && isAncestor(repo, commit, head)) {
      return { phase: commit === head ? 'LEGAL_MERGE' : 'POST_MERGE_SUCCESSOR', head, headFacts, branch, candidate: facts.parents[1], paths };
    }
  }
  return { phase: 'REJECTED', head, headFacts, branch, candidate: null, paths: [] };
}

function schemaStrictObjectProblems(schema) {
  const problems = [];
  const pending = [['#', schema]];
  while (pending.length > 0) {
    const [location, value] = pending.pop();
    if (value === null || typeof value !== 'object') continue;
    if (!Array.isArray(value) && value.type === 'object' && value.additionalProperties !== false) {
      problems.push(`${location} object is not additionalProperties:false`);
    }
    for (const [key, child] of Object.entries(value)) {
      if (child !== null && typeof child === 'object') pending.push([`${location}/${key}`, child]);
    }
  }
  return problems;
}

function examples() {
  const h = (digit) => digit.repeat(64);
  const source = { repository: 'https://example.invalid/aipt-synthetic.git', commit: '1'.repeat(40), tree: '2'.repeat(40) };
  const ref = { id: 'SYNTH-EVIDENCE', path: 'supplemental/evidence.txt', sha256: h('a') };
  const rng = { used: false, version: 'NONE', seed_commitment: '', seed_disclosure_status: 'NOT_APPLICABLE' };
  const replay = {
    schema: 'aipt.replay-evidence/v1', version: '1.0.0', run_id: 'SYNTH-RUN', run_manifest_sha256: h('3'),
    ledger_stream_id: 'SYNTH-STREAM', ledger_tail_sequence: 1, ledger_tail_hash: h('4'),
    live_final_state_hash: h('5'), replayed_final_state_hash: h('5'), hash_match: true,
    implementation: { id: 'SYNTH-REPLAY', version: '1.0.0', sha256: h('6') }, rng,
  };
  const closure = {
    schema: 'aipt.run-evidence-closure/v1', version: '1.0.0', run_id: 'SYNTH-RUN',
    run_manifest: { id: 'SYNTH-MANIFEST', schema: 'aipt.run-manifest/v1', canonical_sha256: h('3') }, source,
    state_authority: 'POSTGRESQL_APPEND_ONLY_HASH_CHAIN',
    ledger: { stream_id: 'SYNTH-STREAM', event_count: 1, tail_sequence: 1, tail_event_hash: h('4') },
    action_receipts: [{ action_id: 'SYNTH-ACTION', sequence: 1, event_hash: h('7'), state_hash: h('8'), projection_hash: h('9'), evidence: ref }],
    projection: { schema: 'aipt.synthetic-projection/v1', canonical_sha256: h('8'), final_state_hash: h('5') },
    rule_citations: [{ rule_id: 'RULE-SYNTH-001', source_sha256: h('b') }], rng, replay,
    coverage_references: [ref], defect_occurrence_ids: ['SYNTH-OCCURRENCE'], anomaly_codes: [],
    gate_eligibility_facts: [{ gate: 'QUALIFICATION', eligible: false, reason_code: 'SYNTHETIC_DOES_NOT_QUALIFY' }],
    model_execution_references: [],
  };
  const projection = { version: 'aipt.defect-fingerprint/v1', root_cause_domain: 'AIPT', semantic_key: 'SYNTHETIC-DEFECT', rule_ids: ['RULE-SYNTH-001'], invariant_ids: ['INV-SYNTH-001'] };
  const family = {
    schema: 'aipt.defect-family/v1', version: '1.0.0', family_id: 'SYNTH-FAMILY', fingerprint_version: 'aipt.defect-fingerprint/v1',
    fingerprint: h('c'), fingerprint_projection: projection, root_cause_domain: 'AIPT', severity: 'LOW', confidence: 'HIGH',
    reproducibility: 'ALWAYS', scope: ['SYNTHETIC-RUN'], priority: 'P4',
  };
  const occurrence = {
    schema: 'aipt.defect-occurrence/v1', version: '1.0.0', occurrence_id: 'SYNTH-OCCURRENCE', family_fingerprint: h('c'),
    run_id: 'SYNTH-RUN', source, root_cause_domain: 'AIPT', severity: 'LOW', confidence: 'HIGH', reproducibility: 'ALWAYS',
    scope: ['SYNTHETIC-RUN'], priority: 'P4', evidence_references: [ref], reproduction_reference: ref, observed_context_sha256: h('d'),
  };
  const report = {
    schema: 'aipt.run-report/v1', version: '1.0.0', report_id: 'SYNTH-REPORT', revision: 1, predecessor_report_sha256: null,
    lifecycle: 'PROVISIONAL', run_id: 'SYNTH-RUN', source, run_manifest: closure.run_manifest, execution_status: 'SYNTHETIC_COMPLETED',
    coverage: { references: [ref], total: 1, covered: 1 }, replay, defect_family_references: ['SYNTH-FAMILY'],
    defect_occurrence_references: ['SYNTH-OCCURRENCE'], anomaly_codes: [], security_findings: [], visibility_findings: [],
    model_execution: { remote_deepseek_real_calls: 0, local_llamacpp_real_calls: 0, provider_model_network_calls: 0, reference_ids: [] },
    gate_eligibility_facts: closure.gate_eligibility_facts, qualification_eligible: false,
    evidence_roots: [{ kind: 'RAW_CAPTURE', sha256: h('e') }, { kind: 'RUN_EVIDENCE_CLOSURE', sha256: h('f') }],
    auditor_verdict_claimed: false, audit_result: null,
  };
  const index = {
    schema: 'aipt.audit-ready.bundle-index/v1', version: '1.0.0',
    core_evidence_classifications: {
      schema: 'aipt.core-evidence-classification/v1', version: '1.0.0', raw_capture: 'PUBLIC',
      run_evidence_closure: 'PUBLIC', replay_evidence: 'PUBLIC', defect_family: 'PUBLIC',
      defect_occurrence: 'PUBLIC', run_report: 'PUBLIC', report_derivatives: 'PUBLIC',
    },
    export_profile: { profile_id: 'SYNTHETIC', inline_threshold: 8, chunk_size: 4, max_asset_bytes: 1024, max_total_bytes: 4096, max_assets: 16, max_chunks: 64 },
    logical_assets: [{ path: 'supplemental/evidence.txt', media_type: 'text/plain', bytes: 9, sha256: h('a'), classification: 'PUBLIC', content_kind: 'SUPPLEMENTAL', storage: { kind: 'CONTENT_ADDRESSED_CHUNKS', chunks: [{ ordinal: 0, path: `chunk-${h('a')}.bin`, bytes: 4, sha256: h('a') }] } }],
  };
  return { closure, family, occurrence, report, index };
}

function schemaProblems(repo) {
  const problems = [];
  const documents = Object.fromEntries(Object.entries(SCHEMAS).map(([name, relative]) => [name, readJSON(repo, relative)]));
  for (const [name, schema] of Object.entries(documents)) {
    const meta = checkSchemaDocument(schema);
    if (!meta.valid) problems.push(`${name} schema meta-check: ${meta.errors.join('; ')}`);
    problems.push(...schemaStrictObjectProblems(schema).map((problem) => `${name} schema ${problem}`));
  }
  const fixture = examples();
  for (const [name, value] of Object.entries(fixture)) {
    const schema = name === 'closure' ? documents.closure : name === 'report' ? documents.report : name === 'index' ? documents.index : documents.defects;
    const report = validateInstance(schema, value);
    if (!report.valid) problems.push(`${name} schema example rejected: ${JSON.stringify(report.errors)}`);
  }
  const unknown = structuredClone(fixture.closure); unknown.unexpected = true;
  if (validateInstance(documents.closure, unknown).valid) problems.push('closure schema accepted unknown field');
  const badReplay = structuredClone(fixture.closure); badReplay.replay.hash_match = false;
  if (validateInstance(documents.closure, badReplay).valid) problems.push('closure schema accepted replay hash_match=false');
  const falseAudit = structuredClone(fixture.report); falseAudit.audit_result = { asset_path: 'audit-result.json', sha256: 'f'.repeat(64), verdict: 'PASS' };
  if (validateInstance(documents.report, falseAudit).valid) problems.push('report schema accepted an unclaimed AUDIT_RESULT');
  const sealedWithoutHistory = structuredClone(fixture.report); sealedWithoutHistory.lifecycle = 'SEALED';
  if (validateInstance(documents.report, sealedWithoutHistory).valid) problems.push('report schema accepted SEALED at revision 1 without history');
  const invalidRng = structuredClone(fixture.report); invalidRng.replay.rng.seed_disclosure_status = 'DISCLOSED_AS_EVIDENCE';
  if (validateInstance(documents.report, invalidRng).valid) problems.push('report schema accepted inconsistent no-RNG evidence');
  const invalidAddendum = {
    schema: 'aipt.run-report-addendum/v1', version: '1.0.0', addendum_id: 'SYNTH-ADDENDUM',
    sealed_report_sha256: 'a'.repeat(64), sequence: 2, predecessor_addendum_sha256: null,
    content_sha256: 'b'.repeat(64), evidence_references: [fixture.closure.coverage_references[0]],
  };
  if (validateInstance(documents.report, invalidAddendum).valid) problems.push('report schema accepted a broken addendum predecessor');
  const unsafeIndex = structuredClone(fixture.index); unsafeIndex.logical_assets[0].path = '../escape';
  if (validateInstance(documents.index, unsafeIndex).valid) problems.push('bundle index schema accepted path traversal');
  return { problems, documents };
}

function sourceProblems(repo) {
  const problems = [];
  const productionPaths = [
    'internal/evidence/audit_ready.go', 'internal/evidence/closure_types.go', 'internal/evidence/closure_validate.go',
    'internal/evidence/raw_material.go', 'internal/evidence/report_render.go', 'internal/evidence/source_verify.go',
    'cmd/aipt-audit-ready/main.go',
  ];
  const sources = Object.fromEntries(productionPaths.map((relative) => [relative, read(repo, relative)]));
  const all = Object.values(sources).join('\n');
  const requiredTokens = new Map([
    ['internal/evidence/audit_ready.go', ['func GenerateAuditReady(', 'func VerifyAuditReady(', 'renameat2NoReplace(', 'CONTENT_ADDRESSED_CHUNKS', 'validateContractEvidenceReferences(', 'validateCoreEvidenceClassifications(', 'validateCoreLogicalAssetDescriptors(', 'inputUnchanged()', 'ErrEncryptionRequired']],
    ['internal/evidence/raw_material.go', ['VerifyRawCapture(directory)', 'openHeldPrivateFile(', 'func (held *heldRawCapture) Stable() bool']],
    ['internal/evidence/source_verify.go', ['type GitMirrorVerifier struct', 'trustedGitExecutable = "/usr/bin/git"', '--no-replace-objects', '--git-dir=/proc/self/fd/3', 'command.ExtraFiles', 'exec.CommandContext(', 'GIT_NO_LAZY_FETCH=1', 'url.Parse(', 'ValidateAuditReadyRepositoryIdentity(', 'cat-file', '--format=%T']],
    ['internal/evidence/closure_validate.go', ['func DefectFingerprint(', 'SEMANTIC_DUPLICATE_CANDIDATE', 'func ResolveDefectDecisionChain(', 'func ValidateReportTransition(', 'previous.Lifecycle == ReportSealed', 'func ValidateReportAddendumChain(']],
    ['internal/evidence/report_render.go', ['func RenderRunReport(', 'renderReportMarkdown(', 'renderReportCSV(', 'renderReportJUnit(', 'renderReportHTML(']],
    ['cmd/aipt-audit-ready/main.go', ['case "generate":', 'case "verify":', 'base64.StdEncoding.Strict()', 'ValidateAuditReadyRepositoryIdentity(', 'stableErrorCode(']],
  ]);
  for (const [relative, tokens] of requiredTokens) {
    for (const token of tokens) if (!sources[relative].includes(token)) problems.push(`${relative} misses required token ${token}`);
  }
  const forbidden = [
    ['wall clock', /time\s*\.\s*Now\s*\(/u], ['hostname', /os\s*\.\s*Hostname\s*\(/u], ['PID', /os\s*\.\s*Getpid\s*\(/u],
    ['network package', /["']net\/http["']|http\s*\.\s*(?:Get|Post|Do)\s*\(/u],
    ['shell execution', /exec\s*\.\s*Command(?:Context)?\s*\([^,]+,\s*["'](?:-c|\/c)["']/u],
    ['model runtime import', /internal\/(?:modelgateway|orchestrator|runcore)|codex-harness|HarnessBackend/u],
    ['database mutation', /\b(?:INSERT|UPDATE|DELETE|ALTER|TRUNCATE|CREATE|DROP)\b/u],
    ['archive or decompression', /archive\/(?:tar|zip)|compress\//u],
  ];
  for (const [label, pattern] of forbidden) if (pattern.test(all)) problems.push(`forbidden B005 production capability: ${label}`);
  if ((all.match(/os\.Getenv\s*\(/gu) ?? []).length > 1 || (all.includes('os.Getenv(') && !all.includes('os.Getenv("PATH")'))) {
    problems.push('B005 production reads ambient environment beyond the executable search path');
  }
  return problems;
}

function statusProblems(status, phase) {
  const problems = [];
  const standalone = status?.tracks?.['AIPT-STANDALONE'];
  const active = standalone?.construction === 'IN_PROGRESS' && standalone?.current_batch === TASK_ID &&
    standalone?.next_serial_batch === 'AIPT-MVP-B006' && standalone?.next_batch_state === 'NOT_AUTHORIZED' &&
    standalone?.next_batch_authorized === false && standalone?.next_batch_started === false &&
    standalone?.batch_history?.[PREDECESSOR] === 'MERGED_CLOSED' && standalone?.batch_history?.[TASK_ID] === 'IN_PROGRESS' &&
    standalone?.batch_history?.['AIPT-MVP-B006'] === 'NOT_STARTED' && standalone?.global_wip === 1;
  const closed = standalone?.batch_history?.[TASK_ID] === 'MERGED_CLOSED' && standalone?.next_serial_batch === 'AIPT-MVP-B006' &&
    standalone?.next_batch_state === 'NOT_AUTHORIZED' && standalone?.next_batch_authorized === false &&
    standalone?.next_batch_started === false && standalone?.construction === 'IDLE_WAITING_NEXT_BATCH' &&
    standalone?.current_batch === 'NO_ACTIVE_BATCH' && standalone?.batch_history?.['AIPT-MVP-B006'] === 'NOT_STARTED' &&
    standalone?.global_wip === 0;
  if ((phase === 'CONSTRUCTION' || phase === 'CANDIDATE') ? !active : !(active || closed)) {
    problems.push('project-status does not carry the lifecycle-appropriate B005 WIP1/next-B006 tuple');
  }
  const b005 = status?.repositories?.AIPT?.mvp_b005;
  const stateValid = (phase === 'CONSTRUCTION' || phase === 'CANDIDATE' || phase === 'LEGAL_MERGE')
    ? b005?.state === 'IN_PROGRESS' : (b005?.state === 'IN_PROGRESS' || b005?.state === 'MERGED_CLOSED');
  if (!b005 || !stateValid || b005.task_id !== TASK_ID ||
      b005.start_authority !== 'OWNER_DIRECTIVE_AIPT-MVP-B005' || b005.risk !== 'evidence-integrity' ||
      b005.base?.commit !== BASE_COMMIT || b005.base?.tree !== BASE_TREE ||
      b005.predecessor?.task_id !== PREDECESSOR || b005.predecessor?.canonical_closeout_sha256 !== PREDECESSOR_SHA256 ||
      b005.predecessor?.integration_manifest_sha256 !== 'de553465a6bd79e0c0ccb89af678721f132d9fe98ec39a41136402a5386ca164' ||
      b005.predecessor?.final_evidence_root_sha256 !== '7ce5014d1951f21d88ca838ef1f7e14fb802b2d8c8c03db6aa3cc902f75cb777' ||
      b005.predecessor?.rerun_performed !== false || b005.scope !== 'RUN_EVIDENCE_CLOSURE_AUDIT_READY_ONLY' ||
      b005.raw_capture_backward_compatible !== true || b005.audit_ready_generator_implemented !== true ||
      b005.audit_ready_verifier_implemented !== true || b005.run_evidence_closure_implemented !== true ||
      b005.replay_contract_implemented !== true || b005.defect_family_occurrence_contracts_implemented !== true ||
      b005.report_contract_and_lifecycle_implemented !== true || b005.deterministic_export_implemented !== true ||
      b005.content_addressed_chunking_implemented !== true || b005.encryption_implemented !== false ||
      b005.signing_implemented !== false || b005.audit_result_generator_implemented !== false ||
      b005.synthetic_public_postgresql_18_4_gate !== 'PASS' || b005.negative_probe_count !== NEGATIVE_PROBE_COUNT ||
      b005.unexpected_acceptances !== 0 || b005.real_model_calls !== 0 ||
      b005.provider_network_calls !== 0 || b005.real_playtest_executed !== false || b005.qualification_runs_executed !== 0 ||
      b005.new_migration !== 'NONE' || b005.runtime_ready !== false || b005.first_blocking_gate !== 'IPC' ||
      b005.publicly_pushed !== false || b005.public_ci_status !== 'NOT_STARTED_AWAITING_OWNER_DISCLOSURE_AUTHORIZATION' ||
      !Array.isArray(b005.open_findings) || b005.open_findings.length !== 0) {
    problems.push('project-status B005 projection is missing or semantically invalid');
  }
  return problems;
}

function expectedConstructionStatus(baseline) {
  const expected = structuredClone(baseline);
  expected.as_of = '2026-09-03';
  expected.authority_snapshot_id = 'AIPT-MVP-B005-CONSTRUCTION-001';
  const standalone = expected.tracks['AIPT-STANDALONE'];
  standalone.construction = 'IN_PROGRESS';
  standalone.current_batch = TASK_ID;
  standalone.next_serial_batch = 'AIPT-MVP-B006';
  standalone.next_batch_state = 'NOT_AUTHORIZED';
  standalone.next_batch_authorized = false;
  standalone.next_batch_started = false;
  standalone.batch_history[TASK_ID] = 'IN_PROGRESS';
  standalone.global_wip = 1;
  expected.repositories.AIPT.mvp_b005 = {
    task_id: TASK_ID,
    state: 'IN_PROGRESS',
    start_authority: 'OWNER_DIRECTIVE_AIPT-MVP-B005',
    base: { commit: BASE_COMMIT, tree: BASE_TREE },
    predecessor: {
      task_id: PREDECESSOR,
      state: 'CLOSED',
      canonical_closeout_sha256: PREDECESSOR_SHA256,
      integration_manifest_sha256: 'de553465a6bd79e0c0ccb89af678721f132d9fe98ec39a41136402a5386ca164',
      final_evidence_root_sha256: '7ce5014d1951f21d88ca838ef1f7e14fb802b2d8c8c03db6aa3cc902f75cb777',
      rerun_performed: false,
    },
    scope: 'RUN_EVIDENCE_CLOSURE_AUDIT_READY_ONLY',
    risk: 'evidence-integrity',
    raw_capture_backward_compatible: true,
    audit_ready_generator_implemented: true,
    audit_ready_verifier_implemented: true,
    run_evidence_closure_implemented: true,
    replay_contract_implemented: true,
    defect_family_occurrence_contracts_implemented: true,
    report_contract_and_lifecycle_implemented: true,
    deterministic_export_implemented: true,
    content_addressed_chunking_implemented: true,
    encryption_implemented: false,
    signing_implemented: false,
    audit_result_generator_implemented: false,
    synthetic_public_postgresql_18_4_gate: 'PASS',
    negative_probe_count: NEGATIVE_PROBE_COUNT,
    unexpected_acceptances: 0,
    real_model_calls: 0,
    provider_network_calls: 0,
    real_playtest_executed: false,
    qualification_runs_executed: 0,
    new_migration: 'NONE',
    runtime_ready: false,
    first_blocking_gate: 'IPC',
    publicly_pushed: false,
    public_ci_status: 'NOT_STARTED_AWAITING_OWNER_DISCLOSURE_AUTHORIZATION',
    open_findings: [],
  };
  expected.runtime.status = 'AIPT-MVP-B005 is the sole active construction batch at GLOBAL_WIP 1; it adds offline AUDIT_READY evidence closure only, does not change Launcher gates, and runtime_ready remains false at IPC with no playtest or qualification Run started';
  return expected;
}

function matrixProblems(matrix) {
  const problems = [];
  if (matrix?.schema !== 'aipt.b005.negative-matrix/v1' || matrix?.task_id !== TASK_ID || !Array.isArray(matrix?.probes) || matrix.probes.length !== NEGATIVE_PROBE_COUNT) {
    return [`negative matrix identity or exact N01-N${NEGATIVE_PROBE_COUNT} count is invalid`];
  }
  for (let index = 0; index < matrix.probes.length; index += 1) {
    const probe = matrix.probes[index];
    const id = `N${String(index + 1).padStart(2, '0')}`;
    if (probe.id !== id || typeof probe.attack !== 'string' || probe.attack.length === 0 || typeof probe.covered_by !== 'string' || probe.covered_by.length === 0 ||
        !['REJECT', 'FLAG_ONLY', 'MATCH_REQUIRED', 'ZERO_REQUIRED'].includes(probe.expected)) problems.push(`negative matrix ${id} is invalid`);
  }
  return problems;
}

function protectedHistoryProblems(repo, paths) {
  const protectedPrefixes = ['internal/runcore/', 'internal/orchestrator/', 'internal/modelgateway/', 'internal/testplan/', 'internal/storage/postgres/migrations/', 'packages/model-harness-gateway/', 'packages/harness-adapter/', 'UNREGISTERED/'];
  return paths.filter((relative) => protectedPrefixes.some((prefix) => relative.startsWith(prefix)))
    .map((relative) => `protected predecessor or out-of-scope path changed: ${relative}`);
}

function publicationInventory(repo, paths) {
  const tracked = nulPaths(gitResult(repo, ['ls-files', '-z']));
  const untracked = nulPaths(gitResult(repo, ['ls-files', '--others', '--exclude-standard', '-z']));
  const available = new Set([...tracked, ...untracked]);
  return paths.filter((relative) => available.has(relative)).sort();
}

export function run(ctx) {
  const problems = [];
  const topology = resolveTopology(ctx.repo);
  if (topology.phase === 'REJECTED') problems.push('Git topology/base/branch/scope is not an authorized B005 lifecycle phase');
  for (const relative of REQUIRED_PATHS) if (!fs.existsSync(path.join(ctx.repo, relative))) problems.push(`required B005 artifact missing: ${relative}`);
  const requiredChanged = REQUIRED_PATHS.filter((relative) => !topology.paths.includes(relative) && relative !== 'internal/evidence/postgres_integration_test.go');
  if (requiredChanged.length > 0) problems.push(`B005 Candidate scope misses required changed artifacts: ${requiredChanged.join(', ')}`);
  problems.push(...protectedHistoryProblems(ctx.repo, topology.paths));

  if (sha256(read(ctx.repo, PREDECESSOR_RECORD)) !== PREDECESSOR_SHA256) problems.push('canonical integration predecessor byte identity drifted');
  if (sha256(read(ctx.repo, LEGACY_SCHEMA)) !== LEGACY_SCHEMA_SHA256) problems.push('legacy Evidence v1 three-stage schema changed');
  if (sha256(read(ctx.repo, LEGACY_GOLDEN)) !== LEGACY_GOLDEN_SHA256) problems.push('legacy RAW_CAPTURE golden changed');

  let schemas = { problems: ['schemas unavailable'], documents: {} };
  let matrix = null;
  let status = null;
  try { schemas = schemaProblems(ctx.repo); problems.push(...schemas.problems); } catch (error) { problems.push(`schema validation failed closed: ${error.message}`); }
  try { matrix = readJSON(ctx.repo, MATRIX_PATH); problems.push(...matrixProblems(matrix)); } catch (error) { problems.push(`negative matrix failed closed: ${error.message}`); }
  try {
    status = readJSON(ctx.repo, STATUS_PATH);
    if (read(ctx.repo, STATUS_PATH) !== `${JSON.stringify(status, null, 2)}\n`) problems.push('project-status is not canonical pretty JSON');
    problems.push(...statusProblems(status, topology.phase));
  } catch (error) { problems.push(`project-status failed closed: ${error.message}`); }
  try { problems.push(...sourceProblems(ctx.repo)); } catch (error) { problems.push(`source validation failed closed: ${error.message}`); }

  const baselineStatus = JSON.parse(gitResult(ctx.repo, ['show', `${BASE_COMMIT}:${STATUS_PATH}`]).stdout);
  if (['CONSTRUCTION', 'CANDIDATE', 'LEGAL_MERGE'].includes(topology.phase) &&
      !isDeepStrictEqual(status, expectedConstructionStatus(baselineStatus))) {
    problems.push('project-status differs from the exact additive B005 construction projection');
  }
  for (const key of ['mvp_b001', 'mvp_b002', 'mvp_b003', 'mvp_b004']) {
    if (!isDeepStrictEqual(status?.repositories?.AIPT?.[key], baselineStatus?.repositories?.AIPT?.[key])) problems.push(`frozen ${key} projection changed`);
  }
  if (!isDeepStrictEqual(status?.integration_closeouts, baselineStatus?.integration_closeouts) ||
      !isDeepStrictEqual(status?.repositories?.UNREGISTERED, baselineStatus?.repositories?.UNREGISTERED)) {
    problems.push('frozen integration or UNREGISTERED projection changed');
  }

  const publicationFiles = publicationInventory(ctx.repo, topology.paths);
  let publication = { result: 'FAIL', errors: ['not executed'], findings: [], files_scanned: 0 };
  try { publication = runPublicationHygiene({ repo: ctx.repo, files: publicationFiles }); } catch { publication = { result: 'FAIL', errors: ['crashed'], findings: [], files_scanned: 0 }; }
  if (publication.result !== 'PASS' || publication.errors.length !== 0 || publication.findings.length !== 0 || publication.files_scanned !== publicationFiles.length) {
    problems.push('publication hygiene did not complete with exact zero-finding coverage');
  }

  const indexWithoutCoreClassifications = structuredClone(examples().index);
  delete indexWithoutCoreClassifications.core_evidence_classifications;
  const mutationProbes = [
    ['M01', topology.phase !== 'REJECTED'],
    ['M02', sha256(read(ctx.repo, PREDECESSOR_RECORD)) === PREDECESSOR_SHA256],
    ['M03', schemas.problems.length === 0],
    ['M04', matrix?.probes?.length === NEGATIVE_PROBE_COUNT],
    ['M05', !validateInstance(schemas.documents.closure ?? {}, { ...examples().closure, unexpected: true }).valid],
    ['M06', !validateInstance(schemas.documents.closure ?? {}, { ...examples().closure, version: '99.0.0' }).valid],
    ['M07', !validateInstance(schemas.documents.report ?? {}, { ...examples().report, lifecycle: 'UNSEALED' }).valid],
    ['M08', !validateInstance(schemas.documents.index ?? {}, { ...examples().index, unexpected: true }).valid],
    ['M09', !sourceProblems(ctx.repo).length],
    ['M10', protectedHistoryProblems(ctx.repo, topology.paths).length === 0],
    ['M11', !validateInstance(schemas.documents.index ?? {}, indexWithoutCoreClassifications).valid],
  ];
  for (const [id, matched] of mutationProbes) if (!matched) problems.push(`${id} validator mutation/control probe failed open`);

  const details = problems.length === 0 ? [
    `ok: ${topology.phase} descends linearly from exact authorized Base ${BASE_COMMIT}/${BASE_TREE}`,
    `ok: canonical integration predecessor is byte-exact at ${PREDECESSOR_SHA256}`,
    'ok: legacy RAW_CAPTURE schema/golden remain byte-exact and additive B005 schemas are strict Draft 2020-12 documents',
    'ok: AUDIT_READY generator/verifier, immutable Git identity, replay, defects, report lifecycle, derivatives and content-addressed chunks are present',
    'ok: offline boundary excludes model/provider calls, predecessor semantics, migrations, Web UI, decompression and database mutation',
    `ok: exact N01-N${NEGATIVE_PROBE_COUNT} executable negative matrix is registered; all ${mutationProbes.length} validator control probes matched`,
    `ok: publication hygiene scanned ${publication.files_scanned} Candidate payload files with complete zero-finding coverage`,
  ] : problems.map((problem) => `FAIL: ${problem}`);
  return {
    result: problems.length === 0 ? 'PASS' : 'FAIL', task_id: TASK_ID, details,
    lifecycle_phase: topology.phase, base_commit: BASE_COMMIT, base_tree: BASE_TREE,
    previous_public_candidate: {
      commit: PREVIOUS_PUBLIC_CANDIDATE, tree: PREVIOUS_PUBLIC_TREE, public_ci: PREVIOUS_PUBLIC_CI,
      ci_conclusion: 'success', status: 'REJECTED_PRE_MERGE_SECURITY_FINDINGS',
    },
    head_commit: topology.head, head_tree: topology.headFacts?.tree ?? null, branch: topology.branch,
    changed_paths: topology.paths, predecessor: { task_id: PREDECESSOR, canonical_closeout_sha256: PREDECESSOR_SHA256 },
    negative_probe_count: matrix?.probes?.length ?? 0,
    validator_control_probe_count: mutationProbes.length,
    unexpected_acceptances: problems.some((problem) => problem.includes('failed open')) ? 1 : 0,
    publication_hygiene: publication,
    integration_rerun_performed: false,
    remote_deepseek_real_calls: 0, local_llamacpp_real_calls: 0, provider_model_network_calls: 0,
    real_playtest_executed: false, qualification_runs_executed: 0,
    runtime_ready: false, first_blocking_gate: 'IPC',
    public_disclosure_reauthorization_required: true, publicly_pushed: false,
    next_batch: 'AIPT-MVP-B006', next_batch_authorized: false, next_batch_started: false,
  };
}

runAsMain(import.meta.url, 'mvp-b005', run);
