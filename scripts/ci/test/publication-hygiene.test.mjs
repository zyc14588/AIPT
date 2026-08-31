import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, test } from 'node:test';
import { runPublicationHygiene } from '../lib/publication-hygiene.mjs';
import { scanTreeForHazards } from '../lib/scan.mjs';

let temporary;
afterEach(() => {
  if (temporary) fs.rmSync(temporary, { recursive: true, force: true });
  temporary = undefined;
});

function runWith(content, environment = {}) {
  temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-publication-hygiene-'));
  fs.writeFileSync(path.join(temporary, 'candidate.txt'), content, 'utf8');
  return runPublicationHygiene({ repo: temporary, files: ['candidate.txt'], environment });
}

test('every synthetic leak class is detected and clean removal passes', () => {
  const specimens = [
    ['credential_leaks', ['s', 'k', '-', 'FAKEONLY123456789'].join('')],
    ['token_leaks', ['Bear', 'er', ' ', 'FAKE_TOKEN_123456789'].join('')],
    ['private_asset_locator_leaks', ['PRIVATE', '_ASSET', '_LOCATOR:', 'GGUF-TEST'].join('')],
    ['private_prompt_leaks', ['BEGIN', ' PRIVATE', ' PROMPT'].join('')],
    ['private_path_leaks', ['/', 'ho', 'me', '/', 'fake-user', '/', 'private', '/', 'model.bin'].join('')],
  ];
  for (const [category, specimen] of specimens) {
    const report = runWith(`synthetic=${specimen}`);
    assert.equal(report.result, 'FAIL', category);
    assert.ok(report.counts[category] > 0, category);
    assert.equal(JSON.stringify(report).includes(specimen), false, 'reports must never echo matched material');
  }
  const environmentValue = ['ENV', '_ONLY', '_FAKE', '_123456789'].join('');
  const environmentReport = runWith(`resolved=${environmentValue}`, { TEST_API_KEY: environmentValue });
  assert.equal(environmentReport.result, 'FAIL');
  assert.ok(environmentReport.counts.environment_secret_leaks > 0);
  const clean = runWith('public candidate without private material');
  assert.equal(clean.result, 'PASS', JSON.stringify(clean));
  assert.equal(clean.required_detectors_executed, true);
  assert.equal(clean.coverage, 'complete');
});

test('missing and unsupported coverage fail closed instead of reporting zero', () => {
  temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-publication-hygiene-'));
  let report = runPublicationHygiene({ repo: temporary, files: ['missing.txt'], environment: {} });
  assert.equal(report.result, 'FAIL');
  assert.equal(report.coverage, 'incomplete');
  fs.writeFileSync(path.join(temporary, 'binary.dat'), Buffer.from([0xff, 0xfe, 0xfd]));
  report = runPublicationHygiene({ repo: temporary, files: ['binary.dat'], environment: {} });
  assert.equal(report.result, 'FAIL');
  assert.equal(report.coverage, 'incomplete');

  fs.writeFileSync(path.join(temporary, 'candidate.txt'), 'clean', 'utf8');
  report = runPublicationHygiene({
    repo: temporary,
    files: ['candidate.txt', 'candidate.txt'],
    environment: {},
  });
  assert.equal(report.result, 'FAIL');
  assert.ok(report.errors.includes('publication inventory contains duplicate paths'));

  fs.symlinkSync('candidate.txt', path.join(temporary, 'linked.txt'));
  report = runPublicationHygiene({ repo: temporary, files: ['linked.txt'], environment: {} });
  assert.equal(report.result, 'FAIL');
  assert.equal(report.coverage, 'incomplete');
});

test('detector and finding budgets fail closed with bounded redacted output', () => {
  const specimen = ['s', 'k', '-', 'FAKEONLY123456789'].join('');
  const report = runWith(Array.from({ length: 300 }, () => specimen).join('\n'));
  assert.equal(report.result, 'FAIL');
  assert.equal(report.coverage, 'incomplete');
  assert.ok(report.errors.some((entry) => entry.includes('exceeded its bounded policy')));
  assert.equal(JSON.stringify(report).includes(specimen), false);

  const assignment = ['TEST_API_KEY=', 'FAKEONLY123456789'].join('');
  fs.writeFileSync(path.join(temporary, '.env'), `${assignment}\n`, 'utf8');
  const assignmentReport = runPublicationHygiene({ repo: temporary, files: ['.env'], environment: {} });
  assert.equal(assignmentReport.result, 'FAIL');
  assert.ok(assignmentReport.counts.credential_leaks > 0);
  assert.equal(JSON.stringify(assignmentReport).includes('FAKEONLY123456789'), false);
});

test('legacy hazard reports never retain or echo matched sensitive material', () => {
  temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'aipt-publication-hygiene-'));
  const specimen = ['s', 'k', '-', 'FAKEONLY123456789012345'].join('');
  fs.writeFileSync(path.join(temporary, 'candidate.mjs'), `const credential = "${specimen}";\n`, 'utf8');
  const findings = scanTreeForHazards(temporary);
  assert.deepEqual(findings, [{ file: 'candidate.mjs', hazard: 'API_KEY_LIKE' }]);
  assert.equal(JSON.stringify(findings).includes(specimen), false);
});
