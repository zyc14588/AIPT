// Shared test helpers: load the repository's public canonical fixture and
// schema (tests never recreate fixture truth).
import fs from 'node:fs';
import path from 'node:path';

export const FIXTURE_DIR = path.resolve(import.meta.dirname, '../../../testdata/protocol/v1/minimal-fixture');
export const SCHEMA_PATH = path.resolve(import.meta.dirname, '../../../schemas/protocol/v1/aipt-protocol.schema.json');

export function loadFixtureJson(rel: string): Record<string, unknown> {
  const text = fs.readFileSync(path.join(FIXTURE_DIR, rel), 'utf8');
  return JSON.parse(text) as Record<string, unknown>;
}

export function loadFixtureText(rel: string): string {
  return fs.readFileSync(path.join(FIXTURE_DIR, rel), 'utf8');
}

export function loadSchema(): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(SCHEMA_PATH, 'utf8')) as Record<string, unknown>;
}
