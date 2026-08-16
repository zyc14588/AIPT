// SBOM determinism validator: generate twice, require byte-identical output,
// and record the SHA-256 of the artifact (B001 does not commit SBOM output).
import crypto from 'node:crypto';
import { buildSbom } from '../sbom/generate-sbom.mjs';
import { runAsMain } from '../lib/cli.mjs';

export function run(ctx) {
  const details = [];
  let pass = true;
  const first = buildSbom(ctx.repo);
  const second = buildSbom(ctx.repo);
  const identical = first.equals(second);
  const sha256 = crypto.createHash('sha256').update(first).digest('hex');
  if (!identical) {
    pass = false;
    details.push('FAIL: SBOM generation is not deterministic (two runs differ byte-wise)');
  } else {
    details.push(`ok: two independent generations are byte-identical (${first.length} bytes)`);
  }
  details.push(`ok: sbom sha256 = ${sha256}`);
  return { name: 'sbom', result: pass ? 'PASS' : 'FAIL', details };
}

runAsMain('sbom', run);
