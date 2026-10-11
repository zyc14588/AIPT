// AIPT control adapter for the exact Owner-accepted game kernel. Core owns
// authentication, sequence, seed, draws and persistence. This adapter owns
// no model transport or game rules and exposes no filesystem operation.
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';

export const TASK0_SOURCE = Object.freeze({
  package_id: 'UNREGISTERED-TASK0-PROTOTYPE-V2',
  schema: 'unregistered.task0-prototype-package/v2',
  repository: 'zyc14588/UNREGISTERED',
  commit: 'd37ae9b38bce84f8bfc164306fee2bebf73178b7',
  tree: 'd802d28c7275e3e75ada5d6ef3edeb7fb57eb7b9',
  canonical_sha256: 'f87f011f8c57c3eef371ad1e8f5569effd035957158fd17ba7fa63655c86e13d',
});

// Dependencies are an in-process verification seam, never CLI input. The
// executable entry below resolves only fixed paths in the accepted private
// read-only capsule; it accepts no root, module or manifest override.
export function createTask0GameGateway(pkg, kernel, bridge, json) {
  const { canonical, exactKeys, requireContent, sha256, deepFreeze } = json;
  requireContent(sha256(canonical(pkg.manifest)) === TASK0_SOURCE.canonical_sha256, 'SOURCE_IDENTITY');
  return function evaluate(input) {
    requireContent(input?.schema === 'aipt.private.b007-task0-game-request/v1' &&
      canonical(input.source_binding) === canonical(TASK0_SOURCE), 'SOURCE_BINDING');
    const base = ['schema', 'operation', 'source_binding'];
    let result;
    if (input.operation === 'INITIAL') {
      exactKeys(input, base);
      result = kernel.initialState(pkg);
    } else if (input.operation === 'PROPOSE') {
      exactKeys(input, [...base, 'state', 'trusted', 'frame']);
      result = bridge.proposalFor(pkg, input.state, input.trusted, input.frame);
    } else if (input.operation === 'CHECK_PROPOSAL') {
      exactKeys(input, [...base, 'state', 'seat', 'proposal']);
      const p = input.proposal;
      const expected = bridge.proposalFor(pkg, input.state,
        { seat: input.seat, run_id: p.run_id, action_id: p.action_id, expected_sequence: p.expected_sequence },
        { actor_id: p.actor_id, action_type: p.action_type, payload: p.payload });
      requireContent(canonical(p) === canonical(expected), 'PROPOSAL_SUBSTITUTION');
      result = { valid: true };
    } else if (input.operation === 'APPLY') {
      exactKeys(input, [...base, 'state', 'seat', 'frame', 'draws']);
      bridge.authenticateFrame(input.seat, input.frame);
      requireContent(Array.isArray(input.draws), 'CORE_DRAWS');
      result = kernel.applyAction(pkg, input.state, input.frame, input.draws).state;
    } else if (input.operation === 'INVARIANT') {
      exactKeys(input, [...base, 'state']);
      kernel.validateState(pkg, input.state);
      result = { valid: true, complete: kernel.complete(pkg, input.state) };
    } else if (input.operation === 'PROJECTION') {
      exactKeys(input, [...base, 'state', 'seat', 'fixture_id']);
      const state = bridge.protocolStateFor(pkg, input.state, input.fixture_id);
      result = bridge.protocolProjectionFor(state, input.seat);
    } else {
      requireContent(false, 'OPERATION');
    }
    return deepFreeze({ schema: 'aipt.private.b007-task0-game-reply/v1',
      operation: input.operation, source_binding: TASK0_SOURCE, result });
  };
}

// A private, owned pipe carries bounded length-prefixed integer JSON. No
// caller-selected address or filesystem path is part of this protocol.
export function serveTask0GameWire(evaluate, json, read, write) {
  const maximum = 1024 * 1024;
  const exact = (size, allowEOF = false) => {
    const body = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const n = read(body, offset, size - offset);
      if (!Number.isSafeInteger(n) || n < 0 || n > size - offset) throw new Error('READ');
      if (n === 0) {
        if (allowEOF && offset === 0) return null;
        throw new Error('TRUNCATED_FRAME');
      }
      offset += n;
    }
    return body;
  };
  const send = value => {
    const body = Buffer.from(json.canonical(value), 'utf8');
    if (body.length < 2 || body.length > maximum) throw new Error('REPLY_LIMIT');
    const header = Buffer.alloc(4);
    header.writeUInt32BE(body.length);
    for (const chunk of [header, body]) {
      let offset = 0;
      while (offset < chunk.length) {
        const n = write(chunk, offset, chunk.length - offset);
        if (!Number.isSafeInteger(n) || n <= 0 || n > chunk.length - offset) throw new Error('WRITE');
        offset += n;
      }
    }
  };
  send({ schema: 'aipt.private.b007-task0-game-ready/v1', source_binding: TASK0_SOURCE });
  for (let count = 0; count < 4096; count += 1) {
    const header = exact(4, true);
    if (header === null) return;
    const size = header.readUInt32BE();
    if (size < 2 || size > maximum) throw new Error('REQUEST_LIMIT');
    send(evaluate(json.parseStrict(exact(size), maximum)));
  }
  throw new Error('EXCHANGE_LIMIT');
}

async function main() {
  try {
    if (process.argv.length !== 2) throw new Error('ARGUMENTS');
    const json = await import('file:///aipt/game/scripts/aipt/task0-json.mjs');
    const kernel = await import('file:///aipt/game/scripts/aipt/task0-prototype.mjs');
    const bridge = await import('file:///aipt/game/scripts/aipt/task0-aipt-bridge.mjs');
    const pkg = kernel.loadPrototype('/aipt/game', TASK0_SOURCE.canonical_sha256);
    const evaluate = createTask0GameGateway(pkg, kernel, bridge, json);
    serveTask0GameWire(evaluate, json,
      (body, offset, count) => fs.readSync(0, body, offset, count, null),
      (body, offset, count) => fs.writeSync(1, body, offset, count));
  } catch {
    // Private source bytes and decoder causes never enter diagnostics.
    process.stderr.write('AIPT_B007_TASK0_GAME_REJECTED\n');
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
