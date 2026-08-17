// Semantic projection validation (full-state projection contract).
//
// Schema validity alone is intentionally insufficient: a projection is also
// checked against the source state with the same stable AIPT_* rejection
// reasons the independent protocol-assets oracle uses. Missing or unknown
// visibility is rejected (AIPT_MISSING_VISIBILITY / AIPT_UNKNOWN_VISIBILITY
// from the shape validation), and hidden data is never treated as an
// ordinary optional field: a field authorized to the projection seat may not
// be omitted, and a field NOT authorized to the projection seat may not
// appear (AIPT_VISIBILITY_UNAUTHORIZED_FIELD).
//
// Iteration 4B hardening: both documents must first pass the lossless
// JSON-value gate (no undefined/function/cycle/unsafe-integer values reach
// the semantic comparison); the projection's fixture_id must equal the
// source state's fixture_id (AIPT_FIXTURE_IDENTITY_MISMATCH); and the known
// seat list is validated as identifiers with deterministic rejection of
// invalid entries and duplicates.
import { CONTRACT_DESCRIPTOR as D } from './contract/descriptor.ts';
import { failResult, issue, okResult, type ValidationIssue, type ValidationResult } from './errors.ts';
import { validateJsonValue } from './json-value.ts';
import type { Projection, State } from './types.ts';
import { validateProjectionShape, validateStateShape } from './validate.ts';

const IDENTIFIER_RE = new RegExp(D.identifier_pattern, 'u');

function jsonEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return false;
    return a.length === b.length && a.every((item, index) => jsonEqual(item, b[index]));
  }
  if (typeof a === 'object' && typeof b === 'object') {
    const keysA = Object.keys(a);
    const keysB = Object.keys(b);
    if (keysA.length !== keysB.length) return false;
    return keysA.every((key) =>
      Object.prototype.hasOwnProperty.call(b, key) && jsonEqual((a as Record<string, unknown>)[key], (b as Record<string, unknown>)[key]),
    );
  }
  return false;
}

// Validate the caller-supplied known-seat list: every entry must be a
// well-formed seat identifier, and duplicates are rejected deterministically
// at their later occurrence. Returns the trusted seat set plus any issues.
function checkKnownSeats(knownSeats: readonly string[], issues: ValidationIssue[]): Set<string> {
  const seatSet = new Set<string>();
  const seen = new Set<string>();
  knownSeats.forEach((seat, index) => {
    const seatPath = `$/known_seats/${index}`;
    if (typeof seat !== 'string' || !IDENTIFIER_RE.test(seat)) {
      issues.push(issue(seatPath, 'AIPT_INVALID_IDENTIFIER', `known seat must match ${D.identifier_pattern}, got ${typeof seat === 'string' ? JSON.stringify(seat) : typeof seat}`));
      return;
    }
    if (seen.has(seat)) {
      issues.push(issue(seatPath, 'AIPT_INVALID_VALUE', `duplicate known seat ${JSON.stringify(seat)}`));
    } else {
      seen.add(seat);
      seatSet.add(seat);
    }
  });
  return seatSet;
}

export function validateProjectionSemantics(state: unknown, projection: unknown, knownSeats: readonly string[]): ValidationResult {
  // Lossless JSON-value gates: state, projection, and the known-seat list
  // must all be faithfully representable before any semantic comparison
  // (no getter/setter is ever invoked on them).
  const stateLossy = validateJsonValue(state, '$');
  const projectionLossy = validateJsonValue(projection, '$');
  const seatsLossy = validateJsonValue(knownSeats, '$/known_seats');
  if (!stateLossy.valid || !projectionLossy.valid || !seatsLossy.valid) {
    return failResult([...stateLossy.issues, ...projectionLossy.issues, ...seatsLossy.issues]);
  }
  const stateCheck = validateStateShape(state, '$');
  const projectionCheck = validateProjectionShape(projection, '$');
  if (!stateCheck.valid || !projectionCheck.valid) {
    return failResult([...stateCheck.issues, ...projectionCheck.issues]);
  }
  const issues: ValidationIssue[] = [];
  const stateDoc = state as unknown as State;
  const projectionDoc = projection as unknown as Projection;
  const seatSet = checkKnownSeats([...knownSeats], issues);

  // Projection identity is bound to the source state: a projection that
  // belongs to a different fixture must never validate against this state.
  if (stateDoc.fixture_id !== projectionDoc.fixture_id) {
    issues.push(issue('$/fixture_id', 'AIPT_FIXTURE_IDENTITY_MISMATCH', `projection fixture_id ${JSON.stringify(projectionDoc.fixture_id)} must equal the source state fixture_id ${JSON.stringify(stateDoc.fixture_id)}`));
  }

  if (!seatSet.has(projectionDoc.seat_id)) {
    issues.push(issue('$/seat_id', 'AIPT_PROJECTION_UNKNOWN_SEAT', `projection seat ${JSON.stringify(projectionDoc.seat_id)} is not a known seat`));
  }

  // State metadata: unique field ids; visibility may only authorize known seats.
  const stateSeen = new Set<string>();
  for (const field of stateDoc.fields) {
    if (stateSeen.has(field.field_id)) {
      issues.push(issue('$/fields', 'AIPT_STATE_DUPLICATE_FIELD_ID', `duplicate field_id ${JSON.stringify(field.field_id)} in the source state`));
    } else {
      stateSeen.add(field.field_id);
    }
    for (const seat of field.visibility.authorized_seat_ids) {
      if (!seatSet.has(seat)) {
        issues.push(issue('$/fields', 'AIPT_VISIBILITY_UNKNOWN_SEAT', `state visibility authorizes unknown seat ${JSON.stringify(seat)}`));
      }
    }
  }

  const stateById = new Map(stateDoc.fields.map((field) => [field.field_id, field]));
  const projectedSeen = new Set<string>();
  for (const field of projectionDoc.fields) {
    const fieldPath = `$/fields/${field.field_id}`;
    if (projectedSeen.has(field.field_id)) {
      issues.push(issue(fieldPath, 'AIPT_PROJECTION_DUPLICATE_FIELD_ID', `duplicate field_id ${JSON.stringify(field.field_id)} in the projection`));
    } else {
      projectedSeen.add(field.field_id);
    }
    const source = stateById.get(field.field_id);
    if (source === undefined) {
      issues.push(issue(fieldPath, 'AIPT_PROJECTION_UNKNOWN_FIELD', `projected field ${JSON.stringify(field.field_id)} does not exist in the source state`));
      continue;
    }
    if (!jsonEqual(source.value, field.value)) {
      issues.push(issue(fieldPath, 'AIPT_PROJECTION_VALUE_DRIFT', `projected value of ${JSON.stringify(field.field_id)} drifted from the source state value`));
    }
    if (!jsonEqual(source.visibility.label, field.visibility.label)) {
      issues.push(issue(fieldPath, 'AIPT_VISIBILITY_RECLASSIFIED', `visibility label of ${JSON.stringify(field.field_id)} was reclassified in the projection`));
    }
    const sourceSeats = [...source.visibility.authorized_seat_ids].sort();
    const projectedSeats = [...field.visibility.authorized_seat_ids].sort();
    if (!jsonEqual(sourceSeats, projectedSeats)) {
      issues.push(issue(fieldPath, 'AIPT_VISIBILITY_AUTHORIZATION_DRIFT', `authorized_seat_ids of ${JSON.stringify(field.field_id)} drifted from the source state (compared as a mathematical set)`));
    }
    if (!field.visibility.authorized_seat_ids.includes(projectionDoc.seat_id)) {
      issues.push(issue(fieldPath, 'AIPT_VISIBILITY_UNAUTHORIZED_FIELD', `field ${JSON.stringify(field.field_id)} is not authorized for projection seat ${JSON.stringify(projectionDoc.seat_id)}`));
    }
  }
  for (const field of stateDoc.fields) {
    if (field.visibility.authorized_seat_ids.includes(projectionDoc.seat_id) && !projectedSeen.has(field.field_id)) {
      issues.push(issue('$', 'AIPT_PROJECTION_MISSING_AUTHORIZED_FIELD', `projection omits field ${JSON.stringify(field.field_id)} which is authorized for seat ${JSON.stringify(projectionDoc.seat_id)} (hidden data is not an ordinary optional field)`));
    }
  }
  return issues.length === 0 ? okResult() : failResult(issues);
}
