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
import { failResult, issue, okResult, type ValidationIssue, type ValidationResult } from './errors.ts';
import type { Projection, State } from './types.ts';
import { validateProjectionShape, validateStateShape } from './validate.ts';

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

export function validateProjectionSemantics(state: unknown, projection: unknown, knownSeats: readonly string[]): ValidationResult {
  const stateCheck = validateStateShape(state, '$');
  const projectionCheck = validateProjectionShape(projection, '$');
  if (!stateCheck.valid || !projectionCheck.valid) {
    return failResult([...stateCheck.issues, ...projectionCheck.issues]);
  }
  const issues: ValidationIssue[] = [];
  const stateDoc = state as unknown as State;
  const projectionDoc = projection as unknown as Projection;
  const seatSet = new Set(knownSeats);

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
