// Validation issue/result types and the protocol validation error.
//
// Every fail-closed rejection is path-addressed: the issue carries the JSON
// pointer-style path of the offending value, a stable AIPT error code, and a
// deterministic human-readable message. No partially trusted value is ever
// returned from a failed validation.
import type { AiptErrorCode } from './types.ts';

export interface ValidationIssue {
  readonly path: string;
  readonly code: AiptErrorCode;
  readonly message: string;
}

export interface ValidationResult {
  readonly valid: boolean;
  readonly issues: readonly ValidationIssue[];
}

export function issue(path: string, code: AiptErrorCode, message: string): ValidationIssue {
  return { path, code, message };
}

export function okResult(): ValidationResult {
  return { valid: true, issues: [] };
}

export function failResult(issues: readonly ValidationIssue[]): ValidationResult {
  return { valid: false, issues };
}

export class ProtocolValidationError extends Error {
  readonly issues: readonly ValidationIssue[];

  constructor(message: string, issues: readonly ValidationIssue[]) {
    super(message);
    this.issues = issues;
  }
}
