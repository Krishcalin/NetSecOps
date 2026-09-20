/** The check library, policies and exceptions (FR-CHK-04 … FR-CHK-07).
 *
 * Mirrors `schemas/checks.py`, which serves all three from one router because they are
 * one subject: a check is the rule, a policy is which rules apply where, and an exception
 * is a rule deliberately not applied — with a reason and an end date.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Outcome = 'pass' | 'fail' | 'warning' | 'not_applicable' | 'not_evaluated' | 'error';

export interface CheckSummary {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  tags: string[];
  logic_type: string;
  vendors: string[];
  platforms: string[];
  /** framework → the control ids this check maps to. */
  frameworks: Record<string, string[]>;
  enabled_by_default: boolean;
  is_custom: boolean;
}

export interface CheckDetail extends CheckSummary {
  rationale: string;
  remediation: string;
  device_classes: string[];
  references: Record<string, unknown>;
  version: number;
  /** The JMESPath predicate, where the check is expressed as one. */
  expression: string | null;
}

/** The result of a dry run. Nothing behind this was written. */
export interface AssessmentPreview {
  check_id: string;
  outcome: Outcome;
  severity: Severity;
  message: string;
  reason: string | null;
  evidence: Record<string, unknown>;
}

export interface EstateQueryRow {
  device_id: string;
  hostname: string | null;
  platform: string | null;
  value: unknown;
  /** Why this device could not answer. Not a match, and not evidence of absence. */
  not_evaluated: string | null;
}

export interface EstateQueryResponse {
  expression: string;
  devices_considered: number;
  devices_not_evaluated: number;
  rows: EstateQueryRow[];
}

export interface Policy {
  id: string;
  name: string;
  description: string | null;
  /** `builtin` or `custom` — where the policy came from. */
  source: string;
  version: number;
  enabled: boolean;
  is_default: boolean;
  frameworks: string[];
  created_at: string;
}

export interface PolicyCheck {
  check_id: string;
  enabled: boolean;
  severity_override: string | null;
  notes: string | null;
}

export interface PolicyDetail extends Policy {
  entries: PolicyCheck[];
}

export type ExceptionScope = 'device' | 'group' | 'global';

export interface Exception {
  id: string;
  check_id: string;
  scope: ExceptionScope;
  device_id: string | null;
  device_group_id: string | null;
  justification: string;
  approver: string | null;
  /** Never null. An exception without an end date is a silently deleted check. */
  expires_at: string;
  status: string;
  created_at: string;
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const OUTCOME_LABELS: Record<Outcome, string> = {
  pass: 'Passed',
  fail: 'Failed',
  warning: 'Warning',
  not_applicable: 'Not applicable',
  not_evaluated: 'Not evaluated',
  error: 'Error',
};
