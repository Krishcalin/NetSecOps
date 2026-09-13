/** Check, finding and policy types, mirroring netsecops/schemas/checks.py. */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Outcome =
  | 'pass'
  | 'fail'
  | 'warning'
  | 'not_applicable'
  | 'not_evaluated'
  | 'error';

export type FindingStatus =
  | 'new'
  | 'open'
  | 'reopened'
  | 'resolved'
  | 'risk_accepted'
  | 'false_positive';

export interface EvidenceLine {
  path: string;
  line_start: number | null;
  line_end: number | null;
  excerpt: string | null;
  command: string | null;
}

export interface Evidence {
  observed: unknown;
  expected: string | null;
  lines: EvidenceLine[];
}

export interface Finding {
  id: string;
  device_id: string;
  kind: string;
  check_id: string | null;
  cve_id: string | null;
  title: string;
  description: string | null;
  severity: Severity;
  status: FindingStatus;
  first_seen_at: string | null;
  last_seen_at: string | null;
  resolved_at: string | null;
  occurrences: number;
  assignee_id: string | null;
  due_at: string | null;
  created_at: string;
}

export interface FindingDetail extends Finding {
  evidence: Evidence;
  remediation: string | null;
  snapshot_id: string | null;
  /** Why the check matters. The first question anyone asks of a failure. */
  rationale: string | null;
  references: Record<string, string[]>;
}

export interface CheckSummary {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  tags: string[];
  logic_type: 'ncm' | 'regex' | 'python';
  vendors: string[];
  platforms: string[];
  frameworks: Record<string, string[]>;
  enabled_by_default: boolean;
  is_custom: boolean;
}

export interface CheckResult {
  id: string;
  device_id: string;
  snapshot_id: string | null;
  check_id: string;
  check_version: number;
  outcome: Outcome;
  severity: Severity;
  message: string;
  reason: string | null;
  evidence: Evidence;
  duration_ms: number;
  suppressed_by_id: string | null;
  created_at: string;
}

export interface Policy {
  id: string;
  name: string;
  description: string | null;
  source: string;
  version: number;
  enabled: boolean;
  is_default: boolean;
  frameworks: string[];
  created_at: string;
}

export interface Risk {
  device_id: string;
  score: number | null;
  /** Passes as a share of what was decided. Not Applicable and Not Evaluated are in
   *  neither half — counting them as passes would reward a failed collection. */
  compliance_percent: number | null;
  /** How much of the policy produced a verdict at all. */
  coverage_percent: number | null;
  checks_evaluated: number;
  checks_passed: number;
  checks_failed: number;
  checks_not_evaluated: number;
  components: Record<string, unknown>;
  assessed_at: string | null;
}

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export const STATUS_LABELS: Record<FindingStatus, string> = {
  new: 'New',
  open: 'Open',
  reopened: 'Reopened',
  resolved: 'Resolved',
  risk_accepted: 'Risk accepted',
  false_positive: 'False positive',
};

export const OUTCOME_LABELS: Record<Outcome, string> = {
  pass: 'Pass',
  fail: 'Fail',
  warning: 'Warning',
  not_applicable: 'Not applicable',
  not_evaluated: 'Not evaluated',
  error: 'Error',
};

/** Statuses an operator may set. `resolved` is deliberately absent: a finding is
 *  resolved by its check passing on a later assessment, never by hand. */
export const SETTABLE_STATUSES: FindingStatus[] = [
  'open',
  'risk_accepted',
  'false_positive',
];
