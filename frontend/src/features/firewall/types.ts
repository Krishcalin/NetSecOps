/** Rulebase viewer types (FR-FW-06, FR-FW-07).
 *
 * Mirrors `netsecops/schemas/firewall.py`. Two fields are worth calling out because
 * getting them wrong in the UI would be worse than not showing them:
 *
 * `logs` is `boolean | null`, and `null` means the parser could not tell. Rendering
 * that as "no" sends someone to enable logging on a rule that already has it.
 *
 * `exposure_analysed` being false means no exposure conclusion was drawn at all —
 * which is not the same as no exposure found, and must not be shown as a clean result.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'none';

export interface RuleIssue {
  issue: string;
  severity: Severity;
  message: string;
  related_rule_order: number | null;
  related_rule_name: string | null;
}

export interface Rule {
  order: number;
  name: string;
  enabled: boolean;
  action: string;
  /** The resolved verdict. Vendors spell denial four ways and Check Point has an
   *  action that is neither, so this is sent rather than inferred from `action`. */
  permits: boolean;
  src_zones: string[];
  dst_zones: string[];
  source: string;
  destination: string;
  services: string;
  source_objects: string[];
  destination_objects: string[];
  service_objects: string[];
  applications: string[];
  users: string[];
  /** null means "not determined", never "no". */
  logs: boolean | null;
  has_profiles: boolean;
  profiles: Record<string, string>;
  schedule: string | null;
  hit_count: number | null;
  last_hit: string | null;
  unresolved: string[];
  source_size: number;
  destination_size: number;
  issues: RuleIssue[];
}

export interface HygieneFinding {
  issue: string;
  severity: Severity;
  name: string;
  message: string;
}

export interface NatRule {
  order: number;
  name: string;
  original: string | null;
  translated: string | null;
  service: string | null;
  direction: string | null;
  issues: RuleIssue[];
}

export interface RulebaseSummary {
  rules_total: number;
  rules_enabled: number;
  rules_analysed: number;
  relationships: Record<string, number>;
  policy_issues: Record<string, number>;
  hygiene_issues: Record<string, number>;
  nat_issues: Record<string, number>;
  analysis_ms: number;
  truncated: boolean;
  exposure_analysed: boolean;
  limitations: string[];
}

export interface Rulebase {
  device_id: string;
  snapshot_id: string;
  platform: string | null;
  zones: string[];
  summary: RulebaseSummary;
  rules: Rule[];
  nat_rules: NatRule[];
  hygiene: HygieneFinding[];
  /** Before filtering, so the UI can say "12 of 5,000". */
  total: number;
}

export interface RuleQueryRequest {
  source: string;
  destination: string;
  protocol: string;
  port: number;
  src_zone?: string | null;
  dst_zone?: string | null;
}

export interface RuleQueryResponse {
  matched: Rule | null;
  also_matched: Rule[];
  limitations: string[];
}

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** The worst severity among a rule's issues, for the row's highlight. */
export function worstSeverity(rule: Rule): Severity {
  const found = new Set(rule.issues.map((i) => i.severity));
  return SEVERITY_ORDER.find((s) => found.has(s)) ?? 'none';
}

/** Human wording for an issue key, so the UI does not show `any_any_any`. */
export const ISSUE_LABELS: Record<string, string> = {
  shadowed: 'Shadowed',
  shadowed_cause: 'Shadows another rule',
  redundant: 'Redundant',
  redundant_cause: 'Makes another rule redundant',
  correlated: 'Order-dependent',
  correlated_cause: 'Order-dependent',
  generalisation: 'Broader than an earlier rule',
  generalisation_cause: 'Narrower exception',
  any_any_any: 'Permits any to any on any service',
  broad_source: 'Broad source',
  broad_destination: 'Broad destination',
  broad_service: 'Broad service',
  no_logging: 'No logging',
  no_profiles: 'No security profile',
  disabled: 'Disabled',
  no_recent_hits: 'No recent hits',
  never_hit: 'Never hit',
  expired_schedule: 'Expired schedule',
  insecure_service: 'Insecure service',
  unresolved_objects: 'Unresolved objects',
  duplicate_object: 'Duplicate object',
  unused_object: 'Unused object',
  nesting_depth: 'Deeply nested group',
  exposed_service: 'Published to an untrusted zone',
  exposed_insecure_service: 'Insecure service published',
  exposed_without_logging: 'Published without logging',
  exposed_without_inspection: 'Published without inspection',
  unmatched_nat: 'NAT with no matching permit',
  nat_without_translation: 'NAT translation unresolved',
};

export function issueLabel(issue: string): string {
  return ISSUE_LABELS[issue] ?? issue.replace(/_/g, ' ');
}

/** How a rule's logging state reads. Three states, never two. */
export function loggingLabel(logs: boolean | null): string {
  if (logs === null) return 'unknown';
  return logs ? 'logged' : 'not logged';
}
