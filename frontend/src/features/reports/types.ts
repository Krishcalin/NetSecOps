/** Report types, mirroring netsecops/schemas/reporting.py. */

export type ReportStatus = 'pending' | 'ready' | 'failed';

export interface ReportTemplate {
  id: string;
  title: string;
  audience: string;
  description: string;
  /** False for templates that are catalogued but cannot be assembled yet. The console
   *  shows them greyed rather than hiding them, so the shape of the feature is visible,
   *  and refuses to offer them rather than returning an empty document — an empty
   *  compliance report reads as a compliant estate. */
  implemented: boolean;
}

export interface Report {
  id: string;
  template: string;
  title: string;
  status: ReportStatus;
  scope_device_id: string | null;
  scope_group_id: string | null;
  compare_to_id: string | null;
  /** SHA-256 of the frozen content. Null until the report is ready. Travels with the
   *  downloaded file so a recipient can check the artefact they hold is the one that
   *  was generated. */
  content_hash: string | null;
  generated_at: string | null;
  expires_at: string | null;
  /** Past its retention date — and still here. Nothing deletes a report: an auditor
   *  cannot be told a background job removed March's evidence, so retention is
   *  reported and acted on by a person. */
  retention_expired: boolean;
  error_message: string | null;
  created_at: string;
}

export interface ReportDetail extends Report {
  parameters: Record<string, unknown>;
  /** Whatever was true at generation. Never recomputed, so a finding resolved since
   *  does not disappear from it. */
  content: Record<string, unknown>;
}

export interface PaginatedReports {
  data: Report[];
  meta: { total: number; limit: number; offset: number };
}

export type ReportFormat = 'json' | 'csv' | 'xlsx' | 'pdf';

/** Every format renders the same frozen content, so all four of one report carry one
 *  content hash — they are one report rendered differently, not four assessments. */
export const FORMATS: ReportFormat[] = ['pdf', 'xlsx', 'csv', 'json'];

/** Templates whose content is not a single table. CSV and XLSX are refused for these
 *  rather than emitting a blank grid, which reads as "no findings". */
export const NO_TABLE = new Set(['trend']);

export function formatsFor(report: Report): ReportFormat[] {
  return NO_TABLE.has(report.template) ? ['pdf', 'json'] : FORMATS;
}

/** What each template needs beyond its name. Asked for up front rather than letting a
 *  failed report teach the lesson. */
export const REQUIRED_PARAMETER: Record<string, 'device' | 'group' | 'comparison'> = {
  device_detail: 'device',
  firewall_rulebase: 'device',
  group_compliance: 'group',
  trend: 'comparison',
};

/** Templates that additionally need a framework named. A compliance report without one
 *  is just a list of checks. */
export const NEEDS_FRAMEWORK = new Set(['group_compliance']);

export function isDownloadable(report: Report): boolean {
  return report.status === 'ready';
}

/** The date a report speaks for — not the date it is being read. */
export function asOf(report: Report): string {
  const stamp = report.generated_at ?? report.created_at;
  return new Date(stamp).toLocaleString();
}
