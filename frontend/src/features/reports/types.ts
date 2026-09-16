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

/** Templates needing a report to compare against. Generating one without it fails, and
 *  the form asks for it up front rather than letting the failure teach the lesson. */
export const NEEDS_COMPARISON = new Set(['trend']);

export function isDownloadable(report: Report): boolean {
  return report.status === 'ready';
}

/** The date a report speaks for — not the date it is being read. */
export function asOf(report: Report): string {
  const stamp = report.generated_at ?? report.created_at;
  return new Date(stamp).toLocaleString();
}
