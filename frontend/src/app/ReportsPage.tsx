/** The report archive (FR-RPT-02, FR-RPT-03).
 *
 * This page is deliberately not a dashboard. Every other page in the console answers
 * "what is true now"; this one answers "what did we know then", and the difference has
 * to survive contact with a user who expects a refresh button.
 *
 * Three things the design has to carry:
 *
 * **A row is dated evidence, not a saved filter.** Each report is stamped with the
 * moment it speaks for and a hash of exactly what it said. Re-reading a March report in
 * September returns March's numbers, including findings that have since been fixed —
 * that is the feature, not staleness, so the page says "as of" rather than "updated".
 *
 * **Templates that cannot be assembled are shown, disabled, with the reason.** Hiding
 * them would make the feature look smaller than it is; offering them would produce an
 * empty document, and an empty compliance report reads as a compliant estate.
 *
 * **Downloading is a separate act from generating**, and the server audits it that way,
 * because downloading is what puts the artefact outside the product. The filename comes
 * from the server's Content-Disposition rather than being rebuilt here: the date in the
 * name is the point, and two places deciding it is one place too many.
 */

import { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';

import { ApiError, api, request } from '../api/client';
import type {
  PaginatedReports,
  Report,
  ReportDetail,
  ReportTemplate,
} from '../features/reports/types';
import type { ReportFormat } from '../features/reports/types';
import {
  NEEDS_FRAMEWORK,
  REQUIRED_PARAMETER,
  asOf,
  formatsFor,
  isDownloadable,
} from '../features/reports/types';

const PAGE_SIZE = 25;

interface Paginated<T> {
  data: T[];
  meta: { total: number };
}

interface DeviceOption {
  id: string;
  hostname: string | null;
  mgmt_ip: string;
}

interface GroupOption {
  id: string;
  name: string;
}

interface FrameworkOption {
  key: string;
  checks: number;
}

function StatusPill({ report }: { report: Report }) {
  if (report.status === 'ready') {
    return <span className="pill pill--low">ready</span>;
  }
  if (report.status === 'failed') {
    return <span className="pill pill--high">failed</span>;
  }
  // Not "empty" and not "clean": a pending report has not finished assembling, and
  // presenting it as a result would be presenting a half-written document as evidence.
  return <span className="pill pill--medium">assembling</span>;
}

function TemplatePicker({
  templates,
  value,
  onChange,
}: {
  templates: ReportTemplate[];
  value: string;
  onChange: (id: string) => void;
}) {
  return (
    <select
      className="field__input field__input--small"
      value={value}
      onChange={(event) => onChange(event.target.value)}
      aria-label="Report template"
    >
      {templates.map((template) => (
        <option key={template.id} value={template.id} disabled={!template.implemented}>
          {template.title}
          {template.implemented ? '' : ' — not available yet'}
        </option>
      ))}
    </select>
  );
}

function GeneratePanel({ templates, reports }: { templates: ReportTemplate[]; reports: Report[] }) {
  const queryClient = useQueryClient();
  const available = templates.filter((t) => t.implemented);
  const [templateId, setTemplateId] = useState(available[0]?.id ?? '');
  const [title, setTitle] = useState('');
  const [compareTo, setCompareTo] = useState('');
  const [deviceId, setDeviceId] = useState('');
  const [groupId, setGroupId] = useState('');
  const [framework, setFramework] = useState('');
  const [error, setError] = useState<string | null>(null);

  const selected = templates.find((t) => t.id === templateId);
  const requires = REQUIRED_PARAMETER[templateId];
  const needsFramework = NEEDS_FRAMEWORK.has(templateId);
  const comparable = reports.filter(isDownloadable);

  // Only fetched when a template actually asks for them, so opening the page does not
  // pull the whole inventory to populate a picker nobody is going to see.
  const devices = useQuery({
    queryKey: ['report-devices'],
    queryFn: () => api.get<Paginated<DeviceOption>>('/devices?limit=500'),
    enabled: requires === 'device',
    staleTime: 60_000,
  });
  const groups = useQuery({
    queryKey: ['report-groups'],
    queryFn: () => api.get<GroupOption[]>('/device-groups'),
    enabled: requires === 'group',
    staleTime: 60_000,
  });
  const frameworks = useQuery({
    queryKey: ['frameworks'],
    queryFn: () => api.get<FrameworkOption[]>('/compliance/frameworks'),
    enabled: needsFramework,
    staleTime: Infinity,
  });

  const missing =
    (requires === 'device' && !deviceId) ||
    (requires === 'group' && !groupId) ||
    (requires === 'comparison' && !compareTo) ||
    (needsFramework && !framework);

  const generate = useMutation({
    mutationFn: () =>
      api.post<ReportDetail>('/reports', {
        template: templateId,
        title: title || null,
        compare_to_id: compareTo || null,
        scope_device_id: deviceId || null,
        scope_group_id: groupId || null,
        framework: framework || null,
      }),
    onSuccess: () => {
      setError(null);
      setTitle('');
      void queryClient.invalidateQueries({ queryKey: ['reports'] });
    },
    onError: (err) =>
      setError(err instanceof ApiError ? err.problem.detail : 'The report could not be generated.'),
  });

  function pickTemplate(id: string) {
    setTemplateId(id);
    // Cleared on switch: carrying a device id into a group report would send a scope
    // the new template cannot use, and the server would reject something the operator
    // never chose.
    setCompareTo('');
    setDeviceId('');
    setGroupId('');
    setFramework('');
    setError(null);
  }

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">Generate a report</h2>
      </div>

      <div className="toolbar">
        <TemplatePicker templates={templates} value={templateId} onChange={pickTemplate} />

        <input
          className="field__input field__input--small"
          value={title}
          onChange={(event) => setTitle(event.target.value)}
          placeholder="Title (optional)"
          aria-label="Report title"
          maxLength={300}
        />

        {requires === 'device' && (
          <select
            className="field__input field__input--small"
            value={deviceId}
            onChange={(event) => setDeviceId(event.target.value)}
            aria-label="Device"
          >
            <option value="">Choose a device…</option>
            {(devices.data?.data ?? []).map((device) => (
              <option key={device.id} value={device.id}>
                {device.hostname ?? device.mgmt_ip}
              </option>
            ))}
          </select>
        )}

        {requires === 'group' && (
          <select
            className="field__input field__input--small"
            value={groupId}
            onChange={(event) => setGroupId(event.target.value)}
            aria-label="Device group"
          >
            <option value="">Choose a group…</option>
            {(groups.data ?? []).map((group) => (
              <option key={group.id} value={group.id}>
                {group.name}
              </option>
            ))}
          </select>
        )}

        {needsFramework && (
          <select
            className="field__input field__input--small"
            value={framework}
            onChange={(event) => setFramework(event.target.value)}
            aria-label="Framework"
          >
            <option value="">Choose a framework…</option>
            {(frameworks.data ?? []).map((entry) => (
              <option key={entry.key} value={entry.key}>
                {/* The mapped-check count is shown, not hidden: 13 checks and 103
                    support very different claims about the same framework. */}
                {entry.key} ({entry.checks} checks)
              </option>
            ))}
          </select>
        )}

        {requires === 'comparison' && (
          <select
            className="field__input field__input--small"
            value={compareTo}
            onChange={(event) => setCompareTo(event.target.value)}
            aria-label="Report to compare against"
          >
            <option value="">Compare against…</option>
            {comparable.map((report) => (
              <option key={report.id} value={report.id}>
                {report.title} — {asOf(report)}
              </option>
            ))}
          </select>
        )}

        <button
          className="button button--primary button--small"
          onClick={() => generate.mutate()}
          disabled={!templateId || missing || generate.isPending}
        >
          {generate.isPending ? 'Generating…' : 'Generate'}
        </button>
      </div>

      {selected && (
        <p className="finding__note">
          <strong>{selected.audience}.</strong> {selected.description}
        </p>
      )}

      {requires === 'device' && (
        <p className="finding__note">
          This report is about one device, and will not fall back to the estate. A device-detail
          report over everything would answer a different question under the same title.
        </p>
      )}

      {requires === 'comparison' && comparable.length === 0 && (
        <div className="alert alert--warning" role="note">
          A trend report compares this moment against an earlier one, and reads the earlier
          report&rsquo;s stored content rather than recomputing it. There is no finished report to
          compare against yet — generate an executive summary first, and the comparison becomes
          available once it exists.
        </div>
      )}

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}
    </section>
  );
}

function ContentPanel({ reportId, onClose }: { reportId: string; onClose: () => void }) {
  const detail = useQuery({
    queryKey: ['report', reportId],
    queryFn: () => api.get<ReportDetail>(`/reports/${reportId}`),
    // An archived report cannot change, so there is nothing to refetch for.
    staleTime: Infinity,
  });

  if (detail.isLoading) return <p className="page-loading">Loading…</p>;
  if (!detail.data) return null;

  const report = detail.data;

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">{report.title}</h2>
        <button className="button button--ghost button--small" onClick={onClose}>
          Close
        </button>
      </div>

      <div className="finding__meta">
        <span>As of {asOf(report)}</span>
        <span>{report.template.replace(/_/g, ' ')}</span>
        <StatusPill report={report} />
      </div>

      {report.status === 'failed' ? (
        <div className="alert alert--error" role="alert">
          {report.error_message ?? 'This report failed to assemble, and did not record why.'}
        </div>
      ) : (
        <>
          <p className="finding__note">
            This is what the estate looked like at the time above. It is not recalculated — a
            finding resolved since does not disappear from it, which is what makes it usable as
            evidence.
          </p>

          {report.content_hash && (
            <p className="mono muted">
              sha256 {report.content_hash}
              <br />
              <span className="muted">
                The same hash travels inside the downloaded file, so a recipient can check the
                artefact they hold is the one that was generated.
              </span>
            </p>
          )}

          <h3 className="finding__heading">Content</h3>
          <pre className="evidence__lines mono">{JSON.stringify(report.content, null, 2)}</pre>
        </>
      )}
    </section>
  );
}

export function ReportsPage() {
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const templates = useQuery({
    queryKey: ['report-templates'],
    queryFn: () => api.get<ReportTemplate[]>('/reports/templates'),
    staleTime: Infinity,
  });

  const list = useQuery({
    queryKey: ['reports', offset],
    queryFn: () => api.get<PaginatedReports>(`/reports?limit=${PAGE_SIZE}&offset=${offset}`),
  });

  const rows = list.data?.data ?? [];
  const total = list.data?.meta.total ?? 0;

  const unavailable = useMemo(
    () => (templates.data ?? []).filter((t) => !t.implemented),
    [templates.data],
  );

  async function download(report: Report, format: ReportFormat) {
    setDownloading(`${report.id}:${format}`);
    setDownloadError(null);
    try {
      const response = await request<Response>(`/reports/${report.id}/download?format=${format}`, {
        method: 'GET',
        parseAs: 'response',
      });
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = filenameFrom(response) ?? `netsecops-report.${format}`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setDownloadError(
        err instanceof ApiError ? err.problem.detail : 'The download could not be completed.',
      );
    } finally {
      setDownloading(null);
    }
  }

  return (
    <div className="page">
      <header className="page__header">
        <h1>Reports</h1>
        <p className="page__subtitle">
          Dated evidence, not a live view. Each report is frozen at the moment it was generated and
          is never recalculated, so it can still answer &ldquo;what did you know on 31 March&rdquo;
          in September.
        </p>
      </header>

      {templates.data && <GeneratePanel templates={templates.data} reports={rows} />}

      {/* Empty today — every catalogued template assembles. Kept because the gate is
          what stops a future template being offered before it can produce anything,
          and an empty compliance report reads like a compliant estate. */}
      {unavailable.length > 0 && (
        <div className="alert alert--info" role="note">
          {unavailable.length} further template{unavailable.length === 1 ? '' : 's'} (
          {unavailable.map((t) => t.title).join(', ')}) {unavailable.length === 1 ? 'is' : 'are'}{' '}
          catalogued but cannot be assembled yet. They are refused rather than returned empty,
          because an empty compliance report reads like a compliant estate.
        </div>
      )}

      {downloadError && (
        <div className="alert alert--error" role="alert">
          {downloadError}
        </div>
      )}

      <section className="card">
        <div className="card__header">
          <h2 className="card__title">Archive</h2>
          <span className="muted">
            {total} report{total === 1 ? '' : 's'}
          </span>
        </div>

        {rows.length === 0 ? (
          <p className="empty">
            No reports yet. Generating one records the estate as it is now; it will keep saying that
            whatever changes later.
          </p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th scope="col">As of</th>
                <th scope="col">Report</th>
                <th scope="col">Template</th>
                <th scope="col">Status</th>
                <th scope="col">Content hash</th>
                <th scope="col">Download</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((report) => (
                <tr key={report.id}>
                  <td>{asOf(report)}</td>
                  <td>
                    <button
                      className="button button--ghost button--small"
                      onClick={() => setSelected(selected === report.id ? null : report.id)}
                    >
                      {report.title}
                    </button>
                    {report.status === 'failed' && report.error_message && (
                      <div className="muted">{report.error_message}</div>
                    )}
                  </td>
                  <td className="muted">{report.template.replace(/_/g, ' ')}</td>
                  <td>
                    <StatusPill report={report} />
                    {report.retention_expired && (
                      <span
                        className="pill pill--medium"
                        title="Past its retention date. Nothing deletes a report — an auditor cannot be told a background job removed the evidence."
                      >
                        retention expired
                      </span>
                    )}
                  </td>
                  <td className="mono muted">
                    {report.content_hash ? report.content_hash.slice(0, 12) : '—'}
                  </td>
                  <td>
                    {isDownloadable(report) ? (
                      // Only the formats this template can honestly produce. A trend
                      // report has no single table, and a blank spreadsheet would read
                      // as "no findings".
                      formatsFor(report).map((format) => (
                        <button
                          key={format}
                          className="button button--ghost button--small"
                          onClick={() => void download(report, format)}
                          disabled={downloading === `${report.id}:${format}`}
                        >
                          {format.toUpperCase()}
                        </button>
                      ))
                    ) : (
                      // Never offered for an incomplete report: a partial artefact outside
                      // the product would read as a finished assessment.
                      <span className="muted">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {total > PAGE_SIZE && (
          <div className="pager">
            <button
              className="button button--ghost button--small"
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              disabled={offset === 0}
            >
              Previous
            </button>
            <span className="pager__status">
              {offset + 1}–{Math.min(offset + PAGE_SIZE, total)} of {total.toLocaleString()}
            </span>
            <button
              className="button button--ghost button--small"
              onClick={() => setOffset(offset + PAGE_SIZE)}
              disabled={offset + PAGE_SIZE >= total}
            >
              Next
            </button>
          </div>
        )}
      </section>

      {selected && <ContentPanel reportId={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

/** Take the filename the server chose rather than rebuilding it here.
 *
 * The server puts the report's date in the name because these files get mailed and
 * filed, and `report.csv` in a downloads folder six months later is evidence nobody can
 * place. Deciding that in two places is one place too many.
 */
function filenameFrom(response: Response): string | null {
  const header = response.headers.get('Content-Disposition');
  const match = header?.match(/filename="([^"]+)"/);
  return match?.[1] ?? null;
}
