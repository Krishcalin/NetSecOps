/** Vulnerability list, CVE detail and feed status (FR-VUL-04, FR-VUL-07).
 *
 * The page's whole job is to carry three distinctions the matcher went to trouble to
 * preserve, each of which disappears the moment a UI renders a null as a zero:
 *
 * 1. **Not Evaluated is not clear.** A device whose version could not be read is
 *    neither affected nor safe. The CVE panel gives those devices their own section
 *    under their own heading, rather than leaving them out — which would read as
 *    "not affected".
 * 2. **KEV null is not KEV false.** "Not in KEV" and "KEV not checked" are different
 *    sentences, and the second one is an instruction to import the catalogue.
 * 3. **Assessed-and-clean is not never-assessed.** The summary strip states the
 *    unassessed count next to the findings count, because an empty table is otherwise
 *    the best possible news and the worst possible news at the same time.
 */

import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { NavLink } from 'react-router-dom';

import { api, request } from '../api/client';
import { useAuth } from '../features/auth/useAuth';
import type {
  CveDetail,
  FeedStatus,
  Vulnerability,
  VulnerabilitySummary,
} from '../features/vulnerabilities/types';
import {
  CONFIDENCE_LABELS,
  CONFIDENCE_MEANINGS,
  formatEpss,
  kevLabel,
} from '../features/vulnerabilities/types';
import type { Paginated } from '../features/inventory/types';

const PAGE_SIZE = 25;
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

/** What `POST /vulnerabilities/feeds/import` reports back (FR-VUL-08).
 *
 * `records_rejected` is shown alongside the successes rather than hidden on a good
 * result: a bundle that loaded ninety per cent of its advisories has left a tenth of the
 * estate unjudged, and an import that only reports what worked reads as complete.
 */
interface FeedImportResult {
  feed: string;
  kind: string;
  status: string;
  advisories_ingested: number;
  cves_ingested: number;
  eol_records_ingested: number;
  kev_entries_ingested: number;
  epss_scores_ingested: number;
  records_rejected: number;
}

function KevBadge({ kev }: { kev: boolean | null }) {
  if (kev === true) {
    return (
      <span className="pill pill--critical" title="Listed in the CISA Known Exploited catalogue">
        KEV
      </span>
    );
  }
  if (kev === false) {
    return <span className="pill pill--info">Not in KEV</span>;
  }
  // The state that must not look like the one above it.
  return (
    <span
      className="pill pill--unknown"
      title="The KEV catalogue has not been imported, so this has never been checked."
    >
      Unchecked
    </span>
  );
}

function ConfidenceBadge({ confidence }: { confidence: Vulnerability['confidence'] }) {
  if (!confidence) return <span className="pill pill--unknown">Unknown</span>;
  return (
    <span className={`pill pill--${confidence}`} title={CONFIDENCE_MEANINGS[confidence]}>
      {CONFIDENCE_LABELS[confidence]}
    </span>
  );
}

function SummaryStrip({ summary }: { summary: VulnerabilitySummary }) {
  return (
    <div className="summary-strip">
      <div className="summary-stat">
        <span className="summary-stat__value">{summary.total.toLocaleString()}</span>
        <span className="summary-stat__label">open vulnerability findings</span>
      </div>
      <div className="summary-stat">
        <span className="summary-stat__value">{summary.kev_count.toLocaleString()}</span>
        <span className="summary-stat__label">known exploited</span>
      </div>
      <div className="summary-stat">
        <span className="summary-stat__value">{summary.devices_affected.toLocaleString()}</span>
        <span className="summary-stat__label">devices affected</span>
      </div>
      {/* Deliberately beside the others rather than in a footnote: an empty table with a
          non-zero count here is not good news. */}
      <div
        className={
          summary.devices_unassessed > 0 ? 'summary-stat summary-stat--warn' : 'summary-stat'
        }
      >
        <span className="summary-stat__value">{summary.devices_unassessed.toLocaleString()}</span>
        <span className="summary-stat__label">devices never assessed</span>
      </div>
    </div>
  );
}

/** Load a bundle, or fetch from the publishers.
 *
 * The offline import is first and the sync second, matching FR-VUL-08 and C-7: an
 * air-gapped deployment has only the former, and `feeds_offline_mode` refuses the latter.
 *
 * The bundle's format is detected from its contents, so this asks for a label rather
 * than a type. Vendor and product are shown as optional because they are needed only for
 * an end-of-life bundle — the API refuses that case with an explanation rather than
 * guessing whose lifecycle dates it is holding, and inventing a format sniffer here to
 * pre-empt it would be a second, worse copy of that judgement.
 */
function FeedControls({ onDone }: { onDone: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [feed, setFeed] = useState('manual');
  const [sha256, setSha256] = useState('');
  const [vendor, setVendor] = useState('');
  const [product, setProduct] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const settled = (message: string) => {
    setError(null);
    setNote(message);
    onDone();
  };

  const failed = (err: unknown, fallback: string) =>
    setError(err instanceof Error ? err.message : fallback);

  const importBundle = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error('Choose a bundle first.');
      const form = new FormData();
      form.append('file', file);

      const params = new URLSearchParams({ feed: feed.trim() || 'manual' });
      if (sha256.trim()) params.set('expected_sha256', sha256.trim());
      if (vendor.trim()) params.set('vendor', vendor.trim());
      if (product.trim()) params.set('product', product.trim());

      return request<FeedImportResult>(`/vulnerabilities/feeds/import?${params}`, {
        method: 'POST',
        body: form,
        rawBody: true,
      });
    },
    onSuccess: (result) => {
      setFile(null);
      settled(
        `Imported ${result.advisories_ingested.toLocaleString()} advisories, ` +
          `${result.cves_ingested.toLocaleString()} CVEs, ` +
          `${result.eol_records_ingested.toLocaleString()} end-of-life records. ` +
          `${result.records_rejected.toLocaleString()} records could not be read.`,
      );
    },
    onError: (err) => failed(err, 'The import failed. Nothing was written.'),
  });

  const sync = useMutation({
    mutationFn: () => api.post<{ id: string }>('/vulnerabilities/feeds/sync'),
    onSuccess: () => settled('A sync has been queued. Its progress is on the Assessments page.'),
    onError: (err) => failed(err, 'The sync could not be queued.'),
  });

  return (
    <div className="card">
      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}
      {note && (
        <div className="alert" role="status">
          {note}
        </div>
      )}

      <div className="form-grid">
        <label className="field">
          <span className="field__label">Bundle</span>
          <input
            className="field__input"
            type="file"
            aria-label="Feed bundle"
            onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          />
          <span className="field__help">NVD, CSAF, endoflife.date, CISA KEV or FIRST EPSS.</span>
        </label>
        <label className="field">
          <span className="field__label">Source label</span>
          <input
            className="field__input"
            value={feed}
            aria-label="Source label"
            onChange={(event) => setFeed(event.target.value)}
          />
          <span className="field__help">Recorded against every advisory the bundle carries.</span>
        </label>
        <label className="field">
          <span className="field__label">Expected SHA-256</span>
          <input
            className="field__input"
            value={sha256}
            aria-label="Expected SHA-256"
            onChange={(event) => setSha256(event.target.value)}
          />
          <span className="field__help">
            Optional. Checked before anything is written; a mismatch imports nothing.
          </span>
        </label>
        <label className="field">
          <span className="field__label">Vendor</span>
          <input
            className="field__input"
            value={vendor}
            aria-label="Vendor"
            onChange={(event) => setVendor(event.target.value)}
          />
          <span className="field__help">End-of-life bundles only.</span>
        </label>
        <label className="field">
          <span className="field__label">Product</span>
          <input
            className="field__input"
            value={product}
            aria-label="Product"
            onChange={(event) => setProduct(event.target.value)}
          />
          <span className="field__help">End-of-life bundles only.</span>
        </label>
      </div>

      <div className="toolbar">
        <button
          className="button button--small"
          disabled={!file || importBundle.isPending}
          onClick={() => importBundle.mutate()}
        >
          Import bundle
        </button>
        <button
          className="button button--ghost button--small"
          disabled={sync.isPending}
          onClick={() => sync.mutate()}
          title="Fetches from CISA, FIRST and NVD. Refused in offline mode."
        >
          Sync from publishers
        </button>
      </div>
    </div>
  );
}

function FeedPanel() {
  const { can } = useAuth();
  const queryClient = useQueryClient();
  const feeds = useQuery({
    queryKey: ['vuln-feeds'],
    queryFn: () => api.get<FeedStatus[]>('/vulnerabilities/feeds?limit=10'),
  });

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['vuln-feeds'] });
    void queryClient.invalidateQueries({ queryKey: ['vuln-summary'] });
  };

  const controls = can('vuln:write') ? <FeedControls onDone={refresh} /> : null;

  if (feeds.isLoading) return <p className="page-loading">Loading…</p>;

  const rows = feeds.data ?? [];

  if (rows.length === 0) {
    return (
      <>
        <p className="empty">
          No feed has ever been imported. Until one is, every device reports no vulnerabilities
          because nothing has been compared against it — which is not the same as being clear.
          Import an NVD, CSAF or end-of-life bundle to begin, and a CISA KEV catalogue to make the
          known-exploited filter mean anything.
        </p>
        {controls}
      </>
    );
  }

  return (
    <>
      {controls}
      {renderFeedTable(rows)}
    </>
  );
}

function renderFeedTable(rows: FeedStatus[]) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Feed</th>
            <th>Status</th>
            <th>Advisories</th>
            <th>CVEs</th>
            <th>EoL records</th>
            <th>KEV / EPSS</th>
            <th>Rejected</th>
            <th>When</th>
            {/* The feed's own stamp, beside the import time. A sync that ran an hour ago
                against a year-old catalogue is fresh and stale at once, and the import
                time alone reports only the reassuring half. */}
            <th>Data dated</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={`${row.feed}-${row.started_at}`}>
              <td className="mono">{row.feed}</td>
              <td>
                {/* "partial" is its own state, not a shade of success: some records
                    could not be read, and the estate is judged on what loaded. */}
                <span
                  className={
                    row.status === 'succeeded'
                      ? 'pill pill--low'
                      : row.status === 'partial'
                        ? 'pill pill--medium'
                        : 'pill pill--critical'
                  }
                >
                  {row.status}
                </span>
              </td>
              <td>{row.advisories_ingested.toLocaleString()}</td>
              <td>{row.cves_ingested.toLocaleString()}</td>
              <td>{row.eol_records_ingested.toLocaleString()}</td>
              <td>
                {row.kev_entries_ingested > 0 || row.epss_scores_ingested > 0
                  ? `${row.kev_entries_ingested.toLocaleString()} / ${row.epss_scores_ingested.toLocaleString()}`
                  : '—'}
              </td>
              <td>{row.records_rejected > 0 ? row.records_rejected.toLocaleString() : '—'}</td>
              <td>{new Date(row.started_at).toLocaleString()}</td>
              <td className="mono">{row.source_version ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {rows.some((row) => row.error_message) && (
        <ul className="limitations">
          {rows
            .filter((row) => row.error_message)
            .map((row) => (
              <li key={`${row.feed}-err-${row.started_at}`}>
                <strong>{row.feed}</strong>: {row.error_message}
              </li>
            ))}
        </ul>
      )}
    </div>
  );
}

function DeviceList({
  devices,
  emptyText,
}: {
  devices: CveDetail['affected_devices'];
  emptyText: string;
}) {
  if (devices.length === 0) return <p className="empty">{emptyText}</p>;

  return (
    <ul className="device-list">
      {devices.map((device) => (
        <li key={device.device_id}>
          <NavLink to={`/inventory/${device.device_id}/config`}>
            {device.hostname ?? device.mgmt_ip ?? device.device_id}
          </NavLink>{' '}
          <span className="muted">
            {device.platform ?? 'platform unknown'}
            {device.installed_version ? ` · ${device.installed_version}` : ''}
          </span>{' '}
          <ConfidenceBadge confidence={device.confidence} />
          {device.fixed_versions.length > 0 && (
            <span className="muted"> · fixed in {device.fixed_versions.join(', ')}</span>
          )}
        </li>
      ))}
    </ul>
  );
}

function CvePanel({ cveId, onClose }: { cveId: string; onClose: () => void }) {
  const detail = useQuery({
    queryKey: ['cve', cveId],
    queryFn: () => api.get<CveDetail>(`/vulnerabilities/${cveId}`),
  });

  if (detail.isLoading) return <p className="page-loading">Loading…</p>;
  if (!detail.data) return null;

  const cve = detail.data;
  const partiallyRead = cve.advisories.filter((a) => !a.fully_interpreted);

  return (
    <section className="card">
      <div className="card__header">
        <h2 className="card__title">
          <span className="mono">{cve.cve_id}</span> <KevBadge kev={cve.kev} />
        </h2>
        <button className="button button--ghost button--small" onClick={onClose}>
          Close
        </button>
      </div>

      {cve.description && <p className="finding__description">{cve.description}</p>}

      <div className="finding__meta">
        <span>CVSS {cve.cvss31?.base_score ?? '—'}</span>
        <span>EPSS {formatEpss(cve.epss)}</span>
        <span>{kevLabel(cve.kev)}</span>
        {cve.kev_due_date && <span>KEV due {cve.kev_due_date}</span>}
        {cve.published && <span>Published {new Date(cve.published).toLocaleDateString()}</span>}
      </div>
      {cve.cvss31?.vector && <p className="mono muted">{cve.cvss31.vector}</p>}

      <h3 className="finding__heading">Affected devices</h3>
      <DeviceList
        devices={cve.affected_devices}
        emptyText="No device in scope was found affected by this CVE."
      />

      {/* Its own heading, never merged with the list above. A device here is not clear. */}
      <h3 className="finding__heading">Could not be evaluated</h3>
      <p className="finding__note">
        The matcher could not reach a verdict on these — no version was collected, the affected
        range was unreadable, or the release trains are not comparable. They are neither affected
        nor clear.
      </p>
      <DeviceList
        devices={cve.unevaluated_devices}
        emptyText="Every device in scope produced a verdict."
      />

      <h3 className="finding__heading">Advisories</h3>
      <ul className="finding__frameworks">
        {cve.advisories.map((advisory) => (
          <li key={`${advisory.source}-${advisory.advisory_id}`}>
            <strong>{advisory.source}</strong> <span className="mono">{advisory.advisory_id}</span>
            {!advisory.fully_interpreted && (
              <span className="pill pill--medium" title="Some statements could not be parsed">
                partly read
              </span>
            )}
          </li>
        ))}
      </ul>

      {partiallyRead.length > 0 && (
        <div className="alert alert--warning" role="note">
          {partiallyRead.length === 1 ? 'One advisory' : `${partiallyRead.length} advisories`} here
          contained statements that could not be parsed. An advisory that is only partly understood
          can raise a finding but can never clear a device, so a “not affected” verdict resting on
          it is weaker than one that is not.
        </div>
      )}
    </section>
  );
}

export function VulnerabilitiesPage() {
  const [severity, setSeverity] = useState('');
  const [confidence, setConfidence] = useState('');
  const [kevOnly, setKevOnly] = useState(false);
  const [offset, setOffset] = useState(0);
  const [selectedCve, setSelectedCve] = useState<string | null>(null);
  const [showFeeds, setShowFeeds] = useState(false);

  const summary = useQuery({
    queryKey: ['vuln-summary'],
    queryFn: () => api.get<VulnerabilitySummary>('/vulnerabilities/summary'),
  });

  const list = useQuery({
    queryKey: ['vulnerabilities', severity, confidence, kevOnly, offset],
    queryFn: () => {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(offset),
      });
      if (severity) params.set('severity', severity);
      if (confidence) params.set('confidence', confidence);
      if (kevOnly) params.set('kev_only', 'true');
      return api.get<Paginated<Vulnerability>>(`/vulnerabilities?${params}`);
    },
  });

  const total = list.data?.meta.total ?? 0;
  const rows = list.data?.data ?? [];
  const filteredAfterCount = Boolean(
    (list.data?.meta as Record<string, unknown> | undefined)?.filtered_after_count,
  );

  return (
    <div className="page">
      <header className="page__header">
        <h1>Vulnerabilities</h1>
        <p className="page__subtitle">
          Derived from the software versions in each device&rsquo;s collected configuration — no
          scanner licence, no credentialed scan, no reachability to the device.
        </p>
      </header>

      {summary.data && <SummaryStrip summary={summary.data} />}

      {summary.data && summary.data.devices_unassessed > 0 && (
        <div className="alert alert--warning" role="note">
          {summary.data.devices_unassessed} device
          {summary.data.devices_unassessed === 1 ? ' has' : 's have'} never been assessed for
          vulnerabilities. They contribute nothing to the counts above, and their absence from this
          table is not a statement that they are clear.
        </div>
      )}

      <div className="toolbar">
        <select
          className="field__input field__input--small"
          value={severity}
          onChange={(event) => {
            setSeverity(event.target.value);
            setOffset(0);
          }}
          aria-label="Filter by severity"
        >
          <option value="">All severities</option>
          {SEVERITIES.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>

        <select
          className="field__input field__input--small"
          value={confidence}
          onChange={(event) => {
            setConfidence(event.target.value);
            setOffset(0);
          }}
          aria-label="Filter by match confidence"
        >
          <option value="">Any confidence</option>
          <option value="confirmed">Confirmed</option>
          <option value="likely">Likely</option>
        </select>

        <label className="toolbar__check">
          <input
            type="checkbox"
            checked={kevOnly}
            onChange={(event) => {
              setKevOnly(event.target.checked);
              setOffset(0);
            }}
          />
          Known exploited only
        </label>

        <button
          className="button button--ghost button--small"
          onClick={() => setShowFeeds(!showFeeds)}
        >
          {showFeeds ? 'Hide feed status' : 'Feed status'}
        </button>
      </div>

      {showFeeds && (
        <section className="card">
          <div className="card__header">
            <h2 className="card__title">Feed synchronisation</h2>
          </div>
          <FeedPanel />
        </section>
      )}

      {list.isLoading ? (
        <p className="page-loading">Loading…</p>
      ) : rows.length === 0 ? (
        <p className="empty">
          No open vulnerability findings.{' '}
          {summary.data && summary.data.devices_unassessed > 0
            ? 'Note that some devices have never been assessed — see above.'
            : 'Every assessed device matched nothing in the imported feeds.'}
        </p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>CVE</th>
                <th>Device</th>
                <th>Installed</th>
                <th>Fixed in</th>
                <th>Confidence</th>
                <th>CVSS</th>
                <th>EPSS</th>
                <th>KEV</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.finding_id}>
                  <td>
                    <span className={`pill pill--${row.severity}`}>{row.severity}</span>
                  </td>
                  <td className="mono">{row.cve_ids[0] ?? row.advisory_id ?? '—'}</td>
                  <td>
                    <NavLink to={`/inventory/${row.device_id}/config`}>
                      {row.device_hostname ?? row.device_id}
                    </NavLink>
                  </td>
                  <td className="mono">{row.installed_version ?? '—'}</td>
                  <td className="mono">
                    {row.fixed_versions.length > 0 ? row.fixed_versions.join(', ') : '—'}
                  </td>
                  <td>
                    <ConfidenceBadge confidence={row.confidence} />
                  </td>
                  <td>{row.cvss?.base_score ?? '—'}</td>
                  <td>{formatEpss(row.epss)}</td>
                  <td>
                    <KevBadge kev={row.kev} />
                  </td>
                  <td>
                    {row.cve_ids[0] && (
                      <button
                        className="button button--ghost button--small"
                        onClick={() =>
                          setSelectedCve(
                            selectedCve === row.cve_ids[0] ? null : (row.cve_ids[0] ?? null),
                          )
                        }
                      >
                        {selectedCve === row.cve_ids[0] ? 'Hide' : 'Details'}
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selectedCve && <CvePanel cveId={selectedCve} onClose={() => setSelectedCve(null)} />}

      <div className="pager">
        <button
          className="button button--ghost button--small"
          disabled={offset === 0}
          onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
        >
          Previous
        </button>
        <span className="pager__status">
          {total === 0 ? '0' : `${offset + 1}–${Math.min(offset + PAGE_SIZE, total)}`} of{' '}
          {total.toLocaleString()}
          {/* The KEV filter is applied after the count, because the flag lives on the
              CVE row rather than the finding. Saying so beats a total that does not
              match the rows. */}
          {filteredAfterCount && ' before the known-exploited filter'}
        </span>
        <button
          className="button button--ghost button--small"
          disabled={offset + PAGE_SIZE >= total}
          onClick={() => setOffset(offset + PAGE_SIZE)}
        >
          Next
        </button>
      </div>
    </div>
  );
}
