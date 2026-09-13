/** CSV device import with a dry-run preview (FR-INV-02).
 *
 * The preview is not decoration. Import is all-or-nothing, so an operator gets to see
 * exactly what would happen — and which line is wrong — before anything is written.
 */

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';

import { ApiError, request } from '../api/client';
import type { ImportPreview } from '../features/inventory/types';

const SAMPLE = `mgmt_ip,hostname,vendor,platform,site,groups,tags
10.0.0.1,core-sw-01,cisco,cisco_ios,HQ,Core|Access,dmz
10.0.0.2,edge-fw-01,fortinet,fortios,HQ,Edge,pci`;

export function ImportPage() {
  const navigate = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function upload(
    path: string,
  ): Promise<ImportPreview | { created: number; updated: number }> {
    if (!file) throw new Error('Choose a file first.');
    const body = new FormData();
    body.append('file', file);
    // FormData sets its own multipart Content-Type boundary; the client must not
    // override it, so the body is passed through rather than JSON-encoded.
    return request(path, { method: 'POST', body, rawBody: true });
  }

  async function handlePreview() {
    setError(null);
    setBusy(true);
    try {
      setPreview((await upload('/devices/import/preview')) as ImportPreview);
    } catch (err) {
      setError(err instanceof ApiError ? err.problem.detail : 'Could not read the file.');
      setPreview(null);
    } finally {
      setBusy(false);
    }
  }

  async function handleApply() {
    setError(null);
    setBusy(true);
    try {
      await upload('/devices/import');
      navigate('/inventory');
    } catch (err) {
      setError(err instanceof ApiError ? err.problem.detail : 'The import failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <header className="page__header">
        <h1>Import devices</h1>
        <p className="page__subtitle">
          Upload a CSV. Nothing is written until you review the preview and confirm.
        </p>
      </header>

      {error && (
        <div className="alert alert--error" role="alert">
          {error}
        </div>
      )}

      <section className="card">
        <h2 className="card__title">CSV format</h2>
        <p className="field__help">
          Only <code>mgmt_ip</code> is required. Separate multiple groups or tags with{' '}
          <code>|</code>. Sites and groups are created if they do not exist.
        </p>
        <pre className="secret-block mono">{SAMPLE}</pre>
      </section>

      <section className="card">
        <h2 className="card__title">Upload</h2>
        <label className="field">
          <span className="field__label">CSV file</span>
          <input
            className="field__input"
            type="file"
            accept=".csv,text/csv"
            onChange={(e) => {
              setFile(e.target.files?.[0] ?? null);
              setPreview(null);
            }}
          />
        </label>
        <button className="button button--primary" onClick={handlePreview} disabled={!file || busy}>
          {busy ? 'Checking…' : 'Preview'}
        </button>
      </section>

      {preview && (
        <section className="card">
          <h2 className="card__title">Preview</h2>

          <div className={`alert ${preview.ok ? 'alert--ok' : 'alert--error'}`} role="status">
            {preview.ok
              ? `${preview.creates} to create, ${preview.updates} to update.`
              : `${preview.invalid} row(s) have errors. Nothing will be imported until they are fixed.`}
          </div>

          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Line</th>
                  <th>Management IP</th>
                  <th>Action</th>
                  <th>Problem</th>
                </tr>
              </thead>
              <tbody>
                {preview.rows.map((row) => (
                  <tr key={row.line}>
                    <td className="mono">{row.line}</td>
                    <td className="mono">{row.mgmt_ip ?? '—'}</td>
                    <td>
                      <span className={`pill pill--${row.valid ? 'success' : 'failure'}`}>
                        {row.action}
                      </span>
                    </td>
                    <td>{row.errors.join('; ') || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="pager">
            <button
              className="button button--primary"
              onClick={handleApply}
              disabled={!preview.ok || busy}
            >
              {busy ? 'Importing…' : `Import ${preview.creates + preview.updates} device(s)`}
            </button>
            <button className="button button--ghost" onClick={() => navigate('/inventory')}>
              Cancel
            </button>
          </div>
        </section>
      )}
    </div>
  );
}
