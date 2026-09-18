/** Compliance pivoted by framework control (FR-CHK-05).
 *
 * The number at the top is a percentage of what was actually *decided* — Not Applicable
 * and Not Evaluated appear in neither half. That distinction is the difference between
 * a compliance figure and a comforting one: counting unevaluated checks as passes would
 * make a device whose collection half-failed score better than one fully assessed.
 */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { api, ApiError } from '../api/client';

interface FrameworkControl {
  control: string;
  checks: string[];
  passed: number;
  failed: number;
  not_evaluated: number;
}

interface Compliance {
  framework: string;
  device_count: number;
  compliance_percent: number | null;
  controls: FrameworkControl[];
}

interface FrameworkOption {
  key: string;
  checks: number;
}

/** Display names for the frameworks the registry serves. A key with no entry here
 *  falls back to itself rather than being hidden: a framework the product maps and the
 *  console does not offer is, to a user, one the product does not have — which is
 *  exactly what happened to CERT-In and CEA while this list was hard-coded. */
const LABELS: Record<string, string> = {
  cis: 'CIS Benchmarks',
  nist_800_53: 'NIST 800-53',
  pci_dss: 'PCI DSS',
  iso_27001: 'ISO 27001',
  cert_in: 'CERT-In',
  cea: 'CEA Cyber Security Guidelines',
};

export function CompliancePage() {
  const [framework, setFramework] = useState('cis');

  const frameworks = useQuery({
    queryKey: ['frameworks'],
    queryFn: () => api.get<FrameworkOption[]>('/compliance/frameworks'),
    staleTime: Infinity,
  });

  const compliance = useQuery({
    queryKey: ['compliance', framework],
    queryFn: () => api.get<Compliance>(`/compliance/${framework}`),
    retry: false,
  });

  const data = compliance.data;

  return (
    <div className="page">
      <header className="page__header">
        <h1>Compliance</h1>
        <p className="page__subtitle">Check results grouped by the control each one maps to.</p>
      </header>

      <div className="toolbar">
        <select
          className="field__input field__input--small"
          value={framework}
          onChange={(event) => setFramework(event.target.value)}
          aria-label="Framework"
        >
          {(frameworks.data ?? []).map((entry) => (
            <option key={entry.key} value={entry.key}>
              {LABELS[entry.key] ?? entry.key} ({entry.checks} checks)
            </option>
          ))}
        </select>
      </div>

      {compliance.isLoading && <p className="page-loading">Loading…</p>}

      {compliance.isError && (
        <div className="alert alert--warning" role="status">
          {compliance.error instanceof ApiError
            ? compliance.error.message
            : 'Compliance data is not available.'}
        </div>
      )}

      {data && (
        <>
          <section className="card-grid">
            <div className="card">
              <h2 className="card__title">Controls passing</h2>
              <p className="stat">
                {data.compliance_percent === null ? '—' : `${data.compliance_percent}%`}
              </p>
              <p className="stat__note">
                Of the checks that produced a verdict. Not Applicable and Not Evaluated are excluded
                from both halves.
              </p>
            </div>
            <div className="card">
              <h2 className="card__title">Devices assessed</h2>
              <p className="stat">{data.device_count}</p>
            </div>
            <div className="card">
              <h2 className="card__title">Controls covered</h2>
              <p className="stat">{data.controls.length}</p>
            </div>
          </section>

          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Control</th>
                  <th>Checks</th>
                  <th>Passed</th>
                  <th>Failed</th>
                  <th>Not evaluated</th>
                </tr>
              </thead>
              <tbody>
                {data.controls.map((control) => (
                  <tr key={control.control}>
                    <td className="mono">{control.control}</td>
                    <td>{control.checks.join(', ')}</td>
                    <td>{control.passed}</td>
                    <td>
                      {control.failed > 0 ? (
                        <strong className="text-error">{control.failed}</strong>
                      ) : (
                        0
                      )}
                    </td>
                    <td>
                      {/* Surfaced rather than hidden: a control with nothing evaluated
                          is not a control that passed. */}
                      {control.not_evaluated > 0 ? (
                        <span className="muted">{control.not_evaluated}</span>
                      ) : (
                        0
                      )}
                    </td>
                  </tr>
                ))}
                {data.controls.length === 0 && (
                  <tr>
                    <td colSpan={5} className="table__empty">
                      Nothing has been assessed against this framework yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
