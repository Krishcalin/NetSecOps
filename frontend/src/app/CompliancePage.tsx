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
import { Dial, SummaryCell } from '../components/Graphics';
import { PageHeader } from '../components/PageHeader';

/** Three bands, not a gradient. A percentage of decided checks does not support
 *  finer judgement than "good", "middling" and "bad", and the dashboard bands it
 *  the same way so the two screens never disagree about a colour. */
function complianceTone(percent: number | null): string {
  if (percent === null) return 'var(--text-faint)';
  if (percent >= 90) return 'var(--sev-low)';
  if (percent >= 70) return 'var(--sev-medium)';
  return 'var(--sev-critical)';
}

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
      <PageHeader
        icon="compliance"
        title="Compliance"
        subtitle="Check results grouped by the control each one maps to."
      />

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
          {/* The same dial the dashboard leads with, on the page the dashboard links
              to. The figure is identical and so is its caveat, which is the point: a
              number that reads one way on the front page and another when you follow
              it is the reason nobody trusts either. */}
          <div className="hero">
            <section className="hero__score">
              <Dial
                value={data.compliance_percent}
                label={framework.toUpperCase().slice(0, 4)}
                tone={complianceTone(data.compliance_percent)}
                caption={
                  data.compliance_percent === null
                    ? 'No check in this framework has been evaluated yet.'
                    : `${data.compliance_percent} per cent of decided checks pass.`
                }
              />
              <div className="hero__score-text">
                <span className="hero__eyebrow">Controls passing</span>
                <h2 className="hero__heading">{LABELS[framework] ?? framework}</h2>
                <p className="hero__note">
                  Of the checks that produced a verdict. Not Applicable and Not Evaluated are
                  excluded from both halves — counting them as passes would make a device whose
                  collection half-failed score better than one fully assessed.
                </p>
              </div>
            </section>

            <section className="hero__spread">
              <div className="summary">
                <SummaryCell
                  icon="device"
                  label="Devices assessed"
                  value={data.device_count}
                  note="Contributing a verdict to this framework"
                />
                <SummaryCell
                  icon="compliance"
                  label="Controls covered"
                  value={data.controls.length}
                  note="Mapped to at least one check"
                />
                <SummaryCell
                  icon="cross"
                  label="Controls failing"
                  value={data.controls.filter((control) => control.failed > 0).length}
                  note="At least one device failed"
                  tone="var(--sev-critical)"
                />
                {/* Beside the other three rather than under them: a control nothing
                    evaluated is not a control that passed, and the percentage above
                    deliberately does not count it either way. */}
                <SummaryCell
                  icon="clock"
                  label="Never evaluated"
                  value={
                    data.controls.filter(
                      (control) =>
                        control.not_evaluated > 0 && control.passed === 0 && control.failed === 0,
                    ).length
                  }
                  note="No device produced a verdict"
                  tone="var(--sev-medium)"
                />
              </div>
            </section>
          </div>

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
