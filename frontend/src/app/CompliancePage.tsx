/** Compliance posture, across every framework the check library maps (FR-CHK-05).
 *
 * **Every framework at once, not one behind a picker.** The page used to open on CIS
 * with the other five in a `<select>`, which made five mappings the product genuinely
 * has effectively invisible — the same failure the framework list itself was fixed for
 * when CERT-In and CEA were hard-coded out of the console. A reader arriving here is
 * usually asking "how do we look", and that question has six answers.
 *
 * **The denominator is ours, not the framework's.** "61 controls" means the controls
 * *this library maps*, not the hundreds CIS contains. Stated on the page, because the
 * two readings differ by an order of magnitude and only one of them is true. Borrowed
 * from MonitorRisk's compliance screen, which carries the same warning for the same
 * reason.
 *
 * **A control nothing evaluated is not a control that passed.** It is drawn dashed and
 * dimmed with em-dashes where its counts would be, never as a row of zeroes — a row
 * reading `0 / 0 / 650` is visually indistinguishable from a clean one, and on the
 * screen this replaced it sat directly beneath controls that genuinely passed.
 *
 * **The breakdown opens in a dialog, not underneath the card.** The cards are a grid,
 * so expanding in place gave a five-column table a third of the page: control names
 * wrapped to four lines, check ids truncated, and the three figures the table exists
 * for were squeezed to nothing. A dialog is the width of the window however many
 * frameworks are on screen beside it, and the card's headline figures are repeated
 * inside it because it covers the card they came from.
 *
 * **The percentage stays, unlike MonitorRisk's.** That product refuses one in as many
 * words, and is right to: it maps *findings* onto controls, and the absence of a
 * finding is not evidence of compliance. NetSecOps runs checks that return an explicit
 * verdict per device, and this figure is the share of those verdicts that passed — Not
 * Applicable and Not Evaluated are in neither half. That is a measurement rather than
 * an inference, and deleting it would throw away the one number this product can
 * legitimately stand behind.
 */

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { api, ApiError } from '../api/client';
import { Icon } from '../components/Icon';
import { Modal } from '../components/Modal';
import { PageHeader } from '../components/PageHeader';

/** Three bands, not a gradient. A percentage of decided checks does not support finer
 *  judgement than "good", "middling" and "bad", and the dashboard bands it the same
 *  way so the two screens never disagree about a colour. */
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

interface FrameworkPosture {
  key: string;
  checks: number;
  controls: number;
  controls_failing: number;
  controls_unevaluated: number;
  device_count: number;
  compliance_percent: number | null;
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

/** A control's state, which decides how its row is drawn.
 *
 * Three states and not two, because "nothing failed" and "nothing was looked at" are
 * opposite facts that a pass/fail reading collapses into the same quiet row. */
function stateOf(control: FrameworkControl): 'failing' | 'passing' | 'unevaluated' {
  if (control.failed > 0) return 'failing';
  if (control.passed > 0) return 'passing';
  return 'unevaluated';
}

/** How many check ids a control shows before folding the rest away.
 *
 * Some controls map to fifteen. Rendered as one comma-run they were wider than the
 * screen, which pushed Passed, Failed and Not evaluated off the right-hand edge — so
 * the column of supporting detail hid the three numbers the page exists to show, and
 * reading them meant scrolling a table sideways.
 *
 * Eight rather than the three this started at. The table used to expand inside a card
 * in a grid, where the column was a third of the page; it opens in a dialog now and
 * has the width to show most controls' checks outright. The fold stays for the few
 * that map more than that — a row eight lines tall stops being a row. */
const CHECKS_SHOWN = 8;

/** The checks behind a control, as chips rather than a sentence of slugs.
 *
 * `aaa-no-cleartext-credentials, aaa-server-admin-mfa, aaa-servers-have-shared-secrets`
 * joined by commas reads as one long hyphenated string — the commas disappear among the
 * hyphens and there is no way to see where one id ends. Each on its own ground is
 * scannable at a glance and wraps without becoming a paragraph.
 */
function CheckChips({ checks }: { checks: string[] }) {
  const [expanded, setExpanded] = useState(false);
  const hidden = checks.length - CHECKS_SHOWN;
  const shown = expanded ? checks : checks.slice(0, CHECKS_SHOWN);

  return (
    <div className="chips">
      {shown.map((check) => (
        <span className="chip mono" key={check}>
          {check}
        </span>
      ))}
      {hidden > 0 && (
        <button type="button" className="chip chip--more" onClick={() => setExpanded(!expanded)}>
          {expanded ? 'show fewer' : `+${hidden} more`}
        </button>
      )}
    </div>
  );
}

function ControlTable({ framework }: { framework: string }) {
  const detail = useQuery({
    queryKey: ['compliance', framework],
    // Fetched when the card is opened rather than on page load: the common visit is
    // reading six headline figures and leaving, and the control tables are the
    // expensive half of this page.
    queryFn: () => api.get<Compliance>(`/compliance/${framework}`),
    retry: false,
  });

  if (detail.isLoading) return <p className="page-loading">Loading controls…</p>;

  if (detail.isError) {
    return (
      <div className="alert alert--warning" role="status">
        {detail.error instanceof ApiError
          ? detail.error.message
          : 'The control breakdown could not be loaded.'}
      </div>
    );
  }

  const controls = detail.data?.controls ?? [];

  if (controls.length === 0) {
    return <p className="empty">Nothing has been assessed against this framework yet.</p>;
  }

  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Control</th>
            <th>Checks</th>
            <th className="num">Passed</th>
            <th className="num">Failed</th>
            <th className="num">Not evaluated</th>
          </tr>
        </thead>
        <tbody>
          {controls.map((control) => {
            const state = stateOf(control);
            return (
              <tr key={control.control} className={`control control--${state}`}>
                {/* Not `nowrap`. It was right when a control was `1.1.1` and wrong the
                    moment a framework names them — CEA's are phrases like "Logging and
                    Monitoring", and holding one on a single line widened the column
                    enough to push the figures off the screen. */}
                <td className="control__id mono">{control.control}</td>
                <td className="control__checks">
                  <CheckChips checks={control.checks} />
                </td>
                {state === 'unevaluated' ? (
                  <>
                    {/* Em-dashes rather than zeroes. `0 passed, 0 failed` is a row a
                        reader scans past as clean; this one has to stop them. */}
                    <td className="num faint" colSpan={2}>
                      not evaluated on any device
                    </td>
                    <td className="num faint">{control.not_evaluated.toLocaleString()}</td>
                  </>
                ) : (
                  <>
                    <td className="num">{control.passed.toLocaleString()}</td>
                    <td className="num">
                      {control.failed > 0 ? (
                        <strong className="text-error">{control.failed.toLocaleString()}</strong>
                      ) : (
                        <span className="faint">—</span>
                      )}
                    </td>
                    <td className="num">
                      {control.not_evaluated > 0 ? (
                        <span className="faint">{control.not_evaluated.toLocaleString()}</span>
                      ) : (
                        <span className="faint">—</span>
                      )}
                    </td>
                  </>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function FrameworkCard({ posture }: { posture: FrameworkPosture }) {
  const [open, setOpen] = useState(false);
  const name = LABELS[posture.key] ?? posture.key;
  const percent = posture.compliance_percent;

  return (
    <section className="framework">
      <div className="framework__head">
        <div className="framework__identity">
          <h2 className="framework__name">{name}</h2>
          <p className="framework__scope">
            {posture.checks} check{posture.checks === 1 ? '' : 's'} mapped to{' '}
            {posture.controls} control{posture.controls === 1 ? '' : 's'}
          </p>
        </div>
        <div className="framework__score">
          <strong className="framework__percent" style={{ color: complianceTone(percent) }}>
            {percent === null ? '—' : `${percent}%`}
          </strong>
          <span className="framework__percent-note">
            {percent === null ? 'nothing decided yet' : 'of decided checks pass'}
          </span>
        </div>
      </div>

      <dl className="framework__figures">
        <div>
          <dt>Controls failing</dt>
          <dd className={posture.controls_failing ? 'text-error' : undefined}>
            {posture.controls_failing.toLocaleString()}
          </dd>
        </div>
        <div>
          <dt>Never evaluated</dt>
          {/* Beside the failures rather than under them: a control nothing looked at
              is the other way this framework's figure can be misread. */}
          <dd className={posture.controls_unevaluated ? 'text-warn' : undefined}>
            {posture.controls_unevaluated.toLocaleString()}
          </dd>
        </div>
        <div>
          <dt>Devices assessed</dt>
          <dd>{posture.device_count.toLocaleString()}</dd>
        </div>
      </dl>

      {/* Opens a dialog rather than expanding in place. These cards sit in a grid, so
          "in place" meant a five-column table inside a third of the page: the control
          names wrapped to four lines, the check ids truncated, and the three figures
          the table exists for were squeezed to nothing. A dialog is the full width of
          the window regardless of how many frameworks are on screen beside it.

          `aria-haspopup`, not `aria-expanded`: this reveals a dialog somewhere else,
          not a region below itself, and `aria-expanded` would tell a screen-reader
          user to look underneath for content that is not there. */}
      <button
        type="button"
        className="framework__toggle"
        onClick={() => setOpen(true)}
        aria-haspopup="dialog"
        disabled={posture.controls === 0}
      >
        <Icon name="chevron" size={14} />
        Show the {posture.controls} control{posture.controls === 1 ? '' : 's'}
      </button>

      {open && (
        <Modal label={`${name} controls`} size="wide" onClose={() => setOpen(false)}>
          {/* The card's own figures repeat inside the dialog. It covers the card it
              was opened from, so without them the reader has the breakdown and not
              the number it breaks down. */}
          <header className="dialog__head">
            <h2 className="dialog__title">{name}</h2>
            <p className="dialog__sub">
              {posture.checks} check{posture.checks === 1 ? '' : 's'} mapped to{' '}
              {posture.controls} control{posture.controls === 1 ? '' : 's'}, assessed on{' '}
              {posture.device_count.toLocaleString()} device
              {posture.device_count === 1 ? '' : 's'}.{' '}
              {percent === null ? (
                'Nothing has produced a verdict yet.'
              ) : (
                <>
                  <strong style={{ color: complianceTone(percent) }}>{percent}%</strong> of
                  decided checks pass — Not Applicable and Not Evaluated are in neither half.
                </>
              )}
            </p>
          </header>
          <ControlTable framework={posture.key} />
        </Modal>
      )}
    </section>
  );
}

export function CompliancePage() {
  const posture = useQuery({
    queryKey: ['compliance', 'posture'],
    queryFn: () => api.get<FrameworkPosture[]>('/compliance/posture'),
    retry: false,
  });

  const frameworks = posture.data ?? [];
  const assessed = frameworks.filter((f) => f.compliance_percent !== null);

  return (
    <div className="page">
      <PageHeader
        icon="compliance"
        title="Compliance"
        subtitle="Check results grouped by the control each one maps to, for every framework this library reaches."
      />

      {/* The scope statement leads, because every figure below is read differently
          once you know the denominator is ours. */}
      <div className="alert alert--info" role="note">
        <strong>Counts are of the controls this product maps</strong> — not of everything a
        framework contains. CIS Benchmarks has far more controls than a read-only
        configuration collection can be evidence about, and only the mapped ones are counted
        here. A percentage is the share of <em>control</em> verdicts that passed — a check
        mapped to two controls counts towards both, because it satisfies or fails both. Not
        Applicable and Not Evaluated are in neither half, since counting them as passes would
        make a device whose collection half-failed score better than one fully assessed.
      </div>

      {posture.isLoading && <p className="page-loading">Loading…</p>}

      {posture.isError && (
        <div className="alert alert--warning" role="status">
          {posture.error instanceof ApiError
            ? posture.error.message
            : 'Compliance data is not available.'}
        </div>
      )}

      {posture.isSuccess && (
        <p className="page__lede">
          {frameworks.length} framework{frameworks.length === 1 ? '' : 's'} mapped.{' '}
          {assessed.length === 0
            ? 'None has been assessed yet — no check in any of them has produced a verdict.'
            : `${assessed.length} ${assessed.length === 1 ? 'has' : 'have'} at least one verdict to report.`}
        </p>
      )}

      <div className="frameworks">
        {frameworks.map((entry) => (
          <FrameworkCard key={entry.key} posture={entry} />
        ))}
      </div>
    </div>
  );
}
