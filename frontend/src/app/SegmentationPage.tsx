/** The segmentation matrix: what we said, against what the estate does (FR-TOPO-07).
 *
 * This is the page somebody prints and signs, which sets the whole design constraint:
 * **nothing on it may read as a pass unless it was actually checked.**
 *
 * The obvious layout is a grid of green and red squares, and it is the wrong one here.
 * A grid has a cell for every zone pair, so it has to put *something* in the pairs
 * nobody declared an intent for and the pairs whose path could not be traced — and
 * whatever is put there will be read as "fine". So this lists the declared rules
 * instead, each with its verdict and the evidence behind it. A pair nobody declared
 * simply is not on the page, which is the truth: no claim was made about it.
 *
 * `unverified` is given its own count in the summary, its own muted-and-dashed
 * treatment, and the sentence "this is not a pass" next to it. It is the status a
 * reader most wants to skim, and the one where skimming is expensive.
 */

import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import { api, ApiError } from '../api/client';
import type { Cell, CellStatus, Matrix } from '../features/segmentation/types';
import { STATUS_LABELS } from '../features/segmentation/types';

const ORDER: CellStatus[] = ['violated', 'unverified', 'upheld'];

function Row({ cell }: { cell: Cell }) {
  const [open, setOpen] = useState(false);
  const status = STATUS_LABELS[cell.status];

  return (
    <li className={`intent intent--${cell.status}`}>
      <button
        type="button"
        className="intent__summary"
        onClick={() => setOpen((current) => !current)}
        aria-expanded={open}
      >
        <span className="intent__pair">
          <span className="visually-hidden">from </span>
          <strong>{cell.source_zone}</strong>
          <span aria-hidden="true"> → </span>
          <span className="visually-hidden">to </span>
          <strong>{cell.destination_zone}</strong>
        </span>
        <span className="intent__traffic mono">
          {cell.protocol}/{cell.port}
        </span>
        <span className="intent__expectation">
          <span className="visually-hidden">policy says </span>
          {cell.expectation}
        </span>
        {/* The verdict names itself in text. Colour alone would fail WCAG 1.4.1, and
            on this page it would also be the difference between "checked and fine"
            and "nobody could check it". */}
        <span className={`pill pill--${status.tone}`}>{status.label}</span>
      </button>

      {open && (
        <div className="intent__detail">
          <p>{cell.detail}</p>
          {cell.status === 'unverified' && (
            <p className="alert alert--info" role="note">
              {status.meaning}
            </p>
          )}

          <dl className="kv">
            <dt>Why this rule exists</dt>
            <dd>{cell.justification}</dd>
            {/* What was actually walked. A cell speaks only for these, and without
                them "upheld" is a claim with no stated scope. */}
            <dt>Checked by walking</dt>
            <dd className="mono">{cell.walked.join(', ') || 'nothing — see above'}</dd>
          </dl>

          {cell.limitations.length > 0 && (
            <ul className="finding__note">
              {cell.limitations.map((limit) => (
                <li key={limit}>{limit}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </li>
  );
}

function Summary({ matrix }: { matrix: Matrix }) {
  return (
    <div className="card-grid">
      <div className="stat">
        <strong>{matrix.violated}</strong>
        <span>violated</span>
      </div>
      {/* Beside the violations, not tucked under them. A reader scanning for red takes
          the absence of it as a pass, and this is the number that says otherwise. */}
      <div className="stat">
        <strong>{matrix.unverified}</strong>
        <span>not verified</span>
      </div>
      <div className="stat">
        <strong>{matrix.upheld}</strong>
        <span>upheld</span>
      </div>
    </div>
  );
}

export function SegmentationPage() {
  const matrix = useQuery({
    queryKey: ['segmentation-matrix'],
    queryFn: () => api.get<Matrix>('/segmentation/matrix'),
  });

  // Worst first. The page is read top-down and the rows that need action are the ones
  // that should be there when a reader stops scrolling.
  const cells = useMemo(() => {
    const rows = [...(matrix.data?.cells ?? [])];
    rows.sort(
      (a, b) =>
        ORDER.indexOf(a.status) - ORDER.indexOf(b.status) ||
        a.source_zone.localeCompare(b.source_zone),
    );
    return rows;
  }, [matrix.data]);

  return (
    <div className="page">
      <header className="page__header">
        <h1>Segmentation</h1>
        <p className="page__subtitle">
          What the policy says should happen between zones, against what the estate actually does.
          Each row is checked by tracing a packet across every device on the path, not by searching
          one firewall&rsquo;s rules.
        </p>
      </header>

      {matrix.isLoading && <p className="page-loading">Tracing every declared pair…</p>}

      {matrix.isError && (
        <p className="alert alert--error" role="alert">
          {matrix.error instanceof ApiError
            ? matrix.error.problem.detail
            : 'The segmentation matrix could not be evaluated.'}
        </p>
      )}

      {matrix.data && (
        <>
          <section className="card">
            <div className="card__header">
              <h2 className="card__title">Where the estate stands</h2>
            </div>
            <Summary matrix={matrix.data} />

            {/* Shown on every result, not only bad ones. An unqualified list of green
                rows would be read as a guarantee about pairs nobody declared. */}
            {matrix.data.limitations.length > 0 && (
              <ul className="finding__note" role="note">
                {matrix.data.limitations.map((note) => (
                  <li key={note}>{note}</li>
                ))}
              </ul>
            )}
          </section>

          <section className="card">
            <div className="card__header">
              <h2 className="card__title">Declared rules</h2>
            </div>

            {cells.length === 0 ? (
              <p className="empty">
                No segmentation policy has been declared yet, so there is nothing to check. An empty
                matrix is not a clean one — declare the zone pairs that matter and each will be
                traced across the estate.
              </p>
            ) : (
              <ul className="intent__list">
                {cells.map((cell) => (
                  <Row key={cell.rule_id} cell={cell} />
                ))}
              </ul>
            )}
          </section>
        </>
      )}
    </div>
  );
}
