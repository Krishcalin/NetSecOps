/** Diff viewer (IF-UI-05, FR-DRIFT-02).
 *
 * Three views of the same change, because they answer different questions:
 *
 * - **Semantic** first, and selected by default. "management.services.telnet.enabled
 *   changed disabled → enabled" is the sentence an operator needs; a wall of +/- lines
 *   makes them derive it themselves.
 * - **Unified** for reading the change in context.
 * - **Side-by-side** for seeing where in the configuration it sits.
 *
 * Both text views work off the redacted configurations, which is all the API returns.
 */

import { useMemo, useState } from 'react';

import type { ConfigDiff } from './types';

type View = 'semantic' | 'unified' | 'split';

interface Props {
  diff: ConfigDiff;
  beforeLabel?: string;
  afterLabel?: string;
}

interface Row {
  before: string | null;
  after: string | null;
  beforeNumber: number | null;
  afterNumber: number | null;
  kind: 'same' | 'added' | 'removed' | 'changed';
}

/**
 * The largest LCS table we will build, in cells.
 *
 * The table is O(before × after), so an unbounded one is a real hazard: a pair of
 * 10,000-line ASA rulebases would ask the browser for 400 MB. Four million cells is
 * 16 MB as a Uint32Array, and after the common prefix and suffix are trimmed it covers
 * every configuration pair that is not a near-total rewrite.
 */
const MAX_LCS_CELLS = 4_000_000;

function row(
  before: string | null,
  after: string | null,
  beforeNumber: number | null,
  afterNumber: number | null,
  kind: Row['kind'],
): Row {
  return { before, after, beforeNumber, afterNumber, kind };
}

/** Pair lines positionally — the fallback when an LCS table would be too large. */
function pairPositionally(before: string[], after: string[], offset: number): Row[] {
  const rows: Row[] = [];
  for (let n = 0; n < Math.max(before.length, after.length); n++) {
    const left = before[n] ?? null;
    const right = after[n] ?? null;
    const kind =
      left === right ? 'same' : left === null ? 'added' : right === null ? 'removed' : 'changed';
    rows.push(
      row(
        left,
        right,
        left === null ? null : offset + n + 1,
        right === null ? null : offset + n + 1,
        kind,
      ),
    );
  }
  return rows;
}

/**
 * Align two line lists for a side-by-side view.
 *
 * A longest-common-subsequence walk over the region that actually differs, which is
 * what makes an inserted block show as an insertion rather than shifting every line
 * below it into "changed" — the failure that makes naive side-by-side diffs unreadable.
 */
function align(before: string[], after: string[]): Row[] {
  // Trim the identical head and tail first. A configuration diff is almost always a
  // small change in a large file, so this usually reduces the table to almost nothing.
  let head = 0;
  while (head < before.length && head < after.length && before[head] === after[head]) head++;

  let tail = 0;
  while (
    tail < before.length - head &&
    tail < after.length - head &&
    before[before.length - 1 - tail] === after[after.length - 1 - tail]
  ) {
    tail++;
  }

  const rows: Row[] = [];
  for (let n = 0; n < head; n++) {
    rows.push(row(before[n] ?? '', after[n] ?? '', n + 1, n + 1, 'same'));
  }

  const left = before.slice(head, before.length - tail);
  const right = after.slice(head, after.length - tail);

  rows.push(...alignWindow(left, right, head));

  for (let n = 0; n < tail; n++) {
    const b = before.length - tail + n;
    const a = after.length - tail + n;
    rows.push(row(before[b] ?? '', after[a] ?? '', b + 1, a + 1, 'same'));
  }

  return rows;
}

function alignWindow(before: string[], after: string[], offset: number): Row[] {
  const n = before.length;
  const m = after.length;

  if (n === 0 && m === 0) return [];
  if ((n + 1) * (m + 1) > MAX_LCS_CELLS) return pairPositionally(before, after, offset);

  // A flat Uint32Array rather than nested arrays: one allocation, and indexing it is
  // typed as a number, not number | undefined.
  const width = m + 1;
  const lengths = new Uint32Array((n + 1) * width);
  const at = (i: number, j: number): number => lengths[i * width + j] as number;

  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lengths[i * width + j] =
        before[i] === after[j] ? at(i + 1, j + 1) + 1 : Math.max(at(i + 1, j), at(i, j + 1));
    }
  }

  const rows: Row[] = [];
  let i = 0;
  let j = 0;

  while (i < n && j < m) {
    if (before[i] === after[j]) {
      rows.push(row(before[i] ?? '', after[j] ?? '', offset + i + 1, offset + j + 1, 'same'));
      i++;
      j++;
    } else if (at(i + 1, j) >= at(i, j + 1)) {
      rows.push(row(before[i] ?? '', null, offset + i + 1, null, 'removed'));
      i++;
    } else {
      rows.push(row(null, after[j] ?? '', null, offset + j + 1, 'added'));
      j++;
    }
  }

  while (i < n) {
    rows.push(row(before[i] ?? '', null, offset + i + 1, null, 'removed'));
    i++;
  }
  while (j < m) {
    rows.push(row(null, after[j] ?? '', null, offset + j + 1, 'added'));
    j++;
  }

  return rows;
}

/** Collapse long runs of unchanged lines, keeping a few for context. */
function fold(rows: Row[], context = 3): (Row | { folded: number })[] {
  const changed = new Set<number>();
  rows.forEach((row, index) => {
    if (row.kind === 'same') return;
    for (let n = index - context; n <= index + context; n++) changed.add(n);
  });

  const output: (Row | { folded: number })[] = [];
  let run = 0;

  rows.forEach((row, index) => {
    if (changed.has(index)) {
      if (run > 0) {
        output.push({ folded: run });
        run = 0;
      }
      output.push(row);
    } else {
      run++;
    }
  });

  if (run > 0) output.push({ folded: run });
  return output;
}

function unifiedClass(line: string): string {
  if (line.startsWith('+++') || line.startsWith('---')) return 'diff__line diff__line--meta';
  if (line.startsWith('@@')) return 'diff__line diff__line--hunk';
  if (line.startsWith('+')) return 'diff__line diff__line--added';
  if (line.startsWith('-')) return 'diff__line diff__line--removed';
  return 'diff__line';
}

export function DiffViewer({ diff, beforeLabel = 'Baseline', afterLabel = 'Current' }: Props) {
  const [view, setView] = useState<View>('semantic');

  const rows = useMemo(
    () => (view === 'split' ? fold(align(diff.before_lines, diff.after_lines)) : []),
    [view, diff.before_lines, diff.after_lines],
  );

  if (!diff.changed) {
    return (
      <div className="card">
        <p className="empty">These two snapshots are identical once volatile lines are ignored.</p>
      </div>
    );
  }

  return (
    <div className="diff">
      <div className="diff__toolbar">
        <div className="segmented" role="tablist" aria-label="Diff view">
          {(
            [
              ['semantic', `What changed (${diff.semantic.length})`],
              ['unified', 'Unified'],
              ['split', 'Side by side'],
            ] as [View, string][]
          ).map(([value, label]) => (
            <button
              key={value}
              type="button"
              role="tab"
              aria-selected={view === value}
              className={`segmented__option${view === value ? ' segmented__option--active' : ''}`}
              onClick={() => setView(value)}
            >
              {label}
            </button>
          ))}
        </div>
        <span className="diff__summary">
          {diff.added.length} added, {diff.removed.length} removed
        </span>
      </div>

      {view === 'semantic' && (
        <div className="diff__semantic">
          {diff.semantic.length === 0 ? (
            <p className="empty">
              The text changed, but nothing the parser understands did — formatting or an
              unrecognised stanza. The unified view shows the raw change.
            </p>
          ) : (
            <ul className="diff__changes">
              {diff.semantic.map((change) => (
                <li key={change.path} className="diff__change">
                  <code className="diff__path">{change.path}</code>
                  <span className="diff__description">{change.description}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {view === 'unified' && (
        <pre className="diff__unified">
          {diff.unified.split('\n').map((line, index) => (
            <div key={index} className={unifiedClass(line)}>
              {line || ' '}
            </div>
          ))}
        </pre>
      )}

      {view === 'split' && (
        <div className="diff__split">
          <div className="diff__split-head">
            <span>{beforeLabel}</span>
            <span>{afterLabel}</span>
          </div>
          <div className="diff__split-body">
            {rows.map((row, index) =>
              'folded' in row ? (
                <div key={`fold-${index}`} className="diff__fold">
                  {row.folded} unchanged {row.folded === 1 ? 'line' : 'lines'}
                </div>
              ) : (
                <div key={index} className={`diff__row diff__row--${row.kind}`}>
                  <span className="diff__num">{row.beforeNumber ?? ''}</span>
                  <span className="diff__cell diff__cell--before">{row.before ?? ''}</span>
                  <span className="diff__num">{row.afterNumber ?? ''}</span>
                  <span className="diff__cell diff__cell--after">{row.after ?? ''}</span>
                </div>
              ),
            )}
          </div>
        </div>
      )}
    </div>
  );
}
