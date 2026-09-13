/** Configuration viewer (IF-UI-04).
 *
 * Line numbers, search, highlighting and jump-to-line, over the *redacted*
 * configuration. There is no unredacted mode here by design: the redacted text is what
 * the snapshot endpoint returns, and the original never leaves the artefact endpoint,
 * which is separately permissioned and audited (SEC-09). A toggle in this component
 * would imply the browser already holds the secret — it does not, and must not.
 *
 * Highlighting is deliberately small: a few token classes that make a configuration
 * skimmable. A full grammar per vendor would be a lot of code to get subtly wrong, and
 * the value here is in finding the line you were sent to, not in syntax colour.
 */

import { useEffect, useMemo, useRef, useState } from 'react';

interface Props {
  config: string;
  /** Scroll to and highlight this 1-based line on mount — findings link here. */
  jumpToLine?: number | null;
  /** Lines to mark as changed, e.g. from a diff. 1-based. */
  highlightLines?: Set<number>;
  /** Shown above the gutter; usually the device or snapshot identity. */
  caption?: string;
}

/** The placeholder redaction leaves behind, so the viewer can mark it visibly. */
const REDACTED_PATTERN = /\[REDACTED:[^\]]*\]/g;

const COMMENT = /^\s*[!#]/;
const NEGATION = /^\s*no\s/;

function classify(line: string): string {
  if (COMMENT.test(line)) return 'cfg__line cfg__line--comment';
  if (NEGATION.test(line)) return 'cfg__line cfg__line--negation';
  if (/^\S/.test(line)) return 'cfg__line cfg__line--stanza';
  return 'cfg__line';
}

/** Split a line into plain text, redaction placeholders and search matches. */
function renderLine(text: string, query: string): React.ReactNode {
  const parts: React.ReactNode[] = [];
  let cursor = 0;
  let key = 0;

  const marks: { start: number; end: number; kind: 'redacted' | 'match' }[] = [];

  for (const match of text.matchAll(REDACTED_PATTERN)) {
    marks.push({
      start: match.index,
      end: match.index + match[0].length,
      kind: 'redacted',
    });
  }

  if (query) {
    const needle = query.toLowerCase();
    const haystack = text.toLowerCase();
    let from = haystack.indexOf(needle);
    while (from !== -1) {
      // A search hit inside a placeholder is not interesting, and overlapping marks
      // would produce nested spans that the browser renders inconsistently.
      const overlaps = marks.some((m) => from < m.end && from + needle.length > m.start);
      if (!overlaps) marks.push({ start: from, end: from + needle.length, kind: 'match' });
      from = haystack.indexOf(needle, from + needle.length);
    }
  }

  marks.sort((a, b) => a.start - b.start);

  for (const mark of marks) {
    if (mark.start > cursor) parts.push(text.slice(cursor, mark.start));
    parts.push(
      <mark key={key++} className={mark.kind === 'redacted' ? 'cfg__redacted' : 'cfg__match'}>
        {text.slice(mark.start, mark.end)}
      </mark>,
    );
    cursor = mark.end;
  }

  if (cursor < text.length) parts.push(text.slice(cursor));
  return parts.length ? parts : ' ';
}

export function ConfigViewer({ config, jumpToLine, highlightLines, caption }: Props) {
  const [query, setQuery] = useState('');
  const [current, setCurrent] = useState(0);
  const container = useRef<HTMLDivElement>(null);

  const lines = useMemo(() => config.split('\n'), [config]);

  const matches = useMemo(() => {
    if (!query) return [];
    const needle = query.toLowerCase();
    return lines.reduce<number[]>((found, line, index) => {
      if (line.toLowerCase().includes(needle)) found.push(index + 1);
      return found;
    }, []);
  }, [lines, query]);

  // Reset the cursor whenever the result set changes, or "next match" would step
  // through positions that no longer exist.
  useEffect(() => setCurrent(0), [query]);

  const target = matches.length ? matches[current % matches.length] : null;

  useEffect(() => {
    const line = target ?? jumpToLine;
    if (!line || !container.current) return;
    container.current
      .querySelector(`[data-line="${line}"]`)
      ?.scrollIntoView({ block: 'center', behavior: 'smooth' });
  }, [target, jumpToLine]);

  return (
    <div className="cfg">
      <div className="cfg__toolbar">
        {caption && <span className="cfg__caption">{caption}</span>}

        <div className="cfg__search">
          <input
            type="search"
            className="field__input field__input--small"
            placeholder="Search configuration…"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            aria-label="Search configuration"
          />
          {query && (
            <>
              <span className="cfg__match-count">
                {matches.length === 0
                  ? 'no matches'
                  : `${(current % matches.length) + 1} of ${matches.length}`}
              </span>
              <button
                type="button"
                className="button button--ghost button--small"
                disabled={matches.length === 0}
                onClick={() => setCurrent((value) => value + 1)}
              >
                Next
              </button>
            </>
          )}
        </div>

        <span className="cfg__note" title="Secrets are replaced before the configuration leaves the server">
          Redacted
        </span>
      </div>

      <div className="cfg__body" ref={container}>
        <pre className="cfg__pre">
          {lines.map((line, index) => {
            const number = index + 1;
            const isTarget = number === target || (!target && number === jumpToLine);
            const isChanged = highlightLines?.has(number);

            return (
              <div
                key={number}
                data-line={number}
                className={[
                  classify(line),
                  isTarget ? 'cfg__line--target' : '',
                  isChanged ? 'cfg__line--changed' : '',
                ]
                  .filter(Boolean)
                  .join(' ')}
              >
                <span className="cfg__gutter" aria-hidden="true">
                  {number}
                </span>
                <span className="cfg__text">{renderLine(line, query)}</span>
              </div>
            );
          })}
        </pre>
      </div>
    </div>
  );
}
