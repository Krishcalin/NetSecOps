/** Filter state kept in the query string rather than in component state.
 *
 * Two things follow from this that component state cannot give you. A filtered view
 * survives a reload, and — the reason it was written — it can be *sent to someone*. A
 * link to "the open critical findings" is how one engineer hands work to another, and
 * it is also what lets a dashboard tile be a real filter rather than a number that
 * drops you at the top of an unfiltered list.
 *
 * A value equal to its default is removed from the URL rather than written out, so the
 * common case stays a clean path and a shared link carries only what was deliberately
 * chosen.
 */

import { useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';

export interface UrlFilters {
  /** The current value of a filter, or its default. */
  read: (key: string) => string;
  /** Apply filter changes. Paging resets unless `keepOffset` is set. */
  write: (changes: Record<string, string>, options?: { keepOffset?: boolean }) => void;
}

export function useUrlFilters(defaults: Record<string, string>): UrlFilters {
  const [search, setSearch] = useSearchParams();

  const read = useCallback(
    (key: string) => search.get(key) ?? defaults[key] ?? '',
    // `defaults` is a literal at every call site, so a dependency on the object itself
    // would rebuild this on every render. The keys are fixed for the life of a page.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [search],
  );

  const write = useCallback(
    (changes: Record<string, string>, options?: { keepOffset?: boolean }) => {
      const next = new URLSearchParams(search);
      for (const [key, value] of Object.entries(changes)) {
        if (value === '' || value === defaults[key]) {
          next.delete(key);
        } else {
          next.set(key, value);
        }
      }
      if (!options?.keepOffset) {
        // A filter change invalidates the page number: offset 100 described a list
        // that no longer exists, and keeping it lands the reader on an empty page
        // that looks like "no results".
        next.delete('offset');
      }
      // `replace` so that changing a filter four times does not put four entries in
      // the back button between the reader and the page they came from.
      setSearch(next, { replace: true });
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [search, setSearch],
  );

  return { read, write };
}
