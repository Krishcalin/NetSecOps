/** Component tests for the diff viewer (IF-UI-05, TEST-05).
 *
 * The alignment is the part worth testing. A side-by-side diff that shifts every line
 * below an insertion into "changed" is technically a diff and practically useless, and
 * that failure is invisible until someone looks at a real configuration.
 */

import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { DiffViewer } from './DiffViewer';
import type { ConfigDiff } from './types';

function makeDiff(before: string[], after: string[], overrides: Partial<ConfigDiff> = {}) {
  const added = after.filter((line) => !before.includes(line));
  const removed = before.filter((line) => !after.includes(line));

  return {
    from_snapshot_id: 'a',
    to_snapshot_id: 'b',
    changed: added.length > 0 || removed.length > 0,
    added,
    removed,
    unified: [
      '--- baseline',
      '+++ current',
      '@@ -1,3 +1,3 @@',
      ...removed.map((line) => `-${line}`),
      ...added.map((line) => `+${line}`),
    ].join('\n'),
    before_lines: before,
    after_lines: after,
    semantic: [
      {
        path: 'management.services.telnet.enabled',
        description: 'management.services.telnet.enabled changed disabled → enabled',
      },
    ],
    ...overrides,
  } satisfies ConfigDiff;
}

describe('DiffViewer', () => {
  it('leads with the semantic change, not a wall of +/- lines', () => {
    render(<DiffViewer diff={makeDiff(['no ip http server'], ['ip http server'])} />);

    expect(screen.getByText(/telnet\.enabled changed disabled → enabled/)).toBeInTheDocument();
  });

  it('says so plainly when nothing changed', () => {
    render(<DiffViewer diff={makeDiff(['hostname a'], ['hostname a'])} />);

    expect(screen.getByText(/identical once volatile lines are ignored/i)).toBeInTheDocument();
  });

  it('explains a text-only change rather than showing an empty list', async () => {
    // A change the parser does not model still has to be reported honestly: silence
    // here would read as "nothing happened".
    render(
      <DiffViewer
        diff={makeDiff(['banner motd ^Cold^C'], ['banner motd ^Cnew^C'], { semantic: [] })}
      />,
    );

    expect(screen.getByText(/nothing the parser understands did/i)).toBeInTheDocument();
  });

  it('switches to the unified view and marks additions and removals', async () => {
    const user = userEvent.setup();
    render(<DiffViewer diff={makeDiff(['no ip http server'], ['ip http server'])} />);

    await user.click(screen.getByRole('tab', { name: 'Unified' }));

    expect(screen.getByText('+ip http server')).toHaveClass('diff__line--added');
    expect(screen.getByText('-no ip http server')).toHaveClass('diff__line--removed');
  });

  describe('side-by-side alignment', () => {
    async function renderSplit(before: string[], after: string[]) {
      const user = userEvent.setup();
      const { container } = render(<DiffViewer diff={makeDiff(before, after)} />);
      await user.click(screen.getByRole('tab', { name: 'Side by side' }));
      return container;
    }

    it('shows an inserted line as an insertion, not as a cascade of changes', async () => {
      // The failure this guards against: without a longest-common-subsequence walk,
      // inserting one line at the top reports every line below it as changed.
      const before = ['hostname sw1', 'ip ssh version 2', 'line vty 0 4'];
      const after = ['hostname sw1', 'logging host 10.0.0.1', 'ip ssh version 2', 'line vty 0 4'];

      const container = await renderSplit(before, after);

      const added = container.querySelectorAll('.diff__row--added');
      const removed = container.querySelectorAll('.diff__row--removed');

      expect(added).toHaveLength(1);
      expect(removed).toHaveLength(0);
      expect(within(added[0] as HTMLElement).getByText('logging host 10.0.0.1')).toBeInTheDocument();
    });

    it('keeps the line numbers of each side independent after an insertion', async () => {
      const container = await renderSplit(
        ['a', 'b'],
        ['a', 'inserted', 'b'],
      );

      const rows = container.querySelectorAll('.diff__row');
      const last = rows[rows.length - 1] as HTMLElement;
      const numbers = within(last)
        .getAllByText(/^\d+$/)
        .map((node) => node.textContent);

      // "b" is line 2 before and line 3 after — the whole point of two gutters.
      expect(numbers).toEqual(['2', '3']);
    });

    it('collapses long runs of unchanged lines', async () => {
      const unchanged = Array.from({ length: 40 }, (_, n) => `interface Gi1/0/${n + 1}`);
      const container = await renderSplit(
        [...unchanged, 'no ip http server'],
        [...unchanged, 'ip http server'],
      );

      const fold = container.querySelector('.diff__fold');
      expect(fold).not.toBeNull();
      expect(fold?.textContent).toMatch(/unchanged lines/);

      // The changed lines are still rendered, which is the point of folding the rest.
      expect(screen.getByText('ip http server')).toBeInTheDocument();
    });

    it('handles a wholly replaced configuration without losing either side', async () => {
      const container = await renderSplit(['old one', 'old two'], ['new one', 'new two']);

      expect(container.querySelectorAll('.diff__row--removed')).toHaveLength(2);
      expect(container.querySelectorAll('.diff__row--added')).toHaveLength(2);
    });

    it('handles an empty baseline', async () => {
      const container = await renderSplit([], ['hostname sw1']);
      expect(container.querySelectorAll('.diff__row--added')).toHaveLength(1);
    });
  });
});
