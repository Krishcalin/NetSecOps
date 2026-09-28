/** Compliance posture (FR-CHK-05).
 *
 * The page this replaced showed one framework and hid five behind a `<select>`, and
 * rendered a control nothing had evaluated as `0 passed, 0 failed, 650 not evaluated`
 * — a row indistinguishable, at a glance, from one that genuinely passed, sitting
 * directly beneath rows that did.
 *
 * So most of what follows is about the two ways this screen can mislead: by hiding a
 * mapping the product has, and by drawing an absence of evidence as a clean result.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { CompliancePage } from './CompliancePage';
import { api } from '../api/client';

const POSTURE = [
  {
    key: 'cis',
    checks: 70,
    controls: 61,
    controls_failing: 44,
    controls_unevaluated: 3,
    device_count: 650,
    compliance_percent: 49,
  },
  {
    key: 'cert_in',
    checks: 12,
    controls: 9,
    controls_failing: 0,
    controls_unevaluated: 9,
    device_count: 0,
    compliance_percent: null,
  },
];

const CONTROLS = {
  framework: 'cis',
  device_count: 650,
  compliance_percent: 49,
  controls: [
    {
      control: '1.1.6',
      checks: ['local-accounts-minimal'],
      passed: 407,
      failed: 0,
      not_evaluated: 0,
    },
    {
      control: '1.1.8',
      checks: ['cisco-aaa-command-authorization', 'cisco-login-block-for'],
      passed: 0,
      failed: 940,
      not_evaluated: 0,
    },
    {
      // The row the redesign exists for.
      control: '1.2.5',
      checks: ['tls-weak-versions'],
      passed: 0,
      failed: 0,
      not_evaluated: 650,
    },
    {
      // A real shape from the CEA mapping: a named control with fifteen checks behind
      // it, which as one comma-run was wider than the screen.
      control: 'Access Control',
      checks: Array.from({ length: 15 }, (_, i) => `aaa-control-check-number-${i + 1}`),
      passed: 120,
      failed: 4,
      not_evaluated: 0,
    },
  ],
};

let posture: unknown = POSTURE;

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <CompliancePage />
    </QueryClientProvider>,
  );
}

describe('CompliancePage', () => {
  beforeEach(() => {
    posture = POSTURE;
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/compliance/posture')) return posture as never;
      if (path.startsWith('/compliance/')) return CONTROLS as never;
      return [] as never;
    });
  });

  afterEach(() => vi.restoreAllMocks());

  describe('every framework is visible', () => {
    it('shows all of them at once rather than one behind a picker', async () => {
      // Five mappings the product genuinely has were invisible, which to a user is
      // indistinguishable from not having them — the same failure the framework list
      // was fixed for when CERT-In was hard-coded out of the console.
      renderPage();

      expect(await screen.findByRole('heading', { name: 'CIS Benchmarks' })).toBeInTheDocument();
      expect(screen.getByRole('heading', { name: 'CERT-In' })).toBeInTheDocument();
      expect(screen.queryByRole('combobox')).toBeNull();
    });

    it('falls back to the key for a framework it has no name for', async () => {
      // A framework the registry serves and this map has not caught up with must still
      // appear. Hiding it is how CERT-In disappeared in the first place.
      posture = [{ ...POSTURE[0], key: 'newly_mapped' }];
      renderPage();

      expect(await screen.findByRole('heading', { name: 'newly_mapped' })).toBeInTheDocument();
    });
  });

  describe('the denominator', () => {
    it('says outright that the counts are of the controls this product maps', async () => {
      // "61 controls" reads as 61 of the framework's controls, which is wrong by an
      // order of magnitude.
      renderPage();

      expect(
        await screen.findByText(/counts are of the controls this product maps/i),
      ).toBeInTheDocument();
    });

    it('states the mapped scope on each card', async () => {
      renderPage();

      expect(await screen.findByText('70 checks mapped to 61 controls')).toBeInTheDocument();
    });
  });

  describe('a framework nothing has decided', () => {
    it('shows a dash rather than nought per cent', async () => {
      // 0% reads as "everything failed". Nothing decided is a different fact.
      renderPage();

      const card = (await screen.findByRole('heading', { name: 'CERT-In' })).closest('section')!;
      expect(within(card).getByText('—')).toBeInTheDocument();
      expect(within(card).queryByText('0%')).toBeNull();
      expect(within(card).getByText(/nothing decided yet/)).toBeInTheDocument();
    });
  });

  describe('a control nothing evaluated', () => {
    it('says so instead of showing a row of zeroes', async () => {
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: /Show the 61 controls/ }));

      const row = (await screen.findByText('1.2.5')).closest('tr')!;
      expect(row).toHaveTextContent(/not evaluated on any device/);
      expect(row.className).toContain('control--unevaluated');
    });

    it('does not dress a genuinely passing control the same way', async () => {
      // The distinction the old table could not make: `0 failed` because everything
      // passed, versus `0 failed` because nothing ran.
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: /Show the 61 controls/ }));

      const row = (await screen.findByText('1.1.6')).closest('tr')!;
      expect(row.className).toContain('control--passing');
      expect(row).toHaveTextContent('407');
    });

    it('marks a failing control as failing', async () => {
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: /Show the 61 controls/ }));

      const row = (await screen.findByText('1.1.8')).closest('tr')!;
      expect(row.className).toContain('control--failing');
      expect(row).toHaveTextContent('940');
    });
  });

  describe('the control tables', () => {
    it('are not fetched until a card is opened', async () => {
      // The common visit is reading the headline figures and leaving; fetching six
      // control pivots for that would be the expensive half of the page done for
      // nothing.
      const get = vi.spyOn(api, 'get');
      renderPage();

      await screen.findByRole('heading', { name: 'CIS Benchmarks' });

      expect(get.mock.calls.map((call) => call[0])).toEqual(['/compliance/posture']);
    });

    it('are fetched once the card is opened', async () => {
      const get = vi.spyOn(api, 'get');
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: /Show the 61 controls/ }));

      await waitFor(() => {
        expect(get.mock.calls.map((call) => call[0])).toContain('/compliance/cis');
      });
    });

    it('offers no disclosure for a framework with no mapped controls', async () => {
      posture = [{ ...POSTURE[0], controls: 0 }];
      renderPage();

      expect(await screen.findByRole('button', { name: /Show the 0 controls/ })).toBeDisabled();
    });
  });

  describe('the breakdown opens in a dialog', () => {
    /** It expanded inside the card, and the cards are a grid — so a five-column table
     *  got a third of the page, the control names wrapped to four lines and the check
     *  ids truncated. The three figures the table exists for were the ones squeezed. */

    it('is a dialog rather than a region below the card', async () => {
      renderPage();
      const trigger = await screen.findByRole('button', { name: /Show the 61 controls/ });

      // `aria-haspopup`, and deliberately not `aria-expanded`: this reveals content
      // somewhere else, and `aria-expanded` would send a screen-reader user looking
      // underneath the button for a region that is not there.
      expect(trigger).toHaveAttribute('aria-haspopup', 'dialog');
      expect(trigger).not.toHaveAttribute('aria-expanded');

      await userEvent.click(trigger);

      expect(await screen.findByRole('dialog', { name: 'CIS Benchmarks controls' })).toBeInTheDocument();
    });

    it('repeats the card’s figures, because it covers the card', async () => {
      // Opening the breakdown must not cost the reader the number it breaks down.
      renderPage();
      await userEvent.click(await screen.findByRole('button', { name: /Show the 61 controls/ }));

      const dialog = await screen.findByRole('dialog');
      expect(within(dialog).getByRole('heading', { name: 'CIS Benchmarks' })).toBeInTheDocument();
      expect(
        within(dialog).getByText(/70 checks mapped to 61 controls, assessed on 650 devices/),
      ).toBeInTheDocument();
      expect(within(dialog).getByText('49%')).toBeInTheDocument();
    });

    it('says nothing has been decided rather than showing a percentage of nothing', async () => {
      // The same distinction the card makes. A framework with no verdicts has no
      // figure, and `0%` would report it as total failure.
      renderPage();
      await userEvent.click(await screen.findByRole('button', { name: /Show the 9 controls/ }));

      const dialog = await screen.findByRole('dialog');
      expect(within(dialog).getByText(/Nothing has produced a verdict yet/)).toBeInTheDocument();
      expect(within(dialog).queryByText('0%')).toBeNull();
    });

    it('is wide, because the truncation was the point', async () => {
      // The default width is a reading measure. A five-column table inside it is the
      // shape the dialog was opened to escape, so this one asks for the wide panel.
      renderPage();
      await userEvent.click(await screen.findByRole('button', { name: /Show the 61 controls/ }));

      expect(await screen.findByRole('dialog')).toHaveClass('modal__panel--wide');
    });

    it('closes, and puts focus back on the control that opened it', async () => {
      renderPage();
      const trigger = await screen.findByRole('button', { name: /Show the 61 controls/ });
      await userEvent.click(trigger);

      await userEvent.click(await screen.findByRole('button', { name: 'Close' }));

      expect(screen.queryByRole('dialog')).toBeNull();
      // Without this a keyboard user restarts at the top of the document, several
      // frameworks above the one they were reading.
      expect(trigger).toHaveFocus();
    });

    it('opens the framework that was asked for, not the first one', async () => {
      // Every card carries the same button label shape. A dialog keyed off the wrong
      // card would show a plausible table of somebody else's controls.
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: /Show the 9 controls/ }));

      expect(await screen.findByRole('dialog')).toHaveAccessibleName('CERT-In controls');
      await waitFor(() => {
        expect(vi.mocked(api.get).mock.calls.map((call) => call[0])).toContain(
          '/compliance/cert_in',
        );
      });
    });

    it('opens one framework at a time', async () => {
      // Each card owns its own open state. Two dialogs stacked would trap focus in
      // whichever mounted last and leave the other unreachable behind it.
      renderPage();
      await userEvent.click(await screen.findByRole('button', { name: /Show the 61 controls/ }));
      await screen.findByRole('dialog');

      expect(screen.getAllByRole('dialog')).toHaveLength(1);
    });
  });

  describe('a control with many checks', () => {
    /** Fifteen check ids joined by commas were wider than the screen, so the three
     *  figures the row exists for — passed, failed, not evaluated — were pushed off
     *  the right-hand edge, and reading them meant scrolling a table sideways. */

    async function openControls() {
      renderPage();
      await userEvent.click(await screen.findByRole('button', { name: /Show the 61 controls/ }));
      return (await screen.findByText('Access Control')).closest('tr')!;
    }

    it('shows only the first few, with the rest folded away', async () => {
      const row = await openControls();

      expect(within(row).getByText('aaa-control-check-number-1')).toBeInTheDocument();
      expect(within(row).getByText('aaa-control-check-number-8')).toBeInTheDocument();
      expect(within(row).queryByText('aaa-control-check-number-9')).toBeNull();
      expect(within(row).getByRole('button', { name: '+7 more' })).toBeInTheDocument();
    });

    it('keeps the figures beside them, which is what the row is for', async () => {
      // The regression this guards: the checks column grew until passed/failed/not
      // evaluated were off-screen.
      const row = await openControls();

      expect(row).toHaveTextContent('120');
      expect(row).toHaveTextContent('4');
    });

    it('shows all of them when asked, and folds them back', async () => {
      const row = await openControls();

      await userEvent.click(within(row).getByRole('button', { name: '+7 more' }));
      expect(within(row).getByText('aaa-control-check-number-15')).toBeInTheDocument();

      await userEvent.click(within(row).getByRole('button', { name: 'show fewer' }));
      expect(within(row).queryByText('aaa-control-check-number-15')).toBeNull();
    });

    it('gives each check its own element rather than one comma-run', async () => {
      // `a-b-c, d-e-f, g-h-i` reads as a single hyphenated string: the commas are lost
      // among the hyphens and there is no way to see where one id ends.
      const row = await openControls();

      const chips = within(row)
        .getAllByText(/^aaa-control-check-number-\d+$/)
        .map((element) => element.textContent);
      expect(chips).toEqual([
        'aaa-control-check-number-1',
        'aaa-control-check-number-2',
        'aaa-control-check-number-3',
        'aaa-control-check-number-4',
        'aaa-control-check-number-5',
        'aaa-control-check-number-6',
        'aaa-control-check-number-7',
        'aaa-control-check-number-8',
      ]);
    });

    it('folds nothing away for a control with only a few', async () => {
      renderPage();
      await userEvent.click(await screen.findByRole('button', { name: /Show the 61 controls/ }));

      const row = (await screen.findByText('1.1.8')).closest('tr')!;
      expect(within(row).queryByRole('button', { name: /more/ })).toBeNull();
      expect(within(row).getByText('cisco-login-block-for')).toBeInTheDocument();
    });
  });
});
