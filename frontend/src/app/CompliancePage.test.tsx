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
});
