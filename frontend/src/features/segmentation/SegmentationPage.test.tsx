/** The segmentation matrix page (FR-TOPO-07, TEST-05).
 *
 * This is the page somebody prints and signs, so every test here is a version of one
 * question: **can a reader mistake something for a pass that was not checked?**
 *
 * The three that matter: `unverified` is never coloured or worded as success, it is
 * counted in the summary beside the violations rather than tucked away, and an empty
 * policy says so instead of rendering an unblemished page.
 */

import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { SegmentationPage } from '../../app/SegmentationPage';
import type { Cell, Matrix } from './types';
import { STATUS_LABELS } from './types';

function cell(overrides: Partial<Cell> = {}): Cell {
  return {
    rule_id: `r-${Math.random()}`,
    source_zone: 'Production',
    destination_zone: 'Cardholder data',
    expectation: 'denied',
    protocol: 'tcp',
    port: 443,
    status: 'upheld',
    detail: 'Traffic is denied at edge-fw, as the policy requires.',
    justification: 'PCI DSS 1.2.1.',
    walked: ['10.10.0.0/24 → 10.20.0.0/24'],
    limitations: [],
    ...overrides,
  };
}

function matrix(overrides: Partial<Matrix> = {}): Matrix {
  return { cells: [], upheld: 0, violated: 0, unverified: 0, limitations: [], ...overrides };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': status >= 400 ? 'application/problem+json' : 'application/json' },
  });
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <SegmentationPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('SegmentationPage', () => {
  let payload: Matrix;

  beforeEach(() => {
    payload = matrix();
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        if (String(input).includes('/segmentation/matrix')) {
          return Promise.resolve(jsonResponse(payload));
        }
        return Promise.resolve(jsonResponse({}, 404));
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  describe('not verified is not a pass', () => {
    it('never gives an unverified cell the success tone', () => {
      // Asserted on the mapping rather than the DOM, because that is where the mistake
      // gets made. A plausible amber would keep every text assertion in this file
      // passing while making the cell read as "mostly fine".
      expect(STATUS_LABELS.unverified.tone).not.toBe(STATUS_LABELS.upheld.tone);
      expect(STATUS_LABELS.unverified.tone).not.toBe('success');
    });

    it('labels it in words, not by colour alone', async () => {
      payload = matrix({ cells: [cell({ status: 'unverified' })], unverified: 1 });
      renderPage();

      expect(await screen.findByText('Not verified')).toBeInTheDocument();
    });

    it('says outright that it is not a pass when the row is opened', async () => {
      payload = matrix({
        cells: [
          cell({
            status: 'unverified',
            detail: 'The path could not be traced far enough to say.',
          }),
        ],
        unverified: 1,
      });
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: /Production/ }));

      expect(screen.getByText(/This is not a pass/)).toBeInTheDocument();
    });

    it('counts it beside the violations rather than tucked under them', async () => {
      // A reader scanning for red takes the absence of it as a pass, and this is the
      // number that says otherwise.
      payload = matrix({ cells: [cell({ status: 'unverified' })], unverified: 3, upheld: 1 });
      renderPage();

      const stat = (await screen.findByText('not verified')).closest('.stat');
      expect(within(stat as HTMLElement).getByText('3')).toBeInTheDocument();
    });
  });

  describe('the list', () => {
    it('puts violations first, then unverified, then upheld', async () => {
      // The page is read top-down and the rows needing action should be where a
      // reader stops scrolling.
      payload = matrix({
        cells: [
          cell({ rule_id: 'a', source_zone: 'AAA', status: 'upheld' }),
          cell({ rule_id: 'b', source_zone: 'BBB', status: 'unverified' }),
          cell({ rule_id: 'c', source_zone: 'CCC', status: 'violated' }),
        ],
        upheld: 1,
        unverified: 1,
        violated: 1,
      });
      renderPage();

      const rows = await screen.findAllByRole('listitem');
      const zones = rows.map((row) => row.textContent?.match(/[A-Z]{3}/)?.[0]);
      expect(zones).toEqual(['CCC', 'BBB', 'AAA']);
    });

    it('shows what was actually walked, so upheld has a stated scope', async () => {
      payload = matrix({
        cells: [cell({ walked: ['10.10.0.0/24 → 10.20.0.0/24'] })],
        upheld: 1,
      });
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: /Production/ }));

      expect(screen.getByText('10.10.0.0/24 → 10.20.0.0/24')).toBeInTheDocument();
    });

    it('carries the justification, so a cell can be argued with', async () => {
      payload = matrix({ cells: [cell({ justification: 'Required by PCI DSS 1.2.1.' })] });
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: /Production/ }));

      expect(screen.getByText('Required by PCI DSS 1.2.1.')).toBeInTheDocument();
    });
  });

  describe('an empty policy', () => {
    it('says nothing has been declared rather than rendering a clean page', async () => {
      // Zero violations out of zero rules is the most misleading thing this page
      // could show, because it is indistinguishable from a compliant estate.
      payload = matrix({
        limitations: ['No segmentation policy has been declared, so there is nothing to check.'],
      });
      renderPage();

      expect(await screen.findByText(/An empty matrix is not a clean one/)).toBeInTheDocument();
    });

    it('repeats the limitations the server sent', async () => {
      payload = matrix({
        cells: [cell()],
        upheld: 1,
        limitations: ['2 of 3 cells could not be verified. Those are not passes.'],
      });
      renderPage();

      expect(await screen.findByText(/Those are not passes/)).toBeInTheDocument();
    });
  });
});
