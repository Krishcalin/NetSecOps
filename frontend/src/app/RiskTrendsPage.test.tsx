/** Risk Trends — direction, closure priority and a letter per appliance.
 *
 * A grade is the most compressed claim this product makes, so most of what follows is
 * about what the page must *not* say:
 *
 * * A device nobody has assessed must not be graded. `A` calls it clean and `F` calls
 *   it broken; the truth is that nobody looked, and the page has to show that.
 * * The distribution must describe the estate, not the rows on screen — and when the
 *   table is cut short it has to say so.
 * * A nought in "overdue" must be readable. `due_at` is only ever set by hand, so it
 *   usually means nobody sets dates rather than nothing being late.
 * * The grid that assigns a priority must be the server's, rendered, so a reader can
 *   check a P1 rather than take it.
 *
 * Three panels use the same four codes — the buckets, the matrix, and the `worst`
 * column of the grade table — so every assertion about one of them is scoped to its
 * panel. An unscoped `getByText('P1')` matches three elements, and the version of
 * this file that did it was not testing the panel it named.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { RiskTrendsPage } from './RiskTrendsPage';
import { api } from '../api/client';

const BANDS = [
  { letter: 'A', floor: 0, ceiling: 4, meaning: 'Clean, or a single low-severity warning.' },
  { letter: 'B', floor: 5, ceiling: 14, meaning: 'A medium-severity failure.' },
  { letter: 'C', floor: 15, ceiling: 29, meaning: 'A high-severity failure.' },
  { letter: 'D', floor: 30, ceiling: 49, meaning: 'A critical failure.' },
  { letter: 'E', floor: 50, ceiling: 74, meaning: 'A critical failure on a device that matters.' },
  { letter: 'F', floor: 75, ceiling: 100, meaning: 'More than one critical failure.' },
];

const PRIORITY_BANDS = [
  { code: 'P1', label: 'Fix now', floor: 30, meaning: 'Any critical finding.' },
  { code: 'P2', label: 'Fix this cycle', floor: 12, meaning: 'Any high finding.' },
  { code: 'P3', label: 'Planned work', floor: 4, meaning: 'Any medium finding.' },
  { code: 'P4', label: 'Backlog', floor: 0, meaning: 'Low and informational findings.' },
];

const ESTATE = {
  days: 90,
  since: '2026-06-29',
  points: [
    { day: '2026-09-25', score: 60, grade: 'E', devices: 2, assessed: 1 },
    { day: '2026-09-26', score: 60, grade: 'E', devices: 2, assessed: 0 },
    { day: '2026-09-27', score: 40, grade: 'D', devices: 2, assessed: 1 },
  ],
  direction: 'improving',
  latest_score: 40,
  latest_grade: 'D',
};

const PRIORITIES = {
  buckets: [
    {
      code: 'P1',
      open: 3,
      devices: 2,
      oldest_first_seen: '2026-08-01T00:00:00Z',
      mean_age_days: 21.5,
      with_due_date: 0,
      overdue: 0,
    },
    {
      code: 'P2',
      open: 1,
      devices: 1,
      oldest_first_seen: '2026-09-23T00:00:00Z',
      mean_age_days: 4,
      with_due_date: 1,
      overdue: 1,
    },
    {
      code: 'P3',
      open: 0,
      devices: 0,
      oldest_first_seen: null,
      mean_age_days: null,
      with_due_date: 0,
      overdue: 0,
    },
    // Dated but not late — the third of the three states the panel has to tell
    // apart, and the one that makes "no due dates set" a claim rather than a default.
    {
      code: 'P4',
      open: 2,
      devices: 1,
      oldest_first_seen: '2026-09-20T00:00:00Z',
      mean_age_days: 3,
      with_due_date: 2,
      overdue: 0,
    },
  ],
  total_open: 6,
  bands: PRIORITY_BANDS,
  matrix: [
    { severity: 'critical', criticality: 'critical', weight: 60, priority: 'P1' },
    { severity: 'critical', criticality: 'low', weight: 32, priority: 'P1' },
    { severity: 'low', criticality: 'critical', weight: 4.5, priority: 'P3' },
    { severity: 'low', criticality: 'low', weight: 2.4, priority: 'P4' },
  ],
};

const GRADES = {
  devices: [
    {
      device_id: 'd1',
      hostname: 'edge-fw-01',
      mgmt_ip: '198.51.100.1',
      device_class: 'firewall',
      criticality: 'critical',
      score: 88,
      grade: 'F',
      assessed_at: '2026-09-27T09:00:00Z',
      open_findings: 3,
      worst_priority: 'P1',
    },
    {
      device_id: 'd2',
      hostname: null,
      mgmt_ip: '198.51.100.2',
      device_class: 'switch',
      criticality: 'low',
      score: null,
      grade: null,
      assessed_at: null,
      open_findings: 0,
      worst_priority: null,
    },
  ],
  total_devices: 2,
  by_grade: { F: 1, E: 0, D: 0, C: 0, B: 0, A: 0 },
  ungraded: 1,
  estate_score: 66,
  estate_grade: 'E',
  bands: BANDS,
};

const FINDINGS = {
  days: 90,
  since: '2026-06-29',
  points: [
    { day: '2026-09-26', first_seen: 2, resolved: 0, first_seen_by_severity: {} },
    { day: '2026-09-27', first_seen: 0, resolved: 1, first_seen_by_severity: {} },
  ],
  open_by_severity: { critical: 1 },
  reopened_now: 2,
  median_days_to_resolve: 12,
  mean_days_to_resolve: 18,
  resolved_in_window: 1,
  total_first_seen: 2,
  total_resolved: 1,
};

/** Reassigned per test so one case can change a payload without leaking into the
 *  next — these were `let`s restored by hand, which only works while the tests run
 *  in the order they are written in. */
let estate: unknown;
let priorities: unknown;
let grades: unknown;

function renderPage(path = '/risk-trends') {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <RiskTrendsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

/** The panel a heading names, once its own query has resolved.
 *
 * Both halves matter. Scoping, because the four priority codes appear in three
 * panels and `getByText('P1')` matches all of them. And the wait, because each panel
 * renders its frame immediately with a placeholder inside — so a helper that returned
 * as soon as the heading existed handed back an empty box, and every assertion made
 * against it failed for a reason that had nothing to do with what it was testing.
 */
async function panelFor(title: string): Promise<HTMLElement> {
  const heading = await screen.findByRole('heading', { name: title });
  const panel = heading.closest('.panel') as HTMLElement;

  await waitFor(() => expect(within(panel).queryByText(/^Loading/)).toBeNull());
  return panel;
}

describe('RiskTrendsPage', () => {
  beforeEach(() => {
    estate = ESTATE;
    priorities = PRIORITIES;
    grades = GRADES;

    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/risk/trend')) return estate as never;
      if (path.startsWith('/risk/priorities')) return priorities as never;
      if (path.startsWith('/risk/grades')) return grades as never;
      if (path.startsWith('/findings/trend')) return FINDINGS as never;
      throw new Error(`unexpected ${path}`);
    });
  });

  afterEach(() => vi.restoreAllMocks());

  describe('the estate trend', () => {
    it('prints both ends of the line, so no figure is estimated off it', async () => {
      renderPage();

      // The chart is the fast path, not the only one — a colour-blind reader and a
      // screen reader both get the same two numbers (WCAG 1.4.1).
      const panel = await panelFor('Estate risk over time');
      expect(within(panel).getByText(/^60 on/)).toBeInTheDocument();
      expect(within(panel).getByText(/^40 on/)).toBeInTheDocument();
    });

    it('names the direction rather than leaving it to the slope', async () => {
      // Risk counts down, so a falling line is good news and an arrow would be
      // ambiguous. The server names it, so a report and this page cannot disagree.
      renderPage();

      expect(await screen.findByText(/improving/)).toBeInTheDocument();
    });

    it('carries the population each figure was computed from', async () => {
      // A score from two devices and one from three hundred are not comparable.
      renderPage();

      expect(await screen.findByText(/across 2 assessed devices/)).toBeInTheDocument();
    });

    it('shows a dash when nothing has been closed, rather than nought days', async () => {
      // `median_days_to_resolve` is null when nothing in the window was resolved.
      // Nought would read as "everything is fixed the moment it is found", which is
      // the opposite of "nothing has been fixed".
      vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
        if (path.startsWith('/risk/trend')) return estate as never;
        if (path.startsWith('/risk/priorities')) return priorities as never;
        if (path.startsWith('/risk/grades')) return grades as never;
        return { ...FINDINGS, median_days_to_resolve: null } as never;
      });
      renderPage();

      const cell = (await screen.findByText('Median time to close')).closest(
        '.summary__cell',
      ) as HTMLElement;
      await waitFor(() => expect(within(cell).getByText('—')).toBeInTheDocument());
      expect(within(cell).queryByText(/0 days/)).not.toBeInTheDocument();
    });

    it('draws a falling line for a falling score', async () => {
      // Risk counts down and the axis puts 100 at the top, so an improving estate
      // slopes downwards. An inverted axis renders cleanly and makes every reader
      // misread the one chart on the page, which no other assertion here would see.
      renderPage();
      const panel = await panelFor('Estate risk over time');
      const line = panel.querySelector('polyline.riskline__line') as SVGPolylineElement;
      const ys = line
        .getAttribute('points')!
        .split(' ')
        .map((pair) => Number(pair.split(',')[1]));

      // 60, 60, then 40.
      expect(ys[1]).toBe(ys[0]);
      expect(ys[2]).toBeGreaterThan(ys[0]!);
    });

    it('draws a gap where there were no readings rather than a line across them', async () => {
      // A straight segment over the days nobody measured claims a value held that
      // nothing recorded. Two runs, so two polylines.
      estate = {
        ...ESTATE,
        points: [
          { day: '2026-09-24', score: 30, grade: 'D', devices: 1, assessed: 1 },
          { day: '2026-09-25', score: null, grade: null, devices: 1, assessed: 0 },
          { day: '2026-09-26', score: 20, grade: 'C', devices: 1, assessed: 1 },
        ],
      };
      renderPage();

      const panel = await panelFor('Estate risk over time');
      await waitFor(() =>
        expect(panel.querySelectorAll('polyline.riskline__line')).toHaveLength(2),
      );
    });

    it('says nothing has been assessed rather than drawing a clean estate', async () => {
      estate = {
        days: 90,
        since: '2026-06-29',
        points: [{ day: '2026-09-27', score: null, grade: null, devices: 0, assessed: 0 }],
        direction: 'unknown',
        latest_score: null,
        latest_grade: null,
      };
      renderPage();

      expect(
        await screen.findByText(/no score to plot.*not a score of zero/is),
      ).toBeInTheDocument();
    });
  });

  describe('closure priority', () => {
    it('shows all four bands, including the empty ones', async () => {
      // A band that vanishes when empty makes "no P1s" look like a rendering bug, and
      // moves the other three about between refreshes.
      renderPage();
      const panel = await panelFor('Closure priority');

      expect([...panel.querySelectorAll('.pband__code')].map((n) => n.textContent)).toEqual([
        'P1',
        'P2',
        'P3',
        'P4',
      ]);
    });

    it('takes each band’s name and meaning from the server', async () => {
      // Not from a copy here. A console that spelled out its own thresholds could say
      // P2 where `grading.py` said P1, and the copy is what a reader sees.
      renderPage();

      const panel = await panelFor('Closure priority');
      expect(within(panel).getByText('Fix now')).toBeInTheDocument();
      expect(within(panel).getByText('Any critical finding.')).toBeInTheDocument();
    });

    it('distinguishes nothing overdue from nobody setting due dates', async () => {
      renderPage();

      const panel = await panelFor('Closure priority');
      const bands = panel.querySelectorAll('.pband');

      // Three states, and the panel has to separate all three: no dates at all,
      // dates with one passed, and dates with none passed. A nought in "overdue"
      // means the last of those and is written as one.
      expect(within(bands[0] as HTMLElement).getByText(/No due dates set/)).toBeInTheDocument();
      expect(
        within(bands[1] as HTMLElement).getByText(/1 of 1 dated past due/),
      ).toBeInTheDocument();
      expect(
        within(bands[3] as HTMLElement).getByText(/0 of 2 dated past due/),
      ).toBeInTheDocument();
    });

    it('says an empty band is empty rather than showing it as nought days old', async () => {
      renderPage();

      const panel = await panelFor('Closure priority');
      const p3 = panel.querySelectorAll('.pband')[2] as HTMLElement;

      expect(within(p3).getByText('Nothing waiting.')).toBeInTheDocument();
      expect(within(p3).queryByText(/0 days/)).not.toBeInTheDocument();
    });

    it('renders the server’s grid so a priority can be checked', async () => {
      renderPage();

      const panel = await panelFor('Closure priority');
      const matrix = panel.querySelector('.matrix') as HTMLElement;

      // The weight as well as the band, so the reader can multiply the two numbers
      // themselves rather than taking the letter on trust.
      expect(within(matrix).getByText('60')).toBeInTheDocument();
      expect(within(matrix).getByText('2.4')).toBeInTheDocument();
      // Inside a disclosure, because it is an explanation rather than the answer —
      // and inside its own scroller, because five columns outgrow a phone and the
      // page body must never slide sideways.
      expect(matrix.closest('details')).not.toBeNull();
      expect(matrix.closest('.matrix-wrap')).not.toBeNull();
      expect(within(panel).getByText('How a priority is decided')).toBeInTheDocument();
    });
  });

  describe('grades', () => {
    it('leads with the worst device', async () => {
      renderPage();

      // Scoped to this panel: the priority matrix is also a table, and an unscoped
      // `findAllByRole('row')` returned its rows instead — which resolve first,
      // because they come from a different query.
      const rows = within(await panelFor('Devices by grade')).getAllByRole('row');

      expect(within(rows[1]!).getByText('edge-fw-01')).toBeInTheDocument();
      expect(within(rows[1]!).getByText('F')).toBeInTheDocument();
    });

    it('gives an unassessed device no letter at all', async () => {
      // The single most important thing on this page. `A` would call a device nobody
      // has collected from the healthiest thing in the estate.
      renderPage();

      const rows = within(await panelFor('Devices by grade')).getAllByRole('row');
      const unassessed = rows[2]!;

      expect(within(unassessed).getByText('not assessed')).toBeInTheDocument();
      expect(within(unassessed).getByText('never')).toBeInTheDocument();
      expect(within(unassessed).queryByText('A')).not.toBeInTheDocument();
      expect(within(unassessed).queryByText('F')).not.toBeInTheDocument();
      // The dash is a rendered thing, not merely the absence of a letter: asserting
      // only that no letter is present passes just as well when the pill is missing
      // altogether, and an empty cell in a grade column reads as a loading failure.
      expect(within(unassessed).getByTitle('Never assessed')).toHaveTextContent('—');
    });

    it('falls back to the management address when a device has no hostname', async () => {
      renderPage();

      expect(await screen.findByText('198.51.100.2')).toBeInTheDocument();
    });

    it('counts the ungraded separately rather than folding them into A', async () => {
      renderPage();

      const none = (await screen.findByText('no score')).closest('.spread__band') as HTMLElement;

      expect(within(none).getByText('1')).toBeInTheDocument();
      expect(within(none).getByText(/Never assessed/)).toBeInTheDocument();
    });

    it('takes the band meanings from the server rather than restating them', async () => {
      renderPage();

      expect(await screen.findByText('More than one critical failure.')).toBeInTheDocument();
      expect(screen.getByText('score 75–100')).toBeInTheDocument();
    });

    it('reads worst first, the way the table below it does', async () => {
      // The server sends the bands ascending, because that is the order they are
      // defined in. A distribution that opened on A would bury the F.
      const panel = await (renderPage(), panelFor('Devices by grade'));

      expect([...panel.querySelectorAll('.spread__letter')].map((n) => n.textContent)).toEqual([
        'F',
        'E',
        'D',
        'C',
        'B',
        'A',
        '—',
      ]);
    });

    it('says the estate grade is weighted rather than averaged', async () => {
      // The one figure on the page that could be mistaken for a mean, and the
      // distinction is the whole reason `roll_up` exists.
      renderPage();

      expect(await screen.findByText(/Weighted towards the worst device/)).toBeInTheDocument();
      expect(screen.getByText('66 / 100')).toBeInTheDocument();
    });

    it('says when the table is showing only the worst of a longer list', async () => {
      // Silent truncation on a page whose job is ranking would be a table that looks
      // like the estate and is the top of it.
      grades = { ...GRADES, total_devices: 140 };
      renderPage();

      expect(await screen.findByText(/worst 2 of 140 devices/)).toBeInTheDocument();
    });

    it('does not say so when the table is complete', async () => {
      renderPage();

      await waitFor(() => expect(screen.getByText('edge-fw-01')).toBeInTheDocument());
      expect(screen.queryByText(/Showing the worst/)).not.toBeInTheDocument();
    });
  });

  describe('filtering by appliance type', () => {
    it('asks the server for one class when the URL carries one', async () => {
      renderPage('/risk-trends?device_class=firewall');

      await waitFor(() =>
        expect(api.get).toHaveBeenCalledWith('/risk/grades?device_class=firewall'),
      );
      expect(api.get).toHaveBeenCalledWith('/risk/priorities?device_class=firewall');
    });

    it('names the filtered view in the heading', async () => {
      // A reader arriving from the sidebar is told what they are looking at, rather
      // than being shown a short table with no explanation for its shortness.
      renderPage('/risk-trends?device_class=firewall');

      expect(
        await screen.findByRole('heading', { name: 'Risk Trends — Firewalls' }),
      ).toBeInTheDocument();
    });

    it('leaves the estate trend unfiltered, because it is the whole estate', async () => {
      // Narrowing it would answer a different question under the same heading: the
      // roll-up of the firewalls is not "the estate's risk".
      renderPage('/risk-trends?device_class=firewall');

      await waitFor(() => expect(api.get).toHaveBeenCalledWith('/risk/trend?days=90'));
    });
  });

  it('keeps going when one panel fails', async () => {
    // Four independent reads. A page that renders nothing because the trend query
    // failed hides the grades, which are the part somebody can act on.
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/risk/trend')) throw new Error('boom');
      if (path.startsWith('/risk/priorities')) return priorities as never;
      if (path.startsWith('/risk/grades')) return grades as never;
      return FINDINGS as never;
    });
    renderPage();

    expect(await screen.findByText('The risk trend could not be loaded.')).toBeInTheDocument();
    expect(screen.getByText('edge-fw-01')).toBeInTheDocument();
  });
});
