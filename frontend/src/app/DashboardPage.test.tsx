/** The front door (FR-RPT-01).
 *
 * The page this replaced rendered a card headed "What is not here yet" listing phases
 * that had since shipped — the landing page of a working product telling every visitor
 * it was unfinished. These tests are mostly about the two properties that make the
 * replacement worth having.
 *
 * **A tile's link must reproduce the tile's number.** A count that drops you at the top
 * of an unfiltered list is the placeholder problem again in a smarter costume, so the
 * hrefs are asserted against the filters the target pages actually read.
 *
 * **An empty estate is not six zeroes.** Nought critical findings on a fleet nobody has
 * collected from is true and useless, and reads as a broken install. The checklist
 * replaces it — and each step ticks from a real count, never from an assumption about
 * what the operator has already done.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { DashboardPage } from './DashboardPage';
import { api } from '../api/client';

const ALL = [
  'device:read',
  'credential:read',
  'job:read',
  'finding:read',
  'vuln:read',
  'audit:read',
  'report:read',
  'snapshot:read',
  'policy:read',
];

let permissions: string[] = ALL;

vi.mock('../features/auth/useAuth', () => ({
  useAuth: () => ({
    user: {
      username: 'ops',
      roles: ['analyst'],
      permissions,
      mfa_enabled: true,
      unrestricted_scope: true,
      device_group_ids: [],
    },
  }),
}));

/** Counts keyed by the path each query asks for. */
let counts: Record<string, number> = {};
let compliancePercent: number | null = 78.4;
let segmentationCells: { rule_id: string }[] = [{ rule_id: 'r1' }];
let recentJobs: { id: string; kind: string; status: string; created_at: string }[] = [
  { id: 'j1', kind: 'assessment', status: 'succeeded', created_at: '2026-09-20T10:00:00Z' },
];

let trend: Record<string, unknown> = {
  days: 90,
  since: '2026-07-01',
  points: [
    { day: '2026-09-25', first_seen: 3, resolved: 0, first_seen_by_severity: {} },
    { day: '2026-09-26', first_seen: 0, resolved: 0, first_seen_by_severity: {} },
    { day: '2026-09-27', first_seen: 1, resolved: 4, first_seen_by_severity: {} },
  ],
  open_by_severity: { critical: 1, high: 2, medium: 0, low: 0, info: 0 },
  reopened_now: 2,
  median_days_to_resolve: 6.5,
  mean_days_to_resolve: 40.2,
  resolved_in_window: 4,
  total_first_seen: 4,
  total_resolved: 4,
};

/** The estate risk roll-up the front page now draws beside the tiles.
 *
 * Declared here rather than left to the catch-all at the bottom of `stubApi`, which
 * answers `{data, meta}` to anything it does not recognise. That stub satisfied
 * `trend !== undefined` and carried no `points`, and the chart threw on it — taking
 * every other panel on the page down with it, which is how a missing branch here turned
 * into nineteen unrelated failures.
 */
let estateRisk: Record<string, unknown> = {
  days: 90,
  since: '2026-07-01',
  points: [
    { day: '2026-09-25', score: 41, grade: 'D', devices: 42, assessed: 3 },
    { day: '2026-09-26', score: 38, grade: 'D', devices: 42, assessed: 0 },
    { day: '2026-09-27', score: 26, grade: 'C', devices: 42, assessed: 5 },
  ],
  direction: 'improving',
  latest_score: 26,
  latest_grade: 'C',
};

function stubApi() {
  vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
    if (path.startsWith('/risk/trend')) {
      return estateRisk as never;
    }
    if (path === '/vulnerabilities/summary') {
      return {
        total: 9,
        by_severity: {},
        by_confidence: { confirmed: 4 },
        kev_count: 2,
        devices_affected: 3,
        devices_unassessed: 7,
      } as never;
    }
    if (path.startsWith('/findings/trend')) {
      return trend as never;
    }
    if (path === '/audit-log/verify') {
      return { total: 120, valid: true } as never;
    }
    if (path === '/findings/summary') {
      // Derived from the same `counts` the list stub serves, so the strip and the
      // tiles cannot drift apart in the fixture the way they used to on the wire.
      const bySeverity = Object.fromEntries(
        (['critical', 'high', 'medium', 'low', 'info'] as const).map((severity) => [
          severity,
          counts[`/findings?severity=${severity}&limit=1`] ?? 0,
        ]),
      );
      return {
        total: Object.values(bySeverity).reduce((sum, n) => sum + n, 0),
        by_severity: bySeverity,
        by_status: { open: 0 },
        devices_affected: 3,
      } as never;
    }
    if (path === '/compliance/cis') {
      return { framework: 'cis', device_count: 42, compliance_percent: compliancePercent } as never;
    }
    if (path === '/topology/summary') {
      return {
        devices: 42,
        devices_with_routes: 40,
        devices_without_route_data: 2,
        devices_with_rulebase: 6,
        routes: 900,
        unmanaged_next_hops: 3,
      } as never;
    }
    if (path === '/segmentation/matrix') {
      return {
        cells: segmentationCells,
        upheld: 4,
        violated: 1,
        unverified: 2,
        limitations: [],
      } as never;
    }
    if (path.startsWith('/jobs?limit=5')) {
      return { items: recentJobs, meta: { total: recentJobs.length } } as never;
    }
    const total = counts[path] ?? 0;
    return { data: [], meta: { total } } as never;
  });
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const POPULATED = {
  '/devices?limit=1': 42,
  '/credentials?limit=1': 3,
  '/jobs?limit=1': 11,
  '/findings?severity=critical&limit=1': 5,
  '/findings?severity=high&limit=1': 18,
  '/findings?limit=1': 60,
};

describe('DashboardPage', () => {
  beforeEach(() => {
    permissions = ALL;
    counts = { ...POPULATED };
    trend = {
      days: 90,
      since: '2026-07-01',
      points: [
        { day: '2026-09-25', first_seen: 3, resolved: 0, first_seen_by_severity: {} },
        { day: '2026-09-26', first_seen: 0, resolved: 0, first_seen_by_severity: {} },
        { day: '2026-09-27', first_seen: 1, resolved: 4, first_seen_by_severity: {} },
      ],
      open_by_severity: { critical: 1, high: 2, medium: 0, low: 0, info: 0 },
      reopened_now: 2,
      median_days_to_resolve: 6.5,
      mean_days_to_resolve: 40.2,
      resolved_in_window: 4,
      total_first_seen: 4,
      total_resolved: 4,
    };
    estateRisk = {
      days: 90,
      since: '2026-07-01',
      points: [
        { day: '2026-09-25', score: 41, grade: 'D', devices: 42, assessed: 3 },
        { day: '2026-09-26', score: 38, grade: 'D', devices: 42, assessed: 0 },
        { day: '2026-09-27', score: 26, grade: 'C', devices: 42, assessed: 5 },
      ],
      direction: 'improving',
      latest_score: 26,
      latest_grade: 'C',
    };
    compliancePercent = 78.4;
    segmentationCells = [{ rule_id: 'r1' }];
    recentJobs = [
      { id: 'j1', kind: 'assessment', status: 'succeeded', created_at: '2026-09-20T10:00:00Z' },
    ];
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        json: async () => ({ status: 'ok', version: '1.0.0', environment: 'test' }),
      })),
    );
    stubApi();
  });

  it('no longer tells the reader the product is unfinished', async () => {
    renderPage();
    await screen.findByRole('link', { name: /Critical findings/ });

    expect(screen.queryByText(/What is not here yet/i)).toBeNull();
  });

  it('links each count to the filter that produced it', async () => {
    renderPage();

    const critical = await screen.findByRole('link', { name: /Critical findings/ });
    expect(critical).toHaveAttribute('href', '/findings?severity=critical');

    expect(screen.getByRole('link', { name: /High findings/ })).toHaveAttribute(
      'href',
      '/findings?severity=high',
    );
    expect(screen.getByRole('link', { name: /Known exploited/ })).toHaveAttribute(
      'href',
      '/vulnerabilities?kev=true',
    );
    expect(screen.getByRole('link', { name: /Confirmed matches/ })).toHaveAttribute(
      'href',
      '/vulnerabilities?confidence=confirmed',
    );
  });

  it('shows the counts it was given', async () => {
    // Waited for rather than read once: a tile renders as soon as its link exists and
    // fills in when its query lands, so asserting immediately races the fetch.
    renderPage();

    await waitFor(() =>
      expect(screen.getByRole('link', { name: /Critical findings/ })).toHaveTextContent('5'),
    );
    expect(screen.getByRole('link', { name: /High findings/ })).toHaveTextContent('18');
    // From the single summary call, not from a per-tile request.
    expect(screen.getByRole('link', { name: /Known exploited/ })).toHaveTextContent('2');
    expect(screen.getByRole('link', { name: /Confirmed matches/ })).toHaveTextContent('4');
  });

  it('surfaces devices never assessed beside the counts', async () => {
    // The number that stops an empty vulnerability table reading as good news.
    renderPage();

    await waitFor(() =>
      expect(screen.getByRole('link', { name: /Never assessed/ })).toHaveTextContent('7'),
    );
  });

  it('shows a dash, not a zero, while a count is still loading', async () => {
    // The distinction this codebase keeps insisting on. An unloaded tile must not
    // render "0 critical findings", which is the most reassuring possible lie.
    renderPage();

    expect(screen.getByRole('link', { name: /Critical findings/ })).toHaveTextContent('—');
    await waitFor(() =>
      expect(screen.getByRole('link', { name: /Critical findings/ })).toHaveTextContent('5'),
    );
  });

  it('keeps the audit chain on the front page', async () => {
    renderPage();

    expect(await screen.findByText('Verified')).toBeInTheDocument();
  });

  it('hides tiles the reader has no permission to open', async () => {
    permissions = ['device:read'];
    renderPage();

    await screen.findByRole('link', { name: /Devices/ });
    expect(screen.queryByRole('link', { name: /Critical findings/ })).toBeNull();
    expect(screen.queryByRole('link', { name: /Known exploited/ })).toBeNull();
  });

  describe('the graphics', () => {
    it('draws compliance, which is the only score this product actually has', async () => {
      renderPage();

      // Not a "posture score" blended out of finding counts. This figure has a
      // referent — the percentage of CIS checks that were actually decided.
      expect(await screen.findByText('78%')).toBeInTheDocument();
      expect(screen.getByText(/neither half/i)).toBeInTheDocument();
    });

    it('shows a dash rather than nought per cent when nothing has been evaluated', async () => {
      // The whole page hangs on this distinction. A 0% ring asserts that everything
      // failed; the truth is that nothing was decided, which is the opposite claim.
      compliancePercent = null;
      renderPage();

      // Asserted through the dial's own text alternative rather than by looking for a
      // dash: unloaded tiles render dashes too, and matching any of them would pass
      // whatever the dial did.
      expect(await screen.findByText(/No CIS check has been evaluated yet/)).toBeInTheDocument();
      expect(screen.queryByText('0%')).toBeNull();
    });

    it('gives the severity bar a text alternative carrying the counts', async () => {
      // The bar is the fast path, never the only one: a reader must not have to
      // estimate a value off a coloured segment (WCAG 1.4.1).
      renderPage();

      await waitFor(() =>
        expect(screen.getByRole('img', { name: /5 critical/ })).toBeInTheDocument(),
      );
      expect(screen.getByRole('img', { name: /18 high/ })).toBeInTheDocument();
    });

    it('prints every severity and its count beside the bar', async () => {
      // The legend is the part that survives greyscale, a colour-blind reader and a
      // printed board pack. Without it the bar is five widths of colour and nothing
      // else — which is exactly what the accessible name alone does not fix, because
      // sighted readers never hear it.
      const { container } = renderPage();
      await screen.findByRole('link', { name: /Critical findings/ });

      const legend = await waitFor(() => {
        const found = container.querySelector('.stackbar__key');
        expect(found?.textContent).toContain('critical');
        return found!;
      });
      // Visible, not merely present. `textContent` reads straight through `hidden`,
      // so a legend that had been hidden would satisfy every string assertion below
      // while showing a sighted reader five bare widths of colour.
      expect(legend).toBeVisible();
      for (const word of ['critical', 'high', 'medium', 'low', 'info']) {
        expect(legend.textContent).toContain(word);
      }
      // And the numbers, not just the words: a legend of five labels all reading zero
      // would pass a word-only assertion while saying nothing.
      expect(legend.textContent).toContain('5');
      expect(legend.textContent).toContain('18');
    });

    it('says outright that unverified segmentation pairs are not passes', async () => {
      renderPage();

      expect(await screen.findByText(/That is not a pass/)).toBeInTheDocument();
    });

    it('marks every icon decorative, so nothing is announced twice', async () => {
      const { container } = renderPage();
      await screen.findByRole('link', { name: /Critical findings/ });

      const icons = container.querySelectorAll('svg');
      expect(icons.length).toBeGreaterThan(0);
      for (const icon of icons) {
        expect(icon).toHaveAttribute('aria-hidden', 'true');
      }
    });

    it('names the estate figures rather than only drawing them', async () => {
      renderPage();

      expect(await screen.findByText('Unmanaged next hops')).toBeInTheDocument();
      await waitFor(() => expect(screen.getByText('900')).toBeInTheDocument());
    });
  });

  describe('an empty estate', () => {
    beforeEach(() => {
      counts = {
        '/devices?limit=1': 0,
        '/credentials?limit=1': 0,
        '/jobs?limit=1': 0,
        '/findings?limit=1': 0,
        '/findings?severity=critical&limit=1': 0,
        '/findings?severity=high&limit=1': 0,
      };
    });

    it('gives instructions rather than a wall of zeroes', async () => {
      renderPage();

      expect(await screen.findByRole('heading', { name: 'Start here' })).toBeInTheDocument();
      expect(screen.queryByRole('link', { name: /Critical findings/ })).toBeNull();
    });

    it('ticks off only the steps the counts actually evidence', async () => {
      counts['/credentials?limit=1'] = 2;
      renderPage();

      const done = await screen.findByRole('heading', { name: /Add a credential/ });
      expect(done).toHaveTextContent('done');
      // The next step has not happened, and the page does not imply it has.
      expect(screen.getByRole('heading', { name: /Add a device/ })).not.toHaveTextContent('done');
    });

    it('says done in words, not only in colour', async () => {
      // A state carried by a green tick alone is a state a screen reader never reports.
      counts['/credentials?limit=1'] = 1;
      renderPage();

      await waitFor(() =>
        expect(screen.getByRole('heading', { name: /Add a credential/ })).toHaveTextContent(/done/),
      );
    });

    it('does not offer the checklist to someone who simply cannot see devices', async () => {
      // An empty device list means "none visible to you" for a scoped reader, which is
      // a different sentence from "the estate is empty".
      permissions = ['finding:read', 'vuln:read'];
      renderPage();

      await screen.findByRole('link', { name: /Critical findings/ });
      expect(screen.queryByRole('heading', { name: 'Start here' })).toBeNull();
    });
  });

  describe('whether it is getting better (FR-FIND-05)', () => {
    /** Every other figure on this page is a level. None of them can tell an estate
     *  sitting at forty criticals for a year from one that was at four hundred in
     *  January, and that is the difference anybody actually wants. */

    it('reports the median time to resolve, not the mean', async () => {
      // One finding open since March drags an average somewhere no finding has been.
      renderPage();

      expect(await screen.findByText('6.5 days')).toBeInTheDocument();
      expect(screen.queryByText('40.2 days')).toBeNull();
    });

    it('shows a dash rather than zero when nothing has been resolved', async () => {
      // Zero days reads as "fixed instantly", which is the opposite of "no data".
      trend = { ...trend, median_days_to_resolve: null, resolved_in_window: 0 };
      renderPage();

      expect(await screen.findByText(/nothing resolved in this window/)).toBeInTheDocument();
    });

    it('says how many came back, because the resolved bars cannot see them', async () => {
      // A reopened finding's earlier resolution is gone from the row, so the series
      // under-reports. Saying so beats a quietly wrong chart.
      renderPage();

      const cameBack = await screen.findByText('Came back');
      // `waitFor`: the panel renders its labels before the query resolves, so reading
      // the value straight away catches the placeholder dash rather than the figure.
      await waitFor(() => expect(cameBack.parentElement).toHaveTextContent('2'));
      expect(cameBack.parentElement).toHaveTextContent(/not counted as resolved/);
    });

    it('draws no per-day open count, which the schema cannot support', async () => {
      // Reopening clears `resolved_at`, so that curve would show every
      // fixed-and-returned problem as open throughout.
      renderPage();

      await screen.findByText('6.5 days');
      const chart = screen.getByRole('img', { name: /first seen and .* resolved/i });
      expect(chart).not.toHaveAccessibleName(/open/i);
    });

    it('carries the totals in text, so the chart survives greyscale', async () => {
      // WCAG 1.4.1 — nothing on this page is coloured without also being counted.
      renderPage();

      // Scoped to the chart's own caption: "4 resolved" also appears in the readout
      // note below it ("median of 4 resolved"), which is the same fact said twice and
      // would make an unscoped query ambiguous rather than wrong.
      const caption = (await screen.findByText(/4 first seen/)).parentElement;
      expect(caption).toHaveTextContent(/4 first seen/);
      expect(caption).toHaveTextContent(/4 resolved/);
    });

    it('says an empty window means no assessments, not a clean estate', async () => {
      trend = { ...trend, total_first_seen: 0, total_resolved: 0 };
      renderPage();

      expect(
        await screen.findByText(
          /assessments have not run yet rather than that the estate is clean/,
        ),
      ).toBeInTheDocument();
    });

    it('does not claim the window is empty while it is still loading', async () => {
      // This page's rule is that a figure which could not be computed shows a dash,
      // never a zero. The same applies to a sentence: "nothing was found or fixed" is
      // a statement about the estate, and flashing it before the data arrives asserts
      // something untrue for as long as the request takes.
      let release: (value: unknown) => void = () => {};
      const pending = new Promise((resolve) => {
        release = resolve;
      });
      const get = vi.spyOn(api, 'get');
      const passthrough = get.getMockImplementation();
      get.mockImplementation(async (path: string) => {
        if (path.startsWith('/findings/trend')) return (await pending) as never;
        return passthrough!(path);
      });

      renderPage();
      await screen.findByRole('heading', { name: 'Ninety days' });
      expect(screen.queryByText(/Nothing was found or fixed/)).toBeNull();

      release({ ...trend, total_first_seen: 0, total_resolved: 0, points: [] });
      expect(await screen.findByText(/Nothing was found or fixed/)).toBeInTheDocument();
    });

    it('is not shown to someone who cannot read findings', async () => {
      permissions = ['device:read'];
      renderPage();

      await waitFor(() => {
        expect(screen.queryByRole('heading', { name: 'Ninety days' })).toBeNull();
      });
    });
  });

  describe('estate risk beside the counts', () => {
    it('draws the line and names both ends in text', async () => {
      renderPage();

      // Awaited on the *content*, not on the heading: the card renders its header while
      // the query is still in flight, so finding the heading proves only that the panel
      // mounted.
      //
      // The figures are printed as well as plotted, so the chart survives greyscale
      // and nobody reads a score off the slope (WCAG 1.4.1).
      expect(await screen.findByText(/41 on/)).toBeInTheDocument();
      expect(screen.getByText(/26 on/)).toBeInTheDocument();
      expect(screen.getByRole('img', { name: /Estate risk from 41/ })).toBeInTheDocument();
    });

    it('shows the grade and the direction in words', async () => {
      renderPage();

      // Risk counts down, so a falling line is good news and neither a colour nor an
      // arrow says which way is which without being read.
      expect(await screen.findByText('improving')).toBeInTheDocument();
      expect(screen.getByText('C')).toBeInTheDocument();
    });

    it('links to the page it is a summary of', async () => {
      renderPage();
      await screen.findByRole('heading', { name: 'Estate risk' });

      expect(screen.getByRole('link', { name: 'Risk trends' })).toHaveAttribute(
        'href',
        '/risk-trends',
      );
    });

    it('shows a dash for an unassessed estate, never a nought', async () => {
      // Zero on this scale is a clean estate. A fleet nobody has looked at must not
      // borrow the best score in the product.
      estateRisk = {
        days: 90,
        since: '2026-07-01',
        points: [{ day: '2026-09-27', score: null, grade: null, devices: 0, assessed: 0 }],
        direction: 'unknown',
        latest_score: null,
        latest_grade: null,
      };
      renderPage();

      expect(await screen.findByText(/nothing has looked/)).toBeInTheDocument();

      // Scoped to this panel. A bare `queryByText('0')` also catches the severity bar's
      // empty bands elsewhere on the page, which are real zeroes and entirely correct.
      const panel = screen.getByRole('heading', { name: 'Estate risk' }).closest('.card')!;
      expect(within(panel as HTMLElement).queryByText('0')).toBeNull();
      expect(within(panel as HTMLElement).getAllByText('—').length).toBeGreaterThan(0);
    });

    it('survives a response with no points rather than taking the page with it', async () => {
      // One chart throwing unmounts every panel beside it. The catch-all API stub
      // produced exactly this shape and did precisely that, so the guard is real.
      estateRisk = {};
      renderPage();

      expect(await screen.findByRole('heading', { name: 'Estate risk' })).toBeInTheDocument();
      // The rest of the page is still there, which is the actual assertion.
      expect(screen.getByRole('link', { name: /Critical findings/ })).toBeInTheDocument();
    });

    it('is not shown to someone who cannot read findings', async () => {
      permissions = ['device:read'];
      renderPage();

      await waitFor(() => {
        expect(screen.queryByRole('heading', { name: 'Estate risk' })).toBeNull();
      });
    });
  });
});
