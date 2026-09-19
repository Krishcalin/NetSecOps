/** Loading the advisory catalogue from the console (FR-VUL-07, FR-VUL-08).
 *
 * Both feed routes shipped with Phase 6 and neither had a control. The page's own empty
 * state told the operator to "import an NVD, CSAF or end-of-life bundle to begin" and
 * offered no way to do it, so the catalogue could only be populated with a REST client.
 *
 * That gap costs more now than it did: the matcher runs after every collection, and an
 * empty catalogue turns each one into a confident-looking clean result rather than an
 * obviously broken one.
 *
 * Rendered through the page rather than in isolation, because the permission gate is
 * half of what is under test.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { VulnerabilitiesPage } from '../../app/VulnerabilitiesPage';
import { api, request } from '../../api/client';

let granted = new Set(['vuln:read', 'vuln:write']);

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ can: (permission: string) => granted.has(permission) }),
}));

// `request` is mocked rather than spied because the upload goes through the exported
// function directly. `api.get` and `api.post` keep their real bodies and are spied on
// per test — they close over the module's own `request`, not this mock, so the two do
// not interfere.
vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>();
  return { ...actual, request: vi.fn() };
});

const SUMMARY = {
  total: 0,
  by_severity: {},
  by_confidence: {},
  kev_count: 0,
  devices_affected: 0,
  devices_unassessed: 0,
};

/** Render, and open the feed section — it is collapsed until asked for. */
async function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const result = render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <VulnerabilitiesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );

  await userEvent.click(await screen.findByText('Feed status'));
  return result;
}

async function chooseBundle(name = 'nvd.json') {
  const input = screen.getByLabelText('Feed bundle');
  await userEvent.upload(
    input,
    new File(['{"vulnerabilities":[]}'], name, {
      type: 'application/json',
    }),
  );
}

describe('feed controls', () => {
  beforeEach(() => {
    granted = new Set(['vuln:read', 'vuln:write']);
    vi.mocked(request).mockReset();
    vi.mocked(request).mockResolvedValue({
      feed: 'nvd',
      kind: 'nvd',
      status: 'succeeded',
      advisories_ingested: 1,
      cves_ingested: 1,
      eol_records_ingested: 0,
      kev_entries_ingested: 0,
      epss_scores_ingested: 0,
      records_rejected: 0,
    } as never);
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/vulnerabilities/summary')) return SUMMARY as never;
      if (path.startsWith('/vulnerabilities/feeds')) return [] as never;
      return { data: [], meta: { total: 0 } } as never;
    });
  });

  afterEach(() => vi.restoreAllMocks());

  describe('permission', () => {
    it('offers no feed controls without vuln:write', async () => {
      // A reader seeing an import button that always 403s is worse than not seeing one.
      granted = new Set(['vuln:read']);
      await renderPage();

      await waitFor(() => expect(screen.getByText(/No feed has ever been imported/)).toBeVisible());
      expect(screen.queryByText('Import bundle')).not.toBeInTheDocument();
      expect(screen.queryByText('Sync from publishers')).not.toBeInTheDocument();
    });

    it('offers them with vuln:write', async () => {
      await renderPage();
      await waitFor(() => expect(screen.getByText('Import bundle')).toBeInTheDocument());
      expect(screen.getByText('Sync from publishers')).toBeInTheDocument();
    });
  });

  describe('import', () => {
    it('will not import before a bundle is chosen', async () => {
      await renderPage();
      await waitFor(() => expect(screen.getByText('Import bundle')).toBeDisabled());
    });

    it('uploads the bundle with its source label', async () => {
      const post = vi.mocked(request);
      await renderPage();

      await waitFor(() => expect(screen.getByText('Import bundle')).toBeInTheDocument());
      await chooseBundle();
      await userEvent.click(screen.getByText('Import bundle'));

      await waitFor(() => expect(post).toHaveBeenCalled());
      const [path, options] = post.mock.calls[0]!;
      expect(path).toContain('/vulnerabilities/feeds/import?');
      expect(path).toContain('feed=manual');
      expect(options?.body).toBeInstanceOf(FormData);
      // Sent raw: a multipart body JSON-encoded by the client would arrive as a string.
      expect(options?.rawBody).toBe(true);
    });

    it('passes a digest to be verified when one is given', async () => {
      const post = vi.mocked(request);
      await renderPage();

      await waitFor(() => expect(screen.getByText('Import bundle')).toBeInTheDocument());
      await userEvent.type(screen.getByLabelText('Expected SHA-256'), 'a'.repeat(64));
      await chooseBundle();
      await userEvent.click(screen.getByText('Import bundle'));

      await waitFor(() => expect(post).toHaveBeenCalled());
      expect(post.mock.calls[0]![0]).toContain(`expected_sha256=${'a'.repeat(64)}`);
    });

    it('omits vendor and product when they are blank', async () => {
      // They apply only to end-of-life bundles. Sending empty strings would have the
      // API treat them as given and file the cycles under a vendor named "".
      const post = vi.mocked(request);
      await renderPage();

      await waitFor(() => expect(screen.getByText('Import bundle')).toBeInTheDocument());
      await chooseBundle();
      await userEvent.click(screen.getByText('Import bundle'));

      await waitFor(() => expect(post).toHaveBeenCalled());
      expect(post.mock.calls[0]![0]).not.toContain('vendor=');
      expect(post.mock.calls[0]![0]).not.toContain('product=');
    });

    it('reports what was rejected alongside what loaded', async () => {
      // A bundle that loaded most of its advisories has left part of the estate
      // unjudged, and a result that shows only the successes reads as complete.
      vi.mocked(request).mockResolvedValue({
        feed: 'nvd',
        kind: 'nvd',
        status: 'partial',
        advisories_ingested: 90,
        cves_ingested: 90,
        eol_records_ingested: 0,
        kev_entries_ingested: 0,
        epss_scores_ingested: 0,
        records_rejected: 10,
      } as never);

      await renderPage();
      await waitFor(() => expect(screen.getByText('Import bundle')).toBeInTheDocument());
      await chooseBundle();
      await userEvent.click(screen.getByText('Import bundle'));

      await waitFor(() =>
        expect(screen.getByRole('status')).toHaveTextContent(/10 records could not be read/),
      );
    });

    it('surfaces a refusal rather than appearing to succeed', async () => {
      // The end-of-life case: the API refuses without a vendor rather than guessing
      // whose lifecycle dates it is holding.
      vi.mocked(request).mockRejectedValue(
        new Error('An end-of-life bundle lists release cycles but does not say whose.'),
      );

      await renderPage();
      await waitFor(() => expect(screen.getByText('Import bundle')).toBeInTheDocument());
      await chooseBundle('endoflife.json');
      await userEvent.click(screen.getByText('Import bundle'));

      await waitFor(() =>
        expect(screen.getByRole('alert')).toHaveTextContent(/does not say whose/),
      );
    });
  });

  describe('sync', () => {
    it('queues a sync and says where to watch it', async () => {
      const post = vi.spyOn(api, 'post').mockResolvedValue({ id: 'job-1' } as never);
      await renderPage();

      await waitFor(() => expect(screen.getByText('Sync from publishers')).toBeInTheDocument());
      await userEvent.click(screen.getByText('Sync from publishers'));

      expect(post).toHaveBeenCalledWith('/vulnerabilities/feeds/sync');
      await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(/queued/));
    });

    it('reports a sync the API refused', async () => {
      // Offline mode (C-7) refuses this, and the refusal is the point: an air-gapped
      // deployment must not be left thinking a sync is running.
      vi.spyOn(api, 'post').mockRejectedValue(new Error('Feed sync is disabled in offline mode.'));
      await renderPage();

      await waitFor(() => expect(screen.getByText('Sync from publishers')).toBeInTheDocument());
      await userEvent.click(screen.getByText('Sync from publishers'));

      await waitFor(() =>
        expect(screen.getByRole('alert')).toHaveTextContent(/disabled in offline mode/),
      );
    });
  });
});
