/** Cancelling and re-running a job from the console (FR-JOB-03).
 *
 * `POST /jobs/{id}/cancel` shipped with the job engine and had no control anywhere in
 * the UI: the page rendered `cancelling` and `cancelled` as status pills with nothing
 * able to produce them. A collection sweeping five hundred devices could be started
 * from the console and not stopped from it.
 *
 * So these are mostly about *when* the buttons appear. A cancel offered on a finished
 * job is a 409 the operator did not need to see, and one withheld from a running job is
 * the original defect.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { JobsPage } from './JobsPage';
import { api } from '../api/client';
import type { Job, JobStatus } from '../features/inventory/types';

const ALLOWED = new Set(['job:read', 'job:execute']);
let granted = ALLOWED;

vi.mock('../features/auth/useAuth', () => ({
  useAuth: () => ({ can: (permission: string) => granted.has(permission) }),
}));

function job(overrides: Partial<Job> & { id: string; status: JobStatus }): Job {
  return {
    job_type: 'collect_and_assess',
    scope: {},
    stats: { total: 3, succeeded: 3, failed: 0 },
    requested_by_id: null,
    started_at: '2026-09-19T09:00:00Z',
    finished_at: null,
    error_message: null,
    created_at: '2026-09-19T09:00:00Z',
    ...overrides,
  } as Job;
}

let rows: Job[] = [];

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <JobsPage />
    </QueryClientProvider>,
  );
}

describe('JobsPage', () => {
  beforeEach(() => {
    granted = ALLOWED;
    vi.spyOn(api, 'get').mockImplementation(
      async () => ({ data: rows, meta: { total: rows.length } }) as never,
    );
  });

  afterEach(() => vi.restoreAllMocks());

  describe('cancel', () => {
    it('offers to cancel a running job', async () => {
      rows = [job({ id: 'a', status: 'running', stats: { total: 3, succeeded: 1, failed: 0 } })];
      renderPage();

      await waitFor(() => expect(screen.getByText('Cancel')).toBeInTheDocument());
    });

    it.each<JobStatus>(['queued', 'paused'])('offers to cancel a %s job', async (status) => {
      rows = [job({ id: 'a', status })];
      renderPage();

      await waitFor(() => expect(screen.getByText('Cancel')).toBeInTheDocument());
    });

    it.each<JobStatus>(['succeeded', 'failed', 'cancelled', 'partial'])(
      'does not offer to cancel a %s job',
      async (status) => {
        // The API rejects these with 409. A button that can only produce an error is
        // worse than no button.
        rows = [job({ id: 'a', status, stats: { total: 3, succeeded: 3, failed: 0 } })];
        renderPage();

        await waitFor(() => expect(screen.getByText('Details')).toBeInTheDocument());
        expect(screen.queryByText('Cancel')).not.toBeInTheDocument();
      },
    );

    it('does not offer to cancel a job that is already cancelling', async () => {
      // The request is in and the devices in flight are finishing. A second button
      // would offer an action that changes nothing.
      rows = [job({ id: 'a', status: 'cancelling' })];
      renderPage();

      await waitFor(() => expect(screen.getByText('Details')).toBeInTheDocument());
      expect(screen.queryByText('Cancel')).not.toBeInTheDocument();
    });

    it('posts the cancel', async () => {
      rows = [job({ id: 'abc', status: 'running' })];
      const post = vi.spyOn(api, 'post').mockResolvedValue({} as never);
      renderPage();

      await waitFor(() => expect(screen.getByText('Cancel')).toBeInTheDocument());
      await userEvent.click(screen.getByText('Cancel'));

      expect(post).toHaveBeenCalledWith('/jobs/abc/cancel');
    });

    it('reports a cancel that the API refused', async () => {
      // The job finished while the list was on screen. Without this the button appears
      // to do nothing at all.
      rows = [job({ id: 'abc', status: 'running' })];
      vi.spyOn(api, 'post').mockRejectedValue(new Error('Job is already succeeded.'));
      renderPage();

      await waitFor(() => expect(screen.getByText('Cancel')).toBeInTheDocument());
      await userEvent.click(screen.getByText('Cancel'));

      await waitFor(() =>
        expect(screen.getByRole('alert')).toHaveTextContent('Job is already succeeded.'),
      );
    });
  });

  describe('re-run failed', () => {
    it('offers to re-run when devices failed', async () => {
      rows = [job({ id: 'a', status: 'partial', stats: { total: 3, succeeded: 2, failed: 1 } })];
      renderPage();

      await waitFor(() => expect(screen.getByText('Re-run failed')).toBeInTheDocument());
    });

    it('does not offer to re-run when nothing failed', async () => {
      // `JobService.rerun_failed` raises a conflict when there is nothing to re-run.
      rows = [job({ id: 'a', status: 'succeeded', stats: { total: 3, succeeded: 3, failed: 0 } })];
      renderPage();

      await waitFor(() => expect(screen.getByText('Details')).toBeInTheDocument());
      expect(screen.queryByText('Re-run failed')).not.toBeInTheDocument();
    });

    it('posts the re-run', async () => {
      rows = [job({ id: 'abc', status: 'failed', stats: { total: 1, succeeded: 0, failed: 1 } })];
      const post = vi.spyOn(api, 'post').mockResolvedValue({} as never);
      renderPage();

      await waitFor(() => expect(screen.getByText('Re-run failed')).toBeInTheDocument());
      await userEvent.click(screen.getByText('Re-run failed'));

      expect(post).toHaveBeenCalledWith('/jobs/abc/rerun-failed');
    });
  });

  describe('permissions', () => {
    it('offers neither action without job:execute', async () => {
      // Both endpoints require JOB_EXECUTE. A reader seeing buttons that always 403 is
      // a worse experience than not seeing them.
      granted = new Set(['job:read']);
      rows = [job({ id: 'a', status: 'running', stats: { total: 3, succeeded: 1, failed: 1 } })];
      renderPage();

      await waitFor(() => expect(screen.getByText('Details')).toBeInTheDocument());
      expect(screen.queryByText('Cancel')).not.toBeInTheDocument();
      expect(screen.queryByText('Re-run failed')).not.toBeInTheDocument();
    });
  });
});
