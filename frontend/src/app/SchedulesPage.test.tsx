/** Recurring assessments (FR-JOB-02).
 *
 * A cron expression is the easiest thing on this page to get wrong and the hardest to
 * notice — `0 2 * * 0` and `0 2 * * *` differ by one character and by a factor of seven.
 * So most of these are about whether the page shows what the expression *means* rather
 * than echoing what was typed.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { SchedulesPage } from './SchedulesPage';
import { api } from '../api/client';

let granted = new Set(['job:read', 'job:execute']);

vi.mock('../features/auth/useAuth', () => ({
  useAuth: () => ({ can: (permission: string) => granted.has(permission) }),
}));

const GROUP = { id: 'g1', name: 'north', description: null, parent_id: null, path: 'a' };

const SCHEDULE = {
  id: 's1',
  name: 'Nightly baseline',
  description: null,
  job_type: 'collect_and_assess',
  scope: { device_ids: [], group_ids: ['g1'], tags: [], include_archived: false },
  cron: '0 2 * * *',
  timezone: 'Europe/London',
  enabled: true,
  blackout: null,
  next_run_at: '2026-09-21T02:00:00Z',
  last_run_at: '2026-09-20T02:00:00Z',
  last_job_id: 'j1',
  created_at: '2026-09-01T00:00:00Z',
};

let schedules: unknown[] = [];

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <SchedulesPage />
    </QueryClientProvider>,
  );
}

describe('SchedulesPage', () => {
  beforeEach(() => {
    granted = new Set(['job:read', 'job:execute']);
    schedules = [SCHEDULE];
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/schedules')) return schedules as never;
      if (path.startsWith('/device-groups')) return [GROUP] as never;
      return [] as never;
    });
  });

  afterEach(() => vi.restoreAllMocks());

  describe('reading the list', () => {
    it('resolves the scope to group names rather than ids', async () => {
      renderPage();

      const row = (await screen.findByText('Nightly baseline')).closest('tr')!;
      await waitFor(() => expect(within(row).getByText('north')).toBeInTheDocument());
    });

    it('says the whole estate when the scope names nothing', async () => {
      // An empty scope is the widest one and does not look like it.
      schedules = [
        {
          ...SCHEDULE,
          scope: { device_ids: [], group_ids: [], tags: [], include_archived: false },
        },
      ];
      renderPage();

      expect(await screen.findByText('the whole estate')).toBeInTheDocument();
    });

    it('flags a schedule whose expression never fires', async () => {
      // The server computes next_run_at before storing the row. A null on an enabled
      // schedule means the cron parses and matches nothing — which otherwise looks
      // exactly like a schedule that is working.
      schedules = [{ ...SCHEDULE, next_run_at: null }];
      renderPage();

      expect(await screen.findByText(/check the expression/)).toBeInTheDocument();
    });

    it('does not claim a next run for a paused schedule', async () => {
      // A stored next_run_at survives pausing, and showing it would say the schedule is
      // about to fire when nothing will.
      schedules = [{ ...SCHEDULE, enabled: false }];
      renderPage();

      const row = (await screen.findByText('Nightly baseline')).closest('tr')!;
      expect(within(row).getAllByText('paused').length).toBeGreaterThan(0);
      expect(within(row).queryByText(/21\/09\/2026|9\/21\/2026/)).not.toBeInTheDocument();
    });

    it('says plainly when nothing is scheduled', async () => {
      schedules = [];
      renderPage();

      expect(await screen.findByText(/started by hand/)).toBeInTheDocument();
    });
  });

  describe('creating one', () => {
    it('sends the cron, the timezone and the selected groups', async () => {
      const post = vi.spyOn(api, 'post').mockResolvedValue(SCHEDULE as never);
      renderPage();

      await userEvent.type(await screen.findByLabelText('Schedule name'), 'Weekly');
      await userEvent.click(screen.getByLabelText('north'));
      await userEvent.click(screen.getByRole('button', { name: 'Weekly, Sunday at 02:00' }));
      await userEvent.click(screen.getByRole('button', { name: 'Create schedule' }));

      await waitFor(() =>
        expect(post).toHaveBeenCalledWith(
          '/schedules',
          expect.objectContaining({
            name: 'Weekly',
            cron: '0 2 * * 0',
            scope: expect.objectContaining({ group_ids: ['g1'] }),
          }),
        ),
      );
    });

    it('warns that an empty group selection means every device', async () => {
      renderPage();

      expect(await screen.findByText(/every device in the estate/)).toBeInTheDocument();
    });

    it('leaves cron as free text rather than only offering the presets', async () => {
      // Cron is the API's contract. A wrapper that hid it would make every expression the
      // product had not anticipated unreachable.
      const post = vi.spyOn(api, 'post').mockResolvedValue(SCHEDULE as never);
      renderPage();

      await userEvent.type(await screen.findByLabelText('Schedule name'), 'Odd');
      const cron = screen.getByLabelText('Cron expression');
      await userEvent.clear(cron);
      await userEvent.type(cron, '15 4 * * 1-5');
      await userEvent.click(screen.getByRole('button', { name: 'Create schedule' }));

      await waitFor(() =>
        expect(post).toHaveBeenCalledWith(
          '/schedules',
          expect.objectContaining({ cron: '15 4 * * 1-5' }),
        ),
      );
    });
  });

  describe('changing one', () => {
    it('pauses rather than deleting', async () => {
      const patch = vi.spyOn(api, 'patch').mockResolvedValue(SCHEDULE as never);
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Pause' }));

      expect(patch).toHaveBeenCalledWith('/schedules/s1', { enabled: false });
    });

    it('asks before removing', async () => {
      const remove = vi.spyOn(api, 'delete').mockResolvedValue(undefined as never);
      renderPage();

      await userEvent.click(await screen.findByRole('button', { name: 'Remove' }));
      expect(remove).not.toHaveBeenCalled();

      await userEvent.click(screen.getByRole('button', { name: 'Yes, remove' }));
      expect(remove).toHaveBeenCalledWith('/schedules/s1');
    });

    it('offers nothing without job:execute', async () => {
      // A schedule is a standing instruction to touch the estate; the server puts it
      // behind the same permission as running a job once.
      granted = new Set(['job:read']);
      renderPage();

      await screen.findByText('Nightly baseline');
      expect(screen.queryByRole('button', { name: 'Pause' })).not.toBeInTheDocument();
      expect(screen.queryByLabelText('Schedule name')).not.toBeInTheDocument();
    });
  });
});
