/** The settings page (FR-ADM-01, FR-INT-01).
 *
 * Two properties, both about what the page refuses to do. It must never render a
 * channel's secret — the API does not return one, and a page that invented somewhere to
 * show it would be the hole — and it must show deliveries that gave up, because an alert
 * nobody received is exactly what somebody goes looking for afterwards.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { SettingsPage } from './SettingsPage';
import { api } from '../api/client';

const CHANNEL = {
  id: '11111111-1111-1111-1111-111111111111',
  name: 'ops-slack',
  channel_type: 'slack',
  enabled: true,
  config: { workspace: 'ops' },
  has_secret: true,
  last_success_at: null,
  last_failure_at: '2026-09-18T10:00:00Z',
  last_error: 'Slack returned HTTP 404.',
};

const DEAD_DELIVERY = {
  id: '22222222-2222-2222-2222-222222222222',
  channel_id: CHANNEL.id,
  event_kind: 'vuln.kev_matched',
  severity: 'critical',
  title: 'KEV match on core-sw-01',
  status: 'dead',
  attempts: 5,
  next_attempt_at: null,
  sent_at: null,
  last_error: 'Slack returned HTTP 404.',
};

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <SettingsPage />
    </QueryClientProvider>,
  );
}

describe('SettingsPage', () => {
  beforeEach(() => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/notifications/channels')) return [CHANNEL] as never;
      if (path.startsWith('/notifications/deliveries')) return [DEAD_DELIVERY] as never;
      if (path.startsWith('/settings')) {
        return [
          {
            key: 'integrations.siem.watermark.audit',
            value: { at: 42 },
            description: 'Managed automatically.',
            managed: true,
          },
        ] as never;
      }
      return [] as never;
    });
  });

  afterEach(() => vi.restoreAllMocks());

  it('reports that a secret is stored without showing one', async () => {
    renderPage();

    await waitFor(() => expect(screen.getByText('ops-slack')).toBeInTheDocument());
    expect(screen.getByText('stored')).toBeInTheDocument();
    // There is no field on the channel that could carry it, and no element that shows it.
    expect(screen.queryByText(/hooks\.slack/)).not.toBeInTheDocument();
  });

  it('shows a channel that has been failing', async () => {
    // A channel quietly failing since somebody rotated a password is the case this
    // column exists for.
    renderPage();
    await waitFor(() => expect(screen.getByText('failing')).toBeInTheDocument());
  });

  it('warns that a notification gave up and was never received', async () => {
    renderPage();

    await waitFor(() =>
      expect(screen.getByRole('status')).toHaveTextContent(/gave up after repeated failures/),
    );
    expect(screen.getByText('KEV match on core-sw-01')).toBeInTheDocument();
  });

  it('offers to retry only the deliveries that gave up', async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText('Try again')).toBeInTheDocument());
  });

  it('marks a managed setting rather than offering to edit it', async () => {
    // Editing a watermark by hand silently skips or repeats part of the forwarded
    // stream, so the page says it is managed rather than presenting an input.
    //
    // Waits on the *key*, not on the word "managed": that word also appears in the
    // section's explanatory sentence, so waiting for it resolves immediately against the
    // hint and the assertion below then runs before the settings query has returned.
    // The first version of this test failed for exactly that reason.
    renderPage();

    await waitFor(() =>
      expect(screen.getByText('integrations.siem.watermark.audit')).toBeInTheDocument(),
    );

    // "managed" appears twice — once in the explanatory sentence, once as the badge on
    // the row. The badge is the one under test.
    const badges = screen.getAllByText('managed').filter((el) => el.classList.contains('badge'));
    expect(badges).toHaveLength(1);
  });
});
