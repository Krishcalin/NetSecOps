/** The settings page (FR-ADM-01, FR-INT-01).
 *
 * Two properties, both about what the page refuses to do. It must never render a
 * channel's secret — the API does not return one, and a page that invented somewhere to
 * show it would be the hole — and it must show deliveries that gave up, because an alert
 * nobody received is exactly what somebody goes looking for afterwards.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
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

let subscriptions: Record<string, unknown>[] = [];
let roleMap: Record<string, unknown> = {
  mappings: [],
  mappable_roles: ['auditor', 'network_engineer', 'security_analyst'],
};

describe('SettingsPage', () => {
  beforeEach(() => {
    subscriptions = [];
    roleMap = {
      mappings: [],
      mappable_roles: ['auditor', 'network_engineer', 'security_analyst'],
    };
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/auth/sso/role-map')) return roleMap as never;
      if (path.startsWith('/notifications/subscriptions')) return subscriptions as never;
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

    // Scoped to the channel table: the name also appears in the subscriptions panel's
    // warning about channels nothing is subscribed to, which is the point of both.
    await waitFor(() => expect(screen.getAllByText('ops-slack').length).toBeGreaterThan(0));
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

    // `getAllByRole`: the page now carries a second status region, for enabled
    // channels that nothing is subscribed to.
    await waitFor(() =>
      expect(
        screen
          .getAllByRole('status')
          .some((el) => /gave up after repeated failures/.test(el.textContent ?? '')),
      ).toBe(true),
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

  describe('what each channel is told', () => {
    /** The gap this closed: the subscription endpoints had no surface at all, so on a
     *  console-only deployment a channel could be created, tested, shown healthy — and
     *  never told anything, with nothing on the page saying why. */

    it('warns that an enabled channel nothing is subscribed to is silent', async () => {
      renderPage();

      await waitFor(() =>
        expect(
          screen
            .getAllByRole('status')
            .some((el) => /no\s+subscription/.test(el.textContent ?? '')),
        ).toBe(true),
      );
    });

    it('stops warning once the channel is subscribed', async () => {
      subscriptions = [
        {
          id: '33333333-3333-3333-3333-333333333333',
          channel_id: CHANNEL.id,
          event_kinds: ['vuln.kev_matched'],
          min_severity: 'high',
          enabled: true,
        },
      ];
      renderPage();

      await waitFor(() =>
        expect(screen.getByText(/Known-exploited CVE matched/)).toBeInTheDocument(),
      );
      // `queryAllByRole`, not `getAllByRole`: the latter throws when there are none,
      // which is one of the outcomes this is asserting is acceptable.
      expect(
        screen
          .queryAllByRole('status')
          .some((el) => /no\s+subscription/.test(el.textContent ?? '')),
      ).toBe(false);
    });

    it('says the severity is a floor rather than an exact match', async () => {
      // "medium" meaning "medium and worse" is the thing somebody discovers from an
      // alert that never arrived, so the row states it.
      subscriptions = [
        {
          id: '44444444-4444-4444-4444-444444444444',
          channel_id: CHANNEL.id,
          event_kinds: [],
          min_severity: 'medium',
          enabled: true,
        },
      ];
      renderPage();

      // Scoped to the table: the form's severity options each say "and worse" too,
      // which is the same promise made in the place where the choice is offered.
      const table = await screen.findByRole('table', { name: /Event subscriptions/ });
      await waitFor(() => expect(within(table).getByText(/and worse/)).toBeInTheDocument());
    });

    it('spells out that no chosen events means every kind', async () => {
      subscriptions = [
        {
          id: '55555555-5555-5555-5555-555555555555',
          channel_id: CHANNEL.id,
          event_kinds: [],
          min_severity: 'info',
          enabled: true,
        },
      ];
      renderPage();

      // An empty cell would read as "nothing", which is the opposite of what it means.
      await waitFor(() => expect(screen.getByText('every kind')).toBeInTheDocument());
    });

    it('offers a subscription form built from the real event vocabulary', async () => {
      renderPage();

      await waitFor(() => expect(screen.getByRole('button', { name: 'Subscribe' })).toBeDisabled());
      // Not a free-text box: an event kind the backend does not know is a subscription
      // that silently matches nothing.
      expect(screen.getByLabelText('Assessment failed')).toBeInTheDocument();
      expect(screen.getByLabelText('Configuration drift')).toBeInTheDocument();
    });
  });

  describe('channel management', () => {
    it('offers disable as well as remove', async () => {
      // Silencing a noisy channel for an afternoon should not require deleting it and
      // re-entering the secret, which is the only other way back.
      renderPage();

      await waitFor(() =>
        expect(screen.getByRole('button', { name: 'Disable' })).toBeInTheDocument(),
      );
      expect(screen.getByRole('button', { name: 'Remove' })).toBeInTheDocument();
    });

    it('patches the channel rather than recreating it', async () => {
      const patch = vi.spyOn(api, 'patch').mockResolvedValue({} as never);
      renderPage();

      await waitFor(() => screen.getByRole('button', { name: 'Disable' }));
      (await screen.findByRole('button', { name: 'Disable' })).click();

      await waitFor(() => expect(patch).toHaveBeenCalled());
      expect(patch.mock.calls[0]?.[0]).toContain(CHANNEL.id);
      expect(patch.mock.calls[0]?.[1]).toEqual({ enabled: false });
    });
  });

  describe('the single sign-on role map (FR-AUTH-04)', () => {
    it('says plainly that an empty mapping changes nobody', async () => {
      // The state every deployment starts in. An empty table with no explanation reads
      // as "not loaded yet" or "broken", and the honest answer — signing in leaves
      // roles exactly as an administrator set them — is the one somebody needs.
      renderPage();

      expect(await screen.findByText(/No groups are mapped/i)).toBeInTheDocument();
    });

    it('offers only the roles the server says may be granted', async () => {
      // Super Admin is refused by the API. Finding that out from a dropdown that never
      // offered it beats finding it out from a save that comes back rejected.
      renderPage();

      await screen.findByText(/No groups are mapped/i);
      fireEvent.click(await screen.findByRole('button', { name: 'Add mapping' }));

      const select = await screen.findByLabelText('Role 1');
      const offered = within(select).getAllByRole('option').map((o) => o.textContent);
      expect(offered).toEqual(['Auditor', 'Network Engineer', 'Security Analyst']);
      expect(offered).not.toContain('Super Admin');
    });

    it('sends the whole mapping, not a single row', async () => {
      // It is read as a set at every sign-in; a partial update would leave a window in
      // which somebody signs in against half of it.
      roleMap = {
        mappings: [{ group: 'net-admins', role: 'network_engineer' }],
        mappable_roles: ['auditor', 'network_engineer', 'security_analyst'],
      };
      const put = vi.spyOn(api, 'put').mockResolvedValue(roleMap as never);
      renderPage();

      // Wait for the stored mapping to arrive: until it does, "Add mapping" is
      // disabled, because the roles it may offer come from the same response.
      await screen.findByDisplayValue('net-admins');
      fireEvent.click(await screen.findByRole('button', { name: 'Add mapping' }));
      const group = await screen.findByLabelText('Group 2');
      fireEvent.change(group, { target: { value: 'audit-ro' } });
      fireEvent.click(await screen.findByRole('button', { name: 'Save mapping' }));

      await waitFor(() => expect(put).toHaveBeenCalled());
      expect(put.mock.calls[0]?.[1]).toEqual({
        mappings: [
          { group: 'net-admins', role: 'network_engineer' },
          { group: 'audit-ro', role: 'auditor' },
        ],
      });
    });

    it('will not save until something has been edited', async () => {
      // Otherwise the obvious way to confirm the page loaded is to press Save, which
      // rewrites the authorization policy and writes an audit entry saying so.
      renderPage();

      await screen.findByText(/No groups are mapped/i);
      expect(await screen.findByRole('button', { name: 'Save mapping' })).toBeDisabled();
    });

    it('says that a change takes effect at the next sign-in, not now', async () => {
      // The mapping is applied during authentication. Somebody who reads "Saved" and
      // expects a colleague's permissions to have changed already will be wrong.
      const put = vi.spyOn(api, 'put').mockResolvedValue(roleMap as never);
      renderPage();

      await screen.findByText(/No groups are mapped/i);
      fireEvent.click(await screen.findByRole('button', { name: 'Add mapping' }));
      fireEvent.click(await screen.findByRole('button', { name: 'Save mapping' }));

      await waitFor(() => expect(put).toHaveBeenCalled());
      expect(await screen.findByText(/next sign-in/i)).toBeInTheDocument();
    });
  });
});
