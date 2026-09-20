/** Sites, Device Groups and tags (FR-INV-03, FR-AUTH-05).
 *
 * Groups are what user scope, policy assignment and schedule coverage are all expressed
 * in, so the tests that matter are about the two ways this page could mislead: offering a
 * move the server will reject, and being quiet about what a move costs.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { OrganisationPage } from './OrganisationPage';
import { api } from '../api/client';

let granted = new Set(['device:read', 'device:write']);

vi.mock('../features/auth/useAuth', () => ({
  useAuth: () => ({ can: (permission: string) => granted.has(permission) }),
}));

const ROOT = {
  id: 'g1',
  name: 'europe',
  description: null,
  parent_id: null,
  path: 'g1',
  created_at: 'x',
};
const CHILD = {
  id: 'g2',
  name: 'london',
  description: null,
  parent_id: 'g1',
  path: 'g1.g2',
  created_at: 'x',
};
const OTHER = {
  id: 'g3',
  name: 'americas',
  description: null,
  parent_id: null,
  path: 'g3',
  created_at: 'x',
};

let groups: unknown[] = [];
let sites: unknown[] = [];
let tags: unknown[] = [];

/** The group list item for `name`.
 *
 * A group's name also appears as an option in the parent pickers, so a bare text query
 * matches several nodes. */
async function groupItem(name: string): Promise<HTMLElement> {
  await screen.findAllByText(name);
  const item = screen
    .getAllByText(name)
    .map((node) => node.closest('li'))
    .find((node): node is HTMLLIElement => node !== null);
  if (!item) throw new Error(`No group list item named ${name}`);
  return item;
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <OrganisationPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe('OrganisationPage', () => {
  beforeEach(() => {
    granted = new Set(['device:read', 'device:write']);
    groups = [ROOT, CHILD, OTHER];
    sites = [{ id: 's1', name: 'HQ', description: null, location: 'London' }];
    tags = [{ id: 't1', name: 'pci', colour: null }];
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/device-groups')) return groups as never;
      if (path.startsWith('/sites')) return sites as never;
      if (path.startsWith('/tags')) return tags as never;
      return [] as never;
    });
  });

  afterEach(() => vi.restoreAllMocks());

  describe('moving a group', () => {
    it('does not offer a group its own subtree as a new parent', async () => {
      // The server rejects a move into a descendant. Offering it would be an option whose
      // only outcome is an error message.
      renderPage();

      const row = await groupItem('europe');
      await userEvent.click(within(row).getByRole('button', { name: 'Move' }));

      const picker = screen.getByLabelText('New parent for europe');
      const options = within(picker)
        .getAllByRole('option')
        .map((option) => option.textContent);
      expect(options).not.toContain('europe');
      expect(options).not.toContain('london');
      expect(options).toContain('americas');
    });

    it('says a move rewrites every path beneath it', async () => {
      // It is not a cosmetic reorganisation: scoped visibility and policy assignments
      // resolve through those paths and follow the move.
      renderPage();

      expect(await screen.findByText(/rewrites every path beneath it/)).toBeInTheDocument();
    });

    it('sends the chosen parent', async () => {
      const put = vi.spyOn(api, 'put').mockResolvedValue(CHILD as never);
      renderPage();

      const row = await groupItem('london');
      await userEvent.click(within(row).getByRole('button', { name: 'Move' }));
      await userEvent.selectOptions(screen.getByLabelText('New parent for london'), 'g3');
      await userEvent.click(within(row).getByRole('button', { name: 'Move' }));

      expect(put).toHaveBeenCalledWith('/device-groups/g2/parent', { parent_id: 'g3' });
    });

    it('sends null to move a group to the top level', async () => {
      const put = vi.spyOn(api, 'put').mockResolvedValue(CHILD as never);
      renderPage();

      const row = await groupItem('london');
      await userEvent.click(within(row).getByRole('button', { name: 'Move' }));
      await userEvent.selectOptions(screen.getByLabelText('New parent for london'), '');
      await userEvent.click(within(row).getByRole('button', { name: 'Move' }));

      expect(put).toHaveBeenCalledWith('/device-groups/g2/parent', { parent_id: null });
    });
  });

  describe('what the absence of groups means', () => {
    it('says it, rather than showing an empty list', async () => {
      // "No groups" is not neutral: every scoped user sees nothing, because the scope
      // filter fails closed.
      groups = [];
      renderPage();

      expect(await screen.findByText(/every scoped user sees nothing/)).toBeInTheDocument();
    });
  });

  describe('sites', () => {
    it('sends the location, which used to be silently discarded', async () => {
      // `SiteCreate` accepted a location, `SiteRead` returned one, the column existed,
      // and the service never stored it.
      const post = vi.spyOn(api, 'post').mockResolvedValue(sites[0] as never);
      renderPage();

      await userEvent.type(await screen.findByLabelText('New site name'), 'DR');
      await userEvent.type(screen.getByLabelText('Site location'), 'Slough');
      await userEvent.click(screen.getByRole('button', { name: 'Create site' }));

      await waitFor(() =>
        expect(post).toHaveBeenCalledWith('/sites', { name: 'DR', location: 'Slough' }),
      );
    });

    it('shows the location it stored', async () => {
      renderPage();

      expect(await screen.findByText(/London/)).toBeInTheDocument();
    });
  });

  describe('tags', () => {
    it('lists them without offering to create one', async () => {
      // A tag exists by being applied to a device. An empty tag would be a name nothing
      // can use.
      renderPage();

      expect(await screen.findByText('pci')).toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /Create tag/ })).not.toBeInTheDocument();
    });
  });

  describe('without device:write', () => {
    it('shows the structure and offers no changes', async () => {
      granted = new Set(['device:read']);
      renderPage();

      await screen.findByText('europe');
      expect(screen.queryByRole('button', { name: 'Move' })).not.toBeInTheDocument();
      expect(screen.queryByLabelText('New group name')).not.toBeInTheDocument();
      expect(screen.queryByLabelText('New site name')).not.toBeInTheDocument();
    });
  });
});
