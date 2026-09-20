/** The check library and its two question surfaces (FR-CHK-04, FR-CHK-06).
 *
 * The tests that matter most are about what a preview promises. "Run it and see" is only
 * a safe offer if running it genuinely writes nothing, and the page says so in as many
 * words — so the claim has to be in the page and the call has to be the one that keeps it.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { ChecksPage } from './ChecksPage';
import { api } from '../api/client';

let granted = new Set(['check:read', 'check:write']);

vi.mock('../features/auth/useAuth', () => ({
  useAuth: () => ({ can: (permission: string) => granted.has(permission) }),
}));

const CHECK = {
  id: 'ssh-version-2',
  title: 'SSH is restricted to version 2',
  severity: 'high',
  description: 'The device does not accept SSH version 1.',
  tags: ['ssh'],
  logic_type: 'ncm',
  vendors: ['cisco'],
  platforms: ['cisco_ios'],
  frameworks: { nist_800_53: ['AC-17'] },
  enabled_by_default: true,
  is_custom: false,
};

const LOW_CHECK = {
  ...CHECK,
  id: 'banner-present',
  title: 'A login banner is configured',
  severity: 'low',
  platforms: ['panos'],
  frameworks: {},
};

const DETAIL = {
  ...CHECK,
  rationale: 'Version 1 is broken.',
  remediation: 'ip ssh version 2',
  device_classes: [],
  references: {},
  version: 1,
  expression: 'management.ssh.version',
};

const DEVICE = { id: 'd1', mgmt_ip: '10.0.0.1', hostname: 'core-sw-01' };

let checks: unknown[] = [];

/** The library renders one Details button per row, so a bare `findByRole` matches
 *  several. The first is the high-severity check the page sorts to the top. */
async function firstDetailsButton(): Promise<HTMLElement> {
  await screen.findByText('SSH is restricted to version 2');
  return screen.getAllByRole('button', { name: 'Details' })[0]!;
}

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ChecksPage />
    </QueryClientProvider>,
  );
}

describe('ChecksPage', () => {
  beforeEach(() => {
    granted = new Set(['check:read', 'check:write']);
    checks = [LOW_CHECK, CHECK];
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.startsWith('/checks/')) return DETAIL as never;
      if (path.startsWith('/checks')) return checks as never;
      if (path.startsWith('/devices')) return { data: [DEVICE], meta: { total: 1 } } as never;
      return { data: [], meta: { total: 0 } } as never;
    });
  });

  afterEach(() => vi.restoreAllMocks());

  describe('the library', () => {
    it('orders by severity, not by whatever the API returned', async () => {
      // The API sorts by id, which puts a low-severity banner check above a high-severity
      // one. Somebody scanning the list reads the top as the important end.
      renderPage();

      await screen.findByText('SSH is restricted to version 2');
      const titles = screen
        .getAllByRole('row')
        .slice(1)
        .map((row) => within(row).getAllByRole('cell')[0]?.textContent ?? '');
      expect(titles[0]).toContain('SSH is restricted to version 2');
    });

    it('shows what a check actually looks at', async () => {
      // "What exactly did this inspect" is the first question asked about a finding, and
      // the answer used to be available only by reading the source tree.
      renderPage();

      await userEvent.click(await firstDetailsButton());

      expect(await screen.findByText('management.ssh.version')).toBeInTheDocument();
      expect(screen.getByRole('listitem')).toHaveTextContent('nist_800_53 — AC-17');
    });

    it('marks a check that is off by default', async () => {
      // A check in the library and in no assessment is invisible everywhere else.
      checks = [{ ...CHECK, enabled_by_default: false }];
      renderPage();

      expect(await screen.findByText('off by default')).toBeInTheDocument();
    });

    it('filters by platform through the API, not in the browser', async () => {
      // The registry decides applicability, including version ranges and required
      // features a summary does not carry. Filtering here would disagree with it.
      const get = vi.spyOn(api, 'get');
      renderPage();

      await screen.findByText('SSH is restricted to version 2');
      await userEvent.selectOptions(screen.getByLabelText('Platform'), 'panos');

      await waitFor(() =>
        expect(get).toHaveBeenCalledWith(expect.stringContaining('platform=panos')),
      );
    });
  });

  describe('previewing', () => {
    it('says the preview wrote nothing', async () => {
      vi.spyOn(api, 'post').mockResolvedValue({
        check_id: 'ssh-version-2',
        outcome: 'fail',
        severity: 'high',
        message: 'SSH version 1 is accepted.',
        reason: null,
        evidence: {},
      } as never);
      renderPage();

      await userEvent.click(await firstDetailsButton());
      await screen.findByLabelText('Device to check');
      await userEvent.selectOptions(screen.getByLabelText('Device to check'), 'd1');
      await userEvent.click(screen.getByRole('button', { name: 'Run it' }));

      expect(await screen.findByText(/Nothing was written/)).toBeInTheDocument();
      expect(screen.getByText(/SSH version 1 is accepted/)).toBeInTheDocument();
    });

    it('will not run a check without a device to run it against', async () => {
      renderPage();

      await userEvent.click(await firstDetailsButton());

      expect(await screen.findByRole('button', { name: 'Run it' })).toBeDisabled();
    });
  });

  describe('asking the estate', () => {
    it('says how many devices could not be asked', async () => {
      // Without this line, a short result list reads as "nothing in my estate does this"
      // when it may mean "most of my estate has never been collected from".
      vi.spyOn(api, 'post').mockResolvedValue({
        expression: 'management.ssh.version',
        devices_considered: 10,
        devices_not_evaluated: 7,
        rows: [
          {
            device_id: 'd1',
            hostname: 'core-sw-01',
            platform: 'cisco_ios',
            value: 2,
            not_evaluated: null,
          },
        ],
      } as never);
      renderPage();

      await userEvent.type(await screen.findByLabelText('Expression'), 'management.ssh.version');
      await userEvent.click(screen.getByRole('button', { name: 'Run query' }));

      expect(await screen.findByText(/7 could not be asked/)).toBeInTheDocument();
    });

    it('shows a device that could not answer, rather than dropping it', async () => {
      vi.spyOn(api, 'post').mockResolvedValue({
        expression: 'x',
        devices_considered: 1,
        devices_not_evaluated: 1,
        rows: [
          {
            device_id: 'd2',
            hostname: 'never-collected',
            platform: null,
            value: null,
            not_evaluated: 'No configuration has been collected from this device.',
          },
        ],
      } as never);
      renderPage();

      await userEvent.type(await screen.findByLabelText('Expression'), 'x');
      await userEvent.click(screen.getByRole('button', { name: 'Run query' }));

      expect(await screen.findByText('never-collected')).toBeInTheDocument();
      expect(screen.getByText(/No configuration has been collected/)).toBeInTheDocument();
    });
  });

  describe('drafting a check', () => {
    it('catches bad JSON in the browser rather than sending it', async () => {
      // A parse error is the author's typo, and the server's answer to it would be less
      // specific than the one the browser already has.
      const post = vi.spyOn(api, 'post');
      renderPage();

      const editor = await screen.findByLabelText('Definition');
      await userEvent.clear(editor);
      await userEvent.type(editor, '{{not json');
      await userEvent.selectOptions(screen.getByLabelText('Device to draft against'), 'd1');
      await userEvent.click(screen.getByRole('button', { name: 'Preview' }));

      expect(post).not.toHaveBeenCalled();
      expect(await screen.findByText(/not valid JSON/)).toBeInTheDocument();
    });

    it('previews the definition in the request, without saving it first', async () => {
      // The whole point: the trail of half-finished checks the dry run avoided in
      // findings had simply moved into the library.
      const post = vi.spyOn(api, 'post').mockResolvedValue({
        check_id: 'custom-ssh-version-2',
        outcome: 'pass',
        severity: 'high',
        message: 'ok',
        reason: null,
        evidence: {},
      } as never);
      renderPage();

      // The select renders before its options arrive, so waiting on the label alone
      // races the device query.
      await screen.findByRole('option', { name: 'core-sw-01' });
      await userEvent.selectOptions(screen.getByLabelText('Device to draft against'), 'd1');
      await userEvent.click(screen.getByRole('button', { name: 'Preview' }));

      expect(post).toHaveBeenCalledWith(
        '/checks/preview',
        expect.objectContaining({ device_id: 'd1' }),
      );
      expect(post).not.toHaveBeenCalledWith('/checks', expect.anything());
    });

    it('is not offered without check:write', async () => {
      granted = new Set(['check:read']);
      renderPage();

      await screen.findByText('SSH is restricted to version 2');
      expect(screen.queryByLabelText('Definition')).not.toBeInTheDocument();
      // The query surface stays: it reads and writes nothing.
      expect(screen.getByLabelText('Expression')).toBeInTheDocument();
    });
  });
});
