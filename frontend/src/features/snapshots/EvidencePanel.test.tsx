/** The evidence panel (FR-COL-03, SEC-09, TEST-05).
 *
 * This panel is the product's read-only claim made checkable, so the tests are about the
 * distinctions surviving to the screen. Every one of them is a case where collapsing two
 * different situations into one would make an unreliable collection look like a clean
 * one: no collection versus no commands, a failed command versus an empty response, a
 * partial collection versus a complete one.
 *
 * The unredacted path gets its own tests because it is the single route by which a
 * secret leaves the system, and because it must stay a deliberate fetch rather than a
 * toggle over text the browser already holds.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { EvidencePanel } from './EvidencePanel';
import { api } from '../../api/client';

let mayViewUnredacted = true;

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ can: () => mayViewUnredacted }),
}));

vi.mock('../../api/client', () => ({
  api: { get: vi.fn() },
}));

const COLLECTION = {
  id: 'c1',
  device_id: 'd1',
  adapter: 'cisco_ios',
  adapter_version: '1.4.0',
  started_at: '2026-09-21T10:00:00Z',
  finished_at: '2026-09-21T10:00:03Z',
  partial: false,
  error_message: null,
  created_at: '2026-09-21T10:00:03Z',
};

const ARTIFACTS = [
  {
    id: 'a1',
    collection_id: 'c1',
    kind: 'command',
    request_text: 'show running-config',
    sha256: 'abc123def4567890aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    size_bytes: 20480,
    duration_ms: 1200,
    ordinal: 1,
    succeeded: true,
    created_at: '2026-09-21T10:00:01Z',
  },
  {
    id: 'a2',
    collection_id: 'c1',
    kind: 'command',
    request_text: 'show ip route',
    sha256: 'ffffffffffffffffbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    size_bytes: 512,
    duration_ms: 90,
    ordinal: 2,
    succeeded: false,
    created_at: '2026-09-21T10:00:02Z',
  },
];

let collection: unknown = COLLECTION;
let artifacts: unknown = ARTIFACTS;
let redactedBody = 'hostname core-sw-01\nsnmp-server community [REDACTED:community:9f3a] RO';
let rawBody = 'hostname core-sw-01\nsnmp-server community s3cr3t RO';

/** Indexing is checked, so a missing element fails here rather than as a null deref. */
function at<T>(items: T[], index: number): T {
  const item = items[index];
  if (item === undefined) throw new Error(`expected an element at index ${index}`);
  return item;
}

/** Open the first command's output — the preamble of most tests below. */
async function openFirstOutput(user: ReturnType<typeof userEvent.setup>) {
  const buttons = await screen.findAllByRole('button', { name: 'View output' });
  await user.click(at(buttons, 0));
}

function renderPanel(collectionId: string | null = 'c1') {
  vi.mocked(api.get).mockImplementation((path: string) => {
    if (path === '/collections/c1') return Promise.resolve(collection);
    if (path === '/collections/c1/artifacts') return Promise.resolve(artifacts);
    if (path.endsWith('/raw')) {
      return Promise.resolve({ ...ARTIFACTS[0], response: rawBody, redacted: false });
    }
    if (path.startsWith('/artifacts/')) {
      return Promise.resolve({ ...ARTIFACTS[0], response: redactedBody, redacted: true });
    }
    return Promise.reject(new Error(`unexpected path ${path}`));
  });

  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <EvidencePanel collectionId={collectionId} />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  mayViewUnredacted = true;
  collection = COLLECTION;
  artifacts = ARTIFACTS;
  redactedBody = 'hostname core-sw-01\nsnmp-server community [REDACTED:community:9f3a] RO';
  rawBody = 'hostname core-sw-01\nsnmp-server community s3cr3t RO';
});

afterEach(() => vi.clearAllMocks());

describe('the command log', () => {
  it('lists every command issued, in the order it was issued', async () => {
    renderPanel();

    const rows = await screen.findAllByRole('row');
    // Header plus two commands.
    expect(rows).toHaveLength(3);
    expect(within(at(rows, 1)).getByText('show running-config')).toBeInTheDocument();
    expect(within(at(rows, 2)).getByText('show ip route')).toBeInTheDocument();
  });

  it('marks a failed command distinctly from one that succeeded', async () => {
    renderPanel();

    expect(await screen.findByText('failed')).toBeInTheDocument();
    expect(screen.getByText('ok')).toBeInTheDocument();
  });

  it('counts the failures in the summary, so a bad collection is visible without reading rows', async () => {
    renderPanel();

    expect(await screen.findByText(/1 of which failed/)).toBeInTheDocument();
  });
});

describe('what it refuses to render as an ordinary empty result', () => {
  it('says an uploaded configuration has no command log, rather than showing nothing', () => {
    renderPanel(null);

    expect(screen.getByText(/uploaded rather than collected/)).toBeInTheDocument();
    // And asks the server for nothing at all: there is no collection to fetch.
    expect(api.get).not.toHaveBeenCalled();
  });

  it('flags a collection that recorded no commands as unexpected', async () => {
    artifacts = [];
    renderPanel();

    expect(await screen.findByText(/recorded no commands/)).toBeInTheDocument();
    expect(screen.getByText(/itself unexpected/)).toBeInTheDocument();
  });

  it('leads with the partial warning and names why, because checks depend on it', async () => {
    collection = {
      ...COLLECTION,
      partial: true,
      error_message: 'show ip route timed out after 30s',
    };
    renderPanel();

    expect(await screen.findByText(/This collection was partial/)).toBeInTheDocument();
    expect(screen.getByText(/timed out after 30s/)).toBeInTheDocument();
    expect(screen.getByText(/Not Evaluated rather than passing/)).toBeInTheDocument();
  });

  it('distinguishes a command that returned nothing from one that failed', async () => {
    const user = userEvent.setup();
    redactedBody = '';
    renderPanel();

    await openFirstOutput(user);

    expect(
      await screen.findByText(/ran and returned nothing. That is the device/),
    ).toBeInTheDocument();
  });
});

describe('viewing output', () => {
  it('fetches the redacted body on demand, not with the list', async () => {
    const user = userEvent.setup();
    renderPanel();

    await screen.findByText('show running-config');
    expect(api.get).not.toHaveBeenCalledWith('/artifacts/a1');

    await openFirstOutput(user);

    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/artifacts/a1'));
    expect(await screen.findByText(/REDACTED:community/)).toBeInTheDocument();
  });

  it('shows the hash of the original alongside the redacted body', async () => {
    const user = userEvent.setup();
    renderPanel();

    await openFirstOutput(user);

    expect(await screen.findByText(/sha256 abc123def4567890/)).toBeInTheDocument();
  });
});

describe('the unredacted original', () => {
  it('is not offered without config:view_unredacted', async () => {
    const user = userEvent.setup();
    mayViewUnredacted = false;
    renderPanel();

    await openFirstOutput(user);
    await screen.findByText(/REDACTED:community/);

    expect(screen.queryByRole('button', { name: 'Show the original' })).not.toBeInTheDocument();
  });

  it('is a separate request, so the browser never holds the secret until it is asked for', async () => {
    const user = userEvent.setup();
    renderPanel();

    await openFirstOutput(user);
    await screen.findByText(/REDACTED:community/);
    expect(api.get).not.toHaveBeenCalledWith('/artifacts/a1/raw');

    await user.click(screen.getByRole('button', { name: 'Show the original' }));

    await waitFor(() => expect(api.get).toHaveBeenCalledWith('/artifacts/a1/raw'));
    expect(await screen.findByText(/community s3cr3t RO/)).toBeInTheDocument();
  });

  it('says plainly that viewing it was recorded against the account', async () => {
    const user = userEvent.setup();
    renderPanel();

    await openFirstOutput(user);
    await user.click(await screen.findByRole('button', { name: 'Show the original' }));

    expect(await screen.findByText(/recorded in the audit log against/)).toBeInTheDocument();
    expect(screen.getByText('original')).toBeInTheDocument();
  });

  it('can be closed again, returning to the redacted body', async () => {
    const user = userEvent.setup();
    renderPanel();

    await openFirstOutput(user);
    await user.click(await screen.findByRole('button', { name: 'Show the original' }));
    await screen.findByText(/community s3cr3t RO/);

    await user.click(screen.getByRole('button', { name: 'Hide the original' }));

    expect(await screen.findByText(/REDACTED:community/)).toBeInTheDocument();
  });
});

