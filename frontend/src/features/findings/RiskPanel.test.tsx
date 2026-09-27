/** A device's risk score and its direction (FR-CHK-09).
 *
 * The score has been computed and stored on every assessment since Phase 3, and no
 * page has ever shown it. Most of what follows is about the two ways putting it on
 * screen could say something false.
 *
 * **Zero is a real score here, and it means clean.** So a device nobody has assessed
 * must not render as zero, or the least-examined box in the estate reads as the
 * healthiest.
 *
 * **The scale counts down.** A falling line is good news, which is the opposite of
 * every other chart's convention — so the direction is a word from the server rather
 * than a slope the reader is left to interpret.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { RiskPanel } from './RiskPanel';
import { api } from '../../api/client';

const DEVICE = '11111111-1111-1111-1111-111111111111';

const ASSESSED = {
  device_id: DEVICE,
  score: 42,
  compliance_percent: 78,
  coverage_percent: 90,
  checks_evaluated: 50,
  checks_passed: 39,
  checks_failed: 11,
  checks_not_evaluated: 6,
  components: {},
  assessed_at: '2026-09-25T10:00:00Z',
};

const HISTORY = {
  device_id: DEVICE,
  points: [
    { at: '2026-08-01T10:00:00Z', score: 80, checks_evaluated: 50 },
    { at: '2026-09-01T10:00:00Z', score: 60, checks_evaluated: 50 },
    { at: '2026-09-25T10:00:00Z', score: 42, checks_evaluated: 50 },
  ],
  direction: 'improving',
};

let risk: Record<string, unknown> = ASSESSED;
let history: Record<string, unknown> = HISTORY;

function renderPanel() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <RiskPanel deviceId={DEVICE} />
    </QueryClientProvider>,
  );
}

describe('RiskPanel', () => {
  beforeEach(() => {
    risk = ASSESSED;
    history = HISTORY;
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path.includes('/risk/history')) return history as never;
      if (path.includes('/risk')) return risk as never;
      return {} as never;
    });
  });

  afterEach(() => vi.restoreAllMocks());

  it('shows the score that has been stored all along', async () => {
    renderPanel();

    expect(await screen.findByText('42')).toBeInTheDocument();
  });

  it('says a device was never assessed rather than scoring it zero', async () => {
    // Zero means clean on this scale, so it would make the least-examined device in
    // the estate read as the healthiest.
    risk = { ...ASSESSED, score: null, assessed_at: null };
    renderPanel();

    expect(await screen.findByText(/never been assessed/)).toBeInTheDocument();
    expect(screen.queryByText('0')).toBeNull();
  });

  it('calls a falling score improving, because the scale counts down', async () => {
    renderPanel();

    expect(await screen.findByText('improving')).toBeInTheDocument();
  });

  it('takes the direction from the server rather than reading the slope', async () => {
    // So a report and this panel cannot describe the same two numbers differently.
    history = { ...HISTORY, direction: 'worsening' };
    renderPanel();

    expect(await screen.findByText('getting worse')).toBeInTheDocument();
  });

  it('says a single reading is not a direction', async () => {
    // A flat line between one point and itself would claim nothing has changed, which
    // is a comparison that has not been made.
    history = { device_id: DEVICE, points: [HISTORY.points[0]], direction: 'unknown' };
    renderPanel();

    // Wait for the history to actually arrive before reading the caption. The panel
    // renders with no points while the query is in flight, and that empty state says
    // the same sentence — so asserting straight away passes whether or not the loaded
    // state is right. The first version of this test did exactly that and survived a
    // mutation that changed the threshold to `> 0`.
    await screen.findByRole('img', { name: /1 readings/ });

    expect(screen.getByText(/a direction needs two/)).toBeInTheDocument();
    expect(screen.getByText('no direction yet')).toBeInTheDocument();
  });

  it('names the checks that produced no verdict', async () => {
    // They are in neither the passed nor the failed figure. Dropping them silently
    // makes a partly-assessed device look fully assessed.
    renderPanel();

    expect(await screen.findByText(/6 could not be evaluated/)).toBeInTheDocument();
  });

  it('describes the sparkline in words for a reader who cannot see it', async () => {
    renderPanel();

    const chart = await screen.findByRole('img', { name: /3 readings/ });
    expect(chart).toHaveAccessibleName(/most recent 42/);
  });

  it('says so rather than drawing an empty chart when there are no readings', async () => {
    history = { device_id: DEVICE, points: [], direction: 'unknown' };
    renderPanel();

    expect(await screen.findByText(/No readings yet/)).toBeInTheDocument();
  });
});
