/** Component tests for the certificate expiry timeline (FR-AAA-06, TEST-05).
 *
 * Every assertion here is about the panel being unable to look cleaner than the data
 * warrants. A timeline is a promise that what is not on it is not coming, and there are
 * two ways to break that promise silently:
 *
 * **Dropping a certificate whose date could not be read.** The list gets shorter and the
 * page looks better, which is exactly backwards.
 *
 * **Rendering an empty timeline as a clean one.** A certificate endpoint that returned
 * 403 produces the same zero rows as an estate with nothing expiring.
 */

import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { CertificateTimeline } from './CertificateTimeline';
import { certificateState, describeRemaining } from './types';
import type { CertificateEntry, CertificateTimeline as Timeline } from './types';

function entry(overrides: Partial<CertificateEntry> = {}): CertificateEntry {
  return {
    device_id: 'd1',
    device: 'ise-01',
    name: 'campus-eap',
    subject: 'ise-psn-01.campus.example.com',
    issuer: 'Campus Issuing CA G2',
    self_signed: false,
    usage: ['EAP Authentication'],
    expires_at: '2027-03-13T09:14:22+00:00',
    days_remaining: 180,
    ...overrides,
  };
}

function timeline(overrides: Partial<Timeline> = {}): Timeline {
  return {
    entries: [entry()],
    total: 1,
    expired: 0,
    expiring_soon: 0,
    expiring_within_horizon: 0,
    undated: 0,
    servers_without_certificates: [],
    soon_days: 30,
    horizon_days: 90,
    ...overrides,
  };
}

describe('CertificateTimeline', () => {
  it('shows what each certificate is used for', () => {
    // The EAP one is the certificate whose expiry takes every wireless client offline
    // at once. Without the usage column it is indistinguishable from the portal cert.
    render(<CertificateTimeline timeline={timeline()} />);

    const row = screen.getByText('campus-eap').closest('tr');
    expect(within(row!).getByText('EAP Authentication')).toBeInTheDocument();
  });

  it('keeps an undated certificate on the list and counts it', () => {
    const undated = entry({ name: 'pxgrid', expires_at: null, days_remaining: null });
    render(
      <CertificateTimeline
        timeline={timeline({ entries: [entry(), undated], total: 2, undated: 1 })}
      />,
    );

    expect(screen.getByText('pxgrid')).toBeInTheDocument();
    expect(screen.getByText('no readable expiry date')).toBeInTheDocument();
    expect(screen.getByText('no readable date')).toBeInTheDocument();
  });

  it('does not render an undated certificate as expired', () => {
    // `null < 0` is false in JavaScript but `null` coerces to 0 in arithmetic, so a
    // careless comparison puts an undated certificate in the expired bucket and pages
    // somebody about a certificate nobody has ever dated.
    const undated = entry({ expires_at: null, days_remaining: null });

    expect(certificateState(undated, { soon_days: 30, horizon_days: 90 })).toBe('undated');
    expect(describeRemaining(undated)).toBe('no readable expiry date');
  });

  it('names the servers it could not read a certificate from', () => {
    render(
      <CertificateTimeline
        timeline={timeline({
          entries: [],
          total: 0,
          servers_without_certificates: ['ise-01', 'fac-01'],
        })}
      />,
    );

    const warning = screen.getByRole('status');
    expect(warning).toHaveTextContent('ise-01, fac-01');
    expect(warning).toHaveTextContent('blind to those servers');
  });

  it('says an empty timeline is not the same as nothing expiring', () => {
    render(<CertificateTimeline timeline={timeline({ entries: [], total: 0 })} />);

    expect(screen.getByText(/not the same as nothing expiring/i)).toBeInTheDocument();
  });

  it('distinguishes expired from expiring', () => {
    render(
      <CertificateTimeline
        timeline={timeline({
          entries: [
            entry({ name: 'gone', days_remaining: -5 }),
            entry({ name: 'soon', days_remaining: 9 }),
          ],
          total: 2,
          expired: 1,
          expiring_soon: 1,
          expiring_within_horizon: 1,
        })}
      />,
    );

    expect(
      within(screen.getByText('gone').closest('tr')!).getByText('expired 5 days ago'),
    ).toBeInTheDocument();
    expect(
      within(screen.getByText('soon').closest('tr')!).getByText('9 days left'),
    ).toBeInTheDocument();
  });

  it('marks a self-signed certificate', () => {
    render(
      <CertificateTimeline timeline={timeline({ entries: [entry({ self_signed: true })] })} />,
    );

    expect(screen.getByText('self-signed')).toBeInTheDocument();
  });
});
