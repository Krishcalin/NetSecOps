/** The path diagram (FR-TOPO-03).
 *
 * A picture is believed faster than a table and argued with less, so the tests here are
 * almost entirely about what it must NOT draw: an unbroken chain to a destination the
 * packet never reaches, a completed trace where the estate ran out, or a router styled
 * like a firewall that permitted something.
 *
 * `buildChain` is tested directly as well as through the render. The "does this reach
 * the destination" decision is the one that can silently invert, and asserting it
 * against the data structure pins it without depending on how a rectangle is drawn.
 */

import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { PathDiagram } from './PathDiagram';
import { buildChain, describeChain } from './pathChain';
import type { Hop, PathResult } from './types';

function hop(hostname: string, overrides: Partial<Hop> = {}): Hop {
  return {
    device_id: `id-${hostname}`,
    hostname,
    platform: 'cisco_asa',
    matched_route: '10.20.0.0/24 via 10.0.1.2',
    next_hop: '10.0.1.2',
    egress_interface: 'dmz',
    ingress_zone: 'trust',
    egress_zone: 'dmz',
    action: 'allow',
    rule_name: 'permit-web',
    rule_order: 2,
    limitations: [],
    ...overrides,
  };
}

function path(overrides: Partial<PathResult> = {}): PathResult {
  return {
    source: '10.10.0.5',
    destination: '10.20.0.5',
    protocol: 'tcp',
    port: 443,
    routing: 'routed',
    policy: 'allowed',
    hops: [hop('edge-fw'), hop('dmz-fw')],
    stopped_at_prefix: null,
    stopped_at_next_hop: null,
    stopped_at_device: null,
    translated_at: [],
    branched_at: [],
    notes: [],
    ...overrides,
  };
}

describe('buildChain', () => {
  it('reaches the destination when the path is routed and permitted', () => {
    const { cells, brokenAfter } = buildChain(path());

    expect(brokenAfter).toBeNull();
    expect(cells.at(-1)).toMatchObject({ title: '10.20.0.5', reached: true });
  });

  it('stops at the denying hop and marks the destination unreached', () => {
    // The picture must agree with the verdict. An unbroken arrow to the destination
    // under "blocked" contradicts it, and people believe the picture.
    const { cells, brokenAfter } = buildChain(
      path({
        policy: 'blocked',
        hops: [hop('edge-fw'), hop('dmz-fw', { action: 'deny', rule_name: 'no-telnet' })],
      }),
    );

    expect(brokenAfter).toBe(2);
    expect(cells.at(-1)).toMatchObject({ title: '10.20.0.5', reached: false });
    expect(cells.at(-1)?.subtitle).toBe('never reached');
  });

  it('ends in an unknown node when the trace left the managed estate', () => {
    // `partially-routed` means there may be another firewall out there. Drawing the
    // chain as complete would assert there is not.
    const { cells } = buildChain(
      path({
        routing: 'partially-routed',
        policy: 'partially-allowed',
        hops: [hop('edge-fw')],
        stopped_at_device: 'edge-fw',
        stopped_at_prefix: '0.0.0.0/0',
        stopped_at_next_hop: '203.0.113.1',
      }),
    );

    const unknown = cells.find((c) => c.kind === 'unknown');
    expect(unknown).toMatchObject({ title: '203.0.113.1', subtitle: 'not in inventory' });
    expect(cells.at(-1)).toMatchObject({ reached: false });
  });

  it('distinguishes a hop that formed no opinion from one that permitted', () => {
    // A router with no rulebase is a hop, not a control. Drawing them alike counts a
    // device that inspected nothing as a check that passed.
    const { cells } = buildChain(
      path({ hops: [hop('core-rtr', { action: null, rule_name: null }), hop('dmz-fw')] }),
    );

    const [, router, firewall] = cells;
    expect(router?.decision).toBe('none');
    expect(firewall?.decision).toBe('allow');
  });

  it('marks the hops where NAT or equal-cost routing changes what the answer means', () => {
    const { cells } = buildChain(
      path({ translated_at: ['edge-fw'], branched_at: ['edge-fw', 'dmz-fw'] }),
    );

    expect(cells.find((c) => c.title === 'edge-fw')?.markers).toEqual(['NAT', 'ECMP']);
    expect(cells.find((c) => c.title === 'dmz-fw')?.markers).toEqual(['ECMP']);
  });
});

describe('describeChain', () => {
  it('states the whole path in words, including whether it arrives', () => {
    // The text alternative is the diagram for anyone who cannot see it, so it carries
    // the same conclusion rather than a label like "path diagram".
    const blocked = path({
      policy: 'blocked',
      hops: [hop('edge-fw'), hop('dmz-fw', { action: 'deny' })],
    });
    const text = describeChain(blocked, buildChain(blocked).cells);

    expect(text).toContain('10.10.0.5 to 10.20.0.5');
    expect(text).toContain('tcp port 443');
    expect(text).toContain('edge-fw permits');
    expect(text).toContain('dmz-fw denies');
    expect(text).toContain('not reaching the destination');
  });
});

describe('PathDiagram', () => {
  it('exposes one image with the path as its accessible description', () => {
    render(<PathDiagram result={path()} />);

    const image = screen.getByRole('img');
    expect(image).toHaveAccessibleName(/Path diagram/);
    expect(image).toHaveAccessibleDescription(/reaching the destination/);
  });

  it('spells out the NAT caveat rather than leaving two letters on a drawing', () => {
    render(<PathDiagram result={path({ translated_at: ['edge-fw'] })} />);

    expect(screen.getByText(/translation itself is not modelled/)).toBeInTheDocument();
  });

  it('spells out the equal-cost caveat', () => {
    render(<PathDiagram result={path({ branched_at: ['edge-fw'] })} />);

    expect(screen.getByText(/firewall on a branch it did not take/)).toBeInTheDocument();
  });

  it('gives each diagram its own ids, so two on a page do not share a description', () => {
    // A hardcoded id would silently point the second diagram's description at the
    // first one's text, which is the kind of a11y defect nothing visible reveals.
    const { container } = render(
      <>
        <PathDiagram result={path()} />
        <PathDiagram result={path({ destination: '10.30.0.9' })} />
      </>,
    );

    const described = [...container.querySelectorAll('svg')].map((s) =>
      s.getAttribute('aria-describedby'),
    );
    expect(described[0]).not.toBe(described[1]);
    expect(new Set(described).size).toBe(2);
  });

  it('draws the stop bar only when something denied', () => {
    const { container: clean } = render(<PathDiagram result={path()} />);
    expect(clean.querySelector('.pathdiagram__stop')).toBeNull();

    const { container: blocked } = render(
      <PathDiagram
        result={path({ policy: 'blocked', hops: [hop('dmz-fw', { action: 'deny' })] })}
      />,
    );
    expect(blocked.querySelector('.pathdiagram__stop')).not.toBeNull();
  });
});
