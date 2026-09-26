/** The estate-wide rule view (FR-FW-07).
 *
 * Two properties carry the whole feature, and both are about not overstating what was
 * found: rules stay grouped and in evaluation order, and a device that could not be
 * read is visibly different from one that was read and matched nothing.
 */

import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { EstateRules } from './EstateRules';
import type { EstateDeviceRules, EstateRules as Payload, Rule } from './types';

function rule(order: number, name: string, issues: string[] = []): Rule {
  return {
    order,
    name,
    enabled: true,
    action: 'allow',
    permits: true,
    src_zones: [],
    dst_zones: [],
    source: 'any',
    destination: 'any',
    services: 'any',
    source_objects: [],
    destination_objects: [],
    service_objects: [],
    applications: [],
    users: [],
    logs: true,
    has_profiles: false,
    profiles: {},
    schedule: null,
    hit_count: null,
    last_hit: null,
    unresolved: [],
    source_size: 0,
    destination_size: 0,
    permissiveness: {
      score: 100,
      band: 'critical',
      source: 100,
      destination: 100,
      service: 100,
      understated: false,
    },
    issues: issues.map((issue) => ({
      issue,
      severity: 'high',
      message: issue,
      related_rule_order: null,
      related_rule_name: null,
    })),
  } as Rule;
}

function device(overrides: Partial<EstateDeviceRules>): EstateDeviceRules {
  return {
    device_id: 'd1',
    hostname: 'fw-01',
    platform: 'panos',
    snapshot_id: 's1',
    rules: [],
    matched: 0,
    rules_total: 0,
    rules_not_retrieved: null,
    truncated: false,
    not_searched: null,
    ...overrides,
  };
}

function payload(overrides: Partial<Payload> = {}): Payload {
  return {
    devices: [],
    matched_total: 0,
    devices_searched: 0,
    devices_not_searched: 0,
    limitations: [],
    ...overrides,
  };
}

function show(data: Payload) {
  return render(
    <MemoryRouter>
      <EstateRules data={data} />
    </MemoryRouter>,
  );
}

describe('EstateRules', () => {
  it('keeps each device rules in evaluation order', () => {
    // Order is meaning: a rule is shadowed because of where it sits. The obvious thing
    // to do with an estate list — sort it by severity — would destroy that.
    show(
      payload({
        devices: [
          device({
            matched: 3,
            rules_total: 40,
            rules: [rule(4, 'Fourth'), rule(11, 'Eleventh'), rule(30, 'Thirtieth')],
          }),
        ],
        matched_total: 3,
        devices_searched: 1,
      }),
    );

    const cells = screen.getAllByRole('cell').filter((c) => /^\d+$/.test(c.textContent ?? ''));
    expect(cells.map((c) => c.textContent)).toEqual(['4', '11', '30']);
  });

  it('separates a device that matched nothing from one nobody could read', () => {
    show(
      payload({
        devices: [
          device({ device_id: 'd1', hostname: 'read-me', matched: 0, rules_total: 12 }),
          device({
            device_id: 'd2',
            hostname: 'never-collected',
            not_searched: 'No configuration has been collected from this device.',
          }),
        ],
        devices_searched: 1,
        devices_not_searched: 1,
      }),
    );

    expect(screen.getByText('No rule on this firewall matches.')).toBeInTheDocument();
    expect(
      screen.getByText(/No configuration has been collected from this device/),
    ).toBeInTheDocument();
    expect(screen.getByText('not searched')).toBeInTheDocument();
  });

  it('states its limitations on every result, not only bad ones', () => {
    show(
      payload({
        devices: [device({ matched: 1, rules_total: 3, rules: [rule(1, 'One')] })],
        matched_total: 1,
        devices_searched: 1,
        limitations: ['Searched 1 of 9 visible devices. This is not the whole estate.'],
      }),
    );

    expect(screen.getByText(/not the whole estate/)).toBeInTheDocument();
  });

  it('warns when a matched device rulebase arrived incomplete', () => {
    // "No match on this firewall" is not a finding about the firewall when part of its
    // policy was never retrieved.
    show(
      payload({
        devices: [device({ matched: 0, rules_total: 50, rules_not_retrieved: 450 })],
        devices_searched: 1,
      }),
    );

    expect(screen.getByText(/450 rules never retrieved/)).toBeInTheDocument();
  });

  it('links a device group to its own rulebase', () => {
    show(
      payload({
        devices: [
          device({ device_id: 'abc', matched: 1, rules_total: 1, rules: [rule(1, 'One')] }),
        ],
        matched_total: 1,
        devices_searched: 1,
      }),
    );

    const group = screen.getByRole('link', { name: 'fw-01' });
    expect(group).toHaveAttribute('href', '/firewall?device=abc');
  });

  it('shows a deny rule breadth as not applicable rather than as zero', () => {
    // Sorting an estate list by breadth is exactly what this column is for, and a 0
    // would put every deny rule at the "tightest" end of it as though that were a
    // measurement rather than a category error.
    const deny = { ...rule(1, 'Block all'), permits: false, permissiveness: null } as Rule;
    show(
      payload({
        devices: [device({ matched: 1, rules_total: 1, rules: [deny] })],
        matched_total: 1,
        devices_searched: 1,
      }),
    );

    const cells = screen.getAllByRole('cell');
    const breadth = cells.at(-2);
    expect(breadth?.textContent).not.toMatch(/\d/);
    expect(breadth?.textContent).toMatch(/breadth not scored/);
  });

  it('counts matches against the rulebase size, so three of four hundred reads as such', () => {
    show(
      payload({
        devices: [device({ matched: 3, rules_total: 400, rules: [rule(1, 'One')] })],
        matched_total: 3,
        devices_searched: 1,
      }),
    );

    const group = screen.getByRole('listitem');
    expect(within(group).getByText('3 of 400 rules')).toBeInTheDocument();
  });
});
