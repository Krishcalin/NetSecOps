/** The map's arithmetic (FR-TOPO-02, TEST-05).
 *
 * Two properties here are the ones a redesign would quietly reverse, and both are about
 * what the picture is allowed to hide.
 *
 * **A device carrying a rulebase is never folded into a bundle.** Collapsing fifty
 * access switches is the whole reason the map is readable; collapsing a firewall would
 * take a control off the picture, and the reader has no way to know it was ever there.
 *
 * **Position is derived, never simulated.** Two runs over an unchanged estate produce
 * the same picture, so this week's map can be compared with last week's.
 */

import { describe, expect, it } from 'vitest';

import { bundleKey, layoutMap, strandPath, tidyAddress, worstSeverity } from './mapLayout';
import type { EstateMap, MapLink, MapNode } from './types';

function device(id: string, overrides: Partial<MapNode> = {}): MapNode {
  return {
    id,
    kind: 'device',
    label: id,
    group: 'g0',
    tier: 0,
    platform: 'cisco_ios',
    vendor: 'cisco',
    device_class: 'switch',
    criticality: 'medium',
    status: 'active',
    site: null,
    has_rulebase: false,
    inspects: false,
    routes: 1,
    routes_known: true,
    interfaces: [],
    interface_count: 0,
    findings: {},
    has_snapshot: true,
    referenced_by: [],
    carries_default_route: false,
    ...overrides,
  };
}

function link(source: string, target: string, overrides: Partial<MapLink> = {}): MapLink {
  return {
    id: `${source}|${target}`,
    source,
    target,
    via: ['10.0.0.1'],
    prefixes: 1,
    carries_default: false,
    bidirectional: false,
    source_interface: null,
    target_interface: null,
    crosses_firewall: false,
    ...overrides,
  };
}

/** A core with four leaf switches and one leaf firewall hanging off it. */
function estate(leafOverrides: Partial<MapNode> = {}): EstateMap {
  const nodes = [
    device('core', { device_class: 'router', tier: 0 }),
    device('sw-1', { tier: 1, ...leafOverrides }),
    device('sw-2', { tier: 1, ...leafOverrides }),
    device('sw-3', { tier: 1, ...leafOverrides }),
    device('sw-4', { tier: 1, ...leafOverrides }),
    device('branch-fw', { tier: 1, device_class: 'firewall', has_rulebase: true, inspects: true }),
  ];
  return {
    nodes,
    links: [
      link('core', 'sw-1'),
      link('core', 'sw-2'),
      link('core', 'sw-3'),
      link('core', 'sw-4'),
      link('core', 'branch-fw'),
    ],
    groups: [
      {
        id: 'g0',
        label: 'site',
        label_source: 'hostname',
        devices: 6,
        firewalls: 1,
        unmanaged: 0,
        links: 5,
        tiers: 2,
      },
    ],
    devices: 6,
    unmanaged: 0,
    devices_without_route_data: 0,
    isolated: 0,
    omitted_groups: [],
    omitted_devices: 0,
  };
}

describe('bundling', () => {
  it('folds sibling leaves into one box', () => {
    const laid = layoutMap(estate());
    const labels = laid.nodes.map((placed) => placed.node.label);

    expect(labels).toContain('4 × switches');
    expect(labels).not.toContain('sw-1');
  });

  it('never folds a device whose rulebase is in force', () => {
    const laid = layoutMap(estate());
    const labels = laid.nodes.map((placed) => placed.node.label);

    // The firewall is attached exactly like the switches — one link, to the same
    // parent — and is still drawn on its own. A control that is folded away is a
    // control the reader cannot see was checked.
    expect(labels).toContain('branch-fw');
  });

  it('does fold a switch whose access list is bound to nothing', () => {
    // `has_rulebase` without `inspects`: an `access-class` on the vty lines filters
    // management access and no transit traffic, so the device is not a control. Reading
    // `has_rulebase` here would leave every such switch unfolded, which on a real
    // estate is most of them — the wall of boxes bundling exists to remove.
    const laid = layoutMap(estate({ has_rulebase: true, inspects: false }));
    const labels = laid.nodes.map((placed) => placed.node.label);

    expect(labels).toContain('4 × switches');
    expect(labels).not.toContain('sw-1');
  });

  it('draws every leaf once a bundle is opened', () => {
    const laid = layoutMap(estate(), { expanded: new Set([bundleKey('core', 1)]) });
    const labels = laid.nodes.map((placed) => placed.node.label);

    expect(labels).toEqual(expect.arrayContaining(['sw-1', 'sw-2', 'sw-3', 'sw-4']));
    expect(labels.some((label) => label.includes('×'))).toBe(false);
  });

  it('leaves two siblings alone, because a bundle of two costs a click and saves nothing', () => {
    const small = estate();
    small.nodes = small.nodes.filter((node) => !['sw-3', 'sw-4'].includes(node.id));
    small.links = small.links.filter((item) => !['core|sw-3', 'core|sw-4'].includes(item.id));

    const labels = layoutMap(small).nodes.map((placed) => placed.node.label);
    expect(labels).toEqual(expect.arrayContaining(['sw-1', 'sw-2']));
  });

  it('folds the links too, and says how many', () => {
    const laid = layoutMap(estate());
    const bundled = laid.links.find(
      (strand) => strand.to.startsWith('bundle:') || strand.from.startsWith('bundle:'),
    );

    expect(bundled?.count).toBe(4);
  });
});

describe('placement', () => {
  it('puts each tier in its own column', () => {
    const laid = layoutMap(estate());
    const core = laid.nodes.find((placed) => placed.node.label === 'core');
    const leaf = laid.nodes.find((placed) => placed.node.label === 'branch-fw');

    expect(core!.x).toBeLessThan(leaf!.x);
  });

  it('never puts two boxes in the same place', () => {
    const laid = layoutMap(estate(), { expandAll: true });
    const seen = new Set(laid.nodes.map((placed) => `${placed.x},${placed.y}`));

    expect(seen.size).toBe(laid.nodes.length);
  });

  it('names the columns in words rather than by depth', () => {
    const map = estate();
    map.nodes.push(device('isp', { kind: 'unmanaged', tier: -1, label: '198.51.100.1' }));
    map.links.push(link('core', 'isp'));

    const laid = layoutMap(map);
    expect(laid.tiers.map((column) => column.label)).toEqual([
      'Outside the estate',
      'Estate edge',
      '1 hop in',
    ]);
  });

  it('lays the same estate out identically twice', () => {
    const map = estate();
    const first = layoutMap(map);
    const second = layoutMap(map);

    expect(first.nodes.map((placed) => [placed.key, placed.x, placed.y])).toEqual(
      second.nodes.map((placed) => [placed.key, placed.x, placed.y]),
    );
  });

  it('draws a strand as a path between the two boxes it joins', () => {
    const laid = layoutMap(estate());
    const strand = laid.links[0]!;
    const path = strandPath(strand);

    expect(path).toContain(`M ${strand.x1} ${strand.y1}`);
    expect(path.endsWith(`${strand.x2} ${strand.y2}`)).toBe(true);
  });
});

describe('reading the numbers', () => {
  it('reports the worst severity present, not the most common', () => {
    expect(worstSeverity({ low: 40, critical: 1 })).toBe('critical');
    expect(worstSeverity({})).toBeNull();
  });

  it('folds a dotted netmask into a prefix length so one list reads consistently', () => {
    expect(tidyAddress('10.20.0.1/255.255.255.0')).toBe('10.20.0.1/24');
    expect(tidyAddress('198.51.100.2/255.255.255.248')).toBe('198.51.100.2/29');
  });

  it('leaves alone anything that is not a contiguous mask', () => {
    // Rewriting these would be inventing a prefix length the device does not have.
    expect(tidyAddress('10.20.0.1/24')).toBe('10.20.0.1/24');
    expect(tidyAddress('10.20.0.1/255.0.255.0')).toBe('10.20.0.1/255.0.255.0');
    expect(tidyAddress('10.20.0.1')).toBe('10.20.0.1');
  });
});
