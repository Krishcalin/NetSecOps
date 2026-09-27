/** The appliance types nested under Inventory.
 *
 * They are views of one page rather than pages of their own, which is the whole reason
 * the active state needs care: all three share `/inventory`, so `NavLink`'s own
 * matching — which compares paths and ignores the query string — would light every one
 * of them the moment any was open, and the sidebar would stop answering "which am I
 * looking at".
 */

import { describe, expect, it } from 'vitest';

import { isChildActive, NAV_ITEMS } from './nav';

const inventory = NAV_ITEMS.find((item) => item.label === 'Inventory')!;

describe('the appliance types under Inventory', () => {
  it('are nested rather than being entries of their own', () => {
    // A top-level entry per device class would say these are separate places. They
    // are the inventory, filtered.
    expect(inventory.children?.map((child) => child.label)).toEqual([
      'Routers',
      'Switches',
      'Firewalls',
    ]);
    expect(NAV_ITEMS.some((item) => item.label === 'Routers')).toBe(false);
  });

  it('filter the page rather than pointing at a route of their own', () => {
    // A `/inventory/routers` route would need its own page, and the two would drift.
    for (const child of inventory.children ?? []) {
      expect(child.to).toMatch(/^\/inventory\?device_class=/);
    }
  });

  it('name device classes the API actually accepts', () => {
    // A typo here produces an empty inventory that looks like an estate with no
    // routers in it. These are the `DeviceClass` values from the backend enum.
    const classes = (inventory.children ?? []).map(
      (child) => new URLSearchParams(child.to!.split('?')[1]).get('device_class'),
    );
    expect(classes).toEqual(['router', 'switch', 'firewall']);
  });
});

describe('which nested entry is lit', () => {
  const routers = '/inventory?device_class=router';
  const switches = '/inventory?device_class=switch';

  it('lights the one whose filter is in force', () => {
    expect(isChildActive(routers, '/inventory', '?device_class=router')).toBe(true);
  });

  it('does not light its siblings', () => {
    // The failure `NavLink` would have produced on its own.
    expect(isChildActive(switches, '/inventory', '?device_class=router')).toBe(false);
  });

  it('lights none of them on the unfiltered inventory', () => {
    expect(isChildActive(routers, '/inventory', '')).toBe(false);
  });

  it('stays lit while paging and searching within that view', () => {
    // The reader has not left the switches by turning a page, and unlighting it here
    // would make the sidebar disagree with the heading.
    expect(isChildActive(switches, '/inventory', '?device_class=switch&offset=25')).toBe(true);
    expect(isChildActive(switches, '/inventory', '?search=core&device_class=switch')).toBe(true);
  });

  it('is not lit on another page that happens to carry the same filter', () => {
    expect(isChildActive(switches, '/findings', '?device_class=switch')).toBe(false);
  });
});
