/** The console's device-class vocabulary matches the server's.
 *
 * Read out of `db/models/inventory.py` rather than restated here, for the same reason
 * `stylesheet.test.ts` reads the stylesheet: a second copy of a list is a list that
 * drifts, and the drift is silent in the direction that matters. A class the API
 * accepts and the console does not offer is, to an operator, a class the product does
 * not have — which is exactly what happened to CERT-In and CEA while the compliance
 * framework list was hard-coded.
 *
 * Two classes were added on 2026-09-28 (`load_balancer`, `waf`) and there were **four**
 * separate copies of the vocabulary in this front end at the time — the `DeviceClass`
 * union, the Inventory page's picker, the Risk Trends page's picker, and a label map
 * beside each. This file exists so the next two do not have to be found by hand.
 */

import { readFileSync } from 'fs';

import { describe, expect, it } from 'vitest';

import {
  CLASS_LABELS,
  CLASS_SINGULAR,
  DEVICE_CLASSES,
  VENDORS,
  VENDOR_LABELS,
  classLabel,
} from './types';

/** The members of a `StrEnum` in the backend model, by class name. */
function backendEnum(name: string, until: string): string[] {
  const source = readFileSync('../backend/netsecops/db/models/inventory.py', 'utf8');
  const body = source.slice(
    source.indexOf(`class ${name}(StrEnum):`),
    source.indexOf(`class ${until}(StrEnum):`),
  );

  // Guard the guard: an empty slice makes every assertion below vacuously true, which
  // is how a renamed class turns this file into decoration.
  expect(body, `${name} not found in the backend model`).not.toHaveLength(0);
  return [...body.matchAll(/^\s{4}[A-Z_]+ = "([a-z_]+)"$/gm)].map((match) => match[1]!);
}

describe('the device-class vocabulary', () => {
  it('offers exactly what the server accepts', () => {
    expect([...DEVICE_CLASSES].sort()).toEqual(
      backendEnum('DeviceClass', 'Criticality').sort(),
    );
  });

  it('includes the two classes added for load balancers and WAFs', () => {
    // Named outright rather than left to the comparison above, because that test also
    // passes if both sides lose them together.
    expect(DEVICE_CLASSES).toContain('load_balancer');
    expect(DEVICE_CLASSES).toContain('waf');
  });

  it('names every class in both forms', () => {
    for (const value of DEVICE_CLASSES) {
      expect(CLASS_LABELS[value], `${value} has no plural label`).toBeDefined();
      expect(CLASS_SINGULAR[value], `${value} has no singular label`).toBeDefined();
    }
  });

  it('falls back to the key rather than to nothing', () => {
    // An unlabelled row is worse than an ugly one: it reads as a loading failure
    // rather than as a console that is behind its server.
    expect(classLabel('something_new')).toBe('something_new');
    expect(classLabel('something_new', 'plural')).toBe('something_new');
  });

  it('distinguishes the two forms, rather than aliasing one to the other', () => {
    expect(classLabel('firewall')).toBe('Firewall');
    expect(classLabel('firewall', 'plural')).toBe('Firewalls');
  });

  it('leads with the three the sidebar navigates by', () => {
    // `nav.ts` offers Routers, Switches and Firewalls as sub-entries under both
    // Inventory and Risk Trends. A picker that buried them under the appliances
    // nobody filters by would disagree with the navigation beside it.
    expect(DEVICE_CLASSES.slice(0, 3)).toEqual(['router', 'switch', 'firewall']);
  });
});

describe('the vendor vocabulary', () => {
  /** The same failure one field along. A vendor the server accepts and the console
   *  cannot name renders as a blank cell in the inventory, which reads as missing
   *  data about the device rather than as a missing label. */

  it('offers exactly what the server accepts', () => {
    expect([...VENDORS].sort()).toEqual(backendEnum('Vendor', 'DeviceClass').sort());
  });

  it('names every one of them', () => {
    for (const vendor of VENDORS) {
      expect(VENDOR_LABELS[vendor], `${vendor} has no label`).toBeDefined();
    }
  });

  it('includes the two vendors added with the new device families', () => {
    expect(VENDOR_LABELS.radware).toBe('Radware');
    expect(VENDOR_LABELS.barracuda).toBe('Barracuda');
  });
});
