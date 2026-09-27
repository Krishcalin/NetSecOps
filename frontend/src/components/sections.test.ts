/** The section colours agree with the navigation that leads to them.
 *
 * The map in `sections.ts` is a second statement of something the sidebar already
 * says, and a second statement drifts. It drifted before this test existed: Firewall
 * Analysis reads as a Risk page and is filed under Network — because it is assembled
 * entirely from stored configuration — and the first version of the map guessed Risk.
 * The page header would then have been violet while the sidebar entry it was reached
 * from sat under a teal heading, leaving a reader with two answers to "where am I".
 *
 * So the sidebar is authoritative and this walks it.
 */

import { describe, expect, it } from 'vitest';

import { NAV_ITEMS } from './nav';
import { SECTION_LABELS, sectionFor, sectionTone, type Section } from './sections';

/** Every entry paired with the group heading above it — the sidebar renders a heading
 *  before an item and it applies until the next one, so the run has to be rebuilt the
 *  same way to know what an entry sits under. */
function entriesWithGroup(): { to: string; label: string; group: string }[] {
  const out: { to: string; label: string; group: string }[] = [];
  let group = 'Dashboard';

  for (const item of NAV_ITEMS) {
    if (item.group) group = item.group;
    if (item.to) out.push({ to: item.to, label: item.label, group });
  }
  return out;
}

const BY_LABEL: Record<string, Section> = Object.fromEntries(
  (Object.entries(SECTION_LABELS) as [Section, string][]).map(([section, label]) => [
    label,
    section,
  ]),
);

describe('section colours', () => {
  it.each(entriesWithGroup())(
    '$label is coloured as its navigation group ($group)',
    ({ to, group }) => {
      expect(BY_LABEL[group]).toBeDefined();
      expect(sectionFor(to)).toBe(BY_LABEL[group]);
    },
  );

  it('covers every navigation group', () => {
    // A group the map has never heard of would silently fall through to the dashboard
    // colour, which is the failure that looks like a design choice.
    const groups = new Set(entriesWithGroup().map((entry) => entry.group));

    expect([...groups].sort()).toEqual(Object.values(SECTION_LABELS).sort());
  });

  it('puts a device rulebase with the firewall analysis, not with the device', () => {
    // `/inventory/:id/firewall` is reached from a device but belongs to Network.
    expect(sectionFor('/inventory/abc-123/firewall')).toBe('network');
    expect(sectionFor('/inventory/abc-123/config')).toBe('estate');
  });

  it('gives an unknown route the dashboard colour rather than none', () => {
    // A missing custom property would leave the page header's rule invisible, so a
    // route nobody mapped still gets a real colour.
    expect(sectionFor('/something-new')).toBe('dashboard');
    expect(sectionTone('/something-new')).toBe('var(--sec-dashboard)');
  });

  it('names a custom property that the stylesheet defines', async () => {
    // The tone is interpolated into `var(--sec-…)`, so a renamed token would fail
    // silently: the rule would fall back to the border colour and look deliberate.
    const css = await import('fs').then((fs) =>
      fs.readFileSync('src/styles/index.css', 'utf8'),
    );

    for (const section of Object.keys(SECTION_LABELS) as Section[]) {
      expect(css).toContain(`--sec-${section}:`);
    }
  });
});
