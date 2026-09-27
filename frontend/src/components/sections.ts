/** Which part of the product a route belongs to, and what colour that part is.
 *
 * Twenty-six screens share one layout, one type scale and one accent, which made them
 * hard to tell apart at a glance — the fastest way to know where you were was to read
 * the heading. The navigation already groups them into five runs; this gives each run
 * a colour and puts it on the page header, so the answer arrives before the reading
 * does.
 *
 * **Derived from the route, never passed in.** A `tone` prop on each page would drift
 * the moment somebody moved an entry between groups, and the page would then disagree
 * with the sidebar about where it lives — which is worse than no colour, because the
 * reader now has two answers. One map, and the sidebar and the header both read it.
 *
 * **It is identity, not meaning.** The severity ramp is the only palette in this
 * product that asserts anything, and these are deliberately outside it: no red, amber
 * or green, so a page header is never mistaken for a verdict about what is on the page.
 */

export type Section = 'dashboard' | 'estate' | 'risk' | 'network' | 'policy' | 'admin';

/** Longest prefix wins. The groups are the sidebar's, not a second opinion about them:
 *  `sections.test.ts` walks `NAV_ITEMS` and fails if the two ever disagree, which they
 *  did on the first attempt — Firewall Analysis reads as Risk and is filed under
 *  Network, because the page is assembled entirely from stored configuration. */
const ROUTES: [string, Section][] = [
  ['/inventory', 'estate'],
  ['/credentials', 'estate'],
  ['/jobs', 'estate'],
  ['/schedules', 'estate'],

  ['/findings', 'risk'],
  ['/vulnerabilities', 'risk'],
  ['/discovery', 'risk'],

  ['/firewall', 'network'],
  ['/topology', 'network'],
  ['/segmentation', 'network'],
  ['/aaa', 'network'],

  ['/checks', 'policy'],
  ['/policies', 'policy'],
  ['/exceptions', 'policy'],
  ['/compliance', 'policy'],
  ['/reports', 'policy'],

  ['/users', 'admin'],
  ['/settings', 'admin'],
  ['/audit', 'admin'],
  ['/profile', 'admin'],
];

export function sectionFor(pathname: string): Section {
  if (pathname === '/' || pathname === '') return 'dashboard';

  // A device's rulebase hangs off `/inventory/:id/firewall` but belongs to Network
  // with the rest of the firewall analysis, not to Estate with the device record.
  //
  // Scoped to `/inventory` rather than matching any path ending in `/firewall`: the
  // looser version also swallowed the top-level `/firewall` route, which made its
  // entry in the table below unreachable — so a mutation test could change that entry
  // to the wrong section and nothing failed.
  if (pathname.startsWith('/inventory') && pathname.endsWith('/firewall')) return 'network';

  const match = ROUTES.filter(([prefix]) => pathname.startsWith(prefix)).sort(
    (a, b) => b[0].length - a[0].length,
  )[0];

  return match ? match[1] : 'dashboard';
}

export function sectionTone(pathname: string): string {
  return `var(--sec-${sectionFor(pathname)})`;
}

/** What the sidebar calls each run, keyed by the section it maps to. Kept here beside
 *  the colours so a renamed group cannot end up tinted as a different one. */
export const SECTION_LABELS: Record<Section, string> = {
  dashboard: 'Dashboard',
  estate: 'Estate',
  risk: 'Risk',
  network: 'Network',
  policy: 'Policy',
  admin: 'Administration',
};
