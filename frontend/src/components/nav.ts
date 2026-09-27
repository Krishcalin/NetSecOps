/** The navigation, as data (IF-UI-01).
 *
 * In its own module rather than beside the component that renders it, for two
 * reasons. A file that exports both a component and a constant loses React Fast
 * Refresh — eslint says so, and it is right. And this list is the authority for which
 * section a page belongs to, which sections.ts mirrors and sections.test.ts checks
 * the two agree on; that check should not have to import the whole layout to run.
 */

import type { IconName } from './Icon';
export interface NavItem {
  label: string;
  to?: string;
  permission?: string;
  phase?: string;
  icon?: IconName;
  /** Starts a new group, headed by this word. Twenty-two flat entries is a list
   *  somebody reads once and then hunts through; four named runs of four or five is
   *  one they navigate. The groups are the order the work happens in. */
  group?: string;
  /** Entries nested under this one, indented beneath it.
   *
   *  For a view of the *same* page rather than a different page — the inventory
   *  filtered to one kind of appliance is still the inventory, and giving each kind
   *  its own top-level entry would say otherwise. They carry a query string, so the
   *  filter they apply is the one the page's own control shows, not a second
   *  mechanism that could disagree with it. */
  children?: NavItem[];
}

/** The appliance types offered under Inventory.
 *
 * Three of the eight `DeviceClass` values, because these are the ones an operator
 * navigates by. The rest — wireless controllers, managers, AAA servers, and anything
 * still unclassified — are reachable from the page's own filter, which lists every
 * one; a sidebar that named all eight would be a filter control wearing a navigation
 * costume. */
const APPLIANCE_TYPES: NavItem[] = [
  { label: 'Routers', to: '/inventory?device_class=router', icon: 'path' },
  { label: 'Switches', to: '/inventory?device_class=switch', icon: 'device' },
  { label: 'Firewalls', to: '/inventory?device_class=firewall', icon: 'firewall' },
];

export const NAV_ITEMS: NavItem[] = [
  { label: 'Dashboard', to: '/', icon: 'dashboard' },
  {
    label: 'Inventory',
    to: '/inventory',
    permission: 'device:read',
    icon: 'inventory',
    group: 'Estate',
    children: APPLIANCE_TYPES,
  },
  // Directly below Inventory because it is the other half of reaching a device: an
  // inventory entry with no credential assigned to it fails its job before a single
  // command is sent, and that is the first thing a new deployment hits.
  { label: 'Credentials', to: '/credentials', permission: 'credential:read', icon: 'credential' },
  { label: 'Assessments', to: '/jobs', permission: 'job:read', icon: 'assessment' },
  // Directly below the run history, because it is the same subject asked forwards: that
  // page says what has run, this says what will.
  { label: 'Schedules', to: '/schedules', permission: 'job:read', icon: 'schedule' },
  {
    label: 'Findings',
    to: '/findings',
    permission: 'finding:read',
    icon: 'finding',
    group: 'Risk',
  },
  {
    label: 'Vulnerabilities',
    to: '/vulnerabilities',
    permission: 'vuln:read',
    icon: 'vulnerability',
  },
  // Sits with Inventory conceptually — it answers "what is on my network that I did not
  // put there" — but after Findings in the list, because until a scope is defined it has
  // nothing to show and should not be the second thing anyone sees.
  { label: 'Discovery', to: '/discovery', permission: 'discovery:read', icon: 'discovery' },
  // A rulebase is configuration, so this sits behind the same permission as the config
  // viewer rather than behind a findings permission.
  {
    label: 'Firewall Analysis',
    to: '/firewall',
    permission: 'snapshot:read',
    icon: 'firewall',
    group: 'Network',
  },
  // Directly below the rulebase viewer, because it is the same question asked across
  // devices instead of one: that viewer answers "which rule matches here", this answers
  // "which firewalls are even in the way". Same permission, for the same reason — both
  // are assembled entirely out of stored configuration.
  // Above path analysis rather than below it, because it is the earlier question: the
  // map is what somebody opens to find out what is out there, and a path query is
  // usually started from a device they found on it. Same permission — both are drawn
  // entirely from stored configuration.
  { label: 'Network Map', to: '/topology/map', permission: 'snapshot:read', icon: 'map' },
  { label: 'Path Analysis', to: '/topology', permission: 'snapshot:read', icon: 'path' },
  // Directly below path analysis because it is that engine run over every declared
  // zone pair at once. Behind `policy:read`, not `snapshot:read`: the page is only
  // meaningful once somebody has written the policy down, and that is policy.
  { label: 'Segmentation', to: '/segmentation', permission: 'policy:read', icon: 'segmentation' },
  // A conclusion about the estate rather than configuration, so it sits behind the
  // findings permission — unlike the rulebase viewer directly above it.
  { label: 'AAA Posture', to: '/aaa', permission: 'finding:read', icon: 'aaa' },
  // The three sit together and in this order because that is the sequence: a check is
  // the rule, a policy is where it applies, and an exception is where it applies and is
  // knowingly not met. Above Compliance, because compliance is what they add up to.
  { label: 'Checks', to: '/checks', permission: 'check:read', icon: 'check', group: 'Policy' },
  { label: 'Policies', to: '/policies', permission: 'policy:read', icon: 'policy' },
  // Behind `policy:read` rather than `exception:write`: the register is worth reading by
  // anyone who reads findings — an auditor especially — and filing one is the part that
  // needs the write permission.
  { label: 'Exceptions', to: '/exceptions', permission: 'policy:read', icon: 'exception' },
  { label: 'Compliance', to: '/compliance', permission: 'report:read', icon: 'compliance' },
  // Below Compliance because it is the archive of what the pages above said, and reads
  // oddly as an entry point: someone arriving with a question wants the live page first.
  { label: 'Reports', to: '/reports', permission: 'report:read', icon: 'report' },
  // Notification channels, delivery history and platform settings. Behind
  // `settings:read` rather than a device permission: a channel's configuration decides
  // where security alerts go, and that belongs with the platform owner rather than with
  // the people operating the devices being reported on.
  // With Settings rather than at the top, though it is the first thing a new deployment
  // needs: an administration area belongs below the work the product is for, and putting
  // user administration first would make NetSecOps look like an access-management tool.
  { label: 'Users', to: '/users', permission: 'user:read', icon: 'users', group: 'Administration' },
  { label: 'Settings', to: '/settings', permission: 'settings:read', icon: 'settings' },
  { label: 'Audit Log', to: '/audit', permission: 'audit:read', icon: 'audit' },
];

/** Whether a nested entry describes the view currently on screen.
 *
 * The path has to match and every filter the entry carries has to be the one in force.
 * Extra parameters are ignored, so paging through the switches or searching within
 * them keeps "Switches" lit — the reader has not left that view, and unlighting it the
 * moment they turn a page would make the sidebar disagree with the page.
 */
export function isChildActive(to: string, pathname: string, search: string): boolean {
  const [path, query = ''] = to.split('?');
  if (path !== pathname) return false;

  const current = new URLSearchParams(search);
  return [...new URLSearchParams(query)].every(([key, value]) => current.get(key) === value);
}
