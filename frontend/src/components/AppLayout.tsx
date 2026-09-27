/** Left-navigation shell (IF-UI-01).
 *
 * Navigation entries that belong to later phases are rendered disabled, with the phase
 * noted, rather than hidden: the shape of the product is visible from day one and there
 * is no guessing about what is missing versus broken.
 */

import { NavLink, Outlet, useNavigate } from 'react-router-dom';

import { useAuth } from '../features/auth/useAuth';
import { ROLE_LABELS } from '../features/auth/types';
import { Icon, type IconName } from './Icon';

interface NavItem {
  label: string;
  to?: string;
  permission?: string;
  phase?: string;
  icon?: IconName;
  /** Starts a new group, headed by this word. Twenty-two flat entries is a list
   *  somebody reads once and then hunts through; four named runs of four or five is
   *  one they navigate. The groups are the order the work happens in. */
  group?: string;
}

const NAV_ITEMS: NavItem[] = [
  { label: 'Dashboard', to: '/', icon: 'dashboard' },
  {
    label: 'Inventory',
    to: '/inventory',
    permission: 'device:read',
    icon: 'inventory',
    group: 'Estate',
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

export function AppLayout() {
  const { user, logout, can } = useAuth();
  const navigate = useNavigate();

  async function handleSignOut() {
    await logout();
    navigate('/login', { replace: true });
  }

  return (
    <div className="layout">
      {/* Twenty-one navigation items sit before the content on every route, so without
          this a keyboard user tabs through all of them again after each navigation.
          WCAG 2.4.1, Level A. Visually hidden until focused, then it appears. */}
      <a className="skip-link" href="#main">
        Skip to main content
      </a>
      <aside className="sidebar">
        <div className="sidebar__brand">
          {/* Decorative: the product name is the very next element, and a non-empty
              `alt` would have a screen reader announce "NetSecOps" twice. */}
          <img
            className="sidebar__brand-mark brand-panel"
            src="/brand/netsecops-mark.png"
            alt=""
            width={26}
            height={26}
          />
          <span className="sidebar__brand-text">
            <span className="sidebar__brand-name">NetSecOps</span>
            <span className="sidebar__brand-sub">read-only assessment</span>
          </span>
        </div>

        <nav className="sidebar__nav" aria-label="Main">
          {NAV_ITEMS.map((item) => {
            const permitted = !item.permission || can(item.permission);
            // Rendered before the entry it heads rather than as a wrapper, so a group
            // whose every entry is hidden by permission leaves its heading behind —
            // which is the honest outcome: the area exists and this role cannot see
            // it, and a vanished heading would make the product look smaller than it
            // is depending on who signed in.
            const heading = item.group ? (
              <span key={`${item.label}-group`} className="sidebar__group">
                {item.group}
              </span>
            ) : null;

            if (!item.to || !permitted) {
              return (
                <span key={item.label} className="sidebar__entry">
                  {heading}
                  <span
                    className="sidebar__link sidebar__link--disabled"
                    aria-disabled="true"
                    title={
                      permitted
                        ? `Arrives in ${item.phase}`
                        : 'Your role does not have access to this area'
                    }
                  >
                    {item.icon && <Icon name={item.icon} size={17} />}
                    {item.label}
                    {permitted && item.phase && (
                      <span className="sidebar__badge">{item.phase}</span>
                    )}
                  </span>
                </span>
              );
            }

            return (
              <span key={item.label} className="sidebar__entry">
                {heading}
                <NavLink
                  to={item.to}
                  end={item.to === '/'}
                  className={({ isActive }) =>
                    `sidebar__link${isActive ? ' sidebar__link--active' : ''}`
                  }
                >
                  {item.icon && <Icon name={item.icon} size={17} />}
                  {item.label}
                </NavLink>
              </span>
            );
          })}
        </nav>

        <div className="sidebar__user">
          <NavLink to="/profile" className="sidebar__user-link">
            <span className="sidebar__user-name">{user?.full_name || user?.username}</span>
            <span className="sidebar__user-role">
              {user?.roles.map((r) => ROLE_LABELS[r]).join(', ') || 'No role assigned'}
            </span>
          </NavLink>
          <button className="button button--ghost button--small" onClick={handleSignOut}>
            Sign out
          </button>
        </div>
      </aside>

      {/* `tabIndex={-1}` so the skip link can actually move focus here. Without it the
          browser scrolls to the target and leaves focus behind in the sidebar, which
          looks like the link worked and leaves the next Tab back at item two. */}
      <main className="content" id="main" tabIndex={-1}>
        {user?.must_change_password && (
          <div className="alert alert--warning" role="alert">
            Your password must be changed. Visit <NavLink to="/profile">your profile</NavLink> to
            set a new one.
          </div>
        )}
        <Outlet />
      </main>
    </div>
  );
}
