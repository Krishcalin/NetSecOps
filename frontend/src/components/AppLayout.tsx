/** Left-navigation shell (IF-UI-01).
 *
 * Navigation entries that belong to later phases are rendered disabled, with the phase
 * noted, rather than hidden: the shape of the product is visible from day one and there
 * is no guessing about what is missing versus broken.
 */

import { NavLink, Outlet, useNavigate } from 'react-router-dom';

import { useAuth } from '../features/auth/useAuth';
import { ROLE_LABELS } from '../features/auth/types';

interface NavItem {
  label: string;
  to?: string;
  permission?: string;
  phase?: string;
}

const NAV_ITEMS: NavItem[] = [
  { label: 'Dashboard', to: '/' },
  { label: 'Inventory', to: '/inventory', permission: 'device:read' },
  { label: 'Assessments', to: '/jobs', permission: 'job:read' },
  { label: 'Findings', to: '/findings', permission: 'finding:read' },
  { label: 'Vulnerabilities', to: '/vulnerabilities', permission: 'vuln:read' },
  // Sits with Inventory conceptually — it answers "what is on my network that I did not
  // put there" — but after Findings in the list, because until a scope is defined it has
  // nothing to show and should not be the second thing anyone sees.
  { label: 'Discovery', to: '/discovery', permission: 'discovery:read' },
  // A rulebase is configuration, so this sits behind the same permission as the config
  // viewer rather than behind a findings permission.
  { label: 'Firewall Analysis', to: '/firewall', permission: 'snapshot:read' },
  // Directly below the rulebase viewer, because it is the same question asked across
  // devices instead of one: that viewer answers "which rule matches here", this answers
  // "which firewalls are even in the way". Same permission, for the same reason — both
  // are assembled entirely out of stored configuration.
  { label: 'Path Analysis', to: '/topology', permission: 'snapshot:read' },
  // A conclusion about the estate rather than configuration, so it sits behind the
  // findings permission — unlike the rulebase viewer directly above it.
  { label: 'AAA Posture', to: '/aaa', permission: 'finding:read' },
  { label: 'Compliance', to: '/compliance', permission: 'report:read' },
  // Below Compliance because it is the archive of what the pages above said, and reads
  // oddly as an entry point: someone arriving with a question wants the live page first.
  { label: 'Reports', to: '/reports', permission: 'report:read' },
  { label: 'Integrations', phase: 'Phase 7' },
  { label: 'Audit Log', to: '/audit', permission: 'audit:read' },
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
      <aside className="sidebar">
        <div className="sidebar__brand">
          <span className="sidebar__brand-name">NetSecOps</span>
          <span className="sidebar__brand-sub">read-only assessment</span>
        </div>

        <nav className="sidebar__nav" aria-label="Main">
          {NAV_ITEMS.map((item) => {
            const permitted = !item.permission || can(item.permission);

            if (!item.to || !permitted) {
              return (
                <span
                  key={item.label}
                  className="sidebar__link sidebar__link--disabled"
                  aria-disabled="true"
                  title={
                    permitted
                      ? `Arrives in ${item.phase}`
                      : 'Your role does not have access to this area'
                  }
                >
                  {item.label}
                  {permitted && item.phase && <span className="sidebar__badge">{item.phase}</span>}
                </span>
              );
            }

            return (
              <NavLink
                key={item.label}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) =>
                  `sidebar__link${isActive ? ' sidebar__link--active' : ''}`
                }
              >
                {item.label}
              </NavLink>
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

      <main className="content">
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
