/** Left-navigation shell (IF-UI-01).
 *
 * Navigation entries that belong to later phases are rendered disabled, with the phase
 * noted, rather than hidden: the shape of the product is visible from day one and there
 * is no guessing about what is missing versus broken.
 */

import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from '../features/auth/useAuth';
import { ROLE_LABELS } from '../features/auth/types';
import { Icon } from './Icon';
import { NAV_ITEMS } from './nav';
import { sectionTone } from './sections';

export function AppLayout() {
  const { user, logout, can } = useAuth();
  const navigate = useNavigate();
  const { pathname } = useLocation();

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
              <span
                key={`${item.label}-group`}
                className="sidebar__group"
                // The colour of the section this run leads to, taken from the first
                // entry's own route — so the heading, the page header's rule and the
                // chip on that page are all one decision rather than three.
                style={{ '--section': sectionTone(item.to ?? '/') } as React.CSSProperties}
              >
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
      {/* The section's colour, set once from the route. Everything below inherits it,
          so a page header tints itself without needing router context of its own. */}
      <main
        className="content"
        id="main"
        tabIndex={-1}
        style={{ '--section': sectionTone(pathname) } as React.CSSProperties}
      >
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
