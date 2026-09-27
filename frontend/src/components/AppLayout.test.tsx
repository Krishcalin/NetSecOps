/** The application shell (IF-UI-01).
 *
 * Untested until now, which is why this file starts with more than the change that
 * prompted it: the shell is the one component every page renders inside, so a
 * regression here is a regression on twenty-six screens at once.
 *
 * The change: the account controls moved from the foot of the navigation to the top
 * right. At the bottom of the sidebar, sign out sat below twenty-one entries and off
 * the bottom of a short window — the one control people go looking for, in the place
 * they look last.
 */

import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { AppLayout } from './AppLayout';

const logout = vi.fn();
let user: Record<string, unknown> | null = {
  username: 'admin',
  full_name: '',
  roles: ['super_admin'],
  permissions: ['device:read'],
  must_change_password: false,
};

vi.mock('../features/auth/useAuth', () => ({
  useAuth: () => ({ user, logout, can: () => true }),
}));

function renderLayout(at = '/') {
  return render(
    <MemoryRouter initialEntries={[at]}>
      <Routes>
        <Route element={<AppLayout />}>
          <Route path="*" element={<p>page content</p>} />
        </Route>
      </Routes>
    </MemoryRouter>,
  );
}

describe('AppLayout', () => {
  beforeEach(() => {
    logout.mockReset();
    user = {
      username: 'admin',
      full_name: '',
      roles: ['super_admin'],
      permissions: ['device:read'],
      must_change_password: false,
    };
  });

  describe('the account controls', () => {
    it('sit in a banner rather than in the navigation', async () => {
      // `banner` is the landmark a screen reader user jumps to for exactly this, and
      // it is what makes the controls reachable without walking the whole nav.
      renderLayout();

      const bar = screen.getByRole('banner');
      expect(within(bar).getByText('admin')).toBeInTheDocument();
      expect(within(bar).getByRole('button', { name: 'Sign out' })).toBeInTheDocument();

      const nav = screen.getByRole('navigation', { name: 'Main' });
      expect(within(nav).queryByRole('button', { name: 'Sign out' })).toBeNull();
    });

    it('names the signed-in user and their role', async () => {
      renderLayout();

      const bar = screen.getByRole('banner');
      expect(within(bar).getByText('admin')).toBeInTheDocument();
      expect(within(bar).getByText('Super Admin')).toBeInTheDocument();
    });

    it('prefers a full name when there is one', async () => {
      user = { ...user, full_name: 'Dana Okafor' };
      renderLayout();

      expect(within(screen.getByRole('banner')).getByText('Dana Okafor')).toBeInTheDocument();
    });

    it('says outright when an account has no role', async () => {
      // A blank where the role goes reads as a rendering fault. "No role assigned" is
      // a real state — an account can be created before anybody grants it anything —
      // and it explains why the rest of the product looks empty.
      user = { ...user, roles: [] };
      renderLayout();

      expect(within(screen.getByRole('banner')).getByText('No role assigned')).toBeInTheDocument();
    });

    it('signs out', async () => {
      renderLayout();

      await userEvent.click(screen.getByRole('button', { name: 'Sign out' }));

      expect(logout).toHaveBeenCalled();
    });

    it('links to the profile', async () => {
      renderLayout();

      const bar = screen.getByRole('banner');
      expect(within(bar).getByRole('link')).toHaveAttribute('href', '/profile');
    });
  });

  describe('the shell', () => {
    it('keeps the skip link pointing at the page', async () => {
      // WCAG 2.4.1. Twenty-one navigation entries sit before the content on every
      // route, so without this a keyboard user tabs through all of them again after
      // each navigation.
      renderLayout();

      expect(screen.getByRole('link', { name: /skip to main content/i })).toHaveAttribute(
        'href',
        '#main',
      );
      expect(screen.getByRole('main')).toHaveAttribute('id', 'main');
    });

    it('renders the routed page inside main', async () => {
      renderLayout();

      expect(within(screen.getByRole('main')).getByText('page content')).toBeInTheDocument();
    });

    it('warns in the page, not the bar, when a password must be changed', async () => {
      // It is about this session's state and belongs with the content it blocks; in
      // the bar it would be a permanent fixture of the chrome.
      user = { ...user, must_change_password: true };
      renderLayout();

      const alert = screen.getByRole('alert');
      expect(alert).toHaveTextContent(/password must be changed/i);
      expect(screen.getByRole('main').contains(alert)).toBe(true);
    });
  });
});
