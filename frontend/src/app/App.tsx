/** Application shell and routing (IF-UI-01).
 *
 * Only the routes delivered so far are live. The remaining navigation entries from
 * IF-UI-01 are rendered as disabled placeholders so the information architecture is
 * visible from the start and each later phase fills one in.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';

import { AuthProvider } from '../features/auth/AuthProvider';
import { useAuth } from '../features/auth/useAuth';
import { LoginPage } from '../features/auth/LoginPage';
import { AppLayout } from '../components/AppLayout';
import { DashboardPage } from './DashboardPage';
import { InventoryPage } from './InventoryPage';
import { ImportPage } from './ImportPage';
import { DeviceConfigPage } from './DeviceConfigPage';
import { FirewallPage } from './FirewallPage';
import { AaaPage } from './AaaPage';
import { FindingsPage } from './FindingsPage';
import { CompliancePage } from './CompliancePage';
import { JobsPage } from './JobsPage';
import { AuditLogPage } from './AuditLogPage';
import { ProfilePage } from './ProfilePage';
import { NotFoundPage } from './NotFoundPage';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (failureCount, error) => {
        // Never retry an authorization failure; it will not start succeeding.
        const status = (error as { status?: number })?.status;
        if (status === 401 || status === 403) return false;
        return failureCount < 2;
      },
      staleTime: 30_000,
      refetchOnWindowFocus: false,
    },
  },
});

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();

  if (loading) {
    return <div className="page-loading">Loading…</div>;
  }
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

function RedirectIfAuthenticated({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();

  if (loading) {
    return <div className="page-loading">Loading…</div>;
  }
  return user ? <Navigate to="/" replace /> : <>{children}</>;
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            <Route
              path="/login"
              element={
                <RedirectIfAuthenticated>
                  <LoginPage />
                </RedirectIfAuthenticated>
              }
            />
            <Route
              path="/"
              element={
                <RequireAuth>
                  <AppLayout />
                </RequireAuth>
              }
            >
              <Route index element={<DashboardPage />} />
              <Route path="inventory" element={<InventoryPage />} />
              <Route path="inventory/import" element={<ImportPage />} />
              <Route path="inventory/:deviceId/config" element={<DeviceConfigPage />} />
              {/* Both spellings reach the same page: the nav entry has no device yet and
                  offers a picker, while a link from a device goes straight to its rules. */}
              <Route path="inventory/:deviceId/firewall" element={<FirewallPage />} />
              <Route path="firewall" element={<FirewallPage />} />
              {/* Estate-wide rather than per-device: the whole subject is what the
                  devices and the AAA servers disagree about. */}
              <Route path="aaa" element={<AaaPage />} />
              <Route path="jobs" element={<JobsPage />} />
              <Route path="findings" element={<FindingsPage />} />
              <Route path="compliance" element={<CompliancePage />} />
              <Route path="audit" element={<AuditLogPage />} />
              <Route path="profile" element={<ProfilePage />} />
              <Route path="*" element={<NotFoundPage />} />
            </Route>
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
