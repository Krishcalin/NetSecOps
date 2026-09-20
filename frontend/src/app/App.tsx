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
import { CredentialsPage } from './CredentialsPage';
import { FirewallPage } from './FirewallPage';
import { AaaPage } from './AaaPage';
import { FindingsPage } from './FindingsPage';
import { VulnerabilitiesPage } from './VulnerabilitiesPage';
import { DiscoveryPage } from './DiscoveryPage';
import { ChecksPage } from './ChecksPage';
import { PoliciesPage } from './PoliciesPage';
import { ExceptionsPage } from './ExceptionsPage';
import { CompliancePage } from './CompliancePage';
import { ReportsPage } from './ReportsPage';
import { TopologyPage } from './TopologyPage';
import { JobsPage } from './JobsPage';
import { UsersPage } from './UsersPage';
import { SettingsPage } from './SettingsPage';
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
              <Route path="credentials" element={<CredentialsPage />} />
              {/* Both spellings reach the same page: the nav entry has no device yet and
                  offers a picker, while a link from a device goes straight to its rules. */}
              <Route path="inventory/:deviceId/firewall" element={<FirewallPage />} />
              <Route path="firewall" element={<FirewallPage />} />
              {/* Estate-wide by nature: the question is which devices are between two
                  hosts, which cannot be asked of one device. */}
              <Route path="topology" element={<TopologyPage />} />
              {/* Estate-wide rather than per-device: the whole subject is what the
                  devices and the AAA servers disagree about. */}
              <Route path="aaa" element={<AaaPage />} />
              <Route path="jobs" element={<JobsPage />} />
              <Route path="findings" element={<FindingsPage />} />
              {/* Estate-wide: a CVE is about a software version, and the same version
                  is usually on many devices, so the question is rarely per-device. */}
              <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
              <Route path="discovery" element={<DiscoveryPage />} />
              {/* The rules, where they apply, and where they were deliberately not
                  applied. Three pages rather than one because they are edited by
                  different people at different times, but they read as a sequence. */}
              <Route path="checks" element={<ChecksPage />} />
              <Route path="policies" element={<PoliciesPage />} />
              <Route path="exceptions" element={<ExceptionsPage />} />
              <Route path="compliance" element={<CompliancePage />} />
              {/* The archive, not a view of it: every report here is frozen at the
                  moment it was generated. */}
              <Route path="reports" element={<ReportsPage />} />
              <Route path="users" element={<UsersPage />} />
              <Route path="settings" element={<SettingsPage />} />
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
