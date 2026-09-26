import { useEffect } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { Spin } from 'antd';
import { useAuthStore } from '@/store/auth';
import BasicLayout from '@/layouts/BasicLayout';
import LoginPage from '@/pages/login';
import DashboardPage from '@/pages/dashboard';
import VulnerabilityListPage from '@/pages/vulnerability/List';
import VulnerabilityDetailPage from '@/pages/vulnerability/Detail';
import ProjectListPage from '@/pages/project/List';
import ProjectDetailPage from '@/pages/project/Detail';
import ScanListPage from '@/pages/scan/List';
import ScanDetailPage from '@/pages/scan/Detail';
import SampleListPage from '@/pages/sample/List';
import ModelDetectPage from '@/pages/model/Detect';
import SettingsPage from '@/pages/setting/Index';

/** 需要登录才能访问的包装 */
function RequireAuth({ children }: { children: React.ReactNode }) {
  const { user, initialized } = useAuthStore();
  const location = useLocation();

  if (!initialized) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh' }}>
        <Spin size="large" tip="正在恢复会话…">
          <div style={{ padding: 40 }} />
        </Spin>
      </div>
    );
  }

  if (!user) {
    const next = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/login?next=${next}`} replace />;
  }
  return <>{children}</>;
}

export default function App() {
  const fetchMe = useAuthStore((s) => s.fetchMe);

  useEffect(() => {
    void fetchMe();
  }, [fetchMe]);

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <RequireAuth>
            <BasicLayout />
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="vulnerabilities" element={<VulnerabilityListPage />} />
        <Route path="vulnerabilities/:id" element={<VulnerabilityDetailPage />} />
        <Route path="projects" element={<ProjectListPage />} />
        <Route path="projects/:id" element={<ProjectDetailPage />} />
        <Route path="scans" element={<ScanListPage />} />
        <Route path="scans/:scanNo" element={<ScanDetailPage />} />
        <Route path="samples" element={<SampleListPage />} />
        <Route path="model" element={<ModelDetectPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
  );
}
