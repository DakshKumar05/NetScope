import { Navigate, Route, Routes } from 'react-router-dom';
import AppLayout from '@/layouts/AppLayout';
import DashboardPage from '@/pages/DashboardPage';
import NewScanPage from '@/pages/NewScanPage';
import ScansPage from '@/pages/ScansPage';
import ScanDetailPage from '@/pages/ScanDetailPage';
import HostDetailPage from '@/pages/HostDetailPage';
import FindingsPage from '@/pages/FindingsPage';

export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route index element={<DashboardPage />} />
        <Route path="scans" element={<ScansPage />} />
        <Route path="scans/new" element={<NewScanPage />} />
        <Route path="scans/:scanId" element={<ScanDetailPage />} />
        <Route path="hosts/:hostId" element={<HostDetailPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
