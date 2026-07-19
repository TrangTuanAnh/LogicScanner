import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { AgentTasksPage } from "./pages/AgentTasksPage";
import { FindingsPage } from "./pages/FindingsPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { OverviewPage } from "./pages/OverviewPage";
import { RepositoriesPage } from "./pages/RepositoriesPage";
import { RepositoryDetailPage } from "./pages/RepositoryDetailPage";
import { RunsPage } from "./pages/RunsPage";
import { SystemPage } from "./pages/SystemPage";
import { TwinPage } from "./pages/TwinPage";

export function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<OverviewPage />} />
        <Route path="repositories" element={<RepositoriesPage />} />
        <Route path="repositories/:analysisId" element={<RepositoryDetailPage />} />
        <Route path="agents" element={<AgentTasksPage />} />
        <Route path="twin" element={<TwinPage />} />
        <Route path="runs" element={<RunsPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="system" element={<SystemPage />} />
        <Route path="overview" element={<Navigate to="/" replace />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
