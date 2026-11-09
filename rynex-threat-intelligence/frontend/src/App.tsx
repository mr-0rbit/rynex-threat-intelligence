import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth";
import { Layout } from "./components/Layout";
import { Spinner } from "./components/ui";
import { Login } from "./pages/Login";
import { Dashboard } from "./pages/Dashboard";
import { Alerts } from "./pages/Alerts";
import { Breaches } from "./pages/Breaches";
import { Vulnerabilities } from "./pages/Vulnerabilities";
import { IOCs } from "./pages/IOCs";
import { News } from "./pages/News";
import { Sources } from "./pages/Sources";
import { SearchResults } from "./pages/Search";
import { DarkWeb } from "./pages/DarkWeb";

function ProtectedApp() {
  const { user, loading } = useAuth();
  if (loading) return <Spinner label="Authenticating…" />;
  if (!user) return <Navigate to="/login" replace />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/breaches" element={<Breaches />} />
        <Route path="/darkweb" element={<DarkWeb />} />
        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
        <Route path="/iocs" element={<IOCs />} />
        <Route path="/news" element={<News />} />
        <Route path="/sources" element={<Sources />} />
        <Route path="/search" element={<SearchResults />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/*" element={<ProtectedApp />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
