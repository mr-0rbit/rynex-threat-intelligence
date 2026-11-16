import { lazy, Suspense } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth";
import { Layout } from "./components/Layout";
import { Spinner } from "./components/ui";

const Login = lazy(() => import("./pages/Login").then((module) => ({ default: module.Login })));
const OIDCCallback = lazy(() => import("./pages/OIDCCallback").then((module) => ({ default: module.OIDCCallback })));
const Dashboard = lazy(() => import("./pages/Dashboard").then((module) => ({ default: module.Dashboard })));
const Alerts = lazy(() => import("./pages/Alerts").then((module) => ({ default: module.Alerts })));
const Breaches = lazy(() => import("./pages/Breaches").then((module) => ({ default: module.Breaches })));
const BreachDetail = lazy(() => import("./pages/BreachDetail").then((module) => ({ default: module.BreachDetail })));
const Vulnerabilities = lazy(() => import("./pages/Vulnerabilities").then((module) => ({ default: module.Vulnerabilities })));
const IOCs = lazy(() => import("./pages/IOCs").then((module) => ({ default: module.IOCs })));
const MitreMatrix = lazy(() => import("./pages/MitreMatrix").then((module) => ({ default: module.MitreMatrix })));
const Integrations = lazy(() => import("./pages/Integrations").then((module) => ({ default: module.Integrations })));
const News = lazy(() => import("./pages/News").then((module) => ({ default: module.News })));
const Sources = lazy(() => import("./pages/Sources").then((module) => ({ default: module.Sources })));
const Investigations = lazy(() => import("./pages/Investigations").then((module) => ({ default: module.Investigations })));
const SearchResults = lazy(() => import("./pages/Search").then((module) => ({ default: module.SearchResults })));
const DarkWeb = lazy(() => import("./pages/DarkWeb").then((module) => ({ default: module.DarkWeb })));
const Assets = lazy(() => import("./pages/Assets").then((module) => ({ default: module.Assets })));
const Account = lazy(() => import("./pages/Account").then((module) => ({ default: module.Account })));

function ProtectedApp() {
  const { user, loading } = useAuth();
  if (loading) return <Spinner label="Authenticating…" />;
  if (!user) return <Navigate to="/login" replace />;
  return (
    <Routes>
        <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/investigations" element={<Investigations />} />
        <Route path="/breaches" element={<Breaches />} />
        <Route path="/breaches/:breachId" element={<BreachDetail />} />
        <Route path="/darkweb" element={<DarkWeb />} />
        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
        <Route path="/mitre" element={<MitreMatrix />} />
        <Route path="/iocs" element={<IOCs />} />
        <Route path="/integrations" element={<Integrations />} />
        <Route path="/news" element={<News />} />
        <Route path="/sources" element={<Sources />} />
        <Route path="/assets" element={<Assets />} />
        <Route path="/account" element={<Account />} />
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
        <Suspense fallback={<Spinner label="Loading platform…" />}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/oidc/callback" element={<OIDCCallback />} />
            <Route path="/*" element={<ProtectedApp />} />
          </Routes>
        </Suspense>
      </BrowserRouter>
    </AuthProvider>
  );
}
