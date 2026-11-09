import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  BellRing,
  Database,
  Globe2,
  LayoutDashboard,
  LogOut,
  Newspaper,
  Rss,
  Search,
  Shield,
  Bug,
} from "lucide-react";
import { api } from "../api/client";
import { useAuth } from "../auth";

const NAV = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard", end: true },
  { to: "/alerts", icon: AlertTriangle, label: "Alerts" },
  { to: "/breaches", icon: Database, label: "Breaches" },
  { to: "/vulnerabilities", icon: Bug, label: "Vulnerabilities" },
  { to: "/iocs", icon: Shield, label: "IOCs" },
  { to: "/news", icon: Newspaper, label: "News" },
  { to: "/sources", icon: Rss, label: "Sources" },
];

export function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [search, setSearch] = useState("");

  useEffect(() => {
    let active = true;
    const tick = () => {
      api<{ items: { status: string }[] }>("/alerts?limit=1")
        .catch(() => null)
        .then((r) => active && r);
    };
    tick();
    return () => {
      active = false;
    };
  }, []);

  const runSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (search.trim().length < 2) return;
    navigate(`/search?q=${encodeURIComponent(search.trim())}`);
  };

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-20 flex w-56 flex-col border-r border-rynex-border bg-rynex-panel">
        <div className="flex items-center gap-2.5 border-b border-rynex-border px-4 py-4">
          <div className="flex h-9 w-9 items-center justify-center rounded-md bg-rynex-accent/10 ring-1 ring-rynex-accent/30">
            <Activity className="h-5 w-5 text-rynex-accent" />
          </div>
          <div>
            <p className="text-sm font-bold tracking-wide text-white">RTIP</p>
            <p className="text-[10px] font-medium uppercase tracking-widest text-rynex-accent">
              Detect · Analyze · Respond
            </p>
          </div>
        </div>
        <nav className="flex-1 space-y-0.5 p-2">
          {NAV.map(({ to, icon: Icon, label, ...rest }) => (
            <NavLink
              key={to}
              to={to}
              end={"end" in rest}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? "bg-rynex-accent/10 font-medium text-rynex-accent"
                    : "text-slate-400 hover:bg-rynex-border/40 hover:text-slate-200"
                }`
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-rynex-border p-3">
          <div className="flex items-center justify-between gap-2">
            <div className="min-w-0">
              <p className="truncate text-xs font-medium text-slate-300">{user?.email}</p>
              <p className="text-[10px] uppercase tracking-wider text-slate-500">{user?.role}</p>
            </div>
            <button
              onClick={() => {
                logout();
                navigate("/login");
              }}
              title="Sign out"
              className="rounded-md p-1.5 text-slate-500 hover:bg-rynex-border/40 hover:text-slate-300"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main */}
      <div className="ml-56 flex min-h-screen flex-1 flex-col">
        <header className="sticky top-0 z-10 flex items-center gap-4 border-b border-rynex-border bg-rynex-bg/95 px-6 py-3 backdrop-blur">
          <form onSubmit={runSearch} className="relative w-full max-w-md">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search CVEs, domains, IPs, hashes, orgs, headlines…"
              className="w-full rounded-md border border-rynex-border bg-rynex-panel py-1.5 pl-9 pr-3 text-sm text-slate-200 placeholder:text-slate-600 focus:border-rynex-accent/50 focus:outline-none"
            />
          </form>
          <div className="ml-auto flex items-center gap-3 text-slate-500">
            <BellRing className="h-4 w-4" />
            <Globe2 className="h-4 w-4" />
          </div>
        </header>
        <main className="flex-1 p-6">
          <Outlet />
        </main>
        <footer className="border-t border-rynex-border px-6 py-2.5 text-[11px] text-slate-600">
          Rynex Threat Intelligence Platform — internal use. Intelligence retains original source
          attribution; ransomware claims are unverified until corroborated.
        </footer>
      </div>
    </div>
  );
}
