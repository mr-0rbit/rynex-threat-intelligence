import { useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Activity,
  Bug,
  Database,
  Globe2,
  LayoutDashboard,
  LogOut,
  Newspaper,
  Rss,
  Search,
  Shield,
  TriangleAlert,
} from "lucide-react";
import { useAuth } from "../auth";

const NAV = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard", end: true },
  { to: "/alerts", icon: TriangleAlert, label: "Alerts" },
  { to: "/breaches", icon: Database, label: "Breach Intel" },
  { to: "/darkweb", icon: Globe2, label: "Dark Web" },
  { to: "/vulnerabilities", icon: Bug, label: "Vulnerabilities" },
  { to: "/iocs", icon: Shield, label: "IOCs" },
  { to: "/news", icon: Newspaper, label: "News" },
  { to: "/sources", icon: Rss, label: "Sources" },
];

export function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [search, setSearch] = useState("");

  const runSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (search.trim().length < 2) return;
    navigate(`/search?q=${encodeURIComponent(search.trim())}`);
  };

  return (
    <div className="flex min-h-screen bg-ink-950">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-20 flex w-52 flex-col border-r border-ink-700 bg-ink-900">
        <div className="border-b border-ink-700 px-4 py-4">
          <div className="flex items-center gap-2.5">
            <Activity className="h-5 w-5 text-accent" strokeWidth={2.5} />
            <div>
              <p className="text-sm font-bold tracking-[0.08em] text-white">RTIP</p>
              <p className="text-[10px] uppercase tracking-[0.22em] text-ink-400">Rynex Technologies</p>
            </div>
          </div>
        </div>
        <nav className="flex-1 py-2">
          {NAV.map(({ to, icon: Icon, label, ...rest }) => (
            <NavLink
              key={to}
              to={to}
              end={"end" in rest}
              className={({ isActive }) =>
                `relative flex items-center gap-2.5 px-4 py-[7px] text-xs tracking-wide transition-colors ${
                  isActive
                    ? "bg-ink-800 font-semibold text-white before:absolute before:inset-y-0 before:left-0 before:w-[2px] before:bg-accent"
                    : "text-ink-300 hover:bg-ink-800 hover:text-white"
                }`
              }
            >
              <Icon className="h-3.5 w-3.5" strokeWidth={2} />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-ink-700 px-4 py-3">
          <div className="flex items-center justify-between">
            <div className="min-w-0">
              <p className="truncate text-2xs text-ink-200">{user?.email}</p>
              <p className="text-[10px] uppercase tracking-[0.16em] text-accent-dim">{user?.role}</p>
            </div>
            <button
              onClick={() => {
                logout();
                navigate("/login");
              }}
              title="Sign out"
              className="p-1 text-ink-400 hover:bg-ink-800 hover:text-white"
            >
              <LogOut className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main column */}
      <div className="ml-52 flex min-h-screen flex-1 flex-col">
        <header className="sticky top-0 z-10 flex items-center border-b border-ink-700 bg-ink-950/95 px-5 py-2.5 backdrop-blur">
          <form onSubmit={runSearch} className="relative w-full max-w-md">
            <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-400" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search CVEs, indicators, organizations, headlines…"
              className="w-full border border-ink-600 bg-ink-850 py-1.5 pl-8 pr-3 text-xs text-ink-100 placeholder:text-ink-400 focus:border-accent focus:outline-none"
            />
          </form>
          <div className="ml-auto flex items-center gap-2 text-2xs uppercase tracking-[0.16em] text-ink-400">
            <Globe2 className="h-3.5 w-3.5" />
            <span>Threat Intelligence Operations</span>
          </div>
        </header>
        <main className="flex-1 p-5">
          <Outlet />
        </main>
        <footer className="border-t border-ink-700 px-5 py-2 text-[10px] tracking-wide text-ink-400">
          RYNEX THREAT INTELLIGENCE PLATFORM — RESTRICTED: INTERNAL ANALYST USE ONLY. INTELLIGENCE RETAINS
          ORIGINAL SOURCE ATTRIBUTION. THREAT-ACTOR CLAIMS ARE UNVERIFIED UNTIL CORROBORATED.
        </footer>
      </div>
    </div>
  );
}
