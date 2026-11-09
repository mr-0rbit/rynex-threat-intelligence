import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
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
import { Footer } from "./Footer";

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
  const [utcTime, setUtcTime] = useState("");

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(now.toISOString().slice(11, 19) + " UTC");
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const runSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (search.trim().length < 2) return;
    navigate(`/search?q=${encodeURIComponent(search.trim())}`);
  };

  return (
    <div className="flex min-h-screen bg-ink-950 font-sans text-ink-100 selection:bg-accent/20 selection:text-white">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-20 flex w-56 flex-col border-r border-ink-700/80 bg-ink-900/95 backdrop-blur-md">
        {/* Brand Header */}
        <div className="border-b border-ink-700/80 px-4 py-3.5">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded border border-ink-600 bg-ink-950 p-1.5 shadow-[0_0_12px_rgba(0,212,255,0.15)] ring-1 ring-accent/20">
              <img
                src="/logo.png"
                alt="Rynex Logo"
                className="h-full w-full object-contain drop-shadow-[0_0_6px_rgba(0,212,255,0.4)]"
              />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                <p className="text-sm font-bold tracking-[0.1em] text-white font-mono leading-none">
                  RTIP
                </p>
                <span className="flex h-1.5 w-1.5 rounded-full bg-accent animate-pulse" title="System Live" />
              </div>
              <p className="mt-1 text-[9px] uppercase tracking-[0.22em] text-ink-400 font-mono">
                Rynex Technologies
              </p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 space-y-0.5 px-2 py-3 overflow-y-auto">
          {NAV.map(({ to, icon: Icon, label, ...rest }) => (
            <NavLink
              key={to}
              to={to}
              end={"end" in rest}
              className={({ isActive }) =>
                `group relative flex items-center gap-2.5 rounded px-3 py-2 text-xs font-mono tracking-wide transition-all ${
                  isActive
                    ? "bg-ink-800 font-semibold text-white before:absolute before:inset-y-0 before:left-0 before:w-[3px] before:rounded-r before:bg-accent shadow-[inset_0_0_12px_rgba(0,212,255,0.06)]"
                    : "text-ink-300 hover:bg-ink-800/70 hover:text-white"
                }`
              }
            >
              <Icon className="h-3.5 w-3.5 shrink-0 transition-transform group-hover:scale-105" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>

        {/* User Identity & Sign Out */}
        <div className="border-t border-ink-700/80 p-3 bg-ink-950/40">
          <div className="flex items-center justify-between gap-2">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-accent" />
                <p className="truncate text-xs font-medium text-ink-200">{user?.email}</p>
              </div>
              <p className="mt-0.5 text-[9px] uppercase tracking-[0.18em] text-accent font-mono">
                [{user?.role || "ANALYST"}]
              </p>
            </div>
            <button
              onClick={() => {
                logout();
                navigate("/login");
              }}
              title="Sign out of console"
              className="rounded p-1.5 text-ink-400 hover:bg-ink-800 hover:text-white hover:border-ink-500 border border-transparent transition-colors"
              aria-label="Sign out"
            >
              <LogOut className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main column */}
      <div className="ml-56 flex min-h-screen flex-1 flex-col">
        {/* Sticky Top Header */}
        <header className="sticky top-0 z-10 flex h-14 items-center justify-between border-b border-ink-700/80 bg-ink-950/90 px-6 backdrop-blur-md">
          <form onSubmit={runSearch} className="relative w-full max-w-md">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-400" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search CVEs, IOCs, threat actors, headlines…"
              className="w-full rounded border border-ink-600/90 bg-ink-900/90 py-1.5 pl-8 pr-12 text-xs text-ink-100 placeholder:text-ink-500 font-mono focus:border-accent focus:bg-ink-900 focus:outline-none focus:ring-1 focus:ring-accent/40 transition-colors"
            />
            <kbd className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 rounded border border-ink-700 bg-ink-950 px-1 py-0.5 text-[9px] font-mono text-ink-400">
              ENTER
            </kbd>
          </form>

          {/* Right Status Indicator & Clock */}
          <div className="flex items-center gap-4 text-xs font-mono">
            <div className="flex items-center gap-2 border border-ink-700/80 bg-ink-900/80 px-2.5 py-1 rounded">
              <span className="flex h-1.5 w-1.5 rounded-full bg-accent animate-pulse" />
              <span className="text-2xs uppercase tracking-wider text-ink-300">
                SOC ACTIVE
              </span>
            </div>

            <div className="hidden sm:flex items-center gap-1.5 text-2xs text-ink-400 tracking-wider">
              <Globe2 className="h-3.5 w-3.5 text-accent" />
              <span className="tabular-nums">{utcTime}</span>
            </div>
          </div>
        </header>

        {/* Content Outlet */}
        <main className="flex-1 p-6">
          <Outlet />
        </main>

        {/* Global Footer from rynexsecurity.com */}
        <Footer />
      </div>
    </div>
  );
}
