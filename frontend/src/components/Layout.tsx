import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Bug,
  Database,
  Globe2,
  Layers,
  LayoutDashboard,
  LogOut,
  Network,
  Newspaper,
  Radio,
  Rss,
  Search,
  Server,
  Shield,
  TriangleAlert,
  UserCog,
} from "lucide-react";
import { useAuth } from "../auth";
import { Footer } from "./Footer";

interface NavItem {
  to: string;
  icon: typeof LayoutDashboard;
  label: string;
  badge?: string;
  end?: boolean;
}

const NAV_GROUPS: { group: string; items: NavItem[] }[] = [
  {
    group: "Core Operations",
    items: [
      { to: "/", icon: LayoutDashboard, label: "Dashboard", end: true },
      { to: "/alerts", icon: TriangleAlert, label: "Alerts", badge: "LIVE" },
      { to: "/investigations", icon: Network, label: "Investigations" },
    ],
  },
  {
    group: "Threat Intelligence",
    items: [
      { to: "/vulnerabilities", icon: Bug, label: "Vulnerabilities" },
      { to: "/mitre", icon: Layers, label: "MITRE ATT&CK" },
      { to: "/darkweb", icon: Globe2, label: "Dark Web Intel" },
      { to: "/breaches", icon: Database, label: "Breach Intel" },
      { to: "/iocs", icon: Shield, label: "IOC Indicators" },
    ],
  },
  {
    group: "Surface & Feeds",
    items: [
      { to: "/assets", icon: Server, label: "Attack Surface" },
      { to: "/integrations", icon: Radio, label: "TAXII & EDLs" },
      { to: "/news", icon: Newspaper, label: "Cyber News" },
      { to: "/sources", icon: Rss, label: "Intel Sources" },
    ],
  },
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
    <div className="flex min-h-screen bg-ink-950 font-sans text-ink-100 selection:bg-accent/25 selection:text-white">
      {/* Sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 flex w-64 flex-col border-r border-ink-700/70 bg-gradient-to-b from-ink-900/98 via-ink-900/95 to-ink-950/98 backdrop-blur-xl shadow-2xl">
        {/* Brand Header */}
        <div className="border-b border-ink-700/60 px-5 py-4 bg-ink-950/40">
          <div className="flex items-center gap-3.5">
            <div className="relative flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-accent/30 bg-gradient-to-br from-ink-900 to-ink-950 p-2 shadow-[0_0_15px_rgba(0,212,255,0.2)] ring-1 ring-accent/20">
              <img
                src="/logo.png"
                alt="Rynex Logo"
                className="h-full w-full object-contain drop-shadow-[0_0_8px_rgba(0,212,255,0.5)]"
              />
              <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-accent" />
              </span>
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm font-extrabold tracking-wider text-white font-mono leading-none bg-gradient-to-r from-white via-ink-100 to-accent bg-clip-text text-transparent">
                  RYNEX TIP
                </span>
                <span className="rounded bg-accent/15 border border-accent/30 px-1 py-0.2 text-[9px] font-mono font-bold text-accent">
                  v2.4
                </span>
              </div>
              <p className="mt-1 text-[10px] uppercase tracking-[0.2em] text-ink-400 font-mono">
                Threat Intelligence
              </p>
            </div>
          </div>
        </div>

        {/* Navigation Groups */}
        <nav className="flex-1 space-y-5 px-3 py-4 overflow-y-auto">
          {NAV_GROUPS.map((group) => (
            <div key={group.group}>
              <p className="px-3 mb-1.5 text-[10px] font-bold uppercase tracking-[0.16em] text-ink-400 font-mono">
                {group.group}
              </p>
              <div className="space-y-0.5">
                {group.items.map(({ to, icon: Icon, label, badge, end }) => (
                  <NavLink
                    key={to}
                    to={to}
                    end={end}
                    className={({ isActive }) =>
                      `group relative flex items-center justify-between rounded-lg px-3 py-2 text-xs font-medium tracking-wide transition-all duration-150 ${
                        isActive
                          ? "bg-accent/15 text-white font-semibold border border-accent/30 shadow-[inset_0_0_12px_rgba(0,212,255,0.08)]"
                          : "text-ink-300 hover:bg-ink-800/70 hover:text-white"
                      }`
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <div className="flex items-center gap-2.5 min-w-0">
                          <Icon
                            className={`h-4 w-4 shrink-0 transition-transform duration-200 group-hover:scale-110 ${
                              isActive ? "text-accent drop-shadow-[0_0_6px_rgba(0,212,255,0.5)]" : "text-ink-400 group-hover:text-ink-200"
                            }`}
                          />
                          <span className="truncate">{label}</span>
                        </div>
                        {badge && (
                          <span
                            className={`rounded px-1.5 py-0.2 text-[9px] font-mono font-bold tracking-wider ${
                              isActive
                                ? "bg-accent text-black shadow-[0_0_8px_rgba(0,212,255,0.4)]"
                                : "bg-accent/15 text-accent border border-accent/30"
                            }`}
                          >
                            {badge}
                          </span>
                        )}
                        {isActive && (
                          <span className="absolute left-0 top-1/2 -translate-y-1/2 h-5 w-1 rounded-r-full bg-accent shadow-[0_0_8px_#00d4ff]" />
                        )}
                      </>
                    )}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>

        {/* User Identity & Sign Out Card */}
        <div className="border-t border-ink-700/60 p-3 bg-gradient-to-t from-ink-950 to-ink-900/60">
          <div className="flex items-center justify-between gap-2 rounded-lg border border-ink-700/70 bg-ink-950/70 p-2">
            <NavLink
              to="/account"
              title="Account settings — credentials & MFA"
              className="group flex min-w-0 flex-1 items-center gap-2.5 text-left transition-colors"
            >
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border border-ink-700 bg-ink-900 text-xs font-bold text-accent font-mono shadow-inner">
                {user?.email?.slice(0, 2).toUpperCase() || "OP"}
              </div>
              <div className="min-w-0 flex-1">
                <p className="truncate text-xs font-medium text-ink-200 group-hover:text-white transition-colors">
                  {user?.email?.split("@")[0] || "Analyst"}
                </p>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_6px_#10b981]" />
                  <span className="text-[9px] uppercase tracking-wider text-accent font-mono">
                    {user?.role || "ANALYST"}
                  </span>
                </div>
              </div>
            </NavLink>

            <div className="flex items-center gap-0.5 shrink-0">
              <NavLink
                to="/account"
                title="Account Settings"
                className="rounded-md p-1.5 text-ink-400 hover:bg-ink-800 hover:text-white transition-colors"
              >
                <UserCog className="h-4 w-4" />
              </NavLink>
              <button
                onClick={() => {
                  logout();
                  navigate("/login");
                }}
                title="Sign out of console"
                className="rounded-md p-1.5 text-ink-400 hover:bg-rose-500/15 hover:text-rose-300 transition-colors"
                aria-label="Sign out"
              >
                <LogOut className="h-4 w-4" />
              </button>
            </div>
          </div>
        </div>
      </aside>

      {/* Main column */}
      <div className="ml-64 flex min-h-screen flex-1 flex-col">
        {/* Sticky Top Header */}
        <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-ink-700/60 bg-ink-950/85 px-6 backdrop-blur-xl">
          {/* Global Search Bar */}
          <form onSubmit={runSearch} className="relative w-full max-w-lg">
            <Search className="absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-400 transition-colors group-focus-within:text-accent" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search CVEs, IOCs, threat actors, ransomware, headlines…"
              className="w-full rounded-lg border border-ink-700/80 bg-ink-900/80 py-2 pl-10 pr-20 text-xs text-ink-100 placeholder:text-ink-500 font-mono transition-all duration-150 focus:border-accent/60 focus:bg-ink-900 focus:outline-none focus:ring-2 focus:ring-accent/20 shadow-inner"
            />
            <div className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 flex items-center gap-1">
              <kbd className="rounded border border-ink-700 bg-ink-950/90 px-1.5 py-0.5 text-[9px] font-mono text-ink-400 shadow-sm">
                ENTER
              </kbd>
            </div>
          </form>

          {/* Right Status Indicators & Telemetry */}
          <div className="flex items-center gap-3.5 text-xs font-mono">
            {/* DEFCON Status Pill */}
            <div className="flex items-center gap-2 rounded-lg border border-accent/25 bg-accent/10 px-3 py-1.5 shadow-[0_0_12px_rgba(0,212,255,0.12)]">
              <span className="flex h-2 w-2 rounded-full bg-accent animate-pulse shadow-[0_0_8px_#00d4ff]" />
              <span className="text-2xs uppercase tracking-wider font-bold text-accent">
                SOC DEFCON 2 · LIVE
              </span>
            </div>

            {/* Live Clock */}
            <div className="hidden sm:flex items-center gap-2 rounded-lg border border-ink-700/70 bg-ink-900/60 px-3 py-1.5 text-2xs text-ink-300">
              <Globe2 className="h-3.5 w-3.5 text-accent" />
              <span className="tabular-nums font-mono">{utcTime || "UTC CLOCK"}</span>
            </div>
          </div>
        </header>

        {/* Content Outlet */}
        <main className="flex-1 p-6 sm:p-8">
          <Outlet />
        </main>

        {/* Global Footer */}
        <Footer />
      </div>
    </div>
  );
}
