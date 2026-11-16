import { useEffect, useState } from "react";
import {
  Bug,
  Database,
  ExternalLink,
  Newspaper,
  Radio,
  RadioTower,
  Shield,
  ShieldAlert,
  TriangleAlert,
  Zap,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../api/client";
import {
  Badge,
  Card,
  CardHeader,
  EmptyState,
  SeverityBadge,
  Spinner,
  StatCard,
  timeAgo,
  ACCENT_STEPS,
  chartTooltipStyle,
} from "../components/ui";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#f43f5e",
  high: "#f59e0b",
  medium: "#00d4ff",
  low: "#38bdf8",
  informational: "#475569",
};

const BREACH_STATUS_COLORS: Record<string, string> = {
  confirmed: "#10b981",
  claimed: "#a855f7",
  reported: "#00d4ff",
  unverified: "#64748b",
  disputed: "#f43f5e",
};

interface Overview {
  alerts: { active: number; new_today: number };
  breaches: { reported_24h: number };
  vulnerabilities: { critical_open: number; known_exploited: number };
  iocs: { total: number; new_24h: number };
  sources: { connected: number; failing: number };
  latest_news: { headline: string; publisher: string; url: string; published_at: string | null }[];
  generated_at: string;
}

interface Charts {
  alerts_over_time: { label: string; value: number }[];
  alert_severity: { label: string; value: number }[];
  ioc_types: { label: string; value: number }[];
  source_contribution: { label: string; value: number }[];
  news_by_publisher: { label: string; value: number }[];
  breaches_by_verification: { label: string; value: number }[];
  cve_severity: { label: string; value: number }[];
  news_over_time: { label: string; value: number }[];
}

function BarBlock({
  title,
  data,
  gradientId,
  color = "#00D4FF",
}: {
  title: string;
  data: { label: string; value: number }[];
  gradientId: string;
  color?: string;
}) {
  return (
    <Card className="flex flex-col">
      <CardHeader title={title} />
      <div className="h-64 p-4 flex-1">
        {data.length === 0 ? (
          <EmptyState message="No telemetry data recorded yet" />
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 8, right: 8, bottom: 4, left: -16 }}>
              <defs>
                <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={color} stopOpacity={0.9} />
                  <stop offset="100%" stopColor={color} stopOpacity={0.15} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#1c2438" strokeDasharray="3 3" vertical={false} />
              <XAxis
                dataKey="label"
                tick={{ fill: "#64748b", fontSize: 10, fontFamily: "JetBrains Mono" }}
                tickLine={false}
                axisLine={{ stroke: "#1c2438" }}
              />
              <YAxis
                tick={{ fill: "#64748b", fontSize: 10, fontFamily: "JetBrains Mono" }}
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
              />
              <Tooltip
                cursor={{ fill: "rgba(0, 212, 255, 0.05)" }}
                contentStyle={chartTooltipStyle}
              />
              <Bar dataKey="value" fill={`url(#${gradientId})`} radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  );
}

function PieBlock({
  title,
  data,
  colorMap,
}: {
  title: string;
  data: { label: string; value: number }[];
  colorMap?: Record<string, string>;
}) {
  return (
    <Card className="flex flex-col">
      <CardHeader title={title} />
      <div className="h-64 p-4 flex-1">
        {data.length === 0 ? (
          <EmptyState message="No intelligence records available" />
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                dataKey="value"
                nameKey="label"
                innerRadius={45}
                outerRadius={75}
                paddingAngle={3}
                stroke="#0b0e17"
                strokeWidth={2}
              >
                {data.map((entry, i) => (
                  <Cell
                    key={i}
                    fill={colorMap?.[entry.label.toLowerCase()] ?? ACCENT_STEPS[i % ACCENT_STEPS.length]}
                  />
                ))}
              </Pie>
              <Legend
                wrapperStyle={{
                  fontSize: 11,
                  fontFamily: "JetBrains Mono",
                  paddingTop: 8,
                  color: "#94a3b8",
                }}
              />
              <Tooltip contentStyle={chartTooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  );
}

export function Dashboard() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [charts, setCharts] = useState<Charts | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api<Overview>("/dashboard/overview"), api<Charts>("/dashboard/charts")])
      .then(([o, c]) => {
        setOverview(o);
        setCharts(c);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load dashboard"));
  }, []);

  if (error) return <EmptyState message={error} />;
  if (!overview || !charts) return <Spinner label="Aggregating global intelligence streams…" />;

  return (
    <div className="space-y-6">
      {/* Top SOC Status Banner */}
      <div className="relative overflow-hidden rounded-2xl border border-ink-700/80 bg-gradient-to-r from-ink-900/95 via-ink-850/90 to-ink-900/95 p-6 shadow-xl backdrop-blur-xl">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute -top-24 right-0 h-64 w-96 bg-accent/10 rounded-full blur-3xl"
        />

        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5 mb-2">
              <span className="flex h-2.5 w-2.5 rounded-full bg-accent animate-pulse shadow-[0_0_10px_#00d4ff]" />
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white font-mono">
                Threat Command Center
              </h1>
              <Badge variant="cyan">GLOBAL FEEDS LIVE</Badge>
            </div>
            <p className="text-xs sm:text-sm text-ink-300 font-sans max-w-2xl leading-relaxed">
              Real-time cyber telemetry, automated dark web reconnaissance, exploit correlation, and threat actor profiling.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 font-mono text-2xs">
            <div className="rounded-lg border border-ink-700/80 bg-ink-950/70 px-3 py-2 flex items-center gap-2 text-ink-300">
              <RadioTower className="h-4 w-4 text-emerald-400" />
              <span>{overview.sources.connected} Ingest Streams</span>
            </div>
            <div className="rounded-lg border border-ink-700/80 bg-ink-950/70 px-3 py-2 flex items-center gap-2 text-ink-300">
              <Zap className="h-4 w-4 text-accent" />
              <span>Synced {timeAgo(overview.generated_at)}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Key Metric Stat Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard
          label="Active Alerts"
          value={overview.alerts.active}
          accent
          variant="rose"
          icon={TriangleAlert}
          hint={`${overview.alerts.new_today} reported in 24h`}
        />
        <StatCard
          label="Exploited CVEs"
          value={overview.vulnerabilities.known_exploited}
          variant="amber"
          icon={Bug}
          hint={`${overview.vulnerabilities.critical_open} critical open`}
        />
        <StatCard
          label="Breaches (24h)"
          value={overview.breaches.reported_24h}
          variant="purple"
          icon={Database}
          hint="Ransomware leaks"
        />
        <StatCard
          label="IOC Records"
          value={overview.iocs.total}
          variant="cyan"
          icon={Shield}
          hint={`${overview.iocs.new_24h} new in 24h`}
        />
        <StatCard
          label="Connected Sources"
          value={overview.sources.connected}
          variant="emerald"
          icon={Radio}
          hint="All feeds healthy"
        />
        <StatCard
          label="Failing Collectors"
          value={overview.sources.failing}
          variant={overview.sources.failing > 0 ? "rose" : "emerald"}
          icon={ShieldAlert}
          hint={overview.sources.failing ? "Requires review" : "Optimal status"}
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <BarBlock
          title="Alert Detection Velocity (14 Days)"
          data={charts.alerts_over_time}
          gradientId="alertGrad"
          color="#00D4FF"
        />
        <PieBlock
          title="Alert Severity Distribution"
          data={charts.alert_severity}
          colorMap={SEVERITY_COLORS}
        />
        <PieBlock
          title="Vulnerability Severity (CVEs)"
          data={charts.cve_severity}
          colorMap={SEVERITY_COLORS}
        />
        <PieBlock
          title="Indicator Types (IOC Breakdown)"
          data={charts.ioc_types}
        />
        <PieBlock
          title="Breaches by Verification Status"
          data={charts.breaches_by_verification}
          colorMap={BREACH_STATUS_COLORS}
        />
        <BarBlock
          title="Collector Source Contributions"
          data={charts.source_contribution}
          gradientId="sourceGrad"
          color="#10b981"
        />
        <BarBlock
          title="News Article Volume (14 Days)"
          data={charts.news_over_time}
          gradientId="newsGrad"
          color="#a855f7"
        />
        <BarBlock
          title="Intelligence by Publisher"
          data={charts.news_by_publisher}
          gradientId="pubGrad"
          color="#38bdf8"
        />
      </div>

      {/* Latest Intelligence News Stream */}
      <Card>
        <CardHeader
          title="Latest Cybersecurity Advisories & Breaking News"
          subtitle="Real-time ingested feed from BleepingComputer, The Hacker News, CISA, Mandiant & threat research desks"
          icon={Newspaper}
        />
        <div className="divide-y divide-ink-700/60">
          {overview.latest_news.map((n) => (
            <div
              key={n.url}
              className="flex items-center justify-between gap-4 px-5 py-3.5 hover:bg-ink-800/50 transition-colors group"
            >
              <div className="min-w-0 flex-1">
                <a
                  href={n.url}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="flex items-center gap-2 font-medium text-sm text-ink-100 group-hover:text-accent transition-colors"
                >
                  <span className="truncate">{n.headline}</span>
                  <ExternalLink className="h-3.5 w-3.5 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity text-accent" />
                </a>
                <div className="mt-1 flex items-center gap-2 text-2xs font-mono text-ink-400">
                  <span className="text-ink-300 font-semibold">{n.publisher}</span>
                  <span>·</span>
                  <span>{timeAgo(n.published_at)}</span>
                </div>
              </div>
              <SeverityBadge severity="informational" className="shrink-0" />
            </div>
          ))}
          {overview.latest_news.length === 0 && (
            <EmptyState message="No articles collected yet. RSS feeds will populate automatically." />
          )}
        </div>
      </Card>
    </div>
  );
}
