import { useEffect, useState } from "react";
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
import { Card, CardHeader, EmptyState, SeverityBadge, Spinner, StatCard, timeAgo, ACCENT, ACCENT_STEPS } from "../components/ui";

// Strict palette: accent hue with opacity steps + white/neutral tones only.
const SEVERITY_COLORS: Record<string, string> = {
  critical: "#FFFFFF",
  high: "#00D4FF",
  medium: "rgba(0,212,255,0.40)",
  low: "rgba(255,255,255,0.28)",
  informational: "#333338",
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

function BarBlock({ title, data, color = ACCENT }: { title: string; data: { label: string; value: number }[]; color?: string }) {
  return (
    <Card>
      <CardHeader title={title} />
      <div className="h-56 p-3">
        {data.length === 0 ? (
          <EmptyState message="No data yet" />
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
              <CartesianGrid stroke="#232327" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="label" tick={{ fill: "#6B6B72", fontSize: 10 }} tickLine={false} axisLine={false} />
              <YAxis tick={{ fill: "#6B6B72", fontSize: 10 }} tickLine={false} axisLine={false} allowDecimals={false} />
              <Tooltip
                cursor={{ fill: "rgba(0,212,255,0.06)" }}
                contentStyle={{ background: "#111113", border: "1px solid #232327", borderRadius: 2, fontSize: 12 }}
              />
              <Bar dataKey="value" fill={color} radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  );
}

function PieBlock({ title, data, colorMap }: { title: string; data: { label: string; value: number }[]; colorMap?: Record<string, string> }) {
  return (
    <Card>
      <CardHeader title={title} />
      <div className="h-56 p-3">
        {data.length === 0 ? (
          <EmptyState message="No data yet" />
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                dataKey="value"
                nameKey="label"
                innerRadius={40}
                outerRadius={70}
                paddingAngle={2}
                strokeWidth={0}
              >
                {data.map((entry, i) => (
                  <Cell
                    key={i}
                    fill={colorMap?.[entry.label] ?? ACCENT_STEPS[i % ACCENT_STEPS.length]}
                  />
                ))}
              </Pie>
              <Legend wrapperStyle={{ fontSize: 11, color: "#9C9CA4" }} />
              <Tooltip contentStyle={{ background: "#111113", border: "1px solid #232327", borderRadius: 2, fontSize: 12 }} />
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
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load"));
  }, []);

  if (error) return <EmptyState message={error} />;
  if (!overview || !charts) return <Spinner label="Loading intelligence overview…" />;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold text-white">Intelligence Overview</h1>
        <p className="text-xs text-ink-400">
          All figures computed from live database records · generated {timeAgo(overview.generated_at as unknown as string)}
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Active Threat Alerts" value={overview.alerts.active} accent hint={`${overview.alerts.new_today} new in 24h`} />
        <StatCard label="Known Exploited CVEs" value={overview.vulnerabilities.known_exploited} hint={`${overview.vulnerabilities.critical_open} critical open`} />
        <StatCard label="Breach Reports (24h)" value={overview.breaches.reported_24h} />
        <StatCard label="IOC Records" value={overview.iocs.total} hint={`${overview.iocs.new_24h} observed in 24h`} />
        <StatCard label="Connected Sources" value={overview.sources.connected} accent />
        <StatCard label="Failing Collectors" value={overview.sources.failing} hint={overview.sources.failing ? "Attention required" : "All healthy"} />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <BarBlock title="Alerts Detected (14 days)" data={charts.alerts_over_time} />
        <PieBlock title="Alert Severity Distribution" data={charts.alert_severity} colorMap={SEVERITY_COLORS} />
        <PieBlock title="CVE Severity Distribution" data={charts.cve_severity} colorMap={SEVERITY_COLORS} />
        <PieBlock title="IOC Type Distribution" data={charts.ioc_types} />
        <BarBlock title="Source Contribution" data={charts.source_contribution} />
        <PieBlock title="Breaches by Verification Status" data={charts.breaches_by_verification} />
        <BarBlock title="News Volume (14 days)" data={charts.news_over_time} color="rgba(255,255,255,0.55)" />
        <BarBlock title="Articles by Publisher" data={charts.news_by_publisher} color="rgba(255,255,255,0.55)" />
      </div>

      <Card>
        <CardHeader title="Latest Cybersecurity News" subtitle="Aggregated from publisher RSS feeds" />
        <ul className="divide-y divide-ink-600">
          {overview.latest_news.map((n) => (
            <li key={n.url} className="flex items-center justify-between gap-4 px-4 py-2.5 hover:bg-ink-700/20">
              <div className="min-w-0">
                <a
                  href={n.url}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="block truncate text-sm text-ink-100 hover:text-accent"
                >
                  {n.headline}
                </a>
                <p className="text-[11px] text-ink-400">
                  {n.publisher} · {timeAgo(n.published_at)}
                </p>
              </div>
              <SeverityBadge severity="informational" />
            </li>
          ))}
          {overview.latest_news.length === 0 && <EmptyState message="No articles collected yet" />}
        </ul>
      </Card>
    </div>
  );
}
