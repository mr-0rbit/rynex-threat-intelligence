import { useEffect, useState } from "react";
import { ExternalLink, Flame, Globe2, ShieldAlert, Users, Zap } from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
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
  Spinner,
  StatusBadge,
  StatCard,
  timeAgo,
  chartTooltipStyle,
} from "../components/ui";

interface DarkWebData {
  policy_notice: string;
  monitored_groups: number;
  claims_24h: number;
  claims_7d: number;
  claims_by_actor: { label: string; value: number }[];
  claims_over_time: { label: string; value: number }[];
  groups: {
    name: string;
    aliases: string[] | null;
    description: string | null;
    first_observed: string | null;
    last_observed: string | null;
    attribution_status: string;
    source_url: string | null;
  }[];
  recent_claims: {
    id: string;
    organization: string;
    domain: string | null;
    actor: string | null;
    industry: string | null;
    country: string | null;
    published_at: string | null;
    verification_status: string;
    confidence: number;
    source_url: string | null;
  }[];
}

export function DarkWeb() {
  const [data, setData] = useState<DarkWebData | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<DarkWebData>("/darkweb/overview")
      .then(setData)
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load"));
  }, []);

  if (error) return <EmptyState message={error} />;
  if (!data) return <Spinner label="Probing dark web intelligence archives…" />;

  return (
    <div className="space-y-5">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Globe2 className="h-5 w-5 text-accent" />
              Dark Web Reconnaissance
            </h1>
            <Badge variant="purple">{data.monitored_groups} RANSOMWARE GROUPS</Badge>
          </div>
          <p className="mt-1 text-xs text-ink-400 font-sans">
            Automated monitoring of extortion sites, victim shaming blogs, and dark web threat actor communications.
          </p>
        </div>
      </div>

      {/* Scope / Ethical Notice Callout */}
      <div className="rounded-xl border border-accent/30 bg-gradient-to-r from-accent/10 via-ink-900/60 to-ink-950 p-4 shadow-sm backdrop-blur-md">
        <div className="flex items-start gap-3">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-accent drop-shadow-[0_0_6px_rgba(0,212,255,0.5)]" />
          <div className="text-xs leading-relaxed text-ink-200 font-sans">
            <span className="font-bold text-white font-mono uppercase tracking-wider text-2xs mr-1.5">
              OPERATIONAL COMPLIANCE NOTICE:
            </span>
            {data.policy_notice}
          </div>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Tracked Threat Groups"
          value={data.monitored_groups}
          accent
          variant="purple"
          icon={Users}
          hint="Active leak portals"
        />
        <StatCard
          label="Victim Disclosures (24h)"
          value={data.claims_24h}
          variant="rose"
          icon={Flame}
          hint="Fresh extortion claims"
        />
        <StatCard
          label="Victim Claims (7d)"
          value={data.claims_7d}
          variant="amber"
          icon={Zap}
          hint="Weekly threat volume"
        />
        <StatCard
          label="Verification Policy"
          value="Claims ≠ Confirmed"
          variant="cyan"
          hint="Corroboration required"
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Card className="flex flex-col">
          <CardHeader
            title="Victim Claims by Threat Actor"
            subtitle="Top leak-site syndicate volume"
          />
          <div className="h-64 p-4 flex-1">
            {data.claims_by_actor.length === 0 ? (
              <EmptyState message="No claims recorded yet" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={data.claims_by_actor}
                  layout="vertical"
                  margin={{ left: 20, right: 16, top: 8, bottom: 4 }}
                >
                  <defs>
                    <linearGradient id="actorGrad" x1="0" y1="0" x2="1" y2="0">
                      <stop offset="0%" stopColor="#a855f7" stopOpacity="0.3" />
                      <stop offset="100%" stopColor="#a855f7" stopOpacity="0.95" />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#1c2438" strokeDasharray="3 3" horizontal={false} />
                  <XAxis
                    type="number"
                    tick={{ fill: "#64748b", fontSize: 10, fontFamily: "JetBrains Mono" }}
                    axisLine={{ stroke: "#1c2438" }}
                    tickLine={false}
                    allowDecimals={false}
                  />
                  <YAxis
                    type="category"
                    dataKey="label"
                    tick={{ fill: "#cbd5e1", fontSize: 11, fontFamily: "JetBrains Mono" }}
                    axisLine={false}
                    tickLine={false}
                    width={90}
                  />
                  <Tooltip cursor={{ fill: "rgba(168, 85, 247, 0.08)" }} contentStyle={chartTooltipStyle} />
                  <Bar dataKey="value" fill="url(#actorGrad)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>

        <Card className="flex flex-col">
          <CardHeader
            title="Extortion Claim Ingestion Velocity"
            subtitle="Past 14 days telemetry"
          />
          <div className="h-64 p-4 flex-1">
            {data.claims_over_time.length === 0 ? (
              <EmptyState message="No timeline data available" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.claims_over_time} margin={{ top: 8, right: 8, bottom: 4, left: -16 }}>
                  <defs>
                    <linearGradient id="darkwebTimeGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#00D4FF" stopOpacity="0.9" />
                      <stop offset="100%" stopColor="#00D4FF" stopOpacity="0.15" />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="#1c2438" strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="label"
                    tick={{ fill: "#64748b", fontSize: 10, fontFamily: "JetBrains Mono" }}
                    axisLine={{ stroke: "#1c2438" }}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fill: "#64748b", fontSize: 10, fontFamily: "JetBrains Mono" }}
                    axisLine={false}
                    tickLine={false}
                    allowDecimals={false}
                  />
                  <Tooltip cursor={{ fill: "rgba(0, 212, 255, 0.05)" }} contentStyle={chartTooltipStyle} />
                  <Bar dataKey="value" fill="url(#darkwebTimeGrad)" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
      </div>

      {/* Recent Claims Table */}
      <Card>
        <CardHeader
          title="Recent Extortion Site Disclosures"
          subtitle="Real-time claims published by ransomware syndicates"
        />
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead>
              <tr className="border-b border-ink-700/80 bg-ink-950/70 text-[10px] font-bold uppercase tracking-wider text-ink-400 font-mono">
                <th className="px-5 py-3">Victim Organization</th>
                <th className="px-4 py-3">Claiming Syndicate</th>
                <th className="px-4 py-3">Sector</th>
                <th className="px-4 py-3">Country</th>
                <th className="px-4 py-3">Published</th>
                <th className="px-4 py-3">Verification</th>
                <th className="px-5 py-3 text-right">Evidence Link</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-700/50">
              {data.recent_claims.map((c) => (
                <tr key={c.id} className="hover:bg-ink-800/40 transition-colors group">
                  <td className="px-5 py-3.5 font-mono font-medium text-white group-hover:text-accent transition-colors">
                    {c.organization}
                  </td>
                  <td className="px-4 py-3.5 font-mono">
                    <span className="font-bold text-purple-300 bg-purple-500/10 border border-purple-500/25 px-2 py-0.5 rounded">
                      {c.actor ?? "UNKNOWN"}
                    </span>
                  </td>
                  <td className="px-4 py-3.5 text-ink-300">{c.industry ?? "—"}</td>
                  <td className="px-4 py-3.5 text-ink-300">{c.country ?? "—"}</td>
                  <td className="px-4 py-3.5 font-mono text-ink-400 whitespace-nowrap">
                    {timeAgo(c.published_at)}
                  </td>
                  <td className="px-4 py-3.5">
                    <StatusBadge status={c.verification_status} />
                  </td>
                  <td className="px-5 py-3.5 text-right">
                    {c.source_url && (
                      <a
                        href={c.source_url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="inline-flex items-center gap-1 rounded border border-ink-700 bg-ink-950 px-2 py-1 text-2xs font-mono text-ink-300 hover:border-accent hover:text-accent transition-colors"
                      >
                        <span>Evidence</span>
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Monitored Groups Grid */}
      <Card>
        <CardHeader
          title={`Monitored Extortion Syndicates & Threat Actors (${data.monitored_groups})`}
          subtitle="Intelligence dossiers and dark web footprint metadata"
        />
        <div className="p-5 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {data.groups.map((g) => (
            <div
              key={g.name}
              className="rounded-xl border border-ink-700/80 bg-ink-950/80 p-4 transition-all hover:border-purple-500/40 hover:shadow-[0_0_15px_rgba(168,85,247,0.12)] flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between gap-2">
                  <h4 className="text-sm font-bold text-white font-mono">{g.name}</h4>
                  <Badge variant="purple" size="xs">
                    {g.attribution_status || "THREAT GROUP"}
                  </Badge>
                </div>
                {g.aliases && g.aliases.length > 0 && (
                  <p className="mt-1 text-2xs font-mono text-ink-400">
                    aka {g.aliases.join(", ")}
                  </p>
                )}
                {g.description && (
                  <p className="mt-2 line-clamp-3 text-2xs leading-relaxed text-ink-300 font-sans">
                    {g.description}
                  </p>
                )}
              </div>

              <div className="mt-3 pt-3 border-t border-ink-700/60 flex items-center justify-between text-[10px] font-mono text-ink-400">
                <span>{g.first_observed ? `Active since ${g.first_observed.slice(0, 10)}` : "Tracking active"}</span>
                {g.source_url && (
                  <a
                    href={g.source_url}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="text-accent hover:underline flex items-center gap-1"
                  >
                    <span>Dossier</span>
                    <ExternalLink className="h-2.5 w-2.5" />
                  </a>
                )}
              </div>
            </div>
          ))}
          {data.groups.length === 0 && (
            <div className="col-span-full">
              <EmptyState message="No threat actor profiles synchronized yet." />
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}
