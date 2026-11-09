import { useEffect, useState } from "react";
import { ExternalLink, ShieldAlert } from "lucide-react";
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
import { ACCENT, Card, CardHeader, EmptyState, Spinner, StatusBadge, StatCard, timeAgo } from "../components/ui";

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
  if (!data) return <Spinner label="Loading dark web monitoring…" />;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-base font-semibold tracking-wide text-white">DARK WEB MONITORING</h1>
        <p className="mt-0.5 text-2xs text-ink-400">
          Ransomware leak-site activity, sourced from legitimate research intermediaries
        </p>
      </div>

      {/* Legal / operational scope notice */}
      <div className="border border-ink-600 bg-ink-800 p-3">
        <p className="flex items-start gap-2 text-2xs leading-relaxed text-ink-300">
          <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent" />
          <span>
            <span className="font-semibold text-white">SCOPE NOTICE.</span> {data.policy_notice}
          </span>
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatCard label="Monitored Groups" value={data.monitored_groups} accent />
        <StatCard label="Victim Claims (24h)" value={data.claims_24h} />
        <StatCard label="Victim Claims (7d)" value={data.claims_7d} />
        <StatCard label="Verification Rule" value="Claims ≠ Confirmed" />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Victim Claims by Group" subtitle="Top 10 leak-site operators" />
          <div className="h-56 p-3">
            {data.claims_by_actor.length === 0 ? (
              <EmptyState message="No claims recorded yet" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.claims_by_actor} layout="vertical" margin={{ left: 40 }}>
                  <CartesianGrid stroke="#232327" strokeDasharray="3 3" horizontal={false} />
                  <XAxis type="number" tick={{ fill: "#6B6B72", fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <YAxis type="category" dataKey="label" tick={{ fill: "#9C9CA4", fontSize: 9 }} axisLine={false} tickLine={false} width={90} />
                  <Tooltip cursor={{ fill: "rgba(0,212,255,0.06)" }} contentStyle={{ background: "#111113", border: "1px solid #232327", borderRadius: 2, fontSize: 12 }} />
                  <Bar dataKey="value" fill={ACCENT} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
        <Card>
          <CardHeader title="Victim Claims per Day" subtitle="Last 14 days" />
          <div className="h-56 p-3">
            {data.claims_over_time.length === 0 ? (
              <EmptyState message="No claims recorded yet" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={data.claims_over_time}>
                  <CartesianGrid stroke="#232327" strokeDasharray="3 3" vertical={false} />
                  <XAxis dataKey="label" tick={{ fill: "#6B6B72", fontSize: 10 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: "#6B6B72", fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip cursor={{ fill: "rgba(0,212,255,0.06)" }} contentStyle={{ background: "#111113", border: "1px solid #232327", borderRadius: 2, fontSize: 12 }} />
                  <Bar dataKey="value" fill={ACCENT} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </Card>
      </div>

      <Card>
        <CardHeader title="Recent Victim Claims" subtitle="Unverified until corroborated — evidence links preserved" />
        <table className="w-full text-left text-xs">
          <thead>
            <tr className="border-b border-ink-600 text-2xs uppercase tracking-[0.1em] text-ink-400">
              <th className="px-4 py-2">Organization</th>
              <th className="px-4 py-2">Claimed by</th>
              <th className="px-4 py-2">Industry</th>
              <th className="px-4 py-2">Country</th>
              <th className="px-4 py-2">Published</th>
              <th className="px-4 py-2">Status</th>
              <th className="px-4 py-2" />
            </tr>
          </thead>
          <tbody className="divide-y divide-ink-700">
            {data.recent_claims.map((c) => (
              <tr key={c.id} className="hover:bg-ink-800">
                <td className="px-4 py-2 text-ink-100">{c.organization}</td>
                <td className="px-4 py-2 text-accent">{c.actor ?? "—"}</td>
                <td className="px-4 py-2 text-ink-300">{c.industry ?? "—"}</td>
                <td className="px-4 py-2 text-ink-300">{c.country ?? "—"}</td>
                <td className="px-4 py-2 text-ink-400">{timeAgo(c.published_at)}</td>
                <td className="px-4 py-2"><StatusBadge status={c.verification_status} /></td>
                <td className="px-4 py-2 text-right">
                  {c.source_url && (
                    <a href={c.source_url} target="_blank" rel="noreferrer noopener" className="text-ink-400 hover:text-accent">
                      <ExternalLink className="h-3 w-3" />
                    </a>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>

      <Card>
        <CardHeader title={`Monitored Leak-Site Operators (${data.monitored_groups})`} subtitle="Metadata profiles only — no onion connectivity" />
        <div className="grid grid-cols-1 gap-px bg-ink-700 md:grid-cols-2 lg:grid-cols-3">
          {data.groups.map((g) => (
            <div key={g.name} className="bg-ink-800 p-3">
              <p className="text-xs font-semibold text-white">{g.name}</p>
              {g.aliases && <p className="mt-0.5 text-2xs text-ink-400">aka {g.aliases.join(", ")}</p>}
              {g.description && <p className="mt-1.5 line-clamp-3 text-2xs leading-relaxed text-ink-300">{g.description}</p>}
              <p className="mt-1.5 text-[10px] uppercase tracking-wider text-ink-400">
                {g.first_observed ? `active since ${g.first_observed.slice(0, 10)}` : "observation window unknown"}
              </p>
            </div>
          ))}
          {data.groups.length === 0 && (
            <div className="col-span-full">
              <EmptyState message="No group profiles collected yet — run the darkweb-groups collector" />
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}
