import { useCallback, useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { api } from "../api/client";
import { Card, EmptyState, Spinner, StatusBadge, timeAgo } from "../components/ui";

interface SourceItem {
  slug: string;
  name: string;
  category: string;
  enabled: boolean;
  health_status: string;
  last_success_at: string | null;
  last_failure_at: string | null;
  consecutive_failures: number;
  total_records_collected: number;
  collection_interval_minutes: number;
  commercial_use_status: string;
  api_key_configured: boolean;
}

interface JobItem {
  id: string;
  status: string;
  trigger: string;
  started_at: string | null;
  duration_seconds: number | null;
  records_received: number;
  records_stored: number;
  records_rejected: number;
  error: string | null;
}

export function Sources() {
  const [sources, setSources] = useState<SourceItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [jobs, setJobs] = useState<JobItem[]>([]);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    api<{ items: SourceItem[] }>("/sources")
      .then((r) => {
        setSources(r.items);
        if (!selected && r.items.length) setSelected(r.items[0].slug);
      })
      .catch(() => setSources([]))
      .finally(() => setLoading(false));
  }, [selected]);

  useEffect(load, [load]);

  useEffect(() => {
    if (!selected) return;
    api<{ items: JobItem[] }>(`/sources/${selected}/jobs`)
      .then((r) => setJobs(r.items))
      .catch(() => setJobs([]));
  }, [selected]);

  const trigger = async (slug: string) => {
    setBusy(slug);
    try {
      await api(`/sources/${slug}/collect`, { method: "POST" });
      load();
    } catch {
      // health status reflects the failure; reload anyway
      load();
    } finally {
      setBusy(null);
    }
  };

  if (loading) return <Spinner />;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-lg font-semibold text-white">Intelligence Sources</h1>
        <p className="text-xs text-slate-500">Collection health, schedules, and manual triggers</p>
      </div>

      {sources.length === 0 ? (
        <Card><EmptyState message="No sources registered yet. Sources register on first collection." /></Card>
      ) : (
        <Card className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-rynex-border text-[11px] uppercase tracking-wider text-slate-500">
                <th className="px-4 py-2.5">Source</th>
                <th className="px-4 py-2.5">Category</th>
                <th className="px-4 py-2.5">Health</th>
                <th className="px-4 py-2.5">Records</th>
                <th className="px-4 py-2.5">Interval</th>
                <th className="px-4 py-2.5">Last success</th>
                <th className="px-4 py-2.5">Last failure</th>
                <th className="px-4 py-2.5">Terms</th>
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody className="divide-y divide-rynex-border">
              {sources.map((s) => (
                <tr
                  key={s.slug}
                  onClick={() => setSelected(s.slug)}
                  className={`cursor-pointer hover:bg-rynex-border/20 ${selected === s.slug ? "bg-rynex-accent/5" : ""}`}
                >
                  <td className="px-4 py-2.5">
                    <p className="text-xs font-medium text-slate-200">{s.name}</p>
                    <p className="text-[10px] text-slate-600">{s.slug}</p>
                  </td>
                  <td className="px-4 py-2.5 text-xs capitalize text-slate-400">{s.category}</td>
                  <td className="px-4 py-2.5"><StatusBadge status={s.health_status} /></td>
                  <td className="px-4 py-2.5 tabular-nums text-slate-300">{s.total_records_collected.toLocaleString()}</td>
                  <td className="px-4 py-2.5 text-xs text-slate-500">{s.collection_interval_minutes}m</td>
                  <td className="px-4 py-2.5 text-xs text-slate-500">{timeAgo(s.last_success_at)}</td>
                  <td className="px-4 py-2.5 text-xs text-slate-500">
                    {s.consecutive_failures > 0 ? <span className="text-red-400">{s.consecutive_failures} in a row</span> : "—"}
                  </td>
                  <td className="px-4 py-2.5 text-[11px] text-slate-500">{s.commercial_use_status}</td>
                  <td className="px-4 py-2.5 text-right">
                    <button
                      disabled={busy === s.slug}
                      onClick={(e) => {
                        e.stopPropagation();
                        trigger(s.slug);
                      }}
                      className="inline-flex items-center gap-1.5 rounded border border-rynex-border px-2.5 py-1 text-[11px] text-rynex-accent hover:border-rynex-accent/50 disabled:opacity-40"
                    >
                      <RefreshCw className={`h-3 w-3 ${busy === s.slug ? "animate-spin" : ""}`} />
                      Collect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}

      {selected && jobs.length > 0 && (
        <Card>
          <div className="border-b border-rynex-border px-4 py-3">
            <h3 className="text-sm font-semibold text-slate-100">Collection history — {selected}</h3>
          </div>
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-rynex-border text-[11px] uppercase tracking-wider text-slate-500">
                <th className="px-4 py-2">Started</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Trigger</th>
                <th className="px-4 py-2">Duration</th>
                <th className="px-4 py-2">Received</th>
                <th className="px-4 py-2">Stored</th>
                <th className="px-4 py-2">Rejected</th>
                <th className="px-4 py-2">Error</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-rynex-border">
              {jobs.map((j) => (
                <tr key={j.id} className="text-xs">
                  <td className="px-4 py-2 text-slate-400">{timeAgo(j.started_at)}</td>
                  <td className="px-4 py-2"><StatusBadge status={j.status === "success" ? "healthy" : "failing"} /></td>
                  <td className="px-4 py-2 text-slate-500">{j.trigger}</td>
                  <td className="px-4 py-2 tabular-nums text-slate-500">{j.duration_seconds != null ? `${j.duration_seconds.toFixed(1)}s` : "—"}</td>
                  <td className="px-4 py-2 tabular-nums text-slate-400">{j.records_received}</td>
                  <td className="px-4 py-2 tabular-nums text-emerald-400">{j.records_stored}</td>
                  <td className="px-4 py-2 tabular-nums text-slate-500">{j.records_rejected}</td>
                  <td className="max-w-72 truncate px-4 py-2 text-red-400" title={j.error ?? ""}>{j.error ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
    </div>
  );
}
