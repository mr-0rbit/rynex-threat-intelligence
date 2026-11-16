import { useCallback, useEffect, useState } from "react";
import { History, RefreshCw, Rss } from "lucide-react";
import { api } from "../api/client";
import { Badge, Card, CardHeader, EmptyState, Spinner, StatusBadge, timeAgo } from "../components/ui";

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
  api_key_required: boolean;
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
      load();
    } finally {
      setBusy(null);
    }
  };

  if (loading) return <Spinner label="Probing feed collector states…" />;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Rss className="h-5 w-5 text-accent" />
              Intelligence Collectors &amp; Feeds
            </h1>
            <Badge variant="cyan">{sources.length} REGISTERED SOURCES</Badge>
          </div>
          <p className="mt-1 text-xs text-ink-400 font-sans">
            Automated intelligence ingest engines, collection health telemetry, and scheduled synchronizations.
          </p>
        </div>

        <button
          onClick={load}
          className="flex items-center gap-1.5 rounded-lg border border-ink-700 bg-ink-900 px-3.5 py-2 text-xs font-mono font-medium text-ink-200 hover:border-accent hover:text-accent transition-colors shadow-sm"
        >
          <RefreshCw className="h-3.5 w-3.5" />
          <span>Refresh Feeds</span>
        </button>
      </div>

      {sources.length === 0 ? (
        <Card>
          <EmptyState message="No intelligence sources registered yet." />
        </Card>
      ) : (
        <div className="overflow-hidden rounded-xl border border-ink-700/80 bg-gradient-to-b from-ink-900/95 to-ink-950/95 shadow-xl backdrop-blur-md">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-sans">
              <thead>
                <tr className="border-b border-ink-700/80 bg-ink-950/70 text-[10px] font-bold uppercase tracking-wider text-ink-400 font-mono">
                  <th className="px-5 py-3">Source Name</th>
                  <th className="px-4 py-3">Category</th>
                  <th className="px-4 py-3">Health Status</th>
                  <th className="px-4 py-3">Collected Records</th>
                  <th className="px-4 py-3">Interval</th>
                  <th className="px-4 py-3">Last Ingest</th>
                  <th className="px-4 py-3">Failure Counter</th>
                  <th className="px-4 py-3">License</th>
                  <th className="px-5 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-700/50">
                {sources.map((s) => {
                  const isSel = selected === s.slug;
                  return (
                    <tr
                      key={s.slug}
                      onClick={() => setSelected(s.slug)}
                      className={`cursor-pointer transition-colors ${
                        isSel
                          ? "bg-accent/10 border-l-2 border-l-accent"
                          : "hover:bg-ink-800/40"
                      }`}
                    >
                      <td className="px-5 py-3.5 font-mono">
                        <p className="text-xs font-bold text-white leading-tight">{s.name}</p>
                        <p className="text-[10px] text-accent mt-0.5">{s.slug}</p>
                        {s.api_key_required && (
                          <p className={`mt-1 text-[10px] ${s.api_key_configured ? "text-emerald-400" : "text-amber-400"}`}>
                            {s.api_key_configured ? "API key configured" : "API key required"}
                          </p>
                        )}
                      </td>
                      <td className="px-4 py-3.5">
                        <span className="rounded bg-ink-800 border border-ink-700 px-2 py-0.5 text-2xs font-mono capitalize text-ink-300">
                          {s.category}
                        </span>
                      </td>
                      <td className="px-4 py-3.5">
                        <StatusBadge status={s.health_status} />
                      </td>
                      <td className="px-4 py-3.5 font-mono tabular-nums text-white font-semibold">
                        {s.total_records_collected.toLocaleString()}
                      </td>
                      <td className="px-4 py-3.5 font-mono text-ink-400">
                        {s.collection_interval_minutes}m
                      </td>
                      <td className="px-4 py-3.5 font-mono text-ink-400 whitespace-nowrap">
                        {timeAgo(s.last_success_at)}
                      </td>
                      <td className="px-4 py-3.5 font-mono text-xs">
                        {s.consecutive_failures > 0 ? (
                          <span className="text-rose-400 font-bold bg-rose-500/15 border border-rose-500/30 px-1.5 py-0.5 rounded">
                            {s.consecutive_failures} fails
                          </span>
                        ) : (
                          <span className="text-emerald-400">0</span>
                        )}
                      </td>
                      <td className="px-4 py-3.5 text-2xs font-mono text-ink-400">
                        {s.commercial_use_status}
                      </td>
                      <td className="px-5 py-3.5 text-right">
                        <button
                          disabled={busy === s.slug}
                          onClick={(e) => {
                            e.stopPropagation();
                            trigger(s.slug);
                          }}
                          className="inline-flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-2xs font-mono font-bold uppercase text-accent hover:bg-accent hover:text-black transition-all shadow-sm disabled:opacity-40"
                        >
                          <RefreshCw className={`h-3 w-3 ${busy === s.slug ? "animate-spin" : ""}`} />
                          <span>Collect</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Selected Collector Job History */}
      {selected && jobs.length > 0 && (
        <Card>
          <CardHeader
            title={`Collection Job History: ${selected}`}
            subtitle="Execution run logs, duration, and record storage counts"
            icon={History}
          />
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-sans">
              <thead>
                <tr className="border-b border-ink-700/80 bg-ink-950/70 text-[10px] font-bold uppercase tracking-wider text-ink-400 font-mono">
                  <th className="px-5 py-3">Started</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Trigger Method</th>
                  <th className="px-4 py-3">Duration</th>
                  <th className="px-4 py-3">Received</th>
                  <th className="px-4 py-3">Stored</th>
                  <th className="px-4 py-3">Rejected</th>
                  <th className="px-5 py-3">Diagnostic Message</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-700/50">
                {jobs.map((j) => (
                  <tr key={j.id} className="hover:bg-ink-800/40 transition-colors font-mono text-xs">
                    <td className="px-5 py-3 text-ink-300">{timeAgo(j.started_at)}</td>
                    <td className="px-4 py-3">
                      <StatusBadge status={j.status === "success" ? "healthy" : "failing"} />
                    </td>
                    <td className="px-4 py-3 text-ink-400 capitalize">{j.trigger}</td>
                    <td className="px-4 py-3 tabular-nums text-ink-300">
                      {j.duration_seconds != null ? `${j.duration_seconds.toFixed(1)}s` : "—"}
                    </td>
                    <td className="px-4 py-3 tabular-nums text-ink-300">{j.records_received}</td>
                    <td className="px-4 py-3 tabular-nums text-accent font-semibold">{j.records_stored}</td>
                    <td className="px-4 py-3 tabular-nums text-ink-500">{j.records_rejected}</td>
                    <td className="px-5 py-3 max-w-xs truncate text-ink-400 font-sans" title={j.error ?? ""}>
                      {j.error ?? "Completed with 0 errors"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
