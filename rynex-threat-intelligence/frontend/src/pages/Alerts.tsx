import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import { Card, EmptyState, SeverityBadge, Spinner, StatusBadge, timeAgo } from "../components/ui";

interface AlertItem {
  id: string;
  title: string;
  category: string;
  severity: string;
  status: string;
  confidence: number;
  detected_at: string;
  first_published_at: string | null;
  occurrence_count: number;
  recommended_action: string | null;
  evidence_sources: { source_slug: string; url: string | null }[];
}

const SEVERITIES = ["", "critical", "high", "medium", "low", "informational"];
const STATUSES = ["", "new", "acknowledged", "investigating", "confirmed", "false_positive", "resolved"];

export function Alerts() {
  const [items, setItems] = useState<AlertItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams({ limit: "25", offset: String(page * 25) });
    if (severity) params.set("severity", severity);
    if (status) params.set("status", status);
    api<{ total: number; items: AlertItem[] }>(`/alerts?${params}`)
      .then((r) => {
        setItems(r.items);
        setTotal(r.total);
      })
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  }, [severity, status, page]);

  useEffect(load, [load]);

  const updateStatus = async (id: string, newStatus: string) => {
    await api(`/alerts/${id}/status`, { method: "POST", body: JSON.stringify({ status: newStatus }) });
    load();
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-white">Alert Management</h1>
          <p className="text-xs text-slate-500">{total.toLocaleString()} alerts matching current filters</p>
        </div>
        <div className="flex gap-2">
          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value);
              setPage(0);
            }}
            className="rounded-md border border-rynex-border bg-rynex-panel px-2.5 py-1.5 text-xs text-slate-300"
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s ? s.toUpperCase() : "All severities"}</option>
            ))}
          </select>
          <select
            value={status}
            onChange={(e) => {
              setStatus(e.target.value);
              setPage(0);
            }}
            className="rounded-md border border-rynex-border bg-rynex-panel px-2.5 py-1.5 text-xs text-slate-300"
          >
            {STATUSES.map((s) => (
              <option key={s} value={s}>{s ? s.replace("_", " ") : "All statuses"}</option>
            ))}
          </select>
        </div>
      </div>

      {loading ? (
        <Spinner />
      ) : items.length === 0 ? (
        <Card>
          <EmptyState message="No alerts match. New intelligence will appear here automatically." />
        </Card>
      ) : (
        <div className="space-y-2">
          {items.map((a) => (
            <Card key={a.id} className="p-4">
              <div className="flex items-start justify-between gap-4">
                <button className="min-w-0 flex-1 text-left" onClick={() => setExpanded(expanded === a.id ? null : a.id)}>
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={a.severity} />
                    <StatusBadge status={a.status} />
                    <span className="text-[10px] uppercase tracking-wider text-slate-600">{a.category.replace(/_/g, " ")}</span>
                    {a.occurrence_count > 1 && (
                      <span className="rounded bg-rynex-border/50 px-1.5 py-0.5 text-[10px] text-slate-400">
                        ×{a.occurrence_count} evidence updates
                      </span>
                    )}
                  </div>
                  <p className="mt-1.5 text-sm font-medium text-slate-100">{a.title}</p>
                  <p className="mt-0.5 text-[11px] text-slate-500">
                    Detected {timeAgo(a.detected_at)} · published {timeAgo(a.first_published_at)} · confidence{" "}
                    {(a.confidence * 100).toFixed(0)}%
                  </p>
                </button>
                <select
                  value={a.status}
                  onChange={(e) => updateStatus(a.id, e.target.value)}
                  className="rounded border border-rynex-border bg-rynex-bg px-2 py-1 text-xs text-slate-300"
                >
                  {STATUSES.filter(Boolean).map((s) => (
                    <option key={s} value={s}>{s.replace("_", " ")}</option>
                  ))}
                </select>
              </div>
              {expanded === a.id && (
                <div className="mt-3 space-y-2 border-t border-rynex-border pt-3 text-xs text-slate-400">
                  {a.recommended_action && (
                    <p>
                      <span className="font-medium text-rynex-accent">Recommended action:</span> {a.recommended_action}
                    </p>
                  )}
                  {a.evidence_sources?.length > 0 && (
                    <p>
                      <span className="font-medium text-slate-300">Evidence:</span>{" "}
                      {a.evidence_sources.map((s, i) => (
                        <span key={i}>
                          {i > 0 && ", "}
                          {s.url ? (
                            <a href={s.url} target="_blank" rel="noreferrer noopener" className="text-rynex-accent hover:underline">
                              {s.source_slug}
                            </a>
                          ) : (
                            s.source_slug
                          )}
                        </span>
                      ))}
                    </p>
                  )}
                </div>
              )}
            </Card>
          ))}
          <div className="flex items-center justify-between text-xs text-slate-500">
            <span>Page {page + 1}</span>
            <div className="flex gap-2">
              <button
                disabled={page === 0}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                className="rounded border border-rynex-border px-3 py-1 disabled:opacity-30"
              >
                Previous
              </button>
              <button
                disabled={(page + 1) * 25 >= total}
                onClick={() => setPage((p) => p + 1)}
                className="rounded border border-rynex-border px-3 py-1 disabled:opacity-30"
              >
                Next
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
