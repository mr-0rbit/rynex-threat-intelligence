/* Alerts.tsx — alert management with a live WebSocket feed.
 *
 * The banner subscribes to /api/v1/ws/alerts (same-origin, token in query).
 * With default filters active, arriving alerts auto-refresh the list; with
 * filters applied they only surface in the banner so the table stays stable.
 * Connection drops auto-reconnect with capped backoff.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { FileDown, X } from "lucide-react";
import { api, createAlertSocket, downloadFile } from "../api/client";
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

interface LiveAlert {
  id: string;
  title: string;
  category: string;
  severity: string;
  confidence: number;
  detected_at: string | null;
}

type LiveState = "connecting" | "live" | "offline";

const SEVERITIES = ["", "critical", "high", "medium", "low", "informational"];
const STATUSES = ["", "new", "acknowledged", "investigating", "confirmed", "false_positive", "resolved"];
const MAX_LIVE_EVENTS = 5;

export function Alerts() {
  const [items, setItems] = useState<AlertItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

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

  // ----- live feed (WebSocket; refs keep the effect mount-only) -----
  const [liveState, setLiveState] = useState<LiveState>("connecting");
  const [liveEvents, setLiveEvents] = useState<LiveAlert[]>([]);
  const [bannerVisible, setBannerVisible] = useState(true);

  const loadRef = useRef(load);
  loadRef.current = load;
  const filterActiveRef = useRef(Boolean(severity || status));
  filterActiveRef.current = Boolean(severity || status);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retryTimer: number | null = null;
    let cancelled = false;
    let attempts = 0;

    const ingest = (msg: LiveAlert) => {
      setLiveEvents((prev) => [msg, ...prev.filter((e) => e.id !== msg.id)].slice(0, MAX_LIVE_EVENTS));
      if (!filterActiveRef.current) loadRef.current();
    };

    const connect = () => {
      if (cancelled) return;
      ws = createAlertSocket();
      if (!ws) {
        setLiveState("offline");
        return;
      }
      ws.onopen = () => {
        attempts = 0;
        setLiveState("live");
      };
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data as string) as { type: string } & LiveAlert;
          if (msg.type === "connected") setLiveState("live");
          else if (msg.type === "alert") ingest(msg);
          // "ping" keepalives need no handling
        } catch {
          /* ignore malformed frames */
        }
      };
      ws.onclose = () => {
        setLiveState("offline");
        if (!cancelled && attempts < 5) {
          attempts += 1;
          retryTimer = window.setTimeout(connect, Math.min(1000 * 2 ** attempts, 15000));
        }
      };
      ws.onerror = () => ws?.close();
    };

    connect();
    return () => {
      cancelled = true;
      if (retryTimer !== null) window.clearTimeout(retryTimer);
      ws?.close();
    };
  }, []);

  const updateStatus = async (id: string, newStatus: string) => {
    await api(`/alerts/${id}/status`, { method: "POST", body: JSON.stringify({ status: newStatus }) });
    load();
  };

  const downloadReport = async (id: string) => {
    setDownloading(id);
    setDownloadError(null);
    try {
      await downloadFile(`/alerts/${id}/report.pdf`, `rtip_alert_${id}.pdf`);
    } catch (e) {
      setDownloadError(e instanceof Error ? e.message : "PDF download failed");
    } finally {
      setDownloading(null);
    }
  };

  const liveDot =
    liveState === "live"
      ? "bg-accent animate-pulse"
      : liveState === "connecting"
        ? "bg-ink-300 animate-pulse"
        : "bg-ink-500";
  const liveLabel =
    liveState === "live" ? "LIVE" : liveState === "connecting" ? "CONNECTING…" : "FEED OFFLINE — retrying";

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-white">Alert Management</h1>
          <p className="text-xs text-ink-400">{total.toLocaleString()} alerts matching current filters</p>
        </div>
        <div className="flex gap-2">
          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value);
              setPage(0);
            }}
            className="rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200"
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
            className="rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200"
          >
            {STATUSES.map((s) => (
              <option key={s} value={s}>{s ? s.replace("_", " ") : "All statuses"}</option>
            ))}
          </select>
        </div>
      </div>

      {/* ----- live feed banner ----- */}
      {bannerVisible && (
        <Card className="p-3">
          <div className="flex items-center gap-3">
            <span className={`flex h-2 w-2 shrink-0 rounded-full ${liveDot}`} />
            <span className="shrink-0 text-2xs font-mono uppercase tracking-[0.14em] text-ink-200">{liveLabel}</span>
            <div className="min-w-0 flex-1">
              {liveEvents.length === 0 ? (
                <span className="text-2xs font-mono text-ink-400">
                  {liveState === "live" ? "Streaming new alerts as they are ingested." : "Waiting for connection…"}
                </span>
              ) : (
                <ul className="space-y-0.5">
                  {liveEvents.map((ev) => (
                    <li key={ev.id} className="flex items-center gap-2 overflow-hidden">
                      <SeverityBadge severity={ev.severity} />
                      <span className="truncate text-2xs text-ink-200">{ev.title}</span>
                      <span className="shrink-0 font-mono text-[10px] text-ink-500">{timeAgo(ev.detected_at)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
            <button
              onClick={load}
              className="shrink-0 rounded-sm border border-ink-600 px-2 py-1 text-2xs uppercase tracking-wider text-ink-300 hover:border-accent hover:text-accent"
            >
              Refresh
            </button>
            <button
              onClick={() => setBannerVisible(false)}
              title="Hide live feed banner"
              className="shrink-0 rounded-sm p-1 text-ink-500 hover:text-ink-200"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        </Card>
      )}

      {downloadError && (
        <Card className="border-accent/50 p-3 text-xs text-accent">{downloadError}</Card>
      )}

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
                    <span className="text-[10px] uppercase tracking-wider text-ink-500">{a.category.replace(/_/g, " ")}</span>
                    {a.occurrence_count > 1 && (
                      <span className="rounded bg-ink-700/50 px-1.5 py-0.5 text-[10px] text-ink-300">
                        ×{a.occurrence_count} evidence updates
                      </span>
                    )}
                  </div>
                  <p className="mt-1.5 text-sm font-medium text-ink-100">{a.title}</p>
                  <p className="mt-0.5 text-[11px] text-ink-400">
                    Detected {timeAgo(a.detected_at)} · published {timeAgo(a.first_published_at)} · confidence{" "}
                    {(a.confidence * 100).toFixed(0)}%
                  </p>
                </button>
                <select
                  value={a.status}
                  onChange={(e) => updateStatus(a.id, e.target.value)}
                  className="rounded border border-ink-600 bg-ink-950 px-2 py-1 text-xs text-ink-200"
                >
                  {STATUSES.filter(Boolean).map((s) => (
                    <option key={s} value={s}>{s.replace("_", " ")}</option>
                  ))}
                </select>
              </div>
              {expanded === a.id && (
                <div className="mt-3 space-y-2 border-t border-ink-600 pt-3 text-xs text-ink-300">
                  {a.recommended_action && (
                    <p>
                      <span className="font-medium text-accent">Recommended action:</span> {a.recommended_action}
                    </p>
                  )}
                  {a.evidence_sources && a.evidence_sources.length > 0 && (
                    <p>
                      <span className="font-medium text-ink-200">Evidence:</span>{" "}
                      {a.evidence_sources.map((s, i) => (
                        <span key={i}>
                          {i > 0 && ", "}
                          {s.url ? (
                            <a href={s.url} target="_blank" rel="noreferrer noopener" className="text-accent hover:underline">
                              {s.source_slug}
                            </a>
                          ) : (
                            s.source_slug
                          )}
                        </span>
                      ))}
                    </p>
                  )}
                  <div>
                    <button
                      onClick={() => downloadReport(a.id)}
                      disabled={downloading === a.id}
                      className="inline-flex items-center gap-1.5 rounded-sm border border-ink-600 px-2.5 py-1.5 text-2xs uppercase tracking-wider text-ink-300 hover:border-accent hover:text-accent disabled:opacity-40"
                    >
                      <FileDown className="h-3.5 w-3.5" />
                      {downloading === a.id ? "Exporting…" : "Download PDF report"}
                    </button>
                  </div>
                </div>
              )}
            </Card>
          ))}
          <div className="flex items-center justify-between text-xs text-ink-400">
            <span>Page {page + 1}</span>
            <div className="flex gap-2">
              <button
                disabled={page === 0}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                className="rounded border border-ink-600 px-3 py-1 disabled:opacity-30"
              >
                Previous
              </button>
              <button
                disabled={(page + 1) * 25 >= total}
                onClick={() => setPage((p) => p + 1)}
                className="rounded border border-ink-600 px-3 py-1 disabled:opacity-30"
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
