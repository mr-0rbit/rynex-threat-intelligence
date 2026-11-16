/* Alerts.tsx — alert management with a live WebSocket feed and fallback polling.
 *
 * The banner subscribes to /api/v1/ws/alerts (same-origin, token in query).
 * If the socket disconnects or fails handshake, it falls back to background
 * polling and auto-reconnects with exponential backoff.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  ChevronDown,
  ChevronUp,
  ExternalLink,
  FileDown,
  RefreshCw,
  TriangleAlert,
  Wifi,
  WifiOff,
  X,
} from "lucide-react";
import { api, createAlertSocket, downloadFile, tryRefresh } from "../api/client";
import {
  Badge,
  Card,
  EmptyState,
  SeverityBadge,
  Spinner,
  StatusBadge,
  timeAgo,
} from "../components/ui";

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

  // ----- live feed (WebSocket + polling fallback) -----
  const [liveState, setLiveState] = useState<LiveState>("connecting");
  const [liveEvents, setLiveEvents] = useState<LiveAlert[]>([]);
  const [bannerVisible, setBannerVisible] = useState(true);

  const loadRef = useRef(load);
  loadRef.current = load;
  const filterActiveRef = useRef(Boolean(severity || status));
  filterActiveRef.current = Boolean(severity || status);

  // Fallback polling when WebSocket is offline
  useEffect(() => {
    if (liveState !== "offline") return;
    const interval = setInterval(() => {
      if (!filterActiveRef.current) {
        loadRef.current();
      }
    }, 15000);
    return () => clearInterval(interval);
  }, [liveState]);

  const reconnectRef = useRef<() => void>(() => {});

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retryTimer: number | null = null;
    let cancelled = false;
    let attempts = 0;

    const ingest = (msg: LiveAlert) => {
      setLiveEvents((prev) => [msg, ...prev.filter((e) => e.id !== msg.id)].slice(0, MAX_LIVE_EVENTS));
      if (!filterActiveRef.current) loadRef.current();
    };

    const scheduleRetry = () => {
      if (cancelled) return;
      attempts += 1;
      const delay = Math.min(2000 * Math.pow(1.5, Math.min(attempts, 6)), 15000);
      if (retryTimer !== null) window.clearTimeout(retryTimer);
      retryTimer = window.setTimeout(connect, delay);
    };

    const connect = async () => {
      if (cancelled) return;
      setLiveState("connecting");

      try {
        ws = await createAlertSocket();
      } catch {
        ws = null;
      }

      if (!ws) {
        setLiveState("offline");
        scheduleRetry();
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
        } catch {
          /* ignore malformed frames */
        }
      };

      ws.onclose = async (ev) => {
        setLiveState("offline");
        // If closed with policy violation (1008), refresh access token
        if (ev.code === 1008) {
          try {
            await tryRefresh();
          } catch {
            /* ignore */
          }
        }
        scheduleRetry();
      };

      ws.onerror = () => {
        ws?.close();
      };
    };

    reconnectRef.current = () => {
      attempts = 0;
      if (retryTimer !== null) window.clearTimeout(retryTimer);
      if (ws) {
        try {
          ws.close();
        } catch {
          /* ignore */
        }
      }
      connect();
    };

    connect();

    return () => {
      cancelled = true;
      if (retryTimer !== null) window.clearTimeout(retryTimer);
      if (ws) {
        try {
          ws.close();
        } catch {
          /* ignore */
        }
      }
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
      ? "bg-emerald-400 shadow-[0_0_8px_#10b981] animate-pulse"
      : liveState === "connecting"
        ? "bg-amber-400 animate-pulse"
        : "bg-ink-500";

  const liveLabel =
    liveState === "live" ? "STREAM LIVE" : liveState === "connecting" ? "CONNECTING…" : "FALLBACK POLLING";

  const liveDescription =
    liveState === "live"
      ? "Subscribed to real-time WebSocket feed · streaming alerts as ingested."
      : liveState === "connecting"
        ? "Negotiating secure socket handshake…"
        : "Real-time socket offline · Background auto-refresh active (every 15s).";

  return (
    <div className="space-y-5">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <TriangleAlert className="h-5 w-5 text-accent" />
              Alert Management
            </h1>
            <Badge variant="cyan">{total.toLocaleString()} ALERTS</Badge>
          </div>
          <p className="mt-1 text-xs text-ink-400 font-sans">
            Real-time correlated telemetry matching security detection rules and asset boundaries.
          </p>
        </div>

        {/* Filter Selects */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative">
            <select
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value);
                setPage(0);
              }}
              className="rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 pl-3 pr-8 text-xs font-mono text-ink-200 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40 shadow-sm cursor-pointer"
            >
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s ? s.toUpperCase() : "All Severities"}
                </option>
              ))}
            </select>
          </div>

          <div className="relative">
            <select
              value={status}
              onChange={(e) => {
                setStatus(e.target.value);
                setPage(0);
              }}
              className="rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 pl-3 pr-8 text-xs font-mono text-ink-200 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40 shadow-sm cursor-pointer"
            >
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s ? s.replace("_", " ").toUpperCase() : "All Statuses"}
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={load}
            title="Refresh alert list"
            className="flex items-center gap-1.5 rounded-lg border border-ink-700/80 bg-ink-900/90 px-3 py-1.5 text-xs font-mono font-medium text-ink-200 hover:border-accent hover:text-accent transition-colors"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* ----- Live feed / Polling banner ----- */}
      {bannerVisible && (
        <div
          className={`relative overflow-hidden rounded-xl border p-3.5 shadow-md backdrop-blur-md transition-all ${
            liveState === "live"
              ? "border-emerald-500/30 bg-gradient-to-r from-ink-900/95 via-emerald-500/[0.04] to-ink-900/95"
              : liveState === "connecting"
                ? "border-amber-500/30 bg-gradient-to-r from-ink-900/95 via-amber-500/[0.04] to-ink-900/95"
                : "border-ink-700/80 bg-gradient-to-r from-ink-900/95 via-ink-850 to-ink-900/95"
          }`}
        >
          <div className="flex items-center gap-3">
            <span className={`flex h-2.5 w-2.5 shrink-0 rounded-full ${liveDot}`} />
            <div className="flex items-center gap-1.5 shrink-0">
              {liveState === "live" ? (
                <Wifi className="h-3.5 w-3.5 text-emerald-400" />
              ) : (
                <WifiOff className="h-3.5 w-3.5 text-ink-400" />
              )}
              <span
                className={`text-2xs font-mono uppercase tracking-[0.14em] font-bold ${
                  liveState === "live"
                    ? "text-emerald-400"
                    : liveState === "connecting"
                      ? "text-amber-400"
                      : "text-ink-300"
                }`}
              >
                {liveLabel}
              </span>
            </div>

            <div className="min-w-0 flex-1">
              {liveEvents.length === 0 ? (
                <span className="text-2xs font-mono text-ink-300">
                  {liveDescription}
                </span>
              ) : (
                <div className="flex items-center gap-3 overflow-x-auto no-scrollbar py-0.5">
                  {liveEvents.map((ev) => (
                    <div
                      key={ev.id}
                      className="flex shrink-0 items-center gap-2 rounded-md border border-ink-700/70 bg-ink-950/80 px-2 py-1 shadow-sm"
                    >
                      <SeverityBadge severity={ev.severity} />
                      <span className="max-w-[200px] truncate text-2xs text-ink-200 font-medium">
                        {ev.title}
                      </span>
                      <span className="shrink-0 font-mono text-[10px] text-ink-400">
                        {timeAgo(ev.detected_at)}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {liveState === "offline" && (
              <button
                onClick={() => reconnectRef.current()}
                title="Attempt to reconnect to live WebSocket"
                className="shrink-0 rounded-lg border border-accent/40 bg-accent/15 px-2.5 py-1 text-2xs font-mono font-bold uppercase tracking-wider text-accent hover:bg-accent hover:text-black transition-all"
              >
                Reconnect
              </button>
            )}

            <button
              onClick={() => setBannerVisible(false)}
              title="Dismiss live feed banner"
              className="shrink-0 rounded-lg p-1 text-ink-400 hover:bg-ink-800 hover:text-ink-200 transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}

      {downloadError && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-950/30 p-3 text-xs text-rose-300 font-mono">
          {downloadError}
        </div>
      )}

      {loading ? (
        <Spinner label="Loading threat alerts…" />
      ) : items.length === 0 ? (
        <Card>
          <EmptyState message="No alerts match the current filter criteria." />
        </Card>
      ) : (
        <div className="space-y-3">
          {items.map((a) => {
            const isExp = expanded === a.id;
            return (
              <div
                key={a.id}
                className={`overflow-hidden rounded-xl border transition-all duration-200 shadow-md ${
                  isExp
                    ? "border-accent/40 bg-ink-900/98 ring-1 ring-accent/20"
                    : "border-ink-700/70 bg-ink-900/85 hover:border-ink-600/90"
                }`}
              >
                <div className="p-4 sm:p-5">
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                    <button
                      className="min-w-0 flex-1 text-left"
                      onClick={() => setExpanded(isExp ? null : a.id)}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={a.severity} />
                        <StatusBadge status={a.status} />
                        <span className="rounded bg-ink-800/80 border border-ink-700 px-2 py-0.5 text-[10px] uppercase font-mono tracking-wider text-ink-300">
                          {a.category.replace(/_/g, " ")}
                        </span>
                        {a.occurrence_count > 1 && (
                          <span className="rounded bg-accent/10 border border-accent/20 px-2 py-0.5 text-[10px] font-mono text-accent">
                            ×{a.occurrence_count} events
                          </span>
                        )}
                      </div>

                      <p className="mt-2 text-sm sm:text-base font-semibold text-white group-hover:text-accent transition-colors">
                        {a.title}
                      </p>

                      <div className="mt-2 flex flex-wrap items-center gap-4 text-2xs text-ink-400 font-mono">
                        <span>Detected {timeAgo(a.detected_at)}</span>
                        <span>·</span>
                        <span>Published {timeAgo(a.first_published_at)}</span>
                        <span>·</span>
                        <div className="flex items-center gap-1.5">
                          <span>Confidence</span>
                          <div className="h-1.5 w-16 overflow-hidden rounded-full bg-ink-800">
                            <div
                              className="h-full rounded-full bg-accent"
                              style={{ width: `${Math.round(a.confidence * 100)}%` }}
                            />
                          </div>
                          <span className="text-white font-semibold">
                            {(a.confidence * 100).toFixed(0)}%
                          </span>
                        </div>
                      </div>
                    </button>

                    <div className="flex items-center gap-2 shrink-0 self-end sm:self-start">
                      <select
                        value={a.status}
                        onChange={(e) => updateStatus(a.id, e.target.value)}
                        className="rounded-lg border border-ink-700/80 bg-ink-950 px-2.5 py-1.5 text-xs font-mono text-ink-200 focus:border-accent focus:outline-none"
                      >
                        {STATUSES.filter(Boolean).map((s) => (
                          <option key={s} value={s}>
                            {s.replace("_", " ").toUpperCase()}
                          </option>
                        ))}
                      </select>

                      <button
                        onClick={() => setExpanded(isExp ? null : a.id)}
                        className="rounded-lg border border-ink-700/80 bg-ink-950 p-1.5 text-ink-400 hover:text-white transition-colors"
                        aria-label={isExp ? "Collapse" : "Expand"}
                      >
                        {isExp ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                      </button>
                    </div>
                  </div>

                  {/* Expanded Detail View */}
                  {isExp && (
                    <div className="mt-4 space-y-3.5 border-t border-ink-700/70 pt-4 text-xs font-sans">
                      {a.recommended_action && (
                        <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3.5 text-amber-200">
                          <p className="font-bold uppercase tracking-wider text-2xs text-amber-300 font-mono mb-1">
                            Recommended Action / Mitigation
                          </p>
                          <p className="text-xs leading-relaxed">{a.recommended_action}</p>
                        </div>
                      )}

                      {a.evidence_sources && a.evidence_sources.length > 0 && (
                        <div>
                          <p className="font-semibold uppercase tracking-wider text-2xs text-ink-400 font-mono mb-2">
                            Correlated Evidence Feeds ({a.evidence_sources.length})
                          </p>
                          <div className="flex flex-wrap gap-2">
                            {a.evidence_sources.map((s, idx) => (
                              <div
                                key={idx}
                                className="inline-flex items-center gap-1.5 rounded-lg border border-ink-700 bg-ink-950 px-2.5 py-1 text-2xs font-mono"
                              >
                                {s.url ? (
                                  <a
                                    href={s.url}
                                    target="_blank"
                                    rel="noreferrer noopener"
                                    className="flex items-center gap-1 text-accent hover:underline"
                                  >
                                    <span>{s.source_slug}</span>
                                    <ExternalLink className="h-3 w-3" />
                                  </a>
                                ) : (
                                  <span className="text-ink-300">{s.source_slug}</span>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      <div className="pt-2 flex items-center justify-between">
                        <button
                          onClick={() => downloadReport(a.id)}
                          disabled={downloading === a.id}
                          className="inline-flex items-center gap-2 rounded-lg border border-accent/40 bg-accent/10 px-3.5 py-2 text-xs font-mono font-bold uppercase tracking-wider text-accent hover:bg-accent hover:text-black transition-all shadow-[0_0_12px_rgba(0,212,255,0.15)] disabled:opacity-50"
                        >
                          <FileDown className="h-4 w-4" />
                          <span>{downloading === a.id ? "Compiling PDF…" : "Export Incident PDF"}</span>
                        </button>

                        <span className="text-2xs text-ink-400 font-mono">
                          UUID: {a.id}
                        </span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            );
          })}

          {/* Pagination */}
          <div className="flex items-center justify-between pt-3 text-xs font-mono text-ink-400">
            <span>
              Page {page + 1} of {Math.max(1, Math.ceil(total / 25))} ({total.toLocaleString()} total)
            </span>
            <div className="flex gap-2">
              <button
                disabled={page === 0}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                className="rounded-lg border border-ink-700/80 bg-ink-900 px-3 py-1.5 text-xs text-ink-200 hover:border-ink-500 disabled:opacity-30 disabled:pointer-events-none transition-colors"
              >
                Previous
              </button>
              <button
                disabled={(page + 1) * 25 >= total}
                onClick={() => setPage((p) => p + 1)}
                className="rounded-lg border border-ink-700/80 bg-ink-900 px-3 py-1.5 text-xs text-ink-200 hover:border-ink-500 disabled:opacity-30 disabled:pointer-events-none transition-colors"
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
