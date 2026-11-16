/* Investigations.tsx — case management over the intelligence platform.
 *
 * Top section: analyst cases (investigations) with status workflow, notes and
 * entity references — CRUD against /api/v1/investigations.
 * Bottom section: the correlation timeline (alerts newest-first) that feeds
 * cases; per-alert PDF case export (backend reportlab extra).
 */

import { useCallback, useEffect, useState, type FormEvent } from "react";
import {
  FileDown,
  Network,
  NotebookPen,
  Plus,
  Search,
  StickyNote,
  Trash2,
  X,
} from "lucide-react";
import { api, downloadFile } from "../api/client";
import {
  Badge,
  Card,
  CardHeader,
  EmptyState,
  SeverityBadge,
  Spinner,
  StatusBadge,
  timeAgo,
} from "../components/ui";
import { useAuth } from "../auth";

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

interface InvestigationNote {
  author: string;
  note: string;
  at: string;
}

interface Investigation {
  id: string;
  title: string;
  status: string;
  severity: string | null;
  summary: string | null;
  entity_refs: Record<string, unknown> | null;
  analyst_notes: InvestigationNote[] | null;
  confidence: number | null;
  created_at: string | null;
  updated_at: string | null;
}

const CASE_STATUSES = ["open", "in_progress", "closed", "reported"];
const CASE_SEVERITIES = ["critical", "high", "medium", "low", "informational"];
const ALERT_SEVERITIES = ["", "critical", "high", "medium", "low", "informational"];
const ALERT_STATUSES = ["", "new", "acknowledged", "investigating", "confirmed", "false_positive", "resolved"];

export function Investigations() {
  const { user } = useAuth();
  const canEdit = user?.role === "admin" || user?.role === "analyst";

  // ----- investigations state -----
  const [cases, setCases] = useState<Investigation[]>([]);
  const [casesTotal, setCasesTotal] = useState(0);
  const [casesLoading, setCasesLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [newTitle, setNewTitle] = useState("");
  const [newSeverity, setNewSeverity] = useState("medium");
  const [newSummary, setNewSummary] = useState("");
  const [noteDrafts, setNoteDrafts] = useState<Record<string, string>>({});
  const [expandedCase, setExpandedCase] = useState<string | null>(null);
  const [casesError, setCasesError] = useState<string | null>(null);

  // ----- timeline state -----
  const [items, setItems] = useState<AlertItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [q, setQ] = useState("");
  const [downloading, setDownloading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadCases = useCallback(() => {
    setCasesLoading(true);
    api<{ total: number; items: Investigation[] }>("/investigations?limit=100")
      .then((r) => {
        setCases(r.items);
        setCasesTotal(r.total);
      })
      .catch((e) => setCasesError(e instanceof Error ? e.message : "Failed to load cases"))
      .finally(() => setCasesLoading(false));
  }, []);

  const load = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams({ limit: "50" });
    if (severity) params.set("severity", severity);
    if (status) params.set("status", status);
    api<{ total: number; items: AlertItem[] }>(`/alerts?${params}`)
      .then((r) => {
        setItems(r.items);
        setTotal(r.total);
      })
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  }, [severity, status]);

  useEffect(loadCases, [loadCases]);
  useEffect(load, [load]);

  const createCase = async (e: FormEvent) => {
    e.preventDefault();
    setCasesError(null);
    try {
      await api("/investigations", {
        method: "POST",
        body: JSON.stringify({
          title: newTitle.trim(),
          status: "open",
          severity: newSeverity,
          summary: newSummary.trim() || undefined,
        }),
      });
      setNewTitle("");
      setNewSummary("");
      setShowCreate(false);
      loadCases();
    } catch (err) {
      setCasesError(err instanceof Error ? err.message : "Create failed");
    }
  };

  const setCaseStatus = async (id: string, newStatus: string) => {
    setCasesError(null);
    try {
      await api(`/investigations/${id}`, { method: "PATCH", body: JSON.stringify({ status: newStatus }) });
      loadCases();
    } catch (err) {
      setCasesError(err instanceof Error ? err.message : "Update failed");
    }
  };

  const addNote = async (id: string) => {
    const note = (noteDrafts[id] || "").trim();
    if (!note) return;
    setCasesError(null);
    try {
      await api(`/investigations/${id}/notes`, { method: "POST", body: JSON.stringify({ note }) });
      setNoteDrafts((d) => ({ ...d, [id]: "" }));
      loadCases();
    } catch (err) {
      setCasesError(err instanceof Error ? err.message : "Note failed");
    }
  };

  const deleteCase = async (id: string) => {
    setCasesError(null);
    try {
      await api(`/investigations/${id}`, { method: "DELETE" });
      if (expandedCase === id) setExpandedCase(null);
      loadCases();
    } catch (err) {
      setCasesError(err instanceof Error ? err.message : "Delete failed");
    }
  };

  const visible = items.filter(
    (a) => !q || a.title.toLowerCase().includes(q.toLowerCase()) || a.category.includes(q.toLowerCase()),
  );

  const downloadReport = async (id: string) => {
    setDownloading(id);
    setError(null);
    try {
      await downloadFile(`/alerts/${id}/report.pdf`, `rtip_alert_${id}.pdf`);
    } catch (e) {
      setError(e instanceof Error ? e.message : "PDF download failed");
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Network className="h-5 w-5 text-accent" />
              Investigation &amp; Correlation Cases
            </h1>
            <Badge variant="cyan">{casesTotal.toLocaleString()} ACTIVE CASES</Badge>
          </div>
          <p className="mt-1 text-xs text-ink-400 font-sans">
            Cross-telemetry case workspaces for deep threat triage, analyst notes, and correlation timeline feeds ({total.toLocaleString()} timeline alerts).
          </p>
        </div>

        {canEdit && (
          <button
            onClick={() => setShowCreate(!showCreate)}
            className="inline-flex items-center gap-2 rounded-xl bg-accent px-4 py-2 text-xs font-mono font-bold uppercase tracking-wider text-black hover:bg-white hover:shadow-[0_0_15px_rgba(0,212,255,0.4)] transition-all"
          >
            {showCreate ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
            <span>{showCreate ? "Cancel" : "Open Investigation"}</span>
          </button>
        )}
      </div>

      {/* Case Creation Card */}
      {showCreate && canEdit && (
        <Card className="border-accent/40 bg-gradient-to-b from-ink-900 to-ink-950 p-5 shadow-xl">
          <CardHeader title="Open New Security Case" subtitle="Assign title, urgency rating, and incident scope" />
          <form onSubmit={createCase} className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="lg:col-span-2">
              <label className="block text-[10px] font-mono uppercase text-ink-400 mb-1">Case Title</label>
              <input
                required
                value={newTitle}
                onChange={(e) => setNewTitle(e.target.value)}
                placeholder="e.g. Cobalt Strike C2 beaconing on cluster gateway-04"
                className="w-full rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 text-xs font-mono text-ink-100 placeholder:text-ink-600 focus:border-accent focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase text-ink-400 mb-1">Initial Severity</label>
              <select
                value={newSeverity}
                onChange={(e) => setNewSeverity(e.target.value)}
                className="w-full rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 text-xs font-mono text-ink-200 focus:border-accent focus:outline-none"
              >
                {CASE_SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase text-ink-400 mb-1">Summary Note</label>
              <input
                value={newSummary}
                onChange={(e) => setNewSummary(e.target.value)}
                placeholder="Initial observations (optional)"
                className="w-full rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 text-xs font-mono text-ink-100 placeholder:text-ink-600 focus:border-accent focus:outline-none"
              />
            </div>

            <div className="sm:col-span-2 lg:col-span-4 flex justify-end gap-2 pt-2">
              <button
                type="submit"
                className="rounded-lg bg-accent px-5 py-2 text-xs font-mono font-bold uppercase tracking-wider text-black hover:bg-white transition-all"
              >
                Launch Investigation
              </button>
            </div>
          </form>
        </Card>
      )}

      {casesError && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-950/30 p-3 text-xs text-rose-300 font-mono">
          {casesError}
        </div>
      )}

      {/* Case Management List */}
      {casesLoading ? (
        <Spinner label="Loading active investigation dossiers…" />
      ) : cases.length === 0 ? (
        <Card>
          <EmptyState message="No investigations active. Triage alerts and launch cases to begin tracking." />
        </Card>
      ) : (
        <Card>
          <CardHeader title="Active Incident Dossiers" subtitle={`${cases.length} cases registered`} />
          <div className="divide-y divide-ink-700/60">
            {cases.map((c) => {
              const isExp = expandedCase === c.id;
              return (
                <div key={c.id} className="p-4 sm:p-5 hover:bg-ink-800/30 transition-colors">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <button
                      className="min-w-0 flex-1 text-left"
                      onClick={() => setExpandedCase(isExp ? null : c.id)}
                    >
                      <div className="flex flex-wrap items-center gap-2">
                        <StatusBadge status={c.status} />
                        {c.severity && <SeverityBadge severity={c.severity} />}
                        <span className="text-base font-bold text-white font-mono hover:text-accent transition-colors">
                          {c.title}
                        </span>
                      </div>
                      <p className="mt-1 text-2xs text-ink-400 font-mono">
                        Opened {timeAgo(c.created_at)} · Updated {timeAgo(c.updated_at)}
                        {c.analyst_notes?.length ? ` · ${c.analyst_notes.length} analyst notes` : ""}
                      </p>
                    </button>

                    {canEdit && (
                      <div className="flex items-center gap-2 shrink-0 self-end sm:self-center">
                        <select
                          value={c.status}
                          onChange={(e) => setCaseStatus(c.id, e.target.value)}
                          className="rounded-lg border border-ink-700/80 bg-ink-950 px-2.5 py-1.5 text-xs font-mono text-ink-200 focus:border-accent focus:outline-none"
                        >
                          {CASE_STATUSES.map((s) => (
                            <option key={s} value={s}>
                              {s.replace("_", " ").toUpperCase()}
                            </option>
                          ))}
                        </select>
                        <button
                          onClick={() => deleteCase(c.id)}
                          title="Archive or delete case"
                          className="rounded-lg border border-ink-700 bg-ink-950 p-1.5 text-ink-400 hover:border-rose-500 hover:text-rose-400 transition-colors"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Expanded Case Notes & Summary */}
                  {isExp && (
                    <div className="mt-4 space-y-4 border-t border-ink-700/70 pt-4">
                      {c.summary && (
                        <div className="rounded-lg border border-ink-700/80 bg-ink-950/80 p-3.5 text-xs text-ink-200 font-sans leading-relaxed">
                          <p className="font-bold text-2xs uppercase tracking-wider text-ink-400 font-mono mb-1">
                            Investigation Overview:
                          </p>
                          {c.summary}
                        </div>
                      )}

                      {/* Notes Feed */}
                      {(c.analyst_notes ?? []).length > 0 && (
                        <div className="space-y-2">
                          <p className="text-[10px] font-mono uppercase tracking-wider text-ink-400 font-bold">
                            Analyst Activity Log
                          </p>
                          <div className="space-y-2">
                            {c.analyst_notes!.map((n, i) => (
                              <div
                                key={i}
                                className="flex items-start gap-2.5 rounded-lg border border-ink-700/60 bg-ink-950/60 p-3 text-xs"
                              >
                                <StickyNote className="mt-0.5 h-3.5 w-3.5 shrink-0 text-accent" />
                                <div className="min-w-0 flex-1 font-sans text-ink-100">{n.note}</div>
                                <span className="shrink-0 font-mono text-[10px] text-ink-400">
                                  {n.author} · {timeAgo(n.at)}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {canEdit && (
                        <div className="flex gap-2 pt-1">
                          <input
                            value={noteDrafts[c.id] || ""}
                            onChange={(e) => setNoteDrafts((d) => ({ ...d, [c.id]: e.target.value }))}
                            onKeyDown={(e) => e.key === "Enter" && addNote(c.id)}
                            placeholder="Add timestamped analyst finding or IOC annotation…"
                            className="flex-1 rounded-lg border border-ink-700/80 bg-ink-950 px-3 py-2 text-xs font-mono text-ink-100 placeholder:text-ink-600 focus:border-accent focus:outline-none"
                          />
                          <button
                            onClick={() => addNote(c.id)}
                            className="inline-flex items-center gap-1.5 rounded-lg bg-accent/15 border border-accent/40 px-4 py-2 text-xs font-mono font-bold uppercase tracking-wider text-accent hover:bg-accent hover:text-black transition-all"
                          >
                            <NotebookPen className="h-3.5 w-3.5" />
                            <span>Add Note</span>
                          </button>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* ------- Correlation Timeline Section ------- */}
      <div className="pt-4 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-ink-700/60 pb-3">
          <div>
            <h2 className="text-base font-bold text-white font-mono">
              Correlation Alert Timeline
            </h2>
            <p className="text-2xs text-ink-400 font-sans">
              Chronological security telemetry feeding active investigations
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-400" />
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Filter timeline…"
                className="w-48 rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 pl-9 pr-3 text-xs font-mono text-ink-100 placeholder:text-ink-500 focus:border-accent focus:outline-none"
              />
            </div>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 px-3 text-xs font-mono text-ink-200 focus:border-accent focus:outline-none cursor-pointer"
            >
              {ALERT_SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s ? s.toUpperCase() : "All Severities"}
                </option>
              ))}
            </select>
            <select
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              className="rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 px-3 text-xs font-mono text-ink-200 focus:border-accent focus:outline-none cursor-pointer"
            >
              {ALERT_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s ? s.replace("_", " ").toUpperCase() : "All Statuses"}
                </option>
              ))}
            </select>
          </div>
        </div>

        {error && (
          <div className="rounded-xl border border-rose-500/40 bg-rose-950/30 p-3 text-xs text-rose-300 font-mono">
            {error}
          </div>
        )}

        {loading ? (
          <Spinner label="Loading telemetry correlation feed…" />
        ) : visible.length === 0 ? (
          <Card>
            <EmptyState message="No timeline alerts match current filter criteria." />
          </Card>
        ) : (
          <Card>
            <div className="divide-y divide-ink-700/60">
              {visible.map((a) => (
                <div
                  key={a.id}
                  className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 hover:bg-ink-800/40 transition-colors"
                >
                  <div className="flex items-start gap-3 min-w-0 flex-1">
                    <SeverityBadge severity={a.severity} className="mt-0.5" />
                    <StatusBadge status={a.status} />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-semibold text-white font-mono">{a.title}</p>
                      <p className="mt-1 text-2xs text-ink-400 font-mono">
                        {a.category.replace(/_/g, " ")} · detected {timeAgo(a.detected_at)} · confidence{" "}
                        {(a.confidence * 100).toFixed(0)}%
                        {a.occurrence_count > 1 && ` · ×${a.occurrence_count} recurring events`}
                      </p>
                    </div>
                  </div>

                  <button
                    onClick={() => downloadReport(a.id)}
                    disabled={downloading === a.id}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-ink-700 bg-ink-950 px-3 py-1.5 text-2xs font-mono text-ink-300 hover:border-accent hover:text-accent transition-colors self-end sm:self-center disabled:opacity-40"
                    title="Export investigation PDF"
                  >
                    <FileDown className="h-3.5 w-3.5" />
                    <span>{downloading === a.id ? "Generating…" : "PDF Report"}</span>
                  </button>
                </div>
              ))}
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}
