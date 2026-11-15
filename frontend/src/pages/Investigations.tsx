/* Investigations.tsx — case management over the intelligence platform.
 *
 * Top section: analyst cases (investigations) with status workflow, notes and
 * entity references — CRUD against /api/v1/investigations.
 * Bottom section: the correlation timeline (alerts newest-first) that feeds
 * cases; per-alert PDF case export (backend reportlab extra).
 */

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { FileDown, NotebookPen, Plus, StickyNote, Trash2 } from "lucide-react";
import { api, downloadFile } from "../api/client";
import { Card, CardHeader, EmptyState, SeverityBadge, Spinner, StatusBadge, timeAgo } from "../components/ui";
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

const caseStatusStyle: Record<string, string> = {
  open: "bg-accent text-black font-semibold",
  in_progress: "border border-accent text-accent",
  closed: "bg-ink-700 text-ink-300",
  reported: "bg-white text-black font-semibold",
};

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

  const inputCls =
    "rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200 placeholder:text-ink-500";

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-white">Investigation &amp; Correlation</h1>
          <p className="text-xs text-ink-400">
            {casesTotal.toLocaleString()} cases · {total.toLocaleString()} alerts in the triage timeline
          </p>
        </div>
        {canEdit && (
          <button
            onClick={() => setShowCreate(!showCreate)}
            className="inline-flex items-center gap-1.5 rounded-sm bg-accent px-3 py-1.5 text-2xs font-bold uppercase tracking-wider text-black hover:bg-white"
          >
            <Plus className="h-3.5 w-3.5" /> Open case
          </button>
        )}
      </div>

      {/* ------- Cases ------- */}
      {showCreate && canEdit && (
        <Card>
          <CardHeader title="New investigation" />
          <form onSubmit={createCase} className="flex flex-wrap items-end gap-2 p-4">
            <input
              required
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              placeholder="Case title — e.g. Suspicious C2 callbacks on edge-01"
              className="min-w-[18rem] flex-1 rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200 placeholder:text-ink-500"
            />
            <select value={newSeverity} onChange={(e) => setNewSeverity(e.target.value)} className={inputCls}>
              {CASE_SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <input
              value={newSummary}
              onChange={(e) => setNewSummary(e.target.value)}
              placeholder="Initial summary (optional)"
              className="w-56 rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200 placeholder:text-ink-500"
            />
            <button type="submit" className="rounded-sm bg-accent px-3 py-1.5 text-2xs font-bold uppercase tracking-wider text-black hover:bg-white">
              Create
            </button>
          </form>
        </Card>
      )}

      {casesError && <Card className="border-accent/50 p-3 text-xs text-accent">{casesError}</Card>}

      {casesLoading ? (
        <Spinner label="Loading cases…" />
      ) : cases.length === 0 ? (
        <Card>
          <EmptyState message="No open investigations — open a case from a significant alert and track it here." />
        </Card>
      ) : (
        <Card>
          <CardHeader title="Cases" subtitle={`${cases.length} shown of ${casesTotal}`} />
          <ul className="divide-y divide-ink-600">
            {cases.map((c) => (
              <li key={c.id} className="px-4 py-3">
                <div className="flex items-center gap-3">
                  <span
                    className={`inline-flex min-w-[6rem] items-center justify-center rounded-sm px-1.5 py-0.5 text-2xs font-mono uppercase tracking-[0.1em] ${
                      caseStatusStyle[c.status] ?? caseStatusStyle.open
                    }`}
                  >
                    {c.status.replace("_", " ")}
                  </span>
                  <button
                    className="min-w-0 flex-1 text-left"
                    onClick={() => setExpandedCase(expandedCase === c.id ? null : c.id)}
                  >
                    <p className="truncate text-sm text-ink-100">{c.title}</p>
                    <p className="mt-0.5 text-[11px] text-ink-400">
                      {c.severity && <>severity: {c.severity} · </>}
                      opened {timeAgo(c.created_at)} · updated {timeAgo(c.updated_at)}
                      {c.analyst_notes?.length ? <> · {c.analyst_notes.length} notes</> : null}
                    </p>
                  </button>
                  {canEdit && (
                    <>
                      <select
                        value={c.status}
                        onChange={(e) => setCaseStatus(c.id, e.target.value)}
                        className="rounded border border-ink-600 bg-ink-950 px-2 py-1 text-xs text-ink-200"
                      >
                        {CASE_STATUSES.map((s) => (
                          <option key={s} value={s}>{s.replace("_", " ")}</option>
                        ))}
                      </select>
                      <button
                        onClick={() => deleteCase(c.id)}
                        title="Delete case"
                        className="rounded-sm border border-ink-600 p-1.5 text-ink-400 hover:border-accent hover:text-accent"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </>
                  )}
                </div>
                {expandedCase === c.id && (
                  <div className="mt-3 space-y-2 border-t border-ink-600 pt-3">
                    {c.summary && <p className="text-xs text-ink-300">{c.summary}</p>}
                    {(c.analyst_notes ?? []).length > 0 && (
                      <ul className="space-y-1.5">
                        {c.analyst_notes!.map((n, i) => (
                          <li key={i} className="flex gap-2 text-xs">
                            <StickyNote className="mt-0.5 h-3 w-3 shrink-0 text-accent" />
                            <span className="text-ink-100">{n.note}</span>
                            <span className="ml-auto shrink-0 font-mono text-[10px] text-ink-500">
                              {n.author} · {timeAgo(n.at)}
                            </span>
                          </li>
                        ))}
                      </ul>
                    )}
                    {canEdit && (
                      <div className="flex gap-2">
                        <input
                          value={noteDrafts[c.id] || ""}
                          onChange={(e) => setNoteDrafts((d) => ({ ...d, [c.id]: e.target.value }))}
                          onKeyDown={(e) => e.key === "Enter" && addNote(c.id)}
                          placeholder="Add analyst note…"
                          className="flex-1 rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200 placeholder:text-ink-500"
                        />
                        <button
                          onClick={() => addNote(c.id)}
                          className="inline-flex items-center gap-1.5 rounded-sm border border-ink-600 px-2.5 py-1.5 text-2xs uppercase tracking-wider text-ink-300 hover:border-accent hover:text-accent"
                        >
                          <NotebookPen className="h-3.5 w-3.5" /> Note
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </Card>
      )}

      {/* ------- Correlation timeline ------- */}
      <div className="flex flex-wrap items-center justify-end gap-2 pt-2">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter by title or category…"
          className="w-44 rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200 placeholder:text-ink-500"
        />
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200"
        >
          {ALERT_SEVERITIES.map((s) => (
            <option key={s} value={s}>{s ? s.toUpperCase() : "All severities"}</option>
          ))}
        </select>
        <select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200"
        >
          {ALERT_STATUSES.map((s) => (
            <option key={s} value={s}>{s ? s.replace("_", " ") : "All statuses"}</option>
          ))}
        </select>
      </div>

      {error && <Card className="border-accent/50 p-3 text-xs text-accent">{error}</Card>}

      {loading ? (
        <Spinner label="Loading investigation timeline…" />
      ) : visible.length === 0 ? (
        <Card><EmptyState message="No alerts match the current filters." /></Card>
      ) : (
        <Card>
          <CardHeader title="Correlation timeline" subtitle="Newest first — occurrence count shows repeated evidence" />
          <ul className="divide-y divide-ink-600">
            {visible.map((a) => (
              <li key={a.id} className="flex items-center gap-3 px-4 py-3">
                <SeverityBadge severity={a.severity} />
                <StatusBadge status={a.status} />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm text-ink-100">{a.title}</p>
                  <p className="mt-0.5 text-[11px] text-ink-400">
                    {a.category.replace(/_/g, " ")} · detected {timeAgo(a.detected_at)} · confidence {(a.confidence * 100).toFixed(0)}%
                    {a.occurrence_count > 1 && <> · ×{a.occurrence_count} evidence updates</>}
                  </p>
                </div>
                <button
                  onClick={() => downloadReport(a.id)}
                  disabled={downloading === a.id}
                  className="inline-flex items-center gap-1.5 rounded-sm border border-ink-600 px-2.5 py-1.5 text-2xs uppercase tracking-wider text-ink-300 hover:border-accent hover:text-accent disabled:opacity-40"
                  title="Download PDF case report"
                >
                  <FileDown className="h-3.5 w-3.5" />
                  {downloading === a.id ? "Exporting…" : "PDF report"}
                </button>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}
