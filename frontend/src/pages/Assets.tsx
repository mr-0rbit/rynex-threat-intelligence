/* Assets.tsx — the organization's own attack surface.
 *
 * Intel matched against these assets escalates severity and names the asset
 * in alerts. CRUD against GET/POST/PATCH/DELETE /api/v1/assets.
 */

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Plus, ShieldCheck, Trash2 } from "lucide-react";
import { api } from "../api/client";
import { Card, CardHeader, EmptyState, Spinner, timeAgo } from "../components/ui";
import { useAuth } from "../auth";

interface Asset {
  id: string;
  type: string;
  value: string;
  display_name: string | null;
  criticality: string;
  owner_team: string | null;
  enabled: boolean;
  match_count: number;
  last_matched_at: string | null;
}

const TYPES = ["domain", "ipv4", "ipv6", "cidr", "product", "vendor", "keyword"];
const CRITICALITIES = ["low", "medium", "high", "critical"];

const criticalityStyle: Record<string, string> = {
  critical: "bg-white text-black font-bold",
  high: "bg-accent text-black font-bold",
  medium: "border border-accent text-accent",
  low: "border border-ink-500 text-ink-300",
};

export function Assets() {
  const { user } = useAuth();
  const canEdit = user?.role === "admin" || user?.role === "analyst";

  const [items, setItems] = useState<Asset[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState("");
  const [critFilter, setCritFilter] = useState("");
  const [q, setQ] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ type: "domain", value: "", criticality: "medium", display_name: "", owner_team: "" });

  const load = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams({ limit: "200" });
    if (typeFilter) params.set("type", typeFilter);
    if (critFilter) params.set("criticality", critFilter);
    if (q) params.set("q", q);
    api<{ total: number; items: Asset[] }>(`/assets?${params}`)
      .then((r) => {
        setItems(r.items);
        setTotal(r.total);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "Failed to load assets"))
      .finally(() => setLoading(false));
  }, [typeFilter, critFilter, q]);

  useEffect(load, [load]);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api("/assets", {
        method: "POST",
        body: JSON.stringify({
          type: form.type,
          value: form.value.trim(),
          criticality: form.criticality,
          display_name: form.display_name.trim() || undefined,
          owner_team: form.owner_team.trim() || undefined,
        }),
      });
      setForm({ type: "domain", value: "", criticality: "medium", display_name: "", owner_team: "" });
      setShowForm(false);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Create failed");
    } finally {
      setBusy(false);
    }
  };

  const toggle = async (a: Asset) => {
    try {
      await api(`/assets/${a.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !a.enabled }) });
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Update failed");
    }
  };

  const remove = async (id: string) => {
    try {
      await api(`/assets/${id}`, { method: "DELETE" });
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Delete failed");
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-white">Asset Inventory</h1>
          <p className="text-xs text-ink-400">
            {total.toLocaleString()} assets · intel touching these escalates and names them in alerts
          </p>
        </div>
        {canEdit && (
          <button
            onClick={() => setShowForm(!showForm)}
            className="inline-flex items-center gap-1.5 rounded-sm bg-accent px-3 py-1.5 text-2xs font-bold uppercase tracking-wider text-black hover:bg-white"
          >
            <Plus className="h-3.5 w-3.5" /> Add asset
          </button>
        )}
      </div>

      {showForm && canEdit && (
        <Card>
          <CardHeader title="New asset" />
          <form onSubmit={create} className="flex flex-wrap items-end gap-2 p-4">
            <select
              value={form.type}
              onChange={(e) => setForm({ ...form, type: e.target.value })}
              className="rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200"
            >
              {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <input
              required
              value={form.value}
              onChange={(e) => setForm({ ...form, value: e.target.value })}
              placeholder="value — e.g. acme.com, 10.0.0.0/16, Exchange"
              className="min-w-[16rem] flex-1 rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200 placeholder:text-ink-500"
            />
            <select
              value={form.criticality}
              onChange={(e) => setForm({ ...form, criticality: e.target.value })}
              className="rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200"
            >
              {CRITICALITIES.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
            <input
              value={form.display_name}
              onChange={(e) => setForm({ ...form, display_name: e.target.value })}
              placeholder="display name (optional)"
              className="w-40 rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200 placeholder:text-ink-500"
            />
            <input
              value={form.owner_team}
              onChange={(e) => setForm({ ...form, owner_team: e.target.value })}
              placeholder="owner team (optional)"
              className="w-36 rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200 placeholder:text-ink-500"
            />
            <button
              type="submit"
              disabled={busy}
              className="rounded-sm bg-accent px-3 py-1.5 text-2xs font-bold uppercase tracking-wider text-black hover:bg-white disabled:opacity-40"
            >
              {busy ? "Saving…" : "Save"}
            </button>
          </form>
        </Card>
      )}

      <div className="flex flex-wrap gap-2">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter by value…"
          className="w-44 rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200 placeholder:text-ink-500"
        />
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200"
        >
          <option value="">All types</option>
          {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select
          value={critFilter}
          onChange={(e) => setCritFilter(e.target.value)}
          className="rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200"
        >
          <option value="">All criticalities</option>
          {CRITICALITIES.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
      </div>

      {error && <Card className="border-accent/50 p-3 text-xs text-accent">{error}</Card>}

      {loading ? (
        <Spinner label="Loading asset inventory…" />
      ) : items.length === 0 ? (
        <Card><EmptyState message="No assets yet — add your domains, IP ranges and products to enable asset-relevant alerting." /></Card>
      ) : (
        <Card>
          <CardHeader title="Inventory" subtitle={`${items.length} shown of ${total}`} />
          <ul className="divide-y divide-ink-600">
            {items.map((a) => (
              <li key={a.id} className="flex items-center gap-3 px-4 py-2.5">
                <span className="w-16 shrink-0 rounded-sm border border-ink-600 px-1.5 py-0.5 text-center text-2xs font-mono uppercase text-ink-300">
                  {a.type}
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm text-ink-100">{a.value}</p>
                  <p className="mt-0.5 text-[11px] text-ink-400">
                    {a.match_count > 0
                      ? `${a.match_count} intel matches · last ${timeAgo(a.last_matched_at)}`
                      : "no matches yet"}
                    {a.owner_team && <> · owner: {a.owner_team}</>}
                  </p>
                </div>
                <span className={`inline-flex items-center rounded-sm px-1.5 py-0.5 text-2xs font-mono uppercase ${criticalityStyle[a.criticality] ?? criticalityStyle.low}`}>
                  {a.criticality}
                </span>
                {canEdit && (
                  <>
                    <button
                      onClick={() => toggle(a)}
                      title={a.enabled ? "Disable matching" : "Enable matching"}
                      className={`rounded-sm border p-1.5 transition-colors ${a.enabled ? "border-accent text-accent" : "border-ink-600 text-ink-500"}`}
                    >
                      <ShieldCheck className="h-3.5 w-3.5" />
                    </button>
                    <button
                      onClick={() => remove(a.id)}
                      title="Delete asset"
                      className="rounded-sm border border-ink-600 p-1.5 text-ink-400 hover:border-accent hover:text-accent"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </>
                )}
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}
