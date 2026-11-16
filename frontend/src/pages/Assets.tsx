/* Assets.tsx — the organization's own attack surface.
 *
 * Intel matched against these assets escalates severity and names the asset
 * in alerts. CRUD against GET/POST/PATCH/DELETE /api/v1/assets.
 */

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Plus, Server, ShieldCheck, Trash2, X } from "lucide-react";
import { api } from "../api/client";
import { Badge, Card, CardHeader, EmptyState, Spinner, timeAgo } from "../components/ui";
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

  const critBadge = (crit: string) => {
    const map: Record<string, "critical" | "warning" | "cyan" | "neutral"> = {
      critical: "critical",
      high: "warning",
      medium: "cyan",
      low: "neutral",
    };
    return <Badge variant={map[crit.toLowerCase()] ?? "neutral"}>{crit}</Badge>;
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Server className="h-5 w-5 text-accent" />
              Attack Surface Inventory
            </h1>
            <Badge variant="cyan">{total.toLocaleString()} ASSETS</Badge>
          </div>
          <p className="mt-1 text-xs text-ink-400 font-sans">
            Corporate domains, CIDRs, external infrastructure and products for prioritized threat matching.
          </p>
        </div>

        {canEdit && (
          <button
            onClick={() => setShowForm(!showForm)}
            className="inline-flex items-center gap-2 rounded-xl bg-accent px-4 py-2 text-xs font-mono font-bold uppercase tracking-wider text-black hover:bg-white hover:shadow-[0_0_15px_rgba(0,212,255,0.4)] transition-all"
          >
            {showForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
            <span>{showForm ? "Cancel" : "Add Target Asset"}</span>
          </button>
        )}
      </div>

      {/* New Asset Form */}
      {showForm && canEdit && (
        <Card className="border-accent/40 bg-gradient-to-b from-ink-900 to-ink-950 p-5 shadow-xl">
          <CardHeader title="Register Attack Surface Asset" subtitle="Threat feeds matching this asset will trigger priority escalation" />
          <form onSubmit={create} className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            <div>
              <label className="block text-[10px] font-mono uppercase text-ink-400 mb-1">Asset Type</label>
              <select
                value={form.type}
                onChange={(e) => setForm({ ...form, type: e.target.value })}
                className="w-full rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 text-xs font-mono text-ink-200 focus:border-accent focus:outline-none"
              >
                {TYPES.map((t) => (
                  <option key={t} value={t}>
                    {t.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>

            <div className="lg:col-span-2">
              <label className="block text-[10px] font-mono uppercase text-ink-400 mb-1">Value (Domain / IP / CIDR)</label>
              <input
                required
                value={form.value}
                onChange={(e) => setForm({ ...form, value: e.target.value })}
                placeholder="acme.com, 198.51.100.0/24, SolarWinds"
                className="w-full rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 text-xs font-mono text-ink-100 placeholder:text-ink-600 focus:border-accent focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase text-ink-400 mb-1">Criticality</label>
              <select
                value={form.criticality}
                onChange={(e) => setForm({ ...form, criticality: e.target.value })}
                className="w-full rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 text-xs font-mono text-ink-200 focus:border-accent focus:outline-none"
              >
                {CRITICALITIES.map((c) => (
                  <option key={c} value={c}>
                    {c.toUpperCase()}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase text-ink-400 mb-1">Owner Team</label>
              <input
                value={form.owner_team}
                onChange={(e) => setForm({ ...form, owner_team: e.target.value })}
                placeholder="SecOps / Cloud"
                className="w-full rounded-lg border border-ink-700 bg-ink-950 px-3 py-2 text-xs font-mono text-ink-100 placeholder:text-ink-600 focus:border-accent focus:outline-none"
              />
            </div>

            <div className="sm:col-span-2 lg:col-span-5 flex justify-end gap-2 pt-2">
              <button
                type="submit"
                disabled={busy}
                className="rounded-lg bg-accent px-5 py-2 text-xs font-mono font-bold uppercase tracking-wider text-black hover:bg-white transition-all disabled:opacity-40"
              >
                {busy ? "Registering…" : "Save Asset"}
              </button>
            </div>
          </form>
        </Card>
      )}

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center gap-2.5">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter by asset value…"
          className="w-56 rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 px-3 text-xs font-mono text-ink-100 placeholder:text-ink-500 focus:border-accent focus:outline-none"
        />
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          className="rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 px-3 text-xs font-mono text-ink-200 focus:border-accent focus:outline-none"
        >
          <option value="">All Asset Types</option>
          {TYPES.map((t) => (
            <option key={t} value={t}>
              {t.toUpperCase()}
            </option>
          ))}
        </select>
        <select
          value={critFilter}
          onChange={(e) => setCritFilter(e.target.value)}
          className="rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 px-3 text-xs font-mono text-ink-200 focus:border-accent focus:outline-none"
        >
          <option value="">All Criticalities</option>
          {CRITICALITIES.map((c) => (
            <option key={c} value={c}>
              {c.toUpperCase()}
            </option>
          ))}
        </select>
      </div>

      {error && <div className="rounded-xl border border-rose-500/40 bg-rose-950/30 p-3 text-xs text-rose-300 font-mono">{error}</div>}

      {loading ? (
        <Spinner label="Loading attack surface inventory…" />
      ) : items.length === 0 ? (
        <Card>
          <EmptyState message="No attack surface assets defined yet. Add domains, IP subnets, or products to begin monitoring." />
        </Card>
      ) : (
        <Card>
          <CardHeader title="Tracked Assets" subtitle={`${items.length} monitored assets shown`} />
          <ul className="divide-y divide-ink-700/60">
            {items.map((a) => (
              <li key={a.id} className="flex items-center justify-between gap-4 px-5 py-3.5 hover:bg-ink-800/40 transition-colors">
                <div className="flex items-center gap-3 min-w-0 flex-1">
                  <span className="w-20 shrink-0 rounded-md border border-ink-700/80 bg-ink-950 px-2 py-0.5 text-center text-[10px] font-mono font-bold uppercase text-accent">
                    {a.type}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-semibold text-white font-mono">{a.value}</p>
                    <p className="mt-0.5 text-2xs text-ink-400 font-mono">
                      {a.match_count > 0 ? (
                        <span className="text-accent font-medium">{a.match_count} threat correlations</span>
                      ) : (
                        "No incidents detected"
                      )}
                      {a.last_matched_at && ` · Last seen ${timeAgo(a.last_matched_at)}`}
                      {a.owner_team && ` · Team: ${a.owner_team}`}
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-3 shrink-0">
                  {critBadge(a.criticality)}
                  {canEdit && (
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => toggle(a)}
                        title={a.enabled ? "Active — click to disable" : "Disabled — click to enable"}
                        className={`rounded-lg border p-1.5 transition-colors ${
                          a.enabled
                            ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400 shadow-[0_0_8px_rgba(16,185,129,0.2)]"
                            : "border-ink-700 bg-ink-900 text-ink-500"
                        }`}
                      >
                        <ShieldCheck className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => remove(a.id)}
                        title="Delete asset"
                        className="rounded-lg border border-ink-700 bg-ink-900 p-1.5 text-ink-400 hover:border-rose-500 hover:text-rose-400 transition-colors"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}
