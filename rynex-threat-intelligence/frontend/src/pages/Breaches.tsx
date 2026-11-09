import { useCallback, useEffect, useState } from "react";
import { ExternalLink, ShieldAlert } from "lucide-react";
import { api } from "../api/client";
import { Card, EmptyState, Spinner, StatusBadge, timeAgo } from "../components/ui";
import { Pagination } from "./Vulnerabilities";

interface Breach {
  id: string;
  organization_name: string;
  organization_domain: string | null;
  industry: string | null;
  country: string | null;
  threat_actor_name: string | null;
  claimed_data_types: string[] | null;
  published_at: string | null;
  verification_status: string;
  confidence: number;
  confidence_reasons: { reasons?: string[] } | null;
  source_slug: string;
  source_url: string | null;
}

export function Breaches() {
  const [items, setItems] = useState<Breach[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [verification, setVerification] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams({ limit: "25", offset: String(page * 25) });
    if (verification) params.set("verification", verification);
    if (q) params.set("q", q);
    api<{ total: number; items: Breach[] }>(`/breaches?${params}`)
      .then((r) => {
        setItems(r.items);
        setTotal(r.total);
      })
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  }, [verification, q, page]);

  useEffect(load, [load]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-white">Data Breach Intelligence</h1>
          <p className="text-xs text-slate-500">
            {total.toLocaleString()} incidents · ransomware group claims are marked <span className="text-orange-400">claimed</span> until corroborated
          </p>
        </div>
        <div className="flex gap-2">
          <input
            value={q}
            onChange={(e) => { setQ(e.target.value); setPage(0); }}
            placeholder="Organization name…"
            className="w-48 rounded-md border border-rynex-border bg-rynex-panel px-2.5 py-1.5 text-xs text-slate-300 placeholder:text-slate-600"
          />
          <select value={verification} onChange={(e) => { setVerification(e.target.value); setPage(0); }} className="rounded-md border border-rynex-border bg-rynex-panel px-2.5 py-1.5 text-xs text-slate-300">
            <option value="">All statuses</option>
            {["confirmed", "reported", "claimed", "unverified", "disputed"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      {loading ? (
        <Spinner />
      ) : items.length === 0 ? (
        <Card><EmptyState message="No breach reports match. New disclosures will appear here." /></Card>
      ) : (
        <div className="space-y-2">
          {items.map((b) => (
            <Card key={b.id} className="p-4">
              <div className="flex items-start justify-between gap-4">
                <button className="min-w-0 flex-1 text-left" onClick={() => setExpanded(expanded === b.id ? null : b.id)}>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-semibold text-slate-100">{b.organization_name}</span>
                    <StatusBadge status={b.verification_status} />
                    {b.threat_actor_name && (
                      <span className="flex items-center gap-1 rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-[10px] text-red-300">
                        <ShieldAlert className="h-3 w-3" /> {b.threat_actor_name}
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-[11px] text-slate-500">
                    {b.industry || "industry unknown"} · {b.country || "region unknown"} · published {timeAgo(b.published_at)} · confidence {(b.confidence * 100).toFixed(0)}% · via {b.source_slug}
                  </p>
                </button>
                {b.source_url && (
                  <a href={b.source_url} target="_blank" rel="noreferrer noopener" className="text-slate-500 hover:text-rynex-accent" title="Original source">
                    <ExternalLink className="h-4 w-4" />
                  </a>
                )}
              </div>
              {expanded === b.id && (
                <div className="mt-3 space-y-1.5 border-t border-rynex-border pt-3 text-xs text-slate-400">
                  {b.organization_domain && <p><span className="text-slate-300">Domain:</span> {b.organization_domain}</p>}
                  {b.claimed_data_types?.filter(Boolean).map((d, i) => <p key={i}><span className="text-slate-300">Claimed:</span> {d}</p>)}
                  {b.confidence_reasons?.reasons?.length && (
                    <p><span className="text-slate-300">Why this confidence:</span> {b.confidence_reasons.reasons.join("; ")}</p>
                  )}
                </div>
              )}
            </Card>
          ))}
          <Pagination page={page} setPage={setPage} total={total} pageSize={25} />
        </div>
      )}
    </div>
  );
}
