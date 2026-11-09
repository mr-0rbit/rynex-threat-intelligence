import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import { Card, EmptyState, Spinner, timeAgo } from "../components/ui";
import { Pagination } from "./Vulnerabilities";

interface IocItem {
  id: string;
  value: string;
  type: string;
  source_slug: string;
  confidence: number;
  confidence_reasons: { reasons?: string[] } | null;
  malware_family: string | null;
  first_seen_at: string | null;
  last_seen_at: string | null;
  reports_count: number;
}

const TYPES = ["", "ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256", "email"];

export function IOCs() {
  const [items, setItems] = useState<IocItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [type, setType] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(0);

  const load = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams({ limit: "25", offset: String(page * 25) });
    if (type) params.set("type", type);
    if (q) params.set("q", q);
    api<{ total: number; items: IocItem[] }>(`/iocs?${params}`)
      .then((r) => {
        setItems(r.items);
        setTotal(r.total);
      })
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  }, [type, q, page]);

  useEffect(load, [load]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-white">Indicator Intelligence</h1>
          <p className="text-xs text-slate-500">{total.toLocaleString()} indicators · deduplicated and normalized</p>
        </div>
        <div className="flex gap-2">
          <input
            value={q}
            onChange={(e) => { setQ(e.target.value); setPage(0); }}
            placeholder="Search indicator value…"
            className="w-52 rounded-md border border-rynex-border bg-rynex-panel px-2.5 py-1.5 font-mono text-xs text-slate-300 placeholder:text-slate-600"
          />
          <select value={type} onChange={(e) => { setType(e.target.value); setPage(0); }} className="rounded-md border border-rynex-border bg-rynex-panel px-2.5 py-1.5 text-xs text-slate-300">
            {TYPES.map((t) => <option key={t} value={t}>{t ? t.toUpperCase() : "All types"}</option>)}
          </select>
        </div>
      </div>

      {loading ? (
        <Spinner />
      ) : items.length === 0 ? (
        <Card><EmptyState message="No indicators match. IOC feeds will populate this view." /></Card>
      ) : (
        <Card className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-rynex-border text-[11px] uppercase tracking-wider text-slate-500">
                <th className="px-4 py-2.5">Indicator</th>
                <th className="px-4 py-2.5">Type</th>
                <th className="px-4 py-2.5">Malware</th>
                <th className="px-4 py-2.5">Confidence</th>
                <th className="px-4 py-2.5">Source</th>
                <th className="px-4 py-2.5">Last seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-rynex-border">
              {items.map((i) => (
                <tr key={i.id} className="hover:bg-rynex-border/20">
                  <td className="max-w-96 truncate px-4 py-2.5 font-mono text-xs text-slate-200" title={i.value}>{i.value}</td>
                  <td className="px-4 py-2.5 text-xs uppercase text-slate-400">{i.type}</td>
                  <td className="px-4 py-2.5 text-xs text-slate-400">{i.malware_family ?? "—"}</td>
                  <td className="px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-rynex-border">
                        <div className="h-full rounded-full bg-rynex-accent" style={{ width: `${i.confidence * 100}%` }} />
                      </div>
                      <span className="text-[11px] tabular-nums text-slate-500">{(i.confidence * 100).toFixed(0)}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-slate-500">{i.source_slug}</td>
                  <td className="px-4 py-2.5 text-xs text-slate-500">{timeAgo(i.last_seen_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
      <Pagination page={page} setPage={setPage} total={total} pageSize={25} />
    </div>
  );
}
