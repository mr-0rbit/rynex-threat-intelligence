import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import { Card, EmptyState, SeverityBadge, Spinner, timeAgo } from "../components/ui";

interface Vuln {
  cve_id: string;
  title: string | null;
  severity: string | null;
  cvss_base_score: number | null;
  epss_score: number | null;
  in_kev: boolean;
  kev_date_added: string | null;
  known_ransomware_use: boolean | null;
  published_at: string | null;
}

export function Vulnerabilities() {
  const [items, setItems] = useState<Vuln[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState("");
  const [kev, setKev] = useState("");
  const [q, setQ] = useState("");
  const [page, setPage] = useState(0);

  const load = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams({ limit: "25", offset: String(page * 25) });
    if (severity) params.set("severity", severity);
    if (kev) params.set("kev", kev);
    if (q) params.set("q", q);
    api<{ total: number; items: Vuln[] }>(`/vulnerabilities?${params}`)
      .then((r) => {
        setItems(r.items);
        setTotal(r.total);
      })
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  }, [severity, kev, q, page]);

  useEffect(load, [load]);

  const sevOf = (v: Vuln) => v.severity ?? (v.in_kev ? "high" : "informational");

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-white">Vulnerability Intelligence</h1>
          <p className="text-xs text-slate-500">{total.toLocaleString()} vulnerabilities tracked</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <input
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setPage(0);
            }}
            placeholder="CVE ID or product…"
            className="w-48 rounded-md border border-rynex-border bg-rynex-panel px-2.5 py-1.5 text-xs text-slate-300 placeholder:text-slate-600"
          />
          <select value={kev} onChange={(e) => { setKev(e.target.value); setPage(0); }} className="rounded-md border border-rynex-border bg-rynex-panel px-2.5 py-1.5 text-xs text-slate-300">
            <option value="">All CVEs</option>
            <option value="true">CISA KEV only</option>
            <option value="false">Not in KEV</option>
          </select>
          <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(0); }} className="rounded-md border border-rynex-border bg-rynex-panel px-2.5 py-1.5 text-xs text-slate-300">
            <option value="">All severities</option>
            {["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>

      {loading ? (
        <Spinner />
      ) : items.length === 0 ? (
        <Card><EmptyState message="No vulnerabilities match the filters." /></Card>
      ) : (
        <Card className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-rynex-border text-[11px] uppercase tracking-wider text-slate-500">
                <th className="px-4 py-2.5">CVE</th>
                <th className="px-4 py-2.5">Severity</th>
                <th className="px-4 py-2.5">CVSS</th>
                <th className="px-4 py-2.5">EPSS</th>
                <th className="px-4 py-2.5">KEV</th>
                <th className="px-4 py-2.5">Published</th>
                <th className="px-4 py-2.5">Product</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-rynex-border">
              {items.map((v) => (
                <tr key={v.cve_id} className="hover:bg-rynex-border/20">
                  <td className="px-4 py-2.5 font-mono text-xs">
                    <a href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`} target="_blank" rel="noreferrer noopener" className="text-rynex-accent hover:underline">
                      {v.cve_id}
                    </a>
                  </td>
                  <td className="px-4 py-2.5"><SeverityBadge severity={sevOf(v)} /></td>
                  <td className="px-4 py-2.5 tabular-nums text-slate-300">{v.cvss_base_score ?? "—"}</td>
                  <td className="px-4 py-2.5 tabular-nums text-slate-500">{v.epss_score != null ? `${(v.epss_score * 100).toFixed(1)}%` : "—"}</td>
                  <td className="px-4 py-2.5">
                    {v.in_kev ? (
                      <span className="flex items-center gap-1.5 text-[11px] text-orange-400">
                        Exploited{v.known_ransomware_use && <span className="text-red-400">· ransomware</span>}
                      </span>
                    ) : (
                      <span className="text-xs text-slate-600">—</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-slate-500">{timeAgo(v.published_at)}</td>
                  <td className="max-w-56 truncate px-4 py-2.5 text-xs text-slate-400">{v.title ?? "—"}</td>
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

export function Pagination({ page, setPage, total, pageSize }: { page: number; setPage: (fn: (p: number) => number) => void; total: number; pageSize: number }) {
  return (
    <div className="flex items-center justify-between text-xs text-slate-500">
      <span>Page {page + 1} of {Math.max(1, Math.ceil(total / pageSize))}</span>
      <div className="flex gap-2">
        <button disabled={page === 0} onClick={() => setPage((p) => Math.max(0, p - 1))} className="rounded border border-rynex-border px-3 py-1 disabled:opacity-30">Previous</button>
        <button disabled={(page + 1) * pageSize >= total} onClick={() => setPage((p) => p + 1)} className="rounded border border-rynex-border px-3 py-1 disabled:opacity-30">Next</button>
      </div>
    </div>
  );
}
