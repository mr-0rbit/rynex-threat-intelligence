import { useCallback, useEffect, useState } from "react";
import { Bug, ChevronLeft, ChevronRight, ExternalLink, Flame, Search } from "lucide-react";
import { api } from "../api/client";
import { Badge, Card, EmptyState, SeverityBadge, Spinner, timeAgo } from "../components/ui";

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

  const cvssBadge = (score: number | null) => {
    if (score === null) return <span className="text-ink-500">—</span>;
    let color = "text-sky-300 bg-sky-500/10 border-sky-500/20";
    if (score >= 9.0) color = "text-rose-300 bg-rose-500/15 border-rose-500/35 shadow-[0_0_8px_rgba(244,63,94,0.2)]";
    else if (score >= 7.0) color = "text-amber-300 bg-amber-500/15 border-amber-500/35 shadow-[0_0_8px_rgba(245,158,11,0.2)]";
    else if (score >= 4.0) color = "text-cyan-300 bg-cyan-500/10 border-cyan-500/30";

    return (
      <span className={`inline-block rounded px-2 py-0.5 text-xs font-mono font-bold border tabular-nums ${color}`}>
        {score.toFixed(1)}
      </span>
    );
  };

  return (
    <div className="space-y-5">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Bug className="h-5 w-5 text-accent" />
              Vulnerability Intelligence (CVEs)
            </h1>
            <Badge variant="cyan">{total.toLocaleString()} CVEs</Badge>
          </div>
          <p className="mt-1 text-xs text-ink-400 font-sans">
            Continuous CVE correlation with CISA Known Exploited Vulnerabilities (KEV) and EPSS exploit probability scores.
          </p>
        </div>

        {/* Filter Bar */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-400" />
            <input
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setPage(0);
              }}
              placeholder="CVE ID or product…"
              className="w-52 rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 pl-9 pr-3 text-xs font-mono text-ink-100 placeholder:text-ink-500 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40 shadow-sm"
            />
          </div>

          <div className="relative">
            <select
              value={kev}
              onChange={(e) => {
                setKev(e.target.value);
                setPage(0);
              }}
              className="rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 px-3 font-mono text-xs text-ink-200 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40 shadow-sm cursor-pointer"
            >
              <option value="">All CVEs</option>
              <option value="true">CISA KEV Only (Active)</option>
              <option value="false">Not in KEV</option>
            </select>
          </div>

          <div className="relative">
            <select
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value);
                setPage(0);
              }}
              className="rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 px-3 font-mono text-xs text-ink-200 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40 shadow-sm cursor-pointer"
            >
              <option value="">All Severities</option>
              {["critical", "high", "medium", "low"].map((s) => (
                <option key={s} value={s}>
                  {s.toUpperCase()}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {loading ? (
        <Spinner label="Loading vulnerability database…" />
      ) : items.length === 0 ? (
        <Card>
          <EmptyState message="No vulnerabilities match the current filter criteria." />
        </Card>
      ) : (
        <div className="overflow-hidden rounded-xl border border-ink-700/80 bg-gradient-to-b from-ink-900/95 to-ink-950/95 shadow-xl backdrop-blur-md">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-sans">
              <thead>
                <tr className="border-b border-ink-700/80 bg-ink-950/70 text-[10px] font-bold uppercase tracking-wider text-ink-400 font-mono">
                  <th className="px-5 py-3">CVE Identifier</th>
                  <th className="px-4 py-3">Severity</th>
                  <th className="px-4 py-3">CVSS Score</th>
                  <th className="px-4 py-3">EPSS Probability</th>
                  <th className="px-4 py-3">CISA KEV Status</th>
                  <th className="px-4 py-3">Published</th>
                  <th className="px-5 py-3">Affected Product / Title</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-700/50">
                {items.map((v) => (
                  <tr
                    key={v.cve_id}
                    className="hover:bg-ink-800/40 transition-colors group"
                  >
                    <td className="px-5 py-3.5 font-mono text-xs">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="inline-flex items-center gap-1.5 font-bold text-accent hover:underline group-hover:brightness-110"
                      >
                        <span>{v.cve_id}</span>
                        <ExternalLink className="h-3 w-3 opacity-0 group-hover:opacity-100 transition-opacity" />
                      </a>
                    </td>
                    <td className="px-4 py-3.5">
                      <SeverityBadge severity={sevOf(v)} />
                    </td>
                    <td className="px-4 py-3.5 font-mono">
                      {cvssBadge(v.cvss_base_score)}
                    </td>
                    <td className="px-4 py-3.5 font-mono text-xs">
                      {v.epss_score != null ? (
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-14 overflow-hidden rounded-full bg-ink-800">
                            <div
                              className="h-full rounded-full bg-cyan-400"
                              style={{ width: `${Math.min(100, Math.round(v.epss_score * 100))}%` }}
                            />
                          </div>
                          <span className="text-ink-200 tabular-nums">
                            {(v.epss_score * 100).toFixed(1)}%
                          </span>
                        </div>
                      ) : (
                        <span className="text-ink-500">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3.5 font-mono text-2xs">
                      {v.in_kev ? (
                        <div className="inline-flex items-center gap-1.5 rounded-md border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-rose-300 font-bold shadow-[0_0_8px_rgba(244,63,94,0.2)]">
                          <Flame className="h-3.5 w-3.5 text-rose-400 animate-pulse" />
                          <span>EXPLOITED</span>
                          {v.known_ransomware_use && (
                            <span className="text-white font-normal">· Ransomware</span>
                          )}
                        </div>
                      ) : (
                        <span className="text-ink-500">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3.5 font-mono text-xs text-ink-400 whitespace-nowrap">
                      {timeAgo(v.published_at)}
                    </td>
                    <td className="px-5 py-3.5 max-w-xs truncate text-xs text-ink-200 font-sans" title={v.title ?? ""}>
                      {v.title ?? "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <Pagination page={page} setPage={setPage} total={total} pageSize={25} />
    </div>
  );
}

export function Pagination({
  page,
  setPage,
  total,
  pageSize,
}: {
  page: number;
  setPage: (fn: (p: number) => number) => void;
  total: number;
  pageSize: number;
}) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="flex items-center justify-between pt-2 text-xs font-mono text-ink-400">
      <span>
        Page <span className="text-white font-semibold">{page + 1}</span> of{" "}
        <span className="text-white font-semibold">{totalPages}</span> ({total.toLocaleString()} total items)
      </span>
      <div className="flex items-center gap-2">
        <button
          disabled={page === 0}
          onClick={() => setPage((p) => Math.max(0, p - 1))}
          className="flex items-center gap-1 rounded-lg border border-ink-700/80 bg-ink-900/90 px-3 py-1.5 text-xs text-ink-200 hover:border-ink-500 hover:text-white disabled:opacity-30 disabled:pointer-events-none transition-colors"
        >
          <ChevronLeft className="h-3.5 w-3.5" />
          <span>Previous</span>
        </button>
        <button
          disabled={(page + 1) * pageSize >= total}
          onClick={() => setPage((p) => p + 1)}
          className="flex items-center gap-1 rounded-lg border border-ink-700/80 bg-ink-900/90 px-3 py-1.5 text-xs text-ink-200 hover:border-ink-500 hover:text-white disabled:opacity-30 disabled:pointer-events-none transition-colors"
        >
          <span>Next</span>
          <ChevronRight className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}
