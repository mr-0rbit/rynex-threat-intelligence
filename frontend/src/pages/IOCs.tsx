import { useCallback, useEffect, useState } from "react";
import { Check, Copy, Search, Shield } from "lucide-react";
import { api } from "../api/client";
import { Badge, Card, EmptyState, Spinner, timeAgo } from "../components/ui";
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
  const [copiedId, setCopiedId] = useState<string | null>(null);

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

  const copyValue = (val: string, id: string) => {
    navigator.clipboard.writeText(val);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const typeVariant = (t: string): "cyan" | "purple" | "warning" | "critical" | "success" | "neutral" => {
    switch (t.toLowerCase()) {
      case "ipv4":
      case "ipv6":
        return "purple";
      case "domain":
        return "cyan";
      case "url":
        return "warning";
      case "md5":
      case "sha1":
      case "sha256":
        return "critical";
      case "email":
        return "success";
      default:
        return "neutral";
    }
  };

  return (
    <div className="space-y-5">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Shield className="h-5 w-5 text-accent" />
              Indicator Intelligence (IOCs)
            </h1>
            <Badge variant="cyan">{total.toLocaleString()} INDICATORS</Badge>
          </div>
          <p className="mt-1 text-xs text-ink-400 font-sans">
            Deduplicated, scored, and cross-correlated network and host indicators from global threat feeds.
          </p>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-400" />
            <input
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setPage(0);
              }}
              placeholder="Filter IP, domain, hash…"
              className="w-56 rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 pl-9 pr-3 font-mono text-xs text-ink-100 placeholder:text-ink-500 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40 shadow-sm"
            />
          </div>

          <div className="relative">
            <select
              value={type}
              onChange={(e) => {
                setType(e.target.value);
                setPage(0);
              }}
              className="rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 px-3 font-mono text-xs text-ink-200 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40 shadow-sm cursor-pointer"
            >
              {TYPES.map((t) => (
                <option key={t} value={t}>
                  {t ? t.toUpperCase() : "All Types"}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {loading ? (
        <Spinner label="Loading indicator intelligence…" />
      ) : items.length === 0 ? (
        <Card>
          <EmptyState message="No indicators match your filter criteria." />
        </Card>
      ) : (
        <div className="overflow-hidden rounded-xl border border-ink-700/80 bg-gradient-to-b from-ink-900/95 to-ink-950/95 shadow-xl backdrop-blur-md">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-sans">
              <thead>
                <tr className="border-b border-ink-700/80 bg-ink-950/70 text-[10px] font-bold uppercase tracking-wider text-ink-400 font-mono">
                  <th className="px-5 py-3">Indicator Value</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Threat / Malware</th>
                  <th className="px-4 py-3">Confidence Score</th>
                  <th className="px-4 py-3">Source Feed</th>
                  <th className="px-5 py-3">Last Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-700/50">
                {items.map((i) => (
                  <tr
                    key={i.id}
                    className="hover:bg-ink-800/40 transition-colors group"
                  >
                    <td className="px-5 py-3.5 font-mono text-xs">
                      <div className="flex items-center gap-2 max-w-md">
                        <span className="truncate text-ink-100 group-hover:text-accent transition-colors font-medium" title={i.value}>
                          {i.value}
                        </span>
                        <button
                          onClick={() => copyValue(i.value, i.id)}
                          className="shrink-0 p-1 text-ink-500 hover:text-accent hover:bg-ink-800 rounded transition-colors"
                          title="Copy indicator value"
                        >
                          {copiedId === i.id ? (
                            <Check className="h-3 w-3 text-emerald-400" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                        </button>
                      </div>
                    </td>
                    <td className="px-4 py-3.5">
                      <Badge variant={typeVariant(i.type)} size="xs">
                        {i.type}
                      </Badge>
                    </td>
                    <td className="px-4 py-3.5 text-xs text-ink-200">
                      {i.malware_family ? (
                        <span className="font-semibold text-rose-300 font-mono">
                          {i.malware_family}
                        </span>
                      ) : (
                        <span className="text-ink-500">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3.5 font-mono">
                      <div className="flex items-center gap-2.5">
                        <div className="h-1.5 w-16 overflow-hidden rounded-full bg-ink-800">
                          <div
                            className="h-full rounded-full bg-accent shadow-[0_0_8px_#00d4ff]"
                            style={{ width: `${Math.round(i.confidence * 100)}%` }}
                          />
                        </div>
                        <span className="text-2xs text-ink-300 tabular-nums font-semibold">
                          {(i.confidence * 100).toFixed(0)}%
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3.5 text-xs font-mono text-ink-300">
                      <span className="rounded bg-ink-800/80 px-2 py-0.5 border border-ink-700/60 text-2xs">
                        {i.source_slug}
                      </span>
                    </td>
                    <td className="px-5 py-3.5 text-xs font-mono text-ink-400 whitespace-nowrap">
                      {timeAgo(i.last_seen_at)}
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
