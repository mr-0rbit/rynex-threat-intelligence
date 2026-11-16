import { useCallback, useEffect, useState } from "react";
import { Database, ExternalLink, Globe, Search, ShieldAlert, Tag } from "lucide-react";
import { api } from "../api/client";
import { Badge, Card, EmptyState, Spinner, StatusBadge, timeAgo } from "../components/ui";
import { Pagination } from "./Vulnerabilities";
import { useNavigate } from "react-router-dom";

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
  const navigate = useNavigate();

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
    <div className="space-y-5">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Database className="h-5 w-5 text-accent" />
              Data Breach Intelligence
            </h1>
            <Badge variant="cyan">{total.toLocaleString()} INCIDENTS</Badge>
          </div>
          <p className="mt-1 text-xs text-ink-400 font-sans">
            Ransomware leak site monitoring, threat actor data claims, and verified corporate exfiltration incidents.
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
              placeholder="Organization or domain…"
              className="w-52 rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 pl-9 pr-3 text-xs font-mono text-ink-100 placeholder:text-ink-500 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40 shadow-sm"
            />
          </div>

          <div className="relative">
            <select
              value={verification}
              onChange={(e) => {
                setVerification(e.target.value);
                setPage(0);
              }}
              className="rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 px-3 text-xs font-mono text-ink-200 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40 shadow-sm cursor-pointer"
            >
              <option value="">All Verification Statuses</option>
              {["confirmed", "reported", "claimed", "unverified", "disputed"].map((s) => (
                <option key={s} value={s}>
                  {s.toUpperCase()}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {loading ? (
        <Spinner label="Scanning breach archives…" />
      ) : items.length === 0 ? (
        <Card>
          <EmptyState message="No breach reports match your search criteria." />
        </Card>
      ) : (
        <div className="space-y-3">
          {items.map((b) => (
            <div
              key={b.id}
              className="group rounded-xl border border-ink-700/70 bg-gradient-to-b from-ink-900/90 to-ink-950/90 p-4 sm:p-5 shadow-lg backdrop-blur-md transition-all hover:border-accent/40 hover:shadow-[0_0_20px_rgba(0,212,255,0.08)]"
            >
              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                <button
                  className="min-w-0 flex-1 text-left"
                  onClick={() => navigate(`/breaches/${b.id}`)}
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-base font-bold text-white group-hover:text-accent transition-colors font-mono">
                      {b.organization_name}
                    </span>
                    <StatusBadge status={b.verification_status} />
                    {b.threat_actor_name && (
                      <span className="inline-flex items-center gap-1.5 rounded-md border border-purple-500/40 bg-purple-500/15 px-2 py-0.5 text-2xs font-mono font-bold text-purple-300 shadow-[0_0_8px_rgba(168,85,247,0.18)]">
                        <ShieldAlert className="h-3 w-3" />
                        <span>{b.threat_actor_name}</span>
                      </span>
                    )}
                  </div>

                  <div className="mt-2.5 flex flex-wrap items-center gap-3 text-2xs text-ink-400 font-mono">
                    <span className="text-ink-300 font-semibold">{b.industry || "General Industry"}</span>
                    <span>·</span>
                    <span className="flex items-center gap-1">
                      <Globe className="h-3 w-3 text-ink-500" />
                      <span>{b.country || "Global Region"}</span>
                    </span>
                    <span>·</span>
                    <span>Published {timeAgo(b.published_at)}</span>
                    <span>·</span>
                    <span className="rounded bg-ink-800 px-1.5 py-0.2 border border-ink-700 text-ink-300">
                      via {b.source_slug}
                    </span>
                  </div>

                  {b.claimed_data_types && b.claimed_data_types.length > 0 && (
                    <div className="mt-3 flex flex-wrap gap-1.5">
                      {b.claimed_data_types.map((t, idx) => (
                        <span
                          key={idx}
                          className="inline-flex items-center gap-1 rounded bg-ink-800/80 border border-ink-700/80 px-2 py-0.5 text-[10px] font-mono text-ink-300"
                        >
                          <Tag className="h-2.5 w-2.5 text-accent" />
                          <span>{t}</span>
                        </span>
                      ))}
                    </div>
                  )}
                </button>

                {b.source_url && (
                  <a
                    href={b.source_url}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="shrink-0 flex items-center gap-1.5 rounded-lg border border-ink-700/80 bg-ink-950 px-2.5 py-1.5 text-2xs font-mono text-ink-300 hover:border-accent hover:text-accent transition-colors self-end sm:self-start"
                    title="Inspect original source"
                  >
                    <span>Original Source</span>
                    <ExternalLink className="h-3 w-3" />
                  </a>
                )}
              </div>
            </div>
          ))}

          <Pagination page={page} setPage={setPage} total={total} pageSize={25} />
        </div>
      )}
    </div>
  );
}
