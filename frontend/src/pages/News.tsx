import { useCallback, useEffect, useState } from "react";
import { ExternalLink, Newspaper, Search, Tag } from "lucide-react";
import { api } from "../api/client";
import { Badge, Card, EmptyState, Spinner, timeAgo } from "../components/ui";
import { Pagination } from "./Vulnerabilities";

interface Article {
  headline: string;
  url: string;
  publisher: string;
  summary: string | null;
  published_at: string | null;
  collected_at: string;
  categories: string[] | null;
}

export function News() {
  const [items, setItems] = useState<Article[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [publisher, setPublisher] = useState("");
  const [page, setPage] = useState(0);

  const load = useCallback(() => {
    setLoading(true);
    const params = new URLSearchParams({ limit: "25", offset: String(page * 25) });
    if (q) params.set("q", q);
    if (publisher) params.set("publisher", publisher);
    api<{ total: number; items: Article[] }>(`/news?${params}`)
      .then((r) => {
        setItems(r.items);
        setTotal(r.total);
      })
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  }, [q, publisher, page]);

  useEffect(load, [load]);

  return (
    <div className="space-y-5">
      {/* Page Header */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-white font-mono flex items-center gap-2">
              <Newspaper className="h-5 w-5 text-accent" />
              Cybersecurity News &amp; Bulletins
            </h1>
            <Badge variant="cyan">{total.toLocaleString()} ARTICLES</Badge>
          </div>
          <p className="mt-1 text-xs text-ink-400 font-sans">
            Real-time multi-publisher RSS aggregation covering zero-day disclosures, exploits, and campaigns.
          </p>
        </div>

        {/* Filter Inputs */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-400" />
            <input
              value={q}
              onChange={(e) => {
                setQ(e.target.value);
                setPage(0);
              }}
              placeholder="Search headlines…"
              className="w-52 rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 pl-9 pr-3 text-xs font-mono text-ink-100 placeholder:text-ink-500 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40 shadow-sm"
            />
          </div>

          <div className="relative">
            <input
              value={publisher}
              onChange={(e) => {
                setPublisher(e.target.value);
                setPage(0);
              }}
              placeholder="Filter publisher…"
              className="w-44 rounded-lg border border-ink-700/80 bg-ink-900/90 py-1.5 px-3 text-xs font-mono text-ink-200 placeholder:text-ink-500 focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent/40 shadow-sm"
            />
          </div>
        </div>
      </div>

      {loading ? (
        <Spinner label="Aggregating news dispatches…" />
      ) : items.length === 0 ? (
        <Card>
          <EmptyState message="No news articles found matching your query." />
        </Card>
      ) : (
        <div className="space-y-3">
          {items.map((a) => (
            <div
              key={a.url}
              className="group rounded-xl border border-ink-700/70 bg-gradient-to-b from-ink-900/90 to-ink-950/90 p-5 shadow-lg backdrop-blur-md transition-all hover:border-accent/40 hover:shadow-[0_0_20px_rgba(0,212,255,0.08)]"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="rounded bg-accent/15 border border-accent/30 px-2 py-0.5 text-2xs font-mono font-bold text-accent">
                      {a.publisher}
                    </span>
                    <span className="text-2xs font-mono text-ink-400">
                      Published {timeAgo(a.published_at)}
                    </span>
                  </div>

                  <a
                    href={a.url}
                    target="_blank"
                    rel="noreferrer noopener"
                    className="text-base font-semibold text-white group-hover:text-accent transition-colors block"
                  >
                    {a.headline}
                  </a>

                  {a.summary && (
                    <p className="mt-2 line-clamp-2 text-xs text-ink-300 font-sans leading-relaxed">
                      {a.summary}
                    </p>
                  )}

                  {a.categories && a.categories.length > 0 && (
                    <div className="mt-3 flex flex-wrap gap-1.5">
                      {a.categories.map((c, i) => (
                        <span
                          key={i}
                          className="inline-flex items-center gap-1 rounded bg-ink-800/80 border border-ink-700/80 px-2 py-0.5 text-[10px] font-mono text-ink-400"
                        >
                          <Tag className="h-2.5 w-2.5 text-accent" />
                          <span>{c}</span>
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <a
                  href={a.url}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="shrink-0 p-2 text-ink-400 hover:text-accent hover:bg-ink-800 rounded-lg transition-colors"
                  title="Read external article"
                >
                  <ExternalLink className="h-4 w-4" />
                </a>
              </div>
            </div>
          ))}

          <Pagination page={page} setPage={setPage} total={total} pageSize={25} />
        </div>
      )}
    </div>
  );
}
