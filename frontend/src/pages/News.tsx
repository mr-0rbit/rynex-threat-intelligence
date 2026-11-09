import { useCallback, useEffect, useState } from "react";
import { ExternalLink } from "lucide-react";
import { api } from "../api/client";
import { Card, EmptyState, Spinner, timeAgo } from "../components/ui";
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
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-white">Cybersecurity News</h1>
          <p className="text-xs text-ink-400">{total.toLocaleString()} articles from publisher RSS feeds</p>
        </div>
        <div className="flex gap-2">
          <input
            value={q}
            onChange={(e) => { setQ(e.target.value); setPage(0); }}
            placeholder="Search headlines…"
            className="w-52 rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200 placeholder:text-ink-500"
          />
          <input
            value={publisher}
            onChange={(e) => { setPublisher(e.target.value); setPage(0); }}
            placeholder="Publisher…"
            className="w-40 rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200 placeholder:text-ink-500"
          />
        </div>
      </div>

      {loading ? (
        <Spinner />
      ) : items.length === 0 ? (
        <Card><EmptyState message="No articles match." /></Card>
      ) : (
        <div className="space-y-2">
          {items.map((a) => (
            <Card key={a.url} className="p-4 hover:border-accent/30">
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <a href={a.url} target="_blank" rel="noreferrer noopener" className="text-sm font-medium text-ink-100 hover:text-accent">
                    {a.headline}
                  </a>
                  <p className="mt-1 line-clamp-2 text-xs text-ink-400">{a.summary}</p>
                  <p className="mt-1.5 text-[11px] text-ink-500">
                    {a.publisher} · published {timeAgo(a.published_at)} · collected {timeAgo(a.collected_at)}
                  </p>
                </div>
                <a href={a.url} target="_blank" rel="noreferrer noopener" className="shrink-0 text-ink-400 hover:text-accent">
                  <ExternalLink className="h-4 w-4" />
                </a>
              </div>
            </Card>
          ))}
          <Pagination page={page} setPage={setPage} total={total} pageSize={25} />
        </div>
      )}
    </div>
  );
}
