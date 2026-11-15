import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import { Card, CardHeader, EmptyState, SeverityBadge, Spinner, StatusBadge } from "../components/ui";

interface SearchResults {
  iocs: { value: string; type: string; confidence: number; source: string }[];
  vulnerabilities: { cve_id: string; severity: string | null; cvss: number | null; in_kev: boolean; title: string | null }[];
  breaches: { organization: string; actor: string | null; verification: string; published_at: string | null }[];
  news: { headline: string; publisher: string; url: string; published_at: string | null }[];
  alerts: { id: string; title: string; severity: string; status: string }[];
}

export function SearchResults() {
  const [params] = useSearchParams();
  const q = params.get("q") || "";
  const [results, setResults] = useState<SearchResults | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api<SearchResults>(`/search?q=${encodeURIComponent(q)}`)
      .then((r) => {
        if (!cancelled) setResults(r);
      })
      .catch(() => {
        if (!cancelled) setResults(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [q]);

  if (loading) return <Spinner label={`Searching for “${q}”…`} />;
  if (!results) return <EmptyState message="Search failed" />;

  const alerts = results.alerts ?? [];
  const vulnerabilities = results.vulnerabilities ?? [];
  const breaches = results.breaches ?? [];
  const news = results.news ?? [];
  const iocs = results.iocs ?? [];

  const empty = [alerts, vulnerabilities, breaches, news, iocs].every((arr) => arr.length === 0);

  return (
    <div className="space-y-4">
      <h1 className="text-lg font-semibold text-white">
        Search results for <span className="text-accent">“{q}”</span>
      </h1>

      {empty && <Card><EmptyState message="No matching intelligence found across any module." /></Card>}

      {alerts.length > 0 && (
        <Card>
          <CardHeader title={`Alerts (${alerts.length})`} />
          <ul className="divide-y divide-ink-600">
            {alerts.map((a) => (
              <li key={a.id} className="flex items-center gap-3 px-4 py-2.5 text-sm">
                <SeverityBadge severity={a.severity} />
                <span className="min-w-0 flex-1 truncate text-ink-100">{a.title}</span>
                <StatusBadge status={a.status} />
              </li>
            ))}
          </ul>
        </Card>
      )}

      {vulnerabilities.length > 0 && (
        <Card>
          <CardHeader title={`Vulnerabilities (${vulnerabilities.length})`} />
          <ul className="divide-y divide-ink-600">
            {vulnerabilities.map((v) => (
              <li key={v.cve_id} className="flex items-center gap-3 px-4 py-2.5 text-sm">
                <SeverityBadge severity={v.severity ?? "informational"} />
                <Link to={`/vulnerabilities?q=${v.cve_id}`} className="font-mono text-xs text-accent hover:underline">{v.cve_id}</Link>
                <span className="min-w-0 flex-1 truncate text-xs text-ink-300">{v.title}</span>
                {v.in_kev && <span className="text-[10px] uppercase text-accent">KEV</span>}
              </li>
            ))}
          </ul>
        </Card>
      )}

      {breaches.length > 0 && (
        <Card>
          <CardHeader title={`Breach incidents (${breaches.length})`} />
          <ul className="divide-y divide-ink-600">
            {breaches.map((b, i) => (
              <li key={i} className="flex items-center gap-3 px-4 py-2.5 text-sm">
                <StatusBadge status={b.verification} />
                <span className="text-ink-100">{b.organization}</span>
                {b.actor && <span className="text-xs text-white">claim by {b.actor}</span>}
              </li>
            ))}
          </ul>
        </Card>
      )}

      {iocs.length > 0 && (
        <Card>
          <CardHeader title={`IOCs (${iocs.length})`} />
          <ul className="divide-y divide-ink-600">
            {iocs.map((ioc, i) => (
              <li key={i} className="flex items-center gap-3 px-4 py-2.5 text-sm">
                <span className="w-16 shrink-0 text-2xs uppercase tracking-wider text-ink-500">{ioc.type}</span>
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-ink-100">{ioc.value}</span>
                <span className="tabular-nums text-2xs text-ink-400">{(ioc.confidence * 100).toFixed(0)}%</span>
                <span className="text-2xs text-ink-500">via {ioc.source}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {news.length > 0 && (
        <Card>
          <CardHeader title={`News (${news.length})`} />
          <ul className="divide-y divide-ink-600">
            {news.map((n) => (
              <li key={n.headline} className="flex items-center gap-3 px-4 py-2.5 text-sm">
                <span className="text-ink-100 truncate">{n.headline}</span>
                <span className="text-xs text-white/60">{n.publisher}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </div>
  );
}

export default SearchResults;
