import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Bug, Database, ExternalLink, Newspaper, Search, Shield, TriangleAlert } from "lucide-react";
import { api } from "../api/client";
import { Badge, Card, CardHeader, EmptyState, SeverityBadge, Spinner, StatusBadge } from "../components/ui";

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

  if (loading) return <Spinner label={`Executing cross-module intelligence query for “${q}”…`} />;
  if (!results) return <EmptyState message="Search failed to return results." />;

  const alerts = results.alerts ?? [];
  const vulnerabilities = results.vulnerabilities ?? [];
  const breaches = results.breaches ?? [];
  const news = results.news ?? [];
  const iocs = results.iocs ?? [];

  const empty = [alerts, vulnerabilities, breaches, news, iocs].every((arr) => arr.length === 0);

  return (
    <div className="space-y-6">
      <div className="border-b border-ink-700/60 pb-5">
        <div className="flex items-center gap-2.5">
          <Search className="h-5 w-5 text-accent" />
          <h1 className="text-xl font-bold tracking-tight text-white font-mono">
            Intelligence Search: <span className="text-accent">“{q}”</span>
          </h1>
        </div>
        <p className="mt-1 text-xs text-ink-400 font-sans">
          Correlated federated search matches across IOCs, vulnerabilities, breach reports, alerts, and news.
        </p>
      </div>

      {empty && (
        <Card>
          <EmptyState message="No matching threat records found across any module." />
        </Card>
      )}

      {/* Alerts matches */}
      {alerts.length > 0 && (
        <Card>
          <CardHeader title={`Alerts (${alerts.length})`} icon={TriangleAlert} />
          <div className="divide-y divide-ink-700/60">
            {alerts.map((a) => (
              <div key={a.id} className="flex items-center gap-3 px-5 py-3 hover:bg-ink-800/40 transition-colors">
                <SeverityBadge severity={a.severity} />
                <StatusBadge status={a.status} />
                <span className="min-w-0 flex-1 truncate text-xs font-mono font-medium text-white">
                  {a.title}
                </span>
                <Link
                  to="/alerts"
                  className="shrink-0 text-2xs font-mono text-accent hover:underline flex items-center gap-1"
                >
                  <span>View in Alerts</span>
                  <ExternalLink className="h-3 w-3" />
                </Link>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Vulnerabilities matches */}
      {vulnerabilities.length > 0 && (
        <Card>
          <CardHeader title={`Vulnerabilities (${vulnerabilities.length})`} icon={Bug} />
          <div className="divide-y divide-ink-700/60">
            {vulnerabilities.map((v) => (
              <div key={v.cve_id} className="flex items-center gap-3 px-5 py-3 hover:bg-ink-800/40 transition-colors">
                <SeverityBadge severity={v.severity ?? "informational"} />
                <Link
                  to={`/vulnerabilities?q=${v.cve_id}`}
                  className="font-mono text-xs font-bold text-accent hover:underline"
                >
                  {v.cve_id}
                </Link>
                <span className="min-w-0 flex-1 truncate text-xs text-ink-300 font-sans">{v.title}</span>
                {v.in_kev && <Badge variant="critical">CISA KEV</Badge>}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Breaches matches */}
      {breaches.length > 0 && (
        <Card>
          <CardHeader title={`Breach Incidents (${breaches.length})`} icon={Database} />
          <div className="divide-y divide-ink-700/60">
            {breaches.map((b, i) => (
              <div key={i} className="flex items-center gap-3 px-5 py-3 hover:bg-ink-800/40 transition-colors">
                <StatusBadge status={b.verification} />
                <span className="text-xs font-bold text-white font-mono">{b.organization}</span>
                {b.actor && (
                  <Badge variant="purple" size="xs">
                    Claim by {b.actor}
                  </Badge>
                )}
                {b.published_at && (
                  <span className="ml-auto text-2xs font-mono text-ink-400">
                    {new Date(b.published_at).toLocaleDateString()}
                  </span>
                )}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* IOCs matches */}
      {iocs.length > 0 && (
        <Card>
          <CardHeader title={`Indicator Records (${iocs.length})`} icon={Shield} />
          <div className="divide-y divide-ink-700/60">
            {iocs.map((ioc, i) => (
              <div key={i} className="flex items-center gap-3 px-5 py-3 hover:bg-ink-800/40 transition-colors">
                <Badge variant="cyan" size="xs">
                  {ioc.type}
                </Badge>
                <span className="min-w-0 flex-1 truncate font-mono text-xs text-ink-100">{ioc.value}</span>
                <span className="tabular-nums font-mono text-2xs text-accent">
                  {(ioc.confidence * 100).toFixed(0)}% confidence
                </span>
                <span className="text-2xs font-mono text-ink-400">via {ioc.source}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* News matches */}
      {news.length > 0 && (
        <Card>
          <CardHeader title={`Cyber News (${news.length})`} icon={Newspaper} />
          <div className="divide-y divide-ink-700/60">
            {news.map((n) => (
              <div key={n.url} className="flex items-center justify-between gap-4 px-5 py-3 hover:bg-ink-800/40 transition-colors">
                <a
                  href={n.url}
                  target="_blank"
                  rel="noreferrer noopener"
                  className="text-xs font-semibold text-white hover:text-accent truncate flex items-center gap-1.5"
                >
                  <span className="truncate">{n.headline}</span>
                  <ExternalLink className="h-3 w-3 shrink-0 text-accent" />
                </a>
                <span className="text-2xs font-mono text-ink-400 shrink-0">{n.publisher}</span>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

export default SearchResults;
