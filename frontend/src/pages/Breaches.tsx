import { ExternalLink, ShieldAlert, MenuAlt2 } from "lucide-react";
import { api } from "../api/client";
import { Card, EmptyState, Spinner, StatusBadge, timeAgo } from "../components/ui";
import { Pagination } from "./Vulnerabilities";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../auth";

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

export function Breaches: React.FC = () => {
  const { user } = useAuth();
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
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-white">Data Breach Intelligence</h1>
          <p className="text-xs text-ink-400">
            {total.toLocaleString()} incidents · ransomware group claims are marked <span className="text-accent">claimed</span> until corroborated
          </p>
        </div>
        <div className="flex gap-2">
          <input
            value={q}
            onChange={(e) => { setQ(e.target.value); setPage(0); }}
            placeholder="Organization name…"
            className="w-48 rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200 placeholder:text-ink-500"
          />
          <select value={verification} onChange={(e) => { setVerification(e.target.value); setPage(0); }} className="rounded-sm border border-ink-600 bg-ink-800 px-2.5 py-1.5 text-xs text-ink-200">
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
                <button className="min-w-0 flex-1 text-left" onClick={() => navigate(`/breaches/${b.id}`)}>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-semibold text-ink-100">{b.organization_name}</span>
                    <StatusBadge status={b.verification_status} />
                    {b.threat_actor_name && (
                      <span className="flex items-center gap-1 rounded border border-ink-500 bg-ink-700 px-1.5 py-0.5 text-[10px] text-ink-100">
                        <ShieldAlert className="h-3 w-3" /> {b.threat_actor_name}
                      </span>
                    )}
                  </div>
                  <p className="mt-1 text-[11px] text-ink-400">
                    {b.industry || "industry unknown"} · {b.country || "region unknown"} · published {timeAgo(b.published_at)} · confidence {(b.confidence * 100).toFixed(0)}% · via {b.source_slug}
                  </p>
                </button>
                {b.source_url && (
                  <a href={b.source_url} target="_blank" rel="noreferrer noopener" className="text-ink-400 hover:text-accent" title="Original source">
                    <ExternalLink className="h-4 w-4" />
                  </a>
                )}
              </div>
            </Card>
          ))}
          <Pagination page={page} setPage={setPage} total={total} pageSize={25} />
        </div>
      )}
    </div>
  );
}