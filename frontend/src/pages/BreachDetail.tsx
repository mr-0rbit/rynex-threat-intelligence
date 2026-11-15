/* BreachDetail.tsx — RTIP specific breach detail page.
 *
 * Shows detailed information for a single breach incident, navigated to from
 * the Breaches list via /breaches/:breachId. Data comes from
 * GET /api/v1/breaches/{breach_id}.
 */

import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, ExternalLink } from "lucide-react";
import { api } from "../api/client";
import { Card, CardHeader, EmptyState, Spinner, StatusBadge, timeAgo } from "../components/ui";

interface BreachDetailData {
  id: string;
  organization_name: string;
  organization_domain: string | null;
  industry: string | null;
  country: string | null;
  region: string | null;
  threat_actor_name: string | null;
  claimed_data_types: string[] | null;
  record_count: number | null;
  record_count_reliability: string | null;
  summary: string | null;
  published_at: string | null;
  verification_status: string;
  confidence: number;
  confidence_reasons: { reasons?: string[] } | null;
  source_slug: string;
  source_url: string | null;
  evidence_references: string[] | null;
}

export function BreachDetail() {
  const { breachId } = useParams<{ breachId: string }>();
  const [loading, setLoading] = useState(true);
  const [breach, setBreach] = useState<BreachDetailData | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setFailed(false);
    api<BreachDetailData>(`/breaches/${breachId}`)
      .then((data) => {
        if (!cancelled) setBreach(data);
      })
      .catch(() => {
        if (!cancelled) {
          setBreach(null);
          setFailed(true);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [breachId]);

  if (loading) return <Spinner label="Loading breach details…" />;
  if (!breach) return <EmptyState message={failed ? "Failed to load breach details" : "Breach not found"} />;

  const reasons = breach.confidence_reasons?.reasons ?? [];

  return (
    <div className="space-y-4">
      <Link to="/breaches" className="inline-flex items-center gap-1.5 text-xs text-ink-400 hover:text-accent">
        <ArrowLeft className="h-3.5 w-3.5" /> Back to breach intelligence
      </Link>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-white">{breach.organization_name}</h1>
          <p className="text-xs text-ink-400">
            {breach.industry || "industry unknown"} · {breach.country || "region unknown"} · published {timeAgo(breach.published_at)} · via {breach.source_slug}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge status={breach.verification_status} />
          {breach.source_url && (
            <a
              href={breach.source_url}
              target="_blank"
              rel="noreferrer noopener"
              className="inline-flex items-center gap-1 border border-ink-600 px-2.5 py-1.5 text-xs text-ink-300 hover:border-accent hover:text-accent"
              title="Original source"
            >
              Original source <ExternalLink className="h-3.5 w-3.5" />
            </a>
          )}
        </div>
      </div>

      <Card>
        <CardHeader title="Incident details" subtitle="Actor claims are treated as unverified until independently corroborated" />
        <dl className="grid grid-cols-1 gap-x-6 gap-y-3 px-4 py-4 text-xs sm:grid-cols-2">
          <div>
            <dt className="text-2xs uppercase tracking-wider text-ink-500">Organization</dt>
            <dd className="mt-0.5 text-ink-100">{breach.organization_name}</dd>
          </div>
          <div>
            <dt className="text-2xs uppercase tracking-wider text-ink-500">Domain</dt>
            <dd className="mt-0.5 font-mono text-ink-200">{breach.organization_domain || "—"}</dd>
          </div>
          <div>
            <dt className="text-2xs uppercase tracking-wider text-ink-500">Threat actor</dt>
            <dd className="mt-0.5 text-ink-100">{breach.threat_actor_name || "—"}</dd>
          </div>
          <div>
            <dt className="text-2xs uppercase tracking-wider text-ink-500">Claimed records</dt>
            <dd className="mt-0.5 tabular-nums text-ink-200">
              {breach.record_count != null ? breach.record_count.toLocaleString() : "—"}
              {breach.record_count_reliability ? ` (${breach.record_count_reliability})` : ""}
            </dd>
          </div>
          <div>
            <dt className="text-2xs uppercase tracking-wider text-ink-500">Published</dt>
            <dd className="mt-0.5 text-ink-200">{breach.published_at ? new Date(breach.published_at).toLocaleString() : "—"}</dd>
          </div>
          <div>
            <dt className="text-2xs uppercase tracking-wider text-ink-500">Platform confidence</dt>
            <dd className="mt-0.5 font-mono tabular-nums text-accent">{(breach.confidence * 100).toFixed(0)}%</dd>
          </div>
        </dl>
        {breach.summary && (
          <p className="border-t border-ink-700/80 px-4 py-3 text-xs leading-relaxed text-ink-300">{breach.summary}</p>
        )}
      </Card>

      <Card>
        <CardHeader title="Claimed data types" />
        {breach.claimed_data_types && breach.claimed_data_types.length > 0 ? (
          <div className="flex flex-wrap gap-2 px-4 py-3">
            {breach.claimed_data_types.map((d, i) => (
              <span key={i} className="border border-ink-600 bg-ink-800/60 px-2 py-1 text-2xs text-ink-200">
                {d}
              </span>
            ))}
          </div>
        ) : (
          <p className="px-4 py-3 text-xs text-ink-500">No data types claimed yet.</p>
        )}
      </Card>

      <Card>
        <CardHeader title="Confidence reasoning" subtitle="Deterministic, auditable factors — no opaque scoring" />
        {reasons.length > 0 ? (
          <ul className="space-y-1.5 px-4 py-3 text-xs text-ink-300">
            {reasons.map((r, i) => (
              <li key={i} className="flex gap-2">
                <span className="text-accent">›</span> {r}
              </li>
            ))}
          </ul>
        ) : (
          <p className="px-4 py-3 text-xs text-ink-500">No breakdown recorded.</p>
        )}
      </Card>
    </div>
  );
}
